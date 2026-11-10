pub mod trie_store;
pub mod cached_trie_store;
pub mod epoch_backend;
pub mod flat_trie_store;
pub mod flat_migrate;
pub mod counting_trie_store;
pub mod rskj_import;
pub use position::{
    BlockRef, Cursor, LineageBreak, Transition, Validated, verify_local_coherence,
};
pub use trie_store::RocksDbTrieStore;
pub mod trie_tool;
pub mod trie_snapshot;
pub mod trie_inspect;
pub mod epoch_store;
pub mod window_store;
pub mod position;
pub mod pruner;
pub mod freezer;
pub mod legacy_event_store;
pub mod silent_store;
pub use cached_trie_store::CachedTrieStore;
pub use flat_trie_store::FlatTrieStore;
pub use epoch_backend::TrieEngine;

use rocksdb::{DB, Options, ColumnFamilyDescriptor, WriteBatch};
use rustock_core::{Block, Header, Receipt, Transaction};
use alloy_primitives::{B256, U256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};
use anyhow::{Result, Context, anyhow, bail};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

/// Parallel point lookups when fetching many headers. Sixteen is what
/// `RocksDbTrieStore` settled on for the same shape of work on this device.
/// How many concurrent point lookups the storage device rewards.
///
/// This is the one number behind every parallel read in the node: headers by
/// hash, trie nodes by hash, and the state verification walk. They all ask the
/// same question -- not "how many cores are there", because these threads
/// spend most of their time waiting on RocksDB, but "how deep a queue does
/// this device answer well".
///
/// That is why 16 is reasonable on a 4-core machine, and why it is wrong to
/// derive it from the core count. It is also why it is worth changing:
///
/// - a spinning disk has one arm, and 16 concurrent random reads is worse
///   than four
/// - network or shared storage is answering for a device that is not this
///   host's
/// - a one-core container gets contention and nothing else
/// - NVMe with deep queues may well reward more than 16
///
/// The default is the value that was hardcoded before this was configurable,
/// so behaviour does not change until an operator changes it. Nobody has
/// measured the curve between 1 and 16; the two ends are known (#198 measured
/// 1,000/s against 7,111/s) and the middle is not.
static READ_THREADS: AtomicUsize = AtomicUsize::new(16);

/// Sets the read concurrency. Call once, at start-up, before any reads.
pub fn set_read_threads(n: usize) {
    READ_THREADS.store(n.max(1), Ordering::Relaxed);
}

/// The configured read concurrency.
pub fn read_threads() -> usize {
    READ_THREADS.load(Ordering::Relaxed)
}

/// Headers frozen in one batch before making them durable.
///
/// Below this the batch is left in the write buffer: see
/// `BlockStore::freeze_headers_below`.
const SYNC_AFTER_HEADERS: u64 = 1_000;

const CF_HEADERS: &str = "headers";
const CF_NUMBERS: &str = "block_numbers";
const CF_TD: &str = "total_difficulty";
const CF_BODIES: &str = "block_bodies";
const CF_RECEIPTS: &str = "receipts";
const CF_TX_INDEX: &str = "tx_index";
/// The trie column family, owned by `trie_store` but named here so the store can
/// tell an emptied trie apart from one that is simply absent.
const CF_TRIE_NODES: &str = "trie_nodes";
/// Bridge events, indexed for scanning by event type.
///
/// Key: `topic0 (32) || block (8 BE) || tx_index (4 BE) || log_index (4 BE)`.
/// Putting the event signature first makes "every occurrence of this event, in
/// block order" a prefix scan, and a block range within it a seek -- which is
/// what answering "when did peg-ins happen" needs. Without it the only way to
/// find one is to walk every receipt in the chain.
const CF_BRIDGE_EVENTS: &str = "bridge_events";
/// Every block hash at a height, canonical or not.
///
/// Key: `number (8 BE) || hash (32)`, value empty. `block_numbers` answers
/// "which block is canonical at height N"; this answers "which blocks exist at
/// height N", which is a different question and the one uncle selection asks --
/// a miner needs the siblings that lost, and those are exactly the ones the
/// canonical pointer does not name.
///
/// Composite key rather than `number -> [hashes]` so that adding a hash is a
/// blind put: no read-modify-write, no lost update when two writers race, and
/// re-indexing the same block is idempotent.
const CF_HEIGHT_INDEX: &str = "block_hashes_by_number";

/// Hash to block number, for headers that live only in the freezer.
///
/// The freezer is addressed by number, so once a header is deleted from
/// `CF_HEADERS` there is no way to answer `header(hash)` without knowing the
/// height first. `CF_HEIGHT_INDEX` maps number to hashes -- the wrong
/// direction -- so this is the index that makes deletion possible at all
/// (#201). 32-byte key, 8-byte value: about 372 MB for 9.26 M blocks, which
/// is the price of reclaiming roughly 10 GB.
const CF_HEADER_NUMBERS: &str = "header_numbers";

/// How far frozen-header deletion has reached.
const KEY_FROZEN_DELETE_CURSOR: &[u8] = b"frozen_delete_cursor";

/// Snapshot chunks already computed, keyed `state_root || cell_index`.
///
/// A cache, not a source of truth: every entry can be recomputed from the
/// trie, and dropping the whole family costs only the recomputation. It earns
/// its place because the snapshot checkpoint moves once every 5000 blocks --
/// about 1.7 days -- so every client syncing in that window asks for the same
/// cells, and computing one costs a trie traversal.
const CF_SNAP_CHUNKS: &str = "snap_chunks";
const KEY_HEAD: &[u8] = b"head";
const KEY_EXEC_HEAD: &[u8] = b"exec_head";

/// Where a background canonical-index pass got to, so an interrupted one
/// resumes instead of starting again.
///
/// Filling the index for a snap-synced node is an hour of disk on a cold
/// store; losing that to a restart would mean it effectively never finishes on
/// a node that restarts daily.
const KEY_INDEX_CURSOR: &[u8] = b"canonical_index_cursor";

/// `number (8 BE) || hash (32)`: sorts by height, then groups every block at
/// that height together, so "all blocks at N" is a prefix scan.
fn height_index_key(number: u64, hash: B256) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key[8..].copy_from_slice(hash.as_slice());
    key
}

/// Safety limit: refuse to reorg deeper than this many blocks.
const MAX_REORG_DEPTH: u64 = 1000;

/// Manages storage of blockchain data using RocksDB.
/// 
/// Data is organized into Column Families:
/// - `headers`: Hash -> RLP(Header)
/// - `block_numbers`: BlockNumber (u64 BE) -> Hash
/// - `total_difficulty`: Hash -> RLP(TotalDifficulty)
/// - `block_bodies`: Hash -> RLP([transactions, ommers])
/// - `default`: Metadata like "head" -> Hash
pub struct BlockStore {
    db: Arc<DB>,
    /// Flat-file storage for canonical headers below the freeze horizon.
    ///
    /// Optional because a node can run perfectly well without it: every header
    /// the freezer holds is also in `CF_HEADERS`, so this only ever changes how
    /// fast a header is found, never whether it is found.
    freezer: std::sync::RwLock<Option<Arc<crate::freezer::Freezer>>>,
}

/// RocksDB settings for a bulk import.
///
/// These are deliberately *not* the settings the node runs with. A node must
/// survive an unclean shutdown; a bulk import does not, because it can simply be
/// run again. That difference is what makes these trades safe here and unsafe in
/// normal operation.
#[derive(Debug, Clone, Copy)]
pub struct ImportTuning {
    /// Size of each memtable. Larger means fewer, bigger flushes and less write
    /// amplification, at the cost of holding more dirty data in RAM.
    pub write_buffer_mb: usize,
    /// Background flush/compaction threads. The import itself is a single
    /// sequential scan, so background work is where spare cores can be used.
    pub parallelism: i32,
    /// Leaving auto-compaction on during a bulk load means repeatedly compacting
    /// data that is still being written. Disabling it defers that to one pass at
    /// the end, which reads and writes each key far fewer times.
    pub auto_compaction: bool,
}

impl Default for ImportTuning {
    fn default() -> Self {
        Self { write_buffer_mb: 256, parallelism: 4, auto_compaction: false }
    }
}

/// RLP-encodes a header exactly as the headers column family stores it.
pub fn encode_header(header: &Header) -> Vec<u8> {
    let mut buf = Vec::new();
    header.encode(&mut buf);
    buf
}

/// RLP-encodes a block body exactly as the bodies column family stores it:
/// `[[transactions], [ommers]]`.
pub fn encode_body(transactions: &[Transaction], ommers: &[Header]) -> Vec<u8> {
    let mut txs_payload = Vec::new();
    for tx in transactions {
        txs_payload.extend_from_slice(&tx.rlp_for_trie());
    }
    let mut ommers_payload = Vec::new();
    for uncle in ommers {
        uncle.encode(&mut ommers_payload);
    }

    let body_len = RlpHeader { list: true, payload_length: txs_payload.len() }.length()
        + txs_payload.len()
        + RlpHeader { list: true, payload_length: ommers_payload.len() }.length()
        + ommers_payload.len();

    let mut buf = Vec::with_capacity(body_len + 5);
    RlpHeader { list: true, payload_length: body_len }.encode(&mut buf);
    RlpHeader { list: true, payload_length: txs_payload.len() }.encode(&mut buf);
    buf.extend_from_slice(&txs_payload);
    RlpHeader { list: true, payload_length: ommers_payload.len() }.encode(&mut buf);
    buf.extend_from_slice(&ommers_payload);
    buf
}

/// The canonical on-disk form of a total difficulty: RLP.
///
/// Exposed as a free function because the import writes this column family
/// through a `WriteBatch` rather than through `put_total_difficulty`, and when
/// the two encodings drifted apart every imported block ended up with a total
/// difficulty the reader could not parse.
pub fn encode_td(td: U256) -> Vec<u8> {
    let mut buf = Vec::new();
    td.encode(&mut buf);
    buf
}

/// Reads a total difficulty, accepting the legacy form as well.
///
/// Databases built by an earlier importer hold raw 32-byte big-endian values
/// here instead of RLP. Rewriting 9.2M of them would be a migration for no
/// benefit, so both are read. They cannot be confused in practice: RLP never
/// begins with a zero byte, and a real total difficulty is nowhere near 2^248,
/// so its raw form always starts with zeros. The length check and the
/// fully-consumed check between them make the choice unambiguous anyway.
pub fn decode_td(bytes: &[u8]) -> Result<U256> {
    let mut slice = bytes;
    if let Ok(v) = U256::decode(&mut slice) {
        if slice.is_empty() {
            return Ok(v);
        }
    }
    if bytes.len() == 32 {
        return Ok(U256::from_be_slice(bytes));
    }
    bail!(
        "total difficulty is neither RLP nor a 32-byte big-endian value ({} bytes)",
        bytes.len()
    )
}

impl BlockStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with(path, None)
    }

    /// Opens the store tuned for bulk import. See [`ImportTuning`].
    pub fn open_for_import<P: AsRef<Path>>(path: P, tuning: ImportTuning) -> Result<Self> {
        Self::open_with(path, Some(tuning))
    }

    /// Opens the store read-only, alongside a live writer.
    ///
    /// RocksDB allows exactly one writer per directory, so a diagnostic that
    /// wants to read a running node's blocks would otherwise have to stop it.
    /// A read-only handle opens against the manifest as it stands and never
    /// takes the lock, at the cost of not seeing anything still in the
    /// writer's memtables -- fine for history, wrong for the tip.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        // See `RocksDbTrieStore::open_read_only` for why this is a bounded
        // block cache rather than a bounded table cache.
        let mut block = rocksdb::BlockBasedOptions::default();
        block.set_block_cache(&rocksdb::Cache::new_lru_cache(64 * 1024 * 1024));
        block.set_cache_index_and_filter_blocks(true);
        opts.set_block_based_table_factory(&block);
        let cfs = vec![
            CF_HEADERS,
            CF_NUMBERS,
            CF_TD,
            CF_BODIES,
            CF_RECEIPTS,
            CF_TX_INDEX,
            CF_BRIDGE_EVENTS,
            CF_SNAP_CHUNKS,
            "trie_nodes",
        ];
        // `false`: do not fail when the writer's WAL files are present.
        //
        // A read-only open must name every column family it wants and fails if
        // one is absent, so a database written before any of these existed
        // would stop opening read-only the moment a build that knows about
        // them shipped. Rather than guess which vintage this is, ask: open
        // exactly the families that are actually there.
        let mut wanted = cfs.clone();
        wanted.push(CF_HEIGHT_INDEX);
        wanted.push(CF_HEADER_NUMBERS);

        let present = DB::list_cf(&opts, path.as_ref()).unwrap_or_default();
        let existing: Vec<&str> = wanted
            .iter()
            .copied()
            .filter(|name| present.iter().any(|p| p == name))
            .collect();

        let db = if existing.is_empty() {
            // Nothing readable, or `list_cf` could not say. Try the full set
            // and let RocksDB report why.
            DB::open_cf_for_read_only(&opts, path.as_ref(), wanted, false)
                .context("Failed to open RocksDB read-only")?
        } else {
            DB::open_cf_for_read_only(&opts, path.as_ref(), existing, false)
                .context("Failed to open RocksDB read-only")?
        };
        Ok(Self { db: Arc::new(db), freezer: std::sync::RwLock::new(None) })
    }

    fn open_with<P: AsRef<Path>>(path: P, tuning: Option<ImportTuning>) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_opts = || {
            let mut o = Options::default();
            if let Some(t) = tuning {
                o.set_write_buffer_size(t.write_buffer_mb * 1024 * 1024);
                // More memtables so writers do not stall waiting for a flush.
                o.set_max_write_buffer_number(4);
                o.set_min_write_buffer_number_to_merge(1);
                o.set_disable_auto_compactions(!t.auto_compaction);
            }
            o
        };

        if let Some(t) = tuning {
            opts.increase_parallelism(t.parallelism);
            opts.set_max_background_jobs(t.parallelism);
        }

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_HEADERS, cf_opts()),
            ColumnFamilyDescriptor::new(CF_NUMBERS, cf_opts()),
            ColumnFamilyDescriptor::new(CF_TD, cf_opts()),
            ColumnFamilyDescriptor::new(CF_BODIES, cf_opts()),
            ColumnFamilyDescriptor::new(CF_RECEIPTS, cf_opts()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, cf_opts()),
            ColumnFamilyDescriptor::new(CF_BRIDGE_EVENTS, cf_opts()),
            ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, cf_opts()),
            ColumnFamilyDescriptor::new(CF_HEADER_NUMBERS, cf_opts()),
            ColumnFamilyDescriptor::new(CF_SNAP_CHUNKS, cf_opts()),
            ColumnFamilyDescriptor::new("trie_nodes", cf_opts()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs).context("Failed to open RocksDB")?;
        Ok(Self { db: Arc::new(db), freezer: std::sync::RwLock::new(None) })
    }

    /// Scans the headers column family for the highest block number.
    ///
    /// Needed when resuming an import whose block phase already finished: the
    /// tip is normally reported by that phase, but on a metadata-only run there
    /// is nothing to report it, and `head` still points wherever the node last
    /// synced to.
    pub fn highest_header(&self) -> Result<Option<B256>> {
        let cf = self.cf(CF_HEADERS)?;
        let mut best: Option<(u64, B256)> = None;
        let mut scanned = 0u64;
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            scanned += 1;
            if k.len() != 32 {
                continue;
            }
            let mut slice: &[u8] = &v;
            if let Ok(h) = Header::decode(&mut slice) {
                if best.is_none_or(|(n, _)| h.number > n) {
                    best = Some((h.number, B256::from_slice(&k)));
                }
            }
            if scanned.is_multiple_of(2_000_000) {
                debug!("highest_header: scanned {scanned}, best #{}", best.map(|b| b.0).unwrap_or(0));
            }
        }
        Ok(best.map(|(_, h)| h))
    }

    /// Compacts every column family. Run this after an import that had
    /// auto-compaction disabled, otherwise the database is left as a deep stack
    /// of un-merged levels and every subsequent read pays for it.
    pub fn compact_all(&self) -> Result<()> {
        for name in [CF_HEADERS, CF_NUMBERS, CF_TD, CF_BODIES, CF_RECEIPTS, CF_TX_INDEX, CF_BRIDGE_EVENTS, "trie_nodes"] {
            if let Some(cf) = self.db.cf_handle(name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }
        Ok(())
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db.cf_handle(name)
            .ok_or_else(|| anyhow!("Column family {} not found", name))
    }

    // --- Header Operations ---

    pub fn put_header(&self, header: &Header) -> Result<()> {
        let hash = header.hash();
        self.put_header_with_hash(hash, header)
    }

    /// Stores a header under an explicit hash key (useful for genesis with non-standard RLP).
    pub fn put_header_with_hash(&self, hash: B256, header: &Header) -> Result<()> {
        let buf = encode_header(header);
        self.db.put_cf(self.cf(CF_HEADERS)?, hash.as_slice(), &buf)
            .context("Failed to write header")?;
        self.index_block_height(header.number, hash)
    }

    /// Record that `hash` exists at `number`, whether or not it is canonical.
    ///
    /// Written wherever a header is, because a block that is an orphan today
    /// may be the uncle a miner includes tomorrow -- and once the header is
    /// stored without an index entry, nothing later goes looking for it.
    pub fn index_block_height(&self, number: u64, hash: B256) -> Result<()> {
        self.db
            .put_cf(self.cf(CF_HEIGHT_INDEX)?, height_index_key(number, hash), [])
            .context("Failed to write height index entry")
    }

    /// Every block hash stored at `number`, canonical or not.
    ///
    /// rskj `BlockStore.getChainBlocksByNumber`. Returns an empty vector on a
    /// database written before this index existed; see `build_height_index`.
    pub fn hashes_at_height(&self, number: u64) -> Result<Vec<B256>> {
        let cf = self.cf(CF_HEIGHT_INDEX)?;
        let prefix = number.to_be_bytes();
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, _) = item.context("Failed to scan height index")?;
            if key.len() != 40 || key[..8] != prefix {
                break;
            }
            out.push(B256::from_slice(&key[8..]));
        }
        Ok(out)
    }

    /// True when the height index holds nothing at all.
    ///
    /// Distinguishes "this database predates the index" from "this height has
    /// no blocks", which otherwise look identical and would have uncle
    /// selection quietly return nothing forever.
    pub fn height_index_is_empty(&self) -> Result<bool> {
        let cf = self.cf(CF_HEIGHT_INDEX)?;
        Ok(self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .next()
            .is_none())
    }

    /// Build the height index from the headers already stored.
    ///
    /// For a database synced before the index existed. Every header is read and
    /// its number decoded, so this is a full scan of the headers column family
    /// -- minutes on a full node, but it reads headers and writes small keys,
    /// and it never touches state. Safe to interrupt and re-run: each entry is
    /// a blind put under a key derived from the header itself, so a partial run
    /// leaves a partial index and a second run completes it.
    ///
    /// `progress` is called every `report_every` headers with the count so far.
    pub fn build_height_index<F: FnMut(u64)>(
        &self,
        report_every: u64,
        mut progress: F,
    ) -> Result<u64> {
        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_index = self.cf(CF_HEIGHT_INDEX)?;

        let mut indexed = 0u64;
        let mut batch = WriteBatch::default();
        let iter = self.db.iterator_cf(cf_headers, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.context("Failed to scan headers")?;
            if key.len() != 32 {
                continue;
            }
            let hash = B256::from_slice(&key);
            // The header is keyed by the hash the node computed for it, which
            // for genesis and for Java-encoded headers is not the hash of a
            // re-encoding. Index under the stored key, never a recomputed one.
            let number = match Header::decode(&mut value.as_ref()) {
                Ok(h) => h.number,
                Err(e) => {
                    warn!(
                        target: "rustock::storage",
                        "Skipping undecodable header {hash:?} while building the height index: {e}"
                    );
                    continue;
                }
            };

            batch.put_cf(cf_index, height_index_key(number, hash), []);
            indexed += 1;

            if indexed.is_multiple_of(10_000) {
                self.db
                    .write(std::mem::take(&mut batch))
                    .context("Failed to write height index batch")?;
            }
            if report_every > 0 && indexed.is_multiple_of(report_every) {
                progress(indexed);
            }
        }

        self.db
            .write(batch)
            .context("Failed to write final height index batch")?;
        Ok(indexed)
    }

    /// Column family handles, for callers that build their own write batches
    /// (the importer does this to batch and to bypass the WAL).
    pub fn cf_headers(&self) -> Result<&rocksdb::ColumnFamily> { self.cf(CF_HEADERS) }
    pub fn cf_bodies(&self) -> Result<&rocksdb::ColumnFamily> { self.cf(CF_BODIES) }
    pub fn cf_numbers(&self) -> Result<&rocksdb::ColumnFamily> { self.cf(CF_NUMBERS) }
    pub fn cf_td(&self) -> Result<&rocksdb::ColumnFamily> { self.cf(CF_TD) }
    pub fn cf_receipts(&self) -> Result<&rocksdb::ColumnFamily> { self.cf(CF_RECEIPTS) }
    pub fn cf_tx_index(&self) -> Result<&rocksdb::ColumnFamily> { self.cf(CF_TX_INDEX) }

    pub fn header(&self, hash: B256) -> Result<Option<Header>> {
        let bytes = self.db.get_cf(self.cf(CF_HEADERS)?, hash.as_slice())
            .context("Failed to read header")?;
        if let Some(b) = bytes {
            return Ok(Some(Header::decode(&mut b.as_slice())?));
        }

        // Not in the database. It may have been frozen and then deleted, in
        // which case the hash-to-number index says where to find it. This
        // costs one extra lookup only when the header is genuinely absent
        // from `CF_HEADERS`, which on a node that never deletes is the
        // not-found path anyway.
        self.frozen_header_by_hash(hash)
    }

    /// A header that lives only in the freezer, found by hash.
    fn frozen_header_by_hash(&self, hash: B256) -> Result<Option<Header>> {
        let Some(f) = self.freezer() else { return Ok(None) };
        let Some(raw) = self
            .db
            .get_cf(self.cf(CF_HEADER_NUMBERS)?, hash.as_slice())
            .context("Failed to read the header number index")?
        else {
            return Ok(None);
        };
        if raw.len() != 8 {
            return Ok(None);
        }
        let number = u64::from_be_bytes(raw[..8].try_into().unwrap());
        Ok(f.header(number).ok().flatten())
    }

    /// Records `hash → number`, so the header can be found once it is only in
    /// the freezer.
    pub fn put_header_number(&self, hash: B256, number: u64) -> Result<()> {
        self.db
            .put_cf(self.cf(CF_HEADER_NUMBERS)?, hash.as_slice(), number.to_be_bytes())
            .context("Failed to write the header number index")
    }

    /// Headers for many hashes at once, positionally.
    ///
    /// # Why a thread pool rather than `multi_get_cf`
    ///
    /// Measured on this database and recorded in `RocksDbTrieStore::get_many`:
    /// **`multi_get_cf` does not overlap I/O**. It reuses one pinned
    /// superversion, but the lookups still run one after another inside
    /// RocksDB — 517 nodes/s against 2,658 for plain `get`. The batching that
    /// helps is concurrency, not the batch API.
    ///
    /// Header hashes have no locality either — they are uniformly distributed,
    /// so consecutive blocks share neither a data block nor usually a file —
    /// which rules out the ordered-cursor trick that works for sorted keys.
    /// What is left is ordinary point lookups issued in parallel, so the device
    /// sees a queue depth equal to the pool size instead of one.
    pub fn headers_by_hash(&self, hashes: &[B256]) -> Vec<Option<Header>> {
        let one = |h: &B256| -> Option<Header> {
            let cf = self.cf(CF_HEADERS).ok()?;
            let bytes = self.db.get_cf(cf, h.as_slice()).ok()??;
            Header::decode(&mut bytes.as_slice()).ok()
        };

        let threads = read_threads();
        if hashes.len() < threads * 2 {
            return hashes.iter().map(one).collect();
        }
        let mut out: Vec<Option<Header>> = vec![None; hashes.len()];
        let chunk = hashes.len().div_ceil(threads);
        std::thread::scope(|scope| {
            for (keys, slots) in hashes.chunks(chunk).zip(out.chunks_mut(chunk)) {
                scope.spawn(|| {
                    for (h, slot) in keys.iter().zip(slots.iter_mut()) {
                        *slot = one(h);
                    }
                });
            }
        });
        out
    }

    /// Canonical hashes for a **descending** run of heights, positionally.
    ///
    /// Unlike headers these keys *are* local: `CF_NUMBERS` is keyed by the
    /// big-endian height, so a run of consecutive numbers is a run of adjacent
    /// keys sharing data blocks. One forward cursor answers the whole range,
    /// which is why this needs no pool.
    pub fn canonical_hashes_descending(&self, top: u64, count: usize) -> Vec<Option<B256>> {
        let mut out = vec![None; count];
        let Ok(cf) = self.cf(CF_NUMBERS) else { return out };
        let lowest = top.saturating_sub(count as u64 - 1);

        // Ascending from the bottom of the range, because an iterator reads
        // forward; results are placed back in descending order.
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&lowest.to_be_bytes(), rocksdb::Direction::Forward),
        );
        for item in iter {
            let Ok((k, v)) = item else { break };
            if k.len() != 8 || v.len() != 32 {
                continue;
            }
            let number = u64::from_be_bytes(k[..8].try_into().unwrap_or([0; 8]));
            if number > top {
                break;
            }
            let idx = (top - number) as usize;
            if idx < count {
                out[idx] = Some(B256::from_slice(&v));
            }
        }
        out
    }

    // --- Canonical Chain Operations ---

    pub fn put_canonical_hash(&self, number: u64, hash: B256) -> Result<()> {
        self.db.put_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes(), hash.as_slice())
            .context("Failed to map number to hash")
    }

    /// The canonical hash at a height.
    ///
    /// `CF_NUMBERS` is the authority, but it is not the only answer. The
    /// freezer holds canonical headers addressed by block number, and a
    /// header's hash is a property of the header -- so for any frozen height
    /// the mapping is already on disk, in a file, reachable by arithmetic.
    ///
    /// That matters because building `CF_NUMBERS` for the whole chain after a
    /// snapshot sync took hours and left the node unable to follow the chain
    /// while it ran (#195). Asking the freezer first means the heights it
    /// covers need no entry at all.
    pub fn canonical_hash(&self, number: u64) -> Result<Option<B256>> {
        let bytes = self.db.get_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes())
            .context("Failed to read canonical hash")?;
        if let Some(b) = bytes {
            return Ok(Some(B256::from_slice(&b)));
        }

        // Only a frozen header can answer, and only because being in the
        // freezer is itself the statement that this height is canonical:
        // nothing else is ever written there.
        if let Some(f) = self.freezer() {
            if let Ok(Some(header)) = f.header(number) {
                return Ok(Some(header.hash()));
            }
        }
        Ok(None)
    }

    /// Removes the canonical `number → hash` mapping for a block height.
    pub fn delete_canonical_hash(&self, number: u64) -> Result<()> {
        self.db.delete_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes())
            .context("Failed to delete canonical hash")
    }

    // --- Total Difficulty Operations ---

    /// Writes the total difficulty bytes exactly as given, without encoding.
    ///
    /// For tests and migration tooling that need to reproduce a historical
    /// on-disk form -- notably the raw 32-byte big-endian values an earlier
    /// importer wrote. Normal writes go through `put_total_difficulty`.
    #[doc(hidden)]
    pub fn put_total_difficulty_raw(&self, hash: B256, bytes: &[u8]) -> Result<()> {
        self.db.put_cf(self.cf(CF_TD)?, hash.as_slice(), bytes)
            .context("Failed to write raw total difficulty")
    }

    pub fn put_total_difficulty(&self, hash: B256, td: U256) -> Result<()> {
        self.db.put_cf(self.cf(CF_TD)?, hash.as_slice(), encode_td(td))
            .context("Failed to write total difficulty")
    }

    /// True when the in-database trie column family holds no entries.
    ///
    /// Distinguishes a database whose trie was moved out (and whose column
    /// family RocksDB then silently recreated, empty, on the next open) from one
    /// that still holds its trie. Cheap: it reads one key, not a count.
    pub fn trie_cf_is_empty(&self) -> bool {
        let Some(cf) = self.db.cf_handle(CF_TRIE_NODES) else {
            return true;
        };
        let mut it = self.db.raw_iterator_cf(cf);
        it.seek_to_first();
        !it.valid()
    }

    pub fn total_difficulty(&self, hash: B256) -> Result<Option<U256>> {
        let bytes = self.db.get_cf(self.cf(CF_TD)?, hash.as_slice())
            .context("Failed to read total difficulty")?;
        bytes.map(|b| decode_td(&b)).transpose()
    }

    /// Checks if a block header exists in the store by hash.
    pub fn has_block(&self, hash: B256) -> Result<bool> {
        Ok(self.db.get_cf(self.cf(CF_HEADERS)?, hash.as_slice())
            .context("Failed to check header existence")?
            .is_some())
    }

    // --- Head Operations ---

    pub fn set_head(&self, hash: B256) -> Result<()> {
        self.db.put(KEY_HEAD, hash.as_slice())
            .context("Failed to set head")
    }

    pub fn head(&self) -> Result<Option<B256>> {
        let bytes = self.db.get(KEY_HEAD)
            .context("Failed to read head")?;

        Ok(bytes.map(|b| B256::from_slice(&b)))
    }

    /// Records the last EXECUTED block (hash) and its post-execution Unitrie
    /// state root. Distinct from `head`, which tracks the best downloaded
    /// block; the executed head is where block execution must resume.
    pub fn set_exec_head(&self, hash: B256, state_root: B256) -> Result<()> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(hash.as_slice());
        buf.extend_from_slice(state_root.as_slice());
        self.db.put(KEY_EXEC_HEAD, &buf)
            .context("Failed to set exec head")
    }

    /// Clears the executed-head marker so the node replays execution from
    /// genesis on next start, reusing already-downloaded headers and bodies
    /// instead of re-fetching them from peers.
    pub fn clear_exec_head(&self) -> Result<()> {
        self.db.delete(KEY_EXEC_HEAD)
            .context("Failed to clear exec head")
    }

    /// Returns the last executed block hash and its Unitrie state root.
    pub fn exec_head(&self) -> Result<Option<(B256, B256)>> {
        let bytes = self.db.get(KEY_EXEC_HEAD)
            .context("Failed to read exec head")?;
        Ok(bytes.filter(|b| b.len() == 64).map(|b| {
            (B256::from_slice(&b[..32]), B256::from_slice(&b[32..]))
        }))
    }

    // --- Batch / High Level Operations ---

    /// Updates the chain head and canonical mapping for a new best block.
    pub fn update_head(&self, header: &Header, td: U256) -> Result<()> {
        let hash = header.hash();

        self.put_header(header)?;
        self.put_total_difficulty(hash, td)?;
        self.put_canonical_hash(header.number, hash)?;
        self.set_head(hash)?;

        Ok(())
    }

    /// Atomically stores a batch of validated headers along with their total
    /// difficulties, then updates the canonical chain if the head changed.
    ///
    /// Headers and TDs are always stored (keyed by hash, safe for forks).
    /// Canonical `number → hash` mappings are only updated for blocks on the
    /// winning chain, preventing fork headers from corrupting the canonical
    /// pointers.
    ///
    /// Returns the hash of the new head (if it changed) or the existing head.
    pub fn store_headers_batch(
        &self,
        entries: &[(&Header, U256)],
        current_head_hash: Option<B256>,
        current_td: U256,
    ) -> Result<Option<B256>> {

        if entries.is_empty() {
            return Ok(current_head_hash);
        }

        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_td = self.cf(CF_TD)?;
        let cf_index = self.cf(CF_HEIGHT_INDEX)?;

        let mut batch = WriteBatch::default();
        let mut best_hash = current_head_hash;
        let mut best_td = current_td;

        for &(header, td) in entries {
            let hash = header.hash();

            let mut header_buf = Vec::new();
            header.encode(&mut header_buf);
            batch.put_cf(cf_headers, hash.as_slice(), &header_buf);

            batch.put_cf(cf_td, hash.as_slice(), encode_td(td));
            // Fork headers arrive through here too, and they are precisely the
            // ones uncle selection is looking for.
            batch.put_cf(cf_index, height_index_key(header.number, hash), []);

            if td > best_td {
                best_td = td;
                best_hash = Some(hash);
            }
        }

        // Commit headers + TDs first so update_canonical_chain can read them.
        self.db.write(batch).context("Failed to write header batch")?;

        // Update canonical chain only if the head actually changed.
        if best_hash != current_head_hash {
            if let Some(new_head) = best_hash {
                self.move_head_to(new_head, current_head_hash)?;
            }
        }

        Ok(best_hash)
    }

    /// Move the head to `new_head` through [`Transition`], so the canonical
    /// lineage, the entries the old chain stranded above the new tip, and the
    /// executed cursor all move in one batch.
    ///
    /// This path used to call `update_canonical_chain`, which writes the
    /// lineage and the head and nothing else. That is fine while the head
    /// climbs and wrong the moment it does not: a reorg onto a heavier but
    /// *shorter* chain left the executed head standing above the validated
    /// one -- coherence violation I4 -- and the node then made no progress
    /// until the chain grew back past the reorg point. On mainnet that was
    /// about 54 times a day, one to six minutes each (issue #307).
    ///
    /// `Transition` has pulled execution down since it was written; the
    /// batch-sync paths have always gone through it. This one, which moves
    /// the head far more often than they do, did not.
    fn move_head_to(&self, new_head: B256, previous: Option<B256>) -> Result<()> {
        let proved = match Validated::prove(self, new_head) {
            Ok(proved) => proved,
            Err(unprovable) => {
                // A header on the way down is missing. That is ordinary
                // during skeleton sync, where headers arrive out of order and
                // the old walk simply stopped at the hole, so this keeps
                // doing that rather than refusing a batch the node has always
                // accepted.
                //
                // It cannot hide the bug above: an unprovable lineage means
                // the head is moving into a part of the chain that is still
                // being downloaded, where execution is far below and there is
                // nothing to pull down.
                debug!(
                    target: "rustock::storage",
                    "head {new_head} has no provable lineage ({unprovable});                      writing the canonical pointers without a transition"
                );
                return self.update_canonical_chain(new_head);
            }
        };

        // Identical work either way -- the distinction is what the logs say
        // happened, and a retreat is worth being able to see.
        let descending = previous
            .and_then(|h| self.header(h).ok().flatten())
            .is_some_and(|h| proved.number() < h.number);
        let transition = if descending {
            Transition::Retreat { to: proved }
        } else {
            Transition::Adopt { head: proved }
        };

        self.apply(&transition)?;
        Ok(())
    }

    /// Walks backward from `new_head` using `parent_hash` links, updating
    /// canonical `number → hash` mappings until the chain below is already
    /// consistent (the fork point).  Also sets `KEY_HEAD`.
    ///
    /// Handles both direct extensions (walk stops after 1 step) and reorgs
    /// (walk continues through the fork chain to the common ancestor).
    ///
    /// Stopping at the first already-canonical block is *not* sufficient: a
    /// prior walk truncated by a not-yet-downloaded parent header can leave a
    /// lower block stale while this one is canonical (skeleton sync delivers
    /// headers out of order). The canonical pointer at #N-1 would then keep
    /// naming an orphan even though #N points at the new fork — an internally
    /// inconsistent chain that wedges execution. So only stop once the
    /// canonical block at the parent's height actually *is* this block's
    /// parent; otherwise keep walking to repair the hole.
    pub fn update_canonical_chain(&self, new_head: B256) -> Result<()> {
        let depth = self.ensure_canonical_lineage(new_head)?;
        self.set_head(new_head)?;

        if depth > 1 {
            debug!(
                target: "rustock::storage",
                "Updated canonical chain ({} blocks rewritten)",
                depth
            );
        }

        Ok(())
    }

    /// Repair canonical `number → hash` pointers by walking back from `hash`
    /// (via `parent_hash`) until the chain below is already consistent, WITHOUT
    /// touching the head. Returns the number of pointers rewritten.
    ///
    /// Used both by `update_canonical_chain` (for a new head) and to repair a
    /// buried hole left by an earlier walk that truncated at a then-missing
    /// parent header — a tip-extension's walk stops at the top and never
    /// revisits such a hole, so it must be repaired explicitly at the block
    /// that exposes it.
    /// Write the canonical lineage of `hash` **without touching the head**.
    ///
    /// Crate-private on purpose. Writing `CF_NUMBERS` and leaving `KEY_HEAD`
    /// behind is the shape of every sync stall this node has had -- most
    /// directly stall 6, where mainnet #9,262,402 was held, linked, valid and
    /// unreachable for three hours because every path that looks for work
    /// reads the head.
    ///
    /// Callers outside this crate use [`Transition::Adopt`], which writes the
    /// lineage and the head in one batch and cannot express the other thing.
    pub(crate) fn ensure_canonical_lineage(&self, hash: B256) -> Result<u64> {
        // The whole walk commits as one batch. Writing pointer by pointer is
        // not crash-safe: the walk moves from the tip down to the fork point,
        // so an interruption part-way leaves the upper heights naming the new
        // fork and the lower ones still naming the old, with no record that a
        // rewrite was in progress. Nothing detects that on restart, and the
        // node wedges -- execution follows the canonical pointers into a block
        // whose parent is a block it never executed. A batch makes the rewrite
        // all-or-nothing, so an interrupted reorg simply did not happen.
        let mut batch = WriteBatch::default();
        let cf = self.cf(CF_NUMBERS)?;

        let mut hash = hash;
        let mut depth: u64 = 0;

        loop {
            let header = match self.header(hash)? {
                Some(h) => h,
                None => break, // parent not in store (e.g. pruned or pre-genesis)
            };

            let already_canonical = self.canonical_hash(header.number)? == Some(hash);
            if !already_canonical {
                batch.put_cf(cf, header.number.to_be_bytes(), hash.as_slice());
            }

            if header.number == 0 {
                break;
            }

            // Stop only when the chain below is already consistent: this block
            // is canonical AND #N-1's canonical hash is this block's parent.
            if already_canonical
                && self.canonical_hash(header.number - 1)? == Some(header.parent_hash)
            {
                break;
            }

            depth += 1;
            if depth >= MAX_REORG_DEPTH {
                warn!(
                    target: "rustock::storage",
                    "Canonical chain update reached MAX_REORG_DEPTH ({}) at block #{}",
                    MAX_REORG_DEPTH, header.number
                );
                break;
            }

            hash = header.parent_hash;
        }

        if !batch.is_empty() {
            self.db
                .write(batch)
                .context("Failed to commit canonical lineage")?;
        }

        Ok(depth)
    }

    /// Rewrites the canonical `number -> hash` pointers for `depth` blocks below
    /// `hash` *unconditionally*, without the "chain below is already
    /// consistent" early stop.
    ///
    /// `ensure_canonical_lineage` stops as soon as a block is canonical and its
    /// parent height agrees, which is the right thing during normal operation
    /// and the wrong thing when repairing: a damaged index can be
    /// self-consistent at the top and broken further down, and the early stop
    /// means the walk never looks there. This one keeps going, so it fixes both
    /// stale pointers and outright missing heights.
    ///
    /// Commits as a single batch, like the walk it repairs.
    pub fn repair_canonical_lineage(&self, hash: B256, depth: u64) -> Result<CanonicalRepair> {
        let mut batch = WriteBatch::default();
        let cf = self.cf(CF_NUMBERS)?;
        let mut report = CanonicalRepair::default();

        let mut hash = hash;
        for _ in 0..depth {
            let header = match self.header(hash)? {
                Some(h) => h,
                None => {
                    report.stopped_at_missing_header = Some(hash);
                    break;
                }
            };

            match self.canonical_hash(header.number)? {
                Some(h) if h == hash => {}
                Some(_) => {
                    report.corrected += 1;
                    batch.put_cf(cf, header.number.to_be_bytes(), hash.as_slice());
                }
                None => {
                    report.filled += 1;
                    batch.put_cf(cf, header.number.to_be_bytes(), hash.as_slice());
                }
            }

            report.walked += 1;
            report.lowest = Some(header.number);
            if header.number == 0 {
                break;
            }
            hash = header.parent_hash;
        }

        if !batch.is_empty() {
            self.db
                .write(batch)
                .context("Failed to commit canonical repair")?;
        }

        Ok(report)
    }
}

/// `state_root || grid || format || cell_index`, big-endian so a state's
/// cells sort together and can be dropped as one range.
///
/// The grid and the format are in the key because they are part of what a
/// cell *is*. A server whose grid changed, or which serves two dialects,
/// would otherwise hand back bytes for a range nobody asked about.
fn snap_chunk_key(state_root: B256, grid: u64, format: u8, index: u64) -> [u8; 49] {
    let mut key = [0u8; 49];
    key[..32].copy_from_slice(state_root.as_slice());
    key[32..40].copy_from_slice(&grid.to_be_bytes());
    key[40] = format;
    key[41..].copy_from_slice(&index.to_be_bytes());
    key
}

/// What a `repair_canonical_lineage` pass changed.
#[derive(Debug, Default, Clone)]
pub struct CanonicalRepair {
    /// Heights visited.
    pub walked: u64,
    /// Heights that named a block from another fork.
    pub corrected: u64,
    /// Heights that had no canonical pointer at all.
    pub filled: u64,
    /// Lowest height reached.
    pub lowest: Option<u64>,
    /// Set when the walk ran out of stored headers before `depth`.
    pub stopped_at_missing_header: Option<B256>,
}

impl BlockStore {
    /// Stores a block body (transactions + ommers) keyed by block hash.
    /// Uses the original peer-received RLP when available to preserve Java's
    /// non-canonical encoding (leading zeros in BigIntegers).
    pub fn put_body(
        &self,
        hash: B256,
        transactions: &[Transaction],
        ommers: &[Header],
    ) -> Result<()> {
        let buf = encode_body(transactions, ommers);
        self.db
            .put_cf(self.cf(CF_BODIES)?, hash.as_slice(), &buf)
            .context("Failed to write block body")
    }

    /// Attaches a freezer, so header runs can be served from flat files.
    pub fn set_freezer(&self, freezer: Arc<crate::freezer::Freezer>) {
        *self.freezer.write().unwrap() = Some(freezer);
    }

    pub fn freezer(&self) -> Option<Arc<crate::freezer::Freezer>> {
        self.freezer.read().unwrap().clone()
    }

    /// Canonical headers for a **descending** run of heights, positionally.
    ///
    /// This is the shape a peer actually asks for -- "the 192 headers below
    /// N" -- and the reason the freezer exists. Below the freeze horizon it is
    /// one index read and one contiguous data read. Above it, or without a
    /// freezer, it falls back to resolving each height to a hash and fetching
    /// the headers by hash, which is where the 6.5x read amplification lives.
    ///
    /// Returns headers newest first, matching `canonical_hashes_descending`.
    pub fn canonical_headers_descending(
        &self,
        top: u64,
        count: usize,
    ) -> Vec<Option<Header>> {
        if count == 0 {
            return Vec::new();
        }
        let lowest = top.saturating_sub(count as u64 - 1);

        // The whole run has to be frozen for the fast path to answer it; a
        // partly-frozen run would need both sources stitched together, and the
        // boundary moves, so the stitch would be the only untested case.
        if let Some(f) = self.freezer() {
            if top < f.end_number() && f.contains(lowest) && f.contains(top) {
                if let Ok(run) = f.run(lowest, count) {
                    if run.iter().all(|h| h.is_some()) {
                        let mut out = run;
                        out.reverse();
                        return out;
                    }
                }
            }
        }

        let hashes = self.canonical_hashes_descending(top, count);
        let resolved: Vec<Option<B256>> = hashes;
        let present: Vec<B256> = resolved.iter().flatten().copied().collect();
        if present.len() != count {
            return vec![None; count];
        }
        self.headers_by_hash(&present)
    }

    /// Moves canonical headers below `horizon` into the freezer.
    ///
    /// Ascending and contiguous from wherever the freezer left off, which is
    /// the order that makes a later run one read. Stops at the first height it
    /// cannot resolve rather than leaving a hole: a hole would be invisible
    /// until a peer asked for a run spanning it.
    ///
    /// Returns how many headers were frozen. Cheap to call repeatedly -- when
    /// there is nothing to do it resolves one height and stops.
    pub fn freeze_headers_below(&self, horizon: u64, max_batch: u64) -> Result<u64> {
        let Some(f) = self.freezer() else { return Ok(0) };
        let start = f.end_number();
        if start >= horizon {
            return Ok(0);
        }
        let want = max_batch.min(horizon - start) as usize;

        // Resolving the heights is cheap: `CF_NUMBERS` is keyed by big-endian
        // height, so a run of consecutive numbers is a run of adjacent keys.
        let mut hashes = Vec::with_capacity(want);
        for n in start..start + want as u64 {
            match self.canonical_hash(n)? {
                Some(h) => hashes.push(h),
                // Stop at the first height that will not resolve rather than
                // leaving a hole, which would be invisible until a peer asked
                // for a run spanning it.
                None => break,
            }
        }
        if hashes.is_empty() {
            return Ok(0);
        }

        // Fetching the headers is the expensive half: hashes are uniformly
        // distributed, so these are unrelated point lookups with the 6.5x
        // amplification the freezer exists to remove. Issued through the
        // thread pool they at least overlap, which is the whole reason
        // `headers_by_hash` exists -- a serial loop here spent hours on what
        // the device can do in minutes.
        let fetched = self.headers_by_hash(&hashes);

        let mut done = 0u64;
        let mut lost_uncles = 0u64;
        for (i, slot) in fetched.into_iter().enumerate() {
            let Some(header) = slot else { break };
            let number = start + i as u64;

            // The uncles go in with the header. They exist only in the body,
            // so this is the last moment they can be captured -- once the
            // pruner reaches the block they are gone for good. `plan_prune`
            // will not let it get ahead of this, but a body already missing
            // from an older database is still possible, so say so rather than
            // freezing a header whose uncles are silently absent.
            match self.body(hashes[i])? {
                Some((_txs, ommers)) => f.put_uncles(number, &ommers)?,
                None if header.uncle_count == 0 => f.put_uncles(number, &[])?,
                None => lost_uncles += 1,
            }

            f.put(number, &header)?;
            done += 1;
        }
        // Syncing a batch of one -- which is what steady state is, once the
        // horizon is only moving as fast as the chain -- would be an fsync per
        // block for a single 1.1 KB header, and would defeat the write buffer
        // entirely. Bulk batches are worth making durable as they go; the tail
        // is left to the buffer and to whoever calls `sync` when it runs out
        // of work. Losing it costs nothing: unsynced headers were never
        // published, and the next fill writes them again.
        if lost_uncles > 0 {
            warn!(
                "froze {lost_uncles} header(s) whose body was already gone, so their uncle \
                 headers could not be captured; those blocks' contribution to total \
                 difficulty is no longer derivable"
            );
        }
        if done >= SYNC_AFTER_HEADERS {
            f.sync()?;
        }
        Ok(done)
    }

    /// Deletes headers from the database that the freezer already holds.
    ///
    /// The ordering is geth's, and it is not negotiable: a header is read
    /// back **out of the freezer** before the database copy is removed. The
    /// failure mode of deleting first is a hole in the chain; the failure
    /// mode of deleting late is duplicated data, which is recoverable and
    /// detectable. So every deletion is preceded by proof that the survivor
    /// can answer.
    ///
    /// `hash → number` is written before the delete too, since without it a
    /// frozen header cannot be found by hash at all.
    ///
    /// Returns how many headers were removed. Off unless the operator asks
    /// for it: see `--prune-frozen-headers`.
    pub fn delete_frozen_headers(&self, up_to: u64, max_batch: u64) -> Result<u64> {
        let Some(f) = self.freezer() else { return Ok(0) };

        let start = self.frozen_delete_cursor()?;
        let end = up_to.min(f.end_number());
        let mut deleted = 0u64;
        let mut n = start;

        while n < end && deleted < max_batch {
            let Some(header) = f.header(n).ok().flatten() else {
                // The freezer cannot answer for this height, so nothing may
                // be deleted at it. Stop rather than skip: a gap here means
                // the freezer is not what it is assumed to be.
                break;
            };
            let hash = header.hash();

            // The index first, so a crash between these two leaves a
            // findable header rather than a lost one.
            self.put_header_number(hash, n)?;

            // And only now, with the freezer proven able to answer and the
            // hash mapped, is the database copy redundant.
            self.db
                .delete_cf(self.cf(CF_HEADERS)?, hash.as_slice())
                .context("Failed to delete a frozen header")?;

            n += 1;
            deleted += 1;
        }

        if deleted > 0 {
            self.set_frozen_delete_cursor(n)?;
        }
        Ok(deleted)
    }

    /// How far frozen-header deletion has reached.
    pub fn frozen_delete_cursor(&self) -> Result<u64> {
        let raw = self
            .db
            .get(KEY_FROZEN_DELETE_CURSOR)
            .context("Failed to read the frozen delete cursor")?;
        Ok(raw
            .filter(|r| r.len() == 8)
            .map(|r| u64::from_be_bytes(r[..8].try_into().unwrap()))
            .unwrap_or(0))
    }

    fn set_frozen_delete_cursor(&self, number: u64) -> Result<()> {
        self.db
            .put(KEY_FROZEN_DELETE_CURSOR, number.to_be_bytes())
            .context("Failed to write the frozen delete cursor")
    }

    /// Reads a block body (transactions + ommers) by hash.
    pub fn body(&self, hash: B256) -> Result<Option<(Vec<Transaction>, Vec<Header>)>> {
        let bytes = self.db
            .get_cf(self.cf(CF_BODIES)?, hash.as_slice())
            .context("Failed to read block body")?;
        match bytes {
            None => Ok(None),
            Some(b) => {
                let mut buf = b.as_slice();
                let outer = RlpHeader::decode(&mut buf)?;
                let mut body = &buf[..outer.payload_length];

                let txs_h = RlpHeader::decode(&mut body)?;
                let mut txs_buf = &body[..txs_h.payload_length];
                body = &body[txs_h.payload_length..];
                let mut transactions = Vec::new();
                while !txs_buf.is_empty() {
                    transactions.push(Transaction::decode(&mut txs_buf)?);
                }

                let ommers_h = RlpHeader::decode(&mut body)?;
                let mut ommers_buf = &body[..ommers_h.payload_length];
                let mut ommers = Vec::new();
                while !ommers_buf.is_empty() {
                    ommers.push(Header::decode(&mut ommers_buf)?);
                }

                Ok(Some((transactions, ommers)))
            }
        }
    }


    /// Returns a full block (header + body) by hash.
    /// If only the header is stored (no body), returns a header-only block
    /// with empty transactions and ommers.
    pub fn block(&self, hash: B256) -> Result<Option<Block>> {
        let header = match self.header(hash)? {
            Some(h) => h,
            None => return Ok(None),
        };

        let (transactions, ommers) = self.body(hash)?
            .unwrap_or_default();

        Ok(Some(Block { header, transactions, ommers }))
    }
}

impl BlockStore {
    /// Stores receipts for a block, keyed by block hash.
    pub fn put_receipts(&self, hash: B256, receipts: &[Receipt]) -> Result<()> {
        let mut payload = Vec::new();
        for r in receipts {
            r.encode(&mut payload);
        }
        let mut buf = Vec::with_capacity(payload.len() + 5);
        RlpHeader { list: true, payload_length: payload.len() }.encode(&mut buf);
        buf.extend_from_slice(&payload);

        self.db
            .put_cf(self.cf(CF_RECEIPTS)?, hash.as_slice(), &buf)
            .context("Failed to write receipts")
    }

    /// Reads receipts for a block by hash.
    pub fn receipts(&self, hash: B256) -> Result<Option<Vec<Receipt>>> {
        let bytes = self.db
            .get_cf(self.cf(CF_RECEIPTS)?, hash.as_slice())
            .context("Failed to read receipts")?;
        match bytes {
            None => Ok(None),
            Some(b) => {
                let mut buf = b.as_slice();
                let header = RlpHeader::decode(&mut buf)?;
                let mut data = &buf[..header.payload_length];
                let mut receipts = Vec::new();
                while !data.is_empty() {
                    receipts.push(Receipt::decode(&mut data)?);
                }
                Ok(Some(receipts))
            }
        }
    }
}

impl BlockStore {
    /// Stores a transaction index entry: tx_hash -> (block_hash, tx_index).
    pub fn put_tx_index(&self, tx_hash: B256, block_hash: B256, tx_index: u32) -> Result<()> {
        let mut val = [0u8; 36];
        val[..32].copy_from_slice(block_hash.as_slice());
        val[32..].copy_from_slice(&tx_index.to_be_bytes());
        self.db
            .put_cf(self.cf(CF_TX_INDEX)?, tx_hash.as_slice(), val)
            .context("Failed to write tx index")
    }

    /// Looks up which block contains a transaction and at what index.
    pub fn tx_location(&self, tx_hash: B256) -> Result<Option<(B256, u32)>> {
        let bytes = self.db
            .get_cf(self.cf(CF_TX_INDEX)?, tx_hash.as_slice())
            .context("Failed to read tx index")?;
        match bytes {
            None => Ok(None),
            Some(b) => {
                if b.len() < 36 {
                    return Err(anyhow!("corrupt tx index entry: {} bytes", b.len()));
                }
                let block_hash = B256::from_slice(&b[..32]);
                let tx_index = u32::from_be_bytes([b[32], b[33], b[34], b[35]]);
                Ok(Some((block_hash, tx_index)))
            }
        }
    }

    /// Indexes all transactions in a block body for fast lookup by tx hash.
    /// Computes each transaction's hash from its RLP encoding.
    pub fn index_block_transactions(&self, block_hash: B256, transactions: &[Transaction]) -> Result<()> {
        for (i, tx) in transactions.iter().enumerate() {
            // `tx.tx_hash()` hashes `rlp_for_trie()`, which returns the ORIGINAL
            // bytes when they were cached at decode time. Re-encoding here
            // instead would key the index by a hash that differs from the
            // canonical one for any transaction whose RLP does not round-trip
            // byte-for-byte -- and reproducing rskj's non-canonical encodings is
            // exactly why `cached_rlp` exists. The index must be keyed by the
            // hash callers actually have.
            self.put_tx_index(tx.tx_hash(), block_hash, i as u32)?;
        }
        Ok(())
    }

    /// Rebuild the transaction index for canonical blocks in `[from, to]`.
    ///
    /// Reads each canonical block's body and writes one `tx_index` entry per
    /// transaction. It touches no trie and executes nothing: the index is
    /// derived entirely from block bodies, which is why this can repair history
    /// a node imported rather than executed.
    ///
    /// `progress` is called every `report_every` blocks with
    /// `(block, blocks_done, txs_indexed)` so a caller can log a rate and an
    /// ETA. Blocks with no canonical hash or no stored body are skipped and
    /// counted rather than failing the run -- a gap in an imported database
    /// should not abort a repair that can still fix everything around it.
    ///
    /// Returns `(blocks_indexed, txs_indexed, blocks_skipped)`.
    ///
    /// RocksDB allows a single writer, so the node must not be running.
    pub fn repair_tx_index<F>(
        &self,
        from: u64,
        to: u64,
        report_every: u64,
        mut progress: F,
    ) -> Result<(u64, u64, u64)>
    where
        F: FnMut(u64, u64, u64),
    {
        let (mut blocks, mut txs, mut skipped) = (0u64, 0u64, 0u64);
        for number in from..=to {
            let Some(hash) = self.canonical_hash(number)? else {
                skipped += 1;
                continue;
            };
            match self.body(hash)? {
                Some((transactions, _ommers)) => {
                    txs += transactions.len() as u64;
                    self.index_block_transactions(hash, &transactions)?;
                    blocks += 1;
                }
                None => skipped += 1,
            }
            if report_every > 0 && number % report_every == 0 {
                progress(number, blocks, txs);
            }
        }
        Ok((blocks, txs, skipped))
    }

    /// A block's own contribution to total difficulty: its header difficulty
    /// plus every uncle's, matching rskj `Block.getCumulativeDifficulty()`.
    ///
    /// This needs the body. The header commits to the uncle list through
    /// `ommers_hash` and records only `uncle_count`, so the uncle difficulties
    /// exist nowhere else -- not in the freezer, which is canonical headers by
    /// height, and an uncle is by definition not canonical. A block whose body
    /// has been pruned therefore has no recoverable contribution, and this
    /// returns `None` rather than the header difficulty alone: a silent
    /// undercount is what put the chain's stored total difficulty wrong in the
    /// first place.
    pub fn cumulative_difficulty(&self, hash: B256, header: &Header) -> Result<Option<U256>> {
        if header.uncle_count == 0 {
            return Ok(Some(header.difficulty));
        }
        let ommers = match self.body(hash)? {
            Some((_txs, ommers)) => ommers,
            None => {
                // The body is pruned. The freezer's uncle store is the only
                // other place these headers exist, and the whole reason it
                // exists: without it this block's contribution is lost for
                // good and no later pass can recover it.
                match self.freezer().map(|f| f.uncles(header.number)).transpose()?.flatten() {
                    Some(ommers) => ommers,
                    None => return Ok(None),
                }
            }
        };
        let mut total = header.difficulty;
        for uncle in &ommers {
            total = total.saturating_add(uncle.difficulty);
        }
        Ok(Some(total))
    }

    /// Rewrite total difficulty across the canonical chain using the rule
    /// rskj applies: `td(n) = td(n-1) + difficulty(n) + sum(uncle difficulties)`.
    ///
    /// Walks upward so each block reads a parent total that this pass has
    /// already corrected. `from` is seeded from the stored total of `from - 1`,
    /// which must itself already be correct -- so a partial repair has to
    /// resume where the last one stopped, and a repair of the whole chain
    /// starts at genesis.
    ///
    /// Returns `(written, unchanged, absent)`, where `absent` counts heights
    /// with no canonical block -- a snap-synced node holds nothing below its
    /// checkpoint, and reporting that as success would hide the fact that
    /// nothing was corrected.
    pub fn recompute_total_difficulty<F>(
        &self,
        from: u64,
        to: u64,
        report_every: u64,
        progress: F,
    ) -> Result<(u64, u64, u64)>
    where
        F: FnMut(u64, u64, U256),
    {
        let (written, unchanged, absent, _) =
            self.walk_chain_work(from, to, report_every, false, progress)?;
        Ok((written, unchanged, absent))
    }

    /// One pass that rebuilds both halves of the chain's work: the uncle
    /// headers go into the freezer, and the totals are recomputed from them.
    ///
    /// They are done together because they read the same thing -- every block
    /// body, once. Splitting them means scanning the chain twice for data that
    /// was already in hand the first time.
    ///
    /// Returns `(written, unchanged, absent, frozen)`.
    pub fn rebuild_chain_work<F>(
        &self,
        from: u64,
        to: u64,
        report_every: u64,
        progress: F,
    ) -> Result<(u64, u64, u64, u64)>
    where
        F: FnMut(u64, u64, U256),
    {
        if self.freezer().is_none() {
            bail!("no freezer is configured, so there is nowhere to put the uncle headers");
        }
        self.walk_chain_work(from, to, report_every, true, progress)
    }

    fn walk_chain_work<F>(
        &self,
        from: u64,
        to: u64,
        report_every: u64,
        freeze_uncles: bool,
        mut progress: F,
    ) -> Result<(u64, u64, u64, u64)>
    where
        F: FnMut(u64, u64, U256),
    {
        let mut frozen = 0u64;
        let (mut written, mut unchanged, mut absent) = (0u64, 0u64, 0u64);

        let mut running = if from == 0 {
            U256::ZERO
        } else {
            let prev = self
                .canonical_hash(from - 1)?
                .ok_or_else(|| anyhow!("no canonical block at #{} to seed from", from - 1))?;
            self.total_difficulty(prev)?
                .ok_or_else(|| anyhow!("no stored total difficulty at #{}", from - 1))?
        };

        for number in from..=to {
            let Some(hash) = self.canonical_hash(number)? else {
                absent += 1;
                continue;
            };
            let Some(header) = self.header(hash)? else {
                absent += 1;
                continue;
            };

            if freeze_uncles {
                // Write the uncles before the total that depends on them. If
                // the pass dies here, a rerun still finds the uncles it needs;
                // the other order can leave a total nothing can re-derive.
                let ommers = match self.body(hash)? {
                    Some((_txs, ommers)) => ommers,
                    None if header.uncle_count == 0 => Vec::new(),
                    None => return Err(anyhow!(
                        "block #{number} has no body, so its uncle headers cannot be frozen"
                    )),
                };
                if let Some(f) = self.freezer() {
                    f.put_uncles(number, &ommers)?;
                    frozen += 1;
                }
            }

            match self.cumulative_difficulty(hash, &header)? {
                Some(contribution) => running = running.saturating_add(contribution),
                None => {
                    // The body is gone, so this block's uncle difficulties are
                    // unrecoverable and every total above it would inherit the
                    // error. Stopping is the honest outcome.
                    return Err(anyhow!(
                        "block #{number} has no body, so its uncle difficulties are                          unrecoverable; totals above it cannot be corrected"
                    ));
                }
            }

            if self.total_difficulty(hash)? == Some(running) {
                unchanged += 1;
            } else {
                self.put_total_difficulty(hash, running)?;
                written += 1;
            }

            if report_every > 0 && number % report_every == 0 {
                progress(number, written, running);
            }
        }

        if freeze_uncles {
            if let Some(f) = self.freezer() {
                f.sync()?;
            }
        }
        Ok((written, unchanged, absent, frozen))
    }

    /// Record one Bridge event. See `CF_BRIDGE_EVENTS` for the key layout.
    pub fn put_bridge_event(
        &self,
        topic0: B256,
        block: u64,
        tx_index: u32,
        log_index: u32,
        tx_hash: B256,
        topics: &[B256],
        data: &[u8],
    ) -> Result<()> {
        let mut key = Vec::with_capacity(48);
        key.extend_from_slice(topic0.as_slice());
        key.extend_from_slice(&block.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key.extend_from_slice(&log_index.to_be_bytes());

        let mut val = Vec::with_capacity(64 + data.len());
        val.extend_from_slice(tx_hash.as_slice());
        val.push(topics.len() as u8);
        for t in topics {
            val.extend_from_slice(t.as_slice());
        }
        val.extend_from_slice(data);

        self.db
            .put_cf(self.cf(CF_BRIDGE_EVENTS)?, key, val)
            .context("Failed to write bridge event")
    }

    /// Index every Bridge log in one block's receipts.
    ///
    /// The single place events enter the index: the commit path calls it as
    /// blocks are executed, and `--build-bridge-index` calls it when rebuilding
    /// from stored receipts, so the two cannot drift apart.
    ///
    /// Receipts carry no transaction hash, so they are paired with the body by
    /// position -- the same ordering the receipts root commits to.
    ///
    /// Returns how many events were written. Cheap for the common block: it
    /// only walks logs that are already in memory, and most blocks emit none.
    pub fn index_bridge_events(
        &self,
        block: u64,
        receipts: &[Receipt],
        transactions: &[Transaction],
        bridge: alloy_primitives::Address,
    ) -> Result<u64> {
        let mut written = 0u64;
        for (tx_index, receipt) in receipts.iter().enumerate() {
            for (log_index, log) in receipt.logs.iter().enumerate() {
                if log.address != bridge {
                    continue;
                }
                let Some(topic0) = log.topics.first().copied() else { continue };
                let tx_hash = transactions.get(tx_index).map(|t| t.tx_hash()).unwrap_or_default();
                self.put_bridge_event(
                    topic0, block, tx_index as u32, log_index as u32,
                    tx_hash, &log.topics, &log.data,
                )?;
                written += 1;
            }
        }
        Ok(written)
    }

    /// Every occurrence of one event type, in block order, optionally bounded.
    ///
    /// Returns `(block, tx_index, log_index, tx_hash, topics, data)`.
    #[allow(clippy::type_complexity)]
    pub fn scan_bridge_events(
        &self,
        topic0: B256,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(u64, u32, u32, B256, Vec<B256>, Vec<u8>)>> {
        self.scan_events_in(CF_BRIDGE_EVENTS, topic0, from_block, to_block)
    }

    /// The shared prefix scan behind [`Self::scan_bridge_events`] and
    /// [`Self::scan_legacy_bridge_events`]. The two column families hold the
    /// same layout on purpose, so they decode with one implementation and
    /// cannot drift apart.
    #[allow(clippy::type_complexity)]
    fn scan_events_in(
        &self,
        cf_name: &str,
        topic0: B256,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(u64, u32, u32, B256, Vec<B256>, Vec<u8>)>> {
        let cf = self.cf(cf_name)?;
        let mut start = Vec::with_capacity(40);
        start.extend_from_slice(topic0.as_slice());
        start.extend_from_slice(&from_block.to_be_bytes());

        let mut out = Vec::new();
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (k, v) = item?;
            if k.len() < 48 || &k[..32] != topic0.as_slice() {
                break; // left this event type: the prefix is exhausted
            }
            let block = u64::from_be_bytes(k[32..40].try_into().unwrap());
            if block > to_block {
                break;
            }
            let tx_index = u32::from_be_bytes(k[40..44].try_into().unwrap());
            let log_index = u32::from_be_bytes(k[44..48].try_into().unwrap());
            if v.len() < 33 {
                continue;
            }
            let tx_hash = B256::from_slice(&v[..32]);
            let n = v[32] as usize;
            let mut topics = Vec::with_capacity(n);
            let mut off = 33;
            for _ in 0..n {
                if off + 32 > v.len() { break }
                topics.push(B256::from_slice(&v[off..off + 32]));
                off += 32;
            }
            out.push((block, tx_index, log_index, tx_hash, topics, v[off..].to_vec()));
        }
        Ok(out)
    }

    /// Every distinct event type present in the Bridge event index, with its
    /// occurrence count and block span.
    ///
    /// The index stores every Bridge log regardless of topic, so this
    /// enumerates what is actually there rather than what a caller thought to
    /// ask for. Returns `(topic0, count, first_block, last_block)`.
    pub fn bridge_event_topics(&self) -> Result<Vec<(B256, u64, u64, u64)>> {
        use std::collections::BTreeMap;
        let cf = self.cf(CF_BRIDGE_EVENTS)?;
        let mut acc: BTreeMap<[u8; 32], (u64, u64, u64)> = BTreeMap::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (k, _) = item?;
            if k.len() < 40 {
                continue;
            }
            let mut topic = [0u8; 32];
            topic.copy_from_slice(&k[..32]);
            let block = u64::from_be_bytes(k[32..40].try_into().unwrap());
            let e = acc.entry(topic).or_insert((0, u64::MAX, 0));
            e.0 += 1;
            e.1 = e.1.min(block);
            e.2 = e.2.max(block);
        }
        Ok(acc
            .into_iter()
            .map(|(t, (c, first, last))| (B256::from(t), c, first, last))
            .collect())
    }

    // NOTE: orphaned doc -- "Returns a reference to the underlying RocksDB
    // instance" documents no item here; left as a comment pending review.
    // --- Snapshot chunk cache ---

    /// A snapshot cell already computed, if it is still here.
    ///
    /// `grid` and `format` are part of the identity of a cell, not decoration:
    /// cell 3 of a 100 KB grid is a different range from cell 3 of a 51,200
    /// byte one, and the same range in two encodings is two different answers.
    /// Keying on the index alone would serve one client another's bytes the
    /// first time an operator changed a setting.
    pub fn snap_chunk(
        &self,
        state_root: B256,
        grid: u64,
        format: u8,
        index: u64,
    ) -> Result<Option<Vec<u8>>> {
        self
            .db
            .get_cf(self.cf(CF_SNAP_CHUNKS)?, snap_chunk_key(state_root, grid, format, index))
            .context("Failed to read a snapshot chunk")
    }

    pub fn put_snap_chunk(
        &self,
        state_root: B256,
        grid: u64,
        format: u8,
        index: u64,
        bytes: &[u8],
    ) -> Result<()> {
        self.db
            .put_cf(
                self.cf(CF_SNAP_CHUNKS)?,
                snap_chunk_key(state_root, grid, format, index),
                bytes,
            )
            .context("Failed to store a snapshot chunk")
    }

    /// Drop every cell of a state, which is what a checkpoint rollover wants:
    /// the old state will never be asked for again and is a gigabyte.
    pub fn clear_snap_chunks(&self, state_root: B256) -> Result<()> {
        let cf = self.cf(CF_SNAP_CHUNKS)?;
        let mut batch = WriteBatch::default();
        // Everything under this state root, whatever grid or format it was
        // stored for.
        batch.delete_range_cf(
            cf,
            snap_chunk_key(state_root, 0, 0, 0),
            snap_chunk_key(state_root, u64::MAX, u8::MAX, u64::MAX),
        );
        // delete_range is end-exclusive, so the last possible cell needs
        // naming; a cache that kept one stale entry per state would leak one
        // per rollover forever.
        batch.delete_cf(cf, snap_chunk_key(state_root, u64::MAX, u8::MAX, u64::MAX));
        self.db.write(batch).context("Failed to clear snapshot chunks")
    }

    /// Every state root that has cells cached, for deciding what to drop.
    pub fn cached_snap_roots(&self) -> Result<Vec<B256>> {
        let cf = self.cf(CF_SNAP_CHUNKS)?;
        let mut roots: Vec<B256> = Vec::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (key, _) = item.context("Failed to iterate snapshot chunks")?;
            if key.len() >= 32 {
                let root = B256::from_slice(&key[..32]);
                if roots.last() != Some(&root) {
                    roots.push(root);
                }
            }
        }
        roots.dedup();
        Ok(roots)
    }

    // --- Background canonical indexing ---

    /// The height a background index pass should resume from, and the hash it
    /// was expecting there.
    pub fn index_cursor(&self) -> Result<Option<(u64, B256)>> {
        let Some(bytes) = self.db.get(KEY_INDEX_CURSOR).context("read index cursor")? else {
            return Ok(None);
        };
        if bytes.len() != 40 {
            return Ok(None);
        }
        let mut number = [0u8; 8];
        number.copy_from_slice(&bytes[..8]);
        Ok(Some((u64::from_be_bytes(number), B256::from_slice(&bytes[8..]))))
    }

    pub fn set_index_cursor(&self, number: u64, hash: B256) -> Result<()> {
        let mut bytes = [0u8; 40];
        bytes[..8].copy_from_slice(&number.to_be_bytes());
        bytes[8..].copy_from_slice(hash.as_slice());
        self.db.put(KEY_INDEX_CURSOR, bytes).context("write index cursor")
    }

    pub fn clear_index_cursor(&self) -> Result<()> {
        self.db.delete(KEY_INDEX_CURSOR).context("clear index cursor")
    }

    /// Index one batch of the canonical chain, walking down from `hash`.
    ///
    /// Heights already mapped to the same block are skipped rather than
    /// rewritten, but the walk does **not** stop at one. A snap-synced node is
    /// indexed at the top and bare underneath, so stopping at the first
    /// agreement would stop at the head having done nothing -- which is
    /// exactly what it did before this was written the other way round.
    ///
    /// Returns how many heights were newly written and where to resume, or
    /// `None` when the walk reached genesis or a header it cannot read.
    /// Bounded, so the caller can yield between batches: this runs behind a
    /// node that has better things to do with its disk.
    pub fn index_canonical_batch(
        &self,
        hash: B256,
        batch_size: u64,
    ) -> Result<(u64, Option<(u64, B256)>)> {
        let cf = self.cf(CF_NUMBERS)?;
        let mut batch = WriteBatch::default();
        let mut written = 0u64;
        let mut current = hash;

        // On a pruning node there is nothing below the floor to index: those
        // blocks are gone, and writing `number -> hash` for them would only
        // give the next sweep more to delete. Checked per height rather than
        // per batch, because a batch spanning the floor would otherwise write
        // straight through it.
        let floor = self.prune_floor()?.map(|f| f.number);

        for _ in 0..batch_size {
            let Some(header) = self.header(current)? else {
                self.db.write(batch).context("commit canonical index batch")?;
                return Ok((written, None));
            };

            if floor.is_some_and(|f| header.number < f) {
                self.db.write(batch).context("commit canonical index batch")?;
                return Ok((written, None));
            }

            // Rewriting an agreeing height would be wasted I/O; disagreeing
            // ones are corrected, because this walk is following the chain the
            // node itself accepted.
            if self.canonical_hash(header.number)? != Some(current) {
                batch.put_cf(cf, header.number.to_be_bytes(), current.as_slice());
                written += 1;
            }

            if header.number == 0 {
                self.db.write(batch).context("commit canonical index batch")?;
                return Ok((written, None));
            }
            current = header.parent_hash;
        }

        self.db.write(batch).context("commit canonical index batch")?;

        let next_number = match self.header(current)? {
            Some(h) => h.number,
            None => return Ok((written, None)),
        };
        Ok((written, Some((next_number, current))))
    }

    pub fn db(&self) -> &Arc<DB> {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_core::{Header, Transaction};
    use alloy_primitives::{Address, B256, U256, Bytes};
    use tempfile::tempdir;

    fn dummy_tx(nonce: u64) -> Transaction {
        Transaction {
            nonce,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1_000_000u64),
            input: Bytes::default(),
            v: 27,
            r: U256::from(nonce + 100),
            s: U256::from(nonce + 200),
            cached_rlp: None,
        }
    }

    pub(super) fn dummy_header(number: u64) -> Header {
        Header {
            number,
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::ZERO,
            gas_limit: U256::ZERO,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    #[test]
    fn test_header_flow() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(1);
        let hash = header.hash();

        // 1. Store Header
        store.put_header(&header).unwrap();
        
        // 2. Retrieve Header
        let retrieved = store.header(hash).unwrap().unwrap();
        assert_eq!(header, retrieved);

        // 3. Set Canonical
        store.put_canonical_hash(1, hash).unwrap();
        assert_eq!(store.canonical_hash(1).unwrap(), Some(hash));

        // 4. Set Head
        store.set_head(hash).unwrap();
        assert_eq!(store.head().unwrap(), Some(hash));

        // 5. Total Difficulty
        store.put_total_difficulty(hash, U256::from(100)).unwrap();
        assert_eq!(store.total_difficulty(hash).unwrap(), Some(U256::from(100)));

        // 6. Executed head (hash + unitrie state root), independent of head
        assert_eq!(store.exec_head().unwrap(), None);
        let state_root = B256::repeat_byte(0x42);
        store.set_exec_head(hash, state_root).unwrap();
        assert_eq!(store.exec_head().unwrap(), Some((hash, state_root)));
        assert_eq!(store.head().unwrap(), Some(hash)); // unchanged
    }

    #[test]
    fn test_update_head_flow() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(100);
        let hash = header.hash();
        let td = U256::from(500);

        store.update_head(&header, td).unwrap();

        // Verify everything was set
        assert_eq!(store.header(hash).unwrap().unwrap(), header);
        assert_eq!(store.canonical_hash(100).unwrap(), Some(hash));
        assert_eq!(store.total_difficulty(hash).unwrap(), Some(td));
        assert_eq!(store.head().unwrap(), Some(hash));
    }

    #[test]
    fn test_put_header_with_hash() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(1);
        let custom_hash = B256::repeat_byte(0xAA);

        store.put_header_with_hash(custom_hash, &header).unwrap();

        assert!(store.header(custom_hash).unwrap().is_some());
        assert!(store.header(header.hash()).unwrap().is_none());
    }

    #[test]
    fn test_has_block() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(1);
        store.put_header(&header).unwrap();

        assert!(store.has_block(header.hash()).unwrap());
        assert!(!store.has_block(B256::repeat_byte(0xFF)).unwrap());
    }

    #[test]
    fn test_put_header_with_hash_for_genesis() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let genesis = dummy_header(0);
        let known_hash = B256::repeat_byte(0x42);
        let td = U256::from(1000);

        store.put_header_with_hash(known_hash, &genesis).unwrap();
        store.put_total_difficulty(known_hash, td).unwrap();

        assert_eq!(store.header(known_hash).unwrap().unwrap(), genesis);
        assert_eq!(store.total_difficulty(known_hash).unwrap(), Some(td));
    }

    // --- store_headers_batch tests ---

    fn dummy_header_with_difficulty(number: u64, difficulty: u64) -> Header {
        let mut h = dummy_header(number);
        h.difficulty = U256::from(difficulty);
        h
    }

    #[test]
    fn test_store_headers_batch_empty() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let result = store
            .store_headers_batch(&[], None, U256::ZERO)
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_store_headers_batch_single_entry() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let h = dummy_header_with_difficulty(1, 10);
        let td = U256::from(10);
        let entries = vec![(&h, td)];

        let new_head = store
            .store_headers_batch(&entries, None, U256::ZERO)
            .unwrap();

        // TD(10) > current TD(0), so head should be updated
        assert_eq!(new_head, Some(h.hash()));
        assert!(store.header(h.hash()).unwrap().is_some());
        assert_eq!(store.total_difficulty(h.hash()).unwrap(), Some(td));
        assert_eq!(store.head().unwrap(), Some(h.hash()));
        assert_eq!(store.canonical_hash(1).unwrap(), Some(h.hash()));
    }

    #[test]
    fn test_store_headers_batch_multiple_ascending_td() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let h1 = dummy_header_with_difficulty(1, 5);
        let h2 = dummy_header_with_difficulty(2, 5);
        let h3 = dummy_header_with_difficulty(3, 5);
        let entries = vec![
            (&h1, U256::from(5)),
            (&h2, U256::from(10)),
            (&h3, U256::from(15)),
        ];

        let new_head = store
            .store_headers_batch(&entries, None, U256::ZERO)
            .unwrap();

        // h3 has the highest TD, so it should be the head
        assert_eq!(new_head, Some(h3.hash()));
        assert_eq!(store.head().unwrap(), Some(h3.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(h3.hash()));

        // All headers should be retrievable
        assert!(store.header(h1.hash()).unwrap().is_some());
        assert!(store.header(h2.hash()).unwrap().is_some());
        assert!(store.header(h3.hash()).unwrap().is_some());

        // All TDs should be stored
        assert_eq!(store.total_difficulty(h1.hash()).unwrap(), Some(U256::from(5)));
        assert_eq!(store.total_difficulty(h3.hash()).unwrap(), Some(U256::from(15)));
    }

    #[test]
    fn test_store_headers_batch_does_not_lower_head() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Set up existing head with TD=100
        let existing = dummy_header_with_difficulty(50, 100);
        store.update_head(&existing, U256::from(100)).unwrap();
        let existing_hash = existing.hash();

        // Batch with lower TD should not change head
        let h = dummy_header_with_difficulty(1, 5);
        let entries = vec![(&h, U256::from(5))];

        let result = store
            .store_headers_batch(&entries, Some(existing_hash), U256::from(100))
            .unwrap();

        // Head should remain unchanged
        assert_eq!(result, Some(existing_hash));
        assert_eq!(store.head().unwrap(), Some(existing_hash));

        // But the header should still be stored
        assert!(store.header(h.hash()).unwrap().is_some());
        assert_eq!(store.total_difficulty(h.hash()).unwrap(), Some(U256::from(5)));
    }

    // --- Reorg / canonical chain tests ---

    pub(super) fn make_chain_header(number: u64, parent_hash: B256, difficulty: u64, nonce: u8) -> Header {
        let mut h = dummy_header(number);
        h.parent_hash = parent_hash;
        h.difficulty = U256::from(difficulty);
        // Use extra_data to differentiate forks at the same height
        h.extra_data = Bytes::from(vec![nonce]);
        h
    }

    /// Build a chain of headers and store them as the canonical chain.
    /// Returns (headers, cumulative TDs) for each block.
    fn build_and_store_chain(
        store: &BlockStore,
        count: usize,
        difficulty: u64,
        nonce: u8,
    ) -> Vec<(Header, U256)> {
        let mut chain = Vec::new();
        let mut parent_hash = B256::ZERO;
        let mut td = U256::ZERO;

        for i in 0..count {
            let h = make_chain_header(i as u64, parent_hash, difficulty, nonce);
            let hash = h.hash();
            td += h.difficulty;
            store.put_header(&h).unwrap();
            store.put_total_difficulty(hash, td).unwrap();
            store.put_canonical_hash(i as u64, hash).unwrap();
            parent_hash = hash;
            chain.push((h, td));
        }
        if let Some((last, _)) = chain.last() {
            store.set_head(last.hash()).unwrap();
        }
        chain
    }

    #[test]
    fn test_reorg_to_higher_td_fork() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Main chain: genesis -> 1A -> 2A -> 3A (difficulty 10 each, TD: 10, 20, 30, 40)
        let chain_a = build_and_store_chain(&store, 4, 10, 0xAA);
        let head_a = chain_a.last().unwrap().0.hash();
        assert_eq!(store.head().unwrap(), Some(head_a));

        // Fork chain: same genesis -> 1B -> 2B -> 3B (difficulty 20 each, higher TD)
        let genesis = &chain_a[0];
        let b1 = make_chain_header(1, genesis.0.hash(), 20, 0xBB);
        let b2 = make_chain_header(2, b1.hash(), 20, 0xBB);
        let b3 = make_chain_header(3, b2.hash(), 20, 0xBB);

        let td_b1 = genesis.1 + b1.difficulty; // 10 + 20 = 30
        let td_b2 = td_b1 + b2.difficulty;     // 30 + 20 = 50
        let td_b3 = td_b2 + b3.difficulty;     // 50 + 20 = 70

        let entries = vec![
            (&b1, td_b1),
            (&b2, td_b2),
            (&b3, td_b3),
        ];

        let result = store
            .store_headers_batch(&entries, Some(head_a), chain_a.last().unwrap().1)
            .unwrap();

        // Fork B has higher TD (70 vs 40), so head should switch
        assert_eq!(result, Some(b3.hash()));
        assert_eq!(store.head().unwrap(), Some(b3.hash()));

        // Canonical chain should now point to fork B
        assert_eq!(store.canonical_hash(0).unwrap(), Some(genesis.0.hash())); // common ancestor
        assert_eq!(store.canonical_hash(1).unwrap(), Some(b1.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(b2.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));

        // Old fork A headers should still be retrievable by hash
        assert!(store.header(chain_a[1].0.hash()).unwrap().is_some());
        assert!(store.header(chain_a[2].0.hash()).unwrap().is_some());
    }

    /// A reorg that lands the head *below* the executed block must bring
    /// execution down with it.
    ///
    /// This is mainnet's shape, seen ~54 times a day: two blocks execute, a
    /// one-block reorg takes the better chain, and the executed head is left
    /// standing above the validated one. The node then refuses to make
    /// progress until the chain grows back past the reorg point -- minutes,
    /// each time (issue #307).
    ///
    /// The batch-sync paths go through `Transition`, which has pulled
    /// execution down since it was written. The header-ingest path did not,
    /// which is why no test caught this.
    #[test]
    fn a_reorg_below_the_executed_block_brings_execution_down() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Chain A: genesis -> 1A -> 2A, all canonical, and executed to 2A.
        let chain_a = build_and_store_chain(&store, 3, 10, 0xAA);
        let a2 = &chain_a[2].0;
        store.set_exec_head(a2.hash(), a2.state_root).unwrap();

        let cursor = store.cursor().unwrap().expect("a cursor");
        assert_eq!(cursor.validated_head.number, 2);
        assert_eq!(cursor.executed.number, 2);

        // Chain B forks at genesis and is one block shorter, but heavier:
        // a single block of difficulty 40 against two of 10.
        let genesis = &chain_a[0];
        let b1 = make_chain_header(1, genesis.0.hash(), 40, 0xBB);
        let td_b1 = genesis.1 + b1.difficulty;

        store
            .store_headers_batch(&[(&b1, td_b1)], Some(a2.hash()), chain_a[2].1)
            .unwrap();

        assert_eq!(store.head().unwrap(), Some(b1.hash()), "the heavier chain wins");

        let after = store.cursor().unwrap().expect("a cursor");
        assert_eq!(after.validated_head.number, 1, "the head retreated");

        // To the fork point, not to the new head. #1 on the winning chain is
        // a block this node never executed, and recording it as executed
        // would claim its state root without having computed it. Genesis is
        // the deepest block still on the chain that was actually executed,
        // so #1 is re-executed from there.
        assert_eq!(
            after.executed.number, 0,
            "execution came down -- leaving it at #2 is I4, and the node \
             stops until the chain grows past the reorg"
        );
        assert_eq!(after.executed.hash, genesis.0.hash());

        // The whole point of the invariant: it must now hold.
        verify_local_coherence(&store, &after).expect("coherent after the reorg");
    }

    /// The canonical entry the old chain left above the new head goes too.
    /// A block that is held, linked and above the head is unreachable --
    /// every path that looks for work reads the head.
    #[test]
    fn a_reorg_drops_the_canonical_entries_it_stranded() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let chain_a = build_and_store_chain(&store, 3, 10, 0xAA);
        let a2 = &chain_a[2].0;
        store.set_exec_head(a2.hash(), a2.state_root).unwrap();
        assert!(store.canonical_hash(2).unwrap().is_some());

        let genesis = &chain_a[0];
        let b1 = make_chain_header(1, genesis.0.hash(), 40, 0xBB);
        let td_b1 = genesis.1 + b1.difficulty;
        store
            .store_headers_batch(&[(&b1, td_b1)], Some(a2.hash()), chain_a[2].1)
            .unwrap();

        assert_eq!(
            store.canonical_hash(2).unwrap(),
            None,
            "nothing canonical may be left above the head"
        );
    }

    #[test]
    fn test_delete_canonical_hash() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let h = B256::repeat_byte(0x7);
        store.put_canonical_hash(42, h).unwrap();
        assert_eq!(store.canonical_hash(42).unwrap(), Some(h));
        store.delete_canonical_hash(42).unwrap();
        assert_eq!(store.canonical_hash(42).unwrap(), None);
        // Deleting an absent mapping is a no-op.
        store.delete_canonical_hash(42).unwrap();
    }

    #[test]
    fn test_canonical_walk_repairs_truncated_reorg_hole() {
        // Reproduces a real wedge: skeleton sync delivers a fork's child header
        // before the fork block itself, so an earlier canonical walk truncates
        // at the missing parent and leaves a hole (canonical #2 still names the
        // orphan while #3 builds on the fork). A later head update must repair
        // the hole, not stop at the first already-canonical block.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Canonical chain A: genesis(#0) <- a1(#1) <- a2(#2).
        let chain_a = build_and_store_chain(&store, 3, 10, 0xAA);
        let a1_hash = chain_a[1].0.hash();
        let a2_hash = chain_a[2].0.hash();

        // Fork B at #2: b2 <- b3 <- b4, all built on a1.
        let b2 = make_chain_header(2, a1_hash, 20, 0xBB);
        let b3 = make_chain_header(3, b2.hash(), 20, 0xBB);
        let b4 = make_chain_header(4, b3.hash(), 20, 0xBB);
        for h in [&b2, &b3, &b4] {
            store.put_header(h).unwrap();
            store.put_total_difficulty(h.hash(), U256::from(100)).unwrap();
        }

        // Simulate the truncated walk: #3 was made canonical (and head), but
        // #2 was never repaired — it still names the orphan a2.
        store.put_canonical_hash(3, b3.hash()).unwrap();
        store.set_head(b3.hash()).unwrap();
        assert_eq!(store.canonical_hash(2).unwrap(), Some(a2_hash), "hole precondition");
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));

        // A new head (b4) triggers a canonical update. The walk must continue
        // past the already-canonical #3 to repair stale #2.
        store.update_canonical_chain(b4.hash()).unwrap();

        assert_eq!(store.canonical_hash(4).unwrap(), Some(b4.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(b2.hash()),
            "hole at #2 must be repaired to the fork block");
        assert_eq!(store.canonical_hash(1).unwrap(), Some(a1_hash), "common ancestor intact");
        // Chain is now internally consistent: each canonical child's parent is
        // the canonical block below it.
        let c3 = store.header(store.canonical_hash(3).unwrap().unwrap()).unwrap().unwrap();
        assert_eq!(c3.parent_hash, store.canonical_hash(2).unwrap().unwrap());
    }

    #[test]
    fn test_repair_fills_buried_missing_canonical_entry() {
        // Reproduces the production wedge. An interrupted canonical rewrite
        // left height #3 with no pointer *at all* (distinct from the stale
        // pointer case above), while every height around it stayed
        // self-consistent. Two mechanisms that look like they should recover
        // from this both decline to:
        //
        //   - a tip update walks down from the head, finds the top already
        //     consistent, and stops before reaching the buried hole;
        //   - the sync reconcile path reads a missing pointer at exec_head+1
        //     as "we are at the tip" and returns.
        //
        // So execution halts at the hole and retries forever.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let chain = build_and_store_chain(&store, 6, 10, 0xAA);
        let head_hash = chain[5].0.hash();
        store.update_canonical_chain(head_hash).unwrap();
        for n in 0..=5u64 {
            assert!(store.canonical_hash(n).unwrap().is_some(), "setup: #{n} canonical");
        }

        // The interrupted rewrite: no pointer at #3.
        store.delete_canonical_hash(3).unwrap();
        assert_eq!(store.canonical_hash(3).unwrap(), None, "hole precondition");

        // A tip update does not repair it -- the chain above the hole is
        // already consistent, so the walk stops at the top.
        store.update_canonical_chain(head_hash).unwrap();
        assert_eq!(
            store.canonical_hash(3).unwrap(),
            None,
            "buried hole survives a tip update; this is why an explicit repair exists"
        );

        // The repair walk has no early stop, so it reaches and fills the hole.
        let report = store.repair_canonical_lineage(head_hash, 16).unwrap();
        assert_eq!(report.filled, 1, "one missing pointer filled");
        assert_eq!(report.corrected, 0, "nothing else was wrong");
        assert_eq!(store.canonical_hash(3).unwrap(), Some(chain[3].0.hash()));

        // Contiguous again: every canonical block's parent is the canonical
        // block below it, which is what execution needs to cross the gap.
        for n in 1..=5u64 {
            let h = store
                .header(store.canonical_hash(n).unwrap().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(h.parent_hash, store.canonical_hash(n - 1).unwrap().unwrap());
        }
    }

    #[test]
    fn test_repair_corrects_index_straddling_two_forks() {
        // The other half of the observed damage: an interrupted rewrite that
        // left the upper heights naming the new fork and the lower ones still
        // naming the old, so the index is a mix of two chains.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let chain_a = build_and_store_chain(&store, 5, 10, 0xAA);
        store.update_canonical_chain(chain_a[4].0.hash()).unwrap();

        // Fork B from #2 upward, heavier.
        let a2_hash = chain_a[2].0.hash();
        let b3 = make_chain_header(3, a2_hash, 20, 0xBB);
        let b4 = make_chain_header(4, b3.hash(), 20, 0xBB);
        for h in [&b3, &b4] {
            store.put_header(h).unwrap();
            store.put_total_difficulty(h.hash(), U256::from(100)).unwrap();
        }

        // Half-applied rewrite: #4 moved to fork B, #3 still names fork A.
        store.put_canonical_hash(4, b4.hash()).unwrap();
        store.set_head(b4.hash()).unwrap();
        assert_eq!(store.canonical_hash(3).unwrap(), Some(chain_a[3].0.hash()));

        let report = store.repair_canonical_lineage(b4.hash(), 16).unwrap();
        assert_eq!(report.corrected, 1, "#3 rewritten to the fork it belongs to");
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(a2_hash), "ancestor intact");

        for n in 1..=4u64 {
            let h = store
                .header(store.canonical_hash(n).unwrap().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(h.parent_hash, store.canonical_hash(n - 1).unwrap().unwrap());
        }
    }

    #[test]
    fn total_difficulty_reads_back_the_importers_encoding() {
        // The import's fast batch path writes total difficulty as raw 32
        // big-endian bytes, while `put_total_difficulty` RLP-encodes it. Both
        // land in the same column family, and the reader only understood one of
        // them -- so every block written by the importer had an unreadable
        // total difficulty, which surfaced as `eth_getBlockByNumber` returning
        // null for all 9.2M imported blocks.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let hash = B256::repeat_byte(0x11);
        let td = U256::from(123_456_789_u64);
        // Exactly what rskj_import writes.
        store.put_total_difficulty_raw(hash, &td.to_be_bytes::<32>()).unwrap();

        let got = store.total_difficulty(hash).unwrap();
        assert_eq!(got, Some(td), "raw 32-byte total difficulty must read back");
    }

    #[test]
    fn total_difficulty_round_trips_both_encodings() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        for (i, td) in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(255u64),
            U256::from(u64::MAX),
            U256::from_be_bytes([0xFF; 32]),
        ]
        .into_iter()
        .enumerate()
        {
            let rlp_hash = B256::repeat_byte(i as u8);
            store.put_total_difficulty(rlp_hash, td).unwrap();
            assert_eq!(store.total_difficulty(rlp_hash).unwrap(), Some(td), "rlp {td}");

            let raw_hash = B256::repeat_byte(0x80 | i as u8);
            store.put_total_difficulty_raw(raw_hash, &td.to_be_bytes::<32>()).unwrap();
            assert_eq!(store.total_difficulty(raw_hash).unwrap(), Some(td), "raw {td}");
        }
    }

    #[test]
    fn test_lower_td_fork_does_not_corrupt_canonical() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Main chain: genesis -> 1A -> 2A -> 3A (difficulty 20 each)
        let chain_a = build_and_store_chain(&store, 4, 20, 0xAA);
        let head_a = chain_a.last().unwrap().0.hash();

        // Fork chain with lower TD (difficulty 5 each)
        let genesis = &chain_a[0];
        let b1 = make_chain_header(1, genesis.0.hash(), 5, 0xBB);
        let b2 = make_chain_header(2, b1.hash(), 5, 0xBB);
        let b3 = make_chain_header(3, b2.hash(), 5, 0xBB);

        let td_b1 = genesis.1 + b1.difficulty;
        let td_b2 = td_b1 + b2.difficulty;
        let td_b3 = td_b2 + b3.difficulty;

        let entries = vec![(&b1, td_b1), (&b2, td_b2), (&b3, td_b3)];

        let result = store
            .store_headers_batch(&entries, Some(head_a), chain_a.last().unwrap().1)
            .unwrap();

        // Head should NOT change (fork B has lower TD)
        assert_eq!(result, Some(head_a));
        assert_eq!(store.head().unwrap(), Some(head_a));

        // Canonical chain must still point to fork A
        assert_eq!(store.canonical_hash(1).unwrap(), Some(chain_a[1].0.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(chain_a[2].0.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(chain_a[3].0.hash()));

        // Fork B headers should still be stored (keyed by hash)
        assert!(store.header(b1.hash()).unwrap().is_some());
        assert!(store.header(b2.hash()).unwrap().is_some());
        assert!(store.header(b3.hash()).unwrap().is_some());
    }

    #[test]
    fn test_direct_extension_updates_canonical() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Build a chain of 3 blocks
        let chain = build_and_store_chain(&store, 3, 10, 0xAA);
        let head = chain.last().unwrap();
        let head_hash = head.0.hash();
        let head_td = head.1;

        // Extend with block 3 (direct child of block 2)
        let b3 = make_chain_header(3, head_hash, 10, 0xAA);
        let td_b3 = head_td + b3.difficulty;
        let entries = vec![(&b3, td_b3)];

        let result = store
            .store_headers_batch(&entries, Some(head_hash), head_td)
            .unwrap();

        // Head should advance
        assert_eq!(result, Some(b3.hash()));
        assert_eq!(store.head().unwrap(), Some(b3.hash()));

        // All canonical pointers should be correct
        assert_eq!(store.canonical_hash(0).unwrap(), Some(chain[0].0.hash()));
        assert_eq!(store.canonical_hash(1).unwrap(), Some(chain[1].0.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(chain[2].0.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
    }

    #[test]
    fn test_update_canonical_chain_direct() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let chain = build_and_store_chain(&store, 3, 10, 0xAA);
        let head = chain.last().unwrap();

        // Add block 3 manually (simulating a new block)
        let b3 = make_chain_header(3, head.0.hash(), 10, 0xAA);
        store.put_header(&b3).unwrap();

        // update_canonical_chain should write canonical for block 3 and stop
        store.update_canonical_chain(b3.hash()).unwrap();

        assert_eq!(store.head().unwrap(), Some(b3.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
        // Previous canonical entries untouched
        assert_eq!(store.canonical_hash(2).unwrap(), Some(head.0.hash()));
    }

    #[test]
    fn test_reorg_longer_fork() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Main chain: 5 blocks, difficulty 10
        let chain_a = build_and_store_chain(&store, 5, 10, 0xAA);
        let head_a = chain_a.last().unwrap();

        // Fork from block 2, with 5 more blocks (longer chain, higher TD)
        let fork_base = &chain_a[2]; // block #2
        let mut parent = fork_base.0.hash();
        let mut fork_entries = Vec::new();
        let mut td = fork_base.1;

        for i in 3..8u64 {
            let h = make_chain_header(i, parent, 15, 0xBB);
            td += h.difficulty;
            fork_entries.push((h.clone(), td));
            parent = h.hash();
        }

        let refs: Vec<(&Header, U256)> = fork_entries.iter().map(|(h, td)| (h, *td)).collect();
        let result = store
            .store_headers_batch(&refs, Some(head_a.0.hash()), head_a.1)
            .unwrap();

        let fork_head = fork_entries.last().unwrap();
        assert_eq!(result, Some(fork_head.0.hash()));
        assert_eq!(store.head().unwrap(), Some(fork_head.0.hash()));

        // Canonical should follow fork B from block 3 onward
        assert_eq!(store.canonical_hash(2).unwrap(), Some(chain_a[2].0.hash())); // common ancestor
        assert_eq!(store.canonical_hash(3).unwrap(), Some(fork_entries[0].0.hash()));
        assert_eq!(store.canonical_hash(7).unwrap(), Some(fork_entries[4].0.hash()));
    }

    // --- Body storage tests ---

    #[test]
    fn test_put_and_get_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xAA);

        let txs = vec![dummy_tx(0), dummy_tx(1), dummy_tx(2)];
        let ommers = vec![dummy_header(99)];

        store.put_body(hash, &txs, &ommers).unwrap();

        let (retrieved_txs, retrieved_ommers) = store.body(hash).unwrap().unwrap();
        assert_eq!(retrieved_txs.len(), 3);
        assert_eq!(retrieved_ommers.len(), 1);
        assert_eq!(retrieved_txs[0].nonce, 0);
        assert_eq!(retrieved_txs[2].nonce, 2);
        assert_eq!(retrieved_ommers[0].number, 99);
    }

    #[test]
    fn test_body_not_found() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert!(store.body(B256::repeat_byte(0xFF)).unwrap().is_none());
    }

    #[test]
    fn test_put_and_get_body_empty() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xBB);

        store.put_body(hash, &[], &[]).unwrap();

        let (txs, ommers) = store.body(hash).unwrap().unwrap();
        assert!(txs.is_empty());
        assert!(ommers.is_empty());
    }

    #[test]
    fn test_storing_a_block_stores_header_and_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(5);
        let txs = vec![dummy_tx(0), dummy_tx(1)];
        let block = Block {
            header: header.clone(),
            transactions: txs.clone(),
            ommers: vec![],
        };
        let hash = block.hash();

        store.put_header(&block.header).unwrap();
        store.put_body(block.hash(), &block.transactions, &block.ommers).unwrap();
        store.put_canonical_hash(block.header.number, block.hash()).unwrap();

        // Header should be stored
        let h = store.header(hash).unwrap().unwrap();
        assert_eq!(h.number, 5);

        // Body should be stored
        let (retrieved_txs, retrieved_ommers) = store.body(hash).unwrap().unwrap();
        assert_eq!(retrieved_txs.len(), 2);
        assert!(retrieved_ommers.is_empty());

        // Full block retrieval
        let full_block = store.block(hash).unwrap().unwrap();
        assert_eq!(full_block.header.number, 5);
        assert_eq!(full_block.transactions.len(), 2);
        assert_eq!(full_block.transactions[0].nonce, 0);
    }

    #[test]
    fn test_block_returns_header_only_when_no_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(10);
        let hash = header.hash();

        store.put_header(&header).unwrap();

        let block = store.block(hash).unwrap().unwrap();
        assert_eq!(block.header.number, 10);
        assert!(block.transactions.is_empty());
        assert!(block.ommers.is_empty());
    }

    #[test]
    fn test_put_body_with_many_txs_and_ommers() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xCC);

        let txs: Vec<Transaction> = (0..10).map(dummy_tx).collect();
        let ommers: Vec<Header> = (100..109).map(dummy_header).collect();

        store.put_body(hash, &txs, &ommers).unwrap();

        let (ret_txs, ret_ommers) = store.body(hash).unwrap().unwrap();
        assert_eq!(ret_txs.len(), 10);
        assert_eq!(ret_ommers.len(), 9);

        for (i, tx) in ret_txs.iter().enumerate() {
            assert_eq!(tx.nonce, i as u64, "tx {i} nonce mismatch");
        }
        for (i, uncle) in ret_ommers.iter().enumerate() {
            assert_eq!(uncle.number, (100 + i) as u64, "uncle {i} number mismatch");
        }
    }

    #[test]
    fn test_put_body_overwrite() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xDD);

        store.put_body(hash, &[dummy_tx(0)], &[]).unwrap();
        let (txs, _) = store.body(hash).unwrap().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].nonce, 0);

        store.put_body(hash, &[dummy_tx(5), dummy_tx(6)], &[]).unwrap();
        let (txs, _) = store.body(hash).unwrap().unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].nonce, 5);
        assert_eq!(txs[1].nonce, 6);
    }

    #[test]
    fn test_storing_a_block_round_trips() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(42);
        let txs = vec![dummy_tx(0), dummy_tx(1), dummy_tx(2)];
        let ommers = vec![dummy_header(40), dummy_header(41)];
        let block = Block {
            header: header.clone(),
            transactions: txs.clone(),
            ommers: ommers.clone(),
        };
        let hash = block.hash();

        store.put_header(&block.header).unwrap();
        store.put_body(block.hash(), &block.transactions, &block.ommers).unwrap();
        store.put_canonical_hash(block.header.number, block.hash()).unwrap();

        let full = store.block(hash).unwrap().unwrap();
        assert_eq!(full.header.number, 42);
        assert_eq!(full.transactions.len(), 3);
        assert_eq!(full.ommers.len(), 2);
        assert_eq!(full.ommers[0].number, 40);
        assert_eq!(full.ommers[1].number, 41);

        for (i, tx) in full.transactions.iter().enumerate() {
            assert_eq!(tx.nonce, i as u64);
        }
    }

    #[test]
    fn test_body_storage_rlp_stability() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xEE);

        let txs = vec![dummy_tx(7)];
        let ommers = vec![dummy_header(99)];

        store.put_body(hash, &txs, &ommers).unwrap();

        // Read raw bytes and re-decode to verify RLP stability
        let raw = store.db.get_cf(store.cf(CF_BODIES).unwrap(), hash.as_slice())
            .unwrap().unwrap();

        // Decode the raw bytes manually
        let mut cursor = raw.as_slice();
        let outer = alloy_rlp::Header::decode(&mut cursor).unwrap();
        assert!(outer.list);

        let txs_header = alloy_rlp::Header::decode(&mut cursor).unwrap();
        assert!(txs_header.list);

        let tx = Transaction::decode(&mut cursor).unwrap();
        assert_eq!(tx.nonce, 7);

        let ommers_header = alloy_rlp::Header::decode(&mut cursor).unwrap();
        assert!(ommers_header.list);

        let uncle = Header::decode(&mut cursor).unwrap();
        assert_eq!(uncle.number, 99);
    }

    // --- Transaction Index tests ---

    /// The index must be keyed by the canonical transaction hash -- the one
    /// callers pass to `eth_getTransactionReceipt` and the one
    /// `eth_getBlockByNumber` hands out.
    ///
    /// `Transaction::tx_hash()` hashes `rlp_for_trie()`, which returns the
    /// ORIGINAL bytes when they were cached at decode time. An earlier version
    /// of `index_block_transactions` re-encoded instead, so for any transaction
    /// whose RLP does not round-trip byte-for-byte it stored a key nobody would
    /// ever look up. Reproducing rskj's non-canonical encodings is precisely why
    /// `cached_rlp` exists, so such transactions are expected, not hypothetical.
    #[test]
    fn index_block_transactions_keys_by_the_canonical_hash_not_a_reencode() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let block_hash = B256::repeat_byte(0xAB);

        let mut tx = Transaction {
            nonce: 7,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(Address::repeat_byte(0xCC).as_slice()),
            value: U256::from(5),
            input: Bytes::new(),
            v: 27,
            r: U256::from(1),
            s: U256::from(2),
            cached_rlp: None,
        };

        // Bytes that deliberately differ from what re-encoding would produce,
        // standing in for a transaction whose stored RLP is not reproducible.
        let mut reencoded = Vec::new();
        tx.encode(&mut reencoded);
        let mut original = reencoded.clone();
        original.push(0x00);
        tx.cached_rlp = Some(original);

        let canonical = tx.tx_hash();
        assert_ne!(
            canonical,
            {
                use sha3::Digest;
                B256::from_slice(&sha3::Keccak256::digest(&reencoded))
            },
            "fixture is pointless unless the two hashes differ"
        );

        store.index_block_transactions(block_hash, &[tx]).unwrap();

        let (found, idx) = store
            .tx_location(canonical)
            .unwrap()
            .expect("index must be reachable by the canonical hash");
        assert_eq!(found, block_hash);
        assert_eq!(idx, 0);
    }

    /// The repair rebuilds the index from bodies alone, which is the whole
    /// point: a node that imported its history rather than executing it has
    /// bodies for every block and index entries for none.
    ///
    /// Also pins that a gap (a height with no canonical hash, or a block whose
    /// body is missing) is skipped and counted rather than aborting the run.
    #[test]
    fn repair_tx_index_rebuilds_from_bodies_and_skips_gaps() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mk_tx = |nonce: u64| Transaction {
            nonce,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(Address::repeat_byte(0xCC).as_slice()),
            value: U256::from(nonce),
            input: Bytes::new(),
            v: 27,
            r: U256::from(nonce + 1),
            s: U256::from(nonce + 2),
            cached_rlp: None,
        };

        // #1 and #3 are complete; #2 is a gap with no canonical hash at all.
        let mut expected = Vec::new();
        for number in [1u64, 3] {
            let header = dummy_header(number);
            let hash = B256::repeat_byte(number as u8);
            let txs = vec![mk_tx(number * 10), mk_tx(number * 10 + 1)];
            store.put_header_with_hash(hash, &header).unwrap();
            store.put_canonical_hash(number, hash).unwrap();
            store.put_body(hash, &txs, &[]).unwrap();
            for (i, tx) in txs.iter().enumerate() {
                expected.push((tx.tx_hash(), hash, i as u32));
            }
        }

        // Nothing is indexed yet -- exactly the state of an imported chain.
        for (tx_hash, _, _) in &expected {
            assert!(store.tx_location(*tx_hash).unwrap().is_none());
        }

        let mut reports = 0;
        let (blocks, txs, skipped) = store
            .repair_tx_index(1, 3, 1, |_, _, _| reports += 1)
            .unwrap();

        assert_eq!(blocks, 2, "two blocks had bodies");
        assert_eq!(txs, 4, "two transactions each");
        assert_eq!(skipped, 1, "#2 has no canonical hash and must be skipped, not fatal");
        assert!(reports > 0, "progress must be reported");

        for (tx_hash, block_hash, index) in expected {
            let found = store.tx_location(tx_hash).unwrap();
            assert_eq!(found, Some((block_hash, index)), "every transaction must be findable");
        }
    }

    /// A scan by event type must return only that event, in block order, and
    /// must stop at the range end rather than walking the rest of the index.
    #[test]
    fn bridge_events_scan_by_type_and_range() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let pegin = B256::repeat_byte(0xA1);
        let pegout = B256::repeat_byte(0xB2);
        let txh = B256::repeat_byte(0xCC);

        for (topic, block) in [(pegin, 10u64), (pegout, 11), (pegin, 12), (pegin, 500), (pegout, 501)] {
            store.put_bridge_event(topic, block, 0, 0, txh, &[topic], b"payload").unwrap();
        }

        let all = store.scan_bridge_events(pegin, 0, u64::MAX).unwrap();
        assert_eq!(all.iter().map(|e| e.0).collect::<Vec<_>>(), vec![10, 12, 500],
                   "only peg-ins, in block order");
        assert_eq!(all[0].3, txh);
        assert_eq!(all[0].5, b"payload");

        let bounded = store.scan_bridge_events(pegin, 11, 499).unwrap();
        assert_eq!(bounded.iter().map(|e| e.0).collect::<Vec<_>>(), vec![12],
                   "range must bound both ends");

        let none = store.scan_bridge_events(B256::repeat_byte(0xFF), 0, u64::MAX).unwrap();
        assert!(none.is_empty(), "an event type never seen returns nothing");
    }

    /// Only the Bridge's own logs are indexed; a log from another contract in
    /// the same receipt must not appear.
    #[test]
    fn index_bridge_events_ignores_other_contracts() {
        use rustock_core::Log;
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let bridge = Address::repeat_byte(0x06);
        let other = Address::repeat_byte(0x99);
        let topic = B256::repeat_byte(0xA1);

        let receipt = Receipt {
            post_tx_state: vec![1], cumulative_gas_used: 0, gas_used: 0,
            logs_bloom: alloy_primitives::Bloom::ZERO, status: true,
            logs: vec![
                Log { address: other,  topics: vec![topic], data: vec![].into() },
                Log { address: bridge, topics: vec![topic], data: b"mine".to_vec().into() },
            ],
        };
        let n = store.index_bridge_events(7, &[receipt], &[], bridge).unwrap();
        assert_eq!(n, 1, "exactly one Bridge log");

        let found = store.scan_bridge_events(topic, 0, u64::MAX).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 7);
        assert_eq!(found[0].5, b"mine");
        assert_eq!(found[0].2, 1, "log index within the receipt is preserved");
    }

    #[test]
    fn test_tx_index_put_and_get() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let tx_hash = B256::repeat_byte(0x11);
        let block_hash = B256::repeat_byte(0x22);
        let tx_index = 5u32;

        store.put_tx_index(tx_hash, block_hash, tx_index).unwrap();

        let (found_block, found_idx) = store.tx_location(tx_hash).unwrap().unwrap();
        assert_eq!(found_block, block_hash);
        assert_eq!(found_idx, tx_index);
    }

    #[test]
    fn test_tx_index_not_found() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert!(store.tx_location(B256::repeat_byte(0xFF)).unwrap().is_none());
    }

    #[test]
    fn test_index_block_transactions() {
        use sha3::{Digest, Keccak256};

        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let block_hash = B256::repeat_byte(0x33);
        let txs = vec![dummy_tx(0), dummy_tx(1), dummy_tx(2)];

        store.index_block_transactions(block_hash, &txs).unwrap();

        for (i, tx) in txs.iter().enumerate() {
            let mut buf = Vec::new();
            tx.encode(&mut buf);
            let tx_hash = B256::from_slice(&Keccak256::digest(&buf));

            let (found_block, found_idx) = store.tx_location(tx_hash).unwrap().unwrap();
            assert_eq!(found_block, block_hash);
            assert_eq!(found_idx, i as u32);
        }
    }

    #[test]
    fn test_tx_index_overwrite() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let tx_hash = B256::repeat_byte(0x44);
        let block_a = B256::repeat_byte(0xAA);
        let block_b = B256::repeat_byte(0xBB);

        store.put_tx_index(tx_hash, block_a, 0).unwrap();
        store.put_tx_index(tx_hash, block_b, 3).unwrap();

        let (found_block, found_idx) = store.tx_location(tx_hash).unwrap().unwrap();
        assert_eq!(found_block, block_b);
        assert_eq!(found_idx, 3);
    }

    // ── the block-height index ────────────────────────────────────────

    /// The point of the index: `block_numbers` names the one canonical block
    /// at a height, this names them all. Uncle selection needs the ones that
    /// lost, which the canonical pointer by definition does not mention.
    #[test]
    fn height_index_returns_every_block_at_a_height_not_just_the_canonical_one() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mut winner = dummy_header(7);
        winner.extra_data = Bytes::from_static(b"winner");
        let mut loser = dummy_header(7);
        loser.extra_data = Bytes::from_static(b"loser");
        assert_ne!(winner.hash(), loser.hash());

        store.put_header(&winner).unwrap();
        store.put_header(&loser).unwrap();
        store.put_canonical_hash(7, winner.hash()).unwrap();

        assert_eq!(store.canonical_hash(7).unwrap(), Some(winner.hash()));

        let mut at_seven = store.hashes_at_height(7).unwrap();
        at_seven.sort();
        let mut expected = vec![winner.hash(), loser.hash()];
        expected.sort();
        assert_eq!(at_seven, expected, "both blocks at #7 must be findable");
    }

    #[test]
    fn height_index_does_not_bleed_between_heights() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        for number in [8u64, 9, 10] {
            store.put_header(&dummy_header(number)).unwrap();
        }

        assert_eq!(store.hashes_at_height(9).unwrap().len(), 1);
        assert_eq!(store.hashes_at_height(9).unwrap()[0], dummy_header(9).hash());
        assert!(store.hashes_at_height(11).unwrap().is_empty());
    }

    /// Indexing the same block twice must not duplicate it: the key is derived
    /// from the block, so a re-run of the backfill overwrites rather than
    /// appends. This is what makes an interrupted upgrade safe to repeat.
    #[test]
    fn height_index_entries_are_idempotent() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(3);
        store.put_header(&header).unwrap();
        store.put_header(&header).unwrap();
        store.index_block_height(3, header.hash()).unwrap();

        assert_eq!(store.hashes_at_height(3).unwrap().len(), 1);
    }

    /// Fork headers arrive through the batch path during sync, and they are
    /// exactly the blocks uncle selection is looking for.
    #[test]
    fn header_batches_are_indexed_by_height() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mut a = dummy_header(4);
        a.extra_data = Bytes::from_static(b"a");
        let mut b = dummy_header(4);
        b.extra_data = Bytes::from_static(b"b");

        store
            .store_headers_batch(&[(&a, U256::from(10)), (&b, U256::from(5))], None, U256::ZERO)
            .unwrap();

        assert_eq!(store.hashes_at_height(4).unwrap().len(), 2);
    }

    /// The upgrade path for a database synced before the index existed:
    /// headers are already there, the index is not, and building it must find
    /// every one of them.
    #[test]
    fn the_index_can_be_built_from_headers_alone() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Write headers the way a pre-index build would have: straight into
        // the headers column family, with no index entry.
        let headers: Vec<Header> = (1..=5).map(dummy_header).collect();
        for header in &headers {
            let buf = encode_header(header);
            store
                .db
                .put_cf(store.cf(CF_HEADERS).unwrap(), header.hash().as_slice(), &buf)
                .unwrap();
        }

        assert!(store.height_index_is_empty().unwrap(), "no index yet");
        assert!(store.hashes_at_height(3).unwrap().is_empty());

        let indexed = store.build_height_index(0, |_| {}).unwrap();
        assert_eq!(indexed, 5);
        assert!(!store.height_index_is_empty().unwrap());

        for header in &headers {
            assert_eq!(
                store.hashes_at_height(header.number).unwrap(),
                vec![header.hash()],
                "#{} must be indexed",
                header.number
            );
        }
    }

    /// A read-only open must name every column family it wants and fails if
    /// one is absent, so a database written before the height index existed
    /// would have stopped opening read-only the moment this shipped -- taking
    /// every diagnostic that reads a running node's blocks with it.
    #[test]
    fn a_database_without_the_index_still_opens_read_only() {
        let dir = tempdir().unwrap();

        // A database as it was before the index: the old column families only.
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let legacy = vec![
                ColumnFamilyDescriptor::new(CF_HEADERS, Options::default()),
                ColumnFamilyDescriptor::new(CF_NUMBERS, Options::default()),
                ColumnFamilyDescriptor::new(CF_TD, Options::default()),
                ColumnFamilyDescriptor::new(CF_BODIES, Options::default()),
                ColumnFamilyDescriptor::new(CF_RECEIPTS, Options::default()),
                ColumnFamilyDescriptor::new(CF_TX_INDEX, Options::default()),
                ColumnFamilyDescriptor::new(CF_BRIDGE_EVENTS, Options::default()),
                ColumnFamilyDescriptor::new("trie_nodes", Options::default()),
            ];
            let db = DB::open_cf_descriptors(&opts, dir.path(), legacy).unwrap();
            let header = dummy_header(1);
            db.put_cf(
                db.cf_handle(CF_HEADERS).unwrap(),
                header.hash().as_slice(),
                encode_header(&header),
            )
            .unwrap();
        }

        let store = BlockStore::open_read_only(dir.path())
            .expect("a database without the height index must still open read-only");
        assert!(store.header(dummy_header(1).hash()).unwrap().is_some());

        // Opening it read-write adds the column family, and the backfill then
        // has something to do.
        drop(store);
        let store = BlockStore::open(dir.path()).unwrap();
        assert!(store.height_index_is_empty().unwrap());
        assert_eq!(store.build_height_index(0, |_| {}).unwrap(), 1);
        assert_eq!(store.hashes_at_height(1).unwrap(), vec![dummy_header(1).hash()]);
    }

    /// An interrupted upgrade leaves a partial index; running it again must
    /// complete it rather than double-count or corrupt what is there.
    #[test]
    fn building_the_index_twice_is_safe() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        for number in 1..=4 {
            store.put_header(&dummy_header(number)).unwrap();
        }

        let first = store.build_height_index(0, |_| {}).unwrap();
        let second = store.build_height_index(0, |_| {}).unwrap();
        assert_eq!(first, second);

        for number in 1..=4 {
            assert_eq!(store.hashes_at_height(number).unwrap().len(), 1);
        }
    }
}

#[cfg(test)]
mod read_threads_tests {
    /// One test, not two: the setting is process-wide, and cargo runs tests
    /// in parallel, so two tests touching it would race each other.
    #[test]
    fn the_setting_defaults_to_what_was_hardcoded_and_clamps_zero() {
        // The default is the value that was hardcoded before this was
        // configurable, so an operator who changes nothing gets the behaviour
        // that was measured.
        assert_eq!(super::read_threads(), 16);

        // Zero would divide the work into no pieces. A misconfiguration
        // should be slow, not a panic.
        super::set_read_threads(0);
        assert_eq!(super::read_threads(), 1);

        super::set_read_threads(4);
        assert_eq!(super::read_threads(), 4);

        super::set_read_threads(16);
    }
}

#[cfg(test)]
mod canonical_hash_freezer_tests {
    use super::*;
    use crate::freezer::Freezer;

    /// A frozen height answers `canonical_hash` without a `CF_NUMBERS` entry.
    ///
    /// This is what lets a snapshot-synced node skip building the index for
    /// the whole chain -- hours during which it could not follow the tip
    /// (#195). Being in the freezer *is* the statement that a height is
    /// canonical: nothing else is ever written there.
    #[test]
    fn a_frozen_height_answers_without_a_numbers_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path().join("db").to_str().unwrap()).unwrap();

        let freezer = Arc::new(Freezer::open(dir.path().join("freezer")).unwrap());
        let header = crate::freezer::tests::test_header(7);
        let expected = header.hash();
        freezer.put(7, &header).unwrap();
        freezer.sync().unwrap();

        // Without the freezer attached there is no answer at all.
        assert_eq!(store.canonical_hash(7).unwrap(), None);

        store.set_freezer(freezer);
        assert_eq!(
            store.canonical_hash(7).unwrap(),
            Some(expected),
            "a frozen header should answer for its own height"
        );
        assert_eq!(
            store.canonical_hash(8).unwrap(),
            None,
            "a height nobody froze still has no answer"
        );
    }

    /// `CF_NUMBERS` stays the authority where it has an entry.
    #[test]
    fn the_database_wins_over_the_freezer() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path().join("db").to_str().unwrap()).unwrap();

        let freezer = Arc::new(Freezer::open(dir.path().join("freezer")).unwrap());
        freezer.put(7, &crate::freezer::tests::test_header(7)).unwrap();
        freezer.sync().unwrap();
        store.set_freezer(freezer);

        let authoritative = B256::repeat_byte(0xCD);
        store.put_canonical_hash(7, authoritative).unwrap();
        assert_eq!(store.canonical_hash(7).unwrap(), Some(authoritative));
    }
}

#[cfg(test)]
mod frozen_delete_tests {
    use super::*;
    use crate::freezer::Freezer;

    fn setup() -> (tempfile::TempDir, BlockStore, Arc<Freezer>) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path().join("db").to_str().unwrap()).unwrap();
        let freezer = Arc::new(Freezer::open(dir.path().join("freezer")).unwrap());
        for n in 0..100 {
            let h = crate::freezer::tests::test_header(n);
            store.put_header_with_hash(h.hash(), &h).unwrap();
            freezer.put(n, &h).unwrap();
        }
        freezer.sync().unwrap();
        store.set_freezer(freezer.clone());
        (dir, store, freezer)
    }

    /// A deleted header is still found by hash, through the index the delete
    /// wrote before removing it.
    #[test]
    fn a_deleted_header_is_still_found_by_hash() {
        let (_d, store, _f) = setup();
        let wanted = crate::freezer::tests::test_header(42);
        let hash = wanted.hash();
        assert!(store.header(hash).unwrap().is_some(), "present to begin with");

        let n = store.delete_frozen_headers(100, 1000).unwrap();
        assert_eq!(n, 100);

        let got = store
            .header(hash)
            .unwrap()
            .expect("a frozen header must still be findable by hash");
        assert_eq!(got.number, 42);
    }

    /// Deletion never runs ahead of the freezer.
    #[test]
    fn nothing_is_deleted_that_the_freezer_cannot_answer_for() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path().join("db").to_str().unwrap()).unwrap();
        let freezer = Arc::new(Freezer::open(dir.path().join("freezer")).unwrap());

        // Headers 0..50 in both; 50..100 only in the database.
        for n in 0..100 {
            let h = crate::freezer::tests::test_header(n);
            store.put_header_with_hash(h.hash(), &h).unwrap();
            if n < 50 {
                freezer.put(n, &h).unwrap();
            }
        }
        freezer.sync().unwrap();
        store.set_freezer(freezer);

        // Asked to go to 100, it stops where the freezer stops.
        assert_eq!(store.delete_frozen_headers(100, 1000).unwrap(), 50);

        let unfrozen = crate::freezer::tests::test_header(70);
        assert!(
            store.header(unfrozen.hash()).unwrap().is_some(),
            "an unfrozen header must not be deleted"
        );
    }

    /// With no freezer attached, nothing is deleted at all.
    #[test]
    fn without_a_freezer_it_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path().join("db").to_str().unwrap()).unwrap();
        let h = crate::freezer::tests::test_header(1);
        store.put_header_with_hash(h.hash(), &h).unwrap();
        assert_eq!(store.delete_frozen_headers(100, 1000).unwrap(), 0);
        assert!(store.header(h.hash()).unwrap().is_some());
    }

    /// It resumes rather than restarting.
    #[test]
    fn it_resumes_from_its_cursor() {
        let (_d, store, _f) = setup();
        assert_eq!(store.delete_frozen_headers(100, 30).unwrap(), 30);
        assert_eq!(store.frozen_delete_cursor().unwrap(), 30);
        assert_eq!(store.delete_frozen_headers(100, 30).unwrap(), 30);
        assert_eq!(store.frozen_delete_cursor().unwrap(), 60);
    }
}

#[cfg(test)]
mod total_difficulty_tests {
    use super::*;
    use super::tests::{dummy_header, make_chain_header};
    use tempfile::tempdir;

    /// An uncle's difficulty counts toward the including block's contribution,
    /// as rskj `Block.getCumulativeDifficulty()` does. rskj rejects a snap
    /// status response whose totals omit it, which is how this was found.
    #[test]
    fn cumulative_difficulty_includes_uncles() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mut uncle_a = dummy_header(4);
        uncle_a.difficulty = U256::from(7u64);
        let mut uncle_b = dummy_header(3);
        uncle_b.difficulty = U256::from(11u64);

        let mut h = make_chain_header(5, B256::ZERO, 100, 0x01);
        h.uncle_count = 2;
        let hash = h.hash();
        store.put_header_with_hash(hash, &h).unwrap();
        store.put_body(hash, &[], &[uncle_a, uncle_b]).unwrap();

        assert_eq!(
            store.cumulative_difficulty(hash, &h).unwrap(),
            Some(U256::from(118u64)),
            "100 + 7 + 11"
        );
    }

    /// A header that declares no uncles needs no body read, so a pruned node
    /// still gets an exact answer for the blocks that absorbed nothing.
    #[test]
    fn cumulative_difficulty_without_uncles_needs_no_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let h = make_chain_header(5, B256::ZERO, 100, 0x01);
        let hash = h.hash();
        store.put_header_with_hash(hash, &h).unwrap();
        // No body stored at all.
        assert_eq!(store.cumulative_difficulty(hash, &h).unwrap(), Some(U256::from(100u64)));
    }

    /// The uncle difficulties are unrecoverable once the body is gone, so the
    /// answer is "cannot say", never the header difficulty alone. Returning the
    /// undercount silently is the bug this whole change exists to remove.
    #[test]
    fn cumulative_difficulty_is_unknown_when_the_body_is_pruned() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let mut h = make_chain_header(5, B256::ZERO, 100, 0x01);
        h.uncle_count = 1;
        let hash = h.hash();
        store.put_header_with_hash(hash, &h).unwrap();
        assert_eq!(store.cumulative_difficulty(hash, &h).unwrap(), None);
    }

    /// Build a chain whose stored totals omit the uncles -- the state every
    /// rustock database was in -- and check the repair rewrites them to the
    /// values rskj computes.
    #[test]
    fn repair_rewrites_totals_to_include_uncles() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mut parent = B256::ZERO;
        let mut wrong = U256::ZERO;
        let mut expected = Vec::new();
        let mut running = U256::ZERO;

        for n in 0..6u64 {
            let mut h = make_chain_header(n, parent, 100, 0x01);
            // Every other block absorbs one uncle worth 30.
            let uncles: Vec<Header> = if n % 2 == 1 {
                let mut u = dummy_header(n - 1);
                u.difficulty = U256::from(30u64);
                vec![u]
            } else {
                Vec::new()
            };
            h.uncle_count = uncles.len() as u64;
            let hash = h.hash();

            store.put_header_with_hash(hash, &h).unwrap();
            store.put_body(hash, &[], &uncles).unwrap();
            store.put_canonical_hash(n, hash).unwrap();

            // The old, wrong accumulation: header difficulty only.
            wrong += h.difficulty;
            store.put_total_difficulty(hash, wrong).unwrap();

            running += h.difficulty + U256::from(30u64) * U256::from(uncles.len() as u64);
            expected.push((hash, running));
            parent = hash;
        }
        store.set_head(parent).unwrap();

        // Precondition: the stored totals really are short.
        let (tip, want) = *expected.last().unwrap();
        assert_ne!(store.total_difficulty(tip).unwrap(), Some(want));

        let (written, _unchanged, absent) =
            store.recompute_total_difficulty(0, 5, 0, |_, _, _| {}).unwrap();
        assert_eq!(absent, 0);
        assert!(written > 0);

        for (hash, want) in expected {
            assert_eq!(store.total_difficulty(hash).unwrap(), Some(want));
        }
    }

    /// A snap-synced node holds nothing below its checkpoint. The repair must
    /// say so rather than reporting a clean run over blocks it never saw.
    #[test]
    fn repair_counts_heights_that_hold_no_block() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let h = make_chain_header(0, B256::ZERO, 100, 0x01);
        let hash = h.hash();
        store.put_header_with_hash(hash, &h).unwrap();
        store.put_canonical_hash(0, hash).unwrap();
        store.set_head(hash).unwrap();

        let (written, unchanged, absent) =
            store.recompute_total_difficulty(0, 99, 0, |_, _, _| {}).unwrap();
        assert_eq!(absent, 99, "heights 1..=99 hold nothing");
        assert_eq!(written + unchanged, 1);
    }

    /// The repair refuses to invent a total it cannot derive: a pruned body
    /// below the range stops it rather than letting the error propagate
    /// upward into every block above.
    #[test]
    fn repair_stops_at_a_block_whose_body_is_gone() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let mut parent = B256::ZERO;
        for n in 0..4u64 {
            let mut h = make_chain_header(n, parent, 100, 0x01);
            h.uncle_count = if n == 2 { 1 } else { 0 };
            let hash = h.hash();
            store.put_header_with_hash(hash, &h).unwrap();
            if n != 2 {
                store.put_body(hash, &[], &[]).unwrap();
            }
            store.put_canonical_hash(n, hash).unwrap();
            store.put_total_difficulty(hash, U256::from((n + 1) * 100)).unwrap();
            parent = hash;
        }
        store.set_head(parent).unwrap();

        let err = store.recompute_total_difficulty(0, 3, 0, |_, _, _| {}).unwrap_err();
        assert!(err.to_string().contains("#2"), "names the block: {err}");
    }
}

#[cfg(test)]
mod chain_work_tests {
    use super::*;
    use super::tests::{dummy_header, make_chain_header};
    use crate::freezer::Freezer;
    use tempfile::tempdir;

    /// One pass must leave both halves right: the uncles in the freezer, and
    /// totals that counted them.
    #[test]
    fn one_pass_freezes_uncles_and_fixes_totals() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let fdir = tempdir().unwrap();
        store.set_freezer(Arc::new(Freezer::open(fdir.path()).unwrap()));

        let mut parent = B256::ZERO;
        let mut wrong = U256::ZERO;
        let mut expected = Vec::new();
        let mut running = U256::ZERO;

        for n in 0..6u64 {
            let mut h = make_chain_header(n, parent, 100, 0x01);
            let uncles: Vec<Header> = if n % 2 == 1 {
                let mut u = dummy_header(n - 1);
                u.difficulty = U256::from(30u64);
                vec![u]
            } else {
                Vec::new()
            };
            h.uncle_count = uncles.len() as u64;
            let hash = h.hash();

            store.put_header_with_hash(hash, &h).unwrap();
            store.put_body(hash, &[], &uncles).unwrap();
            store.put_canonical_hash(n, hash).unwrap();

            wrong += h.difficulty;
            store.put_total_difficulty(hash, wrong).unwrap();

            running += h.difficulty + U256::from(30u64) * U256::from(uncles.len() as u64);
            expected.push((hash, running));
            parent = hash;
        }
        store.set_head(parent).unwrap();

        let (written, _unchanged, absent, frozen) =
            store.rebuild_chain_work(0, 5, 0, |_, _, _| {}).unwrap();
        assert_eq!(absent, 0);
        assert_eq!(frozen, 6, "every block's uncle list written, empty ones included");
        assert!(written > 0);

        for (hash, want) in expected {
            assert_eq!(store.total_difficulty(hash).unwrap(), Some(want));
        }

        let f = store.freezer().unwrap();
        assert_eq!(f.uncles(1).unwrap().unwrap().len(), 1);
        assert_eq!(f.uncles(2).unwrap(), Some(Vec::new()), "stored, and empty");
    }

    /// Once the uncles are frozen, a block whose body has been pruned still
    /// yields its contribution. This is the hole the uncle store closes: before
    /// it, a pruned node could never recompute its own chain's work.
    #[test]
    fn a_pruned_body_still_yields_its_contribution_from_the_freezer() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let fdir = tempdir().unwrap();
        let freezer = Arc::new(Freezer::open(fdir.path()).unwrap());
        store.set_freezer(freezer.clone());

        let mut uncle = dummy_header(4);
        uncle.difficulty = U256::from(30u64);
        let mut h = make_chain_header(5, B256::ZERO, 100, 0x01);
        h.uncle_count = 1;
        let hash = h.hash();
        store.put_header_with_hash(hash, &h).unwrap();

        // The body is gone, as on a pruned node.
        assert_eq!(store.cumulative_difficulty(hash, &h).unwrap(), None);

        freezer.put_uncles(5, &[uncle]).unwrap();
        freezer.sync().unwrap();

        assert_eq!(
            store.cumulative_difficulty(hash, &h).unwrap(),
            Some(U256::from(130u64)),
            "100 + 30, recovered from the freezer"
        );
    }

    /// Without a freezer there is nowhere to put the uncles, and a pass that
    /// quietly skipped them would leave totals nothing can re-derive.
    #[test]
    fn the_pass_refuses_to_run_without_a_freezer() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let err = store.rebuild_chain_work(0, 5, 0, |_, _, _| {}).unwrap_err();
        assert!(err.to_string().contains("freezer"), "{err}");
    }
}
