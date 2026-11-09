//! Old headers, stored in flat files instead of the LSM tree.
//!
//! # The problem this solves
//!
//! Headers live in `CF_HEADERS`, keyed by block hash. Hashes are uniformly
//! distributed, so consecutive blocks share neither a data block nor usually a
//! file. Serving the 192 headers a peer asks for is therefore 192 unrelated
//! point lookups, and each one pulls a whole RocksDB data block off the disk to
//! return ~1.1 KB of header. Measured on this database: **6.5x read
//! amplification**, ~7.1 KB read per header delivered.
//!
//! The amplification is not a tuning problem. It follows from the key: a hash
//! index cannot answer "the headers from N downwards" as a range, because the
//! keys are not ordered by anything the question mentions.
//!
//! # The shape
//!
//! Canonical headers below a threshold are append-only and never change, so
//! they can be stored the way the question asks for them: **by block number, in
//! order, contiguously**. A run of headers becomes one index read and one
//! sequential data read.
//!
//! Two file series, following geth's freezer:
//!
//! - `headers-NNNN.cdat` — the RLP bodies, concatenated, capped at
//!   [`MAX_DATA_FILE_BYTES`] so no single file grows without bound.
//! - `headers.cidx` — a fixed-width index, [`INDEX_ENTRY_BYTES`] per block:
//!   a 2-byte file number and the 4-byte `start` and `end` offsets of that
//!   block's data.
//!
//! Entry `N` is at byte `N * 10`, so finding block `N` is arithmetic rather
//! than a search, and the run `N..N+k` is one read of `k * 10` bytes.
//!
//! # Why each entry carries its own start
//!
//! geth stores only the end offset and takes block `N`'s start from block
//! `N-1`'s end. That is two bytes cheaper and it forces the data to be written
//! in ascending order, which this node cannot promise: a snapshot sync walks
//! the header chain **downwards**, from the tip to genesis, verifying
//! `parent_hash` as it goes. Buffering that walk to re-emit it ascending would
//! mean holding every header from the tip to block 0 -- 8.8 million of them,
//! about 9.7 GB -- before the first append became legal.
//!
//! Carrying both offsets makes the format indifferent to arrival order. A
//! descending walk writes its run backwards through the file and a run is
//! still one contiguous read, because what matters is that a single walk's
//! blocks are adjacent, not that they ascend.
//!
//! An entry of all zeroes means "not here". Block 0 cannot collide with that
//! because its `end` is past its `start`, and the index file is sparse: a hole
//! reads as zeroes, so a number never written simply reports absent.
//!
//! # What is not here
//!
//! **Nothing is deleted from RocksDB.** geth deletes after fsync, and can,
//! because it keeps a hash-to-number index to redirect lookups by hash. This
//! database has no such index -- `CF_HEIGHT_INDEX` maps number to hashes, the
//! wrong direction -- so deleting `CF_HEADERS` would break every lookup by
//! hash. The duplication costs about 10 GB against a measured read win; closing
//! that gap needs the reverse index first, and is deliberately separate work.
//!
//! **Only canonical headers.** A header that is not canonical at its height has
//! no place in a file addressed by height. Those stay in RocksDB, which is also
//! where a reorg goes looking for them.

use alloy_primitives::B256;
use anyhow::{anyhow, bail, Context, Result};
use rustock_core::config::ActivationHeights;
use rustock_core::Header;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Bytes per index entry: a 2-byte file number, then 4-byte `start` and `end`.
///
/// The offsets bound a data file at 4 GiB, which [`MAX_DATA_FILE_BYTES`] stays
/// well under, and the file number allows 65,536 files -- far more than a
/// chain of this size will ever need.
pub const INDEX_ENTRY_BYTES: u64 = 10;

/// Bytes to accumulate before touching the data file.
///
/// A header is about 1.1 KB, so writing each one through on its own would mean
/// a syscall and an `fsync` per block: 8.8 million of each for a chain of this
/// size, which is slower than the random reads the freezer exists to avoid.
/// Buffering to 8 MB makes it roughly 1,200 flushes for the whole chain, each
/// one a sequential write of about 7,300 headers.
///
/// The buffer is also what makes the crash rule cheap to honour: data is
/// flushed and synced first, and only then are that batch's index entries
/// written, so a crash can orphan data but can never publish an index entry
/// pointing at bytes that are not there.
pub const WRITE_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Roll to a new data file past this size.
///
/// geth uses 2 GB. The only thing the size decides is how many files a
/// directory listing has to show and how much a single corrupt file costs;
/// reads are addressed through the index either way.
pub const MAX_DATA_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How far behind the head a block must be before it is frozen.
///
/// One week at Rootstock's measured 30.3-second block time (19,964 blocks over
/// the 100,000 blocks to 2026-09-28), rounded.
///
/// There is no finality gadget here, so this cannot key off finality the way
/// geth and reth do. It is instead anchored against what this node already
/// treats as settled:
///
/// | constant | value | meaning |
/// |---|---|---|
/// | `MAX_REORG_DEPTH` | 1,000 | deepest reorg the canonical index will follow |
/// | `MIN_KEEP_DEPTH` | 8,000 | the floor block pruning refuses to cross |
///
/// 20,000 is 20x the first and 2.5x the second, so a frozen block is one the
/// rest of the node has already stopped expecting to change.
pub const FREEZE_DEPTH: u64 = 20_000;

/// Opens one of the parallel stores, repairing an interrupted append.
///
/// The index is the authority. Anything in the data file past the furthest
/// point any entry accounts for is a partial write from a process that died,
/// and is discarded: an unreferenced tail costs nothing, while an index entry
/// pointing past the data is unreadable.
fn open_store(dir: &Path, prefix: &str, kind: &str) -> Result<Writable> {
    let index_path = dir.join(format!("{prefix}{kind}.cidx"));
    let mut index = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&index_path)
        .with_context(|| format!("opening {}", index_path.display()))?;

    let mut index_len = index.metadata()?.len();

    // A torn index write leaves a partial entry; drop it.
    let ragged = index_len % INDEX_ENTRY_BYTES;
    if ragged != 0 {
        index_len -= ragged;
        index.set_len(index_len)?;
        index.sync_all()?;
    }
    let end_number = index_len / INDEX_ENTRY_BYTES;

    let file_number = newest_data_file(dir, prefix, kind);

    let data_path = dir.join(format!("{prefix}{kind}-{file_number:04}.cdat"));
    let data = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&data_path)
        .with_context(|| format!("opening {}", data_path.display()))?;

    let covered = furthest_end(&mut index, end_number, file_number)?;
    if data.metadata()?.len() > covered as u64 {
        data.set_len(covered as u64)?;
        data.sync_all()?;
    }

    Ok(Writable {
        index,
        data,
        file_number,
        data_len: covered,
        end_number,
        pending_data: Vec::with_capacity(WRITE_BUFFER_BYTES),
        pending_index: Vec::new(),
    })
}

/// The newest data file on disk: the index does not record which one is
/// being appended to, only where each block landed.
fn newest_data_file(dir: &Path, prefix: &str, kind: &str) -> u16 {
    let mut file_number = 0u16;
    for n in 0..=u16::MAX {
        if dir.join(format!("{prefix}{kind}-{n:04}.cdat")).exists() {
            file_number = n;
        } else if n > 0 {
            break;
        }
    }
    file_number
}

/// Opens one of the parallel stores to read only.
///
/// Nothing is created and nothing is repaired. In a freezer another process
/// has open, data past the index's last entry is that writer's append in
/// progress, and a ragged index tail its entry half-written: `open_store`
/// would cut both away, so this leaves both alone and counts whole entries.
fn open_store_read_only(dir: &Path, prefix: &str, kind: &str) -> Result<Writable> {
    let index_path = dir.join(format!("{prefix}{kind}.cidx"));
    let index =
        File::open(&index_path).with_context(|| format!("opening {}", index_path.display()))?;
    let end_number = index.metadata()?.len() / INDEX_ENTRY_BYTES;

    let file_number = newest_data_file(dir, prefix, kind);
    let data_path = dir.join(format!("{prefix}{kind}-{file_number:04}.cdat"));
    let data =
        File::open(&data_path).with_context(|| format!("opening {}", data_path.display()))?;
    let data_len = u32::try_from(data.metadata()?.len()).unwrap_or(u32::MAX);

    Ok(Writable {
        index,
        data,
        file_number,
        data_len,
        end_number,
        pending_data: Vec::new(),
        pending_index: Vec::new(),
    })
}

/// Where one block's data is: which file, and the byte range within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexEntry {
    file: u16,
    start: u32,
    end: u32,
}

impl IndexEntry {
    fn decode(bytes: &[u8]) -> Self {
        Self {
            file: u16::from_be_bytes([bytes[0], bytes[1]]),
            start: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            end: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
        }
    }

    fn encode(&self) -> [u8; INDEX_ENTRY_BYTES as usize] {
        let f = self.file.to_be_bytes();
        let s = self.start.to_be_bytes();
        let e = self.end.to_be_bytes();
        [f[0], f[1], s[0], s[1], s[2], s[3], e[0], e[1], e[2], e[3]]
    }

    /// A hole in the sparse index, or a number never written.
    fn is_absent(&self) -> bool {
        self.end == 0 && self.start == 0
    }
}

/// The append-only side, behind one lock.
struct Writable {
    index: File,
    data: File,
    /// Which data file `data` is.
    file_number: u16,
    /// How many bytes are in it.
    data_len: u32,
    /// One past the highest block number written, so the index length is
    /// known without stat'ing the file.
    end_number: u64,
    /// Header bytes not yet handed to the data file.
    pending_data: Vec<u8>,
    /// Index entries for the blocks sitting in `pending_data`, which must not
    /// be published until that data is durable.
    pending_index: Vec<(u64, IndexEntry)>,
}

/// Flat-file storage for canonical headers below the freeze threshold.
pub struct Freezer {
    dir: PathBuf,
    /// Prepended to every filename.
    ///
    /// Empty for the real freezer. A staging freezer gets one naming the
    /// checkpoint it is being built against, so its files sit beside the real
    /// ones without being them, and are recognisable as not-yet-trusted to
    /// anything that finds them later.
    prefix: String,
    write: Mutex<Writable>,
    /// The uncle headers each frozen block references, in parallel files.
    ///
    /// Uncle headers live nowhere else once a body is pruned: the header
    /// commits to them through `ommers_hash` and records only `uncle_count`,
    /// and an uncle is never canonical so it has no height slot of its own.
    /// Without this, a node that has frozen its headers and pruned its bodies
    /// can neither recompute total difficulty nor prove the uncles its chain
    /// absorbed ever existed.
    uncles: Mutex<Writable>,
    /// Opened by [`Freezer::open_read_only`]: every write is refused.
    read_only: bool,
    /// The heights headers are read under: see [`Freezer::with_activations`].
    activations: Option<ActivationHeights>,
}

/// File-name stems for the two parallel stores.
const HEADERS: &str = "headers";
const UNCLES: &str = "uncles";

impl Freezer {
    /// Opens, or creates, a freezer in `dir`.
    ///
    /// A freezer that was interrupted mid-append is repaired here: the index is
    /// the authority, and any data past what the last index entry accounts for
    /// is a partial write from a process that died, so it is truncated away.
    /// Doing it the other way round -- trusting the data -- would leave a
    /// header the index cannot address, which is worse than losing an append
    /// that can simply be redone.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_prefix(dir, "")
    }

    /// Opens the freezer in `dir` to read beside the node that writes it, as
    /// a diagnostic does.
    ///
    /// Nothing is created, repaired or written: see `open_store_read_only`.
    /// What it holds is the freezer as it stood when opened, and every write
    /// is refused before it touches a file.
    pub fn open_read_only(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let headers = open_store_read_only(&dir, "", HEADERS)?;
        let uncles = open_store_read_only(&dir, "", UNCLES)?;
        Ok(Self {
            dir,
            prefix: String::new(),
            write: Mutex::new(headers),
            uncles: Mutex::new(uncles),
            read_only: true,
            activations: None,
        })
    }

    /// This freezer reading its headers under `activations` rather than the
    /// process-wide heights, as
    /// [`BlockStore::with_activations`](crate::BlockStore::with_activations)
    /// does.
    pub fn with_activations(mut self, activations: ActivationHeights) -> Self {
        self.activations = Some(activations);
        self
    }

    /// The heights this freezer reads headers under.
    fn activations(&self) -> &ActivationHeights {
        match &self.activations {
            Some(activations) => activations,
            None => ActivationHeights::current(),
        }
    }

    /// Refuses a write to a freezer opened read-only. Rolling to a new data
    /// file opens it to create and truncate, which in another process's
    /// freezer is that writer's next file, so read-only handles alone would
    /// not be enough.
    fn writable(&self) -> Result<()> {
        if self.read_only {
            bail!("the freezer at {} is open read-only", self.dir.display());
        }
        Ok(())
    }

    /// Opens a staging freezer for a chain that is not yet trusted.
    ///
    /// A snapshot sync walks down from a checkpoint a *peer* offered. Each
    /// header is verified and linked, but the chain is only known to be this
    /// network's once the walk reaches ground the node already accepted --
    /// until then a lying peer's well-formed headers look exactly like real
    /// ones.
    ///
    /// Writing them into a separate set of files, named for the checkpoint
    /// they rest on, means a walk that turns out to be wrong costs only those
    /// files. [`Freezer::promote`] renames them into place when the walk
    /// succeeds; [`Freezer::discard_staging`] removes them when it does not,
    /// and is also what cleans up after a process that died mid-walk.
    ///
    /// The alternative -- writing into the real files behind a marker -- would
    /// have to discard the *whole* freezer on failure, including millions of
    /// headers frozen legitimately before the walk began.
    /// The files are named for both the checkpoint's height and its hash.
    /// The hash alone would be unique, but these files can outlive the process
    /// that wrote them, and an operator who finds one should be able to tell
    /// what it is without opening it: which block a walk was resting on, and
    /// how far up the chain that was.
    pub fn open_staging(dir: impl AsRef<Path>, number: u64, checkpoint: B256) -> Result<Self> {
        Self::open_with_prefix(dir, &format!("staging-{number}-{checkpoint:x}-"))
    }

    fn open_with_prefix(dir: impl AsRef<Path>, prefix: &str) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let prefix = prefix.to_string();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating freezer directory {}", dir.display()))?;

        let headers = open_store(&dir, &prefix, HEADERS)?;
        // The uncle store is addressed by the same block numbers and repaired
        // by the same rules, so it is the same format -- only the payload
        // differs. Keeping it in its own files means the header files, which
        // hold ten gigabytes on a mainnet node, are never rewritten to add it.
        let uncles = open_store(&dir, &prefix, UNCLES)?;

        Ok(Self {
            dir,
            prefix,
            write: Mutex::new(headers),
            uncles: Mutex::new(uncles),
            read_only: false,
            activations: None,
        })
    }

    /// Where this freezer's files live.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn index_path(&self) -> PathBuf {
        self.kind_index_path(HEADERS)
    }

    fn data_path(&self, file: u16) -> PathBuf {
        self.kind_data_path(HEADERS, file)
    }

    fn kind_index_path(&self, kind: &str) -> PathBuf {
        self.dir.join(format!("{}{kind}.cidx", self.prefix))
    }

    fn kind_data_path(&self, kind: &str, file: u16) -> PathBuf {
        self.dir.join(format!("{}{kind}-{file:04}.cdat", self.prefix))
    }

    /// Whether this freezer holds nothing.
    ///
    /// A walk only feeds a freezer that is empty: promotion renames files into
    /// place, which replaces rather than merges, so anything already frozen
    /// would be lost. A populated freezer is left to the background fill.
    pub fn is_empty(&self) -> bool {
        self.end_number() == 0
    }

    /// Renames a staging freezer's files into the real ones.
    ///
    /// Called once the walk has reached ground this node already accepted,
    /// which is the point at which the chain stops resting on a peer's word.
    /// Flushes first: renaming while the last batch is still in memory would
    /// publish files that do not hold what the index says they do.
    pub fn promote(&self) -> Result<()> {
        if self.prefix.is_empty() {
            return Ok(());
        }
        self.sync()?;

        // Both stores, each data-before-index as everywhere else here: an
        // index naming data that has not arrived is unreadable, while data
        // nothing names yet is merely unreferenced.
        for (store, kind) in [(&self.write, HEADERS), (&self.uncles, UNCLES)] {
            let files = store.lock().unwrap().file_number;
            for f in 0..=files {
                let from = self.kind_data_path(kind, f);
                if from.exists() {
                    let to = self.dir.join(format!("{kind}-{f:04}.cdat"));
                    std::fs::rename(&from, &to)
                        .with_context(|| format!("promoting {}", from.display()))?;
                }
            }
            let from = self.kind_index_path(kind);
            if from.exists() {
                let to = self.dir.join(format!("{kind}.cidx"));
                std::fs::rename(&from, &to)
                    .with_context(|| format!("promoting {}", to.display()))?;
            }
        }
        Ok(())
    }

    /// Removes every staging file in `dir`, whichever checkpoint they name.
    ///
    /// Run at start-up: a process that died mid-walk leaves its staging files
    /// behind, and nothing else will ever come back for them.
    pub fn discard_staging(dir: impl AsRef<Path>) -> usize {
        let dir = dir.as_ref();
        let mut dropped = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().starts_with("staging-") {
                    let _ = std::fs::remove_file(e.path());
                    dropped += 1;
                }
            }
        }
        dropped
    }

    /// One past the highest block number ever written.
    ///
    /// Not a count: the index is sparse, so a number below this may still be
    /// absent. Use [`Freezer::contains`] to ask about one block.
    pub fn end_number(&self) -> u64 {
        self.write.lock().unwrap().end_number
    }

    /// Whether this block's header is in the freezer.
    pub fn contains(&self, number: u64) -> bool {
        self.entry(number).map(|e| !e.is_absent()).unwrap_or(false)
    }

    fn entry(&self, number: u64) -> Option<IndexEntry> {
        let mut index = File::open(self.index_path()).ok()?;
        read_entry_at(&mut index, number).ok().filter(|e| !e.is_absent())
    }

    /// Stores the header for `number`, wherever the write head happens to be.
    ///
    /// Order does not matter to the format -- each entry carries its own byte
    /// range -- but it matters to performance: blocks written consecutively
    /// land consecutively, and only then is a run one read. Callers should
    /// feed a single walk without interleaving another.
    ///
    /// The write is buffered. Nothing reaches the disk until
    /// [`WRITE_BUFFER_BYTES`] have accumulated or [`Freezer::sync`] is called,
    /// and nothing is *readable* until then either -- a buffered block reports
    /// absent, because saying otherwise would promise a read that would fail.
    ///
    /// Writing a number twice overwrites its index entry and orphans the old
    /// data, which is wasteful but not wrong.
    pub fn put(&self, number: u64, header: &Header) -> Result<()> {
        self.put_bytes(&self.write, HEADERS, number, crate::encode_header(header))
    }

    /// Stores the uncle headers `number` references.
    ///
    /// Written as an RLP list of the uncles in the store's form
    /// ([`Header::encode_stored`]). A block with no uncles stores the empty
    /// list, `0xc0`, rather than nothing: a zero-length run would be
    /// indistinguishable from an index entry that was never written, and
    /// "this block has no uncles" and "this block is not frozen" must not be
    /// the same answer.
    pub fn put_uncles(&self, number: u64, uncles: &[Header]) -> Result<()> {
        let mut payload = Vec::new();
        for uncle in uncles {
            payload.extend_from_slice(&uncle.encode_stored());
        }
        let mut encoded = Vec::with_capacity(payload.len() + 9);
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut encoded);
        encoded.extend_from_slice(&payload);
        self.put_bytes(&self.uncles, UNCLES, number, encoded)
    }

    fn put_bytes(
        &self,
        store: &Mutex<Writable>,
        kind: &str,
        number: u64,
        encoded: Vec<u8>,
    ) -> Result<()> {
        self.writable()?;
        let mut w = store.lock().unwrap();

        // Roll before writing, never across: a header must be contiguous
        // within one file, or one read cannot answer for it. The pending
        // buffer belongs to the file it was written against, so it goes out
        // before the roll.
        let after = w.data_len as u64 + w.pending_data.len() as u64 + encoded.len() as u64;
        if after > MAX_DATA_FILE_BYTES {
            self.flush_locked(kind, &mut w)?;
            let next = w
                .file_number
                .checked_add(1)
                .context("freezer is out of data files")?;
            let path = self.kind_data_path(kind, next);
            w.data = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .with_context(|| format!("opening {}", path.display()))?;
            w.file_number = next;
            w.data_len = 0;
        }

        let start = w.data_len + w.pending_data.len() as u32;
        let end = start + encoded.len() as u32;
        w.pending_data.extend_from_slice(&encoded);
        let entry = IndexEntry { file: w.file_number, start, end };
        w.pending_index.push((number, entry));
        w.end_number = w.end_number.max(number + 1);

        if w.pending_data.len() >= WRITE_BUFFER_BYTES {
            self.flush_locked(kind, &mut w)?;
        }
        Ok(())
    }

    /// Writes the buffered batch: data first and synced, then its index
    /// entries.
    ///
    /// The ordering is the whole crash story. Data with no index entry is
    /// unreferenced and `open` discards it; an index entry with no data behind
    /// it would be an unreadable header that nothing detects until a peer asks
    /// for it.
    fn flush_locked(&self, _kind: &str, w: &mut Writable) -> Result<()> {
        if w.pending_data.is_empty() {
            return Ok(());
        }
        let at = w.data_len as u64;
        w.data.seek(SeekFrom::Start(at))?;
        let buf = std::mem::take(&mut w.pending_data);
        w.data.write_all(&buf)?;
        w.data.sync_all()?;
        w.data_len += buf.len() as u32;
        w.pending_data = buf;
        w.pending_data.clear();

        let entries = std::mem::take(&mut w.pending_index);
        for (number, entry) in &entries {
            w.index.seek(SeekFrom::Start(number * INDEX_ENTRY_BYTES))?;
            w.index.write_all(&entry.encode())?;
        }
        Ok(())
    }

    /// Writes out whatever is buffered and makes all of it durable.
    ///
    /// Call this at a point where losing the batch would be a nuisance -- the
    /// end of a sync phase, or shutdown. Losing it is never a correctness
    /// problem: unflushed blocks were never published, so the freezer simply
    /// does not have them, and whatever fills it will write them again.
    pub fn sync(&self) -> Result<()> {
        let mut w = self.write.lock().unwrap();
        self.flush_locked(HEADERS, &mut w)?;
        w.index.sync_all()?;
        drop(w);

        let mut u = self.uncles.lock().unwrap();
        self.flush_locked(UNCLES, &mut u)?;
        u.index.sync_all()?;
        Ok(())
    }

    /// The uncle headers for one block, if they are frozen.
    ///
    /// `Some(vec![])` means the block referenced no uncles; `None` means this
    /// block's uncles are not in the freezer at all. The two are different
    /// answers and a caller computing total difficulty must not confuse them.
    pub fn uncles(&self, number: u64) -> Result<Option<Vec<Header>>> {
        let Some(bytes) = self.read_one(&self.uncles, UNCLES, number)? else {
            return Ok(None);
        };
        let mut buf = bytes.as_slice();
        let h = alloy_rlp::Header::decode(&mut buf)
            .map_err(|e| anyhow!("decoding frozen uncle list for #{number}: {e:?}"))?;
        if !h.list || buf.len() < h.payload_length {
            bail!("frozen uncle list for #{number} is malformed");
        }
        let mut body = &buf[..h.payload_length];
        let mut out = Vec::new();
        while !body.is_empty() {
            out.push(
                Header::decode_with_hash_in(
                    &mut body,
                    self.activations(),
                    rustock_core::types::header::HeaderForm::Stored,
                )
                    .map_err(|e| anyhow!("decoding frozen uncle for #{number}: {e:?}"))?,
            );
        }
        Ok(Some(out))
    }

    /// One block's stored bytes from `store`, flushing first so that a value
    /// written moments ago is visible.
    fn read_one(
        &self,
        store: &Mutex<Writable>,
        kind: &str,
        number: u64,
    ) -> Result<Option<Vec<u8>>> {
        {
            let mut w = store.lock().unwrap();
            self.flush_locked(kind, &mut w)?;
        }
        let mut index = match File::open(self.kind_index_path(kind)) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let entry = match read_entry_at(&mut index, number) {
            Ok(e) if !e.is_absent() => e,
            _ => return Ok(None),
        };
        let mut data = match File::open(self.kind_data_path(kind, entry.file)) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let len = entry.end.saturating_sub(entry.start) as usize;
        let mut buf = vec![0u8; len];
        data.seek(SeekFrom::Start(entry.start as u64))?;
        data.read_exact(&mut buf)?;
        Ok(Some(buf))
    }

    /// The header for one block, if it is frozen.
    pub fn header(&self, number: u64) -> Result<Option<Header>> {
        Ok(self.run(number, 1)?.pop().flatten())
    }

    /// Headers for `count` blocks starting at `from`, ascending, positionally.
    ///
    /// This is the method the whole file format exists for. One index read
    /// covers the run; then, for each data file the run touches -- normally
    /// exactly one -- a single read spans from the lowest offset any of those
    /// blocks occupies to the highest, and each header is sliced out of it.
    ///
    /// That holds whichever direction the run was written in. A descending
    /// walk puts block `N+1` before block `N` in the file, but they are still
    /// adjacent, so the span is still one read.
    pub fn run(&self, from: u64, count: usize) -> Result<Vec<Option<Header>>> {
        let mut out: Vec<Option<Header>> = vec![None; count];
        if count == 0 {
            return Ok(out);
        }

        let end_number = self.end_number();
        if from >= end_number {
            return Ok(out);
        }
        let available = ((end_number - from) as usize).min(count);

        let mut index = File::open(self.index_path())?;
        let mut raw = vec![0u8; available * INDEX_ENTRY_BYTES as usize];
        index.seek(SeekFrom::Start(from * INDEX_ENTRY_BYTES))?;
        // A sparse tail may be shorter than asked for; a short read leaves
        // zeroes, which decode as absent, which is the truth.
        let got = read_up_to(&mut index, &mut raw)?;
        raw.truncate(got - got % INDEX_ENTRY_BYTES as usize);

        let entries: Vec<IndexEntry> = raw
            .chunks_exact(INDEX_ENTRY_BYTES as usize)
            .map(IndexEntry::decode)
            .collect();

        // Bucket the present entries by data file, keeping their slot.
        let mut by_file: std::collections::BTreeMap<u16, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (i, e) in entries.iter().enumerate() {
            if !e.is_absent() {
                by_file.entry(e.file).or_default().push(i);
            }
        }

        for (file, slots) in by_file {
            let lo = slots.iter().map(|i| entries[*i].start).min().unwrap();
            let hi = slots.iter().map(|i| entries[*i].end).max().unwrap();

            let path = self.data_path(file);
            let mut data = File::open(&path)
                .with_context(|| format!("opening {}", path.display()))?;
            let mut buf = vec![0u8; (hi - lo) as usize];
            data.seek(SeekFrom::Start(lo as u64))?;
            data.read_exact(&mut buf)?;

            for i in slots {
                let e = entries[i];
                let bytes = &buf[(e.start - lo) as usize..(e.end - lo) as usize];
                out[i] = decode_header(bytes, self.activations());
            }
        }

        Ok(out)
    }

    /// Drops frozen blocks from `number` upwards.
    ///
    /// Exists for the case the freeze threshold turns out to be wrong. At
    /// [`FREEZE_DEPTH`] it should never run, and a caller reaching for it
    /// should treat that as news.
    ///
    /// Only the index is cut. Data files are left alone: with arbitrary write
    /// order there is no single offset above which everything belongs to the
    /// dropped blocks, and unreferenced bytes cost only space.
    pub fn truncate_head(&self, number: u64) -> Result<()> {
        self.writable()?;
        // Both stores are addressed by block number, so a head that is rolled
        // back must drop the same range from each. Leaving uncles behind for a
        // header that no longer exists would make the uncle store answer for
        // blocks the freezer has disowned.
        for store in [&self.write, &self.uncles] {
            let mut w = store.lock().unwrap();
            if number >= w.end_number {
                continue;
            }
            w.index.set_len(number * INDEX_ENTRY_BYTES)?;
            w.index.sync_all()?;
            w.end_number = number;
        }
        Ok(())
    }

    /// Bytes held across all data files, headers and uncles together.
    pub fn data_bytes(&self) -> u64 {
        self.kind_data_bytes(&self.write, HEADERS) + self.kind_data_bytes(&self.uncles, UNCLES)
    }

    /// Bytes held by the header files alone.
    pub fn header_bytes(&self) -> u64 {
        self.kind_data_bytes(&self.write, HEADERS)
    }

    /// Bytes held by the uncle files alone.
    pub fn uncle_bytes(&self) -> u64 {
        self.kind_data_bytes(&self.uncles, UNCLES)
    }

    fn kind_data_bytes(&self, store: &Mutex<Writable>, kind: &str) -> u64 {
        let w = store.lock().unwrap();
        let mut total = w.data_len as u64;
        for f in 0..w.file_number {
            if let Ok(m) = std::fs::metadata(self.kind_data_path(kind, f)) {
                total += m.len();
            }
        }
        total
    }

    /// One past the highest block whose uncles are frozen.
    pub fn uncles_end_number(&self) -> u64 {
        self.uncles.lock().unwrap().end_number
    }
}

fn read_entry_at(index: &mut File, n: u64) -> Result<IndexEntry> {
    let mut raw = [0u8; INDEX_ENTRY_BYTES as usize];
    index.seek(SeekFrom::Start(n * INDEX_ENTRY_BYTES))?;
    // Past the end, or in a hole, reads as zeroes: absent.
    let got = read_up_to(index, &mut raw)?;
    if got < raw.len() {
        return Ok(IndexEntry { file: 0, start: 0, end: 0 });
    }
    Ok(IndexEntry::decode(&raw))
}

/// Reads as much as is there, returning how much that was.
fn read_up_to(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// The highest `end` offset any entry claims in `file`.
///
/// Scanning the whole index at open is linear in the number of frozen blocks;
/// at 9.2 million entries that is 92 MB read once at start-up. It is done
/// because with arbitrary write order the last entry is not necessarily the
/// furthest one, and guessing wrong here truncates live data.
fn furthest_end(index: &mut File, end_number: u64, file: u16) -> Result<u32> {
    let mut furthest = 0u32;
    let mut raw = vec![0u8; 1 << 16];
    index.seek(SeekFrom::Start(0))?;
    let mut seen = 0u64;
    while seen < end_number {
        let got = read_up_to(index, &mut raw)?;
        if got < INDEX_ENTRY_BYTES as usize {
            break;
        }
        for chunk in raw[..got - got % INDEX_ENTRY_BYTES as usize]
            .chunks_exact(INDEX_ENTRY_BYTES as usize)
        {
            let e = IndexEntry::decode(chunk);
            if !e.is_absent() && e.file == file {
                furthest = furthest.max(e.end);
            }
            seen += 1;
        }
    }
    Ok(furthest)
}

fn decode_header(bytes: &[u8], activations: &ActivationHeights) -> Option<Header> {
    Header::decode_in(
        &mut &bytes[..],
        activations,
        rustock_core::types::header::HeaderForm::Stored,
    )
    .ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, B256, U256};

    pub fn test_header(number: u64) -> Header {
        header(number)
    }

    fn header(number: u64) -> Header {
        Header {
            parent_hash: B256::repeat_byte(number as u8),
            ommers_hash: B256::repeat_byte(2),
            beneficiary: Address::repeat_byte(3),
            state_root: B256::repeat_byte(4),
            transactions_root: B256::repeat_byte(5),
            receipts_root: B256::repeat_byte(6),
            difficulty: U256::from(1_000_000u64 + number),
            number,
            gas_limit: U256::from(6_800_000u64),
            gas_used: 21_000,
            timestamp: 1_700_000_000 + number,
            extra_data: Bytes::from_static(b"rustock"),
            paid_fees: U256::from(1234u64),
            minimum_gas_price: U256::from(59_240_000u64),
            uncle_count: 0,
            logs_bloom: Default::default(),
            extension_data: None,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
            kept: None,
        }
    }

    fn freezer() -> (Freezer, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Freezer::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn a_header_comes_back_as_it_went_in() {
        let (f, _d) = freezer();
        for n in 0..50 {
            f.put(n, &header(n)).unwrap();
        }
        f.sync().unwrap();
        assert_eq!(f.end_number(), 50);
        for n in 0..50 {
            let got = f.header(n).unwrap().expect("frozen");
            assert_eq!(got.number, n);
            assert_eq!(got.difficulty, U256::from(1_000_000u64 + n));
            assert_eq!(got.parent_hash, B256::repeat_byte(n as u8));
        }
    }

    /// The point of the format: a run is answered positionally, in order.
    #[test]
    fn a_run_is_answered_in_one_piece() {
        let (f, _d) = freezer();
        for n in 0..200 {
            f.put(n, &header(n)).unwrap();
        }
        f.sync().unwrap();
        let run = f.run(64, 100).unwrap();
        assert_eq!(run.len(), 100);
        for (i, h) in run.iter().enumerate() {
            assert_eq!(h.as_ref().unwrap().number, 64 + i as u64);
        }
    }

    /// Asking past the end is a short answer, not an error.
    #[test]
    fn a_run_off_the_end_is_padded_with_none() {
        let (f, _d) = freezer();
        for n in 0..10 {
            f.put(n, &header(n)).unwrap();
        }
        f.sync().unwrap();
        let run = f.run(5, 10).unwrap();
        assert_eq!(run.iter().filter(|h| h.is_some()).count(), 5);
        assert!(run[5..].iter().all(|h| h.is_none()));
        assert!(f.header(10).unwrap().is_none());
        assert!(f.run(99, 3).unwrap().iter().all(|h| h.is_none()));
    }

    /// The format is indifferent to arrival order. A snapshot sync walks the
    /// header chain downwards, so this is the ordinary case, not an odd one.
    #[test]
    fn a_descending_walk_reads_back_as_a_run() {
        let (f, _d) = freezer();
        for n in (0..200).rev() {
            f.put(n, &header(n)).unwrap();
        }
        f.sync().unwrap();
        assert_eq!(f.end_number(), 200);

        let run = f.run(64, 100).unwrap();
        for (i, h) in run.iter().enumerate() {
            assert_eq!(
                h.as_ref().expect("written descending, still present").number,
                64 + i as u64
            );
        }
    }

    /// A number nobody wrote is absent, not a wrong answer: the index is
    /// sparse and a hole reads as zeroes.
    #[test]
    fn a_hole_reports_absent() {
        let (f, _d) = freezer();
        f.put(0, &header(0)).unwrap();
        f.put(9, &header(9)).unwrap();
        f.sync().unwrap();
        assert!(f.contains(0));
        assert!(f.contains(9));
        for n in 1..9 {
            assert!(!f.contains(n), "#{n} was never written");
        }
        let run = f.run(0, 10).unwrap();
        assert!(run[0].is_some());
        assert!(run[9].is_some());
        assert!(run[1..9].iter().all(|h| h.is_none()));
    }

    #[test]
    fn it_reopens_where_it_left_off() {
        let dir = tempfile::tempdir().unwrap();
        {
            let f = Freezer::open(dir.path()).unwrap();
            for n in 0..30 {
                f.put(n, &header(n)).unwrap();
            }
            f.sync().unwrap();
            f.sync().unwrap();
        }
        let f = Freezer::open(dir.path()).unwrap();
        assert_eq!(f.end_number(), 30);
        assert_eq!(f.header(29).unwrap().unwrap().number, 29);
        f.put(30, &header(30)).unwrap();
        f.sync().unwrap();
        assert_eq!(f.header(30).unwrap().unwrap().number, 30);
    }

    /// A process that died mid-append leaves data the index does not cover.
    /// The index is the authority; the orphaned tail goes.
    #[test]
    fn a_torn_append_is_repaired_from_the_index() {
        let dir = tempfile::tempdir().unwrap();
        {
            let f = Freezer::open(dir.path()).unwrap();
            for n in 0..20 {
                f.put(n, &header(n)).unwrap();
            }
            f.sync().unwrap();
            f.sync().unwrap();
        }
        // Simulate a partial data write with no index entry behind it.
        let data_path = dir.path().join("headers-0000.cdat");
        let before = std::fs::metadata(&data_path).unwrap().len();
        {
            let mut d = OpenOptions::new().append(true).open(&data_path).unwrap();
            d.write_all(&[0xAA; 512]).unwrap();
        }

        let f = Freezer::open(dir.path()).unwrap();
        assert_eq!(f.end_number(), 20, "the index decides how many blocks there are");
        assert_eq!(
            std::fs::metadata(&data_path).unwrap().len(),
            before,
            "data past the last index entry must be discarded"
        );
        assert_eq!(f.header(19).unwrap().unwrap().number, 19);
    }

    /// A read-only open, beside a writer mid-append, reads what is frozen,
    /// cuts away neither the writer's data nor its half-written index entry,
    /// and refuses every write.
    #[test]
    fn a_read_only_open_reads_and_leaves_a_writers_append_alone() {
        let dir = tempfile::tempdir().unwrap();
        {
            let f = Freezer::open(dir.path()).unwrap();
            for n in 0..20 {
                f.put(n, &header(n)).unwrap();
            }
            f.sync().unwrap();
        }
        let data_path = dir.path().join("headers-0000.cdat");
        let index_path = dir.path().join("headers.cidx");
        let append = |path: &Path, bytes: &[u8]| {
            OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(bytes)
                .unwrap()
        };
        append(&data_path, &[0xAA; 512]);
        append(&index_path, &[0x01; 4]);
        let len = |path: &Path| std::fs::metadata(path).unwrap().len();
        let (data_len, index_len) = (len(&data_path), len(&index_path));

        let f = Freezer::open_read_only(dir.path()).unwrap();
        assert_eq!(f.end_number(), 20, "whole index entries only");
        assert_eq!(f.run(0, 20).unwrap().iter().flatten().count(), 20);
        assert!(f.put(20, &header(20)).is_err());
        assert!(f.put_uncles(20, &[]).is_err());
        assert!(f.truncate_head(10).is_err());
        assert_eq!(len(&data_path), data_len, "the writer's data is not cut");
        assert_eq!(len(&index_path), index_len, "nor its index entry");
        assert_eq!(f.header(15).unwrap().unwrap().number, 15);
    }

    /// Where there is no freezer, a read-only open fails and makes none.
    #[test]
    fn a_read_only_open_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Freezer::open_read_only(dir.path()).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(Freezer::open_read_only(dir.path().join("absent")).is_err());
        assert!(!dir.path().join("absent").exists());
    }

    #[test]
    fn truncate_head_drops_from_a_point_upwards() {
        let (f, _d) = freezer();
        for n in 0..40 {
            f.put(n, &header(n)).unwrap();
        }
        f.sync().unwrap();
        f.truncate_head(25).unwrap();
        assert_eq!(f.end_number(), 25);
        assert!(f.header(25).unwrap().is_none());
        assert!(!f.contains(25));
        assert_eq!(f.header(24).unwrap().unwrap().number, 24);

        // And it can be written to again from there.
        f.put(25, &header(25)).unwrap();
        f.sync().unwrap();
        assert_eq!(f.header(25).unwrap().unwrap().number, 25);
    }

    #[test]
    fn one_week_of_blocks_is_the_freeze_depth() {
        // 30.29 s mean block time, measured over blocks 9,177,825..9,277,825.
        let week = 7.0 * 86_400.0 / 30.29;
        assert!(
            (FREEZE_DEPTH as f64 - week).abs() < 1_000.0,
            "FREEZE_DEPTH should be about a week of blocks, got {FREEZE_DEPTH}"
        );
    }
}

#[cfg(test)]
mod buffering_tests {
    use super::tests::*;
    use super::*;

    /// A buffered block is not readable, and says so. Reporting it present
    /// would promise a read that would fail.
    #[test]
    fn a_buffered_block_reports_absent_until_synced() {
        let dir = tempfile::tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();
        f.put(0, &test_header(0)).unwrap();

        assert_eq!(f.end_number(), 1, "the writer knows it accepted the block");
        assert!(!f.contains(0), "but nothing is readable before a flush");
        assert!(f.header(0).unwrap().is_none());

        f.sync().unwrap();
        assert!(f.contains(0));
        assert_eq!(f.header(0).unwrap().unwrap().number, 0);
    }

    /// Crossing the buffer threshold flushes without being asked, so a long
    /// walk does not grow memory without bound.
    #[test]
    fn it_flushes_itself_once_the_buffer_fills() {
        let dir = tempfile::tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();
        let data = dir.path().join("headers-0000.cdat");

        let mut n = 0u64;
        while std::fs::metadata(&data).map(|m| m.len()).unwrap_or(0) == 0 {
            f.put(n, &test_header(n)).unwrap();
            n += 1;
            assert!(n < 100_000, "should have flushed long before this");
        }

        let written = std::fs::metadata(&data).unwrap().len();
        assert!(
            written >= WRITE_BUFFER_BYTES as u64,
            "a flush should carry a full buffer, got {written}"
        );
        assert!(f.contains(0), "flushed blocks are readable without a sync");
    }
}

/// Decides which headers belong in the freezer, and hands them over.
///
/// The freezer itself takes whatever it is given at whatever number; this is
/// the part that knows *which* blocks are old enough to be given to it, and it
/// is where both sync paths meet.
///
/// # One method, not two
///
/// The plan called for separate ascending and descending adapters, because the
/// original index inferred a block's start from its predecessor's end and so
/// demanded ascending writes. Carrying both offsets per entry removed that
/// constraint, and with it the difference between the two callers: an ordinary
/// sync walking up from the connection point and a snapshot sync walking down
/// from the tip now offer blocks the same way. What is left is one rule, in
/// one place.
///
/// The callers still differ in a way worth knowing: each should feed a single
/// walk without interleaving another, because blocks written consecutively
/// land consecutively, and only then is a run one read.
pub struct FreezerWriter {
    freezer: std::sync::Arc<Freezer>,
    /// Blocks strictly below this may be frozen.
    horizon: u64,
}

impl FreezerWriter {
    pub fn new(freezer: std::sync::Arc<Freezer>) -> Self {
        Self { freezer, horizon: 0 }
    }

    /// Moves the horizon to match a new chain head.
    ///
    /// Only ever forwards. A head that goes backwards is a reorg, and letting
    /// the horizon follow it down would not un-freeze anything anyway -- the
    /// blocks are already in the files. Holding it steady keeps the boundary
    /// monotonic, which is one less thing for a caller to reason about.
    pub fn set_head(&mut self, head: u64) {
        self.horizon = self.horizon.max(head.saturating_sub(FREEZE_DEPTH));
    }

    /// The highest block number that will *not* be frozen.
    pub fn horizon(&self) -> u64 {
        self.horizon
    }

    /// Offers a canonical header. Returns whether it was frozen.
    ///
    /// A block at or above the horizon is declined: it is young enough that a
    /// reorg could still replace it, and a file addressed by height has no way
    /// to express "this height means something else now" short of
    /// [`Freezer::truncate_head`].
    pub fn offer(&self, number: u64, header: &Header) -> Result<bool> {
        if number >= self.horizon {
            return Ok(false);
        }
        self.freezer.put(number, header)?;
        Ok(true)
    }

    /// Makes everything offered so far durable and readable.
    pub fn flush(&self) -> Result<()> {
        self.freezer.sync()
    }

    pub fn freezer(&self) -> &std::sync::Arc<Freezer> {
        &self.freezer
    }
}

#[cfg(test)]
mod writer_tests {
    use super::tests::test_header;
    use super::*;
    use std::sync::Arc;

    fn writer(head: u64) -> (FreezerWriter, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let f = Arc::new(Freezer::open(dir.path()).unwrap());
        let mut w = FreezerWriter::new(f);
        w.set_head(head);
        (w, dir)
    }

    /// The boundary is the part most likely to be wrong, so pin both sides of
    /// it: one block below the horizon freezes, the horizon itself does not.
    #[test]
    fn the_horizon_is_exactly_head_minus_freeze_depth() {
        let head = 1_000_000u64;
        let (w, _d) = writer(head);
        assert_eq!(w.horizon(), head - FREEZE_DEPTH);

        assert!(w.offer(w.horizon() - 1, &test_header(w.horizon() - 1)).unwrap());
        assert!(!w.offer(w.horizon(), &test_header(w.horizon())).unwrap());
        assert!(!w.offer(head, &test_header(head)).unwrap());
    }

    /// A young chain freezes nothing at all rather than underflowing.
    #[test]
    fn a_chain_shorter_than_the_depth_freezes_nothing() {
        let (w, _d) = writer(FREEZE_DEPTH / 2);
        assert_eq!(w.horizon(), 0);
        for n in 0..50 {
            assert!(!w.offer(n, &test_header(n)).unwrap());
        }
        w.flush().unwrap();
        assert_eq!(w.freezer().end_number(), 0);
    }

    /// Both walks reach the same place, which is the point of having one rule.
    #[test]
    fn ascending_and_descending_walks_agree() {
        let head = 100_000u64;
        let (up, _d1) = writer(head);
        let (down, _d2) = writer(head);

        for n in 0..head {
            up.offer(n, &test_header(n)).unwrap();
        }
        for n in (0..head).rev() {
            down.offer(n, &test_header(n)).unwrap();
        }
        up.flush().unwrap();
        down.flush().unwrap();

        let h = head - FREEZE_DEPTH;
        assert_eq!(up.freezer().end_number(), h);
        assert_eq!(down.freezer().end_number(), h);

        let a = up.freezer().run(h - 200, 200).unwrap();
        let b = down.freezer().run(h - 200, 200).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(
                x.as_ref().unwrap().number,
                y.as_ref().unwrap().number,
                "the two walks must produce the same freezer"
            );
        }
        assert!(!up.freezer().contains(h), "the horizon itself stays out");
    }

    /// The horizon does not retreat when the head does.
    #[test]
    fn a_reorg_does_not_move_the_horizon_backwards() {
        let (mut w, _d) = writer(1_000_000);
        let before = w.horizon();
        w.set_head(999_000);
        assert_eq!(w.horizon(), before, "a shorter head must not lower the horizon");
        w.set_head(1_001_000);
        assert_eq!(w.horizon(), 1_001_000 - FREEZE_DEPTH);
    }
}

#[cfg(test)]
mod staging_tests {
    use super::tests::test_header;
    use super::*;

    fn cp(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    /// The name says what the files are, for whoever finds them after a crash.
    #[test]
    fn staging_files_name_their_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let f = Freezer::open_staging(dir.path(), 9_265_000, cp(0xAB)).unwrap();
        f.put(0, &test_header(0)).unwrap();
        f.sync().unwrap();

        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n.contains("9265000") && n.contains(&"ab".repeat(32))),
            "expected height and checkpoint in the filenames, got {names:?}"
        );
    }

    /// A walk that never finished leaves staging files that nothing will come
    /// back for. They are removed, and the real freezer is untouched.
    #[test]
    fn an_abandoned_walk_costs_only_its_own_files() {
        let dir = tempfile::tempdir().unwrap();

        // Headers already frozen legitimately.
        let real = Freezer::open(dir.path()).unwrap();
        for n in 0..100 {
            real.put(n, &test_header(n)).unwrap();
        }
        real.sync().unwrap();
        drop(real);

        // A walk starts staging against a checkpoint, then the process dies.
        {
            let staging = Freezer::open_staging(dir.path(), 500, cp(0xAB)).unwrap();
            for n in 0..500 {
                staging.put(n, &test_header(n)).unwrap();
            }
            staging.sync().unwrap();
        }

        let dropped = Freezer::discard_staging(dir.path());
        assert!(dropped >= 2, "staging index and data should both go");

        let real = Freezer::open(dir.path()).unwrap();
        assert_eq!(real.end_number(), 100, "the real freezer must be untouched");
        assert_eq!(real.header(99).unwrap().unwrap().number, 99);
    }

    /// A walk that reached known ground replaces the real files with its own.
    #[test]
    fn a_completed_walk_is_promoted_by_rename() {
        let dir = tempfile::tempdir().unwrap();
        {
            let staging = Freezer::open_staging(dir.path(), 500, cp(0x07)).unwrap();
            for n in 0..500 {
                staging.put(n, &test_header(n)).unwrap();
            }
            staging.promote().unwrap();
        }
        assert_eq!(
            Freezer::discard_staging(dir.path()),
            0,
            "promotion leaves nothing staged behind"
        );

        let real = Freezer::open(dir.path()).unwrap();
        assert_eq!(real.end_number(), 500);
        assert_eq!(real.header(499).unwrap().unwrap().number, 499);
    }

    /// Promotion flushes first: renaming while the last batch is still in
    /// memory would publish an index naming data that never landed.
    #[test]
    fn promotion_flushes_what_is_buffered() {
        let dir = tempfile::tempdir().unwrap();
        {
            let staging = Freezer::open_staging(dir.path(), 1, cp(0x11)).unwrap();
            staging.put(0, &test_header(0)).unwrap();
            assert!(!staging.contains(0), "still buffered");
            staging.promote().unwrap();
        }
        let real = Freezer::open(dir.path()).unwrap();
        assert_eq!(real.header(0).unwrap().unwrap().number, 0);
    }

    /// Two walks against different checkpoints do not collide.
    #[test]
    fn staging_is_keyed_by_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let a = Freezer::open_staging(dir.path(), 1, cp(0x01)).unwrap();
        let b = Freezer::open_staging(dir.path(), 1, cp(0x02)).unwrap();
        a.put(0, &test_header(0)).unwrap();
        b.put(0, &test_header(1)).unwrap();
        a.sync().unwrap();
        b.sync().unwrap();
        assert_ne!(a.dir().join("x"), std::path::PathBuf::new());
        assert_eq!(a.header(0).unwrap().unwrap().number, 0);
        assert_eq!(b.header(0).unwrap().unwrap().number, 1);
    }

    /// A freezer with contents is left to the background fill, because
    /// promotion replaces rather than merges.
    #[test]
    fn a_populated_freezer_reports_itself_non_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();
        assert!(f.is_empty());
        f.put(0, &test_header(0)).unwrap();
        f.sync().unwrap();
        assert!(!f.is_empty());
    }
}

#[cfg(test)]
mod uncle_store_tests {
    use super::*;
    use super::tests::test_header;
    use tempfile::tempdir;

    fn uncle(number: u64, difficulty: u64) -> Header {
        let mut h = test_header(number);
        h.difficulty = alloy_primitives::U256::from(difficulty);
        h
    }

    #[test]
    fn uncles_round_trip() {
        let dir = tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();

        let uncles = vec![uncle(9, 700), uncle(8, 650)];
        f.put_uncles(10, &uncles).unwrap();
        f.sync().unwrap();

        let got = f.uncles(10).unwrap().expect("frozen");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].difficulty, alloy_primitives::U256::from(700u64));
        assert_eq!(got[1].difficulty, alloy_primitives::U256::from(650u64));
    }

    /// "No uncles" and "not frozen" are different answers. A caller computing
    /// total difficulty that confused them would silently undercount, which is
    /// the whole reason the uncle store exists.
    #[test]
    fn no_uncles_is_not_the_same_as_not_frozen() {
        let dir = tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();

        f.put_uncles(10, &[]).unwrap();
        f.sync().unwrap();

        assert_eq!(f.uncles(10).unwrap(), Some(Vec::new()), "frozen, none referenced");
        assert_eq!(f.uncles(11).unwrap(), None, "never frozen");
    }

    /// The empty list is stored as `0xc0`, so its index entry is non-empty and
    /// cannot be mistaken for the absent sentinel even at offset zero.
    #[test]
    fn the_empty_list_occupies_a_byte_at_offset_zero() {
        let dir = tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();

        // Block 0 is written first, so it lands at offset 0 -- exactly where a
        // zero-length run would be indistinguishable from "never written".
        f.put_uncles(0, &[]).unwrap();
        f.sync().unwrap();

        assert_eq!(f.uncles(0).unwrap(), Some(Vec::new()));
        assert!(f.uncle_bytes() >= 1, "the empty list took a byte");
    }

    /// The two stores are independent: freezing a header does not claim to
    /// know its uncles, and vice versa.
    #[test]
    fn the_stores_are_addressed_separately() {
        let dir = tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();

        f.put(10, &test_header(10)).unwrap();
        f.sync().unwrap();

        assert!(f.header(10).unwrap().is_some());
        assert_eq!(f.uncles(10).unwrap(), None, "header frozen, uncles not yet");

        f.put_uncles(10, &[uncle(9, 700)]).unwrap();
        f.sync().unwrap();
        assert_eq!(f.uncles(10).unwrap().unwrap().len(), 1);
    }

    /// Rolling the head back must drop the same range from both stores, or the
    /// uncle store answers for blocks the freezer has disowned.
    #[test]
    fn truncating_the_head_drops_uncles_too() {
        let dir = tempdir().unwrap();
        let f = Freezer::open(dir.path()).unwrap();

        for n in 0..5u64 {
            f.put(n, &test_header(n)).unwrap();
            f.put_uncles(n, &[uncle(n, 100)]).unwrap();
        }
        f.sync().unwrap();
        assert_eq!(f.uncles(4).unwrap().unwrap().len(), 1);

        f.truncate_head(3).unwrap();
        assert_eq!(f.uncles(4).unwrap(), None, "dropped with the header");
        assert_eq!(f.uncles(2).unwrap().unwrap().len(), 1, "below the cut, kept");
    }

    /// Reopening finds both stores where they were left.
    #[test]
    fn uncles_survive_a_reopen() {
        let dir = tempdir().unwrap();
        {
            let f = Freezer::open(dir.path()).unwrap();
            f.put_uncles(7, &[uncle(6, 999)]).unwrap();
            f.sync().unwrap();
        }
        let f = Freezer::open(dir.path()).unwrap();
        let got = f.uncles(7).unwrap().expect("still there");
        assert_eq!(got[0].difficulty, alloy_primitives::U256::from(999u64));
    }
}
