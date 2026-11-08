use clap::{CommandFactory, FromArgMatches, Parser};

mod config_file;
use rustock_core::config::ChainConfig;
use rustock_core::validation::HeaderVerifier;
use rustock_storage::BlockStore;
use rustock_networking::node::{Node, NodeConfig};
use rustock_sync::{SyncManager, SyncHandler, SyncService, TxRelay};
use rustock_trie::{AccountState, TrieKeySlice, TrieNode, TrieStore, account_key};
use std::sync::Arc;
use alloy_primitives::U256;
use anyhow::{Result, Context};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

/// Reads block bodies from a synced rskj `blocks` LevelDB (keyed by block
/// hash → RLP[header, txs, ommers]) so the node can reuse an existing local
/// chain instead of re-downloading bodies from peers.
struct RskjBlockSource {
    db: rocksdb::DB,
}

impl RskjBlockSource {
    fn open(path: &str) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        let mut bbt = rocksdb::BlockBasedOptions::default();
        bbt.set_block_cache(&rocksdb::Cache::new_lru_cache(512 * 1024 * 1024));
        opts.set_block_based_table_factory(&bbt);
        let db = rocksdb::DB::open_for_read_only(&opts, path, false)
            .context("Failed to open rskj blocks LevelDB")?;
        Ok(Self { db })
    }
}

impl rustock_sync::ExternalBlockSource for RskjBlockSource {
    fn body_by_hash(
        &self,
        hash: alloy_primitives::B256,
    ) -> Option<(Vec<rustock_core::Transaction>, Vec<rustock_core::types::header::Header>)> {
        use alloy_rlp::Decodable;
        let data = self.db.get(hash.as_slice()).ok().flatten()?;
        let block = rustock_core::Block::decode(&mut &data[..]).ok()?;
        Some((block.transactions, block.ommers))
    }
}

struct TxRelaySubmitter(Arc<TxRelay>);

#[async_trait::async_trait]
impl rustock_rpc::server::TxSubmitter for TxRelaySubmitter {
    async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> Result<alloy_primitives::B256, String> {
        self.0.submit_transaction(raw_tx).await
    }
}

struct PoolAdapter(Arc<rustock_sync::TransactionPool>);

/// The gas-price tracker, as `eth_gasPrice` needs it.
struct GasPriceAdapter(Arc<rustock_sync::gas_price::GasPriceTracker>);

impl rustock_rpc::server::GasPriceSource for GasPriceAdapter {
    fn gas_price(&self) -> alloy_primitives::U256 {
        self.0.gas_price()
    }

    fn is_fee_market_working(&self) -> bool {
        self.0.is_fee_market_working()
    }
}

impl rustock_rpc::server::TxPoolReader for PoolAdapter {
    fn get_pending_tx(
        &self,
        hash: &alloy_primitives::B256,
    ) -> Option<(rustock_core::Transaction, alloy_primitives::Address, alloy_primitives::B256)> {
        let ptx = self.0.get(hash)?;
        Some((ptx.tx, ptx.sender, ptx.hash))
    }

    fn pending_nonce(&self, addr: &alloy_primitives::Address) -> Option<u64> {
        self.0.pending_nonce(addr)
    }

    fn pool_status(&self) -> (usize, usize) {
        self.0.status()
    }

    fn pool_content(&self) -> rustock_rpc::server::PoolContent {
        let (pending, queued) = self.0.content();
        rustock_rpc::server::PoolContent { pending, queued }
    }

    fn quota_report(&self, address: &alloy_primitives::Address) -> Option<(f64, u64)> {
        self.0.quota_report_of(address)
    }
}

/// The transaction pool, as the block builder needs it. The pool recovers
/// every sender on admission, so the builder never has to do it again -- which
/// matters because a template is rebuilt every minute over the whole pool.
struct PoolTxSource(Arc<rustock_sync::TransactionPool>);

impl rustock_execution::mining::PendingTransactionSource for PoolTxSource {
    fn pending(&self) -> Vec<rustock_execution::mining::PendingTransaction> {
        self.0
            .pending_transactions()
            .into_iter()
            .map(|ptx| rustock_execution::mining::PendingTransaction {
                tx: ptx.tx,
                sender: ptx.sender,
                hash: ptx.hash,
            })
            .collect()
    }

    fn remove_transactions(&self, hashes: &[alloy_primitives::B256]) {
        self.0.remove_by_hashes(hashes);
    }
}

/// rskj `BlockSyncService.hasBetterBlockToSync`: the last block number a
/// peer announced is at least `longSyncLimit` (24, `reference.conf`) past
/// the node's best. The peer store is async; a task keeps the announced
/// number in `last_known` so the miner's thread can read it.
struct PeerSyncGate {
    store: Arc<rustock_storage::BlockStore>,
    last_known: Arc<std::sync::atomic::AtomicU64>,
}

impl PeerSyncGate {
    /// rskj `reference.conf` `sync.longSyncLimit`.
    const LONG_SYNC_LIMIT: u64 = 24;

    fn spawn(
        store: Arc<rustock_storage::BlockStore>,
        peer_store: Arc<rustock_networking::peers::PeerStore>,
    ) -> Arc<Self> {
        let last_known = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let shared = last_known.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let best = peer_store.best_peer().await.map(|(_, m)| m.best_number).unwrap_or(0);
                // The CURRENT best peer, not the highest ever seen. A
                // high-water mark would be a remote off-switch for mining:
                // peer-announced heights are unauthenticated, so one peer
                // claiming 2^60 once would leave the gate shut for the life
                // of the process and the node would never mine again. rskj
                // reads the sync service's present view for the same reason.
                // With no peers this is 0, which opens the gate -- correct,
                // since nothing is being announced to catch up to.
                shared.store(best, std::sync::atomic::Ordering::Relaxed);
            }
        });
        Arc::new(Self { store, last_known })
    }
}

impl rustock_execution::mining::SyncGate for PeerSyncGate {
    fn has_better_block_to_sync(&self) -> bool {
        let best = self
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);
        self.last_known.load(std::sync::atomic::Ordering::Relaxed)
            >= best.saturating_add(Self::LONG_SYNC_LIMIT)
    }
}

#[derive(Parser, Debug, PartialEq, serde::Serialize)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Read settings from a TOML file.
    ///
    /// Anything given on the command line wins over the file, and the file
    /// wins over the built-in default -- so an operator can override a file
    /// setting with a flag without editing the file. Unknown keys are an
    /// error rather than being ignored.
    ///
    /// One-shot operations (--import-*, --repair, --trie-tool-*, --probe-*)
    /// are command-line only: a node that re-ran an import on every start
    /// would be a trap.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,

    /// Port to listen for P2P connections
    #[arg(short, long, default_value_t = 30303)]
    port: u16,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: String,

    /// Serve JSON-RPC over WebSocket as well, on its own port.
    ///
    /// Off by default, as rskj's `rpc.providers.web.ws.enabled` is. This is
    /// the only transport that carries `eth_subscribe`, so a client wanting
    /// new heads or logs pushed to it needs this on.
    #[arg(long, default_value_t = false)]
    ws: bool,

    /// Port for the WebSocket JSON-RPC server (rskj's default is 4445).
    #[arg(long, default_value_t = 4445)]
    ws_port: u16,

    /// Addresses or CIDR blocks refused at connection time, as rskj's
    /// `peer.bannedPeerIPs`. Repeatable.
    ///
    /// Bans added later through `sco_banAddress` are persisted separately, in
    /// `banned-peers.txt` inside the data directory, and reloaded at start-up.
    #[arg(long, value_name = "ADDRESS_OR_CIDR")]
    banned_peers: Vec<String>,

    /// Record peer scoring but never act on it.
    ///
    /// rskj's `scoring.punishmentEnabled = false`. Events are still counted
    /// and `sco_peerList` still reports them, so an operator can see what
    /// would have been punished before letting it punish.
    #[arg(long, default_value_t = false)]
    no_peer_punishment: bool,

    /// Serve snapshots of this node's state to peers that ask for one.
    ///
    /// Costs disk reads and bandwidth; answers are proved, so a peer needs no
    /// further trust in this node than it would have in any other.
    #[arg(long, default_value_t = false)]
    snap_server: bool,

    /// Catch up by downloading a state instead of replaying the chain into
    /// one.
    ///
    /// The header chain to the snapshot point is verified first, under the
    /// same proof-of-work rules as a full sync, and every chunk of state is
    /// checked against that chain's state root as it arrives. What is given
    /// up is the re-execution of history, not the verification of it.
    #[arg(long, default_value_t = false)]
    snap_sync: bool,

    /// Bytes of state to ask for per chunk.
    #[arg(long, default_value_t = 100_000, value_name = "BYTES")]
    snap_chunk_bytes: u64,

    /// The offset-space grid snapshot chunks sit on.
    ///
    /// Every chunk covers one cell of this grid, so every client asks for the
    /// same ranges and a server answers the second client from cache rather
    /// than from a trie traversal. A server advertises its grid and clients
    /// adopt it; changing this on a server invalidates its cached cells.
    #[arg(long, default_value_t = 100_000, value_name = "BYTES")]
    snap_chunk_grid: u64,

    /// Chunk requests to keep in flight at once, across all peers.
    #[arg(long, default_value_t = 8, value_name = "N")]
    snap_parallel: usize,

    /// After a snapshot sync, fill in the canonical number-to-hash index for
    /// the history below the checkpoint window.
    ///
    /// Nothing about consensus needs it: every execution-path lookup is
    /// bounded well inside the window the sync already indexes. What needs it
    /// is answering RPC about old heights, and serving history to other peers
    /// -- without it the node takes history from the network and gives none
    /// back. Costs about 0.4 GB and, on a cold store, up to an hour and a half
    /// of low-priority background disk. Resumable across restarts.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    snap_index_history: bool,

    /// Establish the header chain by ascending from a block this node already
    /// holds, instead of descending from the peer's offered checkpoint.
    ///
    /// Takes the uncles alongside the headers (`rsk/63`, RSKIP-698) and totals
    /// cumulative difficulty exactly, so the sampling gate and the claimed-work
    /// ceiling are not needed: the offered checkpoint is checked against the
    /// chain this node proved for itself. A peer at `rsk/62` cannot serve this
    /// and the session falls back to the descending walk.
    ///
    /// Experimental. The descending walk is what has been run against mainnet.
    /// See `docs/header-first-sync.md`.
    #[arg(long, default_value_t = false)]
    snap_forward_headers: bool,

    /// Blocks to download below the checkpoint when snapshot syncing.
    ///
    /// These are the blocks the node holds history for once the sync is done.
    /// The default is enough for the block-info precompiles (4,000 back) and a
    /// reorg that re-executes from 4,000 back, with margin.
    ///
    /// Raising it is how a pruning node is given something to prune: set this
    /// above `--prune-keep-depth` and the first sweep after the sync has the
    /// difference to remove.
    #[arg(long, default_value_t = 6_000, value_name = "BLOCKS")]
    snap_blocks: u64,

    /// State bytes per second one peer may be served.
    ///
    /// Computing chunks is bounded by the server's cache -- it serves one
    /// state, so there are only so many distinct cells -- but egress is not
    /// bounded by anything else. Unthrottled, one peer can pull cached cells
    /// at about 300 MB/s. The default gives an honest client the whole
    /// mainnet state in about two minutes from a single server.
    #[arg(long, default_value_t = 8 * 1024 * 1024, value_name = "BYTES")]
    snap_peer_rate: u64,

    /// State bytes per second this server will produce in total.
    ///
    /// Four peers at the per-peer limit reach it. 32 MB/s is 256 Mbit, which
    /// leaves a gigabit host room for the block and transaction traffic it
    /// exists to carry; a smaller uplink wants a smaller number.
    #[arg(long, default_value_t = 32 * 1024 * 1024, value_name = "BYTES")]
    snap_total_rate: u64,

    /// Which chain to run: 30 mainnet, 31 testnet, anything else regtest.
    ///
    /// Named `--network-id` for historical reasons; it selects the chain, not
    /// the wire network id (testnet's is 8100, which is *not* what to pass
    /// here). Passing a value no chain claims gives a regtest node, which
    /// starts cleanly on the wrong genesis and never finds a peer.
    #[arg(long, default_value = "30")]
    network_id: u64,

    /// Secret key for the P2P node (hex). If not provided, a random one will be used.
    #[arg(long)]
    secret_key: Option<String>,

    /// Supply conservation checking: per-transaction, per-block, both or off.
    ///
    /// Per-transaction is the default and is strictly more sensitive:
    /// block-level netting hides a creation when one transaction mints and
    /// another destroys the same amount. Per-block is kept on as a cross-check
    /// that the per-transaction deltas account for the whole block -- a
    /// disagreement means value moved outside any transaction.
    #[arg(long, value_name = "MODE", default_value = "both")]
    supply_check: String,

    /// How many threads may execute a block's parallel sublists (RSKIP-144).
    ///
    /// 1 runs every transaction in order on one thread, which is what every
    /// block on a chain without RSKIP-144 does regardless of this setting --
    /// a block only splits if its header says so. Above 1, the sublists a
    /// block declares run concurrently and are merged in sublist order; the
    /// sequential sublist always runs last, on the merged state.
    ///
    /// RSKIP-144 caps a block at two parallel sublists, so values above 2
    /// buy nothing and are clamped.
    #[arg(long, value_name = "N", default_value = "1")]
    execution_threads: usize,

    /// Build the Bridge event index from stored receipts and exit.
    ///
    /// Indexes every log the Bridge emitted, keyed by event signature, so
    /// "find every peg-in" becomes a prefix scan rather than a walk over every
    /// receipt in the chain. Requires receipts (see --import-rskj-receipts).
    /// The node must be stopped.
    #[arg(long, default_value_t = false)]
    build_bridge_index: bool,

    /// Add the block-height index to an existing database and exit.
    ///
    /// Maps every height to every block hash at it, canonical or not. Uncle
    /// selection needs the blocks that lost, and the canonical pointer names
    /// only the one that won, so a database synced before this index existed
    /// cannot mine with uncles until it is built.
    ///
    /// Reads every stored header and writes one small key per block. It does
    /// not touch state, blocks or receipts, and it can be interrupted and
    /// re-run: each entry is derived from the header it indexes, so a partial
    /// run simply resumes. The node must be stopped -- RocksDB allows a single
    /// writer.
    #[arg(long, default_value_t = false)]
    build_height_index: bool,

    /// Emulate rskj's peg-in sender detection for multisig inputs: `on` or `off`.
    ///
    /// On by default, because rskj still does it and a node that stops would
    /// fork. `off` is for after the RSKIP retiring this path activates, and for
    /// measuring what the path is worth: with it off, a peg-in that depended on
    /// it is simply not classified.
    ///
    /// Whichever way it is set, a peg-in that exercises the path is logged and,
    /// if alerting is configured, mailed.
    #[arg(long, value_name = "on|off", default_value = "on")]
    rskj_multisig_senders: String,

    /// Import rskj's receipts from an extracted snapshot directory and exit.
    ///
    /// rustock only writes receipts for blocks it EXECUTES, so a node that
    /// imported its history has none for those blocks. rskj keys receipts by
    /// transaction and rustock by block, so this converts rather than copies.
    /// Point it at `database/mainnet/receipts` from an extracted snapshot.
    /// The node must be stopped: RocksDB allows a single writer.
    #[arg(long, value_name = "DIR")]
    import_rskj_receipts: Option<String>,

    /// First block for --import-rskj-receipts (default 1).
    #[arg(long)]
    receipts_from: Option<u64>,

    /// Last block for --import-rskj-receipts (default: the chain head).
    #[arg(long)]
    receipts_to: Option<u64>,

    /// Run a one-off repair against the database and exit, instead of starting
    /// the node. The node must be stopped: RocksDB allows a single writer.
    ///
    /// Tasks:
    ///   tx-index   rebuild the transaction index from block bodies, so
    ///              eth_getTransactionByHash and eth_getTransactionReceipt can
    ///              find transactions in blocks that were imported rather than
    ///              executed. Touches no trie and executes nothing.
    ///   canonical  rebuild the canonical number -> hash index by walking the
    ///              head's own ancestry down through --repair-from, so every
    ///              height names the block the one above it actually builds
    ///              on. An index rebuild, not a re-download: the headers are
    ///              already stored. Touches no trie and executes nothing.
    #[arg(long, value_name = "TASK")]
    repair: Option<String>,

    /// First block for --repair (default 1).
    #[arg(long)]
    repair_from: Option<u64>,

    /// Last block for --repair (default: the chain head).
    #[arg(long)]
    repair_to: Option<u64>,

    /// Log level: trace, debug, info, warn, error.
    /// Can also use RUST_LOG-style directives, e.g. "info,rustock_sync=debug".
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log to stdout instead of a file. By default logs are written to
    /// <data-dir>/rustock.log with automatic daily rotation.
    #[arg(long, default_value_t = false)]
    log_to_stdout: bool,

    /// Timezone for log timestamps: `utc`, `local`, or a fixed UTC offset
    /// such as `-03:00`.
    ///
    /// Timestamps stay RFC 3339, so the offset is part of the line rather
    /// than something a reader has to know: UTC prints `…T01:53:47.0+00:00`,
    /// `-03:00` prints `…T22:53:47.0-03:00`. Nothing downstream has to guess
    /// which one it is looking at.
    ///
    /// `local` reads the machine's offset, which is resolved once at start-up
    /// and then fixed for the life of the process -- so a node that runs
    /// across a daylight-saving transition keeps the offset it started with.
    /// A fixed offset avoids that entirely, and is exactly right for zones
    /// without DST (Argentina has had none since 2009).
    ///
    /// `allow_hyphen_values` because a negative offset starts with `-`, and
    /// clap otherwise reads `--log-timezone -03:00` as a missing value
    /// followed by an unknown `-0` flag.
    #[arg(
        long,
        default_value = "utc",
        value_name = "utc|local|±HH:MM",
        allow_hyphen_values = true
    )]
    log_timezone: String,

    /// JSON-RPC server port
    #[arg(long, default_value_t = 4444)]
    rpc_port: u16,

    /// Serve Prometheus metrics on this port. Unset means no metrics
    /// listener is opened at all.
    #[arg(long)]
    metrics_port: Option<u16>,

    /// Address the metrics server binds to
    #[arg(long, default_value = "127.0.0.1")]
    metrics_host: String,

    /// JSON-RPC server bind address
    #[arg(long, default_value = "127.0.0.1")]
    rpc_host: String,

    /// Disable the JSON-RPC server
    #[arg(long, default_value_t = false)]
    no_rpc: bool,

    /// External IP address to advertise to peers (e.g., 203.0.113.42).
    /// If not set, 127.0.0.1 is used.
    #[arg(long)]
    external_ip: Option<std::net::IpAddr>,

    /// Path to a synced rskj `blocks` LevelDB (e.g. ~/.rsk/mainnet/database/blocks).
    /// When set, block bodies are read from it before requesting them from
    /// peers — reusing an existing local chain instead of re-downloading.
    #[arg(long)]
    import_blocks_db: Option<String>,

    /// Discovery bootstrap addresses, `HOST:PORT`, repeatable.
    ///
    /// **Replaces** the chain's built-in list rather than adding to it, which
    /// is the point: given one address, this node bootstraps from that address
    /// and nothing else. That is what makes an isolated two-node network
    /// possible — without it the built-in list is the only way in, and a node
    /// on a private network has no way to say so.
    ///
    /// The port is the **discovery** port, which is the listen port plus one.
    /// A node on `--port 30303` is reached at `HOST:30304`.
    ///
    /// Note this does not by itself keep a node off the public network: peers
    /// found through the one bootstrap address can introduce others. Pair it
    /// with `--closed-network` to stop that, or use a firewall.
    #[arg(long, value_name = "HOST:PORT")]
    bootnodes: Vec<String>,

    /// Re-execute the last N blocks and report what each one read from the
    /// trie, then exit.
    ///
    /// Sizes a stateless witness with a measurement rather than an estimate:
    /// which nodes a block needs depends on the accounts and storage slots
    /// its transactions reach and on how much their paths overlap, and no
    /// amount of reasoning about the trie's shape produces that number.
    ///
    /// Opens both databases **read-only** and keeps every write in memory, so
    /// it can be pointed at a node that is running.
    #[arg(long, value_name = "N")]
    measure_block_reads: Option<u64>,

    /// With `--verify-state`, report the trie's shape instead of verifying it.
    ///
    /// Measures what sizing a stateless witness needs and the node does not
    /// otherwise record: how deep a value sits, which is how many sibling
    /// hashes a proof for it carries, and how many values there are to share
    /// the upper levels between.
    #[arg(long)]
    trie_shape: bool,

    /// Walk the state under a root and confirm every node is present, then
    /// exit.
    ///
    /// The same check a snapshot sync runs before it accepts a downloaded
    /// state, available on demand: it answers "is this node's state actually
    /// all here" without syncing anything. Pass a state root, or leave it
    /// empty to use the executed head's.
    ///
    /// Reads only. Uses `--read-threads` workers.
    #[arg(long, value_name = "ROOT", num_args = 0..=1, default_missing_value = "head")]
    verify_state: Option<String>,

    /// Delete headers from the block database once the freezer holds them.
    ///
    /// Off by default, and deliberately so. The freezer's measured win is
    /// read amplification on header serving, and that is banked without
    /// deleting anything; what deletion buys is space -- roughly 9.6 GB net
    /// on this chain, after the ~372 MB the hash-to-number index costs.
    ///
    /// What it costs is a failure mode duplication currently makes
    /// impossible: a header that is in neither place. Every lookup by hash
    /// for a frozen block then depends on an index entry being right, where
    /// today it depends on nothing.
    ///
    /// Deletion is ordered so that cannot happen quietly -- the header is
    /// read back out of the freezer, and `hash → number` written, *before*
    /// the database copy goes. But the ordering is a mitigation, not a
    /// reason to turn it on. Turn it on when disk pressure justifies the
    /// risk, not before.
    #[arg(long)]
    prune_frozen_headers: bool,

    /// Concurrent point lookups to issue against the storage device.
    ///
    /// One setting behind every parallel read in the node: headers by hash,
    /// trie nodes by hash, and the snapshot state verification walk. They all
    /// ask the same question, and it is not "how many cores are there" --
    /// these threads spend most of their time waiting on RocksDB, so what is
    /// being chosen is how deep a queue the device answers well. That is why
    /// the default is 16 even on a four-core machine.
    ///
    /// Worth changing when the storage is not a local SSD: a spinning disk has
    /// one arm and does worse with 16 concurrent random reads than with four,
    /// network storage is answering for a device that is not this host's, and
    /// a one-core container gets contention and nothing else. NVMe with deep
    /// queues may reward more.
    ///
    /// The default is what was hardcoded before this was configurable, so
    /// behaviour does not change until it is set.
    #[arg(long, default_value_t = 16, value_name = "N")]
    read_threads: usize,

    /// Move settled headers out of RocksDB into flat files.
    ///
    /// Headers are keyed by hash, and hashes have no order, so serving the 192
    /// headers a peer asks for is 192 unrelated point lookups -- measured at
    /// 6.5x read amplification on this database, about 7.1 KB read per header
    /// delivered. Below `head - 20000` a canonical header can no longer
    /// change, so it is written to a file addressed by block number instead,
    /// where a run of headers is one contiguous read.
    ///
    /// On by default, because that is the behaviour a node should have.
    /// `--freezer false` turns it off: to measure against it, to run on a
    /// filesystem where the flat files are unwelcome, or to rule it out while
    /// diagnosing something else. Nothing is deleted from RocksDB either way,
    /// so turning it off loses the read win and costs nothing else.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    freezer: bool,

    /// Learn no peers beyond the ones `--bootnodes` names.
    ///
    /// Discovery exists to find nodes, and it is good at it: a single
    /// Neighbors reply is enough to pull a node that was pointed at one peer
    /// onto the whole network. That is right for joining the chain and wrong
    /// for a controlled test, where the peer set has to stay what the operator
    /// chose -- otherwise the numbers describe whoever answered rather than
    /// the node under test.
    ///
    /// With this set, a node enters the peer table only if its address was
    /// configured. Discovery still answers what it is asked, so this is not a
    /// way to hide; it simply does not act on what it hears.
    ///
    /// Has no effect without `--bootnodes`, which is the list it confines the
    /// node to.
    #[arg(long)]
    closed_network: bool,

    /// Target number of outbound peer connections to maintain (rskj's
    /// `maxActivePeers` default is 30). Higher values give more headroom to
    /// absorb dead/unreachable nodes and recover faster after a network blip.
    #[arg(long, default_value_t = 25)]
    max_peers: usize,

    /// Maximum simultaneous inbound peer connections. Bounds the work an
    /// attacker can force by opening connections: each one costs an ECIES
    /// handshake (secp256k1 ECDH + Keccak) plus per-connection buffers.
    #[arg(long, default_value_t = 32)]
    max_inbound_peers: usize,

    /// Maximum simultaneous inbound connections from a single IP address, so
    /// one host cannot occupy every inbound slot on its own.
    #[arg(long, default_value_t = 4)]
    max_inbound_per_ip: usize,

    /// Maximum simultaneous inbound connections from a single network block.
    /// A per-IP cap alone is sidestepped by anyone holding a subnet, so this
    /// bounds the whole block as well (rskj's peer.filter.maxConnections).
    #[arg(long, default_value_t = 16)]
    max_inbound_per_cidr: usize,

    /// IPv4 prefix length defining a network block for --max-inbound-per-cidr.
    #[arg(long, default_value_t = 24)]
    inbound_cidr_prefix: u8,

    /// Import an extracted rskj database, then exit.
    ///
    /// Expects the directory holding rskj's datasource subdirectories, e.g.
    /// `/mnt/import/extract/database/mainnet` (containing `blocks/` and
    /// `unitrie/`). The two schemas differ structurally, so this converts
    /// rather than copies; see rustock_storage::rskj_import for the details.
    /// Blocks already present are skipped, so an import over a partially
    /// synced datadir fast-forwards.
    #[arg(long)]
    import_rskj: Option<String>,

    /// Write per-phase import metrics to this CSV, for comparing runs.
    #[arg(long)]
    import_metrics: Option<String>,

    /// During import, look up each entry and skip ones already held.
    ///
    /// Off by default. Both datasources are content-addressed, so rewriting an
    /// entry we already hold writes identical bytes -- the check is a
    /// performance trade, not a correctness one. It costs one point lookup per
    /// entry (~700M of them for the state trie), which only pays off when the
    /// destination already holds most of the source. Use it when topping up a
    /// nearly-complete datadir; leave it off for a fresh or mostly-fresh one.
    #[arg(long)]
    import_skip_existing: bool,

    /// Route import writes through the write-ahead log.
    ///
    /// Off by default, which is the right choice: the WAL exists to recover
    /// unflushed writes after a crash, but a failed import is re-run from the
    /// source rather than repaired. Enabling it writes every entry twice.
    #[arg(long)]
    import_enable_wal: bool,

    /// Memtable size during import, in MiB. Larger means fewer, larger flushes
    /// and less write amplification, at the cost of dirty data held in RAM.
    #[arg(long, default_value_t = 256)]
    import_write_buffer_mb: usize,

    /// Leave auto-compaction enabled during import.
    ///
    /// Off by default: compacting while the load is still running repeatedly
    /// rewrites data that is about to change. Disabled, the import does one
    /// compaction pass at the end instead.
    #[arg(long)]
    import_auto_compaction: bool,

    /// Path to the alerting configuration: peg-out monitoring and node health.
    ///
    /// Entirely optional: without it nothing watches and nothing changes. The
    /// watchers only read what the node has already committed, so they cannot
    /// affect consensus or block processing. See `docs/alerts.md` and
    /// `alerts.example.toml`.
    ///
    /// `--pegout-alerts-config` is accepted as an alias, for deployments
    /// written before this file covered more than peg-outs.
    #[arg(long, alias = "pegout-alerts-config")]
    alerts_config: Option<String>,

    /// Background flush/compaction threads during import. 0 uses the CPU count.
    #[arg(long, default_value_t = 0)]
    import_parallelism: usize,

    /// Threads for the trie copy. 0 uses the CPU count; 1 forces the sequential
    /// path.
    ///
    /// Parallel by default because the copy is CPU-bound, not disk-bound: it
    /// sustained 48.6 MB/s against a volume measured at 358 MB/s sequential.
    /// Trie keys are hashes, so the keyspace splits into equal contiguous
    /// ranges and the threads share nothing but the destination handle.
    #[arg(long, default_value_t = 0)]
    import_unitrie_threads: usize,

    /// Probe an rskj unitrie for specific node hashes, then exit.
    ///
    /// Answers whether a snapshot is archival or pruned: pass historical state
    /// roots and see whether their nodes are present. That determines whether
    /// blocks can be re-executed in parallel (every pre-state already on disk)
    /// or only sequentially.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    probe_unitrie: Vec<String>,

    /// Directory holding the rskj unitrie to probe.
    #[arg(long)]
    probe_source: Option<String>,

    /// Skip the trie and block phases and rebuild only the chain metadata.
    ///
    /// Useful when those phases already completed and only the derived
    /// canonical chain and total difficulty are missing -- rerunning the whole
    /// import to redo them would rewrite ~180 GB for nothing.
    #[arg(long)]
    import_metadata_only: bool,

    /// Import the blocks and chain metadata but not the state trie.
    ///
    /// For a database that is going to be *read against* rather than executed
    /// from: a verification run reads state straight out of rskj's own
    /// unitrie, so copying it here would duplicate ~130 GB to no purpose. What
    /// it cannot read out of rskj is a block by height, because rskj keys
    /// blocks by hash and keeps the height index somewhere this cannot read --
    /// which is exactly what the block and metadata phases build.
    #[arg(long)]
    import_skip_unitrie: bool,

    /// Import the blocks but leave the derived chain metadata alone.
    ///
    /// The canonical index and total difficulty are keyed by block hash, and
    /// the block phase writes under rskj's own hashes, so re-importing blocks
    /// into a datadir that already has its metadata leaves that metadata
    /// correct. Rebuilding it anyway is the expensive half of an import --
    /// over six hours on RSK testnet -- for no change.
    #[arg(long)]
    import_skip_metadata: bool,

    /// Rebuild chain metadata for this block range only, then exit.
    ///
    /// For benchmarking the metadata phase without paying for a full pass --
    /// the full rebuild took 5 hours on RSK mainnet, which is far too slow a
    /// loop for trying optimisations. Requires a completed full pass, since it
    /// seeds itself from the existing canonical hash and total difficulty at
    /// the range boundaries. Non-destructive: it recomputes exactly the values
    /// already stored.
    #[arg(long, num_args = 2, value_names = ["FROM", "TO"])]
    metadata_range: Vec<u64>,

    /// Load chain metadata from a dump of rskj's MapDB index (the fast path).
    ///
    /// Produced by tools/dump-index. Reads canonical hash and cumulative
    /// difficulty straight from what rskj already computed, instead of deriving
    /// them by walking parentHash back from the tip -- a chain of 9.2M dependent
    /// random lookups measured at ~1,065 blocks/s, roughly five hours.
    ///
    /// Pass the dump sorted by block number so writes land in key order.
    #[arg(long)]
    import_index_dump: Option<String>,

    /// Derive chain metadata by walking parentHash on disk.
    ///
    /// The original method, kept for comparison and for cases where memory is
    /// too tight for --metadata-in-memory. Slow: the walk is a chain of
    /// dependent random lookups that cannot be batched, measured at ~1,065
    /// blocks/s, roughly five hours for RSK mainnet.
    #[arg(long)]
    metadata_by_walk: bool,

    /// Rebuild chain metadata using an in-memory header index (the fast path).
    ///
    /// Scans the headers column family sequentially into a hash -> (number,
    /// parent, difficulty) map, walks the chain through RAM, then writes in
    /// batches. Costs roughly 150 bytes per header -- about 2 GB for RSK
    /// mainnet -- and needs no JVM or rskj index file.
    #[arg(long)]
    metadata_in_memory: bool,
    /// Scan the Unitrie reachable from a state root and print statistics, then
    /// exit. Defaults to the last executed block; pass --trie-tool-block for
    /// another. Opens the database read-only, so it can run while the node does.
    #[arg(long)]
    trie_tool: bool,

    /// Block whose state root to scan with --trie-tool.
    #[arg(long)]
    trie_tool_block: Option<u64>,

    /// Seconds between progress lines during --trie-tool. 0 disables.
    ///
    /// Wall-clock rather than a node count: the node rate varies by orders of
    /// magnitude with cache warmth, so a count-based interval reports either
    /// constantly or almost never. A scan silent for twenty minutes is also
    /// indistinguishable from one that has hung, which is how an earlier
    /// quadratic version of this scan went unnoticed.
    #[arg(long, default_value_t = 30)]
    trie_tool_progress: u64,

    /// Database to scan or inspect. Defaults to --data-dir.
    ///
    /// Accepts either a node datadir or a standalone trie snapshot written by
    /// --trie-tool-copy. A snapshot is recognised by its metadata file and
    /// carries its own state root, so no block lookup is needed -- or possible,
    /// since a snapshot holds no headers.
    #[arg(long)]
    trie_tool_source: Option<String>,

    /// Copy the scanned state into a new standalone trie database.
    ///
    /// The scan already reads every live node, so extracting them costs the
    /// write and nothing more. The result is under a gigabyte against a 129 GB
    /// source, and is immutable, which makes re-running the statistics a matter
    /// of minutes instead of the better part of an hour -- and makes repeated
    /// runs comparable, since the live store keeps moving as the node syncs.
    ///
    /// Pass a directory, or give the flag alone to name it after the state root.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    trie_tool_copy: Option<String>,

    /// Delete the copy target first if it already exists.
    ///
    /// Off by default. Every key in a trie database is a hash, so a snapshot
    /// written over unrelated data would neither collide nor complain -- it
    /// would just quietly carry whatever was there before.
    #[arg(long)]
    trie_tool_copy_overwrite: bool,

    /// Directory for a detached trie store.
    ///
    /// Used by --trie-backend external and epoch. Defaults to
    /// <data-dir>/trie-<backend>. Pointing this at different directories is how
    /// one switches between trie stores -- a full archival one and a collected
    /// one, say -- without touching headers, bodies or the chain index.
    #[arg(long)]
    trie_dir: Option<String>,

    /// Trie storage backend: "single" (in the main database), "external" (its
    /// own database, no collection) or "epoch" (its own databases, collected).
    ///
    /// Defaults to single, which is what the node has always done: one
    /// database, every historical version retained, unbounded growth. The epoch
    /// backend bounds the size by periodically reclaiming state older than the
    /// retention window -- which means historical state queries below that
    /// window stop working. That is a real trade, so it is opt-in.
    #[arg(long, default_value = "single")]
    trie_backend: String,

    /// Storage engine behind the trie: rocksdb or flatdb.
    ///
    /// Orthogonal to --trie-backend, which chooses retention. This chooses
    /// what holds the nodes. flatdb is measurably faster on reads and far
    /// steadier (docs/flatdb.md), and it is **experimental**: it has not run
    /// on a real chain, so the default stays rocksdb until it has.
    ///
    /// The node refuses to start if the directory on disk was written by the
    /// other engine, rather than opening an empty store beside the data.
    #[arg(long, default_value = "rocksdb")]
    trie_engine: String,

    /// Blocks executed per trie durability point while catching up.
    ///
    /// Trie nodes are derivable — lose them and re-executing the block
    /// recomputes them — so the store may flush less often than the node
    /// executes. What it may not do is advance the executed head past what a
    /// crash would keep, and it does not: the head moves only at a flush.
    ///
    /// The cost of raising this is that many blocks of re-execution after an
    /// unclean stop. Follow mode ignores it and makes every block durable,
    /// because one block every thirty seconds can afford a flush.
    #[arg(long, default_value_t = 100)]
    trie_flush_every: u64,

    /// Keys to size a flatdb epoch's index for. Ignored by rocksdb.
    ///
    /// Zero, the default, derives it from the rotation threshold: an epoch
    /// rotates at --gc-rotate-mb, so the number of records it will ever hold
    /// is bounded and can be computed rather than guessed. Set it only to
    /// override that.
    ///
    /// Exceeding it costs a stop-the-world rehash. Over-sizing costs
    /// reclaimable address space and nothing else -- the index is a file
    /// mapping, not committed memory -- so the two errors are not
    /// symmetric and the derived figure errs large.
    #[arg(long, default_value_t = 0)]
    trie_expected_keys: u64,

    /// Epochs to keep with --trie-backend epoch. Minimum 3.
    ///
    /// More epochs means smaller, more frequent sweeps and less duplication,
    /// at the cost of one more place a read miss has to look.
    #[arg(long, default_value_t = 4)]
    gc_epochs: usize,

    /// Rotate the newest epoch once it reaches this many MB.
    #[arg(long, default_value_t = 1024)]
    gc_rotate_mb: u64,

    /// Blocks a state root must be buried by before it is collected against.
    ///
    /// Must exceed the deepest reorganisation worth surviving: collecting
    /// against a root that is later reorganised away discards the state the
    /// chain needs to rebuild.
    #[arg(long, default_value_t = 4_000)]
    gc_burial: u64,

    /// Entries in the BTC stored-block cache, or 0 to disable it.
    ///
    /// Answering "which BTC block is at height H?" costs one trie read per
    /// block of depth whenever the RSKIP199 height index cannot answer, so a
    /// deep query walks thousands of nodes. The cache holds blocks the node
    /// has already read for consensus; it never pre-loads and never records an
    /// absence, so it changes latency and nothing else.
    ///
    /// About 200 bytes per entry -- ~2 MB at the default.
    #[arg(long, default_value_t = 10_000)]
    btc_block_cache_entries: usize,

    /// Serve the `mnr_*` merged-mining JSON-RPC namespace, so mining software
    /// can ask this node for work and submit Bitcoin solutions back.
    ///
    /// Off by default. With this off the namespace reports as unknown, so a
    /// node that is not a miner looks exactly like one built without mining.
    #[arg(long)]
    mine: bool,

    /// Address block rewards are paid to. Required with --mine: mining to the
    /// zero address is almost never intended, and silently doing it would burn
    /// the reward of every block found.
    #[arg(long, value_name = "ADDRESS")]
    mining_coinbase: Option<String>,

    /// Client string for each mined block's `extraData`, as rskj's
    /// `miner.extraData`: the field is RLP `[1, "<version>-<commit>",
    /// <this>]`, and this is cut so the whole field stays within 32 bytes.
    #[arg(long, default_value = "")]
    mining_extra_data: String,

    /// Minimum gas price to steer mined blocks toward, in wei, as rskj's
    /// `miner.minGasPrice`: one RSKIP-09 step (1% of the parent's) per
    /// block. Absent, each block inherits its parent's.
    #[arg(long, value_name = "WEI")]
    mining_min_gas_price: Option<u64>,

    /// Refuse a merged-mining submission within this many milliseconds of
    /// the previous one, as rskj's `miner.server.workSubmissionRateLimitInMills`.
    /// Zero, the default, disables it.
    #[arg(long, default_value_t = 0, value_name = "MILLIS")]
    mining_submission_rate_limit_ms: u64,

    /// Rebuild the template when transactions worth at least a tenth of the
    /// candidate's fees have arrived, as rskj's
    /// `miner.server.updateWorkOnNewTransaction`. Off by default, as there;
    /// the refresh timer and every new best block rebuild regardless.
    #[arg(long, default_value_t = false)]
    mining_update_work_on_new_transaction: bool,

    /// Seconds between rebuilds of the block template handed to miners.
    ///
    /// A template goes stale as the chain advances and as transactions arrive;
    /// rskj rebuilds once a minute and so does this.
    #[arg(long, default_value_t = 60)]
    mining_refresh_secs: u64,

    /// Mine a block on a clock, as rskj's regtest does with
    /// `miner.client.timedMine`: each block after an exponentially
    /// distributed delay with this median (`10s`, `500ms`), floored at
    /// 100 ms and scaled by the difficulty's drift from the first block's.
    /// Blocks are mined whether or not the pool holds anything. With
    /// `--skip-pow-validation` the Bitcoin nonce is 0 and nothing is
    /// searched, as in rskj. Requires `--mine`; starts with the node, and
    /// `evm_stopMining` / `evm_startMining` (`--dev-rpc`) pause and resume it.
    #[arg(long, value_name = "MEDIAN")]
    mine_timed: Option<String>,

    /// Best blocks between trie flushes for blocks this node mines, like
    /// rskj's `blockchain.flushNumberOfBlocks`. 1 flushes every block,
    /// which is what a node mining for a pool wants.
    #[arg(long, value_name = "N", default_value_t = 10)]
    flush_every: u64,

    /// Blocks of history to keep below the head when pruning.
    ///
    /// Clamped up to 8,000 whatever is given: Rootstock's block-info
    /// precompiles reach 4,000 blocks back, and a reorg may re-execute from
    /// 4,000 back, so a re-executed block can read 8,000 back.
    #[arg(long, default_value_t = 100_000)]
    prune_keep_depth: u64,

    /// Most blocks one prune sweep may remove.
    #[arg(long, default_value_t = 50_000)]
    prune_max_batch: u64,

    /// Open both databases read-only and write nothing.
    ///
    /// Everything that would write is refused: execution, pruning, the
    /// freezer, the canonical index fill. What is left is a node that serves
    /// what it already has.
    ///
    /// For a server that several measurements run against, where the thing
    /// being measured is the client: a server that writes is not the same
    /// fixture twice.
    #[arg(long, default_value_t = false)]
    read_only: bool,

    /// Catch up with new blocks. `--follow-up false` serves what is held and
    /// does not sync, execute or follow.
    ///
    /// On by default, so an ordinary node is unaffected. Off, the node stops
    /// drifting forward, which is what makes a timed comparison against it
    /// repeatable.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    follow_up: bool,

    /// Behave as though the canonical chain ends at this height.
    ///
    /// Everything announced agrees with it, not only the block number: the
    /// status message's best number, hash, parent and **total difficulty as
    /// accumulated to this height**, the served block range, skeleton points,
    /// and the answers to header, body and block-hash requests. A client that
    /// can reach a block above it has not run the test that was intended.
    ///
    /// Only valid with `--follow-up false`. Simulating a shorter chain while
    /// still following a longer one is incoherent, and is rejected at startup
    /// rather than producing a node that disagrees with itself.
    #[arg(long, value_name = "HEIGHT")]
    simulate_height: Option<u64>,

    /// Exit once the chain is synced, reporting how long it took.
    ///
    /// "Synced" means executed, not merely downloaded: the executed head has
    /// reached the best height any peer advertises, and the node is following
    /// rather than still fetching. A node that has the headers but has not run
    /// the blocks has not finished the work being measured.
    ///
    /// For timed comparisons. A process exit is an unambiguous end time;
    /// scraping a log line for one invites disagreement about which line
    /// counts.
    #[arg(long, default_value_t = false)]
    exit_when_synced: bool,

    /// Delete block history below `--prune-keep-depth` as the node runs.
    ///
    /// Off by default, and deliberately: turning it on is not a tuning
    /// change, it deletes history that only a resync can bring back. A node
    /// holding the whole chain keeps holding it until someone says otherwise.
    ///
    /// Bodies, receipts and the transaction index for pruned heights go, so
    /// `eth_getTransactionByHash` and `eth_getTransactionReceipt` stop
    /// answering for them. Bridge events are kept: they live in their own
    /// index, self-contained, and are what the peg is debugged from.
    ///
    /// Sweeps never run while a snapshot sync is in progress.
    ///
    /// Removes **everything** below the floor: headers, the canonical index,
    /// total difficulties, bodies (and the uncles inside them), receipts and
    /// the transaction index. The narrower flags below do one part each.
    #[arg(long, default_value_t = false)]
    prune_blocks: bool,

    /// Remove block bodies below the floor -- and with them the uncles, which
    /// live inside bodies rather than in a store of their own.
    ///
    /// Leaves the headers, so the node keeps a complete chain it can still
    /// walk and serve, without the transactions.
    #[arg(long, default_value_t = false)]
    prune_bodies: bool,

    /// Remove headers, the canonical index and total difficulties below the
    /// floor.
    ///
    /// Requires `--prune-bodies` and `--prune-receipts`: bodies and receipts
    /// are keyed by block hash, and the canonical index that finds the hash
    /// for an old height goes with the headers. Keeping them without it leaves
    /// data nothing can name.
    #[arg(long, default_value_t = false)]
    prune_headers: bool,

    /// Remove receipts and the transaction index below the floor.
    #[arg(long, default_value_t = false)]
    prune_receipts: bool,

    /// Do not archive uncle headers in the freezer.
    ///
    /// Prevention rather than removal, and the name is a little kind to
    /// itself. Uncles have no store of their own in the block database -- they
    /// live inside bodies -- so the only separate copy is the freezer's, and
    /// the freezer cannot drop from the bottom: it has `truncate_head` for
    /// reorgs and no floor, and its 2 GiB segments hold about 1.8M headers
    /// each, so the coarsest it could prune is far larger than any keep depth.
    ///
    /// So a node that does not want uncle history simply never writes it. The
    /// end state is the same. What differs is that a node which already has
    /// uncle history keeps what it has.
    ///
    /// A node with this set cannot serve `rsk/63` for the heights it skipped,
    /// and cannot re-derive its own cumulative difficulty -- uncle difficulty
    /// counts toward it. Implied by `--prune-blocks`.
    #[arg(long, default_value_t = false)]
    prune_uncles: bool,

    /// Require a peer to show it is on the checkpointed chain.
    ///
    /// Asks for the header at the checkpoint height and checks its hash. A
    /// peer that cannot produce it is on a different chain, and the work below
    /// the checkpoint -- over 99% of mainnet's cumulative total -- is not
    /// credited to it.
    ///
    /// Off by default: a checkpoint hash is a statement about which chain is
    /// canonical, and shipping one asks whoever builds the node to choose a
    /// fork. That is a governance decision, so it is opt-in.
    /// `--checkpoint-bound-work` gives much of the benefit without it.
    #[arg(long, default_value_t = false)]
    checkpoint_verify_hash: bool,

    /// Bound a peer's claimed cumulative difficulty, sampling its chain above
    /// the checkpoint to do it.
    ///
    /// The bound and the sampling are one switch and cannot be separated. The
    /// bound alone refutes a claim only for a height at or below the
    /// checkpoint, which an attacker avoids for free by claiming a height
    /// above it -- and would claim anyway, since a sync peer wants to look
    /// like the longest chain. An option to bound without sampling would look
    /// like a defence and be none.
    ///
    /// Costs about 585 messages per peer judged, against rskj's limit of 1,000
    /// per minute. On by default: it is the only half of the gate with any
    /// adversarial value, and unlike `--checkpoint-verify-hash` it does not
    /// ask this node to declare which fork is canonical. Has no effect on a
    /// chain that ships no checkpoint.
    ///
    /// Takes a value because it defaults on: `--checkpoint-bound-work false`
    /// reaches the "no defence" corner of the matrix, and the bare flag still
    /// means on.
    #[arg(
        long,
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    checkpoint_bound_work: bool,

    /// Seconds between prune sweeps.
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    prune_every_secs: u64,

    /// Enable the `evm_*` namespace: snapshot, revert, reset, mine on demand
    /// and move the clock.
    ///
    /// For a development chain only. Every method in it rewrites or extends
    /// the chain on request, so a node running with this reachable from a
    /// network can be told to discard its own history. rskj ships the
    /// namespace on by default; this does not.
    #[arg(long)]
    dev_rpc: bool,

    /// Widest block range an `eth_getLogs` request may span.
    ///
    /// rskj's `rpc.logs.maxBlocksToQuery`, whose default is 5000. A wider
    /// range is rejected rather than served slowly, because the cost is paid
    /// by the node and the caller can always page.
    #[arg(long, default_value_t = rustock_rpc::logs::DEFAULT_MAX_BLOCK_RANGE, value_name = "BLOCKS")]
    rpc_logs_max_blocks: u64,

    /// Remember which key signed which transaction, so the pool and the
    /// executor do not each recover the same signature.
    ///
    /// Recovery is the most expensive arithmetic the node does per
    /// transaction, and almost every transaction in a block passed through
    /// this node's own pool first. On by default. `--sigcache=false` turns it
    /// off and every sender is recomputed, which is how this node behaved
    /// before the cache existed -- useful for measuring what it is worth, or
    /// for ruling it out while diagnosing something else.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    sigcache: bool,
    /// Estimate gas by binary search, as this node did before the
    /// single-pass estimator landed: execute at the cap, then halve the
    /// interval until it closes, about two dozen executions in all.
    ///
    /// The single-pass estimator is the default and answers the same
    /// question from one execution. This flag keeps the old one reachable
    /// for comparison; `the_exactimator_agrees_with_binary_search` is the
    /// test that says they agree.
    #[arg(long, default_value_t = false)]
    gas_estimator_binary_search: bool,

    /// Transactions one sender may have in the pool ahead of its state nonce
    /// (rskj `transaction.accountSlots`). A transaction with a nonce at or
    /// past the state nonce plus this is refused as "nonce too high".
    ///
    /// rskj's default too. A load generator that signs bursts per account
    /// (rsk-perf-lab's k6 suite runs rskj with 500) needs more, or its
    /// later nonces are refused while the earlier ones wait for a block.
    #[arg(long, default_value_t = 16)]
    account_slots: u64,

    /// Rate-limit accounts that broadcast transactions consuming large amounts
    /// of shared resources (rskj `transaction.accountTxRateLimit.enabled`).
    ///
    /// On by default, as in rskj. Each account accumulates "virtual gas" while
    /// idle and spends it when it broadcasts; an account that floods the
    /// mempool runs out and its transactions are refused entry here, so they
    /// are not relayed onward. Ordinary use never reaches the limit.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    account_tx_rate_limit: bool,

    /// Minutes between sweeps that drop accounts which have accumulated the
    /// full quota (rskj `transaction.accountTxRateLimit.cleanerPeriod`).
    ///
    /// An account at the ceiling is indistinguishable from one never seen, so
    /// keeping it costs memory and says nothing. Zero or negative disables the
    /// sweep, matching rskj.
    #[arg(long, default_value_t = 30)]
    account_tx_rate_limit_cleaner_period: i64,

    /// Most accounts tracked at once (rskj `MAX_QUOTAS_SIZE`). The map evicts
    /// the least recently accessed entry, so a flood of distinct addresses
    /// cannot grow it without bound.
    #[arg(long, default_value_t = 400_000)]
    account_tx_rate_limit_max_accounts: usize,

    /// How many seconds of idleness an account may bank, as a multiple of the
    /// per-second accrual (rskj `MAX_QUOTA_GAS_MULTIPLIER`).
    #[arg(long, default_value_t = 2_000)]
    account_tx_rate_limit_quota_multiplier: u64,

    /// Fraction of the block gas limit an account accrues per second of
    /// idleness (rskj `MAX_GAS_PER_SECOND_PERCENT`).
    #[arg(long, default_value_t = 0.9)]
    account_tx_rate_limit_gas_per_second_percent: f64,

    /// Enable administrative JSON-RPC methods.
    ///
    /// Off by default. These act on the node rather than answering questions
    /// about the chain -- rsk_collectTrie deletes a database -- and the RPC
    /// server binding to localhost is a deployment detail, not an access
    /// control decision. With this off the methods report as unknown, so a node
    /// without them is indistinguishable from one that never had them.
    #[arg(long)]
    rpc_admin: bool,

    /// Private keys this node may sign with, one 32-byte hex key per line.
    ///
    /// Off by default, and the only way the node ever holds a key for
    /// signing. Without it `eth_accounts` is empty and `eth_sign`,
    /// `eth_signTransaction` and `eth_sendTransaction` report as unknown
    /// methods, so a node with no wallet is indistinguishable from one
    /// built without the feature.
    ///
    /// A file rather than a flag taking the key itself, because a private
    /// key on the command line is visible in `ps` to every user on the
    /// machine and lands in shell history. Give the file mode 0600.
    ///
    /// Keys are held in memory for the life of the process and never
    /// written anywhere. This is not a keystore: there is no encryption,
    /// no passphrase and no `personal_*` namespace. It exists so a test
    /// harness can drive `eth_sendTransaction` from funded senders.
    ///
    /// **Do not point this at a node serving a public RPC endpoint.**
    #[arg(long, value_name = "FILE")]
    wallet_file: Option<std::path::PathBuf>,

    /// Seconds between checks of whether the store needs collecting.
    #[arg(long, default_value_t = 60)]
    gc_check_secs: u64,

    /// Print everything about the node at this path, then exit.
    ///
    /// Path notation is <hex>/<bits>, e.g. "a3f0/13"; bare hex means four bits
    /// per digit. Reads --trie-tool-source. Paths printed by --trie-tool can
    /// be passed straight back in.
    #[arg(long)]
    trie_node: Option<String>,

    /// Regtest: start from this rskj genesis JSON file instead of the
    /// built-in genesis, so blocks an rskj node mined from it connect here.
    #[arg(long, value_name = "FILE")]
    genesis: Option<std::path::PathBuf>,

    /// Regtest: accept headers without checking merged-mining proof of work,
    /// like rskj's `miner.server.skipPowValidation = true`. For replaying a
    /// chain mined without real proof of work.
    #[arg(long, default_value_t = false)]
    skip_pow_validation: bool,

    /// Regtest: override an rskj consensus rule, as `name=height` (`-1`
    /// disables it), like rskj's `blockchain.config.consensusRules`.
    /// Repeatable. Supported: rskip97.
    #[arg(long, value_name = "NAME=HEIGHT")]
    consensus_rule: Vec<String>,

    /// Regtest: smallest gas limit a header may declare (rskj: 3,000,000).
    #[arg(long, value_name = "GAS")]
    min_gas_limit: Option<u64>,

    /// Regtest: largest gas limit a header may declare (rskj has none).
    #[arg(long, value_name = "GAS")]
    max_gas_limit: Option<u64>,

    /// Regtest: schedule an rskj network upgrade, as `name=height` (`-1`
    /// takes it off the ladder), like rskj's
    /// `blockchain.config.hardforkActivationHeights`. Repeatable. Names are
    /// rskj's, orchid to vetiver900. bahamas, afterBridgeSync and hop401 are
    /// accepted at the height this node already reads them at; orchid060 and
    /// tbd1000 are accepted and change nothing (tbd1000 only turns on
    /// RSKIP-559, pegout sorting in the Bridge, which this node does not
    /// implement).
    #[arg(long, value_name = "NAME=HEIGHT")]
    hardfork: Vec<String>,

    /// Take --hardfork, --consensus-rule, --skip-pow-validation and the
    /// gas-limit bounds on mainnet and testnet too, for replaying blocks
    /// mined on a copy of the chain under rules it has not activated. Never
    /// for a node that follows the real network. --genesis stays refused:
    /// a genesis file would make this another chain.
    #[arg(long, default_value_t = false)]
    allow_chain_overrides: bool,

    /// Import the blocks of an rskj `ExportBlocks` file (`number,hash,td,rlp`
    /// per line, plain or .gz) on top of this node's best block, through the
    /// validation and execution follow mode uses, then exit. Stops with a
    /// non-zero status at the first block that fails a check.
    #[arg(long, value_name = "FILE")]
    import_blocks: Option<std::path::PathBuf>,

    /// Write the canonical chain, from --export-from to --export-to, to this
    /// file in rskj's `ExportBlocks` format (`number,hash,td,rlp` per line;
    /// gzip when the name ends in .gz), then exit. What rskj's
    /// `ConnectBlocks` and this node's --import-blocks read.
    #[arg(long, value_name = "FILE")]
    export_blocks: Option<std::path::PathBuf>,

    /// With --export-blocks: the first block to write (default 1).
    #[arg(long, value_name = "N", default_value_t = 1)]
    export_from: u64,

    /// With --export-blocks: the last block to write (default: the best
    /// block).
    #[arg(long, value_name = "N")]
    export_to: Option<u64>,

    /// With --import-blocks: blocks between trie flushes (rskj's
    /// `blockchain.flushNumberOfBlocks`).
    #[arg(long, value_name = "N", default_value_t = rustock_sync::import::DEFAULT_IMPORT_FLUSH_EVERY)]
    import_flush_every: u64,

    /// Write one timing line per block connected as best to this file, in
    /// the shape of rskj's `block connect breakdown best:` debug line
    /// (milliseconds, three decimals): with --import-blocks for every
    /// imported block, with --mine for every block this node mines and
    /// connects. Off by default, and then no clock is read.
    #[arg(long, value_name = "FILE")]
    breakdown_log: Option<std::path::PathBuf>,
}

/// Apply the file underneath the command line, one setting per line so the
/// mapping from key to flag is readable at a glance.
///
/// `apply` is a no-op for anything the operator typed, which is what makes the
/// precedence `command line > file > default`.
fn apply_file_config(
    matches: &clap::ArgMatches,
    f: &config_file::FileConfig,
    a: &mut Args,
) {
    use config_file::{apply, apply_opt};

    apply(matches, "port", f.node.port.as_ref(), &mut a.port);
    apply_opt(matches, "genesis", f.chain.genesis.as_ref(), &mut a.genesis);
    apply(matches, "skip_pow_validation", f.chain.skip_pow_validation.as_ref(),
        &mut a.skip_pow_validation);
    let rules = f.chain.consensus_rules.as_ref().map(|r| {
        r.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>()
    });
    apply(matches, "consensus_rule", rules.as_ref(), &mut a.consensus_rule);
    apply_opt(matches, "min_gas_limit", f.chain.min_gas_limit.as_ref(), &mut a.min_gas_limit);
    apply_opt(matches, "max_gas_limit", f.chain.max_gas_limit.as_ref(), &mut a.max_gas_limit);
    let hardforks = f.chain.hardforks.as_ref().map(|r| {
        r.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>()
    });
    apply(matches, "hardfork", hardforks.as_ref(), &mut a.hardfork);
    apply(matches, "allow_chain_overrides", f.chain.allow_overrides.as_ref(),
        &mut a.allow_chain_overrides);
    apply(matches, "data_dir", f.node.data_dir.as_ref(), &mut a.data_dir);
    apply(matches, "network_id", f.node.network_id.as_ref(), &mut a.network_id);
    apply_opt(matches, "secret_key", f.node.secret_key.as_ref(), &mut a.secret_key);
    apply_opt(matches, "external_ip", f.node.external_ip.as_ref(), &mut a.external_ip);
    apply(matches, "supply_check", f.node.supply_check.as_ref(), &mut a.supply_check);
    apply(matches, "execution_threads", f.node.execution_threads.as_ref(),
        &mut a.execution_threads);
    apply(matches, "read_only", f.node.read_only.as_ref(), &mut a.read_only);
    apply(matches, "follow_up", f.node.follow_up.as_ref(), &mut a.follow_up);
    apply_opt(matches, "simulate_height", f.node.simulate_height.as_ref(), &mut a.simulate_height);
    apply(matches, "exit_when_synced", f.node.exit_when_synced.as_ref(), &mut a.exit_when_synced);
    apply(matches, "rskj_multisig_senders", f.node.rskj_multisig_senders.as_ref(),
        &mut a.rskj_multisig_senders);

    apply_opt(matches, "metrics_port", f.metrics.port.as_ref(), &mut a.metrics_port);
    apply(matches, "metrics_host", f.metrics.host.as_ref(), &mut a.metrics_host);

    apply(matches, "rpc_host", f.rpc.host.as_ref(), &mut a.rpc_host);
    apply(matches, "rpc_port", f.rpc.port.as_ref(), &mut a.rpc_port);
    apply(matches, "rpc_admin", f.rpc.admin.as_ref(), &mut a.rpc_admin);
    apply_opt(matches, "wallet_file", f.rpc.wallet_file.as_ref(), &mut a.wallet_file);
    apply(matches, "no_rpc", f.rpc.disabled.as_ref(), &mut a.no_rpc);
    apply(matches, "ws", f.rpc.ws.as_ref(), &mut a.ws);
    apply(matches, "ws_port", f.rpc.ws_port.as_ref(), &mut a.ws_port);
    apply(matches, "checkpoint_verify_hash", f.checkpoint.verify_hash.as_ref(),
        &mut a.checkpoint_verify_hash);
    apply(matches, "checkpoint_bound_work", f.checkpoint.bound_work.as_ref(),
        &mut a.checkpoint_bound_work);
    apply(matches, "snap_server", f.snapshot.server.as_ref(), &mut a.snap_server);
    apply(matches, "snap_sync", f.snapshot.sync.as_ref(), &mut a.snap_sync);
    apply(matches, "snap_blocks", f.snapshot.blocks.as_ref(), &mut a.snap_blocks);
    apply(matches, "snap_forward_headers", f.snapshot.forward_headers.as_ref(),
        &mut a.snap_forward_headers);
    apply(matches, "snap_chunk_bytes", f.snapshot.chunk_bytes.as_ref(), &mut a.snap_chunk_bytes);
    apply(matches, "snap_chunk_grid", f.snapshot.chunk_grid.as_ref(), &mut a.snap_chunk_grid);
    apply(matches, "snap_parallel", f.snapshot.parallel.as_ref(), &mut a.snap_parallel);
    apply(
        matches,
        "snap_index_history",
        f.snapshot.index_history.as_ref(),
        &mut a.snap_index_history,
    );
    apply(matches, "snap_peer_rate", f.snapshot.peer_rate.as_ref(), &mut a.snap_peer_rate);
    apply(matches, "snap_total_rate", f.snapshot.total_rate.as_ref(), &mut a.snap_total_rate);

    apply(matches, "max_peers", f.peers.max_peers.as_ref(), &mut a.max_peers);
    apply(matches, "max_inbound_peers", f.peers.max_inbound_peers.as_ref(),
        &mut a.max_inbound_peers);
    apply(matches, "max_inbound_per_ip", f.peers.max_inbound_per_ip.as_ref(),
        &mut a.max_inbound_per_ip);
    apply(matches, "max_inbound_per_cidr", f.peers.max_inbound_per_cidr.as_ref(),
        &mut a.max_inbound_per_cidr);
    apply(matches, "inbound_cidr_prefix", f.peers.inbound_cidr_prefix.as_ref(),
        &mut a.inbound_cidr_prefix);
    apply(matches, "closed_network", f.peers.closed_network.as_ref(),
        &mut a.closed_network);
    // A list, so `apply`'s "the CLI wins" rule does not fit: the two sources
    // are *combined*. An operator keeping a standing ban list in the config
    // file should still be able to add one on the command line without
    // retyping the rest.
    if let Some(banned) = &f.peers.banned_peers {
        for entry in banned {
            if !a.banned_peers.contains(entry) {
                a.banned_peers.push(entry.clone());
            }
        }
    }
    // Unlike `banned_peers` this one **replaces** rather than combines: the
    // flag exists to say "bootstrap from these and nothing else", and merging
    // it with a file's list would quietly defeat that.
    if a.bootnodes.is_empty() {
        if let Some(b) = &f.peers.bootnodes {
            a.bootnodes = b.clone();
        }
    }
    apply(matches, "no_peer_punishment", f.peers.no_peer_punishment.as_ref(),
        &mut a.no_peer_punishment);

    apply(matches, "trie_backend", f.trie.backend.as_ref(), &mut a.trie_backend);
    apply(matches, "trie_engine", f.trie.engine.as_ref(), &mut a.trie_engine);
    apply(matches, "trie_expected_keys", f.trie.expected_keys.as_ref(),
        &mut a.trie_expected_keys);
    apply(matches, "trie_flush_every", f.trie.flush_every.as_ref(),
        &mut a.trie_flush_every);
    apply(
        matches,
        "btc_block_cache_entries",
        f.trie.btc_block_cache_entries.as_ref(),
        &mut a.btc_block_cache_entries,
    );
    apply_opt(matches, "trie_dir", f.trie.dir.as_ref(), &mut a.trie_dir);
    apply_opt(matches, "trie_node", f.trie.node.as_ref(), &mut a.trie_node);

    apply(matches, "gc_epochs", f.gc.epochs.as_ref(), &mut a.gc_epochs);
    apply(matches, "gc_rotate_mb", f.gc.rotate_mb.as_ref(), &mut a.gc_rotate_mb);
    apply(matches, "gc_burial", f.gc.burial.as_ref(), &mut a.gc_burial);
    apply(matches, "gc_check_secs", f.gc.check_secs.as_ref(), &mut a.gc_check_secs);

    apply(matches, "read_threads", f.trie.read_threads.as_ref(), &mut a.read_threads);

    apply(matches, "prune_keep_depth", f.prune.keep_depth.as_ref(), &mut a.prune_keep_depth);
    apply(matches, "prune_max_batch", f.prune.max_batch.as_ref(), &mut a.prune_max_batch);
    apply(matches, "prune_blocks", f.prune.blocks.as_ref(), &mut a.prune_blocks);
    apply(matches, "prune_bodies", f.prune.bodies.as_ref(), &mut a.prune_bodies);
    apply(matches, "prune_headers", f.prune.headers.as_ref(), &mut a.prune_headers);
    apply(matches, "prune_receipts", f.prune.receipts.as_ref(), &mut a.prune_receipts);
    apply(matches, "prune_uncles", f.prune.uncles.as_ref(), &mut a.prune_uncles);
    apply(matches, "prune_every_secs", f.prune.every_secs.as_ref(), &mut a.prune_every_secs);
    apply(matches, "prune_frozen_headers", f.prune.frozen_headers.as_ref(),
        &mut a.prune_frozen_headers);
    apply(matches, "freezer", f.prune.freezer.as_ref(), &mut a.freezer);
    apply(matches, "dev_rpc", f.rpc.dev.as_ref(), &mut a.dev_rpc);
    apply(matches, "sigcache", f.node.sigcache.as_ref(), &mut a.sigcache);
    apply(matches, "account_slots", f.node.account_slots.as_ref(), &mut a.account_slots);
    apply(
        matches,
        "rpc_logs_max_blocks",
        f.rpc.logs_max_blocks.as_ref(),
        &mut a.rpc_logs_max_blocks,
    );
    apply(
        matches,
        "gas_estimator_binary_search",
        f.rpc.gas_estimator_binary_search.as_ref(),
        &mut a.gas_estimator_binary_search,
    );

    apply(matches, "mine", f.mining.enabled.as_ref(), &mut a.mine);
    apply_opt(matches, "mining_coinbase", f.mining.coinbase.as_ref(), &mut a.mining_coinbase);
    apply(matches, "mining_extra_data", f.mining.extra_data.as_ref(), &mut a.mining_extra_data);
    apply(matches, "mining_refresh_secs", f.mining.refresh_secs.as_ref(),
        &mut a.mining_refresh_secs);
    apply_opt(matches, "mining_min_gas_price", f.mining.min_gas_price.as_ref(), &mut a.mining_min_gas_price);
    apply(matches, "mining_submission_rate_limit_ms", f.mining.submission_rate_limit_ms.as_ref(),
        &mut a.mining_submission_rate_limit_ms);
    apply(matches, "mining_update_work_on_new_transaction",
        f.mining.update_work_on_new_transaction.as_ref(), &mut a.mining_update_work_on_new_transaction);
    apply_opt(matches, "mine_timed", f.mining.timed.as_ref(), &mut a.mine_timed);
    apply(matches, "flush_every", f.mining.flush_every.as_ref(), &mut a.flush_every);

    apply(matches, "account_tx_rate_limit", f.account_tx_rate_limit.enabled.as_ref(),
        &mut a.account_tx_rate_limit);
    apply(matches, "account_tx_rate_limit_cleaner_period",
        f.account_tx_rate_limit.cleaner_period.as_ref(),
        &mut a.account_tx_rate_limit_cleaner_period);
    apply(matches, "account_tx_rate_limit_max_accounts",
        f.account_tx_rate_limit.max_accounts.as_ref(),
        &mut a.account_tx_rate_limit_max_accounts);
    apply(matches, "account_tx_rate_limit_quota_multiplier",
        f.account_tx_rate_limit.quota_multiplier.as_ref(),
        &mut a.account_tx_rate_limit_quota_multiplier);
    apply(matches, "account_tx_rate_limit_gas_per_second_percent",
        f.account_tx_rate_limit.gas_per_second_percent.as_ref(),
        &mut a.account_tx_rate_limit_gas_per_second_percent);

    apply(matches, "log_level", f.log.level.as_ref(), &mut a.log_level);
    apply(matches, "log_to_stdout", f.log.to_stdout.as_ref(), &mut a.log_to_stdout);
    apply(matches, "log_timezone", f.log.timezone.as_ref(), &mut a.log_timezone);

    apply_opt(matches, "alerts_config", f.alerts.alerts_config.as_ref(),
        &mut a.alerts_config);
}

/// Parse `--log-timezone` into a UTC offset.
///
/// `utc`, `local`, or a fixed `±HH:MM` / `±HHMM` / `±HH`.
///
/// `local` needs the offset the caller read before the runtime started; when
/// that could not be determined this returns an error rather than quietly
/// logging in UTC, because a timestamp in a timezone the operator did not ask
/// for is worse than a refusal to start. They can pass the offset instead.
fn parse_log_timezone(
    spec: &str,
    local_offset: Option<time::UtcOffset>,
) -> Result<time::UtcOffset> {
    let spec = spec.trim();
    match spec.to_ascii_lowercase().as_str() {
        "utc" | "z" | "" => return Ok(time::UtcOffset::UTC),
        "local" => {
            return local_offset.ok_or_else(|| {
                anyhow::anyhow!(
                    "--log-timezone local: this machine's UTC offset could not be \
                     determined. Pass the offset instead, for example \
                     --log-timezone -03:00"
                )
            })
        }
        _ => {}
    }

    let (sign, rest) = match spec.split_at_checked(1) {
        Some(("+", rest)) => (1i8, rest),
        Some(("-", rest)) => (-1i8, rest),
        _ => {
            return Err(anyhow::anyhow!(
                "--log-timezone {spec:?}: expected `utc`, `local`, or a signed offset \
                 such as -03:00"
            ))
        }
    };

    // The shape is checked rather than the colons stripped. Stripping them
    // accepts `-1:2` and reads it as `-12:00`, which is not a parse failure
    // the operator would ever see -- every log line would simply carry the
    // wrong offset. Two digits mean two digits.
    let digits: Vec<char> = rest.chars().collect();
    let two = |a: char, b: char| -> Option<i8> {
        (a.is_ascii_digit() && b.is_ascii_digit())
            .then(|| (a as i8 - b'0' as i8) * 10 + (b as i8 - b'0' as i8))
    };
    let (hours, minutes) = match digits.as_slice() {
        [h1, h2] => (two(*h1, *h2), Some(0)),
        [h1, h2, m1, m2] => (two(*h1, *h2), two(*m1, *m2)),
        [h1, h2, ':', m1, m2] => (two(*h1, *h2), two(*m1, *m2)),
        _ => {
            return Err(anyhow::anyhow!(
                "--log-timezone {spec:?}: expected ±HH, ±HHMM or ±HH:MM"
            ))
        }
    };
    let (Some(hours), Some(minutes)) = (hours, minutes) else {
        return Err(anyhow::anyhow!(
            "--log-timezone {spec:?}: expected ±HH, ±HHMM or ±HH:MM"
        ));
    };
    if !(0..=59).contains(&minutes) {
        return Err(anyhow::anyhow!("--log-timezone {spec:?}: minutes must be 00-59"));
    }

    time::UtcOffset::from_hms(sign * hours, sign * minutes, 0).map_err(|_| {
        // `time` caps offsets at ±25:59:59; the real world stops at ±14:00.
        anyhow::anyhow!("--log-timezone {spec:?}: offset out of range")
    })
}

/// The timestamp format: RFC 3339 with **one** subsecond digit.
///
/// `2026-09-25T19:02:09.1-03:00`.
///
/// The well-known `Rfc3339` formatter prints full nanosecond precision
/// (`.147085805`), which is nine digits of noise on every line of a node
/// whose interesting events are hundreds of milliseconds apart. RFC 3339
/// allows any number of `time-secfrac` digits, so one is still conformant and
/// still parses.
///
/// The offset is kept mandatory, so it travels with every timestamp -- `Z`
/// for UTC, `-03:00` otherwise -- and neither a reader nor a parser has to be
/// told separately which zone a line is in.
///
/// The cost is that two events inside the same tenth of a second are no
/// longer ordered by their timestamps. The journal preserves arrival order
/// regardless, and the durations that matter are logged as explicit
/// milliseconds rather than inferred from timestamps.
const LOG_TIMESTAMP: &[time::format_description::BorrowedFormatItem<'static>] = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:1][offset_hour sign:mandatory]:[offset_minute]"
);

/// The timer the subscriber formats timestamps with.
fn log_timer(
    spec: &str,
    local_offset: Option<time::UtcOffset>,
) -> Result<
    tracing_subscriber::fmt::time::OffsetTime<
        &'static [time::format_description::BorrowedFormatItem<'static>],
    >,
> {
    let offset = parse_log_timezone(spec, local_offset)?;
    Ok(tracing_subscriber::fmt::time::OffsetTime::new(offset, LOG_TIMESTAMP))
}

/// The machine's UTC offset, read **before** the tokio runtime exists.
///
/// The `time` crate refuses to determine the local offset once a process is
/// multithreaded, and it is right to: another thread calling `setenv("TZ")`
/// concurrently with `localtime_r` is a data race in C, and the crate will
/// not paper over it. `tracing_subscriber`'s `LocalTime` hits exactly this
/// and is gated behind an `--cfg unsound_local_offset` build flag as a
/// result.
///
/// So the offset is read here, in the last moment this process is
/// single-threaded, and then held fixed. That is also why
/// `--log-timezone local` cannot follow a daylight-saving transition: the
/// offset is decided once, at start-up. A fixed `±HH:MM` says so plainly.
/// The pruning flags as one configuration.
///
/// Built in one place so the start-up refusal and the sweep cannot disagree
/// about what was asked for.
fn prune_config_from(args: &Args) -> rustock_storage::pruner::PruneConfig {
    rustock_storage::pruner::PruneConfig {
        keep_depth: args.prune_keep_depth,
        max_batch: args.prune_max_batch,
        headers: args.prune_blocks || args.prune_headers,
        bodies: args.prune_blocks || args.prune_bodies,
        receipts: args.prune_blocks || args.prune_receipts,
    }
}

fn resolve_local_offset() -> Option<time::UtcOffset> {
    time::UtcOffset::current_local_offset().ok()
}

fn main() -> Result<()> {
    // Before anything spawns a thread.
    let local_offset = resolve_local_offset();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(local_offset))
}

async fn run(local_offset: Option<time::UtcOffset>) -> Result<()> {
    // Parse once, keeping the matches so the merge below can ask clap which
    // values the operator actually typed -- with the derive API a flag that was
    // never passed still arrives carrying its default.
    let matches = Args::command().get_matches();
    let mut args = Args::from_arg_matches(&matches)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(path) = args.config.clone() {
        let file = config_file::FileConfig::load(&path)?;
        apply_file_config(&matches, &file, &mut args);
    }
    let args = args;

    // Before anything opens a store: every parallel read in the node reads
    // this, and it is meant to be set once.
    rustock_storage::set_read_threads(args.read_threads);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    // Argument validation, before anything opens a database. A combination that
    // cannot work should say so in the first second, not after a minute of
    // start-up -- and certainly not after the first sweep has run.
    if let Some(why) = prune_config_from(&args).refusal() {
        anyhow::bail!("these pruning options cannot be combined: {why}");
    }

    std::fs::create_dir_all(&args.data_dir).context("Failed to create data directory")?;

    let timer = log_timer(&args.log_timezone, local_offset)?;

    let _guard = if args.log_to_stdout {
        // Colour only when stdout is a terminal. Under systemd it is a pipe
        // into journald, and the escapes are then *stored* in the journal --
        // invisible in `journalctl`'s default view, which strips them, and
        // very visible the moment anyone uses `-o cat`, pipes to a file, or
        // greps. The file path has always passed `false` here; the stdout
        // path assumed a human was watching.
        let colour = std::io::IsTerminal::is_terminal(&std::io::stdout());
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_timer(timer)
            .with_ansi(colour)
            .init();
        None
    } else {
        let file_appender = tracing_appender::rolling::daily(&args.data_dir, "rustock.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_timer(timer)
            .with_writer(non_blocking)
            .init();

        let log_path = std::path::Path::new(&args.data_dir).join("rustock.log");
        eprintln!("Logging to {}", log_path.display());
        eprintln!("Use --log-to-stdout to log to the console instead.");
        eprintln!("Tail the log: tail -f {}", log_path.display());

        Some(guard)
    };

    // Say the offset once, in words, even though every line already carries
    // it. A reader skimming a log for a time they remember should not have to
    // notice a `-03:00` suffix to realise the whole file is not in UTC.
    let offset = parse_log_timezone(&args.log_timezone, local_offset)?;
    let (oh, om, _) = offset.as_hms();
    if offset.is_utc() {
        info!("Log timestamps are UTC (GMT+00:00)");
    } else {
        info!(
            "Log timestamps are GMT{}{:02}:{:02} -- every line carries the offset",
            if oh < 0 || om < 0 { '-' } else { '+' },
            oh.abs(),
            om.abs(),
        );
    }

    info!("Starting Rustock on port {}...", args.port);

    let config = match args.network_id {
        30 => ChainConfig::mainnet(),
        31 => ChainConfig::testnet(),
        _ => ChainConfig::regtest(),
    };
    let config = Arc::new(apply_chain_options(config, &args)?);
    // Block-hash computation (RSKIP92) needs the activation heights before
    // any header is decoded.
    config.activation_heights.clone().install();

    match args.supply_check.as_str() {
        "both" => {}
        "per-transaction" | "tx" => rustock_execution::supply::set_per_block(false),
        "per-block" | "block" => rustock_execution::supply::set_per_transaction(false),
        "off" | "none" => {
            rustock_execution::supply::set_per_transaction(false);
            rustock_execution::supply::set_per_block(false);
            tracing::warn!("supply conservation checking is DISABLED");
        }
        other => anyhow::bail!(
            "unknown --supply-check {other:?}; expected both, per-transaction, per-block or off"
        ),
    }
    info!(
        "supply check: per-transaction {}, per-block {}",
        rustock_execution::supply::per_transaction_enabled(),
        rustock_execution::supply::per_block_enabled()
    );

    if let Some(path) = &args.export_blocks {
        let store = BlockStore::open(&args.data_dir)?;
        return run_export_blocks(&store, path, args.export_from, args.export_to);
    }

    if args.build_bridge_index {
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        rustock_storage::rskj_import::install_signal_handlers();
        run_build_bridge_index(&store, args.receipts_from, args.receipts_to)?;
        return Ok(());
    }

    if args.build_height_index {
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        rustock_storage::rskj_import::install_signal_handlers();
        run_build_height_index(&store)?;
        return Ok(());
    }

    if let Some(dir) = args.import_rskj_receipts.clone() {
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        rustock_storage::rskj_import::install_signal_handlers();
        run_import_receipts(&store, &dir, args.receipts_from, args.receipts_to)?;
        return Ok(());
    }

    if let Some(task) = args.repair.clone() {
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        match task.as_str() {
            "tx-index" => run_repair_tx_index(&store, args.repair_from, args.repair_to)?,
            "total-difficulty" => {
                run_repair_total_difficulty(&store, args.repair_from, args.repair_to)?
            }
            "chain-work" => {
                // The pass writes uncle headers into the freezer, so it needs
                // the real one attached -- the node's own startup path does
                // this later, but a repair never reaches it.
                let dir = std::path::Path::new(&args.data_dir).join("freezer");
                let f = Arc::new(rustock_storage::freezer::Freezer::open(&dir)?);
                info!(
                    "Freezer at {}: {} header(s), {} uncle list(s), {} MB",
                    dir.display(),
                    f.end_number(),
                    f.uncles_end_number(),
                    f.data_bytes() / (1 << 20),
                );
                store.set_freezer(f);
                run_repair_chain_work(&store, args.repair_from, args.repair_to)?
            }
            "canonical" => run_repair_canonical(&store, args.repair_from)?,
            other => anyhow::bail!(
                "unknown repair task {other:?}; known tasks: tx-index, total-difficulty, \
                 chain-work, canonical"
            ),
        }
        return Ok(());
    }

    if args.metadata_in_memory {
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        rustock_storage::rskj_import::install_signal_handlers();
        let wal = if args.import_enable_wal {
            rustock_storage::rskj_import::WalMode::Enabled
        } else {
            rustock_storage::rskj_import::WalMode::Disabled
        };
        let mut csv = match args.import_metrics.as_deref() {
            Some(p) => Some(std::fs::OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        let tip = rustock_storage::rskj_import::rebuild_chain_metadata_in_memory(
            &store,
            wal,
            csv.as_mut().map(|f| f as &mut dyn std::io::Write),
        )?;
        info!("Chain metadata rebuilt in memory, head #{tip}");
        return Ok(());
    }

    if let Some(dump) = args.import_index_dump.clone() {
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        rustock_storage::rskj_import::install_signal_handlers();
        let wal = if args.import_enable_wal {
            rustock_storage::rskj_import::WalMode::Enabled
        } else {
            rustock_storage::rskj_import::WalMode::Disabled
        };
        let mut csv = match args.import_metrics.as_deref() {
            Some(p) => Some(std::fs::OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        let tip = rustock_storage::rskj_import::load_metadata_from_dump(
            &store,
            std::path::Path::new(&dump),
            wal,
            csv.as_mut().map(|f| f as &mut dyn std::io::Write),
        )?;
        info!("Chain metadata loaded from index dump, head #{tip}");
        return Ok(());
    }

    if !args.metadata_range.is_empty() {
        if args.metadata_range.len() != 2 {
            anyhow::bail!("--metadata-range takes exactly two values: FROM TO");
        }
        let (from, to) = (args.metadata_range[0], args.metadata_range[1]);
        let store = Arc::new(BlockStore::open(&args.data_dir)?);
        rustock_storage::rskj_import::install_signal_handlers();
        let mut csv = match args.import_metrics.as_deref() {
            Some(p) => Some(std::fs::OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        rustock_storage::rskj_import::rebuild_chain_metadata_range(
            &store,
            from,
            to,
            csv.as_mut().map(|f| f as &mut dyn std::io::Write),
        )?;
        return Ok(());
    }

    if !args.probe_unitrie.is_empty() {
        let dir = args.probe_source.clone()
            .ok_or_else(|| anyhow::anyhow!("--probe-unitrie needs --probe-source"))?;
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.set_max_open_files(256);
        let path = std::path::Path::new(&dir).join("unitrie");
        let db = rocksdb::DB::open_for_read_only(&opts, &path, false)?;
        for hexkey in &args.probe_unitrie {
            let clean = hexkey.trim_start_matches("0x");
            let key = match hex::decode(clean) {
                Ok(k) => k,
                Err(e) => { println!("{hexkey}: BAD HEX ({e})"); continue; }
            };
            match db.get(&key)? {
                Some(v) => println!("{hexkey}: PRESENT ({} bytes)", v.len()),
                None => println!("{hexkey}: ABSENT"),
            }
        }
        return Ok(());
    }

    if let Some(src) = args.import_rskj.clone() {
        let parallelism = if args.import_parallelism == 0 {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
        } else {
            args.import_parallelism
        } as i32;
        let tuning = rustock_storage::ImportTuning {
            write_buffer_mb: args.import_write_buffer_mb,
            parallelism,
            auto_compaction: args.import_auto_compaction,
        };
        info!("Import tuning: {tuning:?}");
        // Opened with import settings rather than the node's: these trades are
        // safe only because a failed import is re-run, not repaired.
        let store = Arc::new(BlockStore::open_for_import(&args.data_dir, tuning)?);
        return run_rskj_import(
            &src,
            &store,
            args.import_metrics.as_deref(),
            args.import_skip_existing,
            !args.import_enable_wal,
            !args.import_auto_compaction,
            args.import_metadata_only,
            args.import_skip_unitrie,
            args.import_skip_metadata,
            if args.import_unitrie_threads == 0 {
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
            } else {
                args.import_unitrie_threads
            },
        );
    }

    if let Some(path) = args.trie_node.as_deref() {
        let src = args.trie_tool_source.as_deref().unwrap_or(&args.data_dir);
        return run_trie_node(src, args.trie_tool_block, path);
    }

    if args.trie_tool || args.trie_tool_block.is_some() || args.trie_tool_copy.is_some() {
        let src = args.trie_tool_source.as_deref().unwrap_or(&args.data_dir);
        return run_trie_tool(
            src,
            args.trie_tool_block,
            args.trie_tool_progress,
            args.trie_tool_copy.as_deref(),
            args.trie_tool_copy_overwrite,
        );
    }

    // Profiling modes attach to a database another process may own, so they
    // take the read-only path: it does not take RocksDB's lock and cannot
    // write. Everything else opens normally.
    let read_only =
        args.read_only || args.measure_block_reads.is_some() || args.verify_state.is_some();
    let store = Arc::new(if read_only {
        info!("Opening {} READ-ONLY; nothing this node does can write to it", args.data_dir);
        BlockStore::open_read_only(&args.data_dir)?
    } else {
        BlockStore::open(&args.data_dir)?
    });

    let genesis_hash = setup_genesis(&store, &config)?;
    info!("Genesis Hash: {:?}", genesis_hash);

    let verifier = Arc::new(HeaderVerifier::default_rsk(config.clone()));
    // The manager takes ownership below; snapshot sync needs the same rules.
    let verifier_for_snap = verifier.clone();

    let key_path = std::path::Path::new(&args.data_dir).join("node.key");

    let secret_key_bytes = if let Some(hex_key) = args.secret_key {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut bytes).context("Invalid hex for secret key")?;
        bytes
    } else if key_path.exists() {
        let hex_key = std::fs::read_to_string(&key_path).context("Failed to read node.key")?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_key.trim(), &mut bytes).context("Invalid hex in node.key")?;
        info!("Loaded existing node identity from {:?}", key_path);
        bytes
    } else {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);

        std::fs::create_dir_all(&args.data_dir).context("Failed to create data directory")?;
        std::fs::write(&key_path, hex::encode(bytes)).context("Failed to save node.key")?;

        info!("Generated and saved new node identity to {:?}", key_path);
        bytes
    };

    let signing_key = k256::ecdsa::SigningKey::from_slice(&secret_key_bytes)?;
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let node_id = alloy_primitives::B512::from_slice(&encoded_point.as_bytes()[1..]);
    // Printed in full because a peer that must be told who to dial needs it,
    // and deriving it from the key by hand is a step that invites a typo.
    info!("Node ID: {}", alloy_primitives::hex::encode(node_id.as_slice()));

    // `--simulate-height` rejected before anything opens, so a node that
    // disagrees with itself never starts. Simulating a shorter chain while
    // still following a longer one would advertise one head and keep adopting
    // another.
    if args.simulate_height.is_some() && args.follow_up {
        anyhow::bail!(
            "--simulate-height requires --follow-up false: a node that keeps catching up \
             would advertise the simulated head while adopting the real one"
        );
    }

    // The head this node speaks for. Normally its own; under
    // `--simulate-height`, the block at that height instead -- *and the total
    // difficulty accumulated to it*, which is the part that matters. A client
    // chooses what to sync from the advertised difficulty, so a simulated
    // height carrying the real chain's difficulty would be a node claiming the
    // work of blocks it refuses to serve.
    let announced_head = match args.simulate_height {
        Some(h) => store.canonical_hash(h)?.ok_or_else(|| {
            anyhow::anyhow!("--simulate-height {h}: this node has no canonical block there")
        })?,
        None => store.head()?.unwrap_or(genesis_hash),
    };
    if let Some(h) = args.simulate_height {
        info!(
            "Simulating a chain that ends at #{h} ({announced_head:?}); \
             nothing above it is announced or served"
        );
    }

    let (best_hash, best_td, best_number, best_parent) = if store.head()?.is_some() {
        let td = store.total_difficulty(announced_head)?.unwrap_or(U256::ZERO);
        let header = store.header(announced_head)?;
        let number = header.as_ref().map(|h| h.number).unwrap_or(0);
        // The status message is positional: without the parent, elements
        // three onwards cannot be sent at all, which is why this node used to
        // advertise a two-element status and never state its own total
        // difficulty on the RSK protocol.
        (announced_head, td, number, header.map(|h| h.parent_hash))
    } else {
        (genesis_hash, U256::ZERO, 0, None)
    };

    // Lowest block this node can serve. The prune floor when it has one, and
    // genesis otherwise -- a node holding everything says zero rather than
    // staying silent, because silence is what an rskj peer looks like and has
    // to keep meaning "ask me anything".
    let earliest_served = store
        .prune_floor()
        .ok()
        .flatten()
        .map(|f| f.number)
        .unwrap_or(0);

    let node_config = NodeConfig {
        client_id: "Rustock/0.1.0".to_string(),
        listen_port: args.port,
        id: node_id,
        chain_id: config.chain_id,
        network_id: config.network_id,
        genesis_hash,
        best_hash,
        best_block_number: best_number,
        best_block_parent_hash: best_parent,
        total_difficulty: best_td,
        earliest_block: earliest_served,
        // rskj offers `snap/1` whenever it speaks RSK; this node offers it
        // when it has something to do with snapshots at all, so that a peer
        // can tell a snapshot server from a node that will never answer.
        snap_capability: args.snap_server || args.snap_sync,
        bootnodes: if args.bootnodes.is_empty() {
            config.bootnodes()
        } else {
            info!(
                "Bootstrapping from {} given address(es) instead of the chain's built-in list",
                args.bootnodes.len()
            );
            args.bootnodes.clone()
        },
        closed_network: args.closed_network,
        read_only,
        secret_key: secret_key_bytes,
        discovery_port: args.port + 1,
        data_dir: args.data_dir.clone(),
        external_ip: args.external_ip,
        max_outbound_peers: args.max_peers,
        max_inbound_peers: args.max_inbound_peers,
        max_inbound_per_ip: args.max_inbound_per_ip,
        max_inbound_per_cidr: args.max_inbound_per_cidr,
        inbound_cidr_prefix: args.inbound_cidr_prefix,
    };

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let sync_manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    // Both switches, read once: the handler needs `bound_work` for the cheap
    // refutation, and the snapshot session needs both.
    let checkpoint_defence = rustock_core::checkpoint::CheckpointDefence {
        verify_hash: args.checkpoint_verify_hash,
        bound_work: args.checkpoint_bound_work,
    };

    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let sync_handler = Arc::new(
        SyncHandler::new(sync_manager.clone(), event_tx)
            .with_serve_ceiling(args.simulate_height)
            .with_checkpoint_defence(checkpoint_defence)
            .with_checkpoint(snap_checkpoint_for(args.network_id)),
    );
    let gc_config = rustock_storage::epoch_store::EpochConfig {
        epochs: args.gc_epochs,
        burial_depth: args.gc_burial,
        rotate_bytes: args.gc_rotate_mb * (1 << 20),
    };
    let rotate_bytes = gc_config.rotate_bytes;
    let backend = rustock_storage::epoch_store::TrieBackend::parse(&args.trie_backend, gc_config)?;
    let engine = rustock_storage::TrieEngine::parse(&args.trie_engine)?;
    // An epoch's key count is bounded by when it rotates, so the default
    // is computed rather than configured.
    let expected_keys = if args.trie_expected_keys > 0 {
        args.trie_expected_keys
    } else {
        rustock_storage::epoch_backend::keys_for_rotation(rotate_bytes)
    };
    if matches!(backend, rustock_storage::epoch_store::TrieBackend::Single)
        && engine == rustock_storage::TrieEngine::FlatDb
    {
        anyhow::bail!(
            "--trie-backend single keeps nodes in a column family of the node's main \
             database, which only rocksdb can provide; use --trie-backend external or \
             epoch to run flatdb"
        );
    }

    // The node only ever holds an `Arc<dyn TrieStore>`, so this is the entire
    // extent of the choice: nothing downstream knows which store it got.
    let trie_dir = args.trie_dir.clone().unwrap_or_else(|| {
        let suffix = if backend.is_collecting() { "trie-epochs" } else { "trie" };
        std::path::Path::new(&args.data_dir).join(suffix).to_string_lossy().into_owned()
    });
    // Always say where the trie is. With three backends and a migration in the
    // field, "which trie is this node actually reading?" is the first question
    // worth answering in any log, and the answer should not depend on which
    // backend happens to be selected.
    match &backend {
        rustock_storage::epoch_store::TrieBackend::Single => info!(
            "Trie store: single backend (trie_nodes column family inside {})",
            args.data_dir
        ),
        rustock_storage::epoch_store::TrieBackend::External => {
            info!("Trie store: external backend at {trie_dir} (no collection)")
        }
        rustock_storage::epoch_store::TrieBackend::Epochs(cfg) => info!(
            "Trie store: epoch backend at {trie_dir} (collecting; N={}, rotate at {} MB, burial {} blocks)",
            cfg.epochs,
            cfg.rotate_bytes / (1 << 20),
            cfg.burial_depth
        ),
    }

    // Refuse configurations that would come up with no state instead of failing.
    //
    // RocksDB is asked to create missing column families, so opening a database
    // whose trie was moved out recreates `trie_nodes` empty and the node starts
    // against a blank trie -- no error, no missing file, just a node that cannot
    // execute anything and looks like it needs a resync. That is worth stopping
    // for; the operator can always choose a backend, but they cannot recover
    // state that was quietly declared absent.
    {
        let has_chain = store.exec_head()?.is_some() || store.head()?.is_some();
        let detached_dir_populated = std::path::Path::new(&trie_dir)
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

        if !backend.is_detached() && has_chain && store.trie_cf_is_empty() {
            anyhow::bail!(
                "This database has no trie in it, but --trie-backend is \"{}\".\n\
                 \n\
                 Its trie column family is empty, which means the trie was moved \
                 into its own database (see examples/detach_trie.rs) and this \
                 column family was recreated empty on open. Starting like this \
                 would run the node against a blank trie.\n\
                 \n\
                 Start it against the detached trie instead:\n\
                 \x20   --trie-backend external --trie-dir <path-to-trie-db>\n\
                 \x20   --trie-backend epoch    --trie-dir <path-to-epoch-store>",
                args.trie_backend
            );
        }

        if backend.is_detached() && has_chain && !detached_dir_populated && !store.trie_cf_is_empty() {
            anyhow::bail!(
                "--trie-backend {} points at {}, which is empty, while this \
                 database still holds its own trie.\n\
                 \n\
                 Starting would create an empty trie store and the node would be \
                 unable to execute. Move the trie out first:\n\
                 \n\
                 \x20   cargo run --release --example detach_trie -- {} {}\n\
                 \n\
                 then start with the same --trie-dir. The source database is \
                 opened read-only and is not modified.",
                args.trie_backend, trie_dir, args.data_dir, trie_dir
            );
        }
    }

    let epoch_store: Option<Arc<rustock_storage::epoch_store::EpochTrieStore>> = match &backend {
        rustock_storage::epoch_store::TrieBackend::Epochs(cfg) => {
            Some(Arc::new(if read_only {
                rustock_storage::epoch_store::EpochTrieStore::open_read_only(
                    &trie_dir,
                    cfg.clone(),
                )?
            } else {
                // Where execution will resume from. An epoch this open
                // inherits mid-flight holds nothing written above it, so
                // this is the upper bound that lets the collector sweep it
                // later; without it that epoch is never collectable and the
                // store grows without bound.
                let resume_at = match store.exec_head()? {
                    Some((hash, _)) => store.header(hash)?.map(|h| h.number),
                    None => None,
                };
                engine.check_matches(std::path::Path::new(&trie_dir))?;
                rustock_storage::epoch_store::EpochTrieStore::open_with(
                    &trie_dir,
                    cfg.clone(),
                    resume_at,
                    engine.factory(expected_keys),
                )?
            }))
        }
        _ => None,
    };
    let external_store: Option<Arc<dyn rustock_trie::TrieStore>> = match &backend {
        rustock_storage::epoch_store::TrieBackend::External => {
            let dir = std::path::Path::new(&trie_dir);
            engine.check_matches(dir)?;
            Some(match engine {
                rustock_storage::TrieEngine::RocksDb => {
                    Arc::new(rustock_storage::RocksDbTrieStore::open(dir)?)
                }
                rustock_storage::TrieEngine::FlatDb => {
                    Arc::new(rustock_storage::FlatTrieStore::open(
                        dir,
                        rustock_flatdb::Options {
                            expected_keys,
                            ..rustock_flatdb::Options::default()
                        },
                    )?)
                }
            })
        }
        _ => None,
    };
    let trie_store_for_exec: Arc<dyn rustock_trie::TrieStore> = match &epoch_store {
        // No write cache in front of the epoch store yet: CachedTrieStore wraps
        // a RocksDB handle rather than a TrieStore, so it cannot sit on top of
        // this one without a refactor. Execution therefore pays a real read and
        // write per node here, which is a known cost of turning the collector on.
        Some(e) => e.clone(),
        None => match &external_store {
            Some(e) => e.clone(),
            None => Arc::new(rustock_storage::CachedTrieStore::with_defaults(store.db().clone())),
        },
    };

    // The pool and RPC read state too. With a detached trie they must read the
    // same store as execution, or they answer from a trie the node is no longer
    // writing to.
    let detached_for_readers: Option<Arc<dyn rustock_trie::TrieStore>> =
        if backend.is_detached() { Some(trie_store_for_exec.clone()) } else { None };


    if let Some(which) = args.verify_state.clone() {
        let root_hash = if which == "head" {
            store
                .exec_head()?
                .map(|(_, root)| root)
                .ok_or_else(|| anyhow::anyhow!("this node has no executed head to verify"))?
        } else {
            which.trim_start_matches("0x").parse::<alloy_primitives::B256>()
                .map_err(|e| anyhow::anyhow!("not a state root: {e}"))?
        };

        // Same rule as the sync path: verification follows the cores.
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(rustock_storage::read_threads())
            .max(1);
        info!("Verifying the state under {root_hash:?} with {workers} thread(s)");
        let message = trie_store_for_exec
            .get(root_hash.as_slice())
            .ok_or_else(|| anyhow::anyhow!("state root {root_hash:?} is not in the trie store"))?;
        let root = rustock_trie::TrieNode::try_from_message(&message, trie_store_for_exec.as_ref())
            .ok_or_else(|| anyhow::anyhow!("the stored state root does not parse"))?;

        let started = std::time::Instant::now();
        let last = std::sync::Mutex::new(std::time::Instant::now());
        let report = |seen: u64| {
            let mut l = last.lock().unwrap();
            if l.elapsed() < std::time::Duration::from_secs(5) {
                return;
            }
            *l = std::time::Instant::now();
            let secs = started.elapsed().as_secs_f64();
            info!("verifying: {seen} nodes, {secs:.0}s elapsed, {:.0} nodes/s", seen as f64 / secs.max(0.001));
        };

        if args.trie_shape {
            let started = std::time::Instant::now();
            let shape = rustock_trie::snapshot::measure_shape(&root, trie_store_for_exec.as_ref());
            info!(
                "Trie shape under {root_hash:?} ({:.0}s):\n\
                 \x20 nodes              {}\n\
                 \x20 value nodes        {}\n\
                 \x20 mean value depth   {:.2}\n\
                 \x20 max value depth    {}\n\
                 \x20 hash children      {}\n\
                 \x20 embedded children  {}\n\
                 \x20 inline value bytes {}\n\
                 \x20 long value bytes   {}",
                started.elapsed().as_secs_f64(),
                shape.nodes,
                shape.value_nodes,
                shape.mean_value_depth(),
                shape.max_depth,
                shape.hash_children,
                shape.embedded_children,
                shape.inline_value_bytes,
                shape.long_value_bytes,
            );
            return Ok(());
        }

        match rustock_trie::snapshot::verify_complete(
            &root,
            trie_store_for_exec.as_ref(),
            workers,
            &report,
        ) {
            Ok(nodes) => {
                let secs = started.elapsed().as_secs_f64();
                info!(
                    "State verified: {nodes} nodes in {secs:.1}s ({:.0} nodes/s)",
                    nodes as f64 / secs.max(0.001)
                );
                return Ok(());
            }
            Err(missing) => {
                anyhow::bail!("state under {root_hash:?} is incomplete: {missing}");
            }
        }
    }

    let trie_store_for_pool: Arc<dyn rustock_trie::TrieStore> = match &detached_for_readers {
        Some(t) => t.clone(),
        None => Arc::new(rustock_storage::RocksDbTrieStore::from_db(store.db().clone())),
    };
    let pool_config = rustock_sync::txpool::PoolConfig {
        account_slots: args.account_slots,
        quota: rustock_sync::quota::QuotaConfig {
            enabled: args.account_tx_rate_limit,
            cleaner_period_minutes: args.account_tx_rate_limit_cleaner_period,
            max_quotas_size: args.account_tx_rate_limit_max_accounts,
            max_quota_gas_multiplier: args.account_tx_rate_limit_quota_multiplier,
            max_gas_per_second_percent: args.account_tx_rate_limit_gas_per_second_percent,
        },
        ..Default::default()
    };
    // One tracker, shared: the rate limiter's low-gas-price factor and
    // `eth_gasPrice` must not disagree about what the market is doing.
    // rskj primes both its windows from the block store at start-up, so a
    // restart does not leave the node answering with the block minimum until
    // 512 fresh transactions have gone by.
    let gas_price_tracker = Arc::new(rustock_sync::gas_price::GasPriceTracker::default());
    gas_price_tracker.initialize_from_store(&store);

    // One cache, shared. The pool recovers a sender when it admits a
    // transaction; the executor needs the same answer later, when a block
    // carries it. Two private caches would miss exactly that hop, which is
    // the one worth caching.
    let sender_cache = args
        .sigcache
        .then(|| Arc::new(rustock_execution::sender_cache::SenderCache::default()));
    if sender_cache.is_none() {
        info!("Sender cache disabled (--sigcache=false); every sender is recovered");
    }

    // The checks that read the chain's activations and constants, as rskj's
    // TxPendingValidator does: the RSKIP252 per-transaction price cap, the
    // sublist gas limit under RSKIP144, the free Bridge transactions.
    // The same ladder `hardfork_cfg` below is built from, needed earlier
    // because the pool is constructed before it.
    let hardfork_cfg_for_pool =
        rustock_execution::RskHardforkConfig::for_network(config.chain_id as u64);
    let mut pool_builder = rustock_sync::TransactionPool::new(
        pool_config,
        config.chain_id.into(),
        store.clone(),
        trie_store_for_pool.clone(),
    )
    .with_gas_price_tracker(gas_price_tracker.clone())
    .with_chain_rules(rustock_sync::txpool::ChainRules::for_chain(
        hardfork_cfg_for_pool,
        config.min_sequential_set_gas_limit,
    ));
    if let Some(cache) = &sender_cache {
        pool_builder = pool_builder.with_sender_cache(cache.clone());
    }
    let pool = Arc::new(pool_builder);

    // Every line in the transaction path logs at `debug` or `trace` and this
    // node runs at `info`, so the pool is otherwise entirely unobservable: an
    // empty `txpool_status` is equally consistent with healthy traffic that has
    // already been mined and with no transaction ever arriving. Report on a
    // schedule, and stay silent when nothing happened so a line always means
    // something did.
    {
        let pool_for_report = pool.clone();
        tokio::spawn(async move {
            const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(300);
            let mut ticker = tokio::time::interval(REPORT_EVERY);
            ticker.tick().await; // the first tick fires immediately
            loop {
                ticker.tick().await;
                let a = pool_for_report.take_activity();
                if a.is_empty() {
                    continue;
                }
                let rejected = a.rejected();
                // Reasons, most common first, so a change in the mix is visible
                // without turning on debug logging.
                let reasons = if a.rejections.is_empty() {
                    "-".to_string()
                } else {
                    a.rejections
                        .iter()
                        .map(|(reason, n)| format!("{reason}={n}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                tracing::info!(
                    target: "rustock::txpool",
                    "Mempool in the last {}m: {} offered, {} accepted, {rejected} rejected, \
                     {} mined | {reasons}",
                    REPORT_EVERY.as_secs() / 60,
                    a.offered,
                    a.accepted,
                    a.mined,
                );
                // One sender refused many times is the rate limiter working as
                // designed; many senders refused once each is it misfiring on
                // ordinary traffic. Only say so when it actually refused something.
                if a.quota_senders > 0 {
                    let worst = a
                        .quota_worst
                        .map(|(addr, n)| format!("{addr} ({n})"))
                        .unwrap_or_else(|| "-".to_string());
                    tracing::info!(
                        target: "rustock::txpool",
                        "Rate limiter refused {} sender(s); most refused: {worst}",
                        a.quota_senders,
                    );
                }
            }
        });
    }

    // rskj runs the equivalent sweep on a `TxQuotaCleanerTimer`.
    if let Some(period) = pool.quota_cleaner_period() {
        let pool_for_cleaner = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.tick().await; // the first tick fires immediately
            loop {
                ticker.tick().await;
                let dropped = pool_for_cleaner.clean_quotas();
                tracing::debug!(target: "rustock::txpool", "Quota sweep dropped {dropped} accounts");
            }
        });
        tracing::info!(
            "Account tx rate limiting on; quota sweep every {} min",
            period.as_secs() / 60
        );
    } else if !args.account_tx_rate_limit {
        tracing::info!("Account tx rate limiting disabled");
    }

    let (hardfork_cfg, _) = hardfork_config(&config)?;
    let btc_block_cache = if args.btc_block_cache_entries > 0 {
        let cache = Arc::new(rustock_execution::BtcBlockCache::new(
            args.btc_block_cache_entries,
        ));
        info!(
            "BTC block cache: {} entries (~{} MB at full occupancy), demand-populated",
            args.btc_block_cache_entries,
            args.btc_block_cache_entries * 200 / (1024 * 1024)
        );
        Some(cache)
    } else {
        info!("BTC block cache disabled");
        None
    };

    let mut block_processor = rustock_execution::BlockProcessor::new(
        hardfork_cfg.clone(),
        store.clone(),
    );
    if let Some(cache) = &btc_block_cache {
        block_processor = block_processor.with_btc_block_cache(cache.clone());
    }
    if let Some(cache) = &sender_cache {
        block_processor = block_processor.with_sender_cache(cache.clone());
    }
    block_processor = block_processor.with_execution_threads(args.execution_threads);
    if config.genesis_spec.is_some() {
        // A chain from an rskj genesis file is rskj's regtest, Bridge
        // federation included.
        block_processor = block_processor.with_bridge_constants(
            rustock_execution::bridge::constants::BridgeConstants::rskj_regtest(),
        );
    }
    info!(
        "Block processor wired (hardfork config: {:?}, execution threads: {})",
        hardfork_cfg,
        block_processor.execution_threads()
    );

    if let Some(count) = args.measure_block_reads {
        // Re-execute recent blocks and record what each one had to be given.
        //
        // Both databases are already open here; what makes this safe against a
        // running node is that the trie store is wrapped so every write stays
        // in memory, and that the operator points --data-dir at a node they
        // are content to read. Nothing here writes.
        let counting = Arc::new(
            rustock_storage::counting_trie_store::CountingTrieStore::new(
                trie_store_for_exec.clone(),
            ),
        );

        let head = store
            .head()?
            .and_then(|h| store.header(h).ok().flatten())
            .ok_or_else(|| anyhow::anyhow!("no chain head to measure from"))?;
        let from = head.number.saturating_sub(count).max(1);

        info!(
            "Measuring trie reads for blocks #{from}..#{} ({count} requested)",
            head.number
        );

        let mut blocks = 0u64;
        let mut txs = 0u64;
        let mut distinct = 0u64;
        let mut calls = 0u64;
        let mut bytes = 0u64;
        let mut failed = 0u64;
        let mut worst = (0u64, 0u64);
        // The mean says little about a design sized by a threshold: what
        // matters is how many blocks fall under it, and how much of the work
        // the ones above it represent.
        let mut per_block: Vec<u64> = Vec::new();

        for number in from..=head.number {
            let Some(hash) = store.canonical_hash(number)? else { continue };
            let Some(block) = store.block(hash)? else { continue };
            let Some(parent) = store.header(block.header.parent_hash)? else { continue };

            // The pre-state is the parent's root. A node that has collected
            // past it simply cannot answer, which is why this only works on
            // recent blocks.
            let Some(message) = counting.get(parent.state_root.as_slice()) else {
                failed += 1;
                continue;
            };
            let Some(pre) = rustock_trie::TrieNode::try_from_message(&message, counting.as_ref())
            else {
                failed += 1;
                continue;
            };

            counting.clear_overlay();
            let _ = counting.take();

            match block_processor.process_block(&block, &pre, counting.clone()) {
                Ok(_) => {
                    let s = counting.take();
                    blocks += 1;
                    txs += block.transactions.len() as u64;
                    distinct += s.distinct;
                    calls += s.calls;
                    bytes += s.bytes;
                    per_block.push(s.bytes);
                    if s.distinct > worst.1 {
                        worst = (number, s.distinct);
                    }
                }
                Err(e) => {
                    failed += 1;
                    debug!("block #{number} did not re-execute: {e:?}");
                }
            }
        }

        if blocks == 0 {
            anyhow::bail!(
                "no block re-executed ({failed} could not be); the pre-state for this \
                 range is not in the trie store"
            );
        }

        per_block.sort_unstable();
        let pct = |p: usize| -> u64 {
            if per_block.is_empty() {
                return 0;
            }
            per_block[(per_block.len() - 1) * p / 100]
        };
        // How a threshold would actually behave, rather than how the mean
        // suggests it would.
        let mut thresholds = String::new();
        for limit in [16_384u64, 32_768, 51_200, 131_072] {
            let under = per_block.iter().filter(|b| **b <= limit).count();
            let carried: u64 = per_block.iter().filter(|b| **b <= limit).sum();
            thresholds.push_str(&format!(
                "\n\x20 <= {:>3} KB              {:>5.1}% of blocks, {:>5.1}% of their bytes",
                limit / 1024,
                under as f64 / per_block.len() as f64 * 100.0,
                carried as f64 / bytes.max(1) as f64 * 100.0,
            ));
        }

        info!(
            "Trie reads over {blocks} block(s), {txs} transaction(s), {failed} skipped:\n\
             \x20 bytes p50 / p90 / p99   {} / {} / {}\n\
             \x20 bytes min / max         {} / {}\
             {thresholds}\n\
             \x20 distinct nodes / block   {:.1}\n\
             \x20 get calls / block        {:.1}\n\
             \x20 node bytes / block       {:.0}\n\
             \x20 distinct nodes / tx      {:.1}\n\
             \x20 busiest block            #{} with {} nodes\n\
             \x20 totals                   {distinct} nodes, {bytes} bytes",
            pct(50), pct(90), pct(99),
            per_block.first().copied().unwrap_or(0),
            per_block.last().copied().unwrap_or(0),
            distinct as f64 / blocks as f64,
            calls as f64 / blocks as f64,
            bytes as f64 / blocks as f64,
            if txs > 0 { distinct as f64 / txs as f64 } else { 0.0 },
            worst.0,
            worst.1,
        );
        return Ok(());
    }


    let initial_state_root = load_or_build_state(&store, &config, trie_store_for_exec.as_ref())?;
    info!("Initial state root: {:?}", initial_state_root.compute_hash(trie_store_for_exec.as_ref()));

    if let Some(path) = &args.import_blocks {
        let importer = rustock_sync::import::BlockImporter::new(
            store.clone(),
            HeaderVerifier::default_rsk(config.clone()),
            block_processor,
            trie_store_for_exec.clone(),
            initial_state_root,
            args.import_flush_every,
        )?
        .measure(args.breakdown_log.is_some());
        return run_import_blocks(path, importer, args.breakdown_log.as_deref());
    }

    let snap_checkpoint = snap_checkpoint_for(args.network_id);
    if checkpoint_defence.any() && snap_checkpoint.is_none() {
        warn!(
            "Checkpoint defences were asked for, but this chain ships no checkpoint; \
             they will not run"
        );
    } else if checkpoint_defence.any() {
        info!(
            "Checkpoint defences: hash check {}, work bound {}",
            if checkpoint_defence.verify_hash { "on" } else { "off" },
            if checkpoint_defence.bound_work { "on" } else { "off" },
        );
    }

    let snap_config = rustock_sync::SnapConfig {
        server_enabled: args.snap_server,
        client_enabled: args.snap_sync,
        checkpoint: snap_checkpoint,
        checkpoint_defence,
        chunk_bytes: args.snap_chunk_bytes,
        chunk_grid: args.snap_chunk_grid.max(1),
        index_history: args.snap_index_history,
        peer_bytes_per_second: args.snap_peer_rate,
        total_bytes_per_second: args.snap_total_rate,
        max_in_flight: args.snap_parallel.max(1),
        blocks_required: args.snap_blocks,
        forward_headers: args.snap_forward_headers,
        archive_uncles: !(args.prune_blocks || args.prune_uncles),
        serve_ceiling: args.simulate_height,
        ..rustock_sync::SnapConfig::default()
    };

    // Background collection. Kept out of the block-processing path on purpose:
    // mark and drain only read the oldest epoch and write the newest, and block
    // processing also writes the newest, so the two need no coordination beyond
    // the brief lock the sweep takes.
    if let Some(es) = epoch_store.clone() {
        let store_for_gc = store.clone();
        let burial = args.gc_burial;
        let every = std::time::Duration::from_secs(args.gc_check_secs.max(1));
        // The collection root is one state, buried `burial` below the head.
        // A snapshot server offers a state 10,000-15,000 blocks back, which is
        // far deeper, so it is not reachable from that root and is swept
        // without a pin (#143). Recomputed each cycle, because the checkpoint
        // moves. Empty when serving is off, and then collection is exactly
        // what it was.
        let snap_for_gc = snap_config.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if !es.should_collect() {
                    continue;
                }
                // Collect against a buried block, never the head. Collecting
                // against the head would leave nothing to fall back to if the
                // chain reorganised past it.
                let root = (|| {
                    let head_hash = store_for_gc.head().ok().flatten()?;
                    let head = store_for_gc.header(head_hash).ok().flatten()?;
                    let target = head.number.checked_sub(burial)?;
                    let hash = store_for_gc.canonical_hash(target).ok().flatten()?;
                    let header = store_for_gc.header(hash).ok().flatten()?;
                    Some((header.state_root, target))
                })();
                let Some((root, at)) = root else {
                    debug!(target: "rustock::gc", "No block buried {burial} deep yet; not collecting");
                    continue;
                };
                let head_now = store_for_gc
                    .head()
                    .ok()
                    .flatten()
                    .and_then(|h| store_for_gc.header(h).ok().flatten())
                    .map(|h| h.number)
                    .unwrap_or(at);
                // A root the store cannot resolve is normal for a while after
                // seeding: the burial depth reaches below the seeded block until
                // the chain advances past it. That is a "not yet", not a fault,
                // and logging it as an error once a minute would bury the real
                // ones.
                if rustock_trie::TrieStore::get(es.as_ref(), root.as_slice()).is_none() {
                    debug!(
                        target: "rustock::gc",
                        "Collection root #{at} is not in the store yet; waiting for the \
                         chain to advance past the seeded block"
                    );
                    continue;
                }
                let pins = rustock_sync::snap_servable_roots(&store_for_gc, &snap_for_gc);
                if pins.is_empty() {
                    info!(target: "rustock::gc", "Collecting against #{at} ({root:?})");
                } else {
                    info!(
                        target: "rustock::gc",
                        "Collecting against #{at} ({root:?}), pinning {} snapshot state(s)",
                        pins.len()
                    );
                }
                match es.collect_pinned(root, &pins, at, head_now) {
                    Ok(stats) => {
                        for lost in &stats.unservable {
                            warn!(
                                target: "rustock::gc",
                                "Snapshot state {lost:?} is already incomplete; peers asking \
                                 for it will be refused. Collection continued."
                            );
                        }
                    }
                    Err(e) => error!(target: "rustock::gc", "Collection failed: {e:?}"),
                }
            }
        });
    }

    // The chain-event channel that feeds `eth_subscribe`. Created only when
    // the WebSocket server is on: without a receiver every publish is a
    // no-op, but not creating it at all makes that explicit.
    let events = args.ws.then(rustock_core::events::channel);

    // Peer scoring: one service shared by the node (which refuses banned
    // addresses before the handshake), the sync service and the transaction
    // relay (which feed it events), and the RPC layer (which reports and
    // overrides it). Bans live in the data directory so they survive a
    // restart -- rskj's do not.
    let scoring = Arc::new(rustock_networking::scoring::ScoringService::open(
        std::path::Path::new(&args.data_dir),
        &args.banned_peers,
        rustock_networking::scoring::DEFAULT_NODE_CAPACITY,
        !args.no_peer_punishment,
    ));

    // Old headers move to flat files addressed by block number, where a run
    // of them is one contiguous read rather than 192 scattered point lookups.
    let freezer = if !args.freezer {
        info!("Header freezer disabled; old headers stay in the block database");
        None
    } else {
        let dir = std::path::Path::new(&args.data_dir).join("freezer");
        // A process that died mid-walk leaves staging files nothing will come
        // back for. They name the checkpoint they were built against, so they
        // are recognisable, and they are not the real freezer's files.
        let abandoned = rustock_storage::freezer::Freezer::discard_staging(&dir);
        if abandoned > 0 {
            info!(
                "Discarded {abandoned} staged freezer file(s) from a header walk                  that did not finish"
            );
        }
        match rustock_storage::freezer::Freezer::open(&dir) {
            Ok(f) => {
                let f = Arc::new(f);
                info!(
                    "Header freezer at {}: {} header(s), {} MB, freezing below #(head - {})",
                    dir.display(),
                    f.end_number(),
                    f.data_bytes() / (1 << 20),
                    rustock_storage::freezer::FREEZE_DEPTH,
                );
                Some(f)
            }
            // A freezer that will not open is a performance loss, not a
            // correctness one: every header it would have held is still in
            // RocksDB. Say so loudly and carry on rather than refusing to
            // start a node that can serve the chain perfectly well.
            Err(e) => {
                warn!(
                    "Header freezer at {} could not be opened ({e:#}); \
                     continuing without it",
                    dir.display()
                );
                None
            }
        }
    };
    if let Some(f) = freezer.clone() {
        store.set_freezer(f);

        // Fill the freezer from the block database in the background.
        //
        // A node that has already synced has every header in RocksDB and an
        // empty freezer, so there is a one-time catch-up of however many
        // blocks are below the horizon. It runs on a blocking thread because
        // each header is a point lookup, and it yields between batches so it
        // competes with serving rather than starving it.
        //
        // Nothing depends on this having finished: until a run is frozen, the
        // serving path answers it the old way.
        let fill_store = store.clone();
        let prune_frozen = args.prune_frozen_headers;
        if prune_frozen {
            warn!(
                "Frozen headers will be deleted from the block database once the freezer \
                 holds them. Every lookup by hash for those blocks then depends on the \
                 hash-to-number index."
            );
        }
        tokio::task::spawn_blocking(move || {
            const BATCH: u64 = 10_000;
            let mut announced = false;
            loop {
                let head = fill_store
                    .head()
                    .ok()
                    .flatten()
                    .and_then(|h| fill_store.header(h).ok().flatten())
                    .map(|h| h.number)
                    .unwrap_or(0);
                let horizon = head.saturating_sub(rustock_storage::freezer::FREEZE_DEPTH);

                match fill_store.freeze_headers_below(horizon, BATCH) {
                    Ok(0) => {
                        if let Some(f) = fill_store.freezer() {
                            // Nothing left to do is the moment to make the
                            // tail durable: in steady state the batches are
                            // one or two headers and are deliberately left in
                            // the write buffer.
                            let _ = f.sync();
                            if !announced {
                                info!(
                                    "Header freezer caught up: {} header(s), {} MB",
                                    f.end_number(),
                                    f.data_bytes() / (1 << 20)
                                );
                                announced = true;
                            }
                        }
                        // Nothing left to freeze is the moment to reclaim
                        // what the freezer has made redundant -- never
                        // before, and never ahead of the freezer's own
                        // progress.
                        if prune_frozen {
                            match fill_store.delete_frozen_headers(horizon, BATCH) {
                                Ok(0) => {}
                                Ok(n) => info!(
                                    "Reclaimed {n} frozen header(s) from the block database \
                                     (now at #{})",
                                    fill_store.frozen_delete_cursor().unwrap_or(0)
                                ),
                                Err(e) => warn!("Frozen header reclaim stopped: {e:#}"),
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                    Ok(n) => {
                        // Only a full batch means it is genuinely behind. Once
                        // caught up the horizon advances with the chain, so
                        // every round freezes a header or two -- announcing
                        // "caught up" after each of those said it every 30
                        // seconds, forever.
                        if n >= BATCH {
                            announced = false;
                        }
                        if let Some(f) = fill_store.freezer() {
                            let at = f.end_number();
                            if at % 100_000 < n {
                                info!(
                                    "Header freezer: {} of {} header(s) moved to files ({} MB)",
                                    at,
                                    horizon,
                                    f.data_bytes() / (1 << 20)
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Header freezer stopped filling: {e:#}");
                        return;
                    }
                }
            }
        });
    }

    if args.snap_server {
        info!(
            "Snapshot server enabled: serving state at #(head - {}) in chunks of up to {} bytes",
            snap_config.checkpoint_distance, snap_config.max_chunk_bytes
        );
        let snap_server = Arc::new(rustock_sync::SnapServer::new(
            store.clone(),
            trie_store_for_exec.clone(),
            snap_config.clone(),
        ));
        match snap_server.offer() {
            Some((number, root)) => {
                info!("Snapshot server: currently offering the state at #{number} ({root:?})")
            }
            // Worth a warning rather than silence: peers will ask and get no
            // reply, and the operator would have no way to know why.
            None => warn!(
                "Snapshot server: nothing to offer -- the state {} blocks behind the tip is \
                 not retained. A pruning node can only serve snapshots it still holds.",
                snap_config.checkpoint_distance
            ),
        }
        sync_handler.attach_snap_server(snap_server);
    }

    let best_block_listeners = rustock_sync::BestBlockListeners::new();
    let mut sync_service = SyncService::new(sync_manager.clone(), peer_store.clone(), event_rx)
        .with_best_block_listeners(best_block_listeners.clone())
        .with_tx_pool(pool.clone())
        .with_block_processor(block_processor, trie_store_for_exec, initial_state_root)
        .with_gas_price_tracker(gas_price_tracker.clone())
        .with_scoring(Some(scoring.clone()))
        .with_events(events.clone())
        .with_follow_up(args.follow_up)
        .with_trie_flush_every(args.trie_flush_every)
        .with_serve_ceiling(args.simulate_height)
        .with_exit_when_synced(args.exit_when_synced);

    if args.snap_sync {
        info!(
            "Snapshot sync enabled: verifying the header chain to the snapshot point \
             before downloading state, {} chunks of {} bytes in flight",
            snap_config.max_in_flight, snap_config.chunk_bytes
        );
        sync_service.start_snap_sync(snap_config.clone(), verifier_for_snap.clone());
    }

    // Taken before the service is moved into its task: the RPC layer reads the
    // same gauge the sync loop publishes, so `debug_wireProtocolQueueSize`
    // answers with the live backlog.
    // Shared with the prune sweep below. Closed until the sync service has
    // determined what this node is doing.
    let prune_gate = sync_service.prune_gate();
    let wire_queue_depth = sync_service.wire_queue_depth();

    if let Some(path) = &args.import_blocks_db {
        let source = RskjBlockSource::open(path)?;
        info!("Sourcing block bodies from rskj LevelDB at {path} (peers only for what it lacks)");
        sync_service = sync_service.with_block_source(Arc::new(source));
    }
    // `Processed N blocks` says the node is alive but nothing about what it is
    // processing: a node keeping up with an idle chain and one keeping up with
    // a saturated one produce the same line. Report what the blocks actually
    // contained, on the same cadence as the mempool summary, and stay silent
    // when no block was executed -- at the tip that is roughly one every 30
    // seconds, so an empty window is itself worth noticing.
    {
        let activity = sync_service.chain_activity();
        let cache_for_report = btc_block_cache.clone();
        tokio::spawn(async move {
            const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(300);
            let mut ticker = tokio::time::interval(REPORT_EVERY);
            ticker.tick().await; // the first tick fires immediately
            loop {
                ticker.tick().await;
                let a = activity.take();
                if a.is_empty() {
                    continue;
                }
                let range = match a.first_block {
                    Some(first) if first != a.last_block => {
                        format!("#{first}..#{}", a.last_block)
                    }
                    _ => format!("#{}", a.last_block),
                };
                // ns/gas is the figure to watch across windows. Gas measures
                // work, so cost per unit of work should hold steady whatever
                // the chain is doing; a rising figure means each unit is
                // costing more than it used to. Blocks vary too much in size
                // for time-per-block to be comparable the same way.
                tracing::info!(
                    target: "rustock::sync",
                    "Chain in the last {}m: {} block(s) {range}, {:.1} tx/block, \
                     {:.0} gas/block, {:.1}% full | {:.1} ms/block cpu ({:.1} wall), \
                     {:.1} ns/gas cpu ({:.1} wall)",
                    REPORT_EVERY.as_secs() / 60,
                    a.blocks,
                    a.avg_transactions(),
                    a.avg_gas_used(),
                    a.fullness_percent(),
                    a.avg_cpu_ms_per_block(),
                    a.avg_wall_ms_per_block(),
                    a.cpu_nanos_per_gas(),
                    a.wall_nanos_per_gas(),
                );

                // Reported alongside the chain numbers so the cache's value is
                // visible next to the cost it is meant to reduce. A hit rate
                // that stays at zero means the workload never repeats a BTC
                // lookup, and the memory is being spent for nothing.
                if let Some(cache) = &cache_for_report {
                    let s = cache.stats.snapshot();
                    if s.lookups() > 0 {
                        tracing::info!(
                            target: "rustock::sync",
                            "BTC block cache: {}/{} entries (~{} KB), {:.1}% hit rate                              ({} hits, {} misses, {} evictions)",
                            cache.len(),
                            cache.capacity(),
                            cache.approx_bytes() / 1024,
                            s.hit_rate().unwrap_or(0.0),
                            s.hits,
                            s.misses,
                            s.evictions,
                        );
                    }
                }
            }
        });
    }

    let tx_relay = Arc::new(
        TxRelay::with_pool(peer_store.clone(), pool.clone())
            .with_scoring(Some(scoring.clone()))
            .with_events(events.clone()),
    );

    let mut node =
        Node::with_peer_store(node_config, peer_store.clone()).with_scoring(scoring.clone());
    node.add_handler(sync_handler);
    node.add_handler(tx_relay.clone());

    // Peg-out monitoring. Deliberately not wired into execution or sync: it
    // polls what has already been committed, so a slow mail server or a bug in
    // it cannot delay a block.
    // Node health alarms share the alert configuration file and its mail
    // transport, because an operator wanting one wants the other and two mail
    // configurations is how one of them goes stale.
    if let Some(path) = &args.alerts_config {
        match start_health_alerts(path, store.clone(), peer_store.clone()) {
            Ok(true) => info!("Node health alarms started from {path}"),
            Ok(false) => info!("Node health alarms configured but disabled in {path}"),
            Err(e) => warn!("Node health alarms not started: {e:#}"),
        }
    }

    if let Some(path) = &args.alerts_config {
        match start_pegout_alerts(
            path,
            store.clone(),
            trie_store_for_pool.clone(),
            hardfork_cfg.clone(),
        ) {
            Ok(Some(handle)) => {
                info!("Alert watcher started from {path}");
                // Detached deliberately: dropping a tokio JoinHandle does not
                // cancel the task, and the watcher must outlive this scope.
                drop(handle);
            }
            Ok(None) => info!("Peg-out alerts configured but disabled in {path}"),
            // A malformed alert configuration must not stop the node: it is an
            // observability feature, and a node that refuses to start because
            // its mail settings are wrong is worse than one that runs unwatched.
            Err(e) => error!("Peg-out alerts disabled — {path}: {e:#}"),
        }
    }

    // Delete block history the node no longer needs, on a timer.
    //
    // Opt-in. Turning this on discards history that only a resync restores, so
    // a node holding the whole chain keeps holding it until an operator says
    // otherwise.
    //
    // Two things it waits for. A snapshot sync downloads the blocks below its
    // checkpoint as its final phase, so sweeping during one would delete what
    // is still being fetched -- and `--snap-blocks` above `--prune-keep-depth`
    // is exactly how a pruning node is given its first sweep's work. And the
    // canonical index fill writes `number -> hash` downward while this deletes
    // it below the floor; the fill now stops at the floor, so the two meet
    // rather than chase.
    let prune_config = rustock_storage::pruner::PruneConfig {
        keep_depth: args.prune_keep_depth,
        max_batch: args.prune_max_batch,
        headers: args.prune_blocks || args.prune_headers,
        bodies: args.prune_blocks || args.prune_bodies,
        receipts: args.prune_blocks || args.prune_receipts,
    };
    let prune_any = prune_config.removes_anything();

    if prune_any {
        let store_for_prune = store.clone();
        let gate = prune_gate.clone();
        let peers_for_prune = peer_store.clone();
        let cfg = prune_config;
        let every = std::time::Duration::from_secs(args.prune_every_secs.max(1));
        info!(
            "Block pruning on: keeping {} blocks below the head, up to {} per sweep, \
             every {}s",
            args.prune_keep_depth.max(rustock_storage::pruner::MIN_KEEP_DEPTH),
            args.prune_max_batch,
            args.prune_every_secs,
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            ticker.tick().await; // the first tick fires immediately
            let mut announced_wait = false;
            loop {
                ticker.tick().await;

                if !gate.load(std::sync::atomic::Ordering::Relaxed) {
                    if !announced_wait {
                        announced_wait = true;
                        info!(
                            target: "rustock::prune",
                            "holding: pruning waits until the node has settled into ordinary \
                             sync, so a snapshot sync's blocks are never swept while it is \
                             still fetching them"
                        );
                    }
                    continue;
                }
                if announced_wait {
                    announced_wait = false;
                    info!(target: "rustock::prune", "pruning released; sweeping from now on");
                }

                let Ok(Some(head_hash)) = store_for_prune.head() else { continue };
                let Ok(Some(head)) = store_for_prune.header(head_hash) else { continue };

                // Say what is about to go, before it goes.
                //
                // Announcing afterwards leaves a window in which peers believe
                // this node still holds blocks it has already deleted, and
                // during it they ask for exactly those blocks. Announcing
                // first inverts the error: for the length of the sweep this
                // node claims to serve slightly less than it does, and the
                // worst that costs is a request nobody made.
                //
                // The same asymmetry the pruner applies to its own floor
                // record, which it writes before deleting rather than after:
                // over-reporting what exists invites a reader to ask for
                // something gone.
                //
                // In practice the window is a fraction of a second -- observed
                // sweeps take 0.1s to 0.5s for up to fifty thousand blocks --
                // but `max_batch` is configuration and a disk can be slow, so
                // the duration is not something to rely on.
                if let Ok(Some(plan)) = store_for_prune.plan_prune(&cfg, head.number) {
                    announce_block_range(&peers_for_prune, &store_for_prune, plan.new_floor)
                        .await;
                }

                let store_for_task = store_for_prune.clone();
                let cfg_for_task = cfg.clone();
                let number = head.number;
                match tokio::task::spawn_blocking(move || {
                    store_for_task.prune_blocks(&cfg_for_task, number)
                })
                .await
                {
                    Ok(Ok(stats)) if stats.blocks > 0 => {
                        // And correct it afterwards. The sweep can stop short
                        // of its plan -- `max_batch` truncates it, and a batch
                        // that fails leaves the floor where it was -- so the
                        // announcement above is an upper bound and this is the
                        // truth. Correcting downward is always safe; it only
                        // ever tells peers this node holds more than they
                        // thought.
                        let floor = store_for_prune
                            .prune_floor()
                            .ok()
                            .flatten()
                            .map(|f| f.number)
                            .unwrap_or(0);
                        announce_block_range(&peers_for_prune, &store_for_prune, floor).await;
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(target: "rustock::prune", "prune sweep failed: {e:#}")
                    }
                    Err(join) => {
                        error!(target: "rustock::prune", "prune sweep panicked: {join}")
                    }
                }
            }
        });
    }

    // Supervise the sync task: a panic inside it would otherwise be swallowed
    // by tokio and leave the node running but silently stalled.
    let sync_handle = tokio::spawn(sync_service.start());
    tokio::spawn(async move {
        if let Err(e) = sync_handle.await {
            tracing::error!("Sync service terminated unexpectedly: {e}. Shutting down.");
            std::process::exit(1);
        }
    });

    // The miner. It shares the store and trie store with sync but holds its
    // own block processor: `BlockProcessor` is a handle over those two, and
    // the sync service has taken ownership of the one built above.
    let miner: Option<Arc<rustock_execution::MinerServer>> = if args.mine {
        let coinbase_address = match &args.mining_coinbase {
            Some(raw) => raw.parse::<alloy_primitives::Address>().map_err(|e| {
                anyhow::anyhow!("--mining-coinbase is not an address: {e}")
            })?,
            None => anyhow::bail!("--mine requires --mining-coinbase: a miner must say where its rewards go"),
        };
        // rskj `MinerServerImpl.buildExtraData`: the node's identity, then
        // the operator's string cut to fit.
        let identity = format!(
            "{}-{}",
            env!("CARGO_PKG_VERSION"),
            option_env!("RUSTOCK_GIT_COMMIT").unwrap_or("unknown")
        );
        let extra_data =
            rustock_execution::mining::extra_data::build(&identity, args.mining_extra_data.as_bytes());
        if args.mining_extra_data.len() > extra_data.len() {
            info!(
                "--mining-extra-data cut to fit the 32-byte extraData field, after the node identity {identity}"
            );
        }

        let mining_config = rustock_execution::MiningConfig {
            coinbase_address,
            extra_data,
            // rskj `miner.minGasPrice`, through `MinimumGasPriceCalculator`.
            min_gas_price_target: args.mining_min_gas_price.map(alloy_primitives::U256::from),
            ..Default::default()
        };
        // The miner's processor is wired like the node's: the same caches,
        // threads and, on a chain from an rskj genesis file, rskj's regtest
        // Bridge constants. A bare processor here ran REMASC against the
        // built-in federation, so the first payout (block 15 on regtest)
        // reached a state root no node with the right constants reproduces.
        let mut miner_processor =
            rustock_execution::BlockProcessor::new(hardfork_cfg.clone(), store.clone());
        if let Some(cache) = &btc_block_cache {
            miner_processor = miner_processor.with_btc_block_cache(cache.clone());
        }
        if let Some(cache) = &sender_cache {
            miner_processor = miner_processor.with_sender_cache(cache.clone());
        }
        miner_processor = miner_processor.with_execution_threads(args.execution_threads);
        if config.genesis_spec.is_some() {
            miner_processor = miner_processor.with_bridge_constants(
                rustock_execution::bridge::constants::BridgeConstants::rskj_regtest(),
            );
        }
        let builder = rustock_execution::BlockTemplateBuilder::new(
            Arc::new(miner_processor),
            trie_store_for_pool.clone(),
            config.clone(),
            hardfork_cfg.clone(),
            mining_config,
        );
        let chain = Arc::new(rustock_execution::mining::StoreChainAccess::with_flush_every(
            store.clone(),
            trie_store_for_pool.clone(),
            // What the sync service's import path does for a block that
            // arrived from a peer, done here for one this node mined.
            Some({
                let pool = pool.clone();
                Arc::new(move |block: &rustock_core::Block| {
                    pool.remove_mined(&block.transactions);
                    pool.evict_outdated(block.header.number);
                })
            }),
            args.flush_every,
        ));
        let mut server = rustock_execution::MinerServer::new(
            builder,
            chain,
            Arc::new(PoolTxSource(pool.clone())),
            config.clone(),
        )
        .with_sync_gate(PeerSyncGate::spawn(store.clone(), peer_store.clone()))
        .with_submission_rate_limit(args.mining_submission_rate_limit_ms);
        if let Some(log) = &args.breakdown_log {
            // One line per block at a block time of seconds: written and
            // flushed as it comes, so the file is complete whenever the
            // node is stopped.
            server = server.with_breakdown_log(open_breakdown_log(log)?);
            info!("Mined-block timing lines go to {}", log.display());
        }
        let server = Arc::new(server);
        info!("Mining enabled; rewards to {coinbase_address}");

        // rskj `NewBlockTxListener.onBestBlock`: every block the sync
        // service executes as best invalidates the candidate, so rebuild.
        // Off the sync thread: a rebuild executes every pending transaction.
        {
            let server = server.clone();
            best_block_listeners.add(Arc::new(move |_header: &rustock_core::Header| {
                let server = server.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = server.on_best_block() {
                        debug!(target: "rustock::mining", "No new work on best block: {e}");
                    }
                });
            }));
        }
        // rskj `NewBlockTxListener.onPendingTransactionsReceived`, behind
        // `updateWorkOnNewTransaction`: arrivals worth a tenth of the
        // candidate's fees rebuild it.
        if args.mining_update_work_on_new_transaction {
            let server = server.clone();
            pool.set_on_added(Arc::new(move |tx: &rustock_core::Transaction| {
                let server = server.clone();
                let tx = tx.clone();
                tokio::task::spawn_blocking(move || {
                    if let Some(Err(e)) = server.on_pending_transactions_received(&[tx]) {
                        debug!(target: "rustock::mining", "No new work on new transaction: {e}");
                    }
                });
            }));
        }

        // Rebuild the template on a timer. Nothing else does: the sync service
        // owns the execution loop and does not know the miner exists, so
        // without this a pool would keep being handed work for a parent the
        // chain left behind and every solution would be refused.
        let refresh = std::time::Duration::from_secs(args.mining_refresh_secs.max(1));
        let server_for_refresh = server.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh);
            loop {
                ticker.tick().await;
                let server = server_for_refresh.clone();
                let built = tokio::task::spawn_blocking(move || server.build_work()).await;
                match built {
                    Ok(Ok(_)) => {}
                    // Expected while the node is still syncing: there is no
                    // executed head to build on yet.
                    Ok(Err(e)) => debug!(target: "rustock::mining", "No new work: {e}"),
                    Err(e) => error!(target: "rustock::mining", "Work rebuild panicked: {e}"),
                }
            }
        });

        Some(server)
    } else {
        None
    };

    // The timed miner, rskj's `TimedMinerClient`: started here, with the
    // node, so a harness that never calls `evm_startMining` still gets
    // blocks. Nonce 0 without a search when proof of work is not validated;
    // the bounded development search otherwise.
    let timed_miner: Option<Arc<rustock_execution::mining::TimedMiner>> =
        match (&miner, args.mine_timed.as_deref()) {
            (_, None) => None,
            (None, Some(_)) => anyhow::bail!("--mine-timed requires --mine"),
            (Some(server), Some(median)) => {
                let median = parse_block_time(median)
                    .map_err(|e| anyhow::anyhow!("--mine-timed {median:?}: {e}"))?;
                let pow = if config.skip_pow_validation {
                    rustock_execution::mining::Pow::Skip
                } else {
                    rustock_execution::mining::Pow::Search { attempts: 1 << 18 }
                };
                let timed = Arc::new(rustock_execution::mining::TimedMiner::new(
                    server.clone(),
                    median,
                    pow,
                ));
                timed.start();
                Some(timed)
            }
        };

    // Loaded before the server starts, so a bad key file stops the node
    // rather than surfacing as a confusing refusal on the first signing
    // call hours later.
    let wallet = match &args.wallet_file {
        Some(path) => {
            let w = rustock_rpc::wallet::Wallet::from_file(path)
                .with_context(|| format!("loading the wallet from {}", path.display()))?;
            let accounts = w.accounts();
            warn!(
                target: "rustock::rpc",
                "Wallet loaded with {} account(s) from {}; this node will sign \
                 eth_sendTransaction and eth_sign for them. Do not expose this \
                 RPC endpoint publicly. Accounts: {}",
                accounts.len(),
                path.display(),
                accounts.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>().join(", ")
            );
            Some(Arc::new(w))
        }
        None => None,
    };

    if !args.no_rpc {
        let trie_store: Arc<dyn rustock_trie::TrieStore> = match &detached_for_readers {
            Some(t) => t.clone(),
            None => Arc::new(rustock_storage::RocksDbTrieStore::from_db(store.db().clone())),
        };

        let rpc_state = rustock_rpc::server::RpcState {
            store: store.clone(),
            wire_queue_depth: Some(wire_queue_depth.clone()),
            gas_price: Some(Arc::new(GasPriceAdapter(gas_price_tracker.clone()))),
            peer_store: peer_store.clone(),
            config: config.clone(),
            tx_submitter: Some(Arc::new(TxRelaySubmitter(tx_relay.clone()))),
            trie_store: Some(trie_store),
            hardfork_cfg: Some(hardfork_cfg),
            filter_store: Arc::new(rustock_rpc::logs::FilterStore::new()),
            tx_pool: Some(Arc::new(PoolAdapter(pool.clone()))),

            epoch_store: epoch_store.clone(),
            miner: miner.clone().map(|m| m as Arc<dyn rustock_rpc::mnr::MiningService>),
            // The same miner with a loop around it, for
            // `evm_startMining`. The tick bounds how long a transaction
            // waits for its block; a quarter second is short enough that
            // a harness does not notice and long enough that an idle
            // chain is not spinning.
            auto_miner: match &timed_miner {
                // `--mine-timed`: the loop is the timed one, already
                // running; `evm_startMining` is then a no-op that answers
                // true, and `evm_stopMining` pauses it.
                Some(timed) => {
                    Some(timed.clone() as Arc<dyn rustock_rpc::evm::BackgroundMiner>)
                }
                None => miner.clone().map(|m| {
                    Arc::new(rustock_rpc::evm::AutoMiner::new(
                        m as Arc<dyn rustock_rpc::mnr::MiningService>,
                        Some(Arc::new(PoolAdapter(pool.clone()))
                            as Arc<dyn rustock_rpc::server::TxPoolReader>),
                        std::time::Duration::from_millis(250),
                    )) as Arc<dyn rustock_rpc::evm::BackgroundMiner>
                }),
            },
            wallet: wallet.clone(),
            admin_enabled: args.rpc_admin,
            gc_burial: args.gc_burial,
            gc_pins: {
                // Recomputed per cycle, because the checkpoint moves. Empty
                // when serving is off, and then a forced collection is
                // exactly what it always was.
                let store = store.clone();
                let snap = snap_config.clone();
                Some(Arc::new(move || rustock_sync::snap_servable_roots(&store, &snap)))
            },
            prune_keep_depth: args.prune_keep_depth,
            prune_max_batch: args.prune_max_batch,
            logs_max_blocks: args.rpc_logs_max_blocks,
            gas_estimator_binary_search: args.gas_estimator_binary_search,
            snapshots: args
                .dev_rpc
                .then(|| Arc::new(rustock_rpc::evm::SnapshotManager::new())),
            scoring: Some(scoring.clone()),
            events: events.clone(),
        };
        // The WebSocket server shares the same `RpcState`, so every method
        // available over HTTP works over the socket too -- plus
        // `eth_subscribe`, which only means anything on a connection that
        // stays open.
        if args.ws {
            let ws_host = args.rpc_host.clone();
            let ws_port = args.ws_port;
            let ws_state = rpc_state.clone();
            tokio::spawn(async move {
                if let Err(e) = rustock_rpc::ws::start_ws_server(&ws_host, ws_port, ws_state).await
                {
                    tracing::error!("RPC WebSocket server error: {}", e);
                }
            });
        }

        let rpc_host = args.rpc_host.clone();
        let rpc_port = args.rpc_port;
        tokio::spawn(async move {
            if let Err(e) = rustock_rpc::server::start_rpc_server(&rpc_host, rpc_port, rpc_state).await {
                tracing::error!("RPC server error: {}", e);
            }
        });
    }

    // Independent of the RPC server: metrics are useful on a node that
    // serves no RPC at all, and a scrape should not need the RPC port open.
    if let Some(metrics_port) = args.metrics_port {
        let metrics_host = args.metrics_host.clone();
        tokio::spawn(async move {
            if let Err(e) =
                rustock_rpc::metrics_server::start_metrics_server(&metrics_host, metrics_port).await
            {
                tracing::error!("Metrics server error: {}", e);
            }
        });
    }

    node.start().await?;

    Ok(())
}

/// The `--breakdown-log` file as a sink for the miner's timing lines: each
/// line written and flushed at once.
fn open_breakdown_log(log: &std::path::Path) -> Result<rustock_execution::breakdown::BreakdownSink> {
    use std::io::Write;
    if let Some(dir) = log.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let file = std::fs::File::create(log)
        .with_context(|| format!("cannot create {}", log.display()))?;
    let file = std::sync::Mutex::new(std::io::BufWriter::new(file));
    Ok(Arc::new(move |line: &str| {
        let mut out = file.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = writeln!(out, "{line}").and_then(|_| out.flush()) {
            warn!(target: "rustock::mining", "Could not write the breakdown line: {e}");
        }
    }))
}

/// `--mine-timed`'s median: `10s`, `500ms`, `1.5s`, or a bare number of
/// seconds.
fn parse_block_time(raw: &str) -> Result<std::time::Duration, String> {
    let raw = raw.trim();
    let (number, unit) = match raw.find(|c: char| c.is_ascii_alphabetic()) {
        Some(i) => (&raw[..i], raw[i..].trim()),
        None => (raw, "s"),
    };
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("'{number}' is not a number"))?;
    let seconds = match unit {
        "s" | "sec" | "secs" => value,
        "ms" => value / 1000.0,
        "m" | "min" => value * 60.0,
        other => return Err(format!("unknown unit '{other}' (use ms, s or m)")),
    };
    if seconds <= 0.0 || !seconds.is_finite() {
        return Err("the median must be positive".into());
    }
    Ok(std::time::Duration::from_secs_f64(seconds))
}

/// `--import-blocks`: feed every block of an rskj `ExportBlocks` file to
/// `importer`, in file order. The first failure ends the process with the
/// block's number, hash and the check that failed.
fn run_import_blocks(
    path: &std::path::Path,
    mut importer: rustock_sync::import::BlockImporter,
    breakdown_log: Option<&std::path::Path>,
) -> Result<()> {
    use std::io::{BufRead, Write};
    let mut breakdown = match breakdown_log {
        Some(log) => {
            if let Some(dir) = log.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            let file = std::fs::File::create(log)
                .with_context(|| format!("cannot create {}", log.display()))?;
            Some(std::io::BufWriter::new(file))
        }
        None => None,
    };
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let reader: Box<dyn BufRead> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(std::io::BufReader::new(flate2::read::MultiGzDecoder::new(file)))
    } else {
        Box::new(std::io::BufReader::new(file))
    };
    let (start_number, _) = importer.best();
    info!("Importing blocks from {} on top of #{start_number}", path.display());
    let started = std::time::Instant::now();
    let mut imported = 0u64;
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        let exported = match rustock_sync::import::parse_export_line(&line) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => anyhow::bail!("{}:{}: {e:#}", path.display(), index + 1),
        };
        let (number, hash) = (exported.number, exported.hash);
        let block = match importer.import(exported.block) {
            Ok(block) => block,
            Err(e) => anyhow::bail!(
                "import failed at block {number} hash {} check {}: {e}",
                alloy_primitives::hex::encode(hash),
                e.check()
            ),
        };
        if let (Some(out), Some(t)) = (breakdown.as_mut(), block.timings.as_ref()) {
            writeln!(
                out,
                "{}",
                t.breakdown_line(block.number, block.hash, block.tx_count, block.gas_used)
            )?;
        }
        imported += 1;
        if imported.is_multiple_of(1000) {
            info!("Imported {imported} blocks (#{number})");
        }
    }
    let (number, hash) = importer.best();
    importer.finish().map_err(|e| anyhow::anyhow!("final flush: {e}"))?;
    if let Some(mut out) = breakdown {
        out.flush()?;
    }
    info!(
        "Imported {imported} blocks in {:.1}s; best block #{number} {hash:?}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The execution ladder for `config`: the chain's own, with the operator's
/// `--hardfork` and `--consensus-rule` overrides applied. Also returns the
/// names accepted without effect.
fn hardfork_config(
    config: &ChainConfig,
) -> Result<(rustock_execution::RskHardforkConfig, Vec<String>)> {
    rustock_execution::RskHardforkConfig::for_network(config.chain_id as u64)
        .with_rskj_overrides(&config.hardfork_overrides, &config.consensus_rule_overrides)
        .map_err(anyhow::Error::msg)
}

/// `name=height` as rskj's config writes it, `-1` for never.
fn parse_rskj_height(flag: &str, spec: &str) -> Result<(String, Option<u64>)> {
    let (name, height) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("{flag} {spec:?}: expected name=height"))?;
    let height: i64 = height
        .trim()
        .parse()
        .with_context(|| format!("{flag} {spec:?}: height"))?;
    Ok((name.trim().to_string(), u64::try_from(height).ok()))
}

/// `--export-blocks`: write the canonical chain from `from` to `to` (the best
/// block when unset) as rskj's `ExportBlocks` does, one block per line.
fn run_export_blocks(
    store: &BlockStore,
    path: &std::path::Path,
    from: u64,
    to: Option<u64>,
) -> Result<()> {
    use std::io::Write;
    let best = match store.head()? {
        Some(hash) => store
            .header(hash)?
            .ok_or_else(|| anyhow::anyhow!("head header {hash} missing"))?
            .number,
        None => anyhow::bail!("the store has no head block; nothing to export"),
    };
    let to = to.unwrap_or(best);
    anyhow::ensure!(
        to <= best,
        "--export-to {to} is above the best block #{best}"
    );
    anyhow::ensure!(from <= to, "--export-from {from} is above --export-to {to}");

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let file = std::fs::File::create(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    let mut out: Box<dyn Write> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(std::io::BufWriter::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::default(),
        )))
    } else {
        Box::new(std::io::BufWriter::new(file))
    };

    info!("Exporting blocks #{from} to #{to} to {}", path.display());
    let started = std::time::Instant::now();
    for number in from..=to {
        let hash = store
            .canonical_hash(number)?
            .ok_or_else(|| anyhow::anyhow!("no canonical block at #{number}"))?;
        let block = store
            .block(hash)?
            .ok_or_else(|| anyhow::anyhow!("block #{number} {hash} is not in the store"))?;
        anyhow::ensure!(
            block.header.number == number,
            "the canonical index names {hash} at #{number}, but the header says #{}",
            block.header.number
        );
        let td = store
            .total_difficulty(hash)?
            .ok_or_else(|| anyhow::anyhow!("block #{number} {hash} has no total difficulty"))?;
        writeln!(out, "{}", rustock_sync::import::encode_export_line(hash, td, &block))?;
    }
    out.flush()?;
    info!(
        "Exported {} blocks in {:.1}s",
        to - from + 1,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Apply the regtest chain options (`--genesis`, `--skip-pow-validation`,
/// `--consensus-rule`, `--hardfork`, `--min-gas-limit`, `--max-gas-limit`).
/// Refused on mainnet and testnet, whose rules are not the operator's to
/// change, unless `--allow-chain-overrides` says this is a copy of the
/// chain; `--genesis` is refused there regardless.
fn apply_chain_options(mut config: ChainConfig, args: &Args) -> Result<ChainConfig> {
    let any = args.genesis.is_some()
        || args.skip_pow_validation
        || !args.consensus_rule.is_empty()
        || !args.hardfork.is_empty()
        || args.min_gas_limit.is_some()
        || args.max_gas_limit.is_some();
    if !any {
        return Ok(config);
    }
    let real_chain = matches!(config.chain_id, 30 | 31);
    anyhow::ensure!(
        !real_chain || args.allow_chain_overrides,
        "--genesis, --skip-pow-validation, --consensus-rule, --hardfork and the gas-limit \
         bounds are regtest options; --allow-chain-overrides takes all but --genesis on \
         a copy of mainnet or testnet"
    );
    anyhow::ensure!(
        !(real_chain && args.genesis.is_some()),
        "--genesis is a regtest option: a genesis file would make this another chain"
    );
    if real_chain {
        warn!(
            "Chain overrides accepted on chain id {}: this node runs a schedule of its own \
             and must not follow the real network",
            config.chain_id
        );
    }
    // reference.conf: `rskip97 = orchid`. Where the chain keeps that
    // (mainnet), moving orchid moves it, unless --consensus-rule says.
    let orchid_before = config.activation_heights.orchid;
    for spec in &args.hardfork {
        let (name, height) = parse_rskj_height("--hardfork", spec)?;
        config.activation_heights.set_rskj_hardfork(&name, height);
        config.hardfork_overrides.push((name, height));
    }
    if config.activation_heights.rskip97 == Some(orchid_before) {
        config.activation_heights.rskip97 = Some(config.activation_heights.orchid);
    }
    for rule in &args.consensus_rule {
        let (name, height) = parse_rskj_height("--consensus-rule", rule)?;
        match name.as_str() {
            "rskip97" => config.activation_heights.rskip97 = height,
            _ => config.consensus_rule_overrides.push((name, height)),
        }
    }
    // Judged now, so a name the ladder refuses stops the node here.
    let (_, unmodelled) = hardfork_config(&config)?;
    for name in unmodelled {
        info!("Hardfork {name}: accepted, nothing in this node reads it");
    }
    if let Some(gas) = args.min_gas_limit {
        config.min_gas_limit = gas;
    }
    if let Some(gas) = args.max_gas_limit {
        config.max_gas_limit = gas;
    }
    config.skip_pow_validation = args.skip_pow_validation;
    if let Some(path) = &args.genesis {
        let spec = rustock_core::rskj_genesis::GenesisSpec::from_file(path)?;
        config.genesis_spec = Some(spec);
        // rskj writes the root of the state it built into the genesis header,
        // so build it once, in memory, to learn the root.
        let scratch = rustock_trie::MemoryTrieStore::new();
        let root = build_genesis_state(&config, &scratch)?.compute_hash(&scratch);
        let spec = config.genesis_spec.take().map(|s| s.with_state_root(root));
        config.genesis_spec = spec;
        info!(
            "Genesis from {}: state root {root:?}, hash {:?}",
            path.display(),
            config.known_genesis_hash().unwrap_or_default()
        );
    }
    if config.skip_pow_validation {
        tracing::warn!("Merged-mining proof of work is NOT validated (--skip-pow-validation)");
    }
    Ok(config)
}

/// Try to resume from persisted state, falling back to genesis if unavailable.
///
/// On restart, loads the Unitrie root recorded at the last EXECUTED block
/// (`exec_head`). The header's state_root cannot be used: before RSKIP126 it
/// holds the legacy Orchid root, and the download head may be far past the
/// executed head. Children resolve lazily via `NodeRef::Hash` lookups.
fn load_or_build_state(
    store: &BlockStore,
    config: &ChainConfig,
    trie_store: &dyn TrieStore,
) -> Result<TrieNode> {
    if let Some((exec_hash, state_root)) = store.exec_head()? {
        if let Some(data) = trie_store.get(state_root.as_slice()) {
            let root = TrieNode::from_message(&data, trie_store);
            let verified = root.compute_hash(trie_store);
            if verified == state_root {
                let number = store.header(exec_hash)?.map(|h| h.number).unwrap_or(0);
                info!(
                    "Resuming from executed block #{} (state root: {:?})",
                    number, state_root
                );
                return Ok(root);
            }
            tracing::warn!(
                "Exec head state root verification failed: computed={verified:?}, \
                 expected={state_root:?}. Rebuilding from genesis."
            );
        } else {
            tracing::warn!(
                "Exec head state root {:?} not found in trie store. \
                 Rebuilding from genesis.",
                state_root
            );
        }
    }

    build_genesis_state(config, trie_store)
}

/// Build the genesis state trie from the chain config's alloc entries.
///
/// Each alloc entry becomes an account in the Unitrie. RSKj's mainnet
/// genesis only includes the Bridge balance (no storage). The genesis
/// header state root uses a pre-RSKIP126 format that doesn't match
/// our Unitrie hash, so we skip the comparison.
fn build_genesis_state(config: &ChainConfig, trie_store: &dyn TrieStore) -> Result<TrieNode> {
    let alloc = config.genesis_alloc();
    if alloc.is_empty() {
        return Ok(TrieNode::empty());
    }

    let mut root = TrieNode::empty();

    for entry in &alloc {
        let key_bytes = account_key(&entry.address);
        let key = TrieKeySlice::from_key(&key_bytes);
        let acct = AccountState::new(entry.nonce, entry.balance);
        root = root.put(&key, &acct.encode(), trie_store);
    }

    // rskj `GenesisLoaderImpl.setupPrecompiledContractsStorage`: when RSKIP126
    // activates *at* genesis, the genesis precompiles are created if absent and
    // given the contract storage-prefix marker.
    //
    // rustock does this in the block executor at the activation block, which is
    // right for mainnet (#1,591,000, an ordinary executed block) and wrong for
    // testnet, where wasabi100 is height 0 -- genesis is constructed, never
    // executed, so the markers were never written and the genesis state root
    // came out as mainnet's.
    if config.activation_heights.wasabi100 == 0 {
        for addr in rustock_execution::precompiles::GENESIS_PRECOMPILES {
            let acct_key = TrieKeySlice::from_key(&account_key(&addr));
            if root.get(&acct_key, trie_store).is_none() {
                // rskj only creates the account when it does not already
                // exist, so the Bridge keeps the balance the alloc gave it.
                let acct = AccountState::new(U256::ZERO, U256::ZERO);
                root = root.put(&acct_key, &acct.encode(), trie_store);
            }
            let marker = TrieKeySlice::from_key(&rustock_trie::storage_prefix_key(&addr));
            root = root.put(&marker, &[1], trie_store);
        }

        // The second loop of `maintainPrecompiledContractStorageRoots`: any
        // consensus-enabled precompile whose rule also activates at genesis.
        // rskj calls `createAccount` unconditionally for these -- a fresh
        // account, nonce and balance reset -- and then marks it, unlike the
        // genesis set above which is only created when absent.
        for (addr, upgrade) in rustock_execution::precompiles::CONSENSUS_ENABLED_PRECOMPILES {
            use rustock_execution::hardfork::RskNetworkUpgrade as U;
            // A genesis read from an rskj file is rskj's regtest genesis,
            // where every upgrade in this list is at height 0 (regtest.conf),
            // so every one of these precompiles is created at genesis. The
            // execution ladder says the same: it starts at the last upgrade.
            let (ladder, _) = hardfork_config(config)?;
            let height = match upgrade {
                _ if config.genesis_spec.is_some() => {
                    (ladder.active_upgrade(0) >= upgrade).then_some(0)
                }
                U::Wasabi100 => Some(config.activation_heights.wasabi100),
                U::Papyrus200 => Some(config.activation_heights.papyrus200),
                U::Iris300 => Some(config.activation_heights.iris300),
                // Later upgrades are not modelled in ActivationHeights, and
                // none of them can be zero on any chain rustock supports.
                _ => None,
            };
            if height != Some(0) {
                continue;
            }
            let acct_key = TrieKeySlice::from_key(&account_key(&addr));
            let acct = AccountState::new(U256::ZERO, U256::ZERO);
            root = root.put(&acct_key, &acct.encode(), trie_store);
            let marker = TrieKeySlice::from_key(&rustock_trie::storage_prefix_key(&addr));
            root = root.put(&marker, &[1], trie_store);
        }
    }

    let computed = root.compute_hash(trie_store);
    info!("Genesis Unitrie hash: {computed:?}");

    root.save(trie_store, true);
    Ok(root)
}

fn setup_genesis(store: &BlockStore, config: &ChainConfig) -> Result<alloy_primitives::B256> {
    if let Some(genesis) = store.canonical_hash(0)? {
        return Ok(genesis);
    }

    let genesis = config.genesis_header();
    let hash = config.known_genesis_hash().unwrap_or_else(|| genesis.hash());

    store.put_header_with_hash(hash, &genesis)?;
    store.put_total_difficulty(hash, genesis.difficulty)?;
    store.put_canonical_hash(0, hash)?;
    store.set_head(hash)?;
    Ok(hash)
}

/// Runs an rskj database import and returns; the node is not started.
///
/// Order matters: state first, then blocks, then the derived chain metadata.
/// If the import is interrupted, re-running it resumes -- every phase skips
/// what is already present.
fn run_rskj_import(
    src: &str,
    store: &std::sync::Arc<BlockStore>,
    metrics_path: Option<&str>,
    skip_existing: bool,
    disable_wal: bool,
    compact_first: bool,
    metadata_only: bool,
    skip_unitrie: bool,
    skip_metadata: bool,
    unitrie_threads: usize,
) -> Result<()> {
    use rustock_storage::rskj_import::{self, WalMode, WriteMode};
    use std::path::Path;

    // Catch SIGTERM/SIGINT so a stop request flushes rather than discarding
    // memtables. Import writes bypass the WAL, so an uncaught termination
    // silently loses data that a phase has already reported as written.
    rskj_import::install_signal_handlers();
    info!("Signal handlers installed: SIGTERM/SIGINT will flush and stop cleanly (never use SIGKILL)");

    let mode = if skip_existing { WriteMode::SkipExisting } else { WriteMode::Unconditional };
    let wal = if disable_wal { WalMode::Disabled } else { WalMode::Enabled };
    info!("Import write mode: {mode:?}, WAL: {wal:?}");

    let src = Path::new(src);
    if !src.join("blocks").is_dir() || !src.join("unitrie").is_dir() {
        anyhow::bail!(
            "{} does not look like an rskj database directory (expected blocks/ and unitrie/ inside)",
            src.display()
        );
    }

    let mut csv: Option<std::fs::File> = match metrics_path {
        Some(p) => {
            let exists = Path::new(p).exists();
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p)?;
            if !exists {
                use std::io::Write;
                writeln!(f, "phase,scanned,written,skipped,bytes,elapsed_secs")?;
            }
            Some(f)
        }
        None => None,
    };

    let started = std::time::Instant::now();
    info!("Importing rskj database from {}", src.display());

    if metadata_only {
        info!("Metadata-only run: skipping the trie and block phases");
    }

    // State first: if this is interrupted the blocks are still absent, so the
    // node will not come up believing it has a chain it cannot execute.
    let unitrie_phase = if metadata_only || skip_unitrie {
        if skip_unitrie {
            info!("Skipping the trie phase: state will be read from the source instead");
        }
        Default::default()
    } else if unitrie_threads == 1 {
        rskj_import::import_unitrie(
            src,
            store.db(),
            mode,
            wal,
            csv.as_mut().map(|f| f as &mut dyn std::io::Write),
        )?
    } else {
        rskj_import::import_unitrie_parallel(
            src,
            store.db(),
            mode,
            wal,
            unitrie_threads,
            csv.as_mut().map(|f| f as &mut dyn std::io::Write),
        )?
    };

    let block_stats = if metadata_only {
        Default::default()
    } else {
        rskj_import::import_blocks(
        src,
        store,
        mode,
        wal,
        csv.as_mut().map(|f| f as &mut dyn std::io::Write),
    )?
    };

    if skip_metadata {
        info!(
            "Skipping the metadata rebuild: the canonical index is keyed by block hash \
             and the block phase wrote under the source's own hashes, so what is already \
             there still holds"
        );
        info!("Import complete in {:.0}s", started.elapsed().as_secs_f64());
        return Ok(());
    }

    // Compact BEFORE the metadata rebuild, not after.
    //
    // The two write phases above leave the database as a deep stack of
    // un-merged L0 files when auto-compaction is disabled. The metadata rebuild
    // that follows is read-heavy -- roughly 18.5M random header lookups over
    // 9.2M blocks -- and every one of those has to probe bloom filters across
    // each un-merged file. Compacting first was measured to matter: against 735
    // uncompacted SSTs the backward walk managed only ~7 MB/s at 10% CPU.
    if compact_first {
        let t = std::time::Instant::now();
        info!("Compacting before metadata rebuild (the read-heavy phase)");
        store.compact_all()?;
        info!("Compaction finished in {:.0}s", t.elapsed().as_secs_f64());
    }

    // Derive what rskj keeps in its MapDB index, which is not readable here.
    //
    // The tip comes from the block import rather than BlockStore::head: head
    // still points at whatever this node had synced before the import, and is
    // only moved once the metadata rebuild below completes.
    let tip = if metadata_only {
        // No block phase ran, so find the tip by scanning the headers we hold.
        store.highest_header()?.ok_or_else(|| {
            anyhow::anyhow!("metadata-only run but no headers present; run a full import first")
        })?
    } else {
        if block_stats.tip_number == 0 && block_stats.scanned == 0 {
            anyhow::bail!("no blocks found in the source datasource");
        }
        block_stats.tip_hash
    };
    info!("Source tip is {tip:?}; rebuilding canonical chain and difficulty");
    let tip_number = rskj_import::rebuild_chain_metadata(
        store,
        tip,
        csv.as_mut().map(|f| f as &mut dyn std::io::Write),
    )?;

    if rskj_import::shutdown_requested() {
        info!("Import stopped early by signal; phases completed so far are flushed and durable");
        return Ok(());
    }

    info!(
        "Import complete in {:.0}s: {} trie nodes, {} blocks, head #{}",
        started.elapsed().as_secs_f64(),
        unitrie_phase.written,
        block_stats.written,
        tip_number
    );

    Ok(())
}

/// Scans the Unitrie from one state root and prints statistics.
///
/// Opens read-only: the scan is a pure reader, and requiring the node to stop
/// for it would make the tool far less useful. A read-only handle sees the
/// database as of the last flush, which is what we want anyway -- a consistent
/// snapshot rather than a moving target.
/// Opens a trie source and resolves which state root to start from.
///
/// Two shapes are accepted. A node datadir carries headers, so a root can be
/// chosen by block or taken from the executed head. A snapshot carries only
/// trie nodes and its own metadata, so the root comes from there -- and a block
/// cannot be selected, because a snapshot holds exactly one state and no
/// headers to look anything up in.
fn open_trie_source(
    dir: &str,
    block: Option<u64>,
) -> Result<(std::sync::Arc<rocksdb::DB>, alloy_primitives::B256, Option<u64>)> {
    if rustock_storage::trie_snapshot::is_snapshot(dir) {
        let meta = rustock_storage::trie_snapshot::read_meta(dir)?;
        if block.is_some() {
            anyhow::bail!(
                "{dir} is a trie snapshot: it holds one state ({:?}) and no headers, so a                  block cannot be selected. Drop --trie-tool-block, or point at a node datadir.",
                meta.root
            );
        }
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.set_max_open_files(512);
        let db = rocksdb::DB::open_cf_for_read_only(&opts, dir, ["trie_nodes"], false)
            .with_context(|| format!("opening snapshot {dir} read-only"))?;
        info!(
            "Snapshot {dir}: root {:?}, {} nodes, taken {}",
            meta.root, meta.nodes, meta.created
        );
        return Ok((std::sync::Arc::new(db), meta.root, meta.block));
    }
    open_node_trie_source(dir, block)
}

fn open_node_trie_source(
    data_dir: &str,
    block: Option<u64>,
) -> Result<(std::sync::Arc<rocksdb::DB>, alloy_primitives::B256, Option<u64>)> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.set_max_open_files(512);
    let cfs = ["headers", "block_numbers", "total_difficulty", "block_bodies",
               "receipts", "tx_index", "trie_nodes"];
    let db = rocksdb::DB::open_cf_for_read_only(&opts, data_dir, cfs, false)
        .with_context(|| format!("opening {data_dir} read-only"))?;
    let db = std::sync::Arc::new(db);

    // Resolve the root: an explicit block's header, or the last executed block.
    let (root, resolved_block) = match block {
        Some(n) => {
            let cf_num = db.cf_handle("block_numbers")
                .ok_or_else(|| anyhow::anyhow!("missing block_numbers column family"))?;
            let hash = db.get_cf(cf_num, n.to_be_bytes())?
                .ok_or_else(|| anyhow::anyhow!("no canonical block at #{n}"))?;
            let cf_h = db.cf_handle("headers")
                .ok_or_else(|| anyhow::anyhow!("missing headers column family"))?;
            let raw = db.get_cf(cf_h, &hash)?
                .ok_or_else(|| anyhow::anyhow!("header missing for block #{n}"))?;
            let mut slice: &[u8] = &raw;
            let h = <rustock_core::Header as alloy_rlp::Decodable>::decode(&mut slice)?;
            // Before Wasabi100 (RSKIP126, mainnet #1,591,000) the header's
            // state_root is the legacy Orchid root, not a Unitrie node hash, so
            // it will not resolve in the trie store. Say so rather than
            // reporting a bare "not found".
            if n < 1_591_000 {
                anyhow::bail!(
                    "block #{n} predates RSKIP126 (mainnet #1,591,000): its header holds the \
                     legacy Orchid state root, not a Unitrie node hash. Choose a later block."
                );
            }
            (h.state_root, Some(n))
        }
        None => {
            // The last EXECUTED block, not the last downloaded one: only the
            // executed head is guaranteed to have its state present.
            let raw = db.get(b"exec_head")?
                .ok_or_else(|| anyhow::anyhow!(
                    "no exec head recorded; pass --trie-tool-block to choose a block"
                ))?;
            if raw.len() < 64 {
                anyhow::bail!("exec head record is malformed");
            }
            let hash = alloy_primitives::B256::from_slice(&raw[0..32]);
            let root = alloy_primitives::B256::from_slice(&raw[32..64]);
            let cf_h = db.cf_handle("headers")
                .ok_or_else(|| anyhow::anyhow!("missing headers column family"))?;
            let number = db.get_cf(cf_h, hash.as_slice())?.and_then(|raw| {
                let mut slice: &[u8] = &raw;
                <rustock_core::Header as alloy_rlp::Decodable>::decode(&mut slice).ok().map(|h| h.number)
            });
            (root, number)
        }
    };
    Ok((db, root, resolved_block))
}

fn run_trie_tool(
    source: &str,
    block: Option<u64>,
    progress_every: u64,
    copy_to: Option<&str>,
    copy_overwrite: bool,
) -> Result<()> {
    use rustock_storage::trie_tool;
    use rustock_storage::trie_snapshot::SnapshotWriter;

    let (db, root, resolved_block) = open_trie_source(source, block)?;

    // An empty string means the flag was given without a value: name the
    // directory after the root, which is the one label guaranteed to identify
    // the contents.
    let target = copy_to.map(|t| {
        if t.is_empty() {
            format!("{root:?}").trim_start_matches("0x").to_string()
        } else {
            t.to_string()
        }
    });

    let mut writer = match target.as_deref() {
        Some(t) => {
            info!("Copying scanned state to {t}");
            Some(SnapshotWriter::create(t, copy_overwrite)?)
        }
        None => None,
    };

    info!("Scanning Unitrie from state root {root:?}");
    let store = rustock_storage::RocksDbTrieStore::from_db(db);
    let started = std::time::Instant::now();
    let stats = trie_tool::scan_with_options(
        &store,
        root,
        trie_tool::ScanOptions {
            interval_secs: progress_every,
            snapshot: writer.as_mut(),
            ..Default::default()
        },
    )?;
    trie_tool::report(&stats, root, resolved_block, started.elapsed().as_secs_f64());

    if let Some(w) = writer {
        let meta = w.finish(root, resolved_block, source)?;
        println!("SNAPSHOT");
        println!("  {:<34}{:>14}", "directory", target.as_deref().unwrap_or("-"));
        println!("  {:<34}{:>14}", "nodes written", meta.nodes);
        println!("  {:<34}{:>14}", "long values written", meta.long_values);
        println!("  {:<34}{:>14}", "bytes written", meta.bytes);
        println!();
        println!("  Re-scan it with:");
        println!("    rustock --trie-tool --trie-tool-source {}",
            target.as_deref().unwrap_or("-"));
    }
    Ok(())
}

/// Prints every field of the node at one path.
fn run_trie_node(source: &str, block: Option<u64>, path: &str) -> Result<()> {
    use rustock_storage::trie_inspect;

    let bits = trie_inspect::parse_path(path)?;
    let (db, root, _) = open_trie_source(source, block)?;
    let store = rustock_storage::RocksDbTrieStore::from_db(db);

    match trie_inspect::find_by_path(&store, root, &bits)? {
        Some(found) => {
            println!("state root      {root:?}");
            print!("{}", trie_inspect::describe(&found, &store));
        }
        None => {
            println!("state root      {root:?}");
            println!(
                "No node at {}. The path either leaves the trie, or ends partway through a \
                 shared path -- a run of bits the trie keeps compressed inside one node, where \
                 no node exists to address.",
                trie_inspect::format_path(&bits)
            );
        }
    }
    Ok(())
}

/// Build and spawn the peg-out watcher. Returns `None` when the file disables
/// it. Errors mean a bad configuration and are reported without stopping the
/// node.
fn start_pegout_alerts(
    path: &str,
    store: Arc<BlockStore>,
    trie: Arc<dyn rustock_trie::TrieStore>,
    hardfork_cfg: rustock_execution::RskHardforkConfig,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    use rustock_alerts::{AlertSink, Config, LogSink, Watcher};

    let config = Config::load(path)?;
    let email = config.alerts.email;
    let cfg = config.alerts.pegout;
    let contract = config.alerts.contract_value;
    // One watcher serves both: they sweep the same blocks in the same order,
    // and two tasks walking the chain in parallel would read everything twice
    // to no end. Either section alone is enough to start it.
    if !cfg.enabled && !contract.enabled {
        return Ok(None);
    }

    // The log sink is always present, so the record exists even if mail fails.
    // `mut` is needed only under `--features smtp`, where the push below is
    // compiled in. Without the attribute a default build warns, and
    // `clippy --fix` will silently remove the `mut` and break the smtp build.
    #[cfg_attr(not(feature = "smtp"), allow(unused_mut))]
    let mut sinks: Vec<Box<dyn AlertSink>> = vec![Box::new(LogSink)];
    if email.enabled {
        #[cfg(feature = "smtp")]
        sinks.push(Box::new(rustock_alerts::SmtpSink::new(&email)?));
        #[cfg(not(feature = "smtp"))]
        return Err(rustock_alerts::sink::smtp_unavailable());
        #[cfg(feature = "smtp")]
        info!(
            "Peg-out alerts will be emailed to {} via {}:{}",
            email.to.join(", "), email.smtp_host, email.smtp_port
        );
    } else {
        info!("Peg-out alerts will be logged only (email disabled)");
    }

    let change_scripts = cfg.change_scripts()?;

    // Thresholds are retuned by editing the file: the watcher re-reads it when
    // its modification time changes, so a threshold change needs no restart.
    // Block processing raises supply violations on its own thread; it must not
    // block there, so it pushes into this queue and the watcher delivers.
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    if let Err(e) = rustock_execution::supply::set_observer(move |v| {
        let top: Vec<String> = v.deltas.iter().take(8)
            .map(|d| format!("{} {} -> {}", d.address, d.before, d.after))
            .collect();
        // send() fails only once the watcher is gone; nothing to do about it
        // here, and the violation is already in the log.
        let _ = tx.send(rustock_alerts::Alert::SupplyNotConserved {
            block: v.block,
            created: v.created,
            amount_wei: v.amount.to_string(),
            top_accounts: top,
        });
    }) {
        tracing::warn!("supply observer not installed: {e}");
    }

    // The same route for a peg-in that leaned on the sender-detection path we
    // intend to remove. Block processing must not block on mail, so it pushes
    // into the same queue the watcher drains.
    if let Err(e) = rustock_execution::bridge::rskj_sender_compat::set_observer(move |s| {
        let _ = tx2.send(rustock_alerts::Alert::LegacyMultisigPegin {
            block: s.block,
            btc_txid: s.btc_txid.clone(),
            shape: s.shape.to_string(),
            refund_hash160: s.refund_hash160.clone(),
        });
    }) {
        tracing::warn!("multisig-sender observer not installed: {e}");
    }

    let chain_id = hardfork_cfg.chain_id;
    let mut watcher = Watcher::new(store.clone(), trie, cfg, sinks, change_scripts)?
        .reloading_from(path)
        .with_inbox(rx);
    if contract.enabled {
        // Its own processor, not the node's. This one re-executes committed
        // blocks for reading only, so it must not share the mutable wiring
        // -- the BTC block cache, the sender cache -- that block processing
        // depends on being in a known state.
        let processor =
            Arc::new(rustock_execution::BlockProcessor::new(hardfork_cfg, store));

        // The filter that keeps the re-execution off almost every block.
        // Block processing already walks every account a block wrote, for
        // the supply check; this takes the largest of those deltas off the
        // end of that walk. The closure runs on the thread executing blocks,
        // so it does one lock and one insert and nothing else.
        let movements = Arc::new(rustock_alerts::movement::MovementLog::default());
        let sink = movements.clone();
        match rustock_execution::supply::set_movement_observer(move |m| {
            sink.record(m.block_hash, m.max_movement);
        }) {
            Ok(()) => info!(
                "Contract value watch will re-execute a block only when an account moved \
                 more than {} RBTC",
                contract.replay_filter_btc
            ),
            // Without it every block is re-executed: correct, and about 24 ms
            // a block more expensive. Worth saying out loud rather than
            // leaving as an unexplained load.
            Err(e) => warn!(
                "movement observer not installed ({e}); the contract value watch will \
                 re-execute every block"
            ),
        }
        watcher = watcher.with_contract_value(contract, processor, chain_id, movements);
    }
    Ok(Some(tokio::spawn(watcher.run())))
}


/// Rebuild the transaction index over a block range, reporting progress.
///
/// Reads bodies only -- no trie, no execution -- so it can repair the history a
/// node imported rather than executed. Single-threaded on purpose: it is I/O
/// bound on one RocksDB instance that allows a single writer anyway.
fn run_repair_tx_index(
    store: &Arc<BlockStore>,
    from: Option<u64>,
    to: Option<u64>,
) -> anyhow::Result<()> {
    use std::time::Instant;

    let head = match store.head()? {
        Some(hash) => store.header(hash)?.map(|h| h.number).unwrap_or(0),
        None => 0,
    };
    let from = from.unwrap_or(1);
    let to = to.unwrap_or(head);
    if to < from {
        anyhow::bail!("--repair-to ({to}) is below --repair-from ({from})");
    }
    let total = to - from + 1;

    info!("repair tx-index: blocks #{from}..#{to} ({total} blocks), chain head #{head}");
    info!("repair tx-index: reading block bodies only; no trie access, no execution");

    let started = Instant::now();
    let report_every = 10_000u64;
    let (blocks, txs, skipped) = store.repair_tx_index(from, to, report_every, |block, done, txs| {
        let elapsed = started.elapsed().as_secs_f64();
        let scanned = block.saturating_sub(from) + 1;
        let pct = scanned as f64 * 100.0 / total as f64;
        let bps = scanned as f64 / elapsed.max(0.001);
        let tps = txs as f64 / elapsed.max(0.001);
        let eta = if bps > 0.0 { (total - scanned) as f64 / bps } else { 0.0 };
        info!(
            "repair tx-index: {pct:.2}% (#{block}) | {done} blocks indexed, {txs} txs | \
             {bps:.0} blocks/s, {tps:.0} tx/s | elapsed {} | ETA {}",
            fmt_duration(elapsed),
            fmt_duration(eta)
        );
    })?;

    let elapsed = started.elapsed().as_secs_f64();
    info!(
        "repair tx-index: DONE in {} | {blocks} blocks indexed, {txs} transactions, \
         {skipped} blocks skipped (no canonical hash or no body) | {:.0} blocks/s, {:.0} tx/s",
        fmt_duration(elapsed),
        blocks as f64 / elapsed.max(0.001),
        txs as f64 / elapsed.max(0.001),
    );
    Ok(())
}

/// Rewrite stored total difficulty with the uncle contribution rskj includes.
///
/// Reads bodies only -- no trie, no execution. The chain must be offline: this
/// rewrites the values the sync layer ranks chains with.
/// Rebuild the canonical `number -> hash` index from the head's own ancestry.
///
/// The authority is `parent_hash`. Every block names its parent, and the head
/// is on the chain this node accepted, so walking down from it yields the one
/// chain the index should describe -- whatever the index currently says.
///
/// An index rebuild, not a re-download: the headers are already stored. What
/// was wrong is which of them each height pointed at.
///
/// # Why this exists
///
/// A reorg rewrites canonical pointers at and below the fork point.
/// `ensure_canonical_lineage` stops walking at the first consistent pair, so a
/// pointer left stale beneath a healthy stretch is never revisited, and the
/// live repair only ever fired on a *missing* entry -- a stale one is not
/// missing. On mainnet 2026-10-04 seven such pointers accumulated, and the
/// first to mature through REMASC's 4,000-block settlement delay made the node
/// compute a state root the rest of the network does not share, and stop.
fn run_repair_canonical(store: &Arc<BlockStore>, from: Option<u64>) -> anyhow::Result<()> {
    use std::time::Instant;

    let head_hash = store
        .head()?
        .ok_or_else(|| anyhow::anyhow!("this database has no head to walk down from"))?;
    let head = store
        .header(head_hash)?
        .ok_or_else(|| anyhow::anyhow!("the head names a header this database does not hold"))?;

    // Deep enough to cover any reorg by default: a reorg cannot move the chain
    // further than MAX_REORG_DEPTH, so damage cannot begin below that.
    let from = from.unwrap_or_else(|| head.number.saturating_sub(10_000));
    if from > head.number {
        anyhow::bail!("--repair-from ({from}) is above the head (#{})", head.number);
    }
    let depth = head.number - from;

    info!(
        "repair canonical: walking #{} down to #{from} ({depth} blocks) from {:?}",
        head.number, head_hash
    );

    let started = Instant::now();
    let report = store.repair_canonical_lineage(head_hash, depth)?;
    let elapsed = started.elapsed();

    info!(
        "repair canonical: {} pointer(s) rewritten, {} hole(s) filled over {} block(s) \
         down to #{:?} in {:.1}s",
        report.corrected,
        report.filled,
        report.walked,
        report.lowest,
        elapsed.as_secs_f64()
    );
    if report.corrected == 0 && report.filled == 0 {
        info!("repair canonical: the index already linked; nothing changed");
    }
    Ok(())
}

fn run_repair_total_difficulty(
    store: &Arc<BlockStore>,
    from: Option<u64>,
    to: Option<u64>,
) -> anyhow::Result<()> {
    use std::time::Instant;

    let head = match store.head()? {
        Some(hash) => store.header(hash)?.map(|h| h.number).unwrap_or(0),
        None => 0,
    };
    let from = from.unwrap_or(0);
    let to = to.unwrap_or(head);
    if to < from {
        anyhow::bail!("--repair-to ({to}) is below --repair-from ({from})");
    }
    let total = to - from + 1;

    info!("repair total-difficulty: blocks #{from}..#{to} ({total} blocks), chain head #{head}");
    info!(
        "repair total-difficulty: td(n) = td(n-1) + difficulty(n) + sum(uncle difficulties),          as rskj Block.getCumulativeDifficulty does"
    );
    if from > 0 {
        info!(
            "repair total-difficulty: seeding from the stored total at #{}; it must already              be correct, so resume where the last run stopped",
            from - 1
        );
    }

    let started = Instant::now();
    let (written, unchanged, absent) =
        store.recompute_total_difficulty(from, to, 10_000, |block, done, td| {
            let elapsed = started.elapsed().as_secs_f64();
            let scanned = block.saturating_sub(from) + 1;
            let pct = scanned as f64 * 100.0 / total as f64;
            let bps = scanned as f64 / elapsed.max(0.001);
            let eta = if bps > 0.0 { (total - scanned) as f64 / bps } else { 0.0 };
            info!(
                "repair total-difficulty: {pct:.2}% (#{block}) | {done} rewritten | td {td} | \
                 {bps:.0} blocks/s | elapsed {} | ETA {}",
                fmt_duration(elapsed),
                fmt_duration(eta)
            );
        })?;

    let elapsed = started.elapsed().as_secs_f64();
    info!(
        "repair total-difficulty: DONE in {} | {written} rewritten, {unchanged} already correct, \
         {absent} heights with no block | {:.0} blocks/s",
        fmt_duration(elapsed),
        (written + unchanged) as f64 / elapsed.max(0.001),
    );
    if absent > 0 {
        warn!(
            "repair total-difficulty: {absent} of {total} heights hold no block, so their totals \
             were left alone. A snap-synced node has nothing below its checkpoint and cannot \
             rebuild those totals -- it inherits them from the checkpoint it trusted."
        );
    }
    Ok(())
}

/// Freeze the uncle headers and recompute total difficulty, in one pass.
///
/// Both read every block body, so they are done together: splitting them means
/// scanning the chain twice for data that was already in hand. Reads bodies
/// only -- no trie, no execution -- and the chain must be offline.
fn run_repair_chain_work(
    store: &Arc<BlockStore>,
    from: Option<u64>,
    to: Option<u64>,
) -> anyhow::Result<()> {
    use std::time::Instant;

    let head = match store.head()? {
        Some(hash) => store.header(hash)?.map(|h| h.number).unwrap_or(0),
        None => 0,
    };
    let from = from.unwrap_or(0);
    let to = to.unwrap_or(head);
    if to < from {
        anyhow::bail!("--repair-to ({to}) is below --repair-from ({from})");
    }
    let total = to - from + 1;

    info!("repair chain-work: blocks #{from}..#{to} ({total} blocks), chain head #{head}");
    info!(
        "repair chain-work: freezing uncle headers, then td(n) = td(n-1) + difficulty(n) + \
         sum(uncle difficulties), as rskj Block.getCumulativeDifficulty does"
    );
    if from > 0 {
        info!(
            "repair chain-work: seeding from the stored total at #{}; it must already be \
             correct, so resume where the last run stopped",
            from - 1
        );
    }

    let started = Instant::now();
    let (written, unchanged, absent, frozen) =
        store.rebuild_chain_work(from, to, 10_000, |block, done, td| {
            let elapsed = started.elapsed().as_secs_f64();
            let scanned = block.saturating_sub(from) + 1;
            let pct = scanned as f64 * 100.0 / total as f64;
            let bps = scanned as f64 / elapsed.max(0.001);
            let eta = if bps > 0.0 { (total - scanned) as f64 / bps } else { 0.0 };
            info!(
                "repair chain-work: {pct:.2}% (#{block}) | {done} totals rewritten | td {td} | \
                 {bps:.0} blocks/s | elapsed {} | ETA {}",
                fmt_duration(elapsed),
                fmt_duration(eta)
            );
        })?;

    let elapsed = started.elapsed().as_secs_f64();
    info!(
        "repair chain-work: DONE in {} | {frozen} blocks\' uncles frozen | {written} totals \
         rewritten, {unchanged} already correct, {absent} heights with no block | {:.0} blocks/s",
        fmt_duration(elapsed),
        (written + unchanged) as f64 / elapsed.max(0.001),
    );
    if absent > 0 {
        warn!(
            "repair chain-work: {absent} of {total} heights hold no block, so neither their \
             uncles nor their totals could be rebuilt"
        );
    }
    Ok(())
}

/// The difficulty checkpoint the sampled half of the gate measures from.
///
/// Only mainnet has one. Other chains get `None` and behave as they did before
/// the gate was enabled: the header walk still bounds a peer's claim, just
/// without the cheap rejection in front of it.
///
/// Supplying this is what turns `Phase::SamplingClaim` on. Before it, the half
/// that costs requests was built, tested and wired into the session but never
/// ran, because nothing passed a checkpoint -- so a claim *above* the
/// checkpoint height was bounded only after a header walk costing hours
/// instead of after a few hundred headers. The free half, refuting a claim at
/// or below the checkpoint by arithmetic, has been live independently.
fn snap_checkpoint_for(
    network_id: u64,
) -> Option<rustock_core::checkpoint::DifficultyCheckpoint> {
    match network_id {
        30 => Some(rustock_core::checkpoint::MAINNET_CHECKPOINT),
        _ => None,
    }
}

/// Seconds as `2h 04m 31s`, for progress lines a human reads.
fn fmt_duration(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 { format!("{h}h {m:02}m {sec:02}s") } else if m > 0 { format!("{m}m {sec:02}s") } else { format!("{sec}s") }
}

/// Import rskj's receipts, reporting progress the way the repair does.
fn run_import_receipts(
    store: &Arc<BlockStore>,
    dir: &str,
    from: Option<u64>,
    to: Option<u64>,
) -> anyhow::Result<()> {
    use std::time::Instant;

    let head = match store.head()? {
        Some(hash) => store.header(hash)?.map(|h| h.number).unwrap_or(0),
        None => 0,
    };
    let from = from.unwrap_or(1);
    let to = to.unwrap_or(head);
    anyhow::ensure!(to >= from, "--receipts-to ({to}) is below --receipts-from ({from})");
    let total = to - from + 1;

    info!("import receipts: blocks #{from}..#{to} ({total} blocks) from {dir}");
    info!("import receipts: blocks that already have receipts are skipped, so this resumes");

    let started = Instant::now();
    let (blocks, receipts, skipped, missing) = rustock_storage::rskj_import::import_receipts(
        store,
        std::path::Path::new(dir),
        from,
        to,
        10_000,
        |block, done, receipts| {
            let elapsed = started.elapsed().as_secs_f64();
            let scanned = block.saturating_sub(from) + 1;
            let pct = scanned as f64 * 100.0 / total as f64;
            let bps = scanned as f64 / elapsed.max(0.001);
            let eta = if bps > 0.0 { (total - scanned) as f64 / bps } else { 0.0 };
            info!(
                "import receipts: {pct:.2}% (#{block}) | {done} blocks, {receipts} receipts | \
                 {bps:.0} blocks/s | elapsed {} | ETA {}",
                fmt_duration(elapsed), fmt_duration(eta)
            );
        },
    )?;

    let elapsed = started.elapsed().as_secs_f64();
    info!(
        "import receipts: DONE in {} | {blocks} blocks written, {receipts} receipts, \
         {skipped} blocks skipped, {missing} transactions not found in the source",
        fmt_duration(elapsed)
    );
    if missing > 0 {
        tracing::warn!(
            "import receipts: {missing} transactions had no receipt in the source; \
             those blocks were left without receipts rather than written partially"
        );
    }
    Ok(())
}

/// Build the block-height index over an existing database.
fn run_build_height_index(store: &Arc<BlockStore>) -> anyhow::Result<()> {
    let already = !store.height_index_is_empty()?;
    if already {
        info!(
            "A height index is already present; re-running to cover anything added since. \
             This is safe: entries are derived from the headers they index."
        );
    }

    let started = std::time::Instant::now();
    info!("Building the block-height index. This reads every stored header.");

    let indexed = store.build_height_index(250_000, |count| {
        info!("  indexed {count} blocks");
    })?;

    let elapsed = started.elapsed();
    info!(
        "Height index built: {indexed} blocks in {:.1}s. Uncle selection can now find \
         the blocks that lost at each height.",
        elapsed.as_secs_f64()
    );
    Ok(())
}

/// Build the Bridge event index, reporting progress like the other bulk tasks.
fn run_build_bridge_index(
    store: &Arc<BlockStore>,
    from: Option<u64>,
    to: Option<u64>,
) -> anyhow::Result<()> {
    use std::time::Instant;

    let head = match store.head()? {
        Some(hash) => store.header(hash)?.map(|h| h.number).unwrap_or(0),
        None => 0,
    };
    let from = from.unwrap_or(1);
    let to = to.unwrap_or(head);
    anyhow::ensure!(to >= from, "range is empty");
    let total = to - from + 1;
    let bridge = rustock_execution::precompiles::BRIDGE_ADDR;

    info!("bridge index: blocks #{from}..#{to} ({total} blocks), Bridge at {bridge}");

    let started = Instant::now();
    let (scanned, events, no_receipts) = rustock_storage::rskj_import::build_bridge_event_index(
        store, bridge, from, to, 100_000,
        |block, scanned, events| {
            let elapsed = started.elapsed().as_secs_f64();
            let done = block.saturating_sub(from) + 1;
            let bps = done as f64 / elapsed.max(0.001);
            info!(
                "bridge index: {:.2}% (#{block}) | {scanned} blocks with receipts, {events} events | \
                 {bps:.0} blocks/s | elapsed {} | ETA {}",
                done as f64 * 100.0 / total as f64,
                fmt_duration(elapsed),
                fmt_duration(if bps > 0.0 { (total - done) as f64 / bps } else { 0.0 })
            );
        },
    )?;

    info!(
        "bridge index: DONE in {} | {scanned} blocks scanned, {events} Bridge events indexed, \
         {no_receipts} blocks had no receipts",
        fmt_duration(started.elapsed().as_secs_f64())
    );
    if no_receipts > 0 {
        tracing::warn!(
            "bridge index: {no_receipts} blocks had no receipts and contributed nothing; \
             run --import-rskj-receipts first for a complete index"
        );
    }
    Ok(())
}

#[cfg(test)]
mod log_timezone_tests {
    use super::parse_log_timezone;
    use time::UtcOffset;

    fn offset(h: i8, m: i8) -> UtcOffset {
        UtcOffset::from_hms(h, m, 0).unwrap()
    }

    /// The timestamp format, pinned.
    ///
    /// Nanosecond precision was nine digits of noise on every line; one digit
    /// is enough for a node whose interesting events are hundreds of
    /// milliseconds apart. This test is what stops the well-known `Rfc3339`
    /// formatter drifting back in, since it looks like the obvious choice.
    #[test]
    fn a_timestamp_has_one_subsecond_digit_and_a_numeric_offset() {
        use time::macros::datetime;

        let t = datetime!(2026-09-25 19:02:09.147085805 -03:00);
        let rendered = t.format(&super::LOG_TIMESTAMP).unwrap();
        assert_eq!(rendered, "2026-09-25T19:02:09.1-03:00");
        assert_eq!(rendered.len(), 27, "27 characters, not 35");

        // UTC renders as `+00:00`, not `Z`. Both are RFC 3339; the numeric
        // form keeps every line the same width, which is the point of the
        // exercise.
        let utc = datetime!(2026-09-25 22:02:09.9 +00:00);
        assert_eq!(utc.format(&super::LOG_TIMESTAMP).unwrap(), "2026-09-25T22:02:09.9+00:00");

        // Truncation, not rounding: `.98` must not become `.10` of the next
        // second.
        let nearly = datetime!(2026-09-25 22:02:09.98 +00:00);
        assert_eq!(
            nearly.format(&super::LOG_TIMESTAMP).unwrap(),
            "2026-09-25T22:02:09.9+00:00"
        );
    }

    #[test]
    fn utc_is_the_default_and_its_spellings() {
        for spec in ["utc", "UTC", "Utc", "z", "Z", ""] {
            assert_eq!(parse_log_timezone(spec, None).unwrap(), UtcOffset::UTC, "{spec:?}");
        }
    }

    /// Buenos Aires: UTC-3, and no daylight saving since 2009, so a fixed
    /// offset is correct for it year-round.
    #[test]
    fn a_signed_offset_parses_in_every_accepted_spelling() {
        for spec in ["-03:00", "-0300", "-03"] {
            assert_eq!(parse_log_timezone(spec, None).unwrap(), offset(-3, 0), "{spec:?}");
        }
        for spec in ["+05:30", "+0530"] {
            assert_eq!(parse_log_timezone(spec, None).unwrap(), offset(5, 30), "{spec:?}");
        }
        assert_eq!(parse_log_timezone("+00:00", None).unwrap(), UtcOffset::UTC);
    }

    /// The sign applies to the minutes too. `-03:30` is three and a half
    /// hours *behind* UTC, not three hours behind and thirty minutes ahead --
    /// which is what `from_hms(-3, 30, 0)` would mean.
    #[test]
    fn the_sign_carries_to_the_minutes() {
        let parsed = parse_log_timezone("-03:30", None).unwrap();
        assert_eq!(parsed, offset(-3, -30));
        let (h, m, _) = parsed.as_hms();
        assert_eq!((h, m), (-3, -30));
    }

    /// `local` without a resolved offset is an error, not a silent fallback
    /// to UTC: a timestamp in a timezone the operator did not ask for is
    /// worse than a refusal to start.
    #[test]
    fn local_without_a_resolvable_offset_is_an_error() {
        let err = parse_log_timezone("local", None).unwrap_err().to_string();
        assert!(err.contains("could not be determined"), "{err}");
        assert!(err.contains("-03:00"), "the error should suggest the way out: {err}");

        assert_eq!(parse_log_timezone("local", Some(offset(-3, 0))).unwrap(), offset(-3, 0));
    }

    /// clap must accept a value that begins with `-`.
    ///
    /// Without `allow_hyphen_values`, `--log-timezone -03:00` fails with
    /// "unexpected argument '-0' found" -- clap reads the value as another
    /// flag. Found by running the binary; no unit test on the parser could
    /// have caught it, because the parser is never reached.
    #[test]
    fn a_negative_offset_survives_argument_parsing() {
        use clap::Parser;
        let args = super::Args::try_parse_from([
            "rustock-cli",
            "--log-timezone",
            "-03:00",
        ])
        .expect("a leading-minus value must parse");
        assert_eq!(args.log_timezone, "-03:00");
        assert_eq!(parse_log_timezone(&args.log_timezone, None).unwrap(), offset(-3, 0));

        // The `=` form has to keep working too.
        let args =
            super::Args::try_parse_from(["rustock-cli", "--log-timezone=-0300"]).unwrap();
        assert_eq!(parse_log_timezone(&args.log_timezone, None).unwrap(), offset(-3, 0));

        // And the default is still UTC when the flag is absent.
        let args = super::Args::try_parse_from(["rustock-cli"]).unwrap();
        assert_eq!(args.log_timezone, "utc");
    }

    #[test]
    fn account_slots_default_to_rskj_s_and_take_a_value() {
        use clap::Parser;
        let args = super::Args::try_parse_from(["rustock-cli"]).unwrap();
        assert_eq!(args.account_slots, 16);
        let args =
            super::Args::try_parse_from(["rustock-cli", "--account-slots", "500"]).unwrap();
        assert_eq!(args.account_slots, 500);
    }

    #[test]
    fn nonsense_is_rejected_with_a_usable_message() {
        for spec in [
            "America/Argentina/Buenos_Aires",
            "-3",       // one digit
            "03:00",    // unsigned
            "-03:99",   // minutes out of range
            "-0:0",     // one digit either side
            "-1:2",     // would become -12:00 if colons were merely stripped
            "-03:0",
            "-3:00",
            "abc",
        ] {
            let err = parse_log_timezone(spec, None).unwrap_err().to_string();
            assert!(err.contains(spec), "the message should quote the input: {err}");
        }
        // An IANA name is the most likely wrong guess, so make sure it fails
        // loudly rather than being read as some prefix.
        assert!(parse_log_timezone("America/Argentina/Buenos_Aires", None).is_err());
    }
}

/// Reads the node's own height and its peers' for the health alarms.
///
/// Holds only what it reads. It cannot influence sync, execution or peering,
/// which is the property that makes it safe to poll from a background task.
struct NodeHealthSource {
    store: Arc<BlockStore>,
    peers: Arc<rustock_networking::peers::PeerStore>,
}

#[async_trait::async_trait]
impl rustock_alerts::health::HealthSource for NodeHealthSource {
    async fn sample(&self) -> Option<rustock_alerts::health::Sample> {
        // The executed head is what the stall alarm watches: a node fetching
        // blocks it never executes is stalled in every way that matters.
        let executed = self
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.store.header(hash).ok().flatten())
            .map(|h| h.number)?;

        // The best block held is what a peer's advertised best compares
        // against -- comparing their download head to our *executed* head
        // would read as permanently behind during any catch-up.
        let best = self
            .store
            .head()
            .ok()
            .flatten()
            .and_then(|hash| self.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(executed);

        let ids = self.peers.peers().await;
        let mut best_peer: Option<u64> = None;
        for id in &ids {
            if let Some(meta) = self.peers.metadata(id).await {
                // A peer that has not announced a height yet reports zero, and
                // counting that as a real reading would make every fresh
                // connection look like a stale one.
                if meta.best_number > 0 {
                    best_peer = Some(best_peer.map_or(meta.best_number, |b: u64| b.max(meta.best_number)));
                }
            }
        }

        Some(rustock_alerts::health::Sample {
            executed,
            best,
            best_peer,
            peer_count: ids.len(),
        })
    }
}

/// Start the health alarms if the configuration enables them. Returns whether
/// they were started.
fn start_health_alerts(
    path: &str,
    store: Arc<BlockStore>,
    peers: Arc<rustock_networking::peers::PeerStore>,
) -> anyhow::Result<bool> {
    use rustock_alerts::{AlertSink, Config, LogSink};

    let config = Config::load(path)?;
    let health = config.alerts.node_health;
    if !health.enabled {
        return Ok(false);
    }
    health.validate()?;

    // The log sink is always present, so the record exists even if mail fails.
    // Mail reuses the peg-out transport: one configuration, one credential.
    // `mut` is needed only under `--features smtp`, where the push below is
    // compiled in. Without the attribute a default build warns, and
    // `clippy --fix` will silently remove the `mut` and break the smtp build.
    #[cfg_attr(not(feature = "smtp"), allow(unused_mut))]
    let mut sinks: Vec<Box<dyn AlertSink>> = vec![Box::new(LogSink)];
    let email = config.alerts.email;
    if email.enabled {
        #[cfg(feature = "smtp")]
        sinks.push(Box::new(rustock_alerts::SmtpSink::new(&email)?));
        #[cfg(not(feature = "smtp"))]
        return Err(rustock_alerts::sink::smtp_unavailable());
        #[cfg(feature = "smtp")]
        info!(
            "Node health alarms will be emailed to {} (gap {} blocks, after {} min, \
             then quiet for {} h)",
            email.to.join(", "),
            health.block_gap,
            health.for_secs / 60,
            health.cooldown_secs / 3600
        );
    } else {
        info!("Node health alarms will be logged only (email disabled)");
    }

    let source = Arc::new(NodeHealthSource { store, peers });
    let thresholds = health.thresholds();
    let poll = std::time::Duration::from_secs(health.poll_interval_secs);
    tokio::spawn(rustock_alerts::health::run(
        source,
        thresholds,
        poll,
        Arc::new(sinks),
    ));
    Ok(true)
}

/// Tells the peers that can understand it what this node now serves.
///
/// Sent only to peers that negotiated `rsk/63`. An rskj peer receiving an
/// unknown message type throws out of `MessageType.valueOfType`, and its netty
/// handler answers that with `ctx.close()` — so the gate is not politeness, it
/// is the difference between informing a peer and losing it.
async fn announce_block_range(
    peer_store: &std::sync::Arc<rustock_networking::peers::PeerStore>,
    store: &std::sync::Arc<rustock_storage::BlockStore>,
    earliest: u64,
) {
    let Ok(Some(head_hash)) = store.head() else { return };
    let Ok(Some(head)) = store.header(head_hash) else { return };

    let targets = peer_store.peers_understanding_block_range().await;
    if targets.is_empty() {
        return;
    }
    let msg = rustock_networking::protocol::P2pMessage::RskMessage(
        rustock_networking::protocol::RskMessage::new(
            rustock_networking::protocol::RskSubMessage::BlockRangeUpdate(
                rustock_networking::protocol::rsk::BlockRange {
                    earliest_block: earliest,
                    latest_block: head.number,
                    latest_block_hash: head_hash,
                },
            ),
        ),
    );
    debug!(
        target: "rustock::prune",
        "announcing #{earliest}..#{} to {} peer(s) that speak the extension",
        head.number,
        targets.len()
    );
    for peer in targets {
        peer_store.send_to_peer(&peer, msg.clone()).await;
    }
}

#[cfg(test)]
mod snap_checkpoint_tests {
    use super::snap_checkpoint_for;

    /// Mainnet gets the shipped checkpoint, which is what enables the sampled
    /// half of the difficulty gate. Without it `Phase::SamplingClaim` never
    /// runs and a claim above the checkpoint height is bounded only by the
    /// full header walk.
    #[test]
    fn mainnet_gets_the_checkpoint() {
        let cp = snap_checkpoint_for(30).expect("mainnet has a checkpoint");
        assert_eq!(cp.number, rustock_core::checkpoint::MAINNET_CHECKPOINT.number);
    }

    /// Every other chain gets none, and behaves as it did before: the walk
    /// still bounds the claim. Shipping mainnet's checkpoint to testnet or
    /// regtest would measure those chains against a height they do not share.
    #[test]
    fn other_chains_get_none() {
        assert!(snap_checkpoint_for(31).is_none(), "testnet");
        assert!(snap_checkpoint_for(33).is_none(), "regtest");
        assert!(snap_checkpoint_for(0).is_none());
    }

    /// The checkpoint must not contradict a node's own chain, or every node
    /// reports `SelfExceeds` — which means "this build is wrong", not "this
    /// peer is lying", and halts rather than blaming anyone.
    ///
    /// This is the check that caught the stale value: the shipped figure
    /// predated total difficulty counting uncle difficulty, and the chain
    /// carries 1.748x it at that height.
    #[test]
    fn the_shipped_checkpoint_does_not_contradict_its_own_chain() {
        let cp = snap_checkpoint_for(30).unwrap();
        assert_eq!(
            rustock_core::checkpoint::audit_own_chain(&cp, cp.cumulative_difficulty),
            None,
            "the checkpoint contradicts the chain it was read from"
        );
    }
}

#[cfg(test)]
mod block_time_tests {
    use super::parse_block_time;
    use std::time::Duration;

    #[test]
    fn parses_rskj_style_durations() {
        assert_eq!(parse_block_time("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_block_time("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_block_time("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_block_time("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_block_time("7").unwrap(), Duration::from_secs(7));
        assert!(parse_block_time("0s").is_err());
        assert!(parse_block_time("-1s").is_err());
        assert!(parse_block_time("10h").is_err());
        assert!(parse_block_time("abc").is_err());
    }
}

#[cfg(test)]
mod genesis_tests {
    use super::*;
    use rustock_trie::MemoryTrieStore;

    fn regtest_args(extra: &[&str]) -> Args {
        let mut argv = vec!["rustock-cli", "--network-id", "33"];
        argv.extend_from_slice(extra);
        Args::parse_from(argv)
    }

    /// The lab's rskj regtest genesis (`tests/fixtures/rskj-regtest-genesis.json`,
    /// sixteen funded accounts, 25M gas limit). rskj gives it this hash:
    /// block 1 of every chain mined from it names it as parent. Getting there
    /// takes the file's difficulty bytes as written and the precompile
    /// accounts rskj creates at genesis when every upgrade is at height 0.
    #[test]
    fn an_rskj_genesis_file_gives_rskjs_genesis_hash() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rskj-regtest-genesis.json");
        let args = regtest_args(&["--genesis", path]);
        let config = apply_chain_options(ChainConfig::regtest(), &args).unwrap();
        assert_eq!(
            config.known_genesis_hash(),
            Some("0x227d8e8d835f5e7290e333f4177e551ef1222dde4704f677ba4a120051c31cc2".parse().unwrap())
        );
        let header = config.genesis_header();
        assert_eq!(header.hash(), config.known_genesis_hash().unwrap());
        assert_eq!(header.gas_limit, U256::from(25_000_000));
        assert_eq!(config.genesis_alloc().len(), 16);
    }

    #[test]
    fn chain_options_apply_on_regtest_only() {
        let args = regtest_args(&[
            "--skip-pow-validation",
            "--consensus-rule",
            "rskip97=0",
            "--min-gas-limit",
            "3000000",
            "--max-gas-limit",
            "18446744073709551615",
        ]);
        let config = apply_chain_options(ChainConfig::regtest(), &args).unwrap();
        assert!(config.skip_pow_validation);
        assert_eq!(config.activation_heights.rskip97, Some(0));
        assert_eq!((config.min_gas_limit, config.max_gas_limit), (3_000_000, u64::MAX));

        let disabled = regtest_args(&["--consensus-rule", "rskip97=-1"]);
        let config = apply_chain_options(ChainConfig::regtest(), &disabled).unwrap();
        assert_eq!(config.activation_heights.rskip97, None);

        let unknown = regtest_args(&["--consensus-rule", "rskip144=0"]);
        assert!(apply_chain_options(ChainConfig::regtest(), &unknown).is_err());

        let mainnet = Args::parse_from(["rustock-cli", "--skip-pow-validation"]);
        assert!(apply_chain_options(ChainConfig::mainnet(), &mainnet).is_err());
    }

    fn mainnet_args(extra: &[&str]) -> Args {
        let mut argv = vec!["rustock-cli", "--network-id", "30"];
        argv.extend_from_slice(extra);
        Args::parse_from(argv)
    }

    /// The flags the lab passes for perf-lab's mainnet seed: mainnet's
    /// schedule, reed810 and its rules moved to #9,002,504, rskip536 at
    /// vetiver900, no proof of work, 25M gas.
    const SEED_FLAGS: &[&str] = &[
        "--allow-chain-overrides",
        "--hardfork", "bahamas=3397", "--hardfork", "afterBridgeSync=370000",
        "--hardfork", "orchid=729000", "--hardfork", "orchid060=1052700",
        "--hardfork", "wasabi100=1591000", "--hardfork", "twoToThree=2018000",
        "--hardfork", "papyrus200=2392700", "--hardfork", "iris300=3614800",
        "--hardfork", "hop400=4598500", "--hardfork", "hop401=4976300",
        "--hardfork", "fingerroot500=5468000", "--hardfork", "arrowhead600=6223700",
        "--hardfork", "arrowhead631=6549300", "--hardfork", "lovell700=7338024",
        "--hardfork", "reed800=8052200", "--hardfork", "reed810=9002504",
        "--hardfork", "vetiver900=8804200", "--hardfork", "tbd1000=9002504",
        "--consensus-rule", "rskipUMM=2392700", "--consensus-rule", "rskip351=9002504",
        "--consensus-rule", "rskip535=9002504", "--consensus-rule", "rskip536=8804200",
        "--skip-pow-validation",
        "--min-gas-limit", "3000000", "--max-gas-limit", "18446744073709551615",
    ];

    /// Without the opt-in, mainnet is mainnet: every override refused, and a
    /// node started with none has mainnet's heights and ladder exactly.
    #[test]
    fn mainnet_without_the_opt_in_is_untouched() {
        let refused = mainnet_args(&["--hardfork", "reed810=9002504"]);
        assert!(apply_chain_options(ChainConfig::mainnet(), &refused).is_err());
        let refused = mainnet_args(&["--consensus-rule", "rskip535=9002504"]);
        assert!(apply_chain_options(ChainConfig::mainnet(), &refused).is_err());

        let plain = apply_chain_options(ChainConfig::mainnet(), &mainnet_args(&[])).unwrap();
        let mainnet = ChainConfig::mainnet();
        assert_eq!(plain.activation_heights.orchid, mainnet.activation_heights.orchid);
        assert_eq!(plain.activation_heights.rskip97, Some(729_000));
        assert_eq!(plain.activation_heights.rskip144, None);
        // 3,000,000 since the rskj parity fix (rskj `Constants.getMinGasLimit`);
        // this asserts mainnet's own defaults, so it tracks them.
        assert_eq!((plain.min_gas_limit, plain.max_gas_limit), (3_000_000, 1_000_000_000));
        assert!(!plain.skip_pow_validation);
        assert!(plain.hardfork_overrides.is_empty());
        let (ladder, unmodelled) = hardfork_config(&plain).unwrap();
        assert!(unmodelled.is_empty());
        assert!(!ladder.has_rskip144(9_003_580));
        assert!(!ladder.has_rskip351(9_003_580));
        assert_eq!(
            ladder.active_upgrade(9_003_580),
            rustock_execution::hardfork::RskNetworkUpgrade::Vetiver900
        );
    }

    #[test]
    fn the_seed_schedule_applies_on_mainnet_with_the_opt_in() {
        let config = apply_chain_options(ChainConfig::mainnet(), &mainnet_args(SEED_FLAGS)).unwrap();
        assert_eq!(config.chain_id, 30);
        assert_eq!(config.activation_heights.rskip144, Some(9_002_504));
        assert_eq!(config.activation_heights.orchid, 729_000);
        assert_eq!(config.activation_heights.rskip97, Some(729_000));
        assert_eq!(config.activation_heights.papyrus200, 2_392_700);
        assert!(config.skip_pow_validation);
        assert_eq!((config.min_gas_limit, config.max_gas_limit), (3_000_000, u64::MAX));
        assert!(config.genesis_spec.is_none(), "mainnet's genesis stays");
        let (ladder, unmodelled) = hardfork_config(&config).unwrap();
        assert_eq!(unmodelled, vec!["orchid060".to_string(), "tbd1000".to_string()]);
        assert!(!ladder.has_rskip144(9_002_503));
        assert!(ladder.has_rskip144(9_003_580));
        assert!(ladder.has_rskip351(9_003_580));
        assert!(!ladder.has_rskip535(9_002_503));
        assert!(ladder.has_rskip535(9_003_580));
        assert!(ladder.has_rskip536(8_804_200));
        assert_eq!(
            ladder.active_upgrade(9_003_580),
            rustock_execution::hardfork::RskNetworkUpgrade::Vetiver900
        );

        // A genesis file would change the chain: refused even with the opt-in.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rskj-regtest-genesis.json");
        let with_genesis = mainnet_args(&["--allow-chain-overrides", "--genesis", path]);
        assert!(apply_chain_options(ChainConfig::mainnet(), &with_genesis).is_err());
        // A rung this node reads at one height cannot be moved.
        let moved = mainnet_args(&["--allow-chain-overrides", "--hardfork", "hop401=1"]);
        assert!(apply_chain_options(ChainConfig::mainnet(), &moved).is_err());
        // Moving orchid moves rskip97 with it, as reference.conf ties them.
        let orchid = mainnet_args(&["--allow-chain-overrides", "--hardfork", "orchid=100"]);
        let config = apply_chain_options(ChainConfig::mainnet(), &orchid).unwrap();
        assert_eq!(config.activation_heights.rskip97, Some(100));
    }

    /// Testnet's genesis state root, published in rskj's
    /// `genesis/orchid-testnet.json` and in every testnet block #0.
    ///
    /// Reproducing it requires `setupPrecompiledContractsStorage`, which rskj
    /// runs in its *genesis loader* — not in the block executor — precisely
    /// because genesis is constructed rather than executed. rustock ran the
    /// equivalent only at the activation block, which is right for mainnet
    /// (#1,591,000, an ordinary block) and silently wrong for testnet, where
    /// wasabi100 is height 0. Without it the testnet genesis state was just
    /// the allocation, which is *mainnet's* genesis state.
    #[test]
    fn testnet_genesis_state_root_matches_the_chain() {
        let config = ChainConfig::testnet();
        let store = MemoryTrieStore::new();
        let root = build_genesis_state(&config, &store).unwrap();
        assert_eq!(
            root.compute_hash(&store),
            "0x45bce5168430c42b3d568331753f900a32457b4f3748697cbd8375ff4da72641"
                .parse::<alloy_primitives::B256>()
                .unwrap(),
            "testnet genesis state must match the published root"
        );
    }

    /// Regtest's header must commit to its allocation, or the ten funded
    /// accounts cannot be reached.
    ///
    /// This is not a formality. The header is what a state lookup
    /// resolves through, so a header carrying the empty root -- which
    /// regtest's did, correctly, while it funded nobody -- makes
    /// `eth_getBalance` answer "cannot resolve block" and every
    /// transaction fail for insufficient funds, with the state sitting
    /// in the trie the whole time.
    #[test]
    fn regtest_genesis_state_root_matches_the_header() {
        let config = ChainConfig::regtest();
        let store = MemoryTrieStore::new();
        let root = build_genesis_state(&config, &store).unwrap();
        assert_eq!(
            root.compute_hash(&store),
            config.genesis_header().state_root,
            "the regtest header must carry the root of its own allocation"
        );
    }

    /// Mainnet must be untouched by that: RSKIP126 does not activate at its
    /// genesis (wasabi100 is #1,591,000), so no precompile is seeded and the
    /// state is the allocation alone. Its header carries the *orchid* root of
    /// that same allocation, which `test_mainnet_genesis_orchid_state_root_matches_header`
    /// asserts separately.
    #[test]
    fn mainnet_genesis_seeds_no_precompiles() {
        let config = ChainConfig::mainnet();
        let store = MemoryTrieStore::new();
        let root = build_genesis_state(&config, &store).unwrap();

        // The alloc-only unitrie root, unchanged by the testnet fix.
        assert_eq!(
            root.compute_hash(&store),
            "0x21de9a922f22eb925cefc6d4c994cb28e9ec36e7a45862105f79e4d97c0babfc"
                .parse::<alloy_primitives::B256>()
                .unwrap()
        );

        // And specifically: no storage-prefix marker for a genesis precompile.
        let marker = TrieKeySlice::from_key(&rustock_trie::storage_prefix_key(
            &rustock_execution::precompiles::GENESIS_PRECOMPILES[0],
        ));
        assert!(
            root.get(&marker, &store).is_none(),
            "mainnet genesis must not seed precompile markers"
        );
    }

    /// The two chains must not agree: before the fix they did, which was the
    /// bug. Pinned so a future change cannot quietly collapse them again.
    #[test]
    fn the_two_chains_have_different_genesis_state() {
        let store_m = MemoryTrieStore::new();
        let store_t = MemoryTrieStore::new();
        let m = build_genesis_state(&ChainConfig::mainnet(), &store_m).unwrap();
        let t = build_genesis_state(&ChainConfig::testnet(), &store_t).unwrap();
        assert_ne!(m.compute_hash(&store_m), t.compute_hash(&store_t));
    }
}
