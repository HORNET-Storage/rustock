//! Node settings from a TOML file, underneath the command line.
//!
//! # Precedence
//!
//! ```text
//!   command line   >   config file   >   built-in default
//! ```
//!
//! That order is the point. An operator debugging a live node must be able to
//! override a file setting with a flag without editing the file, and every
//! existing invocation must keep working unchanged.
//!
//! Getting it right needs more than "apply the file, then apply the flags":
//! with clap's derive, a flag that was never passed still arrives carrying its
//! default, indistinguishable from one the user typed. So the merge asks clap
//! where each value came from (`ValueSource`) and leaves anything typed on the
//! command line alone.
//!
//! # What belongs here
//!
//! Runtime settings only. The binary also carries about thirty one-shot
//! operations -- `--import-rskj`, `--repair`, `--trie-tool`, `--probe-unitrie`
//! -- which run and then exit. Those have no place in a config file: a node
//! that re-ran an import on every start would be a trap, not a convenience.
//! `ONE_SHOT` lists them, and a test asserts every other flag is configurable,
//! so a new setting cannot be added without deciding which it is.

use clap::parser::ValueSource;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};

/// Settings the file may supply. Every field is optional: absent means "leave
/// whatever the command line or the default decided".
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub rpc: RpcSection,
    #[serde(default)]
    pub peers: PeersSection,
    #[serde(default)]
    pub trie: TrieSection,
    #[serde(default)]
    pub gc: GcSection,
    #[serde(default)]
    pub prune: PruneSection,
    #[serde(default)]
    pub mining: MiningSection,
    #[serde(default)]
    pub account_tx_rate_limit: RateLimitSection,
    #[serde(default)]
    pub log: LogSection,
    #[serde(default)]
    pub alerts: AlertsSection,
    #[serde(default)]
    pub snapshot: SnapshotSection,
    #[serde(default)]
    pub checkpoint: CheckpointSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    #[serde(default)]
    pub chain: ChainSection,
}

/// Regtest chain settings, for a chain that has to match one an rskj node
/// runs: its genesis file, its consensus-rule overrides, its gas-limit
/// bounds, and whether proof of work is checked.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSection {
    /// An rskj genesis JSON file, used instead of the built-in regtest genesis.
    pub genesis: Option<std::path::PathBuf>,
    /// rskj `miner.server.skipPowValidation`.
    pub skip_pow_validation: Option<bool>,
    /// rskj `blockchain.config.consensusRules`, as `name = height`
    /// (-1 disables).
    pub consensus_rules: Option<std::collections::BTreeMap<String, i64>>,
    pub min_gas_limit: Option<u64>,
    pub max_gas_limit: Option<u64>,
    /// rskj `blockchain.config.hardforkActivationHeights`, as `name = height`
    /// (-1 takes the upgrade off the ladder).
    pub hardforks: Option<std::collections::BTreeMap<String, i64>>,
    /// Take the settings above on mainnet and testnet too, for a copy of the
    /// chain run under rules it has not activated. `genesis` stays refused.
    pub allow_overrides: Option<bool>,
}

/// Prometheus metrics. Separate from `[rpc]` because the listener is: a
/// scrape is not an RPC call, and a node may want one without the other.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// Serve metrics on this port. Absent means no listener is opened.
    pub port: Option<u16>,
    pub host: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    pub port: Option<u16>,
    pub data_dir: Option<String>,
    pub network_id: Option<u64>,
    pub secret_key: Option<String>,
    /// Parsed as an IP address, matching the flag's type -- a malformed value
    /// is rejected when the file is read rather than misused later.
    pub external_ip: Option<std::net::IpAddr>,
    pub supply_check: Option<String>,
    /// `"on"` / `"off"`, as the flag takes.
    pub rskj_multisig_senders: Option<String>,
    /// Open both databases read-only and write nothing.
    pub read_only: Option<bool>,
    /// Remember recovered transaction senders, so the pool and the executor
    /// do not each recover the same signature. On by default; `false` turns
    /// it off and every sender is recomputed.
    pub sigcache: Option<bool>,
    pub account_slots: Option<u64>,
    /// Catch up with new blocks. `false` serves what is held and nothing more.
    pub follow_up: Option<bool>,
    /// Behave as though the canonical chain ends at this height. Requires
    /// `follow_up = false`.
    pub simulate_height: Option<u64>,
    /// Exit once the chain is synced, reporting how long it took.
    pub exit_when_synced: Option<bool>,
    /// How many threads may execute a block's parallel sublists (RSKIP-144).
    /// 1 executes every transaction in order on one thread.
    pub execution_threads: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSection {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub admin: Option<bool>,
    pub disabled: Option<bool>,
    /// Serve JSON-RPC over WebSocket too (rskj `providers.web.ws.enabled`).
    pub ws: Option<bool>,
    /// WebSocket port (rskj `providers.web.ws.port`, default 4445).
    pub ws_port: Option<u16>,
    /// Widest block range an `eth_getLogs` may span (rskj
    /// `rpc.logs.maxBlocksToQuery`, whose default is 5000).
    pub logs_max_blocks: Option<u64>,
    /// Enable the `evm_*` development-chain namespace. Off by default.
    pub dev: Option<bool>,
    /// Fall back to the pre-exactimator gas estimator: a binary search over
    /// roughly two dozen executions. The single-pass estimator is the
    /// default; this exists so an operator who suspects it can compare
    /// without rebuilding. See `rustock_execution::gas_estimator`.
    pub gas_estimator_binary_search: Option<bool>,
    /// A file of private keys this node may sign with, one 32-byte hex
    /// key per line. Off by default; see `Args::wallet_file`, which
    /// documents what it costs to turn on.
    pub wallet_file: Option<std::path::PathBuf>,
}

/// Snapshot sync, off on both sides by default (rskj ships it the same way).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSection {
    /// Serve snapshots of this node's state to peers that ask.
    pub server: Option<bool>,
    /// Catch up by downloading a state rather than executing into one.
    pub sync: Option<bool>,
    /// Blocks to download below the checkpoint when snapshot syncing. These
    /// are the blocks the node keeps history for once the sync is done.
    pub blocks: Option<u64>,
    /// Establish the header chain by ascending from ground already held, with
    /// uncles, instead of descending from the peer's offered checkpoint.
    pub forward_headers: Option<bool>,
    /// Bytes of state to ask for per chunk.
    pub chunk_bytes: Option<u64>,
    /// The offset grid chunks sit on. Changing it invalidates a server's
    /// cached cells.
    pub chunk_grid: Option<u64>,
    /// Chunk requests in flight at once, across all peers.
    pub parallel: Option<usize>,
    /// Fill the canonical index for history below the checkpoint window after
    /// a snapshot sync.
    pub index_history: Option<bool>,
    /// State bytes per second one peer may be served.
    pub peer_rate: Option<u64>,
    /// State bytes per second this server will produce in total.
    pub total_rate: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeersSection {
    pub max_peers: Option<usize>,
    pub max_inbound_peers: Option<usize>,
    pub max_inbound_per_ip: Option<usize>,
    pub max_inbound_per_cidr: Option<usize>,
    pub inbound_cidr_prefix: Option<u8>,
    /// Addresses or CIDR blocks refused at connection time, as rskj's
    /// `peer.bannedPeerIPs`.
    pub banned_peers: Option<Vec<String>>,
    /// Discovery bootstrap addresses, `HOST:PORT`. **Replaces** the chain's
    /// built-in list rather than adding to it, which is what makes a private
    /// two-node network possible.
    pub bootnodes: Option<Vec<String>>,
    /// Count scoring events but never punish (rskj
    /// `scoring.punishmentEnabled = false`).
    pub no_peer_punishment: Option<bool>,
    /// Never learn new node ids from peers and never dial them. With
    /// `bootnodes`, this pins the node to exactly the peers named here --
    /// which is what makes a controlled two-node test trustworthy.
    pub closed_network: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrieSection {
    pub backend: Option<String>,
    /// Storage engine: `rocksdb` (default) or `flatdb`.
    pub engine: Option<String>,
    /// Sizes a flatdb index at open. Ignored by rocksdb.
    pub expected_keys: Option<u64>,
    /// Blocks executed per trie durability point while catching up.
    pub flush_every: Option<u64>,
    pub dir: Option<String>,
    pub node: Option<String>,
    /// Entries in the BTC stored-block cache; 0 disables it.
    pub btc_block_cache_entries: Option<usize>,
    /// Threads used for parallel reads, by the snap-sync client and the trie
    /// store as well as the one-shot verifier.
    pub read_threads: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GcSection {
    pub epochs: Option<usize>,
    pub rotate_mb: Option<u64>,
    pub burial: Option<u64>,
    pub check_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSection {
    /// Require a peer to show it is on the checkpointed chain, by asking for
    /// the header at the checkpoint height and checking its hash.
    ///
    /// Off by default: a checkpoint hash states which chain is canonical, and
    /// shipping one asks whoever builds the node to choose a fork.
    pub verify_hash: Option<bool>,
    /// Bound a peer's claimed cumulative difficulty, sampling its chain above
    /// the checkpoint to do it. The bound and the sampling are one setting:
    /// bounding without sampling refutes only a claim made at or below the
    /// checkpoint, which an attacker avoids for free.
    pub bound_work: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PruneSection {
    pub keep_depth: Option<u64>,
    pub max_batch: Option<u64>,
    /// Delete block history below `keep_depth` as the node runs. Off by
    /// default: it discards history that only a resync restores.
    ///
    /// Removes everything: headers, the canonical index, total difficulties,
    /// bodies (and the uncles inside them), receipts and the transaction
    /// index. The narrower keys below do one part each.
    pub blocks: Option<bool>,
    /// Delete block bodies below the floor -- and with them the uncles, which
    /// live inside bodies rather than in a store of their own.
    pub bodies: Option<bool>,
    /// Delete headers, the canonical index and total difficulties below the
    /// floor. Requires `bodies` and `receipts`.
    pub headers: Option<bool>,
    /// Delete receipts and the transaction index below the floor.
    pub receipts: Option<bool>,
    /// Do not archive uncle headers in the freezer. Prevention rather than
    /// removal; see the flag's help for why.
    pub uncles: Option<bool>,
    /// Seconds between sweeps.
    pub every_secs: Option<u64>,
    /// Delete headers from the block database once the freezer holds them.
    /// Every lookup by hash for those blocks then depends on the freezer.
    pub frozen_headers: Option<bool>,
    /// Move settled headers out of the block database into flat files.
    /// `false` keeps them in RocksDB and loses the read win.
    pub freezer: Option<bool>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiningSection {
    pub enabled: Option<bool>,
    pub coinbase: Option<String>,
    pub extra_data: Option<String>,
    pub refresh_secs: Option<u64>,
    pub min_gas_price: Option<u64>,
    pub submission_rate_limit_ms: Option<u64>,
    pub update_work_on_new_transaction: Option<bool>,
    pub timed: Option<String>,
    pub flush_every: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSection {
    pub enabled: Option<bool>,
    pub cleaner_period: Option<i64>,
    pub max_accounts: Option<usize>,
    pub quota_multiplier: Option<u64>,
    pub gas_per_second_percent: Option<f64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    pub level: Option<String>,
    pub to_stdout: Option<bool>,
    /// `utc`, `local`, or a fixed UTC offset such as `-03:00`.
    pub timezone: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsSection {
    pub alerts_config: Option<String>,
}

impl FileConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
        // `deny_unknown_fields` throughout: a misspelled key must be an error,
        // not a setting silently left at its default. Someone who writes
        // `keep_dept = 500` deserves to be told, not to discover it months
        // later when the disk fills.
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing {path}: {e}"))
    }
}

/// Apply `file` to `target` for one setting, unless the command line supplied
/// it. `id` is clap's argument id, which for the derive API is the field name.
pub fn apply<T: Clone>(matches: &ArgMatches, id: &str, file: Option<&T>, target: &mut T) {
    if matches.value_source(id) == Some(ValueSource::CommandLine) {
        return; // typed by the operator; the file does not get to override it
    }
    if let Some(value) = file {
        *target = value.clone();
    }
}

/// Same, for a setting whose flag is `Option<T>` (no default).
pub fn apply_opt<T: Clone>(
    matches: &ArgMatches,
    id: &str,
    file: Option<&T>,
    target: &mut Option<T>,
) {
    if matches.value_source(id) == Some(ValueSource::CommandLine) {
        return;
    }
    if let Some(value) = file {
        *target = Some(value.clone());
    }
}

/// One-shot operations: they run and exit, so they are command-line only.
/// Listing them explicitly (rather than inferring) means adding a flag forces a
/// decision about which kind it is -- see `every_runtime_flag_is_configurable`.
#[allow(dead_code)] // referenced only from tests
pub const ONE_SHOT: &[&str] = &[
    "build_bridge_index",
    "build_height_index",
    "import_rskj_receipts",
    "receipts_from",
    "receipts_to",
    "repair",
    "repair_from",
    "repair_to",
    "import_blocks_db",
    "import_blocks",
    "export_blocks",
    "export_from",
    "export_to",
    "import_flush_every",
    "breakdown_log",
    "import_rskj",
    "import_metrics",
    "import_skip_existing",
    "import_enable_wal",
    "import_write_buffer_mb",
    "import_auto_compaction",
    "import_parallelism",
    "import_unitrie_threads",
    "probe_unitrie",
    "probe_source",
    "import_metadata_only",
    "import_skip_unitrie",
    "import_skip_metadata",
    "metadata_range",
    "import_index_dump",
    "metadata_by_walk",
    "metadata_in_memory",
    "trie_tool",
    "trie_tool_block",
    "trie_tool_progress",
    "trie_tool_source",
    "trie_tool_copy",
    "trie_tool_copy_overwrite",
    "config",
    // Profiling and verification modes: each runs against the database and
    // exits, so there is no session for a file to configure.
    "verify_state",
    "trie_shape",
    "measure_block_reads",
];

/// Every runtime setting the file can supply. Kept beside the merge so the two
/// cannot drift; the test below asserts it covers every flag that is not
/// one-shot.
#[allow(dead_code)] // referenced only from tests
pub const CONFIGURABLE: &[&str] = &[
    "port",
    "data_dir",
    "network_id",
    "secret_key",
    "external_ip",
    "supply_check",
    "execution_threads",
    "rskj_multisig_senders",
    "read_only",
    "follow_up",
    "simulate_height",
    "exit_when_synced",
    "rpc_host",
    "rpc_port",
    "metrics_host",
    "metrics_port",
    "rpc_admin",
    "wallet_file",
    "no_rpc",
    "ws",
    "ws_port",
    "max_peers",
    "max_inbound_peers",
    "max_inbound_per_ip",
    "max_inbound_per_cidr",
    "inbound_cidr_prefix",
    "banned_peers",
    "bootnodes",
    "no_peer_punishment",
    "btc_block_cache_entries",
    "trie_backend",
    "trie_engine",
    "trie_expected_keys",
    "trie_flush_every",
    "trie_dir",
    "trie_node",
    "gc_epochs",
    "gc_rotate_mb",
    "gc_burial",
    "gc_check_secs",
    "prune_keep_depth",
    "prune_max_batch",
    "prune_blocks",
    "prune_bodies",
    "prune_headers",
    "prune_receipts",
    "prune_uncles",
    "prune_every_secs",
    "checkpoint_verify_hash",
    "checkpoint_bound_work",
    "rpc_logs_max_blocks",
    "sigcache",
    "account_slots",
    "gas_estimator_binary_search",
    "dev_rpc",
    "mine",
    "mining_coinbase",
    "mining_extra_data",
    "mining_refresh_secs",
    "mining_min_gas_price",
    "mining_submission_rate_limit_ms",
    "mining_update_work_on_new_transaction",
    "mine_timed",
    "flush_every",
    "account_tx_rate_limit",
    "account_tx_rate_limit_cleaner_period",
    "account_tx_rate_limit_max_accounts",
    "account_tx_rate_limit_quota_multiplier",
    "account_tx_rate_limit_gas_per_second_percent",
    "hardfork",
    "allow_chain_overrides",
    "log_level",
    "log_to_stdout",
    // Read parallelism is read by the snap-sync client and the trie store
    // while the node is running, not only by the one-shot verifier.
    "read_threads",
    "prune_frozen_headers",
    "freezer",
    "closed_network",
    "log_timezone",
    "snap_server",
    "snap_sync",
    "snap_blocks",
    "snap_chunk_bytes",
    "snap_chunk_grid",
    "snap_parallel",
    "snap_index_history",
    "snap_forward_headers",
    "snap_peer_rate",
    "snap_total_rate",
    "alerts_config",
    "genesis",
    "skip_pow_validation",
    "consensus_rule",
    "min_gas_limit",
    "max_gas_limit",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;
    use clap::{CommandFactory, FromArgMatches};

    fn parse(argv: &[&str]) -> (clap::ArgMatches, Args) {
        let matches = Args::command().get_matches_from(argv);
        let args = Args::from_arg_matches(&matches).expect("parses");
        (matches, args)
    }

    fn write(toml_text: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(toml_text.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// The precedence the whole design turns on. An operator debugging a live
    /// node must be able to override a file setting with a flag without
    /// editing the file.
    #[test]
    fn command_line_beats_file_beats_default() {
        let file = write(
            r#"
            [node]
            port = 40404
            [gc]
            burial = 9999
            "#,
        );
        let path = file.path().to_str().unwrap();

        // File only: the file wins over the default (30303).
        let (m, mut a) = parse(&["rustock", "--config", path]);
        crate::apply_file_config(&m, &FileConfig::load(path).unwrap(), &mut a);
        assert_eq!(a.port, 40404, "file beats default");
        assert_eq!(a.gc_burial, 9999);

        // Flag as well: the flag wins over the file.
        let (m, mut a) = parse(&["rustock", "--config", path, "--port", "50505"]);
        crate::apply_file_config(&m, &FileConfig::load(path).unwrap(), &mut a);
        assert_eq!(a.port, 50505, "command line beats file");
        assert_eq!(a.gc_burial, 9999, "and leaves the rest of the file alone");
    }

    /// Listing a flag in `CONFIGURABLE` only declares an intention. This
    /// checks the four runtime flags added alongside the fork-discovery work
    /// actually reach the args, because `deny_unknown_fields` means an
    /// unwired key is not a silent no-op -- it rejects the whole file.
    #[test]
    fn the_runtime_flags_added_last_really_come_from_the_file() {
        let file = write(
            r#"
            [peers]
            closed_network = true
            [trie]
            read_threads = 7
            [prune]
            frozen_headers = true
            freezer = false
            "#,
        );
        let path = file.path().to_str().unwrap();
        let (m, mut a) = parse(&["rustock", "--config", path]);
        crate::apply_file_config(&m, &FileConfig::load(path).unwrap(), &mut a);

        assert!(a.closed_network, "[peers] closed_network");
        assert_eq!(a.read_threads, 7, "[trie] read_threads");
        assert!(a.prune_frozen_headers, "[prune] frozen_headers");
        assert!(!a.freezer, "[prune] freezer");
    }

    /// The subtle case, and the reason the merge consults `ValueSource` rather
    /// than comparing against the default: a flag typed with *exactly* its
    /// default value must still beat the file. Comparing values could not tell
    /// `--port 30303` from not passing `--port` at all.
    #[test]
    fn a_flag_typed_with_its_default_value_still_beats_the_file() {
        let file = write("[node]\nport = 40404\n");
        let path = file.path().to_str().unwrap();
        let (m, mut a) = parse(&["rustock", "--config", path, "--port", "30303"]);
        crate::apply_file_config(&m, &FileConfig::load(path).unwrap(), &mut a);
        assert_eq!(a.port, 30303, "explicitly typed, even though it is the default");
    }

    /// An empty file changes nothing.
    #[test]
    fn an_empty_file_leaves_every_default_alone() {
        let file = write("");
        let path = file.path().to_str().unwrap();
        let (m, mut a) = parse(&["rustock", "--config", path]);
        let before = a.port;
        crate::apply_file_config(&m, &FileConfig::load(path).unwrap(), &mut a);
        assert_eq!(a.port, before);
        assert_eq!(a.gc_burial, 4000);
    }

    /// A typo must be an error. Someone who writes `keep_dept` deserves to be
    /// told, not to discover months later that pruning used the default.
    #[test]
    fn an_unknown_key_is_an_error() {
        let file = write("[prune]\nkeep_dept = 500\n");
        let err = FileConfig::load(file.path().to_str().unwrap()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("keep_dept"), "the error must name the key: {msg}");
    }

    /// Including an unknown *section*.
    #[test]
    fn an_unknown_section_is_an_error() {
        let file = write("[prunning]\nkeep_depth = 500\n");
        assert!(FileConfig::load(file.path().to_str().unwrap()).is_err());
    }

    /// A value of the wrong type is an error too, and names the setting.
    #[test]
    fn a_malformed_value_is_an_error() {
        let file = write("[node]\nport = \"thirty thousand\"\n");
        let err = FileConfig::load(file.path().to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("port"), "{err}");
    }

    /// A missing file is an error naming the path, not a silent fallback to
    /// defaults -- an operator who passes --config means it.
    #[test]
    fn a_missing_file_is_an_error() {
        let err = FileConfig::load("/nonexistent/rustock/node.toml").unwrap_err();
        assert!(err.to_string().contains("/nonexistent/rustock/node.toml"), "{err}");
    }

    /// The drift guard. Every flag is either a runtime setting the file can
    /// supply, or a one-shot operation that is command-line only. Adding a
    /// flag without deciding which fails here, so the config cannot silently
    /// fall behind the command line.
    #[test]
    fn every_runtime_flag_is_configurable() {
        let cmd = Args::command();
        let mut unclassified = Vec::new();
        for arg in cmd.get_arguments() {
            let id = arg.get_id().as_str();
            if id == "help" || id == "version" {
                continue;
            }
            if ONE_SHOT.contains(&id) || CONFIGURABLE.contains(&id) {
                continue;
            }
            unclassified.push(id.to_string());
        }
        assert!(
            unclassified.is_empty(),
            "these flags are in neither ONE_SHOT nor CONFIGURABLE -- decide which \
             each one is: {unclassified:?}"
        );
    }

    /// And the reverse: nothing is listed that is not a real flag, so the
    /// lists cannot rot as flags are renamed or removed.
    #[test]
    fn the_configurable_list_names_only_real_flags() {
        let cmd = Args::command();
        let ids: Vec<String> = cmd
            .get_arguments()
            .map(|a| a.get_id().as_str().to_string())
            .collect();
        for listed in CONFIGURABLE.iter().chain(ONE_SHOT.iter()) {
            assert!(
                ids.iter().any(|id| id == listed),
                "`{listed}` is listed but is not a flag"
            );
        }
    }

    /// One option as the example documents it.
    struct Documented {
        section: String,
        key: String,
        value: String,
        commented: bool,
        line: String,
    }

    const REFERENCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node.example.toml");
    const LIGHT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node-light.example.toml");

    /// Reads the example into one entry per option.
    fn documented_options() -> Vec<Documented> {
        options_in(REFERENCE)
    }

    fn options_in(path: &str) -> Vec<Documented> {
        let raw = std::fs::read_to_string(path).expect("example file");
        let mut out = Vec::new();
        let mut section = String::new();
        for line in raw.lines() {
            let t = line.trim();
            if let Some(name) = t.strip_prefix('[').and_then(|r| r.split(']').next()) {
                if !t.starts_with("[[") {
                    section = name.to_string();
                    continue;
                }
            }
            let (body, commented) = match t.strip_prefix('#') {
                Some(rest) => (rest.trim_start(), true),
                None => (t, false),
            };
            // Anything before the first section header is prose, including
            // the header's own illustration of this very convention.
            if section.is_empty() {
                continue;
            }
            let Some((k, v)) = body.split_once('=') else { continue };
            let key = k.trim();
            if key.is_empty()
                || !key.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
            {
                continue;
            }
            // Strip a trailing inline comment, respecting quotes and brackets.
            let mut value = String::new();
            let (mut in_str, mut depth) = (false, 0i32);
            for c in v.trim().chars() {
                match c {
                    '"' => in_str = !in_str,
                    '[' if !in_str => depth += 1,
                    ']' if !in_str => depth -= 1,
                    '#' if !in_str && depth == 0 => break,
                    _ => {}
                }
                value.push(c);
            }
            out.push(Documented {
                section: section.clone(),
                key: key.to_string(),
                value: value.trim().to_string(),
                commented,
                line: line.to_string(),
            });
        }
        out
    }

    /// A TOML value unlike the one given, so that applying it moves whichever
    /// `Args` field the key drives and reveals which one that is.
    #[allow(dead_code)] // no caller; see the dead-code issue before deleting
    fn perturb(value: &str) -> String {
        match value {
            "true" => "false".into(),
            "false" => "true".into(),
            v if v.starts_with('[') => "[\"probe-value\"]".into(),
            v if v.starts_with('"') => format!("\"{}probe\"", v.trim_matches('"')),
            v => match v.replace('_', "").parse::<i64>() {
                Ok(n) => (n + 7).to_string(),
                Err(_) => match v.parse::<f64>() {
                    Ok(f) => format!("{}", f + 0.25),
                    Err(_) => format!("\"{v}probe\""),
                },
            },
        }
    }

    /// Which `Args` field a `[section] key` drives, found by setting it alone
    /// to something unlike the default and seeing what moved.
    ///
    /// Derived rather than tabulated: a table of 53 mappings is one more thing
    /// to keep in step, and this cannot fall out of step with `apply_file_config`
    /// because it is `apply_file_config` that answers.
    fn field_driven_by(section: &str, key: &str, value: &str) -> Option<String> {
        let text = format!("[{section}]\n{key} = {value}\n");
        let file: FileConfig = toml::from_str(&text).ok()?;
        let (matches, mut moved) = parse(&["rustock"]);
        crate::apply_file_config(&matches, &file, &mut moved);

        let (_, base) = parse(&["rustock"]);
        let a = serde_json::to_value(&moved).ok()?;
        let b = serde_json::to_value(&base).ok()?;
        let (serde_json::Value::Object(a), serde_json::Value::Object(b)) = (a, b) else {
            return None;
        };
        a.into_iter().find(|(k, v)| b.get(k) != Some(v)).map(|(k, _)| k)
    }

    /// Every option states its default, and every statement is true.
    ///
    /// The convention, which the file's header spells out so a reader need not
    /// infer it:
    ///
    /// ```text
    ///   key = value   # default          the value shown IS the built-in default
    ///   # key = ...   # default: unset   no built-in default
    /// ```
    ///
    /// Both claims are checked. `# default` is verified by applying that very
    /// value and requiring nothing moved; `# default: unset` by finding the
    /// field the key drives and requiring the node leaves it empty.
    ///
    /// Six values were wrong when this was written — `data_dir`,
    /// `supply_check`, the three inbound peer limits and the trie backend — so
    /// deleting a line changed behaviour in the direction the line denied.
    #[test]
    fn the_example_declares_the_real_defaults() {
        let (_, defaults) = parse(&["rustock"]);
        let defaults_json = serde_json::to_value(&defaults).expect("serialise");

        let mut wrong = Vec::new();
        for opt in documented_options() {
            let marks_unset = opt.line.contains("default: unset");
            let marks_default = !marks_unset && opt.line.contains("# default");
            if !marks_default && !marks_unset {
                wrong.push(format!(
                    "[{}] {} states no default; every option must carry `# default` or \
                     `# default: unset`",
                    opt.section, opt.key
                ));
                continue;
            }

            if marks_default {
                // Claim: this value is what the node uses anyway. Apply it and
                // nothing should move.
                let text = format!("[{}]\n{} = {}\n", opt.section, opt.key, opt.value);
                let Ok(file) = toml::from_str::<FileConfig>(&text) else {
                    wrong.push(format!("[{}] {} does not parse", opt.section, opt.key));
                    continue;
                };
                let (matches, mut applied) = parse(&["rustock"]);
                crate::apply_file_config(&matches, &file, &mut applied);
                if applied != defaults {
                    wrong.push(format!(
                        "[{}] {} = {} is marked `# default` but is not the default",
                        opt.section, opt.key, opt.value
                    ));
                }
                continue;
            }

            // Claim: no built-in default. The field the key drives must be
            // empty on a node started with no arguments.
            match field_driven_by(&opt.section, &opt.key, &opt.value) {
                Some(field) => {
                    let empty = defaults_json
                        .get(&field)
                        .map(|v| v.is_null() || v == &serde_json::json!([]))
                        .unwrap_or(false);
                    if !empty {
                        wrong.push(format!(
                            "[{}] {} is marked `# default: unset` but `{field}` defaults to {}",
                            opt.section,
                            opt.key,
                            defaults_json.get(&field).unwrap_or(&serde_json::Value::Null)
                        ));
                    }
                }
                // Applying the shown value moved nothing. Either the key is
                // not wired into `apply_file_config`, or the value shown is
                // itself the default -- in which case the option has one and
                // `# default: unset` is the wrong mark.
                None => wrong.push(format!(
                    "[{}] {} is marked `# default: unset`, but setting it to {} changes \
                     nothing: either it is not wired into apply_file_config, or that is \
                     the default and the mark should be `# default`",
                    opt.section, opt.key, opt.value
                )),
            }
        }
        wrong.sort();
        assert!(
            wrong.is_empty(),
            "node.example.toml misstates what the node does by default:\n  {}",
            wrong.join("\n  ")
        );
    }

    /// Every configurable option must appear in the shipped example.
    ///
    /// The weaker test below checks that the example parses and names every
    /// section; it passed for a long time while eighteen of fifty-three
    /// options were undocumented, including a `[snapshot]` section that was
    /// missing outright. "Covers every section" is not "covers every option",
    /// and an operator reading the example has no way to discover what it
    /// leaves out.
    ///
    /// Done by reflection rather than by a list, because a list is one more
    /// thing to forget: the example is parsed with its commented-out keys
    /// uncommented, serialised, and checked for any field still `null`. A new
    /// option is a new `None`, and fails here until it is documented.
    #[test]
    fn the_example_documents_every_option() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node.example.toml");
        let raw = std::fs::read_to_string(path).expect("example file");

        // Uncomment `# key = value`, which is how an optional setting is shown.
        // Prose comments do not match: the line must be a bare lowercase key
        // followed by `=`.
        let mut seen_section = false;
        let uncommented: String = raw
            .lines()
            .map(|line| {
                let t = line.trim_start();
                if t.starts_with('[') {
                    seen_section = true;
                }
                if !seen_section {
                    return line.to_string();
                }
                let Some(rest) = t.strip_prefix('#') else { return line.to_string() };
                let rest = rest.trim_start();
                let is_setting = rest
                    .split_once('=')
                    .is_some_and(|(k, _)| {
                        let k = k.trim();
                        !k.is_empty()
                            && k.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                    });
                if is_setting { rest.to_string() } else { line.to_string() }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let cfg: FileConfig = toml::from_str(&uncommented)
            .expect("the example must still parse once its optional keys are uncommented");
        let value = serde_json::to_value(&cfg).expect("serialise");

        let mut undocumented = Vec::new();
        let serde_json::Value::Object(sections) = &value else { panic!("expected sections") };
        for (section, body) in sections {
            let serde_json::Value::Object(fields) = body else { continue };
            for (field, v) in fields {
                if v.is_null() {
                    undocumented.push(format!("[{section}] {field}"));
                }
            }
        }
        undocumented.sort();
        assert!(
            undocumented.is_empty(),
            "these options are configurable but absent from node.example.toml, so nothing \
             tells an operator they exist:\n  {}",
            undocumented.join("\n  ")
        );
    }

    /// A copy of the example, taken unchanged, does nothing.
    ///
    /// That is the point of shipping it entirely commented out: an operator
    /// copies it, uncomments the few settings being changed, and the
    /// uncommented lines are then exactly the changes -- no diff against the
    /// original needed to find out what was touched.
    ///
    /// An uncommented line here would be a setting applied to every node that
    /// copied the file, silently, whether or not its owner meant it.
    #[test]
    fn the_example_as_shipped_changes_nothing() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../node.example.toml");
        let file = FileConfig::load(path)
            .unwrap_or_else(|e| panic!("node.example.toml does not parse: {e}"));

        let (matches, mut applied) = parse(&["rustock"]);
        crate::apply_file_config(&matches, &file, &mut applied);

        let (_, defaults) = parse(&["rustock"]);
        assert_eq!(
            applied, defaults,
            "a setting in node.example.toml is left uncommented, so copying the file \
             changes behaviour without the copier having asked for it"
        );

        // Checked textually as well, because the comparison above cannot see
        // an uncommented line whose value happens to equal the default. It
        // would change nothing today and silently become a change the moment
        // that default moved -- and it would already spoil the property this
        // file exists for, which is that the uncommented lines in a copy are
        // the copier's own edits.
        let live: Vec<String> = documented_options()
            .into_iter()
            .filter(|o| !o.commented)
            .map(|o| format!("[{}] {}", o.section, o.key))
            .collect();
        assert!(
            live.is_empty(),
            "these settings are uncommented in node.example.toml; every one must be \
             commented out so that a copy shows only what its owner changed:\n  {}",
            live.join("\n  ")
        );
    }

    /// The light profile really is light, and says which settings make it so.
    ///
    /// Everything it changes is uncommented and marked `# light:`, so the
    /// uncommented lines are exactly the difference from the reference file.
    /// Everything it leaves alone stays commented and still states its
    /// default, checked by the same rules as the reference.
    #[test]
    fn the_light_example_states_what_it_changes_and_why() {
        let file = FileConfig::load(LIGHT)
            .unwrap_or_else(|e| panic!("node-light.example.toml does not parse: {e}"));

        // Every live setting is marked as a deliberate departure.
        let unmarked: Vec<String> = options_in(LIGHT)
            .into_iter()
            .filter(|o| !o.commented && !o.line.contains("# light:"))
            .map(|o| format!("[{}] {}", o.section, o.key))
            .collect();
        assert!(
            unmarked.is_empty(),
            "these settings are live in node-light.example.toml but not marked `# light:`, \
             so nothing says why they differ from the reference:\n  {}",
            unmarked.join("\n  ")
        );

        // And the profile is actually the one described.
        assert_eq!(file.prune.blocks, Some(true), "[prune] blocks");
        assert_eq!(file.snapshot.sync, Some(true), "[snapshot] sync");
        assert_eq!(
            file.trie.backend.as_deref(),
            Some("epoch"),
            "[trie] backend — the only setting that turns trie collection on"
        );
        assert_eq!(
            file.prune.freezer,
            Some(false),
            "[prune] freezer — left on, the node keeps 9.5 GB of frozen headers \
             that pruning never touches"
        );

        // The relationship that makes the profile coherent: a node must arrive
        // holding at least as much history as it has undertaken to keep, or
        // the retention depth is a promise about blocks it never had.
        let snap_blocks = file.snapshot.blocks.expect("[snapshot] blocks");
        let keep = file.prune.keep_depth.expect("[prune] keep_depth");
        assert!(
            snap_blocks >= keep,
            "[snapshot] blocks = {snap_blocks} is below [prune] keep_depth = {keep}: the \
             node would arrive with less history than it keeps, and the first sweep would \
             have nothing to do"
        );
        assert!(
            keep >= rustock_storage::pruner::MIN_KEEP_DEPTH,
            "[prune] keep_depth = {keep} is below the floor the node clamps to anyway"
        );
    }

    /// The light profile's commented lines state defaults too, and truthfully.
    ///
    /// It is a copy of the reference with a few lines activated, so the rest
    /// must still be a faithful statement of what the node does by default --
    /// otherwise the two files drift and one of them starts lying.
    #[test]
    fn the_light_example_states_the_real_defaults_for_what_it_leaves_alone() {
        let (_, defaults) = parse(&["rustock"]);
        let mut wrong = Vec::new();
        for opt in options_in(LIGHT).into_iter().filter(|o| o.commented) {
            if opt.line.contains("default: unset") {
                continue; // covered for the reference; same lines
            }
            if !opt.line.contains("# default") {
                wrong.push(format!("[{}] {} states no default", opt.section, opt.key));
                continue;
            }
            let text = format!("[{}]\n{} = {}\n", opt.section, opt.key, opt.value);
            let Ok(file) = toml::from_str::<FileConfig>(&text) else {
                wrong.push(format!("[{}] {} does not parse", opt.section, opt.key));
                continue;
            };
            let (matches, mut applied) = parse(&["rustock"]);
            crate::apply_file_config(&matches, &file, &mut applied);
            if applied != defaults {
                wrong.push(format!(
                    "[{}] {} = {} is marked `# default` but is not the default",
                    opt.section, opt.key, opt.value
                ));
            }
        }
        wrong.sort();
        assert!(
            wrong.is_empty(),
            "node-light.example.toml misstates what the node does by default:\n  {}",
            wrong.join("\n  ")
        );
    }

    /// Both files describe the same node, so they must offer the same options.
    ///
    /// A setting added to one and forgotten in the other is how the pair stops
    /// being two views of one thing and becomes two half-truths.
    #[test]
    fn both_examples_cover_the_same_options() {
        let keys = |path: &str| -> std::collections::BTreeSet<String> {
            options_in(path)
                .into_iter()
                .map(|o| format!("[{}] {}", o.section, o.key))
                .collect()
        };
        let reference = keys(REFERENCE);
        let light = keys(LIGHT);
        let only_reference: Vec<_> = reference.difference(&light).cloned().collect();
        let only_light: Vec<_> = light.difference(&reference).cloned().collect();
        assert!(
            only_reference.is_empty() && only_light.is_empty(),
            "the two example files have drifted.\n  only in node.example.toml: {:?}\n  \
             only in node-light.example.toml: {:?}",
            only_reference, only_light
        );
    }

    /// No flag may be in both lists; the two are a partition.
    #[test]
    fn the_two_lists_do_not_overlap() {
        for id in CONFIGURABLE {
            assert!(!ONE_SHOT.contains(id), "`{id}` is in both lists");
        }
    }
}
