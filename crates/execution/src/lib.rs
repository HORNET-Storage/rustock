pub mod breakdown;
pub mod bridge;
pub mod collision;
pub mod database;
pub mod env;
pub mod executor;
pub mod gas_estimator;
pub mod hardfork;
pub mod mining;
pub mod precompiles;
pub mod processor;
pub mod raw_storage;
pub mod remasc;
pub mod sender_cache;
pub mod rsk_handler;
pub mod rsk_instructions;
pub mod silent;
pub mod state;

/// `ContextTr` with the RSK chain extension (raw-bytes storage overlay).
/// Bridge and REMASC code is generic over this instead of plain `ContextTr`.
pub trait RskContextTr:
    revm::context_interface::ContextTr<Chain = raw_storage::RskChainExt>
{
}
impl<T: revm::context_interface::ContextTr<Chain = raw_storage::RskChainExt>> RskContextTr for T {}

pub use database::RskDatabase;
pub use bridge::btc_block_cache::{BtcBlockCache, CacheStatsSnapshot};
pub use raw_storage::{RawStorage, RskChainExt};
pub use executor::{BlockExecutionResult, ExecutionError, RskExecutor, TxExecutionResult};
pub use hardfork::{RskHardforkConfig, RskNetworkUpgrade, RSK_MAINNET_CHAIN_ID};
pub use precompiles::{
    rsk_precompiles, is_rsk_precompile,
    BRIDGE_ADDR, REMASC_ADDR,
};
pub use mining::{BlockTemplate, BlockTemplateBuilder, MinerServer, MinerWork, MiningConfig};
pub use processor::{BlockProcessor, ProcessError, ProcessTimings, ProcessedBlock};
pub use remasc::RemascConfig;
pub mod tracer;
pub mod supply;
pub use state::apply_state_changes;

/// A context for reading Bridge state at a committed state root.
///
/// Read-only by construction: it carries no database and no journal, so the
/// only thing reachable through it is the raw-storage overlay's read-through
/// to the trie. Tools and benchmarks use it to call Bridge query paths --
/// `main_chain_block_at_height` and friends -- without assembling an executor.
///
/// `cache` installs a [`BtcBlockCache`]; `None` gives the uncached behaviour,
/// which is what a benchmark needs for its baseline.
pub fn bridge_read_context(
    trie: std::sync::Arc<dyn rustock_trie::TrieStore>,
    state_root: rustock_trie::TrieNode,
    cache: Option<std::sync::Arc<BtcBlockCache>>,
) -> impl RskContextTr {
    use revm::MainContext;
    let mut chain_ext = raw_storage::RskChainExt::default();
    chain_ext.raw_storage.set_reader(trie, state_root);
    chain_ext.btc_block_cache = cache;
    revm::Context::mainnet().with_chain(chain_ext)
}
