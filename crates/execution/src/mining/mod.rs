//! Merged mining: building RSK blocks and completing them from Bitcoin
//! solutions.
//!
//! An RSK block is mined by committing to it inside a Bitcoin block's
//! coinbase, so one SHA-256 search secures both chains. The node builds a
//! candidate block, hands out its merged-mining hash, and a miner embeds that
//! hash in a coinbase tagged `RSKBLOCK:` and searches for a Bitcoin block
//! whose hash meets *RSK's* difficulty -- not Bitcoin's, which is why a
//! solution is usually not a valid Bitcoin block at all. The solution comes
//! back and fills in the three `bitcoin_merged_mining_*` header fields.
//!
//! This is the inverse of [`rustock_core::validation::merged_mining`], and the
//! formats are read off it rather than reconstructed: the compressed coinbase,
//! where the tag may sit, and how the merkle proof folds are all stated there
//! from the verifying side. Where something exists only on the producing side
//! -- fork-detection data, transaction selection, the work cache -- it is
//! ported from rskj and the source class is named at the definition.

pub mod dev;
pub mod coinbase;
pub mod extra_data;
pub mod partition;
pub mod workload;
pub mod fork_detection;
pub mod merkle;
pub mod server;
pub mod uncles;
pub mod template;
pub mod timed;

pub use server::{
    ChainAccess, CommitOutcome, ImportResult, MinerServer, MinerWork, RebuildPolicy,
    StoreChainAccess, SubmissionRateLimiter, SubmitError, SubmittedBlockInfo, SyncGate,
    cumulative_difficulty, extract_merged_mining_hash,
};
pub use uncles::{UNCLE_GENERATION_LIMIT, UNCLE_LIST_LIMIT, select_uncles};
pub use timed::{Pow, TimedMiner, TimedSchedule};
pub use template::{
    BlockTemplate, BlockTemplateBuilder, MiningConfig, NoPendingTransactions, PendingTransaction,
    PendingTransactionSource, TemplateError, difficulty_to_target, next_minimum_gas_price,
    remasc_transaction,
};

#[cfg(test)]
mod tests;
