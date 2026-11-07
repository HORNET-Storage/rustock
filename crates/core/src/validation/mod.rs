use crate::types::header::Header;
use thiserror::Error;
use alloy_primitives::{B256, U256};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Block number is invalid: expected {expected}, got {got}")]
    InvalidBlockNumber { expected: u64, got: u64 },
    
    #[error("Parent hash mismatch: expected {expected}, got {got}")]
    ParentHashMismatch { expected: B256, got: B256 },
    
    #[error("Timestamp is in the future: current {current}, got {got}")]
    TimestampInFuture { current: u64, got: u64 },
    
    #[error("Timestamp is older than parent: parent {parent}, got {got}")]
    TimestampOlderThanParent { parent: u64, got: u64 },

    #[error("Failed to read system time")]
    SystemTimeError,

    #[error("Gas used {used} exceeds gas limit {limit}")]
    GasUsedExceedsLimit { used: u64, limit: u64 },

    #[error("Gas limit overflows u64")]
    GasLimitOverflow,

    #[error("Gas limit {got} out of bounds: [{min}, {max}]")]
    GasLimitOutOfBounds { min: u64, max: u64, got: u64 },

    #[error("Gas limit {got} is invalid compared to parent {parent}")]
    GasLimitInvalid { parent: u64, got: u64 },

    #[error("Difficulty mismatch: expected {expected}, got {got}")]
    DifficultyMismatch { expected: U256, got: U256 },

    #[error("Difficulty is zero")]
    DifficultyZero,

    #[error("Failed to decode Bitcoin block header")]
    BitcoinHeaderDecodeError,

    #[error("RSKIP179: RSK timestamp {rsk} and Bitcoin block time {btc} differ by {max} s or more")]
    BitcoinTimestampTooFar { rsk: u64, btc: u64, max: u64 },

    #[error("Failed to decode Bitcoin coinbase transaction")]
    BitcoinCoinbaseDecodeError,

    #[error("Failed to decode Bitcoin merkle proof")]
    BitcoinMerkleProofDecodeError,

    #[error("Bitcoin Proof of Work invalid: hash {hash} exceeds target {target}")]
    BitcoinPowInvalid { hash: B256, target: U256 },

    #[error("Bitcoin Merkle proof invalid")]
    BitcoinMerkleProofInvalid,

    #[error("Bitcoin coinbase tag missing or invalid")]
    BitcoinCoinbaseTagInvalid,

    #[error("Merged-mining merkle proof is {got} bytes, over the {max}-byte limit")]
    MerkleProofTooLarge { max: usize, got: usize },

    #[error("Tx gas price {tx_gas_price} is below the block minimum {block_minimum}")]
    TxGasPriceBelowMinimum { tx_gas_price: U256, block_minimum: U256 },

    #[error("Tx gas price {tx_gas_price} is above the cap {cap}")]
    TxGasPriceAboveCap { tx_gas_price: U256, cap: U256 },

    #[error("Block's last transaction is not the REMASC transaction")]
    RemascTxMissing,

    #[error("Extra data is {got} bytes, over the {max}-byte maximum")]
    ExtraDataTooLarge { max: usize, got: usize },

    #[error("Minimum gas price {got} outside the allowed range [{lower}, {upper}]")]
    MinGasPriceOutOfRange { lower: U256, upper: U256, got: U256 },

    #[error("Uncle list has {got} entries, over the limit of {max}")]
    TooManyUncles { max: usize, got: usize },

    #[error("Uncle {hash} is a direct ancestor of the block")]
    UncleIsAncestor { hash: B256 },

    #[error("Uncle {hash} was already included by an ancestor")]
    UncleAlreadyUsed { hash: B256 },

    #[error("Uncle {hash} appears twice in the same block")]
    UncleRepeated { hash: B256 },

    #[error("Uncle {hash} is a sibling or descendant of the block")]
    UncleIsSiblingOrDescendant { hash: B256 },

    #[error("Uncle {hash} is older than the {limit}-generation limit")]
    UncleTooOld { hash: B256, limit: u64 },

    #[error("Uncle {hash} has no parent among the block's ancestors")]
    UncleHasNoCommonParent { hash: B256 },

    #[error("Fork detection data mismatch: expected {expected:?}, got {got:?}")]
    ForkDetectionDataMismatch { expected: [u8; 12], got: [u8; 12] },

    #[error("Fork detection data could not be read from the coinbase")]
    ForkDetectionDataUnreadable,

    #[error("Invalid transaction execution sublist edges: {reason}")]
    InvalidSublistEdges { reason: String },
}

pub trait HeaderValidator: Send + Sync {
    fn validate(&self, header: &Header) -> Result<(), ValidationError>;
}

pub trait ParentHeaderValidator: Send + Sync {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError>;
}

/// A rule that needs the block body — transactions or uncles — and not just
/// the header. rskj's `BlockValidationRule`.
pub trait BlockValidator: Send + Sync {
    fn validate_block(&self, block: &crate::types::block::Block) -> Result<(), ValidationError>;
}

/// Runs the body-dependent rules. Kept separate from `HeaderVerifier` because
/// the sync pipeline sees headers before bodies: header rules gate the
/// download, these gate acceptance.
pub struct BlockVerifier {
    rules: Vec<Box<dyn BlockValidator>>,
}

impl Default for BlockVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockVerifier {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// The body rules rskj runs on every block, in `RskContext` order.
    /// Uncle and fork-detection validation need the block store and are wired
    /// separately by the caller that has it.
    pub fn default_rsk(config: &crate::config::ChainConfig) -> Self {
        Self::new()
            .with_rule(block_rules::TxsMinGasPriceRule)
            .with_rule(block_rules::BlockTxsMaxGasPriceRule {
                rskip252_height: config.activation_heights.fingerroot500,
            })
            .with_rule(block_rules::RemascValidationRule)
    }

    pub fn with_rule(mut self, rule: impl BlockValidator + 'static) -> Self {
        self.rules.push(Box::new(rule));
        self
    }

    pub fn verify(&self, block: &crate::types::block::Block) -> Result<(), ValidationError> {
        for rule in &self.rules {
            rule.validate_block(block)?;
        }
        Ok(())
    }
}

/// Orchestrator to run multiple validation rules.
pub struct HeaderVerifier {
    static_rules: Vec<Box<dyn HeaderValidator>>,
    parent_rules: Vec<Box<dyn ParentHeaderValidator>>,
}

impl Default for HeaderVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderVerifier {
    pub fn new() -> Self {
        Self {
            static_rules: Vec::new(),
            parent_rules: Vec::new(),
        }
    }

    /// Creates a standard RSK verifier with all consensus rules.
    ///
    /// Note: `ParentHashRule` is intentionally **not** included here because
    /// the sync pipeline looks up the parent by `header.parent_hash`, so
    /// finding it in the store already proves hash consistency.  Including the
    /// rule would break for the genesis block, whose canonical hash is derived
    /// from Java's non-canonical RLP encoding (leading zeros in difficulty)
    /// and cannot be reproduced by our standard `Header::hash()`.
    pub fn default_rsk(config: std::sync::Arc<crate::config::ChainConfig>) -> Self {
        Self::new()
            .with_static_rule(GasUsedRule)
            .with_static_rule(GasLimitBoundsRule { 
                min_gas_limit: config.min_gas_limit, 
                max_gas_limit: config.max_gas_limit 
            })
            .with_static_rule(MergedMiningRule { config: config.clone() })
            .with_static_rule(BitcoinTimestampRule { config: config.clone() })
            .with_static_rule(block_rules::ExtraDataRule::default())
            .with_parent_rule(BlockNumberRule)
            // rskj `newBlockMaxSecondsInTheFuture`; zero turns the rule off.
            .with_parent_rule(TimestampRule::new(config.max_future_block_time))
            .with_parent_rule(BlockParentGasLimitRule { config: config.clone() })
            .with_parent_rule(block_rules::PrevMinGasPriceRule)
            .with_parent_rule(DifficultyRule { config })
    }

    /// The rules that judge a header on its own, proof of work among them.
    ///
    /// Exposed so an uncle can be put through exactly the same rules as a
    /// trunk header. An uncle that is not checked as hard as a trunk block is
    /// a way to credit work nobody did.
    pub fn static_rules(&self) -> &[Box<dyn HeaderValidator>] {
        &self.static_rules
    }

    /// The rules that judge a header against its parent.
    pub fn parent_rules(&self) -> &[Box<dyn ParentHeaderValidator>] {
        &self.parent_rules
    }

    pub fn with_static_rule(mut self, rule: impl HeaderValidator + 'static) -> Self {
        self.static_rules.push(Box::new(rule));
        self
    }

    pub fn with_parent_rule(mut self, rule: impl ParentHeaderValidator + 'static) -> Self {
        self.parent_rules.push(Box::new(rule));
        self
    }

    /// Runs only the rules that relate a header to its parent.
    ///
    /// For walking a chain, where each header's own rules are checked once as
    /// it arrives and its relationship to its neighbour once as the walk
    /// passes: `verify` would re-run the static rules on every header a second
    /// time, and proof-of-work is the expensive half of them.
    pub fn verify_against_parent(
        &self,
        header: &Header,
        parent: &Header,
    ) -> Result<(), ValidationError> {
        for rule in &self.parent_rules {
            rule.validate_with_parent(header, parent)?;
        }
        Ok(())
    }

    pub fn verify(&self, header: &Header, parent: Option<&Header>) -> Result<(), ValidationError> {
        for rule in &self.static_rules {
            rule.validate(header)?;
        }

        if let Some(parent_header) = parent {
            for rule in &self.parent_rules {
                rule.validate_with_parent(header, parent_header)?;
            }
        }

        Ok(())
    }
}

pub mod block_rules;
pub mod fork_detection;
pub mod uncles;
pub mod header_rules;
pub mod difficulty;
pub mod merged_mining;

pub use header_rules::{BlockNumberRule, ParentHashRule, TimestampRule, GasUsedRule, GasLimitBoundsRule, BlockParentGasLimitRule};
pub use difficulty::DifficultyRule;
pub use merged_mining::{BitcoinTimestampRule, MergedMiningRule};
pub use block_rules::{
    BlockTxsMaxGasPriceRule, ExtraDataRule, PrevMinGasPriceRule, RemascValidationRule,
    TxsMinGasPriceRule,
};

#[cfg(test)]
mod tests;
