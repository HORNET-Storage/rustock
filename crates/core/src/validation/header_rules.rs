use super::{HeaderValidator, ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use alloy_primitives::U256;
use std::time::{SystemTime, UNIX_EPOCH};

/// Converts a U256 gas limit to u64, returning an error on overflow.
fn gas_limit_as_u64(gas_limit: U256) -> Result<u64, ValidationError> {
    gas_limit.try_into().map_err(|_| ValidationError::GasLimitOverflow)
}

pub struct BlockNumberRule;
impl ParentHeaderValidator for BlockNumberRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        if header.number != parent.number + 1 {
            return Err(ValidationError::InvalidBlockNumber {
                expected: parent.number + 1,
                got: header.number,
            });
        }
        Ok(())
    }
}

pub struct ParentHashRule;
impl ParentHeaderValidator for ParentHashRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let parent_hash = parent.hash();
        if header.parent_hash != parent_hash {
            return Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: header.parent_hash,
            });
        }
        Ok(())
    }
}

/// rskj `BlockTimeStampValidationRule`: a header may not be timestamped more
/// than `max_future_offset` seconds past the node's clock, and must be
/// strictly after its parent.
///
/// The bound is `Constants.newBlockMaxSecondsInTheFuture`: 60 on mainnet, 540
/// on testnet, 0 on regtest. Zero is rskj's "off", for the whole rule: the
/// parent comparison goes with it (`validPeriodLength == 0` returns true
/// from both `isValid` overloads), which is what lets a regtest replay
/// blocks whose clock has nothing to do with the node's.
pub struct TimestampRule {
    max_future_offset: u64,
}

impl TimestampRule {
    pub fn new(max_future_offset: u64) -> Self {
        Self { max_future_offset }
    }

    fn now() -> Result<u64, ValidationError> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ValidationError::SystemTimeError)?
            .as_secs())
    }

    /// `validate` against a given clock, for tests.
    pub fn validate_at(&self, now: u64, header: &Header) -> Result<(), ValidationError> {
        if self.max_future_offset == 0 {
            return Ok(());
        }
        if header.timestamp > now + self.max_future_offset {
            return Err(ValidationError::TimestampInFuture {
                current: now,
                got: header.timestamp,
            });
        }
        Ok(())
    }

    /// `validate_with_parent` against a given clock, for tests.
    pub fn validate_with_parent_at(
        &self,
        now: u64,
        header: &Header,
        parent: &Header,
    ) -> Result<(), ValidationError> {
        if self.max_future_offset == 0 {
            return Ok(());
        }
        self.validate_at(now, header)?;
        if header.timestamp <= parent.timestamp {
            return Err(ValidationError::TimestampOlderThanParent {
                parent: parent.timestamp,
                got: header.timestamp,
            });
        }
        Ok(())
    }
}

impl HeaderValidator for TimestampRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        self.validate_at(Self::now()?, header)
    }
}

impl ParentHeaderValidator for TimestampRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        self.validate_with_parent_at(Self::now()?, header, parent)
    }
}

pub struct GasUsedRule;
impl HeaderValidator for GasUsedRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let gas_limit = gas_limit_as_u64(header.gas_limit)?;
        if header.gas_used > gas_limit {
            return Err(ValidationError::GasUsedExceedsLimit {
                used: header.gas_used,
                limit: gas_limit,
            });
        }
        Ok(())
    }
}

/// rskj `GasLimitRule` (`Constants.getMinGasLimit()`, 3,000,000 on every
/// network) and the upper bound rustock adds for its own arithmetic.
pub struct GasLimitBoundsRule {
    pub min_gas_limit: u64,
    pub max_gas_limit: u64,
}

impl HeaderValidator for GasLimitBoundsRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let gas_limit = gas_limit_as_u64(header.gas_limit)?;
        if gas_limit < self.min_gas_limit || gas_limit > self.max_gas_limit {
            return Err(ValidationError::GasLimitOutOfBounds {
                min: self.min_gas_limit,
                max: self.max_gas_limit,
                got: gas_limit,
            });
        }
        Ok(())
    }
}

pub struct BlockParentGasLimitRule {
    pub config: std::sync::Arc<crate::config::ChainConfig>,
}

impl ParentHeaderValidator for BlockParentGasLimitRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let limit = gas_limit_as_u64(header.gas_limit)?;
        let parent_limit = gas_limit_as_u64(parent.gas_limit)?;
        let divisor = self.config.gas_limit_bound_divisor;
        let delta = parent_limit / divisor;
        
        if limit < parent_limit - delta || limit > parent_limit + delta {
            return Err(ValidationError::GasLimitInvalid {
                parent: parent_limit,
                got: limit,
            });
        }
        Ok(())
    }
}
