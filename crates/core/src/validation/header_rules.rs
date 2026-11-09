use super::{HeaderValidator, ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use num_bigint::BigUint;
use std::time::{SystemTime, UNIX_EPOCH};

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
///
/// rskj runs the parent form on uncles, and in its relay and snapshot
/// validators. `BlockValidatorImpl`, which decides whether a block joins the
/// chain, runs the rule on the header alone, as its header sync does: a
/// block no later than its parent is one rskj imports. So
/// [`HeaderVerifier::default_rsk`](super::HeaderVerifier::default_rsk) holds
/// a trunk header to the clock alone, and an uncle to its parent too.
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

/// rskj `ValidGasUsedRule`: a header's gas used may not pass its gas limit,
/// which it reads as `new BigInteger(1, bytes).longValue()`, the low 64
/// bits as a `long`. Where they are 2^63 or more that `long` is negative,
/// and no gas used fits under it, not even none.
pub struct GasUsedRule;
impl HeaderValidator for GasUsedRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let limit = header.gas_limit_low_long();
        // rskj reads the gas used exactly, so it is a `long` and never
        // negative.
        if i64::try_from(header.gas_used)
            .ok()
            .is_none_or(|used| used > limit)
        {
            return Err(ValidationError::GasUsedExceedsLimit {
                used: header.gas_used,
                limit,
            });
        }
        Ok(())
    }
}

/// rskj `GasLimitRule`: a block's gas limit, read whole, may not be below
/// `Constants.getMinGasLimit()`, 3,000,000 on every network. Nothing bounds
/// it from above but its parent's (`BlockParentGasLimitRule`).
pub struct GasLimitRule {
    pub min_gas_limit: u64,
}

impl HeaderValidator for GasLimitRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let got = header.gas_limit_value();
        if got < BigUint::from(self.min_gas_limit) {
            return Err(ValidationError::GasLimitBelowMinimum {
                min: self.min_gas_limit,
                got,
            });
        }
        Ok(())
    }
}

/// The fields rskj's `BlockFactory.decodeHeader` reads a header with, which
/// depend on its height: `canBeDecoded` counts them exactly, so a header with
/// one too many or one too few is one rskj cannot read, and so cannot take.
/// The decoder here reads by shape rather than by height, so this holds what
/// it read to what rskj would have.
///
/// - A UMM root from RSKIPUMM on, and none before it: papyrus200 on mainnet
///   and testnet, as `reference.conf` has it, and 1 on rskj's regtest.
/// - No RSKIP351 fields where RSKIP351 is inactive, as it is on mainnet: no
///   version, edges or base event after the UMM root, and no commitment to
///   an extension in the logs bloom's place. The decoder reads whatever is
///   there as the bloom, of any length, as rskj does, so only a header built
///   here could hold one.
///
/// An uncle is read the same way, at its own height.
pub struct HeaderLayoutRule {
    pub config: std::sync::Arc<crate::config::ChainConfig>,
}

impl HeaderValidator for HeaderLayoutRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let heights = &self.config.activation_heights;
        let umm = heights.umm_active(header.number);
        if header.umm_root.is_some() != umm {
            return Err(ValidationError::UmmRootMisplaced {
                number: header.number,
                present: header.umm_root.is_some(),
            });
        }
        let rskip351 = heights.rskip351_active(header.number);
        if !rskip351 && (header.version_fields.is_some() || header.extension_data.is_some()) {
            return Err(ValidationError::VersionedBeforeRskip351 {
                number: header.number,
            });
        }
        Ok(())
    }
}

/// rskj `BlockParentGasLimitRule`: a header's gas limit may move from its
/// parent's by at most a `gas_limit_bound_divisor`th, either way.
pub struct BlockParentGasLimitRule {
    pub config: std::sync::Arc<crate::config::ChainConfig>,
}

impl ParentHeaderValidator for BlockParentGasLimitRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        // rskj reads both whole, of any size, and compares in BigInteger
        // against `parent * (d - 1) / d` and `parent * (d + 1) / d`.
        let got = header.gas_limit_value();
        let parent_limit = parent.gas_limit_value();
        let divisor = self.config.gas_limit_bound_divisor;
        let lower = &parent_limit * (divisor - 1) / divisor;
        let upper = &parent_limit * (divisor + 1) / divisor;
        if got < lower || got > upper {
            return Err(ValidationError::GasLimitInvalid {
                parent: parent_limit,
                got,
            });
        }
        Ok(())
    }
}
