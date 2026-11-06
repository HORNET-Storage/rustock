use super::{ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use alloy_primitives::U256;

/// RSKIP156 increases the difficulty divisor from 50 to 400.
const RSKIP156_DIFFICULTY_DIVISOR: U256 = U256::from_limbs([400, 0, 0, 0]);

/// Pre-RSKIP97: if block is mined > 600s after parent, reset to minimum difficulty.
const TEN_MINUTES: u64 = 600;

pub struct DifficultyRule {
    pub config: std::sync::Arc<crate::config::ChainConfig>,
}

impl ParentHeaderValidator for DifficultyRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let expected = self.calculate_expected_difficulty(header, parent);
        if header.difficulty != expected {
            return Err(ValidationError::DifficultyMismatch {
                expected,
                got: header.difficulty,
            });
        }
        Ok(())
    }
}

impl DifficultyRule {
    /// The difficulty a child of `parent` must carry, given the fields a miner
    /// chooses: its height, timestamp and uncle count.
    ///
    /// Validation answers the same question from a header that already exists;
    /// a miner needs it before one does, so the calculation is shared rather
    /// than duplicated -- the two must not be allowed to drift.
    pub fn difficulty_for_child(
        &self,
        parent: &Header,
        number: u64,
        timestamp: u64,
        uncle_count: u64,
    ) -> U256 {
        let mut probe = parent.clone();
        probe.number = number;
        probe.timestamp = timestamp;
        probe.uncle_count = uncle_count;
        self.calculate_expected_difficulty(&probe, parent)
    }

    fn calculate_expected_difficulty(&self, header: &Header, parent: &Header) -> U256 {
        let activations = &self.config.activation_heights;

        // Before RSKIP97: a block more than ten minutes after its parent
        // resets to the minimum difficulty, so private fallback mining can
        // recover a stalled chain.
        //
        // Gated on its own height, not on orchid. reference.conf defaults
        // `rskip97 = orchid` -- which is mainnet -- but testnet.conf and
        // regtest.conf both override it to -1, so on those chains the drop
        // never goes away. Reading it as orchid made rustock compute
        // 1,027,605 for testnet block #1 against the real 131,072, reject the
        // header, and then fail on #2 for not extending the executed head.
        let rskip97_active = match activations.rskip97 {
            Some(height) => header.number >= height,
            None => false,
        };
        if !rskip97_active {
            let delta_ts = header.timestamp.saturating_sub(parent.timestamp);
            if delta_ts >= TEN_MINUTES {
                return self.config.min_difficulty;
            }
        }

        let delta = header.timestamp.saturating_sub(parent.timestamp);

        // Java's DifficultyCalculator: `if (delta < 0) return pd;`
        // With u64 saturating_sub, negative delta becomes 0 — detect via
        // the original timestamps.  Equal timestamps (delta == 0) must NOT
        // short-circuit: Java continues and sign becomes 1 (calcDur > 0).
        if header.timestamp < parent.timestamp {
            return parent.difficulty;
        }

        // rskj: `int calcDur = (1 + uncleCount) * duration`, in Java `int`
        // arithmetic, which wraps. Nothing ties a header's uncle count to the
        // uncles it carries, so the count is the miner's to choose, and one
        // that wraps the product to zero or below makes any block late: a
        // lower difficulty, which rskj takes, and so must this. Both
        // timestamps are Java `long`s, so the gap fits an `i64`.
        let calc_dur = i64::from(
            1i32.wrapping_add(header.uncle_count as i32)
                .wrapping_mul(self.config.duration_limit as i32),
        );
        let delta = delta as i64;

        let sign = if calc_dur > delta {
            1i8
        } else if calc_dur < delta {
            -1i8
        } else {
            0i8
        };

        if sign == 0 {
            return parent.difficulty;
        }

        // RSKIP156 (papyrus200): difficulty divisor changes from 50 to 400.
        let divisor = if header.number >= activations.papyrus200 {
            RSKIP156_DIFFICULTY_DIVISOR
        } else {
            self.config.difficulty_divisor
        };

        let quotient = parent.difficulty / divisor;

        let from_parent = if sign == 1 {
            parent.difficulty + quotient
        } else if parent.difficulty > quotient {
            parent.difficulty - quotient
        } else {
            U256::ZERO
        };

        // Clamp to minimum difficulty — matches rskj's max(minDifficulty, fromParent).
        if from_parent < self.config.min_difficulty {
            self.config.min_difficulty
        } else {
            from_parent
        }
    }
}

#[cfg(test)]
mod rskip97_tests {
    use super::*;
    use crate::config::ChainConfig;
    use alloy_primitives::{Bytes, B256};
    use std::sync::Arc;

    fn header_at(number: u64, timestamp: u64, difficulty: U256) -> Header {
        let mut h = Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Default::default(),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty,
            number,
            gas_limit: U256::from(1_000_000),
            gas_used: 0,
            timestamp,
            extra_data: Bytes::new(),
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
        };
        h.cached_hash = None;
        h
    }

    /// Testnet block #1, from the live chain: genesis sits at timestamp 0 with
    /// difficulty 1,048,576, and #1 arrives 1,562,334,434 seconds later with
    /// difficulty 131,072 -- the floor, because RSKIP97 never activates on
    /// testnet and the ten-minute drop still applies.
    ///
    /// Before this was modelled, rustock computed 1,027,605 (the ordinary
    /// `parent - parent/50` step), rejected the header, and then failed on
    /// block #2 for not extending the executed head. The testnet sync could
    /// not get past block 1.
    #[test]
    fn testnet_block_1_falls_to_the_minimum_difficulty() {
        let rule = DifficultyRule { config: Arc::new(ChainConfig::testnet()) };
        let genesis = header_at(0, 0, U256::from(1_048_576u64));
        let got = rule.difficulty_for_child(&genesis, 1, 1_562_334_434, 0);
        assert_eq!(got, U256::from(131_072u64), "must fall to the floor, as testnet block #1 does");
    }

    /// The same gap on mainnet after orchid does *not* drop: RSKIP97 is active
    /// there from #729,000, so the rule is gone.
    #[test]
    fn mainnet_after_orchid_does_not_drop() {
        let rule = DifficultyRule { config: Arc::new(ChainConfig::mainnet()) };
        let parent = header_at(800_000, 1_000_000, U256::from(1_048_576u64));
        let got = rule.difficulty_for_child(&parent, 800_001, 1_000_000 + 3600, 0);
        assert_ne!(got, U256::from(131_072u64), "RSKIP97 is active on mainnet here");
    }

    /// And before orchid, mainnet drops like testnet always does -- the two
    /// chains differ in *when* the rule stops, not in what it does.
    ///
    /// Mainnet's floor is 7e15 (FALLBACK_MINING_DIFFICULTY / 2), not
    /// testnet's 131,072, so the drop lands somewhere else entirely. The
    /// minimum is per-chain; only the rule is shared.
    #[test]
    fn mainnet_before_orchid_still_drops() {
        let config = Arc::new(ChainConfig::mainnet());
        let floor = config.min_difficulty;
        let rule = DifficultyRule { config };
        let parent = header_at(1000, 1_000_000, U256::from(1_048_576u64));
        let got = rule.difficulty_for_child(&parent, 1001, 1_000_000 + 601, 0);
        assert_eq!(got, floor, "the ten-minute drop applies before orchid on mainnet too");
        assert_ne!(floor, U256::from(131_072u64), "and mainnet's floor is not testnet's");
    }

    /// Under ten minutes, no drop on either chain.
    #[test]
    fn a_short_gap_does_not_drop_on_testnet() {
        let rule = DifficultyRule { config: Arc::new(ChainConfig::testnet()) };
        let parent = header_at(100, 1_000_000, U256::from(1_048_576u64));
        let got = rule.difficulty_for_child(&parent, 101, 1_000_000 + 599, 0);
        assert_ne!(got, U256::from(131_072u64), "599s is under the ten-minute threshold");
    }

    /// rskj works out the expected time in Java `int` arithmetic, and nothing
    /// ties a header's uncle count to its uncles. A count that wraps the
    /// product to zero, or below it, makes a block late however soon it came,
    /// and its difficulty falls.
    #[test]
    fn the_expected_time_wraps_as_a_java_int() {
        let rule = DifficultyRule { config: Arc::new(ChainConfig::mainnet()) };
        let parent = header_at(5_000_000, 1_000_000, U256::from(10u128.pow(21)));
        let step = parent.difficulty / U256::from(400);
        let child = |uncles: u64| {
            rule.difficulty_for_child(&parent, 5_000_001, 1_000_000 + 10, uncles)
        };

        // (1 + 1) * 14: 28 seconds expected, and 10 is sooner.
        assert_eq!(child(1), parent.difficulty + step);
        // (1 + 2^31 - 1) * 14 wraps to 0, and 10 is later.
        assert_eq!(child(i32::MAX as u64), parent.difficulty - step);
        // (1 + 2^30) * 14 wraps below zero.
        assert_eq!(child(1 << 30), parent.difficulty - step);
    }
}
