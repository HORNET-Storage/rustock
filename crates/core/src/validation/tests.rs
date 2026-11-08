use super::*;
use crate::types::header::Header;
use alloy_primitives::{Address, B256, U256, Bytes};
use bitcoin::consensus::Encodable;
use bitcoin::block::Header as BtcHeader;
use bitcoin::transaction::{Transaction as BtcTransaction, TxOut, TxIn, OutPoint, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytes;
use bitcoin::ScriptBuf;
use sha2::{Sha256, Digest};
use std::sync::Arc;

fn create_dummy_header(number: u64, timestamp: u64, parent_hash: B256) -> Header {
    Header {
        parent_hash,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::ZERO,
        number,
        gas_limit: U256::from(10_000_000),
        gas_used: 0,
        timestamp,
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

/// Build a compressed coinbase with SHA-256 midstate.
///
/// Returns (btc_header_bytes, compressed_coinbase, rskip92_merkle_proof).
/// For a single-transaction block the Merkle proof is empty.
fn build_mm_proof(header: &Header, btc_bits: u32, rsk_tag_hash: Option<B256>) -> (Bytes, Bytes, Bytes) {
    let rsk_tag_hash = rsk_tag_hash.unwrap_or_else(|| header.hash_for_merged_mining());
    let mut rsk_tag = b"RSKBLOCK:".to_vec();
    rsk_tag.extend_from_slice(rsk_tag_hash.as_slice());

    let pb: &PushBytes = rsk_tag.as_slice().try_into().unwrap();
    let coinbase_tx = BtcTransaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(pb),
        }],
    };

    let mut coinbase_bytes = Vec::new();
    coinbase_tx.consensus_encode(&mut coinbase_bytes).unwrap();

    // Build compressed coinbase: SHA-256 midstate of processed prefix + remaining tail.
    // Use split_point = 0 so midstate is initial SHA-256 state and tail = full tx bytes.
    let byte_count: u64 = 0;
    let init_state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut compressed = Vec::with_capacity(40 + coinbase_bytes.len());
    compressed.extend_from_slice(&byte_count.to_be_bytes());
    for &w in &init_state {
        compressed.extend_from_slice(&w.to_be_bytes());
    }
    compressed.extend_from_slice(&coinbase_bytes);

    // Coinbase txid = double-SHA256 of raw tx, byte-reversed.
    let first_hash = Sha256::digest(&coinbase_bytes);
    let txid_bytes = Sha256::digest(first_hash);
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes.copy_from_slice(&txid_bytes);
    merkle_root_bytes.reverse();
    let merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle_root_bytes);

    let btc_header = BtcHeader {
        version: bitcoin::block::Version::from_consensus(1),
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root,
        time: 1000,
        bits: bitcoin::CompactTarget::from_consensus(btc_bits),
        nonce: 0,
    };

    let mut btc_header_bytes = Vec::new();
    btc_header.consensus_encode(&mut btc_header_bytes).unwrap();

    // Single-tx block: RSKIP92 proof is empty (no sibling hashes).
    let merkle_proof = Bytes::new();

    (Bytes::from(btc_header_bytes), Bytes::from(compressed), merkle_proof)
}

#[test]
fn test_block_number_rule() {
    let parent = create_dummy_header(10, 100, B256::ZERO);
    let rule = BlockNumberRule;
    
    let header = create_dummy_header(11, 101, parent.hash());
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    let header = create_dummy_header(12, 101, parent.hash());
    assert!(rule.validate_with_parent(&header, &parent).is_err());
}

#[test]
fn test_parent_hash_rule() {
    let parent = create_dummy_header(10, 100, B256::ZERO);
    let rule = ParentHashRule;
    let parent_hash = parent.hash();
    
    let header = create_dummy_header(11, 101, parent_hash);
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    let header = create_dummy_header(11, 101, B256::repeat_byte(0x99));
    assert!(rule.validate_with_parent(&header, &parent).is_err());
}

#[test]
fn test_timestamp_rule() {
    let parent = create_dummy_header(10, 1000, B256::ZERO);
    let rule = TimestampRule::new(15);
    
    let header = create_dummy_header(11, 1001, parent.hash());
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    let header = create_dummy_header(11, 999, parent.hash());
    assert!(matches!(rule.validate_with_parent(&header, &parent), Err(ValidationError::TimestampOlderThanParent { .. })));
}

#[test]
fn test_gas_used_rule() {
    let rule = GasUsedRule;
    let mut header = create_dummy_header(10, 100, B256::ZERO);
    header.gas_limit = U256::from(100);
    
    header.gas_used = 90;
    assert!(rule.validate(&header).is_ok());
    
    header.gas_used = 110;
    assert!(matches!(rule.validate(&header), Err(ValidationError::GasUsedExceedsLimit { .. })));
}

#[test]
fn test_header_verifier() {
    let mut verifier = HeaderVerifier::new();
    verifier = verifier.with_static_rule(GasUsedRule);
    verifier = verifier.with_parent_rule(BlockNumberRule);
    
    let parent = create_dummy_header(10, 100, B256::ZERO);
    let mut header = create_dummy_header(11, 101, parent.hash());
    header.gas_limit = U256::from(100);
    header.gas_used = 50;
    
    // Fully valid
    assert!(verifier.verify(&header, Some(&parent)).is_ok());
    
    // Static rule fails
    header.gas_used = 150;
    assert!(verifier.verify(&header, Some(&parent)).is_err());
    header.gas_used = 50;
    
    // Parent rule fails
    header.number = 15;
    assert!(verifier.verify(&header, Some(&parent)).is_err());
}

#[test]
fn test_difficulty_rule() {
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = DifficultyRule { config };
    
    let mut parent = create_dummy_header(10, 1000, B256::ZERO);
    parent.difficulty = U256::from(20480);
    
    // Scenario 1: Quick block (delta < duration_limit) -> increase difficulty
    let mut header = create_dummy_header(11, 1005, parent.hash());
    header.difficulty = U256::from(20480 + (20480 / 2048));
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    // Scenario 2: Slow block (delta > duration_limit) -> decrease difficulty
    let mut header = create_dummy_header(11, 1015, parent.hash());
    header.difficulty = U256::from(20480 - (20480 / 2048));
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_gas_limit_rule() {
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = BlockParentGasLimitRule { config };
    
    let mut parent = create_dummy_header(10, 1000, B256::ZERO);
    parent.gas_limit = U256::from(102400); 
    
    let mut header = create_dummy_header(11, 1010, parent.hash());
    header.gas_limit = U256::from(102400);
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    header.gas_limit = U256::from(102500);
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    header.gas_limit = U256::from(102501);
    assert!(rule.validate_with_parent(&header, &parent).is_err());
}

#[test]
fn test_merged_mining_rule_success() {
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);
    
    assert!(rule.validate(&header).is_ok());
}

#[test]
fn test_merged_mining_rule_invalid_pow() {
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::MAX; 
    
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);
    
    let res = rule.validate(&header);
    assert!(matches!(res, Err(ValidationError::BitcoinPowInvalid { .. })));
}

#[test]
fn test_merged_mining_rule_skip_pow_validation() {
    // rskj `miner.server.skipPowValidation`: a header with no valid proof of
    // work, not even a decodable bitcoin header, passes.
    let mut config = crate::config::ChainConfig::regtest();
    config.skip_pow_validation = true;
    let rule = MergedMiningRule { config: Arc::new(config) };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::MAX;
    header.bitcoin_merged_mining_header = Some(Bytes::from_static(&[0x00]));
    assert!(rule.validate(&header).is_ok());
}

#[test]
fn test_merged_mining_rule_invalid_merkle() {
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    
    let (btc_h, btc_cb, _) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    // Odd length (not multiple of 32) triggers decode error
    header.bitcoin_merged_mining_merkle_proof = Some(Bytes::from(vec![0u8; 33]));
    
    let res = rule.validate(&header);
    assert!(matches!(res, Err(ValidationError::BitcoinMerkleProofDecodeError)));
}

#[test]
fn test_merged_mining_rule_wrong_tag() {
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, Some(B256::repeat_byte(0xee)));
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);
    
    let res = rule.validate(&header);
    assert!(matches!(res, Err(ValidationError::BitcoinCoinbaseTagInvalid)));
}

// --- Difficulty rule tests (mainnet) ---

#[test]
fn test_difficulty_min_floor_clamping() {
    let config = Arc::new(crate::config::ChainConfig::mainnet());
    let rule = DifficultyRule { config };

    let min_difficulty = U256::from(7_000_000_000_000_000u64); // 7e15
    let mut parent = create_dummy_header(99, 1000, B256::ZERO);
    parent.difficulty = min_difficulty;

    // Slow block: delta = 30s (> 14s duration_limit)
    let mut header = create_dummy_header(100, 1030, parent.hash());
    header.difficulty = min_difficulty;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_ten_minute_reset() {
    let config = Arc::new(crate::config::ChainConfig::mainnet());
    let rule = DifficultyRule { config };

    let min_difficulty = U256::from(7_000_000_000_000_000u64);
    let mut parent = create_dummy_header(99, 1000, B256::ZERO);
    parent.difficulty = U256::from(100_000_000_000_000_000u64); // 1e17

    // Delta = 700s (> 600s) -> 10-min reset to min_difficulty (before orchid)
    let mut header = create_dummy_header(100, 1700, parent.hash());
    header.difficulty = min_difficulty;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_ten_minute_reset_disabled_after_orchid() {
    let config = Arc::new(crate::config::ChainConfig::mainnet());
    let rule = DifficultyRule { config };

    let mut parent = create_dummy_header(799_999, 1000, B256::ZERO);
    parent.difficulty = U256::from(100_000_000_000_000_000u64); // 1e17

    // Delta = 700s, but orchid active -> no 10-min reset. Slow block with divisor 50.
    // Expected = parent - parent/50 = 98_000_000_000_000_000
    let expected = U256::from(98_000_000_000_000_000u64);
    let mut header = create_dummy_header(800_000, 1700, parent.hash());
    header.difficulty = expected;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_rskip156_divisor_change() {
    let config = Arc::new(crate::config::ChainConfig::mainnet());
    let rule = DifficultyRule { config };

    let mut parent = create_dummy_header(2_499_999, 1000, B256::ZERO);
    parent.difficulty = U256::from(100_000_000_000_000_000u64); // 1e17

    // Fast block, papyrus200 active -> divisor 400
    // Expected = parent + parent/400 = 100_250_000_000_000_000
    let expected = U256::from(100_250_000_000_000_000u64);
    let mut header = create_dummy_header(2_500_000, 1005, parent.hash());
    header.difficulty = expected;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_equal_timestamps_increases() {
    // Java's DifficultyCalculator: when curBlockTS == parentBlockTS, delta = 0.
    // calcDur = (1 + uncleCount) * duration > 0 = delta → sign = 1 → increase.
    let config = Arc::new(crate::config::ChainConfig::regtest());
    let rule = DifficultyRule { config: config.clone() };

    let mut parent = create_dummy_header(10, 1000, B256::ZERO);
    parent.difficulty = U256::from(20480);

    // Same timestamp as parent: delta = 0, calcDur = 10 > 0 → increase
    let expected = U256::from(20480 + (20480 / 2048));
    let mut header = create_dummy_header(11, 1000, parent.hash());
    header.difficulty = expected;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_merged_mining_skipped_before_orchid() {
    let config = Arc::new(crate::config::ChainConfig::mainnet());
    let rule = MergedMiningRule { config };

    // Header at block 100 (before orchid=729,000) with NO bitcoin merged mining fields
    let mut header = create_dummy_header(100, 1000, B256::ZERO);
    header.difficulty = U256::from(7_000_000_000_000_000u64);
    // bitcoin_merged_mining_* are None by default in create_dummy_header

    assert!(rule.validate(&header).is_ok());
}

#[test]
fn test_merged_mining_required_after_orchid() {
    let config = Arc::new(crate::config::ChainConfig::mainnet());
    let rule = MergedMiningRule { config };

    // Header at block 800_000 (after orchid) with NO bitcoin merged mining fields
    let mut header = create_dummy_header(800_000, 1000, B256::ZERO);
    header.difficulty = U256::from(7_000_000_000_000_000u64);
    // bitcoin_merged_mining_* are None by default

    let res = rule.validate(&header);
    assert!(res.is_err());
}

// ── RSKIP179: the Bitcoin-to-RSK timestamp link ───────────────────────

/// A serialized Bitcoin header whose only field of interest is `time`.
fn btc_header_at(time: u32) -> Bytes {
    use bitcoin::hashes::Hash;
    let h = BtcHeader {
        version: bitcoin::block::Version::from_consensus(0x2000_0000),
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    Bytes::from(bitcoin::consensus::encode::serialize(&h))
}

fn rskip179_rule(config: crate::config::ChainConfig) -> BitcoinTimestampRule {
    BitcoinTimestampRule { config: Arc::new(config) }
}

/// Regtest's heights, iris300 at genesis, with the timestamp rule's period
/// on: where it is zero, regtest's own setting, rskj runs none of the rule,
/// RSKIP179 included.
fn regtest_with_a_period() -> crate::config::ChainConfig {
    let mut config = crate::config::ChainConfig::regtest();
    config.max_future_block_time = 540;
    config
}

/// rskj `BlockTimeStampValidationRuleTest.timestampsAreCloseEnough`: equal
/// times pass; exactly five minutes apart fails (strict); one second inside
/// the window passes, in either direction.
#[test]
fn timestamps_are_close_enough() {
    let max = BitcoinTimestampRule::DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS;
    // regtest activates iris300 at genesis.
    let rule = rskip179_rule(regtest_with_a_period());
    let check = |rsk: u64, btc: u64| {
        let mut header = create_dummy_header(10, rsk, B256::ZERO);
        header.bitcoin_merged_mining_header = Some(btc_header_at(btc as u32));
        rule.validate(&header)
    };

    assert!(check(1_000, 1_000).is_ok());
    assert!(matches!(
        check(1_000, 1_000 + max),
        Err(ValidationError::BitcoinTimestampTooFar { rsk: 1_000, btc, max: m }) if btc == 1_000 + max && m == max
    ));
    assert!(check(1_001, 1_000 + max).is_ok());
    assert!(check(1_000 + max, 1_001).is_ok());
}

/// Before RSKIP179 the rule is off: no header, any distance.
#[test]
fn bitcoin_timestamp_is_not_checked_before_rskip179() {
    let mut config = regtest_with_a_period();
    config.activation_heights.iris300 = 100;
    let rule = rskip179_rule(config);

    let mut header = create_dummy_header(99, 1_000, B256::ZERO);
    assert!(rule.validate(&header).is_ok(), "no merged-mining header, and no rule yet");
    header.bitcoin_merged_mining_header = Some(btc_header_at(1_000_000));
    assert!(rule.validate(&header).is_ok());

    header.number = 100;
    assert!(rule.validate(&header).is_err(), "from the activation on, a million seconds is too far");
}

/// rskj: from RSKIP179 on, a missing or undecodable merged-mining header
/// fails the rule by itself.
#[test]
fn a_header_without_a_decodable_bitcoin_header_fails_rskip179() {
    let rule = rskip179_rule(regtest_with_a_period());
    let mut header = create_dummy_header(10, 1_000, B256::ZERO);
    assert!(matches!(rule.validate(&header), Err(ValidationError::BitcoinHeaderDecodeError)));
    header.bitcoin_merged_mining_header = Some(Bytes::from_static(&[0x00]));
    assert!(matches!(rule.validate(&header), Err(ValidationError::BitcoinHeaderDecodeError)));
}

/// rskj `BlockTimeStampValidationRule.isValid` returns before
/// `isBitcoinTimestampValid` when `validPeriodLength` is zero, regtest's
/// setting: RSKIP179 goes with the rest of the rule.
#[test]
fn a_zero_period_turns_rskip179_off_too() {
    let rule = rskip179_rule(crate::config::ChainConfig::regtest());
    let mut header = create_dummy_header(10, 1_000, B256::ZERO);
    assert!(rule.validate(&header).is_ok(), "no merged-mining header");
    header.bitcoin_merged_mining_header = Some(btc_header_at(1_000_000));
    assert!(rule.validate(&header).is_ok(), "a million seconds away");
}

/// rskj `Constants.getMaxTimestampsDiffInSecs`: testnet widens the window to
/// two hours from RSKIP297 (hop400); mainnet keeps five minutes.
#[test]
fn testnet_widens_the_window_from_rskip297() {
    let testnet = rskip179_rule(crate::config::ChainConfig::testnet());
    let hop400 = testnet.config.activation_heights.hop400;
    assert_eq!(testnet.max_timestamps_diff(hop400 - 1), 5 * 60);
    assert_eq!(testnet.max_timestamps_diff(hop400), 120 * 60);

    let mainnet = rskip179_rule(crate::config::ChainConfig::mainnet());
    let hop400 = mainnet.config.activation_heights.hop400;
    assert_eq!(mainnet.max_timestamps_diff(hop400), 5 * 60);

    // An hour apart on testnet after hop400 passes; on mainnet it does not.
    let mut header = create_dummy_header(testnet.config.activation_heights.hop400, 10_000, B256::ZERO);
    header.bitcoin_merged_mining_header = Some(btc_header_at(10_000 + 3_600));
    assert!(testnet.validate(&header).is_ok());
    header.number = mainnet.config.activation_heights.hop400;
    assert!(mainnet.validate(&header).is_err());
}

// ── rskj BlockTimeStampValidationRuleTest, the clock and the parent ───

/// The rskj fixture: `validPeriod` 540, the clock at 10,000 s.
const VALID_PERIOD: u64 = 540;
const NOW: u64 = 10_000;

fn at(timestamp: u64) -> Header {
    create_dummy_header(10, timestamp, B256::ZERO)
}

/// rskj `blockInThePast`.
#[test]
fn block_in_the_past() {
    let rule = TimestampRule::new(VALID_PERIOD);
    assert!(rule.validate_at(NOW, &at(NOW - 1_000)).is_ok());
}

/// rskj `blockInTheFutureLimit`: exactly the period ahead is still valid.
#[test]
fn block_in_the_future_limit() {
    let rule = TimestampRule::new(VALID_PERIOD);
    assert!(rule.validate_at(NOW, &at(NOW + VALID_PERIOD)).is_ok());
}

/// rskj `blockInTheFuture`: twice the period ahead is not.
#[test]
fn block_in_the_future() {
    let rule = TimestampRule::new(VALID_PERIOD);
    assert!(matches!(
        rule.validate_at(NOW, &at(NOW + 2 * VALID_PERIOD)),
        Err(ValidationError::TimestampInFuture { current: NOW, got }) if got == NOW + 2 * VALID_PERIOD
    ));
}

/// rskj `blockTimeLowerThanParentBlockHeaderTime`, `...Equals...`,
/// `...GreaterThan...`: strictly after the parent, or invalid.
#[test]
fn block_time_against_the_parents() {
    let rule = TimestampRule::new(VALID_PERIOD);
    let header = at(NOW);
    assert!(matches!(
        rule.validate_with_parent_at(NOW, &header, &at(NOW + 1_000)),
        Err(ValidationError::TimestampOlderThanParent { .. })
    ));
    assert!(matches!(
        rule.validate_with_parent_at(NOW, &header, &at(NOW)),
        Err(ValidationError::TimestampOlderThanParent { .. })
    ));
    assert!(rule.validate_with_parent_at(NOW, &header, &at(NOW - 1_000)).is_ok());
}

/// rskj `validPeriodLength == 0`, regtest's setting: the rule is off, the
/// parent comparison with it.
#[test]
fn a_zero_period_turns_the_timestamp_rule_off() {
    let rule = TimestampRule::new(0);
    assert!(rule.validate_at(NOW, &at(NOW + 1_000_000)).is_ok());
    assert!(rule.validate_with_parent_at(NOW, &at(NOW), &at(NOW + 1_000)).is_ok());
}

/// rskj `Constants`: `newBlockMaxSecondsInTheFuture` per network, and
/// `getMinGasLimit()` on all of them.
#[test]
fn the_chain_configs_carry_rskj_constants() {
    use crate::config::ChainConfig;
    assert_eq!(ChainConfig::mainnet().max_future_block_time, 60);
    assert_eq!(ChainConfig::testnet().max_future_block_time, 540);
    assert_eq!(ChainConfig::regtest().max_future_block_time, 0);
    for config in [ChainConfig::mainnet(), ChainConfig::testnet(), ChainConfig::regtest()] {
        assert_eq!(config.min_gas_limit, 3_000_000);
    }
}

// ── rskj GasLimitRuleTests ────────────────────────────────────────────

fn gas_limit_rule() -> GasLimitBoundsRule {
    GasLimitBoundsRule { min_gas_limit: 3_000_000, max_gas_limit: u64::MAX }
}

fn with_gas_limit(gas_limit: u64) -> Header {
    let mut header = create_dummy_header(10, 1_000, B256::ZERO);
    header.gas_limit = U256::from(gas_limit);
    header
}

/// rskj `gasLimitGreaterThanMinimumGasLimit`.
#[test]
fn gas_limit_greater_than_minimum_gas_limit() {
    assert!(gas_limit_rule().validate(&with_gas_limit(3_000_000 + 1)).is_ok());
}

/// rskj `gasLimitEqualMinimumGasLimit`.
#[test]
fn gas_limit_equal_minimum_gas_limit() {
    assert!(gas_limit_rule().validate(&with_gas_limit(3_000_000)).is_ok());
}

/// rskj `gasLimitLessThanMinimumGasLimit`.
#[test]
fn gas_limit_less_than_minimum_gas_limit() {
    assert!(matches!(
        gas_limit_rule().validate(&with_gas_limit(3_000_000 - 1)),
        Err(ValidationError::GasLimitOutOfBounds { min: 3_000_000, got: 2_999_999, .. })
    ));
}

// --- rskj's exact parent gas-limit bound, and the rules each uncle must pass

/// rskj bounds a gas limit by `parent * 1023 / 1024` and
/// `parent * 1025 / 1024` in BigInteger. Where 1024 does not divide the
/// parent's limit, the lower bound is one below `parent - parent / 1024`.
#[test]
fn the_parent_gas_limit_bounds_are_rskjs_when_the_divisor_leaves_a_remainder() {
    let rule = BlockParentGasLimitRule { config: Arc::new(crate::config::ChainConfig::mainnet()) };
    let mut parent = create_dummy_header(10, 1000, B256::ZERO);
    parent.gas_limit = U256::from(6_800_000);
    let with = |limit: u64| {
        let mut header = create_dummy_header(11, 1010, parent.hash());
        header.gas_limit = U256::from(limit);
        header
    };

    // 6,800,000 * 1023 / 1024 = 6,793,359.375 and * 1025 / 1024 = 6,806,640.625.
    assert_eq!(rule.validate_with_parent(&with(6_793_359), &parent), Ok(()));
    assert!(matches!(
        rule.validate_with_parent(&with(6_793_358), &parent),
        Err(ValidationError::GasLimitInvalid { .. })
    ));
    assert_eq!(rule.validate_with_parent(&with(6_806_640), &parent), Ok(()));
    assert!(rule.validate_with_parent(&with(6_806_641), &parent).is_err());
}

/// rskj `BtcHeaderSizeRule`: from orchid the field holds a Bitcoin header and
/// nothing else. A byte appended changes neither the proof of work nor the
/// merkle proof, which is why it needs a check of its own.
#[test]
fn merged_mining_wants_exactly_a_bitcoin_header() {
    let rule = MergedMiningRule { config: Arc::new(crate::config::ChainConfig::regtest()) };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);

    let mut longer = btc_h.to_vec();
    longer.push(0);
    header.bitcoin_merged_mining_header = Some(Bytes::from(longer));
    assert_eq!(rule.validate(&header), Err(ValidationError::BitcoinHeaderDecodeError));

    header.bitcoin_merged_mining_header = Some(btc_h);
    assert_eq!(rule.validate(&header), Ok(()));
}

/// A view of the chain that holds nothing.
struct NoChain;

impl fork_detection::MainchainView for NoChain {
    fn headers_from(&self, _from: B256, _count: u64) -> Vec<Header> {
        Vec::new()
    }
}

/// rskj reads no fork-detection data below block 449 and compares none at
/// 449, so twelve bytes after the tag -- which every coinbase has, the rest
/// of the hash -- are no reason to refuse a block there. Above 449, a chain
/// too short to compute from is.
#[test]
fn fork_detection_starts_above_block_449() {
    for number in [100, 449] {
        let header = create_dummy_header(number, 1000, B256::ZERO);
        assert_eq!(fork_detection::validate(&header, Some([7; 12]), &NoChain, 0), Ok(()));
    }
    let header = create_dummy_header(450, 1000, B256::ZERO);
    assert_eq!(
        fork_detection::validate(&header, Some([7; 12]), &NoChain, 0),
        Err(ValidationError::ForkDetectionDataUnreadable)
    );
}

/// Merge-mine `header` the way a miner does: commit to it in a coinbase, and
/// roll the Bitcoin header's nonce until its hash meets the RSK difficulty.
fn seal(header: &mut Header, btc_time: u64) {
    let (btc, coinbase, proof) = build_mm_proof(header, 0x207fffff, None);
    let mut btc: BtcHeader = bitcoin::consensus::deserialize(&btc).unwrap();
    btc.time = btc_time as u32;
    let target = U256::MAX / header.difficulty;
    while U256::from_le_slice(btc.block_hash().as_byte_array()) > target {
        btc.nonce += 1;
    }
    header.bitcoin_merged_mining_header = Some(Bytes::from(bitcoin::consensus::serialize(&btc)));
    header.bitcoin_merged_mining_coinbase_transaction = Some(coinbase);
    header.bitcoin_merged_mining_merkle_proof = Some(proof);
}

/// A chain held in memory, for the uncle rule.
struct Ancestry(std::collections::HashMap<B256, Header>);

impl uncles::AncestorSource for Ancestry {
    fn header(&self, hash: B256) -> Option<Header> {
        self.0.get(&hash).cloned()
    }
    fn uncles_of(&self, _hash: B256) -> Vec<Header> {
        Vec::new()
    }
}

/// Regtest's constants with rskj's timestamp rule switched on, so that every
/// rule an uncle faces runs.
fn uncle_config() -> Arc<crate::config::ChainConfig> {
    let mut config = crate::config::ChainConfig::regtest();
    config.max_future_block_time = 60;
    Arc::new(config)
}

/// Three trunk blocks from `base` and the block above them, with the middle
/// one's parent: (ancestry, parent, block).
fn uncle_chain(base: u64) -> (Ancestry, Header, Header) {
    let mut root = create_dummy_header(base, 980, B256::ZERO);
    root.difficulty = U256::from(1);
    let mut parent = create_dummy_header(base + 1, 1000, root.hash());
    parent.difficulty = U256::from(1);
    let mut tip = create_dummy_header(base + 2, 1020, parent.hash());
    tip.difficulty = U256::from(1);
    let block = create_dummy_header(base + 3, 1030, tip.hash());
    let ancestry = [root, parent.clone(), tip]
        .into_iter()
        .map(|header| (header.hash(), header))
        .collect();
    (Ancestry(ancestry), parent, block)
}

/// The tip's sibling: a child of `parent` at `timestamp`, with the difficulty
/// its parent calls for.
fn uncle_of(parent: &Header, timestamp: u64) -> Header {
    let mut uncle = create_dummy_header(parent.number + 1, timestamp, parent.hash());
    uncle.beneficiary = Address::repeat_byte(0x0b);
    uncle.difficulty = DifficultyRule { config: uncle_config() }
        .difficulty_for_child(parent, uncle.number, timestamp, 0);
    uncle
}

fn judge(
    ancestry: &Ancestry,
    block: &Header,
    uncle: Header,
    fork_detection: Option<uncles::UncleForkDetection<'_>>,
) -> Result<(), ValidationError> {
    let header_rules = uncles::rsk_header_rules(uncle_config());
    let parent_rules = uncles::rsk_parent_rules(uncle_config());
    let block = crate::types::block::Block {
        header: block.clone(),
        transactions: Vec::new(),
        ommers: vec![uncle],
    };
    uncles::UnclesValidationRule {
        store: ancestry,
        uncle_list_limit: uncles::UNCLE_LIST_LIMIT,
        uncle_generation_limit: uncles::UNCLE_GENERATION_LIMIT,
        header_rules: &header_rules,
        parent_rules: &parent_rules,
        fork_detection,
    }
    .validate(&block)
}

/// An uncle's difficulty counts toward the chain's work, so rskj holds it to
/// what a block is held to: its own proof of work, and its difficulty and
/// timestamps against its own parent.
#[test]
fn an_uncle_must_pass_rskjs_rules() {
    let (ancestry, parent, block) = uncle_chain(0);

    let mut uncle = uncle_of(&parent, 1010);
    seal(&mut uncle, 1010);
    assert_eq!(judge(&ancestry, &block, uncle, None), Ok(()));

    // Without its proof of work it is work nobody did.
    let bare = uncle_of(&parent, 1010);
    assert_eq!(
        judge(&ancestry, &block, bare, None),
        Err(ValidationError::BitcoinHeaderDecodeError)
    );
    // Nor is work done for another header: this proof commits to the uncle
    // as it was before its beneficiary changed. Its Bitcoin header is there
    // and in time, so only proof of work can catch it.
    let mut stolen = uncle_of(&parent, 1010);
    seal(&mut stolen, 1010);
    stolen.beneficiary = Address::repeat_byte(0x0c);
    assert_eq!(
        judge(&ancestry, &block, stolen, None),
        Err(ValidationError::BitcoinCoinbaseTagInvalid)
    );

    // Its difficulty is the one its parent calls for, proof or no proof.
    let mut harder = uncle_of(&parent, 1010);
    harder.difficulty += U256::from(1);
    seal(&mut harder, 1010);
    assert!(matches!(
        judge(&ancestry, &block, harder, None),
        Err(ValidationError::DifficultyMismatch { .. })
    ));

    // Its gas limit, minimum gas price and number follow its parent's.
    let mut grasping = uncle_of(&parent, 1010);
    grasping.gas_limit = U256::from(9_990_233);
    seal(&mut grasping, 1010);
    assert!(matches!(
        judge(&ancestry, &block, grasping, None),
        Err(ValidationError::GasLimitInvalid { .. })
    ));
    let mut pricey = uncle_of(&parent, 1010);
    pricey.minimum_gas_price = U256::from(2);
    seal(&mut pricey, 1010);
    assert!(matches!(
        judge(&ancestry, &block, pricey, None),
        Err(ValidationError::MinGasPriceOutOfRange { .. })
    ));
    let mut misnumbered = uncle_of(&parent, 1010);
    misnumbered.number = parent.number;
    seal(&mut misnumbered, 1010);
    assert!(matches!(
        judge(&ancestry, &block, misnumbered, None),
        Err(ValidationError::InvalidBlockNumber { .. })
    ));

    // It comes after its parent.
    let mut early = uncle_of(&parent, parent.timestamp);
    seal(&mut early, parent.timestamp);
    assert!(matches!(
        judge(&ancestry, &block, early, None),
        Err(ValidationError::TimestampOlderThanParent { .. })
    ));

    // And it sits within five minutes of the Bitcoin header that mined it.
    let mut adrift = uncle_of(&parent, 1010);
    seal(&mut adrift, 1010 + 300);
    assert!(matches!(
        judge(&ancestry, &block, adrift, None),
        Err(ValidationError::BitcoinTimestampTooFar { .. })
    ));
}

/// What rskj does not hold an uncle to: a trunk block's 32-byte extra-data
/// cap, or `parent - parent / 1024` where its gas-limit bound is a gas lower.
#[test]
fn an_uncle_is_not_held_to_more_than_rskj_holds_it_to() {
    let (ancestry, parent, block) = uncle_chain(0);

    let mut chatty = uncle_of(&parent, 1010);
    chatty.extra_data = Bytes::from(vec![0xab; 40]);
    seal(&mut chatty, 1010);
    assert_eq!(judge(&ancestry, &block, chatty, None), Ok(()));

    // 10,000,000 * 1023 / 1024 = 9,990,234.375.
    let mut lean = uncle_of(&parent, 1010);
    lean.gas_limit = U256::from(9_990_234);
    seal(&mut lean, 1010);
    assert_eq!(judge(&ancestry, &block, lean, None), Ok(()));
}

/// Asked to, the rule runs fork detection on each uncle, and an uncle above
/// block 449 whose chain cannot be read is refused; not asked, it is not.
#[test]
fn the_uncle_rule_runs_fork_detection_when_asked() {
    let (ancestry, parent, block) = uncle_chain(1_000);
    let mut uncle = uncle_of(&parent, 1010);
    seal(&mut uncle, 1010);

    let asked = uncles::UncleForkDetection { view: &NoChain, rskip110_height: 0 };
    assert_eq!(
        judge(&ancestry, &block, uncle.clone(), Some(asked)),
        Err(ValidationError::ForkDetectionDataUnreadable)
    );
    assert_eq!(judge(&ancestry, &block, uncle, None), Ok(()));
}
