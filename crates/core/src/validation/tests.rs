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

    // A one-transaction block's merkle root is its coinbase's txid, in the
    // internal byte order a Bitcoin header holds: double SHA-256 as it
    // comes, not reversed for display.
    let first_hash = Sha256::digest(&coinbase_bytes);
    let txid_bytes = Sha256::digest(first_hash);
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes.copy_from_slice(&txid_bytes);
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
    
    header.gas_used = 100;
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

/// A view of the chain that holds these headers, newest first.
struct Held(Vec<Header>);

impl fork_detection::MainchainView for Held {
    fn headers_from(&self, _from: B256, count: u64) -> Vec<Header> {
        self.0.iter().take(count as usize).cloned().collect()
    }
}

/// rskj sums the uncle counts of the 32 headers below a block in Java `int`
/// arithmetic (`IntStream.sum`) and caps the sum at 255. A sum that wraps
/// below zero makes `new Uint8` throw, which `tryToConnect` turns into
/// `INVALID_BLOCK`, so the block is refused whatever data it carries; one
/// that wraps on past zero counts what it came to.
#[test]
fn the_uncle_counts_sum_as_a_java_int() {
    let chain = |counts: &[u64]| -> Vec<Header> {
        (0..fork_detection::REQUIRED_BLOCKS)
            .map(|i| {
                let mut header = create_dummy_header(10_000 - i, 1000, B256::ZERO);
                header.uncle_count = counts.get(i as usize).copied().unwrap_or(0);
                header.bitcoin_merged_mining_header = Some(Bytes::from(vec![0u8; 80]));
                header
            })
            .collect()
    };
    let sum = |counts: &[u64]| fork_detection::uncle_sum(&chain(counts));
    let max = i32::MAX as u64;
    let below_zero = || ValidationError::UncleCountsSumBelowZero { sum: i32::MIN };

    assert_eq!(sum(&[1, 2, 3]), Ok(6));
    assert_eq!(sum(&[200, 56]), Ok(255));
    let mut beyond = vec![0; 33];
    beyond[32] = 5;
    assert_eq!(sum(&beyond), Ok(0), "only the 32 newest count");
    assert_eq!(sum(&[max, 1]), Err(below_zero()));
    // 2 * (2^31 - 1) + 9 = 2^32 + 7.
    assert_eq!(sum(&[max, max, 9]), Ok(7));

    let block = create_dummy_header(10_001, 1000, B256::ZERO);
    let wrapped = Held(chain(&[max, max, 9]));
    let data = fork_detection::calculate(&wrapped.0).unwrap();
    assert_eq!(data[7], 7);
    assert_eq!(
        fork_detection::validate(&block, Some(data), &wrapped, 0),
        Ok(())
    );
    // Below zero, no data passes: not the 255 a saturating sum gives, nor the
    // 0 a clamp gives, nor any other count with the right vector and height.
    let refused = Held(chain(&[max, 1]));
    for count in 0..=u8::MAX {
        let mut carried = data;
        carried[7] = count;
        assert_eq!(
            fork_detection::validate(&block, Some(carried), &refused, 0),
            Err(below_zero()),
            "carrying {count}"
        );
    }
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

/// The verifier every sync path holds judges uncles by rskj's uncle rules,
/// not by a trunk header's: no extra-data cap and no gas-limit bounds. The
/// timestamp rule, RSKIP179 included, holds for both.
#[test]
fn default_rsk_holds_uncles_to_rskjs_uncle_rules() {
    let verifier = HeaderVerifier::default_rsk(uncle_config());
    let (_, parent, _) = uncle_chain(0);

    let mut chatty = uncle_of(&parent, 1010);
    chatty.extra_data = Bytes::from(vec![0xab; 40]);
    seal(&mut chatty, 1010);
    assert_eq!(verifier.verify_uncle(&chatty), Ok(()));
    assert!(matches!(
        verifier.verify(&chatty, None),
        Err(ValidationError::ExtraDataTooLarge { .. })
    ));

    let mut thin = uncle_of(&parent, 1010);
    thin.gas_limit = U256::from(2_999_999);
    seal(&mut thin, 1010);
    assert_eq!(verifier.verify_uncle(&thin), Ok(()));
    assert_eq!(
        verifier.verify(&thin, None),
        Err(ValidationError::GasLimitOutOfBounds { min: 3_000_000, max: 10_000_000, got: 2_999_999 })
    );

    let mut adrift = uncle_of(&parent, 1010);
    seal(&mut adrift, 1010 + 300);
    for verdict in [verifier.verify_uncle(&adrift), verifier.verify(&adrift, None)] {
        assert!(matches!(verdict, Err(ValidationError::BitcoinTimestampTooFar { .. })));
    }

    assert_eq!(verifier.uncle_parent_rules().len(), 5, "rskj's five, in its order");
}

/// rskj reads a header's fields by its height (`BlockFactory.canBeDecoded`):
/// a UMM root from RSKIPUMM, papyrus200, on and only then, and no RSKIP351
/// fields where RSKIP351 is inactive, which is all of mainnet. The decoder
/// reads by shape, so the verifier holds what it read to that, for a block
/// and for an uncle alike, before anything else.
#[test]
fn a_header_carries_the_fields_rskj_reads_at_its_height() {
    use crate::config::ChainConfig;
    use crate::types::header::HeaderVersionFields;

    let mainnet = Arc::new(ChainConfig::mainnet());
    let papyrus = mainnet.activation_heights.papyrus200;
    let rule = HeaderLayoutRule { config: mainnet.clone() };
    let at = |number: u64, umm: bool| {
        let mut header = create_dummy_header(number, 1000, B256::ZERO);
        header.umm_root = umm.then(Bytes::new);
        header
    };
    let misplaced = |number, present| Err(ValidationError::UmmRootMisplaced { number, present });

    assert_eq!(rule.validate(&at(papyrus - 1, false)), Ok(()));
    assert_eq!(rule.validate(&at(papyrus - 1, true)), misplaced(papyrus - 1, true));
    assert_eq!(rule.validate(&at(papyrus, true)), Ok(()));
    assert_eq!(rule.validate(&at(papyrus, false)), misplaced(papyrus, false));

    let versioned = |mut header: Header| {
        header.version_fields =
            Some(HeaderVersionFields { version: 1, edges: Some(Vec::new()), base_event: None });
        header
    };
    let compressed = |mut header: Header| {
        header.extension_data = Some(Bytes::from(vec![0xc0]));
        header
    };
    let tip = 9_400_000;
    for header in [versioned(at(tip, true)), compressed(at(tip, true))] {
        assert_eq!(
            rule.validate(&header),
            Err(ValidationError::VersionedBeforeRskip351 { number: tip })
        );
    }
    // Testnet has RSKIP351 from reed810, #7,139,600.
    let testnet = HeaderLayoutRule { config: Arc::new(ChainConfig::testnet()) };
    let reed810 = 7_139_600;
    assert_eq!(
        testnet.validate(&versioned(at(reed810 - 1, true))),
        Err(ValidationError::VersionedBeforeRskip351 { number: reed810 - 1 })
    );
    assert_eq!(testnet.validate(&versioned(at(reed810, true))), Ok(()));

    let verifier = HeaderVerifier::default_rsk(mainnet);
    assert_eq!(verifier.verify(&at(papyrus, false), None), misplaced(papyrus, false));
    assert_eq!(verifier.verify_uncle(&at(papyrus, false)), misplaced(papyrus, false));
}

/// rskj's trunk takes the timestamp rule on the header alone. A block no
/// later than its parent is one `BlockValidatorImpl` imports -- the parent
/// form is for uncles, and for rskj's relay -- so this node must take it
/// too, or part from the chain the network follows.
#[test]
fn a_block_no_later_than_its_parent_joins_the_trunk_but_is_no_uncle() {
    let verifier = HeaderVerifier::default_rsk(uncle_config());
    let (_, parent, _) = uncle_chain(0);

    let mut same = uncle_of(&parent, parent.timestamp);
    seal(&mut same, parent.timestamp);
    assert_eq!(verifier.verify(&same, Some(&parent)), Ok(()));

    let older = Err(ValidationError::TimestampOlderThanParent {
        parent: parent.timestamp,
        got: parent.timestamp,
    });
    assert!(verifier
        .uncle_parent_rules()
        .iter()
        .any(|rule| rule.validate_with_parent(&same, &parent) == older));
}

// --- the merged-mining proof, byte for byte as rskj's `ProofOfWorkRule`

/// A regtest header at `number`, at difficulty 1, where any Bitcoin hash
/// meets the target and only the coinbase and the merkle proof are in
/// question.
fn header_at(number: u64) -> Header {
    let mut header = create_dummy_header(number, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    header
}

/// A coinbase in the compressed form a header carries: the SHA-256 initial
/// state as its midstate, claiming `absorbed` bytes, then `tail`.
fn compressed_coinbase(absorbed: u64, tail: &[u8]) -> Vec<u8> {
    let mut out = absorbed.to_be_bytes().to_vec();
    for word in merged_mining::SHA256_INITIAL_STATE {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out.extend_from_slice(tail);
    out
}

/// A coinbase tail committing to `committed`: `before` bytes, the tag, the
/// 32 committed bytes, then `after` bytes.
fn tail_committing_to(committed: &[u8], before: usize, after: usize) -> Vec<u8> {
    let mut tail = vec![0x11; before];
    tail.extend_from_slice(merged_mining::RSK_TAG);
    tail.extend_from_slice(committed);
    tail.resize(tail.len() + after, 0x22);
    tail
}

/// `header` merge-mined through `coinbase` and `proof`, by a Bitcoin header
/// holding `wire_root` as its merkle root.
fn mined_through(mut header: Header, coinbase: Vec<u8>, proof: Vec<u8>, wire_root: [u8; 32]) -> Header {
    let btc = BtcHeader {
        version: bitcoin::block::Version::from_consensus(1),
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(wire_root),
        time: 1000,
        bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
        nonce: 0,
    };
    header.bitcoin_merged_mining_header = Some(Bytes::from(bitcoin::consensus::serialize(&btc)));
    header.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::from(coinbase));
    header.bitcoin_merged_mining_merkle_proof = Some(Bytes::from(proof));
    header
}

/// A root as a Bitcoin header holds it, for one folded in display order.
fn wire(display: [u8; 32]) -> [u8; 32] {
    let mut out = display;
    out.reverse();
    out
}

fn regtest_merged_mining() -> MergedMiningRule {
    MergedMiningRule { config: Arc::new(crate::config::ChainConfig::regtest()) }
}

/// rskj compares the root its proof folds to in bitcoinj's display order,
/// against the root the Bitcoin header holds in wire order. A proof folding
/// to the root's byte reversal proves nothing, and passed while either order
/// did.
#[test]
fn the_merkle_root_is_compared_in_rskjs_byte_order_only() {
    let header = header_at(10);
    let tail = tail_committing_to(header.hash_for_merged_mining().as_slice(), 10, 20);
    let coinbase = compressed_coinbase(0, &tail);
    // No siblings: the root is the coinbase's own hash.
    let root = merged_mining::compute_coinbase_hash(&coinbase);
    assert_ne!(root, wire(root));

    let right = mined_through(header.clone(), coinbase.clone(), Vec::new(), wire(root));
    assert_eq!(regtest_merged_mining().validate(&right), Ok(()));
    let reversed = mined_through(header, coinbase, Vec::new(), root);
    assert_eq!(
        regtest_merged_mining().validate(&reversed),
        Err(ValidationError::BitcoinMerkleProofInvalid)
    );
}

/// rskj: a coinbase runs past 64 bytes -- the count its midstate claims, read
/// as a Java `long`, plus its tail -- so it cannot pass for an inner node of
/// the merkle tree.
#[test]
fn the_coinbase_must_run_past_64_bytes() {
    let header = header_at(10);
    let hash = header.hash_for_merged_mining();
    let judge = |absorbed: u64, after: usize| {
        let coinbase = compressed_coinbase(absorbed, &tail_committing_to(hash.as_slice(), 0, after));
        let root = merged_mining::compute_coinbase_hash(&coinbase);
        regtest_merged_mining().validate(&mined_through(header.clone(), coinbase, Vec::new(), wire(root)))
    };

    // The tag and the hash are 41 bytes of tail.
    assert_eq!(judge(0, 23), Err(ValidationError::CoinbaseTooShort { length: 64 }));
    assert_eq!(judge(0, 24), Ok(()));
    assert_eq!(judge(23, 0), Err(ValidationError::CoinbaseTooShort { length: 64 }));
    assert_eq!(judge(24, 0), Ok(()));
    // `u64::MAX` is -1 to a Java `long`, and takes a byte off.
    assert_eq!(judge(u64::MAX, 24), Err(ValidationError::CoinbaseTooShort { length: 64 }));
    assert_eq!(judge(u64::MAX, 25), Ok(()));
    // A count that carries the sum past `i64::MAX` wraps it negative.
    assert_eq!(
        judge(i64::MAX as u64, 25),
        Err(ValidationError::CoinbaseTooShort { length: i64::MAX.wrapping_add(66) })
    );
}

/// The coinbase hash as BouncyCastle computes it from a restored midstate,
/// worked out with `sha2`'s compression function rather than this crate's:
/// the padding laid out from the tail's first byte, and the length the count
/// plus the tail, in bits, wrapping as a Java `long` does. Display order.
// `sha2` 0.10 takes its blocks as generic-array 0.14 arrays, which that
// crate now marks deprecated in favour of a 1.x `sha2` has yet to adopt.
#[allow(deprecated)]
fn bouncycastle_coinbase_hash(absorbed: u64, tail: &[u8]) -> [u8; 32] {
    use sha2::digest::generic_array::GenericArray;

    let mut padded = tail.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bits = absorbed.wrapping_add(tail.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bits.to_be_bytes());
    let mut state = merged_mining::SHA256_INITIAL_STATE;
    for block in padded.chunks_exact(64) {
        sha2::compress256(&mut state, &[*GenericArray::from_slice(block)]);
    }
    let mut once = [0u8; 32];
    for (bytes, word) in once.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    let mut hash: [u8; 32] = Sha256::digest(once).into();
    hash.reverse();
    hash
}

/// rskj resumes a coinbase's hash with BouncyCastle, which restores the
/// midstate's byte count but starts its blocks afresh at the tail. A count
/// that is not whole blocks is the miner's to write, and the hash must be
/// the one rskj computes from it, or this node refuses a block rskj takes.
#[test]
fn a_coinbase_hashes_from_its_midstate_as_bouncycastle_does() {
    // With nothing absorbed the midstate is SHA-256's start, and the hash is
    // plain double SHA-256 of the tail, at every length the padding turns on.
    for len in 0..=130usize {
        let tail: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut expected: [u8; 32] = Sha256::digest(Sha256::digest(&tail)).into();
        expected.reverse();
        assert_eq!(
            merged_mining::compute_coinbase_hash(&compressed_coinbase(0, &tail)),
            expected,
            "{len} bytes of tail"
        );
    }
    // Counts of whole blocks and not, and ones that wrap the length.
    let tail: Vec<u8> = (0..100u8).collect();
    for absorbed in [64, 1, 63, 100, u64::MAX, u64::MAX - 99, 1 << 61] {
        assert_eq!(
            merged_mining::compute_coinbase_hash(&compressed_coinbase(absorbed, &tail)),
            bouncycastle_coinbase_hash(absorbed, &tail),
            "{absorbed} bytes absorbed"
        );
    }

    // So a block whose coinbase claims one byte absorbed is one the rule
    // takes, when its Bitcoin header commits to the hash rskj computes.
    let header = header_at(10);
    let tail = tail_committing_to(header.hash_for_merged_mining().as_slice(), 0, 24);
    let root = bouncycastle_coinbase_hash(1, &tail);
    let mined = mined_through(header, compressed_coinbase(1, &tail), Vec::new(), wire(root));
    assert_eq!(regtest_merged_mining().validate(&mined), Ok(()));
}

/// Two merkle nodes, as rskj's `checkNotAValid64ByteTransaction` reads them
/// -- left then right, display order -- that parse as a transaction with one
/// input, one output of a satoshi, and scripts of `input` and `output` bytes.
/// The left node only has to supply the input count, its fifth byte.
fn transaction_shaped(input: u8, output: u8) -> ([u8; 32], [u8; 32]) {
    let mut tx = [0x55u8; 64];
    tx[4] = 1;
    tx[37..41].copy_from_slice(&0u32.to_le_bytes());
    tx[41] = input;
    let at = 46 + usize::from(input);
    tx[at] = 1;
    tx[at + 1..at + 9].copy_from_slice(&1i64.to_le_bytes());
    tx[at + 9] = output;
    (tx[..32].try_into().unwrap(), tx[32..].try_into().unwrap())
}

/// rskj `MerkleTreeUtils.checkNotAValid64ByteTransaction`: each test it
/// makes, at its bounds and past them.
#[test]
fn rskj_refuses_merkle_nodes_that_parse_as_a_transaction() {
    use merged_mining::parses_as_a_64_byte_transaction as parses;

    for input in 0..=4 {
        let (left, right) = transaction_shaped(input, 4 - input);
        assert!(parses(&left, &right), "{input} + {} bytes of script", 4 - input);
    }
    for (input, output) in [(1, 2), (2, 3)] {
        let (left, right) = transaction_shaped(input, output);
        assert!(!parses(&left, &right), "{input} + {output} bytes of script");
    }

    // The shape with two bytes of script each way, with `bytes` written at
    // `at`.
    let edited = |at: usize, bytes: &[u8]| {
        let (left, right) = transaction_shaped(2, 2);
        let mut tx = [0u8; 64];
        tx[..32].copy_from_slice(&left);
        tx[32..].copy_from_slice(&right);
        tx[at..at + bytes.len()].copy_from_slice(bytes);
        parses(&tx[..32].try_into().unwrap(), &tx[32..].try_into().unwrap())
    };
    // One input.
    assert!(!edited(4, &[0]));
    assert!(!edited(4, &[2]));
    // Spending an output at most a million in, or the coinbase's.
    assert!(edited(37, &1_000_000u32.to_le_bytes()));
    assert!(!edited(37, &1_000_001u32.to_le_bytes()));
    assert!(edited(37, &u32::MAX.to_le_bytes()));
    assert!(!edited(37, &(u32::MAX - 1).to_le_bytes()));
    // Script lengths over four, or negative as a Java byte.
    for length in [5, 0x80, 0xff] {
        assert!(!edited(41, &[length]), "input script of {length:#x}");
        assert!(!edited(57, &[length]), "output script of {length:#x}");
    }
    // One output.
    assert!(!edited(48, &[2]));
    // Worth a satoshi to 21 million bitcoin.
    for (value, parses_as_one) in [
        (0i64, false),
        (-1, false),
        (2_100_000_000_000_000, true),
        (2_100_000_000_000_001, false),
    ] {
        assert_eq!(edited(49, &value.to_le_bytes()), parses_as_one, "{value} satoshis");
    }
}

/// rskj runs the guard at every fold of the proof, before any root is
/// compared, so a block whose coinbase hash and first sibling parse as a
/// transaction is no block at all.
#[test]
fn a_merkle_proof_through_a_transaction_shaped_pair_is_refused() {
    let header = header_at(10);
    let hash = header.hash_for_merged_mining();
    // A coinbase whose hash supplies the input count, found by varying what
    // follows the commitment.
    let (coinbase, coinbase_hash) = (0..=u16::MAX)
        .find_map(|salt| {
            let mut tail = tail_committing_to(hash.as_slice(), 0, 24);
            let end = tail.len();
            tail[end - 2..].copy_from_slice(&salt.to_be_bytes());
            let coinbase = compressed_coinbase(0, &tail);
            let coinbase_hash = merged_mining::compute_coinbase_hash(&coinbase);
            (coinbase_hash[4] == 1).then_some((coinbase, coinbase_hash))
        })
        .expect("a coinbase hash with 1 as its fifth byte");
    let (_, sibling) = transaction_shaped(2, 2);

    assert!(merged_mining::parses_as_a_64_byte_transaction(&coinbase_hash, &sibling));
    assert_eq!(merged_mining::rskip92_merkle_root(&coinbase_hash, &sibling), None);
    let root = merged_mining::combine_left_right(&coinbase_hash, &sibling);
    let mined = mined_through(header.clone(), coinbase.clone(), sibling.to_vec(), wire(root));
    assert_eq!(
        regtest_merged_mining().validate(&mined),
        Err(ValidationError::MerkleNodesFormTransaction)
    );

    // A byte more of output script and the pair is no transaction: the same
    // block, with the root that sibling folds to, is merge-mined.
    let mut other = sibling;
    other[57 - 32] = 3;
    assert!(!merged_mining::parses_as_a_64_byte_transaction(&coinbase_hash, &other));
    let root = merged_mining::combine_left_right(&coinbase_hash, &other);
    let mined = mined_through(header, coinbase, other.to_vec(), wire(root));
    assert_eq!(regtest_merged_mining().validate(&mined), Ok(()));
}

/// rskj `BlockHeader.getHashRootForMergedMining`: a UMM root is 20 bytes or
/// none, and any other length throws before there is a hash to look for.
#[test]
fn a_umm_root_is_twenty_bytes_or_none() {
    for (len, valid) in [(0, true), (20, true), (19, false), (21, false), (32, false)] {
        let mut header = header_at(10);
        header.umm_root = Some(Bytes::from(vec![0x0c; len]));
        seal(&mut header, 1000);
        let verdict = regtest_merged_mining().validate(&header);
        if valid {
            assert_eq!(verdict, Ok(()), "{len} bytes");
        } else {
            assert_eq!(verdict, Err(ValidationError::UmmRootInvalid { len }), "{len} bytes");
        }
    }
}

/// rskj puts fork-detection data in the merged-mining hash from RSKIP110
/// (wasabi100) on, and never below block 449. Where it does not, a coinbase
/// commits to the whole hash, and twelve bytes of anything else after its
/// first twenty commit to nothing.
#[test]
fn fork_detection_data_joins_the_hash_from_wasabi100_and_block_449() {
    use crate::config::{ActivationHeights, ChainConfig};

    // Regtest has RSKIP110 from genesis, so there the height alone decides;
    // with wasabi100 at 1,000, it is wasabi100 that does.
    let late = ChainConfig {
        activation_heights: ActivationHeights { wasabi100: 1_000, ..ActivationHeights::regtest() },
        ..ChainConfig::regtest()
    };
    for (config, number, altered_valid) in [
        (ChainConfig::regtest(), 448, false),
        (ChainConfig::regtest(), 449, true),
        (late.clone(), 999, false),
        (late, 1_000, true),
    ] {
        let rule = MergedMiningRule { config: Arc::new(config) };
        let header = header_at(number);
        let hash = header.hash_for_merged_mining();
        let mut altered = hash;
        altered[20..].copy_from_slice(&[0xfd; 12]);
        let judge = |committed: B256| {
            let mut mined = header.clone();
            let (btc, coinbase, proof) = build_mm_proof(&mined, 0x207fffff, Some(committed));
            mined.bitcoin_merged_mining_header = Some(btc);
            mined.bitcoin_merged_mining_coinbase_transaction = Some(coinbase);
            mined.bitcoin_merged_mining_merkle_proof = Some(proof);
            rule.validate(&mined)
        };

        assert_eq!(judge(hash), Ok(()), "block {number}, the whole hash");
        if altered_valid {
            assert_eq!(judge(altered), Ok(()), "block {number}, fork-detection data");
        } else {
            assert_eq!(
                judge(altered),
                Err(ValidationError::BitcoinCoinbaseTagInvalid),
                "block {number}, fork-detection data"
            );
        }
    }
}
