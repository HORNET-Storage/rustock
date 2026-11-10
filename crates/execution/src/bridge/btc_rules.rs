//! bitcoinj-thin's checks on a Bitcoin header the Bridge adds to its chain
//! (`BtcAbstractBlockChain.add`, tag `v0.14.4-rsk-20`). The header's target
//! must be in range and its hash under it (`BtcBlock.verifyHeader`), and the
//! target must be the one its parent's chain calls for
//! (`NetworkParameters.checkDifficultyTransitions`, as each network has it).

use alloy_primitives::U512;
use bitcoin::block::Header as BtcHeader;
use bitcoin::hashes::Hash;

use super::btc_store::{get_stored_block, StoredBlock};
use super::constants::BtcNetwork;

/// `NetworkParameters.TARGET_TIMESPAN`: the two weeks an interval should
/// take, in seconds.
const TARGET_TIMESPAN: i32 = 14 * 24 * 60 * 60;
/// `NetworkParameters.TARGET_SPACING`: the ten minutes a block should take,
/// in seconds.
const TARGET_SPACING: i64 = 10 * 60;
/// `NetworkParameters.INTERVAL`, `TARGET_TIMESPAN / TARGET_SPACING`: the
/// blocks between retargets on mainnet and testnet3.
const INTERVAL: u32 = 2016;
/// `TestNet3Params.testnetDiffDate`, 16 February 2012, in seconds. Testnet3's
/// own rule applies to the blocks after it.
const TESTNET_DIFF_DATE: u64 = 1_329_264_000;

/// `NetworkParameters.interval`. Regtest's is `Integer.MAX_VALUE`, so its
/// target never changes.
fn interval(network: BtcNetwork) -> u32 {
    match network {
        BtcNetwork::Mainnet | BtcNetwork::Testnet => INTERVAL,
        BtcNetwork::Regtest => i32::MAX as u32,
    }
}

/// `NetworkParameters.maxTarget`: `0x1d00ffff` decoded on mainnet and
/// testnet3, and on regtest `RegTestParams.MAX_TARGET`, 2^263 - 1, more than
/// 256 bits hold.
fn max_target(network: BtcNetwork) -> U512 {
    match network {
        BtcNetwork::Mainnet | BtcNetwork::Testnet => U512::from(0xffff_u32) << 208_usize,
        BtcNetwork::Regtest => (U512::from(1_u8) << 263_usize) - U512::from(1_u8),
    }
}

/// bitcoinj `Utils.decodeCompactBits`: the number `bits` writes, as its sign
/// and its magnitude. The top byte counts the bytes of a big-endian number
/// whose first three are the low bytes of `bits`, cut to that count, and the
/// first of them carries the sign in its top bit. `None` past 512 bits,
/// beyond every network's maximum target.
fn decode_compact(bits: u32) -> Option<(bool, U512)> {
    let size = (bits >> 24) as usize;
    let negative = size >= 1 && bits & 0x0080_0000 != 0;
    let mantissa = bits & 0x007f_ffff;
    if size <= 3 {
        return Some((negative, U512::from(mantissa >> (8 * (3 - size)))));
    }
    let shift = 8 * (size - 3);
    if mantissa != 0 && (32 - mantissa.leading_zeros()) as usize + shift > 512 {
        return None;
    }
    Some((negative, U512::from(mantissa) << shift))
}

/// bitcoinj `Utils.encodeCompactBits` for a number that isn't negative: its
/// length in bytes as `BigInteger.toByteArray()` counts it, then its first
/// three bytes. That length leaves room for a sign bit, so the first of them
/// never has its top bit set, and bitcoinj's adjustment for one that has
/// never applies.
fn encode_compact(value: U512) -> u64 {
    let size = value.bit_len() / 8 + 1;
    let mantissa = if size <= 3 {
        value.as_limbs()[0] << (8 * (3 - size))
    } else {
        (value >> (8 * (size - 3))).as_limbs()[0]
    };
    mantissa | (size as u64) << 24
}

/// bitcoinj `BtcBlock.getDifficultyTargetAsInteger`: the target `bits`
/// claims, or `None` where bitcoinj throws "Difficulty target is bad":
/// zero, negative, or above the network's maximum.
fn difficulty_target(bits: u32, network: BtcNetwork) -> Option<U512> {
    let (negative, target) = decode_compact(bits)?;
    (!negative && !target.is_zero() && target <= max_target(network)).then_some(target)
}

/// bitcoinj `BtcBlock.verifyHeader`, which is `checkProofOfWork(true)`: the
/// target in range, and the hash, read as a number, at or under it.
/// bitcoinj-thin leaves out bitcoinj's timestamp check, which reads the
/// local clock.
pub(crate) fn verify_header(header: &BtcHeader, network: BtcNetwork) -> bool {
    difficulty_target(header.bits.to_consensus(), network).is_some_and(|target| {
        // `getHash().toBigInteger()`: the hash in display order read
        // big-endian, which is its bytes read little-endian.
        U512::from_le_slice(&header.block_hash().to_byte_array()) <= target
    })
}

/// `NetworkParameters.checkDifficultyTransitions` for the Bridge's network:
/// whether `next`, whose parent is `prev`, claims the target `prev`'s chain
/// calls for. `false` where bitcoinj throws, including where the stored
/// chain it walks back runs out.
pub(crate) fn check_difficulty_transitions<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    prev: &StoredBlock,
    next: &BtcHeader,
    network: BtcNetwork,
) -> bool {
    // `TestNet3Params`: its own rule between retargets, for a block after
    // `testnetDiffDate` (`nextBlock.getTime().after(testnetDiffDate)`).
    if network == BtcNetwork::Testnet
        && !is_transition_point(prev, network)
        && u64::from(next.time) > TESTNET_DIFF_DATE
    {
        return testnet3(ctx, prev, next);
    }
    retarget(ctx, prev, next, network)
}

/// `isDifficultyTransitionPoint`: the block after `prev` begins an interval.
fn is_transition_point(prev: &StoredBlock, network: BtcNetwork) -> bool {
    (u64::from(prev.height) + 1).is_multiple_of(u64::from(interval(network)))
}

/// `AbstractBitcoinNetParams.checkDifficultyTransitions`. Between retargets a
/// block claims its parent's `bits`, compared as written. At a retarget it
/// claims the parent's target scaled by the time the interval took, held to
/// between a quarter of the two weeks and four times them and to the
/// network's maximum, then cut to the precision the block's own exponent
/// gives it.
fn retarget<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    prev: &StoredBlock,
    next: &BtcHeader,
    network: BtcNetwork,
) -> bool {
    if !is_transition_point(prev, network) {
        return next.bits == prev.header.bits;
    }
    // The interval's first block, `interval - 1` blocks back from `prev`, each
    // of them stored.
    let mut first = prev.clone();
    for _ in 1..interval(network) {
        match get_stored_block(ctx, &first.header.prev_blockhash) {
            Some(block) => first = block,
            None => return false,
        }
    }
    // `(int) (prev.getTimeSeconds() - blockIntervalAgo.getTimeSeconds())`.
    let timespan = (i64::from(prev.header.time) - i64::from(first.header.time)) as i32;
    let timespan = timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);
    // `Utils.decodeCompactBits(prev.getDifficultyTarget())`. A stored block's
    // target is in range, so never negative.
    let Some((false, prev_target)) = decode_compact(prev.header.bits.to_consensus()) else {
        return false;
    };
    let new_target = (prev_target * U512::from(timespan as u32)
        / U512::from(TARGET_TIMESPAN as u32))
    .min(max_target(network));
    // Kept to the three bytes below the block's own exponent, written as
    // compact bits, and compared with the block's.
    let accuracy_bytes = (next.bits.to_consensus() >> 24) as i32 - 3;
    let mask = if accuracy_bytes >= 0 {
        let shift = 8 * accuracy_bytes as usize;
        if shift < 512 {
            U512::from(0x00ff_ffff_u32) << shift
        } else {
            U512::ZERO
        }
    } else {
        U512::from(0x00ff_ffff_u32 >> (8 * accuracy_bytes.unsigned_abs()))
    };
    encode_compact(new_target & mask) == u64::from(next.bits.to_consensus())
}

/// `TestNet3Params.checkDifficultyTransitions` between retargets. A block more
/// than twenty minutes after its parent, or before it, may claim any target
/// in range: bitcoinj checks nothing then. Otherwise it claims the target of
/// the last block, from its parent back, that isn't at the easiest target,
/// walking back no further than the interval's first block. (bitcoinj also
/// stops at the genesis block, which is at height 0, the first block of an
/// interval.) The targets are compared as numbers here, not as written.
fn testnet3<CTX: crate::RskContextTr>(ctx: &mut CTX, prev: &StoredBlock, next: &BtcHeader) -> bool {
    let delta = i64::from(next.time) - i64::from(prev.header.time);
    if !(0..=2 * TARGET_SPACING).contains(&delta) {
        return true;
    }
    let network = BtcNetwork::Testnet;
    let easiest = max_target(network);
    let mut cursor = prev.clone();
    while !cursor.height.is_multiple_of(INTERVAL) {
        match difficulty_target(cursor.header.bits.to_consensus(), network) {
            Some(target) if target == easiest => {}
            Some(_) => break,
            None => return false,
        }
        match get_stored_block(ctx, &cursor.header.prev_blockhash) {
            Some(block) => cursor = block,
            None => return false,
        }
    }
    match (
        difficulty_target(cursor.header.bits.to_consensus(), network),
        difficulty_target(next.bits.to_consensus(), network),
    ) {
        (Some(cursor_target), Some(next_target)) => cursor_target == next_target,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use bitcoin::block::Version;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

    use crate::bridge::btc_store::put_stored_block;

    const EASIEST: u32 = 0x1d00_ffff;
    const HARD: u32 = 0x1c0f_ffff;

    fn empty_ctx() -> impl crate::RskContextTr {
        use revm::MainContext;
        revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default())
    }

    fn header(prev: BlockHash, time: u32, bits: u32, nonce: u32) -> BtcHeader {
        BtcHeader {
            version: Version::from_consensus(1),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    /// A chain from `height`, each block with its time and bits, pointing at
    /// the one before.
    fn chain(height: u32, blocks: &[(u32, u32)]) -> Vec<StoredBlock> {
        let mut prev = BlockHash::all_zeros();
        blocks
            .iter()
            .zip(height..)
            .map(|(&(time, bits), height)| {
                let block = StoredBlock::new(header(prev, time, bits, height), height, U256::ZERO);
                prev = block.header.block_hash();
                block
            })
            .collect()
    }

    fn store<CTX: crate::RskContextTr>(ctx: &mut CTX, blocks: &[StoredBlock]) {
        for block in blocks {
            put_stored_block(ctx, block, true);
        }
    }

    fn child(prev: &StoredBlock, time: u32, bits: u32) -> BtcHeader {
        header(prev.header.block_hash(), time, bits, 0)
    }

    fn hash_of(header: &BtcHeader) -> U512 {
        U512::from_le_slice(&header.block_hash().to_byte_array())
    }

    /// bitcoinj's `getDifficultyTargetAsInteger` refuses a target that's zero
    /// or negative (the compact's sign bit), or above the network's maximum,
    /// which on regtest is past 256 bits.
    #[test]
    fn a_target_is_in_range_where_bitcoinj_takes_it() {
        use BtcNetwork::{Mainnet, Regtest, Testnet};
        let easiest = U512::from(0xffff_u32) << 208_usize;
        assert_eq!(difficulty_target(EASIEST, Mainnet), Some(easiest));
        assert_eq!(difficulty_target(EASIEST, Testnet), Some(easiest));
        assert_eq!(
            difficulty_target(0x1d01_0000, Mainnet),
            None,
            "one past the maximum"
        );
        assert_eq!(
            difficulty_target(0x207f_ffff, Testnet),
            None,
            "regtest's target"
        );
        assert_eq!(
            difficulty_target(0x1c00_ffff, Mainnet),
            Some(U512::from(0xffff_u32) << 200_usize)
        );
        assert_eq!(
            difficulty_target(0x1c80_ffff, Mainnet),
            None,
            "the sign bit"
        );
        assert_eq!(
            difficulty_target(0x0112_3456, Mainnet),
            Some(U512::from(0x12_u8)),
            "a short exponent cuts the mantissa"
        );
        assert_eq!(difficulty_target(0x0100_3456, Mainnet), None, "cut to zero");
        assert_eq!(
            difficulty_target(0x0012_3456, Mainnet),
            None,
            "no bytes at all"
        );
        assert_eq!(
            difficulty_target(0x207f_ffff, Regtest),
            Some(U512::from(0x7f_ffff_u32) << 232_usize)
        );
        assert_eq!(
            difficulty_target(0x2300_007f, Regtest),
            Some(U512::from(0x7f_u8) << 256_usize),
            "past 256 bits"
        );
        assert_eq!(
            difficulty_target(0x2300_0080, Regtest),
            None,
            "2^263, past regtest's maximum"
        );
        assert_eq!(
            difficulty_target(0xff7f_ffff, Regtest),
            None,
            "past 512 bits"
        );
    }

    /// A header mined at regtest's target has its hash under its own target,
    /// but its target is above mainnet's and testnet's maximum.
    #[test]
    fn a_header_at_regtests_target_is_out_of_range_on_mainnet_and_testnet() {
        let mined = (0..)
            .map(|nonce| header(BlockHash::all_zeros(), 1_700_000_000, 0x207f_ffff, nonce))
            .find(|header| verify_header(header, BtcNetwork::Regtest))
            .unwrap();
        assert!(!verify_header(&mined, BtcNetwork::Mainnet));
        assert!(!verify_header(&mined, BtcNetwork::Testnet));
    }

    /// With the compact's sign bit set, no hash is under the target, not even
    /// one under the number the other bits write.
    #[test]
    fn a_negative_target_takes_no_hash() {
        let written = U512::from(0xffff_u32) << 232_usize;
        let mined = (0..)
            .map(|nonce| header(BlockHash::all_zeros(), 1_700_000_000, 0x2080_ffff, nonce))
            .find(|header| hash_of(header) <= written)
            .unwrap();
        assert!(!verify_header(&mined, BtcNetwork::Regtest));
    }

    /// Bitcoin Core's `pow_tests`, which bitcoinj computes alike: the time of
    /// the interval's first block; the parent's height, time and bits; and the
    /// bits the next block must claim.
    const RETARGETS: [(u32, u32, u32, u32, u32); 4] = [
        (
            1_261_130_161,
            32_255,
            1_262_152_739,
            0x1d00_ffff,
            0x1d00_d86a,
        ),
        // Held to the maximum.
        (
            1_231_006_505,
            2_015,
            1_233_061_996,
            0x1d00_ffff,
            0x1d00_ffff,
        ),
        // Held to a quarter of the two weeks.
        (
            1_279_008_237,
            68_543,
            1_279_297_671,
            0x1c05_a3f4,
            0x1c01_68fd,
        ),
        // Held to four times the two weeks.
        (
            1_263_163_443,
            46_367,
            1_269_211_443,
            0x1c38_7f6f,
            0x1d00_e1fd,
        ),
    ];

    /// The interval ending at `prev_height`, every block at `bits`.
    fn interval_to(
        prev_height: u32,
        first_time: u32,
        prev_time: u32,
        bits: u32,
    ) -> Vec<StoredBlock> {
        let blocks: Vec<(u32, u32)> = (0..INTERVAL)
            .map(|i| match i {
                0 => (first_time, bits),
                i if i == INTERVAL - 1 => (prev_time, bits),
                i => (first_time + i, bits),
            })
            .collect();
        chain(prev_height + 1 - INTERVAL, &blocks)
    }

    /// On mainnet and on testnet3, and on testnet3 also after its own rule
    /// began, which leaves retargets alone: a retarget reads only how long its
    /// interval took, so moving the vectors' times past 16 February 2012
    /// changes nothing else.
    #[test]
    fn a_retarget_claims_the_target_bitcoinj_computes() {
        for (first_time, prev_height, prev_time, bits, expected) in RETARGETS {
            for (network, later) in [
                (BtcNetwork::Mainnet, 0),
                (BtcNetwork::Testnet, 0),
                (BtcNetwork::Testnet, 200_000_000),
            ] {
                let (first_time, prev_time) = (first_time + later, prev_time + later);
                let blocks = interval_to(prev_height, first_time, prev_time, bits);
                let prev = blocks.last().unwrap();
                let claims = |ctx: &mut _, bits| {
                    check_difficulty_transitions(
                        ctx,
                        prev,
                        &child(prev, prev_time + 600, bits),
                        network,
                    )
                };
                let mut ctx = empty_ctx();
                store(&mut ctx, &blocks);
                assert!(
                    claims(&mut ctx, expected),
                    "{expected:#x} after #{prev_height}"
                );
                for wrong in [expected - 1, expected + 1] {
                    assert!(!claims(&mut ctx, wrong), "{wrong:#x} after #{prev_height}");
                }
                // Without the interval's first block the walk back runs out.
                let mut ctx = empty_ctx();
                store(&mut ctx, &blocks[1..]);
                assert!(!claims(&mut ctx, expected));
            }
        }
    }

    /// bitcoinj compares a retarget's target with the block's in the block's
    /// own precision (`accuracyBytes`): the target's three bytes below the
    /// exponent the block claims. So a block may also claim the target's next
    /// bytes down at a smaller exponent, a harder target, which bitcoinj then
    /// holds its hash to: after #32,255, two of them, after #68,543 one.
    #[test]
    fn a_retarget_takes_the_target_in_the_precision_the_block_claims() {
        for (prev_height, harder) in [
            (32_255, &[0x1b6a_528b, 0x1a52_8bc8][..]),
            (68_543, &[0x1b68_fd00][..]),
        ] {
            let (first_time, _, prev_time, bits, _) =
                RETARGETS.into_iter().find(|r| r.1 == prev_height).unwrap();
            let blocks = interval_to(prev_height, first_time, prev_time, bits);
            let prev = blocks.last().unwrap();
            let mut ctx = empty_ctx();
            store(&mut ctx, &blocks);
            for &claimed in harder {
                let next = child(prev, prev_time + 600, claimed);
                assert!(
                    check_difficulty_transitions(&mut ctx, prev, &next, BtcNetwork::Mainnet),
                    "{claimed:#x} after #{prev_height}"
                );
            }
        }
    }

    /// Between retargets a block claims its parent's bits as written: the same
    /// number written another way isn't them. Regtest never retargets.
    #[test]
    fn between_retargets_a_block_claims_its_parents_bits() {
        // 0x1c120000 and 0x1d001200 write the same number.
        let blocks = chain(100, &[(1_700_000_000, 0x1c12_0000)]);
        let mut ctx = empty_ctx();
        store(&mut ctx, &blocks);
        let prev = &blocks[0];
        let claims = |ctx: &mut _, bits, network| {
            check_difficulty_transitions(ctx, prev, &child(prev, 1_700_000_600, bits), network)
        };
        assert!(claims(&mut ctx, 0x1c12_0000, BtcNetwork::Mainnet));
        assert!(!claims(&mut ctx, 0x1d00_1200, BtcNetwork::Mainnet));
        assert!(!claims(&mut ctx, EASIEST, BtcNetwork::Mainnet));

        // At mainnet's retarget height, regtest still claims its parent's bits.
        let blocks = chain(2015, &[(1_700_000_000, 0x207f_ffff)]);
        let mut ctx = empty_ctx();
        store(&mut ctx, &blocks);
        let prev = &blocks[0];
        let claims = |ctx: &mut _, bits| {
            check_difficulty_transitions(
                ctx,
                prev,
                &child(prev, 1_700_000_600, bits),
                BtcNetwork::Regtest,
            )
        };
        assert!(claims(&mut ctx, 0x207f_ffff));
        assert!(!claims(&mut ctx, 0x207f_fffe));
    }

    /// Whether testnet3 takes `bits` for a block `seconds` after the last of
    /// `blocks`, stored from `height`.
    fn testnet3_takes(height: u32, blocks: &[(u32, u32)], seconds: i64, bits: u32) -> bool {
        let blocks = chain(height, blocks);
        let mut ctx = empty_ctx();
        store(&mut ctx, &blocks);
        let prev = blocks.last().unwrap();
        let time = (i64::from(prev.header.time) + seconds) as u32;
        check_difficulty_transitions(
            &mut ctx,
            prev,
            &child(prev, time, bits),
            BtcNetwork::Testnet,
        )
    }

    /// Within twenty minutes of its parent a testnet3 block claims the last
    /// target before it that isn't the easiest, found past easy blocks. More
    /// than twenty minutes after its parent, or before it, any target in
    /// range.
    #[test]
    fn testnet3_takes_the_easiest_target_only_after_twenty_minutes() {
        let t = 1_700_000_000;
        let blocks = [(t, HARD), (t + 1300, EASIEST), (t + 2600, EASIEST)];
        let height = INTERVAL * 1000;
        for seconds in [0, 1200] {
            assert!(testnet3_takes(height, &blocks, seconds, HARD));
            assert!(!testnet3_takes(height, &blocks, seconds, EASIEST));
        }
        for bits in [HARD, EASIEST, 0x1c7f_ffff] {
            assert!(testnet3_takes(height, &blocks, 1201, bits));
            assert!(testnet3_takes(height, &blocks, -1, bits));
        }
    }

    /// Testnet3's walk starts at the parent, stops at the interval's first
    /// block whatever its target, and refuses where it runs out of blocks.
    #[test]
    fn testnet3s_walk_starts_at_the_parent_and_stops_at_the_interval() {
        let t = 1_700_000_000;
        let start = INTERVAL * 1000;
        let easy_start = [(t, EASIEST), (t + 1300, EASIEST)];
        assert!(testnet3_takes(start, &easy_start, 600, EASIEST));
        assert!(!testnet3_takes(start, &easy_start, 600, HARD));
        let hard_parent = [(t, EASIEST), (t + 1300, HARD)];
        assert!(testnet3_takes(start + 5, &hard_parent, 600, HARD));
        assert!(!testnet3_takes(start + 5, &hard_parent, 600, EASIEST));
        for bits in [HARD, EASIEST] {
            assert!(
                !testnet3_takes(start + 5, &easy_start, 600, bits),
                "no block before the chain"
            );
        }
        // 0x1c0fff00 and 0x1d000fff write the same target.
        let written_another_way = [(t, 0x1c0f_ff00)];
        assert!(testnet3_takes(
            start + 5,
            &written_another_way,
            600,
            0x1d00_0fff
        ));
    }

    /// Up to 16 February 2012, testnet3 had mainnet's rule.
    #[test]
    fn testnet3s_rule_starts_after_16_february_2012() {
        let blocks = [(1_329_262_000, HARD), (1_329_263_500, EASIEST)];
        let height = INTERVAL * 1000 + 5;
        // 1_329_264_000 is the date itself, not after it.
        assert!(testnet3_takes(height, &blocks, 500, EASIEST));
        assert!(!testnet3_takes(height, &blocks, 500, HARD));
        assert!(testnet3_takes(height, &blocks, 501, HARD));
        assert!(!testnet3_takes(height, &blocks, 501, EASIEST));
    }
}
