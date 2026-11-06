//! RSKIP110 fork-detection data.
//!
//! From wasabi100 on, the 32 bytes a coinbase carries after `RSKBLOCK:` are
//! not all hash: the first 20 are the merged-mining hash and the last 12
//! commit to where on the chain the block was mined. rskj validates them
//! (`ForkDetectionDataRule`), so a miner that fills them in wrongly produces
//! blocks its peers reject, with nothing in the block itself to point at.
//!
//! Ported from rskj `co.rsk.mine.ForkDetectionDataCalculator`.

use rustock_core::validation::fork_detection::uncle_sum;
use rustock_core::validation::ValidationError;
use rustock_core::Header;

/// Bytes of commit-to-parents vector in the fork-detection data.
const CPV_SIZE: usize = 7;
/// Spacing, in blocks, between the ancestors the CPV commits to.
const CPV_JUMP_FACTOR: u64 = 64;

/// Total length of the fork-detection data.
pub const FORK_DETECTION_DATA_LENGTH: usize = 12;

/// Mainchain blocks needed before fork-detection data can be produced at all.
///
/// `CPV_SIZE * CPV_JUMP_FACTOR + 1` -- the `+ 1` is because genesis carries no
/// usable Bitcoin header, so it can never be a CPV element. rskj
/// `MiningConfig.REQUIRED_NUMBER_OF_BLOCKS_FOR_FORK_DETECTION_CALCULATION`.
pub const REQUIRED_MAINCHAIN_BLOCKS: usize = CPV_SIZE * CPV_JUMP_FACTOR as usize + 1;

/// Fork-detection data for the block mined on top of `mainchain[0]`.
///
/// `mainchain` is the best chain in descending order: index 0 is the parent of
/// the block being built, index 1 its parent, and so on. Returns an empty
/// vector when the chain is too short, which is what rskj does and what the
/// header then carries -- early blocks legitimately have none.
///
/// The uncle count is the validator's own sum, so the two can't drift, and
/// its error is rskj's `BlockToMineBuilder` throwing: no block on top of
/// `mainchain[0]` would be valid.
pub fn calculate(mainchain: &[Header]) -> Result<Vec<u8>, ValidationError> {
    if mainchain.len() < REQUIRED_MAINCHAIN_BLOCKS {
        return Ok(Vec::new());
    }

    let mut data = Vec::with_capacity(FORK_DETECTION_DATA_LENGTH);
    data.extend_from_slice(&commit_to_parents_vector(mainchain));
    data.push(uncle_sum(mainchain)?);
    data.extend_from_slice(&((mainchain[0].number + 1) as u32).to_be_bytes());
    debug_assert_eq!(data.len(), FORK_DETECTION_DATA_LENGTH);
    Ok(data)
}

/// One byte per committed ancestor, each the least significant byte of that
/// ancestor's Bitcoin block hash. The ancestors are the last block of each of
/// the seven preceding 64-block windows, so two chains that diverged more than
/// a window ago disagree here.
fn commit_to_parents_vector(mainchain: &[Header]) -> [u8; CPV_SIZE] {
    let best_height = mainchain[0].number;
    let cpv_start_height = (best_height / CPV_JUMP_FACTOR) * CPV_JUMP_FACTOR;

    let mut cpv = [0u8; CPV_SIZE];
    for (i, slot) in cpv.iter_mut().enumerate() {
        let offset = best_height - cpv_start_height + i as u64 * CPV_JUMP_FACTOR;
        *slot = bitcoin_hash_least_significant_byte(&mainchain[offset as usize]);
    }
    cpv
}

/// The last byte of the Bitcoin block hash in its conventional (reversed,
/// as-displayed) order -- which is the *first* byte of the consensus
/// little-endian encoding. A header without a decodable Bitcoin block
/// contributes zero, so chains built without merged mining, as the tests and
/// the load generator build them, still get data. rskj's miner throws there
/// instead, and the validator refuses a block above such a header.
fn bitcoin_hash_least_significant_byte(header: &Header) -> u8 {
    use bitcoin::block::Header as BtcHeader;
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash;

    let Some(bytes) = header.bitcoin_merged_mining_header.as_ref() else {
        return 0;
    };
    let mut reader = &bytes[..];
    match BtcHeader::consensus_decode(&mut reader) {
        Ok(btc) => btc.block_hash().to_byte_array()[0],
        Err(_) => 0,
    }
}

/// Overlay fork-detection data onto a merged-mining hash, producing the 32
/// bytes that go in the coinbase after the tag.
///
/// The base hash keeps its first 20 bytes; the rest is replaced. rskj
/// `BlockHeader.getHashForMergedMining`. Empty fork-detection data leaves the
/// hash whole, which is the pre-wasabi100 (and short-chain) form.
pub fn apply_to_hash(base_hash: alloy_primitives::B256, fork_data: &[u8]) -> alloy_primitives::B256 {
    use rustock_core::validation::merged_mining::HASH_FOR_MERGED_MINING_PREFIX_LENGTH as PREFIX;

    let mut out = base_hash;
    if fork_data.is_empty() {
        return out;
    }
    let len = fork_data.len().min(32 - PREFIX);
    out[PREFIX..PREFIX + len].copy_from_slice(&fork_data[..len]);
    out
}
