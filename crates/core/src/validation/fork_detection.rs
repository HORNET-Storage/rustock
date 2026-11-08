//! RSKIP110 fork-detection data — rskj `ForkDetectionDataRule` and
//! `ForkDetectionDataCalculator`.
//!
//! From wasabi100 the 12 bytes following the RSK tag and the 20-byte
//! merged-mining hash prefix in the coinbase are not free-form: they commit to
//! the miner's view of the mainchain. Consensus checks them, so a miner cannot
//! put anything there.

use super::ValidationError;
use crate::types::header::Header;
use alloy_primitives::B256;

/// `ForkDetectionDataCalculator.CPV_SIZE`.
pub const CPV_SIZE: usize = 7;
/// `ForkDetectionDataCalculator.CPV_JUMP_FACTOR`.
pub const CPV_JUMP_FACTOR: u64 = 64;
/// `ForkDetectionDataCalculator.NUMBER_OF_UNCLES`.
pub const NUMBER_OF_UNCLES: usize = 32;
/// `MiningConfig.REQUIRED_NUMBER_OF_BLOCKS_FOR_FORK_DETECTION_CALCULATION`,
/// and `ForkDetectionDataCalculator.MIN_MAINCHAIN_SIZE` — the same 449
/// (`CPV_SIZE * CPV_JUMP_FACTOR + 1`; the +1 is because genesis carries no
/// valid BTC header).
pub const REQUIRED_BLOCKS: u64 = CPV_SIZE as u64 * CPV_JUMP_FACTOR + 1;

/// The ancestor headers the calculation reads, newest first: index 0 is the
/// parent of the block being validated, index `i` its `i`-th ancestor.
///
/// A trait so the caller can supply a cached rolling window; rskj uses
/// `ConsensusValidationMainchainView` for the same reason. Walking the store
/// 449 times per block is correct but not cheap.
pub trait MainchainView {
    /// Up to `count` headers ending at `from` (inclusive), newest first.
    /// Returning fewer than `count` means the view could not be built.
    fn headers_from(&self, from: B256, count: u64) -> Vec<Header>;
}

/// rskj `ForkDetectionDataCalculator.calculateWithBlockHeaders`.
///
/// `headers[0]` is the best block (the parent of the block being mined).
/// Returns `None` when the view is too short, matching the Java's empty array.
pub fn calculate(headers: &[Header]) -> Option<[u8; 12]> {
    if (headers.len() as u64) < REQUIRED_BLOCKS {
        return None;
    }
    let mut data = [0u8; 12];

    // buildCommitToParentsVector: seven bytes, each the least significant byte
    // of a BTC block hash from a height on a 64-block grid.
    let best_height = headers[0].number;
    let cpv_start = (best_height / CPV_JUMP_FACTOR) * CPV_JUMP_FACTOR;
    for (i, slot) in data.iter_mut().enumerate().take(CPV_SIZE) {
        let index = best_height - cpv_start + i as u64 * CPV_JUMP_FACTOR;
        let header = headers.get(index as usize)?;
        *slot = btc_hash_least_significant_byte(header)?;
    }

    // getNumberOfUncles: the uncle count over the 32 newest blocks, saturating
    // at 255 (`Uint8.MAX_VALUE`).
    let uncle_sum: u64 = headers
        .iter()
        .take(NUMBER_OF_UNCLES)
        .map(|h| h.uncle_count)
        .sum();
    data[7] = uncle_sum.min(u8::MAX as u64) as u8;

    // getBlockBeingMinedHeight: the parent's height plus one, as a big-endian
    // 32-bit integer (Java `(int)` truncation).
    let height_being_mined = best_height.wrapping_add(1) as u32;
    data[8..12].copy_from_slice(&height_being_mined.to_be_bytes());

    Some(data)
}

/// The last byte of the BTC block hash in bitcoinj's `getBytes()` order.
///
/// bitcoinj stores a block hash reversed (`Sha256Hash.wrapReversed`), so its
/// last byte is the FIRST byte of the raw double-SHA — which is what
/// rust-bitcoin's `as_byte_array()` yields at index 0.
fn btc_hash_least_significant_byte(header: &Header) -> Option<u8> {
    use bitcoin::block::Header as BtcHeader;
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash;

    let raw = header.bitcoin_merged_mining_header.as_ref()?;
    let mut reader = &raw[..];
    let btc: BtcHeader = Decodable::consensus_decode(&mut reader).ok()?;
    let hash = btc.block_hash();
    Some(hash.to_raw_hash().as_byte_array()[0])
}

/// rskj `ForkDetectionDataRule.isValid`.
///
/// `actual` is the 12 bytes read out of the block's coinbase (see
/// `merged_mining::extract_fork_detection_data`). `rskip110_height` is
/// wasabi100.
pub fn validate<V: MainchainView + ?Sized>(
    header: &Header,
    actual: Option<[u8; 12]>,
    view: &V,
    rskip110_height: u64,
) -> Result<(), ValidationError> {
    if header.number < rskip110_height {
        return Ok(());
    }

    // rskj reads no fork-detection data from a header below 449 at all
    // (`BlockFactory` builds it with `includeForkDetectionData` false), so
    // its `hasForkDetectionDataWhereItShouldNotHave` branch never fires, and
    // it compares only above 449, not at 449 itself. Reading the coinbase
    // here instead would find twelve bytes after the tag and the hash prefix
    // -- the rest of the hash -- and refuse every early testnet and regtest
    // block.
    if header.number <= REQUIRED_BLOCKS {
        return Ok(());
    }

    let got = actual.ok_or(ValidationError::ForkDetectionDataUnreadable)?;
    let headers = view.headers_from(header.parent_hash, REQUIRED_BLOCKS);

    // hasEnoughBlocksToCalculateForkDetectionData: a short view is a rejection,
    // not a skip.
    let expected = calculate(&headers).ok_or(ValidationError::ForkDetectionDataUnreadable)?;

    if expected != got {
        return Err(ValidationError::ForkDetectionDataMismatch { expected, got });
    }
    Ok(())
}
