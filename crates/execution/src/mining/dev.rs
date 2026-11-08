//! Mining and clock control for a development chain.
//!
//! Everything here exists to serve rskj's `evm_*` RPC namespace, which is how
//! contract test suites drive a node: mine on demand, jump the clock, snapshot
//! and roll back. None of it belongs on a node facing a real network, and the
//! RPC layer gates the whole namespace behind an explicit flag.
//!
//! # The clock
//!
//! `evm_increaseTime` moves the timestamp the *next* block will carry, and
//! every block after it, without moving the system clock. rskj keeps the same
//! offset in `MinerClock`. It is a process-wide offset here because the block
//! template is built in several places and threading a clock through all of
//! them to serve a development-only feature would be worse than one atomic.
//!
//! # Local mining
//!
//! An RSK block needs merged-mining proof of work, so "mine a block" means
//! building a Bitcoin block that commits to the RSK work hash and brute-forcing
//! its nonce until it clears the target. That is what rskj's `MinerClientImpl`
//! does, and on a development chain the target is easy enough that it lands in
//! a handful of attempts.
//!
//! On a real network's difficulty it would not, which is the honest reason
//! this cannot be misused: the loop is bounded and gives up.

use std::sync::atomic::{AtomicI64, Ordering};

/// Seconds added to wall clock when stamping a mined block.
///
/// Signed, because rskj's `increaseTime` takes a value that can in principle
/// be negative, and an offset that silently clamped would make a test that
/// went backwards pass for the wrong reason.
static TIME_OFFSET: AtomicI64 = AtomicI64::new(0);

/// Move the clock forward by `seconds` and return the new total offset, which
/// is what `evm_increaseTime` answers with.
pub fn increase_time(seconds: i64) -> i64 {
    TIME_OFFSET.fetch_add(seconds, Ordering::SeqCst) + seconds
}

/// The current offset, in seconds.
pub fn time_offset() -> i64 {
    TIME_OFFSET.load(Ordering::SeqCst)
}

/// Drop any accumulated offset. `evm_reset` returns the chain to genesis, and
/// a clock still carrying an old test's offset would leak into the next one.
pub fn reset_time() {
    TIME_OFFSET.store(0, Ordering::SeqCst);
}

/// Wall clock plus the development offset.
pub fn now_with_offset() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    now.saturating_add(time_offset()).max(0) as u64
}

/// Mine one block locally: build work, find a Bitcoin nonce that clears the
/// target, and submit it.
///
/// This is rskj's `MinerManager.mineBlock` — `minerServer.buildBlockToMine`
/// followed by `minerClient.mineBlock` — collapsed into one call, because
/// nothing here needs them separable.
///
/// `attempts` bounds the nonce search. On a development chain the target is
/// easy and a solution lands almost immediately; on a real network's
/// difficulty no bound would be enough, and giving up with an error is the
/// correct outcome rather than spinning a core forever.
pub fn mine_one(
    server: &crate::MinerServer,
    attempts: u32,
) -> Result<crate::mining::server::SubmittedBlockInfo, MineError> {
    let work = server.build_work().map_err(MineError::Work)?;
    solve_and_submit(server, &work, attempts)
}

/// The search half of [`mine_one`], over work already built: find a Bitcoin
/// nonce that clears `work.target` and submit the block.
pub fn solve_and_submit(
    server: &crate::MinerServer,
    work: &crate::mining::server::MinerWork,
    attempts: u32,
) -> Result<crate::mining::server::SubmittedBlockInfo, MineError> {
    use alloy_primitives::U256;
    use bitcoin::hashes::Hash;

    // The extra-nonce varies the coinbase, and so the merkle root, and so the
    // header -- without it every attempt at a given nonce would hash the same
    // and the search would be over a 32-bit space that might not contain a
    // solution at all.
    for extra_nonce in 0..16u64 {
        let coinbase =
            super::coinbase::build_coinbase(&work.block_hash_for_merged_mining, extra_nonce);
        for nonce in 0..attempts {
            let block = super::coinbase::build_bitcoin_block(coinbase.clone(), nonce);
            // Bitcoin compares its hash as a little-endian number, which is
            // why this is not the byte order the hash prints in.
            let hash = block.header.block_hash();
            if U256::from_le_slice(hash.as_byte_array()) <= work.target {
                return submit(server, &block);
            }
        }
    }

    Err(MineError::NoSolution { attempts })
}

/// Submit `work` closed with nonce 0 and no search at all: what rskj's
/// `TimedMinerClient.mineBlock` does under `skipPowValidation` (line 133).
///
/// Only meaningful on a chain whose merged-mining rule is off
/// (`--skip-pow-validation`); anywhere else the block fails the server's own
/// self-check before it is stored.
pub fn submit_unsolved(
    server: &crate::MinerServer,
    work: &crate::mining::server::MinerWork,
) -> Result<crate::mining::server::SubmittedBlockInfo, MineError> {
    let coinbase = super::coinbase::build_coinbase(&work.block_hash_for_merged_mining, 0);
    let block = super::coinbase::build_bitcoin_block(coinbase, 0);
    submit(server, &block)
}

fn submit(
    server: &crate::MinerServer,
    block: &bitcoin::Block,
) -> Result<crate::mining::server::SubmittedBlockInfo, MineError> {
    let mut raw = Vec::new();
    bitcoin::consensus::Encodable::consensus_encode(block, &mut raw)
        .map_err(|e| MineError::Encode(e.to_string()))?;
    server.submit_bitcoin_block(&raw).map_err(MineError::Submit)
}

#[derive(Debug)]
pub enum MineError {
    Work(crate::mining::server::SubmitError),
    Submit(crate::mining::server::SubmitError),
    Encode(String),
    NoSolution { attempts: u32 },
}

impl std::fmt::Display for MineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Work(e) => write!(f, "could not build work to mine: {e:?}"),
            Self::Submit(e) => write!(f, "the solved block was rejected: {e:?}"),
            Self::Encode(e) => write!(f, "could not encode the solved block: {e}"),
            Self::NoSolution { attempts } => write!(
                f,
                "no nonce cleared the target in {attempts} attempts per extra-nonce; \
                 this chain's difficulty is too high to mine locally"
            ),
        }
    }
}
