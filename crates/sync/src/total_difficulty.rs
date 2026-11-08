//! A block's total difficulty, once its body is held.
//!
//! rskj gives a block its parent's total difficulty plus its own difficulty and
//! its uncles' (`Block.getCumulativeDifficulty`). The uncles travel only in the
//! body, so a header from an `rsk/62` peer -- every rskj node -- can only be
//! given a lower bound when it arrives: its parent's total and its own
//! difficulty. Nothing raised that bound once the body came, so a node that
//! caught up by header-first sync carried every uncle it skipped in every total
//! above it: on mainnet, 6.9 x 10^25 short of rskj after 8,000 blocks. [`settle`]
//! makes a block's total exact once its body is held, in the order the chain
//! runs, so that each block starts from a parent whose total is exact already.
//!
//! An uncle is credited only once it passes rskj's whole uncle rule against the
//! ancestry this node holds, with every rule a trunk header faces, proof of work
//! included: the standard [`crate::uncle_guard`] holds uncles from the wire to.
//! The body check on receipt proves only that the list is the one the block's
//! header commits to, that its miner chose those uncles, not that each did the
//! work it claims. An uncle that fails is not credited, which leaves the total
//! understated, the safe direction, rather than overstated.

use alloy_primitives::{B256, U256};
use rustock_core::types::block::Block;
use rustock_core::validation::uncles::{
    AncestorSource, UnclesValidationRule, UNCLE_GENERATION_LIMIT, UNCLE_LIST_LIMIT,
};
use rustock_core::validation::HeaderVerifier;
use rustock_core::Header;
use rustock_storage::BlockStore;
use tracing::warn;

/// The ancestry the uncle rule walks, from what this node holds.
struct Held<'a> {
    store: &'a BlockStore,
}

impl Held<'_> {
    /// Whether every ancestor the rule walks is held, with the uncles it named.
    ///
    /// Asked first, because the rule reads an ancestor it cannot find as one
    /// that named no uncles, and could then pass an uncle that one had used.
    fn has_ancestry(&self, number: u64, parent: B256) -> bool {
        let floor = number.saturating_sub(UNCLE_GENERATION_LIMIT);
        let mut cursor = parent;
        loop {
            let Some(header) = self.store.header(cursor).ok().flatten() else {
                return false;
            };
            if header.number < floor {
                return true;
            }
            if held_uncles(self.store, cursor, &header).is_none() {
                return false;
            }
            if header.number == 0 {
                return true;
            }
            cursor = header.parent_hash;
        }
    }
}

impl AncestorSource for Held<'_> {
    fn header(&self, hash: B256) -> Option<Header> {
        self.store.header(hash).ok().flatten()
    }

    fn uncles_of(&self, hash: B256) -> Vec<Header> {
        // Asked only of ancestors that `has_ancestry` found held, so an empty
        // answer means the ancestor named none.
        self.header(hash)
            .and_then(|header| held_uncles(self.store, hash, &header))
            .unwrap_or_default()
    }
}

/// The uncles a held block named: from its body, or once the body is pruned,
/// from the freezer, which keeps them by height for the canonical chain.
/// `None` when neither holds them.
pub(crate) fn held_uncles(store: &BlockStore, hash: B256, header: &Header) -> Option<Vec<Header>> {
    if let Ok(Some(uncles)) = store.uncles(hash) {
        return Some(uncles);
    }
    if store.canonical_hash(header.number).ok().flatten() != Some(hash) {
        return None;
    }
    store.freezer()?.uncles(header.number).ok().flatten()
}

/// The difficulty of `uncles`, the uncles a block names, if they pass rskj's
/// whole uncle rule against the ancestry this node holds; otherwise why not.
pub(crate) fn credited_uncles(
    store: &BlockStore,
    verifier: &HeaderVerifier,
    header: &Header,
    uncles: &[Header],
) -> Result<U256, String> {
    if uncles.is_empty() {
        return Ok(U256::ZERO);
    }
    let held = Held { store };
    if !held.has_ancestry(header.number, header.parent_hash) {
        return Err("the ancestry needed to judge them is not all held".to_string());
    }
    let block = Block {
        header: header.clone(),
        transactions: Vec::new(),
        ommers: uncles.to_vec(),
    };
    UnclesValidationRule {
        store: &held,
        uncle_list_limit: UNCLE_LIST_LIMIT,
        uncle_generation_limit: UNCLE_GENERATION_LIMIT,
        header_rules: verifier.static_rules(),
        parent_rules: verifier.parent_rules(),
        fork_detection: None,
    }
    .validate(&block)
    .map_err(|e| e.to_string())?;
    Ok(uncles.iter().fold(U256::ZERO, |sum, uncle| {
        sum.saturating_add(uncle.difficulty)
    }))
}

/// Give a block whose uncles are `uncles` the total difficulty rskj gives it:
/// its parent's total, its own difficulty, and its uncles' once they pass the
/// rule. Written only where it differs from the stored total.
///
/// The parent's total must be exact already, which holds when blocks are
/// settled in the order the chain runs, from one that is. `None` when the
/// parent has no total to start from.
pub(crate) fn settle(
    store: &BlockStore,
    verifier: &HeaderVerifier,
    hash: B256,
    header: &Header,
    uncles: &[Header],
) -> anyhow::Result<Option<U256>> {
    let Some(parent) = store.total_difficulty(header.parent_hash)? else {
        return Ok(None);
    };
    let credited = credited_uncles(store, verifier, header, uncles).unwrap_or_else(|why| {
        warn!(
            target: "rustock::sync",
            "Block #{} ({:?}): its uncles are not credited with their difficulty: {why}",
            header.number,
            hash
        );
        U256::ZERO
    });
    let total = parent
        .saturating_add(header.difficulty)
        .saturating_add(credited);
    if store.total_difficulty(hash)? != Some(total) {
        store.put_total_difficulty(hash, total)?;
    }
    Ok(Some(total))
}
