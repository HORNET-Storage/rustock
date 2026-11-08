//! Putting uncles through the full consensus rule on a node that has no bodies.
//!
//! `HeaderWithUncles` (RSKIP-698) hands a header-only client the uncle headers
//! a block references, and their difficulties count toward the chain's work.
//! Crediting that work means deciding the uncles are admissible, and
//! `rustock_core::validation::uncles` already says what admissible means --
//! rskj's `BlockUnclesValidationRule`, every rule of it.
//!
//! That rule needs two things from a store: the header behind a hash, and the
//! **uncles of a stored block**. A node syncing headers has the first and not
//! the second: uncle headers live in bodies, and it has no bodies. So it would
//! be stuck checking a fraction of the rules -- which is how a miner gets work
//! credited that it never did.
//!
//! [`UncleGuard`] supplies the missing half from what the wire already
//! delivered. Every `HeaderWithUncles` that passes carries its block's uncle
//! list, so the client keeps those lists for as long as the rule can still
//! refer to them, and answers `uncles_of` from that.
//!
//! # Why a window is enough
//!
//! Consensus lets a block reference an uncle only within
//! [`UNCLE_GENERATION_LIMIT`] generations of it, and `used_uncles` walks no
//! further back than that from the block being judged. Nothing older can
//! affect the verdict, so nothing older is kept. The ledger is bounded by the
//! rule it serves rather than by the length of the chain.
//!
//! # What happens when it cannot decide
//!
//! It refuses. If an ancestor's header or uncle list is missing -- a skeleton
//! chunk that has not landed, a restart that emptied the window -- the rule
//! would run against an incomplete ancestry and could miss a reuse. So the
//! caller credits no uncle difficulty for that block. The total is then a
//! lower bound, which refuses a peer claiming too much rather than admitting
//! one.

use alloy_primitives::B256;
use rustock_core::validation::uncles::{
    AncestorSource, UnclesValidationRule, UNCLE_GENERATION_LIMIT, UNCLE_LIST_LIMIT,
};
use rustock_core::validation::HeaderVerifier;
use rustock_core::Header;
use rustock_storage::BlockStore;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Heights kept beyond the generation limit.
///
/// `used_uncles` walks back `UNCLE_GENERATION_LIMIT` from the block being
/// judged, and blocks do not always arrive in order, so the window holds more
/// than the rule strictly reaches for. Cheap: a handful of hashes a height.
const SLACK: u64 = 2 * UNCLE_GENERATION_LIMIT;

/// The uncle lists a header-only client has been shown, kept for as long as the
/// uncle rule can still refer to them.
#[derive(Debug, Default)]
pub struct UncleGuard {
    /// Uncle headers by the hash of the block that referenced them.
    by_block: HashMap<B256, Vec<Header>>,
    /// The referencing headers themselves.
    ///
    /// Kept because the ancestry has to be walkable *before* the batch being
    /// judged is written to the store -- the difficulty is decided on arrival,
    /// and the store does not have these blocks yet. Without it the walk stops
    /// at the first header of the current batch and the rule refuses every
    /// honest uncle in it.
    headers: HashMap<B256, Header>,
    /// The same hashes by height, so the window can be pruned.
    by_height: BTreeMap<u64, Vec<B256>>,
}

impl UncleGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember what a block referenced, and forget what the rule can no
    /// longer reach.
    pub fn record(&mut self, header: &Header, uncles: Vec<Header>) {
        let block_hash = header.hash();
        let number = header.number;
        self.by_block.insert(block_hash, uncles);
        self.headers.insert(block_hash, header.clone());
        self.by_height.entry(number).or_default().push(block_hash);

        let floor = number.saturating_sub(SLACK);
        while let Some((&h, _)) = self.by_height.iter().next() {
            if h >= floor {
                break;
            }
            if let Some(hashes) = self.by_height.remove(&h) {
                for hash in hashes {
                    self.by_block.remove(&hash);
                    self.headers.remove(&hash);
                }
            }
        }
    }

    /// Whether the window still holds every ancestor the rule will walk.
    ///
    /// Asked before judging, because the rule cannot tell "this ancestor
    /// referenced no uncles" from "this ancestor is not in the window", and
    /// the second must not be read as the first.
    fn ancestry_is_complete(&self, store: &BlockStore, number: u64, parent: B256) -> bool {
        let floor = number.saturating_sub(UNCLE_GENERATION_LIMIT);
        let mut cursor = parent;
        loop {
            let Some(header) = self.look_up(store, cursor) else { return false };
            if header.number < floor {
                return true;
            }
            if header.number == 0 {
                return true;
            }
            if !self.by_block.contains_key(&cursor) {
                return false;
            }
            cursor = header.parent_hash;
        }
    }

    /// A header from the window if it is there, otherwise from the store.
    ///
    /// The window first, because it holds the blocks of the batch being
    /// judged, which the store has not been given yet.
    fn look_up(&self, store: &BlockStore, hash: B256) -> Option<Header> {
        self.headers
            .get(&hash)
            .cloned()
            .or_else(|| store.header(hash).ok().flatten())
    }

    /// Whether this block's uncles may be credited with their difficulty.
    ///
    /// Runs rskj's whole `BlockUnclesValidationRule`: the list limit, the
    /// generation limit, no repeats, no ancestor, nothing already used by an
    /// ancestor, a parent that is itself an ancestor, and every per-header and
    /// parent-relative rule a trunk header faces -- proof of work included.
    ///
    /// Returns the reason when it refuses, for the caller to log.
    pub fn uncles_are_admissible(
        &self,
        store: &Arc<BlockStore>,
        verifier: &HeaderVerifier,
        header: &Header,
        uncles: &[Header],
    ) -> Result<(), String> {
        if uncles.is_empty() {
            return Ok(());
        }
        if uncles.len() as u64 != header.uncle_count {
            return Err(format!(
                "header says {} uncle(s) but {} came with it",
                header.uncle_count,
                uncles.len()
            ));
        }
        if !self.ancestry_is_complete(store, header.number, header.parent_hash) {
            return Err(
                "the ancestry needed to judge them is not all here yet".to_string()
            );
        }

        let source = GuardedAncestors { store: store.clone(), guard: self };
        let rule = UnclesValidationRule {
            store: &source,
            uncle_list_limit: UNCLE_LIST_LIMIT,
            uncle_generation_limit: UNCLE_GENERATION_LIMIT,
            header_rules: verifier.static_rules(),
            parent_rules: verifier.parent_rules(),
            fork_detection: None,
        };
        let block = rustock_core::types::block::Block {
            header: header.clone(),
            transactions: Vec::new(),
            ommers: uncles.to_vec(),
        };
        rule.validate(&block).map_err(|e| e.to_string())
    }
}

/// The store for headers, the guard for uncle lists.
struct GuardedAncestors<'a> {
    store: Arc<BlockStore>,
    guard: &'a UncleGuard,
}

impl AncestorSource for GuardedAncestors<'_> {
    fn header(&self, hash: B256) -> Option<Header> {
        self.guard.look_up(&self.store, hash)
    }

    fn uncles_of(&self, hash: B256) -> Vec<Header> {
        // Only ever consulted for ancestors inside the window, which
        // `ancestry_is_complete` has already confirmed are present. An empty
        // answer here therefore means "referenced none", not "do not know".
        self.guard.by_block.get(&hash).cloned().unwrap_or_default()
    }
}
