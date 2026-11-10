//! Which peers hold which blocks: rskj's `BlockNodeInformation`.
//!
//! A new block is announced only to the peers not known to hold it already
//! (`MessageVisitor.relayBlock`), so this node remembers, for the blocks it
//! heard of lately, the peers it knows hold each one: the peer that announced
//! it (`NodeBlockProcessor.processNewBlockHashesMessage`), the peer that sent
//! it (`BlockSyncService.preprocessBlock`) and each peer that asked for it
//! (`NodeBlockProcessor.processGetBlock`).
//!
//! Bounded as rskj bounds it: the 1,000 blocks touched last, the least recently
//! touched dropped first. A block's peers are not bounded, because there are
//! few peers beside blocks.

use alloy_primitives::{B256, B512};
use lru::LruCache;
use std::collections::HashSet;
use std::num::NonZeroUsize;

/// rskj `BlockNodeInformation()`: `this(1000)`.
pub(crate) const MAX_BLOCKS: usize = 1000;

pub(crate) struct BlockNodes {
    /// rskj `nodesByBlock`: a `LinkedHashMap` in access order, so a read
    /// touches a block as a write does.
    nodes_by_block: LruCache<B256, HashSet<B512>>,
}

impl BlockNodes {
    pub(crate) fn new() -> Self {
        Self::with_capacity(MAX_BLOCKS)
    }

    pub(crate) fn with_capacity(max_blocks: usize) -> Self {
        Self {
            nodes_by_block: LruCache::new(
                NonZeroUsize::new(max_blocks.max(1)).expect("at least one block"),
            ),
        }
    }

    /// rskj `addBlockToNode`: `node` holds `block`.
    pub(crate) fn add(&mut self, block: B256, node: B512) {
        match self.nodes_by_block.get_mut(&block) {
            Some(nodes) => {
                nodes.insert(node);
            }
            None => {
                self.nodes_by_block.put(block, HashSet::from([node]));
            }
        }
    }

    /// rskj `getNodesByBlock`: the peers known to hold `block`, and none for a
    /// block not remembered.
    pub(crate) fn nodes(&mut self, block: B256) -> HashSet<B512> {
        self.nodes_by_block.get(&block).cloned().unwrap_or_default()
    }
}

impl Default for BlockNodes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    fn node(n: u8) -> B512 {
        B512::repeat_byte(n)
    }

    #[test]
    fn a_block_remembers_every_peer_that_holds_it() {
        let mut nodes = BlockNodes::new();
        nodes.add(block(1), node(1));
        nodes.add(block(1), node(2));
        nodes.add(block(1), node(1));
        nodes.add(block(2), node(3));
        assert_eq!(nodes.nodes(block(1)), HashSet::from([node(1), node(2)]));
        assert_eq!(nodes.nodes(block(2)), HashSet::from([node(3)]));
        assert!(
            nodes.nodes(block(3)).is_empty(),
            "a block never heard of has no peers"
        );
    }

    /// rskj keeps 1,000 blocks, and drops the one touched longest ago, a read
    /// counting as a touch (`LinkedHashMap` in access order).
    #[test]
    fn the_block_touched_longest_ago_is_dropped_first() {
        let mut nodes = BlockNodes::with_capacity(2);
        nodes.add(block(1), node(1));
        nodes.add(block(2), node(2));
        // Read the first, so the second is now the one touched longest ago.
        assert!(!nodes.nodes(block(1)).is_empty());
        nodes.add(block(3), node(3));
        assert_eq!(nodes.nodes(block(1)), HashSet::from([node(1)]));
        assert!(
            nodes.nodes(block(2)).is_empty(),
            "the block touched longest ago went"
        );
        assert_eq!(nodes.nodes(block(3)), HashSet::from([node(3)]));
    }

    /// rskj's own figure, not the constant: the thousand-and-first block
    /// touched pushes out the first, and only it.
    #[test]
    fn rskj_keeps_a_thousand_blocks() {
        let mut nodes = BlockNodes::new();
        for n in 0..=1_000u64 {
            nodes.add(B256::from(alloy_primitives::U256::from(n)), node(1));
        }
        assert!(nodes
            .nodes(B256::from(alloy_primitives::U256::ZERO))
            .is_empty());
        assert!(!nodes
            .nodes(B256::from(alloy_primitives::U256::from(1u64)))
            .is_empty());
    }
}
