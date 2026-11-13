//! Shared plumbing for the offline replay diagnostics.
//!
//! Every tool here answers a question of the form "what does rustock compute
//! for block N, and how does it differ from what the chain says?" They all
//! need the same three things: stores opened the right way, the chain's rules
//! selected by network, and a diff over two unitries. Keeping that in one
//! place is why `replay_block` and `block_writes` cannot drift apart on, say,
//! which hardfork config a testnet replay runs under — a mismatch there
//! reports a divergence that is the tool's own.
//!
//! Everything opens read-only so a diagnostic can run beside a live node,
//! which is exactly when a divergence needs investigating.

#![allow(dead_code)] // Each example uses a different subset.

use anyhow::{Context, Result};
use rustock_core::config::ActivationHeights;
use rustock_core::Block;
use rustock_execution::RskHardforkConfig;
use rustock_storage::epoch_store::{EpochConfig, EpochTrieStore};
use rustock_storage::{BlockStore, CachedTrieStore};
use rustock_trie::{AccountState, NodeRef, OverlayTrieStore, TrieKeyKind, TrieNode, TrieStore};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Network ids, as passed on the command line and written in `--network-id`.
pub const MAINNET: u64 = 30;
pub const TESTNET: u64 = 31;

/// The consensus rules to replay under, with the upgrade heights headers are
/// read by.
///
/// Replaying a testnet block under mainnet rules compares against the wrong
/// activation heights, REMASC config and bridge constants. That has already
/// cost one investigation, so the selection is explicit rather than defaulted
/// inside each tool.
///
/// The node installs its network's heights before it reads a header, and so
/// does this: a header is read, and hashed, by its own network's heights, and
/// under mainnet's a testnet header from between the two chains' papyrus200,
/// or from testnet's reed810, does not decode at all. The heights can be
/// installed once per process, and the first header read installs mainnet's,
/// so call this before opening the stores.
pub fn hardfork_for(network_id: u64) -> RskHardforkConfig {
    let (heights, rules) = match network_id {
        MAINNET => (ActivationHeights::mainnet(), RskHardforkConfig::mainnet()),
        TESTNET => (ActivationHeights::testnet(), RskHardforkConfig::testnet()),
        _ => (ActivationHeights::regtest(), RskHardforkConfig::regtest()),
    };
    heights.install();
    rules
}

/// An opened, read-only view of a node's databases, positioned at the
/// executed head.
pub struct Replay {
    pub store: Arc<BlockStore>,
    /// The node's trie, read-only, behind an in-memory write overlay.
    ///
    /// Replaying a block computes a trie, and computing a trie writes nodes.
    /// Those writes land in memory and are discarded on exit, so the node's
    /// own database is only ever read.
    pub trie_store: Arc<dyn TrieStore>,
    /// Height of the executed head — replays start from the block after it.
    pub exec_number: u64,
    /// Post-state trie of the executed head.
    pub root: TrieNode,
}

impl Replay {
    /// Opens the block store and trie store read-only and resolves the
    /// executed head's state root.
    ///
    /// `trie_dir` is required for a node run with `--trie-backend epoch`,
    /// which keeps the trie outside the block database. Without it the root
    /// lookup finds nothing, and the resulting error used to say only "root
    /// node" — hence the explicit message here.
    pub fn open(data_dir: &str, trie_dir: Option<&str>) -> Result<Self> {
        let store = Arc::new(
            BlockStore::open_read_only(data_dir)
                .with_context(|| format!("opening block store at {data_dir} read-only"))?,
        );
        let (exec_hash, state_root) =
            store.exec_head()?.context("no executed head: has this node executed anything?")?;
        let exec_number = store.header(exec_hash)?.context("executed head header missing")?.number;

        let base: Arc<dyn TrieStore> = match trie_dir {
            Some(dir) => Arc::new(
                EpochTrieStore::open_read_only(dir, EpochConfig::default())
                    .with_context(|| format!("opening epoch trie at {dir} read-only"))?,
            ),
            None => Arc::new(CachedTrieStore::with_defaults(store.db().clone())),
        };
        let trie_store: Arc<dyn TrieStore> = Arc::new(OverlayTrieStore::new(base));

        let root_data = trie_store.get(state_root.as_slice()).with_context(|| {
            format!(
                "state root {state_root:?} of executed head #{exec_number} is not in the trie \
                 store — if this node runs `--trie-backend epoch`, pass its trie directory"
            )
        })?;
        let root = TrieNode::from_message(&root_data, trie_store.as_ref());

        Ok(Self { store, trie_store, exec_number, root })
    }

    /// Reads a canonical block by height.
    pub fn block(&self, number: u64) -> Result<Block> {
        let hash =
            self.store.canonical_hash(number)?.with_context(|| format!("no canonical #{number}"))?;
        let header = self.store.header(hash)?.with_context(|| format!("no header #{number}"))?;
        let (transactions, ommers) =
            self.store.body(hash)?.with_context(|| format!("no body #{number}"))?;
        Ok(Block { header, transactions, ommers })
    }

    /// Fails early when the target is at or below the executed head, where
    /// the pre-state needed to replay it has already been superseded.
    pub fn ensure_replayable(&self, number: u64) -> Result<()> {
        anyhow::ensure!(
            number > self.exec_number,
            "target #{number} is not past the executed head #{}; this tool replays \
             forward from the executed head and cannot rewind",
            self.exec_number
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hash-pruned dual walk
// ---------------------------------------------------------------------------

/// A leaf discovered during a diff: the packed trie key, the hash of its
/// value, and the value itself.
///
/// The hash is what two leaves are compared on. A value over the embedding
/// limit is stored out of line and left unloaded (`value == None`), so two
/// *different* long values both read as `None`; comparing values directly
/// would silently call them equal and hide the divergence.
pub type Leaf = (Vec<u8>, Option<[u8; 32]>, Option<Vec<u8>>);

/// Packs a path of one-bit-per-byte into the key bytes it represents.
pub fn pack(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (k, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            out[k / 8] |= 0x80 >> (k % 8);
        }
    }
    out
}

fn leaf_of(node: &TrieNode, path: &[u8]) -> Option<Leaf> {
    node.value_hash.as_ref().map(|vh| (pack(path), Some(vh.0), node.value.clone()))
}

/// Collects every leaf of a subtree, used where one side of a diff is absent.
fn collect(node: &TrieNode, prefix: &mut Vec<u8>, store: &dyn TrieStore, out: &mut Vec<Leaf>) {
    let start = prefix.len();
    prefix.extend_from_slice(node.shared_path.expand());
    if let Some(l) = leaf_of(node, prefix) {
        out.push(l);
    }
    if let Some(left) = node.left.resolve(store) {
        prefix.push(0);
        collect(&left, prefix, store, out);
        prefix.pop();
    }
    if let Some(right) = node.right.resolve(store) {
        prefix.push(1);
        collect(&right, prefix, store, out);
        prefix.pop();
    }
    prefix.truncate(start);
}

/// Walks two unitries, reporting only the leaves where they differ.
///
/// The unitrie is content-addressed, so an identical subtree is hash-identical
/// and one comparison prunes everything beneath it. Cost is therefore
/// proportional to what changed, not to the size of the state — which is what
/// makes this usable on a multi-million-leaf mainnet trie.
///
/// `sa` and `sb` may be different stores (rustock's trie against rskj's) or
/// the same store twice (a block's pre-state against its post-state).
#[allow(clippy::too_many_arguments)]
pub fn diff(
    a: &NodeRef,
    b: &NodeRef,
    aprefix: &mut Vec<u8>,
    bprefix: &mut Vec<u8>,
    sa: &dyn TrieStore,
    sb: &dyn TrieStore,
    aout: &mut Vec<Leaf>,
    bout: &mut Vec<Leaf>,
) {
    if a.get_hash(sa) == b.get_hash(sb) {
        return;
    }
    match (a.resolve(sa), b.resolve(sb)) {
        (None, Some(n)) => collect(&n, bprefix, sb, bout),
        (Some(n), None) => collect(&n, aprefix, sa, aout),
        (Some(an), Some(bn)) => {
            let astart = aprefix.len();
            let bstart = bprefix.len();
            aprefix.extend_from_slice(an.shared_path.expand());
            bprefix.extend_from_slice(bn.shared_path.expand());
            if let Some(l) = leaf_of(&an, aprefix) {
                aout.push(l);
            }
            if let Some(l) = leaf_of(&bn, bprefix) {
                bout.push(l);
            }
            aprefix.push(0);
            bprefix.push(0);
            diff(&an.left, &bn.left, aprefix, bprefix, sa, sb, aout, bout);
            aprefix.pop();
            bprefix.pop();
            aprefix.push(1);
            bprefix.push(1);
            diff(&an.right, &bn.right, aprefix, bprefix, sa, sb, aout, bout);
            aprefix.truncate(astart);
            bprefix.truncate(bstart);
        }
        // Reachable only if the two hashes differ while both sides are empty,
        // which content addressing rules out.
        (None, None) => {}
    }
}

/// Indexes diff output by key for side-by-side comparison.
pub fn index(leaves: Vec<Leaf>) -> BTreeMap<Vec<u8>, (Option<[u8; 32]>, Option<Vec<u8>>)> {
    leaves.into_iter().map(|(k, vh, v)| (k, (vh, v))).collect()
}

/// Convenience wrapper: diff two roots held in the same store.
pub fn diff_roots(
    before: &TrieNode,
    after: &TrieNode,
    store: &dyn TrieStore,
) -> (Vec<Leaf>, Vec<Leaf>) {
    let (mut a, mut b) = (Vec::new(), Vec::new());
    diff(
        &NodeRef::Node(std::sync::Arc::new(before.clone())),
        &NodeRef::Node(std::sync::Arc::new(after.clone())),
        &mut Vec::new(),
        &mut Vec::new(),
        store,
        store,
        &mut a,
        &mut b,
    );
    (a, b)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Names a raw unitrie key for human reading.
pub fn describe_key(key: &[u8]) -> String {
    match rustock_trie::classify_key(key) {
        TrieKeyKind::Account { address } => format!("account  {}", addr(&address)),
        TrieKeyKind::Code { address } => format!("code     {}", addr(&address)),
        TrieKeyKind::StoragePrefix { address } => {
            format!("marker   {} (contract storage prefix)", addr(&address))
        }
        TrieKeyKind::Storage { address, slot: Some(slot), tail } => {
            match ascii_slot_name(&tail) {
                Some(name) => format!("storage  {} slot {slot:#x} (\"{name}\")", addr(&address)),
                None => format!("storage  {} slot {slot:#x}", addr(&address)),
            }
        }
        // The tail did not re-pad to the word that was hashed, so the slot is
        // reported as stored rather than reconstructed into a false value.
        TrieKeyKind::Storage { address, slot: None, tail } => {
            format!("storage  {} slot-tail 0x{} (unrecovered)", addr(&address), hex(&tail))
        }
        TrieKeyKind::Unknown => format!("unknown  0x{}", hex(key)),
    }
}

/// rskj's precompiled contracts address storage by name, not by index: the
/// Bridge writes `DataWord.fromString("releaseTransactionSet")` and friends,
/// so the slot is the ASCII name right-aligned in a word. Recovering it turns
/// an opaque 32-byte slot in a diff into the Bridge field it actually is,
/// which is most of the work in reading a Bridge divergence.
///
/// Returns `None` unless the whole tail is printable ASCII of a plausible
/// length, so a numeric slot is never dressed up as a name.
fn ascii_slot_name(tail: &[u8]) -> Option<String> {
    // Two bytes is too short to tell a name from a small integer; a name
    // cannot exceed the word it is packed into.
    if !(3..=32).contains(&tail.len()) {
        return None;
    }
    // Printable and non-space: rskj's field names are identifiers, and
    // requiring that keeps high-entropy hashes out.
    if !tail.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    String::from_utf8(tail.to_vec()).ok()
}

fn addr(bytes: &[u8]) -> String {
    if bytes.len() == 20 {
        format!("{}", alloy_primitives::Address::from_slice(bytes))
    } else {
        // RSK short addresses (REMASC's sender is the single byte 0x00) are
        // not 20 bytes and must not be padded into a different address.
        format!("0x{} ({}-byte)", hex(bytes), bytes.len())
    }
}

fn hex(bytes: &[u8]) -> String {
    alloy_primitives::hex::encode(bytes)
}

/// Renders a leaf value in the terms of whatever the key names: accounts are
/// decoded, storage words are shown as both hex and integer, code is summarised.
pub fn describe_value(key: &[u8], value: Option<&Vec<u8>>) -> String {
    let Some(v) = value else {
        return "<absent>".to_string();
    };
    match rustock_trie::classify_key(key) {
        TrieKeyKind::Account { .. } => match AccountState::decode(v) {
            Ok(a) => format!("nonce={} balance={}", a.nonce, a.balance),
            Err(e) => format!("0x{} (undecodable account: {e})", hex(v)),
        },
        TrieKeyKind::Code { .. } => format!("{} bytes of code, 0x{}", v.len(), hex(elide(v))),
        _ if v.len() <= 32 => {
            format!("0x{} ({})", hex(v), alloy_primitives::U256::from_be_slice(v))
        }
        // Printed in full, not elided. A Bridge field is an RLP structure of a
        // few hundred bytes, and the only way to tell which of two of them is
        // right is to decode both -- a truncated prefix just says they are
        // long. `BLOCK_WRITES_ELIDE=<n>` caps it where the output is unwieldy.
        _ => format!("{} bytes, 0x{}", v.len(), hex(elide(v))),
    }
}

/// How much of an over-long value to print. Unbounded by default.
fn elide(v: &[u8]) -> &[u8] {
    match std::env::var("BLOCK_WRITES_ELIDE").ok().and_then(|n| n.parse::<usize>().ok()) {
        Some(n) if n < v.len() => &v[..n],
        _ => v,
    }
}
