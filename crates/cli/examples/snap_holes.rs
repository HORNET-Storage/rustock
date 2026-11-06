//! Where are the holes in a downloaded state?
//!
//! Walks the stored trie under a state root in traversal order -- the order
//! snapshot chunks tile -- and reports every subtree that a stored node
//! references but the store does not hold: where it sits in offset space and
//! how large it is. A download that skipped the same part of every cell shows
//! up as holes at the same place in each cell, which is what `--grid` and
//! `--served` test: how much of the missing space falls past the first
//! `served` bytes of a `grid`-sized cell.
//!
//! A missing child's size is not read from the child, which is the thing that
//! is missing, but from its parent: `children_size` commits to both children
//! together, so with one child present the other's size is the difference.
//! With both missing only the pair's span is known, and the hole is reported
//! as one.
//!
//! Opens the trie read-only, so it is safe beside a running node -- with the
//! read-only caveat that writes still in the node's memtables are not seen.
//!
//! Usage: snap_holes <data-dir> <block | 0xSTATE_ROOT> [limit-bytes] [grid] [served]

use alloy_primitives::B256;
use rustock_storage::epoch_store::{EpochConfig, EpochTrieStore};
use rustock_storage::BlockStore;
use rustock_trie::snapshot::{stream_size, total_size};
use rustock_trie::{NodeRef, TrieNode, TrieStore};
use std::sync::Arc;
use std::time::Instant;

struct Holes {
    limit: u64,
    /// Start, end, and whether the end is exact (one child missing) or the
    /// span of a pair (both missing).
    found: Vec<(u64, u64, bool)>,
    missing_bytes: u64,
    present_nodes: u64,
    present_bytes: u64,
}

impl Holes {
    fn hole(&mut self, start: u64, end: u64, exact: bool) {
        self.missing_bytes += end - start;
        self.found.push((start, end, exact));
    }
}

/// A child stored as its own entry: present, missing, or not a separate entry.
enum Child {
    None,
    Embedded(u64),
    Present(Arc<TrieNode>, u64),
    Missing,
}

fn child(r: &NodeRef, store: &dyn TrieStore) -> Child {
    match r {
        NodeRef::Empty => Child::None,
        // Read from a store, an embedded child is parsed in place and a
        // separate one is a hash; nothing else reaches here.
        NodeRef::Node(n) => Child::Embedded(total_size(n, store)),
        NodeRef::Hash(_) => match r.resolve(store) {
            Some(n) => {
                let size = total_size(&n, store);
                Child::Present(n, size)
            }
            None => Child::Missing,
        },
    }
}

fn walk(node: &TrieNode, start: u64, store: &dyn TrieStore, h: &mut Holes) {
    if start >= h.limit {
        return;
    }
    let here = stream_size(node, store);
    let left = child(&node.left, store);
    let right = child(&node.right, store);

    let embedded: u64 = [&left, &right]
        .iter()
        .map(|c| if let Child::Embedded(s) = c { *s } else { 0 })
        .sum();
    let separate = |c: &Child| match c {
        Child::Present(_, s) => Some(*s),
        Child::Missing => None,
        _ => Some(0),
    };
    // children_size = separate left + separate right + embedded.
    let pair = node.children_size.saturating_sub(embedded);
    let (lsize, rsize) = match (separate(&left), separate(&right)) {
        (Some(l), Some(r)) => (l, r),
        (None, Some(r)) => (pair.saturating_sub(r), r),
        (Some(l), None) => (l, pair.saturating_sub(l)),
        (None, None) => {
            h.present_nodes += 1;
            h.present_bytes += here;
            // Only the pair's span is known; this node's own entry sits
            // somewhere inside it.
            h.hole(start, start + pair + here, false);
            return;
        }
    };

    match left {
        Child::Present(n, _) => walk(&n, start, store, h),
        Child::Missing => h.hole(start, start + lsize, true),
        _ => {}
    }
    let at = start + lsize;
    if at < h.limit {
        h.present_nodes += 1;
        h.present_bytes += here;
    }
    let rstart = at + here;
    match right {
        Child::Present(n, _) => walk(&n, rstart, store, h),
        Child::Missing => {
            if rstart < h.limit {
                h.hole(rstart, rstart + rsize, true)
            }
        }
        _ => {}
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: snap_holes <data-dir> <block | 0xSTATE_ROOT> [limit-bytes] [grid] [served]");
        std::process::exit(2);
    }
    let dir = &a[1];
    let limit: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(20_000_000);
    let grid: u64 = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let served: u64 = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(50 * 1024);

    let root_hash: B256 = if let Some(hex) = a[2].strip_prefix("0x") {
        hex.parse()?
    } else {
        let number: u64 = a[2].parse()?;
        let blocks = BlockStore::open_read_only(dir)?;
        let hash = blocks
            .canonical_hash(number)?
            .ok_or_else(|| anyhow::anyhow!("no canonical block at #{number}"))?;
        let header = blocks
            .header(hash)?
            .ok_or_else(|| anyhow::anyhow!("no header for #{number}"))?;
        header.state_root
    };

    let trie_dir = std::env::var("RUSTOCK_TRIE_DIR").unwrap_or_else(|_| format!("{dir}/trie-epochs"));
    let store = EpochTrieStore::open_read_only(&trie_dir, EpochConfig::default())?;
    let message = store
        .get(root_hash.as_slice())
        .ok_or_else(|| anyhow::anyhow!("state root {root_hash:?} is not in the store"))?;
    let root = TrieNode::try_from_message(&message, &store)
        .ok_or_else(|| anyhow::anyhow!("the state root does not parse"))?;
    let total = total_size(&root, &store);

    let started = Instant::now();
    let mut h = Holes {
        limit: limit.min(total),
        found: Vec::new(),
        missing_bytes: 0,
        present_nodes: 0,
        present_bytes: 0,
    };
    // A trie is hundreds of levels deep at most, but give the recursion room.
    let h = std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn_scoped(s, || {
                walk(&root, 0, &store, &mut h);
                h
            })
            .expect("spawn")
            .join()
            .expect("walk")
    });

    println!("state root {root_hash:?}, {total} bytes; walked offsets 0..{} in {:?}", h.limit, started.elapsed());
    println!(
        "present: {} nodes, {} bytes of entries; missing: {} subtree(s), {} bytes ({:.1}% of the span walked)",
        h.present_nodes,
        h.present_bytes,
        h.found.len(),
        h.missing_bytes,
        h.missing_bytes as f64 * 100.0 / h.limit.max(1) as f64
    );

    // How much of the missing space lies past the first `served` bytes of a
    // cell, the part a server serving `served` per request never sends.
    let mut unserved = 0u64;
    for &(s, e, _) in &h.found {
        let mut x = s;
        while x < e {
            let cell = x / grid * grid;
            let next = (cell + grid).min(e);
            let gap_from = (cell + served).max(x);
            if gap_from < next {
                unserved += next - gap_from;
            }
            x = next;
        }
    }
    println!(
        "of the missing bytes, {:.1}% lie past the first {served} bytes of a {grid}-byte cell \
         (a random hole would put {:.1}% there)",
        unserved as f64 * 100.0 / h.missing_bytes.max(1) as f64,
        (grid.saturating_sub(served)) as f64 * 100.0 / grid as f64
    );
    println!();
    println!("{:>14} {:>14} {:>9} {:>8} {:>8}  exact", "start", "end", "bytes", "start%g", "end%g");
    for &(s, e, exact) in h.found.iter().take(40) {
        println!("{s:>14} {e:>14} {:>9} {:>8} {:>8}  {exact}", e - s, s % grid, e % grid);
    }
    Ok(())
}
