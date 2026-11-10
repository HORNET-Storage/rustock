//! Is this node hash in this rustock-format trie store?
//!
//! `rskj_root_probe` answers the same question for rskj's flat LevelDB, where
//! nodes sit in the default column family. Our own stores -- a scratch trie, a
//! segbuild chunk's `sealed` directory -- key them in `trie_nodes` instead, so
//! probing one with that tool opens the wrong column family and reports
//! ABSENT for everything. That failure is indistinguishable from a real miss,
//! which is exactly the kind of answer worth not getting wrong.
//!
//! Usage: trie_probe <store-dir> <0xhash>...

use rustock_storage::RocksDbTrieStore;
use rustock_trie::{NodeRef, TrieNode, TrieStore};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().ok_or_else(|| anyhow::anyhow!("usage: trie_probe <store-dir> <0xhash>..."))?;
    let hashes: Vec<String> = args.collect();
    anyhow::ensure!(!hashes.is_empty(), "give at least one hash");

    let store = RocksDbTrieStore::open_read_only(&dir)
        .map_err(|e| anyhow::anyhow!("opening {dir} read-only: {e}"))?;

    let mut present = 0usize;
    for h in &hashes {
        let raw = alloy_primitives::hex::decode(h.trim_start_matches("0x"))?;
        match store.get(&raw) {
            None => println!("{h}  ABSENT"),
            Some(bytes) => {
                present += 1;
                let node = TrieNode::from_message(&bytes, &store);
                // A node whose children cannot be resolved is a store pruned
                // around it, which is not the same as holding the subtree.
                let refs = [&node.left, &node.right]
                    .iter()
                    .filter(|c| matches!(c, NodeRef::Hash(_) | NodeRef::Node(_)))
                    .count();
                let resolvable = [&node.left, &node.right]
                    .iter()
                    .filter(|c| c.resolve(&store).is_some())
                    .count();
                println!("{h}  PRESENT  {} byte(s), {refs} child ref(s), {resolvable} resolvable", bytes.len());
            }
        }
    }
    println!("\n{present}/{} present", hashes.len());
    Ok(())
}
