//! Does this rskj database still hold the state for a given block?
//!
//! **rskj stores only.** This opens the default RocksDB column family, which
//! is where rskj's flat unitrie keeps its nodes. Our own trie stores — a
//! scratch trie, a segbuild chunk's `sealed` directory — use `trie_nodes`
//! instead, so pointing this at one reports ABSENT for every hash whatever
//! it holds. That has already been mistaken for a real result once. Use
//! `trie_probe` for a rustock-format store.
//!
//! Answers the question that decides whether a historical range can be
//! verified at all: an archival rskj keeps every trie node ever written, a
//! pruned one keeps only state near its head. Re-executing block N needs the
//! trie at N-1, so a pruned snapshot can verify only its own neighbourhood.
//!
//! Resolves each root hash in rskj's unitrie LevelDB and reports whether it is
//! present, with the node's shape as corroboration that it is a real trie node
//! and not an unrelated entry that happens to collide.
//!
//! Read-only: opens the database without taking its lock, so it is safe
//! against a snapshot an import is reading at the same time.
//!
//! ```text
//! rskj_root_probe <unitrie-leveldb-dir> <root-hash-hex>...
//! ```

use rocksdb::{DB, Options};
use rustock_trie::{NodeRef, TrieNode, TrieStore};

struct LevelDbTrieStore {
    db: DB,
}

impl TrieStore for LevelDbTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten()
    }
    fn put(&self, _key: &[u8], _value: &[u8]) {}
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: rskj_root_probe <unitrie-dir> <root-hash>...");
    let roots: Vec<String> = args.collect();
    anyhow::ensure!(!roots.is_empty(), "give at least one root hash");

    let mut opts = Options::default();
    let mut bbt = rocksdb::BlockBasedOptions::default();
    bbt.set_block_cache(&rocksdb::Cache::new_lru_cache(256 * 1024 * 1024));
    opts.set_block_based_table_factory(&bbt);
    let db = DB::open_for_read_only(&opts, &dir, false)?;
    let store = LevelDbTrieStore { db };

    let mut present = 0usize;
    for r in &roots {
        let hash = alloy_primitives::hex::decode(r.trim_start_matches("0x"))?;
        match store.get(&hash) {
            None => println!("{r}  ABSENT"),
            Some(bytes) => {
                present += 1;
                let node = TrieNode::from_message(&bytes, &store);
                // Resolving one level down distinguishes a real root from an
                // entry that merely exists: a root with unresolvable children
                // is a database that has been pruned around it.
                let children = [&node.left, &node.right]
                    .iter()
                    .filter(|c| matches!(c, NodeRef::Hash(_) | NodeRef::Node(_)))
                    .count();
                let resolvable = [&node.left, &node.right]
                    .iter()
                    .filter(|c| c.resolve(&store).is_some())
                    .count();
                println!(
                    "{r}  present ({} byte message, {children} child ref(s), {resolvable} resolvable)",
                    bytes.len()
                );
            }
        }
    }
    println!("\n{present}/{} root(s) present", roots.len());
    Ok(())
}
