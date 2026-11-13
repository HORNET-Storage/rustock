//! Localize a post-wasabi state-root divergence to the exact diverging trie
//! leaves. Replays canonical blocks from the executed head up to `<number>`
//! in memory (computing rustock's — possibly wrong — post-state trie), then
//! diffs it against rskj's own unitrie for the *header's* state root, read
//! directly from rskj's LevelDB. The dual walk descends only where the two
//! tries' subtree hashes differ, so it visits a handful of nodes and finishes
//! instantly even on a multi-million-leaf state.
//!
//! Requires an rskj database synced past the block. Without one, use
//! `block_writes`, which reports what rustock wrote using only our own data.
//!
//! ```text
//! cargo run -p rustock-cli --release --example diff_state -- \
//!     <rustock-data-dir> <number> <rskj-unitrie-leveldb-dir> [network-id] [trie-dir]
//!
//!   network-id  30 mainnet (default), 31 testnet, anything else regtest
//!   trie-dir    required for a node run with `--trie-backend epoch`
//! ```

#[path = "support/mod.rs"]
mod support;

use anyhow::{Context, Result};
use rocksdb::{DB, Options};
use rustock_execution::BlockProcessor;
use rustock_trie::{NodeRef, TrieNode, TrieStore};
use support::Replay;

const USAGE: &str =
    "usage: diff_state <data-dir> <number> <rskj-unitrie-dir> [network-id] [trie-dir]";

struct LevelDbTrieStore {
    db: DB,
}

impl TrieStore for LevelDbTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten()
    }
    fn put(&self, _key: &[u8], _value: &[u8]) {}
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?;
    let number: u64 = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?.parse()?;
    let rskj_dir = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?;
    let network_id: u64 = args.next().map(|a| a.parse()).transpose()?.unwrap_or(support::MAINNET);
    let trie_dir = args.next();
    // Before the stores open: headers are read by the network's heights.
    let hardfork_cfg = support::hardfork_for(network_id);

    // --- rustock side: replay to <number>, get the computed post-state trie ---
    let replay = Replay::open(&data_dir, trie_dir.as_deref())?;
    replay.ensure_replayable(number)?;

    eprintln!("replaying on network-id {network_id} (chain_id {})", hardfork_cfg.chain_id);
    let processor = BlockProcessor::new(hardfork_cfg, replay.store.clone());

    let mut root = replay.root.clone();
    let mut header_state_root = None;
    for n in replay.exec_number + 1..=number {
        let block = replay.block(n)?;
        let processed = processor.execute_block(&block, &root, replay.trie_store.clone())?;
        root = processed.new_state_root;
        if n == number {
            header_state_root = Some(block.header.state_root);
            eprintln!(
                "rustock computed root = {:?}\nheader   (rskj) root = {:?}",
                processed.state_root_hash, block.header.state_root
            );
        }
    }
    let header_state_root = header_state_root.expect("loop runs at least once");

    // --- rskj side: open the unitrie LevelDB, resolve the header's root ---
    let mut opts = Options::default();
    let mut bbt = rocksdb::BlockBasedOptions::default();
    bbt.set_block_cache(&rocksdb::Cache::new_lru_cache(1024 * 1024 * 1024));
    opts.set_block_based_table_factory(&bbt);
    let rskj_db = DB::open_for_read_only(&opts, &rskj_dir, false)?;
    let rskj_store = LevelDbTrieStore { db: rskj_db };
    let rskj_root_data = rskj_store
        .get(header_state_root.as_slice())
        .context("header state root not in rskj unitrie db (is rskj synced past this block?)")?;
    let rskj_root = TrieNode::from_message(&rskj_root_data, &rskj_store);

    // --- hash-pruned dual walk ---
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    support::diff(
        &NodeRef::Node(std::sync::Arc::new(root)),
        &NodeRef::Node(std::sync::Arc::new(rskj_root)),
        &mut Vec::new(),
        &mut Vec::new(),
        replay.trie_store.as_ref(),
        &rskj_store,
        &mut ours,
        &mut theirs,
    );

    let (nours, ntheirs) = (ours.len(), theirs.len());
    let amap = support::index(ours);
    let bmap = support::index(theirs);
    let mut keys: Vec<&Vec<u8>> = amap.keys().chain(bmap.keys()).collect();
    keys.sort();
    keys.dedup();

    let mut ndiff = 0;
    for k in keys {
        let a = amap.get(k);
        let b = bmap.get(k);
        // Compared on the value hash: a long value is stored out of line and
        // left unloaded, so comparing the values themselves would read two
        // different long values as equal.
        if a.map(|e| e.0) == b.map(|e| e.0) {
            continue;
        }
        ndiff += 1;
        // Decoded, so a diverging leaf names the account or storage slot
        // rather than leaving a 44-byte key to be deciphered by hand.
        println!("{}", support::describe_key(k));
        println!("  key    0x{}", alloy_primitives::hex::encode(k));
        println!("  rustock: {}", support::describe_value(k, a.and_then(|e| e.1.as_ref())));
        println!("  rskj   : {}", support::describe_value(k, b.and_then(|e| e.1.as_ref())));
    }
    eprintln!("\n{ndiff} diverging leaves (rustock {nours} / rskj {ntheirs} collected)");
    Ok(())
}
