//! What did rustock write while executing one block?
//!
//! Replays canonical blocks from the executed head up to `<number>`, then
//! diffs the block's pre-state trie against its post-state trie and prints
//! every leaf the block changed — decoded into account, code or storage, with
//! the address and slot in the clear.
//!
//! This is the counterpart to `diff_state`. `diff_state` answers "which leaves
//! disagree with rskj", but it needs rskj's own LevelDB; this answers "which
//! leaves did *we* write", which needs nothing but our database. On testnet,
//! where no rskj snapshot is at hand, each reported write can then be checked
//! against any public node over `eth_getStorageAt` / `eth_getBalance` — which
//! is the difference between localising a divergence and guessing at it.
//!
//! The diff is hash-pruned, so it costs what the block changed, not what the
//! state contains. Everything opens read-only, so this is safe to run beside a
//! syncing node.
//!
//! ```text
//! cargo run -p rustock-cli --release --example block_writes -- \
//!     <data-dir> <number> [network-id] [trie-dir]
//!
//!   network-id  30 mainnet (default), 31 testnet, anything else regtest
//!   trie-dir    required for a node run with `--trie-backend epoch`
//! ```

#[path = "support/mod.rs"]
mod support;

use anyhow::Result;
use rustock_execution::BlockProcessor;
use support::Replay;

const USAGE: &str = "usage: block_writes <data-dir> <number> [network-id] [trie-dir]";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?;
    let number: u64 = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?.parse()?;
    let network_id: u64 = args.next().map(|a| a.parse()).transpose()?.unwrap_or(support::MAINNET);
    let trie_dir = args.next();
    // Before the stores open: headers are read by the network's heights.
    let hardfork_cfg = support::hardfork_for(network_id);

    let replay = Replay::open(&data_dir, trie_dir.as_deref())?;
    replay.ensure_replayable(number)?;

    eprintln!(
        "replaying #{}..=#{number} on network-id {network_id} (chain_id {})",
        replay.exec_number + 1,
        hardfork_cfg.chain_id
    );
    let processor = BlockProcessor::new(hardfork_cfg, replay.store.clone());

    let mut root = replay.root.clone();
    for n in replay.exec_number + 1..=number {
        let block = replay.block(n)?;
        // The pre-state is the previous block's post-state; keep it so the
        // target block's writes can be read off as a diff.
        let pre = root.clone();
        let processed = processor.execute_block(&block, &root, replay.trie_store.clone())?;

        if n < number {
            if processed.state_root_hash != block.header.state_root {
                // Writes reported below would be relative to an already-wrong
                // state, so say so rather than let the report look authoritative.
                eprintln!(
                    "warning: block #{n} already diverges (computed {:?}, header {:?}); \
                     the report for #{number} is relative to that state",
                    processed.state_root_hash, block.header.state_root
                );
            }
            root = processed.new_state_root;
            continue;
        }

        println!("=== block #{n} ===");
        println!("  transactions         {}", block.transactions.len());
        println!("  header   state root  {:?}", block.header.state_root);
        println!("  computed state root  {:?}", processed.state_root_hash);
        println!(
            "  state verdict        {}",
            if processed.state_root_hash == block.header.state_root {
                "MATCH"
            } else {
                "DIVERGES"
            }
        );
        println!(
            "  receipts root        {}",
            if processed.receipts_root == block.header.receipts_root {
                "match"
            } else {
                "DIVERGES"
            }
        );
        println!("  gas used             {} (header {})", processed.gas_used, block.header.gas_used);

        let (pre_leaves, post_leaves) =
            support::diff_roots(&pre, &processed.new_state_root, replay.trie_store.as_ref());
        let before = support::index(pre_leaves);
        let after = support::index(post_leaves);

        let mut keys: Vec<&Vec<u8>> = before.keys().chain(after.keys()).collect();
        keys.sort();
        keys.dedup();
        // A leaf can surface in the walk without having changed, because the
        // diff descends on subtree hashes, not on leaves. Compare on the
        // value hash, which is defined even for out-of-line long values.
        let changed: Vec<&Vec<u8>> = keys
            .into_iter()
            .filter(|k| before.get(*k).map(|e| e.0) != after.get(*k).map(|e| e.0))
            .collect();

        println!("\n  {} leaf/leaves written:", changed.len());
        for k in changed {
            let from = before.get(k).and_then(|e| e.1.as_ref());
            let to = after.get(k).and_then(|e| e.1.as_ref());
            println!("    {}", support::describe_key(k));
            println!("      key  0x{}", alloy_primitives::hex::encode(k));
            println!("      from {}", support::describe_value(k, from));
            println!("      to   {}", support::describe_value(k, to));
        }
    }
    Ok(())
}
