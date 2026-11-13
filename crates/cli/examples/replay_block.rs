//! Re-execute canonical blocks from the executed head up to a target block
//! (in memory, nothing persisted) and report the target's per-transaction
//! results, logs, and computed state/receipts roots vs the header.
//! Deterministic, offline diagnostic for gas/state/receipts divergences.
//!
//! ```text
//! cargo run -p rustock-cli --release --example replay_block -- \
//!     <data-dir> <number> [network-id] [trie-dir]
//!
//!   network-id  30 mainnet (default), 31 testnet, anything else regtest
//!   trie-dir    required for a node run with `--trie-backend epoch`
//!
//! env:
//!   RUSTOCK_TRACE_TARGET_OPS=1  trace every opcode of the target block
//! ```
//!
//! Opens read-only, so it runs beside a live node.
//!
//! When the roots diverge, `block_writes` on the same block lists the leaves
//! that changed, which is usually the next question.

#[path = "support/mod.rs"]
mod support;

use anyhow::Result;
use rustock_execution::BlockProcessor;
use support::Replay;

const USAGE: &str = "usage: replay_block <data-dir> <number> [network-id] [trie-dir]";

fn main() -> Result<()> {
    // Frame tracing is read once by a LazyLock; set before any execution.
    unsafe { std::env::set_var("RUSTOCK_TRACE_FRAMES", "1") };
    tracing_subscriber::fmt()
        .with_env_filter("rustock_execution=debug")
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let data_dir = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?;
    let number: u64 = args.next().ok_or_else(|| anyhow::anyhow!(USAGE))?.parse()?;
    // Default mainnet so existing invocations are unchanged.
    let network_id: u64 = args.next().map(|a| a.parse()).transpose()?.unwrap_or(support::MAINNET);
    let trie_dir = args.next();
    // Before the stores open: headers are read by the network's heights.
    let hardfork_cfg = support::hardfork_for(network_id);

    let replay = Replay::open(&data_dir, trie_dir.as_deref())?;
    replay.ensure_replayable(number)?;

    eprintln!("replaying on network-id {network_id} (chain_id {})", hardfork_cfg.chain_id);
    let processor = BlockProcessor::new(hardfork_cfg, replay.store.clone());

    let mut root = replay.root.clone();
    for n in replay.exec_number + 1..=number {
        // The all-ops tracer is read per execute_block; enable it only for the
        // target block so range replays stay tractable.
        if n == number && std::env::var_os("RUSTOCK_TRACE_TARGET_OPS").is_some() {
            unsafe { std::env::set_var("RUSTOCK_TRACE_ALL_OPS", "1") };
        }
        let block = replay.block(n)?;
        let processed = processor.execute_block(&block, &root, replay.trie_store.clone())?;

        if n < number {
            if processed.state_root_hash != block.header.state_root {
                eprintln!(
                    "intermediate block #{n} state diverges: computed={:?} header={:?}",
                    processed.state_root_hash, block.header.state_root
                );
            }
            if processed.receipts_root != block.header.receipts_root {
                eprintln!(
                    "intermediate block #{n} receipts diverges: computed={:?} header={:?}",
                    processed.receipts_root, block.header.receipts_root
                );
            }
            root = processed.new_state_root;
            continue;
        }

        eprintln!("=== block #{n} per-tx results ===");
        for (i, r) in processed.receipts.iter().enumerate() {
            eprintln!("  tx[{i}] status={:?} gas_used={}", r.status, r.gas_used);
            for log in &r.logs {
                eprintln!("    log address={:?}", log.address);
                for t in &log.topics {
                    eprintln!("      topic {t:?}");
                }
                eprintln!("      data 0x{}", alloy_primitives::hex::encode(&log.data));
            }
        }
        eprintln!("total gas_used={}", processed.gas_used);
        eprintln!(
            "state root:    computed={:?} header={:?} match={}",
            processed.state_root_hash,
            block.header.state_root,
            processed.state_root_hash == block.header.state_root
        );
        eprintln!(
            "receipts root: computed={:?} header={:?} match={}",
            processed.receipts_root,
            block.header.receipts_root,
            processed.receipts_root == block.header.receipts_root
        );
        if processed.state_root_hash != block.header.state_root {
            // Repeat the trie dir so the suggestion is copy-pasteable; an
            // epoch-backed node fails without it.
            let trie_arg = trie_dir.as_deref().map(|d| format!(" {d}")).unwrap_or_default();
            eprintln!(
                "\nnext: `block_writes {data_dir} {n} {network_id}{trie_arg}` lists the \
                 leaves this block wrote."
            );
        }
    }
    Ok(())
}
