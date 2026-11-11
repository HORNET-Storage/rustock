//! Query the reconstructed peg events, alone or unioned with the real index.
//!
//! The node's `bridge_events` index is built from receipts, so it holds only
//! what the Bridge actually logged. The Bridge's event log arrived in stages
//! — `lock_btc` and `release_requested` at papyrus200 (#2,392,700),
//! `pegin_btc` with RSKIP170, `rejected_pegin` and `unrefundable_pegin` at
//! iris300 (#3,614,800) — and before each, the peg went on working and wrote
//! nothing. A `bridge_events` scan over that era returns nothing, which looks
//! exactly like nothing having happened.
//!
//! `verify_range --record-legacy-events` reconstructs those entries from a
//! replay. This reads them back, in the same shape `bridge_events` prints, and
//! with `--with-index` merges the two into one history.
//!
//! ```text
//! legacy_events <store-dir> --topics
//! legacy_events <store-dir> --coverage
//! legacy_events <store-dir> <event-signature|0xtopic> [options]
//!
//!   --from N          first block (default 0)
//!   --to N            last block (default: no limit)
//!   --with-index DIR  also read the node's real index at DIR and merge, so
//!                     the output spans every era. Opened read-only; safe
//!                     against a running node.
//!   --count           print only the number of matches
//! ```
//!
//! The merge is sound because the two never overlap: nothing is reconstructed
//! for a height where the Bridge really logged, so no event is counted twice.
//! Each row is tagged `real` or `recon` so the distinction is never lost.
//!
//! Example:
//!   legacy_events /mnt/import/legacy-events \
//!       'pegin_btc(address,bytes32,int256,int256)' \
//!       --with-index /var/lib/rustock

use alloy_primitives::B256;
use anyhow::{Context, Result};
use rustock_storage::legacy_event_store::{DecodedEvent, LegacyEventStore};
use rustock_storage::BlockStore;
use sha3::{Digest, Keccak256};

const USAGE: &str = "usage: legacy_events <store-dir> [--topics|--coverage|<event-sig>] \
[--from N] [--to N] [--with-index DIR] [--count]";

/// `keccak256(signature)`, the same topic0 the Bridge emits. A bare `0x…`
/// 32-byte value is taken as the topic itself, so a topic read out of one
/// tool's output can be fed straight into this one.
fn topic_of(spec: &str) -> Result<B256> {
    if let Some(hex) = spec.strip_prefix("0x") {
        if hex.len() == 64 {
            let raw = alloy_primitives::hex::decode(hex).context("bad topic hex")?;
            return Ok(B256::from_slice(&raw));
        }
    }
    anyhow::ensure!(
        spec.contains('(') && spec.ends_with(')'),
        "not an event signature or 0x-topic: {spec}"
    );
    Ok(B256::from_slice(&Keccak256::digest(spec.as_bytes())))
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn print_row(tag: &str, e: &DecodedEvent) {
    let (block, tx_index, log_index, tx_hash, topics, data) = e;
    println!("  {tag:<5} #{block:<9} tx[{tx_index}] log[{log_index}]  tx=0x{}", hexs(tx_hash.as_slice()));
    for (i, t) in topics.iter().enumerate().skip(1) {
        println!("          topic{i} 0x{}", hexs(t.as_slice()));
    }
    if !data.is_empty() {
        println!("          data   0x{}", hexs(data));
    }
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        anyhow::bail!("{USAGE}");
    }
    let store_dir = argv[0].clone();
    let opt = |name: &str| -> Option<String> {
        argv.iter().position(|a| a == name).and_then(|i| argv.get(i + 1)).cloned()
    };
    let has = |name: &str| argv.iter().any(|a| a == name);

    let store = LegacyEventStore::open_read_only(&store_dir)
        .with_context(|| format!("opening the legacy event store at {store_dir}"))?;

    if has("--coverage") {
        let spans = store.coverage()?;
        if spans.is_empty() {
            println!("no coverage recorded: nothing has been reconstructed into this store");
            return Ok(());
        }
        println!("coverage ({} span(s)):", spans.len());
        for s in spans {
            println!("  {s}");
        }
        return Ok(());
    }

    if has("--topics") {
        let topics = store.topics()?;
        if topics.is_empty() {
            println!("no events in this store");
            return Ok(());
        }
        // Name the ones we know; an unknown topic still prints, as a hash.
        let known = [
            "pegin_btc(address,bytes32,int256,int256)",
            "lock_btc(address,bytes32,string,int256)",
            "release_requested(bytes32,bytes32,uint256)",
            "rejected_pegin(bytes32,int256)",
            "unrefundable_pegin(bytes32,int256)",
        ];
        println!("{:<66} {:>9}  {:>10} {:>10}  event", "topic0", "count", "first", "last");
        for (t, count, first, last) in topics {
            let name = known
                .iter()
                .find(|s| topic_of(s).map(|k| k == t).unwrap_or(false))
                .copied()
                .unwrap_or("(unknown)");
            println!("0x{:<64} {count:>9}  #{first:<9} #{last:<9}  {name}", hexs(t.as_slice()));
        }
        return Ok(());
    }

    let Some(spec) = argv.get(1).filter(|a| !a.starts_with("--")) else {
        anyhow::bail!("{USAGE}");
    };
    let topic = topic_of(spec)?;
    let from: u64 = opt("--from").map(|s| s.parse()).transpose()?.unwrap_or(0);
    let to: u64 = opt("--to").map(|s| s.parse()).transpose()?.unwrap_or(u64::MAX);

    let mut rows: Vec<(&'static str, DecodedEvent)> =
        store.scan(topic, from, to)?.into_iter().map(|e| ("recon", e)).collect();
    let reconstructed = rows.len();

    let mut real = 0usize;
    if let Some(dir) = opt("--with-index") {
        let blocks = BlockStore::open_read_only(&dir)
            .with_context(|| format!("opening the node store at {dir}"))?;
        let found = blocks.scan_bridge_events(topic, from, to)?;
        real = found.len();
        rows.extend(found.into_iter().map(|e| ("real", e)));
    }

    // One history, in chain order. The two sources never collide, so a stable
    // sort on position is all the merge needs.
    rows.sort_by_key(|(_, e)| (e.0, e.1, e.2));

    if has("--count") {
        println!("{} ({reconstructed} reconstructed, {real} real)", rows.len());
        return Ok(());
    }

    println!("{spec}");
    println!("  topic0 0x{}", hexs(topic.as_slice()));
    if !store.covers(from, to)? {
        println!(
            "  NOTE: #{from}..{} is not wholly covered by this store -- an absent \
             event here may mean the range was never reconstructed, not that \
             nothing happened. Run with --coverage.",
            if to == u64::MAX { "end".into() } else { to.to_string() }
        );
    }
    println!("  {} match(es): {reconstructed} reconstructed, {real} real", rows.len());
    for (tag, e) in &rows {
        print_row(tag, e);
    }
    Ok(())
}
