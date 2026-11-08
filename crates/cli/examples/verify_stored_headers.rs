//! Verify every header in a store by `HeaderVerifier::default_rsk`, the
//! trunk rules the node syncs by, and report what fails, rule by rule.
//!
//! Each header is checked on its own and against its parent, ranges of the
//! chain split across threads, walking back by parent hash within each. The
//! store is opened read-only, so this can run against a copy of a node's
//! data or the store of a node that is stopped.
//!
//! It also counts blocks no later than their parent, which rskj's trunk
//! takes and its relay would not: zero is what an honest chain shows.
//!
//! Usage: verify_stored_headers <data-dir> [lowest-block] [highest-block]

use anyhow::Context;
use rustock_core::config::ChainConfig;
use rustock_core::validation::HeaderVerifier;
use rustock_storage::BlockStore;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// How many failing block numbers to keep per rule.
const EXAMPLES: usize = 8;

#[derive(Default)]
struct Failures {
    count: u64,
    blocks: Vec<u64>,
    first: String,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .context("usage: verify_stored_headers <data-dir> [lowest-block] [highest-block]")?;
    let store = BlockStore::open_read_only(&dir)?;
    let head_hash = store.head()?.context("the store has no head")?;
    let head = store.header(head_hash)?.context("the head header is missing")?;
    let lowest: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(1).max(1);
    let highest: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(head.number);
    anyhow::ensure!(lowest <= highest, "#{lowest} is above #{highest}");

    let verifier = HeaderVerifier::default_rsk(Arc::new(ChainConfig::mainnet()));
    let threads = std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(4);
    let span = (highest - lowest + 1).div_ceil(threads);
    println!(
        "store {dir}\n  head #{}\n  verifying #{highest} down to #{lowest} on {threads} threads",
        head.number
    );

    let failures: Mutex<BTreeMap<String, Failures>> = Mutex::new(BTreeMap::new());
    let checked = AtomicU64::new(0);
    let not_later = AtomicU64::new(0);
    // Headers whose parent the store lacks, checked on their own, and
    // canonical numbers the store has no header for at all.
    let orphaned = AtomicU64::new(0);
    let missing = AtomicU64::new(0);
    let started = Instant::now();

    std::thread::scope(|scope| -> anyhow::Result<()> {
        let mut workers = Vec::new();
        for t in 0..threads {
            let Some(top) = highest.checked_sub(t * span) else { break };
            if top < lowest {
                break;
            }
            let bottom = top.saturating_sub(span - 1).max(lowest);
            let (store, verifier, failures, checked, not_later, orphaned, missing) =
                (&store, &verifier, &failures, &checked, &not_later, &orphaned, &missing);
            workers.push(scope.spawn(move || -> anyhow::Result<()> {
                // The highest block from `number` down to this range's bottom
                // that the store holds, counting the numbers it does not.
                let held_from = |mut number: u64| -> anyhow::Result<Option<rustock_core::Header>> {
                    loop {
                        let found = match store.canonical_hash(number)? {
                            Some(hash) => store.header(hash)?,
                            None => None,
                        };
                        if found.is_some() {
                            return Ok(found);
                        }
                        missing.fetch_add(1, Ordering::Relaxed);
                        if number <= bottom {
                            return Ok(None);
                        }
                        number -= 1;
                    }
                };
                let Some(mut header) = held_from(top)? else { return Ok(()) };
                loop {
                    let parent = store.header(header.parent_hash)?;
                    if let Err(e) = verifier.verify(&header, parent.as_ref()) {
                        let debug = format!("{e:?}");
                        let rule = debug
                            .split(|c: char| !c.is_alphanumeric())
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        let mut failures = failures.lock().unwrap();
                        let entry = failures.entry(rule).or_default();
                        entry.count += 1;
                        if entry.blocks.len() < EXAMPLES {
                            entry.blocks.push(header.number);
                        }
                        if entry.first.is_empty() {
                            entry.first = debug;
                        }
                    }
                    match &parent {
                        Some(parent) if header.timestamp <= parent.timestamp => {
                            not_later.fetch_add(1, Ordering::Relaxed);
                        }
                        Some(_) => {}
                        None => {
                            orphaned.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let done = checked.fetch_add(1, Ordering::Relaxed) + 1;
                    if done % 500_000 == 0 {
                        println!("  {done} checked, {:.0}s", started.elapsed().as_secs_f64());
                    }
                    if header.number <= bottom {
                        break;
                    }
                    header = match parent {
                        Some(parent) => parent,
                        // A hole in the store: go on from the next block below
                        // it that the store holds.
                        None => match held_from(header.number - 1)? {
                            Some(found) => found,
                            None => return Ok(()),
                        },
                    };
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker.join().expect("a worker panicked")?;
        }
        Ok(())
    })?;

    let checked = checked.into_inner();
    let failures = failures.into_inner().unwrap();
    let failed: u64 = failures.values().map(|f| f.count).sum();
    println!(
        "\nverified {checked} headers in {:.0}s: {failed} failed",
        started.elapsed().as_secs_f64()
    );
    for (rule, f) in &failures {
        println!("  {rule}: {} -- e.g. #{:?}\n    first: {}", f.count, f.blocks, f.first);
    }
    println!(
        "  blocks no later than their parent: {}",
        not_later.into_inner()
    );
    let (orphaned, missing) = (orphaned.into_inner(), missing.into_inner());
    println!("  checked without their parent, which the store lacks: {orphaned}");
    println!("  canonical numbers with no header in the store: {missing}");
    let expected = highest - lowest + 1;
    anyhow::ensure!(
        checked + missing == expected,
        "checked {checked} and {missing} missing, expected {expected} in all"
    );
    Ok(())
}
