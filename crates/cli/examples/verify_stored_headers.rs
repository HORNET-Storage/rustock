//! Verify every header in a store by `HeaderVerifier::default_rsk`, the
//! trunk rules the node syncs by, and report what fails, rule by rule.
//!
//! Each header is checked on its own and against its parent, ranges of the
//! chain split across threads, walking back by parent hash within each. The
//! store and its header freezer are both opened read-only, so this can run
//! beside the node that writes them.
//!
//! Fork-detection data (rskj `ForkDetectionDataRule`, from wasabi100) is
//! checked as the node checks it, against the 449 blocks below each block:
//! a thread holds each header until its walk has reached them, and reads on
//! past its range's bottom to finish the range's lowest blocks.
//!
//! It also counts blocks no later than their parent, which rskj's trunk
//! takes and its relay would not: zero is what an honest chain shows.
//!
//! And it hashes each header as rustock writes it back, which is how rskj
//! hashes one, against the hash it is stored under, which the header above
//! it names: a header read in a form rustock can't write back the same
//! would hash as another block.
//!
//! The chain is mainnet's unless named, and its heights are installed
//! before any header is read, as the node does.
//!
//! Usage: verify_stored_headers [--testnet] <data-dir> [lowest-block] [highest-block]

use alloy_primitives::B256;
use anyhow::Context;
use rustock_core::config::ChainConfig;
use rustock_core::validation::{fork_detection, merged_mining, HeaderVerifier};
use rustock_core::Header;
use rustock_storage::BlockStore;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// How many failing block numbers to keep per rule.
const EXAMPLES: usize = 8;

/// A header that hashes, as rustock writes it back, to another hash than
/// the one it is stored under.
#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`, by `record`.
struct Rehashed {
    stored: B256,
    computed: B256,
}

#[derive(Default)]
struct Failures {
    count: u64,
    blocks: Vec<u64>,
    first: String,
}

/// Counts a failure under its rule, the error's variant name, keeping the
/// first in full and the first few block numbers.
fn record(failures: &Mutex<BTreeMap<String, Failures>>, number: u64, error: &impl std::fmt::Debug) {
    let debug = format!("{error:?}");
    let rule = debug
        .split(|c: char| !c.is_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_string();
    let mut failures = failures.lock().unwrap();
    let entry = failures.entry(rule).or_default();
    entry.count += 1;
    if entry.blocks.len() < EXAMPLES {
        entry.blocks.push(number);
    }
    if entry.first.is_empty() {
        entry.first = debug;
    }
}

/// The blocks below the newest a walk holds, newest first.
struct Below<'a>(&'a VecDeque<Header>);

impl fork_detection::MainchainView for Below<'_> {
    fn headers_from(&self, from: B256, count: u64) -> Vec<Header> {
        // Only if they are the chain below `from`: a walk holds no window
        // across a hole.
        if self.0.get(1).map(|h| h.hash()) != Some(from) {
            return Vec::new();
        }
        self.0
            .iter()
            .skip(1)
            .take(count as usize)
            .cloned()
            .collect()
    }
}

/// Takes the next header of a descending walk. Once the 449 blocks below the
/// newest held are in hand, that one's fork-detection data is checked as
/// `BlockProcessor::validate_block_rules` checks it, and it is let go.
fn carry(
    window: &mut VecDeque<Header>,
    header: Header,
    wasabi100: u64,
    failures: &Mutex<BTreeMap<String, Failures>>,
    fork_checked: &AtomicU64,
) {
    window.push_back(header);
    if window.len() as u64 <= fork_detection::REQUIRED_BLOCKS {
        return;
    }
    let block = &window[0];
    if block.number >= wasabi100 && block.number > fork_detection::REQUIRED_BLOCKS {
        let actual = merged_mining::extract_fork_detection_data(block);
        if let Err(e) = fork_detection::validate(block, actual, &Below(window), wasabi100) {
            record(failures, block.number, &e);
        }
        fork_checked.fetch_add(1, Ordering::Relaxed);
    }
    window.pop_front();
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let testnet = args.next_if_eq("--testnet").is_some();
    let dir = args.next().context(
        "usage: verify_stored_headers [--testnet] <data-dir> [lowest-block] [highest-block]",
    )?;
    let lowest = args.next();
    let highest = args.next();
    let config = Arc::new(if testnet {
        ChainConfig::testnet()
    } else {
        ChainConfig::mainnet()
    });
    config.activation_heights.clone().install();
    let store = BlockStore::open_read_only(&dir)?;
    // A snapshot-synced node indexes by number only the window it fetched
    // bodies for, and answers every height below from the freezer.
    let freezer_dir = std::path::Path::new(&dir).join("freezer");
    if freezer_dir.exists() {
        let freezer = rustock_storage::freezer::Freezer::open_read_only(&freezer_dir)?;
        println!(
            "freezer {}: {} header(s)",
            freezer_dir.display(),
            freezer.end_number()
        );
        store.set_freezer(Arc::new(freezer));
    }
    let head_hash = store.head()?.context("the store has no head")?;
    let head = store
        .header(head_hash)?
        .context("the head header is missing")?;
    let lowest: u64 = lowest.map(|s| s.parse()).transpose()?.unwrap_or(1).max(1);
    let highest: u64 = highest
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(head.number);
    anyhow::ensure!(lowest <= highest, "#{lowest} is above #{highest}");

    let wasabi100 = config.activation_heights.wasabi100;
    let verifier = HeaderVerifier::default_rsk(config.clone());
    let threads = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(4);
    let span = (highest - lowest + 1).div_ceil(threads);
    println!(
        "store {dir}, chain {}\n  head #{}\n  verifying #{highest} down to #{lowest} on {threads} threads",
        config.chain_id,
        head.number
    );

    let failures: Mutex<BTreeMap<String, Failures>> = Mutex::new(BTreeMap::new());
    let checked = AtomicU64::new(0);
    let not_later = AtomicU64::new(0);
    // Headers whose parent the store lacks, checked on their own, and
    // canonical numbers the store has no header for at all.
    let orphaned = AtomicU64::new(0);
    let missing = AtomicU64::new(0);
    let fork_checked = AtomicU64::new(0);
    // Headers below orchid that answer for their work with a fallback-mining
    // signature rather than a Bitcoin header.
    let fallback = AtomicU64::new(0);
    // And those below orchid that answer for it with a Bitcoin header, whose
    // coinbase a bitcoinj partial merkle tree proves.
    let trees = AtomicU64::new(0);
    // Headers hashed as rustock writes them back, against their keys.
    let rehashed = AtomicU64::new(0);
    let started = Instant::now();

    std::thread::scope(|scope| -> anyhow::Result<()> {
        let mut workers = Vec::new();
        for t in 0..threads {
            let Some(top) = highest.checked_sub(t * span) else {
                break;
            };
            if top < lowest {
                break;
            }
            let bottom = top.saturating_sub(span - 1).max(lowest);
            let (store, verifier, config, failures, checked, not_later, orphaned, missing) = (
                &store, &verifier, &config, &failures, &checked, &not_later, &orphaned, &missing,
            );
            let (fork_checked, fallback, trees, rehashed) =
                (&fork_checked, &fallback, &trees, &rehashed);
            workers.push(scope.spawn(move || -> anyhow::Result<()> {
                // A header read under `stored`, hashed as rustock writes it.
                // Not genesis: rskj's `GenesisHeader` writes its difficulty
                // with the leading zero its spec gives it, which no decoder
                // keeps, and its hash is known instead
                // (`ChainConfig::known_genesis_hash`).
                let rehash = |header: &Header, stored: B256| {
                    if header.number == 0 {
                        return;
                    }
                    let computed = header.hash();
                    if computed != stored {
                        record(failures, header.number, &Rehashed { stored, computed });
                    }
                    rehashed.fetch_add(1, Ordering::Relaxed);
                };
                // The highest block from `number` down to this range's bottom
                // that the store holds, counting the numbers it does not.
                let held_from = |mut number: u64| -> anyhow::Result<Option<rustock_core::Header>> {
                    loop {
                        let found = match store.canonical_hash(number)? {
                            Some(hash) => store.header(hash)?.inspect(|h| rehash(h, hash)),
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
                let Some(mut header) = held_from(top)? else {
                    return Ok(());
                };
                // Fork detection reads the 449 blocks below a block, which
                // this walk reaches after it: each header is held till then.
                let mut window: VecDeque<Header> = VecDeque::new();
                let below = loop {
                    let parent = store
                        .header(header.parent_hash)?
                        .inspect(|p| rehash(p, header.parent_hash));
                    if merged_mining::is_fallback_mined(&header, config) {
                        fallback.fetch_add(1, Ordering::Relaxed);
                    } else if header.number < config.activation_heights.orchid {
                        trees.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Err(e) = verifier.verify(&header, parent.as_ref()) {
                        record(failures, header.number, &e);
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
                    carry(
                        &mut window,
                        header.clone(),
                        wasabi100,
                        failures,
                        fork_checked,
                    );
                    if header.number <= bottom {
                        break parent;
                    }
                    header = match parent {
                        Some(parent) => parent,
                        // A hole in the store: go on from the next block below
                        // it that the store holds, with no window across it.
                        None => {
                            window.clear();
                            match held_from(header.number - 1)? {
                                Some(found) => found,
                                None => return Ok(()),
                            }
                        }
                    };
                };
                // The range's lowest blocks are checked against blocks below
                // it, which the next range verifies: read on to them.
                let mut next = below;
                while window.front().is_some_and(|h| h.number >= bottom) {
                    let Some(header) = next else { break };
                    next = store.header(header.parent_hash)?;
                    carry(&mut window, header, wasabi100, failures, fork_checked);
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
        println!(
            "  {rule}: {} -- e.g. #{:?}\n    first: {}",
            f.count, f.blocks, f.first
        );
    }
    println!(
        "  blocks no later than their parent: {}",
        not_later.into_inner()
    );
    let (orphaned, missing) = (orphaned.into_inner(), missing.into_inner());
    println!("  checked without their parent, which the store lacks: {orphaned}");
    println!("  canonical numbers with no header in the store: {missing}");
    let fork_checked = fork_checked.into_inner();
    let fork_from = lowest
        .max(wasabi100)
        .max(fork_detection::REQUIRED_BLOCKS + 1);
    let fork_expected = (highest + 1).saturating_sub(fork_from);
    println!("  fork-detection data checked on {fork_checked} blocks, from #{fork_from}");
    println!(
        "  fallback-mined, their signatures checked: {}",
        fallback.into_inner()
    );
    println!(
        "  merge-mined below orchid, their partial merkle trees checked: {}",
        trees.into_inner()
    );
    println!(
        "  hashed as rustock writes them back, against the hash each is stored under: {}",
        rehashed.into_inner()
    );
    let expected = highest - lowest + 1;
    anyhow::ensure!(
        checked + missing == expected,
        "checked {checked} and {missing} missing, expected {expected} in all"
    );
    anyhow::ensure!(
        missing > 0 || fork_checked == fork_expected,
        "fork-detection data checked on {fork_checked} blocks, expected {fork_expected}"
    );
    Ok(())
}
