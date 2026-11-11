//! At which block did the Bridge register each Flyover peg-in?
//!
//! # Why this exists
//!
//! `registerFlyoverBtcTransaction` emits no event (see
//! `docs/flyover-peg-ins.md`), so a Flyover peg-in cannot be found in the
//! event index, and it is an *internal* call, so it cannot be found by
//! reading block bodies either. Only a replay sees it — and replaying
//! #3,614,800 to head at the measured 4-14 blocks/s is 100+ hours.
//!
//! The Bridge's own state makes that unnecessary.
//! `saveFlyoverFederationInformation` writes
//! `keccak("fastBridgeFederationInformation-" || hex(flyoverP2shHash160))`
//! when the peg-in is registered, and never removes it. So for a known
//! derived address the slot is **absent before the registration block and
//! present from it onward** — monotonic, which is exactly the property a
//! binary search needs.
//!
//! Twenty-four probes locate one registration in a 9.4M-block range. For a
//! 449-address census that is ~11k state reads, minutes rather than days, and
//! it yields the **exact block** rather than a window that still has to be
//! scanned.
//!
//! Feed the output to `verify_range --blocks` to reconstruct the events.
//!
//! # Why `try_get` and not `get`
//!
//! A plain `get` answers `None` both when a slot is absent and when the walk
//! reaches a node the store cannot produce. In a binary search those are
//! catastrophically different: the first says "later", the second says
//! nothing at all, and treating a pruned store as "absent" would walk the
//! search straight to a wrong answer with no sign of trouble. A probe that
//! cannot be resolved **aborts that address** rather than guessing.
//!
//! Usage:
//!   flyover_find <data-dir> <archival-trie-dir> [options]
//!
//!     --file LIST      addresses or hash160s, one per line (CSV: first column)
//!     --from N         earliest block to consider (default 3614800, iris300)
//!     --to N           latest (default: the node's head)
//!     --csv FILE       write address,derivation_hash,block
//!     --blocks FILE    write just the block numbers, for `verify_range --blocks`
//!     --threads N      addresses searched in parallel (default 2)

use alloy_primitives::B256;
use rustock_execution::bridge::storage::{compound_key, FAST_BRIDGE_FEDERATION_INFO_KEY};
use rustock_storage::{BlockStore, RocksDbTrieStore};
use rustock_trie::{storage_key, TrieKeySlice, TrieNode, TrieStore};
use std::collections::BTreeSet;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// iris300 — RSKIP176, the first block at which Flyover exists at all.
const FLYOVER_ACTIVATION: u64 = 3_614_800;

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58_hash160(s: &str) -> Option<[u8; 20]> {
    let mut n = [0u8; 25];
    for ch in s.bytes() {
        let d = B58.iter().position(|&c| c == ch)? as u32;
        let mut carry = d;
        for b in n.iter_mut().rev() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&n[1..21]);
    Some(out)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Outcome of one probe. `Unknown` is NOT a synonym for `Absent`.
enum Probe {
    Present(Vec<u8>),
    Absent,
    Unknown,
}

fn probe(
    blocks: &BlockStore,
    trie: &dyn TrieStore,
    slot: alloy_primitives::U256,
    number: u64,
) -> Probe {
    let Ok(Some(hash)) = blocks.canonical_hash(number) else { return Probe::Unknown };
    let Ok(Some(header)) = blocks.header(hash) else { return Probe::Unknown };
    let Some(root_bytes) = trie.get(header.state_root.as_slice()) else { return Probe::Unknown };
    let root = TrieNode::from_message(&root_bytes, trie);
    let key = storage_key(&rustock_execution::precompiles::BRIDGE_ADDR, &B256::from(slot));
    match root.try_get(&TrieKeySlice::from_key(&key), trie) {
        Ok(Some(v)) if !v.is_empty() => Probe::Present(v),
        Ok(_) => Probe::Absent,
        Err(_) => Probe::Unknown,
    }
}

fn opt(a: &[String], name: &str) -> Option<String> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned()
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let pos: Vec<&String> = a
        .iter()
        .enumerate()
        .filter(|(i, s)| !s.starts_with("--") && (*i == 0 || !a[i - 1].starts_with("--")))
        .map(|(_, s)| s)
        .collect();
    if pos.len() < 2 {
        anyhow::bail!(
            "usage: flyover_find <data-dir> <archival-trie-dir> --file LIST \
             [--from N] [--to N] [--csv F] [--blocks F] [--threads N]"
        );
    }

    let blocks = Arc::new(BlockStore::open_read_only(pos[0])?);
    // An archival import stops at the height it was taken; the node's own
    // epoch store covers the recent chain instead. Neither alone spans
    // everything, so the format is a choice.
    let fmt = opt(&a, "--trie-format").unwrap_or_else(|| "rustock".into());
    let trie: Arc<dyn TrieStore> = match fmt.as_str() {
        "rustock" => Arc::new(
            RocksDbTrieStore::open_read_only(pos[1])
                .map_err(|e| anyhow::anyhow!("opening {} read-only: {e}", pos[1]))?,
        ),
        "epoch" => Arc::new(
            rustock_storage::epoch_store::EpochTrieStore::open_read_only_with(
                pos[1],
                rustock_storage::epoch_store::EpochConfig::default(),
                Arc::new(rustock_storage::epoch_backend::FlatFactory::new(0)),
            )
            .map_err(|e| anyhow::anyhow!("opening epoch store {}: {e}", pos[1]))?,
        ),
        other => anyhow::bail!("--trie-format must be rustock or epoch, not {other:?}"),
    };

    let head = blocks
        .head()?
        .and_then(|h| blocks.header(h).ok().flatten())
        .map(|h| h.number)
        .ok_or_else(|| anyhow::anyhow!("no head"))?;
    let from: u64 = opt(&a, "--from").map(|s| s.parse()).transpose()?.unwrap_or(FLYOVER_ACTIVATION);
    let to: u64 = opt(&a, "--to").map(|s| s.parse()).transpose()?.unwrap_or(head);
    let threads: usize = opt(&a, "--threads").map(|s| s.parse()).transpose()?.unwrap_or(2).max(1);

    let list = opt(&a, "--file").ok_or_else(|| anyhow::anyhow!("--file is required"))?;
    let mut candidates: Vec<String> = Vec::new();
    for line in std::fs::read_to_string(&list)?.lines() {
        let t = line.split(',').next().unwrap_or("").trim().to_string();
        if !t.is_empty() && !t.starts_with('#') && t != "address" && t != "address_or_hash160" {
            candidates.push(t);
        }
    }
    anyhow::ensure!(!candidates.is_empty(), "no addresses in {list}");

    // An archival store is a snapshot and stops somewhere. Probing above its
    // top returns Unknown for every address, which looks like 449 failures
    // rather than one fact about the store -- so find the top once, here, and
    // say so.
    let to = {
        let probe_root = |n: u64| -> bool {
            blocks
                .canonical_hash(n)
                .ok()
                .flatten()
                .and_then(|h| blocks.header(h).ok().flatten())
                .map(|hd| trie.get(hd.state_root.as_slice()).is_some())
                .unwrap_or(false)
        };
        if probe_root(to) {
            to
        } else {
            let (mut lo, mut hi) = (from, to);
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if probe_root(mid) { lo = mid } else { hi = mid }
            }
            eprintln!(
                "note: this trie store holds no state above #{lo}; searching to there \
                 instead of #{to}. Registrations after #{lo} will not be located."
            );
            lo
        }
    };

    eprintln!(
        "{} address(es), searching #{from}..#{to} ({} blocks, ~{} probes each), {threads} worker(s)",
        candidates.len(),
        to - from + 1,
        (to - from + 1).ilog2() + 1
    );

    let done = Arc::new(AtomicU64::new(0));
    let probes = Arc::new(AtomicU64::new(0));
    let results: Arc<Mutex<Vec<(String, String, Option<u64>, &'static str)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let next = Arc::new(AtomicU64::new(0));

    std::thread::scope(|scope| {
        for _ in 0..threads {
            let (blocks, trie, results, done, probes, next, candidates) = (
                Arc::clone(&blocks),
                Arc::clone(&trie),
                Arc::clone(&results),
                Arc::clone(&done),
                Arc::clone(&probes),
                Arc::clone(&next),
                &candidates,
            );
            scope.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                let Some(c) = candidates.get(i) else { return };

                let h160 = if c.len() == 40 {
                    alloy_primitives::hex::decode(c).ok().and_then(|v| {
                        (v.len() == 20).then(|| {
                            let mut x = [0u8; 20];
                            x.copy_from_slice(&v);
                            x
                        })
                    })
                } else {
                    b58_hash160(c)
                };
                let Some(h160) = h160 else {
                    results.lock().unwrap().push((c.clone(), String::new(), None, "bad-address"));
                    done.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let slot = compound_key(FAST_BRIDGE_FEDERATION_INFO_KEY, "-", &hexs(&h160));

                // The invariant: absent before registration, present from it
                // onward. Confirm both ends before trusting the midpoints --
                // a search over a non-monotonic predicate returns a confident
                // wrong answer.
                let mut n_probes = 0u64;
                let hi_state = { n_probes += 1; probe(&blocks, trie.as_ref(), slot, to) };
                let deriv = match &hi_state {
                    Probe::Present(v) if v.len() >= 35 => hexs(&v[2..34]),
                    Probe::Present(v) => hexs(v),
                    _ => String::new(),
                };
                let tag = match hi_state {
                    Probe::Unknown => Some("unknown-at-end"),
                    Probe::Absent => Some("never-registered"),
                    Probe::Present(_) => None,
                };
                if let Some(t) = tag {
                    probes.fetch_add(n_probes, Ordering::Relaxed);
                    results.lock().unwrap().push((c.clone(), deriv, None, t));
                    done.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Invariant check at the low end: it must be absent there, or
                // the registration predates the search range.
                n_probes += 1;
                let lo_state = probe(&blocks, trie.as_ref(), slot, from);
                if matches!(lo_state, Probe::Present(_)) {
                    probes.fetch_add(n_probes, Ordering::Relaxed);
                    results.lock().unwrap().push((c.clone(), deriv, Some(from), "at-or-before-from"));
                    done.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Binary search for the first block at which it is present.
                let (mut lo, mut hi) = (from, to); // absent at lo, present at hi
                let mut aborted = false;
                while hi - lo > 1 {
                    let mid = lo + (hi - lo) / 2;
                    n_probes += 1;
                    match probe(&blocks, trie.as_ref(), slot, mid) {
                        Probe::Present(_) => hi = mid,
                        Probe::Absent => lo = mid,
                        // Refuse rather than guess: a missing node says
                        // nothing about whether the slot was written.
                        Probe::Unknown => {
                            aborted = true;
                            break;
                        }
                    }
                }
                probes.fetch_add(n_probes, Ordering::Relaxed);
                let r = if aborted {
                    (c.clone(), deriv, None, "unresolvable-probe")
                } else {
                    (c.clone(), deriv, Some(hi), "found")
                };
                results.lock().unwrap().push(r);
                done.fetch_add(1, Ordering::Relaxed);
            });
        }

        let total = candidates.len() as u64;
        let (rdone, rprobes) = (Arc::clone(&done), Arc::clone(&probes));
        scope.spawn(move || {
            let (done, probes) = (rdone, rprobes);
            let mut last = Instant::now();
            while done.load(Ordering::Relaxed) < total {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if last.elapsed().as_secs() < 10 {
                    continue;
                }
                last = Instant::now();
                let d = done.load(Ordering::Relaxed);
                if d >= total {
                    break;
                }
                eprintln!(
                    "  {d}/{total} addresses, {} probes, {:.0}s",
                    probes.load(Ordering::Relaxed),
                    started.elapsed().as_secs_f64()
                );
            }
        });
    });

    let mut rows = results.lock().unwrap().clone();
    rows.sort_by_key(|(_, _, b, _)| b.unwrap_or(u64::MAX));

    let (mut found, mut other) = (0usize, 0usize);
    let mut block_set: BTreeSet<u64> = BTreeSet::new();
    for (_, _, b, tag) in &rows {
        if *tag == "found" || *tag == "at-or-before-from" {
            found += 1;
            if let Some(n) = b {
                block_set.insert(*n);
            }
        } else {
            other += 1;
        }
    }

    if let Some(p) = opt(&a, "--csv") {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&p)?);
        writeln!(f, "address,derivation_hash,registration_block,status")?;
        for (c, d, b, tag) in &rows {
            writeln!(
                f,
                "{c},{d},{},{tag}",
                b.map(|x| x.to_string()).unwrap_or_default()
            )?;
        }
        eprintln!("wrote {p}");
    }
    if let Some(p) = opt(&a, "--blocks") {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&p)?);
        for n in &block_set {
            writeln!(f, "{n}")?;
        }
        eprintln!("wrote {p} ({} distinct block(s))", block_set.len());
    }

    println!("addresses      {}", rows.len());
    println!("located        {found}");
    println!("distinct blocks{:>8}", block_set.len());
    println!("not located    {other}");
    for tag in ["never-registered", "unknown-at-end", "unresolvable-probe", "bad-address"] {
        let n = rows.iter().filter(|(_, _, _, t)| *t == tag).count();
        if n > 0 {
            println!("  {tag:<20} {n}");
        }
    }
    println!(
        "probes         {} ({:.1}s, {:.1} per address)",
        probes.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64(),
        probes.load(Ordering::Relaxed) as f64 / rows.len().max(1) as f64
    );
    Ok(())
}
