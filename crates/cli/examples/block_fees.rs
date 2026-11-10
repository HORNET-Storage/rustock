//! What did a block's transactions pay in fees?
//!
//! Three ways to answer this, and they are not equivalent.
//!
//! 1. **Sum the receipts.** Correct, but costs one receipt read and one
//!    multiply per transaction, to recompute a number the chain already
//!    committed to.
//! 2. **Read the REMASC `mining_fee_topic` logs.** Tempting and *wrong* for
//!    this question. REMASC pays each miner 10% of an accumulated share per
//!    block, matured over 4,000 blocks, so the logs say what was *paid out*
//!    during a block, not what that block's transactions *collected*. The
//!    payout even names a `processingBlockHash` from thousands of blocks
//!    earlier. At block granularity the two are unrelated; over a long window
//!    they converge, minus whatever REMASC withheld under its selection rules
//!    and never pays to anyone.
//! 3. **Read `paidFees` from the block header.** The RSK header carries the
//!    total fees paid by its transactions as a consensus field — number 14,
//!    where Ethereum has `mixHash`. One header read, no receipts, no
//!    execution, and it is committed to by the block hash.
//!
//! This reports (3). `--verify` also computes (1) and compares, which is how
//! the claim was checked rather than assumed: over #9,396,000–#9,398,000,
//! 4,693 transactions, zero mismatches.
//!
//! # Speed
//!
//! Header reads are small dependent random reads, so the job is I/O-bound and
//! parallelises well. Workers take contiguous chunks; RocksDB serves
//! concurrent reads from one handle.
//!
//! **Count transactions only if you need them.** `--count-txs` adds a body
//! read per block — a much larger value than a header — and is the single
//! biggest cost in a full-chain scan. Fees and gas come from the header
//! alone.
//!
//! Usage:
//!   block_fees <data-dir> <from> <to> [options]
//!
//!     --threads N    workers (default: available parallelism, leave the node a core)
//!     --count-txs    also count transactions (reads each body; much slower)
//!     --verify       also sum the receipts and report mismatches (slowest)
//!     --bucket N     emit a CSV row per N blocks instead of per block
//!     --csv FILE     write rows here
//!     --json         emit the summary as JSON on stdout instead of text
//!
//! # Output contract
//!
//! The text summary is parsed by at least one collector, which matches
//! `blocks\s+(\d+)`, `transactions\s+(\d+)` and
//! `total fees\s+(\d+)\s*wei`. **Those three lines must keep their shape.**
//! Extra lines are safe. Renaming "total fees" to "fees" once broke that
//! parser silently — a regex that matches nothing looks like a chain with no
//! fees, not like an error.
//!
//! `--json` is the better interface for anything automated: it carries a
//! `schemaVersion`, and it distinguishes `"transactions": null` ("not
//! counted") from `0` ("counted, and there were none") — a difference the
//! text summary cannot express. Progress goes to stderr either way, so
//! stdout stays parseable.
//!
//! Per-block CSV over the whole chain is ~9.4M rows; `--bucket 10000` gives a
//! ~940-row series, which is what a chart actually wants.

use alloy_primitives::U256;
use rustock_storage::BlockStore;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Version of the `--json` shape. Bump if a field changes meaning.
const SCHEMA_VERSION: u32 = 1;

#[derive(Default, Clone)]
struct Bucket {
    first: u64,
    last: u64,
    blocks: u64,
    txs: u64,
    gas_used: u64,
    fees: U256,
}

fn opt(a: &[String], name: &str) -> Option<String> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned()
}

/// Renders a decimal wei string as rBTC without going through f64.
fn fmt_rbtc(wei: &U256) -> String {
    let s = wei.to_string();
    if s.len() <= 18 {
        format!("0.{:0>18}", s)
    } else {
        format!("{}.{}", &s[..s.len() - 18], &s[s.len() - 18..])
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let pos: Vec<&String> = a
        .iter()
        .enumerate()
        .filter(|(i, s)| !s.starts_with("--") && (*i == 0 || !a[i - 1].starts_with("--")))
        .map(|(_, s)| s)
        .collect();
    if pos.len() < 3 {
        anyhow::bail!(
            "usage: block_fees <data-dir> <from> <to> [--threads N] [--count-txs] \
             [--verify] [--bucket N] [--csv FILE]"
        );
    }
    let from: u64 = pos[1].parse()?;
    let to: u64 = pos[2].parse()?;
    anyhow::ensure!(to >= from, "empty range");

    let threads = match opt(&a, "--threads") {
        Some(s) => s.parse::<usize>()?.max(1),
        None => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
    };
    let count_txs = a.iter().any(|x| x == "--count-txs");
    let verify = a.iter().any(|x| x == "--verify");
    let bucket_size: u64 = opt(&a, "--bucket").map(|s| s.parse()).transpose()?.unwrap_or(1);
    let csv = opt(&a, "--csv");
    let json = a.iter().any(|x| x == "--json");

    // One handle, shared. RocksDB serves concurrent reads from it; opening
    // one per worker would multiply the block cache instead of sharing it.
    let store = Arc::new(BlockStore::open_read_only(pos[0])?);

    let total_blocks = to - from + 1;
    let done = Arc::new(AtomicU64::new(0));
    let mismatches = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    eprintln!(
        "#{from}..#{to}  {total_blocks} block(s), {threads} worker(s){}{}",
        if count_txs { ", counting transactions" } else { "" },
        if verify { ", verifying against receipts" } else { "" }
    );

    // Contiguous chunks: a worker's blocks are adjacent on disk, so its reads
    // are as local as this access pattern allows.
    let per = total_blocks.div_ceil(threads as u64);
    let out: Arc<Mutex<Vec<(u64, Vec<Bucket>)>>> = Arc::new(Mutex::new(Vec::new()));

    std::thread::scope(|scope| {
        let reporter = {
            let done = Arc::clone(&done);
            scope.spawn(move || {
                let mut last = Instant::now();
                while done.load(Ordering::Relaxed) < total_blocks {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    if last.elapsed().as_secs() < 10 {
                        continue;
                    }
                    last = Instant::now();
                    let d = done.load(Ordering::Relaxed);
                    if d >= total_blocks {
                        break;
                    }
                    let secs = started.elapsed().as_secs_f64();
                    let rate = d as f64 / secs.max(0.001);
                    eprintln!(
                        "  {:5.1}%  {d}/{total_blocks}  {rate:.0} blk/s  ~{:.0}s left",
                        d as f64 * 100.0 / total_blocks as f64,
                        (total_blocks - d) as f64 / rate.max(1.0)
                    );
                }
            })
        };

        for w in 0..threads as u64 {
            let lo = from + w * per;
            if lo > to {
                break;
            }
            let hi = (lo + per - 1).min(to);
            let (store, done, mismatches, out) =
                (Arc::clone(&store), Arc::clone(&done), Arc::clone(&mismatches), Arc::clone(&out));
            scope.spawn(move || {
                let mut buckets: Vec<Bucket> = Vec::new();
                let mut cur = Bucket { first: lo, ..Default::default() };
                let mut local = 0u64;

                for n in lo..=hi {
                    local += 1;
                    if local >= 2048 {
                        done.fetch_add(local, Ordering::Relaxed);
                        local = 0;
                    }
                    let Ok(Some(hash)) = store.canonical_hash(n) else { continue };
                    let Ok(Some(h)) = store.header(hash) else { continue };

                    cur.blocks += 1;
                    cur.last = n;
                    cur.gas_used += h.gas_used;
                    cur.fees += h.paid_fees;

                    if count_txs || verify {
                        if let Ok(Some(body)) = store.body(hash) {
                            cur.txs += body.0.len() as u64;
                            if verify {
                                // gas_used per receipt is the cumulative
                                // delta; the REMASC transaction pays nothing.
                                let receipts = store.receipts(hash).ok().flatten().unwrap_or_default();
                                let mut summed = U256::ZERO;
                                let mut prev = 0u64;
                                for (i, r) in receipts.iter().enumerate() {
                                    let used = r.cumulative_gas_used.saturating_sub(prev);
                                    prev = r.cumulative_gas_used;
                                    if let Some(tx) = body.0.get(i) {
                                        summed += U256::from(used) * tx.gas_price;
                                    }
                                }
                                if summed != h.paid_fees {
                                    mismatches.fetch_add(1, Ordering::Relaxed);
                                    eprintln!(
                                        "  #{n}  MISMATCH header={} receipts={summed}",
                                        h.paid_fees
                                    );
                                }
                            }
                        }
                    }

                    if bucket_size > 1 && cur.blocks >= bucket_size {
                        buckets.push(std::mem::take(&mut cur));
                        cur.first = n + 1;
                    } else if bucket_size == 1 {
                        buckets.push(std::mem::replace(
                            &mut cur,
                            Bucket { first: n + 1, ..Default::default() },
                        ));
                    }
                }
                if cur.blocks > 0 {
                    buckets.push(cur);
                }
                done.fetch_add(local, Ordering::Relaxed);
                out.lock().unwrap().push((lo, buckets));
            });
        }
        let _ = reporter;
    });

    // Chunks are contiguous and disjoint, so ordering by their start block
    // restores chain order without sorting every row.
    let mut parts = out.lock().unwrap().clone();
    parts.sort_by_key(|(lo, _)| *lo);

    let (mut tot_fees, mut tot_blocks, mut tot_txs, mut tot_gas) = (U256::ZERO, 0u64, 0u64, 0u64);
    let mut writer = match &csv {
        Some(p) => {
            let mut f = std::io::BufWriter::new(std::fs::File::create(p)?);
            writeln!(f, "first_block,last_block,blocks,txs,gas_used,paid_fees_wei")?;
            Some(f)
        }
        None => None,
    };
    for (_, buckets) in &parts {
        for b in buckets {
            tot_fees += b.fees;
            tot_blocks += b.blocks;
            tot_txs += b.txs;
            tot_gas += b.gas_used;
            if let Some(f) = writer.as_mut() {
                writeln!(
                    f,
                    "{},{},{},{},{},{}",
                    b.first, b.last, b.blocks, b.txs, b.gas_used, b.fees
                )?;
            }
        }
    }

    let secs = started.elapsed().as_secs_f64();
    let bad = mismatches.load(Ordering::Relaxed);

    if json {
        // Preferred over parsing the summary below: no regex, and a consumer
        // can tell "not counted" from "counted zero".
        println!("{{");
        println!("  \"schemaVersion\": {SCHEMA_VERSION},");
        println!("  \"from\": {from},");
        println!("  \"to\": {to},");
        println!("  \"blocks\": {tot_blocks},");
        if count_txs || verify {
            println!("  \"transactions\": {tot_txs},");
        } else {
            println!("  \"transactions\": null,");
        }
        println!("  \"gasUsed\": {tot_gas},");
        println!("  \"paidFeesWei\": \"{tot_feezz}\",", tot_feezz = tot_fees);
        println!("  \"paidFeesRbtc\": \"{}\",", fmt_rbtc(&tot_fees));
        println!("  \"seconds\": {secs:.1},");
        println!("  \"blocksPerSecond\": {:.0},", tot_blocks as f64 / secs.max(0.001));
        println!("  \"verified\": {verify},");
        println!("  \"mismatches\": {bad}");
        println!("}}");
        return Ok(());
    }

    // STABLE OUTPUT CONTRACT. A collector shells out to this and matches
    // `blocks\s+(\d+)`, `transactions\s+(\d+)` and
    // `total fees\s+(\d+)\s*wei`. Those three lines must keep their shape;
    // additional lines are safe. Renaming "total fees" to "fees" once broke
    // that parser silently -- it matched nothing rather than erroring.
    // Prefer --json for anything automated.
    println!("blocks      {tot_blocks}");
    if count_txs || verify {
        println!("transactions{tot_txs:>12}");
    }
    println!("gas used    {tot_gas}");
    println!("total fees  {tot_fees} wei");
    println!("            {} rBTC", fmt_rbtc(&tot_fees));
    println!("took        {secs:.1}s ({:.0} blk/s)", tot_blocks as f64 / secs.max(0.001));
    if verify {
        println!("verify      {bad} mismatch(es)");
    }
    if let Some(p) = csv {
        println!("wrote       {p}");
    }
    Ok(())
}
