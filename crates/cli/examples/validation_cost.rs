//! What a real block costs *outside* execution.
//!
//! `loadtest` measures execution and the commit, and deliberately nothing
//! else: it hands `execute_block` the senders rather than recovering them,
//! and builds a header with `difficulty: 1` and no merged-mining fields.
//! That is the right shape for an instrument -- adding the rest would put
//! noise between a change and its effect -- but it means its transactions
//! per second are a ceiling for the state half of a block, not a node's
//! throughput.
//!
//! So measure the missing pieces on their own, on real mainnet data, and
//! add them back arithmetically.
//!
//! Two pieces are measured here:
//!
//!   * **Header verification**, the full `HeaderVerifier::default_rsk` set
//!     against the real parent -- gas used and limit bounds, extra data,
//!     block number, timestamp, parent gas limit, previous minimum gas
//!     price, difficulty, and the merged-mining proof of work.
//!   * **Sender recovery**, `Transaction::recover_sender`, which a node
//!     runs once per transaction and `loadtest` never runs at all. Timed
//!     twice: once as the node does it today, through the pure-Rust
//!     `k256`, and once through `secp256k1` -- the rust-bitcoin bindings
//!     to Pieter Wuille's C library, reached here via the `bitcoin`
//!     crate, which already depends on it. Both must agree on every
//!     address or the comparison is meaningless.
//!
//! Both are measured on headers and transactions read from the running
//! node's own store, read-only.
//!
//! Usage: cargo run --release --example validation_cost -- [data-dir] [iters]

use anyhow::{Context, Result};
use rustock_core::config::ChainConfig;
use rustock_core::{Header, Transaction};
use rustock_core::validation::HeaderVerifier;
use rustock_storage::BlockStore;
use std::sync::Arc;
use std::time::Instant;

const MAINNET_CHAIN_ID: u64 = 30;

/// Median and mean of a sample, in microseconds.
fn stats(mut us: Vec<f64>) -> (f64, f64, f64, f64) {
    us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = us.len();
    let median = if n.is_multiple_of(2) { (us[n / 2 - 1] + us[n / 2]) / 2.0 } else { us[n / 2] };
    let mean = us.iter().sum::<f64>() / n as f64;
    (median, mean, us[0], us[n - 1])
}

/// `Transaction::recover_sender`, done through libsecp256k1 instead.
///
/// Deliberately the same shape as the `k256` version in
/// `crates/core/src/types/transaction.rs`, down to the keccak of the
/// uncompressed key's tail, so the two are timed doing the same job. Only
/// the recovery: every transaction timed has passed the network's rules for
/// a signature in `recover_sender` first.
fn recover_with_libsecp(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    tx: &Transaction,
) -> Option<alloy_primitives::Address> {
    use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use bitcoin::secp256k1::Message;
    use sha3::{Digest, Keccak256};

    let hash = tx.signing_hash();
    let (_, recovery_id) = tx.chain_and_recovery_id()?;
    let recovery_id = i32::from(recovery_id);

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&tx.r.to_be_bytes::<32>());
    sig_bytes[32..].copy_from_slice(&tx.s.to_be_bytes::<32>());

    let recid = RecoveryId::from_i32(recovery_id).ok()?;
    let sig = RecoverableSignature::from_compact(&sig_bytes, recid).ok()?;
    let msg = Message::from_digest(hash.0);
    let key = secp.recover_ecdsa(&msg, &sig).ok()?;

    let uncompressed = key.serialize_uncompressed();
    let digest = Keccak256::digest(&uncompressed[1..]);
    Some(alloy_primitives::Address::from_slice(&digest[12..]))
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| "/var/lib/rustock".into());
    let iters: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);

    let store = BlockStore::open_read_only(&dir)
        .with_context(|| format!("opening the block store at {dir} read-only"))?;
    let head = store.head()?.context("the store has no head")?;
    let head_header = store.header(head)?.context("the head header is missing")?;
    let top = head_header.number;
    println!("store {dir}\n  head #{top}");

    // Walk back from the head collecting (header, parent) pairs that carry
    // merged-mining fields, and every transaction found along the way.
    // Mainnet blocks are mostly near-empty, so the transactions have to be
    // gathered over a range rather than taken from one block.
    let mut pairs: Vec<(Header, Header)> = Vec::new();
    let mut txs: Vec<Transaction> = Vec::new();
    let mut blocks_seen = 0u64;
    let mut txs_seen = 0u64;
    let scan = 2_000u64;

    for n in (top.saturating_sub(scan)..=top).rev() {
        let Some(hash) = store.canonical_hash(n)? else { continue };
        let Some(header) = store.header(hash)? else { continue };
        let Some(parent) = store.header(header.parent_hash)? else { continue };
        blocks_seen += 1;
        if let Some((block_txs, _)) = store.body(hash)? {
            txs_seen += block_txs.len() as u64;
            if txs.len() < iters {
                txs.extend(block_txs);
            }
        }
        if pairs.len() < iters && header.bitcoin_merged_mining_header.is_some() {
            pairs.push((header, parent));
        }
        if pairs.len() >= iters && txs.len() >= iters {
            break;
        }
    }

    anyhow::ensure!(!pairs.is_empty(), "no merged-mined headers in the last {scan} blocks");
    anyhow::ensure!(!txs.is_empty(), "no transactions in the last {scan} blocks");
    println!(
        "  sampled {} headers and {} transactions over {blocks_seen} blocks",
        pairs.len(),
        txs.len()
    );
    let txs_per_block = txs_seen as f64 / blocks_seen.max(1) as f64;
    println!("  mainnet averaged {txs_per_block:.2} transactions per block over that range");

    let config = Arc::new(ChainConfig::mainnet());
    let verifier = HeaderVerifier::default_rsk(config);

    // Headers memoise their own hash and their merged-mining hash on first
    // use, and proof of work is the expensive half of verification -- so a
    // loop over one header would measure the cache, not the check. Each
    // iteration gets a header with both caches cleared.
    let mut header_us = Vec::with_capacity(pairs.len());
    let mut accepted = 0usize;
    for (header, parent) in &pairs {
        let mut h = header.clone();
        h.cached_hash = None;
        h.cached_hash_for_merged_mining = None;
        let at = Instant::now();
        let ok = verifier.verify(&h, Some(parent)).is_ok();
        header_us.push(at.elapsed().as_secs_f64() * 1e6);
        if ok {
            accepted += 1;
        }
    }

    // Failures are timed separately rather than mixed in. A transaction
    // whose `v` is not a valid recovery id -- REMASC's, among others --
    // bails before touching the curve, in well under a microsecond, and
    // averaging those together with real recoveries would halve the
    // figure while measuring nothing. A node still pays the failure, but
    // it pays it once and cheaply.
    let mut recover_us = Vec::with_capacity(txs.len());
    let mut rejected_us = Vec::new();
    for tx in &txs {
        let at = Instant::now();
        let ok = tx.recover_sender(MAINNET_CHAIN_ID).is_ok();
        let us = at.elapsed().as_secs_f64() * 1e6;
        if ok { recover_us.push(us) } else { rejected_us.push(us) }
    }
    let recovered = recover_us.len();
    anyhow::ensure!(!recover_us.is_empty(), "no transaction's sender could be recovered");

    // The same recoveries through libsecp256k1. The context holds
    // precomputed tables and is built once, as a node would: building it
    // per call would measure the setup rather than the recovery.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut secp_us = Vec::with_capacity(txs.len());
    let mut agreed = 0usize;
    let mut disagreed = 0usize;
    for tx in &txs {
        let Ok(expected) = tx.recover_sender(MAINNET_CHAIN_ID) else {
            continue;
        };
        let at = Instant::now();
        let got = recover_with_libsecp(&secp, tx);
        secp_us.push(at.elapsed().as_secs_f64() * 1e6);
        match got {
            Some(a) if a == expected => agreed += 1,
            _ => disagreed += 1,
        }
    }

    let (h_med, h_mean, h_min, h_max) = stats(header_us);
    let (r_med, r_mean, r_min, r_max) = stats(recover_us);
    let (s_med, s_mean, s_min, s_max) = stats(secp_us);

    println!("\n{:<22}{:>10}{:>10}{:>10}{:>10}", "", "median", "mean", "min", "max");
    println!("{:<22}{h_med:>10.1}{h_mean:>10.1}{h_min:>10.1}{h_max:>10.1}", "header verify, us");
    println!("{:<22}{r_med:>10.1}{r_mean:>10.1}{r_min:>10.1}{r_max:>10.1}", "recover, k256 us");
    println!("{:<22}{s_med:>10.1}{s_mean:>10.1}{s_min:>10.1}{s_max:>10.1}", "recover, secp256k1");
    println!(
        "  libsecp256k1 is {:.2}x the speed of k256 on the same transactions",
        r_med / s_med.max(f64::MIN_POSITIVE)
    );
    anyhow::ensure!(
        disagreed == 0,
        "{disagreed} of {} recoveries disagreed between the two backends; \
         the comparison means nothing until that is explained",
        agreed + disagreed
    );
    println!("  both backends agreed on all {agreed} addresses");
    println!(
        "\n  {accepted}/{} headers verified, {recovered}/{} senders recovered",
        pairs.len(),
        txs.len()
    );
    if !rejected_us.is_empty() {
        let (j_med, _, _, _) = stats(rejected_us.clone());
        println!(
            "  {} transactions carried no recoverable signature (REMASC and the like), \n  \
             rejected in {j_med:.1} us each -- excluded from the figures above",
            rejected_us.len()
        );
    }

    // What it adds to a block, at the block shapes we have measured.
    println!("\n  added cost per block, by transaction count:");
    println!("  {:>6}  {:>14}  {:>16}", "txs", "header, ms", "recovery, ms");
    let shapes = [txs_per_block.round().max(1.0) as u64, 50, 100, 200];
    for n in shapes {
        println!(
            "  {n:>6}  {:>14.2}  {:>16.2}",
            h_med / 1000.0,
            r_med * n as f64 / 1000.0
        );
    }
    Ok(())
}
