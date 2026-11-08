//! Did a PowPeg functionary ever submit a signature the Bridge refused?
//!
//! # There is no "invalid signature" event, and that shapes everything
//!
//! The obvious plan -- look for the event the Bridge emits when a signature
//! fails -- does not work, because no such event exists. `addSignature`
//! verifies every signature against its input's sighash
//! (`apply_signatures_to_tx`, rskj `BridgeSupport.processSigning`) and on the
//! first one that does not verify it simply **returns without applying
//! anything**. The call succeeds, consumes its gas, changes no state and logs
//! nothing. A malformed DER signature does revert; a well-formed signature
//! over the wrong sighash does not.
//!
//! What does exist is `add_signature`, and RSKIP326 (fingerroot500,
//! mainnet #5,468,000) changed when it fires:
//!
//! - **from #5,468,000**: only once a signature has actually been applied. So
//!   a successful `addSignature` call with **no** `add_signature` event is a
//!   call that applied nothing -- which is the observable footprint of a
//!   refused signature.
//! - **before #5,468,000**: the event fires *before* verification, for every
//!   caller who is a federation member. It cannot distinguish a good
//!   signature from a bad one, so that range is reported as
//!   indeterminate-from-events rather than silently called clean.
//!
//! # How it scans
//!
//! No execution and no trie. Each worker takes a stripe of heights, reads the
//! body straight from the block store, and keeps the transactions sent to the
//! Bridge whose selector is `addSignature`. The `add_signature` events come
//! from the Bridge event index in one prefix scan, so matching a call to its
//! event is a hash lookup rather than a receipt walk.
//!
//! Whether the caller was a functionary at that height comes from the
//! interval database `federation_intervals` writes -- the federation is not
//! in state this node still holds for most of the chain.
//!
//! Usage:
//!   powpeg_signature_audit <data-dir> <federations.json> [from] [to] [threads]

use rustock_storage::BlockStore;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// `addSignature(bytes,bytes[],bytes)`.
const ADD_SIGNATURE_SELECTOR: [u8; 4] = [0xf1, 0x0b, 0x9c, 0x59];
/// RSKIP326 (fingerroot500) on mainnet: where `add_signature` stops firing
/// for signatures that were not applied.
const RSKIP326_MAINNET: u64 = 5_468_000;
const SOLIDITY_ADD_SIGNATURE: &str = "add_signature(bytes32,address,bytes)";
/// `legacy_topic("add_signature_topic")`: the ASCII name right-aligned in 32
/// bytes, which is how the pre-RSKIP146 events are keyed.
const LEGACY_ADD_SIGNATURE: &str =
    "0x000000000000000000000000006164645f7369676e61747572655f746f706963";

fn abi_bytes(data: &[u8], head_index: usize) -> Option<Vec<u8>> {
    let w = data.get(head_index * 32..head_index * 32 + 32)?;
    let off = u64::from_be_bytes(w[24..32].try_into().ok()?) as usize;
    let len = u64::from_be_bytes(data.get(off + 24..off + 32)?.try_into().ok()?) as usize;
    Some(data.get(off + 32..off + 32 + len)?.to_vec())
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug, Clone)]
struct Call {
    block: u64,
    tx_index: u32,
    tx_hash: alloy_primitives::B256,
    federator_key: Vec<u8>,
    /// The pegout being signed: `addSignature`'s third argument.
    rsk_tx_hash: Vec<u8>,
    succeeded: bool,
}

/// Which keys could sign over which heights.
struct Federations {
    intervals: Vec<(u64, u64, HashSet<String>)>,
}

impl Federations {
    fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut intervals = Vec::new();
        for chunk in text.split("{\"from\":").skip(1) {
            let num = |k: &str| -> Option<u64> {
                let i = chunk.find(k)? + k.len();
                let rest = &chunk[i..];
                let end = rest.find(|c: char| !c.is_ascii_digit() && c != ' ').unwrap_or(rest.len());
                rest[..end].trim().parse().ok()
            };
            let from: u64 = chunk[..chunk.find(',').unwrap_or(0)].trim().parse().unwrap_or(0);
            let to = num("\"to\": ").unwrap_or(u64::MAX);
            let keys: HashSet<String> = chunk
                .split("\"keys\": [")
                .nth(1)
                .map(|k| {
                    k[..k.find(']').unwrap_or(k.len())]
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').to_string())
                        .filter(|s| s.len() == 66)
                        .collect()
                })
                .unwrap_or_default();
            intervals.push((from, to, keys));
        }
        anyhow::ensure!(!intervals.is_empty(), "no intervals in {path}");
        Ok(Self { intervals })
    }

    fn is_functionary(&self, block: u64, key_hex: &str) -> bool {
        self.intervals
            .iter()
            .find(|(f, t, _)| block >= *f && block <= *t)
            .is_some_and(|(_, _, keys)| keys.contains(key_hex))
    }
}

fn main() -> anyhow::Result<()> {
    let mut a = std::env::args().skip(1);
    let dir = a.next().expect("usage: powpeg_signature_audit <data-dir> <federations.json> [from] [to] [threads]");
    let feds_path = a.next().expect("federations.json (from federation_intervals)");
    let from: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let store = Arc::new(BlockStore::open_read_only(&dir)?);
    let head = store
        .head()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(0);
    let to: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(head);
    let threads: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(4);
    let feds = Arc::new(Federations::load(&feds_path)?);
    let bridge = rustock_execution::precompiles::BRIDGE_ADDR;

    // Every add_signature event, by (block, tx_index). One prefix scan each.
    let mut emitted: HashSet<(u64, u32)> = HashSet::new();
    for topic in [
        alloy_primitives::keccak256(SOLIDITY_ADD_SIGNATURE.as_bytes()),
        LEGACY_ADD_SIGNATURE.parse()?,
    ] {
        for (b, tx, _l, _h, _t, _d) in store.scan_bridge_events(topic, 0, u64::MAX)? {
            emitted.insert((b, tx));
        }
    }
    eprintln!("add_signature events indexed: {}", emitted.len());

    // When each pegout became fully signed. `release_btc(bytes32 indexed
    // releaseRskTxHash, bytes)` fires once the last signature lands and the
    // entry leaves `pegoutsWaitingForSignatures`, so this says when a pegout
    // stopped being signable -- which is what separates a refused signature
    // from a functionary that simply arrived late.
    let mut released: HashMap<String, u64> = HashMap::new();
    for topic in [
        alloy_primitives::keccak256("release_btc(bytes32,bytes)".as_bytes()),
    ] {
        for (b, _tx, _l, _h, topics, _d) in store.scan_bridge_events(topic, 0, u64::MAX)? {
            if let Some(t1) = topics.get(1) {
                released.entry(hexs(&t1.0)).and_modify(|e| *e = (*e).min(b)).or_insert(b);
            }
        }
    }
    eprintln!("pegouts with a release_btc: {}", released.len());
    eprintln!("scanning #{from}..#{to} on {threads} threads for addSignature calls");

    // Contiguous ranges, one per worker, rather than interleaved strides.
    // The body is keyed by hash so neither layout helps there, but
    // `canonical_hash` is keyed by height: a worker walking a contiguous run
    // of heights hits the same SST blocks repeatedly, where a strided one
    // touches a different block every step.
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let total = to.saturating_sub(from) + 1;
    let started = std::time::Instant::now();

    let found: Vec<Call> = std::thread::scope(|scope| {
        let reporter = {
            let done = Arc::clone(&done);
            scope.spawn(move || {
                use std::sync::atomic::Ordering::Relaxed;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    let d = done.load(Relaxed);
                    if d >= total {
                        return;
                    }
                    let secs = started.elapsed().as_secs_f64().max(0.001);
                    let rate = d as f64 / secs;
                    let left = (total - d) as f64 / rate.max(1.0);
                    eprintln!(
                        "  {:>5.1}%  {d}/{total} blocks  {:.0} blk/s  eta {:.0}m",
                        100.0 * d as f64 / total as f64,
                        rate,
                        left / 60.0
                    );
                }
            })
        };

        let span = total.div_ceil(threads as u64);
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let done = Arc::clone(&done);
                scope.spawn(move || {
                    use std::sync::atomic::Ordering::Relaxed;
                    let lo = from + i as u64 * span;
                    let hi = (lo + span - 1).min(to);
                    let mut out: Vec<Call> = Vec::new();
                    let mut since_report = 0u64;
                    for n in lo..=hi {
                        let Ok(Some(hash)) = store.canonical_hash(n) else {
                            continue;
                        };
                        if let Ok(Some((txs, _))) = store.body(hash) {
                            // Find the calls first. The receipts are read only
                            // when there is one to attach a status to: about
                            // 26,000 blocks in 9.4 million carry an
                            // `addSignature`, so fetching them for every block
                            // was most of the I/O and nearly all of it wasted.
                            let mut hits: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();
                            for (idx, tx) in txs.iter().enumerate() {
                                if tx.to.as_ref() != bridge.as_slice() {
                                    continue;
                                }
                                if tx.input.len() < 4 || tx.input[..4] != ADD_SIGNATURE_SELECTOR {
                                    continue;
                                }
                                hits.push((
                                    idx,
                                    abi_bytes(&tx.input[4..], 0).unwrap_or_default(),
                                    abi_bytes(&tx.input[4..], 2).unwrap_or_default(),
                                ));
                            }
                            if !hits.is_empty() {
                                let receipts = store.receipts(hash).ok().flatten();
                                for (idx, key, pegout) in hits {
                                    out.push(Call {
                                        block: n,
                                        tx_index: idx as u32,
                                        tx_hash: txs[idx].tx_hash(),
                                        federator_key: key,
                                        rsk_tx_hash: pegout,
                                        succeeded: receipts
                                            .as_ref()
                                            .and_then(|r| r.get(idx))
                                            .map(|r| r.status)
                                            .unwrap_or(false),
                                    });
                                }
                            }
                        }
                        since_report += 1;
                        if since_report == 2_000 {
                            done.fetch_add(since_report, Relaxed);
                            since_report = 0;
                        }
                    }
                    done.fetch_add(since_report, Relaxed);
                    out
                })
            })
            .collect();
        let calls: Vec<Call> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        done.store(total, std::sync::atomic::Ordering::Relaxed);
        let _ = reporter.join();
        calls
    });

    let mut calls = found;
    calls.sort_by_key(|c| (c.block, c.tx_index));
    println!("\naddSignature calls found: {}", calls.len());

    // A federator that has already signed a pegout applies nothing when it
    // sends the same signature again: `apply_signatures_to_tx` stops at the
    // first input this key has already signed, so `applied` is false and no
    // event fires. That is a retry, not a refusal, and the signers do it
    // constantly. Recognised without state: if an earlier call from the same
    // key for the same pegout DID emit `add_signature`, this one is a repeat.
    let mut already_signed: HashSet<(String, String)> = HashSet::new();
    for c in &calls {
        if emitted.contains(&(c.block, c.tx_index)) {
            already_signed.insert((hexs(&c.rsk_tx_hash), hexs(&c.federator_key)));
        }
    }

    let (mut reverted, mut not_functionary, mut applied) = (0usize, 0usize, 0usize);
    let mut repeat_post = 0usize;
    let mut silent_post: Vec<&Call> = Vec::new();
    let mut late_post = 0usize;
    let mut silent_pre: Vec<&Call> = Vec::new();
    let mut per_key: BTreeMap<String, usize> = BTreeMap::new();

    for c in &calls {
        let key_hex = hexs(&c.federator_key);
        if !c.succeeded {
            reverted += 1;
            continue;
        }
        if !feds.is_functionary(c.block, &key_hex) {
            not_functionary += 1;
            continue;
        }
        if emitted.contains(&(c.block, c.tx_index)) {
            applied += 1;
        } else if c.block >= RSKIP326_MAINNET {
            // Was the pegout still waiting when this call arrived? If it had
            // already been released, the signature had nothing to apply to
            // and the silence is a race between functionaries, not a fault.
            let finished_earlier = released
                .get(&hexs(&c.rsk_tx_hash))
                .is_some_and(|rb| *rb <= c.block);
            let repeat = already_signed
                .contains(&(hexs(&c.rsk_tx_hash), key_hex.clone()));
            if finished_earlier {
                late_post += 1;
            } else if repeat {
                repeat_post += 1;
            } else {
                silent_post.push(c);
                *per_key.entry(key_hex).or_default() += 1;
            }
        } else {
            silent_pre.push(c);
        }
    }

    println!("  reverted (malformed DER and the like):       {reverted}");
    println!("  caller not a functionary at that height:     {not_functionary}");
    println!("  signature applied (add_signature emitted):   {applied}");
    println!("  pegout already released, call arrived late:  {late_post}");
    println!("  same federator had already signed this pegout: {repeat_post}");
    println!("  functionary call, NO event, >= RSKIP326:     {}  <-- signature not applied", silent_post.len());
    println!("  functionary call, NO event, <  RSKIP326:     {}  (event fires pre-verification; indeterminate)", silent_pre.len());

    if !silent_post.is_empty() {
        println!("\nFunctionary calls from #{RSKIP326_MAINNET} on, against a pegout still waiting, that applied nothing:");
        if let Ok(mut f) = std::fs::File::create("powpeg_unexplained.csv") {
            use std::io::Write;
            let _ = writeln!(f, "block,tx_index,tx_hash,federator_key,rsk_tx_hash");
            for c in &silent_post {
                let _ = writeln!(
                    f,
                    "{},{},0x{},{},{}",
                    c.block,
                    c.tx_index,
                    hexs(&c.tx_hash.0),
                    hexs(&c.federator_key),
                    hexs(&c.rsk_tx_hash)
                );
            }
            println!("(full list written to powpeg_unexplained.csv)");
        }
        for c in silent_post.iter().take(40) {
            println!(
                "  #{:<9} tx{:<3} 0x{}  key {}",
                c.block,
                c.tx_index,
                hexs(&c.tx_hash.0[..8]),
                &hexs(&c.federator_key)[..16]
            );
        }
        println!("\nby functionary key:");
        for (k, n) in &per_key {
            println!("  {}…  {n}", &k[..16]);
        }
    }
    Ok(())
}
