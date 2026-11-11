//! What is in the unitrie at one block: accounts, contracts, storage, code.
//!
//! # Why not `--trie-tool`
//!
//! `storage::trie_tool` answers the same question with a recursive
//! single-threaded descent. `docs/trie-scan-baseline.md` records what that
//! costs on RSK mainnet: a 3.5x rate decay over the run, down to 763 nodes/s,
//! and the scan abandoned at 49.29% after 1h52m. The decay is the signature of
//! dependent random reads — a trie descent cannot issue the next read until
//! the previous one lands, so the device sees one request at a time and the
//! page cache stops helping as the working set grows.
//!
//! This walks the same trie at ~150,000 nodes/s and finishes in under two
//! minutes, by splitting the work before walking it. Every node commits
//! `children_size`, so a subtree's byte weight is known without reading it:
//! take the largest piece and split it, repeatedly, until the largest is a
//! small fraction of a worker's share. Then no straggler can dominate the
//! tail, and workers take pieces from a shared counter rather than being
//! dealt them in advance. That same committed size gives an honest percentage
//! — bytes accounted for, not nodes guessed at.
//!
//! The one thing this walk must do that a verification walk need not is carry
//! the bit-path down with it: a leaf's *kind* is decided by its key, and the
//! key exists only as the path taken to reach it.
//!
//! # What it reports
//!
//! Leaves are told apart by key shape (`rustock_trie::key_mapper`):
//!
//! ```text
//! account        0x00 || keccak(addr)[0:10] || addr
//! code           account_key || 0x80
//! storage root   account_key || 0x00
//! storage cell   account_key || 0x00 || keccak(slot)[0:10] || slot'
//! ```
//!
//! A **contract** is counted as an account with a code leaf, which is the
//! honest definition available from the trie alone: `state_flags` does not
//! distinguish one, and an account's balance says nothing about whether it
//! has code.
//!
//! Sizes come from `value_length()`, which covers inline and long values
//! alike, so code sizes are summed without fetching the bodies.
//!
//! # Running it weekly
//!
//! Read-only, safe against the live node, and writes nothing but its JSON.
//! Pick a settled height rather than the head:
//!
//! ```sh
//! cargo build --release -p rustock-cli --example trie_census
//! ./target/release/examples/trie_census \
//!     /var/lib/rustock /var/lib/rustock/trie-epochs-flat head-20 \
//!     --threads 3 --json /path/to/trie-census-$(date -u +%Y%m%d).json
//! ```
//!
//! `--threads` should leave the node a core: on a 4-core box use 3, or 2 if
//! something else is running. Nothing else is needed — no state is written,
//! no scratch, no lock taken on the node's database.
//!
//! The JSON is one flat object, documented by `schemaVersion`. Bump that if a
//! field changes meaning, so a consumer can tell.

use alloy_primitives::U256;
use rustock_storage::epoch_backend::FlatFactory;
use rustock_storage::epoch_store::{EpochConfig, EpochTrieStore};
use rustock_storage::BlockStore;
use rustock_trie::snapshot::total_size;
use rustock_trie::{classify_key, AccountState, NodeRef, TrieKeyKind, TrieNode, TrieStore};
use std::collections::BinaryHeap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The JSON shape's version. Bump when a field changes meaning.
const SCHEMA_VERSION: u32 = 1;

const REPORT_EVERY: Duration = Duration::from_secs(10);

/// Packs an accumulated bit path back into bytes, MSB-first.
fn pack(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (k, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            out[k / 8] |= 0x80 >> (k % 8);
        }
    }
    out
}

/// A distribution summarised without keeping every sample.
#[derive(Default, Clone)]
struct Dist {
    n: u64,
    total: u64,
    max: u64,
}

impl Dist {
    fn add(&mut self, v: u64) {
        self.n += 1;
        self.total += v;
        self.max = self.max.max(v);
    }
    fn merge(&mut self, o: &Dist) {
        self.n += o.n;
        self.total += o.total;
        self.max = self.max.max(o.max);
    }
    fn mean(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.total as f64 / self.n as f64
        }
    }
}

#[derive(Default)]
struct Census {
    nodes: u64,
    /// Nodes carrying a value, i.e. leaves in the keyspace sense.
    valued: u64,

    accounts: u64,
    /// Accounts whose balance is non-zero.
    accounts_with_balance: u64,
    /// Accounts with a non-zero nonce — has ever sent a transaction, or is a
    /// contract (RSK sets a contract's nonce on creation).
    accounts_with_nonce: u64,
    balance_total: U256,

    /// Accounts that have a code leaf. The definition of "contract" here.
    contracts: u64,
    code_bytes: Dist,
    /// Code leaves whose value is stored out of line (> 32 bytes).
    code_long_values: u64,

    storage_roots: u64,
    storage_cells: u64,
    storage_value_bytes: u64,

    /// Keys the mapper does not recognise. Expected zero.
    unknown: u64,
    /// Account records that would not decode. Expected zero.
    undecodable: u64,
}

impl Census {
    fn merge(&mut self, o: Census) {
        self.nodes += o.nodes;
        self.valued += o.valued;
        self.accounts += o.accounts;
        self.accounts_with_balance += o.accounts_with_balance;
        self.accounts_with_nonce += o.accounts_with_nonce;
        self.balance_total += o.balance_total;
        self.contracts += o.contracts;
        self.code_bytes.merge(&o.code_bytes);
        self.code_long_values += o.code_long_values;
        self.storage_roots += o.storage_roots;
        self.storage_cells += o.storage_cells;
        self.storage_value_bytes += o.storage_value_bytes;
        self.unknown += o.unknown;
        self.undecodable += o.undecodable;
    }
}

/// Accounts for one node.
fn visit(node: &TrieNode, bits: &[u8], c: &mut Census) {
    c.nodes += 1;
    if node.value.is_none() && node.value_hash.is_none() {
        return;
    }
    c.valued += 1;
    // A key is a whole number of bits only at a byte boundary; a valued node
    // elsewhere is not one, and the unitrie does not make them.
    if !bits.len().is_multiple_of(8) {
        c.unknown += 1;
        return;
    }
    match classify_key(&pack(bits)) {
        TrieKeyKind::Account { .. } => {
            c.accounts += 1;
            let Some(v) = &node.value else {
                c.undecodable += 1;
                return;
            };
            match AccountState::decode(v) {
                Ok(a) => {
                    if !a.balance.is_zero() {
                        c.accounts_with_balance += 1;
                    }
                    if !a.nonce.is_zero() {
                        c.accounts_with_nonce += 1;
                    }
                    c.balance_total += a.balance;
                }
                Err(_) => c.undecodable += 1,
            }
        }
        TrieKeyKind::Code { .. } => {
            c.contracts += 1;
            let len = node.value_length() as u64;
            c.code_bytes.add(len);
            if node.has_long_value() {
                c.code_long_values += 1;
            }
        }
        TrieKeyKind::StoragePrefix { .. } => c.storage_roots += 1,
        TrieKeyKind::Storage { .. } => {
            c.storage_cells += 1;
            c.storage_value_bytes += node.value_length() as u64;
        }
        TrieKeyKind::Unknown => c.unknown += 1,
    }
}

fn env_or(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let positional: Vec<&String> = argv
        .iter()
        .enumerate()
        .filter(|(i, s)| !s.starts_with("--") && (*i == 0 || !argv[i - 1].starts_with("--")))
        .map(|(_, s)| s)
        .collect();
    if positional.len() < 2 {
        anyhow::bail!(
            "usage: trie_census <data-dir> <trie-dir> [block|head-N] \
             [--threads N] [--json FILE]"
        );
    }
    let threads = match env_or(&argv, "--threads") {
        Some(s) => s.parse::<usize>()?.max(1),
        None => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
    };
    let json_path = env_or(&argv, "--json");

    let blocks = BlockStore::open_read_only(positional[0])?;
    let trie: Arc<dyn TrieStore> = Arc::new(EpochTrieStore::open_read_only_with(
        positional[1],
        EpochConfig::default(),
        Arc::new(FlatFactory::new(0)),
    )?);

    let head = blocks
        .head()?
        .and_then(|h| blocks.header(h).ok().flatten())
        .map(|h| h.number)
        .ok_or_else(|| anyhow::anyhow!("no head"))?;
    let number = match positional.get(2).map(|s| s.as_str()) {
        None => head,
        Some(s) if s.starts_with("head-") => head.saturating_sub(s[5..].parse::<u64>()?),
        Some(s) => s.parse::<u64>()?,
    };

    let hash = blocks
        .canonical_hash(number)?
        .ok_or_else(|| anyhow::anyhow!("#{number} is not canonical here"))?;
    let header = blocks.header(hash)?.ok_or_else(|| anyhow::anyhow!("no header for #{number}"))?;
    let root_bytes = trie.get(header.state_root.as_slice()).ok_or_else(|| {
        anyhow::anyhow!(
            "state for #{number} is not in this trie store -- an epoch node keeps a \
             window, so old heights need an archive"
        )
    })?;
    let root = TrieNode::from_message(&root_bytes, trie.as_ref());
    let store = trie.as_ref();

    eprintln!("block     #{number}  ({hash})");
    eprintln!("stateRoot {:?}", header.state_root);

    let total_bytes = total_size(&root, store);
    eprintln!("trie      {total_bytes} bytes committed by children_size; {threads} worker(s)");

    // ---- split by committed byte weight ----------------------------------
    let bound = (total_bytes / (threads as u64 * 32)).max(1);
    let max_pieces = threads * 512;
    let start = Instant::now();

    let mut pieces: Vec<(Arc<TrieNode>, Vec<u8>, u64)> = Vec::new();
    let mut heap: BinaryHeap<(u64, usize)> = BinaryHeap::new();
    pieces.push((Arc::new(root.clone()), Vec::new(), total_bytes));
    heap.push((total_bytes, 0));
    let mut head_census = Census::default();

    while let Some(&(size, _)) = heap.peek() {
        if size <= bound || heap.len() >= max_pieces {
            break;
        }
        let (_, idx) = heap.pop().expect("peeked");
        let (node, prefix, _) = pieces[idx].clone();
        let mut bits = prefix;
        bits.extend_from_slice(node.shared_path.expand());
        visit(&node, &bits, &mut head_census);
        for (child, bit) in [(&node.left, 0u8), (&node.right, 1u8)] {
            if matches!(child, NodeRef::Empty) {
                continue;
            }
            let Some(n) = child.resolve(store) else {
                anyhow::bail!("trie is incomplete: a child node is missing from the store");
            };
            let sz = total_size(&n, store);
            let mut b = bits.clone();
            b.push(bit);
            pieces.push((n, b, sz));
            heap.push((sz, pieces.len() - 1));
        }
    }
    let frontier: Vec<(Arc<TrieNode>, Vec<u8>, u64)> =
        heap.into_iter().map(|(_, i)| pieces[i].clone()).collect();
    eprintln!(
        "split     {} piece(s), largest {} bytes, in {:.1}s",
        frontier.len(),
        frontier.iter().map(|p| p.2).max().unwrap_or(0),
        start.elapsed().as_secs_f64()
    );

    // ---- walk ------------------------------------------------------------
    let next = AtomicUsize::new(0);
    let bytes_done = AtomicU64::new(0);
    let pieces_done = AtomicU64::new(0);
    let finished = AtomicBool::new(false);
    let failure: Mutex<Option<String>> = Mutex::new(None);
    let out: Mutex<Vec<Census>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        let reporter = scope.spawn(|| {
            let t0 = Instant::now();
            let mut last = Instant::now();
            while !finished.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                if finished.load(Ordering::Relaxed) || last.elapsed() < REPORT_EVERY {
                    continue;
                }
                last = Instant::now();
                let done = bytes_done.load(Ordering::Relaxed);
                let pct = done as f64 * 100.0 / total_bytes.max(1) as f64;
                eprintln!(
                    "progress  {pct:6.2}%  {}/{} pieces  {:.0}s",
                    pieces_done.load(Ordering::Relaxed),
                    frontier.len(),
                    t0.elapsed().as_secs_f64()
                );
            }
        });

        let mut workers = Vec::new();
        for _ in 0..threads {
            let (frontier, next, failure, out) = (&frontier, &next, &failure, &out);
            let (bytes_done, pieces_done) = (&bytes_done, &pieces_done);
            workers.push(scope.spawn(move || {
                let mut c = Census::default();
                loop {
                    if failure.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((subtree, prefix, size)) = frontier.get(i) else { break };
                    let mut stack: Vec<(Arc<TrieNode>, Vec<u8>)> =
                        vec![(subtree.clone(), prefix.clone())];
                    while let Some((node, prefix)) = stack.pop() {
                        let mut bits = prefix;
                        bits.extend_from_slice(node.shared_path.expand());
                        visit(&node, &bits, &mut c);
                        for (child, bit) in [(&node.left, 0u8), (&node.right, 1u8)] {
                            if matches!(child, NodeRef::Empty) {
                                continue;
                            }
                            match child.resolve(store) {
                                Some(n) => {
                                    let mut b = bits.clone();
                                    b.push(bit);
                                    stack.push((n, b));
                                }
                                None => {
                                    let mut s = failure.lock().unwrap();
                                    if s.is_none() {
                                        *s = Some("trie is incomplete: a node is missing".into());
                                    }
                                    return;
                                }
                            }
                        }
                    }
                    bytes_done.fetch_add(*size, Ordering::Relaxed);
                    pieces_done.fetch_add(1, Ordering::Relaxed);
                }
                out.lock().unwrap().push(c);
            }));
        }
        for w in workers {
            let _ = w.join();
        }
        finished.store(true, Ordering::Relaxed);
        let _ = reporter.join();
    });

    if let Some(e) = failure.lock().unwrap().take() {
        anyhow::bail!(e);
    }

    let mut c = head_census;
    for part in out.lock().unwrap().drain(..) {
        c.merge(part);
    }
    let elapsed = start.elapsed().as_secs_f64();

    // ---- report ----------------------------------------------------------
    let eoa = c.accounts.saturating_sub(c.contracts);
    eprintln!(
        "done      {} nodes in {elapsed:.1}s ({:.0} nodes/s)",
        c.nodes,
        c.nodes as f64 / elapsed.max(0.001)
    );
    eprintln!();
    eprintln!("accounts            {:>14}", c.accounts);
    eprintln!("  with code         {:>14}   (contracts)", c.contracts);
    eprintln!("  without code      {:>14}", eoa);
    eprintln!("  non-zero balance  {:>14}", c.accounts_with_balance);
    eprintln!("  non-zero nonce    {:>14}", c.accounts_with_nonce);
    eprintln!("storage roots       {:>14}", c.storage_roots);
    eprintln!("storage cells       {:>14}", c.storage_cells);
    eprintln!("code bytes          {:>14}   mean {:.0}, max {}",
              c.code_bytes.total, c.code_bytes.mean(), c.code_bytes.max);
    eprintln!("storage value bytes {:>14}", c.storage_value_bytes);
    eprintln!("unrecognised        {:>14}", c.unknown);
    eprintln!("undecodable         {:>14}", c.undecodable);

    if let Some(p) = json_path {
        let cells_per_contract = if c.contracts == 0 {
            0.0
        } else {
            c.storage_cells as f64 / c.contracts as f64
        };
        let generated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let json = format!(
            r#"{{
  "schemaVersion": {SCHEMA_VERSION},
  "generatedAtUnix": {generated},
  "block": {number},
  "blockHash": "{hash:?}",
  "stateRoot": "{:?}",
  "trieBytes": {total_bytes},
  "scan": {{
    "nodes": {},
    "valuedNodes": {},
    "threads": {threads},
    "seconds": {elapsed:.1},
    "nodesPerSecond": {:.0},
    "complete": true
  }},
  "accounts": {{
    "total": {},
    "contracts": {},
    "externallyOwned": {},
    "withNonZeroBalance": {},
    "withNonZeroNonce": {}
  }},
  "code": {{
    "leaves": {},
    "totalBytes": {},
    "meanBytes": {:.1},
    "maxBytes": {},
    "storedOutOfLine": {}
  }},
  "storage": {{
    "roots": {},
    "cells": {},
    "valueBytes": {},
    "cellsPerContract": {cells_per_contract:.1}
  }},
  "balanceTotalWei": "{}",
  "integrity": {{
    "unrecognisedKeys": {},
    "undecodableAccounts": {}
  }}
}}
"#,
            header.state_root,
            c.nodes,
            c.valued,
            c.nodes as f64 / elapsed.max(0.001),
            c.accounts,
            c.contracts,
            eoa,
            c.accounts_with_balance,
            c.accounts_with_nonce,
            c.code_bytes.n,
            c.code_bytes.total,
            c.code_bytes.mean(),
            c.code_bytes.max,
            c.code_long_values,
            c.storage_roots,
            c.storage_cells,
            c.storage_value_bytes,
            c.balance_total,
            c.unknown,
            c.undecodable,
        );
        let mut f = std::fs::File::create(&p)
            .map_err(|e| anyhow::anyhow!("creating {p}: {e}"))?;
        f.write_all(json.as_bytes())?;
        eprintln!("\nwrote {p}");
    }
    Ok(())
}
