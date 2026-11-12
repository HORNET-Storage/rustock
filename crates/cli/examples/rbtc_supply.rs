//! Sum every rBTC balance in the unitrie at one block, and check it against
//! the bitcoin the peg actually holds.
//!
//! # What the number means
//!
//! RSK mints nothing. Genesis hands the Bridge the whole 21,000,000 RBTC
//! (`rskj_genesis.rs`: `0x...01000006` premined with `21000000 * 10^18` wei)
//! and every later balance is a slice of that one premine, so the sum over
//! *all* accounts is an invariant: exactly 21M at every height, forever. A
//! sum that is not 21M is a bug in the node or a corrupt state, and this tool
//! says so.
//!
//! The interesting quantity is therefore not the total but the complement:
//!
//! ```text
//!   issued = 21,000,000 - balance(Bridge)
//! ```
//!
//! the rBTC outside the Bridge, in user accounts and contracts.
//!
//! # Why `issued` is not by itself a claim on bitcoin
//!
//! It is tempting to read `issued` straight across against the bitcoin the
//! peg holds. It does not work, because neither side means quite what it
//! looks like, and the tool reports the pieces rather than a verdict.
//!
//! On this side, some issued rBTC is **locked**. REMASC withholds fees when a
//! selection rule is broken, and `add_to_burned` records them by incrementing
//! a `burnedBalance` storage counter -- it transfers nothing and destroys
//! nothing. (It could not destroy anything: the sum over all accounts is
//! exactly the premine, which is the invariant checked above.) Those fees sit
//! in REMASC's own balance with no code path that ever pays them out, so they
//! are issued, counted, and unclaimable for good. The same account also holds
//! `rewardBalance`, which *is* still owed to miners, so REMASC's balance must
//! not be treated as locked wholesale.
//!
//! On the bitcoin side, `bridge_btc_holdings` reports what the Bridge has
//! *registered*: peg-ins still inside the 100-confirmation window and
//! sub-minimum dust are held by the federation but tracked nowhere. And
//! bitcoin miner fees for peg-out and federation-migration transactions come
//! out of peg funds without retiring any rBTC, which moves the two sides
//! apart a little with every such transaction.
//!
//! So the tool prints `issued`, the locked counters, and the census, and
//! leaves the comparison to a reader who has both sides complete.
//!
//! # How it scans
//!
//! A whole-trie walk, parallel and size-balanced, modelled on
//! `snapshot::verify_complete`. Every node commits `children_size`, so
//! `total_size` gives any subtree's exact byte count without reading it: the
//! walk splits the trie by repeatedly halving the largest piece until no
//! piece can dominate the tail, then workers take pieces from a shared
//! counter. That same committed size is what makes an honest percentage
//! possible -- progress is reported in bytes of trie accounted for, not in
//! nodes visited, which would be a guess.
//!
//! Unlike `verify_complete` this walk has to carry the bit-path down with it,
//! because a leaf's *key* is what says whether it is an account, and the key
//! exists only as the path taken to reach it.
//!
//! Read-only: the block store and the trie are both opened read-only, so a
//! live node can keep running underneath it.
//!
//! Usage:
//!   rbtc_supply <data-dir> <trie-dir> [block|head-N] [options]
//!
//!   --threads N   workers (default: available parallelism)
//!   --log FILE    append progress and the final report here as well as stderr
//!   --top N       list the N richest accounts (default 20, 0 to skip)
//!
//! Example, against this node:
//!   rbtc_supply /var/lib/rustock /var/lib/rustock/trie-epochs-flat head-20 \
//!       --log /tmp/rbtc_supply.log

use alloy_primitives::{B256, U256};
use rustock_execution::precompiles::REMASC_ADDR;
use rustock_execution::remasc::{
    remasc_storage_key, BURNED_BALANCE_KEY, REWARD_BALANCE_KEY,
};
use rustock_storage::epoch_backend::FlatFactory;
use rustock_storage::epoch_store::{EpochConfig, EpochTrieStore};
use rustock_storage::BlockStore;
use rustock_trie::snapshot::total_size;
use rustock_trie::{
    classify_key, storage_key, AccountState, NodeRef, TrieKeyKind, TrieKeySlice, TrieNode,
    TrieStore,
};
use std::collections::BinaryHeap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The Bridge precompile, which holds the undistributed premine.
const BRIDGE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x06,
];

/// How often progress is written, in wall-clock seconds.
const REPORT_EVERY: Duration = Duration::from_secs(10);

/// Reads one EVM storage slot straight out of the unitrie at a state root.
///
/// rskj stores a slot's value as its big-endian bytes with leading zeros
/// stripped, so it is right-aligned into a word on the way out.
fn read_slot(
    root: &TrieNode,
    store: &dyn TrieStore,
    addr: &alloy_primitives::Address,
    slot: U256,
) -> U256 {
    let key = storage_key(addr, &B256::from(slot));
    match root.get(&TrieKeySlice::from_key(&key), store) {
        Some(data) if data.len() <= 32 => {
            let mut padded = [0u8; 32];
            padded[32 - data.len()..].copy_from_slice(&data);
            U256::from_be_bytes(padded)
        }
        _ => U256::ZERO,
    }
}

/// Writes to stderr and, if configured, to a log file.
struct Log(Option<Mutex<std::fs::File>>);

impl Log {
    fn say(&self, line: &str) {
        eprintln!("{line}");
        if let Some(f) = &self.0 {
            let mut f = f.lock().unwrap();
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }
}

/// Packs an accumulated bit path back into bytes, MSB-first.
///
/// Only meaningful when the path is a whole number of bytes; a trie node can
/// sit mid-byte, and such a node is an interior node, never a key.
fn pack(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (k, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            out[k / 8] |= 0x80 >> (k % 8);
        }
    }
    out
}

/// What one worker found. Summed across workers at the end.
#[derive(Default)]
struct Tally {
    nodes: u64,
    accounts: u64,
    balance: U256,
    code: u64,
    storage_prefix: u64,
    storage: u64,
    /// A leaf whose key `classify_key` does not recognise. Expected to be 0.
    unknown: u64,
    /// An account key whose node carries no inline value -- impossible for a
    /// well-formed account record, which is far too short to be stored long.
    /// Counted rather than ignored so a silent undercount cannot happen.
    undecodable: u64,
    /// The Bridge's own balance, picked out during the walk rather than read
    /// off the top-N list: it must be reported even with `--top 0`.
    bridge_balance: Option<U256>,
    /// REMASC's balance, for the same reason. REMASC is where block fees
    /// accumulate before they are paid out, and where burned fees stay.
    remasc_balance: Option<U256>,
    /// Richest accounts, as a min-heap capped at `top_n` (Reverse-ordered).
    top: BinaryHeap<std::cmp::Reverse<(U256, Vec<u8>)>>,
}

impl Tally {
    fn offer(&mut self, bal: U256, addr: &[u8], top_n: usize) {
        if top_n == 0 {
            return;
        }
        if self.top.len() < top_n {
            self.top.push(std::cmp::Reverse((bal, addr.to_vec())));
        } else if let Some(std::cmp::Reverse((min, _))) = self.top.peek() {
            if bal > *min {
                self.top.pop();
                self.top.push(std::cmp::Reverse((bal, addr.to_vec())));
            }
        }
    }

    fn merge(&mut self, other: Tally, top_n: usize) {
        self.nodes += other.nodes;
        self.accounts += other.accounts;
        self.balance += other.balance;
        self.code += other.code;
        self.storage_prefix += other.storage_prefix;
        self.storage += other.storage;
        self.unknown += other.unknown;
        self.undecodable += other.undecodable;
        if let Some(b) = other.bridge_balance {
            self.bridge_balance = Some(b);
        }
        if let Some(b) = other.remasc_balance {
            self.remasc_balance = Some(b);
        }
        for entry in other.top.into_iter() {
            let (b, a) = entry.0;
            self.offer(b, &a, top_n);
        }
    }
}

/// Renders wei as RBTC with full 18-decimal precision, no rounding.
fn rbtc(wei: U256) -> String {
    let unit = U256::from(10u64).pow(U256::from(18));
    let whole = wei / unit;
    let frac = wei % unit;
    // Group the integer part in threes so 21000000 is readable at a glance.
    let w = whole.to_string();
    let mut grouped = String::new();
    for (i, c) in w.chars().enumerate() {
        if i > 0 && (w.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("{grouped}.{:018}", frac)
}

fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let positional: Vec<&String> = argv
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            !s.starts_with("--") && (*i == 0 || !argv[i - 1].starts_with("--"))
        })
        .map(|(_, s)| s)
        .collect();
    if positional.len() < 2 {
        anyhow::bail!(
            "usage: rbtc_supply <data-dir> <trie-dir> [block|head-N] \
             [--threads N] [--log FILE] [--top N]"
        );
    }
    let opt = |name: &str| -> Option<String> {
        argv.iter().position(|a| a == name).and_then(|i| argv.get(i + 1)).cloned()
    };
    let threads = match opt("--threads") {
        Some(s) => s.parse::<usize>()?.max(1),
        None => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8),
    };
    let top_n = match opt("--top") {
        Some(s) => s.parse::<usize>()?,
        None => 20,
    };
    let log = Log(match opt("--log") {
        Some(p) => Some(Mutex::new(
            std::fs::OpenOptions::new().create(true).append(true).open(p)?,
        )),
        None => None,
    });

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

    log.say(&format!("=== rbtc_supply  {}", chrono_now()));
    log.say(&format!("block     #{number}  ({hash})"));
    log.say(&format!("stateRoot {:?}", header.state_root));

    let total_bytes = total_size(&root, store);
    log.say(&format!(
        "trie      {total_bytes} bytes committed by children_size; {threads} worker(s)"
    ));

    // ---- phase one: split by committed size ------------------------------
    //
    // Finer than verify_complete's split (which targets total/(workers*4)),
    // because here the piece is also the unit of progress reporting: a piece
    // worth 3% of the trie would make the percentage jump in 3% steps. Aim
    // for a few thousand pieces so the bar moves smoothly.
    let bound = (total_bytes / (threads as u64 * 32)).max(1);
    let max_pieces = threads * 512;

    let start = Instant::now();
    let mut pieces: Vec<(Arc<TrieNode>, Vec<u8>, u64)> = Vec::new();
    let mut heap: BinaryHeap<(u64, usize)> = BinaryHeap::new();
    pieces.push((Arc::new(root.clone()), Vec::new(), total_bytes));
    heap.push((total_bytes, 0));

    // Nodes visited while splitting are accounted for here, with their keys.
    let mut head_tally = Tally::default();

    while let Some(&(size, _)) = heap.peek() {
        if size <= bound || heap.len() >= max_pieces {
            break;
        }
        let (_, idx) = heap.pop().expect("peeked");
        let (node, prefix, _) = pieces[idx].clone();

        let mut bits = prefix;
        bits.extend_from_slice(node.shared_path.expand());
        visit(&node, &bits, &mut head_tally, top_n);

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
    log.say(&format!(
        "split     {} piece(s), largest {} bytes, in {:.1}s",
        frontier.len(),
        frontier.iter().map(|p| p.2).max().unwrap_or(0),
        start.elapsed().as_secs_f64()
    ));

    // ---- phase two: walk them --------------------------------------------
    let next = AtomicUsize::new(0);
    let bytes_done = AtomicU64::new(0);
    let nodes_seen = AtomicU64::new(0);
    let pieces_done = AtomicU64::new(0);
    let finished = AtomicBool::new(false);
    let failure: Mutex<Option<String>> = Mutex::new(None);
    let tallies: Mutex<Vec<Tally>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        // A reporter thread, so progress is wall-clock paced rather than tied
        // to how fast pieces happen to complete. It is joined explicitly
        // below: a scope waits for every thread it spawned, so leaving this
        // one looping on a flag set after the scope would deadlock.
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
                let secs = t0.elapsed().as_secs_f64();
                let eta = if done > 0 {
                    format!("~{:.0}s left", (total_bytes.saturating_sub(done)) as f64 * secs / done as f64)
                } else {
                    "eta unknown".to_string()
                };
                log.say(&format!(
                    "progress  {pct:6.2}%  {}/{} pieces  {} nodes  {secs:.0}s elapsed  {eta}",
                    pieces_done.load(Ordering::Relaxed),
                    frontier.len(),
                    nodes_seen.load(Ordering::Relaxed),
                ));
            }
        });

        let mut workers = Vec::new();
        for _ in 0..threads {
            let frontier = &frontier;
            let next = &next;
            let failure = &failure;
            let tallies = &tallies;
            let bytes_done = &bytes_done;
            let nodes_seen = &nodes_seen;
            let pieces_done = &pieces_done;
            workers.push(scope.spawn(move || {
                let mut tally = Tally::default();
                loop {
                    if failure.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((subtree, prefix, size)) = frontier.get(i) else { break };

                    let mut stack: Vec<(Arc<TrieNode>, Vec<u8>)> =
                        vec![(subtree.clone(), prefix.clone())];
                    let mut local = 0u64;
                    while let Some((node, prefix)) = stack.pop() {
                        let mut bits = prefix;
                        bits.extend_from_slice(node.shared_path.expand());
                        visit(&node, &bits, &mut tally, top_n);
                        local += 1;

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
                                    let mut slot = failure.lock().unwrap();
                                    if slot.is_none() {
                                        *slot = Some(
                                            "trie is incomplete: a child node is missing"
                                                .to_string(),
                                        );
                                    }
                                    return;
                                }
                            }
                        }
                        if local >= 8192 {
                            nodes_seen.fetch_add(local, Ordering::Relaxed);
                            local = 0;
                        }
                    }
                    nodes_seen.fetch_add(local, Ordering::Relaxed);
                    bytes_done.fetch_add(*size, Ordering::Relaxed);
                    pieces_done.fetch_add(1, Ordering::Relaxed);
                }
                tallies.lock().unwrap().push(tally);
            }));
        }

        // Workers first, then stop the reporter: the scope joins everything
        // it spawned, so the flag has to be set from inside.
        for w in workers {
            let _ = w.join();
        }
        finished.store(true, Ordering::Relaxed);
        let _ = reporter.join();
    });

    if let Some(e) = failure.lock().unwrap().take() {
        anyhow::bail!(e);
    }

    let mut total = head_tally;
    for t in tallies.lock().unwrap().drain(..) {
        total.merge(t, top_n);
    }

    // ---- report -----------------------------------------------------------
    let elapsed = start.elapsed().as_secs_f64();
    let expected = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));
    let bridge = total.bridge_balance;

    log.say(&format!(
        "done      {} nodes in {elapsed:.1}s ({:.0} nodes/s)",
        total.nodes,
        total.nodes as f64 / elapsed.max(0.001)
    ));
    log.say("");
    log.say(&format!("## unitrie census at #{number}"));
    log.say(&format!("  accounts        {:>12}", total.accounts));
    log.say(&format!("  code leaves     {:>12}", total.code));
    log.say(&format!("  storage roots   {:>12}", total.storage_prefix));
    log.say(&format!("  storage slots   {:>12}", total.storage));
    log.say(&format!("  unrecognised    {:>12}", total.unknown));
    log.say(&format!("  undecodable     {:>12}", total.undecodable));
    log.say("");
    log.say(&format!("## rBTC at #{number}"));
    log.say(&format!("  sum of all balances  {:>40} RBTC", rbtc(total.balance)));
    log.say(&format!("  genesis premine      {:>40} RBTC", rbtc(expected)));
    if total.balance == expected {
        log.say("  -> conserved: the sum is exactly the premine, as it must be");
    } else {
        // Not a statement about the peg: this compares the trie's own total
        // against the premine, so a mismatch means a node bug or a corrupt
        // state, not anything about bitcoin backing.
        let (word, d) = if total.balance < expected {
            ("under", expected - total.balance)
        } else {
            ("over", total.balance - expected)
        };
        log.say(&format!(
            "  -> NOT CONSERVED: {word} the premine by {} RBTC",
            rbtc(d)
        ));
        log.say("     The trie total must equal the premine exactly. A mismatch is a");
        log.say("     node or state-corruption bug; it says nothing about peg backing.");
    }

    // REMASC's two counters. `burnedBalance` is the running total of fees
    // the selection rules withheld; `rewardBalance` is what is still owed to
    // miners. Neither moves any rBTC -- both are bookkeeping over the balance
    // REMASC already holds.
    let burned = read_slot(&root, store, &REMASC_ADDR, remasc_storage_key(BURNED_BALANCE_KEY));
    let reward = read_slot(&root, store, &REMASC_ADDR, remasc_storage_key(REWARD_BALANCE_KEY));

    match bridge {
        Some(b) => {
            let outside = total.balance.saturating_sub(b);
            log.say("");
            log.say("  Bridge (0x...01000006) holds the undistributed premine:");
            log.say(&format!("  in the Bridge        {:>40} RBTC", rbtc(b)));
            log.say(&format!("  ISSUED (outside it)  {:>40} RBTC", rbtc(outside)));
            log.say("");
            log.say("  REMASC (0x...01000008), where block fees accumulate:");
            log.say(&format!(
                "  balance              {:>40} RBTC",
                total.remasc_balance.map(rbtc).unwrap_or_else(|| "(no account)".into())
            ));
            log.say(&format!("  burnedBalance        {:>40} RBTC", rbtc(burned)));
            log.say(&format!("  rewardBalance        {:>40} RBTC", rbtc(reward)));
            log.say("");
            log.say("  `burnedBalance` is a counter, not a transfer: the rBTC it names is");
            log.say("  still part of REMASC's balance and of the issued total above, but no");
            log.say("  code path ever pays it out, so it is locked for good.");
            log.say("");
            log.say("  Comparing the issued total against the bitcoin the peg holds is only");
            log.say("  meaningful once both sides are complete. On this side, locked rBTC is");
            log.say("  issued but unclaimable. On the bitcoin side, bridge_btc_holdings sees");
            log.say("  only what the Bridge has registered -- peg-ins inside the");
            log.say("  100-confirmation window and sub-minimum dust are held but untracked --");
            log.say("  and bitcoin miner fees for peg-out and migration transactions are paid");
            log.say("  out of peg funds without retiring any rBTC. Account for all of those");
            log.say("  before reading anything into a difference between the two figures.");
        }
        None => log.say("  (no Bridge account in the trie at this height -- unexpected)"),
    }

    if top_n > 0 {
        let mut ranked: Vec<(U256, Vec<u8>)> =
            total.top.iter().map(|r| r.0.clone()).collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0));
        log.say("");
        log.say(&format!("## the {} richest accounts", ranked.len()));
        for (i, (bal, addr)) in ranked.iter().enumerate() {
            let a: String = addr.iter().map(|x| format!("{x:02x}")).collect();
            let note = if addr.as_slice() == BRIDGE { "  <- Bridge" } else { "" };
            log.say(&format!("  {:>3}. 0x{a:<40} {:>32} RBTC{note}", i + 1, rbtc(*bal)));
        }
    }

    Ok(())
}

/// Accounts for one node: counts it, and if it carries a value, classifies
/// the key the path spells out and folds an account balance into the tally.
fn visit(node: &TrieNode, bits: &[u8], tally: &mut Tally, top_n: usize) {
    tally.nodes += 1;
    if node.value.is_none() && node.value_hash.is_none() {
        return;
    }
    // A key is a whole number of bytes. A valued node on a bit boundary that
    // is not a byte boundary cannot be one, and the unitrie does not make
    // them; counting it as unrecognised would be a lie, so skip it.
    if !bits.len().is_multiple_of(8) {
        tally.unknown += 1;
        return;
    }
    let key = pack(bits);
    match classify_key(&key) {
        TrieKeyKind::Account { address } => {
            tally.accounts += 1;
            // Account records are a short RLP triple, always stored inline.
            // A missing inline value here would silently drop a balance, so
            // it is counted rather than passed over.
            let Some(v) = &node.value else {
                tally.undecodable += 1;
                return;
            };
            match AccountState::decode(v) {
                Ok(acct) => {
                    tally.balance += acct.balance;
                    if address.as_slice() == BRIDGE {
                        tally.bridge_balance = Some(acct.balance);
                    }
                    if address.as_slice() == REMASC_ADDR.as_slice() {
                        tally.remasc_balance = Some(acct.balance);
                    }
                    tally.offer(acct.balance, &address, top_n);
                }
                Err(_) => tally.undecodable += 1,
            }
        }
        TrieKeyKind::Code { .. } => tally.code += 1,
        TrieKeyKind::StoragePrefix { .. } => tally.storage_prefix += 1,
        TrieKeyKind::Storage { .. } => tally.storage += 1,
        TrieKeyKind::Unknown => tally.unknown += 1,
    }
}

/// A timestamp for the log, without pulling in a date crate.
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix {secs}")
}
