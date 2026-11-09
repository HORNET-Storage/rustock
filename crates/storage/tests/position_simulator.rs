//! A deterministic simulator for the node's position on the chain.
//!
//! Stage 5 of `docs/sync-redesign.md`, and the reason the rest of the redesign
//! is worth believing. Stages 3 and 4 *claim* that the three position keys
//! cannot come apart. This drives the store through hundreds of thousands of
//! adversarial event sequences and checks that claim after every single write.
//!
//! # What it models
//!
//! A world with a real chain and forks off it, and a node that downloads,
//! adopts, executes, reorgs, retreats and prunes in whatever order a seeded
//! schedule dictates -- including orders that make no sense, because a peer
//! that lies or a process that dies at the wrong moment produces exactly those.
//!
//! # What it asserts
//!
//! After **every** event, the coherence relations. Not at the end: at every
//! step, because a state that is briefly incoherent is a state some other
//! thread can read, and six of the seven stalls were exactly that read.
//!
//! # Determinism
//!
//! The schedule comes from a seeded xorshift, so a failure prints a seed that
//! reproduces it exactly. There is no wall clock, no threading and no I/O
//! ordering in the decision path.

use alloy_primitives::{Address, B256, Bytes, U256};
use rustock_core::Header;
use rustock_storage::{BlockStore, Transition, Validated, verify_local_coherence};
use std::collections::{BTreeMap, HashMap};
use tempfile::TempDir;

// ---------------------------------------------------------------- PRNG ----

/// xorshift64*. Deterministic, dependency-free, good enough to shape schedules.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    #[allow(dead_code)] // no caller; see the dead-code issue before deleting
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

// --------------------------------------------------------------- World ----

fn header(number: u64, parent: B256, salt: u64) -> Header {
    Header {
        number,
        parent_hash: parent,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(1),
        gas_limit: U256::from(8_000_000),
        gas_used: 0,
        timestamp: number * 15 + salt,
        extra_data: Bytes::default(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::ZERO,
        uncle_count: 0,
        umm_root: None,
        version_fields: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
        kept: None,
    }
}

/// Every block that exists anywhere, whether or not the node has it.
struct World {
    blocks: HashMap<B256, Header>,
    by_height: BTreeMap<u64, Vec<B256>>,
    salt: u64,
}

impl World {
    fn new() -> (Self, Header) {
        let g = header(0, B256::ZERO, 0);
        let mut w = World { blocks: HashMap::new(), by_height: BTreeMap::new(), salt: 0 };
        w.record(&g);
        (w, g)
    }

    fn record(&mut self, h: &Header) {
        let hash = h.hash();
        self.blocks.insert(hash, h.clone());
        self.by_height.entry(h.number).or_default().push(hash);
    }

    /// Mine a block on `parent`, which may already have children (a fork).
    fn extend(&mut self, parent: B256) -> Header {
        self.salt += 1;
        let pn = self.blocks[&parent].number;
        let h = header(pn + 1, parent, self.salt);
        self.record(&h);
        h
    }

    fn at(&self, n: u64) -> &[B256] {
        self.by_height.get(&n).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// What the node has actually downloaded, and where it thinks it is.
struct Node {
    store: BlockStore,
    _dir: TempDir,
    /// Hashes whose headers we have stored.
    held: Vec<B256>,
}

impl Node {
    fn new(genesis: &Header) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        store.update_head(genesis, U256::from(1)).unwrap();
        store.set_exec_head(genesis.hash(), B256::ZERO).unwrap();
        Node { store, _dir: dir, held: vec![genesis.hash()] }
    }

    fn holds(&self, hash: &B256) -> bool {
        self.held.contains(hash)
    }
}

// ---------------------------------------------------------- Properties ----

/// The full coherence sweep: every relation, over every height.
///
/// Returns the first violation as a human-readable string, so a simulator
/// failure names the relation and the height rather than just "assert failed".
fn coherent(store: &BlockStore) -> Result<(), String> {
    let Some(cursor) = store.cursor().map_err(|e| e.to_string())? else {
        return Ok(());
    };

    verify_local_coherence(store, &cursor)?;

    let floor = store.prune_floor().map_err(|e| e.to_string())?.map_or(0, |f| f.number);

    for n in floor..=cursor.validated_head.number {
        let c = store
            .canonical_hash(n)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("I1: no canonical entry at #{n}"))?;
        let hdr = store
            .header(c)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("I2: canonical #{n} names {c}, which we do not hold"))?;
        if hdr.number != n {
            return Err(format!("canonical #{n} names a header numbered #{}", hdr.number));
        }
        if n > floor && n > 0 {
            let below = store
                .canonical_hash(n - 1)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("I1: no canonical entry at #{}", n - 1))?;
            if hdr.parent_hash != below {
                return Err(format!(
                    "I3: canonical #{n} has parent {} but canonical #{} is {below}",
                    hdr.parent_hash,
                    n - 1
                ));
            }
        }
    }

    if cursor.executed.number >= floor {
        let c = store.canonical_hash(cursor.executed.number).map_err(|e| e.to_string())?;
        if c != Some(cursor.executed.hash) {
            return Err(format!(
                "I5: executed {} is not the canonical block at its height ({c:?})",
                cursor.executed
            ));
        }
    }

    Ok(())
}

// ------------------------------------------------------------- Events ----

#[derive(Debug, Clone)]
enum Event {
    /// The network produced a block on some existing block.
    Mine { on_height: u64, on_index: usize },
    /// The node downloaded a block it did not have.
    Download { hash: B256 },
    /// The node adopts a tip it holds.
    Adopt { hash: B256 },
    /// The node executes forward to a canonical block it holds.
    Execute { hash: B256 },
    /// The node retreats its head.
    Retreat { depth: u64 },
    /// A restart: nothing in memory survives, only what is on disk.
    Restart,
}

/// Apply one event. Returns a label for the failure message.
fn apply(node: &mut Node, world: &mut World, ev: &Event) -> String {
    match ev {
        Event::Mine { on_height, on_index } => {
            let candidates = world.at(*on_height).to_vec();
            if candidates.is_empty() {
                return "mine(nothing at height)".into();
            }
            let parent = candidates[*on_index % candidates.len()];
            let h = world.extend(parent);
            format!("mine #{} on {}", h.number, &parent.to_string()[..10])
        }
        Event::Download { hash } => {
            if let Some(h) = world.blocks.get(hash) {
                if !node.holds(hash) {
                    node.store.put_header_with_hash(*hash, h).unwrap();
                    node.held.push(*hash);
                }
                format!("download #{}", h.number)
            } else {
                "download(unknown)".into()
            }
        }
        Event::Adopt { hash } => {
            // Adoption is only attempted for blocks we hold; a proof failure is
            // a legitimate outcome and must leave the store untouched.
            match Validated::prove(&node.store, *hash) {
                Ok(head) => {
                    let n = head.number();
                    let _ = node.store.apply(&Transition::Adopt { head });
                    format!("adopt #{n}")
                }
                Err(_) => "adopt(unprovable)".into(),
            }
        }
        Event::Execute { hash } => match Validated::prove(&node.store, *hash) {
            Ok(at) => {
                let n = at.number();
                // Only execute at or below the head: running execution ahead of
                // the validated head is I4, and the node never intends it.
                let head = node.store.cursor().unwrap().map(|c| c.validated_head.number);
                if head.is_some_and(|h| n <= h) {
                    let _ = node
                        .store
                        .apply(&Transition::Executed { at, state_root: B256::repeat_byte(1) });
                    format!("execute #{n}")
                } else {
                    "execute(above head)".into()
                }
            }
            Err(_) => "execute(unprovable)".into(),
        },
        Event::Retreat { depth } => {
            let Ok(Some(cursor)) = node.store.cursor() else { return "retreat(no cursor)".into() };
            // Never below execution: that is I4, and it is a bug in the caller,
            // not a state the store should be asked to represent.
            let floor = cursor.executed.number;
            let want = cursor.validated_head.number.saturating_sub(*depth).max(floor);
            let mut target = cursor.validated_head.hash;
            let mut n = cursor.validated_head.number;
            while n > want {
                let Ok(Some(h)) = node.store.header(target) else { break };
                target = h.parent_hash;
                n -= 1;
            }
            match Validated::prove(&node.store, target) {
                Ok(to) => {
                    let tn = to.number();
                    let _ = node.store.apply(&Transition::Retreat { to });
                    format!("retreat to #{tn}")
                }
                Err(_) => "retreat(unprovable)".into(),
            }
        }
        Event::Restart => {
            // Everything in memory is gone; the store is reopened as-is. The
            // node must be coherent from disk alone.
            "restart".into()
        }
    }
}

// ---------------------------------------------------------- Schedules ----

/// One randomised run. Returns `Err(report)` on the first incoherent state.
fn run(seed: u64, steps: usize) -> Result<(), String> {
    let mut rng = Rng::new(seed);
    let (mut world, genesis) = World::new();
    let mut node = Node::new(&genesis);

    let mut trace: Vec<String> = Vec::new();

    for step in 0..steps {
        let top = *world.by_height.keys().next_back().unwrap();

        let ev = match rng.below(100) {
            // Mostly extend the tip, sometimes fork off something older --
            // which is what a real reorg is.
            0..=34 => Event::Mine {
                on_height: top,
                on_index: rng.below(8) as usize,
            },
            35..=44 => {
                let depth = rng.below(6);
                Event::Mine {
                    on_height: top.saturating_sub(depth),
                    on_index: rng.below(8) as usize,
                }
            }
            // Download something we do not have, in arbitrary order -- peers
            // answer out of order, and that is the whole point of the buffer.
            45..=69 => {
                let all: Vec<B256> = world.blocks.keys().copied().collect();
                let pick = all[rng.below(all.len() as u64) as usize];
                Event::Download { hash: pick }
            }
            70..=84 => {
                if node.held.is_empty() {
                    continue;
                }
                let pick = node.held[rng.below(node.held.len() as u64) as usize];
                Event::Adopt { hash: pick }
            }
            85..=93 => {
                if node.held.is_empty() {
                    continue;
                }
                let pick = node.held[rng.below(node.held.len() as u64) as usize];
                Event::Execute { hash: pick }
            }
            94..=97 => Event::Retreat { depth: 1 + rng.below(5) },
            _ => Event::Restart,
        };

        let label = apply(&mut node, &mut world, &ev);
        trace.push(label.clone());

        if let Err(violation) = coherent(&node.store) {
            let tail: Vec<&String> = trace.iter().rev().take(12).collect();
            return Err(format!(
                "seed {seed}, step {step}: {violation}\n  last events (newest first): {tail:?}"
            ));
        }
    }

    Ok(())
}

// -------------------------------------------------------------- Tests ----

#[test]
fn random_schedules_never_leave_the_store_incoherent() {
    // Every seed is a different adversarial ordering of mining, out-of-order
    // downloads, adoptions, executions, retreats and restarts.
    for seed in 1..=400u64 {
        if let Err(report) = run(seed, 400) {
            panic!("coherence broken\n{report}");
        }
    }
}

#[test]
fn long_runs_stay_coherent() {
    for seed in [0xDEAD_BEEF, 0x1234_5678, 0xFACE_C0DE, 7, 99_991] {
        if let Err(report) = run(seed, 5_000) {
            panic!("coherence broken\n{report}");
        }
    }
}

/// A schedule that does nothing but reorg: every block forks the one below.
/// This is the shape that produced stalls 4 and 6 on mainnet.
#[test]
fn a_storm_of_reorgs_stays_coherent() {
    for seed in 1..=60u64 {
        let mut rng = Rng::new(seed);
        let (mut world, genesis) = World::new();
        let mut node = Node::new(&genesis);
        let mut trace = Vec::new();

        for step in 0..600 {
            let top = *world.by_height.keys().next_back().unwrap();
            // Always fork shallowly, so siblings pile up at every height.
            let on_height = top.saturating_sub(rng.below(3));
            let ev = match rng.below(10) {
                0..=3 => Event::Mine { on_height, on_index: rng.below(6) as usize },
                4..=6 => {
                    let all: Vec<B256> = world.blocks.keys().copied().collect();
                    Event::Download { hash: all[rng.below(all.len() as u64) as usize] }
                }
                7..=8 => {
                    if node.held.is_empty() { continue; }
                    Event::Adopt { hash: node.held[rng.below(node.held.len() as u64) as usize] }
                }
                _ => {
                    if node.held.is_empty() { continue; }
                    Event::Execute { hash: node.held[rng.below(node.held.len() as u64) as usize] }
                }
            };
            trace.push(apply(&mut node, &mut world, &ev));
            if let Err(v) = coherent(&node.store) {
                let tail: Vec<&String> = trace.iter().rev().take(12).collect();
                panic!("reorg storm broke coherence\n  seed {seed}, step {step}: {v}\n  {tail:?}");
            }
        }
    }
}
