//! Verify a range of blocks against rskj's own state, reporting every
//! divergence rather than stopping at the first.
//!
//! A syncing node is the wrong instrument for this. It executes forward from
//! its own post-state, so the first mismatch both halts it and poisons every
//! block after; finding the second costs a fix, a rebuild and a restart.
//!
//! This takes each block's pre-state from **rskj's** database — the parent
//! header's state root, resolved in rskj's unitrie — so blocks are verified
//! independently. A wrong block says nothing about the next one, and a single
//! pass over a fork boundary reports everything that disagrees.
//!
//! Nothing is written to either database. Blocks are read from a rustock store
//! opened read-only, state from rskj's unitrie opened read-only, and the trie
//! the replay computes goes to a scratch store that can be deleted afterwards.
//!
//! ```text
//! verify_range <data-dir> <rskj-unitrie-dir> <from> <to> [options]
//!
//!   --network-id N     30 mainnet, 31 testnet (default), else regtest
//!   --scratch DIR      where the replay's own trie writes go (default: a temp dir)
//!   --max-failures N   stop after this many (default 10; 0 means never)
//!   --cache-mb N       block cache for the rskj unitrie (default 256)
//!   --explain          on a state-root divergence, print the leaves that
//!                      differ from rskj's own post-state, then stop
//!   --state-format F   how to read <rskj-unitrie-dir>: "rskj" (default, a
//!                      flat RocksDB keyed by node hash) or "rustock" (one of
//!                      our own trie stores, e.g. a segbuild chunk's `sealed`
//!                      directory, which keys nodes in a `trie_nodes` CF)
//!   --state-roots DIR  rskj's `stateRoots` table, which maps a pre-RSKIP126
//!                      header's ORCHID state root to the UNITRIE root holding
//!                      the same state. It is what makes the early chain
//!                      reachable at all: it supplies both the parent to read
//!                      and the root to verify against, with no Orchid
//!                      conversion anywhere.
//!   --parent-roots F   CSV of `block,...,unitrie_root,...` giving the UNITRIE
//!                      root each block computed. Needed below wasabi100,
//!                      where the header's own stateRoot is an orchid root and
//!                      cannot address a unitrie node.
//!   --execution-threads N
//!                      threads for RSKIP-144 parallel sublists (default 1)
//!   --sequential       execute the range in order, carrying each block's
//!                      post-state forward instead of resolving every block's
//!                      parent root from the source. The only way to reach
//!                      blocks below wasabi100 (#1,591,000 on mainnet), whose
//!                      headers carry an ORCHID-format state root that is not
//!                      a unitrie node hash and so can never be looked up.
//!   --seed-genesis     build the genesis state into the scratch store before
//!                      starting, so a contiguous replay from #1 needs no
//!                      historical state source at all
//!   --blocks FILE      verify only the block numbers in FILE (one per line)
//!                      instead of a contiguous range; <from> and <to> are
//!                      then omitted
//!   --record-silent DIR
//!                      also record the Bridge decisions that emit no event
//!                      into a silent-decision store at DIR (created if
//!                      absent, appended to otherwise)
//!   --record-legacy-events DIR
//!                      also reconstruct, into a legacy-event store at DIR,
//!                      the peg events the Bridge of that height did not log
//!                      -- `pegin_btc`, `release_requested`, `rejected_pegin`,
//!                      `unrefundable_pegin` -- in the same key and value
//!                      layout as the node's own `bridge_events` index, so
//!                      one reader spans both. Nothing is written for a
//!                      height where the Bridge really logged, so the union
//!                      of the two never double-counts. Read it back with
//!                      the `legacy_events` tool.
//! ```
//!
//! Both recording options ride on the same drained decisions, so asking for
//! both costs one replay rather than two.
//!
//! `--record-silent` makes the pass pay for itself twice. Verifying a range
//! already executes every block against rskj's own state; recording while it
//! does means a question like "was a peg-in ever refunded here" is answered
//! from an index afterwards instead of by replaying the range again.
//!
//! Only blocks that verified contribute records. A block whose state root
//! disagrees with the chain was executed by this implementation but not by
//! the network, so its decisions are this implementation's, and storing them
//! beside real ones would make the store untrustworthy exactly where it
//! matters. Such blocks become recorded gaps instead.
//!
//! The stop exists because one defect usually breaks every block it touches.
//! Ten instances of a rule that is wrong at every block say exactly what one
//! says, so running the remaining fifty thousand buys nothing and costs an
//! hour. The same goes for a range the snapshot cannot serve: if the first
//! blocks have no pre-state, none of them will.

#[path = "support/mod.rs"]
mod support;

use alloy_primitives::B256;
use anyhow::{Context, Result};
use rocksdb::{DB, Options};
use rustock_core::Block;
use rustock_execution::BlockProcessor;
use rustock_storage::BlockStore;
use rustock_trie::{OverlayTrieStore, TrieNode, TrieStore};
use std::sync::Arc;

/// Closes an open reconstructed-event coverage span at the last good block.
///
/// Mirrors `close_run` for the silent store, and for the same reason. A span
/// is a claim that every block in it was examined; a block whose decisions
/// were dropped -- an execution error, an unresolvable parent, an orchid
/// comparison that yielded no verdict -- breaks that claim. Without this the
/// span would run straight over the hole, and a later `covers()` would answer
/// "yes, examined" for a block whose peg-ins are missing. That is worse than
/// an admitted gap: it reads as authoritative.
#[allow(clippy::too_many_arguments)]
/// Renders the labelled skip counts as a JSON object for the coverage record.
fn render_skips(m: &std::collections::BTreeMap<String, u64>) -> String {
    if m.is_empty() {
        return "{}".to_string();
    }
    let body: Vec<String> = m.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    format!("{{{}}}", body.join(","))
}

#[allow(clippy::too_many_arguments)]
fn close_legacy_run(
    legacy: &Option<rustock_storage::legacy_event_store::LegacyEventStore>,
    start: &mut Option<u64>,
    last_good: u64,
    build: &str,
    blocks: u64,
    verified: u64,
    events: u64,
    skipped: u64,
    skip_detail: &std::collections::BTreeMap<String, u64>,
) -> anyhow::Result<()> {
    let (Some(store), Some(from)) = (legacy, *start) else {
        *start = None;
        return Ok(());
    };
    if last_good >= from {
        store.add_coverage(&rustock_storage::legacy_event_store::Coverage {
            from,
            to: last_good,
            build: build.to_string(),
            blocks,
            verified,
            events,
            skipped,
            skip_detail: render_skips(skip_detail),
        })?;
    }
    *start = None;
    Ok(())
}

/// How often the reconstructed-event coverage span is rewritten. Keyed on
/// the span start, so each write replaces the last rather than accumulating.
const LEGACY_COVERAGE_EVERY: u64 = 50_000;

const USAGE: &str = "usage: verify_range <data-dir> <rskj-unitrie-dir> <from> <to> \
[--network-id N] [--scratch DIR] [--max-failures N] [--cache-mb N] \
[--blocks FILE] [--record-silent DIR] [--record-legacy-events DIR]";

/// Splits `--key value` and `--key=value` options out of the command line,
/// leaving the positional arguments.
///
/// Hand-rolled because these diagnostics take no dependency on an argument
/// parser, and an unknown option must be an error rather than be silently
/// read as a positional -- a mistyped `--max-failures` that became a block
/// number would be worse than no option at all.
fn split_options(argv: Vec<String>) -> Result<(Vec<String>, Vec<(String, String)>)> {
    const WITH_VALUE: [&str; 11] = [
        "--record-legacy-events",
        "--network-id",
        "--scratch",
        "--max-failures",
        "--cache-mb",
        "--record-silent",
        "--blocks",
        "--state-format",
        "--parent-roots",
        "--state-roots",
        "--execution-threads",
    ];
    const SEED: [&str; 2] = ["--seed-genesis", "--sequential"];
    const FLAGS: [&str; 2] = ["--explain", "--read-only"];
    let mut positional = Vec::new();
    let mut options = Vec::new();
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        if !a.starts_with("--") {
            positional.push(a);
            continue;
        }
        let (key, inline) = match a.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (a.clone(), None),
        };
        if FLAGS.contains(&key.as_str()) || SEED.contains(&key.as_str()) {
            options.push((key, "true".to_string()));
            continue;
        }
        anyhow::ensure!(WITH_VALUE.contains(&key.as_str()), "unknown option {key}\n{USAGE}");
        let value = match inline {
            Some(v) => v,
            None => it.next().with_context(|| format!("{key} needs a value"))?,
        };
        options.push((key, value));
    }
    Ok((positional, options))
}

fn option<T: std::str::FromStr>(
    options: &[(String, String)],
    key: &str,
    default: T,
) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match options.iter().rev().find(|(k, _)| k == key) {
        Some((_, v)) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{key}: {e}")),
        None => Ok(default),
    }
}

/// rskj's unitrie, read-only. Content-addressed exactly as rustock's is.
struct RskjUnitrie {
    db: DB,
}

impl TrieStore for RskjUnitrie {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten()
    }
    fn put(&self, _key: &[u8], _value: &[u8]) {
        panic!("the rskj source must never be written to");
    }
}

/// What went wrong with one block, if anything.
#[derive(Default)]
struct Verdict {
    state: bool,
    receipts: bool,
    gas: bool,
}

impl Verdict {
    fn ok(&self) -> bool {
        !self.state && !self.receipts && !self.gas
    }
    fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.state {
            parts.push("state root");
        }
        if self.receipts {
            parts.push("receipts root");
        }
        if self.gas {
            parts.push("gas used");
        }
        parts.join(", ")
    }
}

/// Records `start..=end` as replayed and verified by `build`.
fn write_coverage(
    silent: &Option<rustock_storage::silent_store::SilentStore>,
    start: u64,
    end: u64,
    build: &str,
) -> Result<()> {
    let Some(store) = silent else { return Ok(()) };
    if end < start {
        return Ok(());
    }
    // A block that verifies is no longer a gap, whatever an earlier attempt
    // recorded about it.
    for b in start..=end {
        store.clear_gap(b)?;
    }
    store.add_coverage(&rustock_storage::silent_store::Coverage {
        from: start,
        to: end,
        build: build.to_string(),
        recorded_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        verified: end - start + 1,
        diverged: 0,
    })
}

/// Ends the contiguous verified run at the block before `failed`, and notes
/// why it ended. Coverage must stop short of a block whose decisions were not
/// confirmed against the chain.
fn close_run(
    silent: &Option<rustock_storage::silent_store::SilentStore>,
    run_start: &mut Option<u64>,
    failed: u64,
    build: &str,
    why: &str,
) -> Result<()> {
    let Some(store) = silent else { return Ok(()) };
    if let Some(start) = run_start.take() {
        write_coverage(silent, start, failed - 1, build)?;
    }
    store.add_gap(failed, why)
}

fn main() -> Result<()> {
    // Honour RUST_LOG so a divergence can be chased with the execution
    // crate's own debug output, which is usually the fastest next step.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    let (positional, options) = split_options(std::env::args().skip(1).collect())?;
    let blocks_file: Option<String> =
        options.iter().rev().find(|(k, _)| k == "--blocks").map(|(_, v)| v.clone());

    // A block list replaces the range, so <from> and <to> go away with it.
    let targets: Vec<u64> = match &blocks_file {
        Some(path) => {
            anyhow::ensure!(positional.len() == 2, "{USAGE}");
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading the block list at {path}"))?;
            let mut v: Vec<u64> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.parse::<u64>().with_context(|| format!("block number {l:?}")))
                .collect::<Result<_>>()?;
            // Sorted so the replay walks the state source forward, and deduped
            // so a block listed twice is not verified twice.
            v.sort_unstable();
            v.dedup();
            anyhow::ensure!(!v.is_empty(), "the block list at {path} is empty");
            v
        }
        None => {
            anyhow::ensure!(positional.len() == 4, "{USAGE}");
            let from: u64 = positional[2].parse().context("<from>")?;
            let to: u64 = positional[3].parse().context("<to>")?;
            anyhow::ensure!(from <= to, "empty range: {from} > {to}");
            (from..=to).collect()
        }
    };
    let data_dir = positional[0].clone();
    let unitrie_dir = positional[1].clone();
    let from = *targets.first().expect("non-empty");
    let to = *targets.last().expect("non-empty");
    let network_id: u64 = option(&options, "--network-id", support::TESTNET)?;
    let scratch: Option<String> =
        options.iter().rev().find(|(k, _)| k == "--scratch").map(|(_, v)| v.clone());
    // 0 disables the stop, for a run that is deliberately exhaustive.
    let max_failures: u64 = option(&options, "--max-failures", 10)?;
    // Small by default: this runs beside whatever else is on the machine, and
    // a cache sized for the database rather than the box gets it killed.
    let cache_mb: usize = option(&options, "--cache-mb", 256)?;
    let explain = options.iter().any(|(k, _)| k == "--explain");
    let seed_genesis = options.iter().any(|(k, _)| k == "--seed-genesis");
    let sequential = options.iter().any(|(k, _)| k == "--sequential");
    let state_roots: Option<DB> = match options
        .iter()
        .rev()
        .find(|(k, _)| k == "--state-roots")
        .map(|(_, v)| v.clone())
    {
        None => None,
        Some(dir) => {
            let db = DB::open_for_read_only(&Options::default(), &dir, false)
                .with_context(|| format!("opening rskj stateRoots at {dir} read-only"))?;
            eprintln!("  roots   {dir} (orchid -> unitrie translation)");
            Some(db)
        }
    };
    // rskj `stateRootsDB`: the Unitrie root holding the state an Orchid root
    // named. `None` when the table has no entry, which for a pre-wasabi block
    // means the block cannot be addressed or checked at all.
    let translate = |orchid: &B256| -> Option<B256> {
        let db = state_roots.as_ref()?;
        let v = db.get(orchid.as_slice()).ok().flatten()?;
        (v.len() == 32).then(|| B256::from_slice(&v))
    };
    let parent_roots: std::collections::HashMap<u64, Vec<u8>> = match options
        .iter()
        .rev()
        .find(|(k, _)| k == "--parent-roots")
        .map(|(_, v)| v.clone())
    {
        None => Default::default(),
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading parent roots from {path}"))?;
            let mut m = std::collections::HashMap::new();
            for line in text.lines().skip(1) {
                let mut it = line.split(',');
                let (Some(b), Some(_), Some(r)) = (it.next(), it.next(), it.next()) else {
                    continue;
                };
                let (Ok(b), Some(r)) = (b.trim().parse::<u64>(), r.trim().strip_prefix("0x"))
                else {
                    continue;
                };
                if let Ok(bytes) = alloy_primitives::hex::decode(r) {
                    m.insert(b, bytes);
                }
            }
            eprintln!("  parent roots: {} entries from {path}", m.len());
            m
        }
    };
    let state_format: String = options
        .iter()
        .rev()
        .find(|(k, _)| k == "--state-format")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "rskj".to_string());
    // Coverage over a block list cannot be recorded as a span: the blocks
    // between two listed ones were never replayed, and claiming them would
    // make the store assert exactly the thing it exists to disprove.
    let contiguous = blocks_file.is_none();
    let record_silent: Option<String> =
        options.iter().rev().find(|(k, _)| k == "--record-silent").map(|(_, v)| v.clone());
    // Purely reads: no scratch database, writes held in memory and dropped
    // after each block. Only sound when every block resolves its own parent
    // from the source -- i.e. NOT with --sequential, where the last block's
    // writes are the next one's parent state.
    let read_only = options.iter().any(|(k, _)| k == "--read-only");
    let record_legacy: Option<String> = options
        .iter()
        .rev()
        .find(|(k, _)| k == "--record-legacy-events")
        .map(|(_, v)| v.clone());
    let store = Arc::new(
        BlockStore::open_read_only(&data_dir)
            .with_context(|| format!("opening block store at {data_dir} read-only"))?,
    );

    let mut opts = Options::default();
    let mut bbt = rocksdb::BlockBasedOptions::default();
    bbt.set_block_cache(&rocksdb::Cache::new_lru_cache(cache_mb * 1024 * 1024));
    bbt.set_cache_index_and_filter_blocks(true);
    opts.set_block_based_table_factory(&bbt);
    // A segbuild chunk holds only the nodes its producer touched while
    // executing its range, so a read we issue that the producer did not can
    // return a false absence rather than an error. That is safe here only
    // because every block is checked against its header's state root: a block
    // computed from an incomplete source cannot match, so it is reported as
    // diverged and recorded as a gap, never as a verified decision. Treat a
    // divergence from such a source as "this chunk could not serve the block",
    // not as a consensus finding.
    let source: Arc<dyn TrieStore> = match state_format.as_str() {
        "rskj" => Arc::new(RskjUnitrie {
            db: DB::open_for_read_only(&opts, &unitrie_dir, false)
                .with_context(|| format!("opening rskj unitrie at {unitrie_dir} read-only"))?,
        }),
        "rustock" => Arc::new(
            rustock_storage::RocksDbTrieStore::open_read_only(&unitrie_dir)
                .with_context(|| format!("opening rustock trie store at {unitrie_dir}"))?,
        ),
        // The live node's own backend. Useful for the recent chain, where it
        // is the only store that has the state at all -- an archival import
        // stops at whatever height it was taken.
        "epoch" => Arc::new(
            rustock_storage::epoch_store::EpochTrieStore::open_read_only_with(
                &unitrie_dir,
                rustock_storage::epoch_store::EpochConfig::default(),
                Arc::new(rustock_storage::epoch_backend::FlatFactory::new(0)),
            )
            .with_context(|| format!("opening epoch trie store at {unitrie_dir}"))?,
        ),
        other => {
            anyhow::bail!("--state-format must be rskj, rustock or epoch, not {other:?}")
        }
    };

    // Somewhere for the replay's own writes that is neither database. Kept on
    // disk rather than in memory because a 50,000-block range writes far more
    // trie than belongs in RAM.
    let tmp;
    let scratch_path = match &scratch {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            tmp = tempfile::tempdir().context("creating a scratch directory")?;
            tmp.path().to_path_buf()
        }
    };
    // Kept as the concrete type as well as behind the trait: the replay has
    // to be able to ask whether its own writes succeeded. They go to a
    // scratch directory on whatever filesystem had room, and a full disk
    // makes a trie store answer "absent" for nodes it was asked to keep --
    // which yields wrong roots, not errors.
    anyhow::ensure!(
        !(read_only && sequential),
        "--read-only cannot be combined with --sequential: a sequential replay's \
         parent state IS the previous block's writes, which --read-only discards"
    );
    // `overlay` is kept alongside the trait object so the per-block clear can
    // be called; in read-only mode that is what keeps memory flat.
    let (scratch_store, overlay, trie): (
        Option<Arc<rustock_storage::RocksDbTrieStore>>,
        Option<Arc<OverlayTrieStore>>,
        Arc<dyn TrieStore>,
    ) = if read_only {
        let o = Arc::new(OverlayTrieStore::new(source));
        eprintln!("  scratch (none: --read-only, writes held in memory per block)");
        (None, Some(o.clone()), o)
    } else {
        let sc = Arc::new(
            rustock_storage::RocksDbTrieStore::open(&scratch_path)
                .with_context(|| format!("opening scratch trie at {}", scratch_path.display()))?,
        );
        let spill: Arc<dyn TrieStore> = sc.clone();
        let t: Arc<dyn TrieStore> = Arc::new(OverlayTrieStore::with_spill(source, spill));
        (Some(sc), None, t)
    };

    // Genesis state is not read from anywhere -- it is constructed from the
    // chain config. Build it into the scratch store and a contiguous replay
    // from #1 carries its own state forward, each block's parent root having
    // been written by the one before. In sequential mode the state is carried
    // here rather than resolved per block from the source, which is why the
    // source goes unread in that mode (zero open descriptors on it, measured).
    //
    // A previous version of this comment also claimed a segbuild chunk
    // "captures its producer's read set rather than roots addressable by
    // hash", and gave that as a reason the early chain had no usable state
    // source. **That is false**, and it is worth saying so plainly because it
    // stopped at least one investigation. It came from probing a chunk with
    // `rskj_root_probe`, which opens the DEFAULT column family; our own trie
    // stores key nodes in `trie_nodes`, so that tool reports ABSENT for every
    // hash in a segbuild chunk whatever it holds. Probed through the right
    // column family (`trie_probe`), chunk `000-1-1591000` does hold
    // pre-wasabi100 unitrie roots with resolvable children -- verified
    // against block #6,916's root, taken from rskj's own `stateRoots` table.
    //
    // So a segbuild chunk is a plausible state source for this era. What
    // stops it being used here is not its contents but the composition
    // below: `OverlayTrieStore` reads the spill before the base, and
    // `--seed-genesis` puts every computed node in the spill, so the base is
    // never consulted. Serving reads from a sealed chunk instead would mean
    // reading base-first -- safe, since the trie is content-addressed and a
    // hash cannot map to two different values -- and has not been measured.
    let mut carried: Option<TrieNode> = None;
    anyhow::ensure!(
        !sequential || blocks_file.is_none(),
        "--sequential replays a contiguous range; it cannot take --blocks"
    );
    if seed_genesis {
        use rustock_trie::{account_key, AccountState, TrieKeySlice};
        let config = if network_id == support::MAINNET {
            rustock_core::config::ChainConfig::mainnet()
        } else {
            rustock_core::config::ChainConfig::testnet()
        };
        let mut genesis = TrieNode::empty();
        for e in &config.genesis_alloc() {
            genesis = genesis.put(
                &TrieKeySlice::from_key(&account_key(&e.address)),
                &AccountState::new(e.nonce, e.balance).encode(),
                trie.as_ref(),
            );
        }
        genesis.save(trie.as_ref(), true);
        // The genesis header predates RSKIP126, so its stateRoot is the
        // ORCHID root of this trie, not the unitrie node hash. Comparing the
        // wrong one of those is how a correct genesis looks broken.
        let built = rustock_trie::orchid_state_root(&genesis, trie.as_ref());
        let expected = config.genesis_header().state_root;
        // Checked, not assumed: a wrong genesis would make every block below
        // the first real state source diverge, and look like a consensus bug.
        anyhow::ensure!(
            built == expected,
            "constructed genesis state root {built:?} does not match the genesis header {expected:?}"
        );
        eprintln!("  seeded genesis state (orchid root {built:?})");
        carried = Some(genesis);
    }

    let hardfork_cfg = support::hardfork_for(network_id);
    eprintln!(
        "verifying {} block(s) in #{from}..=#{to} on network-id {network_id} (chain_id {})",
        targets.len(),
        hardfork_cfg.chain_id
    );
    if let Some(path) = &blocks_file {
        eprintln!("  blocks listed in {path}");
    }
    eprintln!("  blocks  {data_dir} (read-only)");
    eprintln!("  state   {unitrie_dir} (read-only, {state_format} format)");
    eprintln!("  scratch {}", scratch_path.display());
    // RSKIP-144 parallel sublists. 1 runs every block as one; above 1, a
    // block that declares at least two parallel sublists runs them on their
    // own threads. Replaying the same range at 1 and at 2 is the check that
    // matters, because both must agree with the reference chain.
    let execution_threads: usize = options
        .iter()
        .find(|(k, _)| k == "--execution-threads")
        .map(|(_, v)| v.parse())
        .transpose()?
        .unwrap_or(1);
    let processor = BlockProcessor::new(hardfork_cfg.clone(), store.clone())
        .with_execution_threads(execution_threads);

    let silent = match &record_silent {
        Some(dir) => {
            let s = rustock_storage::silent_store::SilentStore::open(dir)
                .with_context(|| format!("opening the silent-decision store at {dir}"))?;
            eprintln!("  silent  {dir} (recording Bridge decisions that emit no event)");
            Some(s)
        }
        None => None,
    };
    // The reconstructed-event store rides on the same decisions as the
    // silent store, so either option turns recording on, and both together
    // cost one replay rather than two.
    let legacy = match &record_legacy {
        Some(dir) => {
            let s = rustock_storage::legacy_event_store::LegacyEventStore::open(dir)
                .with_context(|| format!("opening the legacy event store at {dir}"))?;
            eprintln!("  legacy  {dir} (reconstructing peg events the Bridge never logged)");
            Some(s)
        }
        None => None,
    };
    if silent.is_some() || legacy.is_some() {
        rustock_execution::silent::start();
    }
    // Totals for the coverage record, which is what tells a later reader
    // that an empty scan means "none here" rather than "never built".
    let mut legacy_first: Option<u64> = None;
    let mut legacy_last: u64 = 0;
    let mut legacy_blocks: u64 = 0;
    let mut legacy_verified: u64 = 0;
    // The open span, and the last block whose decisions were actually kept.
    let mut legacy_run: Option<u64> = None;
    let mut legacy_good: u64 = 0;
    let mut legacy_events: u64 = 0;
    let mut legacy_skipped: u64 = 0;
    let mut legacy_skip_kinds: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    // The build that produced the records. A replay is only as good as the
    // code that ran it, and this is the only way to tell later which rows
    // came from which rules.
    let build = std::env::var("RUSTOCK_BUILD")
        .ok()
        .or_else(|| option_env!("RUSTOCK_BUILD").map(str::to_string))
        .unwrap_or_else(|| {
            // `-C` the crate's own directory rather than the current one: a
            // run launched from outside the repo recorded "unknown", which is
            // precisely the provenance this field exists to carry.
            std::process::Command::new("git")
                .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
    // The first block of the contiguous run being recorded; a divergence or
    // an unverifiable block closes the run and starts a new one, so coverage
    // describes only blocks that actually verified.
    let mut run_start: Option<u64> = None;
    let mut silent_rows = 0u64;

    if max_failures > 0 {
        eprintln!("  stopping after {max_failures} divergent or unverifiable block(s)");
    }

    // How often to pay for an orchid conversion on pre-RSKIP126 blocks that
    // decided nothing. 0 disables the tripwire.
    let orchid_every: u64 = std::env::var("RUSTOCK_ORCHID_CHECK_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let started = std::time::Instant::now();
    let mut checked = 0u64;
    let mut diverged = 0u64;
    let mut unverifiable = 0u64;
    // Executed to carry state forward, but with no root comparison available:
    // pre-RSKIP126 blocks that decided nothing. Counted apart from `checked`
    // so the summary never calls them verified.
    let mut unchecked = 0u64;
    let mut first_bad: Option<u64> = None;
    let mut stopped_at: Option<u64> = None;

    for (done, n) in targets.iter().copied().enumerate() {
        // Checked at the top of each block so every exit from the body below
        // -- divergence or unverifiable -- is counted before it is consulted.
        if max_failures > 0 && diverged + unverifiable >= max_failures {
            stopped_at = Some(n - 1);
            eprintln!(
                "\nstopping at #{}: {max_failures} failures reached. \
                 Re-run with --max-failures 0 to see the rest.",
                n - 1
            );
            break;
        }

        let Some(hash) = store.canonical_hash(n)? else {
            eprintln!("#{n}: no canonical hash — the metadata rebuild did not reach here");
            close_run(&silent, &mut run_start, n, &build, "no canonical hash")?;
            unverifiable += 1;
            continue;
        };
        let Some(header) = store.header(hash)? else {
            eprintln!("#{n}: header missing");
            close_run(&silent, &mut run_start, n, &build, "header missing")?;
            unverifiable += 1;
            continue;
        };
        let Some((transactions, ommers)) = store.body(hash)? else {
            eprintln!("#{n}: body missing");
            close_run(&silent, &mut run_start, n, &build, "body missing")?;
            unverifiable += 1;
            continue;
        };

        // The pre-state is rskj's, not ours: that is what makes each block an
        // independent check instead of a continuation of the last one.
        let Some(parent) = store.header(header.parent_hash)? else {
            eprintln!("#{n}: parent header missing");
            close_run(&silent, &mut run_start, n, &build, "parent header missing")?;
            unverifiable += 1;
            continue;
        };
        let pre = if sequential {
            match carried.take() {
                Some(r) => r,
                None => {
                    eprintln!("#{n}: no carried state; --sequential needs --seed-genesis \
                               (or a predecessor that succeeded)");
                    close_run(&silent, &mut run_start, n, &build, "no carried state")?;
                    unverifiable += 1;
                    continue;
                }
            }
        } else {
        // Below wasabi100 the header's stateRoot is an orchid root and names
        // no unitrie node, so the recorded unitrie root of the parent is used
        // instead where one was supplied.
        let parent_key: Vec<u8> = match translate(&parent.state_root) {
            Some(unitrie) => unitrie.as_slice().to_vec(),
            None => parent_roots
                .get(&parent.number)
                .cloned()
                .unwrap_or_else(|| parent.state_root.as_slice().to_vec()),
        };
        let Some(root_data) = trie.get(&parent_key) else {
            // States the fact, not a cause: an absent root means the source
            // was pruned below here, or that these blocks and this unitrie
            // are from different chains. Naming only one of those sends the
            // reader after the wrong thing.
            eprintln!(
                "#{n}: parent state root {:?} is not in the source unitrie \
                 (pruned below this height, or not the same chain as these blocks)",
                parent.state_root
            );
            close_run(
                &silent,
                &mut run_start,
                n,
                &build,
                "parent state root not in the source unitrie",
            )?;
            close_legacy_run(&legacy, &mut legacy_run, legacy_good, &build,
                legacy_blocks, legacy_verified, legacy_events, legacy_skipped, &legacy_skip_kinds)?;
            unverifiable += 1;
            continue;
        };
            TrieNode::from_message(&root_data, trie.as_ref())
        };

        let block = Block { header, transactions, ommers };
        let processed = match processor.execute_block(&block, &pre, trie.clone()) {
            Ok(p) => p,
            Err(e) => {
                println!("#{n}  EXECUTION ERROR  {e}");
                // Whatever the failed block recorded before it failed is
                // dropped, not kept and not left to be blamed on the next one.
                rustock_execution::silent::drain();
                close_run(&silent, &mut run_start, n, &build, "execution error")?;
                close_legacy_run(&legacy, &mut legacy_run, legacy_good, &build,
                    legacy_blocks, legacy_verified, legacy_events, legacy_skipped, &legacy_skip_kinds)?;
                diverged += 1;
                first_bad.get_or_insert(n);
                continue;
            }
        };

        // Before the verdict is believed: if the scratch could not keep what
        // this block computed, the comparison below is meaningless, and so is
        // every block after it. Stop rather than record a plausible lie.
        if scratch_store.as_ref().is_some_and(|sc| sc.write_failed()) {
            if let Some(store) = &silent {
                rustock_execution::silent::drain();
                if let Some(start) = run_start.take() {
                    write_coverage(&silent, start, n - 1, &build)?;
                }
                store.add_gap(n, "scratch trie write failed (disk full?)")?;
            }
            anyhow::bail!(
                "#{n}: a write to the scratch trie at {} failed, so the replay can no \
                 longer read back what it computed. Nothing after this point is sound. \
                 Free space and re-run; completed chunks are recorded as coverage.",
                scratch_path.display()
            );
        }

        // Before RSKIP126 the header carries an orchid root, so the unitrie
        // hash cannot be compared against it. Converting is expensive -- it
        // walks the whole state -- so it is paid for only where the answer
        // matters: a block that recorded a decision, or every `orchid_every`
        // blocks as a tripwire. Elsewhere state is carried forward unchecked,
        // and the coverage records say so by omitting those blocks.
        let unitrie_root = hardfork_cfg.has_unitrie_state_root(n);
        let decisions_here = if silent.is_some() || legacy.is_some() {
            rustock_execution::silent::drain()
        } else {
            Vec::new()
        };

        // Below wasabi100 the header's root is an Orchid one and cannot be
        // compared with what we compute. There are two ways to get a verdict,
        // and they are not equally good:
        //
        //  - rskj's own translation table gives the Unitrie root holding the
        //    state that Orchid root named. Comparing that against ours is
        //    like with like, costs a single lookup, and reconstructs no
        //    Orchid trie. Preferred whenever the table is supplied.
        //  - Converting our Unitrie into an Orchid root is the fallback, and
        //    a weak one: Orchid was a different structure, so a mismatch
        //    cannot be told apart from a limit of the conversion.
        let translated = (!unitrie_root)
            .then(|| translate(&block.header.state_root))
            .flatten();
        // Only worth the conversion when nothing better is available, and
        // then only where the answer matters: a block that decided something,
        // one the caller named, or a periodic tripwire.
        let check_orchid = !unitrie_root
            && translated.is_none()
            && (blocks_file.is_some()
                || !decisions_here.is_empty()
                || (orchid_every > 0 && n.is_multiple_of(orchid_every)));
        // What was compared, and against what -- so the report shows the two
        // numbers the verdict actually rests on.
        let (computed_state, expected_state, via_orchid) = if unitrie_root {
            (Some(processed.state_root_hash), block.header.state_root, false)
        } else if let Some(expected) = translated {
            (Some(processed.state_root_hash), expected, false)
        } else if check_orchid {
            (
                Some(rustock_trie::orchid_state_root(&processed.new_state_root, trie.as_ref())),
                block.header.state_root,
                true,
            )
        } else {
            (None, block.header.state_root, false)
        };
        let state_ok = computed_state.is_none_or(|c| c == expected_state);
        let checked_here = unitrie_root || translated.is_some() || check_orchid;
        // A conversion mismatch yields no verdict rather than a divergence.
        let orchid_inconclusive = via_orchid && !state_ok;
        if sequential {
            carried = Some(processed.new_state_root.clone());
        }
        let verdict = Verdict {
            state: !state_ok && !orchid_inconclusive,
            receipts: processed.receipts_root != block.header.receipts_root,
            gas: processed.gas_used != block.header.gas_used,
        };
        if orchid_inconclusive {
            eprintln!(
                "#{n}: pre-wasabi100 orchid comparison did not match; this cannot \
                 distinguish a conversion limit from an execution fault, so the block \
                 is left unverified"
            );
            close_run(
                &silent, &mut run_start, n, &build,
                "pre-wasabi100: orchid comparison inconclusive",
            )?;
            rustock_execution::silent::drain();
            close_legacy_run(&legacy, &mut legacy_run, legacy_good, &build,
                legacy_blocks, legacy_verified, legacy_events, legacy_skipped, &legacy_skip_kinds)?;
            unverifiable += 1;
            continue;
        }
        if checked_here {
            checked += 1;
        } else {
            unchecked += 1;
        }
        // Nothing this block wrote is needed again: the next block resolves
        // its own parent from the source. Dropping it here is what keeps a
        // read-only run at constant memory over millions of blocks.
        if let Some(o) = &overlay {
            o.clear_overlay();
        }
        // Drained above, before the verdict, because the orchid check needs
        // to know whether this block decided anything.
        let decisions = decisions_here;
        // Reconstructed events, written only for blocks that verified: a
        // block whose state root disagrees was executed by this code and not
        // by the network, so its decisions are ours, not the chain's.
        if let Some(lstore) = &legacy {
            if verdict.ok() {
                legacy_first.get_or_insert(n);
                legacy_last = n;
                legacy_run.get_or_insert(n);
                legacy_good = n;
                legacy_blocks += 1;
                if checked_here {
                    legacy_verified += 1;
                }
                let mut rows = Vec::new();
                // One log_index sequence per block, as a receipt would have.
                let mut log_index: u32 = 0;
                for d in &decisions {
                    // Never reconstruct what the Bridge really logged: the
                    // node's own index already has it, and a duplicate would
                    // double-count in the union of the two. A record that
                    // does not say is REFUSED, not assumed -- see
                    // `legacy_events::reconstructable`.
                    match rustock_execution::bridge::legacy_events::reconstructable(d) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(why) => {
                            legacy_skipped += 1;
                            *legacy_skip_kinds
                                .entry(format!("{}/UNGATED({why})", d.kind.name()))
                                .or_insert(0) += 1;
                            continue;
                        }
                    }
                    // A flyover peg-in is the case this whole exercise is
                    // about, and it is rare enough to name individually.
                    if matches!(
                        d.fields.iter().find(|(k, _)| *k == "peginPath").map(|(_, v)| v),
                        Some(rustock_execution::silent::FieldValue::Text(p)) if p == "flyover"
                    ) {
                        let f = |name: &str| {
                            d.fields
                                .iter()
                                .find(|(k, _)| *k == name)
                                .map(|(_, v)| v.to_json())
                                .unwrap_or_else(|| "null".into())
                        };
                        eprintln!(
                            "FLYOVER  #{} tx[{}]  lbc={} amountSat={} btcTx={}",
                            d.block,
                            d.tx_index,
                            f("destination"),
                            f("amountSat"),
                            f("btcTxHash"),
                        );
                    }
                    let evs = rustock_execution::bridge::legacy_events::events_for(d);
                    if evs.is_empty() {
                        legacy_skipped += 1;
                        *legacy_skip_kinds
                            .entry(rustock_execution::bridge::legacy_events::skip_label(d))
                            .or_insert(0) += 1;
                        continue;
                    }
                    // The real index keys each event to its transaction, so
                    // this does too, taken from the body by position -- the
                    // ordering the receipts root commits to.
                    let tx_hash = block
                        .transactions
                        .get(d.tx_index as usize)
                        .map(|t| t.tx_hash())
                        .unwrap_or_default();
                    for e in evs {
                        rows.push(rustock_storage::legacy_event_store::EventRow {
                            topic0: e.topic0,
                            block: d.block,
                            tx_index: d.tx_index,
                            log_index,
                            tx_hash,
                            topics: e.topics,
                            data: e.data,
                        });
                        log_index += 1;
                    }
                }
                if !rows.is_empty() {
                    legacy_events += rows.len() as u64;
                    lstore.put_events(&rows)?;
                }
                // Coverage every so often, not only at the end: this runs for
                // hours, and a span written only on a clean exit is a span
                // lost to any interruption -- leaving events on disk that
                // nothing claims, which reads as "never built".
                if legacy_blocks.is_multiple_of(LEGACY_COVERAGE_EVERY) {
                    if let Some(first) = legacy_run {
                        lstore.add_coverage(
                            &rustock_storage::legacy_event_store::Coverage {
                                from: first,
                                to: n,
                                build: build.clone(),
                                blocks: legacy_blocks,
                                verified: legacy_verified,
                                events: legacy_events,
                                skipped: legacy_skipped,
                                skip_detail: render_skips(&legacy_skip_kinds),
                            },
                        )?;
                    }
                }
            } else {
                // Executed by us and not by the network: its decisions are
                // ours, not the chain's, so the span cannot span it.
                close_legacy_run(&legacy, &mut legacy_run, legacy_good, &build,
                    legacy_blocks, legacy_verified, legacy_events, legacy_skipped, &legacy_skip_kinds)?;
            }
        }
        if let Some(store) = &silent {
            if verdict.ok() {
                if !decisions.is_empty() {
                    let rows: Vec<rustock_storage::silent_store::SilentRow> = decisions
                        .iter()
                        .map(|d| rustock_storage::silent_store::SilentRow {
                            kind: d.kind.name().to_string(),
                            block: d.block,
                            tx_index: d.tx_index,
                            json: d.to_json(),
                        })
                        .collect();
                    silent_rows += rows.len() as u64;
                    store.put_records(&rows)?;
                }
                if contiguous {
                    // A block whose root was never compared is executed, not
                // verified; it carries state forward but must not be claimed.
                if checked_here {
                    run_start.get_or_insert(n);
                } else if run_start.is_some() {
                    close_run(
                        &silent, &mut run_start, n, &build,
                        "state not checked at this height",
                    )?;
                }
                } else {
                    // One span per block: truthful about a scattered replay.
                    write_coverage(&silent, n, n, &build)?;
                }
            } else {
                close_run(&silent, &mut run_start, n, &build, &verdict.label())?;
            }
        }
        if !verdict.ok() {
            diverged += 1;
            first_bad.get_or_insert(n);
            println!("#{n}  DIVERGES  ({})", verdict.label());
            if verdict.state {
                println!(
                    "    state    computed {:?}{}",
                    computed_state.unwrap_or(processed.state_root_hash),
                    if via_orchid { "  (orchid form)" } else { "" }
                );
                println!(
                    "             expected {expected_state:?}{}",
                    if unitrie_root || via_orchid { "" } else { "  (rskj stateRoots translation)" }
                );
            }
            if verdict.receipts {
                println!("    receipts computed {:?}", processed.receipts_root);
                println!("             header   {:?}", block.header.receipts_root);
            }
            if verdict.gas {
                println!(
                    "    gas      computed {} header {} ({} txs)",
                    processed.gas_used,
                    block.header.gas_used,
                    block.transactions.len()
                );
            }

            // A receipts-root divergence has no leaves to walk: the state
            // can be identical and a single receipt still differ. Printing
            // ours per transaction is what makes it comparable against the
            // same block from any node over `eth_getTransactionReceipt`.
            if explain && verdict.receipts {
                println!("\n    our receipts, by transaction:");
                let mut cumulative = 0u64;
                for (i, r) in processed.receipts.iter().enumerate() {
                    cumulative += r.gas_used;
                    println!(
                        "      tx[{i}] status={:?} gas_used={} cumulative={} logs={}",
                        r.status,
                        r.gas_used,
                        cumulative,
                        r.logs.len()
                    );
                    for (j, log) in r.logs.iter().enumerate() {
                        println!("        log[{j}] address={:?} topics={}", log.address, log.topics.len());
                        for t in &log.topics {
                            println!("          {t:?}");
                        }
                        println!(
                            "          data 0x{}",
                            alloy_primitives::hex::encode(&log.data)
                        );
                    }
                }
                if !verdict.state {
                    // Said explicitly: with the state root matching, every
                    // write this block made is right and only the receipt is
                    // wrong -- a much narrower place to look.
                    println!(
                        "\n    (the state root MATCHES: the writes are right, the receipt is not)"
                    );
                    stopped_at = Some(n);
                    println!("\n    (--explain stops at the first explained block)");
                    break;
                }
            }

            // Both post-states are reachable through the same store -- ours
            // from the scratch spill, rskj's from its unitrie -- so the two
            // can be walked against each other directly. That names the
            // leaves that differ instead of leaving a pair of root hashes.
            if explain && verdict.state {
                match trie.get(block.header.state_root.as_slice()) {
                    None => println!(
                        "    (rskj's own post-state for this block is not in its unitrie)"
                    ),
                    Some(bytes) => {
                        let theirs_root = TrieNode::from_message(&bytes, trie.as_ref());
                        let (mine, theirs) = support::diff_roots(
                            &processed.new_state_root,
                            &theirs_root,
                            trie.as_ref(),
                        );
                        let a = support::index(mine);
                        let b = support::index(theirs);
                        let mut keys: Vec<&Vec<u8>> = a.keys().chain(b.keys()).collect();
                        keys.sort();
                        keys.dedup();
                        let differing: Vec<&Vec<u8>> = keys
                            .into_iter()
                            .filter(|k| a.get(*k).map(|e| e.0) != b.get(*k).map(|e| e.0))
                            .collect();
                        // The pre-state too: it separates "wrote the wrong
                        // value" from "wrote nothing and kept the old one",
                        // which are different bugs and look identical without
                        // it.
                        let (pre_leaves, _) =
                            support::diff_roots(&pre, &processed.new_state_root, trie.as_ref());
                        let p = support::index(pre_leaves);

                        println!("\n    {} leaf/leaves differ from rskj:", differing.len());
                        for k in differing {
                            println!("      {}", support::describe_key(k));
                            println!("        key     0x{}", alloy_primitives::hex::encode(k));
                            println!(
                                "        before  {}",
                                support::describe_value(k, p.get(k).and_then(|e| e.1.as_ref()))
                            );
                            println!(
                                "        ours    {}",
                                support::describe_value(k, a.get(k).and_then(|e| e.1.as_ref()))
                            );
                            println!(
                                "        rskj    {}",
                                support::describe_value(k, b.get(k).and_then(|e| e.1.as_ref()))
                            );
                        }
                        stopped_at = Some(n);
                        println!("\n    (--explain stops at the first explained block)");
                        break;
                    }
                }
            }
        }

        let step = if contiguous { 1000 } else { 500 };
        if (done + 1) % step == 0 || n == to {
            let secs = started.elapsed().as_secs_f64();
            eprintln!(
                "  #{n}  {checked} verified, {diverged} diverged, {unverifiable} unverifiable \
                 | {:.1} blk/s | {}/{} done",
                (done + 1) as f64 / secs.max(0.001),
                done + 1,
                targets.len()
            );
        }
    }

    // The last run has no failing block to close it, so close it at the end.
    if let Some(start) = run_start.take() {
        let last = stopped_at.unwrap_or(to);
        write_coverage(&silent, start, last, &build)?;
    }
    if legacy.is_some() {
        close_legacy_run(&legacy, &mut legacy_run, legacy_good, &build,
            legacy_blocks, legacy_verified, legacy_events, legacy_skipped, &legacy_skip_kinds)?;
    }
    if legacy.is_some() {
        let _ = legacy_first;
        let _ = legacy_last;
        eprintln!(
            "\n  legacy: {legacy_events} event(s) reconstructed over {legacy_blocks} executed \
             block(s), {legacy_verified} of them with the state root checked{}",
            if legacy_skipped > 0 {
                format!(", {legacy_skipped} decision(s) not encodable -- see the coverage record")
            } else {
                String::new()
            }
        );
    }
    if let Some(store) = &silent {
        eprintln!(
            "\n  silent: {silent_rows} decision(s) recorded; coverage now {} span(s), {} gap(s)",
            store.coverage()?.len(),
            store.gaps()?.len()
        );
    }
    if silent.is_some() || legacy.is_some() {
        rustock_execution::silent::finish();
    }

    let reached = stopped_at.unwrap_or(to);
    println!("\n=== #{from}..=#{reached} ===");
    if let Some(at) = stopped_at {
        // Said plainly, so the counts are never mistaken for a full pass over
        // the range that was asked for.
        println!("  STOPPED EARLY at #{at}; #{}..=#{to} was not examined", at + 1);
    }
    println!("  verified      {checked}");
    if unchecked > 0 {
        println!(
            "  executed      {unchecked}  (pre-RSKIP126, no root comparison made: state\n\
             \x20               carried forward but NOT verified, and not recorded as coverage)"
        );
    }
    println!("  diverged      {diverged}");
    println!("  unverifiable  {unverifiable}");
    if let Some(n) = first_bad {
        println!("  first failure #{n}");
        println!("\n  next: re-run with --explain to see which leaves differ from rskj");
    }
    println!("  took {:.0}s", started.elapsed().as_secs_f64());

    // A non-zero exit makes this usable from a script without parsing output.
    // An early stop counts as failure even if every examined block passed,
    // because the range was not actually cleared.
    if diverged > 0 || stopped_at.is_some() {
        std::process::exit(1);
    }
    Ok(())
}
