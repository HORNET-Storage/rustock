//! Measure block execution against a realistic trie, at a chosen number of
//! threads.
//!
//! The method, the fixture and the caveats are in
//! `docs/parallel-execution-benchmark.md`. In short: a synthetic trie of
//! about a gigabyte, blocks of transfers between accounts that already
//! exist in it so the trie's depth never changes, writes persisted so the
//! I/O is paid, and a per-block time series so a cold start or a drift is
//! visible rather than averaged away.
//!
//! ```text
//! loadtest <fixture-dir> [options]
//!
//!   --threads N        execution threads (default 1)
//!   --sublists N       parallel sublists each block declares (default 2)
//!   --txs N            transactions per block (default 200)
//!   --blocks N         blocks to execute (default 300)
//!   --seconds N        stop after about this long, whatever the block count
//!   --csv FILE         write the per-block series here
//!   --label TEXT       a name for the run, carried into the CSV
//!   --cache-mb N       RocksDB block cache (default 256, the node's)
//!   --validate BOOL    also do everything a node does besides execute
//! ```
//!
//! # What `--validate` adds, and why it is off by default
//!
//! Without it this measures execution and the commit and nothing else:
//! senders are handed to `execute_block` rather than recovered from their
//! signatures, the header carries `difficulty: 1` and no merged-mining
//! fields, and the transaction and receipt roots are left zero. That is
//! the right shape for an instrument -- the fewer things in the loop, the
//! more a change shows up as itself -- and it is what every figure in
//! `docs/execution-performance.md` was measured with.
//!
//! `--validate true` adds the rest of what a node pays per block, timed
//! as its own phase so it can be read separately or subtracted back out:
//!
//!   * recovering every sender from its signature, checked against the
//!     sender the generator used, so the run fails rather than quietly
//!     measures the wrong thing;
//!   * the full `HeaderVerifier::default_rsk` set against the real parent,
//!     merged-mining proof of work included;
//!   * `BlockVerifier::default_rsk`, the body rules;
//!   * the transaction trie root, compared against the header, and the
//!     receipt trie root.
//!
//! **Proof of work costs the same at any difficulty**, which is what makes
//! this affordable: verification decodes the Bitcoin header, hashes it and
//! compares against the target, and none of those depend on how hard the
//! target is. The blocks are sealed at difficulty 1, where rskj's target is
//! 2^256 / 3: one hash in three meets it, so sealing takes a few nonces and
//! verifying costs exactly what it costs on mainnet.
//!
//! Sealing is deliberately **outside** the timed region. A node receives
//! blocks already mined; making one is not a cost it pays.
//!
//! `--sublists` above `TX_EXECUTION_THREADS` produces blocks that **are not
//! valid on the network**. That is deliberate and is the point of the
//! option: RSKIP-144 specifies four where rskj implements two, and the
//! difference is worth measuring without editing a consensus constant.

use anyhow::{Context, Result};
use alloy_primitives::{Address, B256, U256};
use rustock_core::config::ChainConfig;
use rustock_core::types::receipt::{ordered_trie_root, ordered_tx_trie_root, Receipt};
use rustock_core::validation::{BlockVerifier, HeaderVerifier};
use rustock_core::{Block, Header, Transaction};
use rustock_execution::hardfork::RskHardforkConfig;
use rustock_execution::mining::workload::{account_key, address_of, filler_address, sign};
use rustock_execution::{BlockProcessor, RskExecutor};
use rustock_storage::{BlockStore, RocksDbTrieStore};
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHAIN_ID: u64 = 33;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let fixture = args.next().context("usage: loadtest <fixture-dir> [options]")?;
    let mut threads = 1usize;
    let mut sublists = 2usize;
    let mut txs = 200usize;
    let mut blocks = 300usize;
    let mut seconds: Option<u64> = None;
    let mut csv: Option<String> = None;
    let mut label = String::new();
    let mut cache_mb = 256usize;
    let mut node_lru: usize = 0;
    let mut no_wal: bool = false;
    let mut sst_kb: usize = 0;
    let mut compact_only: bool = false;
    let mut flatdb: bool = false;
    let mut expected_keys: u64 = 24_000_000;
    // How often the store is asked to make itself durable. 1 is once a
    // block. Trie nodes are derivable -- lose them and re-executing the
    // block recomputes them -- so a node may legitimately flush less often
    // than it commits, provided its head pointer lags what is on disk.
    let mut flush_every: u64 = 1;
    // Ways to descend the block's access list before executing it. 0 is
    // off. See `prefetch_access_list`.
    let mut prefetch: usize = 0;
    // Percentage of recipients drawn from beyond the fixture, so the
    // transfer creates the account rather than updating one. 0 -- the
    // default, and what every published figure was measured at -- never
    // inserts a key, so `TrieNode::split` is never reached and the trie
    // keeps its shape for the whole run.
    let mut new_accounts: u64 = 0;
    // Do the rest of what a node does per block, not only execute it. Off
    // by default so every figure already recorded stays comparable.
    let mut validate = false;

    while let Some(flag) = args.next() {
        let value = args.next().with_context(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--threads" => threads = value.parse()?,
            "--sublists" => sublists = value.parse()?,
            "--txs" => txs = value.parse()?,
            "--blocks" => blocks = value.parse()?,
            "--seconds" => seconds = Some(value.parse()?),
            "--csv" => csv = Some(value),
            "--label" => label = value,
            "--cache-mb" => cache_mb = value.parse()?,
            "--node-lru" => node_lru = value.parse()?,
            "--no-wal" => no_wal = value.parse()?,
            "--sst-kb" => sst_kb = value.parse()?,
            "--compact-only" => compact_only = value.parse()?,
            "--flatdb" => flatdb = value.parse()?,
            "--expected-keys" => expected_keys = value.parse()?,
            "--flush-every" => flush_every = value.parse()?,
            "--prefetch" => prefetch = value.parse()?,
            "--new-accounts" => new_accounts = value.parse()?,
            "--validate" => validate = value.parse()?,
            other => anyhow::bail!("unknown option {other}"),
        }
    }

    let manifest = Manifest::read(&fixture)?;
    println!(
        "fixture {fixture}\n  {} accounts, {} with keys, root {}",
        manifest.accounts, manifest.signers, manifest.root
    );
    println!("run  threads {threads}  sublists {sublists}  {txs} tx/block");
    if manifest.signers < txs as u64 {
        anyhow::bail!(
            "{txs} transactions a block needs {txs} distinct senders, and the fixture has \
             {} accounts with keys. Every transaction from a different sender is what keeps \
             them independent; reusing one would connect them through its nonce.",
            manifest.signers
        );
    }

    // The same block cache and bloom filters the node's epoch store runs
    // with. Without them a plain `RocksDbTrieStore` answers every level of
    // every path from disk: the first attempt measured 4.5 seconds a block
    // and a sixfold ramp from start to finish, which is a measurement of
    // uncached RocksDB rather than of execution, and of a configuration no
    // node uses.
    // Rewrite every SST with the configured block size and stop. Changing
    // `block_size` only affects files written afterwards, so measuring a
    // smaller block against a fixture built with the default measures
    // nothing until the fixture is rebuilt.
    if compact_only {
        let started = std::time::Instant::now();
        let store = open_node_cached_store(
            &fixture,
            cache_mb,
            sst_kb,
            rustock_storage::cached_trie_store::Config::default(),
        )?;
        store.compact_all();
        println!("compacted {fixture} at {sst_kb} KB blocks in {:.0}s",
                 started.elapsed().as_secs_f64());
        return Ok(());
    }

    let trie_store: Arc<dyn TrieStore> = if flatdb {
        // FlatDB caches nothing of its own: the heap *is* the page cache,
        // so `--cache-mb` has no counterpart here and the comparison is
        // between RocksDB with a 256 MB block cache and this with none.
        Arc::new(rustock_storage::FlatTrieStore::open(
            &fixture,
            rustock_flatdb::Options {
                expected_keys,
                read_only: false,
                sync_writes: false,
                ..rustock_flatdb::Options::default()
            },
        )?)
    } else if node_lru > 0 {
        Arc::new(open_node_cached_store(
            &fixture,
            cache_mb,
            sst_kb,
            rustock_storage::cached_trie_store::Config {
                lru_capacity: node_lru,
                // A block writes about 6,900 nodes; flushing once a block
                // rather than four times is what "batch the block" means.
                auto_flush_threshold: 100_000,
                disable_wal: no_wal,
            },
        )?)
    } else {
        Arc::new(open_cached_store(&fixture, cache_mb)?)
    };
    let root = trie_store
        .get(manifest.root.as_slice())
        .map(|data| TrieNode::from_message(&data, trie_store.as_ref()))
        .context("the fixture's root is not in its own store")?;

    // A throwaway block store: the chain the blocks hang off, not the state.
    let chain_dir = tempfile::tempdir().context("a temporary chain directory")?;
    let block_store = Arc::new(BlockStore::open(chain_dir.path())?);
    let hardfork_cfg = RskHardforkConfig::all_active_parallel(CHAIN_ID);
    let processor = BlockProcessor::new(hardfork_cfg.clone(), block_store.clone())
        .with_execution_threads(threads);

    // Regtest's activation heights are all zero, so every rule -- orchid,
    // wasabi100, iris300 -- is live from block one. On mainnet's heights a
    // 40-block run would skip merged mining entirely and measure nothing.
    // Regtest's bounds, with the gas limit raised to the one the
    // benchmark's headers have always carried. Changing the header
    // instead would move every figure already recorded, and the bound is
    // not what is being measured.
    let chain = Arc::new(ChainConfig { max_gas_limit: 100_000_000, ..ChainConfig::regtest() });
    let header_verifier = HeaderVerifier::default_rsk(chain.clone());
    let block_verifier = BlockVerifier::default_rsk(&chain);

    let mut state = root;
    let mut parent_hash = B256::ZERO;
    let mut parent_header: Option<Header> = None;
    let mut nonces = vec![0u64; manifest.signers as usize];
    let mut rows: Vec<Row> = Vec::with_capacity(blocks);
    let deadline = seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let started = Instant::now();

    for number in 1..=blocks as u64 {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            println!("  stopping at block {} on the time limit", number - 1);
            break;
        }

        let (mut transactions, mut senders) =
            build_transactions(number, txs, &manifest, new_accounts, &mut nonces);
        // The sublist edges are computed over the user transactions, so
        // REMASC lands in the sequential tail where it belongs -- it
        // reaches a precompile RSKIP-144 marks sequential-only.
        let edges = edges_for(sublists, transactions.len());
        if validate {
            // Every real block ends with REMASC, and `RemascValidationRule`
            // rejects one that does not. It carries no signature, pays no
            // gas, and the executor recognises it by that shape.
            let remasc = remasc_tx();
            transactions.push(remasc.clone());
            senders.push((remasc, Address::ZERO));
        }
        let mut header = bench_header(number, parent_hash,
                                      state.compute_hash(trie_store.as_ref()), edges);
        if validate {
            // Untimed: a node receives blocks already mined, so sealing is
            // not a cost it pays. Only verifying is.
            header.transactions_root = ordered_tx_trie_root(&transactions, true);
            header.gas_used = 21_000 * txs as u64;
            seal_merged_mining(&mut header)?;
        }
        let block = Block { header, transactions, ommers: Vec::new() };

        let validating = Instant::now();
        if validate {
            // Sender recovery, which `execute_block` is spared because the
            // generator already knows who signed.
            //
            // Through the processor's own `recover_senders` rather than a
            // loop written here, so this measures what the node runs --
            // including its threading, which a copy would have to keep in
            // step by hand. Checked rather than discarded: a recovery that
            // silently returned the wrong address would turn this into a
            // benchmark of nothing.
            let recovered = processor
                .recover_senders(&block.transactions, CHAIN_ID)
                .with_context(|| format!("recovering senders in block {number}"))?;
            for ((tx, expected), got) in senders.iter().zip(&recovered) {
                // REMASC gets the zero address rather than a recovery.
                if tx.v == 0 && tx.r.is_zero() && tx.s.is_zero() {
                    continue;
                }
                anyhow::ensure!(
                    got == expected,
                    "block {number}: recovered {got} but the generator signed as {expected}"
                );
            }
            if let Some(parent) = parent_header.as_ref() {
                header_verifier
                    .verify(&block.header, Some(parent))
                    .map_err(|e| anyhow::anyhow!("verifying header {number}: {e:?}"))?;
            }
            block_verifier
                .verify(&block)
                .map_err(|e| anyhow::anyhow!("verifying body {number}: {e:?}"))?;
            let root = ordered_tx_trie_root(&block.transactions, true);
            anyhow::ensure!(
                root == block.header.transactions_root,
                "block {number}: transaction root does not match the header"
            );
        }
        let mut validated = validating.elapsed();
        let mut persisted = Duration::ZERO;

        // Simulate an EIP-2930 access list at 100% coverage.
        //
        // The generator knows every account a block touches -- the sender
        // and the recipient of each transfer -- so the list is exact
        // rather than a hint, and no protocol change is needed to measure
        // what one would be worth. This is therefore an **upper bound**:
        // if the gain is small with perfect coverage, no real scheme that
        // has to transmit, verify or guess the list can do better.
        //
        // The descents are independent of each other even though each is
        // internally dependent, which is the whole point: a
        // content-addressed store cannot batch one descent, because a
        // child's hash is only learned from its parent -- but N descents
        // can be in flight at once.
        let prefetching = Instant::now();
        if prefetch > 0 {
            prefetch_access_list(&state, trie_store.as_ref(), &senders, prefetch);
        }
        let prefetched = prefetching.elapsed();

        let at = Instant::now();
        let executed = RskExecutor::new(hardfork_cfg.clone(), block_store.clone())
            .with_execution_threads(threads)
            .execute_block(
                &block.header,
                &senders,
                &state,
                trie_store.clone(),
            )
            .with_context(|| format!("executing block {number}"))?;
        let execution = at.elapsed();

        if validate {
            // The receipt root needs the receipts, so it cannot be paid
            // before execution. There is nothing in the header to compare
            // it against -- a miner fills that field *after* executing,
            // and this header was built before -- but computing it costs
            // the same either way, which is what is being measured.
            let at = Instant::now();
            let mut cumulative = 0u64;
            let receipts: Vec<Receipt> = executed
                .tx_results
                .iter()
                .map(|r| {
                    cumulative += r.gas_used;
                    // revm's Log and the core Receipt's Log are distinct
                    // types; a node converts between them here too.
                    let logs: Vec<rustock_core::types::receipt::Log> = r
                        .logs
                        .iter()
                        .map(|l| rustock_core::types::receipt::Log {
                            address: l.address,
                            topics: l.topics().to_vec(),
                            data: l.data.data.clone(),
                        })
                        .collect();
                    let mut logs_bloom = Default::default();
                    for log in &logs {
                        rustock_core::bloom::accrue_log(&mut logs_bloom, log);
                    }
                    Receipt {
                        post_tx_state: if r.success { vec![1] } else { Vec::new() },
                        cumulative_gas_used: cumulative,
                        gas_used: r.gas_used,
                        logs_bloom,
                        logs,
                        status: r.success,
                    }
                })
                .collect();
            std::hint::black_box(ordered_trie_root(&receipts, true));
            validated += at.elapsed();

            // Persisting the block is not optional here even as a
            // measurement: REMASC distributes the fees of the block that
            // matured `maturity` blocks ago and reads it back out of the
            // store, so a run longer than the maturity fails without it.
            // A real node writes this anyway. Timed apart because it is
            // I/O and the rest of validation is not.
            let at = Instant::now();
            block_store.put_header(&block.header)?;
            block_store.put_header_number(block.header.hash(), number)?;
            block_store.put_body(block.header.hash(), &block.transactions, &block.ommers)?;
            block_store.put_canonical_hash(number, block.header.hash())?;
            block_store.put_receipts(block.header.hash(), &receipts)?;
            persisted = at.elapsed();
        }

        // Persist, so the I/O a real node pays is paid here too.
        let writing = Instant::now();
        // With one thread the executor hands back the changes and the
        // caller applies them, so the commit happens here instead of
        // inside `execute_block_in_parallel`. Timed the same way, so the
        // breakdown is comparable across thread counts.
        let mut committing = std::time::Duration::ZERO;
        let mut next = match executed.applied_root {
            Some(root) => root,
            None => {
                let at = Instant::now();
                let root = rustock_execution::apply_state_changes(
                    &state,
                    trie_store.as_ref(),
                    &executed.state_changes,
                    &executed.markers,
                );
                committing = at.elapsed();
                root
            }
        };
        // The root hash walks every dirty node of the block: `to_message`
        // recurses into in-memory children to fold in their hashes. One
        // pass, one thread, once a block.
        let hashing = Instant::now();
        let hash = next.compute_hash(trie_store.as_ref());
        let hashed = hashing.elapsed();

        next.save(trie_store.as_ref(), true);
        if number % flush_every == 0 {
            trie_store.flush();
        }
        let write = writing.elapsed();

        // Reload lazily, as the node does: children become hash references
        // resolved on demand, so the next block walks only its own paths
        // instead of carrying the whole accumulated tree in memory.
        let reloading = Instant::now();
        state = trie_store
            .get(hash.as_slice())
            .map(|data| TrieNode::from_message(&data, trie_store.as_ref()))
            .unwrap_or(next);
        let reloaded = reloading.elapsed();
        parent_hash = block.header.hash();
        parent_header = Some(block.header.clone());

        rows.push(Row {
            number,
            transactions: executed.tx_results.len(),
            gas: executed.gas_used,
            execution_us: execution.as_micros() as u64,
            write_us: write.as_micros() as u64,
            prefetch_us: prefetched.as_micros() as u64,
            maintenance_us: executed.phases.maintenance_us,
            sublists_us: executed.phases.sublists_us,
            commit_us: executed.phases.commit_us + committing.as_micros() as u64,
            sequential_us: executed.phases.sequential_us,
            accounts: executed.state_changes.len() as u64,
            hash_us: hashed.as_micros() as u64,
            reload_us: reloaded.as_micros() as u64,
            validate_us: validated.as_micros() as u64,
            persist_us: persisted.as_micros() as u64,
            elapsed_s: started.elapsed().as_secs_f64(),
        });

        if number % 50 == 0 || number == blocks as u64 {
            let recent = &rows[rows.len().saturating_sub(50)..];
            println!(
                "  block {number}  {:.0} tx/s  exec {:.1} ms  write {:.1} ms",
                rate(recent),
                mean(recent, |r| r.execution_us) / 1000.0,
                mean(recent, |r| r.write_us) / 1000.0
            );
        }
    }

    // The state root after the last block. Every configuration of the store
    // must end here: a cache, a lock discipline or a table option that
    // changes this has changed the chain, not its speed.
    println!("\nfinal root     {}", state.compute_hash(trie_store.as_ref()));

    report(&rows, &label, threads, sublists);
    if let Some(path) = csv {
        write_csv(&path, &rows, &label, threads, sublists)?;
        println!("\nseries written to {path}");
    }
    Ok(())
}

/// Walk every account the block will touch, `ways` descents at a time.
///
/// Each descent resolves the path from the root to a leaf and throws the
/// answer away: the point is the side effect, which is that the nodes are
/// in the store's cache by the time execution asks for them.
///
/// Senders and recipients are the whole access list for a native
/// transfer. Duplicates are dropped -- a block reuses accounts, and
/// descending the same path twice would overstate the work a real list
/// would cause.
fn prefetch_access_list(
    state: &TrieNode,
    store: &dyn TrieStore,
    senders: &[(rustock_core::Transaction, Address)],
    ways: usize,
) {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(senders.len() * 2);
    for (tx, from) in senders {
        keys.push(rustock_trie::account_key(from));
        if tx.to.len() == 20 {
            keys.push(rustock_trie::account_key(&Address::from_slice(&tx.to)));
        }
    }
    keys.sort_unstable();
    keys.dedup();

    let ways = ways.max(1).min(keys.len().max(1));
    let chunk = keys.len().div_ceil(ways);
    std::thread::scope(|scope| {
        for part in keys.chunks(chunk) {
            scope.spawn(move || {
                for key in part {
                    // The answer is discarded; the cache it populates is
                    // the product.
                    let _ = state.get(&rustock_trie::TrieKeySlice::from_key(key), store);
                }
            });
        }
    });
}

/// A read-write trie store configured like the node's epoch store: a block
/// cache of the same size and bloom filters on the same terms.
fn open_cached_store(dir: &str, cache_mb: usize) -> Result<RocksDbTrieStore> {
    RocksDbTrieStore::open_with_cache(dir, cache_mb * 1024 * 1024)
        .with_context(|| format!("opening {dir}"))
}

/// The store the node itself runs: a `CachedTrieStore` over the same RocksDB,
/// adding an LRU of **decoded nodes keyed by hash** and a `WriteBatch`.
///
/// The distinction from `--cache-mb` is the point of the option. A RocksDB
/// block cache caches 4 KB SST blocks, and trie keys are hashes, so a block
/// holds ~35 unrelated nodes of which a lookup wants one. An LRU keyed by the
/// node's own hash caches the node itself.
fn open_node_cached_store(
    dir: &str,
    cache_mb: usize,
    sst_kb: usize,
    config: rustock_storage::cached_trie_store::Config,
) -> Result<rustock_storage::CachedTrieStore> {
    use rocksdb::{ColumnFamilyDescriptor, Options};
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let cache = rocksdb::Cache::new_lru_cache(cache_mb * 1024 * 1024);
    let mut block = rocksdb::BlockBasedOptions::default();
    block.set_bloom_filter(10.0, false);
    block.set_block_cache(&cache);
    // Only affects SSTs written from here on, so measuring a smaller block
    // means compacting the fixture with it first.
    if sst_kb > 0 {
        block.set_block_size(sst_kb * 1024);
    }
    let mut cf_opts = Options::default();
    cf_opts.set_block_based_table_factory(&block);
    let cfs = vec![ColumnFamilyDescriptor::new("trie_nodes", cf_opts)];
    let db = rocksdb::DB::open_cf_descriptors(&opts, dir, cfs)
        .with_context(|| format!("opening {dir}"))?;
    Ok(rustock_storage::CachedTrieStore::with_config(Arc::new(db), config))
}

struct Row {
    number: u64,
    transactions: usize,
    gas: u64,
    execution_us: u64,
    write_us: u64,
    prefetch_us: u64,
    maintenance_us: u64,
    sublists_us: u64,
    commit_us: u64,
    /// Running the sequential sublist. Execution, not trie work, and it
    /// used to be counted inside the commit.
    sequential_us: u64,
    /// Accounts the block changed, so the commit's cost can be read
    /// against the work it was given rather than against the clock.
    accounts: u64,
    hash_us: u64,
    reload_us: u64,
    /// Everything a node pays per block besides executing it: sender
    /// recovery, header and body rules, the transaction and receipt
    /// roots. CPU, and all of it divides across transactions. Zero
    /// unless `--validate`.
    validate_us: u64,
    /// Writing the block and its receipts to the block store. I/O, and
    /// kept apart from `validate_us` for that reason. Zero unless
    /// `--validate`.
    persist_us: u64,
    elapsed_s: f64,
}

fn rate(rows: &[Row]) -> f64 {
    let us: u64 = rows.iter().map(|r| r.execution_us + r.write_us + r.prefetch_us).sum();
    let txs: usize = rows.iter().map(|r| r.transactions).sum();
    if us == 0 { 0.0 } else { txs as f64 * 1_000_000.0 / us as f64 }
}

fn mean(rows: &[Row], of: impl Fn(&Row) -> u64) -> f64 {
    if rows.is_empty() {
        return 0.0;
    }
    rows.iter().map(|r| of(r) as f64).sum::<f64>() / rows.len() as f64
}

/// The shape of the question: is the start faster than the end?
fn report(rows: &[Row], label: &str, threads: usize, sublists: usize) {
    if rows.is_empty() {
        println!("no blocks executed");
        return;
    }
    let tenth = (rows.len() / 10).max(1);
    let first = &rows[..tenth];
    let last = &rows[rows.len() - tenth..];
    let total_tx: usize = rows.iter().map(|r| r.transactions).sum();
    let total_us: u64 = rows.iter().map(|r| r.execution_us + r.write_us).sum();

    println!();
    println!("=== {label}  threads {threads}  sublists {sublists} ===");
    println!("  blocks          {}", rows.len());
    println!("  transactions    {total_tx}");
    println!("  wall            {:.1}s", rows.last().map(|r| r.elapsed_s).unwrap_or(0.0));
    println!("  overall         {:.0} tx/s", total_tx as f64 * 1e6 / total_us.max(1) as f64);
    println!("  first 10%       {:.0} tx/s", rate(first));
    println!("  last 10%        {:.0} tx/s", rate(last));
    let drift = if rate(first) > 0.0 { rate(last) / rate(first) } else { 0.0 };
    println!("  last/first      {drift:.2}");
    println!(
        "  prefetch        {:.1} ms/block",
        mean(rows, |r| r.prefetch_us) / 1000.0
    );
    // What parallel execution can and cannot divide. Three of these four
    // run once a block on one thread whatever `--threads` says.
    println!(
        "  maintenance     {:.1}   sublists {:.1}   sequential {:.1}   commit {:.1}   root hash {:.1}   reload {:.1}  ms/block",
        mean(rows, |r| r.maintenance_us) / 1000.0,
        mean(rows, |r| r.sublists_us) / 1000.0,
        mean(rows, |r| r.sequential_us) / 1000.0,
        mean(rows, |r| r.commit_us) / 1000.0,
        mean(rows, |r| r.hash_us) / 1000.0,
        mean(rows, |r| r.reload_us) / 1000.0,
    );
    println!(
        "  accounts/block  {:.0}   commit per account {:.0} us",
        mean(rows, |r| r.accounts),
        mean(rows, |r| r.commit_us) / mean(rows, |r| r.accounts).max(1.0),
    );
    let validating = mean(rows, |r| r.validate_us);
    if validating > 0.0 {
        // Reported next to the per-transaction figure because that is how
        // it scales: sender recovery is once per transaction and dominates
        // the rest of validation by two orders of magnitude.
        println!(
            "  validation      {:.1} ms/block   {:.0} us per transaction",
            validating / 1000.0,
            validating / mean(rows, |r| r.transactions as u64).max(1.0),
        );
        println!(
            "  persist block   {:.1} ms/block",
            mean(rows, |r| r.persist_us) / 1000.0
        );
    }
    let sequential = mean(rows, |r| r.maintenance_us)
        + mean(rows, |r| r.sequential_us)
        + mean(rows, |r| r.commit_us)
        + mean(rows, |r| r.hash_us)
        + mean(rows, |r| r.reload_us);
    let parallel = mean(rows, |r| r.sublists_us);
    if sequential + parallel > 0.0 {
        println!(
            "  of the measured phases, {:.0}% is sequential whatever the thread count",
            100.0 * sequential / (sequential + parallel)
        );
    }
    println!(
        "  execution       {:.1} ms/block   write {:.1} ms/block",
        mean(rows, |r| r.execution_us) / 1000.0,
        mean(rows, |r| r.write_us) / 1000.0
    );
    println!("  gas             {}", rows.iter().map(|r| r.gas).sum::<u64>());
}

fn write_csv(path: &str, rows: &[Row], label: &str, threads: usize, sublists: usize) -> Result<()> {
    let mut out = String::from(
        "label,threads,sublists,block,transactions,gas,prefetch_us,maintenance_us,\
sublists_us,commit_us,hash_us,reload_us,execution_us,write_us,elapsed_s\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{label},{threads},{sublists},{},{},{},{},{},{},{},{},{},{},{},{:.3}\n",
            r.number, r.transactions, r.gas, r.prefetch_us, r.maintenance_us,
            r.sublists_us, r.commit_us, r.hash_us, r.reload_us, r.execution_us,
            r.write_us, r.elapsed_s
        ));
    }
    std::fs::write(path, out).with_context(|| format!("writing {path}"))?;
    Ok(())
}

/// Transfers from keyed accounts to accounts drawn from the whole fixture.
///
/// Every transaction has a different sender, because two from one sender
/// are connected by its nonce and would land in the same sublist whatever
/// else they touch. Recipients are scattered over all nine million so the
/// reads do not settle into a working set.
fn build_transactions(
    block: u64,
    count: usize,
    manifest: &Manifest,
    new_accounts: u64,
    nonces: &mut [u64],
) -> (Vec<Transaction>, Vec<(Transaction, Address)>) {
    let mut transactions = Vec::with_capacity(count);
    let mut with_senders = Vec::with_capacity(count);
    for i in 0..count {
        // A different slice of senders each block, so no small set stays
        // warm across the run.
        let s = ((block as usize * count + i) % manifest.signers as usize) as u64;
        let key = account_key(manifest.seed, s as usize);
        let from = address_of(&key);
        let to = recipient(manifest, block, i, new_accounts);

        let mut tx = Transaction {
            nonce: nonces[s as usize],
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: alloy_primitives::Bytes::copy_from_slice(to.as_slice()),
            value: U256::from(1u64),
            input: alloy_primitives::Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign(&mut tx, &key, CHAIN_ID);
        nonces[s as usize] += 1;
        transactions.push(tx.clone());
        with_senders.push((tx, from));
    }
    (transactions, with_senders)
}

/// The transaction every real block ends with.
///
/// rskj `RemascTransaction`: no signature, no gas, addressed to the REMASC
/// precompile. `RemascValidationRule` checks for exactly this shape as the
/// last entry, and the executor recognises it the same way.
fn remasc_tx() -> Transaction {
    Transaction {
        nonce: 0,
        gas_price: U256::ZERO,
        gas_limit: U256::ZERO,
        to: alloy_primitives::Bytes::copy_from_slice(
            rustock_execution::precompiles::REMASC_ADDR.as_slice(),
        ),
        value: U256::ZERO,
        input: alloy_primitives::Bytes::new(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    }
}

/// Give a header the merged-mining proof a verifier will check.
///
/// Not a cost a node pays -- it receives blocks already mined -- so this
/// runs outside the timed region. It is here because verification has
/// nothing to verify without it, and because at `difficulty: 1` rskj's
/// target is 2^256 / 3, which one hash in three meets, so sealing is a few
/// nonces rather than a search. Verification does the same work it would
/// against a real mainnet target.
fn seal_merged_mining(header: &mut Header) -> Result<()> {
    use bitcoin::hashes::Hash as _;
    use rustock_core::validation::fork_detection::REQUIRED_BLOCKS;
    use rustock_core::validation::merged_mining::{compress_coinbase, difficulty_to_target};
    use rustock_execution::mining::{coinbase, fork_detection, merkle};

    // The coinbase commits to the header's merged-mining hash, which is
    // computed over the header *without* these three fields -- so the
    // order here is not circular, and the caches must be clear or the
    // hash is the one from before the transaction root was set.
    header.cached_hash = None;
    header.cached_hash_for_merged_mining = None;
    // From block 449 the hash's last twelve bytes are fork-detection data,
    // and any twelve do here: this measures proof of work, not fork
    // detection. Below 449 rskj wants the whole hash.
    let fork_data: &[u8] = if header.number >= REQUIRED_BLOCKS { &[0u8; 12] } else { &[] };
    let payload = fork_detection::apply_to_hash(header.hash_for_merged_mining(), fork_data);

    let cb = coinbase::build_coinbase(&payload, 0);
    // One hash in three meets rskj's target at difficulty 1, 2^256 / 3.
    let target = difficulty_to_target(header.difficulty);
    let btc = (0..=u32::MAX)
        .map(|nonce| coinbase::build_bitcoin_block(cb.clone(), nonce))
        .find(|block| U256::from_le_slice(block.header.block_hash().as_byte_array()) <= target)
        .context("no nonce meets the target")?;
    let compressed = compress_coinbase(&coinbase::encode_transaction(&cb), true)
        .map_err(|e| anyhow::anyhow!("compressing the coinbase: {e}"))?;
    let proof = merkle::proof_from_txids(&coinbase::txids_display_order(&btc))
        .map_err(|e| anyhow::anyhow!("building the merkle proof: {e}"))?;

    header.bitcoin_merged_mining_header = Some(coinbase::encode_header(&btc.header).into());
    header.bitcoin_merged_mining_coinbase_transaction = Some(compressed.into());
    header.bitcoin_merged_mining_merkle_proof = Some(proof.into());
    header.cached_hash = None;
    Ok(())
}

/// An account somewhere in the fixture, chosen so the reads scatter.
///
/// With `new_accounts` above zero, that share of recipients is drawn from
/// *past* the fixture's account count instead, so the transfer inserts a
/// key the trie does not hold. That is the only way a run reaches
/// `TrieNode::split` and deepens the trie; at the default of zero it never
/// does, and the run measures updates to a trie of fixed shape.
///
/// Two things change when it is non-zero, and a measurement has to allow
/// for both: the final state root is no longer comparable across different
/// values of the flag, and the trie grows as the run proceeds, so repeated
/// runs must start from a fresh copy of the fixture to be measuring the
/// same thing.
fn recipient(manifest: &Manifest, block: u64, i: usize, new_accounts: u64) -> Address {
    // A multiplicative step coprime with the account count walks the whole
    // range without repeating, which a modulo of a counter would not.
    let step = block.wrapping_mul(2_654_435_761).wrapping_add(i as u64 * 40_503);
    if new_accounts > 0 && step % 100 < new_accounts {
        // Past the fixture's range, so no such account exists yet. The
        // index still advances, so no two transfers create the same one.
        return filler_address(manifest.seed, manifest.accounts + step);
    }
    let index = step % manifest.accounts;
    if index < manifest.signers {
        address_of(&account_key(manifest.seed, index as usize))
    } else {
        filler_address(manifest.seed, index)
    }
}

/// Edges that split `count` transactions into `sublists` parallel parts,
/// leaving the last one sequential.
fn edges_for(sublists: usize, count: usize) -> Vec<i16> {
    if sublists == 0 || count < sublists + 1 {
        return Vec::new();
    }
    // One slot is kept for the sequential set, as a block must have.
    let per = count / (sublists + 1);
    (1..=sublists).map(|i| (i * per) as i16).collect()
}

fn bench_header(number: u64, parent_hash: B256, state_root: B256, edges: Vec<i16>) -> Header {
    Header {
        parent_hash,
        ommers_hash: B256::ZERO,
        beneficiary: Address::repeat_byte(0x11),
        state_root,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        version_fields: (!edges.is_empty()).then(|| {
            rustock_core::types::header::HeaderVersionFields {
                version: 1,
                edges: Some(edges),
                base_event: None,
            }
        }),
        difficulty: U256::from(1),
        number,
        gas_limit: U256::from(100_000_000u64),
        gas_used: 0,
        timestamp: 1_700_000_000 + number * 14,
        extra_data: Default::default(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::ZERO,
        uncle_count: 0,
        umm_root: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
        kept: None,
    }
}

struct Manifest {
    seed: u64,
    accounts: u64,
    signers: u64,
    root: B256,
}

impl Manifest {
    fn read(dir: &str) -> Result<Self> {
        let text = std::fs::read_to_string(format!("{dir}/MANIFEST"))
            .with_context(|| format!("{dir}/MANIFEST -- is this a synthetic_state fixture?"))?;
        let mut seed = 0;
        let mut accounts = 0;
        let mut signers = 0;
        let mut root = B256::ZERO;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("seed"), Some(v)) => seed = v.parse()?,
                (Some("accounts"), Some(v)) => accounts = v.parse()?,
                (Some("signers"), Some(v)) => signers = v.parse()?,
                (Some("root"), Some(v)) => root = v.parse()?,
                _ => {}
            }
        }
        anyhow::ensure!(accounts > 0 && signers > 0, "the manifest is incomplete");
        Ok(Self { seed, accounts, signers, root })
    }
}
