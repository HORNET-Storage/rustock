# The `examples/` tools

Sixty small programs under [`crates/cli/examples/`](../crates/cli/examples/),
each answering one question about a running or stopped node. They are
`cargo` examples rather than subcommands so they stay out of the node binary
and out of its argument surface: a diagnostic that only three people will
ever run should not be a flag everyone has to read past.

Build and run one with:

```sh
cargo run --release -p rustock-cli --example <name> -- <args>
```

Most take a data directory and open it **read-only**, so they are safe to run
against the live node. The ones marked **(writes)** do not: they modify the
database, the head pointers or a segment store, and want the node stopped.

Each entry's description is the first line of the tool's own `//!` comment;
the source is the reference, and run a tool with no arguments to see its
usage.


## Bridge and PowPeg

| tool | what it answers |
|---|---|
| [`powpeg_signature_audit`](../crates/cli/examples/powpeg_signature_audit.rs) | Did a PowPeg functionary ever submit a signature the Bridge refused? |
| [`federation_intervals`](../crates/cli/examples/federation_intervals.rs) | Which PowPeg functionary keys were active over which block range. |
| [`bridge_events`](../crates/cli/examples/bridge_events.rs) | Query the Bridge event index: every occurrence of one event, in block order. |
| [`bridge_method`](../crates/cli/examples/bridge_method.rs) | Identify a Bridge method from its 4-byte ABI selector, using the node's own table rather than a guess. |
| [`bridge_subtree`](../crates/cli/examples/bridge_subtree.rs) | How big is the Bridge's storage subtree, and how much of it is missing from a chunk? |
| [`pegin_refunds`](../crates/cli/examples/pegin_refunds.rs) | Did the Bridge's peg-in refund path ever execute on mainnet? |
| [`scan_pegin_calls`](../crates/cli/examples/scan_pegin_calls.rs) | Find `registerBtcTransaction` calls by reading blocks, without executing them. |
| [`scan_silent`](../crates/cli/examples/scan_silent.rs) | Read the silent-decision store: what the Bridge decided without logging it. |
| [`check_supply`](../crates/cli/examples/check_supply.rs) | Replay canonical blocks and report any that do not conserve the native supply, changing nothing on disk. |

## Chain and block inspection

| tool | what it answers |
|---|---|
| [`block_info`](../crates/cli/examples/block_info.rs) | Prints stored block metadata for given heights, read-only. |
| [`height_peek`](../crates/cli/examples/height_peek.rs) | Every block stored at a height, canonical or not, read-only. |
| [`dump_block`](../crates/cli/examples/dump_block.rs) | Writes a block's stored bytes to disk, for attaching to a bug report. |
| [`inspect_block`](../crates/cli/examples/inspect_block.rs) | Execute one block against an archival trie and print what rustock computed: per-transaction gas and status, block gas, paid fees, and every root. Used to tell "we disagree about a fee" from "we disagree about what happened". |
| [`block_writes`](../crates/cli/examples/block_writes.rs) | What did rustock write while executing one block? |
| [`scan_addr`](../crates/cli/examples/scan_addr.rs) | Diagnostic: scan canonical block bodies for transactions whose `to` (or sender, via recovered address) involves a target address. Used to locate the block/op that creates a given account in rskj but not rustock. |
| [`scan_edges`](../crates/cli/examples/scan_edges.rs) | Where on this chain is RSKIP-144 parallel execution actually *used*? |
| [`uncle_rpc_check`](../crates/cli/examples/uncle_rpc_check.rs) | Renders `eth_getUncleByBlockHashAndIndex` against the real mainnet store, read-only, alongside the running node. |
| [`dump_canonical_receipts`](../crates/cli/examples/dump_canonical_receipts.rs) | Decode the canonical TransactionReceipts for a block from the snapshot receipts DB and print each receipt's fields (postTxState, cumulativeGas, gasUsed, status, bloom, #logs). Receipts DB is keyed by txHash -> RLP[ TransactionInfo[ [receiptRLP, blockHash, index], ... ] ]. |

## State and trie

| tool | what it answers |
|---|---|
| [`dump_state`](../crates/cli/examples/dump_state.rs) | Diagnostic: dump every leaf (key=value) of rustock's persisted unitrie at the executed head. Used to diff against rskj's unitrie for the same block to localize receipts-invisible state divergences. |
| [`diff_state`](../crates/cli/examples/diff_state.rs) | Localize a post-wasabi state-root divergence to the exact diverging trie leaves. Replays canonical blocks from the executed head up to `<number>` in memory (computing rustock's — possibly wrong — post-state trie), then diffs it against rskj's own unitrie for the *header's* state root, read directly from rskj's LevelDB. The dual walk descends only where the two tries' subtree hashes differ, so it visits a handful of nodes and finishes instantly even on a multi-million-leaf state. |
| [`diff_roots`](../crates/cli/examples/diff_roots.rs) | Diff two unitrie roots that live in two different stores. |
| [`diff_self`](../crates/cli/examples/diff_self.rs) | Diagnostic: show the unitrie leaf delta produced by executing a single block. Replays from the executed head to <number>-1 (the base), then executes <number> and hash-prune-diffs the two rustock-computed tries. Prints only the leaves that changed — the exact state delta of <number>. No rskj DB needed (both sides are rustock-computed); use when rskj isn't synced past the target. |
| [`trie_footprint`](../crates/cli/examples/trie_footprint.rs) | Measure the trie working set of a range of blocks. |
| [`trie_window`](../crates/cli/examples/trie_window.rs) | Measure the miss rate of a sliding-window trie cache against window length. |
| [`lsm_stats`](../crates/cli/examples/lsm_stats.rs) | LSM shape and table properties of a trie store: level layout, and whether the SSTs carry bloom filters at all. |
| [`detach_trie`](../crates/cli/examples/detach_trie.rs) **(writes)** | Copies the `trie_nodes` column family out of a node database into a standalone trie database. |
| [`drop_trie_cf`](../crates/cli/examples/drop_trie_cf.rs) **(writes)** | Drops the `trie_nodes` column family from a node database. |
| [`flatdb_convert`](../crates/cli/examples/flatdb_convert.rs) **(writes)** | Copy a RocksDB trie store into a FlatDB one, node for node. |
| [`flatdb_migrate`](../crates/cli/examples/flatdb_migrate.rs) **(writes)** | Move an epoch store from RocksDB to FlatDB, in place, node stopped. |
| [`flatdb_stats`](../crates/cli/examples/flatdb_stats.rs) | What a FlatDB store actually holds: record sizes, and how many cross the threshold that decides whether a key is stored or recomputed. |
| [`synthetic_state`](../crates/cli/examples/synthetic_state.rs) **(writes)** | Build a synthetic world state of a chosen size, so that execution benchmarks start from a trie like a real one. |
| [`pre_unitrie_roots`](../crates/cli/examples/pre_unitrie_roots.rs) | Replay the pre-RSKIP126 era from genesis, recording the Unitrie root each block computes, and optionally validating it against the header. |

## Snapshot sync and segments

| tool | what it answers |
|---|---|
| [`build_segments`](../crates/cli/examples/build_segments.rs) **(writes)** | Replay a block range, verifying every state root, and build the range's trie segments as a by-product. |
| [`audit_chunk`](../crates/cli/examples/audit_chunk.rs) | What does a segment chunk NOT contain that a consumer needs? |
| [`patch_size`](../crates/cli/examples/patch_size.rs) | How many nodes would it take to make a chunk answer the lookups it cannot? |
| [`repair_chunk`](../crates/cli/examples/repair_chunk.rs) **(writes)** | Make a segment chunk answer the lookups a foreign client issues. |
| [`probe_seed`](../crates/cli/examples/probe_seed.rs) | Is each segment chunk missing the parent state root of its own first block? |
| [`snap_serve_check`](../crates/cli/examples/snap_serve_check.rs) | Does snapshot sync work on the real trie? |
| [`pin_cost`](../crates/cli/examples/pin_cost.rs) | What does pinning the snapshot checkpoint cost the collector? |

## Recovery and surgery

| tool | what it answers |
|---|---|
| [`reset_exec_head`](../crates/cli/examples/reset_exec_head.rs) **(writes)** | Reset execution to genesis WITHOUT discarding downloaded blocks. |
| [`set_exec_head`](../crates/cli/examples/set_exec_head.rs) **(writes)** | Rewinds (or advances) the executed head to a chosen canonical block. |
| [`rewind_to`](../crates/cli/examples/rewind_to.rs) **(writes)** | Rewind the download + executed head to a clean block and drop the canonical pointers above it, so the node re-downloads and re-executes the tail cleanly. |
| [`resume_point`](../crates/cli/examples/resume_point.rs) | Where would execution resume? A read-only diagnostic. |
| [`replay_block`](../crates/cli/examples/replay_block.rs) | Re-execute canonical blocks from the executed head up to a target block (in memory, nothing persisted) and report the target's per-transaction results, logs, and computed state/receipts roots vs the header. Deterministic, offline diagnostic for gas/state/receipts divergences. |
| [`verify_range`](../crates/cli/examples/verify_range.rs) | Verify a range of blocks against rskj's own state, reporting every divergence rather than stopping at the first. |

## rskj interoperability

| tool | what it answers |
|---|---|
| [`rskj_blocks_probe`](../crates/cli/examples/rskj_blocks_probe.rs) | Probe: can RocksDB open rskj's `blocks` LevelDB, and how far does it reach? |
| [`rskj_root_probe`](../crates/cli/examples/rskj_root_probe.rs) | Does this rskj database still hold the state for a given block? |
| [`rskj_state_roots`](../crates/cli/examples/rskj_state_roots.rs) | Look up rskj's `stateRoots` translation table. |
| [`dump_rskj_unitrie`](../crates/cli/examples/dump_rskj_unitrie.rs) | Dump every leaf of an rskj unitrie directly from its LevelDB, given a root hash. Post-RSKIP126 (wasabi100, #1,591,000) a header's `state_root` IS the unitrie root, so this lets us oracle-diff any post-wasabi block's state from Rust (no Java). rskj's unitrie LevelDB is content-addressed: nodeHash -> node message bytes, the same scheme rustock uses. |

## Benchmarks and measurement

| tool | what it answers |
|---|---|
| [`replay_bench`](../crates/cli/examples/replay_bench.rs) | Replay a block range against one trie store and report throughput. |
| [`read_bench`](../crates/cli/examples/read_bench.rs) | Isolates read cost: one lookup in a large store versus N lookups across small ones. |
| [`batch_read_bench`](../crates/cli/examples/batch_read_bench.rs) | What a batched read buys, measured on the workload that uses one. |
| [`loadtest`](../crates/cli/examples/loadtest.rs) | Measure block execution against a realistic trie, at a chosen number of threads. |
| [`gc_bench`](../crates/cli/examples/gc_bench.rs) | Synthetic trie-churn benchmark for the epoch garbage collector. |
| [`header_verify_bench`](../crates/cli/examples/header_verify_bench.rs) | How fast can this node verify headers under the full consensus rules? |
| [`btc_cache_bench`](../crates/cli/examples/btc_cache_bench.rs) | Measure BTC main-chain block retrieval with and without the block cache, against a real database. |
| [`canonical_index_cost`](../crates/cli/examples/canonical_index_cost.rs) | What the canonical `number -> hash` index costs. |
| [`validation_cost`](../crates/cli/examples/validation_cost.rs) | What a real block costs *outside* execution. |
| [`parallel_workload`](../crates/cli/examples/parallel_workload.rs) | Generate a block workload with a known collision structure, mine it, and report how the RSKIP-144 miner partitioned it. |

## Configuration

| tool | what it answers |
|---|---|
| [`check_alerts_config`](../crates/cli/examples/check_alerts_config.rs) | Validate a peg-out alert configuration without starting a node or sending mail: parse it, resolve `${NAME}` references against the env file, and report what would happen. Secrets are never printed — only whether they resolved and how long they are. |

## The PowPeg signature audit, in more detail

Two of these were written together to answer "did a PowPeg functionary ever
submit an invalid signature", and they are worth a paragraph because the
answer is not where you would first look for it.

**There is no invalid-signature event.** `addSignature` verifies each
signature against its input's sighash and, on the first that does not
verify, returns without applying anything: the call succeeds, spends its
gas, changes no state and logs nothing. A malformed DER signature reverts; a
well-formed signature over the wrong message is silent.
`a_member_signature_over_the_wrong_sighash_is_not_applied` in
`crates/execution/src/bridge/peg.rs` pins that.

What is observable is `add_signature`, and RSKIP326 (fingerroot500, mainnet
#5,468,000) changed when it fires: from there, only once a signature has
actually been applied. Below that height it fires *before* verification and
cannot distinguish a good signature from a bad one.

So:

1. **`federation_intervals <data-dir> [out.json]`** builds the ad-hoc
   database of which functionary keys could sign over which heights, from
   the sixteen `commit_federation` events — no state, no execution, which
   matters because a pruning node no longer holds the state those heights
   would need. It checks that every handover's outgoing key set is the set
   committed before it, and refuses to be trusted quietly if one does not
   close.

2. **`powpeg_signature_audit <data-dir> <federations.json> [from] [to] [threads]`**
   scans for the calls: workers take contiguous height ranges and read
   bodies straight from the block store, pairing each call against the event
   index. Two benign causes are excluded — a pegout already released when
   the call arrived, and a federator that had already signed that pegout —
   and whatever survives goes to `powpeg_unexplained.csv`.

   Around 9.4 million blocks in half an hour on eight threads, with a
   progress line every thirty seconds.

Run them in that order; the second needs the first's JSON.

