# A purely flat state store: what it would take

> Written in answer to "what would it take to implement a purely flat
> database that keeps only the last entry for each unitrie key, and
> backtrack/redo it on reorgs — is this simple?". Nothing here has been
> implemented. It is a design note, kept so the question does not have to be
> re-derived from scratch.

The idea: instead of storing the trie as content-addressed nodes
(`key = keccak(value)`, which is what [`flatdb.md`](flatdb.md) describes),
store `unitrie key → current value` directly, one entry per key, overwritten
in place. Reorgs are handled by an undo log: reverse diffs per block, applied
backwards to the common ancestor and then forward again.

**Short answer: it is two problems, and only one of them is simple.** The
flat store and the undo log are the easy half. The state root is the hard
half, and it is what makes "purely flat" not quite reachable.

---

## 1. Why purely flat cannot stand alone

Every RSK block header commits to the unitrie root, and the node must compute
it for each block and compare. A store keyed by unitrie *key* holds no trie
nodes, so producing the root means rebuilding the whole trie — 9,300,000
nodes in the synthetic fixture
([`execution-performance.md`](execution-performance.md) §"The state"), more on
mainnet. Per block, that is out of the question.

So an intermediate-hash layer is unavoidable: hashes for interior nodes,
recomputing only the paths a block touched, with leaves read from the flat
state. That is erigon's design, and it works — but at that point the trie's
interior is still being stored, just not its leaves. The honest name for the
result is **flat leaves with a derived interior**, not "purely flat".

---

## 2. Where the time actually is, which redirects the idea

The reason to want this is speed, so it is worth being precise about what is
slow. After the `Arc` fix, on four threads with FlatDB and the access list
prefetched, a block divides roughly as:

| phase | time |
|---|---|
| sublist execution | 39 ms |
| **commit — writing the trie** | **39 ms** |
| root hashing | 6 ms |
| lazy reload | 1 ms |

Source: [`execution-performance.md`](execution-performance.md) §"What is
left".

**Reads are largely dealt with already.** The access list prefetch was worth
2.51× and FlatDB 3.12×. What remains is the commit, now as large as execution
itself — and that *is* what a flat layout attacks. Instead of rewriting a
~23-level spine per touched account (about 6,900 nodes a block), you write one
entry per touched leaf, a few hundred.

But maintaining intermediate hashes gives much of that back: you still touch
~23 levels per account, writing 32-byte hashes rather than whole node
messages. Expect a solid constant-factor cut in the commit, not an order of
magnitude.

---

## 3. What is genuinely simple

The undo log and the reorg machinery. The pieces are already here:

- `exec_head` as a persisted pointer
- `ExecutionCommitter`, and the flush-then-advance discipline
- `roll_execution_back` and `reconcile_exec_head_with_canonical`
- `MAX_ROLLBACK = 1_024` (`crates/sync/src/rollback.rs:49`), which sets the
  depth the undo log must cover

Reverse diffs per block, applied backwards then forward, is a well-trodden
pattern. The one discipline that matters: the undo entries must be written in
the *same* batch as the state they undo, or a crash between the two leaves a
store that cannot be rolled back correctly.

Days of work, not weeks.

---

## 4. What would be given up

This is a product decision rather than an engineering one, and it is the part
most easily overlooked.

Content addressing gives historical state **for free**: old roots stay
reachable because nodes are immutable and never overwritten. A flat store with
an undo log reaches back only as far as the log. That affects:

| | today | with flat state |
|---|---|---|
| snapshot server | serves state at head − 10,000 | needs the log to reach that far |
| `epoch` backend window | state present at 10,000 and 60,000 blocks back, gone by 70,000 ([`follow-mode-rskj-vs-rustock.md`](follow-mode-rskj-vs-rustock.md) §5) | bounded by the log |
| `eth_getProof` | walks stored nodes | needs the intermediate-hash layer |
| `debug_trace*` at depth, archive queries | free | bounded by the log |

An undo log deep enough to replace a 60,000-block window is not an undo log
any more; it is a differently-shaped archive.

---

## 5. Recommendation

Not this first. Two cheaper things attack the same 39 ms:

1. **The parallel-commit overhead.** The commit costs **26 ms more on four
   sublists than on one** — [`execution-performance.md`](execution-performance.md)
   calls it *"an overhead of parallelism rather than a floor under it"*. That
   is most of a 39 ms phase and it is a bug-shaped cost, not an inherent one.

2. **The insertion path, which has never been measured.** Every recipient in
   the benchmark fixture pre-exists, so no run has ever split a trie path or
   deepened the trie. A flat redesign changes insertion economics
   fundamentally; designing against unmeasured ground is how months get spent
   before anyone finds out.

If the commit is still the wall after those, the flat-leaves work has a
measured target instead of an assumed one.

### If it is built anyway

- Behind `--trie-backend flat`, alongside `single`, `external` and `epoch` —
  not replacing them.
- Rough effort: flat store plus undo log, one to two weeks. Intermediate
  hashes, and getting the root bit-identical to the current implementation on
  a full mainnet replay, is the real cost — call it a month with a long soak,
  because every bug in that layer is a consensus bug.
- The acceptance test is not a benchmark. It is a replay from genesis in which
  every block's computed root matches the header, against the existing
  backend, with reorgs exercised.
