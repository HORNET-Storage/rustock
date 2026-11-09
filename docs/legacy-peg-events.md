# Peg events for the era the Bridge logged nothing

## The problem

The node answers "when did peg-ins happen" from `bridge_events`, an index
built from receipts. That index is complete for what the Bridge *logged*, and
the Bridge did not always log.

| event | arrives | mainnet height |
|---|---|---|
| `release_btc`, `update_collections`, `add_signature`, `commit_federation` | genesis, legacy RLP format | 1 |
| `lock_btc`, `release_requested` | RSKIP146, papyrus200 | 2,392,700 |
| `pegin_btc` | RSKIP170 | papyrus200+ |
| `rejected_pegin`, `unrefundable_pegin` | RSKIP181, iris300 | 3,614,800 |

So the peg-out *execution* has always been visible — `release_btc` was there
from the start. What is missing before papyrus200 is every **peg-in**, and
every **peg-out request**; and before iris300, every **rejection**.

A `bridge_events` scan over that era returns nothing. The failure mode is that
nothing distinguishes it from nothing having happened.

## What was built

A standalone store of reconstructed events, written by a replay, in the same
layout as the real index.

```text
  key   = topic0 (32) || block (8 BE) || tx_index (4 BE) || log_index (4 BE)
  value = tx_hash (32) || n_topics (1) || topics (n*32) || data
```

Identical by design: one decoder reads both, a topic scan is a prefix scan in
either, and concatenating the two and sorting by `(block, tx_index,
log_index)` gives a complete history. Nothing is reconstructed for a height
where the Bridge really logged, so the union never double-counts.

Pieces:

- [`crates/storage/src/legacy_event_store.rs`](../crates/storage/src/legacy_event_store.rs)
  — the store, its coverage table, and `covers()`.
- [`crates/execution/src/bridge/legacy_events.rs`](../crates/execution/src/bridge/legacy_events.rs)
  — turns a recorded decision into the log entry the Bridge would emit. Lives
  beside the real encoders and shares their helpers; its tests assert the
  bytes are identical to what `events::log_*` produces.
- `verify_range --record-legacy-events DIR` — writes it during a replay.
- [`legacy_events`](../crates/cli/examples/legacy_events.rs) — reads it, and
  with `--with-index` merges it with the node's real index.

### Why a separate database

Two reasons; the second decides it.

These events are **derived, not observed**. They are in no receipt. Folding
them into the node's own index would make that index assert something about
the chain that is not true of it.

And **the node holds its database's write lock while it runs**. Building this
takes a replay of millions of blocks. Requiring the node be stopped for that
would make it unbuildable in practice. A separate store is written while the
node serves traffic, and can be read — including by `legacy_events` — while it
is still being extended.

### Which event is reconstructed

The **modern** one, not the one that era would have emitted. A peg-in credited
at #300,000 is reconstructed as `pegin_btc`, though `pegin_btc` postdates it
and `lock_btc` came first. The point is a single query that spans all of
history, and that needs one topic per concept. To see what was *actually*
logged, read the real index — that is precisely what it records.

A refunded peg-in becomes two events, as the modern Bridge emits it:
`rejected_pegin` and `release_requested`.

A decision that cannot be encoded faithfully — an unrecognised reason code, a
missing field — produces **nothing**, and is counted as `skipped` in the
coverage record. An invented reason code would be worse than no event: it
would be indistinguishable from a real one, and wrong.

## Two questions this answered along the way

**Was Flyover active in the legacy era?** No. Flyover is RSKIP176, which
activates at iris300 (#3,614,800) — after the whole era. So there are no
always-internal Flyover peg-ins to miss, and narrowing by top-level calls does
not lose them.

**Do peg-outs need execution to find?** Not to *find* the candidates.
`releaseBtc` rejects any call at depth > 1 — a BTC address cannot be derived
from a contract — and pre-RSKIP185 such a call throws `OutOfGas` with no event
and no refund ([`peg.rs`](../crates/execution/src/bridge/peg.rs), the
`call_depth > 1` branch). So a peg-out is always a top-level transaction to
the Bridge, and bodies alone enumerate every candidate block.

Peg-**ins** are the asymmetric case: `registerBtcTransaction` is
`TransactionCallable` with no `isContractTx` restriction, so a contract may
call it, and such a call exists only as an internal transaction. Finding those
requires execution.

## Building it

A contiguous replay from genesis, carrying state forward, needs no historical
state source at all:

```sh
verify_range /var/lib/rustock /mnt/import/rustock-trie 1 2392699 \
    --network-id 30 --sequential --seed-genesis \
    --state-roots /mnt/import/paseo/rskj-stateRoots \
    --scratch <scratch-dir> \
    --record-legacy-events <store-dir> \
    --max-failures 0
```

`--state-roots` is not optional below #1,591,000 — see the coverage section.
Above it the headers carry real unitrie roots and the check is exact without
the table.

Notes, each of which costs something if ignored:

- **`--max-failures 0`.** The default stops after ten; a long pre-wasabi100
  run will exceed that on inconclusive blocks alone (see below) and stop
  early.
- **Scratch grows with the state**, roughly 2.8 KB/block over the early chain.
  Budget ~7 GB for the full era, on `/mnt/import`, not `/tmp`.
- **`TMPDIR=/mnt/import/paseo/tmp`.** `/tmp` is a 3.8 GB tmpfs.
- Progress goes to stderr every 1,000 blocks; redirect it to a file.
- Both `--record-silent` and `--record-legacy-events` ride on the same
  drained decisions, so asking for both costs one replay rather than two.

## The coverage limit, and it is a real one

Below wasabi100 (#1,591,000) a header's `stateRoot` is an **orchid** root. It
is not a unitrie node hash, so it cannot be compared against what the replay
computes. `verify_range` has two ways out, and they are not equally good:

- rskj's `stateRoots` translation table gives the unitrie root holding the
  state that orchid root named. Comparing like with like, exact. A copy lives
  at **`/mnt/import/paseo/rskj-stateRoots/`**; read the
  `rskj-stateRoots-DO-NOT-DELETE.md` beside it before touching it. It is not
  regenerable from anything on this machine.
- Converting our unitrie into an orchid root. A mismatch cannot be told apart
  from a limit of the conversion, so such a block is declared *inconclusive*
  and its decisions are dropped rather than recorded.

That conservatism is correct — a store that mixed corroborated and
uncorroborated decisions would be untrustworthy exactly where it matters —
but it bites hardest here, because the orchid check is run precisely on the
blocks that decided something. Observed at #6,916, a real peg-in: the orchid
conversion did not reproduce the header root, so that peg-in is **not** in the
store. #13,191 passed and is.

Consequently the coverage record carries `blocks` and `verified` separately.
Most pre-wasabi100 blocks are executed and carried forward with **no root
comparison at all**; their events are reconstructed from an execution nothing
corroborated, and `verified` is how a reader sees that. Above #1,591,000 the
roots are real unitrie roots and the check is exact.

Pass `--state-roots /mnt/import/paseo/rskj-stateRoots` and the check becomes
exact for the whole era: a pre-wasabi block is verified by comparing **rskj's
own unitrie root for that block against ours**, one lookup, no orchid trie
reconstructed. A previous run with the table verified all 129 pre-papyrus200
peg-in blocks with 0 diverged, against 34 of 129 without it.

The table is complete and frozen — orchid roots only exist below #1,591,000,
so nothing is added after the migration, and any full-sync snapshot taken
after 2019-07-31 carries the whole thing. A **snap-synced** node never builds
it at all.

Without it, do not build the pre-wasabi100 half. The blocks that decided
something are precisely the ones the orchid fallback drops, so the result
would be a store that is confidently incomplete.

## Reading it

```sh
legacy_events <store-dir> --coverage      # what has been built, and how checked
legacy_events <store-dir> --topics        # what is in it, by event

# one event, merged with the node's real index into a single history
legacy_events <store-dir> 'pegin_btc(address,bytes32,int256,int256)' \
    --with-index /var/lib/rustock
```

Rows are tagged `real` or `recon`, so the distinction survives the merge. A
scan whose range is not wholly covered prints a warning saying so: an absent
event may mean the range was never reconstructed, not that nothing happened.
`--coverage` is the way to tell.
