# Large value transfers in and out of smart contracts

Alerts when rBTC above a threshold moves with a smart contract on either side
of it — an account paying a contract, or a contract paying anyone. Off unless
configured.

```toml
[alerts.contract_value]
enabled = true
transfer_alert_btc = 50.0
replay_filter_btc = 0.1
max_catchup_blocks = 128
```

The threshold is deliberately **not** the peg-out threshold. A peg-out is the
federation moving bitcoin; a contract payment is a different event at a
different scale, and tying them together would mean one of the two is always
set wrong.

Delivery is shared with every other alert in
[`alerts.example.toml`](../alerts.example.toml): the same `[alerts.email]`
transport, the same log sink, one credential.

## This is the one watch that re-executes the block

Every other alert here is a read. A peg-out announces itself with an event, so
the watcher reads receipts. A value transfer announces nothing: moving rBTC
emits no log, writes no receipt field, and leaves behind nothing but two
changed balances.

So a contract paying out **cannot be seen from stored data at all**. The only
way to find one is to run the block again with the call tracer attached — the
same `BlockProcessor::trace_block_calls` that `trace_block` uses — and read
the call tree.

Measured on mainnet, a replay costs **24 ms at the median**, 57 ms at p90,
and 467 ms at the worst block in a 40-block sample. The replay is still an
observer: it is handed a trie node, writes nothing, and runs on the watcher's
own blocking thread, so it cannot change what the node computes or slow block
processing. It consumes CPU, and that is the only thing it consumes.

Empty blocks would be free, but **do not count on that** — over 300
consecutive mainnet blocks sampled in November 2026, every single one had at
least one transaction.

Which is why the replay does not run on every block.

## The filter: what the node already knows

The supply check walks every account a block wrote and records `before` and
`after` for each, on every block, as part of ordinary execution. It exists to
catch rBTC appearing from nothing. The largest of those deltas is also a free,
already-computed answer to *"could anything here be worth looking at"* — so
execution reports it, [`movement::MovementLog`](../crates/alerts/src/movement.rs)
remembers it keyed by block hash, and the watcher replays only blocks where
something moved more than `replay_filter_btc`.

The saving is not marginal. Over those same 300 blocks:

| filter | blocks re-executed |
|---|---|
| none (every block with a transaction) | 300 / 300 |
| 1 RBTC | 1 / 300 |
| 5 RBTC and above | 0 / 300 |

The largest single transfer in any of those blocks was 2.0 RBTC; the median
was zero.

### What the filter gives up

A balance delta is a **net** figure. A transfer is missed only when every
account in the block nets out below the filter — which means the value came
back to where it started inside the same block.

**Pass-through is not that case and is not missed.** A router that receives
100 and forwards 100 nets to zero, but the originator is still −100 and the
final recipient +100, so the block is replayed and every hop reported.
Intermediaries are safe.

**A closed cycle is missed** — most realistically a flash loan, where a pool
lends and is repaid inside one transaction and only the borrower's profit
nets out. This is the reason `replay_filter_btc` is its own setting and
defaults far below `transfer_alert_btc`: at 0.1 RBTC a cycle has to leave
every account within 0.1 RBTC of where it started, which is to say nobody
profited. A value at or above `transfer_alert_btc` is **refused**, because
then the filter — not the alert threshold — would be the real threshold.

Setting it to `0` replays every block: the behaviour before the filter
existed, kept reachable as the control for measuring what the filter saves.

### When there is no record

A block this node imported rather than executed has no entry, and neither
does one executed before the observer was installed. **That is replayed, not
skipped.** Treating "nobody looked" as "nothing happened" is the one failure
that would make this watch quietly useless, so the safe answer is the default
and the range is logged at `info`.

The log is keyed by **block hash**, not number: a block that was executed and
then orphaned shares its number with the canonical block at that height, and
keyed by number the orphan's deltas could answer for the wrong block.

### The one thing this changes about the crate

`rustock-alerts` otherwise has no hook in execution at all. The supply and
multisig observers bend that already, but they fire only on violations; this
one is consulted on every block. What it costs on the execution path is a
`max()` over a vector that was built anyway, one header hash, and one mutex
insert — and it is skipped entirely unless an observer is installed.

## Reorgs

The sweep advances by height and never walks backwards, so on its own it
would examine a height once and move on. That is wrong on this chain: RSK
reorgs constantly — at nearly every height on this node — and a block that
stops being canonical *after* it was examined would never be replaced by the
block that took its place.

This is not a hypothetical. On 2026-11-07 two of seven Flyover peg-outs went
unreported for exactly that reason: the watcher looked at #9390291 and
#9390496 while a different block was canonical at each height, and never
looked again.

So before advancing, every sweep re-checks the last **128 heights** and
re-examines any whose canonical hash has changed. The check is one
canonical-hash lookup per height per poll; the expensive part — re-executing
the block — happens only for a height that actually moved.

Deduplication makes re-examination safe. An alert's key is the transaction
hash plus its position in the call tree, and neither mentions a block, so a
transfer that survived the reorg into the replacement is not reported twice.
Anything genuinely new in the replacement is reported, which is the point.

### Withdrawals

The converse also matters. If a block produced an alert and the block that
replaced it does not contain that transfer, the alert described something
that did not happen. Mail cannot be unsent, so the log says so:

```
WARN WITHDRAWN: an alert reported from #9390291 is not in the block that
     replaced it, so it describes a transfer that did not happen: <key>
```

A monitor that reports a theft that never occurred and never corrects itself
is worse than one that is slightly late.

### What this does not cover

A reorg deeper than 128 blocks, or one that lands on a height the watcher has
already forgotten. Nothing seen on this chain comes close, and the peg-out
watch shares the same protection since both run from the same sweep.

## Falling behind

`max_catchup_blocks` bounds the damage when the watcher falls behind. A node
stopped for a day comes back with thousands of blocks to sweep, none of them
carrying a movement record, so without this they would all be replayed.
Blocks further back than the window are still swept for peg-outs, which is
cheap, and the skipped range is logged — a gap in this watch is never
silent.

## What counts as a transfer

| source | moves value | reported as |
|---|---|---|
| the transaction itself | `tx.value`, to `tx.to` or to the contract it creates | `transaction` |
| `CALL` | yes | `call` |
| `CALLCODE` | **no** — the value is apparent; the frame pays itself | — |
| `DELEGATECALL` | **no** — value is inherited, nothing moves | — |
| `STATICCALL` | **no** — value is always zero | — |
| `CREATE` / `CREATE2` | the endowment, to the new contract | `create` |
| `SELFDESTRUCT` | the dying contract's whole balance, to the beneficiary | `selfdestruct` |

The three excluded call kinds are the easiest thing here to get wrong. A
`DELEGATECALL` carries a non-zero `value` in the trace — the caller's apparent
value, which the callee sees through `CALLVALUE` — and reporting it would
invent a transfer that never happened.

### Reverted frames moved nothing

A frame that reverted or halted is undone, **and so is everything beneath it**.
The walk skips a reverted frame's whole subtree rather than just the frame, and
a failed transaction contributes nothing at all — not even its own top-level
`tx.value`, which reverts with the rest.

### A frame paying itself is not a movement

`SELFDESTRUCT` to self burns the balance rather than transferring it, and
self-sends net to zero. Both are dropped.

## Which side has to be a contract

The rule is one line: **alert when the amount is above the threshold and at
least one side has code.** That covers both halves of the requirement at once,
because of an asymmetry worth naming:

- A **transaction's** sender is an externally owned account, so the
  transaction case reduces to "the recipient is a contract".
- An **internal** transfer's sender is a contract in every case, because only
  running code can originate a `CALL`, a `CREATE` or a `SELFDESTRUCT`. Every
  internal transfer above the threshold therefore qualifies with no lookup at
  all.

A large transfer between two plain accounts is not reported. It is real, and
it is not what this watch is for.

### Which state answers "is this a contract"

The state **after** the block, not before it.

A transaction that creates a contract and funds it in the same breath is
exactly the case this watch exists for, and the created account only has code
in the post-state. Classifying against the parent would miss it.

The cost of that choice is narrow: a contract that self-destructs in the same
block has no code afterwards. Its *outgoing* transfer is still caught — a
`SELFDESTRUCT` frame names a contract by construction and needs no lookup —
but an incoming one in an earlier transaction of the same block is not. If the
post-state is unavailable, the watcher falls back to the parent state and says
so at `debug`.

Lookups are memoised per block and happen only for transfers already above the
threshold, so in practice there are very few.

## What an alert looks like

```
Subject: Large transfer out of a contract: 120.00000000 RBTC at block #9380912

A value transfer out of a contract is above the configured threshold.

  RSK block      #9380912
  transaction    0x4f2c…
  from           0x5f8a…
  to             0x9b31…
  amount         120.00000000 RBTC
  threshold      50.00000000 RBTC
  exact amount   120000000000000000000 wei
  moved by       call

This is an internal transfer, at call-tree position 0.2.

The transfer succeeded: frames that reverted, and everything beneath them, are
excluded, so this is value that actually moved. To see it in context:

  trace_transaction("0x4f2c…")
```

Everything is also logged at `warn` on target `rustock::alerts::pegout`, so the
record exists whether or not mail is configured or reachable.

## Tuning it against a running node

`transfer_alert_btc`, `replay_filter_btc` and `max_catchup_blocks` are
re-read when the configuration file's modification time changes, like the
peg-out thresholds.
`enabled` is not: whether this watch runs decides whether the watcher built a
block processor at startup, so turning it on needs a restart. The log says so
rather than applying half of an edit.

## Checking the configuration without starting a node

```
cargo run --release --features smtp --example check_alerts_config /etc/rustock/alerts.toml
```

Prints the threshold in both RBTC and wei, the catch-up window, and whether the
mail credentials resolved — never their values, and it sends nothing.
