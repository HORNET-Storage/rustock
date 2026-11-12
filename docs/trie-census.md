# Weekly unitrie census

A snapshot of what the state contains at one block — accounts, contracts,
storage cells, code sizes — as a JSON file meant to be consumed by something
other than a human.

Read-only. It takes no lock on the node's database, writes nothing but its
JSON, and is safe to run against the live node.

## Running it

```sh
cd /srv/rustock
cargo build --release -p rustock-cli --example trie_census

nice -n 19 ionice -c3 ./target/release/examples/trie_census \
    /var/lib/rustock /var/lib/rustock/trie-epochs-flat head-20 \
    --threads 2 \
    --json /mnt/import/paseo/metrics/trie-census-$(date -u +%Y%m%d).json
```

That is the whole procedure. Nothing to set up, nothing to clean up.

| argument | why |
|---|---|
| `head-20` | a settled height. The head itself can still be reorganised, and a census of a block that later vanishes is worse than no census. |
| `--threads 2` | leaves the node room. The box has 4 cores; use 3 if nothing else is running, 2 if something is. |
| `nice -n 19 ionice -c3` | the node wins every scheduling contest. The scan takes about a minute, but a minute of contention is still contention. |
| `--json` | without it the tool prints a human summary and nothing else. |

**Takes about 60–90 seconds** for the full mainnet trie — ~12.6M nodes at
roughly 200,000 nodes/s on two threads.

Progress goes to **stderr**, the JSON to the file. So `2>/dev/null` gives a
silent run, and nothing a consumer parses is ever mixed with progress output.

### Exit behaviour

Non-zero exit means no usable output. Two failures are worth distinguishing:

- *"state for #N is not in this trie store"* — an epoch node keeps a window
  of recent state, so a height that has aged out needs an archival store.
  Use a more recent `head-N`.
- *"trie is incomplete: a node is missing"* — the walk reached a reference
  the store could not resolve. The scan is abandoned rather than reported
  partial, because a partial census that looks complete is the failure mode
  worth avoiding. `"complete": true` in the JSON is only ever written after a
  full walk.

## The JSON

One flat object. `schemaVersion` is bumped if a field changes meaning, so a
consumer can detect it rather than silently misread.

```json
{
  "schemaVersion": 1,
  "generatedAtUnix": 1794256243,
  "block": 9398198,
  "blockHash": "0x855d8f…",
  "stateRoot": "0x071a9d…",
  "trieBytes": 925250773,
  "scan":    { "nodes": 12587626, "valuedNodes": 6337758,
               "threads": 2, "seconds": 62.5,
               "nodesPerSecond": 201451, "complete": true },
  "accounts":{ "total": 558456, "contracts": 24715,
               "externallyOwned": 533741,
               "withNonZeroBalance": 108847, "withNonZeroNonce": 142472 },
  "code":    { "leaves": 24715, "totalBytes": 90994417,
               "meanBytes": 3681.7, "maxBytes": 24573,
               "storedOutOfLine": 24528 },
  "storage": { "roots": 24868, "cells": 5729719,
               "valueBytes": 113959172, "cellsPerContract": 231.8 },
  "balanceTotalWei": "21000000000000000000000000",
  "integrity": { "unrecognisedKeys": 0, "undecodableAccounts": 0 }
}
```

### What the fields mean, where it is not obvious

**`accounts.contracts`** is accounts that have a *code leaf*. That is the only
honest definition available from the trie alone: `state_flags` does not mark a
contract, and a balance says nothing about whether an account has code.

**`storage.roots` exceeds `accounts.contracts`** — 24,868 against 24,715 in
the run above. The extra are the `setupContract` storage-prefix markers of
accounts that have storage but no code. Expect a small positive difference;
a large one is worth looking into.

**`code.storedOutOfLine`** counts code leaves whose value exceeds 32 bytes and
therefore lives outside the node. `totalBytes` is correct either way: sizes
come from `value_length()`, which covers inline and long values alike, so no
code body is fetched to measure it.

**`balanceTotalWei` is an invariant, not a measurement.** RSK mints nothing:
genesis hands the Bridge the whole 21,000,000 RBTC and every later balance is
a slice of that one premine. It must read exactly
`21000000000000000000000000` at every height. Anything else is a node bug or
a corrupt state — not a finding about the peg. It is emitted precisely so a
weekly consumer can assert it.

**`integrity` must be zeroes.** A non-zero `unrecognisedKeys` or
`undecodableAccounts` means leaves were skipped, so every count above it is an
undercount. Treat the file as void.

### Assertions worth making weekly

```
scan.complete == true
integrity.unrecognisedKeys == 0
integrity.undecodableAccounts == 0
balanceTotalWei == "21000000000000000000000000"
accounts.contracts + accounts.externallyOwned == accounts.total
```

All five are cheap, and each catches a different way the file could be wrong
while looking right.

## Why not `--trie-tool`

`storage::trie_tool` answers a similar question with a recursive
single-threaded descent, and reports more about node sharing. It is the wrong
instrument for a recurring census: `trie-scan-baseline.md` records it decaying
3.5x over a run, to 763 nodes/s, and being abandoned at 49.29% after 1h52m.

The decay is inherent to the shape, not the code. A trie descent issues
*dependent* random reads — the next read's address comes from the last read's
result — so the device sees one request outstanding at a time, and the page
cache stops helping once the working set outgrows it.

`trie_census` sidesteps it by splitting before walking. Every node commits
`children_size`, so a subtree's byte weight is known without reading it: take
the largest piece, split it, repeat, until the largest is a small fraction of
a worker's share. Workers then take pieces from a shared counter rather than
being dealt them up front, so an uneven split costs nothing. That same
committed size is what makes the progress percentage honest — bytes genuinely
accounted for, not nodes extrapolated.

Result: ~200,000 nodes/s against 763, and a complete scan in a minute rather
than an abandoned one in two hours.
