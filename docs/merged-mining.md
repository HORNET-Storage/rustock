# Merged mining

Rustock builds RSK blocks, hands them to mining software through the `mnr_*`
JSON-RPC namespace, and completes them from Bitcoin solutions submitted back.
This describes what was built, what was verified against mainnet while building
it, and what is deliberately not there.

It replaces the pre-implementation survey this repository used to carry.

---

## 1. Running it

```
rustock-cli --mine --mining-coinbase 0x<address> [--mining-extra-data <string>]
```

`--mine` serves the namespace; without it the four methods report as unknown,
so a node that is not mining is indistinguishable from one built without the
feature. `--mining-coinbase` is required: mining to the zero address would burn
the reward of every block found, and defaulting to it silently is worse than
refusing to start.

The template is rebuilt every `--mining-refresh-secs` (60 by default), matching
rskj. A template goes stale as the chain advances and as transactions arrive.
Nothing else rebuilds it: the sync service owns the execution loop and does not
know the miner exists, so without that timer a pool would keep being handed work
for a parent the chain left behind and every solution would be refused.

The same settings live in the config file:

```toml
[mining]
enabled = false                    # serve the mnr_* namespace
# coinbase = "0x…"                 # REQUIRED when enabled
extra_data = ""                    # at most 32 bytes
refresh_secs = 60
```

`--mining-extra-data` is capped at 32 bytes by the header rules, and the node
checks at startup rather than letting every block fail validation.

| Method | Sends |
|---|---|
| `mnr_getWork` | — |
| `mnr_submitBitcoinBlock` | the whole Bitcoin block |
| `mnr_submitBitcoinBlockTransactions` | header, coinbase, all transaction hashes |
| `mnr_submitBitcoinBlockPartialMerkle` | header, coinbase, the merkle branch |

The JSON shapes are rskj's, field for field, because the consumers are existing
pool daemons. Two are worth naming because the sensible-looking alternative
breaks them: `feesPaidToMiner` is a **decimal** string, and
`blockImportedResult` is the **hex encoding of an ASCII word** such as
`IMPORTED_BEST`. Both are `crates/rpc/src/mnr.rs`, both are pinned by tests.

---

## 2. How a block is mined

1. The node builds a candidate block and computes its merged-mining hash.
2. From wasabi100, only the first 20 bytes of that hash go in the coinbase; the
   last 12 are replaced with RSKIP110 fork-detection data (§4).
3. A miner puts `RSKBLOCK:` followed by those 32 bytes in a Bitcoin coinbase
   and searches for a Bitcoin block whose hash, read little-endian, is at most
   rskj's target: 2^256 / difficulty, or 2^256 / 3 where the difficulty is 2 or
   less (`difficulty_to_target`). That is **RSK's** difficulty, not Bitcoin's,
   so a solution is usually not a valid Bitcoin block.
4. The solution comes back and fills in the three `bitcoin_merged_mining_*`
   header fields: the 80-byte Bitcoin header, the compressed coinbase, and the
   merkle proof linking the coinbase to the Bitcoin merkle root.

Producing all of this is the inverse of
`crates/core/src/validation/merged_mining.rs`, which already verified it. The
compressor lives in that same file, beside the hash it inverts, so the two
formats are read and changed together. Everything that exists only on the
producing side — fork-detection data, transaction selection, the work cache —
is in `crates/execution/src/mining/` with the rskj class named at each
definition.

---

## 3. What was verified against mainnet

Four things were checked against real chain data rather than reasoned about,
because each would have produced blocks that every peer rejects while looking
locally correct.

**`ummRoot` is present and empty.** rskj writes it from papyrus200 (#2,392,700)
on, and nothing in a block's JSON-RPC representation shows the field exists.
Omitting it changes both the block hash and the merged-mining hash. Pinned by
`mainnet_block_9257552_hashes_and_merged_mining_commitment`, which reconstructs
a real header and reproduces its hash and the 20-byte commitment its coinbase
carries.

**RSKIP351 extension data is not in use.**
`reed810 = -1` in rskj's `main.conf`: the fork never activated on mainnet.
`extension_data: None` is correct, and the fixture above confirms it from the
other direction — the header reproduces its real hash with a plain 256-byte
bloom.

**The fork-detection calculation is exact.** All 12 bytes of block #9,257,552's
fork-detection data were reproduced from its 449 mainchain ancestors: the
7-byte commit-to-parents vector, the uncle count, and the height.

**The REMASC transaction's encoding is rskj's.** Its zero fields are *not*
canonical RLP — gas price and gas limit are a literal `0x00`, the value is
`0x80` — and its nonce is the parent's height, not zero. Re-encoding it
canonically moves the transactions root, and the resulting failure names a root
rather than an encoding. Pinned against the real transaction of that same
block.

Two further questions the survey raised are answered by tests rather than by
mainnet:

- **`paid_fees` is not self-referential.** REMASC reads the *matured*
  block's `paid_fees` from storage, not the block being built, so the zero
  placeholder during execution is harmless and no second pass is needed.
  `filling_paid_fees_does_not_change_what_the_block_executes_to`.
- **Filling the mining fields does not move the merged-mining hash.**
  RSKIP92 keeps the proof and coinbase out of the hashed prefix precisely so a
  solution can attach to a block already committed to.

---

## 4. Fork-detection data

From wasabi100, the 12 bytes after the 20-byte hash prefix are:

| Bytes | Contents |
|---|---|
| 0..7 | commit-to-parents vector: the last byte of the Bitcoin block hash of the last block of each of the seven preceding 64-block windows |
| 7 | uncles included by the last 32 mainchain blocks, saturating at 255 |
| 8..12 | the height being mined, big-endian |

rskj validates these (`ForkDetectionDataRule`), so getting them wrong produces
blocks peers reject with nothing in the block to point at. They need 449
mainchain ancestors; below that rskj produces none and its rule rejects a
header that carries any, so a short chain correctly gets an empty field.

Rustock computes them for the blocks it mines but does **not** validate them on
incoming blocks — that rule was not in the node before this work and is not
added by it.

---

## 5. Uncles, and the index they needed

An uncle is a block that lost: mined on the same parent as one of the recent
ancestors, but not the one the chain kept. Including it pays both its miner and
the includer, and `uncle_count` feeds the difficulty calculation and the uncle
byte of the fork-detection data -- so a wrong list is a consensus fault, not a
missed reward.

Selection is ported from rskj `FamilyUtils`: take the ancestors within
`UNCLE_GENERATION_LIMIT` (7), take every block at those heights whose parent is
the right ancestor, drop the ancestors themselves and anything an ancestor
already included, sort by height then hash, and cap at `UNCLE_LIST_LIMIT` (10).

**Candidates are filtered by parentage, not by height.** A block sitting at a
covered height is not thereby an uncle: it is one only if it is a *direct child
of a block on the chain being mined*. This is what keeps an orphaned fork from
poisoning the list. A fork that diverged at #7 and ran on to #8, #9 and #10
contributes exactly one uncle -- #8, whose parent #7 is on our chain. #9 hangs
off #8 and #10 off #9, so neither is family, and including them would produce a
block every peer rejects (rskj checks the same thing independently in
`validateUncleParent`). A fork that diverged below the window contributes
nothing at all, however many of its blocks sit at covered heights.

The ancestor walk follows `parent_hash` back from the parent being mined on,
not the store's canonical pointers. That is deliberate, and matches rskj:
uncles are then selected relative to the chain actually being extended, which
stays correct mid-reorg when the canonical pointers and the mining parent
disagree.
The sort matters: the index returns hashes in whatever order they sit in the
column family, and two nodes building the same block have to agree on the
ommer hash.

Anything unresolvable yields no uncles rather than a guess. If an ancestor's
header says it carried uncles but its body cannot be read, the node cannot tell
whether a candidate was already used, so it mines without uncles and logs why.

### 5.1 The height index, and upgrading an existing database

Candidates are by definition the blocks the canonical pointer does *not* name,
and `block_numbers` maps a height to the one canonical hash. So they were
unfindable: stored by hash, never thrown away, and impossible to enumerate.

`block_hashes_by_number` fixes that. The key is `number (8 BE) || hash (32)`
with an empty value, so every block at a height is a prefix scan, adding one is
a blind put -- no read-modify-write, no lost update if two writers race, and
re-indexing a block is idempotent. It is written wherever a header is:
`put_header_with_hash` and the batch path sync uses, which is where fork
headers actually arrive.

A database synced before the index existed has none of it, and selection would
silently find nothing forever -- so the miner checks and says so once, and the
index can be built without resyncing:

```
rustock-cli --data-dir <dir> --build-height-index
```

It reads every stored header, decodes its number and writes one small key per
block. It does not touch state, blocks or receipts. Interrupting it is safe:
every entry is derived from the header it indexes, so a partial run resumes
rather than corrupts, and re-running it over a complete index is a no-op. The
node must be stopped, because RocksDB allows a single writer.

One thing the upgrade cannot fix: sync downloads the best chain through the
skeleton, so sibling blocks largely never arrived in the first place. Indexing
an existing database makes the forks it *does* hold findable, but a node that
has only ever followed the tip will have few. Uncles accumulate from that point
on.

## 6. Building the template

The load-bearing hook is that `BlockProcessor::execute_block` executes
**without** checking the header's roots, while `process_block` checks them. A
template is assembled with placeholder roots, executed, and has the real roots
written back from the result:

```rust
let mut header = Header { state_root: B256::ZERO, receipts_root: B256::ZERO,
                          logs_bloom: Bloom::ZERO, /* … */ };
let executed = self.processor.execute_block(&block, &state_root, trie)?;
header.state_root    = executed.state_root_hash;
header.receipts_root = executed.receipts_root;
header.logs_bloom    = executed.logs_bloom;
header.gas_used      = executed.gas_used;
header.paid_fees     = executed.paid_fees;
```

There is no second execution path for mining, so a block this builds is
executed by exactly the code that will later re-execute it on the way in.

### Fields the builder computes

- **`timestamp`** — `max(now, parent.timestamp + 1)`. A header not *strictly*
  after its parent is rejected outright. rskj `MinerClock.calculateTimestampForChild`.
- **`difficulty`** — `DifficultyRule::difficulty_for_child(parent, number,
  timestamp, uncle_count)`, shared with validation deliberately: two copies of a
  consensus calculation will drift.
- **`gas_limit`** — one step toward an optional target, bounded by
  `parent / 1024`; `None` inherits the parent's, which is always valid. rskj
  `GasLimitCalculator`.
- **`minimum_gas_price`** — one step toward an optional target, bounded by 1% of
  the parent's, or one wei when 1% rounds to nothing. rskj
  `MinimumGasPriceCalculator` (RSKIP-09).

Neither target is exposed on the command line, so a running node inherits both
from the parent and they never drift.

### The REMASC transaction

REMASC is an ordinary entry in the transaction list, recognised by shape — the
executor does not append it. A template without it executes to a different state
root, and the failure reads as an execution bug rather than a missing
transaction (`a_template_without_remasc_would_not_validate`).

Its `cached_rlp` is not an optimisation: the zero fields are not canonical RLP
(gas price and gas limit are a literal `0x00`, the value `0x80`) and the nonce is
the parent's height. Re-encoding would move the transactions root. Pinned against
mainnet by `remasc_transaction_matches_mainnet`.

### Transaction selection

Ported from rskj `PendingState.sortByPriceTakingIntoAccountSenderAndNonce`:
cluster by sender, order each cluster by nonce, then merge the clusters by
price, always comparing only each sender's *next* transaction. Ordering purely
by price would interleave a sender's own transactions out of nonce order and
strand all but the first.

A candidate is then skipped if it is below `minimum_gas_price`, if its nonce is
not the one the state expects, or if its gas limit no longer fits — the executor
charges each transaction its own gas limit against the block's, so there is no
partial inclusion and a cheaper transaction may still fit after a large one is
skipped.

Ties break by hash, and the merge order by queue index, because a `HashMap` hands
senders back in whatever order it likes and two nodes building the same template
must agree (`transaction_ordering_is_stable_for_equal_prices`). Senders are
pre-recovered by the pool on admission; otherwise the builder would recover every
sender again on every rebuild, once a minute per pending transaction.

---

## 7. The merkle proof

RSKIP92. The coinbase is always transaction 0, so it is always the **left**
operand at every level, and the proof is nothing but the sibling path bottom-up
— no direction bits, no partial-merkle-tree framing. That is the whole of the
RSKIP: the older format serialized a full Bitcoin partial merkle tree, whose flag
bits and transaction count were redundant for a path known to start at index 0.

Every hash is in **display** order, the reverse of Bitcoin's consensus encoding,
matching bitcoinj's `Sha256Hash`. `parse_wire_hashes` reverses each entry on the
way in, because rskj takes these fields as one space-separated string and
reverses every entry (`Utils.reverseBytes`) — so the wire carries consensus order
and everything past that point is display order.

One builder per submit form (rskj `Rskip92MerkleProofBuilder`):

| From | Function | Note |
|---|---|---|
| A whole Bitcoin block | `proof_from_txids` | Walks the tree, duplicating the final hash on odd levels |
| The block's transaction hashes | `proof_from_tx_hashes` | The same walk |
| An already-computed branch | `proof_from_merkle_hashes` | **Drops `hashes[0]`** |

That last one is the trap: the first hash of a partial merkle branch is the
coinbase itself, and the verifier starts from a coinbase hash it computes. Left
in, it would be folded twice.

Bitcoin's odd-level duplication never affects the coinbase's own sibling — index
1 always exists while a level has more than one node — but it does affect the
hashes computed above it, so the walk has to do it.

---

## 8. Work, submission and import

### The cache, and why it is keyed the way it is

A solution arrives minutes after the work it answers, by which time the node has
usually built several newer templates. Templates are kept in a small cache keyed
by **the merged-mining hash the coinbase commits to** — not the block hash, since
that is what a submission can be matched by. rskj keeps 20
(`MinerServerImpl.CACHE_SIZE`); so does this. Keeping only the newest would make
a miner that was merely a little slow lose a block it had legitimately found.

`take_template` does **not** remove the entry it finds. Two solutions to the same
work is not an error, and the second would otherwise be reported as unknown work
rather than as a duplicate block.

`notify` follows rskj `MinerServerImpl.getNotify`: a new parent always warrants a
push to miners, otherwise only fees above 110% of the last notified figure
(`NOTIFY_FEES_PERCENTAGE_INCREASE = 10`), so a pool is not woken for every
transaction that trickles in. `get_work` clears the flag after it is read once —
it marks the transition, not the work — and the build-then-return path goes
through the same clearing code, or the *second* caller would be told to notify
about work the first already took. That bug is the one the real nonce search
surfaced (§10).

### The submit path

All three RPC forms converge on `complete_and_import`:

1. **Match** — `extract_merged_mining_hash` finds the **last** `RSKBLOCK:` in the
   coinbase and reads the 32 bytes after it. rskj
   `MnrModuleImpl.extractBlockHashForMergedMining`.
2. **Check the parent still stands** — if the executed head has moved off the
   template's parent, refuse with `ParentNoLongerHead`.
3. **Compress the coinbase** — `compress_coinbase`, the same function the
   verifier's format is defined by.
4. **Fill the three fields**, with a `debug_assert` that the merged-mining hash
   did not move.
5. **Self-check** — run `MergedMiningRule`, the same rule every peer will run.
   Failing here means the node built something it would itself reject, worth
   catching before it is stored and announced rather than after.
6. **Execute and commit** — `process_and_commit` against the parent state root
   the template recorded, so the submission re-executes from the same point.
7. **Rebuild work** — the chain moved, so whatever is on offer is stale.

### Importing: why not `put_block`

`commit_mined_block` writes header, body and total difficulty separately rather
than calling `put_block`:

```rust
self.store.put_header_with_hash(hash, &block.header)?;
self.store.put_body(hash, &block.transactions, &block.ommers)?;
self.store.put_total_difficulty(hash, td)?;

if td > current_td {
    self.store.update_canonical_chain(hash)?;
    self.store.set_exec_head(hash, state_root)?;
    self.trie_store.flush();
    ImportResult::ImportedBest
} else {
    ImportResult::ImportedNotBest
}
```

`put_block` writes the canonical `number -> hash` pointer **unconditionally**,
which would hand the height to a block that then loses the total-difficulty
comparison two lines below, leaving the canonical chain naming a block that is
not on it. Header and body are safe to store either way, being keyed by hash.
Pinned by `a_losing_block_is_stored_but_not_made_canonical`.

The `flush()` on the winning path matters too: the trie nodes the block wrote are
durable only once flushed, and announcing a head whose state cannot be reloaded
after a restart would leave the node unable to build on its own block.

Miners are told which of `IMPORTED_BEST`, `IMPORTED_NOT_BEST` or `EXIST`
happened, so they can tell "my block won" from "my block was valid but somebody
else's arrived first".

### Error reporting

Every rejected submission becomes one application-defined code, `-33000`
(rskj `JsonRpcApplicationDefinedErrorCodes.SUBMIT_BLOCK`), so a miner
distinguishes causes by message rather than by code. `target` is zero-padded to
the full 32 bytes (`0x{:064x}`) because it is a value to compare a hash against,
not a quantity. `mnr_submitBitcoinBlockTransactions` and `…PartialMerkle` take
the block hash as parameter 0 and ignore it, as rskj does — the hash is
recomputed from the header, and a submission disagreeing with itself about it
would be caught by the merged-mining check anyway.

---

## 9. Deliberate omissions

**Not writing speculative state.** Executing a template writes its trie nodes
through to the store, because that is what `execute_block` does and mining does
not get a second execution path. A template is rebuilt once a minute, so a
mining node accumulates trie nodes for blocks that were never found. The
garbage collector reclaims them (they are unreachable from any canonical
root), but on a node with collection disabled this grows without bound.

**Running a miner and a sync service at once.** The sync service owns the
executed state root and does not know the miner exists. The miner refuses a
submission whose parent is no longer the executed head, so a race is reported
rather than corrupting state — but a node that is actively syncing will refuse
most solutions. Mine on a node that has caught up.

---

## 10. What the tests do and do not cover

The round trip is real as far as it goes: a genuine Bitcoin block is built with
a tagged coinbase, a nonce is actually searched for until the block hash clears
RSK's target, the coinbase is really compressed, the proof really built, and
acceptance is decided by running `MergedMiningRule` -- the same validator that
runs on blocks arriving from peers. The search is not decorative: before it
existed the tests used a fixed nonce, cleared the target only by luck, and that
is how the `get_work` notify bug surfaced.

The difficulty is 2, which rskj takes as 3, so the target is 2^256 / 3 and a
nonce is found in a few tries. Two heights are used deliberately:

- Most tests mine #21, which is fast but **does not exercise REMASC**:
  `RskExecutor::new` hardcodes `RemascConfig::mainnet()` whatever the chain id,
  so at that height `process_miners_fees` returns immediately -- there is no
  matured block 4,000 back. The REMASC *transaction* is still in the block and
  still moves the transactions root, which is what §6 is about, but nothing
  is distributed.
- `a_solution_is_imported_on_a_chain_deep_enough_for_remasc_to_pay` seeds 4,010
  headers and mines #4,011, clearing both the maturity window and the synthetic
  span, so the matured-header fetch, sibling collection and payout all run.

Not covered, in rough order of how much it matters:

1. **No interop.** Nothing verifies that an rskj node accepts a block this
   miner produces. The evidence that it would is indirect: the header encoding,
   fork-detection data and REMASC transaction are pinned against real mainnet
   block #9,257,552, which says the formats are right but is not interop
   testing. Running a regtest rskj against this node is the test that would
   settle it.
2. **No real mining software.** The `mnr_*` JSON shapes match rskj field for
   field and are pinned by tests, but no pool daemon has parsed them.
3. **No real difficulty**, so nothing exercises a long search or template
   refresh under load.
4. **Uncle selection is tested against a synthetic chain only.** The tests
   build forks directly in the store; no test mines on a chain whose forks
   arrived over the wire, because sync does not deliver them (§5.1).

## 11. Where the code is

| Path | What |
|---|---|
| `crates/core/src/validation/merged_mining.rs` | the format: verification, and `compress_coinbase` beside it |
| `crates/execution/src/mining/template.rs` | block template builder, transaction selection, the REMASC transaction |
| `crates/execution/src/mining/server.rs` | work cache, the three submit paths, import |
| `crates/execution/src/mining/fork_detection.rs` | RSKIP110 fork-detection data |
| `crates/execution/src/mining/uncles.rs` | uncle selection (rskj `FamilyUtils`) |
| `crates/execution/src/mining/merkle.rs` | RSKIP92 merkle proofs |
| `crates/execution/src/mining/coinbase.rs` | building the Bitcoin side, for regtest and tests |
| `crates/rpc/src/mnr.rs` | the four JSON-RPC methods |

The two tests worth reading first are
`a_template_validates_against_the_processing_path` — a freshly built template
put back through the validating path a peer would use — and
`a_solution_completes_a_block_and_is_imported`, the whole round trip.
