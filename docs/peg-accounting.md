# Auditing the peg: how much rBTC exists, and how much bitcoin backs it

[`supply-conservation.md`](supply-conservation.md) specifies the *per-block*
rule: no block may increase the total of all balances. This document is about
the other question, the one that rule cannot answer — at a given height, how
much rBTC is outstanding, how much bitcoin is held against it, and how to
compare the two without reaching a wrong conclusion.

Two tools, one per side:

| tool | side | what it reads |
|---|---|---|
| [`rbtc_supply`](../crates/cli/examples/rbtc_supply.rs) | RSK | every account balance in the unitrie at one state root |
| [`bridge_btc_holdings`](../crates/cli/examples/bridge_btc_holdings.rs) | Bitcoin | the Bridge's own UTXO bookkeeping at the same state root |

Both are read-only and safe against a live node.

**The short version: you cannot subtract one tool's output from the other's
and read the difference as a surplus or a deficit.** Four separate terms sit
between the two figures, and three of them are large enough to swamp the
result. The method below exists to account for them. Section 6 works a real
example in which the naive subtraction appears to show a deficit and the
correct accounting shows comfortable headroom.


## 1. Why the naive comparison fails

The intuition is that circulating rBTC should equal bitcoin held. It does not,
for four reasons, and each has a definite sign.

**Locked rBTC — makes the RSK side look bigger than the claim really is.**
REMASC withholds fees when one of its selection rules is broken. The function
that does it, `add_to_burned` in
[`crates/execution/src/remasc.rs`](../crates/execution/src/remasc.rs), only
increments a `burnedBalance` storage counter. It transfers nothing and
destroys nothing. The rBTC stays in REMASC's balance, is counted in any sum
over accounts, and no code path ever pays it out — `BURNED_BALANCE_KEY` is
written by that function and read by no other, and the single transfer out of
REMASC pays amounts from the reward calculation. So it is issued, counted, and
permanently unclaimable.

That it cannot be a true burn is provable from the tool's own output: the sum
over all accounts is exactly the genesis premine. Had anything ever been
destroyed, the total would have fallen below it.

**Unregistered bitcoin — makes the Bitcoin side look smaller than it is.**
`bridge_btc_holdings` reports what the Bridge has *registered*, which is not
everything the federation controls. A peg-in inside the 100-confirmation
window is held but untracked. Bitcoin below the minimum peg-in value is never
registered at all and stays at the federation address indefinitely. Change
from a peg-out re-enters the set only once the spending transaction is itself
registered, so a recent peg-out can leave a very large output invisible to the
Bridge for hours.

**Bitcoin miner fees — a genuine, permanent, one-way leak.** Peg-out and
federation-migration transactions pay their bitcoin fees out of peg funds. No
rBTC is retired when they do, so every such transaction moves the two sides a
little further apart, forever. This is the only one of the four that is a real
reduction in backing rather than a measurement artefact.

**Addresses nobody is summing.** Flyover peg-ins pay a P2SH derived per quote
and are never swept into the federation address, so the federation address
alone does not answer the question. Retired federation addresses may also hold
remnants.


## 2. Running the tools

```sh
cargo build --release -p rustock-cli --examples

# RSK side. --log gets progress and the report; --top 0 skips the rich list.
./target/release/examples/rbtc_supply \
    /var/lib/rustock /var/lib/rustock/trie-epochs-flat <block|head-N> \
    --threads 3 --log /path/to/rbtc_supply.log

# Bitcoin side, at the SAME height. The trailing hash160 is optional and only
# labels the active federation's script instead of leaving it unnamed.
./target/release/examples/bridge_btc_holdings \
    /var/lib/rustock /var/lib/rustock/trie-epochs-flat <same block> \
    a2aaed588a584e3b190d8219d3668749f52ece8a
```

Use the same height for both, and prefer `head-N` over `head` so the state is
settled. An epoch node keeps only a window of state; older heights need an
archive trie.

On threads: `rbtc_supply` defaults to the machine's parallelism. On a box
shared with the production node, set `--threads` to leave it a core. Three
workers walk the full mainnet trie — 12.6 million nodes — in about 80 seconds.

The walk is modelled on `snapshot::verify_complete` and reuses the
`children_size` every node commits: it splits the trie by byte weight,
repeatedly halving the largest piece so no straggler dominates the tail, and
reports progress as bytes genuinely accounted for rather than nodes guessed
at. Progress lines carry a percentage and an ETA every ten seconds.


## 3. Reading `rbtc_supply`

```
## unitrie census at #9395466
  accounts              558452
  code leaves            24715
  storage roots          24868
  storage slots        5729116
  unrecognised               0
  undecodable                0
```

`unrecognised` and `undecodable` must both be zero. They are the tool's own
honesty check: a leaf whose key does not classify, or an account record that
does not decode, would mean a balance was silently dropped from the sum.
Anything non-zero invalidates the run.

```
  sum of all balances             21,000,000.000000000000000000 RBTC
  genesis premine                 21,000,000.000000000000000000 RBTC
  -> conserved: the sum is exactly the premine, as it must be
```

This is the strongest validation available. RSK mints nothing: genesis hands
the Bridge the entire 21,000,000 RBTC and every later balance is a slice of
that one premine, so the total is invariant at every height. Hitting it to the
wei requires the bit-path tracking, the key classification and the RLP decode
to be simultaneously correct.

A mismatch here is reported as `NOT CONSERVED`. It means a node bug or a
corrupt state — **it says nothing about peg backing** and must not be read as
one.

```
  in the Bridge                   20,998,880.452185099190347926 RBTC
  ISSUED (outside it)                  1,119.547814900809652074 RBTC

  REMASC (0x...01000008), where block fees accumulate:
  balance                                  2.709955825463821677 RBTC
  burnedBalance                            2.701510584930417566 RBTC
  rewardBalance                            0.000078048098750301 RBTC
```

`ISSUED` is `21,000,000 − balance(Bridge)` — rBTC outside the Bridge. It is
**not** the claim on bitcoin; subtract the locked portion first.

Do not treat REMASC's whole balance as locked. Only `burnedBalance` is.
`rewardBalance` is still owed to miners, and the remainder (here 0.00837 RBTC)
is live fee income awaiting distribution. Both are ordinary claims.


## 4. Reading `bridge_btc_holdings`

```
## active federation set (newFederationBtcUTXOs)
  5.97157803 BTC across 15 UTXO(s)
  a2aaed588a584e3b190d8219d3668749f52ece8a     5.94378748      13  ACTIVE federation
  b7de8fe34e6e9b342e8b59b288b39ca2d590b07c     0.01768935       1  derived (Flyover)
  4e53e4f0dccd1e68c1609efe3388af84c49f7435     0.01010120       1  derived (Flyover)
```

Grouped by `scriptPubKey`, then listed outpoint by outpoint so the set can be
diffed against what the addresses actually hold on Bitcoin. `tx_hash` is
stored and printed in **display order** — do not byte-reverse it before
looking it up in a block explorer.

The derived scripts are Flyover peg-ins. Each quote pays its own P2SH,
`P2SH(PUSH(derivationHash) OP_DROP <federationRedeem>)`, and nothing sweeps
them into the federation address; they stay put until a peg-out spends them.
This is why the federation address alone understates the peg.

Remember what this total is: **registered** bitcoin, not held bitcoin. To get
held bitcoin, query the addresses themselves.


## 5. The accounting identity

```
  claimable rBTC  =  issued rBTC  −  burnedBalance

  bitcoin accounted  =  held at the federation address
                      + held at every Flyover-derived address
                      + held at any retired federation address

  solvency:  claimable rBTC  ≤  bitcoin accounted
```

The inequality is not expected to be tight. Unregistered bitcoin and peg-ins
in the confirmation window leave the right-hand side larger; cumulative
bitcoin miner fees pull it down over time. The margin between them is the
peg's headroom.

Note the direction of the ordinary lags. A peg-in puts bitcoin at the address
roughly 100 confirmations before the rBTC is credited; a peg-out burns rBTC
immediately and pays bitcoin later. **Both make the bitcoin side the larger
one.** So a deficit is the direction that demands an explanation, whereas a
surplus is routine. If you compute a deficit, the first hypothesis should be
that a term is missing from your accounting — most likely `burnedBalance`, or
bitcoin at addresses you have not summed — not that rBTC is unbacked.


## 6. A worked example: #9,395,466

This is the case the method was built for, because the naive subtraction gets
it backwards.

**Naive, and wrong.** Take `ISSUED` and the two tools' bitcoin figures:

| | BTC |
|---|---|
| issued rBTC | 1119.547814900809652074 |
| federation address `3GX89qzy…`, unspent on Bitcoin | 1119.39512544 |
| + the two Flyover-derived UTXOs | 0.02779055 |
| bitcoin accounted for | 1119.42291599 |
| apparent difference | **−0.124898910809652074** |

Read literally this says 0.125 BTC of rBTC is unbacked. It is wrong, because
`ISSUED` has not had the locked portion removed.

**Correct.** Subtract `burnedBalance`, which is issued but permanently
unclaimable:

| | BTC |
|---|---|
| issued rBTC | 1119.547814900809652074 |
| less locked in REMASC (`burnedBalance`) | −2.701510584930417566 |
| **claimable rBTC** | **1116.846304315879234508** |
| bitcoin accounted for | 1119.42291599 |
| **headroom** | **+2.576611674120765492** |

The inequality holds with 2.58 BTC of margin. The locked balance exceeds the
apparent difference by more than twentyfold.

### Why the Bridge's registered total is so much smaller

At this height `bridge_btc_holdings` reports 5.97 BTC registered while the
federation address holds 1119.40. That gap is the registration lag, and it
resolves outpoint by outpoint. The thirteen UTXOs the Bridge tracks at the
federation script are an exact subset of the address's eighteen unspent
outputs; five are held but untracked:

| txid:vout | BTC | BTC height | confirmations | why untracked |
|---|---|---|---|---|
| `f91bd374…:2` | 1112.79006583 | 975,085 | 10 | peg-out change, inside the 100-confirmation window |
| `07f8036e…:1` | 0.16035391 | 975,084 | 11 | same |
| `aef2ece9…:10` | 0.50000000 | 974,428 | 667 | unexplained; see below |
| `a2a6d5d1…:1` | 0.00090322 | 969,454 | 5,641 | below the minimum peg-in — never registrable |
| `3d1d82d8…:18` | 0.00001500 | 946,211 | 28,884 | same |

Confirmations are `tip − height + 1` at Bitcoin tip 975,094, the snapshot
these figures were taken against.

`f91bd374` is a peg-out: one input of 1123.64 BTC from the federation, two
payments to a user totalling 10.85 BTC, and 1112.79 BTC of change back to the
federation address. The change re-enters the Bridge's set once the transaction
is registered, which needs 100 confirmations. That single output is 99.4% of
the gap and it is pure timing — re-running the tool a day later is the test.

The two dust outputs are permanent. They sit below the minimum peg-in, so the
Bridge will never register them; they are bitcoin the peg holds and no rBTC
claims, which adds to headroom.

`aef2ece9…:10` is the one open item: past the confirmation window, above the
minimum, yet untracked while vouts 11–21 of the same transaction are all
tracked. The likely explanation is that it was selected into a peg-out and
removed from the active set at build time, with the spending transaction not
yet confirmed — `pegoutsWaitingForConfirmations` would show that. Unverified.


## 7. What would actually indicate a problem

- `unrecognised` or `undecodable` non-zero — the run is invalid, fix before
  reading anything else.
- `NOT CONSERVED` — a node bug or corrupt state. Not a peg finding.
- `claimable rBTC > bitcoin accounted`, **after** every term in section 5 has
  been included and the bitcoin side has been read from the addresses rather
  than from the Bridge's registered set. Before concluding anything, confirm
  the bitcoin snapshot is contemporaneous with the RSK height, and check the
  addresses in section 8 that these tools do not yet sum.


## 8. Not yet measured

Honest limits of the method as it stands:

- **Cumulative bitcoin miner fees** paid from peg funds by peg-outs and
  migrations. The mechanism is certain and the leak is permanent; the total is
  not measured here. One observed peg-out paid 3,160 sat, which suggests the
  historical sum is small relative to the locked balance, but that is an
  inference from a single sample.
- **Retired federation addresses.** `federation_intervals` recovers the key
  sets for all seventeen historical federations, from which their addresses
  can be rebuilt and queried. Remnants there would be unsummed backing.
- **Unregistered Flyover peg-ins.** Only the derived addresses the Bridge
  tracks are counted; bitcoin paid to a derived P2SH that was never registered
  is invisible to both tools.

All three cut in the favourable direction — the first reduces an already
unmeasured leak, the other two would add bitcoin — so none of them threatens
a headroom result. They matter for making the accounting exact.
