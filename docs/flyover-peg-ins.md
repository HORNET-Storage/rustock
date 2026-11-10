# Flyover peg-ins: invisible in the event log, recoverable from state

## 1. The Bridge logs nothing for a Flyover peg-in

`registerFlyoverBtcTransaction` emits **no Bridge event**. Not a different
event, not a variant of `pegin_btc` — nothing.

Confirmed on both sides:

- **rskj** — `BridgeSupport.registerFlyoverBtcTransaction` (lines 2735–2923 of
  `rskj-core/src/main/java/co/rsk/peg/BridgeSupport.java`) contains no
  `eventLogger` call. Every method it invokes was enumerated; the only logging
  is SLF4J `debug`/`info`, which reaches the node's text log and not the
  receipts.
- **rustock** — the same, in
  [`peg.rs`](../crates/execution/src/bridge/peg.rs) lines 1599–1957.

The contrast is in the same file. An ordinary peg-in logs at rskj line 729:

```java
if (activations.isActive(ConsensusRule.RSKIP146)) {
    if (activations.isActive(ConsensusRule.RSKIP170)) {
        eventLogger.logPeginBtc(rskDestinationAddress, btcTx, amount, protocolVersion);
    } else {
        eventLogger.logLockBtc(rskDestinationAddress, btcTx, senderBtcAddress, amount);
    }
}
```

**`protocolVersion` there is not a Flyover marker.** It is the peg-in protocol
version from the OP_RETURN payload (RSKIP170 v1 peg-ins use `1`, legacy ones
`0`). Flyover never reaches that line. Reading `protocolVersion == 1` as
"Flyover" is wrong and was briefly believed here.

The one exception is the **rejection** path, which does log — the refund is a
peg-out and the Bridge records it as one:

```
generateFlyoverRejectionReleaseWithWalletProvider (3205)
  -> generateRejectionReleaseFromFederation       (3251)
  -> generateRejectionRelease                     (3301)
  -> logReleaseRequested                          (1418)
  -> eventLogger.logReleaseBtcRequested           (1436)
```

matching our `emit_flyover_rejection_release` → `release_requested_or_record`.

**Consequence.** `bridge_events` is built from receipts, so from iris300
(#3,614,800) onward every *successful* Flyover peg-in is missing from it — not
because the index is incomplete, but because there is nothing to index. A
topic scan for `pegin_btc` across all history silently omits them.

## 2. Only a contract can call it

rskj enforces this first, before anything else:

```java
if (!BridgeUtils.isContractTx(rskTx)) {
    return BigInteger.valueOf(UNPROCESSABLE_TX_NOT_CONTRACT_ERROR.value());  // -300
}
RskAddress sender = rskTx.getSender(signatureCache);
if (!sender.equals(lbcAddress)) {
    return BigInteger.valueOf(UNPROCESSABLE_TX_INVALID_SENDER_ERROR.value()); // -301
}
```

`BridgeUtils.isContractTx` is literally `rskTx.getClass() ==
InternalTransaction.class` — true only when the Bridge is reached by a CALL
from contract code. Our port matches: `call_depth <= 1 → -300`,
`caller != lbc_address → -301`, same constants.

So it is **the mirror image of `releaseBtc`**, which rejects `call_depth > 1`.
Peg-outs are EOA-only; Flyover peg-ins are contract-only. That asymmetry is
why peg-outs can be enumerated from block bodies and Flyover peg-ins cannot:
the latter exist only as internal transactions.

A second, tighter constraint: the caller must equal the `lbcAddress` passed in
the call's own arguments, so not merely "a contract" but the specific
LiquidityBridgeContract named. And note it **returns an error code rather than
reverting** — an EOA call is a successful transaction that quietly does
nothing.

In practice, therefore, every Flyover peg-in that ever took effect came from a
contract. Not by convention — by construction. Whether any EOA ever *tried* is
a separate question, answerable by a static scan for the selector in top-level
calls, since failures are top-level and visible; the successes never are.

## 3. The state knows, even though the log does not

`saveFlyoverFederationInformation` stores
`RLP[derivationHash(32), federationRedeemScriptHash(20)]` under

```
keccak("fastBridgeFederationInformation-" || hex(flyoverP2shHash160))
```

The slot is keyed by the **derived address's hash160**. So any candidate
address can be tested against the Bridge's own state with a single trie read —
no replay, no execution. [`flyover_registry`](../crates/cli/examples/flyover_registry.rs)
does exactly that.

Both the active and the retiring (RSKIP293) paths use this one scheme —
`saveFlyoverRetiringFederationInformation` calls the same
`getStorageKeyForFlyoverFederationInformation` — so there is no second place
to look.

It **cannot be enumerated**: the slot is a keccak of the key string, so there
is no prefix to scan. Candidates must come from elsewhere. Two sources
together cover both halves:

| source | finds | misses |
|---|---|---|
| peg-outs drawing from an address | addresses the Bridge has spent from | anything still unspent |
| the live Bridge UTXO set (`bridge_btc_holdings`) | currently unspent Flyover UTXOs | anything already spent |

Against a 450-address list derived from peg-outs: **447 registered, 3 absent,
0 unresolvable.** The two currently-unspent Flyover addresses — which the
peg-out method structurally cannot see — are also `REGISTERED`, with their
derivation hashes. Registration survives spending, so the oracle works for
both halves.

## 4. Three flyover-shaped addresses that were never registered

The three absentees are not a hole in the oracle. They are the oracle working.

On Bitcoin they look exactly like Flyover quote addresses: 2 transactions, one
funding output, fully spent, all **exactly 800,000 sat**. But the redeem
script revealed when they are spent tells a different story:

```
39yrhd…   OP_PUSHBYTES_32 0x0000…0001 OP_DROP OP_NOTIF OP_PUSHNUM_5 <keys> …
3GQ87zLK… OP_NOTIF OP_PUSHNUM_5 <keys> …          (plain federation, for contrast)
```

It **is** flyover-shaped — `PUSH(derivationHash) OP_DROP <federationRedeem>` —
but the derivation hash is `0x0000…0001`. That is not a keccak output.
`getFlyoverDerivationHash` hashes the quote arguments and could never produce
1. Someone hand-built a flyover-shaped address with a trivial derivation hash
and paid it.

Everything follows from that:

- **No registration record**, because no quote ever produced that hash. The
  absence is correct, not a gap.
- **The Bridge cannot spend it**: spending needs the redeem script, which
  comes from `getFlyoverFederationInformation` — and nothing was stored.
- **The functionaries can**, because the script's live branch is the ordinary
  federation multisig.

The recovery transaction bears this out. It mixes one plain-federation UTXO
with one orphaned flyover-shaped UTXO, 2-in/1-out, and pays a 50,736 sat fee
on 1,600,000 sat — about 3%, far above anything the Bridge's fee logic
produces. It looks manual, and manual is what it would have to be.

### The timelock branch is not a user refund

The flyover script inherits the PowPeg **ERP** structure, so it does have a
timelocked branch:

```
OP_NOTIF  OP_PUSHNUM_5 <9 keys> OP_CHECKMULTISIG
OP_ELSE   OP_PUSHBYTES_3 50cd00 OP_CSV OP_DROP OP_PUSHNUM_3 <keys> OP_PUSHNUM_4 OP_CHECKMULTISIG
OP_ENDIF
```

`50cd00` little-endian = 52,560 blocks ≈ one year. That branch pays the
**emergency keyholders**, never the sender. There is no script path by which a
payer recovers their own coins.

And it was not used here. Both inputs carry **5 signatures** (the 5-of-9
federation branch), the selector before the redeem push is `OP_0` so
`OP_NOTIF` takes the IF branch, and `nSequence = 0xffffffff` — which disables
`OP_CSV` outright, making the ERP branch unsatisfiable in that transaction.

Flyover's real refund is at the RSK layer: the quote carries a
`userRefundAddress`, and a *registered* peg-in that the Bridge rejects gets a
refund transaction built to it (§1). Registration is the precondition, and it
is exactly what is missing here.

**The corollary is worth stating plainly: bitcoin paid to a flyover-shaped
address whose derivation hash the Bridge will never register is not
trustlessly recoverable.** The Bridge cannot spend it, the sender cannot spend
it, and the only route back is the functionaries signing directly.

## 5. Three tooling traps, each of which produced a wrong answer here

**`rskj_root_probe` against one of our stores.** It opens the *default* column
family, because rskj's flat unitrie keeps nodes there. Our stores use
`trie_nodes`. Pointed at a segbuild chunk it reports ABSENT for every hash
whatever the chunk holds. This produced a documented finding — "chunk 000 has
none of six probed roots" — that was false and stood for weeks, and it is
retracted in `/home/paseo/doc/mainnet-pegin-refunds.md`. Use
[`trie_probe`](../crates/cli/examples/trie_probe.rs) for a rustock-format
store.

**`TrieNode::get` versus `try_get`.** `get` answers `None` both when a key is
genuinely absent and when the walk reaches a node the store cannot produce.
Those are opposite answers — "never registered" versus "this database has been
pruned and cannot say". `try_get` returns `Err(hash)` for the second.
`flyover_registry` uses it and reports UNKNOWN separately, which is how GC was
ruled out as the explanation for the three absentees: **0 unknown**, the walk
completed cleanly to the point of absence.

**WTXID versus TXID.** A segwit-serialised `release_btc` hashes to its WTXID,
not its TXID. Getting this wrong halves the matches when extracting addresses
from releases, and looks like missing data rather than a bug. Relatedly, a
txid is the hash *of* a transaction, so searching Bridge calldata for a txid
can never match.

## 6. Reconstructing the missing events

The gap in §1 has the same shape as the legacy-era gap and yields to the same
machinery — see [`legacy-peg-events.md`](legacy-peg-events.md). The Flyover
path already records what is needed:

```rust
record_pegin(SilentKind::PeginAccepted, ..., vec![
    ("peginPath",   FieldValue::Text("flyover".into())),
    ("destination", FieldValue::Addr(lbc_address)),
    ("logged",      FieldValue::Flag(false)),
]);
```

So Flyover peg-ins are distinguishable from ordinary ones by `peginPath`, and
the destination is the LBC credited. No change to the execution path is needed
to tell them apart, and no `protocolVersion` has to be invented.

What a replay still has to supply is the RSK block and transaction index —
those are the event's key — and they cannot come from Bridge state or from
Bitcoin.

**The census makes the search checkable.** Rather than replaying 5.78M blocks
from iris300 to head, each address's first Bitcoin funding height bounds an
RSK window, and only those windows need replaying. On its own that is a
heuristic, and a missed window is an undetectable hole. With §3 it is not: the
census is a known-complete target list, so every address must appear in the
output, and any that does not names its own too-narrow window.

Two properties make the replay cheap. Every block above #1,591,000 carries a
real unitrie root, so blocks can be replayed **in any order and in parallel**,
with no sequential carry. And the state can be read from a segbuild segment,
which is dense and sealed, so the run is **purely reads** — nothing of the
trie needs writing to disk, which removes both the scratch growth and the
compaction cost.
