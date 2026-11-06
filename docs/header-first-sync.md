# Header-first sync: a design note

**This describes a shape the node does not have.** It is a proposal, written
down because the sampling gate, the shipped checkpoint and three of the bugs
found around them (#256, #258, #259) all exist to solve a problem this shape
does not have. Nothing here is implemented.

## The shape

Three phases, in order:

1. **Header pass.** Download every header from genesis to the tip, with the
   uncle headers each references, verifying merged-mining proof of work and
   every consensus rule that does not need a body. No bodies, no execution.
   This establishes the canonical chain and its **exact** cumulative
   difficulty.
2. **State.** Ask a peer for the trie at a checkpoint. Its offer is now checked
   against the chain from phase 1 by hash, which is an index lookup.
3. **Bodies.** The last `blocks_required` blocks before the checkpoint, because
   contracts can read recent block data.

Phase 1 is ordinary forward sync with execution switched off. Phase 2 is what
snapshot sync already does. The change is the order and what phase 2 is allowed
to assume.

## Why this is worth considering

**Snapshot sync already downloads every header.** `HeaderWalk` descends from
the peer's offered checkpoint to "the first block this node already holds,
which is usually but not always genesis" -- and on a fresh node that is
genesis. The walk is 92.4% of a snapshot sync (#244) and took **6,971 s --
nearly two hours** on the measured mainnet run, against 7,545 s for the sync as
a whole. What snapshot sync saves against a full sync is
**bodies and execution**, not headers.

So the difficulty gate is a filter protecting a cost that is paid anyway. It
spends ~585 messages bounding a claim, to decide whether to spend twenty-five
minutes establishing the same quantity exactly. In the shape above there is
nothing to pre-filter: the header pass is unconditional, and the exact total
difficulty falls out of it.

## Why the current walk goes backwards

Worth stating, because it is not a free choice.

`BlockHeadersQuery` is `{ hash, count }`. There is no direction field -- unlike
eth's `GetBlockHeaders`, which has `reverse` -- and `serve_headers_request`
walks backward from the hash, as rskj does. **A forward request is not
expressible on this wire.**

So "forward sync" in RSK does not mean forward requests. It means asking for
block identifiers *by height* (the skeleton, which is height-addressed) and
then pulling a descending run from each. The snapshot walk does exactly that
too. Both shapes fetch descending chunks in parallel and order them by height.

The real difference is where trust is anchored:

| | anchored at | answers |
|---|---|---|
| snapshot walk | the peer's offered checkpoint, descending | "does this `state_root` sit atop real work?" |
| header-first | what this node already holds, ascending | "is there more chain, and how much work is in it?" |

Descent is self-authenticating: `parentHash` determines the ancestor chain and
every link is checkable. Ascent is not -- a header does not name its children,
so going up needs a peer to choose the next block, and the links are what catch
a wrong choice rather than preventing it.

## Parallelism

Both shapes can pipeline, and the skeleton trick that makes the current walk
parallel works just as well here. The difference is not how many requests can
be in flight but **what a failure costs**.

The snapshot walk is one bet on one peer's offered checkpoint. Headers go to a
staging freezer as they are verified and are promoted by rename only when an
unbroken run of links reaches the anchor. If the offer was bogus, or the walk
stalls, the staging freezer is discarded -- every chunk fetched was conditional
on a claim that turned out to be false.

A header-first pass is built upward from something already trusted, so a
segment can be promoted as soon as it links to the prefix below it. Chunks are
permanently valuable the moment they link. That makes aggressive fan-out across
many peers cheap to attempt: a peer that answers wrongly costs its own chunks,
not the sync.

The ceiling is then bandwidth and the per-peer message limit rather than
risk appetite:

```
  9,276,564 headers / 192 per response   =  48,316 chunk requests
  rskj's inbound limit, one peer          =  1,000 messages/minute -> 48 minutes
  the same across eight peers             =  about 6 minutes
  20.6 GB at 100 MB/s aggregate           =  about 3.5 minutes
```

against the **6,971 s** the descending walk measured on mainnet -- an effective
2.84 MB/s over the 21.4 GB it moved, which is nowhere near a bandwidth limit and
is the headroom #244 tracks. This shape makes that headroom safer to use.

## What it costs

Measured on this chain at #9,276,564, from the freezer index and the node's own
RPC:

| | size |
|---|---|
| trunk headers, genesis to tip | 10.1 GB |
| uncle headers they reference | 10.5 GB |
| **header pass total** | **20.6 GB** |
| state at the checkpoint | ~0.9 GB |
| 6,000 bodies | ~8 MB |
| *(for comparison: every block, full sync)* | *22.8 GB* |

The uncle headers are the whole of the extra cost, and **they are not
optional**. Cumulative difficulty in RSK counts uncle difficulty, and the only
way to know that work was performed is to see the proof of work that performed
it. An uncle header carries its own merged-mining proof; nothing else does.

Downloading them yields a *proof*, not an assertion, because three things line
up:

- `unclesHash` is in the trunk header and so is covered by its proof of work,
  which binds the uncle list to that block;
- each uncle header carries its own proof of work, so its difficulty is work
  that was really done;
- the uncle rules -- the generation limit, and that an uncle is not referenced
  twice -- are checkable against the trunk chain the pass already holds.

This is the same 10.5 GB the current walk would have to pay for an exact total.
It does not pay it today, which is #258, and the consequence is that
`walked_difficulty` understates the chain, and the walk bounds the rest from
above (`HeaderWalk::work_ceiling`) rather than counting it.

### RSKIP-699 does not remove this

An earlier revision of this note claimed it did. That was wrong, and badly so.

A header field stating the cumulative total is *data*, not work. A miner can
mine a header with valid trunk proof of work and write any `cumulativeDifficulty`
into it; the rule binding the field to the parent's value is enforced by nodes
that validate the parent's **body**, which a header-only pass by definition does
not have. Reading the field instead of exhibiting the uncles replaces a proof
with an assertion.

The cost of doing so is not a rounding error. An attacker who claims the
consensus maximum of ten uncles in every block multiplies its claim by 11 while
doing only the trunk work:

```
  honest chain claims   1.91 x its trunk work   (measured mainnet uncle rate)
  attacker claims      11.00 x its trunk work   (uncleListLimit, fabricated)
  attacker needs        1.91 / 11 = 17.4%  of the honest chain's trunk hashpower
```

So a client trusting the field without the uncles drops the threshold for
out-claiming the honest chain from above 50% to about **17%**. Exhibiting the
uncles restores it: every uncle's difficulty must be backed by its own proof of
work, so there is no multiplier to exploit.

**RSKIP-698 is what this shape needs; RSKIP-699 is not a substitute for it.**
698 makes the uncles available over the wire at header-sync speed. 699 makes a
number readable, and a readable number is not a proven one.

## What disappears

Everything that exists to approximate a number this shape simply has:

- `ceiling_for`, `max_work_between`, `uncle_allowance_per_mille`, `ChainSampler`,
  `SamplingGate`, `Phase::SamplingClaim`;
- the 17% slack, and the argument for why it is acceptable;
- `MAINNET_CHECKPOINT` as a shipped constant, and with it the governance
  question of asking whoever builds the node to declare a canonical fork;
- `CheckpointVerdict::SelfExceeds`, which exists because a shipped checkpoint
  can be wrong;
- issues #256, #258, #259, and most of RSKIP-695's sampling sections.

**The checkpoint check becomes an index lookup.** A server still dictates which
checkpoint it serves -- `SnapStatusResponse` carries the offered blocks, and a
client cannot request an arbitrary state root. That stops mattering: with the
whole header chain in hand, the client checks whether the offered block is the
one its own canonical index holds at that height. If the hash matches, the
`state_root` is one it derived itself and every chunk proves against it. If it
does not, the peer is on another chain and is dropped. No sampling, no ceiling,
no bound.

**Peer selection stops needing a bound too.** A peer claiming more work must
produce headers carrying it. If it can, the work is real; if it cannot, it
stalls and is dropped. The cost of a liar is bounded by how fast a stall is
noticed, not by a twenty-five minute commitment made in advance. That is what
#253 is really asking for, and this shape answers it by construction.

## What is harder, or unresolved

**Time to first state byte is not better, and may be worse.** The header pass
must finish before the trie download starts, exactly as the walk does today,
and carrying uncles roughly doubles its bytes. This shape is slower end to end
than the current one unless the parallelism above is actually realised -- and
no header field changes that, for the reason given under *What it costs*.

**The tip moves during the pass.** Twenty-five minutes is about 3,000 blocks.
The pass ends at whatever tip it reached, and the checkpoint a server offers is
derived from *that server's* head rounded down. Those will not generally be the
same block, but they do not need to be -- the client only has to recognise the
offered block in its own index, and a server's checkpoint sits 10,000 blocks
below its head, well inside what the pass covered.

**Two header pipelines become one, but not for free.** `snap/headers.rs` and
the ordinary skeleton sync in `service.rs` duplicate validation today. Merging
them is the bulk of the work and is where regressions would come from.

**It still walks from genesis.** This shape does not enable syncing from a
recent checkpoint without touching old history -- neither does the current one,
so it is not a regression, but it is not the thing an MMR would buy either. See
RSKIP-699's rationale for why an MMR is not proposed -- noting that an MMR
with recursive verification is one of the few things that *could* shrink this,
because it changes the proof system rather than adding a field.

**Storage before any state.** 20.6 GB of headers and uncles land before the
trie is requested. The freezer already holds both in parallel stores, so this
is served by existing machinery rather than needing new, but it is a disk
requirement that arrives earlier in the sync than it does today.

## Status

Implemented behind `--snap-forward-headers`, off by default, in
`crates/sync/src/snap/forward.rs`. The descending walk is untouched.

The first real run (2026-10-05) reached **#9,281,664 of #9,285,000 in 6,991 s**
and then stalled, against **6,971 s** for the descending walk over the whole
distance -- so the two are within a percent of each other on a single peer,
which is what this note predicted, since the argument here was never
single-peer speed. Three defects were found and fixed: unanswered requests were
never reissued during an ascent, a target off the 192-block grid could not be
reached at all, and a run that failed to link made its height permanently
unaskable. Recorded in issue #262.

That run used a live server and so does not measure what it set out to.
`docs/snap-sync-test-method.md` says how to run the next one.

## Relationship to the wire proposals

- **RSKIP-698** (headers with uncles) is a prerequisite for the exact total,
  and is implemented. Against an `rsk/62` peer the pass can still run, but it
  computes a lower bound and the checkpoint check falls back to what exists
  today.
- **RSKIP-699** (cumulative difficulty in the header) does **not** help here,
  for the reason given above: it makes the total readable, not proven. It is
  under reconsideration for exactly that.

So this shape rests on RSKIP-698 alone, and its cost is the full 20.6 GB. There
is no header field that makes proving work cheaper, because work is proven by
exhibiting it. Shrinking the proof needs a different proof *system* -- an MMR
with recursive verification, or a succinct argument -- not another field.
