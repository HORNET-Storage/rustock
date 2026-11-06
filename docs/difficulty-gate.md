# The difficulty gate

How this node decides whether a peer's claimed cumulative difficulty is
possible, before spending anything on that peer.

A peer announces a total difficulty in its status message. Nothing makes that
figure true. Sync decisions are made from it — who to follow, whose checkpoint
to trust — so a peer that inflates it steers work toward itself, and a peer
that inflates it enormously can hold a node's attention indefinitely.

The gate answers one question: **could any valid chain carry this much work?**
It does not answer "is this peer honest" or "is this the best chain". It
filters who is worth talking to.

## Two halves, and only one of them is a defence

| | bounds a claim | cost | adversarial value |
|---|---|---|---|
| free half | at or below the checkpoint height | arithmetic, no requests | **none** |
| sampled half | above the checkpoint height | ~585 messages, 0.6 MB | the whole of it |

The split exists because the two cases are not alike. Below the checkpoint the
work is *known*, so refuting a claim is subtraction. Above it there is nothing
to check against — and that window is where a lie lives.

### The free half, and why it secures nothing

`ChainSampler::refuted_by_checkpoint_alone`, reached from
`handler::refuted_by_checkpoint`:

```rust
claimed_height <= checkpoint.number && claimed > checkpoint.cumulative_difficulty
```

A peer claiming more work than the checkpoint allows, *for a height at or below
it*, is refuted by arithmetic and its metadata is never recorded — which is
what stops this node syncing from it, since peer selection reads exactly that.

**Against an adversary this is worth nothing**, and it is important to say so
rather than count it as half a defence:

- the sidestep is free — claim a height above the checkpoint;
- and it is what an attacker would do anyway. To be chosen as a sync peer you
  want to look like the longest, best-worked chain, so you claim a *high*
  height and high work. The trigger condition here is low height with high
  work, which is the opposite of the incentive. A peer would have to go out of
  its way to trip it.

A control that neither raises an attacker's cost nor removes an option from
them is not a security control. What this one catches is a peer that is
**broken rather than hostile**: a miscomputed total, a corrupted import, a bug
on the other side of the wire. That is robustness, it is free, and it is worth
keeping — but it is not a bound on what a lying peer may claim.

The consequence is that **until the sampled half runs, the difficulty gate has
no adversarial value on the sync path at all.** It is not a partial defence; it
is an unarmed one.

### The sampled half

Above the checkpoint, the node picks heights in two stages, asks the peer for a
header at each, verifies every one's proof of work, and feeds the results to
`ceiling_for`.

1. **A random draw** of `RANDOM_SAMPLES = 340` heights, uniformly, from
   whatever the peer's skeleton has named.
2. **Gap filling**: evenly spaced extra heights until no gap exceeds
   `SAMPLE_INTERVAL = 768` blocks.

The two do different jobs and `choose_samples` keeps them separate on purpose.

The random draw is what the **uncle allowance** rests on. The peer is committed
to its chain before it learns where it will be checked, so the heights it is
asked about are a uniform sample of a population it has already fixed. A fixed
grid of `checkpoint + k*768` destroys that: a peer mines real uncles at exactly
those heights and fabricates between them, for a fraction of a percent of the
work it claims.

The gap filling proves nothing about uncles. It exists so that no stretch is
wide enough for the difficulty bound to compound out of usefulness, and it is a
deterministic function of the draw — counting those positions toward the sample
count would overstate what the method proves. Evenly spaced rather than
recursively bisected: bisection yields only power-of-two subdivisions, so a gap
just over `768 * 2^m` costs nearly twice the requests it needs to.

A skeleton arrives in pieces, so selection runs repeatedly as more heights
become known. `ChainSampler` keeps the draw it has made and only tops it up
toward 340 — redrawing from scratch would union one draw onto the next and the
request count would grow without bound.

The samples must come **from the peer being judged**. If its chain is
fabricated, nobody else holds those blocks — so a peer that cannot produce them
has failed by another route. `MISSING_SAMPLES_ALLOWED = 4` gives up on a peer
that will not answer: a peer that will not substantiate its claim is as useless
as one that cannot.

## Why sampling bounds anything

Difficulty cannot move arbitrarily between blocks — the retarget rule limits
each step. So given two sampled blocks, the work in the gap between them is
bounded even though those blocks were never seen.

`max_work_between` computes that bound for one gap; `ceiling_for` tiles the
gaps across the chain and adds the exact work below the checkpoint.

### Two ceilings per block, take the lower

Every block between two samples faces two separate limits:

- **the retarget rule** — it cannot exceed the previous block by more than
  `1/divisor`;
- **the landing constraint** — it cannot be so high that even falling as fast
  as the rule allows, it would still overshoot the next sample's difficulty by
  the end of the gap.

The lower of the two is the most that block could have been. `cap[]` holds the
second limit, built backwards from the next sample.

```rust
for step in 1..=span {
    let risen = d + d / divisor;        // the retarget ceiling
    d = risen.min(cap[step]);           // the landing ceiling
    if d < min_difficulty { d = min_difficulty; }
    total += d;
}
```

A worked example, with `divisor = 4` (±25% a block, rather than the real
0.25%, so the numbers stay legible), `from = to = 100`, `span = 3`:

```
cap, built backwards from `to`:   cap[3]=100   cap[2]=133   cap[1]=177

step 1:   risen = 125    cap = 177   ->   min = 125
step 2:   risen = 156    cap = 133   ->   min = 133
step 3:   risen = 166    cap = 100   ->   min = 100
                                          total = 358
```

A chain that stayed flat at 100 across that gap really carries 300. The bound
says 358 — above the truth, which is what an upper bound has to be.

### Why not a rise-then-fall shape

The intuitive model is a triangle: rise as fast as possible, turn, fall onto
the next sample. It is wrong, and the reason is sharper than "it is less
accurate" — **for an important case it has no valid path at all.**

A rise and a fall do not cancel:

```
rise x fall  =  (1 + 1/divisor) x (1 - 1/divisor)  =  1 - 1/divisor²
```

At `divisor = 4` that is 15/16: a rise followed by a fall lands a sixteenth
*below* where it started. So when two consecutive samples carry the **same**
difficulty, no sequence of max-rate moves can return to it. Every such path
ends somewhere other than `to`.

The one path that does land is the flat one — difficulty unchanged the whole
way, which consensus permits. A triangle cannot express it, because a triangle
is always rising or falling.

Worked, with `from = to = 100`, `span = 2`, `divisor = 4`:

| path | ends at | sum | lands on `to`? |
|---|---|---|---|
| rise, rise | 156.25 | 281.25 | no |
| rise, fall | 93.75 | 218.75 | no |
| fall, rise | 93.75 | 168.75 | no |
| fall, fall | 56.25 | 131.25 | no |
| **flat** | **100** | **200** | **yes** |

Note the rise-then-fall path sums *above* the flat chain, not below. The
triangle's problem is not that it undercounts — it is that it cannot land, and
an implementation forced to produce something anyway can easily return a figure
below the flat chain's real 200. A bound below reality rejects honest peers,
which is the one failure an upper bound must never have.

Taking the lower of two ceilings avoids all of this without needing a concept
for "unchanged": once the rise limit exceeds the cap, `d` simply tracks the
cap, which may sit level. That *is* the flat chain, arrived at by arithmetic
rather than by special-casing.

### Why the `min_difficulty` clamp is safe

Consensus will not let difficulty fall below a floor, but `cap[]` is built
assuming maximal falls, so it can compute values below that floor — positions
no real chain could occupy.

The clamp raises those back to the floor. The **direction** is the point: it
only ever raises a term, and raising terms in an upper bound keeps it an upper
bound. It can make the ceiling more generous, never too tight.

Past the newest sample there is no later difficulty to aim for, so the bound is
unconstrained growth. **This is why the newest sample should sit close to the
head** — the further the head is beyond the last sample, the looser the
ceiling.

## The uncle allowance

`max_work_between` bounds **header difficulty**. The quantity a peer claims is
**cumulative difficulty**, which in RSK is header difficulty plus the
difficulty of every uncle the block references. Those are not the same number,
and the gap is not small: measured over 276,000 blocks above the shipped
checkpoint, uncles add **90.9%** to the work.

A bound on the smaller quantity compared against a claim of the larger one is
the bug that `uncle_allowance_per_mille` exists to close. Before it, the
retarget bound of 1.68× header work came to **0.88×** the real work — below the
honest chain, so every truthful peer would have been judged impossible and the
node would have bounded itself out of the network. Tightening the sampling
interval, the obvious optimisation, made it worse.

### How the allowance is computed

Each sampled header carries its `uncle_count`, which is inside what its proof
of work commits to and so cannot be overstated for a block we looked at.
Because the heights were drawn at random from a population the peer had already
fixed, those counts are a uniform sample of it, and a concentration inequality
turns them into a bound on the mean. The code uses **empirical Bernstein**:

```
mean <= mean_hat + sqrt(2 * V_hat * L / k) + 3 * R * L / k,   L = ln(3/delta)
```

with `R = UNCLE_LIST_LIMIT = 10`, `delta = 1e-9`. Empirical Bernstein rather
than Hoeffding because mainnet's uncle counts are tightly clustered against
that range of 10 — it pays for the observed *variance* in the square-root term
and relegates the range to a term in `1/k`.

Every gap bound is then multiplied by `1 + that`.

### What is and is not being claimed

Not that any particular stretch is free of uncles. A peer can hold a run of
ten-uncle blocks between two samples and no amount of sampling will see it.

What the ceiling needs is weaker: it is a bound on the **sum** over every gap,
and the allowance multiplies every gap alike, so the quantity that has to be
bounded is the population mean. A stretch running hot is paid for by the
stretches that do not. That is why the per-segment objection does not bite, and
it is also why the allowance must be applied globally rather than per gap.

### How tight is it

Against measured mainnet counts:

| samples | allowance | vs. the true 1.91 | vs. the 11.0 cap |
|---|---|---|---|
| 340 | 4.20 | 2.20× | 0.38× |
| 1,000 | 2.78 | 1.45× | 0.25× |
| 3,400 | 2.22 | 1.16× | 0.20× |

So sampling is worth doing — at 340 samples it is nearly three times tighter
than assuming ten uncles everywhere. But the gain decays slowly, because at
these counts the bound is dominated by the range term `3*R*L/k`, which does not
depend on what was observed and shrinks only as `1/k`: at `k = 340` it
contributes 1.93 of the 3.20.

### End to end

The retarget bound loosens roughly as `(1 + 1/divisor)^(N/2)` across a gap of
`N` blocks; the uncle allowance multiplies on top, and at reachable sample
counts it is the larger factor.

With 340 samples over 276,000 blocks and a divisor of 400, the ceiling sits
about **3.9× the real work in the sampled window**. That window is about 6% of
the cumulative total, the rest being exact, so against the figure a peer
actually claims the slack is about **17%**.

That is the honest number and it is not small: a peer can overstate its work by
a sixth and be judged plausible. The gate is still worth having, because the
claim an attacker needs to make is not 17% high but orders of magnitude high.
It exists to refuse a fabricated chain, not to referee a close race.

### A shape in which none of this is needed

Worth knowing while reading the rest of this document: snapshot sync already
downloads every header to genesis, so the gate is a filter protecting a cost
that is paid anyway. A sync that did the header pass first -- with uncles, no
bodies, no execution -- would know the exact cumulative difficulty and would
check a peer's offered checkpoint with an index lookup instead of all of this.

That is a design note, not a plan: `docs/header-first-sync.md`.

### The limit of sampling, and the way past it

More samples is the lever, not a different inequality — but it runs out. The
number of distinct heights a skeleton walk can ask about over the window caps
`k` in the low thousands, and with it the allowance at roughly **1.4×** the
truth. No amount of sampling closes the rest.

What closes it is **seeing the uncles** -- `BlockHeadersWithUncles`, RSKIP-698
-- because then the uncle work is not estimated at all. An uncle header carries
its own proof of work, `unclesHash` binds the list to a block whose proof of
work covers it, and the uncle rules are checkable against the trunk chain
already in hand. That costs about 10.5 GB on mainnet today.

**A header field stating the total does not close it**, and an earlier revision
of this document said it would. That was wrong. Such a field is data, not work:
a miner can mine a header with valid proof of work and write any cumulative
total into it, because the rule binding the field to its parent's value is
enforced by nodes that validate the parent's *body*. Trusting it would be worse
than the bound it replaced --

```
  honest chain claims   1.91 x its trunk work   (measured mainnet uncle rate)
  attacker claims      11.00 x its trunk work   (uncleListLimit, fabricated)
  attacker needs        1.91 / 11 = 17.4%  of the honest chain's trunk hashpower
```

-- so no field makes proving work cheaper. Work is proven by exhibiting it, and
shrinking the proof needs a different proof *system*, not another field.

## What it costs

The samples come from one peer, so the first budget is the **number of
requests** — rskj's inbound limit is 1,000 messages per minute per peer.

Each sampled height costs **one message**. Scattered heights cannot be batched:
`GetBlockHeaders(start, count, skip)` can walk a fixed stride, and the random
draw is specifically not a fixed stride. Paying one message per header is the
price of unpredictability, and it is what the cost model below turns on.

Over the window `W` above the checkpoint:

```
  sample messages = max(RANDOM_SAMPLES, W / SAMPLE_INTERVAL)   one header each
                  + W / (SKELETON_STEP * MAX_SKELETON_ENTRIES) skeleton walk
```

At today's 276,000-block window that is 513 sampled heights plus 72 skeleton
messages, about **585 messages** and **0.6 MB** — roughly thirty-five seconds
against rskj's limit. Samples need only headers, never uncles: `uncle_count` is
a header field.

## When to sample, and when to just download the window

Sampling is not always the cheaper move, and nothing in the code currently
notices when it is not.

The alternative is to download every header **and its uncles** over the window
— RSKIP-698's `BlockHeadersWithUncles` — and compute the cumulative difficulty
exactly. No ceiling, no allowance, no concentration argument. A header walk
alone cannot do this: uncle difficulty counts toward the total and uncle headers
travel only in block bodies, which is what RSKIP-698 exists to fix.

A walk batches **192 headers per message** (`MAX_HEADERS_SERVE`), against the
sampler's one. So:

```
  walk messages   = W / 192
  sample messages = max(340, W / 768)
```

### The crossover

The two meet at **W = RANDOM_SAMPLES * SKELETON_STEP = 65,280 blocks**, about
twenty-three days of chain.

Below it, `choose_samples` finds fewer available heights than `RANDOM_SAMPLES`
and returns *all* of them — it stops being a sampler. It then spends the same
number of messages as the batched walk to retrieve one hundred and ninety-second
of the data, and ends with a 4.2x bound where the walk ends with the exact
number. **In that regime the gate is strictly dominated**, and
`WALK_INSTEAD_BELOW` is where it stops running.

| window | days | sample msgs | walk msgs | walk bytes | |
|---|---|---|---|---|---|
| 40,000 | 14 | 208 | 209 | 96 MB | walk |
| 65,280 | 23 | 338 | 340 | 157 MB | walk |
| 100,000 | 35 | 349 | 521 | 240 MB | marginal |
| 276,000 | 96 | 513 | 1,438 | 663 MB | sample |

### But bytes never favour the walk

Sampling wins on bytes everywhere, by about a thousandfold — 0.6 MB against
663 MB at today's window, and even at the crossover 0.39 MB against 157 MB.

That matters because **the cost is paid per candidate peer**. Vetting is what
you do to a peer you do not yet trust, and you want to do it to several. Five
peers cost 3 MB sampled and 3.3 GB walked; the second number is larger than the
state download the whole sync exists to perform.

So the rule is not one-dimensional:

- **Window under ~65,000 blocks** — walk it. Same messages, exact total, no
  allowance. The gate buys nothing here.
- **Window over ~100,000 blocks** — sample. Bytes diverge fast and the divergence
  multiplies by the number of peers under consideration.
- **Between** — judgment. The walk buys exactness for a few hundred megabytes.

### It turns on the capability, not just the window

The walk only produces the exact number if the peer sends the uncles. From an
`rsk/62` peer — every rskj node today — the walk sums header difficulty alone,
which is a **lower** bound on the chain's work. That is worse than the gate's
upper bound, not better: see `headers.rs` `uncles_omitted`, and issue #258.
The walk does bound what it cannot count (`HeaderWalk::work_ceiling`: each
unseen uncle at most a fiftieth over the heaviest trunk block it could hang
from), so its check of the claim is sound against such a peer too; but that
check comes after the walk, so the gate still decides whether the walk is
worth its cost.

Capabilities are negotiated per peer and known before the status response is
handled, so this is decidable at run time rather than something to wait for a
network-wide upgrade on. `SnapSession::on_status` skips the gate when

```rust
peer_serves_uncles && window < WALK_INSTEAD_BELOW     // 340 * 192 = 65,280
```

and logs the reason. `peer_serves_uncles` comes from
`capabilities(peer).understands_header_uncles()`, resolved in `service.rs`
where a lookup can be awaited; the walk's own header requests are already
upgraded to `BlockHeadersWithUnclesRequest` for such a peer at the send site,
and `on_headers_with_uncles` feeds the walk exact cumulative difficulties
through `proven`.

The effect is that the gate stops running precisely where it was dominated,
against the peers that can replace it — and keeps running everywhere else.

The uncomfortable corollary: with a checkpoint refreshed each release, a node on
a current build sits in the first regime. **The gate matters least when the
checkpoint is fresh and most for nodes on stale builds** — which is where it is
least likely to have been configured.

Sampling the whole chain rather than a window would take about 34 minutes, which
is the reason the checkpoint exists at all.

## Vetting more than one peer

Not implemented today: `service.rs` builds one `SnapSession` holding one
`SamplingGate` for one peer, and on failure puts that peer in `snap_avoid` and
opens a fresh session against another. Vetting is sequential.

When it is built, **each peer gets its own independent draw.** Three reasons, in
increasing order of importance.

**The heights do not mean the same thing.** `ChainSampler::new` takes *that
peer's* head and *that peer's* skeleton. Two peers at different heads have
different windows, and if they are on different chains — which is the case being
vetted for — a given height is a different block for each. There is no shared
set to ask for.

**Sybil cost must scale with identities.** Requests go out concurrently, so an
attacker running `N` identities sees the draw as soon as the first of them is
queried. With a shared draw, all `N` then need valid proof of work only at those
same 340 heights: one set of mined headers, reused `N` times. With independent
draws they need `N` independent sets. Shared is `O(340)`; independent is
`O(340N)`.

**Do not let it become a vote.** The tempting shortcut is to ask every peer the
same heights and compare their answers. That is majority voting among peers, and
voting is exactly what sybils are cheap against. The gate judges each peer
against arithmetic and never against other peers; that property is worth
protecting deliberately.

### What may be shared: answers, not positions

If peer B's skeleton names `(h, H)` and a header with hash `H` at height `h` was
already verified from peer A, it is reusable — proof of work does not need
rechecking and the hash is what binds it. An answer cache keyed by hash is sound
and saves real work in the common case where honest peers agree.

The **draw** must still be independent per peer. Caching answers leaks no
positions; sharing positions does.

### Seeding

The draw must come from a CSPRNG seeded from the OS and never from anything a
peer can see or influence — `StdRng::from_entropy()` in `ChainSampler::new`,
which is ChaCha12.

It must also not be reused across sessions with the same peer, or a peer that
failed once learns where to be honest next time. Today that holds for free
because each retry builds a fresh session. It is incidental rather than
enforced, and it should survive anyone who later tries to "optimise" the gate by
caching a sampler.

## The three verdicts

`CheckpointVerdict`:

- **`Plausible { ceiling }`** — the claim is within what the chain could carry.
  Not proof of honesty; only that it is not arithmetically impossible.
- **`Impossible { claimed, ceiling }`** — no valid chain through the sampled
  headers carries this much work. The peer is lying.
- **`SelfExceeds`** — *this node's own chain* carries more work at the
  checkpoint height than the checkpoint allows. The checkpoint is wrong, or
  this build is not what it claims to be. **This is not a peer's fault and must
  not be charged to one**: the right response is to stop and tell the operator,
  not to pick a side.

That third verdict is the one most likely to be mishandled by a later change.
It looks like a failure and is not one.

## Where it sits in snapshot sync

`Phase::SamplingClaim` runs between `AwaitingStatus` and `VerifyingHeaders`:
bound the claim from a few hundred headers before committing to a walk that
costs hours and tens of gigabytes. A checkpoint that cannot be supported is
abandoned in seconds rather than at the end.

The walk remains the authority. The gate only decides whether the walk is worth
starting.

Note which walk that is. This one descends from the peer's claimed head to the
first block this node already holds — genesis on a fresh node, so the whole
chain, hours and tens of gigabytes. That is not the window-sized walk weighed
against sampling in *When to sample*, which covers only the blocks above the
checkpoint. The gate is cheap against the first and, below the crossover,
pointless against the second.

## Current state

Both halves run by default on mainnet.

| switch | default | |
|---|---|---|
| `--checkpoint-bound-work` | **on** | the work bound, and the sampling that gives it adversarial value |
| `--checkpoint-verify-hash` | off | requires a peer to show it is on the checkpointed chain |

`--checkpoint-bound-work` defaults on because it is the only half with any
adversarial value and, unlike the hash check, it does not ask this node to
declare which fork is canonical — that is a governance decision and stays
opt-in. `--no-checkpoint-bound-work` reaches the "no defence" corner of the
matrix.

The checkpoint itself is network-scoped: `snap_checkpoint_for(network_id)`
returns one for mainnet and `None` elsewhere, and it is passed to both the
handler and the snapshot session. Neither reads `MAINNET_CHECKPOINT` directly.
That matters more now that the switch defaults on — a hard-coded constant would
arm mainnet's view of history against every testnet and regtest peer. It would
happen to be harmless, because those chains' totals are too small to trip the
arithmetic, but by luck rather than design.

### What the gate is worth, stated plainly

The ceiling sits about **17% above the real chain** at 340 samples. A peer can
overstate its work by a sixth and be judged plausible. This is a deliberate
trade, not an oversight:

- the claim an attacker needs is orders of magnitude high, not 17% high — the
  gate exists to refuse a fabricated chain, not to referee a close race;
- raising `RANDOM_SAMPLES` tightens it slowly and runs out near 1.4x the truth,
  because the bound is dominated by a range term that shrinks only as `1/k`;
- closing the rest means seeing the uncles (RSKIP-698), not sampling harder
  and not a header field -- see *The limit of sampling* above.

## Tests

`crates/sync/src/sampler.rs`:

| Test | Pins |
|---|---|
| `an_honest_claim_passes` | the bound does not reject a real chain |
| `an_inflated_claim_is_refused` | the ceiling rejects more work than any chain could carry |
| `a_peer_that_will_not_answer_is_given_up_on` | `MISSING_SAMPLES_ALLOWED` |
| `an_honest_peer_passes_the_gate` | the same, through the gate rather than the sampler |
| `an_inflated_claim_is_rejected_by_the_gate` | the same, end to end |
| `a_claim_below_the_checkpoint_never_reaches_the_network` | the free half costs no requests |
| `a_silent_peer_is_rejected_rather_than_waited_on` | not answering is a verdict, not a stall |
| `no_verdict_before_the_window_is_covered` | the gate does not judge on partial evidence |
