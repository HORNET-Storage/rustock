# Single-pass gas estimation, and where its answer is not the smallest limit

`eth_estimateGas` is asked for the smallest gas limit at which a transaction
succeeds. The obvious way to answer is to binary search: execute at the cap,
then halve the interval until it closes — about two dozen executions. rskj
does not do that. It executes once and derives the answer from three things
recorded during the run, in `EthModule.internalEstimateGas`:

```java
long estimatedGas = reversibleExecutionResult.getMovedRemainingGasToChild() ?
        reversibleExecutionResult.getGasUsed() + reversibleExecutionResult.getDeductedRefund() :
        reversibleExecutionResult.getMaxGasUsed();

if (reversibleExecutionResult.isCallWithValuePerformed()) {
    estimatedGas += GasCost.STIPEND_CALL;
}
```

Rustock implements the same algorithm (`crates/execution/src/gas_estimator.rs`),
with the previous binary search retained behind
`--gas-estimator-binary-search` so the two can be compared on the same node.

Its answers are meant to be rskj's to the unit.
`crates/rpc/src/testdata/rskj_local_calls.txt` holds what rskj's release
(9.0.4) answers to a set of estimates, and the test
`a_local_call_answers_as_rskj_answers_it` asks Rustock the same and compares.

This note is about how the single-pass answer stands to the binary search's:

- §1 is **not a defect.** The single pass answers a stricter question and its
  answer is exactly minimal for that question.
- §2 is the case with a refund. The two agree there, and rskj's formula
  reads as if they wouldn't.
- §3 is a program that creates a contract, which rskj estimates at its cap.

---

## 1. The peak: a larger answer, and the right one

### What happens

A contract calls out with a fixed, generous allowance:

```
CALL(gas = 100000, callee, value = 0, ...)
```

and the callee spends almost nothing.

Measured on a regtest fixture (`setup_estimation_state` in
`crates/rpc/src/tests.rs`):

| | |
|---|---|
| total consumed | 21,721 |
| single-pass estimate | **121,721** |
| binary search | 21,721 |

### Why the single pass is right

RSK never adopted EIP-150's 63/64 retention. `rsk_instructions` overrides the
CALL family to rskj's rule:

```
calleeGas = min(remainingGas, requestedGas + STIPEND_CALL)
```

So a CALL asking for 100,000 when only 11,000 remains **does not fail** — the
callee silently receives 11,000. The transaction therefore still succeeds at a
limit far below the peak, and that is the limit binary search converges on.

But the inner call then runs on different gas than it did when the estimate
was taken. A caller that does not check the CALL's return value carries on and
does something else. Binary search has found a limit at which the transaction
*does not revert*; it has not found a limit at which the transaction *does
what it did*.

The single pass reports `maxGasUsed`, the high-water mark of the caller's
commitment. That is precisely `gasBeforeCall + 100000` — the smallest limit at
which the callee still receives the full allowance it asked for. **It is not a
conservative margin; it is the exact minimum for the stronger property.**

`gasBeforeCall` counts from the transaction's intrinsic cost: rskj charges it
to the program before the program runs (`TransactionExecutor.go`), so it is in
`maxGasUsed`. Here that is 21,000, then 21 for what the caller pushes and 700
for the CALL.

This is the behaviour worth keeping, and `the_estimate_covers_the_allowance_a_call_asks_for`
pins it, asserting both that the single pass covers the allowance and that
binary search does not. `the_exactimator_never_undercuts_binary_search` pins
the gap between the two at what the callee was handed and didn't use.

---

## 2. The refund: what was spent before it, and no more

### What happens

Take the other branch — `movedRemainingGasToChild` — and give the transaction
a storage refund. A contract that clears a slot and then calls out with `GAS`,
handing over everything it has left:

```
SSTORE(slot1, 0)                      // slot1 was non-zero: earns a refund
CALL(gas = GAS, callee, 0, ...)       // hands over all remaining gas
STOP
```

Measured on a regtest fixture (`setup_refund_state`, same file):

| | |
|---|---|
| spent before the refund | 26,726 |
| refund | 13,363  (half of that: the cap binds) |
| single-pass estimate | **26,726** |
| binary search | **26,726** |

### Why the sum is what was spent

`gasUsed + deductedRefund` reads as consumption with the refund on top, which
would be 40,089 here. It isn't, because of when it is read. A local call ends
in `TransactionExecutor.localCallFinalization`:

```java
long gasRefund = refundGas();

result.setGasUsed(getGasConsumed());
```

`refundGas()` works out the refund, records it as `deductedRefund` and adds it
to `gasLeftover`. `getGasConsumed()` is the gas limit less `gasLeftover`. So by
the time `internalEstimateGas` runs, `getGasUsed()` is what the transaction is
charged, the refund already off it, and adding `deductedRefund` gives back
what was spent before the refund.

That is the figure a limit has to cover. The refund is credited at the very
end, so it can't pay for anything before it, and it doesn't have to be held
either.

rskj's release answers accordingly. In `rskj_local_calls.txt`, the scenario
`spend`, `sstores-calls-estimate` is the estimate of a contract that stores 1
and then 0 in a cell and calls out with all its gas. Its run spends 46,731
and earns a refund of 15,000, and rskj answers 46,731.

### What Rustock did before

Rustock took `gasUsed` for the figure before the refund, which is what revm's
`spent` is, and added the refund to that: 40,089 for the fixture above, half
as high again as the transaction needs, and not rskj's answer.
`EstimateTelemetry::estimate` now answers what was spent, and
`the_refund_is_not_added_to_what_was_spent` pins it.

---

## 3. A program that creates a contract: the cap

rskj's `CREATE` and `CREATE2` spend all the gas their program has left, and
hand back what the constructor doesn't use (`Program.createContract`). They
don't set `movedRemainingGasToChild`: only the CALL family does
(`VM.doCALL`). So for a program that creates, `maxGasUsed` is all it was
given, and the estimate is the cap the estimate ran at — 6,800,000 by default,
rskj's `rpc.gasEstimationCap`.

The exception is a program of which a call also took all it had left. That
sets the flag, and the estimate is what was spent, as in §2.

And a `CREATE` that rskj refuses before it begins spends none of that gas:
one whose program holds less than the value it names. The 0 is pushed first
(`Program.createContract`), so the peak is what it was, and the estimate is
not the cap: `create-unpaid-estimate` and `calls-then-create-unpaid-estimate`,
in the scenario `below`. A creation that fails once it has begun, its
constructor reverting, has spent it: `create-reverting-estimate`.

rskj's release answers so, and so does Rustock: `creates-estimate`,
`create-creates-estimate` and `creates-then-calls-all-estimate`, in the same
scenario. Binary search finds the smallest limit instead, which is far below
the cap.

Two more things are counted as rskj counts them, and each has its answers in
that scenario:

- The 2,300 is added where a CALL or a CALLCODE names a value, in a program
  whose result reaches the transaction's own. It is not added for a
  DELEGATECALL of a program that was itself sent value, for a CREATE with an
  endowment, or for a call inside a program that then fails or reverts.
- A call that takes all its program has left switches the estimate to what
  was spent wherever it happens: in the transaction's own program, or in one
  that program calls, if that one ends without failing.

---

## Reproducing

The fixtures are regtest-only and live in `crates/rpc/src/tests.rs`:

```
cargo test -p rustock-rpc -- a_local_call_answers_as_rskj_answers_it
cargo test -p rustock-rpc -- the_estimate_covers_the_allowance_a_call_asks_for
cargo test -p rustock-rpc -- the_refund_is_not_added_to_what_was_spent
cargo test -p rustock-rpc -- the_exactimator_never_undercuts_binary_search
```

To compare the two estimators on a running node, set
`[rpc] gas_estimator_binary_search = true` (or pass
`--gas-estimator-binary-search`) and re-issue the same `eth_estimateGas`.
