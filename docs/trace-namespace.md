# The `trace_*` namespace

Call trees — what a block explorer shows as "internal transactions". Four
methods: `trace_transaction`, `trace_block`, `trace_get`, `trace_filter`.

Source of truth: rskj's `co.rsk.rpc.modules.trace` package —
`TraceModuleImpl`, `TraceTransformer`, `TraceAction`, `TraceResult`,
`ProgramSubtrace`, and the `addSubTrace` calls in
`org/ethereum/vm/program/Program.java`.

## Why it is separate from `debug_traceTransaction`

`debug_*` answers *what the VM did*, opcode by opcode.
`trace_*` answers *who called whom*. They come from the **same** inspector —
`rustock_execution::tracer::RskTracer` — so the two namespaces cannot
disagree about the same transaction; only the rendering differs. Building two
tracers would eventually produce two answers.

`trace_*` asks for `RskTracer::call_tree_only()`, which records the tree and
skips the opcode stream. That matters because `trace_block` traces every
transaction in the block; keeping `structLogs` for all of them would be tens
of megabytes of output nobody renders.

## One replay per block, not per transaction

A transaction's pre-state does not exist anywhere (see
`docs/debug-namespace.md`), so tracing means re-executing its block from the
parent's state. `trace_block` does that **once** and harvests a trace per
transaction — `RskTracer::take_trace` resets between transactions — which is
what rskj does with `ProgramTraceProcessor`. Calling the single-transaction
path in a loop would be quadratic in the block's transaction count.

The retention window is the same as `debug_*`: the parent's state must still
be in the trie, roughly the GC burial depth.

## `trace_filter` recomputes; it does not use an index

rskj's `traceFilter` loops over the block range calling `buildBlockTraces`,
which calls `blockExecutor.traceBlock` on each block. There is no trace index
in rskj anywhere. This matches that.

It is bounded the way rskj bounds it:

| bound | value | rskj |
|---|---|---|
| traces per request | 10,000 | `rpcTraceMaxTracesPerRequest` |
| early termination | once `after + count` traces are collected | `if (tracesProcessed >= totalNeeded) break` |

An index built at execution time would answer faster and would **not** match
rskj, because it could only be built from the tip forward: a node restored
from a database import would answer `trace_filter` differently from a node
that executed the same blocks itself. Two nodes disagreeing about history is
the thing this client exists to avoid.

---

# Seven places rskj's output is not what you expect

Most of these are differences from OpenEthereum/Parity, whose `trace_*` is
what tooling was written against. A client that assumes Parity semantics will
misread an RSK node — rskj's as much as this one.

## 1. Precompile calls do not appear at all

`Program.callToPrecompiledAddress` never calls `addSubTrace`. So a call to a
precompile produces **no** entry in the call tree.

On RSK that is not a footnote: **the Bridge is a precompile**
(`0x0000000000000000000000000000000001000006`). Every peg-in registration,
peg-out request and federation call is invisible to `trace_*`. An indexer
looking for peg activity in call trees will find none, and must read Bridge
events instead — which is what `crates/execution/src/bridge/events.rs` and the
Bridge event index are for.

revm reports the frame either way, so `call_end` drops it when
`was_precompile_called` is set.

## 2. A failed CREATE vanishes, and takes its subtree with it

`Program.createContract` guards the subtrace:

```java
if (programResult.getException() == null && !programResult.isRevert()) {
    getTrace().addSubTrace(ProgramSubtrace.newCreateSubtrace(…));
}
```

A reverted or halted inner CREATE leaves **nothing** in the trace — no entry,
no error, and none of the frames it opened before failing. Parity shows the
failed create with its error. A deployment that reverts therefore looks, in an
RSK trace, exactly like a deployment that never happened.

Reproduced in `RskTracer::leave`, and pinned by
`a_failed_create_leaves_no_subtrace_as_in_rskj`. A CREATE with empty init code
likewise produces nothing, for the same reason (`if (!isEmpty(programCode))`).

Note the asymmetry: a failed **CALL** *is* reported, with `error` set. Only
CREATE is dropped.

## 3. `trace_get` is not a trace-address path

Parity's `trace_get(txHash, positions)` walks `positions` down the call tree.
rskj's `TraceGetRequest` rejects more than one position outright —

```java
if (tracePositions.size() > 1) {
    throw invalidParamError("'positions' accepts only one index");
}
```

— and then indexes the **whole block's** flattened trace list:

```java
List<TransactionTrace> traces = buildBlockTraces(block);   // every tx in the block
TransactionTrace transactionTrace = traces.get(positions.get(0));
```

So `trace_get(tx, ["0x0"])` on the *second* transaction of a block returns a
trace belonging to the **first**. The transaction hash selects the block, not
the traces. Reproduced, and pinned by
`trace_get_takes_one_position_and_indexes_the_block`.

## 4. `trace_filter` addresses match transactions, not traces

Parity matches each individual trace against `fromAddress`/`toAddress`. rskj
filters `block.getTransactionsList()` by the **transaction's own** sender and
receive address, then emits every trace of the surviving transactions:

```java
txStream = txStream.filter(tx -> addresses.contains(tx.getSender(signatureCache)));
```

Two consequences. A transaction sent by a matching address contributes all its
internal calls, to addresses that match nothing. And an internal call *to* a
matching address is invisible unless the top-level transaction also matched —
which is usually the opposite of what the caller wanted.

A contract-creation transaction never matches a `toAddress` filter, because
rskj guards on `tx.getReceiveAddress().getBytes().length > 0`.

## 5. `blockNumber`, `transactionPosition` and `subtraces` are JSON numbers

Everything else in this RPC surface is a hex string. These three are Java
`long`/`int` fields serialised by Jackson, so they come out as `42`, not
`"0x2a"`. `gas`, `value`, `balance` and `gasUsed` *are* hex quantities;
`input`, `init`, `output` and `code` are `0x`-prefixed unformatted hex.

A client that assumes hex everywhere reads `blockNumber` as zero.

## 6. `result` is always present; `error` never is when there is none

rskj's `TransactionTrace` is `@JsonInclude(NON_NULL)`, but `getResult()` is
annotated `@JsonInclude(ALWAYS)`. So a failed trace carries an explicit
`"result": null` **and** an `"error"` key, while a successful one carries a
`result` object and **no** `error` key at all. Not `"error": null` — the key is
absent.

`toTrace` sets `result = null` whenever `error != null`: gas used and output
are dropped from a trace that failed.

A SUICIDE gets neither: `toTrace` skips the whole block for
`TraceType.SUICIDE`, so a suicide entry has `"result": null` and no `error`.

## 7. Addresses here are `0x`-prefixed; in `debug_*` they are not

`trace_*` renders addresses with `RskAddress.toJsonString()` — `0x` plus 40
hex digits. The `debug_*` tracer's `contractAddress` uses
`ByteUtil.toHexString(...)`, which is bare. Both are rskj's, in the same node,
and `docs/quirks-java-artifacts.md` records why (`RskAddress.toString()` is
described in rskj's own source as "a DEBUG representation").

---

## Two smaller conventions worth knowing

**DELEGATECALL swaps `from` and `to`.** `TraceTransformer.toAction`:

```java
from = (callType == DELEGATECALL) ? invoke.getOwnerAddress() : invoke.getCallerAddress();
to   = (callType == DELEGATECALL) ? codeAddress             : invoke.getOwnerAddress();
```

So a delegatecall reads as "this contract is running that contract's code",
rather than naming the frame's actual caller. Parity does the same; it is
noted here because the raw addresses the tracer records are the *unswapped*
ones, and the swap happens in the renderer.

**A plain value transfer is a subtrace.** `callToAddress` emits one even when
the target has no code, with a fresh empty `ProgramResult` — so `gasUsed` is
`0x0` and `output` is `0x`. A CALL to an EOA is therefore visible in the tree.

**The top-level trace comes from the receipt, not from a frame.** Its
`result.gasUsed` is `receipt.getGasUsed()` — the whole transaction including
the intrinsic 21,000 — while every subtrace reports its own frame's spend.
`action.gas` is the frame's gas (limit less intrinsic), which is why the
tracer records `root_gas` separately.

**…except when no `Program` was built, where `action.gas` is `0x0`.**
`TransactionExecutor.extractTrace` has two branches:

```java
if (program != null) { … program.getTrace() … }
else {
    TransferInvoke invoke = new TransferInvoke(sender, receiver, 0L, value, data);
    …
}
```

That hard-coded `0L` is what `action.gas` reports for a plain rBTC transfer
to a codeless account, for a call straight to a precompile, and for a
creation with no init code (`create()` builds a `Program` only for data that
is not empty). The tracer reproduces it by watching `initialize_interp`,
which revm fires when it builds an interpreter for a frame — rskj's
`program != null`, but for that creation, where revm builds one and rskj
does not.

The second branch sets no error and no revert flag either, so such a trace
never has an `error`, whatever became of the transaction. A call straight to
a precompile with too little gas for it fails, its receipt says so, and its
trace still carries a `result`. A transaction the Bridge runs before RSKIP136,
or free of charge for the federation, never enters the EVM here; its trace is
made the same way, as REMASC's is.

**Every RSK block ends with REMASC, and it gets a trace.** It takes the
`program == null` branch above, so `trace_block` on any mainnet block returns
one more entry than it has "real" transactions: a `call` to
`0x…01000008` with `gas: "0x0"`, no subtraces, and **no `from` key** —
`RemascTransaction.getSender()` returns `new RskAddress(new byte[20])`, the
zero address, which `toJsonString()` renders as `null` and `NON_NULL` then
drops. A consumer counting traces per block must expect it.

This is not cosmetic for `trace_block` specifically. rskj's
`buildBlockTraces` bails on the *whole block* if any transaction has no
trace:

```java
if (programTrace == null) { blockTraces.clear(); return Collections.emptyList(); }
```

so a node that skipped REMASC would return an empty list for every block.

## One place this is knowingly not rskj's

**`error` strings for halts.** rskj renders
`programResult.getException().toString()`, a Java class name such as
`org.ethereum.vm.program.Program$OutOfGasException`. There is no such class
here; the revm `InstructionResult` is reported instead. A client that displays
the string sees the same fact; one that *parses* it will not work against both
nodes. The one string that does match exactly is `"Reverted"`, which rskj
hard-codes and so does this.

Same reasoning, and same note, as `docs/debug-namespace.md`.
