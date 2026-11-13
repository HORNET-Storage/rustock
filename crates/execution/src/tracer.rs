//! A VM tracer shaped like rskj's, for `debug_traceTransaction`.
//!
//! # Why this is not go-ethereum's tracer
//!
//! geth returns `{gas, failed, returnValue, structLogs}`. rskj returns its
//! `DetailedProgramTrace`: `contractAddress`, `initStorage`, `structLogs`,
//! `result`, `error`, `reverted`, `storageSize`, `currentStorage`. Consumers
//! of an RSK node are written against the second, so that is what is built
//! here. `docs/debug-namespace.md` has the full comparison.
//!
//! Three details inside `structLogs` are rskj's and easy to get wrong:
//!
//! * **`gas` is measured before the opcode runs, `gasCost` after.** rskj calls
//!   `addOp` with the remaining gas, then `saveGasCost` sets the cost on the
//!   entry it just added. Reporting the post-execution gas instead shifts
//!   every row by one opcode.
//! * **Stack and memory are bare hex, not `0x`-prefixed**, and the stack is
//!   listed **bottom first** -- `stack[0]` is the deepest item, not the top.
//!   Memory is split into 32-byte chunks, the last one short if the memory
//!   size is not a multiple of 32.
//! * **`storage` lags by one opcode, on purpose.** rskj notes the key when it
//!   sees SSTORE or SLOAD (`storageKey = stack.peek()`) and reads its value on
//!   the *next* `addOp`, once the opcode has run. So a step's `storage` shows
//!   the effect of the step before it, and the map accumulates every key
//!   touched so far rather than describing the contract's whole storage.
//!
//! # It must not change what executes
//!
//! A tracer that alters execution is a consensus hazard, not a debugging tool.
//! Two things protect that here: the traced path is separate from block
//! processing -- nothing in `BlockProcessor` consults it -- and the storage
//! read below uses `sload_skip_cold_load`, which does not mark the slot warm.
//!
//! **That second one is defensive rather than load-bearing, and the
//! distinction is worth stating.** On Ethereum a tracer calling plain `sload`
//! would warm the slot and change EIP-2929 gas for every access after it. RSK
//! has no EIP-2929 -- `make_cfg_env` zeroes `cold_storage_cost`,
//! `warm_storage_read_cost` and the rest, which
//! `test_cfg_env_no_eip2929_cold_access_cost` pins -- so on this chain that
//! particular mistake would cost nothing. The skip is used anyway because
//! "this side effect happens to be free here" is an assumption a future RSKIP
//! could quietly invalidate, and not depending on it is free.
//!
//! It follows that `tracing_does_not_change_execution` does **not** prove the
//! tracer is side-effect free; nothing in gas could reveal a warmth change on
//! RSK. What it proves is that the traced and untraced paths agree on gas,
//! output, success and logs -- which is what catches the two setups drifting
//! apart, the likelier failure.

use alloy_primitives::{Address, U256};
use revm::bytecode::opcode::OpCode;
use revm::context::ContextTr;
use revm::context_interface::JournalTr;
use revm::inspector::{inspectors::GasInspector, Inspector};
use revm::interpreter::{
    CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, CreateScheme,
};
use revm::interpreter::{
    interpreter_types::{InputsTr, Jumps, MemoryTr, StackTr},
    Interpreter, InterpreterTypes,
};
use std::collections::BTreeMap;

/// How many steps to record before giving up on the rest.
///
/// A full trace of a large transaction is big -- tens of megabytes for a
/// contract in a loop -- and a tracer that holds every step will exhaust
/// memory on exactly the transaction someone most wants to look at. rskj caps
/// its trace through `vmTrace` config; this is the same idea with a default
/// rather than a setting.
pub const DEFAULT_MAX_STRUCT_LOGS: usize = 200_000;

/// One entry of rskj's `structLogs`, mirroring `org.ethereum.vm.trace.Op`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructLog {
    /// The opcode's name, as `OpCode.code(op).name()` renders it.
    pub op: String,
    pub pc: u64,
    pub depth: u64,
    /// Gas remaining **before** this opcode ran.
    pub gas: u64,
    /// What this opcode cost.
    pub gas_cost: u64,
    /// Bottom first, 64 hex characters each, no `0x`.
    pub stack: Vec<String>,
    /// 32-byte chunks, hex, no `0x`; the last may be shorter.
    pub memory: Vec<String>,
    /// Keys touched so far by SSTORE/SLOAD, with their values after the
    /// opcode that touched them. Both 64 hex characters, no `0x`.
    pub storage: BTreeMap<String, String>,
}

/// rskj's `DetailedProgramTrace`.
#[derive(Debug, Clone, Default)]
pub struct ProgramTrace {
    pub contract_address: String,
    pub struct_logs: Vec<StructLog>,
    /// The return data, hex, no `0x`.
    pub result: String,
    pub error: String,
    pub reverted: bool,
    pub storage_size: usize,
    pub current_storage: BTreeMap<String, String>,
    /// True when the step cap cut the trace short, so a consumer can tell a
    /// truncated trace from a short one.
    pub truncated: bool,
    /// Gas handed to the transaction's own frame -- rskj's
    /// `invoke.getGas()`, which is the transaction gas limit less the
    /// intrinsic cost, and what the top-level trace reports as `action.gas`.
    pub root_gas: u64,
    /// Whether a program ran for the transaction itself -- rskj's
    /// `program != null`. Where none did (a plain transfer, a call straight to
    /// a precompile, a creation with no init code), rskj's trace is a bare
    /// `SummarizedProgramTrace`, which `TransactionExecutor.extractTrace`
    /// gives no gas, no error and no revert, whatever became of the
    /// transaction.
    pub ran_program: bool,
    /// The transaction's call tree: rskj's `SummarizedProgramTrace.subtraces`.
    ///
    /// The transaction's own frame is **not** here. rskj renders the top-level
    /// trace from the receipt rather than from a subtrace, so what this holds
    /// is that frame's children -- the internal transactions.
    pub subtraces: Vec<Subtrace>,
}

/// What an entry of the call tree is, mirroring rskj's `TraceType`.
///
/// rskj also has `REWARD`, which it never emits from the VM -- nothing calls
/// `newRewardSubtrace` -- so it has no counterpart here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtraceKind {
    Call,
    Create,
    Suicide,
}

/// How a call frame was entered, mirroring rskj's `CallType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
}

impl CallKind {
    /// rskj renders this as `callType.name().toLowerCase()`.
    pub fn as_str(self) -> &'static str {
        match self {
            CallKind::Call => "call",
            CallKind::CallCode => "callcode",
            CallKind::DelegateCall => "delegatecall",
            CallKind::StaticCall => "staticcall",
        }
    }
}

/// One node of the call tree -- rskj's `ProgramSubtrace` plus the pieces of
/// its `InvokeData` and `ProgramResult` that the renderer needs.
///
/// The raw addresses are kept here and rskj's rendering conventions applied in
/// the RPC layer, so that the swap `toAction` makes for a DELEGATECALL (`from`
/// becomes the owner, `to` becomes the code address) lives next to the JSON it
/// explains rather than inside the tracer.
#[derive(Debug, Clone)]
pub struct Subtrace {
    pub kind: SubtraceKind,
    /// `None` for a CREATE or a SUICIDE, which rskj gives `CallType.NONE` and
    /// then omits from the JSON.
    pub call_kind: Option<CallKind>,
    /// `true` when the CREATE was a CREATE2, which rskj reports as
    /// `creationMethod`.
    pub is_create2: bool,
    /// rskj `invoke.getCallerAddress()`. For a SUICIDE this is the dying
    /// contract.
    pub caller: Address,
    /// rskj `invoke.getOwnerAddress()` -- the account whose storage the frame
    /// can write. For a CREATE that is the new contract; for a SUICIDE it is
    /// the beneficiary.
    pub owner: Address,
    /// rskj `msg.getCodeAddress()`, only meaningful for a DELEGATECALL.
    pub code_address: Option<Address>,
    /// Gas given to the frame (rskj `invoke.getGas()`).
    pub gas: u64,
    /// Gas the frame spent (rskj `programResult.getGasUsed()`).
    pub gas_used: u64,
    /// Call value, or the transferred balance for a SUICIDE.
    pub value: U256,
    /// Call data, or the init code for a CREATE.
    pub input: Vec<u8>,
    /// Return data, or the deployed code for a CREATE.
    pub output: Vec<u8>,
    /// Set only for a CREATE.
    pub created_address: Option<Address>,
    /// The halt reason, if the frame halted. rskj puts
    /// `programResult.getException().toString()` here; see
    /// `docs/trace-namespace.md` for why this string differs.
    pub error: Option<String>,
    /// rskj reports a REVERT as the literal string `"Reverted"`, which this
    /// matches exactly.
    pub reverted: bool,
    pub subtraces: Vec<Subtrace>,
}

/// Notes a value transfer that rskj reports as a CALL subtrace of a call to
/// a precompile: `BridgeSupport.transferTo` and
/// `RemascFeesPayer.transferPayment` add one for every transfer they make, a
/// zero one included.
pub fn record_precompile_transfer<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    from: Address,
    to: Address,
    value: U256,
) {
    ctx.chain_mut().precompile_transfers.push((from, to, value));
}

/// The subtraces rskj hangs under a transaction sent straight to a
/// precompile, if `success` and `to` is one that transfers: one CALL per
/// transfer it made, from the precompile to the payee, with gas 0 and an empty
/// result (`TransferInvoke(from, to, 0L, value)`,
/// `ProgramSubtrace.newCallSubtrace`). `TransactionExecutor.call` takes
/// `precompiledContract.getSubtraces()` once `execute` returns and
/// `extractTrace` hangs them under the transaction's trace; a precompile a
/// contract calls adds nothing (`Program.callToPrecompiledAddress` reads no
/// subtraces), so its transfers are dropped.
pub fn precompile_subtraces(
    to: Option<Address>,
    success: bool,
    transfers: Vec<(Address, Address, U256)>,
) -> Option<Vec<Subtrace>> {
    let to = to?;
    if !success || (to != crate::BRIDGE_ADDR && to != crate::REMASC_ADDR) {
        return None;
    }
    Some(
        transfers
            .into_iter()
            .map(|(from, to, value)| Subtrace {
                kind: SubtraceKind::Call,
                call_kind: Some(CallKind::Call),
                is_create2: false,
                caller: from,
                owner: to,
                code_address: None,
                gas: 0,
                gas_used: 0,
                value,
                input: Vec::new(),
                output: Vec::new(),
                created_address: None,
                error: None,
                reverted: false,
                subtraces: Vec::new(),
            })
            .collect(),
    )
}

/// A frame the tracer has entered and not yet left.
struct OpenFrame {
    kind: SubtraceKind,
    call_kind: Option<CallKind>,
    is_create2: bool,
    caller: Address,
    owner: Address,
    code_address: Option<Address>,
    gas: u64,
    value: U256,
    input: Vec<u8>,
    children: Vec<Subtrace>,
}

/// Records every opcode of an execution in rskj's shape.
pub struct RskTracer {
    gas_inspector: GasInspector,
    logs: Vec<StructLog>,
    /// The accumulated storage view described in the module docs.
    current_storage: BTreeMap<String, String>,
    /// Set when the previous opcode was SSTORE or SLOAD: its key, whose value
    /// is read on the next step, once that opcode has run.
    pending_storage: Option<(Address, U256)>,
    max_logs: usize,
    truncated: bool,
    /// False for `trace_*`, which wants the call tree and would be made
    /// enormous by the opcode stream. Distinct from `max_logs == 0`, which
    /// means "record steps but the budget is spent" and sets `truncated`.
    record_steps: bool,
    /// Frames entered and not yet left, innermost last. The first is the
    /// transaction's own frame, whose children are the subtraces rskj
    /// reports.
    open_frames: Vec<OpenFrame>,
    /// Completed top-level subtraces of the transaction.
    subtraces: Vec<Subtrace>,
    /// Gas given to the transaction's own frame.
    root_gas: u64,
    /// True once an interpreter has been built for the transaction's own
    /// frame -- rskj's `program != null`.
    root_has_program: bool,
}

impl Default for RskTracer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_STRUCT_LOGS)
    }
}

impl RskTracer {
    pub fn new(max_logs: usize) -> Self {
        Self {
            gas_inspector: GasInspector::new(),
            logs: Vec::new(),
            current_storage: BTreeMap::new(),
            pending_storage: None,
            max_logs,
            truncated: false,
            record_steps: true,
            open_frames: Vec::new(),
            subtraces: Vec::new(),
            root_gas: 0,
            root_has_program: false,
        }
    }

    /// A tracer for `trace_*`: the call tree, and no opcode stream.
    ///
    /// The `trace_*` namespace renders internal transactions and never reads
    /// `structLogs`. Recording them anyway would cost tens of megabytes per
    /// block for output nobody looks at, which matters because `trace_block`
    /// traces every transaction in one pass.
    pub fn call_tree_only() -> Self {
        Self { record_steps: false, ..Self::new(0) }
    }

    /// A new tracer configured like this one, with nothing recorded yet.
    ///
    /// Each parallel sublist runs with its own tracer, on its own thread.
    /// Cloning would copy the accumulated frames and logs along with the
    /// configuration, which is not what a second sublist should start from --
    /// a tracer accumulates per transaction and is drained per transaction,
    /// so starting empty is the only correct state.
    pub fn fresh_like(&self) -> Self {
        if self.record_steps {
            Self::new(self.max_logs)
        } else {
            Self::call_tree_only()
        }
    }

    /// The recorded steps and the storage view they ended with.
    pub fn finish(self) -> (Vec<StructLog>, BTreeMap<String, String>, bool) {
        (self.logs, self.current_storage, self.truncated)
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Take everything recorded for one transaction and reset for the next.
    ///
    /// `trace_block` runs one block pass and harvests per transaction, the way
    /// rskj's `ProgramTraceProcessor` collects a trace per transaction hash
    /// from a single `traceBlock` call. Re-executing the block once per
    /// transaction instead would be quadratic in the block's transaction
    /// count.
    ///
    /// `contract_address`, `result`, `error` and `reverted` are left empty:
    /// they come from the transaction's `ExecutionResult`, which the executor
    /// fills in.
    pub fn take_trace(&mut self) -> ProgramTrace {
        // A frame left open means the interpreter never returned from it,
        // which should not happen -- but dropping it silently would splice
        // its children into the wrong parent on the *next* transaction.
        self.open_frames.clear();
        let current_storage = std::mem::take(&mut self.current_storage);
        let trace = ProgramTrace {
            storage_size: current_storage.len(),
            struct_logs: std::mem::take(&mut self.logs),
            current_storage,
            truncated: self.truncated,
            subtraces: std::mem::take(&mut self.subtraces),
            // rskj `TransactionExecutor.extractTrace`: when no `Program` was
            // built -- a plain transfer, or a call straight to a precompile --
            // the trace is a `SummarizedProgramTrace(TransferInvoke(..., 0L,
            // ...))` whose gas is the literal zero, not the transaction's.
            // So `action.gas` on a plain rBTC transfer is `0x0` in rskj, and
            // reporting the real figure here would disagree with every rskj
            // node.
            root_gas: if self.root_has_program { self.root_gas } else { 0 },
            ran_program: self.root_has_program,
            ..Default::default()
        };
        self.pending_storage = None;
        self.truncated = false;
        self.root_gas = 0;
        self.root_has_program = false;
        self.gas_inspector = GasInspector::new();
        trace
    }

    /// Push a frame the interpreter is about to enter.
    fn enter(&mut self, frame: OpenFrame) {
        self.open_frames.push(frame);
    }

    /// Pop the innermost frame and file it under its parent.
    ///
    /// The outermost frame is the transaction itself, which rskj renders from
    /// the receipt rather than as a subtrace, so its children -- not the frame
    /// -- become `subtraces`.
    fn leave(&mut self, outcome: FrameOutcome) {
        let Some(frame) = self.open_frames.pop() else { return };

        if self.open_frames.is_empty() {
            // The transaction's own frame: keep its children and its gas,
            // drop the frame itself. rskj renders the top-level trace from
            // the receipt, not from a subtrace.
            self.subtraces = frame.children;
            self.root_gas = frame.gas;
            return;
        }

        let subtrace = Subtrace {
            kind: frame.kind,
            call_kind: frame.call_kind,
            is_create2: frame.is_create2,
            caller: frame.caller,
            owner: outcome.created_address.unwrap_or(frame.owner),
            code_address: frame.code_address,
            gas: frame.gas,
            gas_used: outcome.gas_used,
            value: frame.value,
            input: frame.input,
            output: outcome.output,
            created_address: outcome.created_address,
            error: outcome.error,
            reverted: outcome.reverted,
            subtraces: frame.children,
        };

        // rskj drops a CREATE that failed: `addCreateSubtrace` is guarded by
        // `programResult.getException() == null && !programResult.isRevert()`,
        // so a reverted or halted inner CREATE leaves no trace at all -- and
        // neither do the frames it opened. Reproduced here, and recorded in
        // `docs/trace-namespace.md`, because it is a real difference from
        // geth and not one a reader would guess.
        if subtrace.kind == SubtraceKind::Create
            && (subtrace.reverted || subtrace.error.is_some())
        {
            return;
        }

        if let Some(parent) = self.open_frames.last_mut() {
            parent.children.push(subtrace);
        }
    }
}

/// What a frame returned, in the pieces `leave` needs.
struct FrameOutcome {
    gas_used: u64,
    output: Vec<u8>,
    created_address: Option<Address>,
    error: Option<String>,
    reverted: bool,
}

impl FrameOutcome {
    fn of(result: &revm::interpreter::InterpreterResult, created: Option<Address>) -> Self {
        use revm::interpreter::InstructionResult;
        let reverted = result.result == InstructionResult::Revert;
        // rskj: `programResult.getException().toString()` for a halt, and the
        // literal `"Reverted"` for a revert (set by the renderer, not here).
        let error = if result.result.is_ok() || reverted {
            None
        } else {
            Some(format!("{:?}", result.result))
        };
        Self {
            gas_used: result.gas.spent(),
            output: result.output.to_vec(),
            created_address: created,
            error,
            reverted,
        }
    }
}

/// rskj renders a `DataWord` as 64 hex characters with no prefix
/// (`ByteUtil.toHexString(data)` over the full 32 bytes).
fn word_hex(v: &U256) -> String {
    hex::encode(v.to_be_bytes::<32>())
}

impl<CTX, INTR> Inspector<CTX, INTR> for RskTracer
where
    CTX: ContextTr,
    INTR: InterpreterTypes,
{
    fn initialize_interp(&mut self, _interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // Fires when revm builds an interpreter for a frame, which is rskj's
        // `program != null` but for one case: revm builds one for a creation
        // with no init code as well, where rskj's `create()` builds no
        // `Program` (`isEmpty(tx.getData())`). See `take_trace` for why that
        // matters.
        if let [root] = self.open_frames.as_slice() {
            self.root_has_program = root.kind != SubtraceKind::Create || !root.input.is_empty();
        }
    }

    fn step(&mut self, interp: &mut Interpreter<INTR>, context: &mut CTX) {
        self.gas_inspector.step(&interp.gas);

        // rskj resolves the previous SSTORE/SLOAD here, not when it saw it:
        // the value is only meaningful once that opcode has run.
        if let Some((address, key)) = self.pending_storage.take() {
            // `skip_cold_load = true`: do not warm the slot. On RSK that
            // changes no gas -- there is no EIP-2929 here -- so this is
            // defensive, not load-bearing. See the module docs.
            let value = context
                .journal_mut()
                .sload_skip_cold_load(address, key, true)
                .ok()
                .map(|loaded| loaded.data);
            match value {
                Some(v) => {
                    self.current_storage.insert(word_hex(&key), word_hex(&v));
                }
                None => {
                    self.current_storage.remove(&word_hex(&key));
                }
            }
        }

        if !self.record_steps {
            // `trace_*` wants the call tree only. Note this returns *before*
            // the SSTORE/SLOAD bookkeeping below, so `current_storage` stays
            // empty too -- which is right: nothing renders it.
            return;
        }
        if self.logs.len() >= self.max_logs {
            self.truncated = true;
            return;
        }

        let opcode = interp.bytecode.opcode();
        let stack: Vec<String> = interp.stack.data().iter().map(word_hex).collect();

        let size = interp.memory.size();
        let mut memory = Vec::with_capacity(size.div_ceil(32));
        let mut at = 0;
        while at < size {
            let end = (at + 32).min(size);
            memory.push(hex::encode(interp.memory.slice(at..end).as_ref()));
            at = end;
        }

        self.logs.push(StructLog {
            op: OpCode::new(opcode).map(|o| o.as_str().to_string()).unwrap_or_else(|| {
                // rskj's OpCode.code() returns null for an unknown byte and the
                // serializer would NPE; naming it keeps the trace readable.
                format!("UNKNOWN(0x{opcode:02x})")
            }),
            pc: interp.bytecode.pc() as u64,
            depth: context.journal_mut().depth() as u64,
            gas: interp.gas.remaining(),
            gas_cost: 0, // filled in by `step_end`
            stack,
            memory,
            storage: self.current_storage.clone(),
        });

        // SSTORE and SLOAD both take the key from the top of the stack.
        if opcode == revm::bytecode::opcode::SSTORE || opcode == revm::bytecode::opcode::SLOAD {
            if let Some(key) = interp.stack.data().last().copied() {
                let address = interp.input.target_address();
                self.pending_storage = Some((address, key));
            }
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        self.gas_inspector.step_end(&interp.gas);
        if let Some(last) = self.logs.last_mut() {
            last.gas_cost = self.gas_inspector.last_gas_cost();
        }
    }

    fn call(&mut self, _context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // rskj's `toAction` reads `invoke.getCallerAddress()` and
        // `invoke.getOwnerAddress()`; for a DELEGATECALL the owner is the
        // calling contract, which is exactly revm's `target_address`.
        self.enter(OpenFrame {
            kind: SubtraceKind::Call,
            call_kind: Some(match inputs.scheme {
                CallScheme::Call => CallKind::Call,
                CallScheme::CallCode => CallKind::CallCode,
                CallScheme::DelegateCall => CallKind::DelegateCall,
                CallScheme::StaticCall => CallKind::StaticCall,
            }),
            is_create2: false,
            caller: inputs.caller,
            owner: inputs.target_address,
            code_address: Some(inputs.bytecode_address),
            gas: inputs.gas_limit,
            value: inputs.value.get(),
            input: inputs.input.bytes(_context).to_vec(),
            children: Vec::new(),
        });
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        // rskj emits no subtrace for a precompile: `callToPrecompiledAddress`
        // never calls `addSubTrace`, so the Bridge and every other precompile
        // are invisible in a call tree. revm reports the frame either way, so
        // it is dropped here. See `docs/trace-namespace.md`.
        if outcome.was_precompile_called && self.open_frames.len() > 1 {
            self.open_frames.pop();
            return;
        }
        self.leave(FrameOutcome::of(&outcome.result, None));
    }

    fn create(&mut self, _context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        self.enter(OpenFrame {
            kind: SubtraceKind::Create,
            call_kind: None,
            is_create2: matches!(inputs.scheme(), CreateScheme::Create2 { .. }),
            caller: inputs.caller(),
            // Filled in from the outcome, which is where revm reports the
            // created address.
            owner: Address::ZERO,
            code_address: None,
            gas: inputs.gas_limit(),
            value: inputs.value(),
            input: inputs.init_code().to_vec(),
            children: Vec::new(),
        });
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        self.leave(FrameOutcome::of(&outcome.result, outcome.address));
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        // rskj builds this from `SuicideInvoke(caller = the dying contract,
        // owner = the beneficiary, value = the balance moved)`, and emits it
        // even when the balance is zero. It has no result and no gas: rskj's
        // `toTrace` skips both for `TraceType.SUICIDE`.
        let subtrace = Subtrace {
            kind: SubtraceKind::Suicide,
            call_kind: None,
            is_create2: false,
            caller: contract,
            owner: target,
            code_address: None,
            gas: 0,
            gas_used: 0,
            value,
            input: Vec::new(),
            output: Vec::new(),
            created_address: None,
            error: None,
            reverted: false,
            subtraces: Vec::new(),
        };
        if let Some(parent) = self.open_frames.last_mut() {
            parent.children.push(subtrace);
        }
    }
}
