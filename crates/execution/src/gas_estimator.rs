//! Single-pass gas estimation — the "exactimator".
//!
//! `eth_estimateGas` asks for the smallest gas limit at which a transaction
//! still succeeds. The obvious way to answer is to binary search: execute at
//! the cap, then halve the interval until it closes. That costs about
//! `log2(cap)` executions — roughly two dozen — and it is what this node did.
//!
//! It is not necessary. One execution at the cap already knows the answer, if
//! you record the right three things while it runs. The design is Sergio
//! Demian Lerner's, and rskj has carried it since
//! `EthModule.internalEstimateGas`:
//!
//! ```java
//! long estimatedGas = reversibleExecutionResult.getMovedRemainingGasToChild() ?
//!         reversibleExecutionResult.getGasUsed() + reversibleExecutionResult.getDeductedRefund() :
//!         reversibleExecutionResult.getMaxGasUsed();
//! if (reversibleExecutionResult.isCallWithValuePerformed()) {
//!     estimatedGas += GasCost.STIPEND_CALL;
//! }
//! ```
//!
//! ## Why the peak, and not the total
//!
//! rskj's gas counter is not monotonic. At a CALL it adds the *whole*
//! allowance handed to the callee, and when the callee returns it subtracts
//! whatever came back (`ProgramResult.refundGas` is a subtraction). So the
//! counter rises to the full commitment and falls again.
//!
//! The peak is the interesting number. A contract that calls out with a fixed
//! generous stipend -- `CALL(100000, ...)` to a callee that uses 5,000 --
//! finishes having consumed 5,000, but the caller had to *hold* 100,000 at
//! that instant or the call could not have been made. Bill the total and the
//! transaction runs out of gas; bill the peak and it does not. That is what
//! binary search discovers the slow way.
//!
//! ## Why the fallback
//!
//! When a callee is handed every last unit of the caller's remaining gas, the
//! peak stops saying anything: it is just the cap we happened to run at.
//! rskj detects that case (`calleeGas == remainingGas`) and switches to
//! `gasUsed + deductedRefund`. By then `gasUsed` is what the transaction is
//! charged, the refund already off it
//! (`TransactionExecutor.localCallFinalization`), so the sum is what was spent
//! before the refund: the gas that had to be there.
//!
//! Note this is RSK-specific and the reason the rule is this simple here: RSK
//! never adopted EIP-150's 63/64 retention, so a caller really can hand over
//! everything (see `rsk_instructions`, which overrides the CALL family to
//! `calleeGas = min(remaining, requested + stipend)`). On a chain with the
//! 63/64 rule the "all of it" case is unreachable and the detection would
//! need to compare against the retained fraction instead.
//!
//! ## The stipend
//!
//! A CALL that transfers value grants the callee a 2,300-gas stipend it did
//! not have to pay for. The caller still has to be able to cover it, so the
//! estimate carries it.
//!
//! ## What rskj counts
//!
//! The estimate is rskj's to the unit, so what it counts is counted here as
//! it counts it, each point as its release answers `eth_estimateGas` (the rpc
//! crate's `testdata/rskj_local_calls.txt`):
//!
//! - The peak is that of the transaction's own program, and it starts at the
//!   intrinsic cost, which rskj charges the program before it runs
//!   (`TransactionExecutor.go`).
//! - A CREATE spends all the gas its program has left, and what the
//!   constructor doesn't use comes back (`Program.createContract`). So the
//!   peak of a program that creates is all it was given, and the estimate is
//!   the cap, unless a call of that program took all it had left.
//! - The two flags belong to a program (`ProgramResult`). A CALL, CALLCODE,
//!   DELEGATECALL or STATICCALL sets them in the program that runs it
//!   (`VM.doCALL`), whether or not the call is then made. They pass to the
//!   program that called it only where it ends without an exception or a
//!   REVERT (`ProgramResult.merge`), and never from a constructor to the
//!   program that ran its CREATE, which sets neither.
//! - A call carries value where its CALL or CALLCODE names one. A
//!   DELEGATECALL names none, whatever value its program was called with.

use alloy_primitives::Address;
use revm::context::ContextTr;
use revm::inspector::Inspector;
use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter, InterpreterTypes,
};

/// rskj `GasCost.STIPEND_CALL`.
pub const STIPEND_CALL: u64 = 2_300;

/// What one execution has to report for the estimate to be computable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EstimateTelemetry {
    /// Gas consumed before the end-of-transaction refund -- revm's
    /// `ResultGas::spent`. rskj's `getGasUsed() + getDeductedRefund()` is the
    /// same quantity: its `getGasUsed()` is less the refund by the time an
    /// estimate reads it. Not `used()`, which is after the refund and would
    /// under-report.
    pub gas_used: u64,
    /// rskj's `maxGasUsed`: the high-water mark of the transaction's own
    /// program, from the intrinsic cost up, counting a callee's whole
    /// allowance from the moment it is handed over. 0 where no program ran.
    pub max_gas_used: u64,
    /// Some call was given every unit its caller had left, so `max_gas_used`
    /// is an artefact of the cap we ran at rather than a property of the
    /// transaction.
    pub moved_all_to_child: bool,
    /// Some call transferred value, so the callee's stipend has to be
    /// covered.
    pub call_with_value: bool,
}

impl EstimateTelemetry {
    /// The smallest gas limit this transaction is expected to succeed at.
    ///
    /// `cap` is the ceiling the caller asked about -- the block gas limit, or
    /// an explicit `gas` in the call object. The answer is clamped to it for
    /// the same reason rskj clamps: returning more than the caller can
    /// actually supply is not an estimate, it is a refusal in disguise.
    pub fn estimate(&self, cap: u64) -> u64 {
        let mut estimate: u64 = if self.moved_all_to_child {
            // rskj's `getGasUsed() + getDeductedRefund()`: what was spent
            // before the refund. It is only reached when the peak has
            // stopped meaning anything.
            self.gas_used
        } else {
            // The peak. It is never below what was spent, but for two cases
            // the inspector doesn't see, where what was spent is the whole
            // answer: a transfer to an account with no code never enters the
            // interpreter, so there is no peak to report; and the cost of
            // the code a creation leaves is charged after its last step.
            //
            // The floor has to be applied *here*, before the stipend:
            // flooring afterwards would discard the stipend whenever the
            // peak came out below the spend.
            self.max_gas_used.max(self.gas_used)
        };
        if self.call_with_value {
            estimate = estimate.saturating_add(STIPEND_CALL);
        }
        estimate.min(cap)
    }
}

/// What rskj's `ProgramResult` holds of one program for the estimate, beside
/// its gas.
#[derive(Debug, Clone, Copy, Default)]
struct ProgramFlags {
    /// One of its calls was given every unit it had left.
    moved_all_to_child: bool,
    /// One of its calls named a value.
    call_with_value: bool,
}

/// Records what `EstimateTelemetry` needs, and nothing else.
///
/// The peak is the transaction's own program's alone. rskj keeps a counter
/// per program and takes the maximum across them when a callee's result is
/// merged into its caller's, but a callee's peak is bounded by the allowance
/// its caller committed, and that commitment is already in the caller's own
/// peak. The flags are kept for every open program, as rskj keeps them, and
/// passed to the caller as rskj passes them (see the module's last section).
///
/// revm announces the transaction's own call through the `call` or `create`
/// hook exactly as it announces a nested one, so the first program opened is
/// the transaction's own.
#[derive(Debug, Default)]
pub struct EstimationInspector {
    /// The programs that are open, the transaction's own first. That one
    /// stays when it ends: its flags are the answer.
    open: Vec<ProgramFlags>,
    /// The gas limit of the transaction's own program: the transaction's,
    /// less its intrinsic cost. Learned from its first step.
    root_limit: u64,
    /// The gas left to the program that ran the last completed step.
    remaining: u64,
    /// Whether the transaction's own program has been stepped at all. A
    /// transaction that is a plain value transfer never enters the
    /// interpreter.
    stepped: bool,
    /// The most the transaction's own program had spent of `root_limit`.
    max_committed: u64,
}

impl EstimationInspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold the inspector's observations together with the figures only the
    /// finished execution knows: the transaction's gas limit, and what it
    /// spent of it before the refund.
    pub fn into_telemetry(self, gas_limit: u64, gas_used: u64) -> EstimateTelemetry {
        let own = self.open.first().copied().unwrap_or_default();
        EstimateTelemetry {
            gas_used,
            // A transaction that never ran bytecode has no peak to report;
            // its cost is entirely intrinsic, which `gas_used` already holds.
            // One that did was charged the intrinsic cost first: what the
            // transaction's limit has over its program's.
            max_gas_used: if self.stepped {
                gas_limit
                    .saturating_sub(self.root_limit)
                    .saturating_add(self.max_committed)
            } else {
                0
            },
            moved_all_to_child: own.moved_all_to_child,
            call_with_value: own.call_with_value,
        }
    }

    /// A program is being opened: the transaction's own, a callee's or a
    /// constructor's.
    fn open_program(&mut self) {
        self.open.push(ProgramFlags::default());
    }

    /// The program on top has ended. A callee's flags pass to its caller
    /// where `merges`; the transaction's own program stays.
    fn close_program(&mut self, merges: bool) {
        if self.open.len() < 2 {
            return;
        }
        let ended = self.open.pop().unwrap_or_default();
        if let (true, Some(caller)) = (merges, self.open.last_mut()) {
            caller.moved_all_to_child |= ended.moved_all_to_child;
            caller.call_with_value |= ended.call_with_value;
        }
    }
}

impl<CTX, INTR> Inspector<CTX, INTR> for EstimationInspector
where
    CTX: ContextTr,
    INTR: InterpreterTypes,
{
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // Before the opcode runs, so the limit is known even for a program
        // whose first instruction reverts.
        if self.open.len() == 1 && !self.stepped {
            self.root_limit = interp.gas.limit();
            self.stepped = true;
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        // After the opcode, which is the point that matters: a CALL has by
        // now charged both its own cost and the whole allowance it is about
        // to hand over, so this is where the commitment peaks.
        self.remaining = interp.gas.remaining();
        if self.open.len() == 1 {
            let committed = self.root_limit.saturating_sub(self.remaining);
            self.max_committed = self.max_committed.max(committed);
        }
    }

    fn call(&mut self, _context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // With a program open this is a CALL-family opcode it just ran,
        // which has charged its own cost and the callee's allowance: one that
        // left its program with nothing is rskj's `calleeGas == remainingGas`.
        // The transaction's own call sets nothing: its value is paid for by
        // the transaction and grants no stipend.
        let remaining = self.remaining;
        if let Some(caller) = self.open.last_mut() {
            caller.moved_all_to_child |= remaining == 0;
            caller.call_with_value |= inputs.transfers_value();
        }
        self.open_program();
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.close_program(outcome.result.result.is_ok());
    }

    fn create(&mut self, _context: &mut CTX, _inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        self.open_program();
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        _outcome: &mut CreateOutcome,
    ) {
        self.close_program(false);
    }
}

/// Unused, but it keeps the import honest: the inspector is generic over the
/// context and needs `Address` in scope for the trait bounds revm expects.
const _: Option<Address> = None;

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain transfer never enters the interpreter, so there is no peak to
    /// report; the floor on `gas_used` is the whole answer.
    #[test]
    fn a_plain_transfer_is_carried_by_the_floor() {
        let t = EstimateTelemetry { gas_used: 21_000, ..Default::default() };
        assert_eq!(t.estimate(10_000_000), 21_000);
    }

    /// The floor is applied before the stipend, not after. Flooring
    /// afterwards would swallow the 2,300 and return an estimate too small to
    /// execute.
    #[test]
    fn the_floor_does_not_swallow_the_stipend() {
        let t = EstimateTelemetry {
            gas_used: 30_721,
            max_gas_used: 28_000, // below the spend
            call_with_value: true,
            ..Default::default()
        };
        assert_eq!(t.estimate(10_000_000), 30_721 + STIPEND_CALL);
    }

    /// The case binary search exists for: a callee handed far more than it
    /// spends. The caller had to hold the whole allowance.
    #[test]
    fn the_peak_wins_over_the_total() {
        let t = EstimateTelemetry {
            gas_used: 26_000,      // what was actually consumed
            max_gas_used: 121_000, // what had to be available at the CALL
            ..Default::default()
        };
        assert_eq!(t.estimate(10_000_000), 121_000);
    }

    /// When everything was handed over, the peak is just the cap we ran at
    /// and says nothing; the total is the honest answer. It is what was spent
    /// before the refund, and the refund is not added to it again.
    #[test]
    fn handing_over_everything_falls_back_to_the_total() {
        let t = EstimateTelemetry {
            gas_used: 26_000,
            max_gas_used: 9_999_999, // an artefact of the cap
            moved_all_to_child: true,
            ..Default::default()
        };
        assert_eq!(t.estimate(10_000_000), 26_000);
    }

    #[test]
    fn a_value_bearing_call_carries_the_stipend() {
        let t = EstimateTelemetry {
            gas_used: 30_000,
            max_gas_used: 30_000,
            call_with_value: true,
            ..Default::default()
        };
        assert_eq!(t.estimate(10_000_000), 30_000 + STIPEND_CALL);
    }

    /// rskj clamps, and so does this: an estimate above what the caller can
    /// supply is not an estimate.
    #[test]
    fn the_estimate_is_clamped_to_the_cap() {
        let t = EstimateTelemetry {
            gas_used: 50_000,
            max_gas_used: 90_000,
            ..Default::default()
        };
        assert_eq!(t.estimate(60_000), 60_000);
    }

    /// The flags are a program's own, and pass to its caller as rskj's
    /// `ProgramResult.merge` passes them: from a callee that ended well, and
    /// from no constructor. The transaction's own program stays when it ends.
    #[test]
    fn a_programs_flags_pass_to_its_caller_as_rskjs_do() {
        let flagged = ProgramFlags {
            moved_all_to_child: true,
            call_with_value: true,
        };
        let run = |merges: bool| {
            let mut inspector = EstimationInspector::new();
            inspector.open_program();
            inspector.open_program();
            inspector.open[1] = flagged;
            inspector.close_program(merges);
            inspector.close_program(true);
            assert_eq!(
                inspector.open.len(),
                1,
                "the transaction's own program stays"
            );
            inspector.into_telemetry(100_000, 30_000)
        };
        let merged = run(true);
        assert!(merged.moved_all_to_child && merged.call_with_value);
        let dropped = run(false);
        assert!(!dropped.moved_all_to_child && !dropped.call_with_value);
        // Nothing was stepped, so there is no peak.
        assert_eq!((merged.gas_used, merged.max_gas_used), (30_000, 0));
    }
}
