//! rskj-compatible transaction handler.
//!
//! rskj never adopted EIP-158/EIP-161 account semantics: accounts are never
//! state-cleared, `addBalance(0)` CREATES trie nodes (even for zero-value
//! internal calls), and "account exists" means "present in the trie"
//! regardless of its values. revm couples those semantics to the same SpecId
//! that selects opcodes and gas tables, so running BYZANTIUM+ for the
//! instruction set silently brings spurious-dragon account rules with it —
//! mainnet #466,503 OOG'd in rustock because every internal ecrecover call
//! was charged the 25,000 new-account cost, while rskj charges it only until
//! the first call creates the 0x…01 account node.
//!
//! `RskHandler` is `MainnetHandler` with three changes:
//! - after the default `load_accounts` synchronizes the journal spec from the
//!   config, it pins the JOURNAL spec back to HOMESTEAD. The journal spec only
//!   governs account semantics (existence-based emptiness, no state clearing);
//!   the interpreter and gas tables keep the per-era spec from `CfgEnv`.
//! - created contracts keep nonce 0 (no EIP-161). revm seeds them with
//!   nonce 1 from SPURIOUS_DRAGON using the per-era `CfgEnv` spec, which
//!   shifts every address such a contract later derives via CREATE —
//!   mainnet #892,228 paid dividends to wallets created at
//!   keccak(rlp([contract, nonce])) and every recipient came out one nonce
//!   ahead of rskj's.
//! - before RSKIP453 (lovell700), an INTERNAL create whose constructor ran
//!   successfully always succeeds (rskj Program.finalizeContractCreation):
//!   if the code deposit is unpayable or the code exceeds the 0x6000 max
//!   size, the contract is left with EMPTY code, the constructor's state
//!   stays committed and the address is pushed — instead of EIP-2's
//!   out-of-gas. Mainnet #1,071,481 deploys an RNS Deed whose 944,800 gas
//!   deposit can't fit in the 600,000 tx limit; rskj deploys it codeless
//!   and the auction proceeds. Top-level deploy transactions are NOT
//!   affected (rskj TransactionExecutor.createContract throws, like EIP-2).

use revm::context::result::HaltReason;
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use revm::context_interface::{Cfg, ContextTr, JournalTr};
use revm::handler::instructions::InstructionProvider;
use revm::handler::{
    ContextTrDbError, CreateFrame, EthFrame, EvmTr, EvmTrError, FrameData, FrameInitOrResult,
    FrameResult, Handler, ItemOrResult, PrecompileProvider,
};
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::interpreter_action::FrameInit;
use revm::interpreter::{CallOutcome, CreateOutcome, Gas, InstructionResult, InterpreterAction};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address, Bytes, U256};
use revm::inspector::JournalExt;
use revm::state::EvmState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// `MainnetHandler` with rskj's eternal-frontier account semantics
/// (see module docs).
#[derive(Debug, Clone)]
pub struct RskHandler<CTX, ERROR, FRAME> {
    /// Pre-RSKIP453 (lovell700): internal creates with an unpayable code
    /// deposit deploy with empty code instead of failing.
    empty_create_on_unpayable_deposit: bool,
    /// Post-RSKIP125 (wasabi): a contract created by the CREATE/CREATE2
    /// *opcode* has its nonce bumped to 1 (`Program.createContract`). A
    /// top-level CREATE *transaction* never bumps it (`TransactionExecutor
    /// .create`), so this only applies to internal create frames.
    rskip125_active: bool,
    /// Shared with `RskPrecompileProvider`: set when a direct Bridge call
    /// hits rskj's invisible-exception path (parse failure post-RSKIP88).
    /// rskj marks the execution summary failed, so the sender gets NO
    /// leftover refund and REMASC receives gasLimit * gasPrice — while the
    /// receipt stays SUCCESS with only the spent gas (mainnet #764,123:
    /// receipt 47,408 gas, fee charged for the full 1,000,000 limit).
invisible_exception: Arc<AtomicBool>,
    /// Shared with `RskPrecompileProvider`: set when a precompile that a
    /// contract called throws before RSKIP197. rskj's
    /// `Program.executePrecompiled` lets the throw leave the VM, and
    /// `VM.steps` fails the contract that made the call, spending all its gas
    /// (testnet #808,484). The exec loop halts that contract as soon as the
    /// call's result reaches it.
    aborts_caller: Arc<AtomicBool>,
    /// Accumulate the fee instead of crediting it to the beneficiary.
    ///
    /// rskj builds every sublist executor with `postponeFeePayment = true`
    /// where a block runs as its sublists (RSKIP-144 with RSKIP-351), and
    /// settles the block's whole fee total into REMASC just before the REMASC
    /// transaction (`TransactionListExecutor.addFeesToRemascIfEnabled`). Run
    /// as one list it credits per transaction (`postponeFeePayment = false`),
    /// which is what this node always did.
    ///
    /// The end state is the same either way -- the same total reaches the
    /// same account before anything can observe it, since REMASC is the last
    /// transaction. What differs is what a transaction *earlier* in the block
    /// sees if it reads REMASC's balance.
    postpone_fees: bool,
    /// Pre-RSKIP150 (twoToThree, mainnet 2_018_000): rskj's
    /// `Program.callToPrecompiledAddress` saves a successful precompile's
    /// FULL output to the caller's memory at outOffs (`memorySave`, NOT
    /// limited by the CALL's outSize), silently extending memory without
    /// charging gas — so the caller's later memory expansions are measured
    /// from the extended size (mainnet #1,661,324: a Solidity 0.5 proxy
    /// calls BlockHeaderContract with outSize=0; rskj's RETURNDATACOPY then
    /// pays no expansion). `Some` holds the block's active precompile
    /// addresses; `None` disables the quirk (RSKIP150 active).
    pre_rskip150_precompiles: Option<Vec<Address>>,
    /// Active precompile addresses at this block, used to replicate rskj's
    /// returnDataBuffer semantics: `Program.callToAddress` resets the
    /// caller's buffer only inside `executeCode` (callee HAS code) and
    /// `callToPrecompiledAddress`; a call that executes nothing — empty-code
    /// callee, depth limit, insufficient endowment — leaves the PREVIOUS
    /// call's return data in place, where canonical EVM (EIP-211) clears it.
    /// This pre-iris quirk is disabled once RSKIP171 activates.
    active_precompiles: Vec<Address>,
    /// Post-RSKIP171 (iris300): `Program.cleanReturnDataBuffer` now resets
    /// the buffer on EVERY call that runs no new frame (empty-code callee,
    /// insufficient endowment, depth limit, precompile-out-of-gas), matching
    /// canonical EVM / revm's default EIP-211 clearing. When `true`, the
    /// buffer-preservation above is disabled (mainnet #3,616,094: a DEX
    /// router does RETURNDATASIZE right after a value transfer to an empty
    /// account — preserving the prior call's 32-byte output sent it down a
    /// different branch and out of gas).
    rskip171_active: bool,
    /// Fail a transaction as it starts to run code. rskj can't build its
    /// program's invocation from the block's header
    /// (`env::header_fits_program_invoke`), throws, and catches nothing:
    /// the block is not imported, and a miner leaves the transaction out.
    fail_programs: bool,
    /// Shared with `RskPrecompileProvider`: the precompiles that returned in
    /// this transaction, each of which rskj's `callToPrecompiledAddress`
    /// gives a storage root (`setupContract`) in the call's own track. `None`
    /// where the run applies none of them.
    called_precompiles: Option<Arc<Mutex<Vec<Address>>>>,
    /// For each frame of contract code running, innermost last: where what
    /// the precompiles called under it write outside revm's journal begins,
    /// in `RawStorage` (`frame_start`) and in `called_precompiles`. A frame
    /// that fails takes it back, as rskj rolls back the track of a call or
    /// create that reverts or fails, with what the calls under it committed
    /// into it.
    frames: Vec<(usize, usize)>,
    /// A local call: rskj's `TransactionExecutor` with `setLocalCall(true)`,
    /// which serves `eth_call` and `eth_estimateGas`
    /// (`ReversibleTransactionExecutor.reversibleExecution`). `init()` returns
    /// as soon as it has worked out the intrinsic cost, before every gate it
    /// holds a transaction of a block to: the block's gas limit, the
    /// intrinsic cost, the initcode's size, the nonce and the balance
    /// (TransactionExecutor.java:162-217). `execute()` neither bumps the
    /// nonce nor charges the gas (292-301), and `localCallFinalization`
    /// refunds nothing and pays nobody (631-673).
    local_call: bool,
    /// RSKIP136, for a local call's own call to a precompile: from it, a gas
    /// limit short of the precompile's cost and the intrinsic cost throws out
    /// of rskj's `TransactionExecutor.call` (`GasCost.subtract`, 360).
    rskip136_active: bool,
    /// Set by `validate` for a local call whose gas limit can't pay its
    /// intrinsic cost but that runs a program, which rskj's `go()` fails with
    /// all its gas as it charges that cost (455): the loop halts it as it
    /// opens.
    starved: std::cell::Cell<bool>,
    _phantom: core::marker::PhantomData<(CTX, ERROR, FRAME)>,
}

impl<CTX, ERROR, FRAME> RskHandler<CTX, ERROR, FRAME> {
    pub fn new(
        empty_create_on_unpayable_deposit: bool,
        invisible_exception: Arc<AtomicBool>,
    ) -> Self {
        Self::with_rskip125(
            empty_create_on_unpayable_deposit,
            false,
            invisible_exception,
            Arc::default(),
            None,
            Vec::new(),
            false,
        )
    }

    /// Hold the block's fees back from the beneficiary, to be settled at the
    /// REMASC transaction. See the field.
    pub fn postponing_fees(mut self, postpone: bool) -> Self {
        self.postpone_fees = postpone;
        self
    }

    /// Fail every transaction that runs code, where rskj can't build its
    /// program from the block's header. See the field.
    pub fn failing_programs(mut self, fail: bool) -> Self {
        self.fail_programs = fail;
        self
    }

    /// The list of the precompiles called, which the run applies: a frame
    /// that fails takes its calls back off it. See the field.
    pub fn with_called_precompiles(mut self, called: Arc<Mutex<Vec<Address>>>) -> Self {
        self.called_precompiles = Some(called);
        self
    }

    /// Run the transaction as a local call, as rskj runs `eth_call` and
    /// `eth_estimateGas`. See the field.
    pub fn as_local_call(mut self, local_call: bool, rskip136_active: bool) -> Self {
        self.local_call = local_call;
        self.rskip136_active = rskip136_active;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_rskip125(
        empty_create_on_unpayable_deposit: bool,
        rskip125_active: bool,
        invisible_exception: Arc<AtomicBool>,
        aborts_caller: Arc<AtomicBool>,
        pre_rskip150_precompiles: Option<Vec<Address>>,
        active_precompiles: Vec<Address>,
        rskip171_active: bool,
    ) -> Self {
        Self {
            empty_create_on_unpayable_deposit,
            rskip125_active,
            invisible_exception,
            aborts_caller,
            pre_rskip150_precompiles,
            active_precompiles,
            rskip171_active,
            // Per-transaction, as before RSKIP-144; `postponing_fees` opts in.
            postpone_fees: false,
            fail_programs: false,
            called_precompiles: None,
            frames: Vec::new(),
            local_call: false,
            rskip136_active: true,
            starved: std::cell::Cell::new(false),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<CTX, ERROR, FRAME> Default for RskHandler<CTX, ERROR, FRAME> {
    fn default() -> Self {
        Self::new(false, Arc::default())
    }
}

impl<EVM, ERROR> Handler for RskHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: EvmTr<
        // `JournalExt` is what exposes the entry log, and it is the bound
        // revm's own inspectors carry. RSKIP-144 collision tracking needs it
        // for the same reason: a write is only visible while it still stands,
        // and a revert pops the entry that recorded it. `RskChainExt` holds
        // what the precompiles write outside the journal, which a frame that
        // fails takes back too (see `frames`).
        Context: ContextTr<
            Chain = crate::raw_storage::RskChainExt,
            Journal: JournalTr<State = EvmState> + JournalExt,
        >,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
        Precompiles: PrecompileProvider<<EVM as EvmTr>::Context>,
    >,
    ERROR: EvmTrError<EVM>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    /// A transaction of a block is held to revm's gates. A local call is held
    /// to none (see `local_call`), and its intrinsic cost is worked out as for
    /// any transaction. Where its gas limit can't pay that cost, rskj throws
    /// out of `executeTransaction` if no program runs: `GasCost.subtract` in
    /// `call()` for a precompile or an account without code
    /// (TransactionExecutor.java:360, 384) and in `create()` for a creation
    /// without data (406). If a program runs, `go()` fails it with all its gas
    /// as it charges the cost (455), before it runs anything (`starved`). A
    /// precompile's account holds no code.
    fn validate(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<revm::interpreter::InitialAndFloorGas, Self::Error> {
        if !self.local_call {
            self.validate_env(evm)?;
            return self.validate_initial_tx_gas(evm);
        }
        use revm::context_interface::Transaction;
        use revm::primitives::TxKind;
        let ctx = evm.ctx();
        let mut gas = revm::context_interface::cfg::gas::calculate_initial_tx_gas_for_tx(
            ctx.tx(),
            ctx.cfg().spec().into(),
        );
        let gas_limit = ctx.tx().gas_limit();
        let starved = gas.initial_gas > gas_limit;
        if starved {
            let runs_program = match ctx.tx().kind() {
                TxKind::Create => !ctx.tx().input().is_empty(),
                TxKind::Call(to) => ctx
                    .journal_mut()
                    .load_account_with_code(to)
                    .map_err(|e| ERROR::from(e))?
                    .info
                    .code
                    .as_ref()
                    .is_some_and(|code| !code.is_empty()),
            };
            if !runs_program {
                return Err(
                    revm::context_interface::result::InvalidTransaction::CallGasCostMoreThanGasLimit {
                        gas_limit,
                        initial_gas: gas.initial_gas,
                    }
                    .into(),
                );
            }
            gas.initial_gas = gas_limit;
        }
        self.starved.set(starved);
        Ok(gas)
    }

    /// A local call's sender (see `local_call`): its nonce and balance go
    /// unchecked, as does code at its address, which rskj never refuses
    /// (revm's EIP-3607). It's charged no gas and keeps its nonce
    /// (TransactionExecutor.java:292-301). rskj moves the value with
    /// `Repository.transfer` (397, 427), which creates the sender's account
    /// and takes its balance below zero rather than fail. One here can't go
    /// below zero, so a sender short of the value is lifted to it, as revm
    /// lifts one for a simulation (`disable_balance_check`), and holds nothing
    /// where rskj's holds less than nothing.
    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<(), Self::Error> {
        if !self.local_call {
            return revm::handler::pre_execution::validate_against_state_and_deduct_caller(
                evm.ctx(),
            );
        }
        use revm::context_interface::Transaction;
        let ctx = evm.ctx();
        let (caller, value) = (ctx.tx().caller(), ctx.tx().value());
        let mut sender = ctx
            .journal_mut()
            .load_account_mut(caller)
            .map_err(|e| ERROR::from(e))?;
        sender.touch();
        if *sender.balance() < value {
            sender.set_balance(value);
        }
        Ok(())
    }

    fn load_accounts(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        // Clear any stale flag a previous tx left set.
        self.invisible_exception.store(false, Ordering::Relaxed);
        self.aborts_caller.store(false, Ordering::Relaxed);
        revm::handler::pre_execution::load_accounts::<EVM, ERROR>(evm)?;
        // The default sets the journal spec from CfgEnv; pin it back to
        // rskj's eternal frontier account semantics.
        evm.ctx().journal_mut().set_spec_id(SpecId::HOMESTEAD);
        Ok(())
    }

    /// rskj invisible exception: the sender gets NO leftover/refund back —
    /// the full upfront gasLimit * gasPrice deduction stands
    /// (TransactionExecutionSummary leftover/refund are zero when failed).
    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
    ) -> Result<(), Self::Error> {
        // A local call was charged nothing, and `localCallFinalization` hands
        // nothing back (TransactionExecutor.java:631-673).
        if self.local_call {
            return Ok(());
        }
        if self.invisible_exception.load(Ordering::Relaxed) {
            return Ok(());
        }
        revm::handler::post_execution::reimburse_caller(
            evm.ctx(),
            exec_result.gas(),
            U256::ZERO,
        )
        .map_err(From::from)
    }

    /// rskj invisible exception: REMASC (the block beneficiary) receives
    /// the FULL gasLimit * gasPrice (TransactionExecutionSummary.getFee
    /// returns calcCost(gasLimit) when failed).
    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
    ) -> Result<(), Self::Error> {
        use revm::context_interface::journaled_state::account::JournaledAccountTr;
        use revm::context_interface::{Block, Transaction};
        // A local call pays nobody (`localCallFinalization`).
        if self.local_call {
            return Ok(());
        }
        if self.postpone_fees {
            // The executor accumulates the same total and settles it at the
            // REMASC transaction, as rskj does where a block runs as its sublists.
            return Ok(());
        }
        if !self.invisible_exception.load(Ordering::Relaxed) {
            // rskj routes the WHOLE tx fee (gasUsed * gasPrice) to REMASC (the
            // block beneficiary) — RSK never adopted EIP-1559, so no base fee is
            // burned. revm's default `reward_beneficiary` subtracts the base fee
            // from the beneficiary reward at LONDON+; the lovell700+ era maps to
            // SHANGHAI (>= LONDON), so it would burn `minimumGasPrice * gasUsed`
            // (rustock maps RSK's minimumGasPrice to revm's basefee). Pay the
            // full effective-gas-price reward instead. For pre-lovell specs
            // (< LONDON) revm already does this, so the result is identical
            // there. First observed at lovell700 #7,338,024 (REMASC short by
            // basefee 23696000 * gasUsed 58749 = 1392116304000 wei).
            let ctx = evm.ctx();
            let basefee = ctx.block().basefee() as u128;
            let gas = exec_result.gas();
            let billed_gas = (gas.spent() - gas.refunded() as u64) as u128;
            let fee = ctx.tx().effective_gas_price(basefee) * billed_gas;
            let beneficiary = ctx.block().beneficiary();
            ctx.journal_mut()
                .load_account_mut(beneficiary)
                .map_err(|e| ERROR::from(e))?
                .incr_balance(U256::from(fee));
            return Ok(());
        }
        let ctx = evm.ctx();
        let basefee = ctx.block().basefee() as u128;
        let gas_limit = ctx.tx().gas_limit();
        let fee = ctx.tx().effective_gas_price(basefee) * gas_limit as u128;
        let beneficiary = ctx.block().beneficiary();
        ctx.journal_mut()
            .load_account_mut(beneficiary)
            .map_err(|e| ERROR::from(e))?
            .incr_balance(U256::from(fee));
        Ok(())
    }

    /// rskj never adopted EIP-3529: the gas-refund cap stays at gas_used/2
    /// forever, and the SSTORE-clear refund stays 15,000 (GasCost is
    /// fork-independent; TransactionExecutor always refunds `min(futureRefund,
    /// gasUsed/2)`). revm bundles EIP-3529 into LONDON+ and the lovell700+ era
    /// maps to SHANGHAI (>= LONDON), so revm's default `refund` would cap at
    /// gas_used/5. Pin it back to gas_used/2 by always passing `is_london =
    /// false`. For every pre-lovell spec (<= ISTANBUL) revm already passes
    /// false, so this is behaviour-identical there and only changes lovell700+.
    /// First observed at the lovell700 activation block #7,338,024 (a tx with
    /// SSTORE clears whose 19,687 accrued refund fit under gas_used/2 but was
    /// wrongly trimmed to gas_used/5, inflating gas_used by 4,000).
    fn refund(
        &self,
        _evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
        eip7702_refund: i64,
    ) {
        exec_result.gas_mut().record_refund(eip7702_refund);
        exec_result.gas_mut().set_final_refund(false);
    }

    /// The mainnet settlement of the transaction's gas, after one change for
    /// rskj's invisible exception (`TransactionExecutor.call`). When a
    /// precompile throws in the transaction's own call, its frame reverts, so
    /// revm hands the value back and forgets the touch. Here the transaction
    /// becomes a success that used its intrinsic gas and what the precompile
    /// asked for. `reimburse_caller` and `reward_beneficiary` charge the
    /// whole gas limit.
    fn last_frame_result(
        &mut self,
        evm: &mut Self::Evm,
        frame_result: &mut FrameResult,
    ) -> Result<(), Self::Error> {
        use revm::context_interface::Transaction;
        // A local call's own call to a precompile whose cost its gas can't
        // pay: rskj leaves out the check for a local call
        // (TransactionExecutor.java:350), and from RSKIP136 works out the
        // leftover with `GasCost.subtract` (360), which throws out of
        // `executeTransaction`. Before RSKIP136 rskj runs the precompile all
        // the same, which isn't done here.
        if self.local_call
            && self.rskip136_active
            && frame_result.interpreter_result().result == InstructionResult::PrecompileOOG
        {
            return Err(ERROR::from_string(format!(
                "a local call's gas limit of {} can't pay the precompile it calls",
                evm.ctx().tx().gas_limit()
            )));
        }
        if self.invisible_exception.load(Ordering::Relaxed) {
            frame_result.interpreter_result_mut().result = InstructionResult::Return;
        }
        let instruction_result = frame_result.interpreter_result().result;
        let gas = frame_result.gas_mut();
        let remaining = gas.remaining();
        let refunded = gas.refunded();
        // Spend the gas limit; what the transaction left comes back below.
        *gas = Gas::new_spent(evm.ctx().tx().gas_limit());
        if instruction_result.is_ok_or_revert() {
            gas.erase_cost(remaining);
        }
        if instruction_result.is_ok() {
            gas.record_refund(refunded);
        }
        Ok(())
    }

    /// The mainnet exec loop with rskj's rules added (`exec_loop`).
    fn run_exec_loop(
        &mut self,
        evm: &mut Self::Evm,
        first_frame_input: FrameInit,
    ) -> Result<FrameResult, Self::Error> {
        self.exec_loop::<Plain>(evm, first_frame_input)
    }
}

impl<EVM, ERROR> RskHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: EvmTr<
        Context: ContextTr<
            Chain = crate::raw_storage::RskChainExt,
            Journal: JournalTr<State = EvmState> + JournalExt,
        >,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
        Precompiles: PrecompileProvider<<EVM as EvmTr>::Context>,
    >,
    ERROR: EvmTrError<EVM>,
{
    /// The mainnet exec loop with rskj's rules added, among them:
    /// - immediately after a CREATE frame is initialized, reset the created
    ///   account's nonce to 0 (rskj has no EIP-161; revm seeds it to 1 from
    ///   the per-era CfgEnv spec). Must happen before the constructor runs —
    ///   addresses the new contract derives via CREATE depend on its nonce.
    /// - frames return through `rsk_frame_return`, which applies the
    ///   pre-RSKIP453 empty-deploy quirk to internal creates.
    /// - before RSKIP197, a contract whose call to a precompile threw is
    ///   halted as it takes the call's result (see `aborts_caller`).
    /// - what the precompiles called under a frame of contract code write
    ///   outside revm's journal goes back with the frame if it fails (see
    ///   `frames`).
    ///
    /// The chain's run (`run_exec_loop`) and a trace's or an estimate's
    /// (`inspect_run_exec_loop`) both run this loop. They differ only in how
    /// `D` opens and runs a frame: without the inspector's hooks or with them.
    fn exec_loop<D: FrameDriver<EVM>>(
        &mut self,
        evm: &mut EVM,
        first_frame_input: FrameInit,
    ) -> Result<FrameResult, ERROR> {
        // rskj builds a program's invocation only for a transaction that runs
        // code (`TransactionExecutor.call` and `create`); revm opens a frame
        // for a creation with no data too, which runs nothing.
        let runs_code = match &first_frame_input.frame_input {
            revm::interpreter::interpreter_action::FrameInput::Create(inputs) => {
                !inputs.init_code().is_empty()
            }
            _ => true,
        };
        if let ItemOrResult::Result(frame_result) = D::init(evm, first_frame_input)? {
            return Ok(frame_result);
        }
        if self.fail_programs && runs_code {
            return Err(ERROR::from_string(
                "rskj can't build this transaction's program: a field of the \
                 block's header is past 32 bytes"
                    .into(),
            ));
        }
        // Top-level CREATE transaction: rskj's TransactionExecutor.create never
        // bumps the nonce (even post-RSKIP125), so it stays 0.
        set_created_contract_nonce(evm, 0);
        self.open_frame(evm);
        // A local call whose gas limit can't pay its intrinsic cost (see
        // `validate`): rskj's `go()` throws as it charges the cost, before the
        // program runs, and takes back what opening it did.
        if self.starved.get() {
            evm.frame_stack()
                .get()
                .interpreter
                .halt(InstructionResult::OutOfGas);
        }

        loop {
            let call_or_result = D::run(evm, self.empty_create_on_unpayable_deposit)?;

            // Pre-RSKIP150 unbounded precompile output write, applied to the
            // caller after `frame_return_result` (see field docs).
            let mut unbounded_output: Option<(usize, Bytes)> = None;
            // rskj returnDataBuffer preservation: the caller's previous
            // return data, restored after `frame_return_result` when rskj
            // would not have touched the buffer (see field docs).
            let mut preserved_return_buffer: Option<Bytes> = None;

            let mut result = match call_or_result {
                ItemOrResult::Item(init) => {
                    if *TRACE_FRAMES {
                        trace_frame_init(&init);
                    }
                    let callee = match &init.frame_input {
                        revm::interpreter::interpreter_action::FrameInput::Call(c) => {
                            Some(c.bytecode_address)
                        }
                        _ => None,
                    };
                    // RSKIP150 lowers the call-stack limit from 1024 to 400
                    // (rskj Program.getMaxDepth); revm hard-codes 1024, so
                    // the cap is enforced here. rskj's deep checks push 0,
                    // refund the child gas, and return BEFORE any
                    // returnDataBuffer reset.
                    let rskip150_active = self.pre_rskip150_precompiles.is_none();
                    if rskip150_active && init.depth > 400 {
                        if let Some(synth) = call_too_deep_result(&init.frame_input) {
                            use revm::interpreter::interpreter_types::ReturnData;
                            preserved_return_buffer = Some(
                                evm.frame_stack()
                                    .get()
                                    .interpreter
                                    .return_data
                                    .buffer()
                                    .clone(),
                            );
                            if *TRACE_FRAMES {
                                tracing::debug!(
                                    "FRAME REJECTED CallTooDeep depth={} (RSKIP150 limit 400)",
                                    init.depth
                                );
                            }
                            // An inspector hears of the refusal as revm tells it
                            // of a frame refused at its own limit of 1024.
                            let synth = D::refuse(evm, init, synth);
                            note_attempted_writes(evm);
                            let returned = evm.frame_return_result(synth)?;
                            forget_reverted_entries(evm);
                            if let Some(result) = returned {
                                return Ok(result);
                            }
                            if let Some(buffer) = preserved_return_buffer {
                                evm.frame_stack()
                                    .get()
                                    .interpreter
                                    .return_data
                                    .set_buffer(buffer);
                            }
                            continue;
                        }
                    }
                    match D::init(evm, init)? {
                        ItemOrResult::Item(()) => {
                            // Internal CREATE/CREATE2 opcode: post-RSKIP125
                            // (wasabi) rskj's Program.createContract bumps the
                            // created contract's nonce to 1; before, it is 0.
                            let nonce = u64::from(self.rskip125_active);
                            set_created_contract_nonce(evm, nonce);
                            self.open_frame(evm);
                            continue;
                        }
                        // Do not pop the frame since no new frame was created:
                        // this is how a CALL to a precompile, an empty-code
                        // account, or a failed pre-check (depth/endowment)
                        // resolves.
                        ItemOrResult::Result(result) => {
                            if let (Some(precompiles), Some(callee), FrameResult::Call(outcome)) =
                                (&self.pre_rskip150_precompiles, callee, &result)
                            {
                                if precompiles.contains(&callee)
                                    && outcome.instruction_result().is_ok()
                                    && outcome.result.output.len() > outcome.memory_length()
                                {
                                    unbounded_output = Some((
                                        outcome.memory_start(),
                                        outcome.result.output.clone(),
                                    ));
                                }
                            }
                            // rskj: only executed code and precompile calls
                            // reset the caller's returnDataBuffer; a CALL
                            // resolved without running anything keeps the
                            // previous buffer (mainnet #2,669,886: RETURNDATASIZE
                            // after a value transfer to an empty account still
                            // reports the prior call's 32-byte output).
                            // For CREATE only the pre-checks (depth/endowment)
                            // return before rskj's reset.
                            // RSKIP171 (iris300): cleanReturnDataBuffer now
                            // fires on every no-frame call, so the pre-iris
                            // preservation is disabled and revm's EIP-211
                            // clearing stands.
                            let rskj_preserves = !self.rskip171_active
                                && match &result {
                                    FrameResult::Call(_) => callee
                                        .is_some_and(|c| !self.active_precompiles.contains(&c)),
                                    FrameResult::Create(outcome) => matches!(
                                        outcome.instruction_result(),
                                        InstructionResult::CallTooDeep
                                            | InstructionResult::OutOfFunds
                                    ),
                                };
                            if rskj_preserves {
                                use revm::interpreter::interpreter_types::ReturnData;
                                preserved_return_buffer = Some(
                                    evm.frame_stack()
                                        .get()
                                        .interpreter
                                        .return_data
                                        .buffer()
                                        .clone(),
                                );
                            }
                            result
                        }
                    }
                }
                // A frame of contract code ended, having committed exactly
                // when its result is ok (`rsk_frame_return`).
                ItemOrResult::Result(result) => {
                    self.close_frame(evm, result.instruction_result().is_ok());
                    result
                }
            };
            if *TRACE_FRAMES {
                tracing::debug!(
                    "FRAME RESULT {:?} gas_remaining={} gas_spent={}",
                    result.instruction_result(),
                    result.gas().remaining(),
                    result.gas().spent(),
                );
            }

            // rskj `Program.finalizeContractCreation` (the internal CREATE/CREATE2
            // success path) propagates only `logInfos` and `deleteAccounts` from a
            // constructor to the parent result — it never propagates `futureRefund`,
            // unlike the CALL path's full `ProgramResult.merge`. So any gas refund
            // accrued inside a nested constructor (its own SSTORE clears plus any
            // refunds its sub-calls merged up) is DISCARDED. The top-level create
            // *transaction* keeps its refund (TransactionExecutor reads the program's
            // futureRefund directly), so this only applies to nested creates
            // (depth > 0). revm propagates the refund unconditionally; drop it here
            // before it merges into the caller (#6,362,186).
            if let FrameResult::Create(outcome) = &mut result {
                if evm.frame_stack().get().depth > 0 {
                    outcome.result.gas.set_refund(0);
                }
            }
            // RSKIP-144: a frame that fails is about to have its journal
            // entries popped, so the writes it attempted are read off here
            // while they still stand.
            note_attempted_writes(evm);
            let returned = evm.frame_return_result(result)?;
            forget_reverted_entries(evm);
            if let Some(result) = returned {
                return Ok(result);
            }
            if let Some((mem_start, output)) = unbounded_output {
                write_unbounded_precompile_output(evm, mem_start, &output);
            }
            if let Some(buffer) = preserved_return_buffer {
                use revm::interpreter::interpreter_types::ReturnData;
                // Undo revm's insert_call_outcome buffer clear (EIP-211).
                evm.frame_stack().get().interpreter.return_data.set_buffer(buffer);
            }
            // The precompile this contract just called threw before RSKIP197:
            // the contract stops here, its gas spent and its changes undone,
            // as rskj's `VM.steps` stops it.
            if self.aborts_caller.swap(false, Ordering::Relaxed) {
                evm.frame_stack()
                    .get()
                    .interpreter
                    .halt(InstructionResult::PrecompileError);
            }
        }
    }
}

/// How `exec_loop` opens and runs a frame. The chain's run does it plainly;
/// a trace's or an estimate's does it as revm's `inspect_run_exec_loop` does,
/// telling the inspector of every frame that starts or ends and of every
/// step. Every rule rskj's VM keeps in the loop is the loop's, the same for
/// both.
trait FrameDriver<EVM: EvmTr<Frame = EthFrame<EthInterpreter>>> {
    /// `EvmTr::frame_init`: a frame opened, or a result reached without one.
    fn init(
        evm: &mut EVM,
        init: FrameInit,
    ) -> Result<ItemOrResult<(), FrameResult>, revm::handler::evm::ContextDbError<EVM::Context>>;
    /// Runs the top frame until it asks for another or returns.
    fn run(
        evm: &mut EVM,
        empty_create_on_unpayable_deposit: bool,
    ) -> Result<FrameInitOrResult<EthFrame<EthInterpreter>>, ContextTrDbError<EVM::Context>>;
    /// A frame the loop refuses itself (RSKIP150's depth), with the result
    /// revm gives a frame it refuses at its own limit.
    fn refuse(evm: &mut EVM, init: FrameInit, refused: FrameResult) -> FrameResult;
}

/// The chain's run: no inspector.
struct Plain;

impl<EVM> FrameDriver<EVM> for Plain
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
    >,
{
    fn init(
        evm: &mut EVM,
        init: FrameInit,
    ) -> Result<ItemOrResult<(), FrameResult>, revm::handler::evm::ContextDbError<EVM::Context>>
    {
        Ok(evm.frame_init(init)?.map_item(|_| ()))
    }

    fn run(
        evm: &mut EVM,
        empty_create_on_unpayable_deposit: bool,
    ) -> Result<FrameInitOrResult<EthFrame<EthInterpreter>>, ContextTrDbError<EVM::Context>> {
        rsk_frame_run(evm, empty_create_on_unpayable_deposit)
    }

    fn refuse(_evm: &mut EVM, _init: FrameInit, refused: FrameResult) -> FrameResult {
        refused
    }
}

/// A trace's or an estimate's run: the inspector is told what revm's
/// `inspect_frame_init` and `inspect_frame_run` tell it.
struct Inspected;

impl<EVM> FrameDriver<EVM> for Inspected
where
    EVM: revm::inspector::InspectorEvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
    >,
{
    fn init(
        evm: &mut EVM,
        init: FrameInit,
    ) -> Result<ItemOrResult<(), FrameResult>, revm::handler::evm::ContextDbError<EVM::Context>>
    {
        Ok(evm.inspect_frame_init(init)?.map_item(|_| ()))
    }

    fn run(
        evm: &mut EVM,
        empty_create_on_unpayable_deposit: bool,
    ) -> Result<FrameInitOrResult<EthFrame<EthInterpreter>>, ContextTrDbError<EVM::Context>> {
        use revm::inspector::handler::frame_end;
        use revm::inspector::inspect_instructions;
        use revm::interpreter::interpreter_types::LoopControl;
        let (ctx, inspector, frame, instructions) = evm.ctx_inspector_frame_instructions();
        // A frame the loop halted as it took a call's result (a precompile
        // it called threw before RSKIP197) runs no instruction more, and the
        // inspector is told of none: rskj's VM stops it at the CALL.
        let action = if frame.interpreter.bytecode.is_end() {
            frame.interpreter.take_next_action()
        } else {
            inspect_instructions(
                ctx,
                &mut frame.interpreter,
                &mut *inspector,
                instructions.instruction_table(),
            )
        };
        let mut result = rsk_frame_return(ctx, frame, action, empty_create_on_unpayable_deposit);
        if let ItemOrResult::Result(frame_result) = &mut result {
            frame_end(ctx, inspector, &frame.input, frame_result);
        }
        Ok(result)
    }

    fn refuse(evm: &mut EVM, mut init: FrameInit, refused: FrameResult) -> FrameResult {
        use revm::inspector::handler::{frame_end, frame_start};
        let (ctx, inspector) = evm.ctx_inspector();
        let mut result = frame_start(ctx, inspector, &mut init.frame_input).unwrap_or(refused);
        frame_end(ctx, inspector, &init.frame_input, &mut result);
        result
    }
}

impl<EVM, ERROR> RskHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: EvmTr<Context: crate::RskContextTr>,
{
    /// A frame of contract code opens (see `frames`).
    fn open_frame(&mut self, evm: &mut EVM) {
        let raw = evm.ctx().chain().raw_storage.frame_start();
        let called = self
            .called_precompiles
            .as_ref()
            .and_then(|list| list.lock().ok().map(|list| list.len()))
            .unwrap_or_default();
        self.frames.push((raw, called));
    }

    /// The innermost frame of contract code ends, having `committed` or not.
    /// One that didn't takes back what the precompiles called under it wrote
    /// outside revm's journal (see `frames`).
    fn close_frame(&mut self, evm: &mut EVM, committed: bool) {
        let Some((raw, called)) = self.frames.pop() else {
            return;
        };
        if committed {
            return;
        }
        evm.ctx().chain_mut().raw_storage.revert_frame(raw);
        if let Some(Ok(mut list)) = self.called_precompiles.as_ref().map(|list| list.lock()) {
            list.truncate(called);
        }
    }
}

/// Hands the journal's entries to the RSKIP-144 collision tracker.
///
/// Called immediately before every point that can revert a checkpoint. Under
/// the deployed write semantics a reverted write still counts, and revm
/// records a write by pushing an entry and undoes it by popping that entry,
/// so this is the last moment the write exists.
///
/// Inert unless a block declared sublist edges *and* attempted writes are
/// being collected, which is a thread-local load on a path that is otherwise
/// untouched.
fn note_attempted_writes<EVM>(evm: &mut EVM)
where
    EVM: EvmTr<Context: ContextTr<Journal: JournalTr<State = EvmState> + JournalExt>>,
{
    if !crate::collision::records_attempted_writes() {
        return;
    }
    let journal = evm.ctx().journal_mut();
    crate::collision::note_journal_entries(journal.journal(), journal.evm_state());
}

/// Pulls the tracker's entry mark back down to what survived the revert, so
/// entries appended afterwards are read exactly once.
fn forget_reverted_entries<EVM>(evm: &mut EVM)
where
    EVM: EvmTr<Context: ContextTr<Journal: JournalTr<State = EvmState> + JournalExt>>,
{
    if !crate::collision::records_attempted_writes() {
        return;
    }
    let len = evm.ctx().journal_mut().journal().len();
    crate::collision::forget_entries_above(len);
}

/// `EvmTr::frame_run` with the create-return path replaced by
/// `rsk_return_create` (same shape as revm's default implementation).
fn rsk_frame_run<EVM>(
    evm: &mut EVM,
    empty_create_on_unpayable_deposit: bool,
) -> Result<FrameInitOrResult<EthFrame<EthInterpreter>>, ContextTrDbError<EVM::Context>>
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
    >,
{
    let (ctx, instructions, _precompiles, frame_stack) = evm.all_mut();
    let frame = frame_stack.get();

    let action = frame
        .interpreter
        .run_plain(instructions.instruction_table(), ctx);

    Ok(rsk_frame_return(
        ctx,
        frame,
        action,
        empty_create_on_unpayable_deposit,
    ))
}

/// `EthFrame::process_next_action` with the create-return path replaced by
/// `rsk_return_create`: what a frame's run ends in, a frame to open or the
/// frame's result, the frame marked finished once it has one. The chain's
/// run and an inspected one share it.
fn rsk_frame_return<CTX>(
    ctx: &mut CTX,
    frame: &mut EthFrame<EthInterpreter>,
    action: InterpreterAction,
    empty_create_on_unpayable_deposit: bool,
) -> FrameInitOrResult<EthFrame<EthInterpreter>>
where
    CTX: ContextTr<Journal: JournalTr<State = EvmState>>,
{
    let mut interpreter_result = match action {
        InterpreterAction::NewFrame(frame_input) => {
            return ItemOrResult::Item(FrameInit {
                frame_input,
                depth: frame.depth + 1,
                memory: frame.interpreter.memory.new_child_context(),
            });
        }
        InterpreterAction::Return(result) => result,
    };

    let result = match &frame.data {
        FrameData::Call(call) => {
            if interpreter_result.result.is_ok() {
                ctx.journal_mut().checkpoint_commit();
            } else {
                ctx.journal_mut().checkpoint_revert(frame.checkpoint);
            }
            ItemOrResult::Result(FrameResult::Call(CallOutcome::new(
                interpreter_result,
                call.return_memory_range.clone(),
            )))
        }
        FrameData::Create(create) => {
            // The empty-deploy quirk applies only to INTERNAL creates
            // (depth > 0); top-level deploy transactions fail like EIP-2
            // in rskj too.
            if empty_create_on_unpayable_deposit && frame.depth > 0 {
                rsk_return_create(
                    ctx,
                    frame.checkpoint,
                    &mut interpreter_result,
                    create.created_address,
                );
            } else {
                let (cfg, journal) = ctx.cfg_journal_mut();
                revm::handler::return_create(
                    journal,
                    cfg,
                    frame.checkpoint,
                    &mut interpreter_result,
                    create.created_address,
                );
            }
            ItemOrResult::Result(FrameResult::Create(CreateOutcome::new(
                interpreter_result,
                Some(create.created_address),
            )))
        }
    };
    frame.set_finished(true);
    result
}

/// rskj `Program.finalizeContractCreation` before RSKIP453: a constructor
/// that ran successfully always deploys. An unpayable code deposit or
/// over-max-size code (0x6000, rskj Constants.MAX_CONTRACT_SIZE) leaves the
/// contract with EMPTY code — without charging the deposit — while the
/// constructor's state changes stay committed and the address is returned.
fn rsk_return_create<CTX: ContextTr>(
    ctx: &mut CTX,
    checkpoint: revm::context_interface::journaled_state::JournalCheckpoint,
    interpreter_result: &mut revm::interpreter::InterpreterResult,
    address: Address,
) {
    let (cfg, journal) = ctx.cfg_journal_mut();
    if !interpreter_result.result.is_ok() {
        journal.checkpoint_revert(checkpoint);
        return;
    }

    let code_len = interpreter_result.output.len();
    let oversize = code_len > cfg.max_code_size();
    let deposit = cfg.gas_params().code_deposit_cost(code_len);
    // Short-circuit keeps the deposit uncharged in the oversize case, like
    // rskj (the exception set by either check skips spendGas + saveCode).
    if oversize || !interpreter_result.gas.record_cost(deposit) {
        interpreter_result.output = Bytes::new();
    }

    journal.checkpoint_commit();
    journal.set_code(
        address,
        revm::state::Bytecode::new_legacy(interpreter_result.output.clone()),
    );
    interpreter_result.result = InstructionResult::Return;
}

/// Divergence-hunt diagnostic (env-gated): log every sub-frame's input and
/// result during execution.
static TRACE_FRAMES: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var_os("RUSTOCK_TRACE_FRAMES").is_some());

fn trace_frame_init(init: &FrameInit) {
    use revm::interpreter::interpreter_action::FrameInput;
    match &init.frame_input {
        FrameInput::Call(c) => tracing::debug!(
            "FRAME CALL depth={} target={} caller={} scheme={:?} gas_limit={} input_len={}",
            init.depth,
            c.target_address,
            c.caller,
            c.scheme,
            c.gas_limit,
            c.input.len(),
        ),
        FrameInput::Create(c) => tracing::debug!(
            "FRAME CREATE depth={} caller={} scheme={:?} gas_limit={}",
            init.depth,
            c.caller(),
            c.scheme(),
            c.gas_limit(),
        ),
        FrameInput::Empty => {}
    }
}

/// Synthesize the CallTooDeep rejection revm would produce at its own
/// depth limit: the child's full gas refunded, empty output (rskj
/// stackPushZero + refundGas at the Program deep checks).
fn call_too_deep_result(
    frame_input: &revm::interpreter::interpreter_action::FrameInput,
) -> Option<FrameResult> {
    use revm::interpreter::interpreter_action::FrameInput;
    use revm::interpreter::{Gas, InterpreterResult};
    let interp_result = |gas_limit: u64| InterpreterResult {
        result: InstructionResult::CallTooDeep,
        gas: Gas::new(gas_limit),
        output: Bytes::new(),
    };
    match frame_input {
        FrameInput::Call(c) => Some(FrameResult::Call(CallOutcome::new(
            interp_result(c.gas_limit),
            c.return_memory_offset.clone(),
        ))),
        FrameInput::Create(c) => Some(FrameResult::Create(CreateOutcome::new(
            interp_result(c.gas_limit()),
            None,
        ))),
        FrameInput::Empty => None,
    }
}

/// If the top (just-initialized) frame is a CREATE frame, reset the created
/// account's nonce to 0. On revert the AccountCreated journal entry discards
/// the account wholesale, so no extra journaling is needed.
/// Pre-RSKIP150 `Program.memorySave(outOffs, out)`: write a successful
/// precompile's FULL output into the caller's memory, extending it
/// word-aligned WITHOUT charging gas (rskj `Memory.extend` grows the
/// gas-visible softSize for free on this path). The extended size is
/// recorded in the caller's `MemoryGas` so later expansions are priced
/// from it, exactly like rskj's `calcMemGas(oldMemSize, ...)`.
fn write_unbounded_precompile_output<EVM>(evm: &mut EVM, mem_start: usize, output: &[u8])
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
    >,
{
    let gas_params = evm.ctx().cfg().gas_params().clone();
    let frame = evm.frame_stack().get();
    let interpreter = &mut frame.interpreter;
    let Some(end) = mem_start.checked_add(output.len()) else {
        return;
    };
    let new_words = end.div_ceil(32);
    if new_words > interpreter.gas.memory().words_num {
        interpreter.memory.resize(new_words * 32);
        let cost = gas_params.memory_cost(new_words);
        // Record the new size as already paid for; nothing is charged.
        let _ = interpreter.gas.memory_mut().set_words_num(new_words, cost);
    }
    interpreter.memory.set(mem_start, output);
}

fn set_created_contract_nonce<EVM>(evm: &mut EVM, nonce: u64)
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
    >,
{
    let FrameData::Create(CreateFrame { created_address }) = evm.frame_stack().get().data else {
        return;
    };
    if let Ok(mut acc) = evm.ctx().journal_mut().load_account_mut(created_address) {
        acc.set_nonce(nonce);
    }
}

/// Inspection support, for `debug_traceTransaction`, the `trace_*` methods,
/// a traced block's replay and `eth_estimateGas`.
///
/// `inspect_run` mirrors `Handler::run` while driving the inspector's `step`
/// / `call` / `create` hooks, and calls this handler's methods -- all but the
/// loop, which revm defaults to its own mainnet loop. That loop would leave
/// out every rule rskj's VM keeps there: RSKIP150's depth of 400, a created
/// contract's nonce, the empty deploy before RSKIP453, a precompile's whole
/// output before RSKIP150, the return-data buffer before RSKIP171, a nested
/// constructor's refund, RSKIP-144's attempted writes, the halt of a
/// precompile's caller before RSKIP197, and a failed frame taking back what
/// its precompiles wrote. So `inspect_run_exec_loop` runs `exec_loop`, the
/// loop the chain runs, with the inspector told of each frame and step.
///
/// That matters more than the convenience: a tracer describing a different
/// execution from the one the chain performed is worse than no tracer, an
/// estimate of one is no estimate, and a traced block's replay would drift
/// from the chain after the traced transaction.
impl<EVM, ERROR> revm::inspector::InspectorHandler for RskHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: revm::inspector::InspectorEvmTr<
        Context: ContextTr<
            Chain = crate::raw_storage::RskChainExt,
            Journal: JournalTr<State = EvmState>,
        >,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
        Precompiles: PrecompileProvider<<EVM as EvmTr>::Context>,
        Inspector: revm::inspector::Inspector<<EVM as EvmTr>::Context, EthInterpreter>,
    >,
    ERROR: EvmTrError<EVM>,
{
    type IT = EthInterpreter;

    fn inspect_run_exec_loop(
        &mut self,
        evm: &mut Self::Evm,
        first_frame_input: FrameInit,
    ) -> Result<FrameResult, Self::Error> {
        self.exec_loop::<Inspected>(evm, first_frame_input)
    }
}
