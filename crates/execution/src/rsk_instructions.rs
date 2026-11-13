//! rskj-compatible CALL-family instruction overrides.
//!
//! rskj's VM (org.ethereum.vm.VM/Program) never adopted Ethereum's CALL gas
//! forwarding rules, at any era:
//!
//! - `calleeGas = min(remainingGas, requestedGas + STIPEND_CALL)` — the 2300
//!   stipend on value transfers is ADDED to the requested gas and CHARGED to
//!   the caller (canonical EVM conjures the stipend for free, so an unused
//!   stipend effectively refunds 2300 to the caller — mainnet block #356,285
//!   exposed the 2300 difference on a `transfer()` to an EOA).
//! - There is no EIP-150 63/64 retention: a request larger than the remaining
//!   gas is capped at the remaining gas instead of erroring or retaining 1/64.
//! - `NEW_ACCT_CALL` (25,000) is charged for op CALL whenever the callee does
//!   not exist, regardless of value and era (frontier style; EIP-161's
//!   value>0 condition never applied).
//!
//! CREATE/CREATE2 forward all remaining gas in rskj (`Program.createContract`
//! spends `getRemainingGas()` into the child); that is handled by overriding
//! the `call_stipend_reduction` gas param (see `make_cfg_env`) rather than a
//! custom instruction.

use revm::bytecode::opcode;
use revm::handler::instructions::EthInstructions;
use revm::interpreter::instructions::contract::load_account_delegated_handle_error;
use revm::interpreter::interpreter_types::{InputsTr, InterpreterTypes, LoopControl, MemoryTr, RuntimeFlag, StackTr};
use revm::interpreter::{
    CallInput, CallInputs, CallScheme, CallValue, FrameInput, Host, Instruction,
    InstructionContext, InstructionResult, InterpreterAction,
};
use revm::context_interface::host::LoadError;
use revm::primitives::{Address, B256, U256};

/// rskj `GasCost.CALL`: static cost of every CALL-family opcode.
const CALL_STATIC_GAS: u64 = 700;

/// rskj `GasCost.EXT_CODE_SIZE` (== revm's pre-Berlin EXTCODESIZE), EIP-150.
const EXT_CODE_SIZE_GAS: u64 = 700;

/// rskj `GasCost.EXT_CODE_COPY` (== revm's pre-Berlin EXTCODECOPY base), EIP-150.
const EXT_CODE_COPY_GAS: u64 = 700;

/// rskj `GasCost.SLOAD`: fork-independent (RSK never took EIP-1884's 800).
const SLOAD_GAS: u64 = 200;

/// rskj `GasCost.BALANCE`: fork-independent (RSK never took EIP-1884's 700).
const BALANCE_GAS: u64 = 400;

/// rskj `GasCost.SUICIDE`: static cost of SELFDESTRUCT (EIP-150 onward, which
/// is always active for RSK eras). Mirrors revm's TANGERINE+ static gas.
const SUICIDE_STATIC_GAS: u64 = 5000;

/// rskj `OpCodes.OP_DUPN`, `OP_SWAPN` and `OP_TXINDEX`: RSK's own opcodes,
/// which RSKIP191 (iris300) removed. Not revm's `DUPN` and `SWAPN` (EIP-8024,
/// 0xe6 and 0xe7), which rskj doesn't have.
const RSK_DUPN: u8 = 0xa8;
const RSK_SWAPN: u8 = 0xa9;
const RSK_TXINDEX: u8 = 0xaa;

thread_local! {
    /// Addresses for which EXTCODESIZE must report `2^256-1` (rskj RSKIP90:
    /// `VM.doCODESIZE` returns `DataWord.MAX_VALUE` for any active precompile).
    /// Set by `install` for the block being executed (single-threaded).
    static EXTCODESIZE_MAX_PRECOMPILES: core::cell::RefCell<Vec<Address>> =
        const { core::cell::RefCell::new(Vec::new()) };
    /// Active precompiles for which EXTCODEHASH must report `keccak256("")`
    /// (rskj `VM.doEXTCODEHASH` precompile branch). Set by `install`.
    static EXTCODEHASH_PRECOMPILES: core::cell::RefCell<Vec<Address>> =
        const { core::cell::RefCell::new(Vec::new()) };
    /// RSKIP169: whether EXTCODEHASH answers a contract whose code key holds
    /// nothing with `keccak256("")` (`getCodeHashStandard`), or with 0 as
    /// before it (`getCodeHashNonStandard`). Set by `install`.
    static EXTCODEHASH_STANDARD: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
    /// The block's real miner address (`header.getCoinbase()`), pushed by the
    /// COINBASE opcode. rustock sets `block.beneficiary = REMASC_ADDR` so revm
    /// routes gas fees to REMASC; that would make COINBASE return REMASC, but
    /// rskj's `OpCode.COINBASE` returns the actual miner. Set by `install`.
    static REAL_COINBASE: core::cell::Cell<Address> =
        const { core::cell::Cell::new(Address::ZERO) };
    /// The block's gas limit and minimum gas price, whole, which GASLIMIT and
    /// BASEFEE push. rskj's program holds each in a `DataWord`
    /// (`ProgramInvokeImpl`), where revm's block holds a `u64`. Set by
    /// `install`.
    static GAS_LIMIT: core::cell::Cell<U256> = const { core::cell::Cell::new(U256::ZERO) };
    static MINIMUM_GAS_PRICE: core::cell::Cell<U256> =
        const { core::cell::Cell::new(U256::ZERO) };
    /// Whether [`install`] has run on *this* thread.
    ///
    /// The entries above are consensus configuration living in thread-local
    /// storage, and an unset one reads as a perfectly plausible value: no
    /// precompile gets RSKIP90's `EXTCODESIZE`, no precompile gets the
    /// empty-code `EXTCODEHASH`, and `COINBASE`, `GASLIMIT` and `BASEFEE`
    /// push `0x0`. When RSKIP-144 sublists began running on worker threads,
    /// configuring on one thread and executing on another would have
    /// produced a state root no other node reaches, with nothing failing to
    /// compile and no test noticing.
    ///
    /// So the rule is that an EVM is configured on the thread that will use
    /// it, and this is what lets the rule be checked instead of trusted.
    static CONFIGURED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// What the block's header gives the opcodes that read it, as rskj's
/// program holds it (`ProgramInvokeImpl`).
#[derive(Clone, Copy, Debug)]
pub struct BlockWords {
    /// COINBASE's: the block's real miner (see `REAL_COINBASE`).
    pub coinbase: Address,
    /// GASLIMIT's: the gas limit's whole value.
    pub gas_limit: U256,
    /// BASEFEE's: the minimum gas price's whole value.
    pub minimum_gas_price: U256,
}

impl BlockWords {
    /// The words `header` gives. Past 32 bytes no program runs at all (see
    /// `env::header_fits_program_invoke`), so none needs more.
    pub fn of(header: &rustock_core::Header) -> Self {
        Self {
            coinbase: header.beneficiary,
            gas_limit: header.gas_limit,
            minimum_gas_price: header.minimum_gas_price,
        }
    }
}

/// Whether this thread has had an instruction table installed on it.
///
/// Callers that build an EVM on one thread and run it on another are the
/// hazard; see `CONFIGURED`.
pub fn is_configured_on_this_thread() -> bool {
    CONFIGURED.with(|c| c.get())
}

/// Panics in debug builds when consensus configuration is read on a thread
/// that never had [`install`] run on it.
#[inline]
fn assert_configured(what: &str) {
    debug_assert!(
        is_configured_on_this_thread(),
        "{what} was read on a thread where `rsk_instructions::install` never ran:          the value is the thread-local default, not this block's configuration.          An EVM must be configured on the thread that executes it."
    );
}

thread_local! {
    /// The index in its block of the transaction being executed, which
    /// TXINDEX pushes before RSKIP191. rskj counts a block's transactions
    /// from 0 (`BlockExecutor.executeInternal`), and a call a transaction
    /// makes sees the transaction's index (`ProgramInvokeFactoryImpl` passes
    /// it on). [`install`] sets it to 0, and a block sets each transaction's
    /// with [`set_transaction_index`].
    static TX_INDEX: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Sets the index TXINDEX pushes for the transaction about to run on this
/// thread: its place in its block, counted from 0. See `TX_INDEX`.
pub fn set_transaction_index(index: u64) {
    TX_INDEX.with(|i| i.set(index));
}

/// Install the rskj-semantics CALL family into an instruction table.
///
/// `extcodehash_enabled` reflects RSKIP140 (papyrus): the spec is PETERSBURG
/// from wasabi on (for the RSKIP120 shift opcodes and RSKIP125 CREATE2), but
/// EXTCODEHASH only activates at papyrus — so before that it must throw an
/// invalid-opcode exception (consuming all gas), matching rskj's VM.
///
/// `extcodehash_standard` is RSKIP169 (iris300): from it EXTCODEHASH answers a
/// contract whose code key holds nothing as any account without code.
///
/// `dupn_swapn_txindex_enabled` is RSKIP191's absence: before iris300 rskj
/// runs RSK's own DUPN, SWAPN and TXINDEX.
///
/// `block` is what the block's header gives COINBASE, GASLIMIT and BASEFEE.
pub fn install<WIRE, HOST>(
    instructions: &mut EthInstructions<WIRE, HOST>,
    extcodehash_enabled: bool,
    extcodehash_standard: bool,
    istanbul_opcodes_enabled: bool,
    push0_enabled: bool,
    basefee_enabled: bool,
    staticcall_enabled: bool,
    transient_storage_enabled: bool,
    mcopy_enabled: bool,
    dupn_swapn_txindex_enabled: bool,
    extcodesize_max_precompiles: &[Address],
    extcodehash_precompiles: &[Address],
    block: BlockWords,
) where
    WIRE: InterpreterTypes,
    HOST: Host + ContractMarker + BeneficiaryTouch + LocalCallWords,
{
    // RSKIP446 (lovell700): transient storage TLOAD/TSTORE (0x5c/0x5d,
    // EIP-1153, rskj `GasCost.TLOAD`/`TSTORE` = 100 each). RSKIP445 (lovell700):
    // MCOPY (0x5e, EIP-5656, VERY_LOW base + per-word copy + memory expansion).
    // revm gates all three on the CANCUN spec, but lovell700 maps to SHANGHAI,
    // so install unchecked versions (same pattern as PUSH0 at arrowhead600).
    if transient_storage_enabled {
        instructions.insert_instruction(
            opcode::TLOAD,
            Instruction::new(rsk_tload::<WIRE, HOST>, 100),
        );
        instructions.insert_instruction(
            opcode::TSTORE,
            Instruction::new(rsk_tstore::<WIRE, HOST>, 100),
        );
    }
    if mcopy_enabled {
        instructions.insert_instruction(
            opcode::MCOPY,
            Instruction::new(rsk_mcopy::<WIRE, HOST>, 3),
        );
    }
    // RSKIP398 (arrowhead600): PUSH0 (0x5f, rskj `OpCode.PUSH0` BASE_TIER = 2 gas)
    // pushes a zero word. rskj enables it at arrowhead600 but rustock maps that to
    // ISTANBUL (for RSKIP400 calldata), where revm's stock PUSH0 halts NotActivated
    // (it gates on SHANGHAI). Install an unchecked PUSH0 from arrowhead600 onward.
    if push0_enabled {
        instructions.insert_instruction(
            opcode::PUSH0,
            Instruction::new(rsk_push0::<WIRE, HOST>, 2),
        );
    }
    // RSKIP412 (arrowhead600): BASEFEE (0x48, rskj `OpCode.BASEFEE` BASE_TIER =
    // 2 gas) pushes the block's minimum gas price. rskj gates it on RSKIP412
    // (`VM.java` OP_BASEFEE -> invalidOpCode when inactive), which activates at
    // arrowhead600 — but revm bundles BASEFEE into LONDON, and arrowhead600..
    // lovell700 maps to ISTANBUL, so revm's stock BASEFEE halts NotActivated
    // across that whole window. Install an unchecked version, same as PUSH0.
    //
    // It is only needed for that window: every pre-arrowhead upgrade maps to
    // BYZANTIUM or PETERSBURG (no BASEFEE, matching rskj), and lovell700+ maps
    // to SHANGHAI >= LONDON where revm's own BASEFEE is already correct. The
    // unchecked instruction is installed for both, so the behaviour no longer
    // depends on which side of the spec boundary a block falls.
    if basefee_enabled {
        instructions.insert_instruction(
            opcode::BASEFEE,
            Instruction::new(rsk_basefee::<WIRE, HOST>, 2),
        );
    }
    if !extcodehash_enabled {
        instructions.insert_instruction(
            opcode::EXTCODEHASH,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
    } else {
        // rskj `VM.doEXTCODEHASH` keys on trie existence and special-cases
        // active precompiles to `keccak256("")` — see `rsk_extcodehash`.
        EXTCODEHASH_PRECOMPILES
            .with(|p| *p.borrow_mut() = extcodehash_precompiles.to_vec());
        EXTCODEHASH_STANDARD.set(extcodehash_standard);
        instructions.insert_instruction(
            opcode::EXTCODEHASH,
            Instruction::new(rsk_extcodehash::<WIRE, HOST>, 400),
        );
    }
    // RSKIP152 CHAINID / RSKIP151 SELFBALANCE (papyrus200): the spec stays
    // PETERSBURG (RSK never adopted the Istanbul gas repricings), so revm's
    // spec-checked impls would throw NotActivated — install uncheck-ed
    // versions with rskj's tier costs (CHAINID BASE=2, SELFBALANCE LOW=5).
    if istanbul_opcodes_enabled {
        instructions.insert_instruction(
            opcode::CHAINID,
            Instruction::new(rsk_chainid::<WIRE, HOST>, 2),
        );
        instructions.insert_instruction(
            opcode::SELFBALANCE,
            Instruction::new(rsk_selfbalance::<WIRE, HOST>, 5),
        );
    } else {
        // Pre-papyrus rskj throws invalid-opcode (all frame gas consumed).
        // revm's spec-checked impls would halt NotActivated, which spends the
        // frame's gas too; the invalid-opcode handler halts as for any other
        // opcode a height doesn't have (OpcodeNotFound).
        instructions.insert_instruction(
            opcode::CHAINID,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
        instructions.insert_instruction(
            opcode::SELFBALANCE,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
    }
    // rskj's `GasCost` constants are fork-independent (`static final`), so RSK
    // never adopted EIP-1884's Istanbul repricing of SLOAD (200→800) and BALANCE
    // (400→700). Arrowhead600+ maps to revm's ISTANBUL (for the RSKIP400 calldata
    // reduction, which is keyed off the SpecId), so revm's default table would
    // charge the bumped Istanbul prices. Pin both back to rskj's `GasCost.SLOAD`
    // (200) and `GasCost.BALANCE` (400). Pre-Istanbul specs already use these
    // values, so the override is a no-op there; at SHANGHAI (lovell700+) it also
    // corrects the same EIP-1884 over-charge. SLOAD's body is revm's own, which
    // before Berlin (RSK never reaches it) charges everything via the static
    // gas we set here. BALANCE's is `rsk_balance`, which reads the account as
    // revm's does, at the same static gas, and makes the word rskj makes of the
    // balance. (Mainnet #6,223,700.)
    instructions.insert_instruction(
        opcode::SLOAD,
        Instruction::new(
            revm::interpreter::instructions::host::sload::<WIRE, HOST>,
            SLOAD_GAS,
        ),
    );
    instructions.insert_instruction(
        opcode::BALANCE,
        Instruction::new(rsk_balance::<WIRE, HOST>, BALANCE_GAS),
    );
    // GASPRICE at rskj's BASE tier, 2, as revm's: `rsk_gasprice` pushes a
    // local call's price whole.
    instructions.insert_instruction(
        opcode::GASPRICE,
        Instruction::new(rsk_gasprice::<WIRE, HOST>, 2),
    );

    // rskj `VM.doSSTORE` keeps Petersburg metering forever (SET=20000,
    // RESET=CLEAR=5000, REFUND=15000) and has no EIP-2200 reentrancy sentry. Under
    // the ISTANBUL/SHANGHAI specs revm's stock SSTORE applies EIP-2200 net metering
    // and the `gasleft <= stipend` sentry — both consensus divergences for RSK. Use
    // a Petersburg-semantics SSTORE (the gas_params it reads are pinned to rskj's
    // values in make_cfg_env). Static gas 0 here: the cost is charged inside.
    instructions.insert_instruction(
        opcode::SSTORE,
        Instruction::new(rsk_sstore::<WIRE, HOST>, 0),
    );

    // RSKIP90: EXTCODESIZE of an active precompile reports 2^256-1.
    EXTCODESIZE_MAX_PRECOMPILES
        .with(|p| *p.borrow_mut() = extcodesize_max_precompiles.to_vec());
    instructions.insert_instruction(
        opcode::EXTCODESIZE,
        Instruction::new(rsk_extcodesize::<WIRE, HOST>, EXT_CODE_SIZE_GAS),
    );
    // rskj `GasCost.EXT_CODE_COPY` is a flat 700 at every fork. revm's stock
    // EXTCODECOPY body charges only the per-word copy cost (3/word) + memory
    // expansion + a cold-account surcharge (pinned to 0 in make_cfg_env); its
    // 700 base normally comes from the instruction-table static, which EIP-2929
    // drops to 0 at BERLIN+. lovell700 maps to SHANGHAI (≥Berlin), so the stock
    // static would be 0 and EXTCODECOPY would undercharge by 700. Reinstall the
    // body with an explicit static 700 so it matches rskj at every fork.
    // (Mainnet #7,515,160.)
    instructions.insert_instruction(
        opcode::EXTCODECOPY,
        Instruction::new(
            revm::interpreter::instructions::host::extcodecopy::<WIRE, HOST>,
            EXT_CODE_COPY_GAS,
        ),
    );
    instructions.insert_instruction(
        opcode::CALL,
        Instruction::new(rsk_call::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    instructions.insert_instruction(
        opcode::CALLCODE,
        Instruction::new(rsk_call_code::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    instructions.insert_instruction(
        opcode::DELEGATECALL,
        Instruction::new(rsk_delegate_call::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    // RSKIP91 (orchid, mainnet #729,000) introduced STATICCALL. rskj's
    // `VM.java` OP_STATICCALL throws `invalidOpCode` (consuming the frame's
    // gas) while RSKIP91 is inactive; rustock maps Genesis to BYZANTIUM, where
    // revm already provides the opcode, so before orchid it must be replaced
    // with the invalid-opcode handler -- same pattern as EXTCODEHASH before
    // papyrus.
    instructions.insert_instruction(
        opcode::STATICCALL,
        if staticcall_enabled {
            Instruction::new(rsk_static_call::<WIRE, HOST>, CALL_STATIC_GAS)
        } else {
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0)
        },
    );
    instructions.insert_instruction(
        opcode::SELFDESTRUCT,
        Instruction::new(rsk_selfdestruct::<WIRE, HOST>, SUICIDE_STATIC_GAS),
    );

    // rskj `OpCode.COINBASE` returns the block's real miner; rustock keeps
    // `block.beneficiary = REMASC_ADDR` (for gas-fee routing) so the default
    // COINBASE would return REMASC. Push the real coinbase instead.
    REAL_COINBASE.with(|c| c.set(block.coinbase));
    // GASLIMIT and BASEFEE push the whole values, which revm's block cuts to
    // a `u64` (see `GAS_LIMIT`).
    GAS_LIMIT.with(|c| c.set(block.gas_limit));
    MINIMUM_GAS_PRICE.with(|c| c.set(block.minimum_gas_price));
    CONFIGURED.with(|c| c.set(true));
    instructions.insert_instruction(
        opcode::COINBASE,
        Instruction::new(rsk_coinbase::<WIRE, HOST>, 2),
    );
    instructions.insert_instruction(
        opcode::GASLIMIT,
        Instruction::new(rsk_gaslimit::<WIRE, HOST>, 2),
    );

    // RSK's own opcodes, which RSKIP191 (iris300) removed. Before it rskj's VM
    // runs DUPN (VERY_LOW, 3 gas), SWAPN (3) and TXINDEX (BASE, 2); from it
    // rskj throws invalid-opcode, as revm does for a byte it has no opcode
    // for. Installed either way, so that the table says which at every
    // height. An EVM built for one call runs TXINDEX as rskj runs a call
    // outside a block, at index 0 (`ReversibleTransactionExecutor`); a block
    // sets each transaction's with `set_transaction_index`.
    TX_INDEX.with(|i| i.set(0));
    if dupn_swapn_txindex_enabled {
        instructions.insert_instruction(RSK_DUPN, Instruction::new(rsk_dupn::<WIRE, HOST>, 3));
        instructions.insert_instruction(RSK_SWAPN, Instruction::new(rsk_swapn::<WIRE, HOST>, 3));
        instructions
            .insert_instruction(RSK_TXINDEX, Instruction::new(rsk_txindex::<WIRE, HOST>, 2));
    } else {
        for op in [RSK_DUPN, RSK_SWAPN, RSK_TXINDEX] {
            instructions.insert_instruction(op, Instruction::new(invalid_opcode::<WIRE, HOST>, 0));
        }
    }

    // Divergence-hunt diagnostic (env-gated, temporary): log pc/op/gas for
    // EVERY opcode. The wrapper re-dispatches to the default PETERSBURG
    // table, except for the rsk-custom opcodes which dispatch to the local
    // overrides installed above.
    if std::env::var_os("RUSTOCK_TRACE_ALL_OPS").is_some() {
        EXTCODEHASH_ENABLED.with(|f| f.set(extcodehash_enabled));
        ISTANBUL_OPCODES_ENABLED.with(|f| f.set(istanbul_opcodes_enabled));
        PUSH0_ENABLED.with(|f| f.set(push0_enabled));
        BASEFEE_ENABLED.with(|f| f.set(basefee_enabled));
        STATICCALL_ENABLED.with(|f| f.set(staticcall_enabled));
        DUPN_SWAPN_TXINDEX_ENABLED.with(|f| f.set(dupn_swapn_txindex_enabled));
        let default_table = revm::interpreter::instructions::instruction_table_gas_changes_spec::<
            WIRE,
            HOST,
        >(revm::primitives::hardfork::SpecId::PETERSBURG);
        for op in 0u16..=255 {
            let op = op as u8;
            let static_gas = match op {
                opcode::EXTCODESIZE | opcode::CALL | opcode::CALLCODE
                | opcode::DELEGATECALL => CALL_STATIC_GAS,
                opcode::STATICCALL if staticcall_enabled => CALL_STATIC_GAS,
                opcode::STATICCALL => 0,
                opcode::EXTCODEHASH if !extcodehash_enabled => 0,
                opcode::CHAINID if istanbul_opcodes_enabled => 2,
                opcode::SELFBALANCE if istanbul_opcodes_enabled => 5,
                opcode::PUSH0 if push0_enabled => 2,
                opcode::BASEFEE if basefee_enabled => 2,
                RSK_DUPN | RSK_SWAPN if dupn_swapn_txindex_enabled => 3,
                RSK_TXINDEX if dupn_swapn_txindex_enabled => 2,
                _ => default_table[op as usize].static_gas(),
            };
            instructions.insert_instruction(
                op,
                Instruction::new(traced_all::<WIRE, HOST>, static_gas),
            );
        }
        return;
    }

    // Divergence-hunt diagnostics (env-gated): log the inputs of opcodes
    // whose gas charge can dwarf the remaining gas, to locate the exact
    // OOG-with-gas-remaining halt site.
    if std::env::var_os("RUSTOCK_TRACE_OPS").is_some() {
        instructions.insert_instruction(
            opcode::KECCAK256,
            Instruction::new(traced_keccak::<WIRE, HOST>, 30),
        );
        instructions.insert_instruction(
            opcode::CODECOPY,
            Instruction::new(traced_codecopy::<WIRE, HOST>, 3),
        );
        instructions.insert_instruction(
            opcode::RETURN,
            Instruction::new(traced_return::<WIRE, HOST>, 0),
        );
        instructions.insert_instruction(
            opcode::EXP,
            Instruction::new(traced_exp::<WIRE, HOST>, 10),
        );
    }
}

/// An opcode that is not yet activated at this block height: rskj throws an
/// invalid-opcode exception, which halts the frame and consumes all gas.
fn invalid_opcode<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    context.interpreter.halt(InstructionResult::OpcodeNotFound);
}

/// `keccak256("")`, the code hash rskj reports for an existing-but-codeless
/// account and for active precompiles (`Keccak256Helper.keccak256(EMPTY)`).
pub(crate) const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// EXTCODEHASH with rskj's `VM.doEXTCODEHASH` / `getCodeHashStandard`
/// semantics, which key on TRIE EXISTENCE (RSK never adopted EIP-161/1052
/// emptiness):
///   - active precompile  -> `keccak256("")` (rskj special-cases precompiles);
///   - account absent from the trie -> `0`;
///   - account present but not a contract (no code) -> `keccak256("")`;
///   - contract -> its code hash. One whose code key holds nothing answers
///     `keccak256("")` from RSKIP169 (`getCodeHashStandard`) and `0` before
///     it (`getCodeHashNonStandard`), which needs [`ContractMarker`].
///
/// revm's stock EXTCODEHASH instead returns `0` whenever `AccountInfo::is_empty()`
/// (EIP-161: balance==0 && nonce==0 && no code), so an existing-but-empty
/// account (e.g. a zero-balance EOA that a prior tx created via a 0-value call)
/// would wrongly hash to `0` instead of `keccak256("")` — block #3,631,998 tx[1]
/// exposed this (+11 gas, divergent revert branch). `is_empty` here is the
/// host's flag (`true` only when `Database::basic` returned `None`, i.e. the
/// trie has no node — see the HOMESTEAD journal pin in `RskHandler`), which is
/// exactly rskj's `isExist`.
fn rsk_extcodehash<WIRE: InterpreterTypes, H: Host + ContractMarker + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some(([], top)) = context.interpreter.stack.popn_top::<0>() else {
        context.interpreter.halt_underflow();
        return;
    };
    let addr = Address::from_word(B256::from(*top));

    assert_configured("EXTCODEHASH_PRECOMPILES");
    if EXTCODEHASH_PRECOMPILES.with(|p| p.borrow().contains(&addr)) {
        *top = KECCAK_EMPTY.into();
        return;
    }

    let Ok(load) = context.host.load_account_info_skip_cold_load(addr, false, false) else {
        context.interpreter.halt_fatal();
        return;
    };
    // `is_empty` is the host's trie-existence flag (rskj `isExist`).
    let exists = !load.is_empty;
    let code_hash = load.account.code_hash;
    let codeless = load.account.is_empty_code_hash() || code_hash.is_zero();
    let result = if !exists {
        B256::ZERO
    } else if !codeless {
        code_hash
    } else if EXTCODEHASH_STANDARD.get() {
        KECCAK_EMPTY
    } else {
        match context.host.holds_contract_marker(addr) {
            Some(true) => B256::ZERO,
            Some(false) => KECCAK_EMPTY,
            None => {
                context.interpreter.halt_fatal();
                return;
            }
        }
    };
    *top = result.into();
}

/// What EXTCODEHASH asks before RSKIP169 that revm's `Host` can't answer:
/// whether an account is a contract as rskj's `isContract` reads it, by the
/// storage-prefix marker `setupContract` writes.
pub trait ContractMarker {
    /// Whether `address` holds the marker. `None` where the state couldn't be
    /// read, the error left in the context as revm's own loads leave it.
    fn holds_contract_marker(&mut self, address: Address) -> Option<bool>;
}

type RskDb = revm::database::WrapDatabaseRef<crate::database::RskDatabase>;

/// The executor's context. The marker is a creation's of this transaction
/// (the journal), of the block's earlier ones (the chain slot, which also
/// knows what they destroyed, marker and all), or else the parent state's.
impl<BLOCK, TX, CFG, LOCAL> ContractMarker
    for revm::Context<
        BLOCK,
        TX,
        CFG,
        RskDb,
        revm::context::Journal<RskDb>,
        crate::raw_storage::RskChainExt,
        LOCAL,
    >
where
    LOCAL: revm::context_interface::LocalContextTr,
{
    fn holds_contract_marker(&mut self, address: Address) -> Option<bool> {
        let created_now = self
            .journaled_state
            .inner
            .state
            .get(&address)
            .is_some_and(|account| account.is_created_locally());
        if created_now || self.chain.created_in_block.contains(&address) {
            return Some(true);
        }
        if self.chain.deleted_in_block.contains(&address) {
            return Some(false);
        }
        match self
            .journaled_state
            .database
            .0
            .has_contract_marker(&address)
        {
            Ok(holds) => Some(holds),
            Err(e) => {
                self.error = Err(revm::context_interface::ContextError::Db(e));
                None
            }
        }
    }
}

/// What SELFDESTRUCT asks that revm's `Host` can't do: leave the beneficiary
/// as it was. revm's journal touches it whatever the destroyed account held,
/// and under RSK's frontier account rules a touch creates an account that
/// wasn't there.
pub trait BeneficiaryTouch {
    /// Whether `address` is touched already, so that touching it again changes
    /// nothing.
    fn is_touched(&self, address: Address) -> bool;

    /// Takes back the touch that the SELFDESTRUCT which has just run gave
    /// `beneficiary`: the account's flag, and the journal's entry for it.
    fn take_back_touch(&mut self, beneficiary: Address);
}

impl<BLOCK, TX, CFG, LOCAL> BeneficiaryTouch
    for revm::Context<
        BLOCK,
        TX,
        CFG,
        RskDb,
        revm::context::Journal<RskDb>,
        crate::raw_storage::RskChainExt,
        LOCAL,
    >
where
    LOCAL: revm::context_interface::LocalContextTr,
{
    fn is_touched(&self, address: Address) -> bool {
        self.journaled_state
            .inner
            .state
            .get(&address)
            .is_some_and(|account| account.is_touched())
    }

    fn take_back_touch(&mut self, beneficiary: Address) {
        let journal = &mut self.journaled_state.inner;
        if let Some(account) = journal.state.get_mut(&beneficiary) {
            account.unmark_touch();
        }
        // revm's `JournalInner::selfdestruct` journals the touch and then the
        // destruction, so the touch is the last entry but one. It goes too:
        // the sublists' write sets are read from these entries, and rskj
        // only reads this account (`isExist`, for the gas).
        let touch = journal.journal.len().checked_sub(2).filter(|&at| {
            matches!(
                journal.journal[at],
                revm::context::JournalEntry::AccountTouched { address } if address == beneficiary
            )
        });
        debug_assert!(
            touch.is_some(),
            "SELFDESTRUCT journals its touch of {beneficiary}"
        );
        if let Some(at) = touch {
            journal.journal.remove(at);
        }
    }
}

/// What BALANCE, SELFBALANCE and GASPRICE read of a local call (`eth_call`,
/// `eth_estimateGas`) that revm's `Host` can't tell them: rskj holds a
/// balance with its sign and a gas price at any width.
pub trait LocalCallWords {
    /// What `address` owes: the part of a local call's value that its sender
    /// didn't hold (`RskChainExt::owed`), and nothing for any other account.
    fn owed_by(&self, address: Address) -> U256;

    /// The gas price of a local call, where revm's transaction can't hold it
    /// (`RskChainExt::whole_gas_price`).
    fn whole_gas_price(&self) -> Option<U256>;
}

impl<BLOCK, TX, CFG, LOCAL> LocalCallWords
    for revm::Context<
        BLOCK,
        TX,
        CFG,
        RskDb,
        revm::context::Journal<RskDb>,
        crate::raw_storage::RskChainExt,
        LOCAL,
    >
where
    LOCAL: revm::context_interface::LocalContextTr,
{
    fn owed_by(&self, address: Address) -> U256 {
        match self.chain.owed {
            Some((sender, owed)) if sender == address => owed,
            _ => U256::ZERO,
        }
    }

    fn whole_gas_price(&self) -> Option<U256> {
        self.chain.whole_gas_price
    }
}

/// The word rskj's `Program.getBalance` makes of a balance: `DataWord.valueOf`
/// of `Coin.getBytes()`, which is `BigInteger.toByteArray`, the two's
/// complement in the fewest bytes, set at the low end of the word. So a
/// balance below zero reads as those bytes do without their sign: 255 for -1,
/// 0xff7f for -129. One of 2^255 or more takes a sign byte, a 33rd, and
/// `valueOf` throws, as it does below -2^255: `None`, and the program fails.
///
/// `held` is what the journal holds for the account and `owed` what the
/// account owes ([`LocalCallWords::owed_by`]); the balance is the one less the
/// other. On the chain nothing is owed and no account holds 2^255, so the
/// word is the balance.
pub(crate) fn balance_word(held: U256, owed: U256) -> Option<U256> {
    if held >= owed {
        let balance = held - owed;
        return (balance.bit_len() < 256).then_some(balance);
    }
    let below = owed - held;
    // The fewest bytes whose two's complement holds `-below`.
    let bytes = (below - U256::from(1)).bit_len() / 8 + 1;
    match bytes {
        33.. => None,
        32 => Some(below.wrapping_neg()),
        _ => Some((U256::from(1) << (8 * bytes)) - below),
    }
}

/// CHAINID without revm's ISTANBUL spec check (RSKIP152 activates it at
/// papyrus200 while the spec stays PETERSBURG).
fn rsk_chainid<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.interpreter.stack.push(context.host.chain_id()) {
        context.interpreter.halt_overflow();
    }
}

/// PUSH0 (RSKIP398, arrowhead600) without revm's SHANGHAI spec check: pushes a
/// zero word. rskj `VM.doPUSH0`. Static gas (2, BASE_TIER) is charged by the
/// instruction table entry installed in `install`.
fn rsk_push0<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.interpreter.stack.push(U256::ZERO) {
        context.interpreter.halt_overflow();
    }
}

/// BASEFEE (RSKIP412, arrowhead600) without revm's LONDON spec check: pushes
/// the block's minimum gas price, whole. rskj `VM.doBASEFEE` pushes
/// `program.getMinimumGasPrice()`, a `DataWord`, where revm's block holds a
/// `u64`. Static gas (2, BASE_TIER) comes from the instruction table entry
/// installed in `install`.
fn rsk_basefee<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    assert_configured("MINIMUM_GAS_PRICE");
    if !context.interpreter.stack.push(MINIMUM_GAS_PRICE.with(|c| c.get())) {
        context.interpreter.halt_overflow();
    }
}

/// RSKIP446 TLOAD (0x5c, EIP-1153): push the transient-storage value at the
/// popped key (zero if unset). Flat 100 gas (charged by the static table). Same
/// body as revm's `host::tload` minus the CANCUN spec gate.
fn rsk_tload<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some([key]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let value = context.host.tload(context.interpreter.input.target_address(), key);
    if !context.interpreter.stack.push(value) {
        context.interpreter.halt_overflow();
    }
}

/// RSKIP446 TSTORE (0x5d, EIP-1153): write value at key in transient storage.
/// Reverts inside a static call (rskj `doTSTORE` modificationException). Flat
/// 100 gas. Same body as revm's `host::tstore` minus the CANCUN spec gate.
fn rsk_tstore<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if context.interpreter.runtime_flag.is_static() {
        context
            .interpreter
            .halt(InstructionResult::StateChangeDuringStaticCall);
        return;
    }
    let Some([key, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    context
        .host
        .tstore(context.interpreter.input.target_address(), key, value);
}

/// RSKIP445 MCOPY (0x5e, EIP-5656): copy `len` bytes within memory from `src`
/// to `dst`. Cost = VERY_LOW (3, static table) + 3 per word + memory expansion,
/// matching rskj `doMCOPY` (VERY_LOW + computeMemoryCopyGas). Same body as
/// revm's `memory::mcopy` minus the CANCUN spec gate.
fn rsk_mcopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some([dst, src, len]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Ok(len) = usize::try_from(len) else {
        context.interpreter.halt(InstructionResult::InvalidOperandOOG);
        return;
    };
    if !context
        .interpreter
        .gas
        .record_cost(context.host.gas_params().mcopy_cost(len))
    {
        context.interpreter.halt_oog();
        return;
    }
    if len == 0 {
        return;
    }
    let (Ok(dst), Ok(src)) = (usize::try_from(dst), usize::try_from(src)) else {
        context.interpreter.halt(InstructionResult::InvalidOperandOOG);
        return;
    };
    let gas_params = context.host.gas_params();
    if !context
        .interpreter
        .resize_memory(gas_params, core::cmp::max(dst, src), len)
    {
        return;
    }
    context.interpreter.memory.copy(dst, src, len);
}

/// COINBASE returning rskj's real miner address (`header.getCoinbase()`)
/// rather than revm's `block.beneficiary` (which rustock pins to REMASC_ADDR
/// so gas fees route to the REMASC contract). See `REAL_COINBASE`.
fn rsk_coinbase<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    assert_configured("REAL_COINBASE");
    let coinbase = REAL_COINBASE.with(|c| c.get());
    if !context.interpreter.stack.push(U256::from_be_bytes(coinbase.into_word().0)) {
        context.interpreter.halt_overflow();
    }
}

/// GASLIMIT pushing the block's gas limit whole. rskj `VM.doGASLIMIT` pushes
/// `program.getGasLimit()`, a `DataWord` of the header's bytes, where
/// revm's block holds the limit as gas, a `u64`. See `GAS_LIMIT`.
fn rsk_gaslimit<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    assert_configured("GAS_LIMIT");
    if !context.interpreter.stack.push(GAS_LIMIT.with(|c| c.get())) {
        context.interpreter.halt_overflow();
    }
}

/// DUPN (before RSKIP191), rskj `VM.doDUPN`: pops a depth `d` and pushes a
/// copy of the item `d + 1` from the top, so DUPN of 0 is DUP1, then steps
/// over the next byte. A depth the stack doesn't reach throws
/// (`Program.verifyStackSize`, or `DataWord.intValueCheck` from 2^31), which
/// spends all of the frame's gas.
fn rsk_dupn<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    let Some([depth]) = context.interpreter.stack.popn::<1>() else {
        context.interpreter.halt_underflow();
        return;
    };
    // At least 1, which `dup` requires.
    let item = depth.saturating_to::<usize>().checked_add(1);
    if !item.is_some_and(|n| context.interpreter.stack.dup(n)) {
        context.interpreter.halt_underflow();
        return;
    }
    step_over_next_byte(context.interpreter);
}

/// SWAPN (before RSKIP191), rskj `VM.doSWAPN`: pops a depth `d` and swaps the
/// top with the item `d + 2` from the top, so SWAPN of 0 is SWAP1. It fails
/// as DUPN does, and steps over the next byte in the same way.
fn rsk_swapn<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    let Some([depth]) = context.interpreter.stack.popn::<1>() else {
        context.interpreter.halt_underflow();
        return;
    };
    // `exchange(0, m)` swaps the top with the item `m` below it; `m` is at
    // least 1, which it requires.
    let below = depth.saturating_to::<usize>().checked_add(1);
    if !below.is_some_and(|m| context.interpreter.stack.exchange(0, m)) {
        context.interpreter.halt_underflow();
        return;
    }
    step_over_next_byte(context.interpreter);
}

/// rskj's second `program.step()` in `doDUPN` and `doSWAPN`: the counter
/// moves past the byte after the opcode, which never runs, though a jump may
/// still land on it (`Program.computeJumpDests` skips only PUSH data, as
/// revm's analysis does). Where that takes the counter past the code,
/// rskj's `Program.setPC` stops the program. revm pads code with as little
/// as one STOP and reads the next opcode unchecked, so the stop is made here
/// rather than by stepping off the end.
fn step_over_next_byte<WIRE: InterpreterTypes>(
    interpreter: &mut revm::interpreter::Interpreter<WIRE>,
) {
    use revm::interpreter::interpreter_types::{Jumps, LegacyBytecode};
    // revm stepped past the opcode itself before running it.
    if interpreter.bytecode.pc() + 1 >= interpreter.bytecode.bytecode_len() {
        interpreter.halt(InstructionResult::Stop);
    } else {
        interpreter.bytecode.relative_jump(1);
    }
}

/// TXINDEX (before RSKIP191), rskj `VM.doTXINDEX`: pushes the index in its
/// block of the transaction being executed. See `TX_INDEX`.
fn rsk_txindex<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    assert_configured("TX_INDEX");
    let index = TX_INDEX.with(|i| i.get());
    if !context.interpreter.stack.push(U256::from(index)) {
        context.interpreter.halt_overflow();
    }
}

/// SELFBALANCE without revm's ISTANBUL spec check (RSKIP151, papyrus200),
/// pushing the word rskj makes of the balance ([`balance_word`]).
fn rsk_selfbalance<WIRE: InterpreterTypes, H: Host + LocalCallWords + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let address = context.interpreter.input.target_address();
    let Some(balance) = context.host.balance(address) else {
        context.interpreter.halt_fatal();
        return;
    };
    let Some(word) = balance_word(balance.data, context.host.owed_by(address)) else {
        context.interpreter.halt(InstructionResult::OutOfGas);
        return;
    };
    if !context.interpreter.stack.push(word) {
        context.interpreter.halt_overflow();
    }
}

/// BALANCE, pushing the word rskj makes of the balance ([`balance_word`]).
/// The account is read as revm's BALANCE reads one before Berlin, and the
/// instruction's static gas is all it costs (see `install`).
fn rsk_balance<WIRE: InterpreterTypes, H: Host + LocalCallWords + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let address = {
        let Some(([], top)) = context.interpreter.stack.popn_top::<0>() else {
            context.interpreter.halt_underflow();
            return;
        };
        Address::from_word(B256::from(*top))
    };
    let Some(balance) = context.host.balance(address) else {
        context.interpreter.halt_fatal();
        return;
    };
    let Some(word) = balance_word(balance.data, context.host.owed_by(address)) else {
        context.interpreter.halt(InstructionResult::OutOfGas);
        return;
    };
    if let Some(([], top)) = context.interpreter.stack.popn_top::<0>() {
        *top = word;
    }
}

/// GASPRICE, pushing a local call's price whole where revm's transaction
/// can't hold it ([`LocalCallWords`]).
fn rsk_gasprice<WIRE: InterpreterTypes, H: Host + LocalCallWords + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let price = context
        .host
        .whole_gas_price()
        .unwrap_or_else(|| context.host.effective_gas_price());
    if !context.interpreter.stack.push(price) {
        context.interpreter.halt_overflow();
    }
}

/// EXTCODESIZE with rskj's RSKIP90 quirk: the code size of an active precompile
/// is reported as `2^256-1` (`VM.doCODESIZE` → `DataWord.MAX_VALUE`), so a proxy
/// guarding `extcodesize(precompile) != 0` works. All other addresses fall
/// through to revm's standard EXTCODESIZE.
fn rsk_extcodesize<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let addr = {
        let Some(([], top)) = context.interpreter.stack.popn_top::<0>() else {
            context.interpreter.halt_underflow();
            return;
        };
        Address::from_word(B256::from(*top))
    };
    assert_configured("EXTCODESIZE_MAX_PRECOMPILES");
    let is_precompile = EXTCODESIZE_MAX_PRECOMPILES.with(|p| p.borrow().contains(&addr));
    if is_precompile {
        if let Some(([], top)) = context.interpreter.stack.popn_top::<0>() {
            *top = U256::MAX;
        }
    } else {
        revm::interpreter::instructions::host::extcodesize(context);
    }
}

macro_rules! traced_op {
    ($name:ident, $label:literal, $peek:literal, $delegate:path) => {
        fn $name<WIRE: InterpreterTypes, H: Host + ?Sized>(
            context: InstructionContext<'_, H, WIRE>,
        ) {
            let data = context.interpreter.stack.data();
            let vals: Vec<String> = data
                .iter()
                .rev()
                .take($peek)
                .map(|v| format!("{:x}", v))
                .collect();
            tracing::debug!(
                "OP {} stack_top={:?} gas_remaining={}",
                $label,
                vals,
                context.interpreter.gas.remaining()
            );
            $delegate(context)
        }
    };
}

thread_local! {
    /// RSKIP140 flag for the all-ops tracer's EXTCODEHASH dispatch.
    static EXTCODEHASH_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
    /// RSKIP151/152 flag for the all-ops tracer's CHAINID/SELFBALANCE dispatch.
    static ISTANBUL_OPCODES_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
    /// RSKIP398 flag for the all-ops tracer's PUSH0 dispatch.
    static PUSH0_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// RSKIP412 flag for the all-ops tracer's BASEFEE dispatch.
    static BASEFEE_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// RSKIP91 flag for the all-ops tracer's STATICCALL dispatch.
    static STATICCALL_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
    /// RSKIP191 flag for the all-ops tracer's DUPN/SWAPN/TXINDEX dispatch.
    static DUPN_SWAPN_TXINDEX_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// All-ops tracer: log pc/opcode/gas (post-static-charge), then dispatch to
/// the real implementation (custom rsk op or default PETERSBURG table).
fn traced_all<
    WIRE: InterpreterTypes,
    HOST: Host + ContractMarker + BeneficiaryTouch + LocalCallWords,
>(
    context: InstructionContext<'_, HOST, WIRE>,
) {
    use revm::interpreter::interpreter_types::{InputsTr, Jumps, LegacyBytecode};
    let pc = context.interpreter.bytecode.pc().saturating_sub(1);
    // step() already advanced pc by 1, so the executing opcode is at pc-1.
    let op = context
        .interpreter
        .bytecode
        .bytecode_slice()
        .get(pc)
        .copied()
        .unwrap_or(opcode::STOP);
    tracing::debug!(
        "OPTRACE addr={} pc={pc:04x} op={:02x} {} gas={}",
        context.interpreter.input.target_address(),
        op,
        revm::bytecode::opcode::OpCode::new(op).map(|o| o.as_str()).unwrap_or("?"),
        context.interpreter.gas.remaining(),
    );
    // NOTE: addr= field added for the per-opcode trace oracle (rskj diff).
    match op {
        opcode::EXTCODESIZE => rsk_extcodesize(context),
        opcode::BALANCE => rsk_balance(context),
        opcode::GASPRICE => rsk_gasprice(context),
        opcode::CALL => rsk_call(context),
        opcode::CALLCODE => rsk_call_code(context),
        opcode::DELEGATECALL => rsk_delegate_call(context),
        opcode::STATICCALL => {
            if STATICCALL_ENABLED.with(|f| f.get()) {
                rsk_static_call(context)
            } else {
                invalid_opcode(context)
            }
        }
        opcode::SELFDESTRUCT => rsk_selfdestruct(context),
        opcode::COINBASE => rsk_coinbase(context),
        opcode::GASLIMIT => rsk_gaslimit(context),
        opcode::EXTCODEHASH if !EXTCODEHASH_ENABLED.with(|f| f.get()) => {
            invalid_opcode(context)
        }
        opcode::EXTCODEHASH => rsk_extcodehash(context),
        opcode::CHAINID => {
            if ISTANBUL_OPCODES_ENABLED.with(|f| f.get()) {
                rsk_chainid(context)
            } else {
                invalid_opcode(context)
            }
        }
        opcode::SELFBALANCE => {
            if ISTANBUL_OPCODES_ENABLED.with(|f| f.get()) {
                rsk_selfbalance(context)
            } else {
                invalid_opcode(context)
            }
        }
        opcode::PUSH0 => {
            if PUSH0_ENABLED.with(|f| f.get()) {
                rsk_push0(context)
            } else {
                invalid_opcode(context)
            }
        }
        opcode::BASEFEE => {
            if BASEFEE_ENABLED.with(|f| f.get()) {
                rsk_basefee(context)
            } else {
                invalid_opcode(context)
            }
        }
        RSK_DUPN | RSK_SWAPN | RSK_TXINDEX if !DUPN_SWAPN_TXINDEX_ENABLED.with(|f| f.get()) => {
            invalid_opcode(context)
        }
        RSK_DUPN => rsk_dupn(context),
        RSK_SWAPN => rsk_swapn(context),
        RSK_TXINDEX => rsk_txindex(context),
        _ => {
            let table = revm::interpreter::instructions::instruction_table_gas_changes_spec::<
                WIRE,
                HOST,
            >(revm::primitives::hardfork::SpecId::PETERSBURG);
            table[op as usize].execute(context)
        }
    }
}

traced_op!(traced_keccak, "KECCAK256", 2, revm::interpreter::instructions::system::keccak256);
traced_op!(traced_codecopy, "CODECOPY", 3, revm::interpreter::instructions::system::codecopy);
traced_op!(traced_return, "RETURN", 2, revm::interpreter::instructions::control::ret);
traced_op!(traced_exp, "EXP", 2, revm::interpreter::instructions::arithmetic::exp);

/// revm's `get_memory_input_and_out_ranges`, except the OUT range keeps the
/// REAL offset when outSize == 0 (revm substitutes a usize::MAX sentinel).
/// Pre-RSKIP150 the handler writes a successful precompile's full output at
/// rskj's actual outOffs (`Program.memorySave`), so the offset must survive
/// zero-size out regions.
fn rsk_memory_input_and_out_ranges<WIRE: InterpreterTypes>(
    interpreter: &mut revm::interpreter::Interpreter<WIRE>,
    gas_params: &revm::context_interface::cfg::GasParams,
) -> Option<(core::ops::Range<usize>, core::ops::Range<usize>)> {
    let Some([in_offset, in_len, out_offset, out_len]) = interpreter.stack.popn() else {
        interpreter.halt_underflow();
        return None;
    };

    let mut in_range = rsk_call_memory_range(interpreter, gas_params, in_offset, in_len)?;
    if !in_range.is_empty() {
        let off = interpreter.memory.local_memory_offset();
        in_range = in_range.start.saturating_add(off)..in_range.end.saturating_add(off);
    }
    let out_range = rsk_call_memory_range(interpreter, gas_params, out_offset, out_len)?;
    Some((in_range, out_range))
}

fn rsk_call_memory_range<WIRE: InterpreterTypes>(
    interpreter: &mut revm::interpreter::Interpreter<WIRE>,
    gas_params: &revm::context_interface::cfg::GasParams,
    offset: U256,
    len: U256,
) -> Option<core::ops::Range<usize>> {
    let Ok(len) = usize::try_from(len) else {
        interpreter.halt(InstructionResult::InvalidOperandOOG);
        return None;
    };
    let offset = if len != 0 {
        let Ok(offset) = usize::try_from(offset) else {
            interpreter.halt(InstructionResult::InvalidOperandOOG);
            return None;
        };
        if !interpreter.resize_memory(gas_params, offset, len) {
            return None;
        }
        offset
    } else {
        // Zero-size region: keep the true offset when it fits, falling back
        // to revm's usize::MAX sentinel (which disables the pre-RSKIP150
        // unbounded write) for pathological offsets.
        usize::try_from(offset).unwrap_or(usize::MAX)
    };
    Some(offset..offset.saturating_add(len))
}

/// rskj `VM.getMessageCall` gas math, shared by the four call opcodes.
///
/// Assumes the base costs (static 700, memory expansion, value transfer,
/// new-account) are already charged. Charges and returns the callee gas:
/// `min(remaining, requested + stipend)`, stipend only on value transfers.
fn rsk_callee_gas<WIRE, H>(
    context: &mut InstructionContext<'_, H, WIRE>,
    requested: u64,
    has_transfer: bool,
) -> Option<u64>
where
    WIRE: InterpreterTypes,
    H: Host + ?Sized,
{
    let stipend = if has_transfer {
        context.host.gas_params().call_stipend()
    } else {
        0
    };
    let remaining = context.interpreter.gas.remaining();
    // rskj notEnoughSpendingGas: the caller must at least cover the stipend.
    if remaining < stipend {
        context.interpreter.halt_oog();
        return None;
    }
    let callee_gas = core::cmp::min(remaining, requested.saturating_add(stipend));
    if !context.interpreter.gas.record_cost(callee_gas) {
        context.interpreter.halt_oog();
        return None;
    }
    Some(callee_gas)
}

/// Pops the value, charges VT_CALL, loads the callee (charging new-account
/// for op CALL) and computes the callee gas. Returns
/// `(gas_limit, bytecode, code_hash)`.
fn rsk_call_gas_common<WIRE, H>(
    context: &mut InstructionContext<'_, H, WIRE>,
    to: Address,
    requested: u64,
    value: U256,
    charge_new_account: bool,
) -> Option<(u64, revm::state::Bytecode, B256)>
where
    WIRE: InterpreterTypes,
    H: Host + ?Sized,
{
    let has_transfer = !value.is_zero();

    // rskj computeCallGas: VT_CALL when transferring value.
    if has_transfer {
        let vt = context.host.gas_params().transfer_value_cost();
        if !context.interpreter.gas.record_cost(vt) {
            context.interpreter.halt_oog();
            return None;
        }
    }

    // rskj charges NEW_ACCT_CALL for op CALL whenever the callee does not
    // exist, regardless of value: passing transfers_value=true makes revm's
    // new_account_cost unconditional on emptiness.
    // (Approximation: revm reports EIP-161 emptiness, rskj checks trie
    // existence; they differ only for existing-but-empty accounts.)
    let (cost, bytecode, code_hash) =
        load_account_delegated_handle_error(context, to, true, charge_new_account)?;
    if !context.interpreter.gas.record_cost(cost) {
        context.interpreter.halt_oog();
        return None;
    }

    let gas_limit = rsk_callee_gas(context, requested, has_transfer)?;
    Some((gas_limit, bytecode, code_hash))
}

/// CALL with rskj gas semantics.
pub fn rsk_call<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    let has_transfer = !value.is_zero();

    if context.interpreter.runtime_flag.is_static() && has_transfer {
        context
            .interpreter
            .halt(InstructionResult::CallNotAllowedInsideStatic);
        return;
    }

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, value, true)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: to,
                caller: context.interpreter.input.target_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Transfer(value),
                scheme: CallScheme::Call,
                is_static: context.interpreter.runtime_flag.is_static(),
                return_memory_offset,
            },
        ))));
}

/// SELFDESTRUCT with rskj gas semantics.
///
/// rskj `VM.doSUICIDE` adds `NEW_ACCT_SUICIDE` (25,000) whenever the
/// beneficiary does not exist (`!track.isExist`), with NO condition on the
/// suiciding contract's balance. revm's stock `selfdestruct` instead gates the
/// top-up on `had_value && !target_exists` once Spurious Dragon is active
/// (EIP-161), which is always the case for RSK eras (spec >= Byzantium) — so a
/// zero-balance contract self-destructing to an absent beneficiary would skip
/// the 25,000 charge and diverge. This override drops the value condition,
/// matching rskj frontier-style suicide gas. Everything else (base 5,000 via
/// static gas, cold cost, refund) mirrors revm's instruction.
///
/// And with rskj's account semantics: `Program.suicide` transfers only a
/// balance that is not zero, so with nothing to hand over the beneficiary is
/// left as it was, and one that did not exist still does not, though the
/// 25,000 for it was charged. revm's journal touches the beneficiary whatever
/// the balance, which under RSK's frontier account rules would create it, so
/// that touch is taken back ([`BeneficiaryTouch`]).
pub fn rsk_selfdestruct<WIRE: InterpreterTypes, H: Host + BeneficiaryTouch + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if context.interpreter.runtime_flag.is_static() {
        context
            .interpreter
            .halt(InstructionResult::StateChangeDuringStaticCall);
        return;
    }
    let Some([target]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let target = Address::from_word(B256::from(target));

    let address = context.interpreter.input.target_address();

    let cold_load_gas = context.host.gas_params().selfdestruct_cold_cost();
    let skip_cold_load = context.interpreter.gas.remaining() < cold_load_gas;
    // Whether the touch revm is about to give the beneficiary is a new one.
    let touches = address != target && !context.host.is_touched(target);
    let res = match context.host.selfdestruct(address, target, skip_cold_load) {
        Ok(res) => res,
        Err(LoadError::ColdLoadSkipped) => return context.interpreter.halt_oog(),
        Err(LoadError::DBError) => return context.interpreter.halt_fatal(),
    };

    if touches && !res.had_value {
        context.host.take_back_touch(target);
    }

    // rskj charges NEW_ACCT_SUICIDE on beneficiary non-existence regardless of
    // value (no `had_value &&` gate, unlike revm's EIP-161 path).
    let should_charge_topup = !res.target_exists;

    let cost = context
        .host
        .gas_params()
        .selfdestruct_cost(should_charge_topup, res.is_cold);
    if !context.interpreter.gas.record_cost(cost) {
        context.interpreter.halt_oog();
        return;
    }

    if !res.previously_destroyed {
        context
            .interpreter
            .gas
            .record_refund(context.host.gas_params().selfdestruct_refund());
    }

    context.interpreter.halt(InstructionResult::SelfDestruct);
}

/// SSTORE with rskj's fork-independent Petersburg metering (`VM.doSSTORE`).
///
/// RSK never adopted EIP-2200: there is no `gasleft <= stipend` reentrancy
/// sentry, and the dynamic cost/refund use the pre-Istanbul rules — present-zero
/// → non-zero charges SET, every other write charges RESET, and clearing a
/// non-zero slot to zero refunds CLEAR. The required gas_params are pinned to
/// rskj's `GasCost` values (SET=20000 split as static 5000 + 15000, RESET=5000 +
/// 0, REFUND=15000) in `make_cfg_env`. This mirrors revm's `host::sstore`
/// with the ISTANBUL branches forced off. (Mainnet #6,223,700, arrowhead600.)
fn rsk_sstore<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if context.interpreter.runtime_flag.is_static() {
        context
            .interpreter
            .halt(InstructionResult::StateChangeDuringStaticCall);
        return;
    }
    let Some([index, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };

    // Static SSTORE cost (rskj `GasCost.RESET_SSTORE`/`CLEAR_SSTORE` = 5000),
    // charged before the store, matching revm's `host::sstore` ordering.
    let static_gas = context.host.gas_params().sstore_static_gas();
    if !context.interpreter.gas.record_cost(static_gas) {
        context.interpreter.halt_oog();
        return;
    }

    let target = context.interpreter.input.target_address();
    let Some(state_load) = context.host.sstore(target, index, value) else {
        context.interpreter.halt_fatal();
        return;
    };

    // Pre-Istanbul (Petersburg) dynamic cost: `is_istanbul = false`.
    let dynamic = context
        .host
        .gas_params()
        .sstore_dynamic_gas(false, &state_load.data, state_load.is_cold);
    if !context.interpreter.gas.record_cost(dynamic) {
        context.interpreter.halt_oog();
        return;
    }

    // RSKIP-144: the cell counts as written whatever value went into it.
    // revm journals an `SSTORE` only when the value changes
    // (`JournaledAccount::sstore_concrete_error`: `if slot.present_value !=
    // new`), so storing a value a cell already holds leaves no entry for the
    // collision tracker to find. rskj has no such check --
    // `Program.storageSave` calls `addStorageRow` unconditionally -- so a
    // sublist that stores an unchanged value collides there with one that
    // merely reads the cell, and without this we would accept a block the
    // network rejects.
    //
    // Recorded here rather than beside `host.sstore` above because rskj
    // spends the gas before `storageSave` (`VM.doSSTORE`): an SSTORE that
    // runs out of gas writes nothing and must record nothing.
    if crate::collision::records_attempted_writes() {
        crate::collision::note_storage_write_attempt(target, B256::from(index));
    }

    context
        .interpreter
        .gas
        .record_refund(context.host.gas_params().sstore_refund(false, &state_load.data));
}

/// CALLCODE with rskj gas semantics (no new-account charge).
pub fn rsk_call_code<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, value, false)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: context.interpreter.input.target_address(),
                caller: context.interpreter.input.target_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Transfer(value),
                scheme: CallScheme::CallCode,
                is_static: context.interpreter.runtime_flag.is_static(),
                return_memory_offset,
            },
        ))));
}

/// DELEGATECALL with rskj gas semantics (zero value: no stipend, no VT).
pub fn rsk_delegate_call<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, U256::ZERO, false)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: context.interpreter.input.target_address(),
                caller: context.interpreter.input.caller_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Apparent(context.interpreter.input.call_value()),
                scheme: CallScheme::DelegateCall,
                is_static: context.interpreter.runtime_flag.is_static(),
                return_memory_offset,
            },
        ))));
}

/// STATICCALL with rskj gas semantics (zero value: no stipend, no VT).
pub fn rsk_static_call<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    if std::env::var_os("RUSTOCK_TRACE_OPS").is_some() {
        let bytes = context.interpreter.memory.slice(input.clone());
        tracing::debug!("STATICCALL to={to} input=0x{}", alloy_primitives::hex::encode(&*bytes));
    }

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, U256::ZERO, false)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: to,
                caller: context.interpreter.input.target_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Transfer(U256::ZERO),
                scheme: CallScheme::StaticCall,
                is_static: true,
                return_memory_offset,
            },
        ))));
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::context_interface::cfg::GasParams;
    use revm::interpreter::interpreter::EthInterpreter;
    use revm::interpreter::Interpreter;

    /// Pre-RSKIP150 the handler writes a precompile's full output at the
    /// CALL's real outOffs even when outSize == 0, so the range must keep
    /// the true offset (revm substitutes usize::MAX for zero-size regions).
    #[test]
    fn zero_size_call_range_keeps_real_offset() {
        let mut interp = Interpreter::<EthInterpreter>::default();
        let params = GasParams::default();

        let r = rsk_call_memory_range(&mut interp, &params, U256::from(0x80), U256::ZERO)
            .expect("range");
        assert_eq!(r, 0x80..0x80);

        // Offsets that don't fit usize fall back to revm's sentinel.
        let r = rsk_call_memory_range(&mut interp, &params, U256::MAX, U256::ZERO)
            .expect("range");
        assert_eq!(r.start, usize::MAX);
        assert!(r.is_empty());
    }

    /// The word BALANCE pushes is the one rskj makes of the balance: the
    /// balance itself, the bytes of one below zero without their sign
    /// (`BigInteger.toByteArray`), and none for one that takes a 33rd byte.
    /// rskj's release answered each of those below zero here, down to
    /// -10^18, through `eth_call` (the rpc crate's
    /// `testdata/rskj_local_calls.txt`).
    #[test]
    fn a_balance_reads_as_the_word_rskj_makes_of_it() {
        let word = |held: u64, owed: u64| balance_word(U256::from(held), U256::from(owed));
        assert_eq!(word(7, 0), Some(U256::from(7)));
        assert_eq!(word(7, 7), Some(U256::ZERO));
        assert_eq!(word(0, 1), Some(U256::from(0xff)));
        assert_eq!(word(1, 3), Some(U256::from(0xfe)));
        assert_eq!(word(0, 127), Some(U256::from(0x81)));
        assert_eq!(word(0, 128), Some(U256::from(0x80)));
        assert_eq!(word(0, 129), Some(U256::from(0xff7f)));
        assert_eq!(
            word(0, 1_000_000_000_000_000_000),
            Some(U256::from(0xf21f_494c_589c_0000u64))
        );

        // 32 bytes hold -2^255 to 2^255 - 1.
        let (one, top) = (U256::from(1), U256::from(1) << 255);
        assert_eq!(balance_word(top - one, U256::ZERO), Some(top - one));
        assert_eq!(balance_word(top, U256::ZERO), None);
        assert_eq!(balance_word(U256::MAX, U256::ZERO), None);
        assert_eq!(balance_word(U256::ZERO, top - one), Some(top + one));
        assert_eq!(balance_word(U256::ZERO, top), Some(top));
        assert_eq!(balance_word(U256::ZERO, top + one), None);
        assert_eq!(balance_word(U256::ZERO, U256::MAX), None);
    }
}

#[cfg(test)]
mod thread_affinity_tests {
    use super::*;

    /// The hazard, demonstrated rather than described: installing on one
    /// thread leaves every other thread holding the defaults, and the
    /// defaults are all plausible consensus values. This is why an EVM is
    /// configured on the thread that executes it.
    #[test]
    fn configuration_does_not_cross_threads() {
        assert!(
            !is_configured_on_this_thread(),
            "nothing has been installed on the test thread"
        );

        let child_saw = std::thread::spawn(|| {
            let mut table =
                EthInstructions::<revm::interpreter::interpreter::EthInterpreter, DummyHost>::new_mainnet_with_spec(revm::primitives::hardfork::SpecId::SHANGHAI);
            install(
                &mut table,
                true,
                true,
                true,
                false,
                false,
                true,
                false,
                false,
                false,
                &[Address::new([0x01; 20])],
                &[Address::new([0x01; 20])],
                BlockWords {
                    coinbase: Address::new([0xbb; 20]),
                    gas_limit: U256::from(6_800_000),
                    minimum_gas_price: U256::from(60_000_000),
                },
            );
            (
                is_configured_on_this_thread(),
                REAL_COINBASE.with(|c| c.get()),
                GAS_LIMIT.with(|c| c.get()),
                EXTCODESIZE_MAX_PRECOMPILES.with(|p| p.borrow().len()),
            )
        })
        .join()
        .expect("child thread");

        assert_eq!(
            child_saw,
            (true, Address::new([0xbb; 20]), U256::from(6_800_000), 1),
            "the thread that installed sees its own configuration"
        );
        assert!(
            !is_configured_on_this_thread(),
            "and no other thread sees any of it -- a worker executing with \
             these defaults would push COINBASE 0x0 and lose RSKIP90"
        );
    }

    /// `DummyHost` only needs to exist for the table to be generic over
    /// something the instructions take, which is the executor's context: it
    /// answers EXTCODEHASH's `ContractMarker`. No instruction runs here.
    type DummyHost = revm::context::Context<
        revm::context::BlockEnv,
        revm::context::TxEnv,
        revm::context::CfgEnv,
        RskDb,
        revm::context::Journal<RskDb>,
        crate::raw_storage::RskChainExt,
    >;
}
