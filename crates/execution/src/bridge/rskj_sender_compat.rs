//! rskj-compatible peg-in sender detection for P2SH-multisig inputs, and the
//! redeem-script parsing it shares with signature stripping.
//!
//! # Why this file exists, and why it is separate
//!
//! A legacy peg-in's sender is inferred from the first input's `scriptSig`.
//! Two of the four shapes rskj recognises -- `P2SHMULTISIG` and `P2SHP2WSH` --
//! can never be *credited*: no single public key can be recovered, so no RSK
//! destination exists, and `isTxLockableForLegacyVersion` rejects them. They
//! are recognised only to compute a Bitcoin address to refund to.
//!
//! Recognising them faithfully requires reproducing `bitcoinj-thin`'s
//! `Script.isSentToMultiSig`, which is not a shape test but a dispatch over
//! five redeem-script parsers, each with its own structure validator and
//! inner-redeem extractor, one of them recursive. All of it runs on bytes an
//! attacker chose.
//!
//! An RSKIP proposes deleting this from consensus. Until that is adopted the
//! behaviour must be emulated exactly, so everything belonging to it lives
//! here, behind one predicate and one switch:
//!
//! * [`is_sent_to_multisig`] -- the port. Nothing else in the tree parses
//!   redeem scripts this way.
//! * [`set_enabled`] -- turns the sender path off. When the RSKIP activates,
//!   the node sets it false at the activation height, and the path's two
//!   callers in `peg.rs` can then be deleted.
//! * [`set_observer`] -- fires whenever the path is actually exercised, so an
//!   operator learns that a peg-in depended on code we intend to remove.
//!
//! rskj strips a transaction's signatures with the same parsers
//! (`BitcoinUtils.removeSignaturesFromMultiSigTransaction`, which the SVP
//! checks and the pegout index run on every input), so the port,
//! [`redeem_script_of_input`] and [`signatures_required_to_spend`] serve that
//! too. That use isn't the sender path: it doesn't follow [`set_enabled`], and
//! it stays when the sender path goes.
//!
//! # Fidelity notes
//!
//! Verified against `co.rsk.bitcoinj:bitcoinj-thin:0.14.4-rsk-18`, the artifact
//! `rskj-core/build.gradle` pins -- not against classic bitcoinj, which is a
//! different codebase.
//!
//! This module deliberately does **not** reuse `release_tx::parse_chunks` or
//! `release_tx::Chunk`. Those model a script the way rustock finds convenient;
//! bitcoinj's `ScriptChunk` keeps the opcode alongside the data, and several
//! decisions here turn on the opcode of a *push* -- notably that `OP_0` is
//! push data rather than an opcode, and that a pushed number can serve as M or
//! N. A shared type would quietly lose that.

use std::sync::atomic::{AtomicBool, Ordering};

// --- opcodes, named as bitcoinj names them ---------------------------------

// Named for the reader even though only the tests mention it: `OP_0` being
// push data rather than an opcode is the fact that makes rskj throw, and the
// constant is where that is written down.
#[allow(dead_code)]
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_DUP: u8 = 0x76;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;

/// `RedeemScriptParserFactory.NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT_SERIALIZED`.
///
/// bitcoinj carries this one script as a special case because a validation bug
/// meant it was never detected as an ERP federation on testnet, and testnet
/// consensus depends on that continuing. Its parser returns `getM() == -1`, so
/// `isSentToMultiSig` answers false for it and for nothing else that parses.
const NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT: &str = "6453210208f40073a9e43b3e9103acec79767a6de9b0409749884e989960fee578012fce210225e892391625854128c5c4ea4340de0c2a70570f33db53426fc9c746597a03f42102afc230c2d355b1a577682b07bc2646041b5d0177af0f98395a46018da699b6da210344a3c38cd59afcba3edcebe143e025574594b001700dec41e59409bdbd0f2a0921039a060badbeb24bee49eb2063f616c0f0f0765d4ca646b20a88ce828f259fcdb955670300cd50b27552210216c23b2ea8e4f11c3f9e22711addb1d16a93964796913830856b568cc3ea21d3210275562901dd8faae20de0a4166362a4f82188db77dbed4ca887422ea1ec185f1421034db69f2112f4fb1bb6141bf6e2bd6631f0484d0bd95b16767902c9fe219d4a6f5368ae";

/// Guard against unbounded recursion through nested flyover prefixes.
///
/// bitcoinj has no such guard and would eventually raise StackOverflowError.
/// A flyover prefix costs 34 bytes, and Bitcoin caps a script at 10,000, so no
/// real script exceeds ~294 levels; this bound cannot be reached by anything
/// that could arrive in a block, and exists only so a malformed input cannot
/// take the process down.
const MAX_FLYOVER_DEPTH: usize = 1_000;

// --- the verdict -----------------------------------------------------------

/// What rskj does with a redeem script, including the case where it does not
/// return at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// `isSentToMultiSig()` returned true.
    Multisig,
    /// `isSentToMultiSig()` returned false, whether by answering or by
    /// catching `ScriptException`.
    NotMultisig,
    /// rskj throws a RuntimeException that `isSentToMultiSig`'s
    /// `catch (ScriptException)` does not catch.
    ///
    /// `Bridge.execute` catches it, logs, calls `panicProcessor.panic` and
    /// rethrows as `VMException`, so the whole `registerBtcTransaction` call
    /// fails. Every rskj node does this identically, which makes it
    /// deterministic rather than a consensus hazard -- but it is a completely
    /// different outcome from "not a multisig", and a node that answered false
    /// here would diverge.
    ///
    /// Demonstrated against the pinned artifact: a redeem script whose first
    /// chunk is `OP_0` reaches `decodePositiveNConsideringEncoding`, which
    /// indexes `data[data.length - 1]` on empty data and raises
    /// `ArrayIndexOutOfBoundsException`. So does an ERP-shaped script whose
    /// `OP_ELSE` is third from the end: both ERP validators read one chunk
    /// past it, and `List.get` raises `IndexOutOfBoundsException`.
    RskjThrows(&'static str),
}

// --- switch ----------------------------------------------------------------

static ENABLED: AtomicBool = AtomicBool::new(true);

/// Turn the emulation on or off. On by default: rskj has not changed, so a
/// node that wants to stay in consensus must emulate it.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    #[cfg(test)]
    if let Some(on) = TEST_SWITCH.with(std::cell::Cell::get) {
        return on;
    }
    ENABLED.load(Ordering::Relaxed)
}

#[cfg(test)]
thread_local! {
    /// A test's own setting of the switch, on its own thread alone. A test
    /// that flipped the process-wide switch changed the answers of the tests
    /// running beside it.
    static TEST_SWITCH: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Sets the switch for the calling thread alone, or with `None` clears that
/// setting.
#[cfg(test)]
pub(crate) fn set_enabled_on_this_thread(on: Option<bool>) {
    TEST_SWITCH.with(|switch| switch.set(on));
}

// --- observer --------------------------------------------------------------

/// A peg-in that exercised the path this node intends to remove.
#[derive(Debug, Clone)]
pub struct Sighting {
    pub block: u64,
    /// The Bitcoin transaction being registered, as a hex txid.
    pub btc_txid: String,
    /// `"P2SH-multisig"` or `"P2SH-P2WSH"`, or the throwing case.
    pub shape: &'static str,
    /// The address the refund would go to, hash160 in hex.
    pub refund_hash160: String,
}

type Observer = Box<dyn Fn(&Sighting) + Send + Sync>;
static OBSERVER: std::sync::OnceLock<Observer> = std::sync::OnceLock::new();

/// Install the process-wide observer, once. The execution crate cannot depend
/// on the alerting crate -- alerting depends on execution -- so the node wires
/// them together at startup, exactly as it does for supply conservation.
pub fn set_observer<F>(f: F) -> Result<(), &'static str>
where
    F: Fn(&Sighting) + Send + Sync + 'static,
{
    OBSERVER.set(Box::new(f)).map_err(|_| "sender-compat observer already installed")
}

/// Log the sighting and hand it to the observer if one is installed.
///
/// Logging happens either way, so the record exists whether or not the node was
/// built with mail support or is running a replay harness.
pub fn report(s: &Sighting) {
    tracing::warn!(
        target: "rustock::bridge",
        "peg-in at #{} (btc tx {}) used the rskj-compat {} sender path, refunding to {}. \
         This path is scheduled for removal; see docs/open-divergence-redeem-parser.md",
        s.block, s.btc_txid, s.shape, s.refund_hash160
    );
    if let Some(obs) = OBSERVER.get() {
        obs(s);
    }
}

// --- bitcoinj's ScriptChunk ------------------------------------------------

/// `co.rsk.bitcoinj.script.ScriptChunk`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JChunk {
    opcode: u8,
    /// `null` in Java for a pure opcode; `Some(vec![])` for `OP_0`, which
    /// pushes an empty vector. The distinction is load-bearing.
    data: Option<Vec<u8>>,
}

impl JChunk {
    /// `isOpCode(): opcode > OP_PUSHDATA4`. Note this makes `OP_0` NOT an
    /// opcode, and makes `OP_1..OP_16` opcodes.
    fn is_op_code(&self) -> bool {
        self.opcode > OP_PUSHDATA4
    }

    /// `isPushData(): opcode <= OP_16`.
    fn is_push_data(&self) -> bool {
        self.opcode <= OP_16
    }

    fn is_opcode_small_number(&self) -> bool {
        self.is_op_code() && self.opcode >= OP_1 && self.opcode <= OP_16
    }

    fn equals_op_code(&self, op: u8) -> bool {
        self.is_op_code() && self.opcode == op
    }

    fn is_op_checkmultisig(&self) -> bool {
        self.is_op_code()
            && (self.opcode == OP_CHECKMULTISIG || self.opcode == OP_CHECKMULTISIGVERIFY)
    }

    /// `decodePositiveN()`. `Err(Some(_))` is an `IllegalArgumentException`,
    /// which callers catch; `Err(None)` is the uncaught index error.
    fn decode_positive_n(&self) -> Result<i64, Option<()>> {
        if self.is_opcode_small_number() {
            // decodeOpN: OP_1..OP_16 -> 1..16
            return Ok((self.opcode - (OP_1 - 1)) as i64);
        }
        if self.is_push_data() {
            return self.decode_positive_n_considering_encoding();
        }
        Err(Some(())) // IllegalArgumentException
    }

    /// `decodePositiveNConsideringEncoding()`.
    ///
    /// The empty-data case is the one that matters: Java reads
    /// `data[dataLength - 1]` before checking the length, so `OP_0` -- whose
    /// data is an empty array, not null -- raises
    /// `ArrayIndexOutOfBoundsException`. That is not an
    /// `IllegalArgumentException`, so `isPositiveN`'s catch does not cover it,
    /// nor does `hasStandardRedeemScriptStructure`'s `catch (IllegalStateException)`,
    /// nor `isSentToMultiSig`'s `catch (ScriptException)`.
    fn decode_positive_n_considering_encoding(&self) -> Result<i64, Option<()>> {
        let data = match &self.data {
            None => return Err(Some(())), // "Chunk has null data."
            Some(d) => d,
        };
        if data.is_empty() {
            return Err(None); // ArrayIndexOutOfBoundsException: Index -1
        }
        if data[data.len() - 1] & 0x80 != 0 {
            return Err(Some(())); // "Number from chunk is not positive."
        }
        if data.len() > 4 {
            return Err(Some(())); // "more than 4 bytes"
        }
        // decodeMPI over the big-endian reversal of a little-endian value,
        // with the sign bit already known clear.
        let mut v: i64 = 0;
        for (i, b) in data.iter().enumerate() {
            v |= (*b as i64) << (8 * i);
        }
        Ok(v)
    }

    /// `isPositiveN()`: true when `decodePositiveN` returns. An
    /// `IllegalArgumentException` yields false; the index error propagates.
    fn is_positive_n(&self) -> Result<bool, ()> {
        match self.decode_positive_n() {
            Ok(_) => Ok(true),
            Err(Some(())) => Ok(false),
            Err(None) => Err(()),
        }
    }
}

/// `ScriptParser.parseScriptProgram`. `None` is a `ScriptException`.
fn parse_script_program(program: &[u8]) -> Option<Vec<JChunk>> {
    let mut chunks = Vec::new();
    let mut pos = 0usize;
    while pos < program.len() {
        let opcode = program[pos];
        pos += 1;
        let data_to_read: Option<usize> = match opcode {
            o if o < OP_PUSHDATA1 => Some(o as usize),
            OP_PUSHDATA1 => {
                if program.len() - pos < 1 { return None; }
                let n = program[pos] as usize;
                pos += 1;
                Some(n)
            }
            OP_PUSHDATA2 => {
                if program.len() - pos < 2 { return None; }
                let n = u16::from_le_bytes([program[pos], program[pos + 1]]) as usize;
                pos += 2;
                Some(n)
            }
            OP_PUSHDATA4 => {
                if program.len() - pos < 4 { return None; }
                let n = u32::from_le_bytes([
                    program[pos], program[pos + 1], program[pos + 2], program[pos + 3],
                ]) as usize;
                pos += 4;
                Some(n)
            }
            _ => None,
        };
        match data_to_read {
            None => chunks.push(JChunk { opcode, data: None }),
            Some(n) => {
                if n > program.len() - pos {
                    return None; // "Push of data element that is larger than remaining data"
                }
                chunks.push(JChunk { opcode, data: Some(program[pos..pos + n].to_vec()) });
                pos += n;
            }
        }
    }
    Some(chunks)
}

/// Whether bitcoinj parses `program` as a script. `new Script(program)` throws
/// a `ScriptException` for one it can't: a push that runs past the end.
pub fn parses_as_script(program: &[u8]) -> bool {
    parse_script_program(program).is_some()
}

/// A script's chunks as bitcoinj holds them, each by its data: `None` for an
/// opcode, which has none, and the bytes for a push, which `OP_0` makes of
/// nothing. `None` overall is the `ScriptException` for a script bitcoinj
/// can't parse.
pub fn chunk_data(program: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
    Some(
        parse_script_program(program)?
            .into_iter()
            .map(|chunk| chunk.data)
            .collect(),
    )
}

// --- RedeemScriptValidator -------------------------------------------------

fn is_redeem_like_script(chunks: &[JChunk]) -> bool {
    if chunks.len() < 4 {
        return false;
    }
    let last = &chunks[chunks.len() - 1];
    if last.is_op_checkmultisig() {
        return true;
    }
    let penultimate = &chunks[chunks.len() - 2];
    last.equals_op_code(OP_ENDIF) && penultimate.is_op_checkmultisig()
}

/// `hasStandardRedeemScriptStructure`. `Err(())` is the uncaught index error.
fn has_standard_structure(chunks: &[JChunk]) -> Result<bool, ()> {
    if !is_redeem_like_script(chunks) {
        return Ok(false);
    }
    let size = chunks.len();
    if !chunks[size - 1].is_op_checkmultisig() {
        return Ok(false);
    }
    let first = &chunks[0];
    let second_to_last_index = size - 2;
    let second_to_last = &chunks[second_to_last_index];

    // Java evaluates the left operand first, so a first chunk that raises the
    // index error does so before the second is examined.
    if !(first.is_positive_n()? && second_to_last.is_positive_n()?) {
        return Ok(false);
    }
    let num_keys = match second_to_last.decode_positive_n() {
        Ok(n) => n,
        Err(Some(())) => return Ok(false),
        Err(None) => return Err(()),
    };
    if size as i64 != num_keys + 3 {
        return Ok(false);
    }
    for c in &chunks[1..second_to_last_index] {
        if c.is_op_code() {
            return Ok(false); // should be public keys, not opcodes
        }
    }
    Ok(true)
}

/// `hasFlyoverPrefix`. The hash is pushed by the opcode 32 itself: 32 bytes
/// behind an `OP_PUSHDATA` opcode aren't a prefix.
fn has_flyover_prefix(chunks: &[JChunk]) -> bool {
    chunks.len() > 2
        && chunks[0].opcode == 32
        && chunks[0].data.as_ref().is_some_and(|d| d.len() == 32)
        && chunks[1].equals_op_code(OP_DROP)
}

fn has_flyover_structure(chunks: &[JChunk]) -> bool {
    has_flyover_prefix(chunks) && is_redeem_like_script(&chunks[2..])
}

/// The OP_ELSE scan shared by both ERP validators: the first `OP_ELSE` that is
/// at least third from the end, whose next three chunks must be a push,
/// `OP_CSV` and `OP_DROP`. Java reads all three before it tests any, and its
/// bound lets the third lie one past the end: `Err` is the
/// `IndexOutOfBoundsException` that read raises.
fn find_erp_else(chunks: &[JChunk]) -> Result<Option<usize>, &'static str> {
    for i in 1..chunks.len() {
        if chunks[i].equals_op_code(OP_ELSE) && chunks.len() >= i + 3 {
            let Some(drop) = chunks.get(i + 3) else {
                return Err("IndexOutOfBoundsException reading past an ERP script's OP_ELSE");
            };
            let ok = chunks[i + 1].is_push_data()
                && chunks[i + 2].equals_op_code(OP_CHECKSEQUENCEVERIFY)
                && drop.equals_op_code(OP_DROP);
            return Ok(ok.then_some(i));
        }
    }
    Ok(None)
}

/// `hasP2shErpRedeemScriptStructure`. `Err` is an index error nothing catches,
/// named.
fn has_p2sh_erp_structure(chunks: &[JChunk]) -> Result<bool, &'static str> {
    if !is_redeem_like_script(chunks) {
        return Ok(false);
    }
    if !chunks[0].equals_op_code(OP_NOTIF) || !chunks[chunks.len() - 1].equals_op_code(OP_ENDIF) {
        return Ok(false);
    }
    let Some(else_index) = find_erp_else(chunks)? else {
        return Ok(false);
    };
    let default_fed = &chunks[1..else_index];
    if else_index + 4 > chunks.len() - 1 {
        return Ok(false);
    }
    let erp_fed = &chunks[else_index + 4..chunks.len() - 1];
    let standard = |fed: &[JChunk]| {
        has_standard_structure(fed)
            .map_err(|()| "ArrayIndexOutOfBoundsException decoding the P2SH-ERP inner redeem")
    };
    Ok(standard(default_fed)? && standard(erp_fed)?)
}

/// `hasNonStandardErpRedeemScriptStructure`, with the same `Err`.
fn has_non_standard_erp_structure(chunks: &[JChunk]) -> Result<bool, &'static str> {
    if !is_redeem_like_script(chunks) {
        return Ok(false);
    }
    if chunks[0].opcode != OP_NOTIF || !chunks[chunks.len() - 2].equals_op_code(OP_ENDIF) {
        return Ok(false);
    }
    let Some(else_index) = find_erp_else(chunks)? else {
        return Ok(false);
    };

    // Both halves are validated with OP_CHECKMULTISIG appended, because a
    // non-standard ERP redeem carries it once at the end rather than in each
    // branch.
    let cms = JChunk { opcode: OP_CHECKMULTISIG, data: None };
    let mut default_fed: Vec<JChunk> = chunks[1..else_index].to_vec();
    default_fed.push(cms.clone());
    if else_index + 4 > chunks.len() - 2 {
        return Ok(false);
    }
    let mut erp_fed: Vec<JChunk> = chunks[else_index + 4..chunks.len() - 2].to_vec();
    erp_fed.push(cms);

    let standard = |fed: &[JChunk]| {
        has_standard_structure(fed).map_err(|()| {
            "ArrayIndexOutOfBoundsException decoding the non-standard ERP inner redeem"
        })
    };
    Ok(standard(&default_fed)? && standard(&erp_fed)?)
}

// --- the dispatch ----------------------------------------------------------

/// `Script.isSentToMultiSig()` over a redeem script.
///
/// Mirrors `RedeemScriptParserFactory.get` followed by `getM() > 0`. Every
/// parser the factory can return delegates `getM()` inward to a standard
/// parser, whose M is `decodePositiveN(chunk 0)`. That refuses a negative
/// number and nothing else, so an M pushed as zero passes the structure check
/// and selects a parser, and the answer is then false. The hardcoded testnet
/// script's parser returns -1 on purpose.
pub fn is_sent_to_multisig(redeem_script: &[u8]) -> Verdict {
    let Some(chunks) = parse_script_program(redeem_script) else {
        return Verdict::NotMultisig; // ScriptException, caught
    };
    dispatch(&chunks, 0)
}

fn dispatch(chunks: &[JChunk], depth: usize) -> Verdict {
    if depth > MAX_FLYOVER_DEPTH {
        return Verdict::NotMultisig;
    }
    // The hardcoded testnet script is compared before anything else, and its
    // parser reports M = -1. bitcoinj compares the chunks with `List.equals`,
    // and a chunk equals another only at the same offset in its program, so
    // the script is matched as a whole program alone. Behind a flyover prefix
    // its chunks start 34 bytes on, and it is parsed like any other script.
    if depth == 0 {
        let hardcoded = parse_script_program(&hex_decode(NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT));
        if hardcoded.is_some_and(|hardcoded| chunks == hardcoded.as_slice()) {
            return Verdict::NotMultisig;
        }
    }
    if chunks.len() < 4 {
        return Verdict::NotMultisig; // factory throws ScriptException, caught
    }
    if has_flyover_structure(chunks) {
        // FlyoverRedeemScriptParser calls the factory again on the inner script.
        return dispatch(&chunks[2..], depth + 1);
    }
    match has_standard_structure(chunks) {
        Err(()) => return Verdict::RskjThrows(
            "ArrayIndexOutOfBoundsException decoding M or N from an empty push",
        ),
        Ok(true) => return positive_m(&chunks[0]),
        Ok(false) => {}
    }
    // An ERP script's M is its default federation's, which follows OP_NOTIF.
    match has_p2sh_erp_structure(chunks) {
        Err(why) => return Verdict::RskjThrows(why),
        Ok(true) => return positive_m(&chunks[1]),
        Ok(false) => {}
    }
    match has_non_standard_erp_structure(chunks) {
        Err(why) => return Verdict::RskjThrows(why),
        Ok(true) => return positive_m(&chunks[1]),
        Ok(false) => {}
    }
    Verdict::NotMultisig // factory throws "unknown redeem script", caught
}

/// `getM() > 0` over the chunk the selected parser reads M from. The structure
/// check has decoded that chunk already, so only a zero is left to refuse.
fn positive_m(m: &JChunk) -> Verdict {
    match m.decode_positive_n() {
        Ok(m) if m > 0 => Verdict::Multisig,
        _ => Verdict::NotMultisig,
    }
}

// --- signature stripping ----------------------------------------------------

/// `BitcoinUtils.extractRedeemScriptFromInput`: the last push of an input's
/// witness if it has one, else the last chunk of its scriptSig, in either case
/// only if bitcoinj can parse it as a script.
///
/// `Err` is the `ScriptException` `TransactionInput.getScriptSig()` throws on a
/// scriptSig it can't parse, which nothing between it and `Bridge.execute`
/// catches.
pub fn redeem_script_of_input(
    script_sig: &[u8],
    last_witness_push: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, &'static str> {
    if let Some(push) = last_witness_push {
        return Ok(parse_script_program(push).map(|_| push.to_vec()));
    }
    let Some(chunks) = parse_script_program(script_sig) else {
        return Err("ScriptException parsing an input's scriptSig");
    };
    // An opcode's data is null, which finds no script. OP_0's is empty, which
    // finds the empty one.
    let Some(program) = chunks.last().and_then(|c| c.data.as_ref()) else {
        return Ok(None);
    };
    Ok(parse_script_program(program).map(|_| program.clone()))
}

/// `Script.getNumberOfSignaturesRequiredToSpend()`: a multisig's M, and one for
/// a pay-to-address or pay-to-pubkey script. bitcoinj throws for anything else:
/// an `IllegalStateException`, or `isSentToAddress`'s `NullPointerException`
/// for a script that opens `OP_DUP OP_HASH160` with an opcode where the hash
/// belongs. Nothing between it and `Bridge.execute` catches any of them.
/// Callers pass only scripts bitcoinj has parsed, so the unparseable answer is
/// never reached.
pub fn signatures_required_to_spend(script: &[u8]) -> Result<i64, &'static str> {
    let Some(chunks) = parse_script_program(script) else {
        return Err("ScriptException parsing the script");
    };
    match dispatch(&chunks, 0) {
        Verdict::Multisig => multisig_m(&chunks),
        Verdict::RskjThrows(why) => Err(why),
        Verdict::NotMultisig if is_sent_to_address(&chunks) || is_sent_to_raw_pub_key(&chunks) => {
            Ok(1)
        }
        Verdict::NotMultisig => Err("bitcoinj can't count the signatures this script needs"),
    }
}

/// `getRedeemScriptParser().getM()` for a script `dispatch` finds a multisig:
/// a flyover script's inner script's, a standard multisig's first chunk, and an
/// ERP script's default multisig's first chunk, which follows its `OP_NOTIF`.
/// The structure checks have decoded that chunk already, so the error can't be
/// reached.
fn multisig_m(chunks: &[JChunk]) -> Result<i64, &'static str> {
    if has_flyover_structure(chunks) {
        return multisig_m(&chunks[2..]);
    }
    let first = if has_standard_structure(chunks) == Ok(true) {
        &chunks[0]
    } else {
        &chunks[1]
    };
    first
        .decode_positive_n()
        .map_err(|_| "decoding a multisig's M")
}

/// `Script.isSentToAddress()`. Where Java's missing null check throws, for an
/// opcode in the hash's place, this answers false: its one caller fails the
/// same either way.
fn is_sent_to_address(chunks: &[JChunk]) -> bool {
    chunks.len() == 5
        && chunks[0].equals_op_code(OP_DUP)
        && chunks[1].equals_op_code(OP_HASH160)
        && chunks[2].data.as_ref().is_some_and(|hash| hash.len() == 20)
        && chunks[3].equals_op_code(OP_EQUALVERIFY)
        && chunks[4].equals_op_code(OP_CHECKSIG)
}

/// `Script.isSentToRawPubKey()`.
fn is_sent_to_raw_pub_key(chunks: &[JChunk]) -> bool {
    chunks.len() == 2
        && chunks[1].equals_op_code(OP_CHECKSIG)
        && !chunks[0].is_op_code()
        && chunks[0].data.as_ref().is_some_and(|d| d.len() > 1)
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> Vec<u8> {
        let mut k = vec![0x02u8; 33];
        k[32] = i;
        k
    }

    fn standard_redeem(m: u8, n: u8) -> Vec<u8> {
        let mut s = vec![0x50 + m];
        for i in 0..n {
            s.push(33);
            s.extend_from_slice(&key(i));
        }
        s.push(0x50 + n);
        s.push(OP_CHECKMULTISIG);
        s
    }

    /// A flyover prefix, which is a hash pushed by the opcode 32 and `OP_DROP`,
    /// in front of `inner`.
    fn flyover(inner: &[u8]) -> Vec<u8> {
        let mut s = vec![32];
        s.extend_from_slice(&[0xAB; 32]);
        s.push(OP_DROP);
        s.extend_from_slice(inner);
        s
    }

    /// What both ERP shapes carry between their two federations.
    const ELSE_CSV_DROP: [u8; 6] = [OP_ELSE, 0x02, 0x00, 0x20, OP_CHECKSEQUENCEVERIFY, OP_DROP];

    fn p2sh_erp(default_fed: &[u8], erp_fed: &[u8]) -> Vec<u8> {
        let mut s = vec![OP_NOTIF];
        s.extend_from_slice(default_fed);
        s.extend_from_slice(&ELSE_CSV_DROP);
        s.extend_from_slice(erp_fed);
        s.push(OP_ENDIF);
        s
    }

    /// The older ERP shape: neither multisig keeps its own `OP_CHECKMULTISIG`,
    /// and one closes the script.
    fn non_standard_erp(default_fed: &[u8], erp_fed: &[u8]) -> Vec<u8> {
        let mut s = vec![OP_NOTIF];
        s.extend_from_slice(&default_fed[..default_fed.len() - 1]);
        s.extend_from_slice(&ELSE_CSV_DROP);
        s.extend_from_slice(&erp_fed[..erp_fed.len() - 1]);
        s.extend_from_slice(&[OP_ENDIF, OP_CHECKMULTISIG]);
        s
    }

    #[test]
    fn standard_multisig_is_multisig() {
        assert_eq!(is_sent_to_multisig(&standard_redeem(2, 3)), Verdict::Multisig);
        let mut verify = standard_redeem(2, 3);
        *verify.last_mut().unwrap() = OP_CHECKMULTISIGVERIFY;
        assert_eq!(is_sent_to_multisig(&verify), Verdict::Multisig);
    }

    /// The divergence this module exists to close: rustock's own shape check
    /// answers false for a flyover-wrapped redeem, rskj answers true by
    /// stripping the prefix and calling the factory again.
    #[test]
    fn flyover_wrapped_redeem_is_multisig() {
        let mut s = vec![32];
        s.extend_from_slice(&[0xAB; 32]);
        s.push(OP_DROP);
        s.extend_from_slice(&standard_redeem(2, 3));
        assert_eq!(is_sent_to_multisig(&s), Verdict::Multisig);
    }

    #[test]
    fn nested_flyover_resolves_through_the_recursion() {
        let mut inner = vec![32];
        inner.extend_from_slice(&[0xCD; 32]);
        inner.push(OP_DROP);
        inner.extend_from_slice(&standard_redeem(1, 2));
        let mut s = vec![32];
        s.extend_from_slice(&[0xAB; 32]);
        s.push(OP_DROP);
        s.extend_from_slice(&inner);
        assert_eq!(is_sent_to_multisig(&s), Verdict::Multisig);
    }

    #[test]
    fn p2sh_erp_redeem_is_multisig() {
        let mut s = vec![OP_NOTIF];
        s.extend_from_slice(&standard_redeem(2, 3));
        s.push(OP_ELSE);
        s.push(0x02);
        s.extend_from_slice(&[0x00, 0x20]);
        s.push(OP_CHECKSEQUENCEVERIFY);
        s.push(OP_DROP);
        s.extend_from_slice(&standard_redeem(1, 2));
        s.push(OP_ENDIF);
        assert_eq!(is_sent_to_multisig(&s), Verdict::Multisig);
    }

    /// Demonstrated against bitcoinj-thin 0.14.4-rsk-18:
    ///   new Script(hex("000
    ///   1AA01BBAE")).isSentToMultiSig()
    ///   -> java.lang.ArrayIndexOutOfBoundsException: Index -1 out of bounds for length 0
    ///
    /// rskj's Bridge.execute catches it and rethrows as VMException, failing
    /// the whole registerBtcTransaction call. A node that answered "not
    /// multisig" here would process a peg-in rskj refuses outright.
    #[test]
    fn op_zero_as_m_makes_rskj_throw() {
        let redeem = [OP_0, 0x01, 0xAA, 0x01, 0xBB, OP_CHECKMULTISIG];
        assert!(
            matches!(is_sent_to_multisig(&redeem), Verdict::RskjThrows(_)),
            "an empty push where M belongs raises the index error in rskj"
        );
    }

    #[test]
    fn the_hardcoded_testnet_script_is_not_multisig() {
        let script = hex_decode(NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT);
        assert_eq!(
            is_sent_to_multisig(&script),
            Verdict::NotMultisig,
            "its parser returns M = -1 on purpose, to preserve testnet consensus"
        );
    }

    /// Demonstrated against bitcoinj-thin 0.14.4-rsk-18:
    ///   new Script(hex("6467ae68")).isSentToMultiSig()
    ///   -> java.lang.IndexOutOfBoundsException: Index 4 out of bounds for length 4
    ///
    /// Both ERP validators look for an `OP_ELSE` with `chunks.size() >= i + 3`
    /// and then read `chunks.get(i + 3)`, so an `OP_ELSE` third from the end
    /// has them read one chunk past it.
    #[test]
    fn an_op_else_third_from_the_end_makes_rskj_throw() {
        let p2sh_erp_shape = [OP_NOTIF, OP_ELSE, OP_CHECKMULTISIG, OP_ENDIF];
        let non_standard_shape = [OP_NOTIF, OP_ELSE, OP_ENDIF, OP_CHECKMULTISIG];
        // A real default federation in front of the OP_ELSE changes nothing.
        let mut after_a_federation = vec![OP_NOTIF];
        after_a_federation.extend_from_slice(&standard_redeem(2, 3));
        after_a_federation.extend_from_slice(&[OP_ELSE, OP_CHECKMULTISIG, OP_ENDIF]);
        for script in [
            &p2sh_erp_shape[..],
            &non_standard_shape[..],
            &after_a_federation,
            &flyover(&p2sh_erp_shape),
        ] {
            assert!(
                matches!(is_sent_to_multisig(script), Verdict::RskjThrows(_)),
                "{script:02x?}"
            );
        }

        // With one more chunk after the OP_ELSE the read stays inside.
        let inside = [OP_NOTIF, OP_1, OP_ELSE, OP_1, OP_ENDIF, OP_CHECKMULTISIG];
        assert_eq!(is_sent_to_multisig(&inside), Verdict::NotMultisig);
    }

    /// `hasFlyoverPrefix` wants the hash pushed by the opcode 32 itself. Pushed
    /// with `OP_PUSHDATA1` or `OP_PUSHDATA2`, the same 32 bytes aren't a flyover
    /// prefix, and the script is no redeem script bitcoinj knows.
    #[test]
    fn a_flyover_prefix_is_a_direct_push_of_32_bytes() {
        let wrapped = flyover(&standard_redeem(2, 3));
        assert_eq!(is_sent_to_multisig(&wrapped), Verdict::Multisig);

        let mut pushdata1 = vec![OP_PUSHDATA1];
        pushdata1.extend_from_slice(&wrapped);
        assert_eq!(is_sent_to_multisig(&pushdata1), Verdict::NotMultisig);

        let mut pushdata2 = vec![OP_PUSHDATA2, 32, 0];
        pushdata2.extend_from_slice(&wrapped[1..]);
        assert_eq!(is_sent_to_multisig(&pushdata2), Verdict::NotMultisig);
    }

    /// `decodePositiveN` refuses a negative number and nothing else, so the
    /// structure checks pass an M pushed as zero and a parser is selected.
    /// `getM() > 0` is then false.
    #[test]
    fn an_m_pushed_as_zero_is_not_multisig() {
        let zero_of_three = |push: &[u8]| {
            let mut s = push.to_vec();
            s.extend_from_slice(&standard_redeem(2, 3)[1..]);
            s
        };
        let standard = zero_of_three(&[0x01, 0x00]);
        let one_of_two = standard_redeem(1, 2);
        for script in [
            standard.clone(),
            zero_of_three(&[0x02, 0x00, 0x00]),
            flyover(&standard),
            p2sh_erp(&standard, &one_of_two),
            non_standard_erp(&standard, &one_of_two),
        ] {
            assert_eq!(
                is_sent_to_multisig(&script),
                Verdict::NotMultisig,
                "{script:02x?}"
            );
        }
        // bitcoinj: IllegalStateException("Unsupported script type").
        assert!(signatures_required_to_spend(&standard).is_err());

        // An ERP script's M is its default federation's. The emergency
        // multisig's isn't read.
        let erp_side_only = p2sh_erp(&standard_redeem(2, 3), &zero_of_three(&[0x01, 0x00]));
        assert_eq!(is_sent_to_multisig(&erp_side_only), Verdict::Multisig);
        assert_eq!(signatures_required_to_spend(&erp_side_only), Ok(2));
    }

    /// The factory compares the hardcoded script with `List.equals`, and a
    /// `ScriptChunk` equals another only at the same offset in its program.
    /// Behind a flyover prefix every chunk starts 34 bytes later, so the script
    /// isn't matched there, and it parses as the non-standard ERP redeem it is,
    /// with M = 3.
    #[test]
    fn the_hardcoded_testnet_script_is_matched_only_as_the_whole_program() {
        let script = hex_decode(NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT);
        assert_eq!(is_sent_to_multisig(&script), Verdict::NotMultisig);
        assert!(signatures_required_to_spend(&script).is_err());

        let wrapped = flyover(&script);
        assert_eq!(is_sent_to_multisig(&wrapped), Verdict::Multisig);
        assert_eq!(signatures_required_to_spend(&wrapped), Ok(3));
    }

    #[test]
    fn a_non_standard_erp_redeem_is_multisig() {
        let script = non_standard_erp(&standard_redeem(2, 3), &standard_redeem(1, 2));
        assert_eq!(is_sent_to_multisig(&script), Verdict::Multisig);
        assert_eq!(signatures_required_to_spend(&script), Ok(2));
    }

    /// bitcoinj's decodePositiveN accepts a PUSHED number as well as
    /// OP_1..OP_16, which a shape check that only looks for the opcodes misses.
    #[test]
    fn a_pushed_m_is_accepted() {
        let mut s = vec![0x01, 0x02]; // push the number 2 rather than OP_2
        for i in 0..3u8 {
            s.push(33);
            s.extend_from_slice(&key(i));
        }
        s.push(0x53);
        s.push(OP_CHECKMULTISIG);
        assert_eq!(is_sent_to_multisig(&s), Verdict::Multisig);
    }

    #[test]
    fn non_multisig_shapes_are_rejected() {
        assert_eq!(is_sent_to_multisig(&[]), Verdict::NotMultisig);
        assert_eq!(is_sent_to_multisig(&[0x52, 0xae]), Verdict::NotMultisig);
        let mut wrong_terminator = standard_redeem(2, 3);
        *wrong_terminator.last_mut().unwrap() = 0xac; // OP_CHECKSIG
        assert_eq!(is_sent_to_multisig(&wrong_terminator), Verdict::NotMultisig);
        // declared key count disagreeing with the pushes
        let mut short = vec![0x52];
        for i in 0..2u8 {
            short.push(33);
            short.extend_from_slice(&key(i));
        }
        short.push(0x53);
        short.push(OP_CHECKMULTISIG);
        assert_eq!(is_sent_to_multisig(&short), Verdict::NotMultisig);
    }


    /// Differential fixture: every vector below was run through
    /// `co.rsk.bitcoinj:bitcoinj-thin:0.14.4-rsk-18` -- the artifact rskj pins
    /// -- and the recorded outcome is what the Java actually printed, not what
    /// this port believes.
    ///
    /// Reproduce with a three-line harness:
    ///
    ///   new Script(Utils.HEX.decode(hex)).isSentToMultiSig()
    ///
    /// catching Throwable, against that jar plus guava and slf4j.
    ///
    /// If a change to this module makes a row disagree, the port has drifted
    /// from rskj and the node will fork. That is the whole purpose of the file,
    /// so the fixture is the test that matters most in it.
    #[test]
    fn matches_bitcoinj_thin_on_recorded_vectors() {
        // (label, redeem script hex, what the Java produced)
        let vectors: &[(&str, &str, Verdict)] = &[
            ("standard 2of3",
             "5221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae",
             Verdict::Multisig),
            ("standard, CHECKMULTISIGVERIFY",
             "5221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253af",
             Verdict::Multisig),
            ("flyover-wrapped standard",
             "20abababababababababababababababababababababababababababababababab755221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae",
             Verdict::Multisig),
            ("nested flyover",
             "20abababababababababababababababababababababababababababababababab7520cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd7551210202020202020202020202020202020202020202020202020202020202020202002102020202020202020202020202020202020202020202020202020202020202020152ae",
             Verdict::Multisig),
            ("p2sh-erp",
             "645221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae67020020b27551210202020202020202020202020202020202020202020202020202020202020202002102020202020202020202020202020202020202020202020202020202020202020152ae68",
             Verdict::Multisig),
            ("pushed M rather than OP_M",
             "010221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae",
             Verdict::Multisig),
            ("empty script", "", Verdict::NotMultisig),
            ("too short", "52ae", Verdict::NotMultisig),
            ("OP_CHECKSIG terminator",
             "5221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ac",
             Verdict::NotMultisig),
            ("declared key count mismatch",
             "52210202020202020202020202020202020202020202020202020202020202020202002102020202020202020202020202020202020202020202020202020202020202020153ae",
             Verdict::NotMultisig),
            ("hardcoded testnet script", NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT,
             Verdict::NotMultisig),
            ("non-standard erp",
             "64522102020202020202020202020202020202020202020202020202020202020202020021020202020202020202020202020202020202020202020202020202020202020201210202020202020202020202020202020202020202020202020202020202020202025367020020b2755121020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202015268ae",
             Verdict::Multisig),
            ("p2sh-erp, CSV value pushed as OP_16",
             "645221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae6760b27551210202020202020202020202020202020202020202020202020202020202020202002102020202020202020202020202020202020202020202020202020202020202020152ae68",
             Verdict::Multisig),
            ("flyover prefix pushed with OP_PUSHDATA1",
             "4c20abababababababababababababababababababababababababababababababab755221020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae",
             Verdict::NotMultisig),
            ("M pushed as zero",
             "010021020202020202020202020202020202020202020202020202020202020202020200210202020202020202020202020202020202020202020202020202020202020202012102020202020202020202020202020202020202020202020202020202020202020253ae",
             Verdict::NotMultisig),
            ("p2sh-erp, an OP_ELSE inside the default federation",
             "645221020202020202020202020202020202020202020202020202020202020202020200672102020202020202020202020202020202020202020202020202020202020202020253ae67020020b27551210202020202020202020202020202020202020202020202020202020202020202002102020202020202020202020202020202020202020202020202020202020202020152ae68",
             Verdict::NotMultisig),
            ("OP_ELSE fourth from the end", "6451675168ae", Verdict::NotMultisig),
        ];

        for (label, hex, expected) in vectors {
            let got = is_sent_to_multisig(&hex_decode(hex));
            assert_eq!(&got, expected, "diverged from bitcoinj-thin on: {label}");
        }

        // The hardcoded testnet script behind a flyover prefix: true, and
        // getNumberOfSignaturesRequiredToSpend() is 3.
        let mut wrapped =
            hex_decode("20abababababababababababababababababababababababababababababababab75");
        wrapped.extend_from_slice(&hex_decode(NON_STANDARD_ERP_TESTNET_REDEEM_SCRIPT));
        assert_eq!(is_sent_to_multisig(&wrapped), Verdict::Multisig);
        assert_eq!(signatures_required_to_spend(&wrapped), Ok(3));

        // Recorded separately because the Java outcome is an exception rather
        // than a return value:
        //   new Script(hex("0001aa01bbae")).isSentToMultiSig()
        //     -> java.lang.ArrayIndexOutOfBoundsException: Index -1 out of bounds for length 0
        //   new Script(hex("6467ae68")).isSentToMultiSig()
        //     -> java.lang.IndexOutOfBoundsException: Index 4 out of bounds for length 4
        //   new Script(hex("646768ae")).isSentToMultiSig()
        //     -> java.lang.IndexOutOfBoundsException: Index 4 out of bounds for length 4
        for hex in ["0001aa01bbae", "6467ae68", "646768ae"] {
            assert!(
                matches!(
                    is_sent_to_multisig(&hex_decode(hex)),
                    Verdict::RskjThrows(_)
                ),
                "diverged from bitcoinj-thin on: {hex} (Java throws)"
            );
        }
    }

    #[test]
    fn the_switch_defaults_to_on() {
        assert!(enabled(), "rskj has not changed, so emulation must be on by default");
    }
}
