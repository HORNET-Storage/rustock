/// RSK precompiled contracts for revm.
///
/// RSK extends Ethereum's standard precompiles (0x01–0x09) with its own
/// native contracts at higher addresses (0x01000006+). This module defines
/// all RSK precompile addresses, implements the RSK-specific ones, and
/// provides a builder that produces the complete `Precompiles` set for a
/// given block height.
///
/// ## Address Layout
///
/// | Range          | Type                | Examples                        |
/// |----------------|---------------------|---------------------------------|
/// | 0x01–0x05      | Ethereum (genesis)  | ECRecover, SHA256, Identity     |
/// | 0x06–0x08      | Ethereum (RSKIP137) | BN128 add/mul/pairing           |
/// | 0x09           | Ethereum (RSKIP153) | Blake2F                         |
/// | 0x01000006     | RSK (genesis)       | Bridge                          |
/// | 0x01000008     | RSK (genesis)       | REMASC                          |
/// | 0x01000009+    | RSK (various)       | HDWalletUtils, BlockHeader, etc |
use alloy_primitives::{Address, Bytes, B256};
use revm::context::{Cfg, LocalContextTr};
use revm::context_interface::{Block as BlockTr, ContextTr, JournalTr};
use revm::handler::PrecompileProvider;
use revm::interpreter::{CallInput, CallInputs, Gas, InstructionResult, InterpreterResult};
use revm::precompile::{
    Precompile, PrecompileId, PrecompileOutput, PrecompileError, Precompiles,
    PrecompileSpecId,
};
use revm::primitives::hardfork::SpecId;
use rustock_storage::BlockStore;
use std::sync::Arc;

use crate::bridge::constants::BridgeConstants;
use crate::hardfork::{RskHardforkConfig, RskNetworkUpgrade};
use crate::native::block_header::BlockHeader;
use crate::native::environment::Environment;
use crate::native::hd_wallet::HdWalletUtils;
use crate::native::{self, Outcome};
use crate::remasc::RemascConfig;

// ---------------------------------------------------------------------------
// RSK-specific precompile addresses
// ---------------------------------------------------------------------------

pub const BRIDGE_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000006"));

pub const REMASC_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000008"));

pub const HD_WALLET_UTILS_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000009"));

pub const BLOCK_HEADER_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000010"));

pub const ENVIRONMENT_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000011"));

pub const SECP256K1_ADD_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000016"));

pub const SECP256K1_MUL_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000017"));

/// rskj `PrecompiledContracts.GENESIS_ADDRESSES`: precompiles that exist from
/// genesis. At the RSKIP126 activation block all of them are created (if
/// absent) and get the contract storage-prefix marker
/// (`BlockExecutor.maintainPrecompiledContractStorageRoots`).
pub const GENESIS_PRECOMPILES: [Address; 7] = [
    Address::new(hex_addr("0000000000000000000000000000000000000001")), // ecrecover
    Address::new(hex_addr("0000000000000000000000000000000000000002")), // sha256
    Address::new(hex_addr("0000000000000000000000000000000000000003")), // ripemd160
    Address::new(hex_addr("0000000000000000000000000000000000000004")), // identity
    Address::new(hex_addr("0000000000000000000000000000000000000005")), // modexp
    BRIDGE_ADDR,
    REMASC_ADDR,
];

/// rskj `PrecompiledContracts.CONSENSUS_ENABLED_ADDRESSES`: precompiles
/// enabled by a network upgrade. At each one's activation block rskj
/// re-creates the account (resetting nonce/balance) and writes the marker.
pub const CONSENSUS_ENABLED_PRECOMPILES: [(Address, crate::hardfork::RskNetworkUpgrade); 9] = [
    (HD_WALLET_UTILS_ADDR, crate::hardfork::RskNetworkUpgrade::Wasabi100), // RSKIP106
    (BLOCK_HEADER_ADDR, crate::hardfork::RskNetworkUpgrade::Wasabi100),    // RSKIP119
    (Address::new(hex_addr("0000000000000000000000000000000000000006")), crate::hardfork::RskNetworkUpgrade::Papyrus200), // altBN128 add, RSKIP137
    (Address::new(hex_addr("0000000000000000000000000000000000000007")), crate::hardfork::RskNetworkUpgrade::Papyrus200), // altBN128 mul, RSKIP137
    (Address::new(hex_addr("0000000000000000000000000000000000000008")), crate::hardfork::RskNetworkUpgrade::Papyrus200), // altBN128 pairing, RSKIP137
    (Address::new(hex_addr("0000000000000000000000000000000000000009")), crate::hardfork::RskNetworkUpgrade::Iris300), // blake2f, RSKIP153
    (ENVIRONMENT_ADDR, crate::hardfork::RskNetworkUpgrade::Arrowhead600), // RSKIP203
    (SECP256K1_ADD_ADDR, crate::hardfork::RskNetworkUpgrade::Reed800),    // RSKIP516
    (SECP256K1_MUL_ADDR, crate::hardfork::RskNetworkUpgrade::Reed800),    // RSKIP516
];

/// Returns all RSK precompile addresses (including standard Ethereum ones).
pub fn all_rsk_precompile_addresses() -> Vec<Address> {
    vec![
        BRIDGE_ADDR,
        REMASC_ADDR,
        HD_WALLET_UTILS_ADDR,
        BLOCK_HEADER_ADDR,
        ENVIRONMENT_ADDR,
        SECP256K1_ADD_ADDR,
        SECP256K1_MUL_ADDR,
    ]
}

// ---------------------------------------------------------------------------
// RSK precompile implementations
// ---------------------------------------------------------------------------

/// REMASC: Reward Manager Smart Contract.
/// Called as the last transaction in every block to distribute miner fees.
/// Gas cost: 0 (free). Returns empty output on success.
fn remasc_run(_input: &[u8], _gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    Ok(PrecompileOutput::new(0, Vec::new().into()))
}

/// Bridge: BTC–RSK two-way peg bridge.
/// Full implementation is complex (~60 methods). For now, returns empty output
/// and charges a minimal gas cost. Will be fully implemented in a later phase.
fn bridge_run(_input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 10_000u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas_cost, Vec::new().into()))
}

/// What the precompile set holds for HDWalletUtils, BlockHeader and
/// Environment, so each address is a precompile from its activation on.
/// `RskPrecompileProvider` runs these native contracts itself
/// ([`crate::native`]) and never calls this.
fn native_contract(_input: &[u8], _gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    Err(PrecompileError::Fatal(
        "a native contract runs through RskPrecompileProvider".into(),
    ))
}

/// ECRecover's address, 0x01.
const ECRECOVER_ADDR: Address = Address::new(hex_addr("0000000000000000000000000000000000000001"));

/// rskj's ECRecover (`PrecompiledContracts.ECRecover`), which parts from
/// Ethereum's, the one revm runs, in two places:
///
/// - only the last byte of the `v` word counts: `isValid` reads `v[31]`, so
///   a word whose other bytes aren't zero still recovers a key, where revm
///   answers nothing;
/// - a signature whose key is the point at infinity recovers the address
///   rskj gives that key, the infinity sender, where revm answers nothing.
///
/// The rest is as Ethereum's: 3,000 gas, the input's first 128 bytes read,
/// and nothing for a `v` byte other than 27 or 28, an r or s outside 1 to
/// below the curve's order, or a key that doesn't recover. An input too
/// short to hold the hash, `v` and r makes `execute`'s `System.arraycopy`
/// throw, and it answers nothing for any exception; an s cut short ends in
/// zeros.
fn rsk_ecrecover_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    const GAS: u64 = 3_000;
    if gas_limit < GAS {
        return Err(PrecompileError::OutOfGas);
    }
    let answer = ecrecover(input).map_or_else(Vec::new, |word| word.to_vec());
    Ok(PrecompileOutput::new(GAS, answer.into()))
}

/// The word ECRecover answers, the recovered address at its end, or `None`
/// for an empty answer. See [`rsk_ecrecover_run`].
fn ecrecover(input: &[u8]) -> Option<[u8; 32]> {
    if input.len() < 96 {
        return None;
    }
    let v = input[63];
    if v != 27 && v != 28 {
        return None;
    }
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&input[..32]);
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&input[64..96]);
    let s = &input[96..input.len().min(128)];
    signature[32..32 + s.len()].copy_from_slice(s);
    let address = rustock_core::types::transaction::recover_address(&hash, &signature, v - 27)?;
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    Some(word)
}

/// ModExp's address, 0x05.
const MODEXP_ADDR: Address = Address::new(hex_addr("0000000000000000000000000000000000000005"));

/// rskj's ModExp (`PrecompiledContracts.BigIntegerModexp`): EIP-198's price
/// and arithmetic, with the lengths read as rskj reads them.
///
/// revm's modexp takes a length at its full width. rskj takes it as a Java
/// int (`DataWord.intValueSafe`), so that 2^31 or more counts as
/// `Integer.MAX_VALUE`, and answers nothing when an offset passes an int
/// (`Math.addExact`) or an argument passes what a `BigInteger` holds, 2^31 - 1
/// bits. The two agree on every call that affords less than about 10^8 gas:
/// the cheapest call past those limits, an exponent of 2^28 bytes with a
/// one-byte base and modulus, costs 107,374,182.
fn rsk_modexp_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas = modexp::gas_for_data(input);
    if gas > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas, modexp::execute(input)?.into()))
}

/// rskj's `BigIntegerModexp`, step by step.
mod modexp {
    use revm::precompile::PrecompileError;

    /// Where the base starts, after the three lengths.
    const ARGS_OFFSET: i32 = 96;

    /// The most bits a `BigInteger` holds.
    const BIG_INTEGER_BITS: u64 = i32::MAX as u64;

    /// `getGasForData`: EIP-198's price, at most `Long.MAX_VALUE`
    /// (`GasCost.toGas`).
    pub(super) fn gas_for_data(data: &[u8]) -> u64 {
        let [base_len, exp_len, mod_len] = lengths(data);
        let mult_complexity = mult_complexity(base_len.max(mod_len) as u64);
        let exp_high_bytes = match ARGS_OFFSET.checked_add(base_len) {
            Some(offset) => parse_bytes(data, offset, exp_len.min(32)),
            None => Vec::new(),
        };
        let adjusted = adjusted_exponent_length(&exp_high_bytes, exp_len);
        let gas = u128::from(mult_complexity) * u128::from(adjusted.max(1)) / 20;
        gas.min(i64::MAX as u128) as u64
    }

    /// `execute`: the result left-padded to the modulus's length, or nothing
    /// where an `ArithmeticException` ends it.
    pub(super) fn execute(data: &[u8]) -> Result<Vec<u8>, PrecompileError> {
        let [base_len, exp_len, mod_len] = lengths(data);
        if base_len == 0 && mod_len == 0 {
            return Ok(Vec::new());
        }
        // `Math.addExact` throws past an int.
        let Some(exp_offset) = ARGS_OFFSET.checked_add(base_len) else {
            return Ok(Vec::new());
        };
        let Some(mod_offset) = exp_offset.checked_add(exp_len) else {
            return Ok(Vec::new());
        };
        let args = [
            (ARGS_OFFSET, base_len),
            (exp_offset, exp_len),
            (mod_offset, mod_len),
        ];
        // `new BigInteger(1, bytes)` throws past its bits. rskj reads each
        // argument whole first; here each is measured before any is read.
        if args
            .iter()
            .any(|&(offset, len)| bit_length(data, offset, len) > BIG_INTEGER_BITS)
        {
            return Ok(Vec::new());
        }
        let mut answer = vec![0; mod_len as usize];
        // A modulus of zero answers zeros.
        if bit_length(data, mod_offset, mod_len) == 0 {
            return Ok(answer);
        }
        let [base, exp, modulus] = args.map(|(offset, len)| parse_bytes(data, offset, len));
        let result = revm::precompile::crypto().modexp(&base, &exp, &modulus)?;
        let result = &result[result.iter().take_while(|&&byte| byte == 0).count()..];
        let Some(start) = answer.len().checked_sub(result.len()) else {
            return Err(PrecompileError::Fatal(
                "modexp answered more than its modulus holds".into(),
            ));
        };
        answer[start..].copy_from_slice(result);
        Ok(answer)
    }

    /// `parseLen` of the three lengths, each word read as
    /// `DataWord.intValueSafe` reads it: 2^31 or more is `Integer.MAX_VALUE`.
    fn lengths(data: &[u8]) -> [i32; 3] {
        [0, 1, 2].map(|index| {
            let mut word = [0u8; 32];
            let bytes = parse_bytes(data, 32 * index, 32);
            word[..bytes.len()].copy_from_slice(&bytes);
            let low = i32::from_be_bytes([word[28], word[29], word[30], word[31]]);
            if word[..28].iter().any(|&byte| byte != 0) || low < 0 {
                i32::MAX
            } else {
                low
            }
        })
    }

    /// `ByteUtil.parseBytes`: `len` bytes of `data` from `offset`, zeros past
    /// its end, and none at all from past its end or for `len` zero.
    fn parse_bytes(data: &[u8], offset: i32, len: i32) -> Vec<u8> {
        let (offset, len) = (offset as usize, len as usize);
        if offset >= data.len() || len == 0 {
            return Vec::new();
        }
        let mut bytes = vec![0; len];
        let present = (data.len() - offset).min(len);
        bytes[..present].copy_from_slice(&data[offset..offset + present]);
        bytes
    }

    /// How many bits the number `parse_bytes(data, offset, len)` reads holds,
    /// found without reading it: its highest byte is one of `data`'s, the rest
    /// being the zeros it is padded with.
    fn bit_length(data: &[u8], offset: i32, len: i32) -> u64 {
        let (offset, len) = (offset as usize, len as usize);
        let present = data.get(offset..).unwrap_or_default();
        let present = &present[..present.len().min(len)];
        match present.iter().position(|&byte| byte != 0) {
            None => 0,
            Some(i) => 8 * (len - i) as u64 - u64::from(present[i].leading_zeros()),
        }
    }

    /// `getMultComplexity`. `x` is at most 2^31 - 1, so `x * x` fits, as in
    /// rskj's long arithmetic.
    fn mult_complexity(x: u64) -> u64 {
        let x2 = x * x;
        if x <= 64 {
            x2
        } else if x <= 1024 {
            x2 / 4 + 96 * x - 3072
        } else {
            x2 / 16 + 480 * x - 199_680
        }
    }

    /// `getAdjustedExponentLength`: the index of the highest bit among the
    /// exponent's first 32 bytes, and 8 for each byte after them.
    fn adjusted_exponent_length(exp_high_bytes: &[u8], exp_len: i32) -> u64 {
        let leading_zeros = match exp_high_bytes.iter().position(|&byte| byte != 0) {
            None => 8 * exp_high_bytes.len(),
            Some(i) => 8 * i + exp_high_bytes[i].leading_zeros() as usize,
        };
        let highest_bit = (8 * exp_high_bytes.len() - leading_zeros).saturating_sub(1) as u64;
        if exp_len <= 32 {
            highest_bit
        } else {
            8 * (exp_len as u64 - 32) + highest_bit
        }
    }
}

/// Secp256k1 point addition.
/// Input: up to 128 bytes = [x1(32) | y1(32) | x2(32) | y2(32)], big-endian.
/// Output: 64 bytes = [x(32) | y(32)].
/// (0,0) represents the point at infinity.
/// Gas cost: 150.
fn secp256k1_add_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 150u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    let p1 = parse_secp256k1_point(input, 0)?;
    let p2 = parse_secp256k1_point(input, 64)?;
    let result = p1 + p2;
    Ok(PrecompileOutput::new(gas_cost, encode_secp256k1_point(result).into()))
}

/// Secp256k1 scalar multiplication.
/// Input: up to 96 bytes = [x(32) | y(32) | scalar(32)], big-endian.
/// Output: 64 bytes = [x(32) | y(32)].
/// Gas cost: 3000.
fn secp256k1_mul_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 3_000u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    let point = parse_secp256k1_point(input, 0)?;
    let scalar = parse_word(input, 64);
    let k = <k256::Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce(
        k256::U256::from_be_slice(&scalar),
    );
    let result = point * k;
    Ok(PrecompileOutput::new(gas_cost, encode_secp256k1_point(result).into()))
}

/// Read a 32-byte big-endian word from `data` at `offset`. rskj's
/// `ByteUtil.parseWord` pads a word `data` ends inside with zeros on the
/// right, and reads one past its end as zero.
fn parse_word(data: &[u8], offset: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    if offset < data.len() {
        let end = std::cmp::min(offset + 32, data.len());
        let len = end - offset;
        word[..len].copy_from_slice(&data[offset..end]);
    }
    word
}

/// Parse a secp256k1 affine point from two consecutive 32-byte words at `offset`.
/// (0,0) is treated as the point at infinity.
fn parse_secp256k1_point(
    data: &[u8],
    offset: usize,
) -> Result<k256::ProjectivePoint, PrecompileError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;

    let x_bytes = parse_word(data, offset);
    let y_bytes = parse_word(data, offset + 32);

    let is_zero = x_bytes.iter().all(|&b| b == 0) && y_bytes.iter().all(|&b| b == 0);
    if is_zero {
        return Ok(k256::ProjectivePoint::IDENTITY);
    }

    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&x_bytes);
    uncompressed[33..65].copy_from_slice(&y_bytes);

    let encoded = k256::EncodedPoint::from_bytes(uncompressed)
        .map_err(|_| PrecompileError::other("invalid secp256k1 point encoding"))?;

    let affine = k256::AffinePoint::from_encoded_point(&encoded);
    if affine.is_none().into() {
        return Err(PrecompileError::other("point not on secp256k1 curve"));
    }
    Ok(k256::ProjectivePoint::from(affine.unwrap()))
}

/// Encode a projective point as 64 bytes [x(32) | y(32)].
/// The identity (point at infinity) encodes as all zeros.
fn encode_secp256k1_point(point: k256::ProjectivePoint) -> Vec<u8> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let affine = k256::AffinePoint::from(point);
    let encoded = affine.to_encoded_point(false);

    if encoded.is_identity() {
        return vec![0u8; 64];
    }

    let mut out = vec![0u8; 64];
    let x = encoded.x().expect("non-identity point has x");
    let y = encoded.y().expect("non-identity point has y");
    out[..32].copy_from_slice(x);
    out[32..].copy_from_slice(y);
    out
}

// ---------------------------------------------------------------------------
// Precompile set builder
// ---------------------------------------------------------------------------

/// Builds the complete revm `Precompiles` set for an RSK block.
///
/// Starts with the Ethereum precompiles matching the block's SpecId,
/// then adds RSK-specific precompiles gated by their activation RSKIPs.
pub fn rsk_precompiles(hardfork_cfg: &RskHardforkConfig, block_number: u64) -> Precompiles {
    let upgrade = hardfork_cfg.active_upgrade(block_number);

    // rskj gates each precompile on its own RSKIP rather than Ethereum spec
    // buckets (PrecompiledContracts.getContractForAddress). From genesis:
    // 0x01-0x04 (ecrecover, sha256, ripemd160, identity) plus 0x05 modexp,
    // EIP-198's. ECRecover and ModExp are rskj's own, in place of revm's.
    let mut precompiles = Precompiles::new(PrecompileSpecId::HOMESTEAD).clone();
    precompiles.extend([
        Precompile::new(
            PrecompileId::custom("rsk-ecrecover"),
            ECRECOVER_ADDR,
            rsk_ecrecover_run,
        ),
        Precompile::new(
            PrecompileId::custom("rsk-modexp"),
            MODEXP_ADDR,
            rsk_modexp_run,
        ),
    ]);

    // RSKIP137 (Papyrus200): BN128 add/mul/pairing, priced per EIP-1108
    // (Istanbul: 150 / 6000 / 45000 + 34000 per pair) from activation.
    if upgrade >= RskNetworkUpgrade::Papyrus200 {
        precompiles.extend([
            revm::precompile::bn254::add::ISTANBUL,
            revm::precompile::bn254::mul::ISTANBUL,
            revm::precompile::bn254::pair::ISTANBUL,
        ]);
    }

    // RSKIP153 (Iris300): Blake2F
    if upgrade >= RskNetworkUpgrade::Iris300 {
        precompiles.extend([revm::precompile::blake2::FUN]);
    }

    // Genesis precompiles: Bridge, REMASC (always active)
    precompiles.extend([
        Precompile::new(
            PrecompileId::custom("rsk-remasc"),
            REMASC_ADDR,
            remasc_run,
        ),
        Precompile::new(
            PrecompileId::custom("rsk-bridge"),
            BRIDGE_ADDR,
            bridge_run,
        ),
    ]);

    // RSKIP106 (Wasabi100): HDWalletUtils
    if upgrade >= RskNetworkUpgrade::Wasabi100 {
        precompiles.extend([Precompile::new(
            PrecompileId::custom("rsk-hdwallet"),
            HD_WALLET_UTILS_ADDR,
            native_contract,
        )]);
    }

    // RSKIP119 (Wasabi100): BlockHeaderContract
    if upgrade >= RskNetworkUpgrade::Wasabi100 {
        precompiles.extend([Precompile::new(
            PrecompileId::custom("rsk-blockheader"),
            BLOCK_HEADER_ADDR,
            native_contract,
        )]);
    }

    // RSKIP203 (Arrowhead600): Environment
    if upgrade >= RskNetworkUpgrade::Arrowhead600 {
        precompiles.extend([Precompile::new(
            PrecompileId::custom("rsk-environment"),
            ENVIRONMENT_ADDR,
            native_contract,
        )]);
    }

    // RSKIP516 (Reed800): Secp256k1 Addition/Multiplication
    if upgrade >= RskNetworkUpgrade::Reed800 {
        precompiles.extend([
            Precompile::new(
                PrecompileId::custom("rsk-secp256k1-add"),
                SECP256K1_ADD_ADDR,
                secp256k1_add_run,
            ),
            Precompile::new(
                PrecompileId::custom("rsk-secp256k1-mul"),
                SECP256K1_MUL_ADDR,
                secp256k1_mul_run,
            ),
        ]);
    }

    precompiles
}

// ---------------------------------------------------------------------------
// PrecompileProvider implementation for revm integration
// ---------------------------------------------------------------------------

/// Context about the currently-executing transaction, used by Bridge precompile.
///
/// The Bridge's `releaseBtc` method needs:
/// - The RSK tx hash (for RSKIP146 release queue format)
/// - The BTC destination hash160 (derived from the sender's compressed pubkey)
///
/// This context is set by the executor before each `transact_one` call and
/// read by the Bridge precompile inside `run_bridge`.
#[derive(Debug, Clone, Default)]
pub struct BridgeTxContext {
    /// Keccak256 of the RLP-encoded transaction.
    pub rsk_tx_hash: [u8; 32],
    /// BTC P2PKH destination: RIPEMD160(SHA256(compressed_pubkey)).
    /// Derived from the RSK transaction's secp256k1 signature.
    /// Zero bytes if the pubkey cannot be recovered (system/REMASC transactions).
    pub btc_sender_hash160: [u8; 20],
    /// RSK sender address of the executing transaction (Bridge event payloads).
    pub rsk_sender: Address,
    /// Whether this is a *local* call -- rskj's `Transaction.isLocalCall`,
    /// set by `ReversibleTransactionExecutor` (the `eth_call`/`estimateGas`
    /// path) via `TransactionExecutor.setLocalCall(true)`.
    ///
    /// Bridge methods marked `LocalOnly` execute only for such a call and
    /// throw for anything on-chain (`Bridge.validateLocalCall`,
    /// Bridge.java:431). It is false for every transaction in a block, so it
    /// can never change consensus; it only decides whether a read-only query
    /// over RPC is answered or rejected.
    pub local_call: bool,
    /// Position of this transaction in its block. Not consensus -- it exists
    /// so a recorded Bridge decision can be located afterwards, and is zero
    /// outside block execution.
    pub tx_index: u32,
}

/// The Ethereum precompiles rskj added after genesis.
const BN128_ADD_ADDR: Address = Address::new(hex_addr("0000000000000000000000000000000000000006"));
const BN128_MUL_ADDR: Address = Address::new(hex_addr("0000000000000000000000000000000000000007"));
const BN128_PAIRING_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000000000008"));
const BLAKE2F_ADDR: Address = Address::new(hex_addr("0000000000000000000000000000000000000009"));

/// rskj's `getGasForData` for the precompiles of the set whose `execute` can
/// throw: what a call costs whether it returns or throws, charged before the
/// precompile runs.
///
/// BN128 add, mul and pairing (0x06 to 0x08) refuse a point off the curve,
/// and BLAKE2F (0x09) a final-block byte other than 0 or 1, or an input that
/// is not 213 bytes. From reed800 the secp256k1 contracts (RSKIP516) refuse a
/// point off the curve or a coordinate of p or more; their gas never depends
/// on the input.
///
/// `None` for the precompiles that never throw. The native contracts work
/// out their own ([`crate::native`]).
fn gas_for_data(addr: &Address, input: &[u8]) -> Option<u64> {
    const BN128_PAIR_SIZE: usize = 192;
    match *addr {
        // EIP-1108's prices, which rskj charges from RSKIP137 on.
        BN128_ADD_ADDR => Some(150),
        BN128_MUL_ADDR => Some(6_000),
        BN128_PAIRING_ADDR => Some(
            ((input.len() / BN128_PAIR_SIZE) as u64)
                .saturating_mul(34_000)
                .saturating_add(45_000),
        ),
        // `Blake2F.getGasForData`: the big-endian rounds count, F_ROUND being
        // 1, or 0 when the input is the wrong length to hold one.
        BLAKE2F_ADDR => Some(match input.split_first_chunk::<4>() {
            Some((rounds, _)) if input.len() == 213 => u64::from(u32::from_be_bytes(*rounds)),
            _ => 0,
        }),
        SECP256K1_ADD_ADDR => Some(150),
        SECP256K1_MUL_ADDR => Some(3_000),
        _ => None,
    }
}

/// Wraps an owned `Precompiles` set to implement revm's `PrecompileProvider`.
///
/// Unlike `EthPrecompiles` which holds a `&'static Precompiles`, this owns the
/// set because RSK precompiles are dynamically built per-block based on which
/// RSKIPs are active.
pub struct RskPrecompileProvider {
    precompiles: Precompiles,
    hardfork_cfg: RskHardforkConfig,
    spec: SpecId,
    block_store: Option<Arc<BlockStore>>,
    /// The executing block's parent, where BlockHeader starts looking.
    parent_hash: B256,
    remasc_config: RemascConfig,
    bridge_config: BridgeConstants,
    /// Shared slot for per-transaction context used by Bridge precompile.
    /// Updated by the executor before each `transact_one`.
    bridge_tx_context: std::sync::Arc<std::sync::Mutex<BridgeTxContext>>,
    /// Set when a direct Bridge call hits rskj's invisible-exception path
    /// (parse failure post-RSKIP88). `RskHandler` reads it during fee
    /// finalization: no leftover refund, REMASC gets gasLimit * gasPrice.
    /// Cleared by `RskHandler::load_accounts` before each transaction.
    invisible_exception: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set when a precompile that a contract called throws before RSKIP197.
    /// rskj's `Program.executePrecompiled` has no error handling: the throw
    /// leaves the VM as a `RuntimeException`, and `VM.steps` fails the
    /// contract that made the call, spending all its gas. `RskHandler`
    /// halts that contract as it takes the call's result.
    aborts_caller: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Precompiles successfully called during the current transaction. rskj
    /// writes the contract storage-prefix marker (`setupContract`) on every
    /// successful precompile call, in the call's own track; the executor
    /// drains this after each tx and applies the markers to the trie if the
    /// tx committed. A frame that fails takes its calls back off it
    /// (`RskHandler`), as rskj rolls that track back with the frame's.
    called_precompiles: std::sync::Arc<std::sync::Mutex<Vec<Address>>>,
    /// Set when this transaction reaches REMASC or the Bridge. See
    /// [`RskPrecompileProvider::reached_sequential_only_slot`].
    reached_sequential_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for RskPrecompileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RskPrecompileProvider")
            .field("hardfork_cfg", &self.hardfork_cfg)
            .field("spec", &self.spec)
            .field(
                "block_store",
                &self.block_store.as_ref().map(|_| "BlockStore"),
            )
            .field("parent_hash", &self.parent_hash)
            .finish()
    }
}

impl RskPrecompileProvider {
    /// Returns the shared bridge tx context Arc, allowing the executor to update
    /// per-transaction context before each `transact_one` call.
    pub fn bridge_tx_context_slot(&self) -> std::sync::Arc<std::sync::Mutex<BridgeTxContext>> {
        std::sync::Arc::clone(&self.bridge_tx_context)
    }

    /// Returns the shared invisible-exception flag for `RskHandler`.
    pub fn invisible_exception_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.invisible_exception)
    }

    /// Returns the shared caller-abort flag for `RskHandler` (see the field).
    pub fn aborts_caller_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.aborts_caller)
    }

    /// Returns the shared list of successfully-called precompiles.
    pub fn called_precompiles_slot(&self) -> std::sync::Arc<std::sync::Mutex<Vec<Address>>> {
        std::sync::Arc::clone(&self.called_precompiles)
    }

    /// Whether this transaction has reached a precompile that bars it from a
    /// parallel sublist.
    ///
    /// Deliberately **not** the same question as `called_precompiles_slot`,
    /// which records a precompile that returned successfully because that is
    /// when rskj writes its storage-prefix marker. This one records reaching
    /// the precompile at all, whatever came of it, because that is what rskj
    /// records: `Program.callToPrecompiledAddress` adds the address before
    /// doing anything, and a child frame's set merges into its parent's
    /// before the parent checks whether the child succeeded. A Bridge call
    /// that reverts still bars the transaction.
    pub fn reached_sequential_only_slot(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.reached_sequential_only)
    }

    fn record_called(&self, addr: Address) {
        if let Ok(mut called) = self.called_precompiles.lock() {
            if !called.contains(&addr) {
                called.push(addr);
            }
        }
    }

    /// RSKIP197 (iris300): whether failing precompile calls are handled
    /// (push 0, refund the surplus, continue) rather than aborting the caller.
    fn rskip197_active<CTX: crate::RskContextTr>(&self, context: &CTX) -> bool {
        self.hardfork_cfg
            .has_rskip197(context.block().number().to::<u64>())
    }

    /// RSKIP516 (reed800): how much of a contract's input the precompile at
    /// `addr` takes, its `getMaxInput` (`Program.getInputLength`), or `None`
    /// for all of it. A transaction's own data reaches a precompile whole
    /// (`TransactionExecutor.call`), and so does a contract's before reed800
    /// or to any other precompile. Only BLAKE2F answers differently for it:
    /// the others never read past their limit, while BLAKE2F refuses an input
    /// that isn't 213 bytes, at no cost.
    fn max_input<CTX: crate::RskContextTr>(&self, context: &CTX, addr: &Address) -> Option<usize> {
        let block = context.block().number().to::<u64>();
        if context.journal().depth() == 1 || !self.hardfork_cfg.has_rskip516(block) {
            return None;
        }
        match *addr {
            ECRECOVER_ADDR | BN128_ADD_ADDR | SECP256K1_ADD_ADDR => Some(128),
            BN128_MUL_ADDR | SECP256K1_MUL_ADDR => Some(96),
            BLAKE2F_ADDR => Some(213),
            _ => None,
        }
    }

    /// Whether this is a transaction's own call to BLAKE2F with no data before
    /// RSKIP552 (vetiver900), whose block rskj can't process. rskj reads empty
    /// data as null (`RLPItem.getRLPData`), and BLAKE2F's `getGasForData`
    /// reads its length: a NullPointerException, which
    /// `TransactionExecutor.call` doesn't catch. RSKIP552 prices null data at
    /// 0 and refuses it as any other wrong length. Every other precompile's
    /// `getGasForData` takes null, and a contract's call never passes null
    /// (`Program.callToPrecompiledAddress`).
    fn blake2f_reads_null<CTX: crate::RskContextTr>(
        &self,
        context: &CTX,
        addr: &Address,
        input: &[u8],
    ) -> bool {
        let block = context.block().number().to::<u64>();
        *addr == BLAKE2F_ADDR
            && input.is_empty()
            && context.journal().depth() == 1
            && !self.hardfork_cfg.has_rskip552(block)
    }
}

/// REMASC and the Bridge, which run with the whole context: they read and
/// write the state themselves, the Bridge's storage beside revm's.
const STATEFUL_PRECOMPILES: [Address; 2] = [REMASC_ADDR, BRIDGE_ADDR];

/// rskj's native contracts (`co.rsk.pcc.NativeContract`), which
/// [`crate::native`] runs.
const NATIVE_CONTRACTS: [Address; 3] = [HD_WALLET_UTILS_ADDR, BLOCK_HEADER_ADDR, ENVIRONMENT_ADDR];

/// Precompiles a transaction may not reach from a parallel sublist.
///
/// rskj's `concurrentContractsDisallowed` (`RskSystemProperties`), and it is
/// consensus rather than a miner's preference: the parallel sublist
/// executors are built with this set and
/// `TransactionListExecutor.call` fails the sublist -- and so the block --
/// for a transaction that reached one of them. The sequential sublist is
/// built with an empty set, "as there's no concurrency in it".
///
/// Both are stateful, which is why reaching them is recorded in
/// `run_stateful` and nowhere else.
pub const SEQUENTIAL_ONLY_PRECOMPILES: [Address; 2] = [REMASC_ADDR, BRIDGE_ADDR];

impl RskPrecompileProvider {
    pub fn new(
        precompiles: Precompiles,
        hardfork_cfg: &RskHardforkConfig,
        block_store: Option<Arc<BlockStore>>,
        parent_hash: B256,
        remasc_config: RemascConfig,
    ) -> Self {
        Self {
            precompiles,
            hardfork_cfg: hardfork_cfg.clone(),
            spec: SpecId::default(),
            block_store,
            parent_hash,
            remasc_config,
            bridge_config: BridgeConstants::mainnet(),
            bridge_tx_context: std::sync::Arc::new(std::sync::Mutex::new(BridgeTxContext::default())),
            invisible_exception: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            aborts_caller: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            called_precompiles: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            reached_sequential_only: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        }
    }

    /// Override Bridge configuration (for testnet/regtest).
    pub fn with_bridge_config(mut self, config: BridgeConstants) -> Self {
        self.bridge_config = config;
        self
    }


    /// REMASC and the Bridge, which read and write the state themselves.
    ///
    /// Returns `Ok(Some(result))` if the address was handled, `Ok(None)` to
    /// fall through to the generic (pure-function) precompile path.
    fn run_stateful<CTX: crate::RskContextTr>(
        &self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        let addr = &inputs.bytecode_address;

        if !STATEFUL_PRECOMPILES.contains(addr) {
            return Ok(None);
        }

        // Before dispatch, so the outcome cannot change the answer: under
        // RSKIP-144 a transaction that reaches REMASC or the Bridge may only
        // sit in the sequential sublist, and rskj records the address on the
        // way in (`Program.callToPrecompiledAddress`).
        if SEQUENTIAL_ONLY_PRECOMPILES.contains(addr) {
            self.reached_sequential_only
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // Copy input to owned bytes so we can pass &mut CTX to the handler
        // without conflicting with the SharedBuffer borrow.
        let input_bytes: Vec<u8> = match &inputs.input {
            CallInput::SharedBuffer(range) => {
                if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                    slice.as_ref().to_vec()
                } else {
                    Vec::new()
                }
            }
            CallInput::Bytes(bytes) => bytes.to_vec(),
        };

        // rskj Program.callToPrecompiledAddress: the zero-value transfer
        // CREATES the account of the call's context address on first call
        // (isExist becomes true, so NEW_ACCT_CALL is charged at most once per
        // address ever). That is the precompile for CALL and STATICCALL, and
        // the caller itself for CALLCODE and DELEGATECALL
        // (`msg.getType().isStateless()`), which leave the precompile without
        // an account. Touching the loaded account persists it under the
        // pinned pre-spurious journal semantics.
        {
            use revm::context_interface::JournalTr;
            let _ = context.journal_mut().load_account(inputs.target_address);
            context.journal_mut().touch_account(inputs.target_address);
        }

        // What the journal holds of logs before the call, to tell the call's
        // own apart afterwards.
        let logs_before = {
            use revm::context_interface::JournalTr;
            context.journal().logs().len()
        };

        let exec_result = if *addr == BRIDGE_ADDR {
            // rskj gives the Bridge an internal transaction from the program
            // that made the call (`getOwnerRskAddress`), with the value the
            // opcode took off the stack. DELEGATECALL takes none, and revm's
            // caller and value for it are those of the frame that delegates.
            let (owner, value) = match inputs.scheme {
                revm::interpreter::CallScheme::DelegateCall => {
                    (inputs.target_address, revm::primitives::U256::ZERO)
                }
                _ => (inputs.caller, inputs.call_value()),
            };
            self.run_bridge(
                context,
                &input_bytes,
                inputs.gas_limit,
                owner,
                inputs.scheme,
                value,
            )
        } else {
            self.run_remasc(context, &input_bytes, inputs.gas_limit)
        };

        // Raw-bytes storage commit discipline (rskj commits the call's child
        // repository track only when the method succeeds).
        match &exec_result {
            Ok(o) if !o.reverted => context.chain_mut().raw_storage.commit_call(),
            _ => context.chain_mut().raw_storage.discard_call(),
        }

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        };

        // rskj invisible exception (direct Bridge call, parse failure
        // post-RSKIP88): the CALL succeeds with the flat parse-failure gas,
        // empty output and no endowment; `RskHandler` reads the flag during
        // fee finalization to charge the sender the full gas limit.
        if let Err(e) = &exec_result {
            if let Some(spent) = crate::bridge::invisible_exception_gas(e) {
                self.invisible_exception
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                // The CALL frame already transferred the endowment; rskj
                // skips it when execute() throws (TransactionExecutor.call).
                if let Some(value) = inputs.transfer_value().filter(|v| !v.is_zero()) {
                    let _ = context
                        .journal_mut()
                        .transfer(inputs.target_address, inputs.caller, value);
                }
                // rskj `getGasForData` (requiredGas): the precompile frame
                // records only this cost. REMASC carries 0; the Bridge carries
                // the flat parse-failure cost or the method's getGasForData.
                let spent = if *addr == BRIDGE_ADDR { spent } else { 0 };
                let underflow = result.gas.record_cost(spent);
                assert!(underflow, "gas pre-checked against the cost");
                return Ok(Some(result));
            }
            // A call that ends the contract that made it, in every era
            // (`bridge::CALLER_ABORT_MARKER`): `RskHandler` halts the contract
            // on the flag, as for a throw before RSKIP197 below.
            if crate::bridge::ends_its_caller(e) {
                self.aborts_caller
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                let underflow = result.gas.record_cost(inputs.gas_limit);
                assert!(underflow, "spending exactly the forwarded gas");
                result.result = InstructionResult::PrecompileError;
                return Ok(Some(result));
            }
            // Internal (depth>1) throw, by a Bridge method or by REMASC: rskj
            // `Program.executePrecompiledAndHandleError` consumes only
            // `requiredGas` and the CALL fails (pushes zero). Record that cost
            // and revert so the caller refunds the forwarded leftover.
            if let Some(spent) = crate::bridge::internal_throw_gas(e) {
                if !self.rskip197_active(context) {
                    // Before RSKIP197 (iris300) `Program.executePrecompiled`
                    // has no error handling: the throw leaves the VM and fails
                    // the contract that made the call, with all its gas, which
                    // `RskHandler` does on the flag. Testnet #808,484 is the
                    // live instance: a constructor calls the Bridge with a
                    // selector that is not a Bridge method, which post-RSKIP88
                    // throws, and the transaction is charged its whole limit.
                    self.aborts_caller
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    let underflow = result.gas.record_cost(inputs.gas_limit);
                    assert!(underflow, "spending exactly the forwarded gas");
                    result.result = InstructionResult::PrecompileError;
                    return Ok(Some(result));
                }
                // The catch rolls back the call's track and nothing else. The
                // Bridge wrote its logs straight into the calling program's
                // list (`callToPrecompiledAddress` hands it
                // `result.getLogInfoList()`), so those stay with the caller;
                // `RskHandler` writes them again once revm has dropped them
                // with this call's checkpoint.
                {
                    use revm::context_interface::JournalTr;
                    let kept = context.journal().logs()[logs_before..].to_vec();
                    context.chain_mut().kept_logs.extend(kept);
                }
                let underflow = result.gas.record_cost(spent);
                assert!(underflow, "gas pre-checked against requiredGas");
                result.result = InstructionResult::Revert;
                return Ok(Some(result));
            }
            // Internal (depth>1) Bridge call with insufficient gas: rskj
            // `Program.callToPrecompiledAddress` does `refundGas(0);
            // stackPushZero(); rollback()` — consume ALL forwarded gas, the
            // CALL fails (pushes zero) and the caller CONTINUES (it is not a
            // propagating OOG). Map to a plain CALL revert with the forwarded
            // gas fully spent. (Program.java:1567-1573)
            if let Some(consumed) = crate::bridge::insufficient_gas_consumed(e) {
                let underflow = result.gas.record_cost(consumed);
                assert!(underflow, "consumed gas is the forwarded gas_limit");
                result.result = InstructionResult::Revert;
                return Ok(Some(result));
            }
        }

        match exec_result {
            Ok(output) => {
                result.gas.record_refund(output.gas_refunded);
                let underflow = result.gas.record_cost(output.gas_used);
                assert!(underflow, "Gas underflow is not possible");
                result.result = if output.reverted {
                    InstructionResult::Revert
                } else {
                    // rskj setupContract on successful precompile calls.
                    self.record_called(*addr);
                    InstructionResult::Return
                };
                result.output = output.bytes;
            }
            Err(PrecompileError::Fatal(e)) => return Err(e),
            Err(e) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
                if !e.is_oog() && context.journal().depth() == 1 {
                    context
                        .local_mut()
                        .set_precompile_error_context(e.to_string());
                }
            }
        }

        Ok(Some(result))
    }

    /// Bridge precompile (0x01000006).
    /// BTC–RSK two-way peg with 69 ABI methods.
    fn run_bridge<CTX: crate::RskContextTr>(
        &self,
        context: &mut CTX,
        input: &[u8],
        gas_limit: u64,
        caller: Address,
        scheme: revm::interpreter::CallScheme,
        call_value: revm::primitives::U256,
    ) -> Result<PrecompileOutput, PrecompileError> {
        use revm::context_interface::JournalTr;
        use revm::interpreter::CallScheme;
        let call_kind = match scheme {
            CallScheme::Call => crate::bridge::BridgeCallKind::Call,
            CallScheme::StaticCall => crate::bridge::BridgeCallKind::StaticCall,
            CallScheme::DelegateCall | CallScheme::CallCode => {
                crate::bridge::BridgeCallKind::DelegateOrCallCode
            }
        };
        let block_number = context.block().number().to::<u64>();
        let use_v2 = self.hardfork_cfg.has_stored_block_v2(block_number);
        // Call depth as seen by the Bridge precompile: > 1 means the Bridge was
        // reached via a contract CALL (rskj `isContractTx`). revm's depth here
        // already counts the precompile's own frame.
        let call_depth = context.journal().depth();
        let tx_ctx = self.bridge_tx_context.lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        crate::bridge::execute_bridge(
            context,
            input,
            gas_limit,
            &self.bridge_config,
            self.block_store.as_ref(),
            use_v2,
            &self.hardfork_cfg,
            &tx_ctx,
            caller,
            call_depth,
            call_kind,
            call_value,
        )
    }

    /// REMASC precompile (0x01000008). Gas: 0 (rskj getGasForData).
    ///
    /// Fee distribution itself runs only for the block's REMASC system tx,
    /// which the executor dispatches directly — every invocation arriving
    /// here is a user tx or an internal CALL. rskj (Remasc.processMinersFees)
    /// throws RemascInvalidInvocationException for those, EXCEPT
    /// getStateForDebugging(), which has no caller guard and answers with the
    /// contract's state, and then saves as every REMASC method that returns
    /// does (`RemascContract.execute`).
    fn run_remasc<CTX: crate::RskContextTr>(
        &self,
        context: &mut CTX,
        input: &[u8],
        _gas_limit: u64,
    ) -> Result<PrecompileOutput, PrecompileError> {
        // `RemascContract.getFunction` takes a selector of exactly four bytes.
        if input == crate::remasc::GET_STATE_FOR_DEBUGGING {
            let state = crate::remasc::state_for_debugging(context);
            // `RemascStorageProvider.save`: the method set no balance and no
            // flag, so the siblings cell is all it writes, as it always does
            // (`saveSiblings`). It writes through `addStorageBytes`, which
            // creates REMASC's account where there is none: the one thing
            // of this a later call can tell, since every block's REMASC
            // transaction has written the same cell since block 1.
            {
                use revm::context_interface::JournalTr;
                let _ = context.journal_mut().load_account(REMASC_ADDR);
                context.journal_mut().touch_account(REMASC_ADDR);
            }
            context.chain_mut().raw_storage.put(
                REMASC_ADDR,
                crate::remasc::remasc_storage_key("siblings"),
                Some(vec![alloy_rlp::EMPTY_LIST_CODE]),
            );
            return Ok(PrecompileOutput::new(0, state.into()));
        }
        // Everything else throws in rskj: invisible for a direct tx
        // (receipt SUCCESS, intrinsic gas, sender charged the full limit).
        // For a contract's call it is the Bridge's internal throw, costing
        // REMASC's getGasForData: from RSKIP197 a failed CALL that gives all
        // the forwarded gas back, and before it the end of the contract that
        // made the call.
        use revm::context_interface::JournalTr;
        if context.journal().depth() == 1 {
            // REMASC getGasForData is 0; the invisible path forces 0 anyway.
            return Err(crate::bridge::invisible_exception_marker_with_gas(0));
        }
        Err(crate::bridge::internal_throw_marker_with_gas(0))
    }

    /// One of rskj's native contracts, on the block executing.
    fn run_native<CTX: crate::RskContextTr>(
        &self,
        context: &CTX,
        addr: Address,
        input: &[u8],
        gas_limit: u64,
    ) -> Outcome {
        match addr {
            HD_WALLET_UTILS_ADDR => native::call(&HdWalletUtils, input, gas_limit),
            BLOCK_HEADER_ADDR => {
                let Some(blocks) = self.block_store.as_deref() else {
                    return Outcome::Fatal(
                        "BlockHeader reads a block store, and there is none".into(),
                    );
                };
                let number = context.block().number().to::<u64>();
                let contract = BlockHeader {
                    blocks,
                    parent: self.parent_hash,
                    rskip536: self.hardfork_cfg.has_rskip536(number),
                };
                native::call(&contract, input, gas_limit)
            }
            ENVIRONMENT_ADDR => {
                // A precompile's frame is one deeper than its caller's, and the
                // transaction's own call is at depth 1, so a contract the
                // transaction calls, rskj's depth 0, calls from depth 2.
                let caller_depth = context
                    .journal()
                    .depth()
                    .checked_sub(2)
                    .and_then(|depth| u32::try_from(depth).ok());
                native::call(&Environment { caller_depth }, input, gas_limit)
            }
            _ => Outcome::Fatal(format!("{addr} is not a native contract")),
        }
    }

    /// Settles what a precompile did, as rskj's `TransactionExecutor.call`
    /// does for a transaction's own call and `Program.callToPrecompiledAddress`
    /// for a contract's.
    ///
    /// A precompile that throws in a transaction's own call is rskj's
    /// invisible exception: the transaction succeeds with no output, having
    /// used its intrinsic gas and the precompile's, while its sender pays for
    /// the whole gas limit and keeps the value. The frame reverts here, so
    /// revm hands the value back and forgets the account's touch, and
    /// `RskHandler` turns the transaction's result back into a success.
    ///
    /// In a contract's call, from RSKIP197 a throw costs what the precompile
    /// asked for and the call fails. Before it the throw escapes the VM and
    /// fails the contract that made the call, with all its gas: the call fails
    /// here, and `RskHandler` halts that contract on the flag set here.
    fn finish<CTX: crate::RskContextTr>(
        &self,
        context: &CTX,
        addr: Address,
        gas_limit: u64,
        outcome: Outcome,
    ) -> Result<InterpreterResult, String> {
        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(gas_limit),
            output: Bytes::new(),
        };
        let gas = match &outcome {
            Outcome::Returned { gas, .. } | Outcome::Threw { gas, .. } => *gas,
            Outcome::OutOfGas | Outcome::Fatal(_) => 0,
        };
        // Held to the limit before the precompile ran, so this always fits.
        if !result.gas.record_cost(gas) {
            result.result = InstructionResult::PrecompileOOG;
            return Ok(result);
        }
        match outcome {
            Outcome::Returned { output, .. } => {
                // rskj's setupContract, for a precompile that returns.
                self.record_called(addr);
                result.output = output;
            }
            Outcome::OutOfGas => result.result = InstructionResult::PrecompileOOG,
            Outcome::Threw { reason, .. } => {
                tracing::debug!(target: "rustock::precompile", %addr, %reason, "precompile threw");
                result.result = if context.journal().depth() == 1 {
                    self.invisible_exception
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    InstructionResult::Revert
                } else if self.rskip197_active(context) {
                    InstructionResult::Revert
                } else {
                    self.aborts_caller
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    InstructionResult::PrecompileError
                };
            }
            Outcome::Fatal(reason) => return Err(reason),
        }
        Ok(result)
    }
}

impl Clone for RskPrecompileProvider {
    fn clone(&self) -> Self {
        Self {
            precompiles: self.precompiles.clone(),
            hardfork_cfg: self.hardfork_cfg.clone(),
            spec: self.spec,
            block_store: self.block_store.clone(),
            parent_hash: self.parent_hash,
            remasc_config: self.remasc_config.clone(),
            bridge_config: self.bridge_config.clone(),
            bridge_tx_context: std::sync::Arc::clone(&self.bridge_tx_context),
            invisible_exception: std::sync::Arc::clone(&self.invisible_exception),
            aborts_caller: std::sync::Arc::clone(&self.aborts_caller),
            called_precompiles: std::sync::Arc::clone(&self.called_precompiles),
            reached_sequential_only: std::sync::Arc::clone(&self.reached_sequential_only),
        }
    }
}

impl<CTX: crate::RskContextTr> PrecompileProvider<CTX> for RskPrecompileProvider {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let spec: SpecId = spec.into();
        if spec == self.spec {
            return false;
        }
        self.spec = spec;
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        // REMASC and the Bridge first, for the whole context.
        if let Some(result) = self.run_stateful(context, inputs)? {
            return Ok(Some(result));
        }

        // The set holds only what is active at this block; before its
        // activation a precompile's address is an account like any other.
        let addr = inputs.bytecode_address;
        let Some(precompile) = self.precompiles.get(&addr) else {
            return Ok(None);
        };

        // rskj creates the account of the call's context address on first
        // call: the precompile's, or for CALLCODE and DELEGATECALL the
        // caller's own (see the stateful path above).
        {
            use revm::context_interface::JournalTr;
            let _ = context.journal_mut().load_account(inputs.target_address);
            context.journal_mut().touch_account(inputs.target_address);
        }

        let rskip197 = self.rskip197_active(context);
        let max_input = self.max_input(context, &addr);
        let outcome = {
            let shared;
            let input = match &inputs.input {
                CallInput::SharedBuffer(range) => {
                    match context.local().shared_memory_buffer_slice(range.clone()) {
                        Some(slice) => {
                            shared = slice;
                            shared.as_ref()
                        }
                        None => &[],
                    }
                }
                CallInput::Bytes(bytes) => bytes.as_ref(),
            };
            let input = max_input.map_or(input, |max| &input[..input.len().min(max)]);
            if self.blake2f_reads_null(context, &addr, input) {
                Outcome::Fatal("BLAKE2F's getGasForData throws on null data".into())
            } else if NATIVE_CONTRACTS.contains(&addr) {
                self.run_native(context, addr, input, inputs.gas_limit)
            } else {
                run_precompile(precompile, &addr, input, inputs.gas_limit, rskip197)
            }
        };
        self.finish(context, addr, inputs.gas_limit, outcome)
            .map(Some)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        Box::new(self.precompiles.addresses().cloned())
    }

    fn contains(&self, address: &Address) -> bool {
        self.precompiles.contains(address)
    }
}

/// A precompile of the set that is not one of rskj's native contracts, run as
/// rskj runs it: what `getGasForData` asks for is held to the gas limit
/// before it runs, and an input it refuses makes it throw.
fn run_precompile(
    precompile: &Precompile,
    addr: &Address,
    input: &[u8],
    gas_limit: u64,
    rskip197: bool,
) -> Outcome {
    let required = gas_for_data(addr, input);
    if required.is_some_and(|required| required > gas_limit) {
        return Outcome::OutOfGas;
    }
    match precompile.execute(input, gas_limit) {
        Ok(output) => Outcome::Returned {
            gas: output.gas_used,
            output: output.bytes,
        },
        Err(PrecompileError::Fatal(reason)) => Outcome::Fatal(reason),
        Err(error) if error.is_oog() => Outcome::OutOfGas,
        Err(error) => match required {
            // `BN128PrecompiledContract.safeExecute`: before RSKIP197 a point
            // BN128 refuses gets an answer with no bytes.
            Some(gas)
                if !rskip197
                    && [BN128_ADD_ADDR, BN128_MUL_ADDR, BN128_PAIRING_ADDR].contains(addr) =>
            {
                Outcome::Returned {
                    gas,
                    output: Bytes::new(),
                }
            }
            Some(gas) => Outcome::Threw {
                gas,
                reason: error.to_string(),
            },
            // Every precompile that can throw has its price in `gas_for_data`.
            None => Outcome::Fatal(format!(
                "precompile {addr} threw, and rustock has no price for it: {error}"
            )),
        },
    }
}

/// Helper to check if an address is an RSK precompile at a given block.
pub fn is_rsk_precompile(
    address: &Address,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> bool {
    let precompiles = rsk_precompiles(hardfork_cfg, block_number);
    precompiles.contains(address)
}

// ---------------------------------------------------------------------------
// Compile-time hex address helper
// ---------------------------------------------------------------------------

const fn hex_addr(hex: &str) -> [u8; 20] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 40, "hex address must be 40 chars");
    let mut result = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        result[i] = (hex_val(bytes[i * 2]) << 4) | hex_val(bytes[i * 2 + 1]);
        i += 1;
    }
    result
}

const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex char"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // getGasForData, and what a precompile that throws comes to
    // -----------------------------------------------------------------------

    /// Audit FRCR-280. rskj charges a precompile call `getGasForData(input)`,
    /// whether it returns or throws, and the secp256k1 contracts return their
    /// flat cost from `getGasForData` without ever looking at the input
    /// (`Secp256k1Addition.java:27` EC_256_ADDITION_GAS_COST = 150,
    /// `Secp256k1Multiplication.java:27` = 3000). Missing from the table, a
    /// call that throws would be free: a consensus divergence from reed800
    /// onwards.
    #[test]
    fn the_secp256k1_contracts_cost_the_same_whatever_their_input() {
        assert_eq!(gas_for_data(&SECP256K1_ADD_ADDR, &[]), Some(150));
        assert_eq!(gas_for_data(&SECP256K1_MUL_ADDR, &[]), Some(3_000));
        assert_eq!(gas_for_data(&SECP256K1_ADD_ADDR, &[0xff; 128]), Some(150));
        assert_eq!(gas_for_data(&SECP256K1_MUL_ADDR, &[0xff; 96]), Some(3_000));
    }

    /// The failure above is only reachable if an off-curve point really does
    /// produce a *non-OOG* `Err` — an OOG error takes the other branch and
    /// consumes everything. This pins the premise, so the table entry above
    /// cannot be deleted as unreachable.
    #[test]
    fn secp256k1_off_curve_point_is_a_non_oog_error() {
        // x = 1 is not a valid secp256k1 x-coordinate (1 + 7 = 8 is not a QR).
        let mut input = [0u8; 128];
        input[31] = 1; // p1.x = 1
        input[63] = 1; // p1.y = 1  -> not on the curve
        input[95] = 1; // p2.x = 1
        input[127] = 1;

        let err = secp256k1_add_run(&input, 1_000_000).expect_err("off-curve must fail");
        assert!(!err.is_oog(), "must not be OOG, got {err:?}");

        let err = secp256k1_mul_run(&input[..96], 1_000_000).expect_err("off-curve must fail");
        assert!(!err.is_oog(), "must not be OOG, got {err:?}");
    }

    /// The other precompiles that can throw, pinned together so the table is
    /// read as a whole. rskj: `BN128Addition.getGasForData` = 150,
    /// `BN128Multiplication` = 6000, `BN128Pairing` = 45000 + 34000*pairs,
    /// `Blake2F` = the big-endian rounds word (0 when the length is wrong).
    #[test]
    fn bn128_and_blake2f_cost_what_rskj_charges() {
        assert_eq!(gas_for_data(&BN128_ADD_ADDR, &[]), Some(150));
        assert_eq!(gas_for_data(&BN128_MUL_ADDR, &[]), Some(6_000));
        assert_eq!(
            gas_for_data(&BN128_PAIRING_ADDR, &[0u8; 384]),
            Some(45_000 + 2 * 34_000)
        );

        let mut blake_input = [0u8; 213];
        blake_input[..4].copy_from_slice(&12u32.to_be_bytes());
        assert_eq!(gas_for_data(&BLAKE2F_ADDR, &blake_input), Some(12));
        assert_eq!(gas_for_data(&BLAKE2F_ADDR, &[0u8; 100]), Some(0));

        // ecrecover never throws in rskj; it returns empty.
        let ecrecover = Address::new(hex_addr("0000000000000000000000000000000000000001"));
        assert_eq!(gas_for_data(&ecrecover, &[]), None);
    }

    /// What `run_precompile` makes of each kind of refusal: rskj's throw, for
    /// what `getGasForData` asked; for BN128 before RSKIP197, an answer with
    /// no bytes; and for a modexp length no int holds, running out of gas.
    #[test]
    fn a_precompile_that_refuses_its_input_throws_for_its_price() {
        let set = rsk_precompiles(&RskHardforkConfig::all_active(33), 0);
        let run = |addr: Address, input: &[u8], gas: u64, rskip197: bool| {
            run_precompile(set.get(&addr).expect("active"), &addr, input, gas, rskip197)
        };
        // (1, 1) is on neither BN128's curve nor secp256k1's.
        let mut off_curve = [0u8; 128];
        off_curve[31] = 1;
        off_curve[63] = 1;
        assert!(matches!(
            run(BN128_ADD_ADDR, &off_curve, 1_000, true),
            Outcome::Threw { gas: 150, .. }
        ));
        assert_eq!(
            run(BN128_ADD_ADDR, &off_curve, 1_000, false),
            Outcome::Returned {
                gas: 150,
                output: Bytes::new()
            }
        );
        assert_eq!(
            run(BN128_ADD_ADDR, &off_curve, 149, true),
            Outcome::OutOfGas
        );
        assert!(matches!(
            run(BN128_MUL_ADDR, &off_curve[..96], 6_000, true),
            Outcome::Threw { gas: 6_000, .. }
        ));
        assert_eq!(
            run(BN128_MUL_ADDR, &off_curve[..96], 5_999, true),
            Outcome::OutOfGas
        );
        // A pairing input that is not whole pairs.
        assert!(matches!(
            run(BN128_PAIRING_ADDR, &[0; 100], 1_000_000, true),
            Outcome::Threw { gas: 45_000, .. }
        ));
        // BLAKE2F's input is 213 bytes, or it costs nothing and throws.
        assert!(matches!(
            run(BLAKE2F_ADDR, &[0; 100], 1_000, true),
            Outcome::Threw { gas: 0, .. }
        ));
        let mut blake = [0u8; 213];
        blake[3] = 12;
        blake[212] = 2;
        assert!(
            matches!(
                run(BLAKE2F_ADDR, &blake, 12, true),
                Outcome::Threw { gas: 12, .. }
            ),
            "a bad final-block flag"
        );
        assert_eq!(run(BLAKE2F_ADDR, &blake, 11, true), Outcome::OutOfGas);
        assert!(matches!(
            run(SECP256K1_ADD_ADDR, &off_curve, 1_000, true),
            Outcome::Threw { gas: 150, .. }
        ));
        // A base length of 2^248.
        let mut huge = [0u8; 96];
        huge[0] = 1;
        assert_eq!(
            run(Address::with_last_byte(5), &huge, 1_000_000, true),
            Outcome::OutOfGas
        );
        // What a precompile answers comes through as it is.
        assert_eq!(
            run(Address::with_last_byte(4), b"abc", 1_000, true),
            Outcome::Returned {
                gas: 18,
                output: Bytes::from_static(b"abc")
            }
        );
    }

    // -----------------------------------------------------------------------
    // ModExp, as rskj's BigIntegerModexp
    // -----------------------------------------------------------------------

    /// A modexp input: the base, exponent and modulus lengths as words, then
    /// `rest`.
    fn modexp_input(lengths: [alloy_primitives::U256; 3], rest: &[u8]) -> Vec<u8> {
        let mut input: Vec<u8> = lengths
            .iter()
            .flat_map(|len| len.to_be_bytes::<32>())
            .collect();
        input.extend_from_slice(rest);
        input
    }

    fn run_modexp(input: &[u8], gas: u64) -> Result<PrecompileOutput, PrecompileError> {
        rsk_precompiles(&RskHardforkConfig::mainnet(), 0)
            .get(&MODEXP_ADDR)
            .expect("modexp is a genesis precompile")
            .execute(input, gas)
    }

    /// EIP-198's examples: 3^(p - 1) mod p is 1 for secp256k1's prime p, and
    /// 0^(p - 1) mod p is 0, each for 13,056 gas -- a 32-byte modulus,
    /// squared, times the exponent's top bit, 255, over 20.
    #[test]
    fn modexp_answers_eip198s_examples() {
        use alloy_primitives::{hex, U256};
        let exponent = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
        let p = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
        let (one, thirty_two) = (U256::from(1), U256::from(32));

        let input = modexp_input(
            [one, thirty_two, thirty_two],
            &[&[3u8][..], &exponent[..], &p[..]].concat(),
        );
        let mut answer = [0u8; 32];
        answer[31] = 1;
        let out = run_modexp(&input, 13_056).unwrap();
        assert_eq!((out.gas_used, out.bytes.as_ref()), (13_056, &answer[..]));

        let input = modexp_input(
            [U256::ZERO, thirty_two, thirty_two],
            &[exponent, p].concat(),
        );
        let out = run_modexp(&input, 13_056).unwrap();
        assert_eq!((out.gas_used, out.bytes.as_ref()), (13_056, &[0u8; 32][..]));
        assert!(matches!(
            run_modexp(&input, 13_055),
            Err(PrecompileError::OutOfGas)
        ));
    }

    /// Where every length fits an int and every argument a `BigInteger`,
    /// rskj's ModExp is EIP-198's, revm's: the same price and the same
    /// answer, for lengths each side of 64 and of 1,024 bytes and inputs cut
    /// short of what their lengths declare.
    #[test]
    fn modexp_is_eip198s_within_rskjs_limits() {
        use alloy_primitives::U256;
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for case in 0..300 {
            let mut len = || {
                if next() % 20 == 0 {
                    1_000 + next() % 100
                } else {
                    next() % 70
                }
            };
            let lengths = [len(), len(), len()];
            let declared: u64 = lengths.iter().sum();
            let rest: Vec<u8> = (0..next() % (declared + 16))
                .map(|_| next() as u8)
                .collect();
            let input = modexp_input(lengths.map(U256::from), &rest);

            let ours = run_modexp(&input, u64::MAX).unwrap();
            let eip198 = revm::precompile::modexp::byzantium_run(&input, u64::MAX).unwrap();
            assert_eq!(
                (ours.gas_used, &ours.bytes),
                (eip198.gas_used, &eip198.bytes),
                "case {case}: lengths {lengths:?}"
            );
            if ours.gas_used > 0 {
                let short = run_modexp(&input, ours.gas_used - 1);
                assert!(
                    matches!(short, Err(PrecompileError::OutOfGas)),
                    "case {case}"
                );
            }
        }
    }

    /// rskj reads a length as a Java int, one of 2^31 or more as
    /// `Integer.MAX_VALUE`. An exponent 2^32 bytes long is priced as one of
    /// 2^31 - 1 bytes, and with a one-byte base and modulus the call answers
    /// nothing, the modulus starting past an int. revm prices the length it
    /// was given, and runs out of gas.
    #[test]
    fn modexp_reads_a_length_as_a_java_int() {
        use alloy_primitives::U256;
        let one = U256::from(1);
        let input = modexp_input([one, one << 32, one], &[2, 1]);
        // The exponent's top bit among its first 32 bytes is bit 248:
        // 8 * (2^31 - 1 - 32) + 248 = 17,179,869,168, over 20.
        let out = run_modexp(&input, 858_993_458).unwrap();
        assert_eq!((out.gas_used, out.bytes.len()), (858_993_458, 0));
        assert!(matches!(
            run_modexp(&input, 858_993_457),
            Err(PrecompileError::OutOfGas)
        ));
        assert!(matches!(
            revm::precompile::modexp::byzantium_run(&input, 858_993_458),
            Err(PrecompileError::OutOfGas)
        ));

        // A base no int holds: (2^31 - 1)^2 / 16 + 480 (2^31 - 1) - 199,680,
        // over 20. No call with such a base or modulus costs less.
        let input = modexp_input([one << 255, U256::ZERO, U256::ZERO], &[]);
        let out = run_modexp(&input, 14_411_570_333_761_358).unwrap();
        assert_eq!((out.gas_used, out.bytes.len()), (14_411_570_333_761_358, 0));
        // The price stops at Long.MAX_VALUE.
        let input = modexp_input([U256::MAX; 3], &[]);
        assert_eq!(
            run_modexp(&input, u64::MAX).unwrap().gas_used,
            i64::MAX as u64
        );
    }

    /// rskj's `execute` answers nothing for an `ArithmeticException`: an
    /// offset past an int (`Math.addExact`), or an argument past what a
    /// `BigInteger` holds, 2^31 - 1 bits. The cheapest call to reach either
    /// is an exponent of 2^28 bytes whose top bit is set, 107,374,182 gas;
    /// with the bit below it the exponent fits, and the zero modulus past the
    /// input's end answers a zero byte.
    #[test]
    fn modexp_answers_nothing_where_rskj_throws() {
        use alloy_primitives::U256;
        let one = U256::from(1);
        let two_28 = one << 28;
        for (top, answer) in [(0x80, &[][..]), (0x40, &[0][..])] {
            let input = modexp_input([one, two_28, one], &[2, top]);
            let out = run_modexp(&input, 107_374_182).unwrap();
            assert_eq!(
                (out.gas_used, out.bytes.as_ref()),
                (107_374_182, answer),
                "{top:#x}"
            );
            // The base, the same way, at whatever price.
            let input = modexp_input([two_28, one, one], &[top]);
            let out = run_modexp(&input, u64::MAX).unwrap();
            assert_eq!(out.bytes.as_ref(), answer, "base {top:#x}");
        }
        // The modulus would start at 2^31, past an int. The exponent is all
        // zeros, which a `BigInteger` holds whatever their number.
        let input = modexp_input([one, U256::from(i32::MAX as u64 - 96), one], &[2]);
        assert!(run_modexp(&input, u64::MAX).unwrap().bytes.is_empty());
    }

    #[test]
    fn test_remasc_address() {
        assert_eq!(
            format!("{:x}", REMASC_ADDR),
            "0000000000000000000000000000000001000008"
        );
    }

    #[test]
    fn test_bridge_address() {
        assert_eq!(
            format!("{:x}", BRIDGE_ADDR),
            "0000000000000000000000000000000001000006"
        );
    }

    #[test]
    fn test_genesis_precompiles_always_present() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 0);

        assert!(precompiles.contains(&REMASC_ADDR));
        assert!(precompiles.contains(&BRIDGE_ADDR));

        // Standard Ethereum precompiles should also be present
        let ecrecover = Address::new(hex_addr("0000000000000000000000000000000000000001"));
        assert!(precompiles.contains(&ecrecover));
    }

    // -----------------------------------------------------------------------
    // ECRecover, as rskj's
    // -----------------------------------------------------------------------

    /// The generator's x. Its y is even, so with recovery id 0 the point R
    /// whose x is r is the generator itself.
    const GENERATOR_X: [u8; 32] =
        alloy_primitives::hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    /// ECRecover's input for the hash 1, `v`, r the generator's x and s =
    /// `s`. The key is r⁻¹(sR − G), where R is G for v 27 and −G for 28.
    fn ecrecover_input(v: u8, s: u8) -> Vec<u8> {
        let mut input = vec![0_u8; 128];
        input[31] = 1;
        input[63] = v;
        input[64..96].copy_from_slice(&GENERATOR_X);
        input[127] = s;
        input
    }

    fn rskj_ecrecover(input: &[u8]) -> Bytes {
        rsk_ecrecover_run(input, 3_000).unwrap().bytes
    }

    fn ethereum_ecrecover(input: &[u8]) -> Bytes {
        use revm::precompile::secp256k1::ec_recover_run;
        ec_recover_run(input, 3_000).unwrap().bytes
    }

    /// For an ordinary signature rskj's ECRecover recovers what Ethereum's
    /// does, reading 128 bytes and ending a short s in zeros.
    #[test]
    fn ecrecover_recovers_an_ordinary_key_as_ethereums_does() {
        for v in [27, 28] {
            let input = ecrecover_input(v, 2);
            let key = rskj_ecrecover(&input);
            assert_eq!(key.len(), 32, "v {v} recovers a key");
            assert_eq!(key, ethereum_ecrecover(&input));
            let mut longer = input.clone();
            longer.extend([0xff; 32]);
            assert_eq!(rskj_ecrecover(&longer), key, "only 128 bytes are read");
        }
        // s = 2^249, all in its first byte.
        let mut short = ecrecover_input(27, 0);
        short[96] = 2;
        let whole = rskj_ecrecover(&short);
        assert_eq!(whole.len(), 32);
        assert_eq!(rskj_ecrecover(&short[..97]), whole);
        assert_eq!(ethereum_ecrecover(&short[..97]), whole);

        // Too short to hold r, a v of neither 27 nor 28, or no input: nothing.
        assert!(rskj_ecrecover(&ecrecover_input(27, 2)[..95]).is_empty());
        assert!(rskj_ecrecover(&ecrecover_input(29, 2)).is_empty());
        assert!(rskj_ecrecover(&[]).is_empty());
        assert!(matches!(
            rsk_ecrecover_run(&[], 2_999),
            Err(PrecompileError::OutOfGas)
        ));
    }

    /// rskj's `isValid` reads only the last byte of the `v` word, so a word
    /// with other bytes set still recovers the key. Ethereum's answers nothing.
    #[test]
    fn ecrecover_reads_only_the_last_byte_of_v() {
        let clean = ecrecover_input(27, 2);
        let mut dirty = clean.clone();
        dirty[32] = 0x01;
        dirty[50] = 0xff;
        assert_eq!(rskj_ecrecover(&dirty), rskj_ecrecover(&clean));
        assert!(ethereum_ecrecover(&dirty).is_empty());
    }

    /// With R = G and s = e = 1, sR = eG, and the key is the point at
    /// infinity: rskj recovers the address it gives that key, from keccak256 of
    /// nothing, where Ethereum's ECRecover answers nothing. With v 28, R is −G
    /// and the key an ordinary one. The set from genesis runs rskj's.
    #[test]
    fn ecrecover_recovers_the_infinity_sender_as_rskj_does() {
        let mut infinity = [0_u8; 32];
        infinity[12..]
            .copy_from_slice(rustock_core::types::transaction::INFINITY_SENDER.as_slice());
        let infinity = Bytes::copy_from_slice(&infinity);
        let input = ecrecover_input(27, 1);
        assert_eq!(rskj_ecrecover(&input), infinity);
        assert!(ethereum_ecrecover(&input).is_empty());

        let ordinary = ecrecover_input(28, 1);
        assert_ne!(rskj_ecrecover(&ordinary), infinity);
        assert_eq!(rskj_ecrecover(&ordinary), ethereum_ecrecover(&ordinary));
        assert_eq!(rskj_ecrecover(&ordinary).len(), 32);

        let set = rsk_precompiles(&RskHardforkConfig::mainnet(), 0);
        let ecrecover = set.get(&ECRECOVER_ADDR).unwrap();
        assert_eq!(ecrecover.execute(&input, 3_000).unwrap().bytes, infinity);
    }

    #[test]
    fn test_hdwallet_not_active_before_wasabi100() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 0);
        assert!(!precompiles.contains(&HD_WALLET_UTILS_ADDR));
    }

    #[test]
    fn test_blockheader_active_after_wasabi() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 1_590_999);
        assert!(!pre.contains(&BLOCK_HEADER_ADDR));

        let post = rsk_precompiles(&cfg, 1_591_000);
        assert!(post.contains(&BLOCK_HEADER_ADDR));
    }

    /// rskj reference.conf: rskip203 = arrowhead600 (mainnet 6_223_700).
    #[test]
    fn test_environment_active_after_arrowhead600() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 6_223_699);
        assert!(!pre.contains(&ENVIRONMENT_ADDR));

        let post = rsk_precompiles(&cfg, 6_223_700);
        assert!(post.contains(&ENVIRONMENT_ADDR));
    }

    /// rskj reference.conf: rskip106 = wasabi100 (mainnet 1_591_000).
    #[test]
    fn test_hdwallet_active_after_wasabi100() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 1_590_999);
        assert!(!pre.contains(&HD_WALLET_UTILS_ADDR));

        let post = rsk_precompiles(&cfg, 1_591_000);
        assert!(post.contains(&HD_WALLET_UTILS_ADDR));
    }

    /// rskj reference.conf: rskip137 = papyrus200 (mainnet 2_392_700).
    /// BN128 uses EIP-1108 (Istanbul) pricing from activation: add = 150
    /// (rskj BN128Addition.getGasForData groundtruth).
    #[test]
    fn test_bn128_active_after_papyrus200_with_istanbul_gas() {
        let cfg = RskHardforkConfig::mainnet();
        let bn_add: Address = revm::precompile::u64_to_address(6);
        let bn_mul: Address = revm::precompile::u64_to_address(7);
        let bn_pair: Address = revm::precompile::u64_to_address(8);

        let pre = rsk_precompiles(&cfg, 2_392_699);
        assert!(!pre.contains(&bn_add));
        assert!(!pre.contains(&bn_mul));
        assert!(!pre.contains(&bn_pair));

        let post = rsk_precompiles(&cfg, 2_392_700);
        assert!(post.contains(&bn_add));
        assert!(post.contains(&bn_mul));
        assert!(post.contains(&bn_pair));

        // Istanbul pricing at activation: two valid points at infinity, add = 150 gas.
        let out = post.get(&bn_add).unwrap().execute(&[0u8; 128], 200).unwrap();
        assert_eq!(out.gas_used, 150, "rskj uses EIP-1108 pricing from rskip137");
    }

    /// rskj reference.conf: rskip153 = iris300 (mainnet 3_614_800).
    #[test]
    fn test_blake2f_active_after_iris300() {
        let cfg = RskHardforkConfig::mainnet();
        let blake2f: Address = revm::precompile::u64_to_address(9);

        let pre = rsk_precompiles(&cfg, 3_614_799);
        assert!(!pre.contains(&blake2f));

        let post = rsk_precompiles(&cfg, 3_614_800);
        assert!(post.contains(&blake2f));
    }

    /// RSK has no KZG point-evaluation precompile (Ethereum 0x0a, Cancun-only).
    #[test]
    fn test_no_kzg_precompile() {
        let cfg = RskHardforkConfig::mainnet();
        let kzg: Address = revm::precompile::u64_to_address(10);
        assert!(!rsk_precompiles(&cfg, 8_804_200).contains(&kzg));
    }

    /// Ported from rskj Blake2fNullDataTest (post-RSKIP552 semantics): calling
    /// Blake2F with empty input fails with an input-length error instead of
    /// crashing — revm's blake2 run() returns an error for non-213-byte input,
    /// matching rskj's VMException path.
    #[test]
    fn test_blake2f_empty_input_errors() {
        let out = revm::precompile::blake2::run(&[], 100_000);
        assert!(out.is_err(), "empty input must be rejected (213 bytes required)");
    }

    #[test]
    fn test_secp256k1_active_after_reed() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 8_052_199);
        assert!(!pre.contains(&SECP256K1_ADD_ADDR));
        assert!(!pre.contains(&SECP256K1_MUL_ADDR));

        let post = rsk_precompiles(&cfg, 8_052_200);
        assert!(post.contains(&SECP256K1_ADD_ADDR));
        assert!(post.contains(&SECP256K1_MUL_ADDR));
    }

    #[test]
    fn test_all_active_has_everything() {
        let cfg = RskHardforkConfig::all_active(33);
        let precompiles = rsk_precompiles(&cfg, 0);

        assert!(precompiles.contains(&REMASC_ADDR));
        assert!(precompiles.contains(&BRIDGE_ADDR));
        assert!(precompiles.contains(&HD_WALLET_UTILS_ADDR));
        assert!(precompiles.contains(&BLOCK_HEADER_ADDR));
        assert!(precompiles.contains(&ENVIRONMENT_ADDR));
        assert!(precompiles.contains(&SECP256K1_ADD_ADDR));
        assert!(precompiles.contains(&SECP256K1_MUL_ADDR));
    }

    #[test]
    fn test_remasc_zero_gas() {
        let result = remasc_run(&[], 0).unwrap();
        assert_eq!(result.gas_used, 0);
        assert!(result.bytes.is_empty());
    }

    #[test]
    fn test_bridge_charges_gas() {
        let result = bridge_run(&[], 100_000).unwrap();
        assert_eq!(result.gas_used, 10_000);

        let oog = bridge_run(&[], 5_000);
        assert!(matches!(oog, Err(PrecompileError::OutOfGas)));
    }

    #[test]
    fn test_secp256k1_gas_costs() {
        let add = secp256k1_add_run(&[], 1_000).unwrap();
        assert_eq!(add.gas_used, 150);

        let mul = secp256k1_mul_run(&[], 10_000).unwrap();
        assert_eq!(mul.gas_used, 3_000);
    }

    // -----------------------------------------------------------------------
    // Secp256k1 add/mul tests ported from rskj Secp256k1ServiceTest.java
    // -----------------------------------------------------------------------

    const V1Y: &str =
        "29896722852569046015560700294576055776214335159245303116488692907525646231534";
    const V1BY2X: &str =
        "90462569716653277674664832038037428010367175520031690655826237506178777087235";
    const V1BY2Y: &str =
        "30122570767565969031174451675354718271714177419582540229636601003470726681395";
    const V1BY9X: &str =
        "46171929588085016379679198610744759757996296651373714437564035753833216770329";
    const V1BY9Y: &str =
        "4076329532618667641907419885981677362511359868272295070859229146922980867493";
    const SECP256K1_P: &str =
        "115792089237316195423570985008687907853269984665640564039457584007908834671663";

    fn decimal_to_32bytes(s: &str) -> [u8; 32] {
        alloy_primitives::U256::from_str_radix(s, 10)
            .expect("valid decimal")
            .to_be_bytes::<32>()
    }

    fn build_add_input(x1: &str, y1: &str, x2: &str, y2: &str) -> Vec<u8> {
        let mut input = vec![0u8; 128];
        input[..32].copy_from_slice(&decimal_to_32bytes(x1));
        input[32..64].copy_from_slice(&decimal_to_32bytes(y1));
        input[64..96].copy_from_slice(&decimal_to_32bytes(x2));
        input[96..128].copy_from_slice(&decimal_to_32bytes(y2));
        input
    }

    fn build_mul_input(x: &str, y: &str, scalar: &str) -> Vec<u8> {
        let mut input = vec![0u8; 96];
        input[..32].copy_from_slice(&decimal_to_32bytes(x));
        input[32..64].copy_from_slice(&decimal_to_32bytes(y));
        input[64..96].copy_from_slice(&decimal_to_32bytes(scalar));
        input
    }

    fn build_output(x: &str, y: &str) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[..32].copy_from_slice(&decimal_to_32bytes(x));
        out[32..64].copy_from_slice(&decimal_to_32bytes(y));
        out
    }

    fn negate_field(y: &str) -> String {
        let p = alloy_primitives::U256::from_str_radix(SECP256K1_P, 10).unwrap();
        let val = alloy_primitives::U256::from_str_radix(y, 10).unwrap();
        (p - val).to_string()
    }

    // --- Addition tests ---

    #[test]
    fn test_secp_add_two_identical_points() {
        let input = build_add_input("1", V1Y, "1", V1Y);
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output(V1BY2X, V1BY2Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_zero_points_is_zero() {
        let input = vec![0u8; 128];
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_add_empty_input_is_zero() {
        let result = secp256k1_add_run(&[], 1_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_add_point_plus_infinity_is_point() {
        let input = build_add_input("1", V1Y, "0", "0");
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output("1", V1Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_infinity_plus_point_is_point() {
        let input = build_add_input("0", "0", "1", V1Y);
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output("1", V1Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_point_not_on_curve_fails() {
        let bad = decimal_to_32bytes(
            "7711111111111111111111111111111111111111111111111111111111111111",
        );
        let mut input = vec![0u8; 128];
        input[..32].copy_from_slice(&bad);
        input[32..64].copy_from_slice(&bad);
        input[64..96].copy_from_slice(&bad);
        input[96..128].copy_from_slice(&bad);
        assert!(secp256k1_add_run(&input, 1_000).is_err());
    }

    #[test]
    fn test_secp_add_inverse_points_is_infinity() {
        let y_str = "21320899557911560362763253855565071047772010424612278905734793689199612115787";
        let neg_y = negate_field(y_str);
        let input = build_add_input("3", y_str, "3", &neg_y);
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_add_two_valid_points() {
        let input = build_add_input(
            "4",
            "40508090799132825824753983223610497876805216745196355809233758402754120847507",
            "1624070059937464756887933993293429854168590106605707304006200119738501412969",
            "48810817106871756219742442189260392858217846784043974224646271552914041676099",
        );
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output(
            "59470963110652214182270290319243047549711080187995156844066669631124720856270",
            "75549874947483386113764723043915448105868538368156141886808196158351727282824",
        );
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_gas_constant_regardless_of_input_length() {
        let r1 = secp256k1_add_run(&[], 1_000).unwrap();
        let r2 = secp256k1_add_run(&[0u8; 64], 1_000).unwrap();
        let r3 = secp256k1_add_run(&[0u8; 128], 1_000).unwrap();
        assert_eq!(r1.gas_used, 150);
        assert_eq!(r2.gas_used, 150);
        assert_eq!(r3.gas_used, 150);
    }

    #[test]
    fn test_secp_add_oog() {
        assert!(matches!(
            secp256k1_add_run(&[], 100),
            Err(PrecompileError::OutOfGas)
        ));
    }

    #[test]
    fn test_secp_add_zero_padded_32_bytes_is_zero() {
        let result = secp256k1_add_run(&[0u8; 32], 1_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secp_add_zero_padded_64_bytes_is_zero() {
        let result = secp256k1_add_run(&[0u8; 64], 1_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    // --- Multiplication tests ---

    #[test]
    fn test_secp_mul_scalar_and_point() {
        let input = build_mul_input(
            "1",
            V1Y,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        );
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output(
            "68306631035792818416930554521980007078198693994042647901813352646899028694565",
            "763410389832780290161227297165449309800016629866253823160953352172730927280",
        );
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_identity_when_multiplied_by_one() {
        let input = build_mul_input("1", V1Y, "1");
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output("1", V1Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_point_by_scalar_9() {
        let input = build_mul_input("1", V1Y, "9");
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output(V1BY9X, V1BY9Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_point_by_scalar_2() {
        let input = build_mul_input("1", V1Y, "2");
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output(V1BY2X, V1BY2Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    /// rskj reads each word with `ByteUtil.parseWord`, which pads a word the
    /// input ends inside with zeros on the right: the number keeps the bytes
    /// it has as its high ones. A scalar of the one byte 0x01 multiplies the
    /// point by 2^248, not by 1.
    #[test]
    fn a_word_the_input_ends_inside_is_padded_on_the_right() {
        let mut input = build_mul_input("1", V1Y, "0");
        input[64] = 0x01;
        let by_two_to_the_248 = secp256k1_mul_run(&input, 10_000).unwrap();
        let cut_after_one_byte = secp256k1_mul_run(&input[..65], 10_000).unwrap();
        assert_eq!(cut_after_one_byte.bytes, by_two_to_the_248.bytes);
        assert_ne!(
            cut_after_one_byte.bytes.as_ref(),
            build_output("1", V1Y).as_slice()
        );

        assert_eq!(parse_word(&[0xaa, 0xbb], 0)[..3], [0xaa, 0xbb, 0x00]);
        assert_eq!(parse_word(&[0xaa; 40], 64), [0; 32]);
    }

    #[test]
    fn test_secp_mul_point_not_on_curve_fails() {
        let bad = decimal_to_32bytes(
            "7711111111111111111111111111111111111111111111111111111111111111",
        );
        let mut input = vec![0u8; 96];
        input[..32].copy_from_slice(&bad);
        input[32..64].copy_from_slice(&bad);
        input[64..96].copy_from_slice(&bad);
        assert!(secp256k1_mul_run(&input, 10_000).is_err());
    }

    #[test]
    fn test_secp_mul_empty_input_is_zero() {
        let result = secp256k1_mul_run(&[], 10_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_mul_gas_constant_regardless_of_input_length() {
        let r1 = secp256k1_mul_run(&[], 10_000).unwrap();
        let r2 = secp256k1_mul_run(&[0u8; 64], 10_000).unwrap();
        let r3 = secp256k1_mul_run(&[0u8; 96], 10_000).unwrap();
        assert_eq!(r1.gas_used, 3_000);
        assert_eq!(r2.gas_used, 3_000);
        assert_eq!(r3.gas_used, 3_000);
    }

    #[test]
    fn test_secp_mul_oog() {
        assert!(matches!(
            secp256k1_mul_run(&[], 2_000),
            Err(PrecompileError::OutOfGas)
        ));
    }

    #[test]
    fn test_secp_mul_zero_padded_32_bytes_is_zero() {
        let result = secp256k1_mul_run(&[0u8; 32], 10_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secp_mul_zero_padded_64_bytes_is_zero() {
        let result = secp256k1_mul_run(&[0u8; 64], 10_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_precompile_count_at_genesis() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 0);

        // Standard Ethereum (Byzantium): 0x01-0x08 = 8
        // RSK genesis: Bridge, REMASC = 2
        // Total = 10
        // Note: exact count depends on revm's Byzantium set
        assert!(precompiles.len() >= 6, "should have at least 6 precompiles at genesis");
    }

    #[test]
    fn test_is_rsk_precompile() {
        let cfg = RskHardforkConfig::all_active(33);
        assert!(is_rsk_precompile(&REMASC_ADDR, &cfg, 0));
        assert!(is_rsk_precompile(&BRIDGE_ADDR, &cfg, 0));
        assert!(!is_rsk_precompile(&Address::repeat_byte(0xFF), &cfg, 0));
    }

    // -----------------------------------------------------------------------
    // Stateful dispatch infrastructure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stateful_precompiles_list() {
        assert_eq!(STATEFUL_PRECOMPILES, [REMASC_ADDR, BRIDGE_ADDR]);
        assert_eq!(
            NATIVE_CONTRACTS,
            [HD_WALLET_UTILS_ADDR, BLOCK_HEADER_ADDR, ENVIRONMENT_ADDR]
        );
    }

    #[test]
    fn test_stateful_addresses_still_in_precompile_set() {
        let cfg = RskHardforkConfig::all_active(33);
        let precompiles = rsk_precompiles(&cfg, 0);

        assert!(precompiles.contains(&ENVIRONMENT_ADDR));
        assert!(precompiles.contains(&BLOCK_HEADER_ADDR));
        assert!(precompiles.contains(&REMASC_ADDR));
    }

    #[test]
    fn test_provider_contains_stateful_addresses() {
        let cfg = RskHardforkConfig::all_active(33);
        let precompiles = rsk_precompiles(&cfg, 0);
        let provider = RskPrecompileProvider::new(
            precompiles,
            &cfg,
            None,
            B256::ZERO,
            RemascConfig::regtest(),
        );

        assert!(provider.precompiles.contains(&ENVIRONMENT_ADDR));
        assert!(provider.precompiles.contains(&BLOCK_HEADER_ADDR));
        assert!(provider.precompiles.contains(&REMASC_ADDR));
        assert!(provider.precompiles.contains(&BRIDGE_ADDR));
        assert!(provider.precompiles.contains(&SECP256K1_ADD_ADDR));
    }
}
