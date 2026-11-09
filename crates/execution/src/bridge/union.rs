//! RSKIP-502: the union bridge.
//!
//! A second bridge, to a chain other than Bitcoin, that draws RBTC from the
//! powpeg up to a locking cap and returns it. The Bridge holds the accounting;
//! the union bridge contract itself lives outside and is identified by an
//! address this module stores.
//!
//! Seven methods, all gated on RSKIP502 (testnet reed810, #7,139,600). They
//! were the whole of testnet's remaining divergence after the header work:
//! a method rustock does not know fails exactly like a malformed call, so a
//! single missing selector shows up as a failed transaction or a doubled gas
//! bill rather than as anything naming the Bridge.
//!
//! RSKIP529 adds six more on the same schedule: a "super event" and a
//! "base event", each a string of at most 128 bytes that only the union
//! bridge contract may set or clear and anyone may read.
//!
//! Storage keys are `DataWord.fromLongString` -- keccak of the name -- not the
//! right-aligned ASCII form the older Bridge cells use
//! (`UnionBridgeStorageIndexKey`).

use alloy_primitives::{Address, Bytes, U256};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::storage::{bridge_load_bytes, bridge_storage_key_long, bridge_store_bytes};
use crate::hardfork::{RskHardforkConfig, RSK_MAINNET_CHAIN_ID, RSK_TESTNET_CHAIN_ID};

/// rskj `UnionResponseCode`. Returned as an int256 by every mutating method.
///
/// `REQUEST_DISABLED` and `RELEASE_DISABLED` share the value -3 in rskj; they
/// are distinct names for one code, so only the code is modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnionResponse {
    Success = 0,
    UnauthorizedCaller = -1,
    InvalidValue = -2,
    TransferDisabled = -3,
    GenericError = -10,
}

impl UnionResponse {
    fn code(self) -> i64 {
        self as i64
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

pub const UNION_CONTRACT_ADDRESS_KEY: &str = "unionBridgeContractAddress";
pub const UNION_LOCKING_CAP_KEY: &str = "unionBridgeLockingCap";
pub const WEIS_TRANSFERRED_KEY: &str = "weisTransferredToUnionBridge";
pub const UNION_REQUEST_ENABLED_KEY: &str = "unionBridgeRequestEnabled";
pub const UNION_RELEASE_ENABLED_KEY: &str = "unionBridgeReleaseEnabled";
/// RSKIP529. The event's bytes as they came, with no RLP around them.
pub const SUPER_EVENT_KEY: &str = "superEvent";
/// RSKIP529. Read into a mined header's `baseEvent` field under RSKIP535.
pub const BASE_EVENT_KEY: &str = "baseEvent";

/// rskj `UnionBridgeSupportImpl.MAX_EVENT_DATA_LENGTH`.
pub const MAX_EVENT_DATA_LENGTH: usize = 128;

/// rskj `UnionBridgeConstants`, per network.
///
/// Mainnet's address and all three authorizers are the zero address: the
/// union bridge is configured on testnet and not yet on mainnet, so every
/// authorized method there rejects.
pub struct UnionConstants {
    pub address: Address,
    pub initial_locking_cap: U256,
    pub locking_cap_increments_multiplier: u64,
    pub change_address_authorizer: Address,
    pub change_locking_cap_authorizer: Address,
    pub change_transfer_permissions_authorizer: Address,
}

fn one_rbtc() -> U256 {
    U256::from(10u64).pow(U256::from(18))
}

pub fn union_constants(hardfork_cfg: &RskHardforkConfig) -> UnionConstants {
    match hardfork_cfg.chain_id {
        RSK_TESTNET_CHAIN_ID => UnionConstants {
            address: Address::ZERO,
            initial_locking_cap: one_rbtc(),
            locking_cap_increments_multiplier: 2,
            change_address_authorizer: addr("54fdb399cf235c9b0d464ab4055af9251883bbfe"),
            change_locking_cap_authorizer: addr("1a8109af0f019ed3045fbcdf45e5e90d6b6aafaf"),
            change_transfer_permissions_authorizer: addr("8db1f83e8119e4dce5bc708ec2f4390ffd910b19"),
        },
        // Mainnet and regtest alike: zero address throughout, so nothing is
        // authorized and the contract address falls back to zero.
        _ => UnionConstants {
            address: Address::ZERO,
            initial_locking_cap: one_rbtc(),
            locking_cap_increments_multiplier: 2,
            change_address_authorizer: Address::ZERO,
            change_locking_cap_authorizer: Address::ZERO,
            change_transfer_permissions_authorizer: Address::ZERO,
        },
    }
}

/// Union bridge cells are keyed by `DataWord.fromLongString` -- keccak of the
/// name -- unlike the older Bridge cells, which right-align the ASCII.
fn load_long<CTX: crate::RskContextTr>(ctx: &mut CTX, name: &str) -> Vec<u8> {
    bridge_load_bytes(ctx, bridge_storage_key_long(name))
}

fn store_long<CTX: crate::RskContextTr>(ctx: &mut CTX, name: &str, value: &[u8]) {
    bridge_store_bytes(ctx, bridge_storage_key_long(name), value);
}

fn addr(hex: &str) -> Address {
    Address::from_slice(&alloy_primitives::hex::decode(hex).expect("constant address"))
}

/// rskj `getUnionBridgeContractAddress`: mainnet always answers from the
/// constants; every other network lets the stored value override them.
pub fn contract_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    hardfork_cfg: &RskHardforkConfig,
) -> Address {
    let constants = union_constants(hardfork_cfg);
    if hardfork_cfg.chain_id == RSK_MAINNET_CHAIN_ID {
        return constants.address;
    }
    // rskj `serializeRskAddress` is `RLP.encodeElement(bytes)`, so the cell
    // holds 0x94 followed by the twenty address bytes, not the bare address.
    match rlp_element(&load_long(ctx, UNION_CONTRACT_ADDRESS_KEY)) {
        Some(b) if b.len() == 20 => Address::from_slice(&b),
        _ => constants.address,
    }
}

pub fn locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    hardfork_cfg: &RskHardforkConfig,
) -> U256 {
    match rlp_element(&load_long(ctx, UNION_LOCKING_CAP_KEY)) {
        Some(b) => U256::from_be_slice(&b),
        None => union_constants(hardfork_cfg).initial_locking_cap,
    }
}

fn weis_transferred<CTX: crate::RskContextTr>(ctx: &mut CTX) -> U256 {
    rlp_element(&load_long(ctx, WEIS_TRANSFERRED_KEY))
        .map(|b| U256::from_be_slice(&b))
        .unwrap_or(U256::ZERO)
}

/// rskj `serializeRskCoin` is `RLP.encodeBigInteger`, so these cells are RLP
/// too -- an empty string for zero, otherwise the trimmed magnitude.
fn store_coin<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str, v: U256) {
    store_long(ctx, key, &rlp_encode_bytes(&trim_leading_zeros(&v.to_be_bytes::<32>())));
}

fn trim_leading_zeros(b: &[u8]) -> Vec<u8> {
    match b.iter().position(|&x| x != 0) {
        Some(i) => b[i..].to_vec(),
        None => Vec::new(),
    }
}

/// The payload of a single RLP string, which is what every union bridge cell
/// holds. Returns `None` for an absent cell so a default can be applied.
fn rlp_element(raw: &[u8]) -> Option<Vec<u8>> {
    match raw.first()? {
        // A single byte below 0x80 is its own encoding.
        b if *b < 0x80 => Some(vec![*b]),
        0x80 => Some(Vec::new()),
        b if *b < 0xb8 => {
            let len = (*b - 0x80) as usize;
            raw.get(1..1 + len).map(|s| s.to_vec())
        }
        // Longer forms do not occur here: an address is 20 bytes and a coin
        // at most 32.
        _ => None,
    }
}

fn rlp_encode_bytes(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return vec![0x80];
    }
    if payload.len() == 1 && payload[0] < 0x80 {
        return payload.to_vec();
    }
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(0x80 + payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

/// rskj `serializeBoolean`/`deserializeBoolean`, with the default applied when
/// the cell is absent -- both permissions start enabled.
fn flag<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str) -> bool {
    // rskj `serializeBoolean` is `RLP.encodeInt(0|1)`; an absent cell means
    // the permission has never been set, and both default to enabled.
    match rlp_element(&load_long(ctx, key)) {
        Some(b) => b.iter().any(|x| *x != 0),
        None => true,
    }
}

fn store_flag<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str, value: bool) {
    // RLP.encodeInt(0) is the empty string 0x80, not 0x00.
    store_long(ctx, key, &rlp_encode_bytes(if value { &[1u8][..] } else { &[][..] }));
}

/// Whether the union bridge may draw from the powpeg.
pub fn request_enabled<CTX: crate::RskContextTr>(ctx: &mut CTX) -> bool {
    flag(ctx, UNION_REQUEST_ENABLED_KEY)
}

/// Whether the union bridge may return RBTC to the powpeg.
pub fn release_enabled<CTX: crate::RskContextTr>(ctx: &mut CTX) -> bool {
    flag(ctx, UNION_RELEASE_ENABLED_KEY)
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

fn int_result(gas: u64, code: i64) -> Result<PrecompileOutput, PrecompileError> {
    Ok(super::governance::encode_int_result(gas, code))
}

/// `setUnionBridgeContractAddressForTestnet(address)` -> int256.
///
/// rskj wraps this in `executeIfTestnetAndAuthorized`, so it is both
/// network-gated and authorizer-gated.
pub fn set_contract_address_for_testnet<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<PrecompileOutput, PrecompileError> {
    if hardfork_cfg.chain_id == RSK_MAINNET_CHAIN_ID {
        return int_result(gas_cost, UnionResponse::GenericError.code());
    }
    let constants = union_constants(hardfork_cfg);
    if sender != constants.change_address_authorizer {
        return int_result(gas_cost, UnionResponse::UnauthorizedCaller.code());
    }
    // rskj `new RskAddress((DataWord) args[0])`: the address as its decoder
    // reads it, an empty argument list being the zero address.
    let Some(new_address) = crate::abi::Args::new(args).address(0) else {
        return int_result(gas_cost, UnionResponse::GenericError.code());
    };
    store_long(ctx, UNION_CONTRACT_ADDRESS_KEY, &rlp_encode_bytes(new_address.as_slice()));
    int_result(gas_cost, UnionResponse::Success.code())
}

/// `getUnionBridgeContractAddress()` -> address.
pub fn get_contract_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let address = contract_address(ctx, hardfork_cfg);
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(address.as_slice());
    Ok(PrecompileOutput::new(gas_cost, out.into()))
}

/// `getUnionBridgeLockingCap()` -> uint256.
pub fn get_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let cap = locking_cap(ctx, hardfork_cfg);
    Ok(PrecompileOutput::new(gas_cost, cap.to_be_bytes::<32>().to_vec().into()))
}

/// `increaseUnionBridgeLockingCap(uint256)` -> int256.
///
/// Only upward, and by at most the multiplier: a new cap that does not exceed
/// the current one, or exceeds `current * multiplier`, is rejected.
pub fn increase_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<PrecompileOutput, PrecompileError> {
    let constants = union_constants(hardfork_cfg);
    if sender != constants.change_locking_cap_authorizer {
        return int_result(gas_cost, UnionResponse::UnauthorizedCaller.code());
    }
    let Some(new_cap) = crate::abi::Args::new(args).int(0) else {
        return int_result(gas_cost, UnionResponse::GenericError.code());
    };
    let current = locking_cap(ctx, hardfork_cfg);
    let max_allowed = current * U256::from(constants.locking_cap_increments_multiplier);
    // A negative cap never increases the current one.
    let Some(new_cap) = coin(&new_cap) else {
        return int_result(gas_cost, UnionResponse::InvalidValue.code());
    };
    if new_cap <= current || new_cap > max_allowed {
        return int_result(gas_cost, UnionResponse::InvalidValue.code());
    }
    store_coin(ctx, UNION_LOCKING_CAP_KEY, new_cap);
    super::events::log_union_locking_cap_increased(ctx, sender, current, new_cap);
    int_result(gas_cost, UnionResponse::Success.code())
}

/// `requestUnionBridgeRbtc(uint256)` -> int256.
///
/// Draws RBTC from the Bridge to the union bridge contract, bounded by the
/// locking cap against everything drawn so far.
#[allow(clippy::too_many_arguments)]
pub fn request_rbtc<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<PrecompileOutput, PrecompileError> {
    let union_address = contract_address(ctx, hardfork_cfg);
    if sender != union_address {
        return int_result(gas_cost, UnionResponse::UnauthorizedCaller.code());
    }
    if !request_enabled(ctx) {
        return int_result(gas_cost, UnionResponse::TransferDisabled.code());
    }
    let Some(amount) = crate::abi::Args::new(args).int(0) else {
        return int_result(gas_cost, UnionResponse::GenericError.code());
    };
    // rskj `isAmountRequestedValid` refuses an amount that is not positive,
    // and the amount is signed: a negative one would otherwise wrap the total
    // below the cap.
    let Some(amount) = coin(&amount).filter(|amount| !amount.is_zero()) else {
        return int_result(gas_cost, UnionResponse::InvalidValue.code());
    };
    let previous = weis_transferred(ctx);
    let new_total = previous + amount;
    if new_total > locking_cap(ctx, hardfork_cfg) {
        return int_result(gas_cost, UnionResponse::InvalidValue.code());
    }
    store_coin(ctx, WEIS_TRANSFERRED_KEY, new_total);

    // rskj `BridgeSupport.requestUnionBridgeRbtc` transfers only on success,
    // and to the union bridge *contract address* rather than to the caller --
    // the same address, since an unauthorized caller never reaches here.
    transfer_from_bridge(ctx, union_address, amount)?;
    super::events::log_union_rbtc_requested(ctx, union_address, amount);
    int_result(gas_cost, UnionResponse::Success.code())
}

/// `releaseUnionBridgeRbtc()` -> int256, payable.
///
/// The value sent with the call is what is being returned. Anything that
/// stops the release has to hand that value back, since the CALL already
/// moved it to the Bridge.
pub fn release_rbtc<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
    call_value: U256,
) -> Result<PrecompileOutput, PrecompileError> {
    let union_address = contract_address(ctx, hardfork_cfg);
    let outcome = release_outcome(ctx, hardfork_cfg, sender, call_value, union_address);

    if outcome != UnionResponse::Success && !call_value.is_zero() {
        transfer_from_bridge(ctx, sender, call_value)?;
    }
    int_result(gas_cost, outcome.code())
}

fn release_outcome<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    _hardfork_cfg: &RskHardforkConfig,
    sender: Address,
    call_value: U256,
    union_address: Address,
) -> UnionResponse {
    if sender != union_address {
        return UnionResponse::UnauthorizedCaller;
    }
    if !release_enabled(ctx) {
        return UnionResponse::TransferDisabled;
    }
    if call_value.is_zero() {
        return UnionResponse::InvalidValue;
    }
    let transferred = weis_transferred(ctx);
    if transferred < call_value {
        // Returning more than was ever drawn means the accounting is wrong,
        // and rskj reacts by shutting both directions off rather than by
        // rejecting the one call.
        store_flag(ctx, UNION_REQUEST_ENABLED_KEY, false);
        store_flag(ctx, UNION_RELEASE_ENABLED_KEY, false);
        super::events::log_union_transfer_permissions_updated(
            ctx,
            crate::precompiles::BRIDGE_ADDR,
            false,
            false,
        );
        return UnionResponse::InvalidValue;
    }
    store_coin(ctx, WEIS_TRANSFERRED_KEY, transferred - call_value);
    super::events::log_union_rbtc_released(ctx, sender, call_value);
    UnionResponse::Success
}

/// `setUnionBridgeTransferPermissions(bool,bool)` -> int256.
pub fn set_transfer_permissions<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<PrecompileOutput, PrecompileError> {
    let constants = union_constants(hardfork_cfg);
    if sender != constants.change_transfer_permissions_authorizer {
        return int_result(gas_cost, UnionResponse::UnauthorizedCaller.code());
    }
    // rskj's `BoolType` looks at its word's low 32 bits only, and an empty
    // argument list reads as two falses.
    let args = crate::abi::Args::new(args);
    let (Some(request), Some(release)) = (args.bool(0), args.bool(1)) else {
        return int_result(gas_cost, UnionResponse::GenericError.code());
    };

    // Already in the requested state: rskj returns success without writing or
    // logging, so a repeat call leaves no trace in the state or the receipt.
    if request_enabled(ctx) == request && release_enabled(ctx) == release {
        return int_result(gas_cost, UnionResponse::Success.code());
    }
    store_flag(ctx, UNION_REQUEST_ENABLED_KEY, request);
    store_flag(ctx, UNION_RELEASE_ENABLED_KEY, release);
    super::events::log_union_transfer_permissions_updated(ctx, sender, request, release);
    int_result(gas_cost, UnionResponse::Success.code())
}

/// `getSuperEvent()` / `getBaseEvent()` -> bytes: the event `key` holds,
/// empty when there is none.
///
/// rskj `UnionBridgeStorageProviderImpl.getSuperEvent` takes the cell's bytes
/// as they are (`data -> data`), with no RLP to strip, and an absent cell
/// reads as the empty array.
pub fn get_event<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    key: &str,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let event = load_long(ctx, key);
    let encoded = super::getters::abi_encode_bytes(&event);
    Ok(PrecompileOutput::new(gas_cost, encoded.into()))
}

/// `setSuperEvent(bytes)` / `setBaseEvent(bytes)`, void.
///
/// rskj `UnionBridgeSupportImpl.setSuperEvent`: the caller must be the union
/// bridge contract and the event at most 128 bytes. Unlike the RSKIP502
/// methods, which answer a refusal with a response code, both checks throw
/// `IllegalArgumentException`, so the call fails as any Bridge method that
/// throws: its cost is spent and nothing is written.
pub fn set_event<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    key: &str,
    args: &[u8],
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<PrecompileOutput, PrecompileError> {
    let event = crate::abi::Args::new(args)
        .bytes(0)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            PrecompileError::other("union bridge event: the bytes argument does not decode")
        })?;
    require_union_bridge_caller(ctx, hardfork_cfg, sender)?;
    if event.len() > MAX_EVENT_DATA_LENGTH {
        return Err(PrecompileError::other(format!(
            "union bridge event: {} bytes is above the maximum of {MAX_EVENT_DATA_LENGTH}",
            event.len()
        )));
    }
    // An empty event deletes the cell, as rskj's addStorageBytes does.
    store_long(ctx, key, &event);
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// `clearSuperEvent()` / `clearBaseEvent()`, void: the union bridge contract
/// sets the event to the empty array, which deletes the cell.
pub fn clear_event<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    key: &str,
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<PrecompileOutput, PrecompileError> {
    require_union_bridge_caller(ctx, hardfork_cfg, sender)?;
    store_long(ctx, key, &[]);
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// rskj `UnionBridgeSupportImpl.validateCallerIsUnionBridge`, which throws.
fn require_union_bridge_caller<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    hardfork_cfg: &RskHardforkConfig,
    sender: Address,
) -> Result<(), PrecompileError> {
    if sender != contract_address(ctx, hardfork_cfg) {
        return Err(PrecompileError::other(
            "union bridge event: the caller is not the union bridge contract",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// rskj `new co.rsk.core.Coin((BigInteger) arg)`: the word as a signed
/// number, `None` where it is negative.
fn coin(value: &crate::abi::Int) -> Option<U256> {
    let value = value.signed();
    (!value.is_negative()).then(|| value.into_raw())
}

/// Moves RBTC out of the Bridge's own balance.
fn transfer_from_bridge<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    to: Address,
    amount: U256,
) -> Result<(), PrecompileError> {
    use revm::context_interface::JournalTr;
    ctx.journal_mut()
        .transfer(crate::precompiles::BRIDGE_ADDR, to, amount)
        .map_err(|e| PrecompileError::other(format!("union bridge transfer: {e:?}")))?;
    Ok(())
}

/// The storage key for a union bridge cell, exposed for tests and tooling.
pub fn union_key(name: &str) -> U256 {
    bridge_storage_key_long(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> impl crate::RskContextTr {
        use revm::MainContext;
        revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default())
    }

    /// rskj serializes every union bridge cell through RLP, which is what the
    /// chain actually holds: testnet's `unionBridgeContractAddress` reads
    /// `0x94` followed by the twenty address bytes, not the bare address.
    /// Reading it raw yields nothing, the address falls back to the zero
    /// constant, and every authorized call is then rejected as unauthorized --
    /// which is exactly how testnet #7,629,709 failed.
    #[test]
    fn an_address_cell_is_rlp_encoded_the_way_the_chain_holds_it() {
        let a = addr("2c1d1ba63ca24d08a92b309db6729332c4f76834");
        let encoded = rlp_encode_bytes(a.as_slice());
        assert_eq!(encoded[0], 0x94, "0x80 + 20");
        assert_eq!(encoded.len(), 21);
        assert_eq!(rlp_element(&encoded).as_deref(), Some(a.as_slice()));
    }

    /// `RLP.encodeInt(0)` is the empty string, not a zero byte.
    #[test]
    fn a_false_flag_is_the_empty_rlp_string() {
        assert_eq!(rlp_encode_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_element(&[0x80]).as_deref(), Some(&[][..]));
        assert_eq!(rlp_encode_bytes(&[1]), vec![0x01]);
    }

    /// An absent cell is not a false permission: both default to enabled.
    #[test]
    fn transfer_permissions_default_to_enabled() {
        let mut c = ctx();
        assert!(request_enabled(&mut c));
        assert!(release_enabled(&mut c));

        store_flag(&mut c, UNION_REQUEST_ENABLED_KEY, false);
        assert!(!request_enabled(&mut c));
        assert!(release_enabled(&mut c), "the two are independent");
    }

    #[test]
    fn a_coin_cell_round_trips_through_rlp() {
        let mut c = ctx();
        assert_eq!(weis_transferred(&mut c), U256::ZERO, "absent reads as zero");
        for v in [U256::from(1u64), one_rbtc(), U256::from(255u64), U256::from(0x80u64)] {
            store_coin(&mut c, WEIS_TRANSFERRED_KEY, v);
            assert_eq!(weis_transferred(&mut c), v, "value {v}");
        }
        store_coin(&mut c, WEIS_TRANSFERRED_KEY, U256::ZERO);
        assert_eq!(weis_transferred(&mut c), U256::ZERO);
    }

    /// Mainnet reads its address from the constants and ignores the cell, so a
    /// value written on another network cannot leak into it.
    #[test]
    fn mainnet_ignores_the_stored_address() {
        let mut c = ctx();
        let cfg = RskHardforkConfig::mainnet();
        store_long(
            &mut c,
            UNION_CONTRACT_ADDRESS_KEY,
            &rlp_encode_bytes(addr("2c1d1ba63ca24d08a92b309db6729332c4f76834").as_slice()),
        );
        assert_eq!(contract_address(&mut c, &cfg), Address::ZERO);

        let tcfg = RskHardforkConfig::testnet();
        assert_ne!(contract_address(&mut c, &tcfg), Address::ZERO, "testnet honours it");
    }

    /// The cap only moves up, and by at most the multiplier.
    #[test]
    fn the_locking_cap_may_only_double_upwards() {
        let cfg = RskHardforkConfig::testnet();
        let authorizer = union_constants(&cfg).change_locking_cap_authorizer;
        let current = one_rbtc();

        let run = |new_cap: U256| {
            let mut c = ctx();
            let mut args = [0u8; 32];
            args.copy_from_slice(&new_cap.to_be_bytes::<32>());
            let out = increase_locking_cap(&mut c, &args, 0, &cfg, authorizer).unwrap();
            let code = i64::from_be_bytes(out.bytes[24..32].try_into().unwrap());
            (code, locking_cap(&mut c, &cfg))
        };

        assert_eq!(run(current).0, UnionResponse::InvalidValue.code(), "equal is not an increase");
        assert_eq!(
            run(current * U256::from(2u64) + U256::from(1u64)).0,
            UnionResponse::InvalidValue.code(),
            "above the multiplier"
        );
        let (code, cap) = run(current * U256::from(2u64));
        assert_eq!(code, UnionResponse::Success.code());
        assert_eq!(cap, current * U256::from(2u64));
    }

    /// Only the configured authorizer may move the cap.
    #[test]
    fn an_unauthorized_caller_cannot_move_the_locking_cap() {
        let cfg = RskHardforkConfig::testnet();
        let mut c = ctx();
        let args = (one_rbtc() * U256::from(2u64)).to_be_bytes::<32>();
        let out = increase_locking_cap(&mut c, &args, 0, &cfg, Address::repeat_byte(0xAA)).unwrap();
        let code = i64::from_be_bytes(out.bytes[24..32].try_into().unwrap());
        assert_eq!(code, UnionResponse::UnauthorizedCaller.code());
        assert_eq!(locking_cap(&mut c, &cfg), one_rbtc(), "unchanged");
    }

    // -- RSKIP529: the super and base events ------------------------------

    /// The union bridge contract testnet's tests call from.
    fn union_bridge() -> Address {
        addr("2c1d1ba63ca24d08a92b309db6729332c4f76834")
    }

    /// A testnet context whose union bridge contract is `union_bridge()`.
    fn testnet_ctx() -> impl crate::RskContextTr {
        let mut c = ctx();
        let address = rlp_encode_bytes(union_bridge().as_slice());
        store_long(&mut c, UNION_CONTRACT_ADDRESS_KEY, &address);
        c
    }

    /// `bytes` as a lone ABI argument: offset, length, data padded to a word.
    fn bytes_arg(data: &[u8]) -> Vec<u8> {
        let mut a = U256::from(32u64).to_be_bytes::<32>().to_vec();
        a.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
        a.extend_from_slice(data);
        a.resize(64 + data.len().div_ceil(32) * 32, 0);
        a
    }

    /// `setSuperEvent` / `setBaseEvent` on testnet, called by `from`.
    fn set_as(
        c: &mut impl crate::RskContextTr,
        key: &str,
        event: &[u8],
        from: Address,
    ) -> Result<PrecompileOutput, PrecompileError> {
        let cfg = RskHardforkConfig::testnet();
        set_event(c, key, &bytes_arg(event), 8_000, &cfg, from)
    }

    /// `clearSuperEvent` / `clearBaseEvent` on testnet, called by `from`.
    fn clear_as(
        c: &mut impl crate::RskContextTr,
        key: &str,
        from: Address,
    ) -> Result<PrecompileOutput, PrecompileError> {
        clear_event(c, key, 8_000, &RskHardforkConfig::testnet(), from)
    }

    /// rskj stores the event as it came, with no RLP around it, and answers
    /// it ABI-encoded as `bytes`.
    #[test]
    fn an_event_is_stored_as_it_came_and_read_back_as_bytes() {
        let mut c = testnet_ctx();
        let event = b"a super event".to_vec();
        set_as(&mut c, SUPER_EVENT_KEY, &event, union_bridge()).unwrap();
        assert_eq!(load_long(&mut c, SUPER_EVENT_KEY), event, "no RLP");

        let out = get_event(&mut c, SUPER_EVENT_KEY, 3_000).unwrap();
        assert_eq!(out.bytes.as_ref(), bytes_arg(&event).as_slice());
        assert_eq!(out.gas_used, 3_000);
    }

    /// An absent event reads as the empty array, which rskj's `BytesType`
    /// encodes as 96 bytes: offset 32, length 0, and one zero word of data.
    #[test]
    fn an_absent_event_reads_as_empty_bytes() {
        let mut c = testnet_ctx();
        let out = get_event(&mut c, BASE_EVENT_KEY, 3_000).unwrap();
        let mut empty = U256::from(32u64).to_be_bytes::<32>().to_vec();
        empty.resize(96, 0);
        assert_eq!(out.bytes.as_ref(), empty.as_slice());
    }

    /// rskj `setSuperEvent_afterChangingUnionBridgeAddress_newAddressShouldSet_
    /// oldAddressShouldNot` and its `clear` twin: only the contract the Bridge
    /// currently names may write, and a refusal is a throw, not a code.
    #[test]
    fn only_the_union_bridge_contract_may_set_or_clear_an_event() {
        let mut c = testnet_ctx();
        let first = b"first".to_vec();
        set_as(&mut c, BASE_EVENT_KEY, &first, union_bridge()).unwrap();

        let stranger = Address::repeat_byte(0xAA);
        assert!(set_as(&mut c, BASE_EVENT_KEY, b"x", stranger).is_err());
        assert!(clear_as(&mut c, BASE_EVENT_KEY, stranger).is_err());
        assert_eq!(load_long(&mut c, BASE_EVENT_KEY), first, "untouched");

        // The address moves: the old contract is refused, the new one is not.
        let moved = Address::repeat_byte(0x11);
        let address = rlp_encode_bytes(moved.as_slice());
        store_long(&mut c, UNION_CONTRACT_ADDRESS_KEY, &address);
        assert!(clear_as(&mut c, BASE_EVENT_KEY, union_bridge()).is_err());
        clear_as(&mut c, BASE_EVENT_KEY, moved).unwrap();
        assert_eq!(load_long(&mut c, BASE_EVENT_KEY), Vec::<u8>::new());
    }

    /// `MAX_EVENT_DATA_LENGTH`: 128 bytes is an event, 129 is a throw.
    #[test]
    fn an_event_may_be_128_bytes_and_no_more() {
        let mut c = testnet_ctx();
        let longest = vec![0x5A; MAX_EVENT_DATA_LENGTH];
        set_as(&mut c, SUPER_EVENT_KEY, &longest, union_bridge()).unwrap();
        assert_eq!(load_long(&mut c, SUPER_EVENT_KEY), longest);

        let too_long = vec![0x5A; MAX_EVENT_DATA_LENGTH + 1];
        let refused = set_as(&mut c, SUPER_EVENT_KEY, &too_long, union_bridge());
        assert!(refused.is_err());
        assert_eq!(load_long(&mut c, SUPER_EVENT_KEY), longest, "unchanged");
    }

    /// Clearing, or setting the empty array, deletes the cell (rskj's
    /// `addStorageBytes` stores an empty value as no value), and the two
    /// events are separate cells.
    #[test]
    fn clearing_an_event_deletes_only_its_own_cell() {
        let mut c = testnet_ctx();
        let base = b"base".to_vec();
        set_as(&mut c, SUPER_EVENT_KEY, b"super", union_bridge()).unwrap();
        set_as(&mut c, BASE_EVENT_KEY, &base, union_bridge()).unwrap();

        clear_as(&mut c, SUPER_EVENT_KEY, union_bridge()).unwrap();
        let cell = super::super::storage::bridge_load_raw(&mut c, union_key(SUPER_EVENT_KEY));
        assert_eq!(cell, None, "no value at all, not an empty one");
        assert_eq!(load_long(&mut c, BASE_EVENT_KEY), base, "its own cell");

        set_as(&mut c, BASE_EVENT_KEY, &[], union_bridge()).unwrap();
        assert_eq!(load_long(&mut c, BASE_EVENT_KEY), Vec::<u8>::new());
    }

    /// rskj reads the offset and length words as Java ints, so a word whose
    /// high bytes are set still says 32. Converting the whole word to a
    /// `usize` panics on it instead.
    #[test]
    fn the_bytes_argument_is_read_as_rskj_reads_it() {
        let event = b"event".to_vec();
        let mut args = bytes_arg(&event);
        args[..28].fill(0xFF);
        args[32..60].fill(0x01);
        let cfg = RskHardforkConfig::testnet();
        let mut c = testnet_ctx();
        set_event(&mut c, SUPER_EVENT_KEY, &args, 8_000, &cfg, union_bridge()).unwrap();
        assert_eq!(load_long(&mut c, SUPER_EVENT_KEY), event);
        assert!(set_event(&mut c, SUPER_EVENT_KEY, &[], 8_000, &cfg, union_bridge()).is_err());
        assert!(
            set_event(
                &mut c,
                SUPER_EVENT_KEY,
                &args[..40],
                8_000,
                &cfg,
                union_bridge()
            )
            .is_err(),
            "the length word is cut short"
        );
    }

    fn code(out: PrecompileOutput) -> i64 {
        i64::from_be_bytes(out.bytes[24..32].try_into().unwrap())
    }

    /// rskj's amounts are signed: a word with its top bit set is a negative
    /// cap or request, refused as INVALID_VALUE, where read unsigned it was a
    /// huge one that wrapped the running total back under the cap.
    #[test]
    fn a_negative_cap_or_amount_is_an_invalid_value() {
        let cfg = RskHardforkConfig::testnet();
        let minus_one = [0xFF; 32];
        let authorizer = union_constants(&cfg).change_locking_cap_authorizer;
        let mut c = ctx();
        let out = increase_locking_cap(&mut c, &minus_one, 0, &cfg, authorizer).unwrap();
        assert_eq!(code(out), UnionResponse::InvalidValue.code());

        let mut c = testnet_ctx();
        store_coin(&mut c, WEIS_TRANSFERRED_KEY, U256::from(5u64));
        let out = request_rbtc(&mut c, &minus_one, 0, &cfg, union_bridge()).unwrap();
        assert_eq!(code(out), UnionResponse::InvalidValue.code());
        assert_eq!(
            weis_transferred(&mut c),
            U256::from(5u64),
            "the total is untouched"
        );
    }

    /// An empty argument list reads as zeros: two falses for the permissions,
    /// and a zero cap, which is no increase.
    #[test]
    fn an_empty_argument_list_reads_as_zeros() {
        let cfg = RskHardforkConfig::testnet();
        let constants = union_constants(&cfg);
        let mut c = ctx();
        let out = set_transfer_permissions(
            &mut c,
            &[],
            0,
            &cfg,
            constants.change_transfer_permissions_authorizer,
        )
        .unwrap();
        assert_eq!(code(out), UnionResponse::Success.code());
        assert!(!request_enabled(&mut c) && !release_enabled(&mut c));

        let out = increase_locking_cap(
            &mut c,
            &[],
            0,
            &cfg,
            constants.change_locking_cap_authorizer,
        )
        .unwrap();
        assert_eq!(code(out), UnionResponse::InvalidValue.code());
    }

    /// rskj's `BoolType` is `intValue() != 0`: a word whose only set bits are
    /// above its low 32 is false.
    #[test]
    fn a_flag_looks_only_at_its_low_32_bits() {
        let cfg = RskHardforkConfig::testnet();
        let authorizer = union_constants(&cfg).change_transfer_permissions_authorizer;
        let mut args = [0u8; 64];
        args[0] = 1;
        args[63] = 1;
        let mut c = ctx();
        set_transfer_permissions(&mut c, &args, 0, &cfg, authorizer).unwrap();
        assert!(!request_enabled(&mut c), "only a high bit set");
        assert!(release_enabled(&mut c));
    }
}
