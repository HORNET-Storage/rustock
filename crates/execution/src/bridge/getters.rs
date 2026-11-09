//! Bridge local-only getter implementations.
//!
//! These methods read federation data, fee parameters, and locking cap
//! from Bridge contract storage. They are consensus-safe read-only queries.

use alloy_primitives::{Bytes, U256};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::constants::BridgeConstants;
use super::serialization;
use super::storage::*;

/// `getFederationAddress()` → string (ABI-encoded), the Base58Check P2SH
/// address of the **active** federation (rskj `Bridge.getFederationAddress`,
/// `Federation.getAddress().toBase58()`).
///
/// This is deliberately built from the same two functions the peg-out path
/// uses to decide where change goes — `active_federation_keys_and_redeem` and
/// `active_federation_format` — so the address reported here cannot disagree
/// with the script the Bridge actually pays to. They carry the parts that are
/// easy to get wrong: the new/old selection by activation age, the stored
/// format version, the genesis-federation fallback when nothing is stored, and
/// the P2SH-P2WSH hashing for format ≥ 4000 (RSKIP305).
pub fn get_federation_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let (_keys, redeem) =
        super::peg::active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    let format = super::peg::active_federation_format(ctx, config, hardfork_cfg, block_number);
    let hash160 = super::peg::federation_output_hash160(&redeem, format);
    let address = super::governance::p2sh_base58_address(&hash160, config);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_string(&address).into()))
}

/// `getRetiringFederationAddress()` → string (ABI-encoded).
///
/// rskj returns the empty string when there is no retiring federation
/// (`Bridge.getRetiringFederationAddress` → `NON_EXISTING_RETIRING_FEDERATION`),
/// which is the common case outside a migration.
pub fn get_retiring_federation_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let Some((_keys, redeem)) =
        super::peg::retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number)
    else {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_string("").into()));
    };
    let format = super::peg::federation_format_version_pub(
        ctx,
        super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY,
    );
    let hash160 = super::peg::federation_output_hash160(&redeem, format);
    let address = super::governance::p2sh_base58_address(&hash160, config);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_string(&address).into()))
}

/// `getFederationSize()` → int256
///
/// Reads whichever federation is **active**, not `newFederation`. During a new
/// federation's activation window the old one is still the active one, and
/// with nothing stored it is the genesis federation -- reading the storage key
/// directly answered 0 there, as though the Bridge had no federation at all.
pub fn get_federation_size<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fed = super::peg::active_federation(ctx, config, hardfork_cfg, block_number);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(fed.members.len() as i64)))
}

/// `getFederationThreshold()` → int256, i.e. the multisig `M`.
pub fn get_federation_threshold<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fed = super::peg::active_federation(ctx, config, hardfork_cfg, block_number);
    let threshold = (fed.members.len() / 2) + 1;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(threshold as i64)))
}

/// `getFederationCreationBlockNumber()` → int256.
///
/// rskj answers with `Federation.getCreationBlockNumber()` -- the block stored
/// *inside* the federation -- not the `activeFedCreationBlockHeight` cell,
/// which is RSKIP186's separate record and is absent before it.
pub fn get_federation_creation_block_number<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fed = super::peg::active_federation(ctx, config, hardfork_cfg, block_number);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(fed.creation_block as i64)))
}

/// `getFederationCreationTime()` → int256.
///
/// **The unit changes at RSKIP419**: milliseconds before, seconds from there
/// on (`Bridge.getFederationCreationTimeEpochBasedOnActivation`). Storage
/// always holds milliseconds, so returning the stored number unchanged -- as
/// this did -- is off by a factor of 1000 for every call after lovell700.
pub fn get_federation_creation_time<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fed = super::peg::active_federation(ctx, config, hardfork_cfg, block_number);
    let value = creation_time_for_era(fed.creation_time_millis, hardfork_cfg, block_number);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getFederatorPublicKey(int256 index)` → bytes (the BTC key).
///
/// An index past the end **reverts**: rskj's `getActiveFederatorBtcPublicKey`
/// throws `IndexOutOfBoundsException` and the Bridge turns that into a
/// `VMException`. Returning empty bytes instead made an out-of-range index
/// look like a federator with no key.
pub fn get_federator_public_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let index = index_arg(args, "getFederatorPublicKey")?;
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fed = super::peg::active_federation(ctx, config, hardfork_cfg, block_number);
    let key = member_key_at(&fed.members, index, KeyType::Btc, "Federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

/// `getFederatorPublicKeyOfType(int256 index, string keyType)` → bytes
///
/// This used to delegate to `getFederatorPublicKey`, i.e. answer with the BTC
/// key whatever was asked. Post-RSKIP123 federations carry three distinct keys
/// per member, and the RSK key is the one that identifies a federator's RSK
/// address -- returning the BTC key for `"rsk"` gives a different address, so
/// a caller checking who signed would have compared against the wrong one.
pub fn get_federator_public_key_of_type<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let (index, key_type) = decode_index_and_key_type(args)?;
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fed = super::peg::active_federation(ctx, config, hardfork_cfg, block_number);
    let key = member_key_at(&fed.members, index, key_type, "Federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

/// `getFeePerKb()` → int256
pub fn get_fee_per_kb<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = bridge_load_u256(ctx, "feePerKb");
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(val)))
}

/// `getLockingCap()` → int256 (satoshis)
///
/// rskj BridgeSupport.getLockingCap lazily initializes the cap on first
/// read (local-only method, so the write never reaches consensus state).
pub fn get_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = super::peg::get_or_init_locking_cap(ctx, config);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(U256::from(val))))
}

/// `getMinimumLockTxValue()` → int256
pub fn get_minimum_lock_tx_value(
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    let satoshi_value = config.minimum_pegin_tx_value;
    let wei = U256::from(satoshi_value) * U256::from(10_000_000_000u64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(wei)))
}

/// `getRetiringFederationSize()` → int256, `-1` when there is none.
///
/// "There is a retiring federation" is not "oldFederation is stored": rskj
/// also requires the new federation to have reached its activation age. During
/// the window the old federation sits in storage and is still the *active*
/// one, and rskj reports no retiring federation -- which is what
/// `peg::retiring_federation` encodes.
pub fn get_retiring_federation_size<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let value = super::peg::retiring_federation(ctx, config, hardfork_cfg, block_number)
        .map_or(FEDERATION_NON_EXISTENT, |fed| fed.members.len() as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getRetiringFederationThreshold()` → int256, `-1` when there is none.
pub fn get_retiring_federation_threshold<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let value = super::peg::retiring_federation(ctx, config, hardfork_cfg, block_number)
        .map_or(FEDERATION_NON_EXISTENT, |fed| (fed.members.len() / 2 + 1) as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getPendingFederationSize()` → int256
pub fn get_pending_federation_size<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(FEDERATION_NON_EXISTENT)));
    }
    // The pending federation is a flat member list (legacy keys or multikey
    // member lists), unlike the Federation format.
    let size = serialization::rlp_decode_list(&fed_data).map_or(0, |items| items.len());
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(size as i64)))
}

/// `isBtcTxHashAlreadyProcessed(string hash)` → bool
pub fn is_btc_tx_hash_already_processed<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // rskj: `Sha256Hash.wrap((String) args[0])` inside a catch-all that throws a
    // VMException, so a string that is not 64 lower-case hex digits reverts
    // the call rather than answering false.
    let hash_display = hash_arg(args, "isBtcTxHashAlreadyProcessed")?;
    // rskj goes through getHeightIfBtcTxhashIsAlreadyProcessed, which checks
    // the legacy btcTxHashesAP map first at every era (and loads it, so the
    // post-call save persists the possibly-empty map entry).
    let mut hash_internal = hash_display;
    hash_internal.reverse();
    let processed = super::tx::is_btc_tx_processed(ctx, &hash_internal);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bool(processed)))
}

// ---------------------------------------------------------------------------
// Lock whitelist
// ---------------------------------------------------------------------------
//
// rskj's `LockWhitelist` is a **`TreeMap` ordered by hash160**, not a HashMap:
//
// ```java
// private static final Comparator<Address> LEXICOGRAPHICAL_COMPARATOR
//     = Comparator.comparing(Address::getHash160, UnsignedBytes.lexicographicalComparator());
// private SortedMap<Address, LockWhitelistEntry> whitelistedAddresses;
// ```
//
// Two things follow, and both are the opposite of what the types suggest:
//
// * **The index order is defined**, and it is the one-off and unlimited
//   entries *merged* and sorted by hash160 ascending -- not one list after the
//   other, and not an arbitrary hash order.
// * **Lookup ignores the version byte.** A `TreeMap` searches with its
//   comparator, and this one compares `getHash160()` alone, so `Address.equals`
//   -- which does compare the version -- never runs. The same hash160
//   presented as a P2SH address finds a whitelisted P2PKH entry.
//
// (See docs/quirks-java-artifacts.md §11b, where the same TreeMap ordering
// was found from the *serialized* whitelist cells at mainnet #1,590,999.)

/// `getLockWhitelistSize()` → int256, one-off plus unlimited entries.
///
/// Every lock-whitelist getter that reads the whitelist writes it back as the
/// call returns, as rskj's `save()` does for whatever the call loaded (see
/// `save_lock_whitelist`). Only a getter run in a transaction keeps that
/// write, so only one reached before RSKIP88 made them local calls.
pub fn get_lock_whitelist_size<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let entries = merged_whitelist(&loaded_and_saved_whitelist(ctx, hardfork_cfg));
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(entries.len() as i64)))
}

/// `getLockWhitelistAddress(int256 index)` → string, `""` when out of range.
///
/// The index walks the merged whitelist in hash160 order (see above). The
/// address is rendered **P2PKH**, because that is how rskj reconstructs it
/// from the stored hash160 (`new Address(parameters, hash160)`) -- so a P2SH
/// address that was whitelisted comes back as a different string than the one
/// that was added.
pub fn get_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let index = index_arg(args, "getLockWhitelistAddress")?;
    let entries = merged_whitelist(&loaded_and_saved_whitelist(ctx, hardfork_cfg));

    // rskj `getLockWhitelistEntryByIndex`: a negative index is not found either.
    let address = match usize::try_from(index).ok().and_then(|i| entries.get(i)) {
        // rskj: "Empty string is returned when address is not found".
        None => String::new(),
        Some((hash160, _)) => p2pkh_base58_address(hash160, config),
    };
    Ok(PrecompileOutput::new(gas_cost, abi_encode_string(&address).into()))
}

/// `getLockWhitelistEntryByAddress(string address)` → int256.
///
/// rskj's `WhitelistResponseCode`: the one-off entry's `maxTransferValue` in
/// satoshis, `0` (UNLIMITED_MODE) for an unlimited entry, `-1`
/// (ADDRESS_NOT_EXIST) when the address is not whitelisted **or does not
/// parse**. `-2` (INVALID_ADDRESS_FORMAT) is unreachable in rskj: it is
/// returned only if `(String) args[0]` fails to cast, and by then the ABI
/// decoder has already produced a String or thrown.
///
/// A parse failure answering with the same `-1` as "not whitelisted" is rskj's
/// behaviour, not a simplification: `WhitelistSupportImpl` catches
/// `AddressFormatException` and returns `Optional.empty()`, which the Bridge
/// maps to ADDRESS_NOT_EXIST. What *does* fail to parse is an address whose
/// version byte belongs to another network -- bitcoinj's `Address.fromBase58`
/// accepts only this network's P2PKH and P2SH headers.
pub fn get_lock_whitelist_entry_by_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let Some(addr_str) = crate::abi::Args::new(args).string(0) else {
        return Err(PrecompileError::other(
            "getLockWhitelistEntryByAddress: malformed string argument",
        ));
    };

    // rskj parses the address before it reads the whitelist, so one that
    // doesn't parse leaves the whitelist unread and unwritten.
    let Some(hash160) = parse_network_address_hash160(&addr_str, config) else {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(ADDRESS_NOT_EXIST)));
    };

    let value = merged_whitelist(&loaded_and_saved_whitelist(ctx, hardfork_cfg))
        .into_iter()
        .find(|(h, _)| *h == hash160)
        .map_or(ADDRESS_NOT_EXIST, |(_, cap)| match cap {
            // rskj returns UNLIMITED_MODE for an UnlimitedWhiteListEntry and
            // the cap for a OneOffWhiteListEntry.
            None => UNLIMITED_MODE,
            Some(satoshis) => satoshis as i64,
        });
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// rskj `getLockWhitelist` for the block being run, written back as the call
/// returns.
fn loaded_and_saved_whitelist<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> LockWhitelist {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let whitelist = LockWhitelist::load(ctx, hardfork_cfg.has_rskip87(block_number));
    whitelist.save(ctx);
    whitelist
}

/// The whitelist as rskj's `LockWhitelist` holds it: one-off and unlimited
/// entries in one map, ordered by hash160 ascending. `None` marks an unlimited
/// entry, `Some(cap)` a one-off entry's `maxTransferValue`.
fn merged_whitelist(whitelist: &LockWhitelist) -> Vec<([u8; 20], Option<u64>)> {
    let mut entries: Vec<([u8; 20], Option<u64>)> = whitelist
        .one_off
        .iter()
        .map(|&(hash160, cap)| (hash160, Some(cap)))
        .collect();
    entries.extend(whitelist.unlimited.iter().map(|&h| (h, None)));
    // `UnsignedBytes.lexicographicalComparator()` over the 20-byte hash160.
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// Base58Check P2PKH address for a hash160 (bitcoinj
/// `new Address(parameters, hash160).toBase58()`; mainnet version 0x00,
/// testnet/regtest 0x6f).
fn p2pkh_base58_address(hash160: &[u8; 20], config: &BridgeConstants) -> String {
    let mut payload = [0u8; 21];
    payload[0] = p2pkh_version(config);
    payload[1..].copy_from_slice(hash160);
    bitcoin::base58::encode_check(&payload)
}

fn p2pkh_version(config: &BridgeConstants) -> u8 {
    match config.btc_network {
        super::constants::BtcNetwork::Mainnet => 0,
        _ => 111,
    }
}

fn p2sh_version(config: &BridgeConstants) -> u8 {
    match config.btc_network {
        super::constants::BtcNetwork::Mainnet => 5,
        _ => 196,
    }
}

/// The hash160 of a Base58Check address that bitcoinj's
/// `Address.fromBase58(params, s)` would accept for this network: either
/// version header, P2PKH or P2SH. Anything else throws `WrongNetworkException`.
///
/// The version is checked but then discarded, because the whitelist's TreeMap
/// comparator looks at the hash160 alone.
pub(super) fn parse_network_address_hash160(
    addr: &str,
    config: &BridgeConstants,
) -> Option<[u8; 20]> {
    let decoded = bitcoin::base58::decode_check(addr).ok()?;
    if decoded.len() != 21 {
        return None;
    }
    if decoded[0] != p2pkh_version(config) && decoded[0] != p2sh_version(config) {
        return None;
    }
    decoded[1..21].try_into().ok()
}

/// rskj `WhitelistResponseCode.ADDRESS_NOT_EXIST`.
const ADDRESS_NOT_EXIST: i64 = -1;
/// rskj `WhitelistResponseCode.UNLIMITED_MODE`.
const UNLIMITED_MODE: i64 = 0;
/// rskj `FederationChangeResponseCode.FEDERATION_NON_EXISTENT`.
const FEDERATION_NON_EXISTENT: i64 = -1;

// ---------------------------------------------------------------------------
// Federator public keys, by key type
// ---------------------------------------------------------------------------

/// rskj `FederationMember.KeyType`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeyType {
    Btc,
    Rsk,
    Mst,
}

/// rskj `FederationMember.KeyType.byValue`, which throws on anything else --
/// and the Bridge turns that throw into a `VMException`, i.e. the call
/// reverts. It does not fall back to the BTC key.
fn parse_key_type(value: &str) -> Option<KeyType> {
    match value {
        "btc" => Some(KeyType::Btc),
        "rsk" => Some(KeyType::Rsk),
        "mst" => Some(KeyType::Mst),
        _ => None,
    }
}

fn member_key(member: &super::federation::StoredMember, key_type: KeyType) -> [u8; 33] {
    match key_type {
        KeyType::Btc => member.btc,
        KeyType::Rsk => member.rsk,
        KeyType::Mst => member.mst,
    }
}

/// The `(index, keyType)` pair the `*PublicKeyOfType` methods take: the index
/// as rskj's `intValue()`, the key type through `KeyType.byValue`, which
/// throws for anything but "btc", "rsk" and "mst".
fn decode_index_and_key_type(args: &[u8]) -> Result<(i32, KeyType), PrecompileError> {
    let index = index_arg(args, "PublicKeyOfType")?;
    let key_type = crate::abi::Args::new(args)
        .string(1)
        .as_deref()
        .and_then(parse_key_type)
        .ok_or_else(|| PrecompileError::other("PublicKeyOfType: unknown key type"))?;
    Ok((index, key_type))
}

/// rskj `FederationSupportImpl.getFederationMemberPublicKeyOfType`: an index
/// outside the member list, a negative one included, throws
/// `IndexOutOfBoundsException`, which the Bridge turns into a `VMException`
/// -- the call **reverts**, it does not return empty bytes. The index is
/// checked only here, after the caller has found the federation: with no
/// federation to look in, rskj answers empty whatever the index.
fn member_key_at(
    members: &[super::federation::StoredMember],
    index: i32,
    key_type: KeyType,
    who: &'static str,
) -> Result<[u8; 33], PrecompileError> {
    usize::try_from(index)
        .ok()
        .and_then(|index| members.get(index))
        .map(|m| member_key(m, key_type))
        .ok_or_else(|| {
            PrecompileError::Other(
                format!("{who} index must be between 0 and {}", members.len() as i64 - 1).into(),
            )
        })
}

// ---------------------------------------------------------------------------
// Pending federation
// ---------------------------------------------------------------------------

/// `getPendingFederationHash()` → bytes.
///
/// `PendingFederation.getHash()` is keccak over `serializeOnlyBtcKeys()` at
/// **every** era, including after RSKIP123 stored the pending federation in
/// multikey form -- the hash a `commitFederation` vote has to match. Empty
/// bytes when there is no pending federation.
pub fn get_pending_federation_hash<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let members = pending_federation_members(ctx);
    if members.is_empty() && bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&[]).into()));
    }
    let hash = super::governance::pending_federation_hash(&members);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&hash).into()))
}

/// `getPendingFederatorPublicKey(int256 index)` → bytes (the BTC key).
///
/// No pending federation is **empty bytes**, not an empty return: rskj's
/// `getPendingFederatorBtcPublicKey` returns `EMPTY_BYTE_ARRAY`, which is
/// non-null and so gets ABI-encoded. An index past the end reverts --
/// `publicKeys.get(index)` has no bounds check there.
pub fn get_pending_federator_public_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let index = index_arg(args, "getPendingFederatorPublicKey")?;

    if bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&[]).into()));
    }
    let members = pending_federation_members(ctx);
    let key = member_key_at(&members, index, KeyType::Btc, "Pending federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

/// `getPendingFederatorPublicKeyOfType(int256 index, string keyType)` → bytes.
pub fn get_pending_federator_public_key_of_type<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let (index, key_type) = decode_index_and_key_type(args)?;
    if bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&[]).into()));
    }
    let members = pending_federation_members(ctx);
    let key = member_key_at(&members, index, key_type, "Pending federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

fn pending_federation_members<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
) -> Vec<super::federation::StoredMember> {
    let data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    serialization::rlp_decode_list(&data)
        .unwrap_or_default()
        .iter()
        .filter_map(|m| super::federation::StoredMember::from_stored(m))
        .collect()
}

// ---------------------------------------------------------------------------
// Retiring federation
// ---------------------------------------------------------------------------

/// `getRetiringFederationCreationBlockNumber()` → int256, `-1` when there is
/// no retiring federation.
pub fn get_retiring_federation_creation_block_number<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let value = super::peg::retiring_federation(ctx, config, hardfork_cfg, block_number)
        .map_or(FEDERATION_NON_EXISTENT, |fed| fed.creation_block as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getRetiringFederationCreationTime()` → int256, `-1` when there is none.
///
/// The unit changes at RSKIP419: milliseconds before, **seconds** after
/// (`Bridge.getFederationCreationTimeEpochBasedOnActivation`). Storage always
/// holds milliseconds; only the answer changes.
pub fn get_retiring_federation_creation_time<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let value = super::peg::retiring_federation(ctx, config, hardfork_cfg, block_number)
        .map_or(FEDERATION_NON_EXISTENT, |fed| {
            creation_time_for_era(fed.creation_time_millis, hardfork_cfg, block_number)
        });
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getRetiringFederatorPublicKey(int256 index)` → bytes (BTC key), empty
/// bytes when there is no retiring federation.
pub fn get_retiring_federator_public_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let index = index_arg(args, "getRetiringFederatorPublicKey")?;
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let Some(fed) = super::peg::retiring_federation(ctx, config, hardfork_cfg, block_number) else {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&[]).into()));
    };
    let key = member_key_at(&fed.members, index, KeyType::Btc, "Retiring federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

/// `getRetiringFederatorPublicKeyOfType(int256 index, string keyType)` → bytes.
pub fn get_retiring_federator_public_key_of_type<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let (index, key_type) = decode_index_and_key_type(args)?;
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let Some(fed) = super::peg::retiring_federation(ctx, config, hardfork_cfg, block_number) else {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&[]).into()));
    };
    let key = member_key_at(&fed.members, index, key_type, "Retiring federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

// ---------------------------------------------------------------------------
// Proposed federation (RSKIP419 / SVP)
// ---------------------------------------------------------------------------

/// `getProposedFederationAddress()` → string, `""` when there is none.
pub fn get_proposed_federation_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    let Some(fed) = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY) else {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_string("").into()));
    };
    let keys: Vec<[u8; 33]> = fed.members.iter().map(|m| m.btc).collect();
    let format = super::peg::federation_format_version_pub(ctx, PROPOSED_FEDERATION_FORMAT_VERSION_KEY);
    let redeem = super::peg::federation_redeem_for_format_pub(&keys, format, config);
    let hash160 = super::peg::federation_output_hash160(&redeem, format);
    let address = super::governance::p2sh_base58_address(&hash160, config);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_string(&address).into()))
}

/// `getProposedFederationSize()` → int256, `-1` when there is none.
pub fn get_proposed_federation_size<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let value = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
        .map_or(FEDERATION_NON_EXISTENT, |fed| fed.members.len() as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getProposedFederationCreationTime()` → int256, **always in seconds**.
///
/// Unlike the active and retiring variants this one does not consult
/// RSKIP419: `Bridge.getProposedFederationCreationTime` calls
/// `Instant::getEpochSecond` directly. A proposed federation cannot exist
/// before RSKIP419 anyway, so there is no era in which the other branch could
/// be taken.
pub fn get_proposed_federation_creation_time<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let value = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
        .map_or(-1i64, |fed| (fed.creation_time_millis / 1000) as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getProposedFederationCreationBlockNumber()` → int256, `-1` when none.
pub fn get_proposed_federation_creation_block_number<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let value = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
        .map_or(FEDERATION_NON_EXISTENT, |fed| fed.creation_block as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(value)))
}

/// `getProposedFederatorPublicKeyOfType(int256 index, string keyType)` → bytes.
pub fn get_proposed_federator_public_key_of_type<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let (index, key_type) = decode_index_and_key_type(args)?;
    let Some(fed) = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY) else {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&[]).into()));
    };
    let key = member_key_at(&fed.members, index, key_type, "Proposed Federator")?;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&key).into()))
}

// ---------------------------------------------------------------------------
// BTC transaction index
// ---------------------------------------------------------------------------

/// `getBtcTxHashProcessedHeight(string btcTxHash)` → int256, `-1` when the
/// transaction has not been processed.
///
/// The hash argument is in **display order** (the string bitcoin explorers
/// show), which is the reverse of the internal byte order the index is keyed
/// by -- the same convention `isBtcTxHashAlreadyProcessed` takes.
pub fn get_btc_tx_hash_processed_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // rskj: `Sha256Hash.wrap` throws, the Bridge wraps it in a VMException.
    let mut hash = hash_arg(args, "getBtcTxHashProcessedHeight")?;
    hash.reverse();
    let height = super::tx::get_btc_tx_processed_height(ctx, &hash).map_or(-1i64, |h| h as i64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(height)))
}

/// A method's first argument as an index: `((BigInteger) args[0]).intValue()`.
fn index_arg(args: &[u8], method: &str) -> Result<i32, PrecompileError> {
    crate::abi::Args::new(args)
        .int(0)
        .map(|index| index.int_value())
        .ok_or_else(|| PrecompileError::Other(format!("{method}: no index").into()))
}

/// A method's first argument as a BTC transaction hash in display order:
/// `Sha256Hash.wrap((String) args[0])`, whose lower-case-only hex decoding
/// and 32-byte check both throw.
fn hash_arg(args: &[u8], method: &str) -> Result<[u8; 32], PrecompileError> {
    crate::abi::Args::new(args)
        .string(0)
        .as_deref()
        .and_then(sha256_hash_from_hex)
        .ok_or_else(|| PrecompileError::Other(format!("{method}: not a 32-byte hash").into()))
}

/// `Sha256Hash.wrap(String)`: bitcoinj's `Utils.HEX`, Guava's lower-case
/// base16, decodes the string, and the hash must be 32 bytes. Upper-case
/// digits are refused.
fn sha256_hash_from_hex(hex: &str) -> Option<[u8; 32]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut hash = [0u8; 32];
    for (byte, pair) in hash.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(hash)
}

/// The federation creation time as the era reports it: milliseconds before
/// RSKIP419, seconds from RSKIP419 on. Storage always holds milliseconds.
fn creation_time_for_era(
    millis: u64,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_number: u64,
) -> i64 {
    if hardfork_cfg.has_rskip419(block_number) {
        (millis / 1000) as i64
    } else {
        millis as i64
    }
}

// ---------------------------------------------------------------------------
// Federator-client state
// ---------------------------------------------------------------------------
//
// Three methods that hand a federator's signing client the Bridge state it
// needs. All three return an RLP blob inside an ABI `bytes`, and all three are
// `LocalOnly`.

/// `getStateForBtcReleaseClient()` → bytes.
///
/// rskj: `new StateForFederator(provider.getPegoutsWaitingForSignatures()).encodeToRlp()`,
/// which is `RLP.encodeList(serializeRskTxsWaitingForSignatures(map))` -- the
/// serialized map, itself an RLP list, wrapped in a one-element outer list.
/// The double wrapping is not redundant: `StateForFederator`'s decoder reads
/// `rlpList.get(0)`, so a client parsing this expects the extra level.
///
/// This is the map the signing client polls: every peg-out awaiting federator
/// signatures, keyed by the RSK transaction that created it.
pub fn get_state_for_btc_release_client<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let data = bridge_load_bytes_named(ctx, PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
    let waiting = super::peg::deserialize_rsk_txs_waiting_for_signatures(&data);
    let serialized = super::peg::serialize_rsk_txs_waiting_for_signatures(&waiting);
    let encoded = serialization::rlp_encode_list(&[serialized]);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&encoded).into()))
}

/// `getStateForSvpClient()` → bytes.
///
/// rskj returns `RLP.encodeList(serializeRskTxWaitingForSignatures(entry))`
/// for the single SVP spend transaction awaiting signatures, and
/// `RLP.encodeList(RLP.encodedEmptyList())` when there is none -- an empty
/// list inside a list, not an empty blob, so the client's decoder finds the
/// element it indexes and sees it empty.
///
/// The SVP (RSKIP419) is the protocol that proves a proposed federation can
/// sign before it takes over. Outside a federation change this is the empty
/// case.
pub fn get_state_for_svp_client<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let stored = bridge_load_bytes_named(ctx, SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY);
    // Stored as RLP[rskTxHash, btcTx]; rskj serializes the entry the same way.
    let inner = if stored.is_empty() {
        serialization::rlp_encode_list(&[])
    } else {
        stored
    };
    let encoded = serialization::rlp_encode_list(&[inner]);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&encoded).into()))
}

/// `getStateForDebugging()` → bytes: the whole Bridge state in one call.
///
/// rskj `BridgeState.getEncoded()`, a six-element RLP list:
///
/// ```text
/// [ btcBlockchainBestChainHeight   (RLP.encodeBigInteger, not an element)
/// , activeFederationBtcUTXOs       (element of serializeUTXOList)
/// , rskTxsWaitingForSignatures     (element)
/// , releaseRequestQueue            (element; with-txhash form from RSKIP146)
/// , pegoutsWaitingForConfirmations (element; with-txhash form from RSKIP146)
/// , nextPegoutCreationBlockNumber  (element of serializeLong) ]
/// ```
///
/// The first field is the odd one: `encodeBigInteger` rather than
/// `encodeElement`, so the height is a minimal-length integer while the other
/// five are byte strings. Encoding it like its neighbours produces a blob a
/// client decodes as the wrong type.
///
/// **The UTXOs are the *new* federation's**, read from
/// `newFederationBtcUTXOs` directly -- `getNewFederationBtcUTXOs()`, not the
/// active-federation selection that switches to the old key during an
/// activation window. `eth_bridgeState` exposes none of this; this method is
/// the only one that returns the whole thing, which is why it is priced at
/// 3,000,000 gas.
pub fn get_state_for_debugging<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    // rskj `BridgeState.shouldUsePapyrusEncoding` == RSKIP146.
    let papyrus = hardfork_cfg.has_rskip146(block_number);

    let height = super::btc_store::load_chain_head(ctx).map_or(0u32, |h| h.height);
    let utxos = load_federation_utxos(ctx, hardfork_cfg, block_number);
    let waiting_for_signatures = super::peg::serialize_rsk_txs_waiting_for_signatures(
        &super::peg::deserialize_rsk_txs_waiting_for_signatures(&bridge_load_bytes_named(
            ctx,
            PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
        )),
    );
    let queue = super::peg::load_release_request_queue(ctx, papyrus);
    let queue_bytes = if papyrus {
        super::peg::serialize_release_queue_with_hash(&queue)
    } else {
        super::peg::serialize_release_queue_legacy(&queue)
    };
    let confirmations = super::peg::load_pegout_confirmation_set(ctx, papyrus);
    let confirmations_bytes =
        super::peg::serialize_pegouts_waiting_for_confirmations(&confirmations, papyrus);
    let next_pegout = bridge_load_u256(ctx, NEXT_PEGOUT_HEIGHT_KEY).to::<u64>();

    let encoded = serialization::rlp_encode_list(&[
        // encodeBigInteger, not encodeElement: a minimal-length integer.
        serialization::rlp_encode_u64(u64::from(height)),
        serialization::rlp_encode_element(&serialize_utxo_list(&utxos)),
        serialization::rlp_encode_element(&waiting_for_signatures),
        serialization::rlp_encode_element(&queue_bytes),
        serialization::rlp_encode_element(&confirmations_bytes),
        serialization::rlp_encode_element(&serialization::serialize_long(next_pegout)),
    ]);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bytes(&encoded).into()))
}

/// ABI-encode a `string[]`.
///
/// A dynamic array of dynamic values: an offset to the array, its length, then
/// one offset per element relative to the start of the element section, then
/// each element as a length word plus its bytes padded to 32.
pub(crate) fn abi_encode_string_array_pub(items: &[String]) -> Vec<u8> {
    abi_encode_string_array(items)
}

fn abi_encode_string_array(items: &[String]) -> Vec<u8> {
    let mut head = Vec::new();
    let mut body = Vec::new();

    // Offsets are measured from the first word after the length.
    let mut offset = items.len() * 32;
    for item in items {
        head.extend_from_slice(&word(offset as u64));
        let bytes = item.as_bytes();
        body.extend_from_slice(&word(bytes.len() as u64));
        let mut padded = bytes.to_vec();
        padded.resize(bytes.len().div_ceil(32) * 32, 0);
        body.extend_from_slice(&padded);
        offset += 32 + bytes.len().div_ceil(32) * 32;
    }

    let mut out = Vec::new();
    out.extend_from_slice(&word(32)); // offset to the array
    out.extend_from_slice(&word(items.len() as u64));
    out.extend_from_slice(&head);
    out.extend_from_slice(&body);
    out
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    w
}

// ---------------------------------------------------------------------------
// ABI encoding helpers
// ---------------------------------------------------------------------------

fn abi_encode_int(value: i64) -> Bytes {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    Bytes::copy_from_slice(&output)
}

fn abi_encode_u256(value: U256) -> Bytes {
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

fn abi_encode_bool(value: bool) -> Bytes {
    let mut output = [0u8; 32];
    if value {
        output[31] = 1;
    }
    Bytes::copy_from_slice(&output)
}

/// ABI-encode a `string`. rskj's `SolidityType.StringType` extends `BytesType`
/// and encodes the UTF-8 bytes, so the layout is identical to `abi_encode_bytes`.
fn abi_encode_string(s: &str) -> Vec<u8> {
    abi_encode_bytes(s.as_bytes())
}

pub(crate) fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    // rskj's `SolidityType.BytesType.encode` sizes the data section as
    // `((len - 1) / 32 + 1) * 32` with Java's truncating division, so an EMPTY
    // `bytes` still emits one 32-byte zero word (-1/32 == 0 → 1 word): empty
    // encodes to 96 bytes, not 64. Rust's `/` truncates the same way.
    let data_section = (((data.len() as i64 - 1) / 32 + 1) * 32) as usize;
    let mut output = Vec::with_capacity(64 + data_section);
    // offset to data (always 32 for single bytes param)
    let mut offset = [0u8; 32];
    offset[28..32].copy_from_slice(&32u32.to_be_bytes());
    output.extend_from_slice(&offset);
    // length
    let mut len_word = [0u8; 32];
    len_word[28..32].copy_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(&len_word);
    // data (padded per rskj's BytesType formula)
    output.extend_from_slice(data);
    output.resize(64 + data_section, 0);
    output
}




#[cfg(test)]
mod tests {
    use super::abi_encode_bytes;
    use super::*;
    use crate::bridge::constants::BridgeConstants;
    use crate::bridge::federation::StoredMember;
    use crate::hardfork::RskHardforkConfig;

    /// A writable Bridge context at `block_number`, backed by the raw-storage
    /// overlay alone -- no trie, no database. Everything these getters read is
    /// written through `bridge_store_bytes_named`, so the overlay is the whole
    /// world.
    fn ctx_at(block_number: u64) -> impl crate::RskContextTr {
        use revm::MainContext;
        let chain_ext = crate::raw_storage::RskChainExt::default();
        let block_env = revm::context::BlockEnv {
            number: U256::from(block_number),
            ..revm::context::BlockEnv::default()
        };
        revm::Context::mainnet().with_block(block_env).with_chain(chain_ext)
    }

    fn mainnet() -> BridgeConstants {
        BridgeConstants::mainnet()
    }

    fn hardforks() -> RskHardforkConfig {
        RskHardforkConfig::mainnet()
    }

    fn member(tag: u8) -> StoredMember {
        StoredMember {
            btc: key_of(0x02, tag),
            rsk: key_of(0x03, tag),
            mst: key_of(0x02, tag.wrapping_add(0x40)),
        }
    }

    fn key_of(prefix: u8, tag: u8) -> [u8; 33] {
        let mut k = [tag; 33];
        k[0] = prefix;
        k
    }

    /// The last 32 bytes of an ABI `int256` return, as a signed value.
    fn as_int(out: &PrecompileOutput) -> i64 {
        let b = out.bytes.as_ref();
        assert_eq!(b.len(), 32, "int256 returns are one word");
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&b[24..32]);
        i64::from_be_bytes(buf)
    }

    /// The payload of an ABI `bytes`/`string` return.
    fn as_bytes(out: &PrecompileOutput) -> Vec<u8> {
        let b = out.bytes.as_ref();
        assert!(b.len() >= 64, "dynamic returns carry offset and length");
        let len = U256::from_be_slice(&b[32..64]).to::<usize>();
        b[64..64 + len].to_vec()
    }

    fn as_string(out: &PrecompileOutput) -> String {
        String::from_utf8(as_bytes(out)).unwrap()
    }

    // ---- lock whitelist ----

    #[test]
    fn lock_whitelist_size_counts_both_lists() {
        let mut ctx = ctx_at(1_000_000);
        store_one_off_whitelist(&mut ctx, &[([0x11; 20], 500), ([0x22; 20], 600)], 1_000);
        store_unlimited_whitelist(&mut ctx, &[[0x33; 20]]);

        let out = get_lock_whitelist_size(&mut ctx, 0, &hardforks()).unwrap();
        assert_eq!(as_int(&out), 3);
    }

    #[test]
    fn lock_whitelist_entry_by_address_reports_the_transfer_cap() {
        let mut ctx = ctx_at(1_000_000);
        let config = mainnet();
        store_one_off_whitelist(&mut ctx, &[([0x11; 20], 12_345)], 1_000);
        store_unlimited_whitelist(&mut ctx, &[[0x22; 20]]);

        let one_off = p2pkh_base58_address(&[0x11; 20], &config);
        let unlimited = p2pkh_base58_address(&[0x22; 20], &config);
        let stranger = p2pkh_base58_address(&[0x99; 20], &config);

        assert_eq!(as_int(&query_whitelist(&mut ctx, &one_off, &config)), 12_345);
        assert_eq!(
            as_int(&query_whitelist(&mut ctx, &unlimited, &config)),
            0,
            "an unlimited entry is UNLIMITED_MODE (0), not its cap"
        );
        assert_eq!(as_int(&query_whitelist(&mut ctx, &stranger, &config)), -1);
        assert_eq!(
            as_int(&query_whitelist(&mut ctx, "not an address", &config)),
            -1,
            "a parse failure is ADDRESS_NOT_EXIST, not INVALID_ADDRESS_FORMAT"
        );
    }

    /// The whitelist is a `TreeMap` keyed by a comparator over `getHash160()`
    /// alone, so lookup never reaches `Address.equals` and the version byte
    /// does not have to match: a whitelisted P2PKH entry is found by the P2SH
    /// rendering of the same hash160.
    ///
    /// The version is still *parsed*, because `Address.fromBase58` rejects a
    /// header belonging to another network.
    #[test]
    fn lock_whitelist_entry_by_address_matches_on_hash160_alone() {
        let mut ctx = ctx_at(1_000_000);
        let config = mainnet();
        store_one_off_whitelist(&mut ctx, &[([0x11; 20], 12_345)], 1_000);

        let p2sh = crate::bridge::governance::p2sh_base58_address(&[0x11; 20], &config);
        assert_eq!(
            as_int(&query_whitelist(&mut ctx, &p2sh, &config)),
            12_345,
            "the TreeMap comparator compares hash160, not the version byte"
        );

        // A testnet-header address is a different network and does not parse.
        let mut foreign = [0u8; 21];
        foreign[0] = 111;
        foreign[1..].copy_from_slice(&[0x11; 20]);
        let foreign = bitcoin::base58::encode_check(&foreign);
        assert_eq!(as_int(&query_whitelist(&mut ctx, &foreign, &config)), -1);
    }

    fn query_whitelist<CTX: crate::RskContextTr>(
        ctx: &mut CTX,
        address: &str,
        config: &BridgeConstants,
    ) -> PrecompileOutput {
        get_lock_whitelist_entry_by_address(ctx, &abi_string_arg(address), 0, config, &hardforks())
            .unwrap()
    }

    /// A getter that reads the whitelist writes it back as the call returns,
    /// as rskj's `save()` does for whatever the call loaded (upstream #291),
    /// so on a store that never held it the cells appear: the unlimited one
    /// from RSKIP87 on. The by-address getter parses the address first, and
    /// one that doesn't parse leaves the whitelist unread.
    #[test]
    fn the_whitelist_getters_write_the_whitelist_back() {
        fn cells<CTX: crate::RskContextTr>(ctx: &mut CTX) -> (String, String) {
            let mut cell =
                |key: &str| alloy_primitives::hex::encode(bridge_load_bytes_named(ctx, key));
            (cell(LOCK_WHITELIST_KEY), cell(UNLIMITED_LOCK_WHITELIST_KEY))
        }
        let read = ("c5847fffffff".to_string(), "c0".to_string());
        let config = mainnet();

        let mut ctx = ctx_at(1_000_000);
        assert_eq!(
            as_int(&get_lock_whitelist_size(&mut ctx, 0, &hardforks()).unwrap()),
            0
        );
        assert_eq!(cells(&mut ctx), read);

        let mut ctx = ctx_at(728_999);
        get_lock_whitelist_size(&mut ctx, 0, &hardforks()).unwrap();
        assert_eq!(
            cells(&mut ctx),
            ("c5847fffffff".to_string(), String::new()),
            "before RSKIP87, the one-off cell alone"
        );

        let mut ctx = ctx_at(1_000_000);
        get_lock_whitelist_address(&mut ctx, &[0u8; 32], 0, &config, &hardforks()).unwrap();
        assert_eq!(cells(&mut ctx), read);

        let mut ctx = ctx_at(1_000_000);
        assert_eq!(
            as_int(&query_whitelist(&mut ctx, "not an address", &config)),
            -1
        );
        assert_eq!(cells(&mut ctx), (String::new(), String::new()), "unread");
        let stranger = p2pkh_base58_address(&[0x99; 20], &config);
        assert_eq!(as_int(&query_whitelist(&mut ctx, &stranger, &config)), -1);
        assert_eq!(cells(&mut ctx), read);
    }

    /// ABI head+tail for a single `string` argument.
    fn abi_string_arg(s: &str) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[31] = 32;
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(s.len() as u64).to_be_bytes());
        out.extend_from_slice(&len);
        out.extend_from_slice(s.as_bytes());
        out.resize(64 + s.len().div_ceil(32) * 32, 0);
        out
    }

    /// ABI head+tail for `(int256, string)`.
    fn abi_index_and_key_type(index: u64, key_type: &str) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[24..32].copy_from_slice(&index.to_be_bytes());
        out[63] = 64; // offset to the string
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(key_type.len() as u64).to_be_bytes());
        out.extend_from_slice(&len);
        out.extend_from_slice(key_type.as_bytes());
        out.resize(96 + key_type.len().div_ceil(32) * 32, 0);
        out
    }

    /// The index order is the two lists **merged** and sorted by hash160, not
    /// one list after the other: rskj's `LockWhitelist` copies both into one
    /// `TreeMap` ordered by `UnsignedBytes.lexicographicalComparator()` over
    /// the hash160. Here the unlimited entry sorts *before* the one-off one.
    #[test]
    fn lock_whitelist_address_walks_hash160_order_and_renders_p2pkh() {
        let mut ctx = ctx_at(1_000_000);
        let config = mainnet();
        store_one_off_whitelist(&mut ctx, &[([0xcc; 20], 1)], 1_000);
        store_unlimited_whitelist(&mut ctx, &[[0x22; 20]]);

        let at = |ctx: &mut _, i: u64| {
            let mut arg = [0u8; 32];
            arg[24..32].copy_from_slice(&i.to_be_bytes());
            as_string(&get_lock_whitelist_address(ctx, &arg, 0, &config, &hardforks()).unwrap())
        };
        assert_eq!(
            at(&mut ctx, 0),
            p2pkh_base58_address(&[0x22; 20], &config),
            "0x22 sorts before 0xcc even though it is the unlimited entry"
        );
        assert_eq!(at(&mut ctx, 1), p2pkh_base58_address(&[0xcc; 20], &config));
        assert_eq!(at(&mut ctx, 2), "", "out of range is the empty string");
    }

    /// Unsigned lexicographic order, so a hash160 starting 0xff sorts last --
    /// signed byte comparison would put it first.
    #[test]
    fn lock_whitelist_order_is_unsigned() {
        let mut ctx = ctx_at(1_000_000);
        store_one_off_whitelist(&mut ctx, &[([0xff; 20], 1), ([0x01; 20], 2)], 1_000);
        let merged = merged_whitelist(&LockWhitelist::load(&mut ctx, true));
        assert_eq!(
            merged.iter().map(|(h, _)| h[0]).collect::<Vec<_>>(),
            vec![0x01, 0xff]
        );
    }

    // ---- federator public keys ----

    /// The regression this replaces: `getFederatorPublicKeyOfType` used to
    /// delegate to the BTC-key getter, so `"rsk"` and `"mst"` both answered
    /// with the BTC key.
    #[test]
    fn federator_public_key_of_type_returns_the_requested_key() {
        let mut ctx = ctx_at(6_500_000);
        let (config, forks) = (mainnet(), hardforks());
        let members = vec![member(1), member(2)];
        store_federation(&mut ctx, NEW_FEDERATION_KEY, &members, 1_000, 100);

        let index = sorted_index(&members, 0);
        let btc = as_bytes(
            &get_federator_public_key_of_type(
                &mut ctx,
                &abi_index_and_key_type(index as u64, "btc"),
                0,
                &config,
                &forks,
            )
            .unwrap(),
        );
        let rsk = as_bytes(
            &get_federator_public_key_of_type(
                &mut ctx,
                &abi_index_and_key_type(index as u64, "rsk"),
                0,
                &config,
                &forks,
            )
            .unwrap(),
        );
        let mst = as_bytes(
            &get_federator_public_key_of_type(
                &mut ctx,
                &abi_index_and_key_type(index as u64, "mst"),
                0,
                &config,
                &forks,
            )
            .unwrap(),
        );

        assert_ne!(btc, rsk, "the BTC and RSK keys of a member are different");
        assert_ne!(btc, mst);
        assert_eq!(btc.len(), 33);
    }

    #[test]
    fn federator_public_key_of_type_rejects_an_unknown_key_type() {
        let mut ctx = ctx_at(6_500_000);
        let (config, forks) = (mainnet(), hardforks());
        store_federation(&mut ctx, NEW_FEDERATION_KEY, &[member(1)], 1_000, 100);

        assert!(
            get_federator_public_key_of_type(
                &mut ctx,
                &abi_index_and_key_type(0, "eth"),
                0,
                &config,
                &forks
            )
            .is_err(),
            "KeyType.byValue throws, and the Bridge turns that into a revert"
        );
    }

    /// rskj bounds-checks and throws; returning empty bytes would look like a
    /// federator that has no key.
    #[test]
    fn federator_public_key_out_of_range_reverts() {
        let mut ctx = ctx_at(6_500_000);
        let (config, forks) = (mainnet(), hardforks());
        store_federation(&mut ctx, NEW_FEDERATION_KEY, &[member(1)], 1_000, 100);

        let mut arg = [0u8; 32];
        arg[31] = 5;
        assert!(get_federator_public_key(&mut ctx, &arg, 0, &config, &forks).is_err());
    }

    // ---- pending federation ----

    #[test]
    fn pending_federation_hash_matches_the_btc_key_serialization() {
        use sha3::{Digest, Keccak256};
        let mut ctx = ctx_at(6_500_000);
        let members = vec![member(3), member(4)];
        bridge_store_bytes_named(
            &mut ctx,
            PENDING_FEDERATION_KEY,
            &pending_multikey_bytes(&members),
        );

        let out = get_pending_federation_hash(&mut ctx, 0).unwrap();
        let expected: [u8; 32] =
            Keccak256::digest(sorted_btc_key_rlp(&members)).into();
        assert_eq!(as_bytes(&out), expected.to_vec());
    }

    #[test]
    fn pending_federation_getters_with_no_pending_federation() {
        let mut ctx = ctx_at(6_500_000);
        // Empty bytes, ABI-encoded -- rskj returns EMPTY_BYTE_ARRAY, which is
        // non-null and so gets encoded, rather than an empty return.
        let hash = get_pending_federation_hash(&mut ctx, 0).unwrap();
        assert_eq!(as_bytes(&hash), Vec::<u8>::new());
        assert_eq!(hash.bytes.len(), 96, "empty `bytes` is still 96 bytes");

        let key = get_pending_federator_public_key_of_type(
            &mut ctx,
            &abi_index_and_key_type(0, "btc"),
            0,
        )
        .unwrap();
        assert_eq!(as_bytes(&key), Vec::<u8>::new());
    }

    // ---- retiring federation ----

    /// A stored `oldFederation` is not by itself a retiring federation: the
    /// new one must have reached its activation age first.
    #[test]
    fn retiring_federation_is_none_during_the_activation_window() {
        let (config, forks) = (mainnet(), hardforks());
        let new_creation_block = 6_000_000u64;
        let age = crate::bridge::governance::federation_activation_age(
            &config,
            &forks,
            new_creation_block,
        );

        let mut during = ctx_at(new_creation_block + age - 1);
        store_federation(&mut during, NEW_FEDERATION_KEY, &[member(1)], 1_000, new_creation_block);
        store_federation(&mut during, OLD_FEDERATION_KEY, &[member(2), member(3)], 900, 5_000_000);
        assert_eq!(
            as_int(&get_retiring_federation_size(&mut during, 0, &config, &forks).unwrap()),
            -1,
            "inside the window there is no retiring federation"
        );

        let mut after = ctx_at(new_creation_block + age);
        store_federation(&mut after, NEW_FEDERATION_KEY, &[member(1)], 1_000, new_creation_block);
        store_federation(&mut after, OLD_FEDERATION_KEY, &[member(2), member(3)], 900, 5_000_000);
        assert_eq!(
            as_int(&get_retiring_federation_size(&mut after, 0, &config, &forks).unwrap()),
            2
        );
        assert_eq!(
            as_int(
                &get_retiring_federation_creation_block_number(&mut after, 0, &config, &forks)
                    .unwrap()
            ),
            5_000_000
        );
    }

    // ---- creation time units ----

    /// RSKIP419 changes the unit from milliseconds to seconds. Storage keeps
    /// milliseconds either way.
    #[test]
    fn federation_creation_time_unit_changes_at_rskip419() {
        let (config, forks) = (mainnet(), hardforks());
        let millis = 1_700_000_000_000u64;

        let before = 7_338_023u64; // lovell700 - 1
        let after = 7_338_024u64; // lovell700
        assert!(!forks.has_rskip419(before) && forks.has_rskip419(after));

        let mut ctx_before = ctx_at(before);
        store_federation(&mut ctx_before, NEW_FEDERATION_KEY, &[member(1)], millis, 100);
        assert_eq!(
            as_int(&get_federation_creation_time(&mut ctx_before, 0, &config, &forks).unwrap()),
            millis as i64
        );

        let mut ctx_after = ctx_at(after);
        store_federation(&mut ctx_after, NEW_FEDERATION_KEY, &[member(1)], millis, 100);
        assert_eq!(
            as_int(&get_federation_creation_time(&mut ctx_after, 0, &config, &forks).unwrap()),
            (millis / 1000) as i64
        );
    }

    // ---- proposed federation ----

    #[test]
    fn proposed_federation_getters_report_minus_one_when_absent() {
        let mut ctx = ctx_at(7_400_000);
        assert_eq!(as_int(&get_proposed_federation_size(&mut ctx, 0).unwrap()), -1);
        assert_eq!(
            as_int(&get_proposed_federation_creation_block_number(&mut ctx, 0).unwrap()),
            -1
        );
        assert_eq!(
            as_int(&get_proposed_federation_creation_time(&mut ctx, 0).unwrap()),
            -1
        );
    }

    /// Unlike the active and retiring variants, this one is in seconds at
    /// every height: rskj calls `Instant::getEpochSecond` directly.
    #[test]
    fn proposed_federation_creation_time_is_always_seconds() {
        let mut ctx = ctx_at(7_400_000);
        store_federation(&mut ctx, PROPOSED_FEDERATION_KEY, &[member(1)], 1_700_000_000_000, 7_399_000);
        assert_eq!(
            as_int(&get_proposed_federation_creation_time(&mut ctx, 0).unwrap()),
            1_700_000_000
        );
        assert_eq!(as_int(&get_proposed_federation_size(&mut ctx, 0).unwrap()), 1);
    }

    // ---- federator-client state ----

    /// rskj wraps the serialized map in an outer one-element list
    /// (`StateForFederator.encodeToRlp`), and its decoder reads
    /// `rlpList.get(0)` -- so the extra level is load-bearing, not redundant.
    #[test]
    fn state_for_btc_release_client_is_double_wrapped() {
        let mut ctx = ctx_at(6_500_000);
        let out = get_state_for_btc_release_client(&mut ctx, 0).unwrap();
        let rlp = as_bytes(&out);

        let outer = crate::bridge::serialization::rlp_decode_list(&rlp)
            .expect("the answer is an RLP list");
        assert_eq!(outer.len(), 1, "one element: the serialized map");
        assert!(
            crate::bridge::serialization::rlp_decode_list(&outer[0]).is_some(),
            "and that element is itself a list -- the map"
        );
    }

    /// With nothing awaiting signatures rskj still returns the shape, not an
    /// empty blob: a client indexes into it either way.
    #[test]
    fn state_for_svp_client_is_an_empty_list_when_there_is_nothing() {
        let mut ctx = ctx_at(7_400_000);
        let out = get_state_for_svp_client(&mut ctx, 0).unwrap();
        let rlp = as_bytes(&out);

        let outer = crate::bridge::serialization::rlp_decode_list(&rlp).unwrap();
        assert_eq!(outer.len(), 1);
        let inner = crate::bridge::serialization::rlp_decode_list(&outer[0]).unwrap();
        assert!(inner.is_empty(), "an empty list inside a list");
    }

    /// `BridgeState.getEncoded` is six fields, and the first is encoded as a
    /// **big integer** while the other five are byte strings. Encoding the
    /// height like its neighbours produces a blob that decodes as the wrong
    /// type.
    #[test]
    fn state_for_debugging_has_six_fields_with_the_height_as_an_integer() {
        let mut ctx = ctx_at(6_500_000);
        let forks = hardforks();
        let out = get_state_for_debugging(&mut ctx, 0, &forks).unwrap();
        let rlp = as_bytes(&out);

        let fields = crate::bridge::serialization::rlp_decode_list(&rlp)
            .expect("BridgeState is an RLP list");
        assert_eq!(fields.len(), 6, "btcHeight, utxos, waitingFS, queue, pegouts, nextHeight");

        // An empty store gives height 0, which `encodeBigInteger` renders as
        // the empty byte string rather than a zero byte.
        assert!(fields[0].is_empty() || fields[0] == vec![0u8], "height as an integer");
        // The middle four are byte strings holding their own RLP lists.
        for (i, field) in fields.iter().enumerate().take(5).skip(1) {
            assert!(
                crate::bridge::serialization::rlp_decode_list(field).is_some(),
                "field {i} should carry a serialized collection"
            );
        }
    }

    // ---- BTC tx index ----

    #[test]
    fn btc_tx_hash_processed_height_reports_minus_one_when_unprocessed() {
        let mut ctx = ctx_at(6_500_000);
        let display = "a".repeat(64);
        let out =
            get_btc_tx_hash_processed_height(&mut ctx, &abi_string_arg(&display), 0).unwrap();
        assert_eq!(as_int(&out), -1);
    }

    #[test]
    fn btc_tx_hash_processed_height_reads_the_index() {
        let mut ctx = ctx_at(6_500_000);
        // The argument is in display order; the index is keyed by the reverse.
        let mut internal = [0u8; 32];
        for (i, b) in internal.iter_mut().enumerate() {
            *b = i as u8;
        }
        crate::bridge::tx::set_btc_tx_processed(&mut ctx, &internal, 4_242_000, true);

        let mut display = internal;
        display.reverse();
        let display_hex: String = display.iter().map(|b| format!("{b:02x}")).collect();

        let out =
            get_btc_tx_hash_processed_height(&mut ctx, &abi_string_arg(&display_hex), 0).unwrap();
        assert_eq!(as_int(&out), 4_242_000);
    }

    #[test]
    fn btc_tx_hash_processed_height_rejects_a_malformed_hash() {
        let mut ctx = ctx_at(6_500_000);
        assert!(get_btc_tx_hash_processed_height(&mut ctx, &abi_string_arg("beef"), 0).is_err());
    }

    // ---- helpers for the federation fixtures ----

    fn store_federation<CTX: crate::RskContextTr>(
        ctx: &mut CTX,
        key: &str,
        members: &[StoredMember],
        creation_time_millis: u64,
        creation_block: u64,
    ) {
        let data = crate::bridge::federation::serialize_federation_multikey(
            members,
            creation_time_millis,
            creation_block,
        );
        bridge_store_bytes_named(ctx, key, &data);
    }

    /// Members are stored sorted, so a member's index is its position in the
    /// sorted order, not the order the fixture lists them in.
    fn sorted_index(members: &[StoredMember], which: usize) -> usize {
        let mut sorted = members.to_vec();
        sorted.sort();
        sorted.iter().position(|m| *m == members[which]).unwrap()
    }

    fn pending_multikey_bytes(members: &[StoredMember]) -> Vec<u8> {
        let mut sorted = members.to_vec();
        sorted.sort();
        let encoded: Vec<Vec<u8>> = sorted.iter().map(|m| m.to_rlp()).collect();
        crate::bridge::serialization::rlp_encode_list(&encoded)
    }

    fn sorted_btc_key_rlp(members: &[StoredMember]) -> Vec<u8> {
        use crate::bridge::serialization::{rlp_encode_element, rlp_encode_list};
        let mut keys: Vec<[u8; 33]> = members.iter().map(|m| m.btc).collect();
        keys.sort();
        let items: Vec<Vec<u8>> = keys.iter().map(|k| rlp_encode_element(k)).collect();
        rlp_encode_list(&items)
    }

    /// rskj's `SolidityType.BytesType.encode` emits one zero word even for an
    /// empty array (`-1 / 32 == 0` → 1 word), so empty `bytes` returns are 96
    /// bytes, not 64. See `btc_chain::encode_abi_bytes` (mainnet #8,417,579).
    #[test]
    fn abi_encode_bytes_empty_is_96_bytes() {
        let out = abi_encode_bytes(&[]);
        assert_eq!(out.len(), 96);
        assert_eq!(out[31], 32); // offset
        assert!(out[32..].iter().all(|&b| b == 0));
    }

    #[test]
    fn abi_encode_bytes_nonempty_layout() {
        let out = abi_encode_bytes(&[0xAA; 33]);
        assert_eq!(out.len(), 64 + 64);
        assert_eq!(out[31], 32); // offset
        assert_eq!(out[63], 33); // length
        assert_eq!(out[64], 0xAA);
    }

    /// rskj `Sha256Hash.wrap(String)` decodes with Guava's lower-case base16
    /// and wants 32 bytes, so an upper-case or short hash throws: it is not
    /// read as a hash that was never processed.
    #[test]
    fn a_tx_hash_string_must_be_64_lower_case_hex_digits() {
        let mut ctx = ctx_at(1);
        let lower = "ab".repeat(32);
        let args = |s: &str| abi_encode_bytes(s.as_bytes());
        let out = is_btc_tx_hash_already_processed(&mut ctx, &args(&lower), 0).unwrap();
        assert_eq!(as_int(&out), 0);
        assert!(
            is_btc_tx_hash_already_processed(&mut ctx, &args(&lower.to_uppercase()), 0).is_err()
        );
        assert!(get_btc_tx_hash_processed_height(&mut ctx, &args("ab"), 0).is_err());
    }

    /// rskj's `IntType` reads an empty payload as zero, so an index-taking
    /// getter called with no arguments at all answers for index 0.
    #[test]
    fn no_arguments_is_index_zero() {
        let mut ctx = ctx_at(1);
        let empty = get_federator_public_key(&mut ctx, &[], 0, &mainnet(), &hardforks()).unwrap();
        let zero =
            get_federator_public_key(&mut ctx, &[0u8; 32], 0, &mainnet(), &hardforks()).unwrap();
        assert_eq!(empty.bytes, zero.bytes);
        assert_eq!(as_bytes(&empty).len(), 33);
    }

    #[test]
    fn a_hash_string_is_64_lower_case_hex_digits() {
        let lower = "00".repeat(31) + "ab";
        assert_eq!(sha256_hash_from_hex(&lower).map(|h| h[31]), Some(0xAB));
        assert_eq!(sha256_hash_from_hex(&lower.to_uppercase()), None);
        assert_eq!(sha256_hash_from_hex(&lower[2..]), None);
        assert_eq!(sha256_hash_from_hex(&("0".repeat(61) + "\u{FFFD}")), None);
    }
}
