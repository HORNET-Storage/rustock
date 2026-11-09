//! Bridge governance — federation voting, fee/whitelist/locking cap management.
//!
//! ## Federation lifecycle
//!
//! 1. `createFederation()` — creates a new pending federation (if none exists)
//! 2. `addFederatorPublicKey(bytes)` / `addFederatorPublicKeyMultikey(bytes,bytes,bytes)`
//!    — adds a member to the pending federation
//! 3. `commitFederation(bytes pendingHash)` — commits the pending federation
//!    as the new active federation, demoting the current one to retiring
//! 4. `rollbackFederation()` — discards the pending federation
//!
//! ## Other governance
//!
//! - `voteFeePerKbChange(int256)` — authorized vote on BTC fee per KB
//! - `addOneOffLockWhitelistAddress` / `addUnlimitedLockWhitelistAddress`
//!   / `removeLockWhitelistAddress` / `setLockWhitelistDisableBlockDelay`
//! - `increaseLockingCap(int256)` — increase the RBTC locking cap
//!
//! ## Lock whitelist
//!
//! The lock whitelist controls which BTC addresses can participate in peg-in.
//! Two whitelist variants:
//! - One-off: each address has a maximum transfer value and is removed after use.
//!   Stored under `lockWhitelist` key (pre and post-RSKIP87).
//! - Unlimited: no transfer limit. Stored under `unlimitedLockWhitelist` key (post-RSKIP87).
//!
//! Serialization matches rskj `BridgeSerializationUtils.serializeOneOffLockWhitelist`:
//!   RLP_list [ hash160_0, bigint(maxVal_0), ..., bigint(disableBlockHeight) ]

use alloy_primitives::{Bytes, U256};
use revm::context_interface::ContextTr;
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::federation::StoredMember;
use super::serialization;
use super::storage::*;

// ---------------------------------------------------------------------------
// BTC address ABI decoding helpers
// ---------------------------------------------------------------------------

/// The `string` argument at parameter slot `slot`, read as rskj's decoder
/// reads it: UTF-8 with bad sequences replaced, never refused for its
/// content. A payload that reaches a method has already decoded, so this
/// only fails for a caller that skipped the Bridge's argument check.
fn abi_decode_string_arg(args: &[u8], slot: usize) -> Result<String, PrecompileError> {
    crate::abi::Args::new(args)
        .string(slot)
        .ok_or_else(|| PrecompileError::other("governance: malformed string argument"))
}

/// Decode a BTC address string (Base58Check) to its 20-byte hash160, as
/// rskj's `Address.fromBase58(networkParameters, s)`: this network's P2PKH
/// or P2SH version byte, and nothing else.
fn btc_address_to_hash160(
    addr_str: &str,
    config: &super::constants::BridgeConstants,
) -> Result<[u8; 20], PrecompileError> {
    super::getters::parse_network_address_hash160(addr_str, config)
        .ok_or_else(|| PrecompileError::other("governance: not a BTC address of this network"))
}

/// The satoshis a one-off whitelist entry stores for `maxTransferValue`.
///
/// rskj takes `Coin.valueOf(maxTransferValue.longValueExact())`, which
/// throws for a value no long holds and keeps a negative one, and stores it
/// with `RLP.encodeBigInteger`, whose `asUnsignedByteArray` writes a negative
/// number's shortest two's-complement bytes. What the entry reads back as,
/// in rskj and here, is those bytes taken unsigned: -5 becomes 251.
fn one_off_max_transfer_value(max: &crate::abi::Int) -> Option<u64> {
    let value = max.long_value_exact()?;
    if value >= 0 {
        return Some(value as u64);
    }
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0 {
        start += 1;
    }
    Some(
        bytes[start..]
            .iter()
            .fold(0u64, |n, b| n << 8 | u64::from(*b)),
    )
}

// ---------------------------------------------------------------------------
// Storage key constants for governance
// ---------------------------------------------------------------------------

// Use the shared constants from storage.rs (LOCKING_CAP_KEY, FEE_PER_KB_KEY
// come in via the glob import above).

// ---------------------------------------------------------------------------
// Federation change methods
// ---------------------------------------------------------------------------

// Federation-change governance (rskj FederationSupportImpl
// .voteFederationChange): createFederation / addFederatorPublicKey /
// commitFederation / rollbackFederation are VOTES in an ABICallElection
// keyed by (function, args); only a MAJORITY of the federation-change
// authorizer keys executes the action. Mainnet block #648,926 carried the
// first winning commit.

const FEDERATION_ELECTION_KEY: &str = "federationElection";

fn federation_change_authorizers(
    config: &super::constants::BridgeConstants,
) -> Vec<alloy_primitives::Address> {
    config
        .federation_change_authorizer_keys
        .iter()
        .filter_map(|hex| {
            alloy_primitives::hex::decode(hex)
                .ok()
                .and_then(|k| super::federation::rsk_address_from_public_key(&k))
        })
        .collect()
}

/// `createFederation()` → int256
pub fn create_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let code = vote_federation_change(ctx, "create", vec![], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `addFederatorPublicKey(bytes key)` → int256 (pre-RSKIP123 only)
pub fn add_federator_public_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let Ok(pubkey) = decode_bytes_arg(args) else {
        return Ok(encode_int_result(gas_cost, -10));
    };
    let code = vote_federation_change(ctx, "add", vec![pubkey], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `addFederatorPublicKeyMultikey(bytes btcKey, bytes rskKey, bytes mstKey)`
/// → int256 (post-RSKIP123)
pub fn add_federator_public_key_multikey<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    // rskj Bridge.addFederatorPublicKeyMultikey passes the three RAW arg
    // byte arrays into the ABICallSpec (key parsing happens at vote-execution
    // time); the spec args are what the stored election serializes.
    let (Ok(btc_key), Ok(rsk_key), Ok(mst_key)) = (
        decode_bytes_arg_at(args, 0),
        decode_bytes_arg_at(args, 1),
        decode_bytes_arg_at(args, 2),
    ) else {
        return Ok(encode_int_result(gas_cost, -10));
    };
    let code = vote_federation_change(
        ctx,
        "add-multi",
        vec![btc_key, rsk_key, mst_key],
        config,
        hardfork_cfg,
        tx_ctx,
    );
    Ok(encode_int_result(gas_cost, code))
}

/// `commitFederation(bytes pendingHash)` → int256
pub fn commit_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let Ok(hash) = decode_bytes_arg(args) else {
        return Ok(encode_int_result(gas_cost, -10));
    };
    let code = vote_federation_change(ctx, "commit", vec![hash], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `rollbackFederation()` → int256
pub fn rollback_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let code = vote_federation_change(ctx, "rollback", vec![], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

fn vote_federation_change<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    function: &str,
    args: Vec<Vec<u8>>,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> i64 {
    let authorizers = federation_change_authorizers(config);
    if !authorizers.contains(&tx_ctx.rsk_sender) {
        return -10; // UNAUTHORIZED_CALLER
    }

    // Dry-run first; only register the vote when the call would succeed.
    let dry = execute_federation_change(ctx, function, &args, true, config, hardfork_cfg);
    if dry != 1 {
        return dry;
    }

    let spec = super::vote::AbiCallSpec::new(function, args.clone());
    let mut election = super::vote::Election::load(ctx, FEDERATION_ELECTION_KEY);
    if !election.vote(&spec, tx_ctx.rsk_sender) {
        return -10; // GENERIC_ERROR (duplicate vote)
    }

    let required = authorizers.len() / 2 + 1;
    let mut code = 1i64;
    if let Some(winner) = election.winner(required) {
        code = execute_federation_change(ctx, function, &args, false, config, hardfork_cfg);
        // create/commit/rollback clear the whole election inside the action;
        // clearWinners then removes the winning entry.
        if matches!(function, "create" | "commit" | "rollback") && code == 1 {
            election.clear();
        } else {
            election.remove(winner);
        }
    }
    election.store(ctx, FEDERATION_ELECTION_KEY);
    code
}

/// rskj FederationSupportImpl.executeVoteFederationChangeFunction.
fn execute_federation_change<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    function: &str,
    args: &[Vec<u8>],
    dry_run: bool,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> i64 {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let multikey = hardfork_cfg.has_rskip123(block_number);
    // FederationMember stores all keys COMPRESSED, however they were passed.
    let parse_key = |bytes: &[u8]| -> Option<[u8; 33]> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let parsed = k256::PublicKey::from_sec1_bytes(bytes).ok()?;
        parsed.to_encoded_point(true).as_bytes().try_into().ok()
    };
    match function {
        "create" => {
            if !bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
                return -1; // PENDING_FEDERATION_ALREADY_EXISTS
            }
            let new_fed = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
            let old_fed = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
            let age = federation_activation_age(config, hardfork_cfg, block_number);
            if let (Some(new), Some(_)) = (&new_fed, &old_fed) {
                if block_number < new.creation_block + age {
                    return -2; // EXISTING_FEDERATION_AWAITING_ACTIVATION
                }
                return -3; // RETIRING_FEDERATION_ALREADY_EXISTS
            }
            if dry_run {
                return 1;
            }
            store_pending_federation(ctx, Some(&[]), multikey);
            1
        }
        "add" | "add-multi" => {
            if function == "add" && multikey {
                return -10; // "add" disabled post-RSKIP123
            }
            let pending_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
            if pending_data.is_empty() {
                return -1; // FEDERATION_NON_EXISTENT
            }
            // BtcECKey/ECKey.fromPublicOnly failure -> BridgeIllegalArgumentException -> -10
            let member = if function == "add" {
                let Some(btc) = parse_key(&args[0]) else { return -10 };
                StoredMember::from_btc(btc)
            } else {
                let (Some(btc), Some(rsk), Some(mst)) = (
                    args.first().and_then(|k| parse_key(k)),
                    args.get(1).and_then(|k| parse_key(k)),
                    args.get(2).and_then(|k| parse_key(k)),
                ) else {
                    return -10;
                };
                StoredMember { btc, rsk, mst }
            };
            let mut members = deserialize_pending_federation(&pending_data);
            if members
                .iter()
                .any(|m| m.btc == member.btc || m.rsk == member.rsk || m.mst == member.mst)
            {
                return -2; // FEDERATOR_ALREADY_PRESENT
            }
            if dry_run {
                return 1;
            }
            members.push(member);
            store_pending_federation(ctx, Some(&members), multikey);
            1
        }
        "commit" => {
            let pending_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
            if pending_data.is_empty() {
                return -1; // FEDERATION_NON_EXISTENT
            }
            let members = deserialize_pending_federation(&pending_data);
            if members.len() < 2 {
                return -2; // INSUFFICIENT_MEMBERS
            }
            // PendingFederation.getHash: keccak over the sorted BTC keys RLP
            // (serializePendingFederationOnlyBtcKeys at every era).
            let pending_hash = {
                use sha3::{Digest, Keccak256};
                Keccak256::digest(serialize_pending_federation_btc_keys(&members))
            };
            if args[0] != pending_hash[..] {
                return -3; // PENDING_FEDERATION_MISMATCHED_HASH
            }
            if dry_run {
                return 1;
            }
            commit_pending_federation(ctx, &members, config, hardfork_cfg);
            1
        }
        "rollback" => {
            if bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
                return -1; // FEDERATION_NON_EXISTENT
            }
            if dry_run {
                return 1;
            }
            store_pending_federation(ctx, None, multikey);
            1
        }
        _ => -10, // NON_EXISTING_FUNCTION_CALLED
    }
}

/// rskj `FederationFormatVersion` for a federation built at `block_number`
/// (PendingFederation.buildFederation): 1000 standard multisig (pre-RSKIP201),
/// 2000 non-standard ERP (RSKIP201, !RSKIP353), 3000 P2SH-ERP (RSKIP353,
/// !RSKIP305), 4000 P2SH-P2WSH-ERP (RSKIP305).
pub(crate) fn federation_format_version(
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_number: u64,
) -> u64 {
    if !hardfork_cfg.has_rskip201(block_number) {
        1000
    } else if !hardfork_cfg.has_rskip353(block_number) {
        2000
    } else if !hardfork_cfg.has_rskip305(block_number) {
        3000
    } else {
        4000
    }
}

pub(crate) fn federation_activation_age(
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_number: u64,
) -> u64 {
    if hardfork_cfg.has_rskip383(block_number) {
        config.federation_activation_age
    } else {
        config.federation_activation_age_legacy
    }
}

/// rskj `FederationStorageProviderImpl.getNextFederationCreationBlockHeight`
/// (RSKIP186): the pending next-federation creation height, or `None` when the
/// cell is absent (`deserializeOptionalLong(null)`).
fn get_next_federation_creation_block_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
) -> Option<u64> {
    let data = bridge_load_bytes_named(ctx, NEXT_FEDERATION_CREATION_BLOCK_HEIGHT_KEY);
    if data.is_empty() {
        return None;
    }
    Some(rlp_decode_uint(&data).to::<u64>())
}

/// rskj `FederationSupportImpl.updateFederationCreationBlockHeights` (RSKIP186),
/// called every `updateCollections`. Once the new federation reaches its
/// activation age, promote the pending `nextFederationCreationBlockHeight` to
/// `activeFederationCreationBlockHeight` and clear the next cell. Fires exactly
/// once per federation change — on the first updateCollections at/after
/// `nextCreation + federationActivationAge` — and is receipts-invisible (pure
/// state). Without it the next/active cells fork from rskj at that block
/// (mainnet #4,671,284 for the #4,652,781 federation change).
pub(crate) fn update_federation_creation_block_heights<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_number: u64,
) {
    if !hardfork_cfg.has_rskip186(block_number) {
        return;
    }
    let Some(next_creation) = get_next_federation_creation_block_height(ctx) else {
        return;
    };
    let activation_age = federation_activation_age(config, hardfork_cfg, block_number);
    // newFederationShouldNotBeActiveYet
    if block_number < next_creation + activation_age {
        return;
    }
    // setActiveFederationCreationBlockHeight + clearNextFederationCreationBlockHeight.
    // serializeLong = RLP.encodeBigInteger(BigInteger.valueOf(..)) = rlp_encode_u64;
    // clearing saves null, which deletes the cell (empty value -> leaf removed).
    bridge_store_bytes_named(
        ctx,
        ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY,
        &serialization::rlp_encode_u64(next_creation),
    );
    bridge_store_bytes_named(ctx, NEXT_FEDERATION_CREATION_BLOCK_HEIGHT_KEY, &[]);
}

/// rskj `FederationSupportImpl.commitProposedFederation` (RSKIP419): once the
/// SVP spend transaction is registered, promote the proposed federation. This is
/// `handoverToNewFederation(proposedFederation)` — move the active fed's UTXOs to
/// the old set, store the active fed as old / the proposed fed as new (with their
/// format versions), and (RSKIP186) persist the retiring fed's P2SH script + the
/// new fed's creation block height — followed by `clearProposedFederation`. No
/// commit_federation event (it was already logged when the proposal was voted).
pub(crate) fn commit_proposed_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let Some(proposed) = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
    else {
        return;
    };
    let new_members = proposed.members.clone();
    let new_block = proposed.creation_block;
    let new_time = proposed.creation_time_millis;
    let new_format = federation_format_version(hardfork_cfg, new_block);

    // Current ACTIVE (= "new") federation becomes the old one (genesis if none).
    let active = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let (old_members, old_time, old_block) = match &active {
        Some(fed) => (fed.members.clone(), fed.creation_time_millis, fed.creation_block),
        None => (
            super::peg::genesis_federation_keys(config)
                .into_iter()
                .map(StoredMember::from_btc)
                .collect(),
            config.genesis_federation_creation_time_millis,
            1,
        ),
    };
    let old_keys: Vec<[u8; 33]> = old_members.iter().map(|m| m.btc).collect();
    let old_format = federation_format_version(hardfork_cfg, old_block);

    // moveUTXOsFromNewToOldFederation.
    let active_utxos = load_federation_utxos(ctx, hardfork_cfg, block_number);
    store_federation_utxos(ctx, hardfork_cfg, block_number, &[]);
    super::storage::store_old_federation_utxos(ctx, &active_utxos);

    // setOldAndNewFederations (always multikey post-RSKIP419).
    bridge_store_bytes_named(
        ctx,
        OLD_FEDERATION_FORMAT_VERSION_KEY,
        &serialization::rlp_encode_u64(old_format),
    );
    bridge_store_bytes_named(
        ctx,
        OLD_FEDERATION_KEY,
        &super::federation::serialize_federation_multikey(&old_members, old_time, old_block),
    );
    bridge_store_bytes_named(
        ctx,
        NEW_FEDERATION_FORMAT_VERSION_KEY,
        &serialization::rlp_encode_u64(new_format),
    );
    bridge_store_bytes_named(
        ctx,
        NEW_FEDERATION_KEY,
        &super::federation::serialize_federation_multikey(&new_members, new_time, new_block),
    );

    // RSKIP186: saveLastRetiredFederationScript (the retiring = old fed) +
    // setNextFederationCreationBlockHeight(proposed fed's creation block).
    if hardfork_cfg.has_rskip186(block_number) {
        let old_redeem = super::peg::build_committed_federation_redeem_script(
            &old_keys, config, hardfork_cfg, old_block,
        );
        let old_hash160 = super::peg::redeem_script_hash160_pub(&old_redeem);
        // RSKIP377: getDefaultP2SHScript() = getOutputScript(getDefaultRedeemScript())
        // — the *default* (standard multisig) redeem, wrapped P2SH-P2WSH for a
        // segwit (format ≥ 4000) federation and plain P2SH otherwise
        // (ErpFederation.getOutputScript). `federation_output_hash160` selects
        // the witness-program hash for ≥ 4000 and the plain hash below it.
        let members_hash160 = if hardfork_cfg.has_rskip377(block_number) && old_format >= 2000 {
            super::peg::federation_output_hash160(
                &super::peg::build_federation_redeem_script(&old_keys, old_keys.len() / 2 + 1),
                old_format,
            )
        } else {
            old_hash160
        };
        let last_retired_script = super::peg::p2sh_output_script_program(&members_hash160);
        bridge_store_bytes_named(
            ctx,
            LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY,
            &serialization::rlp_encode_list(&[serialization::rlp_encode_element(
                &last_retired_script,
            )]),
        );
        bridge_store_bytes_named(
            ctx,
            NEXT_FEDERATION_CREATION_BLOCK_HEIGHT_KEY,
            &serialization::rlp_encode_u64(new_block),
        );
    }

    // clearProposedFederation.
    bridge_store_bytes_named(ctx, PROPOSED_FEDERATION_KEY, &[]);
    bridge_store_bytes_named(ctx, PROPOSED_FEDERATION_FORMAT_VERSION_KEY, &[]);
}

/// rskj `commitPendingFederationAccordingToActivations`: build the federation
/// from the pending keys, wipe the pending federation, and log the
/// commit_federation event. Pre-RSKIP419 (`legacyCommitPendingFederation`) this
/// immediately hands over to the new federation (moves the active fed's UTXOs to
/// the old set, stores active as old / built as new, persists the retiring P2SH +
/// next creation height). From RSKIP419 (`commitPendingFederation`) it instead
/// stores a *proposed* federation that must pass the SVP before being promoted
/// by `commit_proposed_federation`; the existing federations are left untouched.
fn commit_pending_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    pending_members: &[StoredMember],
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) {
    use revm::context_interface::Block as _;
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let timestamp = ctx.block().timestamp().to::<u64>();
    let multikey = hardfork_cfg.has_rskip123(block_number);

    // Built federation: the pending members, creation block = this block.
    let mut new_keys: Vec<[u8; 33]> = pending_members.iter().map(|m| m.btc).collect();
    new_keys.sort();

    // Current ACTIVE federation (= "new") is the one being retired (genesis
    // when none). Loaded BEFORE any rotation so the event/last-retired data is
    // the pre-handover active fed in both paths.
    let active = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let (old_members, old_time, old_block) = match &active {
        Some(fed) => (fed.members.clone(), fed.creation_time_millis, fed.creation_block),
        None => (
            super::peg::genesis_federation_keys(config)
                .into_iter()
                .map(StoredMember::from_btc)
                .collect(),
            config.genesis_federation_creation_time_millis,
            1,
        ),
    };
    let old_keys: Vec<[u8; 33]> = old_members.iter().map(|m| m.btc).collect();

    // Format version encodes the federation TYPE (FederationFormatVersion):
    // 1000 standard multisig, 2000 non-standard ERP, 3000 P2SH-ERP, 4000
    // P2SH-P2WSH-ERP. The old fed's type is fixed by its creation block; the
    // built fed's by this block.
    let old_format = federation_format_version(hardfork_cfg, old_block);
    let new_format = federation_format_version(hardfork_cfg, block_number);

    // Redeem scripts / hash160s: needed for the commit_federation event in BOTH
    // paths, and for the retiring fed's lastRetiredFederationP2SHScript in the
    // legacy handover. The retiring fed's redeem is rebuilt as the type it was
    // CREATED with (keyed on its creation block); the built fed's by THIS
    // block's activations (rskj PendingFederation.buildFederation).
    let old_redeem = super::peg::build_committed_federation_redeem_script(
        &old_keys, config, hardfork_cfg, old_block,
    );
    let new_redeem = super::peg::build_committed_federation_redeem_script(
        &new_keys, config, hardfork_cfg, block_number,
    );
    // The address hash160 is format-aware: a P2SH-P2WSH (format 4000, RSKIP305)
    // federation hashes its P2WSH witness program, not the redeem directly.
    let old_hash160 = super::peg::federation_output_hash160(&old_redeem, old_format);
    let new_hash160 = super::peg::federation_output_hash160(&new_redeem, new_format);

    if hardfork_cfg.has_rskip419(block_number) {
        // RSKIP419: commitFederation no longer rotates the federations; it
        // stores a PROPOSED federation (always multikey post-RSKIP123) that must
        // pass the SVP before commit_proposed_federation promotes it. The active
        // and retiring federations and their UTXOs are left untouched.
        // getFederationCreationTime switches Instant.ofEpochMilli ->
        // ofEpochSecond, so the stored creation-time (millis) is timestamp*1000.
        let creation_time_millis = timestamp.saturating_mul(1000);
        bridge_store_bytes_named(
            ctx,
            PROPOSED_FEDERATION_FORMAT_VERSION_KEY,
            &serialization::rlp_encode_u64(new_format),
        );
        bridge_store_bytes_named(
            ctx,
            PROPOSED_FEDERATION_KEY,
            &super::federation::serialize_federation_multikey(
                pending_members,
                creation_time_millis,
                block_number,
            ),
        );
        store_pending_federation(ctx, None, multikey);
    } else {
        // Legacy handover. Move active-federation UTXOs to the old set.
        let active_utxos = load_federation_utxos(ctx, hardfork_cfg, block_number);
        store_federation_utxos(ctx, hardfork_cfg, block_number, &[]);
        super::storage::store_old_federation_utxos(ctx, &active_utxos);

        // rskj saveOldFederation/saveNewFederation: post-RSKIP123 store the
        // multikey member format plus format-version cells; pre-123 only-btc.
        if multikey {
            bridge_store_bytes_named(
                ctx,
                OLD_FEDERATION_FORMAT_VERSION_KEY,
                &serialization::rlp_encode_u64(old_format),
            );
            bridge_store_bytes_named(
                ctx,
                OLD_FEDERATION_KEY,
                &super::federation::serialize_federation_multikey(&old_members, old_time, old_block),
            );
            bridge_store_bytes_named(
                ctx,
                NEW_FEDERATION_FORMAT_VERSION_KEY,
                &serialization::rlp_encode_u64(new_format),
            );
            bridge_store_bytes_named(
                ctx,
                NEW_FEDERATION_KEY,
                &super::federation::serialize_federation_multikey(
                    pending_members,
                    timestamp,
                    block_number,
                ),
            );
        } else {
            bridge_store_bytes_named(
                ctx,
                OLD_FEDERATION_KEY,
                &super::federation::serialize_federation_only_btc_keys(
                    &old_keys, old_time, old_block,
                ),
            );
            bridge_store_bytes_named(
                ctx,
                NEW_FEDERATION_KEY,
                &super::federation::serialize_federation_only_btc_keys(
                    &new_keys,
                    timestamp,
                    block_number,
                ),
            );
        }
        store_pending_federation(ctx, None, multikey);

        // rskj handoverToNewFederation (RSKIP186): persist the retiring fed's
        // members P2SH script + the new fed's creation block height. After
        // setOldAndNewFederations, getActiveFederation() still resolves to the
        // OLD (retiring) fed (the new fed's age 0 is below the activation age),
        // so lastRetiredFederationP2SHScript is the OLD fed's P2SH script. For a
        // standard multisig the members P2SH script equals its P2SH output
        // script; for an ERP fed it is the full ERP P2SH before RSKIP377 and the
        // *default* (standard multisig branch) P2SH from RSKIP377 on.
        if hardfork_cfg.has_rskip186(block_number) {
            // RSKIP377: P2SH-P2WSH-wrap the default redeem for a segwit (format ≥
            // 4000) federation (ErpFederation.getDefaultP2SHScript →
            // getOutputScript); `federation_output_hash160` picks the witness-
            // program hash for ≥ 4000 and the plain hash below it.
            let members_hash160 =
                if hardfork_cfg.has_rskip377(block_number) && old_format >= 2000 {
                    super::peg::federation_output_hash160(
                        &super::peg::build_federation_redeem_script(
                            &old_keys,
                            old_keys.len() / 2 + 1,
                        ),
                        old_format,
                    )
                } else {
                    old_hash160
                };
            let last_retired_script = super::peg::p2sh_output_script_program(&members_hash160);
            bridge_store_bytes_named(
                ctx,
                LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY,
                &serialization::rlp_encode_list(&[serialization::rlp_encode_element(
                    &last_retired_script,
                )]),
            );
            bridge_store_bytes_named(
                ctx,
                NEXT_FEDERATION_CREATION_BLOCK_HEIGHT_KEY,
                &serialization::rlp_encode_u64(block_number),
            );
        }
    }

    // commit_federation event (identical in both paths: retiring = active fed,
    // voted = built/proposed fed). Solidity format from RSKIP146, legacy before.
    let activation =
        block_number + federation_activation_age(config, hardfork_cfg, block_number);
    if hardfork_cfg.has_rskip146(block_number) {
        super::events::log_solidity_commit_federation(
            ctx,
            &old_keys,
            &p2sh_base58_address(&old_hash160, config),
            &new_keys,
            &p2sh_base58_address(&new_hash160, config),
            activation,
        );
    } else {
        super::events::log_legacy_commit_federation(
            ctx,
            &old_hash160,
            &old_keys,
            &new_hash160,
            &new_keys,
            activation,
        );
    }
}

/// Base58Check P2SH address string for a script hash (rskj
/// `Address.toBase58`; mainnet version 0x05, testnet/regtest 0xc4).
pub(crate) fn p2sh_base58_address(hash160: &[u8; 20], config: &super::constants::BridgeConstants) -> String {
    let version: u8 = match config.btc_network {
        super::constants::BtcNetwork::Mainnet => 5,
        _ => 196,
    };
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(hash160);
    bitcoin::base58::encode_check(&payload)
}

// ---------------------------------------------------------------------------
// Fee per KB voting
// ---------------------------------------------------------------------------

/// `voteFeePerKbChange(int256 feePerKb)` → int256
///
/// Authorized vote to change the BTC fee per KB for peg-out transactions.
///
/// rskj FeePerKbSupportImpl.voteFeePerKbChange: votes accumulate in an
/// ABICallElection stored under `feePerKbElection`; the fee only changes
/// when a MAJORITY of the authorizer keys vote the same value, after which
/// the election is cleared.
/// Returns 1 successful vote/winner, -1 negative fee or duplicate vote,
/// -2 fee above maximum, -10 unauthorized.
pub fn vote_fee_per_kb_change<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    // rskj `Bridge.voteFeePerKbChange` takes `Coin.valueOf(longValueExact())`
    // before anything else, and a value no long holds is GENERIC_ERROR: -10,
    // the same code an unauthorized caller gets.
    let Some(fee) = crate::abi::Args::new(args)
        .int(0)
        .and_then(|fee| fee.long_value_exact())
    else {
        return Ok(encode_int_result(gas_cost, -10));
    };

    let authorizers: Vec<alloy_primitives::Address> = config
        .fee_per_kb_authorizer_keys
        .iter()
        .filter_map(|hex| {
            alloy_primitives::hex::decode(hex)
                .ok()
                .and_then(|k| super::federation::rsk_address_from_public_key(&k))
        })
        .collect();
    let sender = tx_ctx.rsk_sender;
    if !authorizers.contains(&sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    // FeePerKbSupportImpl: `!feePerKb.isPositive()` is NEGATIVE_FEE_VOTED (-1),
    // and a fee above the maximum EXCESSIVE_FEE_VOTED (-2).
    let Ok(fee_satoshis) = u64::try_from(fee) else {
        return Ok(encode_int_result(gas_cost, -1));
    };
    if fee_satoshis == 0 {
        return Ok(encode_int_result(gas_cost, -1));
    }
    if fee_satoshis > config.max_fee_per_kb {
        return Ok(encode_int_result(gas_cost, -2));
    }

    // MAJORITY of the authorizer set must vote the same value. Entries are
    // keyed by the RLP-ENCODED coin (serializeCoin) bytes, like rskj's
    // ABICallSpec arguments.
    let required = authorizers.len() / 2 + 1;
    let coin_encoded = serialization::rlp_encode_u64(fee_satoshis);
    let mut election = load_fee_per_kb_election(ctx);
    let entry = election
        .iter_mut()
        .find(|(value, _)| *value == coin_encoded);
    let voters = match entry {
        Some((_, voters)) => voters,
        None => {
            election.push((coin_encoded, Vec::new()));
            &mut election.last_mut().expect("just pushed").1
        }
    };
    if voters.contains(&sender) {
        return Ok(encode_int_result(gas_cost, -1)); // duplicate vote
    }
    voters.push(sender);

    if voters.len() >= required {
        // rskj setFeePerKb: serializeCoin (RLP).
        bridge_store_u256(ctx, FEE_PER_KB_KEY, U256::from(fee_satoshis));
        store_fee_per_kb_election(ctx, &[]);
    } else {
        store_fee_per_kb_election(ctx, &election);
    }

    Ok(encode_int_result(gas_cost, 1))
}

const FEE_PER_KB_ELECTION_KEY: &str = "feePerKbElection";

/// rskj BridgeSerializationUtils.serializeElection for the feePerKb
/// election: RLP list of (ABICallSpec, voters) pairs sorted by the
/// serialized spec bytes. The spec is
/// `RLP[ "setFeePerKb", RLP[ rlp(serializeCoin(fee)) ] ]` and the voters a
/// sorted RLP list of 20-byte addresses.
fn serialize_fee_per_kb_spec(coin_encoded: &[u8]) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list};
    let args = rlp_encode_list(&[rlp_encode_element(coin_encoded)]);
    rlp_encode_list(&[rlp_encode_element(b"setFeePerKb"), args])
}

fn store_fee_per_kb_election<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    election: &[(Vec<u8>, Vec<alloy_primitives::Address>)],
) {
    use super::serialization::{rlp_encode_element, rlp_encode_list};
    // rskj sorts by ABICallSpec.byBytesComparator: SIGNED-byte order of
    // getEncoded() = "setFeePerKb" || serializeCoin(fee).
    let mut entries: Vec<(Vec<u8>, Vec<u8>, &Vec<alloy_primitives::Address>)> = election
        .iter()
        .map(|(coin, voters)| {
            let mut encoded = b"setFeePerKb".to_vec();
            encoded.extend_from_slice(coin);
            (encoded, serialize_fee_per_kb_spec(coin), voters)
        })
        .collect();
    entries.sort_by(|a, b| super::vote::signed_bytes_cmp(&a.0, &b.0));

    let mut items = Vec::with_capacity(entries.len() * 2);
    for (_, spec, voters) in entries {
        items.push(spec);
        let mut sorted: Vec<&alloy_primitives::Address> = voters.iter().collect();
        sorted.sort();
        let voter_items: Vec<Vec<u8>> = sorted
            .iter()
            .map(|v| rlp_encode_element(v.as_slice()))
            .collect();
        items.push(rlp_encode_list(&voter_items));
    }
    let data = rlp_encode_list(&items);
    bridge_store_bytes_named(ctx, FEE_PER_KB_ELECTION_KEY, &data);
}

fn load_fee_per_kb_election<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
) -> Vec<(Vec<u8>, Vec<alloy_primitives::Address>)> {
    use super::serialization::rlp_decode_list;
    let data = bridge_load_bytes_named(ctx, FEE_PER_KB_ELECTION_KEY);
    if data.is_empty() {
        return Vec::new();
    }
    let Some(items) = rlp_decode_list(&data) else {
        return Vec::new();
    };
    let mut election = Vec::new();
    let mut i = 0;
    while i + 1 < items.len() {
        // spec: RLP[function, RLP[args]]; the argument is kept as the
        // RLP-encoded coin bytes (rskj compares raw spec arguments).
        let coin = rlp_decode_list(&items[i])
            .filter(|spec| spec.len() == 2 && spec[0] == b"setFeePerKb")
            .and_then(|spec| rlp_decode_list(&spec[1]))
            .and_then(|args| args.first().cloned());
        let voters = rlp_decode_list(&items[i + 1])
            .map(|vs| {
                vs.into_iter()
                    .filter(|v| v.len() == 20)
                    .map(|v| alloy_primitives::Address::from_slice(&v))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(coin) = coin {
            election.push((coin, voters));
        }
        i += 2;
    }
    election
}

// ---------------------------------------------------------------------------
// Locking cap
// ---------------------------------------------------------------------------

/// `increaseLockingCap(int256 newCap)` → bool
///
/// rskj `Bridge.increaseLockingCap` + `BridgeSupport.increaseLockingCap`:
/// a non-positive or over-long value throws BridgeIllegalArgumentException;
/// the sender must match an increase-locking-cap authorizer key (minimum
/// ONE); the new cap may not be below the current one (equal is allowed)
/// nor above current × lockingCapIncrementsMultiplier. Reading the current
/// cap lazily initializes it (getLockingCap), so a failed bound check still
/// persists the initial value — but a failed authorizer check does not.
pub fn increase_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    // int256 satoshis; rskj getCoinFromBigInteger (longValueExact) and the
    // <= 0 check both end in BridgeIllegalArgumentException, before the
    // authorizer is looked at.
    let new_cap = crate::abi::Args::new(args)
        .int(0)
        .and_then(|cap| cap.long_value_exact())
        .and_then(|cap| u64::try_from(cap).ok())
        .filter(|cap| *cap > 0)
        .ok_or_else(|| PrecompileError::other("increaseLockingCap: invalid value"))?;

    let authorized = config.increase_locking_cap_authorizer_keys.iter().any(|hex| {
        alloy_primitives::hex::decode(hex)
            .ok()
            .and_then(|k| super::federation::rsk_address_from_public_key(&k))
            .is_some_and(|a| a == tx_ctx.rsk_sender)
    });
    let mut output = [0u8; 32];
    if !authorized {
        return Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()));
    }

    let current_cap = super::peg::get_or_init_locking_cap(ctx, config);
    if new_cap < current_cap
        || new_cap > current_cap.saturating_mul(config.locking_cap_increments_multiplier)
    {
        return Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()));
    }

    // rskj setLockingCap: serializeCoin (RLP).
    bridge_store_u256(ctx, LOCKING_CAP_KEY, U256::from(new_cap));

    output[31] = 1; // true
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Whitelist management
// ---------------------------------------------------------------------------

/// `addLockWhitelistAddress(string address, int256 maxTransferValue)` → int256
///
/// Legacy alias for `addOneOffLockWhitelistAddress` (per rskj BridgeMethods.java).
/// Adds a one-off entry with the given max transfer value.
///
/// Returns:
///   1  = success
///  -1  = address already in whitelist
///  -2  = invalid address
pub fn add_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    add_one_off_lock_whitelist_address(ctx, args, gas_cost, config, hardfork_cfg, tx_ctx)
}

/// rskj AddressBasedAuthorizer (minimum ONE): the tx sender must be the RSK
/// address of one of the whitelist-change authorizer keys.
fn is_whitelist_change_authorized(
    config: &super::constants::BridgeConstants,
    sender: alloy_primitives::Address,
) -> bool {
    config.whitelist_authorizer_keys.iter().any(|hex| {
        alloy_primitives::hex::decode(hex)
            .ok()
            .and_then(|k| super::federation::rsk_address_from_public_key(&k))
            .is_some_and(|a| a == sender)
    })
}

/// `addOneOffLockWhitelistAddress(string address, int256 maxTransferValue)` → int256
///
/// Adds a one-off entry to the lock whitelist.
/// The entry allows one peg-in up to `maxTransferValue` satoshis.
///
/// Returns:
///   1  = success
///  -1  = address already in whitelist
///  -2  = invalid address
pub fn add_one_off_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let addr_str = match abi_decode_string_arg(args, 0) {
        Ok(s) => s,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    // WhitelistSupportImpl.addOneOffLockWhitelistAddress parses the address
    // (INVALID_ADDRESS_FORMAT, -2), then the value, whose `longValueExact`
    // throws, and only then asks whether the caller may change the list.
    let hash160 = match btc_address_to_hash160(&addr_str, config) {
        Ok(h) => h,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    let max_val = crate::abi::Args::new(args)
        .int(1)
        .as_ref()
        .and_then(one_off_max_transfer_value)
        .ok_or_else(|| {
            PrecompileError::other("addOneOffLockWhitelistAddress: the value is not a long")
        })?;

    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    // rskj reads the whitelist from here on, so it writes it back however the
    // call ends.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let mut whitelist = LockWhitelist::load(ctx, hardfork_cfg.has_rskip87(block_number));
    let code = if whitelist.contains(&hash160) {
        -1
    } else {
        whitelist.one_off.push((hash160, max_val));
        1
    };
    whitelist.save(ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `addUnlimitedLockWhitelistAddress(string address)` → int256
///
/// Adds an unlimited entry to the lock whitelist (active post-RSKIP87).
/// Unlimited entries have no transfer cap and are never consumed.
///
/// Returns:
///   1  = success
///  -1  = address already in unlimited whitelist
///  -2  = invalid address
pub fn add_unlimited_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let addr_str = match abi_decode_string_arg(args, 0) {
        Ok(s) => s,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    let hash160 = match btc_address_to_hash160(&addr_str, config) {
        Ok(h) => h,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    // rskj reads the whitelist from here on, so it writes it back however the
    // call ends.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let mut whitelist = LockWhitelist::load(ctx, hardfork_cfg.has_rskip87(block_number));
    let code = if whitelist.contains(&hash160) {
        -1
    } else {
        whitelist.unlimited.push(hash160);
        1
    };
    whitelist.save(ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `removeLockWhitelistAddress(string address)` → int256
///
/// Removes an address from either the one-off or unlimited lock whitelist.
///
/// Returns:
///   1  = success
///  -1  = address not found
///  -2  = invalid address
pub fn remove_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    let addr_str = match abi_decode_string_arg(args, 0) {
        Ok(s) => s,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    // rskj reads the whitelist before it parses the address, so it writes it
    // back however the call ends, for an address that doesn't parse too.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let mut whitelist = LockWhitelist::load(ctx, hardfork_cfg.has_rskip87(block_number));
    let code = match btc_address_to_hash160(&addr_str, config) {
        Err(_) => -2,
        Ok(hash160) if whitelist.remove(&hash160) => 1,
        Ok(_) => -1,
    };
    whitelist.save(ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `setLockWhitelistDisableBlockDelay(int256 delay)` → int256
///
/// rskj WhitelistSupportImpl: sets the whitelist disable height to the BTC
/// best-chain height plus the delay, inside the one-off whitelist blob.
/// Returns 1 success, -1 delay already set, -2 invalid delay,
/// -10 unauthorized.
pub fn set_lock_whitelist_disable_block_delay<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    use_v2: bool,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    // rskj `BridgeSupport.setLockWhitelistDisableBlockDelay` reads the BTC
    // chain's height before anything asks who is calling, and seeds the chain
    // where nothing has yet (`ensureBtcBlockStore`), whoever calls.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);
    let best_height = super::btc_store::load_chain_head(ctx)
        .map(|h| h.height as i32)
        .unwrap_or(0);

    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    // rskj reads the whitelist from here on, so it writes it back however the
    // call ends but a throw.
    let mut whitelist = LockWhitelist::load(ctx, hardfork_cfg.has_rskip87(block_number));
    let code = if whitelist.disable_height < i32::MAX {
        -1 // delay already set
    } else {
        // rskj `disableBlockDelayBI.intValueExact()`: a delay no int holds
        // throws. The sum is Java int arithmetic, so one that wraps is not
        // above the height either.
        let delay = crate::abi::Args::new(args)
            .int(0)
            .and_then(|delay| delay.int_value_exact())
            .ok_or_else(|| {
                PrecompileError::other("setLockWhitelistDisableBlockDelay: the delay is not an int")
            })?;
        if delay.wrapping_add(best_height) <= best_height {
            -2 // invalid delay
        } else {
            whitelist.disable_height = best_height.wrapping_add(delay);
            1
        }
    };
    whitelist.save(ctx);
    Ok(encode_int_result(gas_cost, code))
}

// ---------------------------------------------------------------------------
// Read-only governance methods
// ---------------------------------------------------------------------------

/// `getActivePowpegRedeemScript()` → bytes
pub fn get_active_powpeg_redeem_script<CTX: crate::RskContextTr>(
    _ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Return empty bytes (no federation configured yet)
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// `getActiveFederationCreationBlockHeight()` → uint256
pub fn get_active_federation_creation_block_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = bridge_load_u256(ctx, ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY);
    let output = val.to_be_bytes::<32>();
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Federation RLP serialization (matching BridgeSerializationUtils)
// ---------------------------------------------------------------------------

/// rskj `BridgeSerializationUtils.serializeBtcPublicKeys`: sorted compressed
/// BTC keys as RLP elements. This is the legacy (pre-RSKIP123) pending
/// federation format AND the preimage of `PendingFederation.getHash()` at
/// every era (the hash a commit vote must match).
pub(crate) fn pending_federation_hash(members: &[StoredMember]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(serialize_pending_federation_btc_keys(members)).into()
}

fn serialize_pending_federation_btc_keys(members: &[StoredMember]) -> Vec<u8> {
    let mut keys: Vec<[u8; 33]> = members.iter().map(|m| m.btc).collect();
    keys.sort();
    let encoded_keys: Vec<Vec<u8>> = keys
        .iter()
        .map(|k| serialization::rlp_encode_element(k))
        .collect();
    serialization::rlp_encode_list(&encoded_keys)
}

/// rskj `BridgeSerializationUtils.serializePendingFederation` (post-RSKIP123):
/// sorted members, each `RLP[btc, rsk, mst]` embedded directly in the outer
/// list — NOT wrapped as an RLP element, unlike the Federation serialization.
fn serialize_pending_federation_multikey(members: &[StoredMember]) -> Vec<u8> {
    let mut sorted = members.to_vec();
    sorted.sort();
    let encoded: Vec<Vec<u8>> = sorted.iter().map(|m| m.to_rlp()).collect();
    serialization::rlp_encode_list(&encoded)
}

/// Deserialize a pending federation from either stored shape (see
/// `StoredMember::from_stored`).
fn deserialize_pending_federation(data: &[u8]) -> Vec<StoredMember> {
    serialization::rlp_decode_list(data)
        .unwrap_or_default()
        .iter()
        .filter_map(|m| StoredMember::from_stored(m))
        .collect()
}

/// rskj `BridgeStorageProvider.savePendingFederation`: once RSKIP123 is
/// active, EVERY save also writes the format-version cell
/// (`pendingFederationFormatVersion` = RLP(1000)) — including the saves that
/// clear the pending federation (commit/rollback store null, which deletes
/// the data cell but still writes the version cell).
fn store_pending_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    members: Option<&[StoredMember]>,
    multikey: bool,
) {
    if multikey {
        bridge_store_bytes_named(
            ctx,
            PENDING_FEDERATION_FORMAT_VERSION_KEY,
            &serialization::rlp_encode_u64(1000),
        );
    }
    let data = members.map_or_else(Vec::new, |m| {
        if multikey {
            serialize_pending_federation_multikey(m)
        } else {
            serialize_pending_federation_btc_keys(m)
        }
    });
    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &data);
}


/// Decode a single `bytes` ABI argument from calldata.
fn decode_bytes_arg(args: &[u8]) -> Result<Vec<u8>, PrecompileError> {
    decode_bytes_arg_at(args, 0)
}

/// Decode the `index`-th `bytes` ABI argument, as rskj's decoder does.
fn decode_bytes_arg_at(args: &[u8], index: usize) -> Result<Vec<u8>, PrecompileError> {
    crate::abi::Args::new(args)
        .bytes(index)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| PrecompileError::other("bytes arg: malformed"))
}

pub(crate) fn encode_int_result(gas_cost: u64, value: i64) -> PrecompileOutput {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    PrecompileOutput::new(gas_cost, output.to_vec().into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_int_success() {
        let out = encode_int_result(0, 1);
        assert_eq!(out.bytes[31], 1);
    }

    #[test]
    fn encode_int_error() {
        let out = encode_int_result(0, -1);
        assert!(out.bytes.iter().all(|&b| b == 0xFF));
    }

    // -----------------------------------------------------------------------
    // Federation serialization tests — ported from rskj
    // BridgeSerializationUtilsTest.serializeAndDeserializeFederationOnlyBtcKeys
    // -----------------------------------------------------------------------

    /// Ported from rskj: pending federation roundtrip (legacy btc-keys list).
    #[test]
    fn rskj_pending_federation_roundtrip() {
        let members: Vec<StoredMember> = [[0x02u8; 33], [0x03; 33], [0x04; 33]]
            .into_iter()
            .map(StoredMember::from_btc)
            .collect();

        let encoded = serialize_pending_federation_btc_keys(&members);
        let decoded = deserialize_pending_federation(&encoded);
        assert_eq!(decoded, members);
    }

    /// Ported from rskj: empty pending federation (both formats serialize to
    /// the empty RLP list, 0xc0).
    #[test]
    fn rskj_pending_federation_empty() {
        assert_eq!(serialize_pending_federation_btc_keys(&[]), vec![0xc0]);
        assert_eq!(serialize_pending_federation_multikey(&[]), vec![0xc0]);
        assert!(deserialize_pending_federation(&[0xc0]).is_empty());
    }

    /// rskj BridgeSerializationUtils.serializePendingFederation: members
    /// sorted by BTC_RSK_MST_PUBKEYS_COMPARATOR, each `RLP[btc, rsk, mst]`
    /// embedded DIRECTLY in the outer list (no element wrap, unlike the
    /// Federation serialization).
    #[test]
    fn pending_federation_multikey_format() {
        let m1 = StoredMember { btc: [0x03; 33], rsk: [0x02; 33], mst: [0x02; 33] };
        let m2 = StoredMember { btc: [0x02; 33], rsk: [0x03; 33], mst: [0x02; 33] };

        let encoded = serialize_pending_federation_multikey(&[m1, m2]);
        // Each member: 0xf8 0x66 (list, 102 bytes) + 3 × (0xa1 + 33 bytes).
        let member = |m: &StoredMember| {
            let mut v = vec![0xf8, 0x66];
            for k in [m.btc, m.rsk, m.mst] {
                v.push(0xa1);
                v.extend_from_slice(&k);
            }
            v
        };
        // Sorted: m2 (btc 0x02..) before m1 (btc 0x03..). Payload is
        // 2 × 104 = 208 bytes -> long-list header 0xf8 0xd0.
        let mut expected = vec![0xf8, 0xd0];
        expected.extend(member(&m2));
        expected.extend(member(&m1));
        assert_eq!(encoded, expected);
        assert_eq!(deserialize_pending_federation(&encoded), vec![m2, m1]);
    }

    /// The format-version cell value: rskj serializeInteger(1000) =
    /// RLP 0x8203e8 — the exact leaf mainnet #2,132,960 writes on
    /// createFederation (pendingFederationFormatVersion).
    #[test]
    fn federation_format_version_cell_encoding() {
        assert_eq!(serialization::rlp_encode_u64(1000), vec![0x82, 0x03, 0xe8]);
    }

    /// PendingFederation.getHash is keccak over the SORTED BTC-KEYS
    /// serialization at every era — even post-RSKIP123 when the stored
    /// pending federation uses the multikey format.
    #[test]
    fn pending_federation_hash_uses_btc_keys_serialization() {
        use sha3::{Digest, Keccak256};
        let m1 = StoredMember { btc: [0x03; 33], rsk: [0x05; 33], mst: [0x06; 33] };
        let m2 = StoredMember { btc: [0x02; 33], rsk: [0x07; 33], mst: [0x08; 33] };
        let hash = Keccak256::digest(serialize_pending_federation_btc_keys(&[m1, m2]));
        // Same hash regardless of rsk/mst keys and member order.
        let m1b = StoredMember { btc: [0x03; 33], rsk: [0x09; 33], mst: [0x0a; 33] };
        let hash2 = Keccak256::digest(serialize_pending_federation_btc_keys(&[m2, m1b]));
        assert_eq!(hash, hash2);
    }

    /// Ported from rskj: committed federation roundtrip with known values.
    /// Matches BridgeSerializationUtilsTest pattern: 6 keys, creation_time=5000,
/// rskj serializeFederationOnlyBtcKeys layout:
    /// RLP[creationTime(millis), creationBlockNumber, RLP[keys...]] with
    /// keys sorted lexicographically.
    #[test]
    fn rskj_federation_only_btc_keys_roundtrip() {
        let mut keys: Vec<[u8; 33]> = (100u8..106).map(|i| [i; 33]).collect();
        keys.reverse(); // serializer must sort

        let encoded =
            super::super::federation::serialize_federation_only_btc_keys(&keys, 5000, 42);
        let decoded = serialization::rlp_decode_list(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(serialization::rlp_decode_u64(&decoded[0]), 5000);
        assert_eq!(serialization::rlp_decode_u64(&decoded[1]), 42);
        let decoded_keys = serialization::rlp_decode_list(&decoded[2]).unwrap();
        assert_eq!(decoded_keys.len(), 6);
        assert_eq!(decoded_keys[0], vec![100u8; 33], "keys sorted");
    }

    /// RSKIP186 federation-creation-height promotion threshold, groundtruthed
    /// against mainnet #4,671,284 (the #4,652,781 federation change). Pre-RSKIP383
    /// (fingerroot500) the federation activation age is the legacy 18,500, so the
    /// `nextFederationCreationBlockHeight` (= the commit block #4,652,781) is
    /// promoted to `activeFederationCreationBlockHeight` on the first
    /// updateCollections at/after 4,652,781 + 18,500 = #4,671,281 — which is
    /// #4,671,284. `updateFederationCreationBlockHeights` matches there byte-for-byte.
    #[test]
    fn federation_creation_height_promotion_threshold_4671284() {
        let cfg = super::super::constants::BridgeConstants::mainnet();
        let hf = crate::hardfork::RskHardforkConfig::mainnet();
        let next_creation = 4_652_781u64;

        // Pre-fingerroot500 the legacy activation age (18,500) is in effect.
        assert!(!hf.has_rskip383(4_671_284));
        assert_eq!(federation_activation_age(&cfg, &hf, 4_671_284), 18_500);

        let threshold = next_creation + federation_activation_age(&cfg, &hf, 4_671_284);
        assert_eq!(threshold, 4_671_281);
        // The divergence block is the first updateCollections at/after the threshold.
        assert!(4_671_284 >= threshold);
        assert!(4_671_280 < threshold);

        // The promoted active-height cell encodes as serializeLong = RLP bigint.
        assert_eq!(serialization::rlp_encode_u64(next_creation), vec![0x83, 0x46, 0xfe, 0xed]);
    }

    /// rskj `addOneOffLockWhitelistAddress` parses the address first, -2 where
    /// it does not parse, then reads the value with `longValueExact`, which
    /// throws for one beyond a Java long -- all before the sender is checked.
    #[test]
    fn a_one_off_value_beyond_a_long_throws_before_the_sender_check() {
        use crate::abi::encode::{self, Arg};
        use revm::MainContext;
        let config = super::super::constants::BridgeConstants::mainnet();
        let hardforks = crate::hardfork::RskHardforkConfig::mainnet();
        let tx_ctx = crate::precompiles::BridgeTxContext::default();
        let mut ctx =
            revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());
        let mut call = |address: &str, value: [u8; 32]| {
            let args = encode::args(&[Arg::Bytes(address.as_bytes()), Arg::Word(value)]);
            add_one_off_lock_whitelist_address(&mut ctx, &args, 0, &config, &hardforks, &tx_ctx)
                .map(|out| i64::from_be_bytes(out.bytes[24..32].try_into().unwrap()))
        };
        let address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let mut beyond = [0u8; 32];
        beyond[23] = 1; // 2^64
        assert!(call(address, beyond).is_err());
        assert_eq!(call("not an address", beyond).unwrap(), -2);
        assert_eq!(
            call(address, encode::int(1_000)).unwrap(),
            -10,
            "then the sender"
        );
    }

    /// A Bridge call that reads the whitelist writes it back as the call
    /// returns, whatever it answers (upstream #291): `save()` writes whatever
    /// the call loaded. The changes read it after the sender check, the adds
    /// only once the address parses, and a removal before it parses. On a store
    /// that never held the whitelist, the cells show which answers read it.
    #[test]
    fn a_whitelist_change_writes_the_whitelist_back_once_it_has_read_it() {
        use crate::abi::encode::{self, Arg};
        use crate::precompiles::BridgeTxContext;
        use revm::MainContext;

        /// The call's answer, then the one-off and unlimited cells after it.
        fn run<CTX: crate::RskContextTr>(
            mut ctx: CTX,
            call: impl FnOnce(&mut CTX) -> Result<PrecompileOutput, PrecompileError>,
        ) -> (i64, String, String) {
            let out = call(&mut ctx).unwrap();
            let code = i64::from_be_bytes(out.bytes[24..32].try_into().unwrap());
            let mut cell =
                |key: &str| alloy_primitives::hex::encode(bridge_load_bytes_named(&mut ctx, key));
            (
                code,
                cell(LOCK_WHITELIST_KEY),
                cell(UNLIMITED_LOCK_WHITELIST_KEY),
            )
        }
        let fresh =
            || revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());
        let config = super::super::constants::BridgeConstants::mainnet();
        // Block 0, where regtest has RSKIP87 and mainnet doesn't.
        let (all, mainnet) = (
            crate::hardfork::RskHardforkConfig::regtest(),
            crate::hardfork::RskHardforkConfig::mainnet(),
        );
        let authorizer =
            alloy_primitives::hex::decode(config.whitelist_authorizer_keys[0]).unwrap();
        let authorized = BridgeTxContext {
            rsk_sender: super::super::federation::rsk_address_from_public_key(&authorizer).unwrap(),
            ..BridgeTxContext::default()
        };
        let stranger = BridgeTxContext::default();
        let address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let hash160 = btc_address_to_hash160(address, &config).unwrap();
        let string = |s: &str| encode::args(&[Arg::Bytes(s.as_bytes())]);
        let one_off =
            |s: &str| encode::args(&[Arg::Bytes(s.as_bytes()), Arg::Word(encode::int(1_000))]);
        let delay = |n: i64| encode::args(&[Arg::Word(encode::int(n))]);
        let read = |code: i64| (code, "c5847fffffff".to_string(), "c0".to_string());
        let unread = |code: i64| (code, String::new(), String::new());
        // The address on the one-off list, in a store with no unlimited cell.
        let listed = || {
            let mut ctx = fresh();
            store_one_off_whitelist(&mut ctx, &[(hash160, 1_000)], i32::MAX);
            ctx
        };
        let listed_cell = alloy_primitives::hex::encode(serialize_one_off_whitelist(
            &[(hash160, 1_000)],
            i32::MAX,
        ));

        // The address on the unlimited list.
        let unlimited_listed = || {
            let mut ctx = fresh();
            store_one_off_whitelist(&mut ctx, &[], i32::MAX);
            store_unlimited_whitelist(&mut ctx, &[hash160]);
            ctx
        };
        let unlimited_cell =
            alloy_primitives::hex::encode(serialize_unlimited_whitelist(&[hash160]));

        let add = |ctx, args: Vec<u8>, tx: &BridgeTxContext, hardforks| {
            run(ctx, |ctx| {
                add_one_off_lock_whitelist_address(ctx, &args, 0, &config, hardforks, tx)
            })
        };
        assert_eq!(add(fresh(), one_off(address), &stranger, &all), unread(-10));
        assert_eq!(
            add(fresh(), one_off("not an address"), &authorized, &all),
            unread(-2)
        );
        assert_eq!(
            add(listed(), one_off(address), &authorized, &all),
            (-1, listed_cell.clone(), "c0".to_string()),
            "already listed, and written back"
        );
        assert_eq!(
            add(listed(), one_off(address), &authorized, &mainnet),
            (-1, listed_cell.clone(), String::new())
        );
        assert_eq!(
            add(unlimited_listed(), one_off(address), &authorized, &all),
            (-1, "c5847fffffff".to_string(), unlimited_cell.clone()),
            "listed as unlimited"
        );
        let unlimited = |ctx, args: Vec<u8>| {
            run(ctx, |ctx| {
                add_unlimited_lock_whitelist_address(ctx, &args, 0, &config, &all, &authorized)
            })
        };
        assert_eq!(unlimited(fresh(), string("not an address")), unread(-2));
        assert_eq!(
            unlimited(listed(), string(address)),
            (-1, listed_cell, "c0".to_string())
        );
        assert_eq!(
            unlimited(unlimited_listed(), string(address)),
            (-1, "c5847fffffff".to_string(), unlimited_cell)
        );

        let remove = |ctx, args: Vec<u8>, tx: &BridgeTxContext, hardforks| {
            run(ctx, |ctx| {
                remove_lock_whitelist_address(ctx, &args, 0, &config, hardforks, tx)
            })
        };
        assert_eq!(
            remove(fresh(), string(address), &stranger, &all),
            unread(-10)
        );
        assert_eq!(
            remove(fresh(), string("not an address"), &authorized, &all),
            read(-2),
            "read before the address is parsed"
        );
        assert_eq!(
            remove(fresh(), string(address), &authorized, &all),
            read(-1)
        );
        assert_eq!(
            remove(fresh(), string(address), &authorized, &mainnet),
            (-1, "c5847fffffff".to_string(), String::new()),
            "the unlimited cell is written from RSKIP87 on"
        );
        assert_eq!(
            remove(unlimited_listed(), string(address), &authorized, &all),
            read(1)
        );

        let set = |ctx, args: Vec<u8>, tx: &BridgeTxContext, hardforks| {
            run(ctx, |ctx| {
                set_lock_whitelist_disable_block_delay(ctx, &args, 0, &config, hardforks, true, tx)
            })
        };
        assert_eq!(set(fresh(), delay(100), &stranger, &all), unread(-10));
        assert_eq!(set(fresh(), delay(0), &authorized, &all), read(-2));
        assert_eq!(
            set(fresh(), delay(0), &authorized, &mainnet),
            (-2, "c5847fffffff".to_string(), String::new())
        );
        let disabled = || {
            let mut ctx = fresh();
            store_one_off_whitelist(&mut ctx, &[], 50);
            ctx
        };
        assert_eq!(
            set(disabled(), delay(100), &authorized, &all),
            (-1, "c132".to_string(), "c0".to_string())
        );
        let mut ctx = fresh();
        let beyond_an_int = encode::args(&[Arg::Word(encode::int(1 << 31))]);
        assert!(set_lock_whitelist_disable_block_delay(
            &mut ctx,
            &beyond_an_int,
            0,
            &config,
            &all,
            true,
            &authorized
        )
        .is_err());
        assert!(
            bridge_load_bytes_named(&mut ctx, LOCK_WHITELIST_KEY).is_empty(),
            "a throw ends the call before it saves"
        );
    }

    /// rskj `setLockWhitelistDisableBlockDelay` reads the BTC chain's height
    /// first, which seeds a chain nothing has seeded yet, whoever calls; the
    /// disable height is then counted from the checkpoint.
    #[test]
    fn the_disable_delay_counts_from_the_seeded_btc_chain() {
        use crate::abi::encode::{self, Arg};
        use revm::MainContext;
        let config = super::super::constants::BridgeConstants::mainnet();
        let hardforks = crate::hardfork::RskHardforkConfig::regtest();
        let checkpoint = config.btc_checkpoint.unwrap().1 as i32;
        let authorizer =
            alloy_primitives::hex::decode(config.whitelist_authorizer_keys[0]).unwrap();
        let authorized = crate::precompiles::BridgeTxContext {
            rsk_sender: super::super::federation::rsk_address_from_public_key(&authorizer).unwrap(),
            ..crate::precompiles::BridgeTxContext::default()
        };
        let args = encode::args(&[Arg::Word(encode::int(100))]);
        let fresh =
            || revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());

        let mut ctx = fresh();
        let stranger = crate::precompiles::BridgeTxContext::default();
        set_lock_whitelist_disable_block_delay(
            &mut ctx, &args, 0, &config, &hardforks, true, &stranger,
        )
        .unwrap();
        assert_eq!(
            super::super::btc_store::load_chain_head(&mut ctx).map(|head| head.height as i32),
            Some(checkpoint),
            "seeded before the sender check"
        );

        let mut ctx = fresh();
        set_lock_whitelist_disable_block_delay(
            &mut ctx,
            &args,
            0,
            &config,
            &hardforks,
            true,
            &authorized,
        )
        .unwrap();
        assert_eq!(
            LockWhitelist::load(&mut ctx, true).disable_height,
            checkpoint + 100
        );
    }
}
