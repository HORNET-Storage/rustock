//! Peg-in and peg-out logic for the Bridge.
//!
//! ## Peg-in (`registerBtcTransaction`)
//!
//! The core flow:
//! 1. Verify BTC transaction is included in a stored block (via PMT)
//! 2. Check the block has sufficient confirmations
//! 3. Classify the transaction (peg-in / migration / etc.)
//! 4. For peg-in: identify the federation address in outputs, credit RBTC
//! 5. Mark the transaction as processed
//!
//! ## Peg-out (`releaseBtc`)
//!
//! Enqueues a release request that will be processed by `updateCollections`.
//!
//! ## Release request queue formats (rskj BridgeSerializationUtils)
//!
//! Pre-RSKIP146 (`releaseRequestQueue`):
//!   RLP_list [ btc_addr_hash160_0, bigint(sat_0), btc_addr_hash160_1, bigint(sat_1), ... ]
//!
//! Post-RSKIP146 (`releaseRequestQueueWithTxHash`):
//!   RLP_list [ btc_addr_hash160_0, bigint(sat_0), rsk_tx_hash_0, ... ] (triples)
//!
//! ## rskTxsWaitingFS (pegoutsWaitingForSignatures)
//!
//! SortedMap<keccak256_rsk_tx_hash → raw_btc_tx_bytes> stored as:
//!   RLP_list [ rlp_bytes(rsk_hash_0), rlp_bytes(btc_tx_raw_0), rlp_bytes(rsk_hash_1), ... ]

use alloy_primitives::{Address as RskAddress, Bytes, U256};
use bitcoin::consensus::{deserialize, serialize as btc_serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction as BtcTransaction;
use revm::context_interface::{ContextTr, JournalTr};
use revm::precompile::{PrecompileError, PrecompileOutput};
use std::collections::BTreeMap;

use sha2;
use ripemd;

use super::btc_store::load_chain_head;
use super::constants::BridgeConstants;
use super::pmt::PartialMerkleTree;
use super::serialization::{rlp_decode_list, rlp_encode_element, rlp_encode_list, rlp_encode_u64};
use super::storage::*;
use super::tx::*;
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::{BRIDGE_ADDR, BridgeTxContext};
use crate::silent::{FieldValue, SilentKind};

/// rskj `BridgeSupport.BURN_ADDRESS`: receiver of the sBTC burned when a
/// pegout's dusty change output is raised to the non-dust minimum.
const BURN_ADDR: RskAddress = RskAddress::new([0xff; 20]);

/// A pending peg-out release request, matching rskj's ReleaseRequestQueue.Entry.
///
/// The BTC destination address is the P2PKH hash160 derived from the RSK
/// transaction sender's public key (matching rskj's BridgeUtils.recoverBtcAddressFromEthTransaction).
#[derive(Debug, Clone)]
pub struct ReleaseRequest {
    /// BTC destination address as 20-byte P2PKH hash160.
    pub btc_dest_hash160: [u8; 20],
    /// Amount in satoshis (NOT wei).
    pub amount_satoshis: u64,
    /// RSK transaction hash (post-RSKIP146 only; None for pre-RSKIP146 queue).
    pub rsk_tx_hash: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// registerBtcTransaction
// ---------------------------------------------------------------------------

/// `registerBtcTransaction(bytes btcTxSerialized, int256 height, bytes pmtSerialized)`
///
/// The core peg-in method. Verifies a BTC transaction is included in the
/// BTC header chain, classifies it, and credits RBTC to the sender.
/// rskj BridgeSupport.shouldMarkRejectedPeginAsProcessed: only between
/// RSKIP459 (lovell700) and RSKIP551 (vetiver900) are rejected
/// non-refundable peg-ins marked as processed.
fn should_mark_rejected_pegin_as_processed(cfg: &RskHardforkConfig, block_number: u64) -> bool {
    cfg.has_rskip459(block_number) && !cfg.has_rskip551(block_number)
}

/// rskj `PegUtilsLegacy.isValidPegInTx` minimum gate over the live-federations
/// outputs. Under RSKIP293 each UTXO must be at least `min`
/// (`isAnyUTXOAmountBelowMinimum`); before it, the *total* sent must be
/// (`valueSentToMe.isLessThan`). An EMPTY set of live-fed outputs is not below
/// minimum under RSKIP293 (`anyMatch` over an empty stream is false), so a tx
/// that pays no live federation is still a valid (amount-0) peg-in; pre-RSKIP293
/// a 0 total is below minimum and is not a peg-in.
fn pegin_below_minimum(live_output_values: &[u64], min: u64, rskip293: bool) -> bool {
    if rskip293 {
        live_output_values.iter().any(|v| *v < min)
    } else {
        live_output_values.iter().sum::<u64>() < min
    }
}

pub fn register_btc_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 96 {
        return Err(PrecompileError::other(
            "registerBtcTransaction: args too short",
        ));
    }

    // Parse ABI arguments:
    // arg0: bytes btcTxSerialized (dynamic)
    // arg1: int256 height
    // arg2: bytes pmtSerialized (dynamic)

    let btc_tx_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let btc_block_height = {
        let raw = U256::from_be_slice(&args[32..64]);
        raw.to::<u64>()
    };
    let pmt_offset = U256::from_be_slice(&args[64..96]).to::<usize>();

    let btc_tx_data = read_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_dynamic_bytes(args, pmt_offset)?;

    // Compute BTC tx hash
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    // A fresh bridge BTC store must be seeded with the rskj checkpoint
    // before any chain lookups.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_v2 = hardfork_cfg.has_stored_block_v2(block_number);
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // rskj wraps the registerBtcTransaction body in
    // `try { ... } catch (RegisterBtcTransactionException e) { log }`: an
    // already-processed tx or any failed validation
    // (validationsForRegisterBtcTransaction → "Could not validate
    // transaction") is logged and the call returns SUCCESSFULLY without
    // registering anything. Mirror that — these are a no-op success, not a
    // failed tx. Only a malformed BTC tx (parsed below, a separate
    // exception) propagates and fails the tx.
    // rskj's validation failures are NOT all equivalent, and treating them as
    // if they were diverged mainnet #9,227,292.
    //
    // `BridgeSupport.registerBtcTransaction` wraps its body in
    // `catch (RegisterBtcTransactionException e) { log }`, so a validation that
    // *returns false* is a silent no-op success. But
    // `validationsForRegisterBtcTransaction` also **throws**
    // `BridgeIllegalArgumentException` for a malformed partial merkle tree, and
    // that is not a `RegisterBtcTransactionException` -- it escapes the catch,
    // reaches `Bridge.execute`'s outer handler, becomes a `VMException`, and
    // charges the sender the full gas limit (quirks-frozen-bugs.md §9d).
    //
    // Order is load-bearing too: rskj validates height and confirmations FIRST
    // and returns false there, so a transaction with bad confirmations *and* a
    // malformed PMT is swallowed, never reaching the throw.
    enum Invalid {
        /// `return false` in rskj: logged, call succeeds, nothing registered.
        Swallowed(&'static str),
        /// `throw BridgeIllegalArgumentException`: escapes the catch and fails
        /// the transaction with the full gas limit charged.
        Thrown(&'static str),
    }

    let validation = (|| -> Result<(), Invalid> {
        // Check if already processed (rskj: RegisterBtcTransactionException).
        if is_btc_tx_processed(ctx, &btc_tx_hash) {
            return Err(Invalid::Swallowed("transaction already processed"));
        }

        // Height and confirmations come first, and are swallowed
        // (BridgeUtils.validateHeightAndConfirmations -> return false). The
        // block itself counts as one confirmation, and the CALLER-supplied
        // height is what gets validated.
        let best_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);
        let confirmations = best_height as i64 - btc_block_height as i64 + 1;
        if confirmations < config.btc2rsk_minimum_acceptable_confirmations as i64 {
            return Err(Invalid::Swallowed("insufficient confirmations"));
        }

        // PMT size: rskj THROWS BridgeIllegalArgumentException here.
        if !PartialMerkleTree::has_expected_size(&pmt_data) {
            return Err(Invalid::Thrown("PartialMerkleTree doesn't have expected size"));
        }
        // `BridgeUtils.calculateMerkleRoot` constructs the PMT and walks it;
        // a VerificationException from either is rethrown as
        // BridgeIllegalArgumentException, so both of these throw.
        let pmt = PartialMerkleTree::parse(&pmt_data)
            .ok_or(Invalid::Thrown("failed to parse PMT"))?;
        let pmt_result = pmt
            .extract_matches()
            .ok_or(Invalid::Thrown("PMT verification failed"))?;

        // Tx not among the matched hashes: `calculateMerkleRoot` returns null,
        // so the caller returns false -- swallowed.
        if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
            return Err(Invalid::Swallowed("tx not in PMT"));
        }

        // Look up the BTC block on the main chain at the caller-supplied
        // height (walks the chain pre-RSKIP199, indexed lookup afterwards).
        let stored_block =
            super::btc_chain::stored_block_at_main_chain_height(ctx, btc_block_height as u32, rskip199)
                .ok_or(Invalid::Swallowed("BTC block not found at height"))?;
        let block_hash = stored_block.header.block_hash();

        // Verify merkle root matches
        let block_merkle_root = {
            let raw = stored_block.header.merkle_root.to_raw_hash();
            *raw.as_byte_array()
        };
        let root_valid = if pmt_result.merkle_root == block_merkle_root {
            true
        } else {
            // Post-RSKIP143: also accept witness merkle root. The coinbase
            // information is keyed by the block hash in DISPLAY byte order
            // (rskj `Sha256Hash.toString()`; see set_coinbase_information),
            // the reverse of rust-bitcoin's internal order.
            let block_hash_bytes = {
                let mut raw = *block_hash.to_raw_hash().as_byte_array();
                raw.reverse();
                raw
            };
            match get_coinbase_information(ctx, &block_hash_bytes) {
                // The stored witness merkle root is in DISPLAY byte order
                // (rskj registerBtcCoinbaseTransaction wraps the ABI arg and
                // reverses it for the commitment, BridgeSupport l.2574), while
                // the PMT merkle root is internal order — compare reversed.
                Some(mut witness_root) => {
                    witness_root.reverse();
                    pmt_result.merkle_root == witness_root
                }
                None => false,
            }
        };
        if !root_valid {
            return Err(Invalid::Swallowed("merkle root mismatch"));
        }
        Ok(())
    })();
    match validation {
        Ok(()) => {}
        Err(Invalid::Swallowed(m)) => {
            tracing::debug!(
                "registerBtcTransaction: {m}; returning success \
                 (rskj swallows RegisterBtcTransactionException)"
            );
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }
        Err(Invalid::Thrown(m)) => {
            tracing::debug!(
                "registerBtcTransaction: {m}; throwing \
                 (rskj BridgeIllegalArgumentException escapes the catch)"
            );
            return Err(PrecompileError::other(m));
        }
    }

    // Parse the BTC transaction
    let btc_tx: BtcTransaction = deserialize(&btc_tx_data).map_err(|_| {
        PrecompileError::other("registerBtcTransaction: invalid BTC transaction")
    })?;

    // rskj re-checks "already processed" using the witness-stripped txid
    // (BridgeSupport.registerBtcTransaction l.404, `btcTx.getHash(false)`):
    // the pre-parse check above used the wtxid (`calculateBtcTxHash` over the
    // raw bytes), so for a SegWit tx the two keys differ and this second check
    // is what actually guards the legacy-txid-keyed map. Every mark below uses
    // this same legacy txid (rskj markTxAsProcessed l.763).
    let legacy_txid = legacy_btc_txid(&btc_tx);
    if is_btc_tx_processed(ctx, &legacy_txid) {
        tracing::debug!("registerBtcTransaction: transaction already processed (txid); returning success");
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Live federations (active + retiring during migration): their P2SH
    // scripts identify which outputs are peg-ins and which inputs make the
    // tx a peg-out (rskj getNoSpendWalletForLiveFederations).
    let block_number_now = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    // Each live federation's redeem script (and hence the P2SH address used to
    // recognize peg-in outputs / peg-out inputs) is built from its STORED format
    // version, not the current block — an ERP federation keeps its ERP script
    // even after a later template hardfork (rskj getActiveFederation /
    // getRetiringFederation → Federation.getRedeemScript()).
    let (federation_keys, fed_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number_now);
    // getActiveFederationAddress is format-aware: a P2SH-P2WSH (format 4000,
    // RSKIP305) federation is recognized at its P2SH-P2WSH address, so peg-in /
    // UTXO-registration output matching must use that script, not a plain P2SH.
    let active_format = active_federation_format(ctx, config, hardfork_cfg, block_number_now);
    let fed_script = p2sh_output_script(&federation_output_hash160(&fed_redeem, active_format));
    // rskj isPegOutTx compares against each federation's STANDARD redeem script
    // (getStandardRedeemScript) — for an ERP federation this is the default
    // multisig branch only, not the full ERP/flyover-wrapped redeem.
    let fed_standard_redeem =
        build_federation_redeem_script(&federation_keys, federation_keys.len() / 2 + 1);
    let retiring_format =
        federation_format_version(ctx, super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY);
    let retiring = retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number_now)
        .map(|(_keys, redeem)| {
            let script = p2sh_output_script(&federation_output_hash160(&redeem, retiring_format));
            (redeem, script)
        });
    let retiring_standard_redeem = retiring_federation_keys(ctx, config, hardfork_cfg, block_number_now)
        .map(|keys| build_federation_redeem_script(&keys, keys.len() / 2 + 1));

    // rskj marks processed txs with the RSK execution block number
    // (BridgeSupport.markTxAsProcessed), not the BTC block height.
    let rsk_height = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    // Attribute anything this call records, including from helpers several
    // frames down that have no block of their own.
    crate::silent::set_position(rsk_height, tx_ctx.tx_index);

    // RSKIP419: an SVP fund/spend transaction is recognized by its
    // signature-stripped txid matching the stored unsigned hash. rskj's
    // PegUtils.getTransactionType checks this BEFORE the pegin/pegout
    // classification; the matched tx is handled by registerSvpFundTx /
    // registerSvpSpendTx (= registerNewUtxos + the SVP state transition) and
    // nothing else.
    if hardfork_cfg.has_rskip419(rsk_height) {
        if let Some(without_sigs) = multisig_txid_without_signatures(&btc_tx) {
            let fund_hash = super::serialization::rlp_decode_element(&bridge_load_bytes_named(
                ctx,
                super::storage::SVP_FUND_TX_HASH_UNSIGNED_KEY,
            ));
            let spend_hash = super::serialization::rlp_decode_element(&bridge_load_bytes_named(
                ctx,
                super::storage::SVP_SPEND_TX_HASH_UNSIGNED_KEY,
            ));
            let is_fund = fund_hash.as_deref() == Some(&without_sigs[..]);
            let is_spend = spend_hash.as_deref() == Some(&without_sigs[..]);
            if is_fund || is_spend {
                // registerNewUtxos: register outputs paying the active (and
                // retiring) federation, then mark the tx processed.
                let active_utxo_key =
                    active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
                register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
                if let Some((_, retiring_script)) = &retiring {
                    register_federation_outputs(
                        ctx,
                        &btc_tx,
                        retiring_script,
                        super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
                    );
                }
                if is_fund {
                    // registerSvpFundTx: if the SVP window is still open, record
                    // the signed fund tx and clear its unsigned hash.
                    if svp_is_ongoing(ctx, config, rsk_height) {
                        bridge_store_bytes_named(
                            ctx,
                            super::storage::SVP_FUND_TX_SIGNED_KEY,
                            &super::serialization::rlp_encode_element(&btc_serialize(&btc_tx)),
                        );
                        bridge_store_bytes_named(
                            ctx,
                            super::storage::SVP_FUND_TX_HASH_UNSIGNED_KEY,
                            &[],
                        );
                    }
                } else {
                    // registerSvpSpendTx: clear the spend hash and commit the
                    // proposed federation (the real handover).
                    bridge_store_bytes_named(
                        ctx,
                        super::storage::SVP_SPEND_TX_HASH_UNSIGNED_KEY,
                        &[],
                    );
                    super::governance::commit_proposed_federation(ctx, config, hardfork_cfg);
                }
                record_pegin(
                    SilentKind::BtcTxMarkedProcessed,
                    &btc_tx,
                    tx_ctx,
                    0,
                    if is_fund { "SVP_FUND_TX" } else { "SVP_SPEND_TX" },
                    vec![],
                );
                set_btc_tx_processed(
                    ctx,
                    &legacy_txid,
                    rsk_height,
                    hardfork_cfg.has_rskip134(rsk_height),
                );
                return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
            }
        }
    }

    // Minimum peg-in value (legacy until RSKIP219, strictly-below comparison
    // per PegUtilsLegacy.isValidPegInTx). Needed both for the migration
    // moveToActive check below and the peg-in value gate further down.
    let min_pegin = if hardfork_cfg.has_rskip219(rsk_height) {
        config.minimum_pegin_tx_value
    } else {
        config.legacy_minimum_pegin_tx_value
    };

    // rskj PegUtilsLegacy.getTransactionType — PEGOUT_OR_MIGRATION detection.
    // An input "spends" a federation when its scriptSig redeem hashes to that
    // federation's P2SH; isPegOutTx/migration compare the input's STANDARD
    // (default-branch) redeem (extractStandardRedeemScript) to each fed's
    // standard P2SH, while txIsFromOldFederation compares the FULL redeem.
    let active_std_hash160 = redeem_script_hash160(&fed_standard_redeem);
    let retiring_std_hash160 = retiring_standard_redeem.as_ref().map(|r| redeem_script_hash160(r));
    // lastRetiredFederationP2SHScript (RSKIP186): the P2SH of the last fully
    // retired federation, stored as serializeScript = RLP([program]).
    let retired_hash160: Option<[u8; 20]> = if hardfork_cfg.has_rskip186(rsk_height) {
        let raw = super::storage::bridge_load_bytes_named(
            ctx,
            super::storage::LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY,
        );
        rlp_decode_list(&raw)
            .and_then(|items| items.into_iter().next())
            .filter(|p| p.len() == 23)
            .map(|p| p[2..22].try_into().expect("23-byte P2SH program"))
    } else {
        None
    };
    // rskj `PegUtilsLegacy.isPegOutTx` builds BOTH `createP2SHOutputScript` and
    // (post-RSKIP305) `createP2SHP2WSHOutputScript` of the input's STANDARD
    // redeem and matches either against each federation's
    // `getFederationStandardP2SHScript` (`getDefaultP2SHScript`, which is the
    // P2SH-P2WSH form for a segwit federation). The input's standard redeem is
    // the same redeem the federation stored, so checking the input's legacy AND
    // witness-program hashes against a federation's stored hash matches it
    // whichever form that hash was stored in (a segwit retired/retiring/active
    // fed stores the witness-program hash; #8,569,377).
    let has_rskip305 = hardfork_cfg.has_rskip305(rsk_height);
    let input_matches_fed = |full: &[u8], target: [u8; 20]| -> bool {
        let std = build_federation_redeem_script(
            &super::release_tx::spending_redeem_keys(full),
            super::release_tx::redeem_script_threshold(full),
        );
        redeem_script_hash160(&std) == target
            || (has_rskip305 && federation_output_hash160(&std, 4000) == target)
    };

    // rskj `BitcoinUtils.extractRedeemScriptFromInput`: a segwit (P2SH-P2WSH)
    // input carries its redeem in the witness (last item), not the scriptSig
    // (which is just the witness-program push) — so classification must read it
    // from there to recognize a segwit peg-out/migration.
    let input_redeem = |i: &bitcoin::TxIn| -> Option<Vec<u8>> {
        if !i.witness.is_empty() {
            i.witness.last().map(|r| r.to_vec())
        } else {
            super::release_tx::extract_redeem_script(i.script_sig.as_bytes())
        }
    };
    // (1) txIsFromOldFederation (RSKIP199): any input spends the hardcoded old
    //     federation address — unconditionally a migration.
    let tx_from_old_fed = hardfork_cfg.has_rskip199(rsk_height)
        && btc_tx.input.iter().any(|i| {
            input_redeem(i)
                .is_some_and(|r| redeem_script_hash160(&r) == config.old_federation_address_hash160)
        });
    // (4) isPegOutTx(liveFeds): an input's standard redeem matches the active
    //     or retiring federation.
    let spends_live_fed = btc_tx.input.iter().any(|i| {
        input_redeem(i).is_some_and(|r| {
            input_matches_fed(&r, active_std_hash160)
                || retiring_std_hash160.is_some_and(|t| input_matches_fed(&r, t))
        })
    });
    // (3) isMigrationTx: an input spends the retired or retiring federation AND
    //     an output funds the active federation (moveFromRetiringOrRetired &&
    //     moveToActive).
    let spends_retired_or_retiring = btc_tx.input.iter().any(|i| {
        input_redeem(i).is_some_and(|r| {
            retired_hash160.is_some_and(|t| input_matches_fed(&r, t))
                || retiring_std_hash160.is_some_and(|t| input_matches_fed(&r, t))
        })
    });
    let active_output_values: Vec<u64> = btc_tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == fed_script)
        .map(|o| o.value.to_sat())
        .collect();
    let move_to_active = if hardfork_cfg.has_rskip293(rsk_height) {
        !active_output_values.is_empty() && active_output_values.iter().all(|v| *v >= min_pegin)
    } else {
        active_output_values.iter().sum::<u64>() >= min_pegin
    };
    let is_migration = spends_retired_or_retiring && move_to_active;

    if tx_from_old_fed || is_migration || spends_live_fed {
        record_pegin(
            SilentKind::BtcTxMarkedProcessed,
            &btc_tx,
            tx_ctx,
            active_output_values.iter().sum(),
            if tx_from_old_fed {
                "FROM_OLD_FEDERATION"
            } else if is_migration {
                "MIGRATION"
            } else {
                "PEGOUT"
            },
            vec![],
        );
        let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
        register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
        if let Some((_, retiring_script)) = &retiring {
            register_federation_outputs(
                ctx,
                &btc_tx,
                retiring_script,
                super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
            );
        }
        set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Peg-in value: the outputs paying any live federation
    // (rskj computeTotalAmountSent over the live-federations wallet).
    let pays_live_federation = |script: &bitcoin::ScriptBuf| {
        *script == fed_script || retiring.as_ref().is_some_and(|(_, rs)| *script == *rs)
    };
    let live_output_values: Vec<u64> = btc_tx
        .output
        .iter()
        .filter(|o| pays_live_federation(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .collect();
    let total_value: u64 = live_output_values.iter().sum();

    // rskj PegUtilsLegacy.isValidPegInTx minimum gate: under RSKIP293 it checks
    // EACH UTXO (isAnyUTXOAmountBelowMinimum), otherwise the total amount sent
    // (valueSentToMe.isLessThan). Crucially, an EMPTY live-output set is not
    // "below minimum" under RSKIP293 (anyMatch over an empty stream is false),
    // so a tx that pays no live federation (e.g. only a now-retired one, once
    // the retiring federation has been cleared earlier in the block) is still a
    // valid peg-in — processed with amount 0 (pegin_btc amount=0, destination
    // account created). Pre-RSKIP293 a 0 total is below minimum → not a peg-in.
    let rskip379 = hardfork_cfg.has_rskip379(rsk_height);
    // RSKIP379 (Arrowhead600) moves the minimum-value gate to
    // `PegUtils.allUTXOsToFedAreAboveMinimumPeginValue`, which EXPLICITLY rejects
    // an empty fed-output set (`if (fedUtxos.isEmpty()) return false;`). So an
    // empty (or any-below-minimum) set is below minimum — the OPPOSITE of the
    // pre-379 legacy rule where `anyMatch`/`!isAnyUTXOAmountBelowMinimum` is
    // vacuously satisfied by an empty set (a valid amount-0 peg-in, #5,171,600).
    let below_min = if rskip379 {
        live_output_values.is_empty() || live_output_values.iter().any(|&v| v < min_pegin)
    } else {
        pegin_below_minimum(&live_output_values, min_pegin, hardfork_cfg.has_rskip293(rsk_height))
    };
    if below_min {
        // Pre-RSKIP379: rskj getTransactionType returns UNKNOWN (neither a
        // migration nor a peg-out), so registerBtcTransaction ignores it silently.
        // Post-RSKIP379: evaluatePegin returns (NO_REFUND, INVALID_AMOUNT), and
        // BridgeSupport.handleNonRefundablePegin logs rejected_pegin(INVALID_AMOUNT=5)
        // then unrefundable_pegin(NonRefundablePeginReason.INVALID_AMOUNT=3); it
        // marks the tx processed only when shouldMarkRejectedPeginAsProcessed
        // (RSKIP459 && !RSKIP551 — not yet active at Arrowhead600).
        record_pegin(
            SilentKind::PeginRejectedNoRefund,
            &btc_tx,
            tx_ctx,
            total_value,
            "INVALID_AMOUNT",
            vec![
                ("minimumSat", FieldValue::U64(min_pegin)),
                ("fedOutputs", FieldValue::U64(live_output_values.len() as u64)),
                // Whether the chain also logged this. Before RSKIP379 it did
                // not, which is the gap these records exist to fill.
                ("logged", FieldValue::Flag(rskip379)),
            ],
        );
        if rskip379 {
            let hash = btc_txid_event_bytes(&btc_tx);
            super::events::log_rejected_pegin(ctx, &hash, 5);
            super::events::log_unrefundable_pegin(ctx, &hash, 3);
        }
        if should_mark_rejected_pegin_as_processed(hardfork_cfg, rsk_height) {
            set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Sender classification (rskj BtcLockSenderProvider). Used by the legacy
    // (v0) path for the destination/refund, and as the v1 fallback refund.
    let sender = match classify_pegin_sender(&btc_tx) {
        Ok(s) => s,
        Err(why) => {
            // rskj raises an uncaught RuntimeException on this input;
            // Bridge.execute catches it, panics and rethrows as VMException, so
            // the whole registerBtcTransaction call fails. Failing here is what
            // keeps the two nodes agreeing.
            return Err(PrecompileError::other(format!(
                "registerBtcTransaction: rskj aborts on this scriptSig ({why})"
            )));
        }
    };

    // Announce any peg-in that depended on the sender-detection path this node
    // intends to remove, so the operator hears about it before the RSKIP lands
    // rather than after. Single-key senders -- P2PKH and P2SH-P2WPKH, the ones
    // that can actually be credited -- are silent.
    if let Some((shape, hash160)) = match &sender {
        Some(PeginSender::P2shMultisig { p2sh_hash }) => Some(("P2SH-multisig", *p2sh_hash)),
        Some(PeginSender::P2shP2wsh { p2sh_hash }) => Some(("P2SH-P2WSH", *p2sh_hash)),
        _ => None,
    } {
        super::rskj_sender_compat::report(&super::rskj_sender_compat::Sighting {
            block: rsk_height,
            btc_txid: hex::encode(legacy_txid),
            shape,
            refund_hash160: hex::encode(hash160),
        });
    }

    // rskj `PeginInformation.parse`: the BtcLockSender sets the default
    // (version-0) info; then, if RSKIP170 is active, an RSKT OP_RETURN
    // overrides it (version 1). A malformed RSKT payload throws
    // `PeginInstructionsException` and rejects the v1 peg-in. NoOpReturn
    // (Ok(None)) leaves the legacy info in place.
    let instructions = if hardfork_cfg.has_rskip170(rsk_height) {
        match super::pegin_instructions::build_pegin_instructions(&btc_tx) {
            Ok(opt) => opt,
            Err(_) => {
                // processPegIn: parse exception. RSKIP181 logs
                // PEGIN_V1_INVALID_PAYLOAD(4); refund to the sender (the only
                // refund address available — a malformed payload has no v1
                // refund), then mark processed.
                if hardfork_cfg.has_rskip181(rsk_height) {
                    super::events::log_rejected_pegin(ctx, &btc_txid_event_bytes(&btc_tx), 4);
                }
                match &sender {
                    Some(s) => {
                        let (h, p2sh) = sender_refund_target(s);
                        let mut extra = refund_fields(&h, p2sh, config);
                        extra.push((
                            "senderType",
                            FieldValue::Text(sender_type_name(Some(s)).into()),
                        ));
                        extra.push(("peginVersion", FieldValue::U64(1)));
                        extra.push((
                            "logged",
                            FieldValue::Flag(hardfork_cfg.has_rskip181(rsk_height)),
                        ));
                        record_pegin(
                            SilentKind::PeginRefunded,
                            &btc_tx,
                            tx_ctx,
                            total_value,
                            "PEGIN_V1_INVALID_PAYLOAD",
                            extra,
                        );
                    }
                    None => record_pegin(
                        SilentKind::PeginRejectedNoRefund,
                        &btc_tx,
                        tx_ctx,
                        total_value,
                        "PEGIN_V1_INVALID_PAYLOAD",
                        vec![
                            ("logged", FieldValue::Flag(hardfork_cfg.has_rskip181(rsk_height))),
                            ("senderType", FieldValue::Text("UNDETERMINED".into())),
                            ("peginVersion", FieldValue::U64(1)),
                        ],
                    ),
                }
                if let Some(sender) = &sender {
                    let (refund_hash160, refund_is_p2sh) = sender_refund_target(sender);
                    emit_pegin_rejection_release(
                        ctx, &btc_tx, &refund_hash160, refund_is_p2sh, total_value, &fed_redeem,
                        &retiring, &pays_live_federation, rsk_height, config, hardfork_cfg, tx_ctx,
                    );
                }
                set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
                return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
            }
        }
    } else {
        None
    };

    let cap_ok = |ctx: &mut CTX| {
        !hardfork_cfg.has_rskip134(rsk_height)
            || verify_lock_does_not_surpass_locking_cap(ctx, config, total_value)
    };
    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_value);

    // ---- Version 1 (RSKIP170 OP_RETURN) peg-in ----
    if let Some(instr) = instructions {
        // processPegInVersion1: NO whitelist, only the locking cap.
        if !cap_ok(ctx) {
            if hardfork_cfg.has_rskip181(rsk_height) {
                super::events::log_rejected_pegin(ctx, &btc_txid_event_bytes(&btc_tx), 1); // PEGIN_CAP_SURPASSED
            }
            // refundTxSender: refund to the v1 refund address if present, else
            // the BtcLockSender address; if neither, no refund (a non-refundable
            // peg-in — unrefundable_pegin event not modeled, see TODO).
            match v1_refund_target(&instr, sender.as_ref()) {
                Some((h, p2sh)) => {
                    let mut extra = refund_fields(&h, p2sh, config);
                    extra.push((
                        "senderType",
                        FieldValue::Text(sender_type_name(sender.as_ref()).into()),
                    ));
                    extra.push(("peginVersion", FieldValue::U64(1)));
                    // Whether the refund address came from the OP_RETURN or
                    // fell back to the sender -- the RSKIP distinguishes them.
                    extra.push((
                        "refundFromPayload",
                        FieldValue::Flag(instr.btc_refund_address.is_some()),
                    ));
                    extra.push(("logged", FieldValue::Flag(hardfork_cfg.has_rskip181(rsk_height))));
                    record_pegin(
                        SilentKind::PeginRefunded,
                        &btc_tx,
                        tx_ctx,
                        total_value,
                        "PEGIN_CAP_SURPASSED",
                        extra,
                    );
                }
                None => record_pegin(
                    SilentKind::PeginRejectedNoRefund,
                    &btc_tx,
                    tx_ctx,
                    total_value,
                    "PEGIN_CAP_SURPASSED",
                    vec![
                        ("logged", FieldValue::Flag(hardfork_cfg.has_rskip181(rsk_height))),
                        ("senderType", FieldValue::Text("UNDETERMINED".into())),
                        ("peginVersion", FieldValue::U64(1)),
                    ],
                ),
            }
            if let Some((refund_hash160, refund_is_p2sh)) = v1_refund_target(&instr, sender.as_ref()) {
                emit_pegin_rejection_release(
                    ctx, &btc_tx, &refund_hash160, refund_is_p2sh, total_value, &fed_redeem,
                    &retiring, &pays_live_federation, rsk_height, config, hardfork_cfg, tx_ctx,
                );
            }
            set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }

        // executePegIn: credit the v1 destination from the OP_RETURN payload.
        let dest = RskAddress::from(instr.rsk_destination);
        if !rbtc_amount.is_zero() {
            let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, dest, rbtc_amount);
        } else {
            // transferTo(dest, 0) still creates+persists the account (RSK keeps
            // empty touched accounts — see the legacy path below).
            let _ = ctx.journal_mut().load_account(dest);
            ctx.journal_mut().touch_account(dest);
        }
        // RSKIP170 is required for v1, so pegin_btc (protocolVersion = 1).
        super::events::log_pegin_btc(ctx, dest, &btc_txid_event_bytes(&btc_tx), total_value, 1);
        record_pegin(
            SilentKind::PeginAccepted,
            &btc_tx,
            tx_ctx,
            total_value,
            "ACCEPTED",
            vec![
                ("destination", FieldValue::Addr(dest)),
                ("senderType", FieldValue::Text(sender_type_name(sender.as_ref()).into())),
                ("peginVersion", FieldValue::U64(1)),
                ("logged", FieldValue::Flag(true)),
            ],
        );

        let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
        register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
        if let Some((_, retiring_script)) = &retiring {
            register_federation_outputs(ctx, &btc_tx, retiring_script, super::storage::OLD_FEDERATION_BTC_UTXOS_KEY);
        }
        set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // ---- Version 0 (legacy) peg-in ----
    // A non-P2PKH sender before RSKIP143 (txIsProcessable) aborts WITHOUT
    // marking the tx as processed (no BtcLockSender or unsupported type).
    let Some(sender) = sender else {
        // rskj `PegUtils.evaluateLegacyPegin` default case (PegUtils.java:256):
        // an undetermined sender type (no BtcLockSender) →
        // (NO_REFUND, LEGACY_PEGIN_UNDETERMINED_SENDER). Post-RSKIP379
        // `handleNonRefundablePegin` logs rejected_pegin(LEGACY_PEGIN_UNDETERMINED_SENDER=3)
        // then unrefundable_pegin(NonRefundablePeginReason.LEGACY_PEGIN_UNDETERMINED_SENDER=1),
        // and marks the tx processed only when RSKIP459 && !RSKIP551. Pre-379 the
        // legacy path aborts silently (sender could not be determined).
        record_pegin(
            SilentKind::PeginRejectedNoRefund,
            &btc_tx,
            tx_ctx,
            total_value,
            "LEGACY_PEGIN_UNDETERMINED_SENDER",
            vec![
                // Post-RSKIP379 this path logs rejected_pegin then
                // unrefundable_pegin; pre-379 it aborts silently.
                ("logged", FieldValue::Flag(hardfork_cfg.has_rskip379(rsk_height))),
                ("senderType", FieldValue::Text("UNDETERMINED".into())),
                ("inputShape", FieldValue::Text(undetermined_input_shape(&btc_tx).into())),
                (
                    "scriptSigLen",
                    FieldValue::U64(
                        btc_tx
                            .input
                            .first()
                            .map(|i| i.script_sig.as_bytes().len() as u64)
                            .unwrap_or(0),
                    ),
                ),
                (
                    "witnessItems",
                    FieldValue::U64(
                        btc_tx.input.first().map(|i| i.witness.len() as u64).unwrap_or(0),
                    ),
                ),
                ("peginVersion", FieldValue::U64(0)),
                ("logged", FieldValue::Flag(hardfork_cfg.has_rskip379(rsk_height))),
            ],
        );
        if hardfork_cfg.has_rskip379(rsk_height) {
            let hash = btc_txid_event_bytes(&btc_tx);
            super::events::log_rejected_pegin(ctx, &hash, 3);
            super::events::log_unrefundable_pegin(ctx, &hash, 1);
            if should_mark_rejected_pegin_as_processed(hardfork_cfg, rsk_height) {
                set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
            }
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };
    let rskip143 = hardfork_cfg.has_rskip143(rsk_height);
    if !matches!(sender, PeginSender::P2pkh { .. }) && !rskip143 {
        // Dropped without a refund, without being marked processed and
        // without a log line of any kind: the quietest outcome the Bridge has.
        record_pegin(
            SilentKind::PeginRejectedNoRefund,
            &btc_tx,
            tx_ctx,
            total_value,
            "SENDER_NOT_PROCESSABLE_PRE_RSKIP143",
            vec![
                ("senderType", FieldValue::Text(sender_type_name(Some(&sender)).into())),
                ("peginVersion", FieldValue::U64(0)),
                ("logged", FieldValue::Flag(false)),
                ("markedProcessed", FieldValue::Flag(false)),
            ],
        );
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }
    // rskj txIsLockable: only P2PKH and (post-RSKIP143) P2SH-P2WPKH senders
    // can lock; other processable types are refunded ("Btc tx type not
    // supported, returning funds to sender") without consulting the
    // whitelist or the locking cap.
    let (sender_hash160, sender_is_p2sh, sender_pubkey, lockable): ([u8; 20], bool, Option<&[u8]>, bool) =
        match &sender {
            PeginSender::P2pkh { pubkey } => (pubkey_hash160(pubkey), false, Some(pubkey), true),
            PeginSender::P2shP2wpkh { pubkey, p2sh_hash } => {
                (*p2sh_hash, true, Some(pubkey), true)
            }
            PeginSender::P2shMultisig { p2sh_hash } | PeginSender::P2shP2wsh { p2sh_hash } => {
                (*p2sh_hash, true, None, false)
            }
        };

    // Lock whitelist gate (rskj verifyLockSenderIsWhitelisted): the matching
    // one-off entry is consumed on success; rejection generates a refund
    // peg-out back to the sender (generateRejectionRelease).
    // Locking cap gate (rskj verifyLockDoesNotSurpassLockingCap, RSKIP134):
    // evaluated only when the whitelist passed (rskj short-circuits the &&,
    // so a whitelist rejection never lazily initializes the cap). A cap
    // rejection produces the same refund release as a whitelist one.
    let allowed = lockable
        && whitelist_allows_and_consume(
            ctx,
            &sender_hash160,
            total_value,
            btc_block_height,
            hardfork_cfg.has_rskip87(rsk_height),
        )
        && cap_ok(ctx);
    tracing::debug!(
        "pegin lock check: sender {} amount {} btc_height {} -> {}",
        to_hex(&sender_hash160),
        total_value,
        btc_block_height,
        allowed
    );
    if !allowed {
        // RSKIP181 (iris300): log rejected_pegin. rskj processPegInVersionLegacy
        // re-runs the lockable/cap checks in the rejection branch (NOT the
        // whitelist): `!isTxLockableForLegacyVersion` -> LEGACY_PEGIN_MULTISIG_SENDER(2),
        // else `!verifyLockDoesNotSurpassLockingCap` -> PEGIN_CAP_SURPASSED(1).
        // A whitelist-only rejection (lockable, cap ok) logs nothing. The cap
        // re-evaluation here also lazily initializes the locking-cap cell, like
        // rskj's second verifyLockDoesNotSurpassLockingCap call.
        //
        // The silent reason is read off this same evaluation rather than
        // recomputed: `cap_ok` WRITES (it lazily initializes the locking-cap
        // cell), so calling it a second time -- or calling it pre-RSKIP181,
        // where rskj does not -- would change the state root. A diagnostic
        // that alters what it observes is worse than no diagnostic.
        let silent_reason;
        if hardfork_cfg.has_rskip181(rsk_height) {
            let reason = if !lockable {
                silent_reason = "LEGACY_PEGIN_MULTISIG_SENDER";
                Some(2u64) // LEGACY_PEGIN_MULTISIG_SENDER
            } else if !cap_ok(ctx) {
                silent_reason = "PEGIN_CAP_SURPASSED";
                Some(1u64) // PEGIN_CAP_SURPASSED
            } else {
                silent_reason = "LOCK_WHITELIST_REJECTED";
                None // whitelist rejection: no event
            };
            if let Some(reason) = reason {
                super::events::log_rejected_pegin(ctx, &btc_txid_event_bytes(&btc_tx), reason);
            }
        } else if !lockable {
            silent_reason = "LEGACY_PEGIN_MULTISIG_SENDER";
        } else if crate::silent::is_recording()
            && hardfork_cfg.has_rskip134(rsk_height)
            && !locking_cap_would_allow(ctx, config, total_value)
        {
            // Pre-RSKIP181 rskj does not re-evaluate the cap here, so the
            // reason is established by a read-only equivalent rather than by
            // the real check, which writes. Guarded on recording only to skip
            // the reads when nobody wants the answer -- it changes nothing.
            //
            // Gated on RSKIP134 as `cap_ok` is: before papyrus200 no locking
            // cap exists, so the cell is unset and the read-only equivalent
            // would fall back to `initial_locking_cap` and could blame a cap
            // that was not yet a rule. In that era the only way to reach this
            // branch is a lock-whitelist rejection, which is the one thing a
            // pre-papyrus200 replay exists to find.
            silent_reason = "PEGIN_CAP_SURPASSED";
        } else {
            silent_reason = "LOCK_WHITELIST_REJECTED";
        }
        let mut extra = refund_fields(&sender_hash160, sender_is_p2sh, config);
        extra.push(("senderType", FieldValue::Text(sender_type_name(Some(&sender)).into())));
        extra.push(("peginVersion", FieldValue::U64(0)));
        extra.push((
            "logged",
            FieldValue::Flag(
                hardfork_cfg.has_rskip181(rsk_height)
                    && silent_reason != "LOCK_WHITELIST_REJECTED",
            ),
        ));
        record_pegin(SilentKind::PeginRefunded, &btc_tx, tx_ctx, total_value, silent_reason, extra);
        emit_pegin_rejection_release(
            ctx, &btc_tx, &sender_hash160, sender_is_p2sh, total_value, &fed_redeem,
            &retiring, &pays_live_federation, rsk_height, config, hardfork_cfg, tx_ctx,
        );
        set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // RSK destination: rskj's legacy peg-in credits the address derived from
    // the sender's public key (ethereumj ECKey.getAddress over the
    // UNCOMPRESSED point — mainnet #267,460 used a 65-byte pubkey).
    let rsk_destination = sender_pubkey.and_then(super::federation::rsk_address_from_public_key);

    // Credit the derived destination address (transfer from Bridge balance)
    if let Some(dest) = rsk_destination {
        if !rbtc_amount.is_zero() {
            let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, dest, rbtc_amount);
        } else {
            // rskj executePegIn always calls transferTo(dest, amount); a 0-value
            // transfer still creates and persists the destination account (RSK
            // keeps empty touched accounts — no EIP-161 cleanup). An amount-0
            // peg-in therefore materializes the destination with balance 0.
            let _ = ctx.journal_mut().load_account(dest);
            ctx.journal_mut().touch_account(dest);
        }

        // Peg-in events: lock_btc from RSKIP146, pegin_btc from RSKIP170
        // (a legacy peg-in past RSKIP170 logs pegin_btc with protocolVersion 0).
        let txid_bytes = btc_txid_event_bytes(&btc_tx);
        record_pegin(
            SilentKind::PeginAccepted,
            &btc_tx,
            tx_ctx,
            total_value,
            "ACCEPTED",
            vec![
                ("destination", FieldValue::Addr(dest)),
                ("senderType", FieldValue::Text(sender_type_name(Some(&sender)).into())),
                (
                    "senderAddress",
                    FieldValue::Text(sender_base58_address(&sender_hash160, sender_is_p2sh, config)),
                ),
                ("peginVersion", FieldValue::U64(0)),
                // `logged` is PER TOPIC, and the topic reconstructed for an
                // accepted peg-in is `pegin_btc` -- so the test is RSKIP170,
                // not RSKIP146.
                //
                // Between papyrus200 and iris300 the Bridge logs `lock_btc`
                // instead. That peg-in is therefore visible in the real index
                // under a different topic, and reconstructing `pegin_btc` for
                // it duplicates nothing: a scan of either topic over the union
                // of the two stores returns each peg-in exactly once, and a
                // scan of `pegin_btc` alone spans all of history, which is the
                // point of reconstructing the modern event rather than the
                // contemporaneous one.
                ("logged", FieldValue::Flag(hardfork_cfg.has_rskip170(rsk_height))),
            ],
        );
        if hardfork_cfg.has_rskip170(rsk_height) {
            super::events::log_pegin_btc(ctx, dest, &txid_bytes, total_value, 0);
        } else if hardfork_cfg.has_rskip146(rsk_height) {
            let sender_addr = sender_base58_address(&sender_hash160, sender_is_p2sh, config);
            super::events::log_lock_btc(ctx, dest, &txid_bytes, &sender_addr, total_value);
        }
    }

    // rskj registerNewUtxos: outputs paying the active federation feed the
    // set that backs it (the OLD set while a committed federation awaits
    // activation); outputs paying the retiring federation feed the OLD set.
    let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
    register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
    if let Some((_, retiring_script)) = &retiring {
        register_federation_outputs(
            ctx,
            &btc_tx,
            retiring_script,
            super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
        );
    }

    // Mark as processed
    set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// Emits `release_requested`, or records it when the Bridge of the day did
/// not.
///
/// The event arrives with RSKIP146 (papyrus200). Before it the peg-out was
/// queued exactly the same way and nothing was written to the receipts, which
/// is why a receipts-derived index has no peg-outs for that era. Recording
/// the same three fields here is what lets the legacy-event store rebuild the
/// event rather than approximate it.
///
/// A no-op on the recording side unless a replay tool turned recording on, so
/// production pays one thread-local read per peg-out.
fn release_requested_or_record<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    logged: bool,
    rsk_tx_hash: &[u8; 32],
    btc_tx_hash: &[u8; 32],
    amount_satoshis: u64,
) {
    if logged {
        super::events::log_release_requested(ctx, rsk_tx_hash, btc_tx_hash, amount_satoshis);
        return;
    }
    crate::silent::record_here(
        SilentKind::PegoutRequested,
        vec![
            ("rskTxHash", FieldValue::Bytes(rsk_tx_hash.to_vec())),
            ("btcTxHash", FieldValue::Bytes(btc_tx_hash.to_vec())),
            ("amountSat", FieldValue::U64(amount_satoshis)),
        ],
    );
}

/// Describes a peg-in decision for the silent-decision store.
///
/// A no-op unless a replay tool turned recording on, so the cost on an
/// ordinary block is one thread-local read per decision. Nothing here is read
/// back during execution -- see [`crate::silent`].
fn record_pegin(
    kind: SilentKind,
    btc_tx: &BtcTransaction,
    tx_ctx: &BridgeTxContext,
    amount_sat: u64,
    reason: &'static str,
    extra: Vec<(&'static str, FieldValue)>,
) {
    if !crate::silent::is_recording() {
        return;
    }
    let mut fields = vec![
        ("btcTxHash", FieldValue::Bytes(btc_txid_event_bytes(btc_tx).to_vec())),
        ("rskTxHash", FieldValue::Bytes(tx_ctx.rsk_tx_hash.to_vec())),
        ("amountSat", FieldValue::U64(amount_sat)),
        ("reason", FieldValue::Text(reason.to_string())),
    ];
    fields.extend(extra);
    crate::silent::record_here(kind, fields);
}

/// Why `classify_pegin_sender` returned nothing, read off the first input.
///
/// Every shape it recognises requires a NON-EMPTY scriptSig: P2PKH wants
/// `[sig, pubkey]`, and the three P2SH forms want one chunk or three. A
/// native segwit (bech32) input carries an empty scriptSig and puts
/// everything in the witness, so it matches none of them and the peg-in is
/// refused with the bitcoin kept. Recording which shape it was turns "the
/// sender was undetermined" into something that can be counted.
fn undetermined_input_shape(tx: &BtcTransaction) -> &'static str {
    use super::release_tx::parse_chunks;
    let Some(first) = tx.input.first() else { return "NO_INPUTS" };
    let script_sig = first.script_sig.as_bytes();
    let witness: Vec<&[u8]> = first.witness.iter().collect();
    if script_sig.is_empty() {
        return match witness.len() {
            0 => "EMPTY_SCRIPTSIG_NO_WITNESS",
            // P2WPKH spends are [signature, 33-byte compressed pubkey].
            2 if witness[1].len() == 33 => "NATIVE_P2WPKH",
            _ => "NATIVE_SEGWIT_OTHER",
        };
    }
    match parse_chunks(script_sig) {
        None => "UNPARSEABLE_SCRIPTSIG",
        Some(chunks) => match chunks.len() {
            1 => "ONE_CHUNK_UNRECOGNISED",
            2 => "TWO_CHUNKS_BAD_PUBKEY",
            _ => "OTHER_SCRIPTSIG",
        },
    }
}

/// The sender shape rskj's `BtcLockSenderProvider` settled on, named for a
/// reader. `None` is the undetermined case, which is itself a decision.
fn sender_type_name(sender: Option<&PeginSender>) -> &'static str {
    match sender {
        Some(PeginSender::P2pkh { .. }) => "P2PKH",
        Some(PeginSender::P2shP2wpkh { .. }) => "P2SH-P2WPKH",
        Some(PeginSender::P2shMultisig { .. }) => "P2SH-MULTISIG",
        Some(PeginSender::P2shP2wsh { .. }) => "P2SH-P2WSH",
        None => "UNDETERMINED",
    }
}

/// The refund destination as it would be paid: the base58 address and whether
/// it is a P2SH. This is the field the event log never carried, and the one a
/// question about past refunds actually turns on.
fn refund_fields(
    hash160: &[u8; 20],
    is_p2sh: bool,
    config: &BridgeConstants,
) -> Vec<(&'static str, FieldValue)> {
    vec![
        ("refundAddress", FieldValue::Text(sender_base58_address(hash160, is_p2sh, config))),
        (
            "refundAddressType",
            FieldValue::Text(if is_p2sh { "P2SH".into() } else { "P2PKH".into() }),
        ),
        ("refundHash160", FieldValue::Bytes(hash160.to_vec())),
    ]
}

/// rskj `BtcLockSender.getBTCAddress` target for a legacy refund: the sender's
/// hash160 and whether it is a P2SH address.
fn sender_refund_target(sender: &PeginSender) -> ([u8; 20], bool) {
    match sender {
        PeginSender::P2pkh { pubkey } => (pubkey_hash160(pubkey), false),
        PeginSender::P2shP2wpkh { p2sh_hash, .. }
        | PeginSender::P2shMultisig { p2sh_hash }
        | PeginSender::P2shP2wsh { p2sh_hash } => (*p2sh_hash, true),
    }
}

/// rskj `refundTxSender` for a v1 peg-in: the refund goes to the v1 OP_RETURN
/// refund address if present, otherwise the BtcLockSender address. Returns
/// `None` when neither is available (a non-refundable peg-in).
fn v1_refund_target(
    instr: &super::pegin_instructions::PeginInstructions,
    sender: Option<&PeginSender>,
) -> Option<([u8; 20], bool)> {
    if let Some(refund) = &instr.btc_refund_address {
        return Some((refund.hash160, refund.is_p2sh));
    }
    sender.map(sender_refund_target)
}

/// rskj `generateRejectionRelease`: build an empty-wallet refund of all the
/// outputs paying the live federation(s) back to `refund_hash160`, enqueue it
/// in the pegouts-waiting-for-confirmations set, and (post-RSKIP146) log
/// release_requested with the registering RSK tx hash.
#[allow(clippy::too_many_arguments)]
fn emit_pegin_rejection_release<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    refund_hash160: &[u8; 20],
    refund_is_p2sh: bool,
    total_value: u64,
    fed_redeem: &[u8],
    retiring: &Option<(Vec<u8>, bitcoin::ScriptBuf)>,
    pays_live_federation: &impl Fn(&bitcoin::ScriptBuf) -> bool,
    rsk_height: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) {
    // TODO(rustock): a rejected peg-in paying BOTH live federations would
    // need per-input redeem scripts in the refund; none exists on
    // mainnet pre-wasabi. Inputs paying the retiring federation use its
    // redeem via the same builder when the active outputs are absent.
    let pegin_utxos: Vec<BridgeUtxo> = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| pays_live_federation(&o.script_pubkey))
        .map(|(index, o)| BridgeUtxo {
            tx_hash: btc_txid_event_bytes(btc_tx),
            vout: index as u32,
            value_satoshis: o.value.to_sat(),
            height: 0,
            script: o.script_pubkey.to_bytes(),
            coinbase: btc_tx.is_coinbase(),
        })
        .collect();
    let refund_redeem = if pegin_utxos
        .iter()
        .all(|u| retiring.as_ref().is_some_and(|(_, rs)| u.script == rs.to_bytes()))
    {
        &retiring.as_ref().expect("checked above").0
    } else {
        fed_redeem
    };
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    let tx_version = if hardfork_cfg.has_rskip201(rsk_height) { 2 } else { 1 };
    let refund_script = if refund_is_p2sh {
        p2sh_output_script(refund_hash160)
    } else {
        p2pkh_output_script(refund_hash160)
    };
    let built = super::release_tx::build_empty_wallet_to(
        &pegin_utxos,
        &refund_script,
        refund_redeem,
        fee_per_kb,
        tx_version,
    );
    tracing::debug!(
        "pegin rejection release: utxos {} fee_per_kb {} built {:?}",
        pegin_utxos.len(),
        fee_per_kb,
        built.as_ref().map(|b| b.tx.compute_txid().to_string())
    );
    if let Some(built) = built {
        // rskj generateRejectionRelease: post-RSKIP146 the entry carries
        // this registerBtcTransaction tx hash and logs release_requested.
        let use_tx_hash = hardfork_cfg.has_rskip146(rsk_height);
        let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
        waiting.push(PegoutWaitingForConfirmations {
            btc_tx_raw: btc_serialize(&built.tx),
            rsk_block_height: rsk_height,
            rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
        });
        release_requested_or_record(
            ctx,
            use_tx_hash,
            &tx_ctx.rsk_tx_hash,
            &btc_txid_event_bytes(&built.tx),
            total_value,
        );
        store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);
    } else {
        // The refund was due and could not be built -- in practice the inputs
        // do not cover the fee. rskj logs a warn line and moves on, so the
        // peg-in is refused and the bitcoin stays with the federation, with
        // no event to say so. Recorded separately because a `pegin_refunded`
        // row on its own would claim a refund that never went out.
        crate::silent::record_here(
            SilentKind::RefundBuildFailed,
            vec![
                ("btcTxHash", FieldValue::Bytes(btc_txid_event_bytes(btc_tx).to_vec())),
                ("amountSat", FieldValue::U64(total_value)),
                ("utxos", FieldValue::U64(pegin_utxos.len() as u64)),
                ("feePerKb", FieldValue::U64(fee_per_kb)),
                (
                    "refundAddress",
                    FieldValue::Text(sender_base58_address(refund_hash160, refund_is_p2sh, config)),
                ),
            ],
        );
    }
}

/// rskj `BtcLockSender.TxType`: the peg-in sender classification derived
/// from the FIRST input. `hash160` is the sender's BTC address hash (pubkey
/// hash for P2PKH, script hash for the P2SH variants) — what rskj's
/// `senderBtcAddress` carries into the whitelist check and the refund.
enum PeginSender {
    P2pkh { pubkey: Vec<u8> },
    P2shP2wpkh { pubkey: Vec<u8>, p2sh_hash: [u8; 20] },
    P2shMultisig { p2sh_hash: [u8; 20] },
    P2shP2wsh { p2sh_hash: [u8; 20] },
}
/// rskj `BtcLockSenderProvider.tryGetBtcLockSender`: try P2PKH, then
/// P2SH-P2WPKH, then P2SH-MULTISIG, then P2SH-P2WSH — all on the first
/// input. Returns `None` when no parser matches (rskj then returns from
/// registerBtcTransaction WITHOUT marking the tx as processed).
fn classify_pegin_sender(
    tx: &BtcTransaction,
) -> Result<Option<PeginSender>, &'static str> {
    use super::release_tx::{parse_chunks, Chunk};
    let Some(first) = tx.input.first() else { return Ok(None) };
    let Some(chunks) = parse_chunks(first.script_sig.as_bytes()) else { return Ok(None) };

    // P2PKH: scriptSig is exactly [sig, pubkey] with a valid curve point
    // (rskj derives both the BTC and RSK addresses from it).
    if let [Chunk::Data(_sig), Chunk::Data(pubkey)] = chunks.as_slice() {
        if compress_pubkey(pubkey).is_some() {
            return Ok(Some(PeginSender::P2pkh { pubkey: pubkey.clone() }));
        }
    }

    let witness: Vec<&[u8]> = first.witness.iter().collect();

    // P2SH-P2WPKH: single-chunk scriptSig, witness [sig, compressed pubkey];
    // P2SH hash = hash160(0x0014 || hash160(pubkey)).
    if chunks.len() == 1 && witness.len() == 2 {
        let pubkey = witness[1];
        if pubkey.len() == 33 && compress_pubkey(pubkey).is_some() {
            let mut redeem = vec![0x00, 0x14];
            redeem.extend_from_slice(&pubkey_hash160(pubkey));
            return Ok(Some(PeginSender::P2shP2wpkh {
                pubkey: pubkey.to_vec(),
                p2sh_hash: pubkey_hash160(&redeem),
            }));
        }
    }

    // P2SH-MULTISIG: scriptSig [.., sigs.., redeem] with a multisig redeem;
    // P2SH hash = hash160(redeem).
    //
    // The predicate lives in `rskj_sender_compat` rather than here: it is a
    // faithful port of bitcoinj's parser dispatch, kept apart so that it can be
    // switched off and deleted when the RSKIP retiring this path activates.
    if super::rskj_sender_compat::enabled() && chunks.len() >= 3 {
        if let Some(Chunk::Data(redeem)) = chunks.last() {
            match super::rskj_sender_compat::is_sent_to_multisig(redeem) {
                super::rskj_sender_compat::Verdict::Multisig => {
                    return Ok(Some(PeginSender::P2shMultisig {
                        p2sh_hash: pubkey_hash160(redeem),
                    }));
                }
                super::rskj_sender_compat::Verdict::RskjThrows(why) => return Err(why),
                super::rskj_sender_compat::Verdict::NotMultisig => {}
            }
        }
    }

    // P2SH-P2WSH: single-chunk scriptSig, witness [.., sigs.., redeem] with
    // a multisig redeem; P2SH hash = hash160(0x0020 || sha256(redeem)).
    if super::rskj_sender_compat::enabled() && chunks.len() == 1 && witness.len() >= 3 {
        let redeem = witness[witness.len() - 1];
        match super::rskj_sender_compat::is_sent_to_multisig(redeem) {
            super::rskj_sender_compat::Verdict::Multisig => {
                use sha2::Digest;
                let mut merged = vec![0x00, 0x20];
                merged.extend_from_slice(&sha2::Sha256::digest(redeem));
                return Ok(Some(PeginSender::P2shP2wsh { p2sh_hash: pubkey_hash160(&merged) }));
            }
            super::rskj_sender_compat::Verdict::RskjThrows(why) => return Err(why),
            super::rskj_sender_compat::Verdict::NotMultisig => {}
        }
    }

    Ok(None)
}

/// Base58Check address string for the peg-in sender (rskj
/// `senderBtcAddress.toString()`, used in the lock_btc event).
fn sender_base58_address(
    hash160: &[u8; 20],
    p2sh: bool,
    config: &BridgeConstants,
) -> String {
    let version: u8 = match (config.btc_network, p2sh) {
        (super::constants::BtcNetwork::Mainnet, false) => 0,
        (super::constants::BtcNetwork::Mainnet, true) => 5,
        (_, false) => 111,
        (_, true) => 196,
    };
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(hash160);
    bitcoin::base58::encode_check(&payload)
}

/// rskj `BridgeSupport.getLockingCap` (RSKIP134): lazily initializes the cap
/// to the network's initial value on first read, persisting it (the provider
/// caches the value and `saveLockingCap` writes it on the bridge save).
pub(super) fn get_or_init_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
) -> u64 {
    if bridge_load_bytes_named(ctx, LOCKING_CAP_KEY).is_empty() {
        bridge_store_u256(ctx, LOCKING_CAP_KEY, U256::from(config.initial_locking_cap));
        return config.initial_locking_cap;
    }
    bridge_load_u256(ctx, LOCKING_CAP_KEY).to::<u64>()
}

/// The locking-cap verdict WITHOUT the lazy initialization.
///
/// `verify_lock_does_not_surpass_locking_cap` writes the cap cell when it is
/// unset, which is consensus behaviour and must happen exactly where rskj
/// does it. Before RSKIP181 rskj does not re-evaluate the cap in the
/// rejection branch at all, so a recorder that called the real check to name
/// the reason would write a cell the chain never wrote. This reads the same
/// inputs and decides the same way, without the write.
fn locking_cap_would_allow<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    total_amount_satoshis: u64,
) -> bool {
    let raw = bridge_load_bytes_named(ctx, LOCKING_CAP_KEY);
    let cap = if raw.is_empty() {
        // Unset means the initial cap applies: the same value the real check
        // would have stored and then used.
        config.initial_locking_cap
    } else {
        bridge_load_u256(ctx, LOCKING_CAP_KEY).to::<u64>()
    };
    let bridge_balance_wei = ctx
        .journal_mut()
        .load_account(crate::precompiles::BRIDGE_ADDR)
        .map(|a| a.info.balance)
        .unwrap_or_default();
    let balance_satoshis = (bridge_balance_wei / U256::from(10_000_000_000u64)).to::<u64>();
    const MAX_RBTC_SATOSHIS: u64 = 2_100_000_000_000_000;
    let fed_current_funds = MAX_RBTC_SATOSHIS.saturating_sub(balance_satoshis);
    fed_current_funds + total_amount_satoshis <= cap
}

/// rskj `BridgeSupport.verifyLockDoesNotSurpassLockingCap`: the federation's
/// current funds are maxRbtc (21M BTC) minus the Bridge contract balance;
/// the peg-in is rejected when funds + amount exceed the cap.
fn verify_lock_does_not_surpass_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    total_amount_satoshis: u64,
) -> bool {
    let cap = get_or_init_locking_cap(ctx, config);
    let bridge_balance_wei = ctx
        .journal_mut()
        .load_account(crate::precompiles::BRIDGE_ADDR)
        .map(|a| a.info.balance)
        .unwrap_or_default();
    // co.rsk.core.Coin.toBitcoin: truncating wei -> satoshi division.
    let balance_satoshis = (bridge_balance_wei / U256::from(10_000_000_000u64)).to::<u64>();
    const MAX_RBTC_SATOSHIS: u64 = 2_100_000_000_000_000; // Constants maxRbtc, 21M BTC
    let fed_current_funds = MAX_RBTC_SATOSHIS.saturating_sub(balance_satoshis);
    fed_current_funds + total_amount_satoshis <= cap
}

/// rskj `LockWhitelist.isWhitelistedFor` + `consume`: returns whether the
/// sender may peg in `amount` at BTC height `height`, consuming the matching
/// one-off entry. A height past the disable height turns the whitelist off
/// (but a matching one-off entry is still consumed).
fn whitelist_allows_and_consume<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    sender_hash160: &[u8; 20],
    amount: u64,
    height: u64,
    rskip87: bool,
) -> bool {
    // rskj `getLockWhitelist()` deserializes BOTH cells together, so reaching
    // this function reads both even where the decision needs only one.
    let (mut one_off, disable_h) = load_one_off_whitelist(ctx);
    let unlimited = load_unlimited_whitelist(ctx);
    let disabled = (height as i64) > (disable_h as i64);

    let allowed = if let Some(pos) = one_off.iter().position(|(h, _)| h == sender_hash160) {
        let allowed = disabled || amount <= one_off[pos].1;
        if allowed {
            // A one-off entry is spent here and gone from the next block's
            // state, with nothing logged to say it was ever used.
            crate::silent::record_here(
                SilentKind::WhitelistEntryConsumed,
                vec![
                    ("senderHash160", FieldValue::Bytes(sender_hash160.to_vec())),
                    ("amountSat", FieldValue::U64(amount)),
                    ("entryMaxSat", FieldValue::U64(one_off[pos].1)),
                    ("whitelistDisabled", FieldValue::Flag(disabled)),
                ],
            );
            // rskj consumes the matching one-off entry only on success.
            one_off.remove(pos);
        }
        allowed
    } else if disabled {
        true
    } else {
        unlimited.contains(sender_hash160)
    };

    // Unconditional, including on rejection: rskj's save() writes the
    // whitelist back because the call loaded it, not because it changed it.
    // See `save_lock_whitelist` -- this write is why testnet #6,602 has a
    // `lockWhitelist` cell at all.
    super::storage::save_lock_whitelist(ctx, &one_off, disable_h, &unlimited, rskip87);
    allowed
}

/// rskj `BridgeSupport.registerNewUtxos`: register every output paying the
/// given federation script into the given UTXO storage set.
fn register_federation_outputs<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    fed_script: &bitcoin::ScriptBuf,
    utxo_key: &str,
) {
    let new_utxos: Vec<BridgeUtxo> = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == *fed_script)
        .map(|(index, o)| BridgeUtxo {
            tx_hash: btc_txid_event_bytes(btc_tx),
            vout: index as u32,
            value_satoshis: o.value.to_sat(),
            height: 0,
            script: o.script_pubkey.to_bytes(),
            coinbase: btc_tx.is_coinbase(),
        })
        .collect();
    if new_utxos.is_empty() {
        return;
    }
    let mut utxos = load_utxos_at(ctx, utxo_key);
    utxos.extend(new_utxos);
    store_utxos_at(ctx, utxo_key, &utxos);
}

// ---------------------------------------------------------------------------
// registerFastBridgeBtcTransaction (Flyover)
// ---------------------------------------------------------------------------

/// rskj `FlyoverTxResponseCodes`: the int256 status the method returns on the
/// rejection / unprocessable paths. The success path returns the locked amount
/// in wei instead.
mod flyover_codes {
    pub const REFUNDED_USER: i64 = -100;
    pub const REFUNDED_LP: i64 = -200;
    pub const UNPROCESSABLE_NOT_CONTRACT: i64 = -300;
    pub const UNPROCESSABLE_INVALID_SENDER: i64 = -301;
    pub const UNPROCESSABLE_ALREADY_PROCESSED: i64 = -302;
    pub const UNPROCESSABLE_VALIDATIONS: i64 = -303;
    pub const UNPROCESSABLE_VALUE_ZERO: i64 = -304;
    pub const UNPROCESSABLE_UTXO_BELOW_MINIMUM: i64 = -305;
    pub const GENERIC_ERROR: i64 = -900;
}

/// ABI-encode a signed int256 response code as 32 big-endian bytes (two's
/// complement), matching rskj `BigInteger.valueOf(code)` Solidity encoding.
/// The value must be sign-extended to the FULL 256 bits: a negative code is
/// `2^256 - |code|` (all high bytes 0xff), not merely 128-bit-wide — otherwise
/// a caller that adds back the code (e.g. the LBC `value + 900 == 0` check)
/// overflows at bit 128 instead of wrapping at bit 256 and branches wrongly
/// (mainnet #5,967,453: GENERIC_ERROR -900 mis-encoded as `2^128-900`).
fn flyover_code_output(code: i64) -> Bytes {
    let value = if code < 0 {
        // Full 256-bit two's complement: 2^256 - |code|.
        U256::ZERO.wrapping_sub(U256::from(code.unsigned_abs()))
    } else {
        U256::from(code as u64)
    };
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

/// rskj `PegUtils.getFlyoverDerivationHash`:
/// `keccak256(derivationArgumentsHash(32) || userRefundAddrBytes ||
/// lbcAddress(20) || lpBtcAddrBytes)`. Note the array-copy order puts the LBC
/// address BEFORE the LP address (NOT the parameter order). The BTC-address
/// bytes are `serializeBtcAddressWithVersion`; pre-RSKIP284 (iris) that
/// round-trips the input `[version || hash160]` arg unchanged (a single version
/// byte for every mainnet address version), so the raw 21-byte ABI args are
/// used verbatim.
fn flyover_derivation_hash(
    derivation_arguments_hash: &[u8; 32],
    user_refund_addr_bytes: &[u8],
    lbc_address: &RskAddress,
    lp_btc_addr_bytes: &[u8],
) -> [u8; 32] {
    use sha3::Digest;
    let mut preimage = Vec::with_capacity(32 + user_refund_addr_bytes.len() + 20 + lp_btc_addr_bytes.len());
    preimage.extend_from_slice(derivation_arguments_hash);
    preimage.extend_from_slice(user_refund_addr_bytes);
    preimage.extend_from_slice(lbc_address.as_slice());
    preimage.extend_from_slice(lp_btc_addr_bytes);
    sha3::Keccak256::digest(&preimage).into()
}

/// rskj `FlyoverRedeemScriptBuilderImpl.of`: prepend `PUSH(derivationHash)
/// OP_DROP` to the federation redeem script.
fn flyover_redeem_script(flyover_derivation_hash: &[u8; 32], federation_redeem: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34 + federation_redeem.len());
    script.push(32); // OP_PUSHBYTES_32
    script.extend_from_slice(flyover_derivation_hash);
    script.push(0x75); // OP_DROP
    script.extend_from_slice(federation_redeem);
    script
}

/// `registerFastBridgeBtcTransaction(bytes,uint256,bytes,bytes32,bytes,address,bytes,bool)`
///
/// Flyover (RSKIP176, iris300) peg-in. Full port of rskj
/// `BridgeSupport.registerFlyoverBtcTransaction`. Returns an int256:
/// the locked amount in wei on success, or a negative `FlyoverTxResponseCodes`
/// value on every rejection / unprocessable path. The method only ever fails
/// the tx for a malformed BTC transaction or PMT (mirrors rskj's outer
/// try/catch returning GENERIC_ERROR for those).
#[allow(clippy::too_many_arguments)]
pub fn register_fast_bridge_btc_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
    caller: RskAddress,
    call_depth: usize,
) -> Result<PrecompileOutput, PrecompileError> {
    let ok = |code: Bytes| Ok(PrecompileOutput::new(gas_cost, code));

    // Attribute anything this call records. Flyover is a second peg-in path
    // with its own refund rules, and it reaches the Bridge only through a
    // contract (`call_depth > 1`), so nothing registered here is visible to a
    // scan of top-level transactions.
    crate::silent::set_position(rsk_height_of(ctx), tx_ctx.tx_index);

    // rskj wraps the whole body in try/catch → GENERIC_ERROR. Any malformed
    // ABI / arg shape returns GENERIC_ERROR (NOT a failed tx).
    let parse = (|| -> Option<(usize, u64, usize, [u8; 32], Vec<u8>, RskAddress, Vec<u8>, bool)> {
        if args.len() < 256 {
            return None;
        }
        let btc_tx_offset = U256::from_be_slice(args.get(0..32)?).to::<usize>();
        let btc_block_height = U256::from_be_slice(args.get(32..64)?).to::<u64>();
        let pmt_offset = U256::from_be_slice(args.get(64..96)?).to::<usize>();
        let derivation_args_hash: [u8; 32] = args.get(96..128)?.try_into().ok()?;
        let user_refund_offset = U256::from_be_slice(args.get(128..160)?).to::<usize>();
        // arg5: address (right-aligned in 32 bytes → low 20 bytes).
        let lbc_address = RskAddress::from_slice(args.get(172..192)?);
        let lp_offset = U256::from_be_slice(args.get(192..224)?).to::<usize>();
        let should_transfer_to_contract = U256::from_be_slice(args.get(224..256)?) != U256::ZERO;
        let user_refund_addr = read_dynamic_bytes(args, user_refund_offset).ok()?;
        let lp_btc_addr = read_dynamic_bytes(args, lp_offset).ok()?;
        Some((
            btc_tx_offset, btc_block_height, pmt_offset, derivation_args_hash,
            user_refund_addr, lbc_address, lp_btc_addr, should_transfer_to_contract,
        ))
    })();
    let Some((
        btc_tx_offset, btc_block_height, pmt_offset, derivation_args_hash,
        user_refund_addr, lbc_address, lp_btc_addr, should_transfer_to_contract,
    )) = parse
    else {
        return ok(flyover_code_output(flyover_codes::GENERIC_ERROR));
    };

    // rskj parses BOTH BTC addresses in the ABI layer (`Bridge.registerFlyover-
    // BtcTransaction`) via `BridgeUtils.deserializeBtcAddressWithVersion`, wrapped
    // in a try/catch that returns GENERIC_ERROR on ANY exception — and this runs
    // BEFORE `bridgeSupport.registerFlyoverBtcTransaction`'s isContractTx/sender
    // checks. Post-RSKIP284 (hop400) the deserializer REQUIRES exactly 21 bytes
    // (`[version || 20-byte hash160]`), throwing `BridgeIllegalArgumentException`
    // otherwise; pre-RSKIP284 the legacy path only needs ≥21 bytes (a shorter
    // array throws `ArrayIndexOutOfBoundsException` in its `arraycopy`). Either
    // way a bad-length address yields GENERIC_ERROR. The userRefund address is
    // parsed first, the LP address second (mainnet #5,967,453: a 33-byte
    // userRefund address makes rskj return GENERIC_ERROR, not a validations code).
    let rskip284 = hardfork_cfg.has_rskip284(rsk_height_of(ctx));
    let address_len_ok = |bytes: &[u8]| -> bool {
        if rskip284 { bytes.len() == 21 } else { bytes.len() >= 21 }
    };
    if !address_len_ok(&user_refund_addr) || !address_len_ok(&lp_btc_addr) {
        return ok(flyover_code_output(flyover_codes::GENERIC_ERROR));
    }

    // rskj `isContractTx`: the rskTx must be an InternalTransaction (the Bridge
    // was reached via a contract CALL), i.e. call depth > 1.
    if call_depth <= 1 {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_NOT_CONTRACT));
    }
    // The calling contract must be the declared LBC address.
    if caller != lbc_address {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_INVALID_SENDER));
    }

    let btc_tx_data = read_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_dynamic_bytes(args, pmt_offset)?;

    // wtxid (calculateBtcTxHash over the raw bytes) — the first already-used key.
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_v2 = hardfork_cfg.has_stored_block_v2(block_number);
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // getFlyoverDerivationHash (over the raw 21-byte address args; see helper).
    let flyover_hash = flyover_derivation_hash(
        &derivation_args_hash,
        &user_refund_addr,
        &lbc_address,
        &lp_btc_addr,
    );

    // First already-used check, keyed by the wtxid.
    if is_flyover_derivation_hash_used(ctx, &btc_tx_hash, &flyover_hash) {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_ALREADY_PROCESSED));
    }

    // validationsForRegisterBtcTransaction: PMT + merkle root + confirmations.
    let validations = (|| -> bool {
        if !PartialMerkleTree::has_expected_size(&pmt_data) {
            return false;
        }
        let Some(pmt) = PartialMerkleTree::parse(&pmt_data) else { return false };
        let Some(pmt_result) = pmt.extract_matches() else { return false };
        if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
            return false;
        }
        let Some(stored_block) =
            super::btc_chain::stored_block_at_main_chain_height(ctx, btc_block_height as u32, rskip199)
        else {
            return false;
        };
        let block_hash = stored_block.header.block_hash();
        let block_merkle_root = *stored_block.header.merkle_root.to_raw_hash().as_byte_array();
        let root_valid = pmt_result.merkle_root == block_merkle_root || {
            let block_hash_bytes = {
                let mut raw = *block_hash.to_raw_hash().as_byte_array();
                raw.reverse();
                raw
            };
            match get_coinbase_information(ctx, &block_hash_bytes) {
                Some(mut wr) => {
                    wr.reverse();
                    pmt_result.merkle_root == wr
                }
                None => false,
            }
        };
        if !root_valid {
            return false;
        }
        let best_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);
        let confirmations = best_height as i64 - btc_block_height as i64 + 1;
        confirmations >= config.btc2rsk_minimum_acceptable_confirmations as i64
    })();
    if !validations {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_VALIDATIONS));
    }

    // Parse the BTC tx and compute the witness-stripped txid (getHash(false)).
    let btc_tx: BtcTransaction = deserialize(&btc_tx_data)
        .map_err(|_| PrecompileError::other("registerFastBridgeBtcTransaction: invalid BTC transaction"))?;
    let btc_tx_hash_no_witness = legacy_btc_txid(&btc_tx);

    // Second already-used check, keyed by the legacy txid (only when it differs
    // from the wtxid, i.e. a SegWit tx).
    if btc_tx_hash_no_witness != btc_tx_hash
        && is_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash)
    {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_ALREADY_PROCESSED));
    }

    // createFlyoverFederationInformation for the ACTIVE federation: build the
    // flyover redeem script (PUSH(hash) OP_DROP <fedRedeem>) and its P2SH.
    // rskj `getActiveFederation().getRedeemScript()` is format-aware: a P2SH-ERP
    // federation (RSKIP353, active at fingerroot500) yields its ERP redeem, not a
    // plain multisig — so the flyover P2SH must wrap the ERP redeem to match the
    // address the BTC tx actually paid (mainnet #5,831,167).
    let (_active_keys, fed_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    // getFlyoverFederationOutputScript / federation.getP2SHScript(): a P2SH-P2WSH
    // (format 4000, RSKIP305) federation contributes P2SH-P2WSH output scripts,
    // so the BTC tx's flyover output is matched (and the fed P2SH stored) using
    // the witness-program hash, not a plain P2SH.
    let active_format = active_federation_format(ctx, config, hardfork_cfg, block_number);
    let fed_p2sh_hash = federation_output_hash160(&fed_redeem, active_format);
    let flyover_redeem = flyover_redeem_script(&flyover_hash, &fed_redeem);
    let flyover_p2sh_hash = federation_output_hash160(&flyover_redeem, active_format);
    let flyover_script = p2sh_output_script(&flyover_p2sh_hash);

    // createFlyoverFederationInformation for the RETIRING federation (RSKIP293,
    // hop400). rskj `getRetiringFederation()` is the OLD federation once the new
    // one has activated; its redeem follows the OLD federation's STORED format
    // version (`federation.getRedeemScript()`), so an ERP retiring federation
    // gets its ERP flyover redeem. The flyover output script is a plain P2SH for
    // every federation format except P2SH-P2WSH-ERP (`getFlyoverFederationOutputScript`),
    // which rustock does not yet support — feds at hop400 are P2SH-ERP.
    let retiring_format =
        federation_format_version(ctx, super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY);
    let retiring_flyover = if hardfork_cfg.has_rskip293(block_number) {
        retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number).map(
            |(_keys, retiring_redeem)| {
                let retiring_p2sh_hash = federation_output_hash160(&retiring_redeem, retiring_format);
                let retiring_flyover_redeem = flyover_redeem_script(&flyover_hash, &retiring_redeem);
                let retiring_flyover_p2sh_hash =
                    federation_output_hash160(&retiring_flyover_redeem, retiring_format);
                let retiring_flyover_script = p2sh_output_script(&retiring_flyover_p2sh_hash);
                FlyoverFedInfo {
                    fed_p2sh_hash: retiring_p2sh_hash,
                    flyover_redeem: retiring_flyover_redeem,
                    flyover_p2sh_hash: retiring_flyover_p2sh_hash,
                    flyover_script: retiring_flyover_script,
                }
            },
        )
    } else {
        None
    };

    // validateFlyoverPeginValue: the amount sent to the flyover address(es) must
    // be non-zero (getAmountSentToAddresses sums outputs paying any flyover
    // address — under RSKIP293 both active and retiring). Under RSKIP293 it then
    // gates EACH flyover UTXO against the minimum peg-in value
    // (PegUtils.allUTXOsToFedAreAboveMinimumPeginValue; pre-RSKIP379 this is
    // isAnyUTXOAmountBelowMinimum, the path that applies at hop400).
    let pays_flyover = |script: &bitcoin::ScriptBuf| {
        *script == flyover_script
            || retiring_flyover.as_ref().is_some_and(|r| *script == r.flyover_script)
    };
    let flyover_output_values: Vec<u64> = btc_tx
        .output
        .iter()
        .filter(|o| pays_flyover(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .collect();
    let total_satoshis: u64 = flyover_output_values.iter().sum();
    if total_satoshis == 0 {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_VALUE_ZERO));
    }
    if hardfork_cfg.has_rskip293(block_number) {
        let min_pegin = config.minimum_pegin_tx_value; // RSKIP219 active alongside RSKIP293.
        if flyover_output_values.iter().any(|v| *v < min_pegin) {
            // Refused with the bitcoin kept: no refund is generated on this
            // path, and the flyover derivation hash is not marked used, so the
            // same transaction can be presented again. The flyover analogue of
            // INVALID_AMOUNT, and logged by nothing.
            record_pegin(
                SilentKind::PeginRejectedNoRefund,
                &btc_tx,
                tx_ctx,
                total_satoshis,
                "FLYOVER_UTXO_BELOW_MINIMUM",
                vec![
                    ("peginPath", FieldValue::Text("flyover".into())),
                    ("minimumSat", FieldValue::U64(min_pegin)),
                    ("fedOutputs", FieldValue::U64(flyover_output_values.len() as u64)),
                    ("logged", FieldValue::Flag(false)),
                ],
            );
            return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_UTXO_BELOW_MINIMUM));
        }
    }

    let refund_to = |should_lp: bool| -> (&[u8], bool) {
        // Refund destination: the LP BTC address when shouldTransferToContract,
        // else the user refund address. Both are `[version || hash160]`.
        if should_lp {
            (&lp_btc_addr[..], true)
        } else {
            (&user_refund_addr[..], false)
        }
    };

    // verifyLockDoesNotSurpassLockingCap (RSKIP134): a flyover peg-in is always
    // post-RSKIP134 (iris). On surplus, refund (LP or user) and mark used.
    if !verify_lock_does_not_surpass_locking_cap(ctx, config, total_satoshis) {
        // markFlyoverDerivationHashAsUsed(btcTxHashWithoutWitness, hash).
        mark_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash);
        let (refund_addr_bytes, is_lp) = refund_to(should_transfer_to_contract);
        let refund_hash160: [u8; 20] = refund_addr_bytes
            .get(1..21)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0u8; 20]);
        // The refund address version byte distinguishes P2PKH from P2SH:
        // use P2SH iff the version equals the network's P2SH header.
        let p2sh_version: u8 = match config.btc_network {
            super::constants::BtcNetwork::Mainnet => 5,
            _ => 196,
        };
        let refund_is_p2sh = refund_addr_bytes.first() == Some(&p2sh_version);
        let rsk_height = rsk_height_of(ctx);
        // generateFlyoverRejectionReleaseWithWalletProvider: the refund spends the
        // flyover UTXOs of BOTH the active and (RSKIP293) retiring feds, resolving
        // each input's redeem from its flyover P2SH (FlyoverCompatibleBtcWallet-
        // WithMultipleScripts).
        let mut flyover_redeems: Vec<Vec<u8>> = vec![flyover_redeem.clone()];
        if let Some(r) = &retiring_flyover {
            flyover_redeems.push(r.flyover_redeem.clone());
        }
        let mut extra = refund_fields(&refund_hash160, refund_is_p2sh, config);
        extra.push(("peginPath", FieldValue::Text("flyover".into())));
        // Which of the two addresses the flyover protocol chose. The event
        // log carries neither.
        extra.push(("refundedTo", FieldValue::Text(if is_lp { "liquidity_provider".into() } else { "user".into() })));
        extra.push(("logged", FieldValue::Flag(false)));
        record_pegin(
            SilentKind::PeginRefunded,
            &btc_tx,
            tx_ctx,
            total_satoshis,
            "FLYOVER_PEGIN_CAP_SURPASSED",
            extra,
        );
        emit_flyover_rejection_release(
            ctx, &btc_tx, &refund_hash160, refund_is_p2sh, total_satoshis,
            &flyover_redeems, rsk_height, config, hardfork_cfg, tx_ctx,
        );
        return ok(flyover_code_output(if is_lp {
            flyover_codes::REFUNDED_LP
        } else {
            flyover_codes::REFUNDED_USER
        }));
    }

    record_pegin(
        SilentKind::PeginAccepted,
        &btc_tx,
        tx_ctx,
        total_satoshis,
        "ACCEPTED",
        vec![
            ("peginPath", FieldValue::Text("flyover".into())),
            ("destination", FieldValue::Addr(lbc_address)),
            // FALSE AT EVERY HEIGHT, today: registerFlyoverBtcTransaction
            // calls no eventLogger in rskj or here, so a Flyover peg-in is in
            // no receipt and so in no event index.
            //
            // WHEN A FUTURE UPGRADE MAKES THE BRIDGE LOG IT, change this to
            // the activation predicate for that RSKIP -- e.g.
            // `hardfork_cfg.has_rskipNNN(rsk_height)` -- at the same time as
            // adding the log call above. The reconstruction gate reads this
            // flag per topic, so setting it correctly is what stops the
            // synthesised event and the real one from both existing across
            // the activation. Leaving it hardcoded false would duplicate
            // every Flyover peg-in from that block onward.
            ("logged", FieldValue::Flag(false)),
        ],
    );

    // transferTo(lbcAddress, amount): credit the LBC contract.
    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_satoshis);
    if !rbtc_amount.is_zero() {
        let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, lbc_address, rbtc_amount);
    }

    // saveFlyoverActiveFederationDataInStorage:
    //   - mark the flyover hash used (keyed by the legacy txid)
    //   - persist the flyover federation information
    //   - add the flyover UTXOs to the ACTIVE federation UTXO set
    mark_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash);
    set_flyover_federation_information(ctx, &flyover_hash, &fed_p2sh_hash, &flyover_p2sh_hash);

    let rsk_height = rsk_height_of(ctx);
    let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
    register_federation_outputs(ctx, &btc_tx, &flyover_script, active_utxo_key);

    // saveFlyoverRetiringFederationDataInStorage (RSKIP293): only when the
    // retiring fed actually received flyover UTXOs (rskj guards on a non-empty
    // utxosForRetiringFed list). markFlyoverDerivationHashAsUsed is called again
    // (idempotent) and the retiring flyover fed info is persisted under the same
    // key scheme keyed by ITS flyover P2SH hash; the UTXOs go to the retiring
    // (old) federation set.
    if let Some(r) = &retiring_flyover {
        if btc_tx.output.iter().any(|o| o.script_pubkey == r.flyover_script) {
            mark_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash);
            set_flyover_federation_information(
                ctx, &flyover_hash, &r.fed_p2sh_hash, &r.flyover_p2sh_hash,
            );
            register_federation_outputs(
                ctx, &btc_tx, &r.flyover_script, super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
            );
        }
    }

    // Returns the locked amount in wei (co.rsk.core.Coin.fromBitcoin.asBigInteger).
    ok(Bytes::copy_from_slice(&rbtc_amount.to_be_bytes::<32>()))
}

/// Flyover federation information for one federation (active or retiring): the
/// destination fed's redeem-script P2SH hash, plus the derived flyover redeem,
/// its P2SH hash, and its P2SH output script. Mirrors rskj
/// `createFlyoverFederationInformation` + `getFlyoverFederationOutputScript`.
struct FlyoverFedInfo {
    fed_p2sh_hash: [u8; 20],
    flyover_redeem: Vec<u8>,
    flyover_p2sh_hash: [u8; 20],
    flyover_script: bitcoin::ScriptBuf,
}

/// Current RSK execution block number.
fn rsk_height_of<CTX: crate::RskContextTr>(ctx: &mut CTX) -> u64 {
    revm::context_interface::Block::number(ctx.block()).to::<u64>()
}

/// rskj `BridgeStorageProvider.isFlyoverDerivationHashUsed`: the cell at
/// `fastBridgeHashUsedInBtcTx-<btcTxHash.toString()><derivationHash.toString()>`
/// holds a single TRUE byte. `Sha256Hash.toString()` is DISPLAY order;
/// `Keccak256.toString()` is forward order.
fn is_flyover_derivation_hash_used<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    flyover_hash: &[u8; 32],
) -> bool {
    let key = flyover_hash_used_key(btc_tx_hash, flyover_hash);
    super::storage::bridge_load_raw(ctx, key)
        .is_some_and(|d| d.len() == 1 && d[0] == 1)
}

/// rskj `markFlyoverDerivationHashAsUsed` → `saveFlyoverDerivationHash`:
/// `addStorageBytes(key, [TRUE])`.
fn mark_flyover_derivation_hash_used<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    flyover_hash: &[u8; 32],
) {
    let key = flyover_hash_used_key(btc_tx_hash, flyover_hash);
    super::storage::bridge_store_raw(ctx, key, Some(vec![1]));
}

/// rskj `BridgeStorageProvider.setPegoutTxSigHash`/`savePegoutTxSigHashes`
/// (RSKIP379): index a created pegout by the legacy SIGHASH_ALL of its first
/// input (`BitcoinUtils.getSigHashForPegoutIndex` → `hashForSignature(0,
/// redeemScript, ALL, false)`). The key identifier is the sigHash's
/// `Sha256Hash.toString()`, which for a `hashForSignature` result is bitcoinj
/// `Sha256Hash.twiceOf` = INTERNAL byte order — NOT reversed, unlike a txid's
/// `getHash().toString()` (`wrapReversed`). So the hex is taken directly, not
/// via `btc_hash_hex_display`. Value is a single TRUE byte (`new byte[]{1}`).
fn save_pegout_tx_sig_hash<CTX: crate::RskContextTr>(ctx: &mut CTX, sig_hash: &[u8; 32]) {
    let key = compound_key(super::storage::PEGOUT_TX_SIG_HASH_KEY, "-", &to_hex(sig_hash));
    super::storage::bridge_store_raw(ctx, key, Some(vec![1]));
}

/// rskj `BitcoinUtils.getSigHashForPegoutIndex`: index a created pegout by the
/// `hashForSignature(0, redeemScript, ALL, false)` of its signatures-stripped tx.
///
/// **Consensus-critical rskj quirk:** for a *segwit* pegout this is NOT the
/// standard legacy sighash. bitcoinj's `hashForSignature` clears the input
/// scriptSigs and sets input 0's to the redeem, but leaves the (base) witnesses
/// in place, and `BtcTransaction.bitcoinSerializeToStream` writes the witness
/// bytes whenever `hasWitness()` — so the preimage is the **segwit**
/// serialization (marker/flag + witnesses), not a witness-stripped legacy one.
/// We reproduce that byte-for-byte: clear scriptSigs (input 0 → redeem), keep the
/// witnesses, segwit-serialize, append the 4-byte LE SIGHASH_ALL, double-SHA256.
/// A legacy pegout (no witness) takes the ordinary legacy sighash.
fn first_input_sig_hash(tx: &BtcTransaction, redeem0: &[u8], _value0: u64) -> [u8; 32] {
    if tx.input.iter().all(|i| i.witness.is_empty()) {
        return super::release_tx::legacy_sighash_all(tx, 0, redeem0);
    }
    use bitcoin::hashes::Hash;
    let mut copy = tx.clone();
    for (i, input) in copy.input.iter_mut().enumerate() {
        input.script_sig = if i == 0 {
            bitcoin::ScriptBuf::from_bytes(redeem0.to_vec())
        } else {
            bitcoin::ScriptBuf::new()
        };
    }
    let mut preimage = bitcoin::consensus::serialize(&copy);
    preimage.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // SIGHASH_ALL, 4-byte LE
    *bitcoin::hashes::sha256d::Hash::hash(&preimage).as_byte_array()
}

/// rskj `BridgeStorageProvider.setReleaseOutpointsValues` (RSKIP305, reed800):
/// inside `processReleaseTransactionInfo`, right after the RSKIP428
/// `pegout_transaction_created` event, every settled release also persists its
/// spent-input values (bitcoinj VarInt concatenation, `serializeOutpointsValues`)
/// keyed by `releasesOutpointsValues-<btcTxHash>` (display-order hex). No-op
/// before reed800. (Mainnet #8,052,418.)
fn save_release_outpoints_values<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash_display: &[u8; 32],
    outpoint_values: &[u64],
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) {
    if !hardfork_cfg.has_rskip305(block_number) {
        return;
    }
    let serialized: Vec<u8> =
        outpoint_values.iter().flat_map(|&v| super::events::encode_varint(v)).collect();
    let key = compound_key(
        super::storage::RELEASES_OUTPOINTS_VALUES_KEY,
        "-",
        &to_hex(btc_tx_hash_display),
    );
    super::storage::bridge_store_raw(ctx, key, Some(serialized));
}

/// rskj `BridgeStorageProvider.getReleaseOutpointsValues`: the per-input spent
/// values stored when a release tx is created, keyed by its witness-stripped
/// hash. Decodes the bitcoinj `VarInt` concatenation (`UtxoUtils`).
fn load_release_outpoints_values<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash_display: &[u8; 32],
) -> Vec<u64> {
    let key = compound_key(
        super::storage::RELEASES_OUTPOINTS_VALUES_KEY,
        "-",
        &to_hex(btc_tx_hash_display),
    );
    let Some(bytes) = super::storage::bridge_load_raw(ctx, key) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let (v, consumed) = match bytes[i] {
            0xFF => (
                u64::from_le_bytes(bytes.get(i + 1..i + 9).and_then(|s| s.try_into().ok()).unwrap_or([0; 8])),
                9,
            ),
            0xFE => (
                u32::from_le_bytes(bytes.get(i + 1..i + 5).and_then(|s| s.try_into().ok()).unwrap_or([0; 4])) as u64,
                5,
            ),
            0xFD => (
                u16::from_le_bytes(bytes.get(i + 1..i + 3).and_then(|s| s.try_into().ok()).unwrap_or([0; 2])) as u64,
                3,
            ),
            b => (b as u64, 1),
        };
        values.push(v);
        i += consumed;
    }
    values
}

/// rskj `getStorageKeyForFlyoverHash`:
/// `fastBridgeHashUsedInBtcTx-` + `Sha256Hash.toString()` (display order) +
/// `Keccak256.toString()` (forward order).
fn flyover_hash_used_key(btc_tx_hash: &[u8; 32], flyover_hash: &[u8; 32]) -> U256 {
    let identifier = format!(
        "{}{}",
        super::tx::btc_hash_hex_display(btc_tx_hash),
        to_hex(flyover_hash)
    );
    compound_key(FAST_BRIDGE_HASH_USED_KEY, "-", &identifier)
}

/// rskj `setFlyoverFederationInformation` → `saveFlyoverFederationInformation`:
/// store `RLP([derivationHash, federationRedeemScriptHash])` keyed by
/// `fastBridgeFederationInformation-` + hex(flyoverFederationRedeemScriptHash).
fn set_flyover_federation_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    flyover_hash: &[u8; 32],
    fed_p2sh_hash: &[u8; 20],
    flyover_p2sh_hash: &[u8; 20],
) {
    let key = compound_key(
        FAST_BRIDGE_FEDERATION_INFO_KEY,
        "-",
        &to_hex(flyover_p2sh_hash),
    );
    let value = rlp_encode_list(&[
        rlp_encode_element(flyover_hash),
        rlp_encode_element(fed_p2sh_hash),
    ]);
    super::storage::bridge_store_raw(ctx, key, Some(value));
}

/// rskj `BridgeStorageProvider.getFlyoverFederationInformation`: read the
/// `RLP[derivationHash(32), fedRedeemScriptHash(20)]` stored for a flyover P2SH
/// hash160, or `None` if the input is not a flyover UTXO.
fn get_flyover_federation_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    flyover_p2sh_hash: &[u8; 20],
) -> Option<([u8; 32], [u8; 20])> {
    let key = compound_key(FAST_BRIDGE_FEDERATION_INFO_KEY, "-", &to_hex(flyover_p2sh_hash));
    let data = super::storage::bridge_load_raw(ctx, key)?;
    let items = super::serialization::rlp_decode_list(&data)?;
    let derivation: [u8; 32] = items.first()?.as_slice().try_into().ok()?;
    let fed_hash: [u8; 20] = items.get(1)?.as_slice().try_into().ok()?;
    Some((derivation, fed_hash))
}

/// Extract the hash160 from a P2SH output script
/// (`OP_HASH160 <20 bytes> OP_EQUAL`).
fn p2sh_script_hash160(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        script[2..22].try_into().ok()
    } else {
        None
    }
}

/// rskj `FlyoverCompatibleBtcWalletWithStorage.findRedeemDataFromScriptHash`:
/// resolve the redeem script for each spending UTXO. A flyover UTXO (whose P2SH
/// hash has stored flyover federation information) spends with
/// `PUSH32 <derivationHash> OP_DROP <fedRedeem>`, where `fedRedeem` is the
/// destination federation's redeem (the active or retiring federation whose
/// hash160 matches the stored `fedRedeemScriptHash`); every other UTXO spends
/// with `default_redeem`. Returns one redeem per UTXO, in input order.
///
/// `candidate_fed_redeems` lists the redeem scripts of the federations
/// `getDestinationFederation` searches (active + retiring), used to rebuild the
/// inner fed redeem from the stored hash. Returns a sparse map of per-UTXO
/// flyover redeem overrides keyed by `(tx_hash, vout)`; UTXOs absent from the
/// map spend with the default redeem. The map is stable across coin selection
/// (it does not depend on the mutating available-UTXO list).
fn resolve_flyover_input_redeems<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    utxos: &[BridgeUtxo],
    candidate_fed_redeems: &[Vec<u8>],
) -> std::collections::HashMap<([u8; 32], u32), Vec<u8>> {
    let mut overrides = std::collections::HashMap::new();
    for u in utxos {
        let flyover = p2sh_script_hash160(&u.script)
            .and_then(|h| get_flyover_federation_information(ctx, &h))
            .and_then(|(derivation, fed_hash)| {
                // The stored fedRedeemScriptHash is `federation.getP2SHScript()
                // .getPubKeyHash()` — a plain-P2SH hash for a legacy fed, but a
                // P2SH-P2WSH (witness-program) hash for a format-4000 segwit fed.
                // Match a candidate by either form.
                candidate_fed_redeems
                    .iter()
                    .find(|r| {
                        redeem_script_hash160(r) == fed_hash
                            || federation_output_hash160(r, 4000) == fed_hash
                    })
                    .map(|fed_redeem| flyover_redeem_script(&derivation, fed_redeem))
            });
        if let Some(redeem) = flyover {
            overrides.insert((u.tx_hash, u.vout), redeem);
        }
    }
    overrides
}

/// rskj `generateFlyoverRejectionReleaseWithWalletProvider`: build an
/// empty-wallet refund of the flyover-federation outputs to `refund_hash160`
/// using the FLYOVER redeem script(s), enqueue it, and log release_requested.
///
/// `flyover_redeems` is the list of candidate flyover redeem scripts (the active
/// fed's, plus the retiring fed's under RSKIP293). The refund spends every output
/// paying any of their flyover P2SH addresses; each input is resolved to its own
/// redeem (rskj `FlyoverCompatibleBtcWalletWithMultipleScripts`).
#[allow(clippy::too_many_arguments)]
fn emit_flyover_rejection_release<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    refund_hash160: &[u8; 20],
    refund_is_p2sh: bool,
    total_satoshis: u64,
    flyover_redeems: &[Vec<u8>],
    rsk_height: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) {
    // Map each flyover P2SH output script → its redeem, then gather the spending
    // UTXOs in output order with their resolved redeem.
    let scripts: Vec<(bitcoin::ScriptBuf, &[u8])> = flyover_redeems
        .iter()
        .map(|r| (p2sh_output_script(&redeem_script_hash160(r)), r.as_slice()))
        .collect();
    let mut utxos: Vec<BridgeUtxo> = Vec::new();
    let mut input_redeems: Vec<&[u8]> = Vec::new();
    for (index, o) in btc_tx.output.iter().enumerate() {
        if let Some((_, redeem)) = scripts.iter().find(|(s, _)| *s == o.script_pubkey) {
            utxos.push(BridgeUtxo {
                tx_hash: btc_txid_event_bytes(btc_tx),
                vout: index as u32,
                value_satoshis: o.value.to_sat(),
                height: 0,
                script: o.script_pubkey.to_bytes(),
                coinbase: btc_tx.is_coinbase(),
            });
            input_redeems.push(redeem);
        }
    }
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    let tx_version = if hardfork_cfg.has_rskip201(rsk_height) { 2 } else { 1 };
    let refund_script = if refund_is_p2sh {
        p2sh_output_script(refund_hash160)
    } else {
        p2pkh_output_script(refund_hash160)
    };
    // When every spent UTXO shares a single redeem (the common case — only the
    // active fed received funds), defer to the shared single-redeem builder for
    // byte-exact parity; otherwise build the empty-wallet refund with per-input
    // redeems (rskj buildEmptyWalletTo over the multi-script flyover wallet).
    let built = if input_redeems.iter().all(|r| *r == input_redeems.first().copied().unwrap_or(&[])) {
        let single = input_redeems.first().copied().unwrap_or(&[]);
        super::release_tx::build_empty_wallet_to(
            &utxos, &refund_script, single, fee_per_kb, tx_version,
        )
    } else {
        build_flyover_empty_wallet_multi(
            &utxos, &input_redeems, &refund_script, fee_per_kb, tx_version,
        )
    };
    if let Some(built) = built {
        let use_tx_hash = hardfork_cfg.has_rskip146(rsk_height);
        let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
        waiting.push(PegoutWaitingForConfirmations {
            btc_tx_raw: btc_serialize(&built.tx),
            rsk_block_height: rsk_height,
            rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
        });
        release_requested_or_record(
            ctx,
            use_tx_hash,
            &tx_ctx.rsk_tx_hash,
            &btc_txid_event_bytes(&built.tx),
            total_satoshis,
        );
        store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);
    }
}

/// rskj `ReleaseTransactionBuilder.buildEmptyWalletTo` over a multi-script
/// flyover wallet: like `release_tx::build_empty_wallet_to` but each input is
/// signed/sized with its OWN redeem script (`input_redeems[i]` pairs with
/// `utxos[i]`). Used only for the rare RSKIP293 locking-cap rejection where a
/// single flyover tx funds BOTH the active and retiring flyover feds.
///
/// The fee sizing mirrors bitcoinj exactly: a single downward fee adjustment of
/// `feePerKb * size / 1000`, where `size` is the empty-scriptSig serialized
/// length plus, per input, `threshold * SIG_SIZE + redeemScript.len()`. The
/// final placeholder-filled tx must not exceed MAX_STANDARD_TX_SIZE.
fn build_flyover_empty_wallet_multi(
    utxos: &[BridgeUtxo],
    input_redeems: &[&[u8]],
    refund_script: &bitcoin::ScriptBuf,
    fee_per_kb: u64,
    version: i32,
) -> Option<super::release_tx::BuiltPegout> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, TxIn, TxOut, Witness,
    };
    // bitcoinj constants (see release_tx.rs): SIG_SIZE=75, min fee 5000 sat/kB,
    // MAX_STANDARD_TX_SIZE=100k.
    const SIG_SIZE: usize = 75;
    const REFERENCE_DEFAULT_MIN_TX_FEE: u64 = 5000;
    const MAX_STANDARD_TX_SIZE: usize = 100_000;

    if utxos.is_empty() {
        return None;
    }
    let thresholds: Vec<usize> = input_redeems
        .iter()
        .map(|r| super::release_tx::redeem_script_threshold(r))
        .collect();
    if thresholds.contains(&0) {
        return None;
    }
    let gathered: u64 = utxos.iter().map(|u| u.value_satoshis).sum();

    // Convert a stored UTXO hash (bitcoinj display/stored byte order) into a
    // rust-bitcoin Txid (internal byte order).
    let txid_from_stored = |stored: &[u8; 32]| -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        let mut internal = *stored;
        internal.reverse();
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(internal))
    };
    let inputs: Vec<TxIn> = utxos
        .iter()
        .map(|u| TxIn {
            previous_output: OutPoint {
                txid: txid_from_stored(&u.tx_hash),
                vout: u.vout,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        })
        .collect();
    let mut tx = BtcTransaction {
        version: Version(version),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(gathered),
            script_pubkey: refund_script.clone(),
        }],
    };

    let base_size = bitcoin::consensus::serialize(&tx).len();
    let sig_estimate: usize = input_redeems
        .iter()
        .zip(&thresholds)
        .map(|(r, t)| t * SIG_SIZE + r.len())
        .sum();
    let size = base_size + sig_estimate;
    let fee_rate = fee_per_kb.max(REFERENCE_DEFAULT_MIN_TX_FEE);
    let fee = fee_rate * size as u64 / 1000;
    if fee >= gathered {
        return None;
    }
    let value = gathered - fee;
    if value < super::release_tx::min_non_dust_value(refund_script) {
        return None;
    }
    tx.output[0].value = Amount::from_sat(value);

    for (input, (redeem, threshold)) in tx.input.iter_mut().zip(input_redeems.iter().zip(&thresholds)) {
        input.script_sig =
            bitcoin::ScriptBuf::from_bytes(super::release_tx::placeholder_scriptsig(redeem, *threshold));
    }
    if bitcoin::consensus::serialize(&tx).len() > MAX_STANDARD_TX_SIZE {
        return None;
    }
    Some(super::release_tx::BuiltPegout { tx, used_utxos: utxos.to_vec() })
}

// ---------------------------------------------------------------------------
// releaseBtc
// ---------------------------------------------------------------------------

/// `releaseBtc()` — enqueue a peg-out request.
///
/// The caller sends RBTC to the Bridge address. This method enqueues a
/// release request that will be batched and signed by `updateCollections`.
///
/// Matches rskj's `BridgeSupport.releaseBtc()`:
/// - Reads the call value from the Bridge's received balance delta
/// - Validates minimum peg-out amount (in satoshis)
/// - Derives the BTC destination address from the RSK tx sender's public key
///   (matches `BridgeUtils.recoverBtcAddressFromEthTransaction`)
/// - Post-RSKIP146: stores to `releaseRequestQueueWithTxHash` (triple format)
/// - Pre-RSKIP146: stores to `releaseRequestQueue` (pair format)
pub fn release_btc<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
    caller: alloy_primitives::Address,
    call_depth: usize,
    call_value_wei: U256,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    // rskj `BridgeSupport.releaseBtc` reads `rskTx.getValue()` — the value of
    // THIS call (the CALL's endowment, `msg.getEndowment()` for an internal
    // call), NOT the top-level transaction's value. For a contract that forwards
    // its own RBTC to the Bridge, the endowment differs from the outer tx value
    // (mainnet #6,223,939 tx[0]: tx value 0, but the contract sends 10000 sat).

    // NOTE: do NOT early-return on a zero call value. rskj's
    // `BridgeSupport.releaseBtc` always forwards to `requestRelease`, which
    // rejects a below-minimum amount (a zero value is below any minimum) and,
    // post-RSKIP185, refunds the sender and emits `release_request_rejected`.
    // A zero-value EOA call therefore still produces a receipts-visible log
    // (mainnet #4,212,341 tx[3]: value=0 empty-input Bridge call → LOW_AMOUNT).

    // Convert Wei to satoshis: 1 satoshi = 10^10 wei
    let satoshis_per_wei = U256::from(10_000_000_000u64);
    let amount_satoshis_u256 = call_value_wei / satoshis_per_wei;
    let amount_satoshis = amount_satoshis_u256.to::<u64>();

    // rskj `BridgeSupport.releaseBtc` (BridgeSupport.java:891) rejects a peg-out
    // requested by a CONTRACT before any min-value check, because a BTC address
    // cannot be derived from a contract. `BridgeUtils.isContractTx` is true when
    // the Bridge is reached via a CALL from contract code (an InternalTransaction),
    // i.e. at journal depth > 1; a top-level transaction to the Bridge is depth 1.
    // The reject sender is the IMMEDIATE caller (`rskTx.getSender()` of the
    // InternalTransaction = `getOwnerRskAddress()` = the calling contract), and
    // the value is NOT refunded. Post-RSKIP185 it emits `release_request_rejected`
    // with CALLER_CONTRACT(2); pre-RSKIP185 it throws OutOfGas (consume all gas).
    // (mainnet #6,223,900..6,223,933 tx[2]: contract 0x4309efcc CALLs releaseBtc →
    // CALLER_CONTRACT with sender = the contract, no refund.)
    if call_depth > 1 {
        if hardfork_cfg.has_rskip185(block_number) {
            let event_amount = if hardfork_cfg.has_rskip427(block_number) {
                call_value_wei
            } else {
                U256::from(amount_satoshis)
            };
            super::events::log_release_request_rejected(
                ctx,
                caller,
                event_amount,
                2, // RejectedPegoutReason.CALLER_CONTRACT
            );
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }
        // Pre-RSKIP185: rskj throws Program.OutOfGasException (no event, no refund).
        return Err(PrecompileError::OutOfGas);
    }

    // rskj BridgeSupport.requestRelease: post-RSKIP219 the minimum is INCLUSIVE
    // and is the max of `minimumPegoutTxValue` and a fee-based estimate; the
    // legacy rule is EXCLUSIVE (value must be strictly greater than the legacy
    // minimum). On rejection the reason distinguishes LOW_AMOUNT from
    // FEE_ABOVE_VALUE (the latter when the fee estimate is the binding bound).
    let reject_reason: Option<u64> = if hardfork_cfg.has_rskip219(block_number) {
        let fee_per_kb = get_effective_fee_per_kb(ctx, config);
        // rskj getRegularPegoutTxSize uses getActiveFederation().getRedeemScript():
        // the active federation's actual (format-aware, possibly P2SH-ERP) redeem
        // script and its required-signature count drive the fee-based minimum.
        let (active_keys, active_redeem) =
            active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
        let num_sigs_required = (active_keys.len() / 2 + 1) as u64;
        let require_funds_for_fee = require_funds_for_fee(
            &active_redeem,
            num_sigs_required,
            fee_per_kb,
            hardfork_cfg.has_rskip271(block_number),
            config,
        );
        let min_value = config.minimum_pegout_tx_value.max(require_funds_for_fee);
        if amount_satoshis < min_value {
            // rskj: FEE_ABOVE_VALUE when minValue == requireFundsForFee, else
            // LOW_AMOUNT. RejectedPegoutReason: LOW_AMOUNT=1, FEE_ABOVE_VALUE=3.
            Some(if min_value == require_funds_for_fee { 3 } else { 1 })
        } else {
            None
        }
    } else if amount_satoshis_u256 <= U256::from(config.legacy_minimum_pegout_tx_value) {
        Some(1) // legacy: always LOW_AMOUNT
    } else {
        None
    };

    if let Some(reason) = reject_reason {
        // RSKIP185 (Iris300): refund the value to the sender and emit the
        // release_request_rejected event. Before RSKIP185 the request was
        // silently dropped (value retained by the Bridge).
        if hardfork_cfg.has_rskip185(block_number) {
            // rskj refundAndEmitRejectEvent: from RSKIP427 (lovell700) the refund
            // is the FULL wei call value; before 427 it was
            // `Coin.fromBitcoin(weis.toBitcoin())` — the wei truncated to satoshi
            // granularity, which silently kept the sub-satoshi remainder in the
            // Bridge (mainnet #8,010,127: a 340,353-sat pegout below the 400,000
            // minimum, 4,349,191,903 wei of sub-satoshi remainder).
            let refund_wei = if hardfork_cfg.has_rskip427(block_number) {
                call_value_wei
            } else {
                amount_satoshis_u256 * U256::from(10_000_000_000u64)
            };
            let _ = ctx
                .journal_mut()
                .transfer(BRIDGE_ADDR, tx_ctx.rsk_sender, refund_wei);
            // Pre-RSKIP427 the event amount is in satoshis; post-427 it is the
            // full wei call value (rskj logs `releaseRequestedValueInWeis`).
            let event_amount = if hardfork_cfg.has_rskip427(block_number) {
                call_value_wei
            } else {
                U256::from(amount_satoshis)
            };
            super::events::log_release_request_rejected(
                ctx,
                tx_ctx.rsk_sender,
                event_amount,
                reason,
            );
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // BTC destination: RIPEMD160(SHA256(compressed_pubkey)) derived from tx sender.
    // tx_ctx.btc_sender_hash160 was computed by the executor from the RSK tx signature,
    // matching rskj's BridgeUtils.recoverBtcAddressFromEthTransaction.
    let btc_dest = tx_ctx.btc_sender_hash160;

    let use_tx_hash_format = hardfork_cfg.has_rskip146(block_number);

    if use_tx_hash_format {
        // Post-RSKIP146: store in releaseRequestQueueWithTxHash (triple format)
        let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY);
        let existing = bridge_load_bytes(ctx, key);
        let mut queue = deserialize_release_queue_with_hash(&existing);
        queue.push(ReleaseRequest {
            btc_dest_hash160: btc_dest,
            amount_satoshis,
            rsk_tx_hash: Some(tx_ctx.rsk_tx_hash),
        });
        let updated = serialize_release_queue_with_hash(&queue);
        bridge_store_bytes(ctx, key, &updated);
    } else {
        // Pre-RSKIP146: store in releaseRequestQueue (pair format)
        let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
        let existing = bridge_load_bytes(ctx, key);
        let mut queue = deserialize_release_queue_legacy(&existing);
        queue.push(ReleaseRequest {
            btc_dest_hash160: btc_dest,
            amount_satoshis,
            rsk_tx_hash: None,
        });
        let updated = serialize_release_queue_legacy(&queue);
        bridge_store_bytes(ctx, key, &updated);
    }

    // RSKIP185 (Iris300): an accepted peg-out emits release_request_received
    // (rskj BridgeSupport.requestRelease). The destination is the sender's
    // P2PKH BTC address. Pre-RSKIP326 the event carries the 20-byte hash160,
    // post-326 the Base58 string; pre-RSKIP427 the amount is satoshis, post-427
    // the full wei call value.
    if hardfork_cfg.has_rskip185(block_number) {
        let dest_base58 = sender_base58_address(&btc_dest, false, config);
        let event_amount = if hardfork_cfg.has_rskip427(block_number) {
            call_value_wei
        } else {
            U256::from(amount_satoshis)
        };
        super::events::log_release_request_received(
            ctx,
            tx_ctx.rsk_sender,
            &btc_dest,
            &dest_base58,
            event_amount,
            hardfork_cfg.has_rskip326(block_number),
        );
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// updateCollections
// ---------------------------------------------------------------------------

/// `updateCollections()` — orchestrator for peg-out processing.
///
/// Matches rskj's `BridgeSupport.updateCollections()`. Key state transitions:
///
/// 1. **Process pending releases** from the release request queue:
///    - Load pending requests (from `releaseRequestQueueWithTxHash` or legacy queue)
///    - Build unsigned BTC peg-out transaction(s) using federation UTXOs
///    - Store in `pegoutsWaitingForConfirmations` (or `releaseTransactionSetWithTxHash`)
///    - Clear the processed queue entries
///    - Update `nextPegoutHeight` (post-RSKIP271)
///
/// 2. **Promote confirmed pegouts** to signing stage:
///    - For each entry in `pegoutsWaitingForConfirmations` that has enough RSK block
///      confirmations (`rsk2btc_minimum_acceptable_confirmations`), move it to
///      `rskTxsWaitingFS` (pegoutsWaitingForSignatures).
pub fn update_collections<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_tx_hash = hardfork_cfg.has_rskip146(block_number);
    let use_rskip271 = hardfork_cfg.has_rskip271(block_number);

    // rskj BridgeSupport.updateCollections logs an update_collections event;
    // the single-topic legacy format applies before RSKIP146, the Solidity
    // format afterwards.
    if use_tx_hash {
        super::events::log_solidity_update_collections(ctx, tx_ctx.rsk_sender);
    } else {
        super::events::log_legacy_update_collections(ctx, tx_ctx.rsk_sender);
    }

    // rskj BridgeStorageProvider.save() persists every collection the call
    // LOADED, including empty ones. updateCollections always loads the
    // active federation UTXO list (getActiveFederationWallet), the release
    // request queue, the release tx set and the signatures-waiting map, so
    // their RLP-empty `[0xc0]` entries materialize on the first call
    // (mainnet #615). Post-RSKIP146 the with-txhash queue/set variants are
    // loaded (and thus materialized) too.
    {
        let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
        let mut touched: Vec<&str> = vec![
            active_utxo_key,
            RELEASE_REQUEST_QUEUE_KEY,
            PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY,
            PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
        ];
        if use_tx_hash {
            touched.push(super::storage::RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY);
            touched.push(super::storage::PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY);
        }
        for key_name in touched {
            let key = bridge_storage_key(key_name);
            if super::storage::bridge_load_raw(ctx, key).is_none() {
                // RLP.encodeList() of an empty collection.
                super::storage::bridge_store_raw(ctx, key, Some(vec![0xc0]));
            }
        }
    }

    // updateCollections loads the active federation (getActiveFederationWallet),
    // so rskj's save() re-serializes it. Post-RSKIP123 the first such save
    // migrates `newFederation` to the multikey member format and writes
    // `newFederationFormatVersion` (mainnet #1,591,009).
    super::federation::save_new_federation_multikey(ctx, hardfork_cfg, block_number);

    // -----------------------------------------------------------------------
    // Step 0: Funds migration (rskj processFundsMigration) — while the new
    // federation is in its migration window, each updateCollections call
    // moves the retiring federation's balance into the active federation
    // with a migration transaction queued like a peg-out.
    // -----------------------------------------------------------------------
    process_funds_migration(ctx, config, hardfork_cfg, block_number, tx_ctx);

    // -----------------------------------------------------------------------
    // Step 1: Process peg-out requests (rskj processPegoutRequests)
    // -----------------------------------------------------------------------
    let should_process_requests = if use_rskip271 {
        // RSKIP271: batching — only process when nextPegoutHeight ≤ current block
        let next_height =
            super::storage::bridge_load_u256(ctx, NEXT_PEGOUT_HEIGHT_KEY).to::<u64>();
        block_number >= next_height
    } else {
        true // Pre-RSKIP271: process every block
    };

    if should_process_requests {
        // rskj `getReleaseRequestQueue` concatenates the legacy queue with the
        // with-txhash one; it does not pick whichever is populated. Reading
        // only one was correct on mainnet by circumstance -- the legacy queue
        // was drained before RSKIP146 activated at iris300 (#3,614,800) and
        // every request since carries a tx hash -- but it is not correct by
        // construction, and an entry that ever landed in the legacy queue
        // afterwards would have been silently stranded there forever.
        let pending = load_release_request_queue(ctx, use_tx_hash);

        // RSKIP271: rskj processPegoutsInBatch sets nextPegoutHeight whenever
        // the queue ends up empty — including the case where it was empty to
        // begin with (BridgeSupport.processPegoutsInBatch line 1555). Track
        // whether the queue is empty after this call so we can mirror that.
        let mut queue_emptied = pending.is_empty();

        if !pending.is_empty() {
            // rskj getActiveFederation().getRedeemScript(): the spending
            // federation's redeem follows its STORED format version (plain /
            // NON_STANDARD_ERP / P2SH-ERP / P2SH-P2WSH-ERP), not the plain
            // multisig builder — otherwise the pegout's per-input placeholder
            // scriptSig and the change P2SH (hence the txid) fork. See #4,677,503.
            let (federation_keys, redeem_script) =
                active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
            if !federation_keys.is_empty() {
                // getActiveFederationAddress / isSegwitCompatible: a P2SH-P2WSH
                // (format 4000, RSKIP305) active federation pays change to its
                // P2SH-P2WSH address and is spent with segwit inputs.
                let active_format =
                    active_federation_format(ctx, config, hardfork_cfg, block_number);
                let is_segwit = active_format >= 4000;
                let change_script =
                    p2sh_output_script(&federation_output_hash160(&redeem_script, active_format));
                let fee_per_kb = get_effective_fee_per_kb(ctx, config);
                let tx_version = if hardfork_cfg.has_rskip201(block_number) { 2 } else { 1 };

                let active_utxo_key =
                    active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
                let mut available = load_utxos_at(ctx, active_utxo_key);

                // rskj getActiveFederationWallet builds a FlyoverCompatibleBtcWallet:
                // resolve a flyover UTXO's redeem per input (PUSH32 <hash> OP_DROP
                // <fedRedeem>). getDestinationFederation searches active + retiring.
                let mut candidate_fed_redeems = vec![redeem_script.clone()];
                if let Some((_, retiring_redeem)) =
                    retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number)
                {
                    candidate_fed_redeems.push(retiring_redeem);
                }
                let flyover_overrides =
                    resolve_flyover_input_redeems(ctx, &available, &candidate_fed_redeems);
                let redeem_for = |u: &BridgeUtxo| -> &[u8] {
                    flyover_overrides
                        .get(&(u.tx_hash, u.vout))
                        .map(|r| r.as_slice())
                        .unwrap_or(redeem_script.as_slice())
                };

                let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
                let mut created_any = false;

                // Settle one successfully built peg-out: remove the spent
                // UTXOs, queue it for confirmations, (RSKIP146+) log
                // release_requested with the creation RSK tx hash, and burn
                // the dusty-change surplus (adjustBalancesIfChangeOutputWasDust).
                let settle = |ctx: &mut CTX,
                                  built: super::release_tx::BuiltPegout,
                                  rsk_tx_hash: Option<[u8; 32]>,
                                  amount: u64,
                                  available: &mut Vec<BridgeUtxo>,
                                  waiting: &mut Vec<PegoutWaitingForConfirmations>| {
                    available.retain(|u| {
                        !built
                            .used_utxos
                            .iter()
                            .any(|s| s.tx_hash == u.tx_hash && s.vout == u.vout)
                    });
                    waiting.push(PegoutWaitingForConfirmations {
                        btc_tx_raw: btc_serialize(&built.tx),
                        rsk_block_height: block_number,
                        rsk_tx_hash: if use_tx_hash { rsk_tx_hash } else { None },
                    });
                    if let Some(hash) = rsk_tx_hash {
                        release_requested_or_record(
                            ctx,
                            use_tx_hash,
                            &hash,
                            &btc_txid_event_bytes(&built.tx),
                            amount,
                        );
                    }
                    // RSKIP428 (lovell700): processReleaseTransactionInfo emits
                    // pegout_transaction_created right after release_requested,
                    // listing each spent input's value (in input order).
                    if hardfork_cfg.has_rskip428(block_number) {
                        let outpoint_values: Vec<u64> =
                            built.used_utxos.iter().map(|u| u.value_satoshis).collect();
                        let txid = btc_txid_event_bytes(&built.tx);
                        super::events::log_pegout_transaction_created(
                            ctx,
                            &txid,
                            &outpoint_values,
                        );
                        save_release_outpoints_values(
                            ctx,
                            &txid,
                            &outpoint_values,
                            hardfork_cfg,
                            block_number,
                        );
                    }
                    // rskj BridgeSupport.adjustBalancesIfChangeOutputWasDust
                    // (unconditional since genesis): when a dusty change
                    // output was raised to the non-dust minimum (paid by the
                    // recipient), the federation spent less BTC than the user
                    // sent, so the difference is burned — transferred from
                    // the Bridge to 0xffff...ff (BridgeSupport.BURN_ADDRESS).
                    if built.tx.output.len() > 1 {
                        let sum_inputs: u64 =
                            built.used_utxos.iter().map(|u| u.value_satoshis).sum();
                        // Papyrus-era rskj reads getOutput(1); HOP+ reads
                        // getValueSentToMe(wallet). Both equal the change
                        // paid back to the federation P2SH script.
                        let change: u64 = built
                            .tx
                            .output
                            .iter()
                            .filter(|o| o.script_pubkey == *change_script)
                            .map(|o| o.value.to_sat())
                            .sum();
                        let spent_by_federation = sum_inputs.saturating_sub(change);
                        if spent_by_federation < amount {
                            let to_burn = amount - spent_by_federation;
                            let _ = ctx.journal_mut().transfer(
                                BRIDGE_ADDR,
                                BURN_ADDR,
                                btc_satoshi_to_rbtc_wei(to_burn),
                            );
                        }
                    }
                };

                if !use_rskip271 {
                    // Pre-RSKIP271 (processPegoutsIndividually): one BTC tx
                    // per request, up to MAX_RELEASE_ITERATIONS(30) per call;
                    // failed builds are re-appended at the end of the queue.
                    const MAX_RELEASE_ITERATIONS: usize = 30;
                    let mut kept = Vec::new();
                    let mut to_retry = Vec::new();
                    for (i, request) in pending.iter().enumerate() {
                        if i >= MAX_RELEASE_ITERATIONS {
                            kept.push(request.clone());
                            continue;
                        }
                        let outputs = [super::release_tx::PegoutOutput {
                            script: p2pkh_output_script(&request.btc_dest_hash160),
                            amount_satoshis: request.amount_satoshis,
                        }];
                        match super::release_tx::complete_pegout_tx(
                            &available,
                            &outputs,
                            &change_script,
                            redeem_for,
                            fee_per_kb,
                            tx_version,
                            is_segwit,
                        ) {
                            Some(built) => {
                                settle(
                                    ctx,
                                    built,
                                    request.rsk_tx_hash,
                                    request.amount_satoshis,
                                    &mut available,
                                    &mut waiting,
                                );
                                created_any = true;
                            }
                            None => to_retry.push(request.clone()),
                        }
                    }
                    kept.extend(to_retry);
                    save_release_request_queue(ctx, &kept, use_tx_hash);
                } else {
                    // RSKIP271+ (processPegoutsInBatch): one batched BTC tx
                    // for the whole queue, keyed by this updateCollections
                    // call's tx hash.
                    let outputs: Vec<super::release_tx::PegoutOutput> = pending
                        .iter()
                        .map(|r| super::release_tx::PegoutOutput {
                            script: p2pkh_output_script(&r.btc_dest_hash160),
                            amount_satoshis: r.amount_satoshis,
                        })
                        .collect();
                    if let Some(built) = super::release_tx::complete_pegout_tx(
                        &available,
                        &outputs,
                        &change_script,
                        redeem_for,
                        fee_per_kb,
                        tx_version,
                        is_segwit,
                    ) {
                        let total: u64 = pending.iter().map(|r| r.amount_satoshis).sum();
                        // rskj logBatchPegoutCreated needs the batch BTC tx hash
                        // and the per-request creation RSK tx hashes; capture
                        // them before `settle` consumes `built`.
                        let batch_btc_tx_hash = btc_txid_event_bytes(&built.tx);
                        let batch_rsk_tx_hashes: Vec<[u8; 32]> = pending
                            .iter()
                            .map(|r| r.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash))
                            .collect();
                        // RSKIP379: index this pegout by the legacy sighash of
                        // its first input (BridgeSupport.savePegoutTxSigHash,
                        // inside settleReleaseRequest). Compute before `settle`
                        // consumes `built`. When RSKIP379 is active RSKIP271 is
                        // too, so only this batch path is ever reached.
                        if hardfork_cfg.has_rskip379(block_number) {
                            let sig_hash = {
                                let redeem0 = redeem_for(&built.used_utxos[0]);
                                first_input_sig_hash(
                                    &built.tx,
                                    redeem0,
                                    built.used_utxos[0].value_satoshis,
                                )
                            };
                            save_pegout_tx_sig_hash(ctx, &sig_hash);
                        }
                        settle(
                            ctx,
                            built,
                            Some(tx_ctx.rsk_tx_hash),
                            total,
                            &mut available,
                            &mut waiting,
                        );
                        // rskj BridgeSupport.processPegoutsInBatch logs
                        // batch_pegout_created right after settleReleaseRequest
                        // (which already logged release_requested), listing every
                        // batched request's RSK creation tx hash.
                        super::events::log_batch_pegout_created(
                            ctx,
                            &batch_btc_tx_hash,
                            &batch_rsk_tx_hashes,
                        );
                        created_any = true;
                        // The whole queue was batched into one BTC tx, so it
                        // is now empty (rskj removeEntries(pegoutEntries)).
                        // rskj re-serializes the emptied queue, so the cell
                        // holds RLP.encodeList([]) = [0xc0], NOT empty bytes.
                        save_release_request_queue(ctx, &[], use_tx_hash);
                        queue_emptied = true;
                    }
                }

                if created_any {
                    store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);
                    store_utxos_at(ctx, active_utxo_key, &available);
                }
            }
        }

        // RSKIP271: set nextPegoutHeight when there are no pending pegout
        // requests left (either none to begin with, or all batched). This is
        // independent of whether a BTC tx was actually built, matching rskj
        // BridgeSupport.processPegoutsInBatch (the `pegoutRequests.getEntries()
        // .isEmpty()` tail at line 1555). A failed/insufficient build leaves
        // the queue non-empty and thus does NOT advance the height.
        if use_rskip271 && queue_emptied {
            let next_height = block_number + config.number_of_blocks_between_pegouts;
            super::storage::bridge_store_u256(
                ctx,
                NEXT_PEGOUT_HEIGHT_KEY,
                U256::from(next_height),
            );
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: Promote ONE confirmed pegout → waiting for signatures
    // (rskj processConfirmedPegouts: getNextPegoutWithEnoughConfirmations
    // promotes a single entry per updateCollections call)
    // -----------------------------------------------------------------------
    {
        let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
        let min_confirmations = config.rsk2btc_minimum_acceptable_confirmations as u64;
        let confirmed_pos = next_pegout_with_enough_confirmations(
            &waiting,
            block_number,
            min_confirmations,
        );

        if let Some(pos) = confirmed_pos {
            let entry = waiting.remove(pos);
            tracing::debug!(
                "promoting confirmed pegout created at #{} ({} bytes) into WFS",
                entry.rsk_block_height,
                entry.btc_tx_raw.len()
            );
            store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);

            // rskj BridgeSupport.processConfirmedPegouts l.1617 logs
            // pegout_confirmed for the promoted entry (RSKIP326, fingerroot500).
            // Capture the event inputs before `btc_tx_raw` is moved into the WFS.
            let pegout_confirmed = hardfork_cfg.has_rskip326(block_number).then(|| {
                (
                    btc_txid_event_bytes(
                        &deserialize::<BtcTransaction>(&entry.btc_tx_raw)
                            .expect("confirmed pegout btc tx deserializes"),
                    ),
                    entry.rsk_block_height,
                )
            });

            // rskj getPegoutWaitingForSignatureKey:
            // - RSKIP375+: the pegout creation RSK tx hash
            // - RSKIP146..RSKIP176: creation hash, falling back to this tx
            // - otherwise (incl. pre-RSKIP146): this updateCollections tx hash
            #[allow(clippy::if_same_then_else)] // distinct rskj rules that coincide today
            let rsk_hash = if hardfork_cfg.has_rskip375(block_number) {
                entry.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash)
            } else if use_tx_hash && !hardfork_cfg.has_rskip176(block_number) {
                entry.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash)
            } else {
                tx_ctx.rsk_tx_hash
            };

            let wfs_key = bridge_storage_key(PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
            let wfs_data = bridge_load_bytes(ctx, wfs_key);
            let mut wfs = deserialize_rsk_txs_waiting_for_signatures(&wfs_data);
            wfs.insert(rsk_hash, entry.btc_tx_raw);
            let updated_wfs = serialize_rsk_txs_waiting_for_signatures(&wfs);
            bridge_store_bytes(ctx, wfs_key, &updated_wfs);

            if let Some((btc_tx_hash, rsk_block_height)) = pegout_confirmed {
                super::events::log_pegout_confirmed(ctx, &btc_tx_hash, rsk_block_height);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: Promote the pending federation creation height once the new
    // federation reaches its activation age (rskj updateFederationCreationBlockHeights).
    // -----------------------------------------------------------------------
    super::governance::update_federation_creation_block_heights(
        ctx,
        config,
        hardfork_cfg,
        block_number,
    );

    // -----------------------------------------------------------------------
    // Step 4: drive the RSKIP419 Sign Validation Protocol for a proposed
    // federation (rskj updateSvpState).
    // -----------------------------------------------------------------------
    update_svp_state(ctx, config, hardfork_cfg, block_number, tx_ctx);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// rskj `BridgeSupport.updateSvpState` (RSKIP419): once a federation has been
/// committed as *proposed*, drive its Sign Validation Protocol. If the
/// validation window has elapsed the proposal failed; otherwise create the SVP
/// fund transaction (when no SVP values are set yet) and, once the fund tx has
/// been registered as signed, the SVP spend transaction.
fn update_svp_state<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    tx_ctx: &BridgeTxContext,
) {
    if !hardfork_cfg.has_rskip419(block_number) {
        return;
    }
    let Some(proposed) = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
    else {
        return;
    };

    // isSvpOngoing: the proposal is still within its validation window.
    if block_number >= proposed.creation_block + config.validation_period_duration_in_blocks {
        process_svp_failure(ctx, &proposed, config, hardfork_cfg, block_number);
        return;
    }

    // shouldCreateAndProcessSvpFundTransaction: every SVP value must be clear.
    let fund_unsigned = bridge_load_bytes_named(ctx, super::storage::SVP_FUND_TX_HASH_UNSIGNED_KEY);
    let fund_signed = bridge_load_bytes_named(ctx, super::storage::SVP_FUND_TX_SIGNED_KEY);
    let spend_unsigned =
        bridge_load_bytes_named(ctx, super::storage::SVP_SPEND_TX_HASH_UNSIGNED_KEY);
    if fund_unsigned.is_empty() && fund_signed.is_empty() && spend_unsigned.is_empty() {
        process_svp_fund_transaction_unsigned(
            ctx,
            &proposed,
            config,
            hardfork_cfg,
            block_number,
            tx_ctx,
        );
    }

    // Once the fund tx change has been registered (svpFundTxSigned set), build
    // the SVP spend transaction.
    let fund_signed = bridge_load_bytes_named(ctx, super::storage::SVP_FUND_TX_SIGNED_KEY);
    if !fund_signed.is_empty() {
        process_svp_spend_transaction_unsigned(
            ctx,
            &proposed,
            &fund_signed,
            config,
            hardfork_cfg,
            block_number,
            tx_ctx,
        );
    }
}

/// rskj `BridgeSupport.processSvpFailure`: the proposed federation did not pass
/// validation within its window. Log commit_federation_failure and clear the
/// proposed federation + every SVP value so a new federation election can run.
fn process_svp_failure<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    proposed: &super::federation::StoredFederation,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) {
    let proposed_redeem = build_committed_federation_redeem_script(
        &proposed.btc_keys(),
        config,
        hardfork_cfg,
        proposed.creation_block,
    );
    super::events::log_commit_federation_failed(ctx, &proposed_redeem, block_number);
    clear_proposed_federation(ctx);
    clear_svp_values(ctx);
}

/// rskj `FederationSupportImpl.clearProposedFederation` /
/// `setProposedFederation(null)`: delete the proposed federation and its format
/// version cell.
fn clear_proposed_federation<CTX: crate::RskContextTr>(ctx: &mut CTX) {
    bridge_store_bytes_named(ctx, PROPOSED_FEDERATION_KEY, &[]);
    bridge_store_bytes_named(ctx, PROPOSED_FEDERATION_FORMAT_VERSION_KEY, &[]);
}

/// rskj `BridgeStorageProvider.clearSvpValues`: delete every SVP value cell.
fn clear_svp_values<CTX: crate::RskContextTr>(ctx: &mut CTX) {
    bridge_store_bytes_named(ctx, super::storage::SVP_FUND_TX_HASH_UNSIGNED_KEY, &[]);
    bridge_store_bytes_named(ctx, super::storage::SVP_FUND_TX_SIGNED_KEY, &[]);
    bridge_store_bytes_named(ctx, super::storage::SVP_SPEND_TX_HASH_UNSIGNED_KEY, &[]);
    bridge_store_bytes_named(ctx, super::storage::SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY, &[]);
}

/// rskj `BridgeSupport.processSvpFundTransactionUnsigned`: build the SVP fund
/// transaction (two outputs of `svpFundTxOutputsValue` — one to the proposed
/// federation, one to its flyover variant — plus change to the active
/// federation), record its unsigned hash, and settle it like a peg-out.
fn process_svp_fund_transaction_unsigned<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    proposed: &super::federation::StoredFederation,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    tx_ctx: &BridgeTxContext,
) {
    let svp_fund_tx_outputs_value = config.minimum_pegout_tx_value * 2;
    let Some(built) =
        build_svp_fund_transaction(ctx, proposed, svp_fund_tx_outputs_value, config, hardfork_cfg, block_number)
    else {
        return;
    };

    // setSvpFundTxHashUnsigned(tx.getHash()) = RLP element of the display-order txid.
    let fund_hash = btc_txid_event_bytes(&built.tx);
    bridge_store_bytes_named(
        ctx,
        super::storage::SVP_FUND_TX_HASH_UNSIGNED_KEY,
        &super::serialization::rlp_encode_element(&fund_hash),
    );

    // settleReleaseRequest(activeUtxos, pegouts, fundTx, rskTxHash, 2*outputsValue).
    let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
    let (_active_keys, active_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);

    // removeSpentUtxos.
    let mut available = load_utxos_at(ctx, active_utxo_key);
    available.retain(|u| {
        !built.used_utxos.iter().any(|s| s.tx_hash == u.tx_hash && s.vout == u.vout)
    });
    store_utxos_at(ctx, active_utxo_key, &available);

    // addPegoutToPegoutsWaitingForConfirmations (RSKIP146 → with-txhash entry).
    let use_tx_hash = hardfork_cfg.has_rskip146(block_number);
    let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
    waiting.push(PegoutWaitingForConfirmations {
        btc_tx_raw: btc_serialize(&built.tx),
        rsk_block_height: block_number,
        rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
    });
    store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);

    // savePegoutTxSigHash (RSKIP379): index by the first-input sighash. rskj
    // `BitcoinUtils.extractRedeemScriptFromInput` reads the redeem from the
    // witness (last item) for a segwit (P2SH-P2WSH) input and from the scriptSig
    // otherwise; `first_input_sig_hash` then takes the segwit-serialized
    // preimage when the fund tx is segwit (§73) and the plain legacy sighash
    // otherwise. A segwit active federation makes both apply here.
    if hardfork_cfg.has_rskip379(block_number) {
        let redeem0 = built
            .tx
            .input
            .first()
            .and_then(|i| {
                if !i.witness.is_empty() {
                    i.witness.last().map(|r| r.to_vec())
                } else {
                    super::release_tx::extract_redeem_script(i.script_sig.as_bytes())
                }
            })
            .unwrap_or_else(|| active_redeem.clone());
        let value0 = built.used_utxos.first().map(|u| u.value_satoshis).unwrap_or(0);
        let sig_hash = first_input_sig_hash(&built.tx, &redeem0, value0);
        save_pegout_tx_sig_hash(ctx, &sig_hash);
    }

    // logReleaseRequested + processReleaseTransactionInfo (RSKIP428): the
    // requested amount is the total sent to the proposed federation.
    let amount = svp_fund_tx_outputs_value * 2;
    super::events::log_release_requested(
        ctx,
        &tx_ctx.rsk_tx_hash,
        &fund_hash,
        amount,
    );
    if hardfork_cfg.has_rskip428(block_number) {
        let outpoint_values: Vec<u64> =
            built.used_utxos.iter().map(|u| u.value_satoshis).collect();
        super::events::log_pegout_transaction_created(ctx, &fund_hash, &outpoint_values);
        save_release_outpoints_values(ctx, &fund_hash, &outpoint_values, hardfork_cfg, block_number);
    }
}

/// rskj `BridgeSupport.processSvpSpendTransactionUnsigned`: once the SVP fund
/// transaction's change has been registered (`svpFundTxSigned` set), build the
/// SVP spend transaction (move the proposed-fed + flyover-proposed-fed outputs
/// back to the active federation), record its unsigned hash and the
/// waiting-for-signatures entry, clear `svpFundTxSigned`, and log
/// release_requested + pegout_transaction_created.
#[allow(clippy::too_many_arguments)]
fn process_svp_spend_transaction_unsigned<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    proposed: &super::federation::StoredFederation,
    svp_fund_tx_signed: &[u8],
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    tx_ctx: &BridgeTxContext,
) {
    // svpFundTxSigned is stored as RLP.encodeElement(bitcoinSerialize).
    let Some(fund_tx_bytes) = super::serialization::rlp_decode_element(svp_fund_tx_signed) else {
        return;
    };
    let Ok(fund_tx) = deserialize::<BtcTransaction>(&fund_tx_bytes) else {
        return;
    };

    let Some(spend) =
        create_svp_spend_transaction(ctx, &fund_tx, proposed, config, hardfork_cfg, block_number)
    else {
        return;
    };

    // updateSvpSpendTransactionValues: set the unsigned hash + waiting-for-
    // signatures entry (RLP[rskTxHash, btcTx]), and clear svpFundTxSigned.
    let spend_hash = btc_txid_event_bytes(&spend);
    bridge_store_bytes_named(
        ctx,
        super::storage::SVP_SPEND_TX_HASH_UNSIGNED_KEY,
        &super::serialization::rlp_encode_element(&spend_hash),
    );
    let wfs = super::serialization::rlp_encode_list(&[
        super::serialization::rlp_encode_element(&tx_ctx.rsk_tx_hash),
        super::serialization::rlp_encode_element(&btc_serialize(&spend)),
    ]);
    bridge_store_bytes_named(ctx, super::storage::SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY, &wfs);
    bridge_store_bytes_named(ctx, super::storage::SVP_FUND_TX_SIGNED_KEY, &[]);

    // logReleaseRequested(amount = output[0] value) + processReleaseTransactionInfo.
    let amount = spend.output[0].value.to_sat();
    super::events::log_release_requested(ctx, &tx_ctx.rsk_tx_hash, &spend_hash, amount);
    if hardfork_cfg.has_rskip428(block_number) {
        // extractOutpointValues: each input's connected value = the fund tx
        // output it spends (the two svpFundTxOutputsValue outputs).
        let outpoint_values: Vec<u64> = spend
            .input
            .iter()
            .map(|i| {
                fund_tx
                    .output
                    .get(i.previous_output.vout as usize)
                    .map(|o| o.value.to_sat())
                    .unwrap_or(0)
            })
            .collect();
        super::events::log_pegout_transaction_created(ctx, &spend_hash, &outpoint_values);
        save_release_outpoints_values(ctx, &spend_hash, &outpoint_values, hardfork_cfg, block_number);
    }
}

/// rskj `BridgeSupport.createSvpSpendTransaction`: a version-2 BTC tx spending
/// the fund tx's two outputs (the one paying the proposed federation P2SH and
/// the one paying its flyover P2SH) into a single output to the active
/// federation worth `2*outputsValue - fees`. Each input carries the legacy
/// placeholder scriptSig of its redeem (proposed redeem / flyover-proposed
/// redeem), so the unsigned txid matches `svpSpendTxHashUnsigned`.
fn create_svp_spend_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    fund_tx: &BtcTransaction,
    proposed: &super::federation::StoredFederation,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<BtcTransaction> {
    let proposed_keys = proposed.btc_keys();
    let proposed_redeem = build_committed_federation_redeem_script(
        &proposed_keys,
        config,
        hardfork_cfg,
        proposed.creation_block,
    );
    let proposed_threshold = super::release_tx::redeem_script_threshold(&proposed_redeem);
    let proposed_format =
        super::governance::federation_format_version(hardfork_cfg, proposed.creation_block);
    let proposed_script =
        p2sh_output_script(&federation_output_hash160(&proposed_redeem, proposed_format));

    let mut flyover_prefix = [0u8; 32];
    flyover_prefix[31] = 1;
    let flyover_redeem = flyover_redeem_script(&flyover_prefix, &proposed_redeem);
    let flyover_threshold = super::release_tx::redeem_script_threshold(&flyover_redeem);
    let flyover_script =
        p2sh_output_script(&federation_output_hash160(&flyover_redeem, proposed_format));

    // searchForOutput: the fund tx outputs paying the proposed fed / flyover fed.
    let (idx0, out0) =
        fund_tx.output.iter().enumerate().find(|(_, o)| o.script_pubkey == proposed_script)?;
    let (idx1, out1) =
        fund_tx.output.iter().enumerate().find(|(_, o)| o.script_pubkey == flyover_script)?;
    let value_to_proposed = out0.value.to_sat();
    let value_to_flyover = out1.value.to_sat();

    // The single output pays the active federation's own address, which for a
    // segwit (P2SH-P2WSH, format ≥ 4000) federation is the witness-program
    // hash, not the plain redeem hash.
    let (_active_keys, active_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    let active_format = active_federation_format(ctx, config, hardfork_cfg, block_number);
    let active_script =
        p2sh_output_script(&federation_output_hash160(&active_redeem, active_format));

    let fees = calculate_svp_spend_tx_fees(
        ctx,
        &proposed_redeem,
        &proposed_script,
        proposed_threshold,
        proposed_format,
        config,
    );
    let value_to_send = (value_to_proposed + value_to_flyover).saturating_sub(fees);

    let fund_txid = fund_tx.compute_txid();
    // addSpendingFederationBaseScript: format ≥ 4000 spends via segwit (scriptSig
    // = the P2WSH program push, redeem + sig placeholders in the witness), else
    // the legacy placeholder scriptSig with an empty witness.
    let spend_input = |vout: u32, redeem: &[u8], threshold: usize| -> bitcoin::TxIn {
        let (script_sig, witness) = if proposed_format >= 4000 {
            super::release_tx::segwit_base_input(redeem, threshold)
        } else {
            (
                bitcoin::ScriptBuf::from_bytes(super::release_tx::placeholder_scriptsig(
                    redeem, threshold,
                )),
                bitcoin::Witness::new(),
            )
        };
        bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid: fund_txid, vout },
            script_sig,
            sequence: bitcoin::Sequence::MAX,
            witness,
        }
    };
    let input = vec![
        spend_input(idx0 as u32, &proposed_redeem, proposed_threshold),
        spend_input(idx1 as u32, &flyover_redeem, flyover_threshold),
    ];
    Some(BtcTransaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value_to_send),
            script_pubkey: active_script,
        }],
    })
}

/// rskj `BridgeSupport.calculateSvpSpendTxFees`: size the spend tx as a peg-out
/// of the proposed federation with 2 inputs / 1 output (`calculatePegoutTxSize`),
/// inflate by 12/10, and apply the fee-per-kB.
fn calculate_svp_spend_tx_fees<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    proposed_redeem: &[u8],
    proposed_script: &bitcoin::ScriptBuf,
    proposed_threshold: usize,
    proposed_format: u64,
    config: &BridgeConstants,
) -> u64 {
    // calculatePegoutTxSize: a P2SH-P2WSH (format ≥ 4000) federation is sized as
    // a segwit tx (witness-discounted vsize); otherwise as a legacy tx.
    let size = if proposed_format >= 4000 {
        pegout_tx_size_segwit(proposed_redeem, proposed_script, proposed_threshold, 2, 1)
    } else {
        pegout_tx_size_legacy(proposed_redeem, proposed_script, proposed_threshold, 2, 1)
    };
    let backed_up_size = size as u64 * 12 / 10;
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    fee_per_kb * backed_up_size / 1000
}

/// rskj `BridgeUtils.calculateSegwitTxSize`: BIP141 weight-based vsize for a
/// P2SH-P2WSH federation spend — `inputs` segwit inputs (scriptSig = the 36-byte
/// witness-program push, redeem + sigs in the witness) and `outputs` P2SH
/// outputs. The witness bytes (redeem + signatures) are quartered.
fn pegout_tx_size_segwit(
    redeem: &[u8],
    fed_script: &bitcoin::ScriptBuf,
    threshold: usize,
    inputs: usize,
    outputs: usize,
) -> usize {
    // calculateTxBaseSize: an input-less tx with `outputs` P2SH outputs, plus
    // SEGWIT_COMPATIBLE_SCRIPT_SIG_SIZE (36) per segwit input.
    let output: Vec<bitcoin::TxOut> = (0..outputs)
        .map(|_| bitcoin::TxOut { value: bitcoin::Amount::ZERO, script_pubkey: fed_script.clone() })
        .collect();
    let tx = BtcTransaction {
        version: bitcoin::transaction::Version(1),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output,
    };
    // bitcoinj `bitcoinSerialize` writes a witness-less tx in legacy form (no
    // segwit marker/flag); rust-bitcoin force-tags a 0-input tx as segwit, so
    // use `base_size` (the witness-stripped length) to match bitcoinj.
    let base_size = tx.base_size() + inputs * 36;
    let signing_size = threshold * inputs * 72;
    let total_size = base_size + signing_size + inputs * redeem.len();
    let tx_weight = total_size + 3 * base_size;
    tx_weight / 4
}

/// rskj `BridgeUtils.calculateLegacyTxSize`: serialize a tx with `inputs`
/// inputs whose scriptSig is the federation redeem script and `outputs` P2SH
/// outputs, then add `threshold * inputs * 72` signing bytes.
fn pegout_tx_size_legacy(
    redeem: &[u8],
    fed_script: &bitcoin::ScriptBuf,
    threshold: usize,
    inputs: usize,
    outputs: usize,
) -> usize {
    let input: Vec<bitcoin::TxIn> = (0..inputs)
        .map(|_| bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::from_bytes(redeem.to_vec()),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        })
        .collect();
    let output: Vec<bitcoin::TxOut> = (0..outputs)
        .map(|_| bitcoin::TxOut { value: bitcoin::Amount::ZERO, script_pubkey: fed_script.clone() })
        .collect();
    let tx = BtcTransaction {
        version: bitcoin::transaction::Version(1),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output,
    };
    bitcoin::consensus::serialize(&tx).len() + threshold * inputs * 72
}

/// rskj `BridgeSupport.isSvpOngoing`: a proposed federation exists and the
/// current block is still within its `validationPeriodDurationInBlocks` window.
fn svp_is_ongoing<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    block_number: u64,
) -> bool {
    super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
        .is_some_and(|p| block_number < p.creation_block + config.validation_period_duration_in_blocks)
}

/// rskj `BitcoinUtils.getMultiSigTransactionHashWithoutSignatures`: the txid a
/// signed multisig tx would have with its signatures stripped (each input's
/// scriptSig rebuilt as the redeem placeholder). Returns the display-order hash,
/// or `None` if any input is not a standard P2SH multisig (rskj throws → not an
/// SVP tx). Witness txs use the plain txid.
fn multisig_txid_without_signatures(tx: &BtcTransaction) -> Option<[u8; 32]> {
    // Witness txs use the plain txid (rskj getMultiSigTransactionHashWithoutSignatures).
    if tx.input.iter().any(|i| !i.witness.is_empty()) {
        return Some(btc_txid_event_bytes(tx));
    }
    let mut copy = tx.clone();
    for input in &mut copy.input {
        // Each input must be a P2SH multisig (standard or ERP): extract its
        // redeem and rebuild the placeholder scriptSig. `placeholder_scriptsig`
        // adds the extra OP_0 for the ERP OP_NOTIF branch, matching bitcoinj
        // `createEmptyInputScript`. A non-multisig input (no redeem push, or
        // threshold 0) is not an SVP tx (rskj throws → caught → false).
        let redeem = super::release_tx::extract_redeem_script(input.script_sig.as_bytes())?;
        let threshold = super::release_tx::redeem_script_threshold(&redeem);
        if threshold == 0 {
            return None;
        }
        input.script_sig =
            bitcoin::ScriptBuf::from_bytes(super::release_tx::placeholder_scriptsig(&redeem, threshold));
    }
    Some(btc_txid_event_bytes(&copy))
}

/// rskj `ReleaseTransactionBuilder.buildSvpFundTransaction`: two fixed outputs
/// of `svp_fund_tx_outputs_value` (to the proposed federation P2SH and to its
/// flyover P2SH, derived with the `proposedFederationFlyoverPrefix` = 1), with
/// change to the active federation. `recipientsPayFees = false`, version 2.
fn build_svp_fund_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    proposed: &super::federation::StoredFederation,
    svp_fund_tx_outputs_value: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<super::release_tx::BuiltPegout> {
    // Proposed federation redeem + P2SH (its TYPE is keyed on its creation block).
    let proposed_keys = proposed.btc_keys();
    let proposed_redeem = build_committed_federation_redeem_script(
        &proposed_keys,
        config,
        hardfork_cfg,
        proposed.creation_block,
    );
    // Proposed federation format keys its output type: format ≥ 4000 (RSKIP305)
    // pays P2SH-P2WSH, else plain P2SH.
    let proposed_format =
        super::governance::federation_format_version(hardfork_cfg, proposed.creation_block);
    let proposed_script =
        p2sh_output_script(&federation_output_hash160(&proposed_redeem, proposed_format));

    // Flyover proposed federation: PUSH32 <prefix=1> OP_DROP <proposedRedeem>,
    // P2SH-P2WSH of that for format ≥ 4000, else plain P2SH.
    let mut flyover_prefix = [0u8; 32];
    flyover_prefix[31] = 1;
    let flyover_redeem = flyover_redeem_script(&flyover_prefix, &proposed_redeem);
    let flyover_script =
        p2sh_output_script(&federation_output_hash160(&flyover_redeem, proposed_format));

    // Active federation: spending wallet + change address. The change goes back
    // to the active federation's own address, which for a segwit (P2SH-P2WSH,
    // format ≥ 4000) federation is the witness-program hash, not the plain
    // redeem hash; the fund tx's inputs/fee are segwit-weighted to match.
    let (_active_keys, active_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    let active_format = active_federation_format(ctx, config, hardfork_cfg, block_number);
    let is_segwit = active_format >= 4000;
    let change_script =
        p2sh_output_script(&federation_output_hash160(&active_redeem, active_format));

    let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
    let available = load_utxos_at(ctx, active_utxo_key);
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);

    // rskj getActiveFederationWallet is flyover-compatible; resolve a flyover
    // input's redeem per UTXO (same as the pegout path), else the plain redeem.
    let candidate_fed_redeems = vec![active_redeem.clone()];
    let flyover_overrides =
        resolve_flyover_input_redeems(ctx, &available, &candidate_fed_redeems);
    let redeem_for = |u: &BridgeUtxo| -> &[u8] {
        flyover_overrides
            .get(&(u.tx_hash, u.vout))
            .map(|r| r.as_slice())
            .unwrap_or(active_redeem.as_slice())
    };

    let outputs = [
        super::release_tx::PegoutOutput {
            script: proposed_script,
            amount_satoshis: svp_fund_tx_outputs_value,
        },
        super::release_tx::PegoutOutput {
            script: flyover_script,
            amount_satoshis: svp_fund_tx_outputs_value,
        },
    ];
    super::release_tx::complete_recipients_dont_pay_fees_tx(
        &available,
        &outputs,
        &change_script,
        redeem_for,
        fee_per_kb,
        2,
        is_segwit,
    )
}

/// rskj `PegoutsWaitingForConfirmations.getNextPegoutWithEnoughConfirmations`:
/// `entries.stream().filter(hasEnoughConfirmations).findFirst()` over a Java
/// `HashSet<Entry>`. The selected entry is therefore the first confirmed one in
/// Java `HashSet` iteration order — NOT the storage (btc-tx-sorted) order. When
/// two entries share the same creation height (so both confirm on the same
/// block) the choice between them depends on this iteration order, which is
/// consensus-critical (block #3,345,557 mainnet).
///
/// `HashSet` iteration walks buckets `0..table.length` ascending, and within a
/// bucket in insertion order. The bucket is `(table.length-1) & spread(hash)`
/// with `spread(h) = h ^ (h >>> 16)` and
/// `hash = Objects.hash(btcTx, Long(height))`
/// (`= 31*(31 + btcTx.hashCode()) + Long.hashCode(height)`), where
/// `btcTx.hashCode()` is the last 4 bytes of the display-order txid read
/// big-endian (bitcoinj `Sha256Hash.hashCode`).
///
/// **Table capacity.** The set iterated here is the one cached by
/// `BridgeStorageProvider.getPegoutsWaitingForConfirmations`, whose LAST step is
/// `new PegoutsWaitingForConfirmations(entries)` →
/// `this.entries = new HashSet<>(entries)` (constructor, NOT incremental). The
/// `HashSet(Collection)` constructor pre-sizes the table to
/// `tableSizeFor(max((int)(n / 0.75f) + 1, 16))`, so for `n` final entries the
/// capacity is the next power of two `>= max((int)(n / 0.75) + 1, 16)`. This
/// differs from an incremental default-16 fill exactly at the resize boundaries
/// (e.g. `n = 12` -> cap 32 here, but an incremental fill would stay at 16;
/// `n = 24` -> 64 vs 32), and getting it wrong reshuffles the bucket walk and
/// forks the pegout selection (mainnet #3,344,303). Returns the index into
/// `entries`.
fn next_pegout_with_enough_confirmations(
    entries: &[PegoutWaitingForConfirmations],
    current_block: u64,
    min_confirmations: u64,
) -> Option<usize> {
    if entries.is_empty() {
        return None;
    }

    let cap = java_hashset_capacity(entries.len());

    // Bucket each entry; within a bucket preserve insertion (storage) order.
    let mut buckets: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let h = pegout_entry_hash(entry);
        let spread = h ^ (h >> 16);
        let bucket = (cap - 1) & spread;
        buckets.entry(bucket).or_default().push(i);
    }

    // findFirst over the confirmation-filtered stream in iteration order.
    buckets.into_values().flatten().find(|&i| {
        current_block
            .checked_sub(entries[i].rsk_block_height)
            .is_some_and(|d| d >= min_confirmations)
    })
}

/// Java `HashSet(Collection)` / `HashMap(int)` table capacity for a set built
/// with the collection constructor from `n` elements. `HashSet(Collection c)`
/// uses `initialCapacity = max((int)(c.size() / 0.75f) + 1, 16)`, and
/// `HashMap(initialCapacity)` rounds that up to a power of two via
/// `tableSizeFor` (`HashMap.putVal`'s first `resize()` adopts the stored
/// threshold as the table length). So the result is the smallest power-of-two
/// `>= max((int)(n / 0.75) + 1, 16)` — which, at the boundaries, is one doubling
/// LARGER than an incremental default-16 fill of the same `n`.
fn java_hashset_capacity(n: usize) -> u32 {
    let init_cap = std::cmp::max((n as f32 / 0.75) as u32 + 1, 16);
    init_cap.next_power_of_two()
}

/// rskj `PegoutsWaitingForConfirmations.Entry.hashCode()`:
/// `Objects.hash(btcTransaction, pegoutCreationRskBlockNumber)`
/// `= 31 * (31 * 1 + btcTransaction.hashCode()) + Long.hashCode(height)`.
/// `btcTransaction.hashCode()` (bitcoinj) is `Sha256Hash.hashCode()` of the
/// txid: the last 4 bytes of the display-order hash read big-endian.
fn pegout_entry_hash(entry: &PegoutWaitingForConfirmations) -> u32 {
    // Display-order txid = reverse of rust-bitcoin's internal SHA256d.
    let btc_hash_code = match deserialize::<BtcTransaction>(&entry.btc_tx_raw) {
        Ok(tx) => {
            let mut disp = *tx.compute_txid().to_raw_hash().as_byte_array();
            disp.reverse();
            u32::from_be_bytes([disp[28], disp[29], disp[30], disp[31]])
        }
        Err(_) => 0,
    };
    let long_hash_code =
        (entry.rsk_block_height ^ (entry.rsk_block_height >> 32)) as u32;
    // Objects.hash(btcTx, height) = 31 * (31 + btcTx.hashCode()) + Long.hashCode.
    let r = 31u32.wrapping_add(btc_hash_code);
    31u32.wrapping_mul(r).wrapping_add(long_hash_code)
}

/// rskj `BridgeSupport.processFundsMigration` (pre-RSKIP294/376 era).
fn process_funds_migration<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    tx_ctx: &BridgeTxContext,
) {
    let Some(retiring_keys) =
        retiring_federation_keys(ctx, config, hardfork_cfg, block_number)
    else {
        return;
    };
    let Some(new_fed) = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY)
    else {
        return;
    };

    let age = block_number.saturating_sub(new_fed.creation_block);
    let activation_age =
        super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    // rskj FederationConstants.getFundsMigrationAgeSinceActivationEnd: while
    // RSKIP357 is active and RSKIP374 is not (mainnet hop401 #4,976,300 ..
    // fingerroot500 #5,468,000), the migration window end takes its special-case
    // value (mainnet 172,800 instead of 10,585), greatly extending the window.
    let migration_age_end = if hardfork_cfg.has_rskip357(block_number)
        && !hardfork_cfg.has_rskip374(block_number)
    {
        config.special_case_funds_migration_age_end
    } else {
        config.funds_migration_age_end
    };
    let migration_start = activation_age + config.funds_migration_age_begin;
    let migration_end = activation_age + migration_age_end;
    let in_migration_age = age > migration_start && age < migration_end;
    let past_migration_age = age >= migration_end;
    if !in_migration_age && !past_migration_age {
        return;
    }

    let mut old_utxos = super::storage::load_old_federation_utxos(ctx);
    // rskj `getRetiringFederationWallet`: post-RSKIP294 the spend wallet caps
    // its UTXO set to the first `maxInputsPerPegoutTransaction` entries
    // (`utxos.subList(0, limit)`, BridgeSupport.java:1249-1251, 312-323), so the
    // migration balance, fee floor, and coin selection only ever see those.
    let migration_utxos: Vec<super::storage::BridgeUtxo> = if hardfork_cfg.has_rskip294(block_number)
    {
        old_utxos
            .iter()
            .take(config.max_inputs_per_pegout_transaction as usize)
            .cloned()
            .collect()
    } else {
        old_utxos.clone()
    };
    let balance: u64 = migration_utxos.iter().map(|u| u.value_satoshis).sum();
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);

    let should_migrate = (in_migration_age && balance > fee_per_kb / 2)
        || (past_migration_age && balance > 0);
    if should_migrate {
        // The retiring federation spends with the redeem of its STORED format
        // version (plain / NON_STANDARD_ERP / P2SH-ERP / P2SH-P2WSH-ERP), like
        // the regular pegout path — `getRetiringFederation().getRedeemScript()`.
        // Once the retiring federation is itself an ERP federation, the plain
        // multisig builder gives the wrong per-input placeholder scriptSig and
        // thus a wrong unsigned migration txid (same class as #4,677,503, but on
        // the migration path — first hit at #4,998,800).
        let retiring_redeem =
            retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number)
                .map(|(_keys, redeem)| redeem)
                .unwrap_or_else(|| {
                    build_federation_redeem_script(&retiring_keys, retiring_keys.len() / 2 + 1)
                });
        // rskj `migrateFunds` sends the migration to `getActiveFederationAddress()`
        // = the NEW (active) federation's P2SH address (BridgeSupport.java:1308,
        // FederationSupportImpl.getActiveFederationAddress -> getAddress()). The
        // active federation here is the ERP federation committed at #4,652,781, so
        // its address derives from the (RSKIP201-era non-standard) ERP redeem
        // script, NOT a plain multisig. Use the committed-federation redeem builder
        // so this matches whatever federation format was committed (standard pre-
        // RSKIP201, non-standard ERP, P2SH-ERP, or P2SH-P2WSH-ERP).
        let new_btc_keys = new_fed.btc_keys();
        let new_redeem = build_committed_federation_redeem_script(
            &new_btc_keys,
            config,
            hardfork_cfg,
            block_number,
        );
        // getActiveFederationAddress is format-aware: a P2SH-P2WSH (format 4000,
        // RSKIP305) active federation receives the migration at its P2SH-P2WSH
        // address, not a plain P2SH of the redeem. First hit when the first
        // reed800 segwit federation activates (#8,147,324).
        let new_format = federation_format_version(ctx, super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY);
        let active_script = p2sh_output_script(&federation_output_hash160(&new_redeem, new_format));

        // The migration spends the retiring (OLD) federation; a P2SH-P2WSH
        // retiring federation is spent with segwit inputs (isSegwitCompatible).
        let retiring_is_segwit =
            federation_format_version(ctx, super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY) >= 4000;

        // rskj getRetiringFederationWallet builds a FlyoverCompatibleBtcWallet:
        // a flyover UTXO in the migration set spends with the flyover redeem
        // (PUSH32 <derivationHash> OP_DROP <fedRedeem>) of its destination
        // federation, not the plain retiring redeem. Resolve per input.
        // getDestinationFederation searches active + retiring; the stored
        // fedRedeemScriptHash is the *plain* multisig hash of whichever fed was
        // active at the flyover peg-in (now the retiring fed for this batch).
        let plain_new_redeem = build_federation_redeem_script(&new_btc_keys, new_btc_keys.len() / 2 + 1);
        let candidate_fed_redeems = vec![retiring_redeem.clone(), plain_new_redeem];
        let flyover_overrides =
            resolve_flyover_input_redeems(ctx, &migration_utxos, &candidate_fed_redeems);
        let redeem_for = |u: &BridgeUtxo| -> &[u8] {
            flyover_overrides
                .get(&(u.tx_hash, u.vout))
                .map(|r| r.as_slice())
                .unwrap_or(retiring_redeem.as_slice())
        };

        // createMigrationTransaction: target the full balance, halving on
        // size overflow. rskj ReleaseTransactionBuilder sets version 2 once
        // RSKIP201 is active (setDefaultTxConfig), but buildMigrationTransaction
        // forces it back to version 1 until RSKIP376 — from RSKIP376 (arrowhead600)
        // on, migration txs are version 2 like every other pegout.
        let migration_tx_version = if hardfork_cfg.has_rskip376(block_number) { 2 } else { 1 };
        let mut target = balance;
        let built = loop {
            let outputs = [super::release_tx::PegoutOutput {
                script: active_script.clone(),
                amount_satoshis: target,
            }];
            match super::release_tx::complete_pegout_tx(
                &migration_utxos,
                &outputs,
                &active_script,
                redeem_for,
                fee_per_kb,
                migration_tx_version,
                retiring_is_segwit,
            ) {
                Some(b) => break Some(b),
                None => {
                    target /= 2;
                    if target < 10_000 {
                        break None;
                    }
                }
            }
        };

        if let Some(built) = built {
            // RSKIP379: settleReleaseRequest indexes every pegout — migrations
            // included — by the first-input sighash (segwit BIP-143 when the
            // retiring federation is P2SH-P2WSH; BridgeSupport.savePegoutTxSigHash).
            if hardfork_cfg.has_rskip379(block_number) {
                let sig_hash = {
                    let redeem0 = redeem_for(&built.used_utxos[0]);
                    first_input_sig_hash(&built.tx, redeem0, built.used_utxos[0].value_satoshis)
                };
                save_pegout_tx_sig_hash(ctx, &sig_hash);
            }
            // rskj processFundsMigration: post-RSKIP146 the entry carries the
            // updateCollections tx hash and logs release_requested with the
            // migrated amount (sum of the selected UTXO values).
            let use_tx_hash = hardfork_cfg.has_rskip146(block_number);
            let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
            waiting.push(PegoutWaitingForConfirmations {
                btc_tx_raw: btc_serialize(&built.tx),
                rsk_block_height: block_number,
                rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
            });
            {
                let amount_migrated: u64 =
                    built.used_utxos.iter().map(|u| u.value_satoshis).sum();
                release_requested_or_record(
                    ctx,
                    use_tx_hash,
                    &tx_ctx.rsk_tx_hash,
                    &btc_txid_event_bytes(&built.tx),
                    amount_migrated,
                );
            }
            // RSKIP428 (lovell700): pegout_transaction_created for the migration
            // tx too (settleReleaseRequest -> processReleaseTransactionInfo).
            if hardfork_cfg.has_rskip428(block_number) {
                let outpoint_values: Vec<u64> =
                    built.used_utxos.iter().map(|u| u.value_satoshis).collect();
                let txid = btc_txid_event_bytes(&built.tx);
                super::events::log_pegout_transaction_created(ctx, &txid, &outpoint_values);
                save_release_outpoints_values(
                    ctx,
                    &txid,
                    &outpoint_values,
                    hardfork_cfg,
                    block_number,
                );
            }
            store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);

            old_utxos.retain(|u| {
                !built
                    .used_utxos
                    .iter()
                    .any(|s| s.tx_hash == u.tx_hash && s.vout == u.vout)
            });
            super::storage::store_old_federation_utxos(ctx, &old_utxos);
            tracing::debug!(
                "funds migration: queued {} ({} utxos) at #{block_number}",
                built.tx.compute_txid(),
                built.used_utxos.len()
            );
        }
    }

    if past_migration_age {
        // clearRetiredFederation: the old federation is gone for good. rskj
        // saveOldFederation writes the format-version cell on every save once
        // RSKIP123 is active — even this clearing one (the federation cell is
        // deleted, the version cell stays).
        if hardfork_cfg.has_rskip123(block_number) {
            bridge_store_bytes_named(
                ctx,
                OLD_FEDERATION_FORMAT_VERSION_KEY,
                &super::serialization::rlp_encode_u64(1000),
            );
        }
        bridge_store_bytes_named(ctx, OLD_FEDERATION_KEY, &[]);
    }
}

/// Active federation member keys (rskj FederationSupport.getActiveFederation):
/// the committed (new) federation once it reaches the activation age, the old
/// federation while the new one awaits activation, or the genesis federation
/// when none was ever stored.
pub(crate) fn federation_keys_or_genesis<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    want_rsk: bool,
) -> Vec<[u8; 33]> {
    // `want_rsk` selects the member's RSK public key instead of its BTC key
    // (RSKIP415 REMASC payout). Genesis-fallback members are single-key, so
    // their RSK key equals their BTC key.
    let keys = |f: &super::federation::StoredFederation| {
        if want_rsk { f.rsk_keys() } else { f.btc_keys() }
    };
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age =
        super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    match (new, old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                keys(&n)
            } else {
                keys(&o)
            }
        }
        (Some(n), None) => keys(&n),
        (None, _) => genesis_federation_keys(config),
    }
}

/// The RSK public key of the federation member whose BTC public key is
/// `btc_key`, searching the active federation first and then the retiring one
/// (rskj `BridgeSupport.getFederationMember` via `getFederationFromPublicKey`).
/// For legacy single-key members rsk == btc, so this returns `btc_key` itself.
/// `None` when no federation member matches.
fn federator_rsk_key_for_btc<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    btc_key: &[u8; 33],
) -> Option<[u8; 33]> {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    // Active federation: new once it reaches activation age, otherwise old.
    let (active, retiring) = match (&new, &old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                (Some(n), Some(o))
            } else {
                (Some(o), None)
            }
        }
        (Some(n), None) => (Some(n), None),
        (None, _) => (None, None),
    };
    for fed in [active, retiring].into_iter().flatten() {
        if let Some(m) = fed.members.iter().find(|m| &m.btc == btc_key) {
            return Some(m.rsk);
        }
    }
    None
}

/// Which UTXO storage set backs the ACTIVE federation: after a commit and
/// until activation the active federation IS the old one, whose UTXOs were
/// moved to oldFederationBtcUTXOs (rskj getActiveFederationBtcUTXOs).
pub(crate) fn active_federation_utxo_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> &'static str {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    if let (Some(n), Some(_)) = (new, old) {
        let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
        if block_number < n.creation_block + age {
            return super::storage::OLD_FEDERATION_BTC_UTXOS_KEY;
        }
    }
    super::storage::new_federation_utxos_key(hardfork_cfg, block_number)
}

fn load_utxos_at<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str) -> Vec<BridgeUtxo> {
    super::storage::deserialize_utxo_list(&bridge_load_bytes_named(ctx, key))
}

fn store_utxos_at<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str, utxos: &[BridgeUtxo]) {
    bridge_store_bytes_named(ctx, key, &super::storage::serialize_utxo_list(utxos));
}

/// Active federation keys together with the redeem script built from the
/// federation's STORED format version (rskj `getActiveFederation().getRedeemScript()`).
/// During the activation window the active federation is still the OLD one, so its
/// format cell (and keys) must be used.
/// The ACTIVE federation, as the local-only getters need it: members with all
/// three key types, plus creation time and block.
///
/// Same new/old selection as `active_federation_keys_and_redeem` -- during a
/// new federation's activation window the **old** one is still active -- and
/// the same genesis fallback when nothing is stored. Reading
/// `newFederation` directly, which several of these getters used to do, is
/// wrong in both cases.
///
/// The genesis federation's creation time is rskj's
/// `ZonedDateTime.parse("1970-01-18T12:49:08.400Z")`: an Instant built from
/// what was meant to be a seconds value, so `toEpochMilli()` is 1514948400.
/// `genesis_federation_creation_time_millis` carries that number verbatim.
pub(crate) fn active_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> super::federation::StoredFederation {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    match (new, old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                n
            } else {
                o
            }
        }
        (Some(n), None) => n,
        (None, _) => super::federation::StoredFederation {
            members: genesis_federation_keys(config)
                .into_iter()
                .map(super::federation::StoredMember::from_btc)
                .collect(),
            creation_time_millis: config.genesis_federation_creation_time_millis,
            creation_block: 1,
        },
    }
}

pub(crate) fn active_federation_keys_and_redeem<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> (Vec<[u8; 33]>, Vec<u8>) {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    let (keys, format_key) = match (new, old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                (n.btc_keys(), super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY)
            } else {
                (o.btc_keys(), super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY)
            }
        }
        (Some(n), None) => (n.btc_keys(), super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY),
        (None, _) => return {
            let keys = genesis_federation_keys(config);
            let redeem = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
            (keys, redeem)
        },
    };
    let version = federation_format_version(ctx, format_key);
    let redeem = federation_redeem_for_format(&keys, version, config);
    (keys, redeem)
}

/// Stored format version of whichever federation is currently active (the same
/// new/old selection as `active_federation_keys_and_redeem`). Used to decide the
/// active federation's output type (P2SH vs P2SH-P2WSH) and segwit spending.
pub(crate) fn active_federation_format<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> u64 {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    let format_key = match (new, old) {
        (Some(n), Some(_)) => {
            if block_number >= n.creation_block + age {
                super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY
            } else {
                super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY
            }
        }
        (Some(_), None) => super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY,
        (None, _) => return 1000, // genesis federation: plain multisig
    };
    federation_format_version(ctx, format_key)
}

/// Retiring federation keys + redeem (rskj `getRetiringFederation().getRedeemScript()`).
/// The retiring federation is the OLD federation once the new one has activated;
/// its redeem script follows the OLD federation's stored format version.
/// Stored format version under `key`, for callers outside this module.
pub(crate) fn federation_format_version_pub<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    key: &str,
) -> u64 {
    federation_format_version(ctx, key)
}

pub(crate) fn retiring_federation_keys_and_redeem<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<(Vec<[u8; 33]>, Vec<u8>)> {
    let keys = retiring_federation_keys(ctx, config, hardfork_cfg, block_number)?;
    let version = federation_format_version(ctx, super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY);
    let redeem = federation_redeem_for_format(&keys, version, config);
    Some((keys, redeem))
}

/// Retiring federation keys (rskj getRetiringFederation): the old federation
/// while both old+new exist and the new one has reached activation age.
pub(crate) fn retiring_federation_keys<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<Vec<[u8; 33]>> {
    retiring_federation(ctx, config, hardfork_cfg, block_number).map(|fed| fed.btc_keys())
}

/// The retiring federation itself, or `None`.
///
/// rskj `FederationSupportImpl.getRetiringFederationReference`: **both** the
/// old and the new federation must be stored, *and* the new one must have
/// reached its activation age. A stored old federation alone is not a
/// retiring federation -- during the activation window there is none, and
/// every getter that asks reports `FEDERATION_NON_EXISTENT` rather than
/// describing the federation sitting in storage.
pub(crate) fn retiring_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<super::federation::StoredFederation> {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY)?;
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY)?;
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    if block_number >= new.creation_block + age {
        Some(old)
    } else {
        None
    }
}

/// `federation_redeem_for_format`, for callers outside this module.
pub(crate) fn federation_redeem_for_format_pub(
    keys: &[[u8; 33]],
    format_version: u64,
    config: &BridgeConstants,
) -> Vec<u8> {
    federation_redeem_for_format(keys, format_version, config)
}

/// rskj `BridgeUtils.isFromFederateMember(rskTx, federation)`: true when the
/// call's sender RSK address matches the RSK public-key address of any member
/// of the ACTIVE or RETIRING federation. This is the authorization enforced by
/// `Bridge.activeAndRetiringFederationOnly` for `updateCollections` (always)
/// and `receiveHeaders` (post-RSKIP200). `sender` is the immediate caller of
/// the Bridge precompile (= rskj's internalTx sender = `getOwnerRskAddress`),
/// so a relay contract forwarding the call is checked, not the original EOA.
pub(crate) fn is_sender_active_or_retiring_fed_member<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    sender: alloy_primitives::Address,
) -> bool {
    use super::federation::{rsk_address_from_public_key, StoredFederation};

    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);

    // getActiveFederation / getRetiringFederation: the new federation is active
    // once it reaches activation age, with the old one retiring; before that the
    // old federation is still active and there is no retiring federation.
    let (active, retiring): (Option<StoredFederation>, Option<StoredFederation>) =
        match (new, old) {
            (Some(n), Some(o)) => {
                if block_number >= n.creation_block + age {
                    (Some(n), Some(o))
                } else {
                    (Some(o), None)
                }
            }
            (Some(n), None) => (Some(n), None),
            (None, _) => (None, None),
        };

    let member_match = |fed: &StoredFederation| {
        fed.members.iter().any(|m| {
            rsk_address_from_public_key(&m.rsk) == Some(sender)
        })
    };

    if active.as_ref().map(member_match).unwrap_or(false) {
        return true;
    }
    if retiring.as_ref().map(member_match).unwrap_or(false) {
        return true;
    }

    // No stored federation yet → genesis federation. Genesis members are
    // single-key (rsk == btc), so match the sender against each genesis BTC key.
    if active.is_none() {
        return genesis_federation_keys(config)
            .iter()
            .any(|k| rsk_address_from_public_key(k) == Some(sender));
    }
    false
}

pub(crate) fn genesis_federation_keys(config: &BridgeConstants) -> Vec<[u8; 33]> {
    // rskj Federation sorts members by compressed BTC public key.
    let mut keys: Vec<[u8; 33]> = config
        .genesis_federation_public_keys
        .iter()
        .filter_map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).ok()?;
            bytes.try_into().ok()
        })
        .collect();
    keys.sort();
    keys
}

// ---------------------------------------------------------------------------
// addSignature
// ---------------------------------------------------------------------------

/// `addSignature(bytes federatorPublicKey, bytes[] signatures, bytes rskTxHash)`
///
/// Collects federator DER signatures for a pending peg-out BTC transaction.
///
/// Matches rskj's `BridgeSupport.addSignature()`:
/// 1. Parse federator public key, signature array, and RSK tx hash
/// 2. Load the BTC tx from `rskTxsWaitingFS` by RSK tx hash
/// 3. Apply each DER signature to the matching BTC tx input(s)
/// 4. Determine signature threshold from federation stored in Bridge storage
/// 5. If threshold reached: remove from `rskTxsWaitingFS` (tx is fully signed)
/// 6. If not yet threshold: reserialize with new signatures and store back
///
/// The BTC P2SH-multisig scriptSig format (per input):
///   OP_0 <der_sig_1> <der_sig_2> ... <redeemScript>
/// Does `sig` parse the way bitcoinj's `ECDSASignature.decodeFromDER` requires?
///
/// bitcoinj reads one ASN.1 object and casts it to a sequence, then casts the
/// first two elements to integers; anything else throws. It does *not* check
/// for trailing data, and it reads r and s with `getPositiveValue()`, so a
/// negative encoding is tolerated rather than rejected. This mirrors that: a
/// DER SEQUENCE whose first two elements are INTEGERs, with lengths that stay
/// inside the buffer. Stricter checks would reject signatures rskj accepts.
fn is_der_signature(sig: &[u8]) -> bool {
    // SEQUENCE tag plus a definite-length byte.
    if sig.len() < 2 || sig[0] != 0x30 {
        return false;
    }
    let (seq_len, mut i) = match sig[1] {
        n if n < 0x80 => (n as usize, 2usize),
        0x81 if sig.len() >= 3 => (sig[2] as usize, 3usize),
        _ => return false, // longer forms never appear in a 32-byte-scalar signature
    };
    if seq_len > sig.len() - i {
        return false;
    }
    let end = i + seq_len;
    // Two INTEGERs.
    for _ in 0..2 {
        if i + 2 > end || sig[i] != 0x02 {
            return false;
        }
        let len = sig[i + 1] as usize;
        if len == 0 || len >= 0x80 || i + 2 + len > end {
            return false;
        }
        i += 2 + len;
    }
    true
}

pub fn add_signature<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 96 {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // ABI layout: bytes federatorPublicKey, bytes[] signatures, bytes rskTxHash.
    // An out-of-range (oversized) ABI offset cannot index this calldata; treat
    // it as a parse failure (empty output) rather than panicking — rskj's
    // Solidity decoder likewise rejects such inputs. Mainnet #6,223,783 tx[3]
    // forwards malformed calldata whose `signatures` offset points into the
    // middle of the federator key, yielding an absurd array count.
    let (Ok(fed_key_offset), Ok(sigs_offset), Ok(rsk_hash_offset)) = (
        usize::try_from(U256::from_be_slice(&args[0..32])),
        usize::try_from(U256::from_be_slice(&args[32..64])),
        usize::try_from(U256::from_be_slice(&args[64..96])),
    ) else {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };

    // Parse federator public key
    let fed_key = match read_dynamic_bytes(args, fed_key_offset) {
        Ok(k) => k,
        Err(_) => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };
    if fed_key.len() != 33 && fed_key.len() != 65 {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Parse RSK tx hash (32 bytes)
    let rsk_tx_hash_bytes = match read_dynamic_bytes(args, rsk_hash_offset) {
        Ok(h) if h.len() == 32 => h,
        _ => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };
    let mut rsk_tx_hash = [0u8; 32];
    rsk_tx_hash.copy_from_slice(&rsk_tx_hash_bytes);

    // Parse signatures array
    let sigs = parse_bytes_array(args, sigs_offset);
    if sigs.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // rskj `Bridge.addSignature` (Bridge.java:632) runs every signature through
    // `BtcECKey.ECDSASignature.decodeFromDER` before `bridgeSupport` sees it,
    // and a parse failure throws `BridgeIllegalArgumentException`. `Bridge.execute`
    // wraps that in a `VMException`, which `TransactionExecutor` records as
    // `result.setException` -- marking the execution summary failed, so the
    // sender is charged the FULL gas limit with no leftover refund, while the
    // receipt still reports SUCCESS because its status comes from
    // `executionError` (TransactionExecutor.java:565), which this path never
    // sets. Returning the error here lets the existing depth-aware marker turn
    // it into exactly those semantics.
    //
    // Mainnet #9,217,796 tx[1] submits a 71-byte signature beginning 0x9f
    // rather than a DER SEQUENCE. Without this check rustock reached the
    // pegouts-waiting-for-signatures lookup, missed, returned quietly and
    // refunded 104,512 gas the chain had charged -- diverging the state root.
    for sig in &sigs {
        if !is_der_signature(sig) {
            return Err(PrecompileError::other(
                "addSignature: signature could not be parsed as DER",
            ));
        }
    }

    // RSKIP419: if the SVP is ongoing and this RSK tx hash is the one that
    // created the SVP spend transaction, sign that (with the PROPOSED
    // federation) instead of a peg-out (rskj addSignature → addSvpSpendTxSignatures).
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    if hardfork_cfg.has_rskip419(block_number) && svp_is_ongoing(ctx, config, block_number) {
        let wfs_raw =
            bridge_load_bytes_named(ctx, super::storage::SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY);
        if let Some(items) = rlp_decode_list(&wfs_raw) {
            if items.len() == 2 && items[0] == rsk_tx_hash {
                return add_svp_spend_tx_signatures(
                    ctx,
                    &fed_key,
                    &sigs,
                    &rsk_tx_hash,
                    &items[1],
                    block_number,
                    gas_cost,
                );
            }
        }
    }

    // Load the waiting-for-signatures map
    let wfs_key = bridge_storage_key(PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
    let wfs_data = bridge_load_bytes(ctx, wfs_key);
    let mut wfs = deserialize_rsk_txs_waiting_for_signatures(&wfs_data);

    // Find the BTC tx by RSK tx hash
    let btc_tx_raw = match wfs.get(&rsk_tx_hash) {
        Some(r) => r.clone(),
        None => {
            // Temporary diagnostics for the #272,850 pipeline debug: show how
            // far the peg-out pipeline progressed when the lookup misses.
            let queue_len = {
                let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
                deserialize_release_queue_legacy(&bridge_load_bytes(ctx, key)).len()
            };
            let wfc_len = {
                let key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
                deserialize_pegouts_waiting_for_confirmations(&bridge_load_bytes(ctx, key), false)
                    .len()
            };
            let utxo_count = load_federation_utxos(ctx, hardfork_cfg, block_number).len();
            let wfc_raw_len = {
                let key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
                bridge_load_bytes(ctx, key).len()
            };
            let wfs_raw_len = bridge_load_bytes(ctx, wfs_key).len();
            let fee_per_kb = get_effective_fee_per_kb(ctx, config);
            let stored_fed = load_federation_member_keys(ctx).len();
            tracing::debug!(
                "WFS raw {} bytes, WFC raw {} bytes, fee_per_kb {}, stored fed keys {}",
                wfs_raw_len,
                wfc_raw_len,
                fee_per_kb,
                stored_fed
            );
            let (one_off, disable_h) = load_one_off_whitelist(ctx);
            tracing::debug!(
                "addSignature: WFS miss for {} (wfs keys: {:?}; queue {} entries, wfc {} entries, {} federation utxos; whitelist {:?} disable={} unlimited={})",
                to_hex(&rsk_tx_hash),
                wfs.keys().map(|k| to_hex(&k[..4])).collect::<Vec<_>>(),
                queue_len,
                wfc_len,
                utxo_count,
                one_off
                    .iter()
                    .map(|(h, v)| format!("{}:{}", to_hex(h), v))
                    .collect::<Vec<_>>(),
                disable_h,
                load_unlimited_whitelist(ctx).len()
            );
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }
    };

    let mut btc_tx: BtcTransaction = match deserialize(&btc_tx_raw) {
        Ok(tx) => tx,
        Err(_) => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    // rskj areSignaturesEnoughToSignAllTxInputs: one signature per input.
    if sigs.len() != btc_tx.input.len() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Membership check against the active federation (genesis fallback).
    // TODO(rustock): rskj also accepts retiring-federation members.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let federation_keys = federation_keys_or_genesis(ctx, config, hardfork_cfg, block_number, false);
    if federation_keys.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }
    let Some(compressed_key) = compress_pubkey(&fed_key) else {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };
    // rskj getFederationFromPublicKey: active first, then retiring.
    let is_member = federation_keys.contains(&compressed_key)
        || retiring_federation_keys(ctx, config, hardfork_cfg, block_number)
            .is_some_and(|keys| keys.contains(&compressed_key));
    if !is_member {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // rskj logs an add_signature event for a federation member: before
    // RSKIP326 it fires BEFORE the signatures are verified and applied;
    // afterwards only when a signature was actually applied. The format is
    // legacy single-topic before RSKIP146 and Solidity afterwards.
    let legacy_events = !hardfork_cfg.has_rskip146(block_number);
    let log_only_when_applied = hardfork_cfg.has_rskip326(block_number);
    // rskj `BridgeEventLoggerImpl.getFederatorRskPublicKey`: the add_signature
    // event's federatorRskAddress topic derives from the member's BTC public
    // key before RSKIP415 (arrowhead600) and from its RSK public key after.
    // For legacy single-key members the two keys are identical.
    let federator_addr_key: Vec<u8> = if hardfork_cfg.has_rskip415(block_number) {
        federator_rsk_key_for_btc(ctx, config, hardfork_cfg, block_number, &compressed_key)
            .map(|k| k.to_vec())
            .unwrap_or_else(|| fed_key.clone())
    } else {
        fed_key.clone()
    };
    let emit_add_signature = |ctx: &mut CTX, btc_tx: &BtcTransaction| {
        if legacy_events {
            let txid = btc_tx.compute_txid().to_string();
            super::events::log_legacy_add_signature(
                ctx,
                &txid,
                &pubkey_hash160(&compressed_key),
                &rsk_tx_hash,
            );
        } else if let Some(addr) = super::federation::rsk_address_from_public_key(&federator_addr_key) {
            // Topic = federatorRskAddress; data = the BTC public key (always).
            super::events::log_solidity_add_signature(ctx, &rsk_tx_hash, addr, &fed_key);
        }
    };
    if !log_only_when_applied {
        emit_add_signature(ctx, &btc_tx);
    }

    // rskj processSigning: verify every provided signature against its
    // input's sighash before applying any, then insert each at the position
    // determined by the key order in the redeem script. A segwit pegout signs
    // each input with its BIP-143 sighash, whose prevValue comes from the
    // releasesOutpointsValues entry keyed by the tx's witness-stripped hash.
    let prev_values = {
        let txid = btc_txid_event_bytes(&btc_tx);
        load_release_outpoints_values(ctx, &txid)
    };
    let applied = apply_signatures_to_tx(&mut btc_tx, &sigs, &compressed_key, &prev_values);
    if log_only_when_applied && applied {
        emit_add_signature(ctx, &btc_tx);
    }

    if super::release_tx::has_enough_signatures(&btc_tx) {
        // Fully signed: rskj logs release_btc with the signed transaction
        // and removes it from the waiting map (the BTC tx is broadcast
        // off-chain by the federation nodes).
        if legacy_events {
            let txid = btc_tx.compute_txid().to_string();
            super::events::log_legacy_release_btc(ctx, &txid, &btc_serialize(&btc_tx));
        } else {
            super::events::log_solidity_release_btc(ctx, &rsk_tx_hash, &btc_serialize(&btc_tx));
        }
        wfs.remove(&rsk_tx_hash);
        let updated = serialize_rsk_txs_waiting_for_signatures(&wfs);
        bridge_store_bytes(ctx, wfs_key, &updated);
    } else if applied {
        // Partially signed — update the map with the new signatures.
        let updated_raw = btc_serialize(&btc_tx);
        wfs.insert(rsk_tx_hash, updated_raw);
        let updated = serialize_rsk_txs_waiting_for_signatures(&wfs);
        bridge_store_bytes(ctx, wfs_key, &updated);
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// rskj `BridgeSupport.addSvpSpendTxSignatures`: apply a proposed-federation
/// member's signatures to the SVP spend transaction. The signing federation is
/// the PROPOSED federation (not active/retiring); the event's federatorRskAddress
/// derives from the proposed member's RSK key. The updated tx is always stored
/// back to `svpSpendTxWaitingForSignatures`; once fully signed, release_btc is
/// logged and the entry cleared. (lovell700 >> RSKIP146/326/415, so the modern
/// Solidity / log-after-applied / RSK-key paths always apply.)
#[allow(clippy::too_many_arguments)]
fn add_svp_spend_tx_signatures<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    fed_key: &[u8],
    sigs: &[Vec<u8>],
    rsk_tx_hash: &[u8; 32],
    spend_tx_bytes: &[u8],
    _block_number: u64,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let empty = || Ok(PrecompileOutput::new(gas_cost, Bytes::new()));

    let Some(proposed) = super::federation::load_stored_federation(ctx, PROPOSED_FEDERATION_KEY)
    else {
        return empty();
    };
    let Some(compressed_key) = compress_pubkey(fed_key) else {
        return empty();
    };
    // The federator must belong to the proposed federation.
    let Some(member_rsk) =
        proposed.members.iter().find(|m| m.btc == compressed_key).map(|m| m.rsk)
    else {
        return empty();
    };
    let mut spend_tx: BtcTransaction = match deserialize(spend_tx_bytes) {
        Ok(tx) => tx,
        Err(_) => return empty(),
    };
    // areSignaturesEnoughToSignAllTxInputs: one signature per input.
    if sigs.len() != spend_tx.input.len() {
        return empty();
    }

    // generateInputSigHash (segwit): the per-input prevValue comes from the
    // releasesOutpointsValues entry keyed by the spend tx's witness-stripped
    // hash, saved when the spend tx was created (processReleaseTransactionInfo).
    let spend_hash = btc_txid_event_bytes(&spend_tx);
    let prev_values = load_release_outpoints_values(ctx, &spend_hash);

    // processSigning: apply the signatures, then (RSKIP326) log add_signature.
    let applied = apply_signatures_to_tx(&mut spend_tx, sigs, &compressed_key, &prev_values);
    if applied {
        if let Some(addr) = super::federation::rsk_address_from_public_key(&member_rsk) {
            super::events::log_solidity_add_signature(ctx, rsk_tx_hash, addr, fed_key);
        }
    }

    // setSvpSpendTxWaitingForSignatures(updated entry) — always.
    let wfs = super::serialization::rlp_encode_list(&[
        super::serialization::rlp_encode_element(rsk_tx_hash),
        super::serialization::rlp_encode_element(&btc_serialize(&spend_tx)),
    ]);
    bridge_store_bytes_named(ctx, super::storage::SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY, &wfs);

    // Once fully signed: log release_btc and clear the waiting entry.
    if super::release_tx::has_enough_signatures(&spend_tx) {
        super::events::log_solidity_release_btc(ctx, rsk_tx_hash, &btc_serialize(&spend_tx));
        bridge_store_bytes_named(ctx, super::storage::SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY, &[]);
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// BTC txid in rskj event byte order: bitcoinj `Sha256Hash.getBytes()` keeps
/// the display (big-endian) order, the reverse of rust-bitcoin's internal one.
fn btc_txid_event_bytes(tx: &BtcTransaction) -> [u8; 32] {
    let mut bytes = *tx.compute_txid().to_raw_hash().as_byte_array();
    bytes.reverse();
    bytes
}

/// Compress a SEC1 public key (33- or 65-byte) to its 33-byte form.
fn compress_pubkey(key: &[u8]) -> Option<[u8; 33]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let parsed = k256::PublicKey::from_sec1_bytes(key).ok()?;
    let point = parsed.to_encoded_point(true);
    point.as_bytes().try_into().ok()
}

/// RIPEMD160(SHA256(pubkey)) — bitcoinj `ECKey.getPubKeyHash` over the key
/// bytes as provided.
fn pubkey_hash160(key: &[u8]) -> [u8; 20] {
    use sha2::Digest as Sha2Digest;
    let sha256 = sha2::Sha256::digest(key);
    let hash160 = ripemd::Ripemd160::digest(sha256);
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&hash160);
    arr
}

// ---------------------------------------------------------------------------
// rskTxsWaitingFS (pegoutsWaitingForSignatures) serialization
//
// Matches rskj BridgeSerializationUtils.serializeRskTxsWaitingForSignatures:
//   RLP_list [ rlp_bytes(rsk_hash_0), rlp_bytes(btc_tx_raw_0), ... ]
//
// The map is a Java TreeMap<Keccak256, BtcTransaction>, so entries serialize in
// Keccak256 natural order — and rskj's `Keccak256.compareTo` compares bytes
// UNSIGNED from the LAST byte (index 31) down to the first, i.e. reverse-byte
// (little-endian) order. A plain BTreeMap<[u8;32]> orders forward (big-endian),
// which diverges whenever the two orderings disagree, so we re-sort at
// serialization time rather than rely on the in-memory map's iteration order.
// ---------------------------------------------------------------------------

/// Serialize the pegouts-waiting-for-signatures map.
pub fn serialize_rsk_txs_waiting_for_signatures(
    map: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Vec<u8> {
    // rskj Keccak256.compareTo: unsigned, from byte[31] down to byte[0].
    let mut entries: Vec<(&[u8; 32], &Vec<u8>)> = map.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.iter().rev().cmp(b.iter().rev()));
    let mut items = Vec::with_capacity(entries.len() * 2);
    for (rsk_hash, btc_tx_raw) in entries {
        items.push(rlp_encode_element(rsk_hash));
        items.push(rlp_encode_element(btc_tx_raw));
    }
    rlp_encode_list(&items)
}

/// Deserialize the pegouts-waiting-for-signatures map.
/// Returns sorted BTreeMap (RSK tx hash → raw BTC tx bytes).
pub fn deserialize_rsk_txs_waiting_for_signatures(data: &[u8]) -> BTreeMap<[u8; 32], Vec<u8>> {
    let mut map = BTreeMap::new();
    if data.is_empty() {
        return map;
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return map,
    };
    if items.len() % 2 != 0 {
        return map;
    }
    for pair in items.chunks_exact(2) {
        if pair[0].len() != 32 {
            continue;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&pair[0]);
        map.insert(hash, pair[1].clone());
    }
    map
}

// ---------------------------------------------------------------------------
// PegoutsWaitingForConfirmations serialization
//
// Pre-RSKIP146 format (pairs): RLP_list [ btc_tx_bytes, height_bigint, ... ]
// Post-RSKIP146 format (triples): RLP_list [ btc_tx_bytes, height_bigint, rsk_tx_hash, ... ]
//
// Matches rskj BridgeSerializationUtils.serializePegoutsWaitingForConfirmations.
// ---------------------------------------------------------------------------

/// Entry in the pegouts-waiting-for-confirmations set.
#[derive(Debug, Clone)]
pub struct PegoutWaitingForConfirmations {
    pub btc_tx_raw: Vec<u8>,
    pub rsk_block_height: u64,
    pub rsk_tx_hash: Option<[u8; 32]>,
}

pub fn serialize_pegouts_waiting_for_confirmations(
    entries: &[PegoutWaitingForConfirmations],
    use_tx_hash: bool,
) -> Vec<u8> {
    // rskj sorts entries by the serialized BTC transaction bytes
    // (PegoutsWaitingForConfirmations.Entry.BTC_TX_COMPARATOR).
    let mut entries: Vec<&PegoutWaitingForConfirmations> = entries.iter().collect();
    entries.sort_by(|a, b| a.btc_tx_raw.cmp(&b.btc_tx_raw));

    let capacity = if use_tx_hash { entries.len() * 3 } else { entries.len() * 2 };
    let mut items = Vec::with_capacity(capacity);
    for entry in entries {
        items.push(rlp_encode_element(&entry.btc_tx_raw));
        items.push(rlp_encode_u64(entry.rsk_block_height));
        if use_tx_hash {
            let hash = entry.rsk_tx_hash.unwrap_or([0u8; 32]);
            items.push(rlp_encode_element(&hash));
        }
    }
    rlp_encode_list(&items)
}

/// rskj `BridgeStorageProvider.getReleaseTransactionSet`: one in-memory set
/// loaded from the legacy cell (pair entries, no hash), merged post-RSKIP146
/// with the with-txhash cell (triple entries).
pub(crate) fn load_pegout_confirmation_set<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    use_tx_hash: bool,
) -> Vec<PegoutWaitingForConfirmations> {
    let legacy_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
    let mut entries =
        deserialize_pegouts_waiting_for_confirmations(&bridge_load_bytes(ctx, legacy_key), false);
    if use_tx_hash {
        let key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY);
        entries.extend(deserialize_pegouts_waiting_for_confirmations(
            &bridge_load_bytes(ctx, key),
            true,
        ));
    }
    entries
}

/// rskj `BridgeStorageProvider.saveReleaseTransactionSet`: the hash-less
/// entries go to the legacy cell (pair format); post-RSKIP146 the
/// hash-bearing entries go to the with-txhash cell (triple format) — BOTH
/// cells are written on every save.
pub fn store_pegout_confirmation_set<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    entries: &[PegoutWaitingForConfirmations],
    use_tx_hash: bool,
) {
    let legacy_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
    if !use_tx_hash {
        let bytes = serialize_pegouts_waiting_for_confirmations(entries, false);
        bridge_store_bytes(ctx, legacy_key, &bytes);
        return;
    }
    let (with, without): (Vec<_>, Vec<_>) = entries
        .iter()
        .cloned()
        .partition(|e| e.rsk_tx_hash.is_some());
    let legacy_bytes = serialize_pegouts_waiting_for_confirmations(&without, false);
    bridge_store_bytes(ctx, legacy_key, &legacy_bytes);
    let with_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY);
    let with_bytes = serialize_pegouts_waiting_for_confirmations(&with, true);
    bridge_store_bytes(ctx, with_key, &with_bytes);
}

pub fn deserialize_pegouts_waiting_for_confirmations(
    data: &[u8],
    use_tx_hash: bool,
) -> Vec<PegoutWaitingForConfirmations> {
    use super::serialization::rlp_decode_u64;

    if data.is_empty() {
        return Vec::new();
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let stride = if use_tx_hash { 3 } else { 2 };
    let mut entries = Vec::new();
    let mut i = 0;
    while i + stride <= items.len() {
        let btc_tx_raw = items[i].clone();
        let height = rlp_decode_u64(&items[i + 1]);
        let rsk_tx_hash = if use_tx_hash && items[i + 2].len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&items[i + 2]);
            Some(hash)
        } else {
            None
        };
        entries.push(PegoutWaitingForConfirmations { btc_tx_raw, rsk_block_height: height, rsk_tx_hash });
        i += stride;
    }
    entries
}

// ---------------------------------------------------------------------------
// Release request queue serialization
//
// Pre-RSKIP146 (pairs):
//   RLP_list [ hash160_0, bigint(sat_0), hash160_1, bigint(sat_1), ... ]
//
// Post-RSKIP146 (triples, key = releaseRequestQueueWithTxHash):
//   RLP_list [ hash160_0, bigint(sat_0), rsk_hash_0, hash160_1, ... ]
//
// Matches rskj BridgeSerializationUtils.serializeReleaseRequestQueue.
// ---------------------------------------------------------------------------

pub fn serialize_release_queue_legacy(entries: &[ReleaseRequest]) -> Vec<u8> {
    let mut items = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        items.push(rlp_encode_element(&entry.btc_dest_hash160));
        items.push(rlp_encode_u64(entry.amount_satoshis));
    }
    rlp_encode_list(&items)
}

pub fn deserialize_release_queue_legacy(data: &[u8]) -> Vec<ReleaseRequest> {
    use super::serialization::rlp_decode_u64;

    if data.is_empty() {
        return Vec::new();
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    let mut i = 0;
    while i + 1 < items.len() {
        if items[i].len() != 20 {
            i += 2;
            continue;
        }
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&items[i]);
        let amount = rlp_decode_u64(&items[i + 1]);
        entries.push(ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: amount, rsk_tx_hash: None });
        i += 2;
    }
    entries
}

pub fn serialize_release_queue_with_hash(entries: &[ReleaseRequest]) -> Vec<u8> {
    let mut items = Vec::with_capacity(entries.len() * 3);
    for entry in entries {
        items.push(rlp_encode_element(&entry.btc_dest_hash160));
        items.push(rlp_encode_u64(entry.amount_satoshis));
        let hash = entry.rsk_tx_hash.unwrap_or([0u8; 32]);
        items.push(rlp_encode_element(&hash));
    }
    rlp_encode_list(&items)
}

pub fn deserialize_release_queue_with_hash(data: &[u8]) -> Vec<ReleaseRequest> {
    use super::serialization::rlp_decode_u64;

    if data.is_empty() {
        return Vec::new();
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    let mut i = 0;
    while i + 2 < items.len() {
        if items[i].len() != 20 {
            i += 3;
            continue;
        }
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&items[i]);
        let amount = rlp_decode_u64(&items[i + 1]);
        let rsk_hash = if items[i + 2].len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&items[i + 2]);
            Some(h)
        } else {
            None
        };
        entries.push(ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: amount, rsk_tx_hash: rsk_hash });
        i += 3;
    }
    entries
}

// ---------------------------------------------------------------------------
// BTC peg-out transaction builder
//
// Matches rskj's ReleaseTransactionBuilder:
// - Version 2
// - DefaultCoinSelector: sort UTXOs largest first, select greedily
// - Fee = ceil(estimatedVBytes * feePerKb / 1000)
// - Change output to federation P2SH if remainder > dust (546 satoshis)
// ---------------------------------------------------------------------------

/// BTC P2SH script: OP_HASH160 <hash160> OP_EQUAL (23 bytes)
fn p2sh_output_script(hash160: &[u8; 20]) -> bitcoin::ScriptBuf {
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::{OP_HASH160, OP_EQUAL};
    Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(hash160)
        .push_opcode(OP_EQUAL)
        .into_script()
}

/// BTC P2PKH script: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
fn p2pkh_output_script(hash160: &[u8; 20]) -> bitcoin::ScriptBuf {
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::{OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG};
    Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(hash160)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the federation P2SH redeem script from member public keys.
///
/// m-of-n multisig: OP_m <key1> ... <keyn> OP_n OP_CHECKMULTISIG
/// Keys are sorted (matching bitcoinj's createRedeemScript behavior).
pub fn build_federation_redeem_script(keys: &[[u8; 33]], threshold: usize) -> Vec<u8> {
    let mut sorted_keys = keys.to_vec();
    sorted_keys.sort();

    let mut script = Vec::new();
    script.push(0x50 + threshold as u8); // OP_m
    for key in &sorted_keys {
        script.push(33); // OP_PUSHBYTES_33
        script.extend_from_slice(key);
    }
    script.push(0x50 + sorted_keys.len() as u8); // OP_n
    script.push(0xAE); // OP_CHECKMULTISIG
    script
}

/// rskj `Utils.signedLongToByteArrayLE`: `reverseBytes(BigInteger.valueOf(v)
/// .toByteArray())` — the minimal big-endian two's-complement byte array
/// (Java `BigInteger.toByteArray`, which keeps a leading 0x00 sign byte when
/// the top bit is set) reversed to little-endian. NOT BIP68-minimal: e.g.
/// 52560 -> `50 cd 00` (3 bytes), because 0xCD has its high bit set. This is
/// the CSV-delay push consensus byte sequence; a from-scratch minimal encoding
/// would emit `50 cd` and fork. (co/rsk/bitcoinj/core/Utils.java)
fn signed_long_to_byte_array_le(value: i64) -> Vec<u8> {
    // BigInteger.valueOf(value).toByteArray(): minimal big-endian two's complement.
    let mut be = value.to_be_bytes().to_vec();
    // Strip redundant sign-extension bytes (keep one byte that carries the sign).
    while be.len() > 1 {
        let b0 = be[0];
        let b1 = be[1];
        // Drop a leading 0x00 only if the next byte's top bit is also 0 (still
        // positive), or a leading 0xFF only if the next byte's top bit is 1.
        if (b0 == 0x00 && b1 & 0x80 == 0) || (b0 == 0xff && b1 & 0x80 != 0) {
            be.remove(0);
        } else {
            break;
        }
    }
    be.reverse();
    be
}

/// rskj `NonStandardErpRedeemScriptBuilder` (post-RSKIP284/293) and
/// `P2shErpRedeemScriptBuilder` (post-RSKIP353) emergency-multisig template.
///
/// Both wrap a default N-of-M multisig and an emergency K-of-J multisig in a
/// CSV-gated `OP_NOTIF ... OP_ELSE <csv> OP_CHECKSEQUENCEVERIFY OP_DROP ...
/// OP_ENDIF`. The non-standard form strips the trailing `OP_CHECKMULTISIG`
/// from each inner script and appends a single `OP_CHECKMULTISIG` after
/// `OP_ENDIF`; the P2SH-ERP form keeps each inner script intact (incl. its
/// `OP_CHECKMULTISIG`) and emits nothing after `OP_ENDIF`. Inner scripts are
/// standard multisig with keys sorted lexicographically (see
/// [`build_federation_redeem_script`]). The CSV delay is pushed via
/// [`signed_long_to_byte_array_le`].
fn build_erp_redeem_script(
    default_keys: &[[u8; 33]],
    default_threshold: usize,
    erp_keys: &[[u8; 33]],
    erp_threshold: usize,
    csv_delay: i64,
    p2sh: bool,
) -> Vec<u8> {
    let default_redeem = build_federation_redeem_script(default_keys, default_threshold);
    let erp_redeem = build_federation_redeem_script(erp_keys, erp_threshold);
    let csv = signed_long_to_byte_array_le(csv_delay);

    // `removeOpCheckMultisig`: drop the trailing OP_CHECKMULTISIG (last byte).
    let default_inner: &[u8] = if p2sh { &default_redeem } else { &default_redeem[..default_redeem.len() - 1] };
    let erp_inner: &[u8] = if p2sh { &erp_redeem } else { &erp_redeem[..erp_redeem.len() - 1] };

    let mut script = Vec::with_capacity(default_inner.len() + erp_inner.len() + csv.len() + 8);
    script.push(0x64); // OP_NOTIF
    script.extend_from_slice(default_inner);
    script.push(0x67); // OP_ELSE
    script.push(csv.len() as u8); // push CSV bytes
    script.extend_from_slice(&csv);
    script.push(0xb2); // OP_CHECKSEQUENCEVERIFY
    script.push(0x75); // OP_DROP
    script.extend_from_slice(erp_inner);
    script.push(0x68); // OP_ENDIF
    if !p2sh {
        script.push(0xae); // OP_CHECKMULTISIG
    }
    script
}

/// rskj `PendingFederation.buildFederation` redeem-script selection: a
/// committed federation is a standard multisig (pre-RSKIP201), a non-standard
/// ERP federation (RSKIP201 active, RSKIP353 not), a P2SH-ERP federation
/// (RSKIP353 active, RSKIP305 not), or a P2SH-P2WSH-ERP federation (RSKIP305).
/// The emergency keys/threshold and CSV delay come from the network's
/// federation constants. Returns the redeem script whose hash160 is the
/// federation's P2SH address. (P2SH-P2WSH-ERP shares the P2SH-ERP redeem
/// template — see FederationFactory.buildP2shP2wshErpFederation.)
pub fn build_committed_federation_redeem_script(
    keys: &[[u8; 33]],
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Vec<u8> {
    let threshold = keys.len() / 2 + 1;
    if !hardfork_cfg.has_rskip201(block_number) {
        return build_federation_redeem_script(keys, threshold);
    }
    let erp_keys: Vec<[u8; 33]> = config
        .erp_fed_pubkeys
        .iter()
        .map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).expect("valid erp pubkey hex");
            bytes.try_into().expect("33-byte compressed erp pubkey")
        })
        .collect();
    let erp_threshold = erp_keys.len() / 2 + 1;
    let csv = config.erp_fed_activation_delay;
    let p2sh = hardfork_cfg.has_rskip353(block_number);
    build_erp_redeem_script(keys, threshold, &erp_keys, erp_threshold, csv, p2sh)
}

/// Build a live federation's redeem script from its **stored format version**,
/// mirroring rskj `BridgeSerializationUtils.deserializeFederationAccordingToVersion` +
/// `FederationFactory`. A federation that outlives the hardfork that introduced
/// a newer template keeps its original type, so the redeem script (and hence the
/// P2SH address used to recognize peg-in outputs / peg-out inputs) must be chosen
/// by the format the federation was stored with — NOT by the current block height.
///   1000 STANDARD_MULTISIG      → plain N-of-M multisig
///   2000 NON_STANDARD_ERP       → non-standard ERP (no trailing OP_CHECKMULTISIG per inner)
///   3000 P2SH_ERP / 4000 P2SH_P2WSH_ERP → P2SH-ERP template
/// (The P2SH-P2WSH-ERP federation reuses the P2SH-ERP redeem template — see
/// `FederationFactory.buildP2shP2wshErpFederation`.)
fn federation_redeem_for_format(
    keys: &[[u8; 33]],
    format_version: u64,
    config: &BridgeConstants,
) -> Vec<u8> {
    let threshold = keys.len() / 2 + 1;
    if format_version <= 1000 {
        return build_federation_redeem_script(keys, threshold);
    }
    let erp_keys: Vec<[u8; 33]> = config
        .erp_fed_pubkeys
        .iter()
        .map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).expect("valid erp pubkey hex");
            bytes.try_into().expect("33-byte compressed erp pubkey")
        })
        .collect();
    let erp_threshold = erp_keys.len() / 2 + 1;
    let csv = config.erp_fed_activation_delay;
    // 2000 = non-standard ERP (p2sh=false); 3000/4000 = P2SH-ERP template (p2sh=true).
    let p2sh = format_version >= 3000;
    build_erp_redeem_script(keys, threshold, &erp_keys, erp_threshold, csv, p2sh)
}

/// Read a federation's stored format version (rskj
/// `FederationStorageProviderImpl.getFederationFormatVersion`): the value in the
/// `*FederationFormatVersion` cell, or `STANDARD_MULTISIG_FEDERATION` (1000) when
/// the cell is absent (a pre-RSKIP123 only-BTC-keys federation).
fn federation_format_version<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str) -> u64 {
    let cell = bridge_load_bytes_named(ctx, key_name);
    if cell.is_empty() {
        1000
    } else {
        super::storage::rlp_decode_uint(&cell).to::<u64>()
    }
}

/// Public wrapper for governance (commit_federation event addresses).
pub fn redeem_script_hash160_pub(redeem_script: &[u8]) -> [u8; 20] {
    redeem_script_hash160(redeem_script)
}

/// hash160 of a federation's P2SH output script — the value behind its address
/// and `p2sh_output_script`. For a P2SH-P2WSH (format ≥ 4000, RSKIP305/reed800)
/// federation this is `hash160(OP_0 PUSH32 sha256(redeem))` (rskj
/// `ScriptBuilder.createP2SHP2WSHOutputScript`); otherwise plain
/// `hash160(redeem)` (P2SH). The ERP redeem script itself is identical for both.
pub fn federation_output_hash160(redeem_script: &[u8], format_version: u64) -> [u8; 20] {
    if format_version >= 4000 {
        use sha2::Digest as Sha2Digest;
        let mut witness_program = vec![0x00, 0x20]; // OP_0 PUSH32
        witness_program.extend_from_slice(&sha2::Sha256::digest(redeem_script));
        redeem_script_hash160(&witness_program)
    } else {
        redeem_script_hash160(redeem_script)
    }
}

/// P2SH output script program bytes for a script hash160
/// (`OP_HASH160 <hash160> OP_EQUAL`), matching bitcoinj
/// `ScriptBuilder.createP2SHOutputScript(...).getProgram()`. Used by the
/// federation handover to persist `lastRetiredFederationP2SHScript`.
pub fn p2sh_output_script_program(hash160: &[u8; 20]) -> Vec<u8> {
    p2sh_output_script(hash160).into_bytes()
}

/// Compute RIPEMD160(SHA256(redeem_script)) = P2SH address hash160.
fn redeem_script_hash160(redeem_script: &[u8]) -> [u8; 20] {
    use sha2::Digest as Sha2Digest;
    let sha256 = sha2::Sha256::digest(redeem_script);
    let hash160 = ripemd::Ripemd160::digest(sha256);
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&hash160);
    arr
}

/// Load federation member compressed public keys from Bridge storage.
/// Returns sorted keys matching the federation's multisig ordering.
pub(crate) fn load_federation_member_keys<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<[u8; 33]> {
    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Vec::new();
    }

    // Federation RLP format (from governance.rs):
    //   RLP_list [ key1_rlp, key2_rlp, ... ] for pending, OR
    //   RLP_list [ creation_time, block_number, key_list ] for committed
    // Try committed format first (3-item outer list)
    if let Some(outer) = rlp_decode_list(&fed_data) {
        let key_list_data = if outer.len() == 3 {
            &outer[2] // committed: [time, block, keys]
        } else {
            &fed_data  // pending: just the keys list
        };

        if let Some(keys) = rlp_decode_list(key_list_data) {
            return keys.into_iter().filter_map(|k| {
                if k.len() == 33 {
                    let mut arr = [0u8; 33];
                    arr.copy_from_slice(&k);
                    Some(arr)
                } else {
                    None
                }
            }).collect();
        }
    }
    Vec::new()
}

/// rskj `BridgeUtils.getRegularPegoutTxSize` for a regular peg-out (two inputs,
/// two outputs). The active federation's actual (format-aware, possibly ERP)
/// redeem script length and required-signature count drive the estimate.
///
/// - Pre-RSKIP271: `BridgeUtilsLegacy.calculatePegoutTxSize` — an analytic
///   approximation parameterised by the script-sig chunk size.
/// - Post-RSKIP271: `BridgeUtils.calculateLegacyTxSize` — the exact
///   `BtcTransaction.bitcoinSerialize()` length of a 2-in/2-out legacy tx whose
///   inputs carry the redeem script as their scriptSig, plus
///   `numSigsRequired * inputsCount * 72`. (Mainnet federations are never
///   segwit at the heights rustock handles, so only the legacy branch applies.)
fn regular_pegout_tx_size(redeem: &[u8], num_sigs_required: u64, rskip271: bool) -> u64 {
    const INPUTS: u64 = 2;
    const OUTPUTS: u64 = 2;

    if !rskip271 {
        const SIGNATURE_MULTIPLIER: u64 = 71;
        const OUTPUT_SIZE: u64 = 25;
        const INPUT_ADDITIONAL_DATA_SIZE: u64 = 40;
        const OUTPUT_ADDITIONAL_DATA_SIZE: u64 = 9;
        const TX_ADDITIONAL_DATA_SIZE: u64 = 4;

        let script_sig_chunk =
            num_sigs_required * (SIGNATURE_MULTIPLIER + 1) + redeem.len() as u64 + 1;
        return TX_ADDITIONAL_DATA_SIZE
            + (script_sig_chunk + INPUT_ADDITIONAL_DATA_SIZE) * INPUTS
            + (OUTPUT_SIZE + 1 + OUTPUT_ADDITIONAL_DATA_SIZE) * OUTPUTS;
    }

    // Post-RSKIP271: exact bitcoinSerialize() length of the legacy tx that
    // BridgeUtils.calculateLegacyTxSize builds (input scriptSig = redeem,
    // output scriptPubKey = the 23-byte P2SH-to-federation script).
    const P2SH_SCRIPT_LEN: u64 = 23;
    let r = redeem.len() as u64;
    let base_size = 4 // version
        + varint_size(INPUTS)
        + INPUTS * (36 + varint_size(r) + r + 4)
        + varint_size(OUTPUTS)
        + OUTPUTS * (8 + varint_size(P2SH_SCRIPT_LEN) + P2SH_SCRIPT_LEN)
        + 4; // locktime
    let signing_size = num_sigs_required * INPUTS * 72;
    base_size + signing_size
}

/// bitcoinj `VarInt` serialized length.
fn varint_size(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// rskj `BridgeSupport.requestRelease` minimum-fee estimate (post-RSKIP219):
/// `feePerKb * pegoutSize / 1000`, plus a configured percentage gap.
fn require_funds_for_fee(
    redeem: &[u8],
    num_sigs_required: u64,
    fee_per_kb: u64,
    rskip271: bool,
    config: &BridgeConstants,
) -> u64 {
    let pegout_size = regular_pegout_tx_size(redeem, num_sigs_required, rskip271);
    let base = fee_per_kb * pegout_size / 1000;
    base + base * config.minimum_pegout_value_percentage_to_receive_after_fee / 100
}

/// Read the effective fee per KB from storage, falling back to genesis value.
fn get_effective_fee_per_kb<CTX: crate::RskContextTr>(ctx: &mut CTX, config: &BridgeConstants) -> u64 {
    let stored = super::storage::bridge_load_u256(ctx, super::storage::FEE_PER_KB_KEY);
    if stored.is_zero() {
        config.genesis_fee_per_kb
    } else {
        stored.to::<u64>()
    }
}

/// Apply a federator's DER signatures to a peg-out BTC transaction
/// (rskj `BridgeSupport.processSigning` + `sign`).
///
/// All provided signatures are verified against their input's legacy
/// SIGHASH_ALL hash (over the redeem script extracted from the placeholder
/// scriptSig) before any is applied; a single invalid signature aborts the
/// call. Each valid signature is then inserted at the position dictated by
/// the key order in the redeem script, consuming one OP_0 placeholder.
/// Returns whether at least one signature was applied.
fn apply_signatures_to_tx(
    tx: &mut BtcTransaction,
    sigs: &[Vec<u8>],
    fed_key: &[u8; 33],
    prev_values: &[u64],
) -> bool {
    use super::release_tx::{
        extract_redeem_script, input_signed_by, legacy_sighash_all, segwit_sighash_all,
        sig_insertion_index, update_script_with_signature, verify_der_signature,
        witness_input_signed_by, witness_sig_insertion_index, witness_update_with_signature,
    };

    let n = tx.input.len();
    // generateInputSigHash: a segwit input takes a BIP-143 sighash with the
    // value from releasesOutpointsValues and the redeem from its witness; a
    // legacy input takes the redeem from its scriptSig and a legacy sighash.
    let is_witness: Vec<bool> = (0..n).map(|i| !tx.input[i].witness.is_empty()).collect();
    let mut redeems = Vec::with_capacity(n);
    let mut sighashes = Vec::with_capacity(n);
    #[allow(clippy::needless_range_loop)] // indexes several parallel collections
    for i in 0..n {
        let redeem = if is_witness[i] {
            tx.input[i].witness.last().map(|r| r.to_vec())
        } else {
            extract_redeem_script(tx.input[i].script_sig.as_bytes())
        };
        let Some(redeem) = redeem else {
            return false;
        };
        let sighash = if is_witness[i] {
            segwit_sighash_all(tx, i, &redeem, prev_values.get(i).copied().unwrap_or(0))
        } else {
            legacy_sighash_all(tx, i, &redeem)
        };
        sighashes.push(sighash);
        redeems.push(redeem);
    }

    // getTransactionSignatures: any malformed or non-verifying signature
    // aborts without applying anything.
    for (sig, sighash) in sigs.iter().zip(&sighashes) {
        if !verify_der_signature(sig, sighash, fed_key) {
            return false;
        }
    }

    // sign(): stop at the first input already signed by this federator.
    let mut signed = false;
    for i in 0..n {
        let already = if is_witness[i] {
            let pushes: Vec<Vec<u8>> = tx.input[i].witness.iter().map(|p| p.to_vec()).collect();
            witness_input_signed_by(&pushes, fed_key, &sighashes[i])
        } else {
            input_signed_by(tx, i, fed_key, &sighashes[i])
        };
        if already {
            break;
        }
        // rskj getSigInsertionIndex -> findKeyInRedeem throws when the
        // federator's key is not in this input's redeem script (e.g. a
        // NEW-federation member signing a migration tx that spends the OLD
        // federation's UTXOs); processSigning catches it and returns,
        // keeping any inputs already signed in this call. The signature
        // verified fine against the federator's own key, so without this
        // gate it would fill a placeholder it has no claim to (#2,448,984).
        if !super::release_tx::spending_redeem_keys(&redeems[i]).contains(fed_key) {
            return signed;
        }
        let mut encoded = sigs[i].clone();
        encoded.push(0x01); // SIGHASH_ALL
        if is_witness[i] {
            let pushes: Vec<Vec<u8>> = tx.input[i].witness.iter().map(|p| p.to_vec()).collect();
            let index =
                witness_sig_insertion_index(&pushes, &sighashes[i], fed_key, &redeems[i]);
            let Some(updated) = witness_update_with_signature(&pushes, &encoded, index) else {
                return false; // no placeholder left (bitcoinj throws)
            };
            tx.input[i].witness = bitcoin::Witness::from_slice(&updated);
        } else {
            let script_sig = tx.input[i].script_sig.as_bytes().to_vec();
            let index = sig_insertion_index(&script_sig, &sighashes[i], fed_key, &redeems[i]);
            let Some(updated) = update_script_with_signature(&script_sig, &encoded, index) else {
                return false; // no placeholder left (bitcoinj throws)
            };
            tx.input[i].script_sig = bitcoin::ScriptBuf::from_bytes(updated);
        }
        signed = true;
    }
    signed
}

/// Parse an array of dynamic bytes from ABI-encoded `bytes[]` argument.
fn parse_bytes_array(args: &[u8], array_offset: usize) -> Vec<Vec<u8>> {
    if array_offset + 32 > args.len() {
        return Vec::new();
    }
    // Any ABI length/offset that does not fit in a usize is necessarily out of
    // range for this calldata, so treat it as unparseable (an empty/short
    // result) rather than panicking — rskj's Solidity decoder likewise rejects
    // such inputs (the count guard runs after the read, so the conversion must
    // never overflow). Mainnet #6,223,783 tx[3] feeds a count of ~uint256::MAX.
    let Ok(count) = usize::try_from(U256::from_be_slice(&args[array_offset..array_offset + 32]))
    else {
        return Vec::new();
    };
    if count == 0 || count > 1000 {
        return Vec::new();
    }

    let offsets_start = array_offset + 32;
    let mut result = Vec::with_capacity(count);

    for i in 0..count {
        let off_pos = offsets_start + i * 32;
        if off_pos + 32 > args.len() {
            break;
        }
        let Ok(elem_rel_offset) =
            usize::try_from(U256::from_be_slice(&args[off_pos..off_pos + 32]))
        else {
            break;
        };
        let elem_abs = offsets_start + elem_rel_offset;
        if elem_abs + 32 > args.len() {
            break;
        }
        let Ok(elem_len) = usize::try_from(U256::from_be_slice(&args[elem_abs..elem_abs + 32]))
        else {
            break;
        };
        let data_start = elem_abs + 32;
        if data_start + elem_len > args.len() {
            break;
        }
        result.push(args[data_start..data_start + elem_len].to_vec());
    }
    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert BTC satoshis to RBTC wei.
/// 1 BTC = 10^8 satoshis = 10^18 wei RBTC, so 1 satoshi = 10^10 wei.
fn btc_satoshi_to_rbtc_wei(satoshis: u64) -> U256 {
    U256::from(satoshis) * U256::from(10_000_000_000u64) // 10^10
}

fn read_dynamic_bytes(args: &[u8], offset: usize) -> Result<Vec<u8>, PrecompileError> {
    if offset + 32 > args.len() {
        return Err(PrecompileError::other("ABI: offset out of bounds"));
    }
    // An oversized length can never fit this calldata: reject it (rskj's
    // decoder does the same) instead of panicking on the usize conversion.
    let Ok(len) = usize::try_from(U256::from_be_slice(&args[offset..offset + 32])) else {
        return Err(PrecompileError::other("ABI: length out of bounds"));
    };
    let data_start = offset + 32;
    if data_start + len > args.len() {
        return Err(PrecompileError::other("ABI: data out of bounds"));
    }
    Ok(args[data_start..data_start + len].to_vec())
}

// ---------------------------------------------------------------------------
// Read-only query methods
// ---------------------------------------------------------------------------

/// `getNextPegoutCreationBlockNumber()` → int256
pub fn get_next_pegout_creation_block_number<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = super::storage::bridge_load_u256(ctx, NEXT_PEGOUT_HEIGHT_KEY);
    let mut output = [0u8; 32];
    let bytes = val.to_be_bytes::<32>();
    output.copy_from_slice(&bytes);
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

/// `getQueuedPegoutsCount()` → uint256
///
/// Returns the number of pending peg-out requests in the release queue.
/// Checks both `releaseRequestQueueWithTxHash` (post-RSKIP146) and the
/// legacy `releaseRequestQueue`.
pub fn get_queued_pegouts_count<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Both queues, as rskj's `getReleaseRequestQueue().getEntries().size()`
    // counts them -- not whichever one happens to be populated. The method
    // only exists from RSKIP271 (hop400), which is well past RSKIP146, so the
    // with-txhash half is always in scope here.
    let entries = load_release_request_queue(ctx, true);
    let count = U256::from(entries.len());
    Ok(PrecompileOutput::new(gas_cost, count.to_be_bytes::<32>().to_vec().into()))
}

/// rskj `BridgeStorageProvider.saveReleaseRequestQueue` (l.197-207): the queue
/// is written back **split by whether an entry carries its creating RSK tx
/// hash** -- `serializeReleaseRequestQueue` takes `getEntriesWithoutHash()`
/// and `serializeReleaseRequestQueueWithTxHash` takes `getEntriesWithHash()`.
///
/// Both cells are written once RSKIP146 is active. That matters for the case
/// this fixes: after processing a concatenated queue, the legacy half has to
/// be rewritten with what is left of it, or entries that were just paid out
/// would still be sitting there. On mainnet the legacy half is empty and this
/// rewrites `[0xc0]` over `[0xc0]`, which is the value `updateCollections`
/// already materializes on its first call.
fn save_release_request_queue<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    entries: &[ReleaseRequest],
    rskip146: bool,
) {
    let without_hash: Vec<ReleaseRequest> = entries
        .iter()
        .filter(|e| e.rsk_tx_hash.is_none())
        .cloned()
        .collect();
    bridge_store_bytes(
        ctx,
        bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY),
        &serialize_release_queue_legacy(&without_hash),
    );
    if rskip146 {
        let with_hash: Vec<ReleaseRequest> = entries
            .iter()
            .filter(|e| e.rsk_tx_hash.is_some())
            .cloned()
            .collect();
        bridge_store_bytes(
            ctx,
            bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY),
            &serialize_release_queue_with_hash(&with_hash),
        );
    }
}

/// rskj `BridgeStorageProvider.getReleaseRequestQueue` (l.168-193): the legacy
/// `releaseRequestQueue` entries FIRST, then — once RSKIP146 is active — the
/// `releaseRequestQueueWithTxHash` entries appended. Both lists, concatenated,
/// not one or the other.
pub(crate) fn load_release_request_queue<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    rskip146: bool,
) -> Vec<ReleaseRequest> {
    let legacy = bridge_load_bytes(ctx, bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY));
    let mut entries = deserialize_release_queue_legacy(&legacy);
    if rskip146 {
        let with_hash =
            bridge_load_bytes(ctx, bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY));
        entries.extend(deserialize_release_queue_with_hash(&with_hash));
    }
    entries
}

/// The deterministic recipient rskj uses for the hypothetical extra peg-out in
/// `getEstimatedFeesFromPegoutTransactionSimulation`:
/// `BtcECKey.fromPublicOnly(<this pubkey>).toAddress(params)` — a P2PKH of its
/// hash160. The key exists only to make the simulated output deterministic.
const SIMULATION_RECIPIENT_PUBKEY: [u8; 33] = [
    0x03, 0x29, 0xf5, 0x19, 0xf8, 0xd1, 0x3a, 0x7e, 0x3d, 0xd3, 0x5f, 0xa5, 0xc2, 0x48, 0x0c, 0x6b,
    0xf6, 0xc0, 0x48, 0x9d, 0xa4, 0x00, 0x81, 0xe8, 0x31, 0x1a, 0x91, 0x81, 0x34, 0x92, 0x08, 0x39,
    0x53,
];

/// rskj `BridgeSupport.getEstimatedFeesForNextPegOutEvent` (BridgeSupport.java
/// l.2632-2644), in satoshis.
///
/// ```text
///   shouldReturnZeroEstimatedFees()        -> 0
///   !RSKIP305                              -> getEstimatedFeesFromInputsAndOutputsCount()
///   otherwise                              -> getEstimatedFeesFromPegoutTransactionSimulation()
///                                             (falling back to the former on failure)
/// ```
fn estimated_fees_for_next_pegout<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> u64 {
    let queue = load_release_request_queue(ctx, hardfork_cfg.has_rskip146(block_number));

    // shouldReturnZeroEstimatedFees (l.2646-2651).
    if !hardfork_cfg.has_rskip385(block_number)
        && (!hardfork_cfg.has_rskip271(block_number) || queue.is_empty())
    {
        return 0;
    }

    if !hardfork_cfg.has_rskip305(block_number) {
        return estimated_fees_from_inputs_and_outputs_count(
            ctx, config, hardfork_cfg, block_number, queue.len(),
        );
    }

    // getEstimatedFeesFromPegoutTransactionSimulation (l.2677-2692): the
    // hypothetical next peg-out is worth the minimum peg-out value from
    // RSKIP540, and 1 BTC (`Coin.valueOf(1, 0)`) before it.
    let estimated_next_amount = if hardfork_cfg.has_rskip540(block_number) {
        config.minimum_pegout_tx_value
    } else {
        100_000_000
    };

    simulate_pegout_fee(ctx, config, hardfork_cfg, block_number, &queue, estimated_next_amount)
        .unwrap_or_else(|| {
            // BridgeIllegalArgumentException -> "fallback to old logic".
            estimated_fees_from_inputs_and_outputs_count(
                ctx, config, hardfork_cfg, block_number, queue.len(),
            )
        })
}

/// rskj `BridgeSupport.getEstimatedFeesFromInputsAndOutputsCount`
/// (l.2664-2675): size a peg-out with 2 inputs and `queued + 2` outputs, then
/// `feePerKB * size / 1000`.
fn estimated_fees_from_inputs_and_outputs_count<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    queued_pegouts: usize,
) -> u64 {
    let (keys, redeem_script) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    if keys.is_empty() {
        return 0;
    }
    let format = active_federation_format(ctx, config, hardfork_cfg, block_number);
    let fed_script = p2sh_output_script(&federation_output_hash160(&redeem_script, format));
    let threshold = super::release_tx::redeem_script_threshold(&redeem_script);

    let outputs_count = queued_pegouts + 2;
    let inputs_count = 2;

    // rskj BridgeUtils.simulatePegoutTxSize: RSKIP378 (cardamom1000) is -1 on
    // both mainnet and testnet, so the pre-cardamom branch is the live one —
    // and it picks the sizer by federation format, not by activation.
    let size = if format >= 4000 {
        pegout_tx_size_segwit(&redeem_script, &fed_script, threshold, inputs_count, outputs_count)
    } else {
        pegout_tx_size_legacy(&redeem_script, &fed_script, threshold, inputs_count, outputs_count)
    };

    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    fee_per_kb.saturating_mul(size as u64) / 1000
}

/// rskj `BridgeSupport.getEstimatedFeesFromPegoutTransactionSimulation(Coin)`
/// (l.2694-2732): append one hypothetical request to a COPY of the release
/// queue, run the ordinary batched-peg-out builder over the active
/// federation's real UTXO set, and report `inputSum - outputSum`.
///
/// `None` mirrors the `BridgeIllegalArgumentException` rskj throws when the
/// builder does not return SUCCESS; the caller then falls back.
fn simulate_pegout_fee<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    queue: &[ReleaseRequest],
    estimated_next_amount: u64,
) -> Option<u64> {
    let (keys, redeem_script) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    if keys.is_empty() {
        return None;
    }
    let format = active_federation_format(ctx, config, hardfork_cfg, block_number);
    let is_segwit = format >= 4000;
    let change_script = p2sh_output_script(&federation_output_hash160(&redeem_script, format));
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    let tx_version = if hardfork_cfg.has_rskip201(block_number) { 2 } else { 1 };

    let utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
    let available = load_utxos_at(ctx, utxo_key);

    // Same FlyoverCompatibleBtcWallet resolution updateCollections uses.
    let mut candidate_fed_redeems = vec![redeem_script.clone()];
    if let Some((_, retiring_redeem)) =
        retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number)
    {
        candidate_fed_redeems.push(retiring_redeem);
    }
    let flyover_overrides = resolve_flyover_input_redeems(ctx, &available, &candidate_fed_redeems);
    let redeem_for = |u: &BridgeUtxo| -> &[u8] {
        flyover_overrides
            .get(&(u.tx_hash, u.vout))
            .map(|r| r.as_slice())
            .unwrap_or(redeem_script.as_slice())
    };

    let mut outputs: Vec<super::release_tx::PegoutOutput> = queue
        .iter()
        .map(|r| super::release_tx::PegoutOutput {
            script: p2pkh_output_script(&r.btc_dest_hash160),
            amount_satoshis: r.amount_satoshis,
        })
        .collect();
    outputs.push(super::release_tx::PegoutOutput {
        script: p2pkh_output_script(&redeem_script_hash160(&SIMULATION_RECIPIENT_PUBKEY)),
        amount_satoshis: estimated_next_amount,
    });

    let built = super::release_tx::complete_pegout_tx(
        &available,
        &outputs,
        &change_script,
        redeem_for,
        fee_per_kb,
        tx_version,
        is_segwit,
    )?;

    let input_sum: u64 = built.used_utxos.iter().map(|u| u.value_satoshis).sum();
    let output_sum: u64 = built.tx.output.iter().map(|o| o.value.to_sat()).sum();
    Some(input_sum.saturating_sub(output_sum))
}

/// `getEstimatedFeesForNextPegOutEvent()` → uint256 (satoshis)
///
/// Transaction-callable (rskj `BridgeMethods` `fixedPermission(false)`), so the
/// value it returns is consensus-visible: a contract can CALL it and branch on
/// the answer. It used to return a hardcoded 0.
pub fn get_estimated_fees_for_next_pegout<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let fee = estimated_fees_for_next_pegout(ctx, config, hardfork_cfg, block_number);
    let out = U256::from(fee).to_be_bytes::<32>();
    Ok(PrecompileOutput::new(gas_cost, out.to_vec().into()))
}

/// `getEstimatedFeesForPegOutAmount(uint256 pegoutAmountInWeis)` → uint256
///
/// Enabled by RSKIP540 (Vetiver900). Validates the amount against the
/// minimum peg-out value like rskj BridgeSupport.getEstimatedFeesForPegOutAmount;
/// the fee simulation itself shares getEstimatedFeesForNextPegOutEvent's
/// (stub) fidelity.
pub fn get_estimated_fees_for_pegout_amount<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    if !hardfork_cfg.has_rskip540(block_number) {
        return Err(PrecompileError::other(
            "getEstimatedFeesForPegOutAmount: method not enabled",
        ));
    }
    if args.len() < 32 {
        return Err(PrecompileError::other(
            "getEstimatedFeesForPegOutAmount: args too short",
        ));
    }

    // co.rsk.core.Coin (wei) -> bitcoin Coin (satoshi): / 10^10
    let wei = U256::from_be_slice(&args[0..32]);
    let satoshis = wei / U256::from(10_000_000_000u64);
    if satoshis < U256::from(config.minimum_pegout_tx_value) {
        return Err(PrecompileError::other(
            "getEstimatedFeesForPegOutAmount: peg-out amount is below the minimum peg-out value",
        ));
    }

    // rskj getEstimatedFeesForPegOutAmount: the same peg-out simulation as
    // getEstimatedFeesForNextPegOutEvent, with the caller's amount as the
    // hypothetical extra request. rskj does NOT fall back here -- a builder
    // failure propagates as BridgeIllegalArgumentException.
    // A BTC Coin is a signed 64-bit satoshi count; anything larger cannot be
    // built into a transaction at all, so it takes the same failure path.
    let amount: u64 = satoshis.try_into().map_err(|_| {
        PrecompileError::other("getEstimatedFeesForPegOutAmount: cannot simulate peg-out")
    })?;
    let queue = load_release_request_queue(ctx, hardfork_cfg.has_rskip146(block_number));
    let fee = simulate_pegout_fee(ctx, config, hardfork_cfg, block_number, &queue, amount)
        .ok_or_else(|| {
            PrecompileError::other("getEstimatedFeesForPegOutAmount: cannot simulate peg-out")
        })?;
    let out = U256::from(fee).to_be_bytes::<32>();
    Ok(PrecompileOutput::new(gas_cost, out.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A writable Bridge context with nothing in it but the raw-storage
    /// overlay -- enough for the release-queue reads and writes.
    fn queue_ctx() -> impl crate::RskContextTr {
        use revm::MainContext;
        revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default())
    }

    /// Recording must be observation only. The whitelist consumer is the
    /// hook that sits inside a state-mutating function, so it is the one
    /// where a careless record could write; and the rejection branch nearby
    /// re-evaluates a locking-cap check that lazily initializes its cell.
    /// If turning recording on changed the writes, every replayed root would
    /// differ from the chain and the records would describe a fiction.
    #[test]
    fn recording_does_not_change_what_is_written() {
        use revm::MainContext;

        fn run(record: bool) -> Vec<crate::raw_storage::RawWrite> {
            let mut ctx =
                revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());
            let sender = [0x7au8; 20];
            super::super::storage::save_lock_whitelist(
                &mut ctx,
                &[(sender, 1_000_000u64)],
                0,
                &[],
                true,
            );
            ctx.chain.raw_storage.commit_call();

            if record {
                crate::silent::start();
                crate::silent::set_position(2_745_770, 1);
            }
            let allowed = whitelist_allows_and_consume(&mut ctx, &sender, 500_000, 10, true);
            assert!(allowed, "the entry covers the amount");
            if record {
                let recorded = crate::silent::finish();
                assert_eq!(recorded.len(), 1, "the consumed entry was recorded");
                assert_eq!(recorded[0].kind, SilentKind::WhitelistEntryConsumed);
            }
            ctx.chain.raw_storage.commit_call();
            ctx.chain.raw_storage.drain()
        }

        assert_eq!(run(false), run(true), "recording changed the written state");
    }

    fn legacy_entry(tag: u8, amount: u64) -> ReleaseRequest {
        ReleaseRequest { btc_dest_hash160: [tag; 20], amount_satoshis: amount, rsk_tx_hash: None }
    }

    fn hashed_entry(tag: u8, amount: u64) -> ReleaseRequest {
        ReleaseRequest {
            btc_dest_hash160: [tag; 20],
            amount_satoshis: amount,
            rsk_tx_hash: Some([tag; 32]),
        }
    }

    /// rskj `getReleaseRequestQueue` concatenates, legacy first. Reading one
    /// queue or the other -- which is what `updateCollections` and
    /// `getQueuedPegoutsCount` used to do -- loses entries whenever both are
    /// populated. Mainnet never reaches that state, because the legacy queue
    /// was drained before RSKIP146 activated at iris300 (#3,614,800), so this
    /// is a divergence that only a test can reach.
    #[test]
    fn release_request_queue_concatenates_legacy_then_with_tx_hash() {
        let mut ctx = queue_ctx();
        let legacy = vec![legacy_entry(0x11, 1_000), legacy_entry(0x22, 2_000)];
        let hashed = vec![hashed_entry(0x33, 3_000)];
        bridge_store_bytes(
            &mut ctx,
            bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY),
            &serialize_release_queue_legacy(&legacy),
        );
        bridge_store_bytes(
            &mut ctx,
            bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY),
            &serialize_release_queue_with_hash(&hashed),
        );

        let all = load_release_request_queue(&mut ctx, true);
        assert_eq!(
            all.iter().map(|e| e.amount_satoshis).collect::<Vec<_>>(),
            vec![1_000, 2_000, 3_000],
            "legacy entries come first, in queue order, then the hashed ones"
        );

        // Before RSKIP146 the with-txhash queue is not in scope at all.
        let pre = load_release_request_queue(&mut ctx, false);
        assert_eq!(pre.len(), 2);
    }

    /// Ground truth: rootstock testnet #6,602, whose only state-changing
    /// peg-in was *rejected*. The reference node's storage at that block
    /// holds `lockWhitelist = 0xc5847fffffff` and
    /// `unlimitedLockWhitelist = 0xc0` where #6,601 held neither, so rskj
    /// created both cells on a rejection that changed nothing.
    ///
    /// Writing only on modification makes rustock's state root diverge from
    /// #6,602 onward, which is what issue #290 was.
    #[test]
    fn a_rejected_pegin_still_materialises_both_whitelist_cells() {
        let mut ctx = queue_ctx();
        let sender = [0x42u8; 20];

        assert!(
            bridge_load_bytes_named(&mut ctx, LOCK_WHITELIST_KEY).is_empty(),
            "precondition: the whitelist has never been written"
        );

        let allowed = whitelist_allows_and_consume(&mut ctx, &sender, 1_000, 100, true);
        assert!(!allowed, "an address on neither list is not whitelisted");

        assert_eq!(
            to_hex(&bridge_load_bytes_named(&mut ctx, LOCK_WHITELIST_KEY)),
            "c5847fffffff",
            "empty one-off list plus the i32::MAX disable height, as rskj writes it"
        );
        assert_eq!(
            to_hex(&bridge_load_bytes_named(&mut ctx, UNLIMITED_LOCK_WHITELIST_KEY)),
            "c0",
            "empty unlimited list"
        );
    }

    /// Before RSKIP87 rskj's `saveLockWhitelist` skips the unlimited cell, so
    /// writing it early would diverge in the other direction.
    #[test]
    fn the_unlimited_cell_is_not_written_before_rskip87() {
        let mut ctx = queue_ctx();
        whitelist_allows_and_consume(&mut ctx, &[0x42; 20], 1_000, 100, false);

        assert_eq!(
            to_hex(&bridge_load_bytes_named(&mut ctx, LOCK_WHITELIST_KEY)),
            "c5847fffffff",
            "the one-off cell is written at every activation"
        );
        assert!(
            bridge_load_bytes_named(&mut ctx, UNLIMITED_LOCK_WHITELIST_KEY).is_empty(),
            "the unlimited cell does not exist before RSKIP87"
        );
    }

    /// The save-back must not disturb the entry it did not touch, and a
    /// successful one-off lock must still consume its entry.
    #[test]
    fn a_consumed_one_off_entry_is_removed_and_the_rest_survive() {
        let mut ctx = queue_ctx();
        let user = [0x11u8; 20];
        let other = [0x22u8; 20];
        store_one_off_whitelist(&mut ctx, &[(user, 5_000), (other, 7_000)], i32::MAX);

        assert!(whitelist_allows_and_consume(&mut ctx, &user, 5_000, 100, true));

        let (entries, disable_h) = load_one_off_whitelist(&mut ctx);
        assert_eq!(entries, vec![(other, 7_000)], "only the used entry is consumed");
        assert_eq!(disable_h, i32::MAX);
    }

    /// A one-off entry too small for the amount rejects *and keeps* the
    /// entry: rskj consumes only after `isWhitelistedFor` passes.
    #[test]
    fn an_over_cap_lock_is_rejected_without_consuming_the_entry() {
        let mut ctx = queue_ctx();
        let user = [0x11u8; 20];
        store_one_off_whitelist(&mut ctx, &[(user, 5_000)], i32::MAX);

        assert!(!whitelist_allows_and_consume(&mut ctx, &user, 9_000, 100, true));

        assert_eq!(
            load_one_off_whitelist(&mut ctx).0,
            vec![(user, 5_000)],
            "a rejected lock leaves the entry in place"
        );
    }

    /// An unlimited entry is never consumed, and the save-back must preserve
    /// it rather than write the empty list the one-off branch computed.
    #[test]
    fn an_unlimited_entry_survives_the_lock_it_authorises() {
        let mut ctx = queue_ctx();
        let user = [0x33u8; 20];
        store_unlimited_whitelist(&mut ctx, &[user]);

        assert!(whitelist_allows_and_consume(&mut ctx, &user, 1_000_000, 100, true));
        assert_eq!(load_unlimited_whitelist(&mut ctx), vec![user]);

        // And again: unlimited entries authorise repeatedly.
        assert!(whitelist_allows_and_consume(&mut ctx, &user, 1_000_000, 100, true));
        assert_eq!(load_unlimited_whitelist(&mut ctx), vec![user]);
    }

    /// Past the disable height the whitelist stops gating, but it is still
    /// loaded -- and so still saved.
    #[test]
    fn a_disabled_whitelist_allows_anyone_and_is_still_written_back() {
        let mut ctx = queue_ctx();
        store_one_off_whitelist(&mut ctx, &[], 50);

        assert!(whitelist_allows_and_consume(&mut ctx, &[0x99; 20], 1_000, 51, true));
        assert_eq!(
            load_one_off_whitelist(&mut ctx),
            (Vec::new(), 50),
            "the disable height survives the save-back"
        );
        assert_eq!(
            to_hex(&bridge_load_bytes_named(&mut ctx, UNLIMITED_LOCK_WHITELIST_KEY)),
            "c0"
        );
    }

    #[test]
    fn queued_pegouts_count_sums_both_queues() {
        let mut ctx = queue_ctx();
        bridge_store_bytes(
            &mut ctx,
            bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY),
            &serialize_release_queue_legacy(&[legacy_entry(0x11, 1_000)]),
        );
        bridge_store_bytes(
            &mut ctx,
            bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY),
            &serialize_release_queue_with_hash(&[
                hashed_entry(0x22, 2_000),
                hashed_entry(0x33, 3_000),
            ]),
        );

        let out = get_queued_pegouts_count(&mut ctx, 0).unwrap();
        assert_eq!(
            U256::from_be_slice(out.bytes.as_ref()),
            U256::from(3),
            "the count is both queues, not whichever one is populated"
        );
    }

    /// rskj `saveReleaseRequestQueue` writes the queue back split by whether
    /// an entry carries its creating RSK tx hash, and writes **both** cells
    /// once RSKIP146 is active -- so a legacy half that was just drained is
    /// rewritten empty rather than left holding entries that were already
    /// paid out.
    #[test]
    fn saving_a_mixed_queue_splits_it_by_tx_hash() {
        let mut ctx = queue_ctx();
        let mixed = vec![legacy_entry(0x11, 1_000), hashed_entry(0x22, 2_000)];
        save_release_request_queue(&mut ctx, &mixed, true);

        let legacy_cell =
            bridge_load_bytes(&mut ctx, bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY));
        let hashed_cell = bridge_load_bytes(
            &mut ctx,
            bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY),
        );
        assert_eq!(deserialize_release_queue_legacy(&legacy_cell).len(), 1);
        assert_eq!(deserialize_release_queue_with_hash(&hashed_cell).len(), 1);

        // Round-trip: what comes back out is what went in, in the same order.
        let reloaded = load_release_request_queue(&mut ctx, true);
        let shape = |q: &[ReleaseRequest]| -> Vec<(u8, u64, bool)> {
            q.iter()
                .map(|e| (e.btc_dest_hash160[0], e.amount_satoshis, e.rsk_tx_hash.is_some()))
                .collect()
        };
        assert_eq!(shape(&reloaded), shape(&mixed));

        // Draining the legacy half rewrites its cell as RLP.encodeList([]).
        save_release_request_queue(&mut ctx, &[hashed_entry(0x22, 2_000)], true);
        let legacy_cell =
            bridge_load_bytes(&mut ctx, bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY));
        assert_eq!(legacy_cell, vec![0xc0], "emptied, not left stale");
        assert_eq!(load_release_request_queue(&mut ctx, true).len(), 1);
    }

    /// Ground truth from mainnet #8,113,398 (the segwit SVP spend tx for the
    /// first reed800 P2SH-P2WSH proposed federation): a format-4000 spend with
    /// a 457-byte ERP redeem, threshold 5, 2 inputs / 1 output sizes to 522
    /// vbytes (`calculateSegwitTxSize`), giving a 5,008-sat fee at 8,000 sat/kB.
    #[test]
    fn svp_spend_segwit_tx_size_8113398() {
        let redeem = vec![0u8; 457];
        // 23-byte P2SH-P2WSH output script (OP_HASH160 PUSH20 <20> OP_EQUAL).
        let fed_script = p2sh_output_script(&[0u8; 20]);
        assert_eq!(pegout_tx_size_segwit(&redeem, &fed_script, 5, 2, 1), 522);
        let backed_up = 522u64 * 12 / 10;
        assert_eq!(8000u64 * backed_up / 1000, 5008);
    }

    /// rskj `setSpendingBaseScriptSegwit`: scriptSig is a single push of the
    /// witness program `OP_0 PUSH32 sha256(redeem)`; the base witness is the
    /// CHECKMULTISIG dummy + `threshold` empty sig placeholders + the OP_NOTIF
    /// flag + the redeem (threshold 5 → 8 stack items).
    #[test]
    fn svp_spend_segwit_base_input_layout() {
        use sha2::Digest as _;
        let redeem = vec![0xabu8; 100];
        let (script_sig, witness) = super::super::release_tx::segwit_base_input(&redeem, 5);
        let mut expected_sig = vec![0x22u8, 0x00, 0x20];
        expected_sig.extend_from_slice(&sha2::Sha256::digest(&redeem));
        assert_eq!(script_sig.as_bytes(), expected_sig.as_slice());
        assert_eq!(witness.len(), 8); // 1 dummy + 5 sigs + 1 OP_NOTIF + redeem
        assert!(witness.iter().take(7).all(|i| i.is_empty()));
        assert_eq!(witness.iter().nth(7).unwrap(), redeem.as_slice());
    }

    /// Regression for mainnet #5,967,453: a flyover negative response code must
    /// be ABI-encoded as a FULL 256-bit two's-complement int256 (rskj
    /// `BigInteger.valueOf(code)`), not a 128-bit-wide value zero-extended to
    /// 256 bits. The LBC contract checks `bridgeResponse + 900 == 0` to detect
    /// GENERIC_ERROR (-900); the old `code as i128 as u128` produced `2^128-900`,
    /// so adding 900 overflowed at bit 128 to `2^128` (non-zero) instead of
    /// wrapping at bit 256 to 0 — flipping a JUMPI and over-charging 51,580 gas
    /// (computed 194,449 vs header 142,869).
    #[test]
    fn flyover_code_output_full_256bit_twos_complement() {
        // -900 = 0xffff...fc7c with ALL 31 high bytes 0xff (64 hex f's).
        let out = flyover_code_output(flyover_codes::GENERIC_ERROR);
        let expected = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7c";
        assert_eq!(alloy_primitives::hex::encode(&out), expected);

        // The contract's check: response + 900 == 0 (mod 2^256).
        let v = U256::from_be_slice(&out);
        assert_eq!(v.wrapping_add(U256::from(900u64)), U256::ZERO);

        // Every negative flyover code round-trips: value + |code| == 0 (mod 2^256).
        for code in [
            flyover_codes::REFUNDED_USER,
            flyover_codes::REFUNDED_LP,
            flyover_codes::UNPROCESSABLE_NOT_CONTRACT,
            flyover_codes::UNPROCESSABLE_VALIDATIONS,
            flyover_codes::GENERIC_ERROR,
        ] {
            let v = U256::from_be_slice(&flyover_code_output(code));
            assert_eq!(v.wrapping_add(U256::from(code.unsigned_abs())), U256::ZERO);
            // High byte is 0xff (sign-extended across the whole word).
            assert_eq!(flyover_code_output(code)[0], 0xff);
        }

        // A non-negative locked-amount code encodes as a plain big-endian uint.
        assert_eq!(U256::from_be_slice(&flyover_code_output(0)), U256::ZERO);
        assert_eq!(U256::from_be_slice(&flyover_code_output(123_456)), U256::from(123_456u64));
    }

    /// Regression for mainnet #5,171,600: once the retiring federation is
    /// cleared earlier in the block, a btc tx that pays only the now-retired
    /// federation leaves an EMPTY set of live-federation outputs. rskj's
    /// `isAnyUTXOAmountBelowMinimum` (RSKIP293) is `false` over that empty set,
    /// so the tx is a valid amount-0 peg-in (it emits pegin_btc(amount=0),
    /// creates the destination account and is marked processed) rather than
    /// being ignored. Pre-RSKIP293 the 0 total is below minimum → not a peg-in.
    #[test]
    fn empty_live_outputs_are_not_below_minimum_under_rskip293() {
        let min = 500_000;
        // RSKIP293: per-UTXO. Empty set → not below minimum (valid amount-0 peg-in).
        assert!(!pegin_below_minimum(&[], min, true));
        // A single below-minimum UTXO → below minimum (rejected).
        assert!(pegin_below_minimum(&[100_000], min, true));
        // Any below-minimum UTXO fails even if the total clears the minimum.
        assert!(pegin_below_minimum(&[100_000, 600_000], min, true));
        // All UTXOs at/above the minimum → valid.
        assert!(!pegin_below_minimum(&[500_000, 600_000], min, true));

        // Pre-RSKIP293: total comparison. Empty set (0 total) IS below minimum.
        assert!(pegin_below_minimum(&[], min, false));
        // A mix below the minimum total is below; one clearing it is not.
        assert!(pegin_below_minimum(&[100_000, 300_000], min, false));
        assert!(!pegin_below_minimum(&[100_000, 600_000], min, false));
    }

    /// Regression for mainnet #5,527,682 (RSKIP377, Fingerroot500): on a
    /// federation handover the retiring ERP federation's
    /// `lastRetiredFederationP2SHScript` is its *members* (default / standard
    /// multisig branch) P2SH, NOT the full ERP P2SH. rskj
    /// `FederationSupportImpl.getFederationMembersP2SHScript` returns
    /// `ErpFederation.getDefaultP2SHScript()` for an ERP federation. Pre-RSKIP377
    /// it stored the full ERP P2SH; the two hash160s differ, so getting this
    /// wrong forks the state trie at the `lastRetiredFedP2SHScript` leaf.
    #[test]
    fn rskip377_last_retired_fed_uses_default_branch_p2sh() {
        let config = crate::bridge::constants::BridgeConstants::mainnet();
        let hardfork = RskHardforkConfig::mainnet();
        // A P2SH-ERP federation (RSKIP353 active at fingerroot500).
        let block = 5_527_682u64;
        assert!(hardfork.has_rskip201(block));
        assert!(hardfork.has_rskip353(block));
        assert!(hardfork.has_rskip377(block));

        let key = |seed: u8| -> [u8; 33] {
            use k256::ecdsa::SigningKey;
            let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
            sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap()
        };
        let mut keys: Vec<[u8; 33]> = (1u8..=5).map(key).collect();
        keys.sort();

        // Full ERP redeem (what the federation IS) vs the default/standard branch.
        let full_erp = build_committed_federation_redeem_script(&keys, &config, &hardfork, block);
        let default_branch = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
        assert_ne!(full_erp, default_branch, "ERP redeem must differ from its default branch");

        let full_hash = redeem_script_hash160(&full_erp);
        let default_hash = redeem_script_hash160(&default_branch);
        // RSKIP377 stores the default-branch P2SH; the legacy bug stored the ERP one.
        assert_ne!(
            full_hash, default_hash,
            "members P2SH (default branch) must differ from the full ERP P2SH",
        );
    }

    /// Mainnet #9,217,796 tx[1]: a federator submits a 71-byte "signature"
    /// beginning 0x9f, not a DER SEQUENCE. rskj's `Bridge.addSignature` runs
    /// every element through `BtcECKey.ECDSASignature.decodeFromDER` and throws
    /// on failure, which becomes an invisible exception: receipt SUCCESS, but
    /// the sender charged the full gas limit with no refund.
    ///
    /// rustock accepted it, reached the pegouts-waiting-for-signatures lookup,
    /// missed, returned quietly and refunded 104,512 gas the chain had charged
    /// -- diverging the state root by exactly that fee.
    #[test]
    fn mainnet_9217796_signature_is_not_der() {
        let sig = hex::decode(
            "9f2c0070c9e4c56639df9eb25efec97a1e4886a848f49a38fcdc970c7aec9274             821124693dc8ec5c699ddee0283c71331d86b5f61b6865182e0618dfb7bb52b2             65158d1987d0e1".replace([' ', '\n'], ""),
        )
        .unwrap();
        assert_eq!(sig.len(), 71, "the signature from the block is 71 bytes");
        assert!(!is_der_signature(&sig), "0x9f is not a DER SEQUENCE tag");
    }

    #[test]
    fn der_signature_accepts_a_real_signature() {
        // 0x30 len 0x02 r(32) 0x02 s(32)
        let mut sig = vec![0x30, 0x44, 0x02, 0x20];
        sig.extend_from_slice(&[0x11u8; 32]);
        sig.extend_from_slice(&[0x02, 0x20]);
        sig.extend_from_slice(&[0x22u8; 32]);
        assert!(is_der_signature(&sig));
    }

    #[test]
    fn der_signature_accepts_a_leading_zero_pad() {
        // r needs a 0x00 pad when its top bit is set: 33-byte integer.
        let mut sig = vec![0x30, 0x45, 0x02, 0x21, 0x00];
        sig.extend_from_slice(&[0xFFu8; 32]);
        sig.extend_from_slice(&[0x02, 0x20]);
        sig.extend_from_slice(&[0x22u8; 32]);
        assert!(is_der_signature(&sig));
    }

    #[test]
    fn der_signature_rejects_malformed_shapes() {
        assert!(!is_der_signature(&[]), "empty");
        assert!(!is_der_signature(&[0x30]), "tag only");
        assert!(!is_der_signature(&[0x31, 0x44]), "wrong tag");
        // sequence length runs past the buffer
        assert!(!is_der_signature(&[0x30, 0x44, 0x02, 0x20, 0x01]), "truncated");
        // second element is not an INTEGER
        let mut sig = vec![0x30, 0x44, 0x02, 0x20];
        sig.extend_from_slice(&[0x11u8; 32]);
        sig.extend_from_slice(&[0x03, 0x20]);
        sig.extend_from_slice(&[0x22u8; 32]);
        assert!(!is_der_signature(&sig), "second element must be INTEGER");
        // zero-length integer
        assert!(!is_der_signature(&[0x30, 0x04, 0x02, 0x00, 0x02, 0x00]), "empty integer");
    }

    /// A federation member's signature over the **wrong sighash** is not
    /// applied, and the call reports that by returning false rather than by
    /// failing.
    ///
    /// This is the premise the PowPeg signature audit rests on
    /// (`crates/cli/examples/powpeg_signature_audit.rs`), so it is pinned
    /// here rather than inferred from reading `processSigning`. The Bridge
    /// has **no event for a refused signature**: a malformed DER signature
    /// reverts, but a well-formed one over the wrong message simply applies
    /// nothing, and from RSKIP326 on the absence of `add_signature` is the
    /// only trace it leaves. If this test ever starts passing a bad
    /// signature, the audit's central discriminator is gone with it.
    #[test]
    fn a_member_signature_over_the_wrong_sighash_is_not_applied() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};

        let key_pair = |seed: u8| {
            let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
            let pk: [u8; 33] =
                sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
            (sk, pk)
        };
        let members: Vec<_> = (1u8..=3).map(key_pair).collect();
        let member_keys: Vec<[u8; 33]> = members.iter().map(|(_, pk)| *pk).collect();
        let redeem = build_federation_redeem_script(&member_keys, 2);

        let mut tx = BtcTransaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(
                    super::super::release_tx::placeholder_scriptsig(&redeem, 2),
                ),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let correct = super::super::release_tx::legacy_sighash_all(&tx, 0, &redeem);
        let wrong = [0x5au8; 32];
        assert_ne!(correct, wrong);

        let (sk, pk) = &members[0];
        let sig_over = |msg: &[u8; 32]| {
            let sig: Signature = sk.sign_prehash(msg).unwrap();
            sig.to_der().as_bytes().to_vec()
        };

        // Well formed DER, right key, right federation -- wrong message.
        let before = tx.input[0].script_sig.clone();
        assert!(
            !apply_signatures_to_tx(&mut tx, &[sig_over(&wrong)], pk, &[]),
            "a signature over the wrong sighash must not be applied"
        );
        assert_eq!(tx.input[0].script_sig, before, "nothing may be written");

        // The control: the same key over the right message does apply, so the
        // rejection above is about the message and not the setup.
        assert!(apply_signatures_to_tx(&mut tx, &[sig_over(&correct)], pk, &[]));
        assert_ne!(tx.input[0].script_sig, before);
    }

    /// Regression for mainnet #2,448,984: a federator whose key is NOT in an
    /// input's redeem script (a NEW-federation member signing the migration
    /// tx that spends the OLD federation's UTXOs) must not have its
    /// signature applied — rskj's getSigInsertionIndex/findKeyInRedeem
    /// throws and processSigning returns. The signature itself verifies
    /// against the federator's own key, so only redeem membership blocks it.
    #[test]
    fn add_signature_rejects_key_not_in_redeem_script() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};

        let key_pair = |seed: u8| {
            let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
            let pk: [u8; 33] = sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            (sk, pk)
        };
        let members: Vec<_> = (1u8..=3).map(key_pair).collect();
        let (outsider_sk, outsider_pk) = key_pair(9);
        let member_keys: Vec<[u8; 33]> = members.iter().map(|(_, pk)| *pk).collect();
        let redeem = build_federation_redeem_script(&member_keys, 2);

        let mut tx = BtcTransaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(
                    super::super::release_tx::placeholder_scriptsig(&redeem, 2),
                ),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let sighash = super::super::release_tx::legacy_sighash_all(&tx, 0, &redeem);
        let sign = |sk: &SigningKey| {
            let sig: Signature = sk.sign_prehash(&sighash).unwrap();
            sig.to_der().as_bytes().to_vec()
        };

        // Outsider: verifies against its own key but is not in the redeem.
        let before = tx.input[0].script_sig.clone();
        assert!(!apply_signatures_to_tx(&mut tx, &[sign(&outsider_sk)], &outsider_pk, &[]));
        assert_eq!(tx.input[0].script_sig, before, "script must be untouched");

        // Member: applied normally.
        assert!(apply_signatures_to_tx(&mut tx, &[sign(&members[0].0)], &members[0].1, &[]));
        assert_ne!(tx.input[0].script_sig, before);
    }

    /// Regression for mainnet #4,598,511 (just after Hop400 / RSKIP271 at
    /// #4,598,500): a state-root divergence caused by NOT advancing the
    /// Bridge's `nextPegoutHeight` storage cell when an updateCollections call
    /// runs with an empty release-request queue.
    ///
    /// rskj `BridgeSupport.processPegoutsInBatch` (BridgeSupport.java:1554-1559)
    /// sets `nextPegoutHeight = currentBlock + numberOfBlocksBetweenPegouts`
    /// whenever the queue ends up empty — *including* when it was empty to begin
    /// with — as long as `currentBlock >= nextPegoutHeight` (the gate at
    /// line 1501). At Hop400 the cell is unset (0), so the gate is open and the
    /// very first updateCollections after activation writes the cell, mutating
    /// Bridge storage and thus the state root.
    ///
    /// Ground truth: mainnet `numberOfBlocksBetweenPegouts = 360`
    /// (BridgeMainNetConstants.java:45), so block #4,598,511 advances the height
    /// to 4,598,871.
    #[test]
    fn rskip271_next_pegout_height_formula_mainnet() {
        let cfg = crate::RskHardforkConfig::mainnet();
        let constants = BridgeConstants::mainnet();
        assert_eq!(constants.number_of_blocks_between_pegouts, 360);

        // RSKIP271 active at Hop400 (#4,598,500) and onward.
        assert!(cfg.has_rskip271(4_598_500));
        assert!(cfg.has_rskip271(4_598_511));
        assert!(!cfg.has_rskip271(4_598_499));

        // The gate: a freshly-activated chain has nextPegoutHeight = 0, so any
        // post-activation block satisfies `block >= nextPegoutHeight` and the
        // empty-queue tail must advance the height.
        let block_number = 4_598_511u64;
        let next_height = block_number + constants.number_of_blocks_between_pegouts;
        assert_eq!(next_height, 4_598_871);
    }

    #[test]
    fn satoshi_to_wei_conversion() {
        assert_eq!(btc_satoshi_to_rbtc_wei(1), U256::from(10_000_000_000u64));
        assert_eq!(
            btc_satoshi_to_rbtc_wei(100_000_000),
            U256::from(10u128).pow(U256::from(18))
        );
    }

    #[test]
    fn satoshi_to_wei_zero() {
        assert_eq!(btc_satoshi_to_rbtc_wei(0), U256::ZERO);
    }

    // -----------------------------------------------------------------------
    // Release queue serialization tests — ported from rskj
    // BridgeSerializationUtils / BridgeSupportReleaseBtcTest patterns
    // -----------------------------------------------------------------------

    fn make_request(hash160: [u8; 20], satoshis: u64) -> ReleaseRequest {
        ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: satoshis, rsk_tx_hash: None }
    }

    fn make_request_with_hash(hash160: [u8; 20], satoshis: u64, rsk_hash: [u8; 32]) -> ReleaseRequest {
        ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: satoshis, rsk_tx_hash: Some(rsk_hash) }
    }

    /// Legacy queue: empty roundtrip.
    #[test]
    fn rskj_release_queue_empty_roundtrip() {
        let queue: Vec<ReleaseRequest> = vec![];
        let encoded = serialize_release_queue_legacy(&queue);
        let decoded = deserialize_release_queue_legacy(&encoded);
        assert!(decoded.is_empty());
    }

    /// Legacy queue: single entry roundtrip.
    #[test]
    fn rskj_release_queue_single_entry_roundtrip() {
        let hash160 = [0xAAu8; 20];
        let amount = 250_000u64;
        let queue = vec![make_request(hash160, amount)];

        let encoded = serialize_release_queue_legacy(&queue);
        let decoded = deserialize_release_queue_legacy(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].btc_dest_hash160, hash160);
        assert_eq!(decoded[0].amount_satoshis, amount);
    }

    /// Legacy queue: multiple entries preserves order.
    #[test]
    fn rskj_release_queue_multiple_entries_roundtrip() {
        let entries = vec![
            make_request([0x11u8; 20], 400_000),
            make_request([0x22u8; 20], 800_000),
            make_request([0x33u8; 20], 1_200_000),
        ];

        let encoded = serialize_release_queue_legacy(&entries);
        let decoded = deserialize_release_queue_legacy(&encoded);

        assert_eq!(decoded.len(), 3);
        for (orig, dec) in entries.iter().zip(decoded.iter()) {
            assert_eq!(orig.btc_dest_hash160, dec.btc_dest_hash160);
            assert_eq!(orig.amount_satoshis, dec.amount_satoshis);
        }
    }

    /// Legacy queue: empty data returns empty vec.
    #[test]
    fn rskj_release_queue_deserialize_empty() {
        assert!(deserialize_release_queue_legacy(&[]).is_empty());
    }

    /// Post-RSKIP146 queue with tx hash: roundtrip.
    #[test]
    fn rskj_release_queue_with_hash_roundtrip() {
        let hash160 = [0xBBu8; 20];
        let rsk_hash = [0xCCu8; 32];
        let entries = vec![make_request_with_hash(hash160, 500_000, rsk_hash)];

        let encoded = serialize_release_queue_with_hash(&entries);
        let decoded = deserialize_release_queue_with_hash(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].btc_dest_hash160, hash160);
        assert_eq!(decoded[0].amount_satoshis, 500_000);
        assert_eq!(decoded[0].rsk_tx_hash, Some(rsk_hash));
    }

    /// rskTxsWaitingFS: empty roundtrip.
    #[test]
    fn rskj_rsk_txs_waiting_fs_empty_roundtrip() {
        let map = BTreeMap::new();
        let encoded = serialize_rsk_txs_waiting_for_signatures(&map);
        let decoded = deserialize_rsk_txs_waiting_for_signatures(&encoded);
        assert!(decoded.is_empty());
    }

    /// rskTxsWaitingFS: single entry roundtrip with sorted ordering.
    #[test]
    fn rskj_rsk_txs_waiting_fs_roundtrip() {
        let mut map = BTreeMap::new();
        let hash1 = [0x11u8; 32];
        let hash2 = [0xAAu8; 32];
        let btc1 = vec![0x01, 0x02, 0x03];
        let btc2 = vec![0x04, 0x05, 0x06];
        map.insert(hash2, btc2.clone());
        map.insert(hash1, btc1.clone());

        let encoded = serialize_rsk_txs_waiting_for_signatures(&map);
        let decoded = deserialize_rsk_txs_waiting_for_signatures(&encoded);

        assert_eq!(decoded.len(), 2);
        // BTreeMap ensures sorted order: hash1 (0x11...) < hash2 (0xAA...)
        assert_eq!(decoded[&hash1], btc1);
        assert_eq!(decoded[&hash2], btc2);
    }

    /// Byte-exact ground truth: the mainnet `releaseTransactionSetWithTxHash`
    /// cell at #2,421,462 (one pegout created by updateCollections), dumped
    /// from a synced rskj unitrie. rskj splits the ONE in-memory set across
    /// the legacy cell (hash-less entries, pairs) and the with-txhash cell
    /// (hash-bearing entries, triples); this entry carries the requesting RSK
    /// tx hash and lives ONLY in the with-txhash cell (legacy stays 0xc0).
    #[test]
    fn rskj_pegout_set_with_txhash_groundtruth_2421462() {
        use alloy_primitives::hex;
        let rskj = hex::decode(
            "f901ddb901b5010000000105fa7bc00829cc15870c0bab2fb67c4d0e8dcfb08cb926148c9fbc0eb159252001000000fd3e01\
             0000000000004d35015521027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c81715\
             0f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2102a9c6848e302193179ce6479516c2d97f6967e136\
             5c707e3b9d3e0cb683ccb8222103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93210372cd\
             46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33\
             ae751e248ae60094cc989fb880f62103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103\
             b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c45732103ecd8af1e93c57a1b8c7f917bd9980af7\
             98adeb0205e9687865673353eb041e8d59aeffffffff02026b1000000000001976a914410deef0190ff5ef7bb4da984c804b\
             fe12a843c888ac20c375470000000017a914279d4b44e8cf5e3f04c0ea21c78f1a0ecaa4cd9f87000000008324f2d6a08036\
             e82984f100a1213c8ac65fb620aa65dab57ddaba3577b55bd81d0a40234a",
        )
        .unwrap();
        let decoded = deserialize_pegouts_waiting_for_confirmations(&rskj, true);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rsk_block_height, 2_421_462);
        assert_eq!(
            hex::encode(decoded[0].rsk_tx_hash.unwrap()),
            "8036e82984f100a1213c8ac65fb620aa65dab57ddaba3577b55bd81d0a40234a"
        );
        assert_eq!(serialize_pegouts_waiting_for_confirmations(&decoded, true), rskj);
        // The same entries serialized for the LEGACY cell must exclude the
        // hash-bearing entry entirely (rskj getEntriesWithoutHash) — that
        // cell stays an empty list.
        let hashless: Vec<PegoutWaitingForConfirmations> = decoded
            .iter()
            .filter(|e| e.rsk_tx_hash.is_none())
            .cloned()
            .collect();
        assert_eq!(serialize_pegouts_waiting_for_confirmations(&hashless, false), vec![0xc0]);
    }

    /// PegoutsWaitingForConfirmations: legacy pair format roundtrip.
    #[test]
    fn rskj_pegouts_waiting_for_confirmations_legacy_roundtrip() {
        let entries = vec![
            PegoutWaitingForConfirmations { btc_tx_raw: vec![0xDE, 0xAD], rsk_block_height: 1000, rsk_tx_hash: None },
            PegoutWaitingForConfirmations { btc_tx_raw: vec![0xBE, 0xEF], rsk_block_height: 2000, rsk_tx_hash: None },
        ];

        let encoded = serialize_pegouts_waiting_for_confirmations(&entries, false);
        let decoded = deserialize_pegouts_waiting_for_confirmations(&encoded, false);

        assert_eq!(decoded.len(), 2);
        // rskj sorts entries by serialized BTC tx bytes (BTC_TX_COMPARATOR):
        // 0xBEEF < 0xDEAD.
        assert_eq!(decoded[0].btc_tx_raw, vec![0xBE, 0xEF]);
        assert_eq!(decoded[0].rsk_block_height, 2000);
        assert_eq!(decoded[1].btc_tx_raw, vec![0xDE, 0xAD]);
        assert_eq!(decoded[1].rsk_block_height, 1000);
    }

    /// PegoutsWaitingForConfirmations: RSKIP146 triple format roundtrip.
    #[test]
    fn rskj_pegouts_waiting_for_confirmations_with_hash_roundtrip() {
        let rsk_hash = [0xFFu8; 32];
        let entries = vec![
            PegoutWaitingForConfirmations {
                btc_tx_raw: vec![0x01, 0x02],
                rsk_block_height: 5000,
                rsk_tx_hash: Some(rsk_hash),
            },
        ];

        let encoded = serialize_pegouts_waiting_for_confirmations(&entries, true);
        let decoded = deserialize_pegouts_waiting_for_confirmations(&encoded, true);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].btc_tx_raw, vec![0x01, 0x02]);
        assert_eq!(decoded[0].rsk_block_height, 5000);
        assert_eq!(decoded[0].rsk_tx_hash, Some(rsk_hash));
    }

    /// Federation redeem script: correct multisig format.
    #[test]
    fn rskj_federation_redeem_script_format() {
        let keys: Vec<[u8; 33]> = vec![
            [0x02; 33],
            [0x03; 33],
            [0x04; 33],
        ];
        let threshold = 2;
        let script = build_federation_redeem_script(&keys, threshold);

        // OP_2 + 3 keys (each: 0x21 + 33 bytes) + OP_3 + OP_CHECKMULTISIG
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[script.len() - 2], 0x53); // OP_3
        assert_eq!(script[script.len() - 1], 0xAE); // OP_CHECKMULTISIG
        assert_eq!(script.len(), 1 + 3 * 34 + 2);
    }

    /// Redeem script hash160.
    #[test]
    fn rskj_redeem_script_hash160_non_zero() {
        let keys: Vec<[u8; 33]> = vec![[0x02; 33], [0x03; 33]];
        let script = build_federation_redeem_script(&keys, 1);
        let hash = redeem_script_hash160(&script);
        assert_ne!(hash, [0u8; 20], "hash160 should not be zero");
    }

    fn key(hex: &str) -> [u8; 33] {
        alloy_primitives::hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn p2sh_base58_mainnet(redeem: &[u8]) -> String {
        let mut payload = [0u8; 21];
        payload[0] = 5; // mainnet P2SH version
        payload[1..].copy_from_slice(&redeem_script_hash160(redeem));
        bitcoin::base58::encode_check(&payload)
    }

    /// rskj `Utils.signedLongToByteArrayLE`: 52560 -> `50 cd 00` (sign byte
    /// preserved, NOT BIP68-minimal). Consensus-critical CSV-delay encoding.
    #[test]
    fn erp_csv_delay_encoding_groundtruth() {
        assert_eq!(signed_long_to_byte_array_le(52560), vec![0x50, 0xcd, 0x00]);
        assert_eq!(signed_long_to_byte_array_le(500), vec![0xf4, 0x01]);
        assert_eq!(signed_long_to_byte_array_le(1), vec![0x01]);
    }

    /// Ground truth: the first real RSK mainnet federation change committed at
    /// block #4,652,781 produced a NON-STANDARD ERP federation (RSKIP201 active,
    /// RSKIP353 not). Its base58 P2SH address appears in the block's
    /// commit_federation event (header receipts root
    /// 0x883ea305...). New federation 5-of-9 default keys + the 4 mainnet
    /// emergency keys, CSV 52560.
    #[test]
    fn nonstandard_erp_federation_address_mainnet_4652781() {
        let new_keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        ]
        .map(key);
        let erp_keys = BridgeConstants::mainnet()
            .erp_fed_pubkeys
            .iter()
            .map(|h| key(h))
            .collect::<Vec<_>>();
        // NonStandard ERP (p2sh = false): default 5-of-9, emergency 3-of-4.
        let redeem = build_erp_redeem_script(&new_keys, 5, &erp_keys, 3, 52560, false);
        assert_eq!(p2sh_base58_mainnet(&redeem), "3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh");
    }

    /// Ground truth ported from rskj P2shErpFederationTest
    /// `createdFederationInfo_withRealValues_equalsExistingFederationInfo_mainnet`:
    /// P2SH-ERP federation (RSKIP353 active) for a real mainnet fed →
    /// program `a9142c1bab6ea51fdaf85c8366bd2b1502eaa69b6ae687`, address
    /// `35iEoWHfDfEXRQ5ZWM5F6eMsY2Uxrc64YK`.
    #[test]
    fn p2sh_erp_federation_address_rskj_fixture() {
        let default_keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c949",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b35888771906",
        ]
        .map(key);
        let erp_keys = BridgeConstants::mainnet()
            .erp_fed_pubkeys
            .iter()
            .map(|h| key(h))
            .collect::<Vec<_>>();
        let redeem = build_erp_redeem_script(&default_keys, 5, &erp_keys, 3, 52560, true);
        assert_eq!(
            alloy_primitives::hex::encode(p2sh_output_script(&redeem_script_hash160(&redeem)).as_bytes()),
            "a9142c1bab6ea51fdaf85c8366bd2b1502eaa69b6ae687"
        );
        assert_eq!(p2sh_base58_mainnet(&redeem), "35iEoWHfDfEXRQ5ZWM5F6eMsY2Uxrc64YK");
    }

    /// Ground truth for `federation_redeem_for_format` — the dispatch that fixes
    /// the #4,677,229 divergence. A live federation's redeem script must follow
    /// its STORED format version, not the current block. At #4,677,229 the active
    /// federation is the format-2000 (NON_STANDARD_ERP) fed and the retiring one
    /// is format-1000 (STANDARD_MULTISIG); a `registerBtcTransaction` migration tx
    /// pays the active fed's P2SH (3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh), and the
    /// change UTXO is only registered if that script is reconstructed correctly.
    #[test]
    fn federation_redeem_for_format_groundtruth() {
        // The real format-2000 ERP federation active at #4,677,229 (== the fed
        // committed at #4,652,781), 5-of-9 default keys.
        let active_keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        ]
        .map(key);
        let config = BridgeConstants::mainnet();

        // format 2000 (NON_STANDARD_ERP) → the active fed's real mainnet P2SH.
        let r2000 = federation_redeem_for_format(&active_keys, 2000, &config);
        assert_eq!(
            p2sh_base58_mainnet(&r2000),
            "3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh",
            "format 2000 must build the non-standard ERP redeem script"
        );

        // format 1000 (STANDARD_MULTISIG) → plain N-of-M, a DIFFERENT address.
        let r1000 = federation_redeem_for_format(&active_keys, 1000, &config);
        assert_eq!(
            r1000,
            build_federation_redeem_script(&active_keys, active_keys.len() / 2 + 1),
            "format 1000 must build a plain multisig redeem script"
        );
        assert_ne!(
            p2sh_base58_mainnet(&r1000),
            "3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh",
            "the standard multisig must NOT collide with the ERP address"
        );

        // format 3000 (P2SH_ERP) → the P2SH-ERP template (p2sh=true), distinct
        // from the non-standard ERP form.
        let r3000 = federation_redeem_for_format(&active_keys, 3000, &config);
        assert_ne!(r3000, r2000, "P2SH-ERP and non-standard ERP differ");
    }

    // -----------------------------------------------------------------------
    // Golden vector tests — format verification against rskj
    // Ported from BridgeSerializationUtilsTest.java
    // -----------------------------------------------------------------------

    /// rskTxsWaitingFS: two entries with createHash3(1) and createHash3(2) keys
    /// are stored in BTreeMap order (hash1 < hash2 since 0x01 < 0x02).
    ///
    /// Matches rskj BridgeSerializationUtilsTest.serializeAndDeserializeRskTxsWaitingForSignatures.
    #[test]
    fn rskj_rsk_txs_waiting_fs_ordering_golden() {
        // createHash3(1) = [0x01, 0x00, ..., 0x00]
        let mut hash1 = [0u8; 32];
        hash1[0] = 0x01;

        // createHash3(2) = [0x02, 0x00, ..., 0x00]
        let mut hash2 = [0u8; 32];
        hash2[0] = 0x02;

        // Minimal BTC tx bytes (insert in reverse order to confirm sorting)
        let btc1 = vec![0x01, 0x00, 0x00, 0x00]; // version=1 LE, minimal
        let btc2 = vec![0x02, 0x00, 0x00, 0x00];

        let mut map = BTreeMap::new();
        map.insert(hash2, btc2.clone()); // insert hash2 first
        map.insert(hash1, btc1.clone());

        let encoded = serialize_rsk_txs_waiting_for_signatures(&map);
        let decoded = deserialize_rsk_txs_waiting_for_signatures(&encoded);

        assert_eq!(decoded.len(), 2);
        // Keys should be sorted: hash1 (0x01...) < hash2 (0x02...)
        let keys: Vec<[u8; 32]> = decoded.keys().cloned().collect();
        assert_eq!(keys[0], hash1, "hash1 should come first (BTreeMap sorted)");
        assert_eq!(keys[1], hash2, "hash2 should come second");
        assert_eq!(decoded[&hash1], btc1);
        assert_eq!(decoded[&hash2], btc2);

        // Verify the RLP structure: outer list with 4 elements (2 pairs)
        let items = rlp_decode_list(&encoded).unwrap();
        assert_eq!(items.len(), 4, "should have 4 RLP items (2 hash-tx pairs)");
        assert_eq!(items[0].len(), 32);
        assert_eq!(items[0][0], 0x01, "first item should be hash1");
        assert_eq!(items[2][0], 0x02, "third item should be hash2");
    }

    /// rskj `getNextPegoutWithEnoughConfirmations` selects the first confirmed
    /// entry in Java `HashSet` iteration order — not storage (btc-tx-sorted)
    /// order. Groundtruth from RSK Mainnet block #3,345,557 (migration window):
    /// two pegout entries share creation height 3,341,556 and both confirm at
    /// this block (min 4000 confirmations), so the tie is broken purely by
    /// HashSet bucket order. rskj moved the `a7c69a46…` input tx
    /// (pegoutCreationRskTxHash `26dc74c8…`) into pegoutsWaitingForSignatures,
    /// leaving the lexicographically-smaller `0260d432…` tx in the set. A naive
    /// btc-tx-sorted selection would pick the wrong one and fork the chain.
    #[test]
    fn rskj_next_pegout_hashset_iteration_order_groundtruth() {
        // The two real h=3,341,556 entries from the diverging cell at #3,345,557.
        // rskj-selected (moved to WFS): btc spends input a7c69a46…:1.
        let selected_btc = hex::decode(
            "010000000122fab61f4bdfe74f41dfecbe2a52d0cb5aa42c898687c6142d3f8497469ac6a701000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff029a686c09000000001976a914fb53759d716de10362f5b57d28151a6481fd30e188ace354f1f00c00000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        // rskj-kept (NOT selected): btc spends input 0260d432…:1, smaller bytes.
        let kept_btc = hex::decode(
            "01000000010260d43256d4072e46f87acec7e3225752beff0fcb60288baf5088f5d5e9949401000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff02a69bbc06000000001976a9140b9c738761bb47eba3802df6ac169717aa85b6f088ac104bd32d0100000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();

        let mk = |btc: &[u8], h: u64| PegoutWaitingForConfirmations {
            btc_tx_raw: btc.to_vec(),
            rsk_block_height: h,
            rsk_tx_hash: Some([0u8; 32]),
        };

        // 13 entries (the real cell size at #3,345,557) so the HashSet capacity
        // is 32. The 11 fillers carry height 3,345,000 (only 557 confirmations
        // at block 3,345,557) so they never confirm and the tie is decided by
        // the two real entries' buckets: a7c69a46→9, 0260d432→20.
        let mut entries = vec![mk(&kept_btc, 3_341_556), mk(&selected_btc, 3_341_556)];
        for i in 0..11u8 {
            entries.push(mk(&[1, 0, 0, 0, i], 3_345_000));
        }

        let pos = next_pegout_with_enough_confirmations(&entries, 3_345_557, 4000)
            .expect("one confirmed entry");
        assert_eq!(
            entries[pos].btc_tx_raw, selected_btc,
            "must promote the a7c69a46… tx (HashSet bucket 9) like rskj, not the \
             lexicographically-smaller 0260d432… tx (bucket 20)"
        );
    }

    /// rskj caches the pegouts-waiting-for-confirmations set as
    /// `new PegoutsWaitingForConfirmations(entries)` →
    /// `this.entries = new HashSet<>(entries)`, the `HashSet(Collection)`
    /// constructor, which PRE-SIZES the table to
    /// `tableSizeFor(max((int)(n / 0.75f) + 1, 16))` (next power of two). This is
    /// one doubling LARGER than an incremental default-16 fill of the same `n` at
    /// the boundaries: a 12-entry set has capacity 32 (incremental fill would
    /// stay at 16); a 24-entry set has capacity 64, not 32. Getting the capacity
    /// wrong reshuffles the bucket walk and forks the pegout selection
    /// (mainnet #3,344,303).
    #[test]
    fn java_hashset_capacity_resize_boundaries() {
        // n=0,1: max((int)(n/0.75)+1, 16) = 16 → 16.
        assert_eq!(java_hashset_capacity(0), 16);
        assert_eq!(java_hashset_capacity(1), 16);
        // n=11: (int)(11/0.75)+1 = 15 → 16. n=12: (int)(12/0.75)+1 = 17 → 32.
        assert_eq!(java_hashset_capacity(11), 16);
        assert_eq!(java_hashset_capacity(12), 32);
        assert_eq!(java_hashset_capacity(13), 32);
        // n=23: (int)(23/0.75)+1 = 31 → 32. n=24: (int)(24/0.75)+1 = 33 → 64.
        assert_eq!(java_hashset_capacity(23), 32);
        assert_eq!(java_hashset_capacity(24), 64);
        assert_eq!(java_hashset_capacity(25), 64);
        // n=47: (int)(47/0.75)+1 = 63 → 64. n=48: (int)(48/0.75)+1 = 65 → 128.
        assert_eq!(java_hashset_capacity(47), 64);
        assert_eq!(java_hashset_capacity(48), 128);
    }

    /// Resize-boundary selection: with the two real h=3,341,556 entries plus
    /// fillers totalling exactly 13 entries the capacity is 32 (a7c69a46→bucket 9,
    /// 0260d432→bucket 20), so the a7c69a46 tx is selected — the #3,345,557
    /// groundtruth. The `HashSet(Collection)` pre-size formula gives 32 at n=13
    /// (`max((int)(13/0.75)+1, 16) = 18 → 32`); this guards that selection.
    #[test]
    fn pegout_selection_at_16_to_32_resize_boundary() {
        let selected_btc = hex::decode(
            "010000000122fab61f4bdfe74f41dfecbe2a52d0cb5aa42c898687c6142d3f8497469ac6a701000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff029a686c09000000001976a914fb53759d716de10362f5b57d28151a6481fd30e188ace354f1f00c00000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        let kept_btc = hex::decode(
            "01000000010260d43256d4072e46f87acec7e3225752beff0fcb60288baf5088f5d5e9949401000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff02a69bbc06000000001976a9140b9c738761bb47eba3802df6ac169717aa85b6f088ac104bd32d0100000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        let mk = |btc: &[u8], h: u64| PegoutWaitingForConfirmations {
            btc_tx_raw: btc.to_vec(),
            rsk_block_height: h,
            rsk_tx_hash: Some([0u8; 32]),
        };
        let mut entries = vec![mk(&kept_btc, 3_341_556), mk(&selected_btc, 3_341_556)];
        for i in 0..11u8 {
            entries.push(mk(&[1, 0, 0, 0, i], 3_345_000));
        }
        assert_eq!(entries.len(), 13);
        assert_eq!(java_hashset_capacity(entries.len()), 32);
        let pos = next_pegout_with_enough_confirmations(&entries, 3_345_557, 4000)
            .expect("one confirmed entry");
        assert_eq!(entries[pos].btc_tx_raw, selected_btc);
    }

    /// Mainnet #3,344,303 regression: the confirmations set holds exactly 12
    /// entries, of which the only two with >= 4000 confirmations are the two
    /// h=3,340,302 pegouts below. `getNextPegoutWithEnoughConfirmations` iterates
    /// the cached set — built by `new PegoutsWaitingForConfirmations(entries)` =
    /// `new HashSet<>(entries)`, which PRE-SIZES the table to 32 for n=12. At
    /// capacity 32 the `20806d…` tx (bucket 15) precedes `415c14…` (bucket 21),
    /// so rskj promotes `20806d…`. The previous incremental model gave capacity
    /// 16, where `415c14…` (bucket 5) precedes `20806d…` (bucket 15) and the
    /// wrong entry was promoted — forking both the confirmations set and the
    /// signatures-waiting map (computed state root 0x62047bea… vs header
    /// 0x0d4bed56…).
    #[test]
    fn pegout_selection_n12_presize_picks_rskj_entry() {
        // rskj-promoted (txid 20806dad…c376edb9), recipient fb53759d…
        let rskj_btc = hex::decode(
            "010000000158fc2de209f41b6faa714856b621aec5b268369804046269e017fc7107ead5ca01000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff02c2f2aa09000000001976a914fb53759d716de10362f5b57d28151a6481fd30e188ac132c42980000000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        // the wrong entry the cap-16 model would promote (txid 415c14…, recipient 9fc53016…)
        let wrong_btc = hex::decode(
            "0100000001961576fed5c343511f011b32e11681b90ab0df1e33fde103913698476fd8ddca01000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff027e0c3012000000001976a9149fc530162154c490cb5ca484b8ad883d0bf18a1788ac48e38d410100000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        let mk = |btc: &[u8], h: u64| PegoutWaitingForConfirmations {
            btc_tx_raw: btc.to_vec(),
            rsk_block_height: h,
            rsk_tx_hash: Some([0u8; 32]),
        };
        // 12 entries: the two confirmed h=3,340,302 pegouts + 10 not-yet-confirmed
        // fillers (height too recent for 4000 confirmations at #3,344,303).
        let mut entries = vec![mk(&wrong_btc, 3_340_302), mk(&rskj_btc, 3_340_302)];
        for i in 0..10u8 {
            entries.push(mk(&[1, 0, 0, 0, i], 3_344_000));
        }
        assert_eq!(entries.len(), 12);
        // n=12 → the HashSet(Collection) constructor pre-sizes to 32.
        assert_eq!(java_hashset_capacity(12), 32);
        let pos = next_pegout_with_enough_confirmations(&entries, 3_344_303, 4000)
            .expect("a confirmed entry");
        assert_eq!(
            entries[pos].btc_tx_raw, rskj_btc,
            "must promote the rskj-selected pegout (20806d…), not 415c14…"
        );
    }

    /// Empty rskTxsWaitingFS: empty data → empty map (matches rskj behavior).
    ///
    /// Ported from rskj: deserializeRskTxsWaitingForSignatures with null/empty → empty map.
    #[test]
    fn rskj_rsk_txs_waiting_fs_null_empty_returns_empty() {
        let decoded_null = deserialize_rsk_txs_waiting_for_signatures(&[]);
        assert!(decoded_null.is_empty(), "null data should return empty map");

        // Empty RLP list → empty map
        let empty_rlp = vec![0xc0u8]; // RLP encoded empty list
        let decoded_empty = deserialize_rsk_txs_waiting_for_signatures(&empty_rlp);
        assert!(decoded_empty.is_empty(), "empty list should return empty map");
    }

    /// Release queue legacy format: amount is stored as RLP-encoded BigInteger
    /// (satoshis), not as Wei.
    ///
    /// Verifies that 400_000 satoshis is stored correctly (not as Wei amount).
    #[test]
    fn rskj_release_queue_stores_satoshis_not_wei() {
        let hash160 = [0x42u8; 20];
        let satoshis = 400_000u64; // minimum pegout value
        let entries = vec![make_request(hash160, satoshis)];
        let encoded = serialize_release_queue_legacy(&entries);

        let decoded = deserialize_release_queue_legacy(&encoded);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].amount_satoshis, satoshis,
            "amount should be in satoshis, not wei");
        // Verify: 400_000 in satoshis should NOT equal 400_000 * 10^10 (wei)
        assert_ne!(decoded[0].amount_satoshis, 400_000 * 10_000_000_000u64,
            "amount must NOT be in wei");
    }

    /// Release queue with hash: RSK tx hash is stored as 32 bytes in the third slot.
    #[test]
    fn rskj_release_queue_with_hash_format_verified() {
        let hash160 = [0x11u8; 20];
        let satoshis = 500_000u64;
        // createHash3(1) from rskj test patterns
        let mut rsk_hash = [0u8; 32];
        rsk_hash[0] = 0x01;

        let entries = vec![make_request_with_hash(hash160, satoshis, rsk_hash)];
        let encoded = serialize_release_queue_with_hash(&entries);

        let items = rlp_decode_list(&encoded).unwrap();
        assert_eq!(items.len(), 3, "post-RSKIP146 entry should have 3 items");
        assert_eq!(items[0], hash160.as_slice(), "first item is hash160");
        assert_eq!(items[2].len(), 32, "third item is RSK tx hash (32 bytes)");
        assert_eq!(items[2][0], 0x01, "RSK hash matches createHash3(1)");
    }

    /// Mainnet #267,460: a peg-in from an UNCOMPRESSED-pubkey sender credits
    /// the RSK address of the uncompressed point (ethereumj ECKey.getAddress).
    /// Our 33-byte-only parser missed it, leaving the recipient at balance 0
    /// until their first spend failed at #400,982.
    #[test]
    fn rskj_pegin_destination_from_uncompressed_pubkey() {
        let pubkey = alloy_primitives::hex::decode(
            "04869eeeb358fa4e76da63b1596a38305bdc1007b981b6d5c59f54156678280cc6120605a7c8492adb33ab50f529162c9554f5f9491faba644719517e36d12d64c",
        )
        .unwrap();
        let addr = crate::bridge::federation::rsk_address_from_public_key(&pubkey).unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(addr),
            "95bf476114e3241b808e81144228fe833fd38887"
        );

        // And through the scriptSig parser: <72-byte sig> <65-byte pubkey>.
        let mut script = vec![71u8];
        script.extend_from_slice(&[0x30; 71]);
        script.push(65);
        script.extend_from_slice(&pubkey);
        let tx = BtcTransaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: Default::default(),
                script_sig: bitcoin::ScriptBuf::from_bytes(script),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        match classify_pegin_sender(&tx).unwrap() {
            Some(PeginSender::P2pkh { pubkey: parsed }) => assert_eq!(parsed, pubkey),
            other => panic!("expected P2PKH sender, got {}", other.is_some()),
        }
    }

    // NOTE: truncated doc -- "rskj BtcLockSenderProvider: a P2SH-multisig first
    // input (OP_0, signatures, multisig redeem) classifies as P2SHMULTISIG with
    // the ..." was cut off here; see the filed issue.
    // --- peg-in sender classification -------------------------------------
    //
    // Translated from rskj's four BtcLockSender test classes:
    //   P2pkhBtcLockSenderTest, P2shMultisigBtcLockSenderTest,
    //   P2shP2wpkhBtcLockSenderTest, P2shP2wshBtcLockSenderTest
    //
    // Each of those asserts that its parser accepts its own shape and
    // *rejects the other three*. rustock has one classifier instead of four
    // parsers, so the same guarantee is one matrix: every shape must land on
    // its own variant and no other. This is security-relevant rather than
    // cosmetic -- the classification picks the address a rejected peg-in is
    // refunded to, so a shape decoded as the wrong type sends someone else's
    // bitcoin somewhere they do not control.

    /// A valid-shape compressed key that differs per index. Shape only: the
    /// x-coordinate is not a curve point, which is all the multisig redeem
    /// parser looks at.
    fn test_pubkey(i: u8) -> [u8; 33] {
        let mut k = [0x02u8; 33];
        k[32] = i;
        k
    }

    /// A real secp256k1 point (the generator G), for the branches that decode
    /// the key rather than just measuring it.
    fn real_pubkey() -> [u8; 33] {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        k[1..].copy_from_slice(&[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95,
            0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
            0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        ]);
        k
    }

    fn multisig_redeem() -> Vec<u8> {
        let mut redeem = vec![0x52]; // OP_2
        for i in 0..3u8 {
            redeem.push(33);
            redeem.extend_from_slice(&test_pubkey(i));
        }
        redeem.push(0x53); // OP_3
        redeem.push(0xae); // OP_CHECKMULTISIG
        redeem
    }

    fn tx_with(script_sig: Vec<u8>, witness_items: Vec<Vec<u8>>) -> BtcTransaction {
        let mut witness = bitcoin::Witness::new();
        for item in &witness_items {
            witness.push(item);
        }
        BtcTransaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: Default::default(),
                script_sig: bitcoin::ScriptBuf::from_bytes(script_sig),
                sequence: bitcoin::Sequence::MAX,
                witness,
            }],
            output: vec![],
        }
    }

    /// scriptSig = [sig, pubkey]
    fn p2pkh_tx() -> BtcTransaction {
        let mut script = vec![71];
        script.extend_from_slice(&[0x30; 71]);
        script.push(33);
        script.extend_from_slice(&real_pubkey());
        tx_with(script, vec![])
    }

    /// scriptSig = [redeem-push], witness = [sig, compressed pubkey]
    fn p2sh_p2wpkh_tx() -> BtcTransaction {
        // The redeem is the 22-byte witness program 0x0014 || hash160(pubkey),
        // pushed as the single scriptSig chunk.
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&pubkey_hash160(&real_pubkey()));
        let mut script = vec![redeem.len() as u8];
        script.extend_from_slice(&redeem);
        tx_with(script, vec![vec![0x30; 71], real_pubkey().to_vec()])
    }

    /// scriptSig = [sig, sig, redeem]
    fn p2sh_multisig_tx() -> BtcTransaction {
        let redeem = multisig_redeem();
        let mut script = vec![0x00, 71];
        script.extend_from_slice(&[0x30; 71]);
        script.push(71);
        script.extend_from_slice(&[0x30; 71]);
        script.push(0x4c);
        script.push(redeem.len() as u8);
        script.extend_from_slice(&redeem);
        tx_with(script, vec![])
    }

    /// scriptSig = [redeem-push], witness = [empty, sig, sig, redeem]
    fn p2sh_p2wsh_tx() -> BtcTransaction {
        use sha2::Digest;
        let redeem = multisig_redeem();
        // The scriptSig chunk is the 34-byte witness program
        // 0x0020 || sha256(redeem).
        let mut program = vec![0x00, 0x20];
        program.extend_from_slice(&sha2::Sha256::digest(&redeem));
        let mut script = vec![program.len() as u8];
        script.extend_from_slice(&program);
        tx_with(script, vec![vec![], vec![0x30; 71], vec![0x30; 71], redeem])
    }
    // --- refund targets ---------------------------------------------------

    /// Where a rejected peg-in's bitcoin goes, per sender shape. rskj derives
    /// this inside each BtcLockSender implementation: P2PKH refunds to
    /// hash160(pubkey) as a P2PKH address, and all three P2SH shapes refund to
    /// their script hash as a P2SH address. Getting the *flag* wrong is as bad
    /// as getting the hash wrong -- the same 20 bytes encode to a different
    /// address under a different version byte, so the refund is spendable by
    /// nobody.
    #[test]
    fn sender_refund_target_distinguishes_p2pkh_from_the_p2sh_shapes() {
        let pubkey = real_pubkey().to_vec();
        let (hash, is_p2sh) = sender_refund_target(&PeginSender::P2pkh { pubkey: pubkey.clone() });
        assert_eq!(hash, pubkey_hash160(&pubkey), "P2PKH refunds to hash160(pubkey)");
        assert!(!is_p2sh, "P2PKH is not a P2SH address");

        let marker = [0xABu8; 20];
        for sender in [
            PeginSender::P2shP2wpkh { pubkey, p2sh_hash: marker },
            PeginSender::P2shMultisig { p2sh_hash: marker },
            PeginSender::P2shP2wsh { p2sh_hash: marker },
        ] {
            let (hash, is_p2sh) = sender_refund_target(&sender);
            assert_eq!(hash, marker, "a P2SH shape refunds to its script hash");
            assert!(is_p2sh, "a P2SH shape must be flagged P2SH");
        }
    }

    /// rskj `BridgeSupport.refundTxSender` for a v1 peg-in, and the reason
    /// RSKIP170 added the field: the sender of a peg-in need not be its owner.
    /// When the OP_RETURN carries a refund address it wins over whatever the
    /// scriptSig says, and when neither is available the peg-in is not
    /// refundable at all rather than refundable to a guess.
    #[test]
    fn v1_refund_target_prefers_the_op_return_address_over_the_sender() {
        let op_return = [0x11u8; 20];
        let from_sender = [0x22u8; 20];
        let with_refund = super::super::pegin_instructions::PeginInstructions {
            protocol_version: 1,
            rsk_destination: [0u8; 20],
            btc_refund_address: Some(super::super::pegin_instructions::BtcRefundAddress {
                is_p2sh: true,
                hash160: op_return,
            }),
        };
        let without_refund = super::super::pegin_instructions::PeginInstructions {
            protocol_version: 1,
            rsk_destination: [0u8; 20],
            btc_refund_address: None,
        };
        let sender = PeginSender::P2shMultisig { p2sh_hash: from_sender };

        assert_eq!(
            v1_refund_target(&with_refund, Some(&sender)),
            Some((op_return, true)),
            "the OP_RETURN refund address must override the sender"
        );
        assert_eq!(
            v1_refund_target(&with_refund, None),
            Some((op_return, true)),
            "and must be used even when the sender could not be classified"
        );
        assert_eq!(
            v1_refund_target(&without_refund, Some(&sender)),
            Some((from_sender, true)),
            "with no refund address it falls back to the sender"
        );
        assert_eq!(
            v1_refund_target(&without_refund, None),
            None,
            "neither available means NOT refundable -- never refundable to a guess"
        );
    }

    /// The segregation is real: with the emulation off, the two shapes it
    /// exists to recognise stop being classified, and nothing else changes.
    /// This is the test that makes "flip a switch to remove it" a fact rather
    /// than an intention.
    #[test]
    fn the_switch_removes_exactly_the_two_multisig_shapes() {
        use super::super::rskj_sender_compat as compat;

        // Guard: this flips process-wide state, so restore it.
        let was = compat::enabled();
        compat::set_enabled(false);

        assert!(
            matches!(classify_pegin_sender(&p2pkh_tx()).unwrap(), Some(PeginSender::P2pkh { .. })),
            "P2PKH is unaffected -- it is credited, not refunded"
        );
        assert!(
            matches!(classify_pegin_sender(&p2sh_p2wpkh_tx()).unwrap(), Some(PeginSender::P2shP2wpkh { .. })),
            "P2SH-P2WPKH is unaffected for the same reason"
        );
        assert!(
            classify_pegin_sender(&p2sh_multisig_tx()).unwrap().is_none(),
            "P2SH-multisig is no longer classified"
        );
        assert!(
            classify_pegin_sender(&p2sh_p2wsh_tx()).unwrap().is_none(),
            "P2SH-P2WSH is no longer classified"
        );

        compat::set_enabled(was);
        assert!(
            matches!(classify_pegin_sender(&p2sh_multisig_tx()).unwrap(), Some(PeginSender::P2shMultisig { .. })),
            "and switching back restores it"
        );
    }

    /// rskj: the `gets_*_btc_lock_sender_from_raw_transaction` case in each of
    /// the four classes, and every `rejects_*` case in all four, as one matrix.
    #[test]
    fn classify_pegin_sender_maps_each_shape_to_exactly_one_variant() {
        assert!(
            matches!(classify_pegin_sender(&p2pkh_tx()).unwrap(), Some(PeginSender::P2pkh { .. })),
            "P2PKH scriptSig [sig, pubkey] must classify as P2PKH"
        );
        assert!(
            matches!(classify_pegin_sender(&p2sh_p2wpkh_tx()).unwrap(), Some(PeginSender::P2shP2wpkh { .. })),
            "single-chunk scriptSig with a 2-item witness must classify as P2SH-P2WPKH"
        );
        assert!(
            matches!(classify_pegin_sender(&p2sh_multisig_tx()).unwrap(), Some(PeginSender::P2shMultisig { .. })),
            "scriptSig ending in a multisig redeem must classify as P2SH-multisig"
        );
        assert!(
            matches!(classify_pegin_sender(&p2sh_p2wsh_tx()).unwrap(), Some(PeginSender::P2shP2wsh { .. })),
            "single-chunk scriptSig with a >=3-item witness ending in a multisig \
             redeem must classify as P2SH-P2WSH"
        );
    }

    /// rskj: `doesnt_parse_if_tx_doesnt_have_inputs`,
    /// `doesnt_parse_if_tx_doesnt_have_scriptsig`,
    /// `doesnt_parse_if_transaction_doesnt_have_witness`,
    /// `doesnt_parse_if_transaction_witness_doesnt_have_two_pushes`,
    /// `doesnt_parse_if_transaction_has_scriptsig_with_more_than_one_chunk`,
    /// `doesnt_parse_if_transaction_witness_doesnt_have_at_least_three_pushes`.
    ///
    /// rskj's null-transaction cases have no analogue: a `&BtcTransaction`
    /// cannot be null.
    #[test]
    fn classify_pegin_sender_refuses_malformed_inputs() {
        let no_inputs = BtcTransaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert!(classify_pegin_sender(&no_inputs).unwrap().is_none(), "no inputs");

        assert!(
            classify_pegin_sender(&tx_with(vec![], vec![])).unwrap().is_none(),
            "empty scriptSig and no witness"
        );

        // Single-chunk scriptSig but a one-item witness: neither the P2WPKH
        // shape (needs 2) nor the P2WSH shape (needs >= 3).
        assert!(
            classify_pegin_sender(&tx_with(vec![2, 0x00, 0x14], vec![vec![0x30; 71]])).unwrap().is_none(),
            "witness with a single push matches no shape"
        );

        // Witness has two pushes but the second is not a valid compressed key.
        assert!(
            classify_pegin_sender(&tx_with(vec![2, 0x00, 0x14],
                vec![vec![0x30; 71], vec![0xFFu8; 33]])).unwrap().is_none(),
            "P2SH-P2WPKH requires the witness key to be a curve point"
        );

        // Three witness items but the last is not a multisig redeem.
        assert!(
            classify_pegin_sender(&tx_with(vec![2, 0x00, 0x20],
                vec![vec![], vec![0x30; 71], vec![0x01, 0x02, 0x03]])).unwrap().is_none(),
            "P2SH-P2WSH requires a multisig redeem as the last witness item"
        );
    }

    /// The P2PKH branch accepts only a real curve point. rskj gets this from
    /// BtcECKey.fromPublicOnly throwing; rustock from `compress_pubkey`
    /// returning None. Without it a two-chunk scriptSig whose second push is
    /// arbitrary bytes would be read as P2PKH and refunded to a hash160 of
    /// data the sender never controlled.
    #[test]
    fn classify_pegin_sender_p2pkh_requires_a_valid_public_key() {
        let mut script = vec![71];
        script.extend_from_slice(&[0x30; 71]);
        script.push(33);
        script.extend_from_slice(&[0xFFu8; 33]); // not on the curve
        assert!(
            classify_pegin_sender(&tx_with(script, vec![])).unwrap().is_none(),
            "a non-curve 33-byte push must not classify as P2PKH"
        );
    }

    /// sender address = P2SH(hash160(redeem)) — processable post-RSKIP143
    /// but NOT lockable (refunded). Groundtruth shape from mainnet
    /// #2,851,909 tx 2.
    #[test]
    fn classify_p2sh_multisig_pegin_sender() {
        // 2-of-3 multisig redeem with valid-shape compressed keys.
        let mut redeem = vec![0x52];
        for i in 0..3u8 {
            redeem.push(33);
            let mut k = [0x02u8; 33];
            k[32] = i;
            redeem.extend_from_slice(&k);
        }
        redeem.push(0x53);
        redeem.push(0xae);
        let mut script = vec![0x00, 71];
        script.extend_from_slice(&[0x30; 71]);
        script.push(71);
        script.extend_from_slice(&[0x30; 71]);
        script.push(0x4c); // PUSHDATA1
        script.push(redeem.len() as u8);
        script.extend_from_slice(&redeem);
        let tx = BtcTransaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: Default::default(),
                script_sig: bitcoin::ScriptBuf::from_bytes(script),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        match classify_pegin_sender(&tx).unwrap() {
            Some(PeginSender::P2shMultisig { p2sh_hash }) => {
                assert_eq!(p2sh_hash, pubkey_hash160(&redeem));
            }
            other => panic!("expected P2SH-multisig sender, got {}", other.is_some()),
        }
    }

    /// Conversion: 1 satoshi = 10^10 wei.
    #[test]
    fn rskj_satoshi_wei_conversion() {
        assert_eq!(btc_satoshi_to_rbtc_wei(1), U256::from(10_000_000_000u64));
        assert_eq!(btc_satoshi_to_rbtc_wei(100_000_000), U256::from(10u128.pow(18)));
        assert_eq!(btc_satoshi_to_rbtc_wei(0), U256::ZERO);
    }

    /// Ported from rskj BridgeSupportTestUtil.shouldMarkRejectedPeginAsProcessed
    /// and BridgeSupportRejectedPeginTest activation matrix: rejected
    /// non-refundable peg-ins are marked as processed only between RSKIP459
    /// (lovell700, mainnet 7_338_024) and RSKIP551 (vetiver900, mainnet 8_804_200).
    #[test]
    fn test_should_mark_rejected_pegin_as_processed_window() {
        let cfg = RskHardforkConfig::mainnet();
        // Before lovell700: no marking.
        assert!(!should_mark_rejected_pegin_as_processed(&cfg, 7_338_023));
        // lovell700 .. vetiver900: marking active.
        assert!(should_mark_rejected_pegin_as_processed(&cfg, 7_338_024));
        assert!(should_mark_rejected_pegin_as_processed(&cfg, 8_804_199));
        // From vetiver900 (RSKIP551): disabled again.
        assert!(!should_mark_rejected_pegin_as_processed(&cfg, 8_804_200));
    }

    /// rskTxsWaitingFS is a Java TreeMap<Keccak256, BtcTransaction>; rskj's
    /// `Keccak256.compareTo` compares bytes UNSIGNED from the LAST byte down to
    /// the first (reverse/little-endian order). Ground truth from RSK Mainnet
    /// block #3,340,065: the two waiting-for-signatures RSK tx hashes must
    /// serialize with `285b…0c` BEFORE `12b7…f0` (last bytes 0x0c < 0xf0),
    /// the opposite of forward (big-endian) BTreeMap order (0x12 < 0x28).
    #[test]
    fn rsk_txs_waiting_fs_keccak_reverse_byte_order() {
        let k_12b7: [u8; 32] =
            hex::decode("12b7dd806871857a4d949c2bbd25ab95bce3c4a38ef5c7fcee7bc43ea3a6baf0")
                .unwrap()
                .try_into()
                .unwrap();
        let k_285b: [u8; 32] =
            hex::decode("285b09d3973cbe2a324cb7d3248b36ee668b66093f2976f1e5a5a4b5d9a7d10c")
                .unwrap()
                .try_into()
                .unwrap();
        let mut map = BTreeMap::new();
        map.insert(k_12b7, vec![0xaa]);
        map.insert(k_285b, vec![0xbb]);
        let out = serialize_rsk_txs_waiting_for_signatures(&map);
        let items = rlp_decode_list(&out).unwrap();
        // First serialized key must be 285b… (smaller under reverse-byte order).
        assert_eq!(items[0], k_285b);
        assert_eq!(items[2], k_12b7);
    }

    /// A 13-member standard multisig federation's regular peg-out (2 inputs,
    /// 2 outputs). The redeem script is the 7-of-13 multisig (445 bytes).
    ///
    /// Pre-RSKIP271 (`BridgeUtilsLegacy.calculatePegoutTxSize`) must size to
    /// within 2% of the real-world 2076 bytes. Post-RSKIP271
    /// (`BridgeUtils.calculateLegacyTxSize`) is the exact `bitcoinSerialize()`
    /// length: ported ground truth from rskj
    /// `BridgeUtilsTest.testCalculatePegoutTxSize_2Inputs_2Outputs` = 2058 bytes.
    #[test]
    fn regular_pegout_tx_size_matches_rskj() {
        use k256::ecdsa::SigningKey;
        let keys: Vec<[u8; 33]> = (1u8..=13)
            .map(|seed| {
                SigningKey::from_slice(&[seed; 32])
                    .unwrap()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            })
            .collect();
        let threshold = keys.len() / 2 + 1; // 7
        let redeem = build_federation_redeem_script(&keys, threshold);

        // Post-RSKIP271: exact match against rskj's 2058.
        assert_eq!(regular_pegout_tx_size(&redeem, threshold as u64, true), 2058);

        // Pre-RSKIP271: within 2% of the real-world 2076-byte tx.
        let legacy = regular_pegout_tx_size(&redeem, threshold as u64, false) as i64;
        let orig = 2076i64;
        assert!(
            (orig - legacy).abs() as f64 <= orig as f64 * 0.02,
            "legacy size {legacy} too far from {orig}"
        );
    }

    /// At mainnet #3,615,279 (feePerKb 30000 sat/kB, mainnet federation) the
    /// fee-based minimum is far below the 400000-sat minimumPegoutTxValue, so a
    /// 10000-sat direct transfer is rejected with reason LOW_AMOUNT (not
    /// FEE_ABOVE_VALUE). This pins the reason-selection branch.
    #[test]
    fn require_funds_for_fee_below_minimum_pegout_value() {
        let config = BridgeConstants::mainnet();
        let keys = genesis_federation_keys(&config);
        let threshold = keys.len() / 2 + 1;
        let redeem = build_federation_redeem_script(&keys, threshold);
        let fee = require_funds_for_fee(&redeem, threshold as u64, 30_000, true, &config);
        assert!(
            fee < config.minimum_pegout_tx_value,
            "require_funds_for_fee {fee} should be below {} so reason is LOW_AMOUNT",
            config.minimum_pegout_tx_value
        );
    }

    // -----------------------------------------------------------------------
    // Flyover (RSKIP176) ground-truth tests
    // -----------------------------------------------------------------------

    /// rskj `BitcoinTestUtils.createP2PKHAddress`: priv = keccak256(seed),
    /// address = `[version=0] || hash160(compressed pubkey)` on mainnet.
    fn mainnet_p2pkh_addr_bytes(seed: &str) -> Vec<u8> {
        use k256::ecdsa::SigningKey;
        use sha3::Digest;
        let priv_bytes: [u8; 32] = sha3::Keccak256::digest(seed.as_bytes()).into();
        let sk = SigningKey::from_slice(&priv_bytes).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(true); // compressed
        let hash160 = pubkey_hash160(pubkey.as_bytes());
        let mut out = vec![0u8]; // mainnet P2PKH version
        out.extend_from_slice(&hash160);
        out
    }

    /// Ported from rskj `PegUtilsTest.getFlyoverDerivationHash_returnsExpectedDerivationHash`
    /// (hardcoded expected hash `56d4f6bd…44d8`).
    #[test]
    fn flyover_derivation_hash_groundtruth() {
        // derivationArgumentsHash = PegTestUtils.createHash3(5) → byte[0]=5.
        let mut derivation_args = [0u8; 32];
        derivation_args[0] = 5;
        let user_refund = mainnet_p2pkh_addr_bytes("userRefundBtcAddress");
        let lp_btc = mainnet_p2pkh_addr_bytes("lpBtcAddress");
        let lbc = RskAddress::from_slice(
            &hex_to_bytes("461750b4824b14c3d9b7702bc6fbb82469082b23"),
        );

        let hash = flyover_derivation_hash(&derivation_args, &user_refund, &lbc, &lp_btc);
        assert_eq!(
            to_hex(&hash),
            "56d4f6bd69378ef607e091832903ddc2b5aac5008bd06987a26f14bb248c44d8"
        );
    }

    /// Ported from rskj `PegUtilsTest.getFlyoverValues_fromRealLegacyFedTx`:
    /// the flyover redeem script (`PUSH(hash) OP_DROP <fedRedeem>`) and its
    /// P2SH hash160 for derivation hash `fc2bb9…0439`.
    #[test]
    fn flyover_redeem_script_and_p2sh_groundtruth() {
        let flyover_hash: [u8; 32] = hex_to_bytes(
            "fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d500439",
        )
        .try_into()
        .unwrap();
        // The full expected flyover redeem script from rskj.
        let expected_flyover_redeem = hex_to_bytes(
            "20fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d50043975645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c21025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db210275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c9492102a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f25210350179f143a632ce4e6ac9a755b82f7f4266cfebb116a42cadb104c2c2a3350f92103b04fbd87ef5e2c0946a684c8c93950301a45943bbe56d979602038698facf9032103b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b3588877190659ae670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b354ae68",
        );
        // The federation redeem script is the suffix after `PUSH(32) hash OP_DROP`
        // (33 + 1 bytes of prefix).
        let federation_redeem = &expected_flyover_redeem[34..];

        let flyover_redeem = flyover_redeem_script(&flyover_hash, federation_redeem);
        assert_eq!(
            to_hex(&flyover_redeem),
            to_hex(&expected_flyover_redeem),
            "flyover redeem script must match rskj"
        );

        let p2sh_hash = redeem_script_hash160(&flyover_redeem);
        assert_eq!(
            to_hex(&p2sh_hash),
            "18fc3b52a5b7d5277f41b9765719b45bfa427730",
            "flyover P2SH hash160 must match rskj"
        );
    }

    /// Regression for mainnet #5,831,167 (registerFastBridgeBtcTransaction,
    /// fingerroot500): rskj's `createFlyoverFederationInformation` derives the
    /// active flyover P2SH from `getActiveFederation().getRedeemScript()`, which
    /// is FORMAT-AWARE — at fingerroot500 the active fed is a P2SH-ERP federation
    /// (RSKIP353), so the flyover redeem must wrap the ERP redeem. rustock
    /// previously built a PLAIN multisig redeem here, producing the wrong P2SH;
    /// the BTC tx's flyover output then matched nothing, the bridge returned
    /// UNPROCESSABLE_VALUE_ZERO (-304) instead of the locked amount, and the
    /// LiquidityBridgeContract took the wrong branch — overcharging gas by 6,817
    /// (216,145 vs the header's 209,328).
    #[test]
    fn flyover_active_p2sh_uses_erp_redeem_5831167() {
        // The real ERP active-federation redeem at #5,831,167 (captured from the
        // format-aware builder) and the block's flyover derivation hash.
        let flyover_hash: [u8; 32] = hex_to_bytes(
            "5f157f6ea6385bfdc191321bda7fd285d4df84c499d9fef7660de63af590cf80",
        )
        .try_into()
        .unwrap();
        let erp_fed_redeem = hex_to_bytes(
            "645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c21025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db21026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c210275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c9492102a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f252103b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b358887719062103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff678029959ae670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b354ae68",
        );

        // Format-aware (ERP) redeem → the P2SH hash160 the BTC tx actually paid.
        let flyover_redeem = flyover_redeem_script(&flyover_hash, &erp_fed_redeem);
        assert_eq!(
            to_hex(&redeem_script_hash160(&flyover_redeem)),
            "69206b978af5523129667292dae54f464170256a",
            "active flyover P2SH must derive from the ERP redeem"
        );

        // The plain-multisig redeem over the SAME keys yields a DIFFERENT P2SH —
        // the bug that made the flyover output match nothing.
        let keys: Vec<[u8; 33]> = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "0275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c949",
            "02a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f25",
            "03b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b35888771906",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
        ]
        .iter()
        .map(|h| hex_to_bytes(h).try_into().unwrap())
        .collect();
        let plain_redeem = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
        let plain_p2sh = redeem_script_hash160(&flyover_redeem_script(&flyover_hash, &plain_redeem));
        assert_ne!(
            to_hex(&plain_p2sh),
            "69206b978af5523129667292dae54f464170256a",
            "plain multisig must NOT match the ERP flyover P2SH"
        );
    }

    /// The flyover-hash-used storage key uses the DISPLAY-order BTC tx hash and
    /// the FORWARD-order derivation hash (rskj getStorageKeyForFlyoverHash).
    #[test]
    fn flyover_hash_used_key_byte_order() {
        // wtxid in internal order; display order is the reverse.
        let btc_hash = hex_to_bytes(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        )
        .try_into()
        .unwrap();
        let flyover_hash = hex_to_bytes(
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        )
        .try_into()
        .unwrap();
        let key = flyover_hash_used_key(&btc_hash, &flyover_hash);
        // Reconstruct the expected compound identifier: display(btc) + forward(flyover).
        let expected = compound_key(
            FAST_BRIDGE_HASH_USED_KEY,
            "-",
            "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        );
        assert_eq!(key, expected);
    }

    /// RSKIP293 retiring-federation flyover (hop400): the retiring fed's flyover
    /// federation information is built with the SAME math as the active fed
    /// (createFlyoverFederationInformation(hash, federation) →
    /// flyover redeem = PUSH(hash) OP_DROP <fedRedeem>, P2SH = its hash160). Here
    /// we feed an ERP retiring redeem (the iris-era flyover groundtruth's inner
    /// redeem) and confirm the FlyoverFedInfo fields match the same vector the
    /// active-fed groundtruth test asserts.
    #[test]
    fn flyover_retiring_federation_information_groundtruth() {
        let flyover_hash: [u8; 32] = hex_to_bytes(
            "fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d500439",
        )
        .try_into()
        .unwrap();
        let expected_flyover_redeem = hex_to_bytes(
            "20fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d50043975645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c21025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db210275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c9492102a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f25210350179f143a632ce4e6ac9a755b82f7f4266cfebb116a42cadb104c2c2a3350f92103b04fbd87ef5e2c0946a684c8c93950301a45943bbe56d979602038698facf9032103b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b3588877190659ae670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b354ae68",
        );
        let retiring_fed_redeem = &expected_flyover_redeem[34..];

        // Mirror the retiring branch of register_fast_bridge_btc_transaction.
        let flyover_redeem = flyover_redeem_script(&flyover_hash, retiring_fed_redeem);
        let flyover_p2sh_hash = redeem_script_hash160(&flyover_redeem);
        let flyover_script = p2sh_output_script(&flyover_p2sh_hash);

        assert_eq!(to_hex(&flyover_redeem), to_hex(&expected_flyover_redeem));
        assert_eq!(
            to_hex(&flyover_p2sh_hash),
            "18fc3b52a5b7d5277f41b9765719b45bfa427730",
            "retiring flyover P2SH hash160 must match rskj"
        );
        // The flyover output script is a plain P2SH (OP_HASH160 <h> OP_EQUAL).
        assert_eq!(flyover_script.as_bytes()[0], 0xa9);
        assert_eq!(flyover_script.as_bytes()[1], 0x14);
        assert_eq!(flyover_script.as_bytes()[22], 0x87);
        // fed_p2sh_hash is the hash160 of the (ERP) retiring redeem itself.
        assert_eq!(redeem_script_hash160(retiring_fed_redeem).len(), 20);
    }

    /// RSKIP293 per-UTXO minimum gate (validateFlyoverPeginValue →
    /// allUTXOsToFedAreAboveMinimumPeginValue → isAnyUTXOAmountBelowMinimum at
    /// hop400): under RSKIP293 ANY flyover UTXO strictly below the minimum
    /// rejects the whole tx with -305; pre-RSKIP293 only the total-is-zero gate
    /// applies. Mirrors the gate used in register_fast_bridge_btc_transaction.
    #[test]
    fn flyover_per_utxo_minimum_gate() {
        let min = 500_000u64; // RSKIP219 minimum peg-in value (mainnet).
        // One UTXO below the minimum among otherwise-fine ones → below min.
        let with_dust = [min, min - 1, min + 10];
        assert!(with_dust.iter().any(|v| *v < min));
        // All at/above the minimum → OK.
        let all_ok = [min, min + 1, 2 * min];
        assert!(!all_ok.iter().any(|v| *v < min));
        // Empty set → not below minimum (anyMatch over empty stream is false);
        // the separate total==0 gate (-304) handles a no-output tx.
        let empty: [u64; 0] = [];
        assert!(!empty.iter().any(|v| *v < min));
    }

    /// `build_flyover_empty_wallet_multi` must agree byte-for-byte with the
    /// single-redeem `release_tx::build_empty_wallet_to` when every input shares
    /// the same flyover redeem (the degenerate active-only case), and must
    /// produce a valid refund with per-input redeems when the active and
    /// retiring flyover redeems differ.
    #[test]
    fn flyover_multi_empty_wallet_matches_single_when_uniform() {
        let flyover_hash = [7u8; 32];
        // Two distinct 2-of-3 fed redeems → two distinct flyover redeems.
        let keys_a: Vec<[u8; 33]> = (1u8..=3).map(|i| [i; 33]).collect();
        let keys_b: Vec<[u8; 33]> = (4u8..=6).map(|i| [i; 33]).collect();
        let fed_a = build_federation_redeem_script(&keys_a, 2);
        let fed_b = build_federation_redeem_script(&keys_b, 2);
        let fly_a = flyover_redeem_script(&flyover_hash, &fed_a);
        let fly_b = flyover_redeem_script(&flyover_hash, &fed_b);

        let refund = p2sh_output_script(&[9u8; 20]);
        let mk_utxo = |seed: u8, sats: u64| BridgeUtxo {
            tx_hash: [seed; 32],
            vout: 0,
            value_satoshis: sats,
            height: 0,
            script: vec![],
            coinbase: false,
        };

        // Uniform case: both inputs use fly_a → must equal the single-redeem build.
        let utxos = [mk_utxo(1, 5_000_000), mk_utxo(2, 6_000_000)];
        let redeems_uniform: Vec<&[u8]> = vec![fly_a.as_slice(), fly_a.as_slice()];
        let multi = build_flyover_empty_wallet_multi(&utxos, &redeems_uniform, &refund, 1000, 2)
            .expect("multi build");
        let single =
            crate::bridge::release_tx::build_empty_wallet_to(&utxos, &refund, &fly_a, 1000, 2)
                .expect("single build");
        assert_eq!(
            bitcoin::consensus::serialize(&multi.tx),
            bitcoin::consensus::serialize(&single.tx),
            "uniform-redeem multi build must equal single build"
        );

        // Mixed case: input 0 uses fly_a, input 1 uses fly_b. The refund spends
        // both, each input carries its own placeholder scriptSig (sizes differ
        // only if the redeems differ in length; here they are equal length but
        // distinct content).
        let redeems_mixed: Vec<&[u8]> = vec![fly_a.as_slice(), fly_b.as_slice()];
        let mixed = build_flyover_empty_wallet_multi(&utxos, &redeems_mixed, &refund, 1000, 2)
            .expect("mixed build");
        assert_eq!(mixed.tx.input.len(), 2);
        assert_eq!(mixed.used_utxos.len(), 2);
        // Each input's scriptSig is the placeholder built from its own redeem.
        let ss0 = crate::bridge::release_tx::placeholder_scriptsig(
            &fly_a,
            crate::bridge::release_tx::redeem_script_threshold(&fly_a),
        );
        let ss1 = crate::bridge::release_tx::placeholder_scriptsig(
            &fly_b,
            crate::bridge::release_tx::redeem_script_threshold(&fly_b),
        );
        assert_eq!(mixed.tx.input[0].script_sig.as_bytes(), ss0.as_slice());
        assert_eq!(mixed.tx.input[1].script_sig.as_bytes(), ss1.as_slice());
        assert_ne!(ss0, ss1, "the two flyover redeems must produce distinct scriptSigs");
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Regression for mainnet #4,683,511: a btc tx spending the LAST RETIRED
    /// federation (a pre-ERP 7-of-13 multisig) and paying the active ERP
    /// federation must classify as PEGOUT_OR_MIGRATION (registerNewUtxos, no
    /// events) — rskj PegUtilsLegacy.isMigrationTx via
    /// getLastRetiredFederationP2SHScript. The decisive step is reducing the
    /// input's full redeem to its STANDARD redeem and hashing it
    /// (extractStandardRedeemScript + createP2SHOutputScript), which must equal
    /// the stored retired-federation P2SH hash160.
    #[test]
    fn retired_federation_input_reduces_to_its_standard_p2sh() {
        // input[0] full redeem from the #4,683,511 migration tx (e92052db…).
        let input_redeem = hex_to_bytes(
            "57210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36\
21026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c\
21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344\
210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc\
2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93\
21033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad\
210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42\
210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6\
2103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6\
2103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d1\
2103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2\
2103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299\
2103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d\
5dae",
        );
        // This federation is a plain (non-ERP) multisig: the standard redeem is
        // the full redeem, so the standard P2SH equals the spent address.
        let std_redeem = build_federation_redeem_script(
            &super::super::release_tx::spending_redeem_keys(&input_redeem),
            super::super::release_tx::redeem_script_threshold(&input_redeem),
        );
        assert_eq!(std_redeem, input_redeem, "non-ERP redeem is its own standard");
        let std_hash160 = redeem_script_hash160(&std_redeem);
        // hash160 of the spent address (the lastRetiredFederationP2SHScript at
        // this block) — base58 35cqv4Hr…/program a914596cff92…87.
        assert_eq!(
            to_hex(&std_hash160),
            "596cff92a275960df9cb2ab9df0ff69faa2b1d8a"
        );
    }

    /// Regression for mainnet #4,998,800: a funds migration spends the RETIRING
    /// federation. Once that federation is itself an ERP federation (stored
    /// format 2000+), its spending redeem is the ERP redeem, not the plain
    /// multisig — the migration path must resolve it via the same format-aware
    /// builder the regular pegout uses (`getRetiringFederation().getRedeemScript()`),
    /// otherwise the per-input placeholder scriptSig and the unsigned migration
    /// txid fork. This locks that the format-2000 redeem differs from the plain
    /// builder the buggy migration code used.
    #[test]
    fn erp_retiring_federation_migration_redeem_is_not_plain() {
        let keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
        ]
        .map(key);
        let config = BridgeConstants::mainnet();
        let plain = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
        let erp = federation_redeem_for_format(&keys, 2000, &config);
        assert_ne!(
            plain, erp,
            "an ERP retiring federation must not migrate with the plain multisig redeem"
        );
    }

    /// The hardcoded mainnet old-federation address (rskj
    /// FederationMainNetConstants.oldFederationAddress
    /// "35JUi1FxabGdhygLhnNUEFG4AgvpNMgxK1") decodes to this hash160, used by
    /// PegUtilsLegacy.txIsFromOldFederation.
    #[test]
    fn mainnet_old_federation_address_hash160() {
        let config = super::super::constants::BridgeConstants::mainnet();
        assert_eq!(
            to_hex(&config.old_federation_address_hash160),
            "279d4b44e8cf5e3f04c0ea21c78f1a0ecaa4cd9f"
        );
    }

    /// Regression: an ABI `bytes[]` whose declared count does not fit in a
    /// usize must be rejected (empty result), never panic on the U256->usize
    /// conversion. Mainnet #6,223,783 tx[3] forwarded malformed addSignature
    /// calldata whose `signatures` offset landed mid-key, yielding an absurd
    /// (~uint256::MAX) array count.
    #[test]
    fn parse_bytes_array_rejects_oversized_count_without_panic() {
        // 32-byte count word = uint256::MAX (left of any plausible calldata).
        let args = vec![0xFFu8; 32];
        assert!(parse_bytes_array(&args, 0).is_empty());

        // A within-range but too-large count (> 1000 guard) is also rejected.
        let mut over = [0u8; 32];
        over[30] = 0x10; // 0x1000 = 4096 > 1000
        assert!(parse_bytes_array(&over, 0).is_empty());
    }

    /// Regression: `read_dynamic_bytes` must reject an oversized ABI length
    /// rather than panic converting it to usize (same malformed-calldata path).
    #[test]
    fn read_dynamic_bytes_rejects_oversized_length() {
        let args = vec![0xFFu8; 64]; // offset 0 -> length word = uint256::MAX
        assert!(read_dynamic_bytes(&args, 0).is_err());
    }
}
