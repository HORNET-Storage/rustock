//! BTC transaction verification and processed tx tracking for the Bridge.
//!
//! Implements:
//! - `registerBtcCoinbaseTransaction`: verify and store coinbase witness info
//! - `hasBtcBlockCoinbaseTransactionInformation`: check if coinbase info exists
//! - `getBtcTransactionConfirmations`: compute confirmations via merkle branch
//! - Processed tx hash tracking (pre/post RSKIP134)

use alloy_primitives::{Bytes, U256};
use bitcoin::hashes::{Hash, sha256d};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::btc_chain::b256_to_bitcoin_hash;

/// Encode bytes as lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Render a BTC hash (internal byte order) as rskj's `Sha256Hash.toString()`:
/// DISPLAY-order hex, used in compound storage keys.
pub fn btc_hash_hex_display(hash: &[u8; 32]) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}
use super::btc_store::{get_block_keeping_testnet_consensus, get_stored_block, load_chain_head};
use super::pmt::{MerkleBranch, PartialMerkleTree};
use super::serialization::{rlp_decode_list, rlp_encode_element, rlp_encode_list};
use super::storage::*;

// ---------------------------------------------------------------------------
// Processed tx hash tracking
// ---------------------------------------------------------------------------

/// Load the legacy processed-tx map ("btcTxHashesAP" — the only form before
/// RSKIP134), and write it back: rskj loads it on ANY processed-height
/// lookup and the post-call save rewrites it, creating the (possibly empty)
/// RLP map entry the first time the bridge reads it. Hashes are kept in
/// internal byte order; the serialized form uses display order, sorted by
/// bitcoinj `Sha256Hash.compareTo` (= internal-order lexicographic).
fn load_legacy_processed_map<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<([u8; 32], u64)> {
    let key = bridge_storage_key(BTC_TX_HASHES_ALREADY_PROCESSED_KEY);
    let mut map = Vec::new();
    if let Some(data) = bridge_load_raw(ctx, key) {
        if let Some(items) = rlp_decode_list(&data) {
            let mut i = 0;
            while i + 1 < items.len() {
                if items[i].len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&items[i]);
                    hash.reverse(); // display -> internal
                    let height = U256::from_be_slice(&items[i + 1]).to::<u64>();
                    map.push((hash, height));
                }
                i += 2;
            }
        }
    }
    store_legacy_processed_map(ctx, map.clone());
    map
}

/// Serialize and store the legacy map (rskj `serializeMapOfHashesToLong`).
fn store_legacy_processed_map<CTX: crate::RskContextTr>(ctx: &mut CTX, mut map: Vec<([u8; 32], u64)>) {
    map.sort_by(|a, b| a.0.cmp(&b.0));
    let mut items = Vec::with_capacity(map.len() * 2);
    for (hash_internal, height) in &map {
        let mut display = *hash_internal;
        display.reverse();
        items.push(rlp_encode_element(&display));
        items.push(rlp_encode_uint(U256::from(*height)));
    }
    let key = bridge_storage_key(BTC_TX_HASHES_ALREADY_PROCESSED_KEY);
    bridge_store_raw(ctx, key, Some(rlp_encode_list(&items)));
}

/// Check if a BTC tx hash has already been processed. rskj checks the
/// legacy map first at every era, then (post-RSKIP134) the per-hash
/// compound entry.
pub fn is_btc_tx_processed<CTX: crate::RskContextTr>(ctx: &mut CTX, btc_tx_hash: &[u8; 32]) -> bool {
    get_btc_tx_processed_height(ctx, btc_tx_hash).is_some()
}

/// Mark a BTC tx hash as processed at a given RSK height
/// (rskj `setHeightBtcTxhashAlreadyProcessed`).
pub fn set_btc_tx_processed<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    height: u64,
    rskip134: bool,
) {
    if rskip134 {
        let hash_hex = btc_hash_hex_display(btc_tx_hash);
        let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
        // serializeLong (RLP).
        bridge_store_raw(ctx, key, Some(rlp_encode_uint(U256::from(height))));
    } else {
        let mut map = load_legacy_processed_map(ctx);
        map.retain(|(h, _)| h != btc_tx_hash);
        map.push((*btc_tx_hash, height));
        store_legacy_processed_map(ctx, map);
    }
}

/// Get the height at which a BTC tx was processed
/// (rskj `getHeightIfBtcTxhashIsAlreadyProcessed`).
pub fn get_btc_tx_processed_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
) -> Option<u64> {
    let map = load_legacy_processed_map(ctx);
    if let Some((_, height)) = map.iter().find(|(h, _)| h == btc_tx_hash) {
        return Some(*height);
    }
    let hash_hex = btc_hash_hex_display(btc_tx_hash);
    let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
    bridge_load_raw(ctx, key).map(|d| rlp_decode_uint(&d).to::<u64>())
}

// ---------------------------------------------------------------------------
// Coinbase information
// ---------------------------------------------------------------------------

/// Store the witness merkle root for a BTC block's coinbase transaction.
/// Keyed by the BTC block hash.
pub fn set_coinbase_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    block_hash: &[u8; 32],
    witness_merkle_root: &[u8; 32],
) {
    // rskj keys by `Sha256Hash.wrap(blockHashArg).toString()`. bitcoinj's
    // `toString()` hex-encodes the wrapped bytes WITHOUT reversing (only
    // `wrapReversed`/`getHash` reverse), and the ABI `blockHash` arg is already
    // in display order — so the preimage uses the arg bytes as-is, not reversed.
    let hash_hex = to_hex(block_hash);
    let key = compound_key(COINBASE_INFORMATION_KEY, "-", &hash_hex);
    // rskj serializeCoinbaseInformation: RLP list of one element.
    let value = rlp_encode_list(&[rlp_encode_element(witness_merkle_root)]);
    bridge_store_raw(ctx, key, Some(value));
}

/// Load the witness merkle root for a BTC block's coinbase transaction.
pub fn get_coinbase_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    block_hash: &[u8; 32],
) -> Option<[u8; 32]> {
    // See `set_coinbase_information`: the ABI block-hash arg is used as-is
    // (no reversal) to match rskj's `Sha256Hash.toString()` of the wrapped arg.
    let hash_hex = to_hex(block_hash);
    let key = compound_key(COINBASE_INFORMATION_KEY, "-", &hash_hex);
    let data = bridge_load_raw(ctx, key)?;
    let items = rlp_decode_list(&data)?;
    let root = items.first()?;
    (root.len() == 32).then(|| {
        let mut out = [0u8; 32];
        out.copy_from_slice(root);
        out
    })
}

/// Check if coinbase info exists for a block hash.
pub fn has_coinbase_information<CTX: crate::RskContextTr>(ctx: &mut CTX, block_hash: &[u8; 32]) -> bool {
    get_coinbase_information(ctx, block_hash).is_some()
}

// ---------------------------------------------------------------------------
// registerBtcCoinbaseTransaction
// ---------------------------------------------------------------------------

/// `registerBtcCoinbaseTransaction(bytes btcTx, bytes32 blockHash, bytes pmtSerialized, bytes32 witnessMerkleRoot, bytes32 witnessReservedValue)`
pub fn register_btc_coinbase_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    // The five arguments, as rskj's decoder reads them: the transaction, the
    // block hash, the partial merkle tree, the witness merkle root and the
    // witness reserved value.
    let decoded = crate::abi::Args::new(args);
    let (
        Some(btc_tx_data),
        Some(block_hash),
        Some(pmt_data),
        Some(witness_merkle_root),
        Some(witness_reserved_value),
    ) = (
        decoded.bytes(0),
        decoded.bytes32(1),
        decoded.bytes(2),
        decoded.bytes32(3),
        decoded.bytes32(4),
    )
    else {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: malformed arguments",
        ));
    };
    let (btc_tx_data, pmt_data) = (btc_tx_data.to_vec(), pmt_data.to_vec());

    // rskj `ensureBtcBlockStore` comes first, so a store nothing has seeded
    // yet is seeded even where the call then returns without registering.
    super::btc_chain::ensure_btc_block_store(ctx, config, hardfork_cfg);

    // Compute BTC tx hash (double-SHA256)
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    // Validate PMT format
    if !PartialMerkleTree::has_expected_size(&pmt_data) {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: invalid PMT size",
        ));
    }

    // Parse and verify PMT
    let pmt = PartialMerkleTree::parse(&pmt_data).ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: failed to parse PMT")
    })?;

    let pmt_result = pmt.extract_matches().ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: PMT verification failed")
    })?;

    // Check that the tx hash is among the matched hashes. rskj
    // (BridgeSupport.registerBtcCoinbaseTransaction l.2505-2513) logs a
    // warning and `return`s — it does NOT throw — so the call SUCCEEDS as a
    // no-op (no coinbase info stored). A throw here would mark the summary
    // failed and bill the full gas limit instead of gasUsed.
    if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Verify the merkle root matches the stored block's merkle root
    let btc_block_hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from(block_hash));
    let stored_block = get_stored_block(ctx, &btc_block_hash).ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: block not found")
    })?;

    let block_merkle_root = {
        let raw = stored_block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    // rskj (BridgeSupport.registerBtcCoinbaseTransaction l.2548-2557) logs the
    // panic message and `return`s on a merkle-root mismatch — it does NOT
    // throw. The call SUCCEEDS as a no-op (no coinbase info stored), so the
    // summary is NOT marked failed and the sender is billed gasUsed, not the
    // full gas limit (mainnet #4,603,038 tx[2]).
    if block_merkle_root != pmt_result.merkle_root {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // rskj parses the transaction and runs bitcoinj's `btcTx.verify()` on it
    // (BridgeSupport l.2559-2560). Either throws.
    let btc_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&btc_tx_data)
        .map_err(|_| PrecompileError::other("registerBtcCoinbaseTransaction: invalid btc tx"))?;
    verify_btc_transaction(&btc_tx, btc_tx_data.len()).map_err(PrecompileError::other)?;

    // `findWitnessCommitment` opens with `Preconditions.checkState(tx.isCoinBase())`:
    // only a block's coinbase names its witness root.
    if !btc_tx.is_coinbase() {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: the transaction isn't a coinbase",
        ));
    }

    // Validate the witness commitment (rskj `validateWitnessInformation`,
    // BridgeSupport l.2570-2589). The commitment embedded in the coinbase tx
    // must equal SHA256d(witnessMerkleRoot.getReversedBytes() || witnessReservedValue).
    // The ABI arg is the witness merkle root in display order (bitcoinj
    // `Sha256Hash.wrap` keeps the bytes as given), and the commitment hashes it
    // in wire order, so it is reversed here. It is stored as given.
    let mut commitment_data = [0u8; 64];
    commitment_data[..32].copy_from_slice(&witness_merkle_root);
    commitment_data[..32].reverse();
    commitment_data[32..].copy_from_slice(&witness_reserved_value);
    let calculated_commitment = *sha256d::Hash::hash(&commitment_data).as_byte_array();

    // If the embedded commitment is missing or does not match, rskj throws
    // `BridgeIllegalArgumentException` (BridgeSupport l.2578-2587), which
    // `Bridge.execute` wraps in a `VMException` — the call FAILS (no store),
    // unlike the no-op `return` paths above. A `PrecompileError::other` here is
    // translated by the bridge dispatch into the same VMException gas semantics.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let found = find_witness_commitment(&btc_tx, !hardfork_cfg.has_rskip460(block_number))
        .map_err(PrecompileError::other)?;
    match found {
        Some(expected) if expected == calculated_commitment => {}
        _ => {
            return Err(PrecompileError::other(
                "registerBtcCoinbaseTransaction: witness commitment does not match",
            ));
        }
    }

    // Store coinbase information keyed by block hash
    set_coinbase_information(ctx, &block_hash, &witness_merkle_root);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// hasBtcBlockCoinbaseTransactionInformation
// ---------------------------------------------------------------------------

/// `hasBtcBlockCoinbaseTransactionInformation(bytes32 blockHash)` → bool
pub fn has_btc_block_coinbase_info<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_hash = crate::abi::Args::new(args).bytes32(0).ok_or_else(|| {
        PrecompileError::other("hasBtcBlockCoinbaseTransactionInformation: no block hash")
    })?;
    let has_info = has_coinbase_information(ctx, &block_hash);

    let mut output = [0u8; 32];
    if has_info {
        output[31] = 1;
    }

    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// getBtcTransactionConfirmations
// ---------------------------------------------------------------------------

// getBtcTransactionConfirmations result codes. Ground truth is rskj
// `BridgeSupport.java:90-94` — the calling contract branches on these
// integers, so a client that invents its own values forks.
const CONFIRMATION_ERR_INEXISTENT_BLOCK_HASH: i64 = -1;
const CONFIRMATION_ERR_BLOCK_NOT_IN_BEST_CHAIN: i64 = -2;
const CONFIRMATION_ERR_INCONSISTENT_BLOCK: i64 = -3;
const CONFIRMATION_ERR_BLOCK_TOO_OLD: i64 = -4;
const CONFIRMATION_ERR_INVALID_MERKLE_BRANCH: i64 = -5;

/// `getBtcTransactionConfirmations(bytes32 btcTxHash, bytes32 btcBlockHash, uint256 merkleBranchPath, bytes32[] merkleBranchHashes)` → int256
///
/// Mirrors rskj `BridgeSupport.getBtcTransactionConfirmations`
/// (BridgeSupport.java:2194-2235). The ORDER of the checks is consensus: each
/// one returns a distinct code, so performing them in a different sequence
/// reports a different error for an input that fails more than one.
pub fn get_btc_transaction_confirmations<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    use_v2: bool,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let (branch, tx_hash, block_hash_bytes) =
        MerkleBranch::from_abi_args(args).ok_or_else(|| {
            PrecompileError::other("getBtcTransactionConfirmations: invalid args")
        })?;

    // rskj `this.ensureBtcBlockChain()` — the chain head always exists by the
    // time the checks below run.
    let block_number =
        revm::context_interface::Block::number(revm::context_interface::ContextTr::block(ctx))
            .to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // 1. Block must exist (rskj `getBlockKeepingTestnetConsensus`, which at
    //    testnet's block #5,148,285 answers a hard-coded block).
    let block_hash =
        b256_to_bitcoin_hash(&alloy_primitives::B256::from(block_hash_bytes));
    let block = match get_block_keeping_testnet_consensus(ctx, config, &block_hash) {
        Some(b) => b,
        None => {
            return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_INEXISTENT_BLOCK_HASH))
        }
    };

    let best_chain_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);

    // 2. Too deep. `Math.max(0, bestChainHeight - block.getHeight())`, so a
    //    block ABOVE the head has depth 0 and passes here — it is rejected by
    //    the best-chain check below, with a different code.
    let block_depth = best_chain_height.saturating_sub(block.height);
    // rskj `BridgeSupport.BTC_TRANSACTION_CONFIRMATION_MAX_DEPTH` = 4320,
    // held in BridgeConstants here so the gas estimate
    // (`btc_tx_confirmations_cost`) and the result cannot drift apart.
    if block_depth > config.btc_transaction_confirmation_max_depth {
        return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BLOCK_TOO_OLD));
    }

    // 3. The block must be the one the main chain holds at its height — a
    //    block on an orphaned fork is stored, and confirming a transaction
    //    from it would be exactly the double-spend this check prevents.
    //    rskj's null return maps to -2, its BlockStoreException to -3.
    match super::btc_chain::main_chain_block_at_height(ctx, block.height, rskip199, Some(config)) {
        super::btc_chain::MainChainLookup::Found(main) => {
            // bitcoinj `StoredBlock.equals`: header, chainWork and height.
            let same = main.header.block_hash() == block.header.block_hash()
                && main.height == block.height
                && main.chain_work == block.chain_work;
            if !same {
                return Ok(encode_int_output(
                    gas_cost,
                    CONFIRMATION_ERR_BLOCK_NOT_IN_BEST_CHAIN,
                ));
            }
        }
        super::btc_chain::MainChainLookup::Absent => {
            return Ok(encode_int_output(
                gas_cost,
                CONFIRMATION_ERR_BLOCK_NOT_IN_BEST_CHAIN,
            ))
        }
        super::btc_chain::MainChainLookup::StoreError => {
            return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_INCONSISTENT_BLOCK))
        }
    }

    // 4. The branch must climb to the block's merkle root or, from RSKIP143,
    //    to the witness merkle root registered for the block (rskj
    //    `isBlockMerkleRootValid`). rskj holds all of them in display order:
    //    the branch and the transaction as the ABI gives them, the header's
    //    root as bitcoinj reads it, and the witness root as
    //    `registerBtcCoinbaseTransaction` stored it. Two branch nodes that
    //    form a 64-byte transaction make rskj's `combineLeftRight` throw,
    //    which fails the call.
    let computed_root = branch.reduce_from(&tx_hash).ok_or_else(|| {
        PrecompileError::other(
            "getBtcTransactionConfirmations: two branch nodes form a transaction",
        )
    })?;
    let block_merkle_root = {
        let mut root = *block.header.merkle_root.to_raw_hash().as_byte_array();
        root.reverse();
        root
    };
    let root_valid = computed_root == block_merkle_root
        || get_coinbase_information(ctx, &block_hash_bytes)
            .is_some_and(|witness_root| witness_root == computed_root);
    if !root_valid {
        return Ok(encode_int_output(
            gas_cost,
            CONFIRMATION_ERR_INVALID_MERKLE_BRANCH,
        ));
    }

    // `bestChainHeight - block.getHeight() + 1`. Step 3 guarantees the block
    // is at or below the head, so this is >= 1.
    Ok(encode_int_output(gas_cost, block_depth as i64 + 1))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the BTC transaction hash (double-SHA256 of raw tx bytes).
/// Returns the hash in internal byte order (same as bitcoinj's Sha256Hash).
///
/// This is rskj `BtcTransactionFormatUtils.calculateBtcTxHash`
/// (`hashTwice(btcTxSerialized)`): it hashes the bytes AS SUPPLIED, so for a
/// SegWit-serialized tx it yields the wtxid. rskj uses this hash for PMT
/// matching and merkle-root validation (BridgeSupport.registerBtcTransaction
/// l.385, validationsForRegisterBtcTransaction). The btcTxHashesAlreadyProcessed
/// map instead keys by the witness-stripped txid `btcTx.getHash(false)` — see
/// `legacy_btc_txid`.
pub fn calculate_btc_tx_hash(tx_bytes: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(tx_bytes);
    *hash.as_byte_array()
}

/// The witness-stripped BTC txid (bitcoinj `BtcTransaction.getHash(false)`),
/// in internal byte order. For non-SegWit txs this equals
/// `calculate_btc_tx_hash`; for SegWit txs the raw bytes carry the
/// marker/flag and witness stack, so the two differ. rskj marks/looks up
/// peg-ins in btcTxHashesAlreadyProcessed by THIS hash
/// (BridgeSupport.registerBtcTransaction l.404, l.763).
pub fn legacy_btc_txid(tx: &bitcoin::Transaction) -> [u8; 32] {
    *tx.compute_txid().to_raw_hash().as_byte_array()
}

/// Witness-commitment header (BIP141), rskj `BitcoinUtils.WITNESS_COMMITMENT_HEADER`.
const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
/// `OP_RETURN` opcode.
const OP_RETURN: u8 = 0x6a;
/// 4-byte header + 32-byte commitment hash (rskj `WITNESS_COMMITMENT_LENGTH`).
const WITNESS_COMMITMENT_LENGTH: u8 = 36;
/// Minimum scriptPubKey size: `OP_RETURN` + push-length byte + 36-byte payload
/// (rskj `BitcoinUtils.MINIMUM_WITNESS_COMMITMENT_SIZE`).
const MINIMUM_WITNESS_COMMITMENT_SIZE: usize = 38;

/// Find the witness commitment hash embedded in a coinbase transaction's
/// outputs, mirroring rskj `BitcoinUtils.findWitnessCommitment`
/// (rskj-core .../peg/bitcoin/BitcoinUtils.java l.309-365).
///
/// The commitment lives in an output whose scriptPubKey is
/// `OP_RETURN <push 36> aa21a9ed <32-byte commitment>`. If several such
/// outputs exist, BIP141 takes the LAST one, so rskj iterates the outputs
/// reversed and returns the first match. Returns the 32-byte commitment in
/// internal byte order (bitcoinj `Sha256Hash.wrap`).
///
/// Before RSKIP460 rskj reads each script with `getScriptPubKey().getProgram()`,
/// which answers the same bytes but first parses them, and throws a
/// `ScriptException` for a script bitcoinj can't parse: the `Err`. The scan
/// stops at the commitment, so outputs before it are never parsed.
fn find_witness_commitment(
    tx: &bitcoin::Transaction,
    before_rskip460: bool,
) -> Result<Option<[u8; 32]>, &'static str> {
    for out in tx.output.iter().rev() {
        let spk = out.script_pubkey.as_bytes();
        if before_rskip460 && !super::rskj_sender_compat::parses_as_script(spk) {
            return Err(
                "registerBtcCoinbaseTransaction: ScriptException parsing an output's script",
            );
        }
        if spk.len() >= MINIMUM_WITNESS_COMMITMENT_SIZE
            && spk[0] == OP_RETURN
            && spk[1] == WITNESS_COMMITMENT_LENGTH
            && spk[2..6] == WITNESS_COMMITMENT_HEADER
        {
            return Ok(spk[6..MINIMUM_WITNESS_COMMITMENT_SIZE].try_into().ok());
        }
    }
    Ok(None)
}

/// bitcoinj `BtcBlock.MAX_BLOCK_SIZE`, which `BtcTransaction.verify()` holds a
/// transaction's serialized size to.
const MAX_BLOCK_SIZE: usize = 1_000_000;

/// bitcoinj `NetworkParameters.MAX_MONEY`, in satoshis.
const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// bitcoinj `BtcTransaction.verify()`. Every failure is an exception
/// `Bridge.execute` rethrows. `serialized_size` is the transaction's
/// `getMessageSize()`: the bytes it was parsed from.
fn verify_btc_transaction(
    tx: &bitcoin::Transaction,
    serialized_size: usize,
) -> Result<(), &'static str> {
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err("bitcoinj verify: no inputs or no outputs");
    }
    if serialized_size > MAX_BLOCK_SIZE {
        return Err("bitcoinj verify: larger than a block");
    }
    let mut outpoints = std::collections::HashSet::new();
    if !tx
        .input
        .iter()
        .all(|input| outpoints.insert(input.previous_output))
    {
        return Err("bitcoinj verify: an outpoint spent twice");
    }
    // bitcoinj reads a value as a signed 64-bit number, and holds the running
    // sum to the 21 million bitcoins after each output.
    let mut value_out: i64 = 0;
    for output in &tx.output {
        let value = output.value.to_sat() as i64;
        if value < 0 {
            return Err("bitcoinj verify: a negative output value");
        }
        value_out = match value_out.checked_add(value) {
            Some(sum) if sum <= MAX_MONEY => sum,
            _ => return Err("bitcoinj verify: more output value than there is money"),
        };
    }
    if tx.is_coinbase() {
        if !(2..=100).contains(&tx.input[0].script_sig.len()) {
            return Err("bitcoinj verify: coinbase script size out of range");
        }
    } else if tx.input.iter().any(|input| input.previous_output.is_null()) {
        return Err("bitcoinj verify: a coinbase input in a transaction that isn't one");
    }
    Ok(())
}

fn encode_int_output(gas_cost: u64, value: i64) -> PrecompileOutput {
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
    fn btc_tx_hash_known_vector() {
        // A simple test: hash of empty tx data should be double-sha256 of empty
        let hash = calculate_btc_tx_hash(&[]);
        let expected = sha256d::Hash::hash(&[]);
        assert_eq!(hash, *expected.as_byte_array());
    }

    #[test]
    fn btc_tx_hash_deterministic() {
        let data = vec![0x01, 0x00, 0x00, 0x00];
        let h1 = calculate_btc_tx_hash(&data);
        let h2 = calculate_btc_tx_hash(&data);
        assert_eq!(h1, h2);
    }

    /// Ground truth ported from rskj BtcTransactionFormatUtilsTest.calculateBtcTxHash:
    /// `calculate_btc_tx_hash` hashes the raw bytes as supplied (rskj
    /// `BtcTransactionFormatUtils.calculateBtcTxHash = hashTwice(serialized)`).
    /// rskj asserts the DISPLAY-order hash 4d63ac30…151576; our internal-order
    /// result is its reverse.
    #[test]
    fn calculate_btc_tx_hash_legacy_vector() {
        let hex_str = "020000000418bc858998739dbb7e7676435178dba5e71157b1537d415518d5c1fce6349018000000006a47304402204317903e40f8736858f87758e68bf18372bc075bc928fd82aa8e6c03ae8ce9fb022074a59d7449cc753c5a6b10e70db20469076e2a8b950aa44624ee7ff70633f732012103161014902a3984b695c41627f1403f56b0e631152ff265ddb42e36ba0d57b796feffffff6b853f36edb3a55c419792d3923790147b3c429bb6082d11846ff563edcdae05010000006b483045022100e202a463722821875bcecea315041623b4f4b7c615bc63c85ddcb4185035cc0502201beb9c556c1a672d326e66c4d4b44ac189b7f3296c5ce6128bf9e52f96cfcabc012103a6ba50eaba8d2fc9a638123cf3fe155610cf162253e8cf672f70945fe00fd317feffffffac932fbdbb882a3947652710b6c9117729962efb30f77779265436f804a5f4bc010000006b483045022100ddc4be4b2d61eb6bdecbb76002cc85c304630465807039f7c9eaf5583d5c6cce02203bc3dc7429a17a92c63b6ec517d82f3964beda7f3c375a388c0326e3db3a455101210366d0e8c0c72ea7e8a48ae9fe525fb51bcea39702b9ba2903758a582e26a7d0b9feffffffe89b208401d4eb6fc01deef1393fe00c1f56e2b86b77268629491894f560adb6010000006b483045022100ac01733d947bf43ad97a5792864766c6c6d9963e359a6e0ab470b68565d679b6022003d4afeb917e7711e797b665f5a95893dea2f53d07e2840b6441a72702f88412012102b005a7d4368c02dc8e5f171765db281f546b99b921eac18b2910c82d38f820f7feffffff02441427010000000017a914056bce3306ec98a0247cebb654809943045d6b51877ff21500000000001976a914f7da7f0f7669bce303cfc48921bb7303e3918b1288acdfdc0700";
        let raw = hex::decode(hex_str).unwrap();
        let mut expected_display =
            hex::decode("4d63ac307e0daba3597a0d8075facb4e6cba3908a60920259b7447e28a151576").unwrap();
        expected_display.reverse(); // display -> internal
        assert_eq!(calculate_btc_tx_hash(&raw).to_vec(), expected_display);
    }

    /// RSK Mainnet block #3,231,219 tx[2]: a SegWit-serialized peg-in. rskj
    /// `BtcTransactionFormatUtils.calculateBtcTxHash` hashes the raw bytes
    /// (wtxid) for PMT matching, while `btcTx.getHash(false)` (= our
    /// `legacy_btc_txid`) strips the witness for the
    /// btcTxHashesAlreadyProcessed map. The two MUST differ for a SegWit tx.
    /// Ground truth: the legacy txid (display order 124f95f3…f09b7e) is the
    /// UTXO hash rskj appended to newFederationBtcUTXOs in that block.
    #[test]
    fn segwit_pegin_wtxid_vs_legacy_txid() {
        let raw = hex::decode(
            "01000000000102ad5193f8f5af5fa13b9555811ae1de6e08e7c65801cb731a79ff445abd1b5061000000006a473044\
             02206dd90517b2b462b1edf9592cdc75d5b10196c275e39cb22fc63c053c57f001dd02203594e7c41258948f40f4bf3\
             f5628cfefac04adb639da5a227fca772f33ab83a30121037975b80b0275420aa52cad67dff83a26c9fc398f5e7698c5\
             014bb5a6937c17c0ffffffff706fce5df32d6c0f1c3a770282d80a2f3d96809cacb488476d70a0a41e8f12580000000\
             000ffffffff0241420f000000000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a873b6a1700000000001\
             976a914935fe65e138f8cc6d5aa72801aebe59f78d7289f88ac00024730440220660b129d3f75041c30b5a8d51b41b4\
             d13b07818cfe5e3274ddad39bdea3b2d2e02205ab94a07c9a13a4419d8f07edcca45ab7006c1fdd8d35d903d2a1a2a7\
             9799f40012102240177f45453feca344644d99a285ab33674d3eaa5fb0ae3e17d10b08f85d6e200000000",
        )
        .unwrap();
        // wtxid (raw double-SHA256, internal order).
        let mut expected_wtxid =
            hex::decode("cfe20fb72fd2d39bb59f6b89da3dea74733f4f9710192cd19431dfdb95620897").unwrap();
        expected_wtxid.reverse();
        assert_eq!(calculate_btc_tx_hash(&raw).to_vec(), expected_wtxid);

        // legacy txid (witness stripped, internal order).
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let mut expected_txid =
            hex::decode("124f95f3c6f1a52918077550997fd68df3402ad51e97414fac9e23a029f09b7e").unwrap();
        expected_txid.reverse();
        assert_eq!(legacy_btc_txid(&tx).to_vec(), expected_txid);

        // The whole point: for a SegWit tx the two hashes differ.
        assert_ne!(calculate_btc_tx_hash(&raw), legacy_btc_txid(&tx));
    }

    /// Ground truth from RSK Mainnet block #3,229,522 (registerBtcCoinbaseTransaction):
    /// rskj keys coinbase information by `DataWord.fromLongString("coinbaseInformation-" +
    /// Sha256Hash.wrap(blockHashArg).toString())`, and bitcoinj's `toString()` hex-encodes
    /// the wrapped bytes WITHOUT reversing. The block-hash ABI arg below is the exact one
    /// from that block; the expected DataWord is the storage slot read from rskj's own unitrie.
    #[test]
    fn coinbase_information_storage_key_mainnet() {
        let block_hash: [u8; 32] =
            hex::decode("0000000000000000000b718fb9d9d0c032cbfbebae6e3f99da00a131a7433fe4")
                .unwrap()
                .try_into()
                .unwrap();
        let key = compound_key(COINBASE_INFORMATION_KEY, "-", &to_hex(&block_hash));
        let expected = U256::from_be_bytes(
            <[u8; 32]>::try_from(
                hex::decode("4e92fd4d2d1f5769b361ef086f963fea4d74d700b5544f67b5a9a2c587fd3f2f")
                    .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(key, expected, "coinbase storage key must match rskj (no hash reversal)");
    }

    /// Ground truth ported from rskj `BridgeSupportTest.registerBtcCoinbaseTransaction`
    /// (rskj-core .../peg/BridgeSupportTest.java l.6597-6681). The coinbase tx below
    /// carries a witness commitment in its zero-value OP_RETURN output:
    /// `6a24 aa21a9ed <commitment>`. rskj asserts
    /// `Sha256Hash.twiceOf(witnessRoot.getReversedBytes(), witnessReservedValue) == witCom`,
    /// then stores the coinbase info. This proves both the extraction rule and the
    /// witnessMerkleRoot reversal — and guards against rejecting valid registrations.
    #[test]
    fn register_btc_coinbase_witness_commitment_positive() {
        // The exact coinbase tx rawTx from the rskj test (SegWit-serialized).
        let raw_tx = hex::decode(
            "020000000001010000000000000000000000000000000000000000000000000000000000000000ff\
             ffffff0502cc000101ffffffff029c070395000000002321036d6b5bc8c0e902f296b5bdf3dfd4b6\
             f095d8d0987818a557e1766ea25c664524ac0000000000000000266a24aa21a9edfeb3b9170ae765\
             cc6586edd67229eaa8bc19f9674d64cb10ee8a205f4ccf0bc60120000000000000000000000000000\
             000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();

        // The embedded commitment (32 bytes after the aa21a9ed header), internal order.
        let expected = find_witness_commitment(&tx, false)
            .unwrap()
            .expect("coinbase has a witness commitment");
        assert_eq!(
            to_hex(&expected),
            "feb3b9170ae765cc6586edd67229eaa8bc19f9674d64cb10ee8a205f4ccf0bc6"
        );

        // witnessMerkleRoot ABI arg, display order (bitcoinj Sha256Hash.wrap):
        // = MerkleTreeUtils.combineLeftRight(ZERO_HASH, secondHashTx) from the rskj test.
        let witness_merkle_root: [u8; 32] =
            hex::decode("613cb22535df8d9443fe94b66d807cd60312f982e305e25e825b00e6f429799f")
                .unwrap()
                .try_into()
                .unwrap();
        // witnessReservedValue = the input-0 witness push (32 zero bytes).
        let witness_reserved_value = [0u8; 32];

        // The fix: hash reversed(witnessMerkleRoot) || witnessReservedValue.
        let mut commitment_data = [0u8; 64];
        commitment_data[..32].copy_from_slice(&witness_merkle_root);
        commitment_data[..32].reverse();
        commitment_data[32..].copy_from_slice(&witness_reserved_value);
        let calculated = *sha256d::Hash::hash(&commitment_data).as_byte_array();

        assert_eq!(calculated, expected, "valid commitment must match -> info IS stored");
    }

    /// Negative case: a witnessMerkleRoot that does not produce the embedded
    /// commitment must NOT match — rskj throws (no store).
    #[test]
    fn register_btc_coinbase_witness_commitment_negative() {
        let raw_tx = hex::decode(
            "020000000001010000000000000000000000000000000000000000000000000000000000000000ff\
             ffffff0502cc000101ffffffff029c070395000000002321036d6b5bc8c0e902f296b5bdf3dfd4b6\
             f095d8d0987818a557e1766ea25c664524ac0000000000000000266a24aa21a9edfeb3b9170ae765\
             cc6586edd67229eaa8bc19f9674d64cb10ee8a205f4ccf0bc60120000000000000000000000000000\
             000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        let expected = find_witness_commitment(&tx, false).unwrap().unwrap();

        // Tweak the last byte of the witness merkle root -> commitment must differ.
        let mut witness_merkle_root: [u8; 32] =
            hex::decode("613cb22535df8d9443fe94b66d807cd60312f982e305e25e825b00e6f429799f")
                .unwrap()
                .try_into()
                .unwrap();
        witness_merkle_root[31] ^= 0x01;

        let mut commitment_data = [0u8; 64];
        commitment_data[..32].copy_from_slice(&witness_merkle_root);
        commitment_data[..32].reverse();
        let calculated = *sha256d::Hash::hash(&commitment_data).as_byte_array();

        assert_ne!(calculated, expected, "mismatching commitment must be rejected");
    }

    /// rskj's `registerBtcCoinbaseTransaction` seeds the BTC store before
    /// anything else (`ensureBtcBlockStore`), so a store nothing has seeded
    /// yet is seeded even by a call that then registers nothing, as one whose
    /// transaction isn't in its tree.
    #[test]
    fn a_coinbase_registration_seeds_an_empty_store_first() {
        use crate::abi::encode::{self, Arg};
        use revm::MainContext;
        let config = super::super::constants::BridgeConstants::mainnet();
        let cfg = crate::hardfork::RskHardforkConfig::mainnet();
        let mut ctx =
            revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());
        // A tree of one transaction, not the one sent.
        let mut pmt = 1u32.to_le_bytes().to_vec();
        pmt.push(1);
        pmt.extend_from_slice(&[0xaa; 32]);
        pmt.extend_from_slice(&[1, 0x01]);
        let args = encode::args(&[
            Arg::Bytes(&[]),
            Arg::Word([0x11; 32]),
            Arg::Bytes(&pmt),
            Arg::Word([0; 32]),
            Arg::Word([0; 32]),
        ]);

        let out = register_btc_coinbase_transaction(&mut ctx, &args, 0, &config, &cfg).unwrap();
        assert!(out.bytes.is_empty(), "registered nothing");
        assert_eq!(
            load_chain_head(&mut ctx).map(|head| head.height),
            Some(config.btc_checkpoint.unwrap().1)
        );
    }

    /// The witness root the registrations below name, as the ABI carries it.
    const WITNESS_ROOT: [u8; 32] = [0x77; 32];

    /// The output that commits to `WITNESS_ROOT` with a reserved value of zeros.
    fn commitment_output() -> bitcoin::TxOut {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&WITNESS_ROOT);
        preimage[..32].reverse();
        let mut script = vec![OP_RETURN, WITNESS_COMMITMENT_LENGTH];
        script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        script.extend_from_slice(sha256d::Hash::hash(&preimage).as_byte_array());
        output(0, script)
    }

    fn output(sats: u64, script: Vec<u8>) -> bitcoin::TxOut {
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(sats),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
        }
    }

    /// A serialized transaction of one input, which spends `previous_output`.
    fn one_input_tx(
        previous_output: bitcoin::OutPoint,
        script_sig: Vec<u8>,
        output: Vec<bitcoin::TxOut>,
    ) -> Vec<u8> {
        bitcoin::consensus::serialize(&bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output,
                script_sig: bitcoin::ScriptBuf::from_bytes(script_sig),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output,
        })
    }

    fn coinbase(script_sig: Vec<u8>, output: Vec<bitcoin::TxOut>) -> Vec<u8> {
        one_input_tx(bitcoin::OutPoint::null(), script_sig, output)
    }

    /// Calls `registerBtcCoinbaseTransaction` at mainnet's `block_number` with
    /// `raw_tx` as the only transaction of a stored Bitcoin block, naming
    /// `WITNESS_ROOT`. Answers whether the call returned, and whether it stored
    /// the block's coinbase information.
    fn register_sole_transaction(raw_tx: &[u8], block_number: u64) -> (bool, bool) {
        use crate::abi::encode::{self, Arg};
        use revm::MainContext;
        let config = super::super::constants::BridgeConstants::mainnet();
        let cfg = crate::hardfork::RskHardforkConfig::mainnet();
        let mut ctx =
            revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());
        ctx.block.number = U256::from(block_number);

        let tx_hash = calculate_btc_tx_hash(raw_tx);
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(tx_hash),
            time: 1_700_000_000,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 0,
        };
        let block = super::super::btc_store::StoredBlock::new(header, 800_000, U256::from(1));
        super::super::btc_store::put_stored_block(
            &mut ctx,
            &block,
            cfg.has_stored_block_v2(block_number),
        );
        let mut block_hash = block.block_hash().to_byte_array();
        block_hash.reverse();

        // A tree of the one transaction: its hash is the root.
        let mut pmt = 1u32.to_le_bytes().to_vec();
        pmt.push(1);
        pmt.extend_from_slice(&tx_hash);
        pmt.extend_from_slice(&[1, 0x01]);
        let args = encode::args(&[
            Arg::Bytes(raw_tx),
            Arg::Word(block_hash),
            Arg::Bytes(&pmt),
            Arg::Word(WITNESS_ROOT),
            Arg::Word([0; 32]),
        ]);

        let returned = register_btc_coinbase_transaction(&mut ctx, &args, 0, &config, &cfg).is_ok();
        (returned, has_coinbase_information(&mut ctx, &block_hash))
    }

    /// Mainnet heights on either side of lovell700 (7,338,024), where RSKIP460
    /// activates.
    const BEFORE_RSKIP460: u64 = 7_000_000;
    const AFTER_RSKIP460: u64 = 7_400_000;

    const REGISTERED: (bool, bool) = (true, true);
    const THROWN: (bool, bool) = (false, false);

    #[test]
    fn a_coinbase_whose_commitment_matches_is_registered() {
        let tx = coinbase(
            vec![0x51, 0x51],
            vec![output(50, vec![0x51]), commitment_output()],
        );
        assert_eq!(register_sole_transaction(&tx, BEFORE_RSKIP460), REGISTERED);
        assert_eq!(register_sole_transaction(&tx, AFTER_RSKIP460), REGISTERED);
    }

    /// rskj's `findWitnessCommitment` opens with
    /// `Preconditions.checkState(tx.isCoinBase())`. Without it any transaction
    /// of a block could name the block's witness root, with an output that
    /// looks like a commitment, and a peg-in nobody made could then be proved
    /// against that root.
    #[test]
    fn a_transaction_that_is_not_a_coinbase_names_no_witness_root() {
        let spends = |previous_output| {
            one_input_tx(previous_output, vec![0x51, 0x51], vec![commitment_output()])
        };
        let payment = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xaa; 32]),
            vout: 0,
        };
        // A null hash with any index but 0xffffffff isn't a coinbase's either.
        let null_hash = bitcoin::OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        for block_number in [BEFORE_RSKIP460, AFTER_RSKIP460] {
            assert_eq!(
                register_sole_transaction(&spends(payment), block_number),
                THROWN
            );
            assert_eq!(
                register_sole_transaction(&spends(null_hash), block_number),
                THROWN
            );
        }
    }

    /// rskj runs bitcoinj's `BtcTransaction.verify()` on the transaction before
    /// it looks for the commitment. Each row was run through bitcoinj-thin
    /// `0.14.4-rsk-18`, which threw the exception named.
    #[test]
    fn a_coinbase_bitcoinj_does_not_verify_is_refused() {
        let commits = |script_sig: Vec<u8>, first: bitcoin::TxOut| {
            coinbase(script_sig, vec![first, commitment_output()])
        };
        let max_money = 21_000_000 * 100_000_000u64;
        let refused = [
            // CoinbaseScriptSizeOutOfRange: 2 to 100 bytes.
            commits(vec![0x51], output(50, vec![0x51])),
            commits(vec![0x51; 101], output(50, vec![0x51])),
            // NegativeValueOutput: the value is a signed 64-bit number.
            commits(vec![0x51, 0x51], output(u64::MAX, vec![0x51])),
            // ExcessiveValue: more than 21 million bitcoins.
            commits(vec![0x51, 0x51], output(max_money + 1, vec![0x51])),
            // LargerThanMaxBlockSize: over 1,000,000 bytes serialized.
            commits(vec![0x51, 0x51], output(50, vec![0x51; 1_000_000])),
        ];
        for tx in &refused {
            assert_eq!(register_sole_transaction(tx, AFTER_RSKIP460), THROWN);
        }

        let accepted = [
            commits(vec![0x51; 100], output(50, vec![0x51])),
            commits(vec![0x51, 0x51], output(max_money, vec![0x51])),
        ];
        for tx in &accepted {
            assert_eq!(register_sole_transaction(tx, AFTER_RSKIP460), REGISTERED);
        }
    }

    /// Before RSKIP460 rskj reads each output's script with
    /// `getScriptPubKey().getProgram()`, which throws a `ScriptException` for
    /// one bitcoinj can't parse. It reads them last to first and stops at the
    /// commitment, so only an output after the commitment is reached.
    #[test]
    fn before_rskip460_a_script_bitcoinj_cannot_parse_is_refused() {
        // OP_PUSHDATA1 with no length byte after it.
        let unparseable = || output(1, vec![0x4c]);
        let after_the_commitment =
            coinbase(vec![0x51, 0x51], vec![commitment_output(), unparseable()]);
        assert_eq!(
            register_sole_transaction(&after_the_commitment, BEFORE_RSKIP460),
            THROWN
        );
        assert_eq!(
            register_sole_transaction(&after_the_commitment, AFTER_RSKIP460),
            REGISTERED
        );

        let before_the_commitment =
            coinbase(vec![0x51, 0x51], vec![unparseable(), commitment_output()]);
        assert_eq!(
            register_sole_transaction(&before_the_commitment, BEFORE_RSKIP460),
            REGISTERED
        );
        assert_eq!(
            register_sole_transaction(&before_the_commitment, AFTER_RSKIP460),
            REGISTERED
        );
    }

    /// `find_witness_commitment` must take the LAST matching output (BIP141 / rskj
    /// `findWitnessCommitment` iterates outputs reversed) and ignore non-commitment
    /// outputs.
    #[test]
    fn find_witness_commitment_takes_last() {
        use bitcoin::{ScriptBuf, Sequence, TxIn, TxOut, Witness, Amount, OutPoint};
        use bitcoin::transaction::Version;
        use bitcoin::absolute::LockTime;

        let commitment_a = [0x11u8; 32];
        let commitment_b = [0x22u8; 32];
        let mk = |c: &[u8; 32]| {
            let mut spk = vec![OP_RETURN, WITNESS_COMMITMENT_LENGTH];
            spk.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
            spk.extend_from_slice(c);
            TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) }
        };
        let tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                // a normal payment output (no commitment)
                TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]) },
                mk(&commitment_a),
                mk(&commitment_b),
            ],
        };
        // Parsing the scripts first, as before RSKIP460, finds the same one.
        assert_eq!(find_witness_commitment(&tx, false), Ok(Some(commitment_b)));
        assert_eq!(find_witness_commitment(&tx, true), Ok(Some(commitment_b)));
    }

    /// Ground truth: rskj `BridgeSupport.java:90-94`. These integers are the
    /// method's public contract — every caller branches on them — so a client
    /// that renumbers them forks even when its logic is right. rustock used to
    /// return -2 for a bad merkle branch (rskj: -5), reserved -3 for "too old"
    /// (rskj: -4) and invented -4 for "BTC chain not ready", which rskj has no
    /// code for because `ensureBtcBlockChain` guarantees a chain head.
    #[test]
    fn btc_transaction_confirmation_codes_match_rskj() {
        assert_eq!(CONFIRMATION_ERR_INEXISTENT_BLOCK_HASH, -1);
        assert_eq!(CONFIRMATION_ERR_BLOCK_NOT_IN_BEST_CHAIN, -2);
        assert_eq!(CONFIRMATION_ERR_INCONSISTENT_BLOCK, -3);
        assert_eq!(CONFIRMATION_ERR_BLOCK_TOO_OLD, -4);
        assert_eq!(CONFIRMATION_ERR_INVALID_MERKLE_BRANCH, -5);

        // BridgeSupport.java:104. The gas estimate and the result must use the
        // same bound, or a call can be priced as shallow and answered as deep.
        for c in [
            super::super::constants::BridgeConstants::mainnet(),
            super::super::constants::BridgeConstants::testnet(),
            super::super::constants::BridgeConstants::regtest(),
        ] {
            assert_eq!(c.btc_transaction_confirmation_max_depth, 4320);
        }
    }
}
