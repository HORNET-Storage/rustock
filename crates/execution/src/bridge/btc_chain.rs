//! BTC header chain validation for the Bridge.
//!
//! Implements `receiveHeader` and `receiveHeaders` — the methods that allow
//! relayers to submit BTC block headers to the Bridge contract, building
//! an SPV header chain in contract storage.
//!
//! Error codes (matching rskj `BridgeSupport.java:96-100` and
//! `Bridge.java:243`):
//! -   0: success
//! -  -1: called too soon (RSKIP200 rate limiting)
//! -  -2: block too old
//! -  -3: previous block not found
//! -  -4: block previously saved
//! - -20: header size mismatch (returned by `Bridge`, not `BridgeSupport`)
//! - -99: unexpected exception

use alloy_primitives::{Bytes, U256};
use bitcoin::block::Header as BtcHeader;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::BlockHash;
use revm::context_interface::{Block as BlockTr, ContextTr};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::btc_rules::{check_difficulty_transitions, verify_header};
use super::btc_store::{
    compute_work, get_stored_block, load_chain_head, put_stored_block, store_chain_head,
    StoredBlock,
};
use super::constants::{BridgeConstants, BtcNetwork};
use crate::hardfork::RskHardforkConfig;

// receiveHeader result codes — must match rskj BridgeSupport exactly
// (BridgeSupport.java:96-100). A from-scratch client that picked its own
// codes (e.g. SUCCESS=1) would fork because callers branch on these values.
const SUCCESS: i64 = 0;
const ERR_TOO_SOON: i64 = -1;
const ERR_BLOCK_TOO_OLD: i64 = -2;
const ERR_PREV_NOT_FOUND: i64 = -3;
const ERR_ALREADY_KNOWN: i64 = -4;
const ERR_UNEXPECTED_EXCEPTION: i64 = -99;
/// rskj `Bridge.RECEIVE_HEADER_ERROR_SIZE_MISTMATCH` (Bridge.java:243).
/// Unlike the codes above this one is produced by `Bridge.receiveHeader`
/// itself, before `BridgeSupport` is reached, and is *returned* — the call
/// succeeds and the caller sees -20 on the stack.
const ERR_SIZE_MISMATCH: i64 = -20;

/// rskj `BtcTransactionFormatUtils.isBlockHeaderSize`: exactly 80 bytes once
/// RSKIP124 is active, otherwise 80..=85 (bitcoinj's `makeBlock` tolerated a
/// trailing transaction-count varint).
fn is_block_header_size(size: usize, rskip124: bool) -> bool {
    const MIN_BLOCK_HEADER_SIZE: usize = 80;
    const MAX_BLOCK_HEADER_SIZE: usize = 85;
    if rskip124 {
        size == MIN_BLOCK_HEADER_SIZE
    } else {
        (MIN_BLOCK_HEADER_SIZE..=MAX_BLOCK_HEADER_SIZE).contains(&size)
    }
}

/// Process a single BTC header submitted via `receiveHeader(bytes)`.
///
/// Returns ABI-encoded int256 result code.
pub fn receive_header<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    // `gas_cost` is rskj `Bridge.getGasForData` = RECEIVE_HEADER functionCost
    // (10_600) + `data.length * 2` (Bridge.java:296-321). The data cost must be
    // included: charging only the bare 10_600 undercharged every receiveHeader
    // call by `2 * input.len()` (mainnet #6,223,762 tx[2]: 2*164 = 328 gas).
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    let header_bytes = crate::abi::Args::new(args)
        .bytes(0)
        .ok_or_else(|| PrecompileError::other("receiveHeader: invalid ABI encoding"))?;

    // Deserialize BTC header (80 bytes). rskj has already parsed the header
    // (Bridge.receiveHeader takes a BtcBlock) by this point, so the order of
    // checks below mirrors BridgeSupport.receiveHeader (BridgeSupport.java:227).
    // rskj `Bridge.receiveHeader` size gate (Bridge.java:573-576). A wrong
    // size is NOT an exception: it returns -20 and the call succeeds. rustock
    // used to raise a precompile error for anything under 80 bytes and to
    // silently truncate anything over — both fork from rskj, which rejects
    // 81 bytes just as firmly as it rejects 79.
    if !is_block_header_size(header_bytes.len(), hardfork_cfg.has_rskip124(block_number)) {
        return Ok(encode_int_result(gas_cost, ERR_SIZE_MISMATCH));
    }

    let btc_header: BtcHeader = deserialize(&header_bytes[..80])
        .map_err(|_| PrecompileError::other("receiveHeader: invalid BTC header"))?;

    let block_hash = btc_header.block_hash();

    // 1. Already saved? (rskj checks this FIRST, before the time window.)
    if get_stored_block(ctx, &block_hash).is_some() {
        return Ok(encode_int_result(gas_cost, ERR_ALREADY_KNOWN));
    }

    // 2. Called too soon (RSKIP200 rate limit).
    let last_timestamp =
        super::storage::bridge_load_timestamp(ctx, super::storage::RECEIVE_HEADERS_TIMESTAMP_KEY);
    let current_timestamp = ctx.block().timestamp();
    if config.min_seconds_between_calls_receive_header > 0
        && current_timestamp < last_timestamp + config.min_seconds_between_calls_receive_header
    {
        return Ok(encode_int_result(gas_cost, ERR_TOO_SOON));
    }

    // 3. Parent (previous block) must be known.
    let parent = match get_stored_block(ctx, &btc_header.prev_blockhash) {
        Some(p) => p,
        None => return Ok(encode_int_result(gas_cost, ERR_PREV_NOT_FOUND)),
    };

    let new_height = parent.height + 1;

    // 4. Too old: bestChainHeight - newHeight > maxDepthBlockchainAccepted.
    let best_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);
    if (best_height as i64) - (new_height as i64) > config.max_depth_blockchain_accepted as i64 {
        return Ok(encode_int_result(gas_cost, ERR_BLOCK_TOO_OLD));
    }

    // 5. cannotProcessNextBlock: the bitcoinj 12-byte chainwork overflow guard
    // (BridgeSupport.cannotProcessNextBlock). Same gate as receiveHeaders.
    let is_mainnet = matches!(config.btc_network, super::constants::BtcNetwork::Mainnet);
    if new_height >= config.block_with_too_much_chain_work_height
        && is_mainnet
        && !hardfork_cfg.has_rskip434(block_number)
    {
        return Ok(encode_int_result(gas_cost, ERR_UNEXPECTED_EXCEPTION));
    }

    // 6. btcBlockChain.add(header): where bitcoinj throws, rskj answers
    // UNEXPECTED_EXCEPTION.
    if !add(
        ctx,
        &btc_header,
        &parent,
        config.btc_network,
        use_v2,
        rskip199,
    ) {
        return Ok(encode_int_result(gas_cost, ERR_UNEXPECTED_EXCEPTION));
    }

    // Update timestamp (rskj serializeLong -> RLP)
    super::storage::bridge_store_timestamp(
        ctx,
        super::storage::RECEIVE_HEADERS_TIMESTAMP_KEY,
        current_timestamp.to::<u64>(),
    );

    Ok(encode_int_result(gas_cost, SUCCESS))
}

/// bitcoinj `BtcAbstractBlockChain.add`, for a header that isn't stored, on
/// its stored `parent`: the header's target must be in range and its hash
/// under it (`verifyHeader`), and its target the one its parent's chain calls
/// for (`checkDifficultyTransitions`); then it's connected (`connectBlock`).
/// `false` where bitcoinj throws.
fn add<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    header: &BtcHeader,
    parent: &StoredBlock,
    network: BtcNetwork,
    use_v2: bool,
    rskip199: bool,
) -> bool {
    verify_header(header, network)
        && check_difficulty_transitions(ctx, parent, header, network)
        && connect_block(ctx, header, parent, use_v2, rskip199)
}

/// bitcoinj `BtcAbstractBlockChain.connectBlock` in header-only mode
/// (`shouldVerifyTransactions() == false`, which is how the Bridge runs it),
/// for a header that isn't stored, on its stored `parent` (bitcoinj's
/// `storedPrev`). `false` where bitcoinj throws.
///
/// - A header on the head (`storedPrev.equals(chainHead)`) is stored and
///   becomes the head.
/// - Any other is a fork. `findSplit` walks it and the head back to the block
///   they share, and throws where a walk runs out of stored blocks, as it
///   does for a fork from the genesis block on mainnet and testnet, whose
///   stored chain begins at the checkpoint: then nothing is stored.
///   Otherwise the fork is stored, and if it has **strictly more work** than
///   the head (`StoredBlock.moreWorkThan`, so a tie doesn't reorganize),
///   `handleNewBestChain` makes it the head.
///
/// bitcoinj's checkpoint lock-in decides nothing here: mainnet's checkpoints
/// are at heights only a fork from the genesis block reaches, and testnet3
/// and regtest have none.
fn connect_block<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    header: &BtcHeader,
    parent: &StoredBlock,
    use_v2: bool,
    rskip199: bool,
) -> bool {
    // `StoredBlock.build`.
    let stored = StoredBlock::new(
        *header,
        parent.height + 1,
        parent.chain_work.wrapping_add(compute_work(header.bits)),
    );
    let head = match load_chain_head(ctx) {
        Some(head) if head.header.block_hash() != parent.header.block_hash() => head,
        // On the head, or with no head yet (the chain not seeded).
        _ => {
            put_stored_block(ctx, &stored, use_v2);
            set_chain_head(ctx, &stored, use_v2, rskip199);
            return true;
        }
    };
    let Some(split) = find_split(&stored, &head, |hash| get_stored_block(ctx, hash)) else {
        return false;
    };
    if stored.chain_work > head.chain_work {
        handle_new_best_chain(ctx, &stored, &split, use_v2, rskip199)
    } else {
        put_stored_block(ctx, &stored, use_v2);
        true
    }
}

/// bitcoinj `handleNewBestChain`, given the `split` `findSplit` found: every
/// block on the new branch above the split (`getPartialChain`) takes its
/// height in the height->hash main-chain index (`setMainChainBlock`, from
/// RSKIP199), then the new block is stored and becomes the head, which
/// indexes its height again. rustock once indexed the head's height alone,
/// so a reorg deeper than one block left stale entries at the heights below
/// it, in the `btcBlockHeight-<height>` cells. `false` where bitcoinj throws.
fn handle_new_best_chain<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    new_head: &StoredBlock,
    split: &StoredBlock,
    use_v2: bool,
    rskip199: bool,
) -> bool {
    let Some(new_branch) = get_partial_chain(new_head, split, |hash| get_stored_block(ctx, hash))
    else {
        return false;
    };
    if rskip199 {
        for block in new_branch {
            super::storage::bridge_store_btc_block_hash_by_height(
                ctx,
                block.height,
                bitcoin_hash_to_b256(&block.header.block_hash()),
            );
        }
    }
    put_stored_block(ctx, new_head, use_v2);
    set_chain_head(ctx, new_head, use_v2, rskip199);
    true
}

/// bitcoinj `findSplit(newChainHead, oldChainHead, store)`: walk both branches
/// back (by `getPrev`), the higher first, until they meet at the block they
/// share. `get_prev` resolves a block's parent. `None` where a walk runs out
/// of stored blocks, where bitcoinj throws ("Attempt to follow an orphan
/// chain").
fn find_split(
    new_head: &StoredBlock,
    old_head: &StoredBlock,
    mut get_prev: impl FnMut(&BlockHash) -> Option<StoredBlock>,
) -> Option<StoredBlock> {
    let mut current_chain_cursor = old_head.clone();
    let mut new_chain_cursor = new_head.clone();
    while current_chain_cursor.header.block_hash() != new_chain_cursor.header.block_hash() {
        if current_chain_cursor.height > new_chain_cursor.height {
            current_chain_cursor = get_prev(&current_chain_cursor.header.prev_blockhash)?;
        } else {
            new_chain_cursor = get_prev(&new_chain_cursor.header.prev_blockhash)?;
        }
    }
    Some(current_chain_cursor)
}

/// bitcoinj `getPartialChain(higher, lower, store)`: blocks from `higher` down
/// to (but excluding) `lower`, in head→split order. Walks from the in-memory
/// `higher` and resolves its ancestors through `get_prev`. `None` where the
/// walk runs out of stored blocks ("Ran off the end of the chain").
fn get_partial_chain(
    higher: &StoredBlock,
    lower: &StoredBlock,
    mut get_prev: impl FnMut(&BlockHash) -> Option<StoredBlock>,
) -> Option<Vec<StoredBlock>> {
    debug_assert!(higher.height > lower.height, "higher and lower are reversed");
    let mut results = Vec::new();
    let mut cursor = higher.clone();
    loop {
        results.push(cursor.clone());
        cursor = get_prev(&cursor.header.prev_blockhash)?;
        if cursor.header.block_hash() == lower.header.block_hash() {
            return Some(results);
        }
    }
}

/// Update the chain head (rskj `RepositoryBtcBlockStoreWithCache.setChainHead` +
/// `setMainChainBlock`): the height->hash main-chain index only exists from
/// RSKIP199 (iris300).
fn set_chain_head<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    stored: &StoredBlock,
    use_v2: bool,
    rskip199: bool,
) {
    store_chain_head(ctx, stored, use_v2);
    if rskip199 {
        super::storage::bridge_store_btc_block_hash_by_height(
            ctx,
            stored.height,
            bitcoin_hash_to_b256(&stored.header.block_hash()),
        );
    }
}

/// rskj `BtcBlockStoreWithCache.getStoredBlockAtMainChainHeight`: the
/// main-chain block at `height`.
///
/// rskj only persists the height→hash index from RSKIP199 (iris300); before
/// that it WALKS the main chain from the head down `depth = head - height`
/// parents (`getStoredBlockAtMainChainDepth`). We mirror that exactly — the
/// index is empty pre-RSKIP199, so a height lookup must walk. Returns `None`
/// when the height is above the head or the chain cannot be walked to it.
pub fn stored_block_at_main_chain_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    height: u32,
    rskip199: bool,
) -> Option<StoredBlock> {
    match main_chain_block_at_height(ctx, height, rskip199, None) {
        MainChainLookup::Found(b) => Some(b),
        MainChainLookup::Absent | MainChainLookup::StoreError => None,
    }
}

/// The three outcomes rskj's `getStoredBlockAtMainChainHeight` can produce.
///
/// Java distinguishes them by *how* it returns: a `StoredBlock`, `null`, or a
/// thrown `BlockStoreException`. Callers that only care whether a block was
/// found can collapse `Absent` and `StoredError` (see
/// `stored_block_at_main_chain_height`), but `getBtcTransactionConfirmations`
/// maps them to two different error codes (-2 and -3), so the distinction has
/// to survive.
pub enum MainChainLookup {
    Found(StoredBlock),
    /// Java returned `null`: the walk ran off the end of what is stored.
    Absent,
    /// Java threw `BlockStoreException`: the height is above the chain head,
    /// below the RSKIP199 search limit, or the walk landed on a block whose
    /// recorded height disagrees with its depth.
    StoreError,
}

/// rskj `RepositoryBtcBlockStoreWithCache.getStoredBlockAtMainChainHeight`
/// (l.198-244), preserving the null-vs-exception distinction.
///
/// `config` enables the RSKIP199 search-depth limit (l.213-233); pass `None`
/// to skip it, which is what the pre-existing callers did.
pub fn main_chain_block_at_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    height: u32,
    rskip199: bool,
    config: Option<&BridgeConstants>,
) -> MainChainLookup {
    let Some(head) = load_chain_head(ctx) else {
        return MainChainLookup::StoreError;
    };
    if height > head.height {
        // `depth < 0` -> BlockStoreException (l.203-211).
        return MainChainLookup::StoreError;
    }
    let depth = head.height - height;

    // l.213-233: below RSKIP199, blocks older than the search limit are not
    // reachable at all and the lookup throws.
    if rskip199 {
        if let Some(config) = config {
            let index_activation = config.btc_height_when_block_index_activates;
            let max_depth = config.max_depth_to_search_blocks_below_index_activation;
            let limit = if head.height.saturating_sub(index_activation) > max_depth {
                index_activation
            } else {
                head.height.saturating_sub(max_depth)
            };
            if height < limit {
                return MainChainLookup::StoreError;
            }
        }
    }

    // `getInMainchain(height)`: the indexed lookup. Absent for blocks below the
    // index activation, in which case rskj falls back to the walk.
    if rskip199 {
        if let Some(hash) = super::storage::bridge_load_btc_block_hash_by_height(ctx, height) {
            if let Some(block) = get_stored_block(ctx, &b256_to_bitcoin_hash(&hash)) {
                return MainChainLookup::Found(block);
            }
        }
    }

    // Walk `depth` parents down from the head (getStoredBlockAtMainChainDepth,
    // l.271-310). A missing block returns null; a height mismatch throws.
    let mut block_hash = head.header.block_hash();
    for _ in 0..depth {
        match get_stored_block(ctx, &block_hash) {
            Some(b) => block_hash = b.header.prev_blockhash,
            None => return MainChainLookup::Absent,
        }
    }
    match get_stored_block(ctx, &block_hash) {
        None => MainChainLookup::Absent,
        Some(block) if block.height == height => MainChainLookup::Found(block),
        Some(_) => MainChainLookup::StoreError,
    }
}

/// Seed the bridge BTC chain on first use, in rskj's two steps, each of which
/// sets the head. `RepositoryBtcBlockStoreWithCache.checkIfInitialized` makes
/// a store with no head take the BTC GENESIS stored block as its head; then
/// `BridgeSupport.ensureBtcBlockStore` runs bitcoinj's
/// `CheckpointManager.checkpoint` on a store whose head is still the genesis
/// block, which adds the checkpoint block (see
/// `BridgeConstants::btc_checkpoint`) and moves the head to it. BOTH
/// stored-block entries remain in bridge storage (mainnet block #457), and
/// from RSKIP199 both heads are in the height index.
pub fn ensure_btc_chain_seeded<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    use_v2: bool,
    rskip199: bool,
) {
    let head = load_chain_head(ctx);
    // rskj checkpoints a store whose head is still its genesis block, the
    // only block at height 0, so a head above it has been through both steps.
    if head.as_ref().is_some_and(|head| head.height > 0) {
        return;
    }
    if head.is_none() {
        let network = match config.btc_network {
            super::constants::BtcNetwork::Mainnet => bitcoin::Network::Bitcoin,
            super::constants::BtcNetwork::Testnet => bitcoin::Network::Testnet,
            super::constants::BtcNetwork::Regtest => bitcoin::Network::Regtest,
        };
        let genesis = bitcoin::constants::genesis_block(network).header;
        let stored = StoredBlock::new(genesis, 0, compute_work(genesis.bits));
        put_stored_block(ctx, &stored, use_v2);
        set_chain_head(ctx, &stored, use_v2, rskip199);
    }

    let Some((header_hex, height, chain_work_hex)) = config.btc_checkpoint else {
        return;
    };
    let Some(header) = alloy_primitives::hex::decode(header_hex)
        .ok()
        .and_then(|bytes| deserialize::<BtcHeader>(&bytes).ok())
    else {
        return;
    };
    let work =
        U256::from_be_slice(&alloy_primitives::hex::decode(chain_work_hex).unwrap_or_default());
    let checkpoint = StoredBlock::new(header, height, work);
    put_stored_block(ctx, &checkpoint, use_v2);
    set_chain_head(ctx, &checkpoint, use_v2, rskip199);
}

/// rskj `BridgeSupport.ensureBtcBlockStore`, which every Bridge method that
/// reads the BTC chain runs before it reads, whoever calls and whatever the
/// method then answers: a store nothing has seeded yet gets its genesis
/// block and checkpoint ([`ensure_btc_chain_seeded`]), in the block's layout.
pub fn ensure_btc_block_store<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_v2 = hardfork_cfg.has_stored_block_v2(block_number);
    ensure_btc_chain_seeded(ctx, config, use_v2, hardfork_cfg.has_rskip199(block_number));
}

/// Whether bitcoinj's `BtcBlock.parseTransactions` reads `rest`, the at most
/// five bytes that may follow a header's 80 before RSKIP124, as no
/// transactions: nothing at all, or a transaction count of 0 in any of
/// `VarInt`'s widths, after which it reads no further. Any other count asks
/// for transactions that five bytes can't hold (or, above
/// `Integer.MAX_VALUE`, for a list of negative size), and bitcoinj throws.
fn no_transactions_follow(rest: &[u8]) -> bool {
    let zero = |bytes: Option<&[u8]>| bytes.is_some_and(|bytes| bytes.iter().all(|&b| b == 0));
    match rest.first() {
        None => true,
        Some(0xfd) => zero(rest.get(1..3)),
        Some(0xfe) => zero(rest.get(1..5)),
        Some(0xff) => zero(rest.get(1..9)),
        Some(&count) => count == 0,
    }
}

/// rskj `Bridge.receiveHeaders` and `BridgeSupport.receiveHeaders`: every
/// header, in order, through bitcoinj's `add`, each it can't add skipped.
pub fn receive_headers<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let headers = crate::abi::Args::new(args)
        .bytes_array(0)
        .ok_or_else(|| PrecompileError::other("receiveHeaders: invalid ABI encoding"))?;

    // NOTE: rskj's receiveHeaders has NO rate limiting — the
    // minSecondsBetweenCallsToReceiveHeader window only applies to the
    // singular receiveHeader (RSKIP200). The federation calls this every
    // few blocks.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // rskj `Bridge.receiveHeaders` refuses the whole call when any header is
    // not a header's size, before it parses one (Bridge.java:539-544), and
    // then when it can't parse one (`makeBlock`). Both throw
    // `BridgeIllegalArgumentException`, which `Bridge.execute` answers with
    // null before RSKIP88: a success with no output, nothing saved.
    let rskip124 = hardfork_cfg.has_rskip124(block_number);
    let refuse = |why: &'static str| -> Result<PrecompileOutput, PrecompileError> {
        if hardfork_cfg.has_rskip88(block_number) {
            Err(PrecompileError::other(why))
        } else {
            Ok(PrecompileOutput::new(
                gas_cost,
                alloy_primitives::Bytes::new(),
            ))
        }
    };
    if headers
        .iter()
        .any(|header| !is_block_header_size(header.len(), rskip124))
    {
        return refuse("receiveHeaders: a header is not a header's size");
    }
    if headers
        .iter()
        .any(|header| !no_transactions_follow(&header[80..]))
    {
        return refuse("receiveHeaders: a header could not be parsed");
    }

    let rskip434 = hardfork_cfg.has_rskip434(block_number);
    let rskip199 = hardfork_cfg.has_rskip199(block_number);

    ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);
    let is_mainnet = matches!(config.btc_network, super::constants::BtcNetwork::Mainnet);

    // However many there are.
    for header_bytes in &headers {
        let Ok(btc_header) = deserialize::<BtcHeader>(&header_bytes[..80]) else {
            continue;
        };
        // The parent first: with none stored, `cannotProcessNextBlock` throws
        // on it, and rskj skips the header.
        let Some(parent) = get_stored_block(ctx, &btc_header.prev_blockhash) else {
            continue;
        };
        // rskj cannotProcessNextBlock: bitcoinj's 12-byte chainwork
        // overflows at BTC mainnet #849,138; headers from there cannot be
        // processed until RSKIP434. It stops the loop before `add` looks at
        // the header, so even at a header already stored.
        if parent.height + 1 >= config.block_with_too_much_chain_work_height
            && is_mainnet
            && !rskip434
        {
            break;
        }
        // `btcBlockChain.add`, which takes a header already stored as it is.
        if get_stored_block(ctx, &btc_header.block_hash()).is_none() {
            add(
                ctx,
                &btc_header,
                &parent,
                config.btc_network,
                use_v2,
                rskip199,
            );
        }
    }

    // rskj `receiveHeaders` is a VOID method (BridgeMethods.RECEIVE_HEADERS
    // declares no output, Bridge::receiveHeaders is BridgeMethodExecutorVoid).
    // Bridge.execute therefore returns the void value — `null` before RSKIP417
    // and EMPTY_BYTE_ARRAY afterwards (Bridge.calculateVoidReturnValue). No
    // output here stands for both; what a contract's call makes of the null,
    // which differs by era, is `execute_bridge`'s to say. Returning a 32-byte
    // int here makes a calling contract decode 32 bytes where rskj sees 0,
    // forking the execution (mainnet #6,223,768 tx[0]: relay 0x82494fb1 OOGs
    // vs success).
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// BTC chain query methods
// ---------------------------------------------------------------------------

/// `getBtcBlockchainBlockLocator()` → string[], a bitcoin-style block locator
/// over the Bridge's BTC header chain.
///
/// The head, then the blocks at `best - 2^i` for i = 0, 1, 2 …, stopping at
/// the lowest block the store holds and capped at 100 hashes -- the classic
/// exponentially-widening locator, so a peer can find the fork point in a
/// bounded number of steps.
///
/// **Removed at RSKIP89**, and the method table already knows: it is
/// `Until(Orchid)`, so on mainnet today the selector does not resolve at all
/// and this is reachable only by `eth_call` against a pre-orchid block.
/// `getBtcBlockchainBlockHashAtDepth` replaced it.
///
/// Hashes are rendered by `Sha256Hash.toString()`, which is display order and
/// carries no `0x`.
pub fn get_block_locator<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    /// rskj `maxHashesToInform`.
    const MAX_HASHES: usize = 100;

    ensure_btc_block_store(ctx, config, hardfork_cfg);
    let Some(head) = load_chain_head(ctx) else {
        return Err(PrecompileError::other("getBtcBlockchainBlockLocator: no BTC chain head"));
    };
    let lowest = lowest_stored_height(config).unwrap_or(0);
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);

    let mut hashes: Vec<String> =
        vec![hex::encode(bitcoin_hash_to_b256(&head.header.block_hash()))];

    if head.height > lowest {
        let mut i = 0u32;
        loop {
            if hashes.len() > MAX_HASHES {
                break;
            }
            let step = 2u64.saturating_pow(i);
            let height = (head.height as u64).saturating_sub(step);
            if height <= lowest as u64 {
                if let Some(block) = stored_block_at_main_chain_height(ctx, lowest, rskip199) {
                    hashes.push(hex::encode(bitcoin_hash_to_b256(&block.header.block_hash())));
                }
                break;
            }
            match stored_block_at_main_chain_height(ctx, height as u32, rskip199) {
                Some(block) => {
                    hashes.push(hex::encode(bitcoin_hash_to_b256(&block.header.block_hash())))
                }
                // rskj panics and rethrows here; refusing is the same outcome
                // without the panic processor.
                None => {
                    return Err(PrecompileError::other(
                        "getBtcBlockchainBlockLocator: cannot walk the BTC chain",
                    ))
                }
            }
            i += 1;
        }
    }

    Ok(PrecompileOutput::new(
        gas_cost,
        super::getters::abi_encode_string_array_pub(&hashes).into(),
    ))
}

/// `getBtcBlockchainInitialBlockHeight()` → int256, the height of the lowest
/// block this node's Bridge BTC store holds.
///
/// **This can disagree with rskj, by design.** rskj recomputes the answer on
/// every call: `getLowestBlock()` opens bitcoinj's checkpoints file and picks
/// `getCheckpointBefore(activeFederation.creationTime)`, so the number moves
/// forward every time the federation changes, even though the store's actual
/// lowest block never does. rustock does not carry the checkpoints file; it
/// carries the single checkpoint its store was seeded from, and answers with
/// that -- which is the truthful description of what the node has.
///
/// The two coincide for as long as the active federation is the one the store
/// was seeded against, and diverge after a powpeg change. Reporting a height
/// for a block the node does not have would be worse than reporting the one it
/// does.
pub fn get_initial_block_height(
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    let height = lowest_stored_height(config).ok_or_else(|| {
        PrecompileError::other("getBtcBlockchainInitialBlockHeight: no BTC checkpoint configured")
    })?;
    Ok(encode_int_result(gas_cost, height as i64))
}

/// `getBtcBlockchainBlockHashAtDepth(int256 depth)` → bytes32, the hash of the
/// main-chain block `depth` blocks below the head.
///
/// rskj bounds `depth` by `head.getHeight() - getLowestBlock().getHeight()`
/// and throws `IndexOutOfBoundsException` outside it -- which the Bridge turns
/// into a revert. The bound here uses the store's own lowest block rather than
/// the checkpoints file (see `get_initial_block_height`), so for depths
/// between the two bounds this returns a real block hash where rskj refuses.
/// Every hash it does return is the one rskj would return.
pub fn get_block_hash_at_depth<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    // rskj reads the argument as `((BigInteger) args[0]).intValue()`: its low
    // 32 bits, so 2^32 + 5 is depth 5, and a negative int fails the bound
    // check below.
    let depth = i64::from(
        crate::abi::Args::new(args)
            .int(0)
            .ok_or_else(|| PrecompileError::other("getBtcBlockchainBlockHashAtDepth: no depth"))?
            .int_value(),
    );

    ensure_btc_block_store(ctx, config, hardfork_cfg);
    let head = load_chain_head(ctx).ok_or_else(|| {
        PrecompileError::other("getBtcBlockchainBlockHashAtDepth: no BTC chain head")
    })?;
    let lowest = lowest_stored_height(config).unwrap_or(0);
    let max_depth = head.height as i64 - lowest as i64;
    if depth < 0 || depth > max_depth {
        return Err(PrecompileError::Other(
            format!("Depth must be between 0 and {max_depth}").into(),
        ));
    }

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    let height = head.height - depth as u32;
    let block = stored_block_at_main_chain_height(ctx, height, rskip199).ok_or_else(|| {
        PrecompileError::other("getBtcBlockchainBlockHashAtDepth: block not in store")
    })?;

    // The ABI return type is `bytes`, not `bytes32` -- so the 32 bytes come
    // back offset-and-length prefixed, 96 bytes in all.
    //
    // rskj answers with `blockHash.getBytes()`, and a bitcoinj `Sha256Hash`
    // for a block hash holds its bytes in DISPLAY order (`Block.getHash()`
    // wraps the double-SHA256 reversed). rust-bitcoin keeps the raw internal
    // order, so it has to be reversed to match.
    let hash = bitcoin_hash_to_b256(&block.header.block_hash());
    Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(hash.as_slice()).into()))
}

/// The height of the lowest block the Bridge BTC store can hold: the
/// checkpoint the chain was seeded from.
fn lowest_stored_height(config: &BridgeConstants) -> Option<u32> {
    config.btc_checkpoint.map(|(_, height, _)| height)
}

/// `getBtcBlockchainBestChainHeight()` → int256, the BTC chain head's height.
pub fn get_best_chain_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    ensure_btc_block_store(ctx, config, hardfork_cfg);
    let height = match load_chain_head(ctx) {
        Some(head) => head.height as i64,
        None => 0,
    };
    Ok(encode_int_result(gas_cost, height))
}

/// `getBtcBlockchainBestBlockHeader()` → bytes, the BTC chain head's header.
pub fn get_best_block_header<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    ensure_btc_block_store(ctx, config, hardfork_cfg);
    // A seeded store always has a head; rskj's `serializeBlockHeader` of none
    // is `EMPTY_BYTE_ARRAY`, ABI-encoded like any other `byte[]`.
    let header_bytes = load_chain_head(ctx)
        .map(|head| serialize(&head.header))
        .unwrap_or_default();
    Ok(PrecompileOutput::new(
        gas_cost,
        encode_abi_bytes(&header_bytes).into(),
    ))
}

/// `getBtcBlockchainBlockHeaderByHash(bytes32)` → bytes
pub fn get_block_header_by_hash<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let hash = crate::abi::Args::new(args)
        .bytes32(0)
        .ok_or_else(|| PrecompileError::other("getBlockHeaderByHash: no hash"))?;
    let hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from(hash));
    ensure_btc_block_store(ctx, config, hardfork_cfg);

    // rskj's `serializeBlockHeader` answers a block it does not hold with
    // `EMPTY_BYTE_ARRAY`, which `Bridge.execute` ABI-encodes like any other
    // `byte[]`: an encoded empty `bytes`, not zero-length return data.
    let header_bytes = get_stored_block(ctx, &hash)
        .map(|block| serialize(&block.header))
        .unwrap_or_default();
    Ok(PrecompileOutput::new(
        gas_cost,
        encode_abi_bytes(&header_bytes).into(),
    ))
}

/// `getBtcBlockchainBlockHeaderByHeight(uint256)` → bytes
///
/// rskj reads the height with `intValue()` and looks it up with
/// `getStoredBlockAtMainChainHeight`, catching whatever that throws: a
/// height above the head, one below RSKIP199's search limit, or a walk that
/// finds the wrong block all answer `EMPTY_BYTE_ARRAY`. `Bridge.execute`
/// always ABI-encodes the `byte[]` result via `encodeOutputs`
/// (Bridge.java:418), so an empty result is returned as the ABI encoding of
/// an empty `bytes`, NOT as zero-length return data.
pub fn get_block_header_by_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let height = crate::abi::Args::new(args)
        .int(0)
        .ok_or_else(|| PrecompileError::other("getBlockHeaderByHeight: no height"))?
        .int_value();
    ensure_btc_block_store(ctx, config, hardfork_cfg);
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    // A negative height is below every search limit, or walks off the stored
    // chain where there is none: not found either way.
    let header_bytes = u32::try_from(height)
        .ok()
        .and_then(
            |height| match main_chain_block_at_height(ctx, height, rskip199, Some(config)) {
                MainChainLookup::Found(block) => Some(serialize(&block.header)),
                MainChainLookup::Absent | MainChainLookup::StoreError => None,
            },
        )
        .unwrap_or_default();
    Ok(PrecompileOutput::new(
        gas_cost,
        encode_abi_bytes(&header_bytes).into(),
    ))
}

/// `getBtcBlockchainParentBlockHeaderByHash(bytes32)` → bytes
pub fn get_parent_block_header_by_hash<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let hash = crate::abi::Args::new(args)
        .bytes32(0)
        .ok_or_else(|| PrecompileError::other("getParentBlockHeaderByHash: no hash"))?;
    let hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from(hash));
    ensure_btc_block_store(ctx, config, hardfork_cfg);

    // As in `get_block_header_by_height`, an absent block yields rskj's
    // `EMPTY_BYTE_ARRAY`, which `Bridge.execute` still ABI-encodes as an empty
    // `bytes` (96 bytes, see `encode_abi_bytes`), not zero-length return data.
    let header_bytes = get_stored_block(ctx, &hash)
        .and_then(|block| get_stored_block(ctx, &block.header.prev_blockhash))
        .map(|parent| serialize(&parent.header))
        .unwrap_or_default();
    Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(&header_bytes).into()))
}

// ---------------------------------------------------------------------------
// ABI encoding helpers (arguments are read through `crate::abi`)
// ---------------------------------------------------------------------------

/// ABI-encode a `bytes` return value.
fn encode_abi_bytes(data: &[u8]) -> Vec<u8> {
    // rskj's `SolidityType.BytesType.encode` sizes the data section as
    // `((len - 1) / 32 + 1) * 32` using Java's truncating integer division
    // (SolidityType.java:296). For a non-empty array this is the usual
    // `ceil(len/32)*32`, but for an EMPTY array `(0 - 1) / 32 == -1 / 32 == 0`
    // in Java, so `+ 1` yields one 32-byte zero word rather than zero words:
    // empty `bytes` encodes to offset(0x20) + length(0) + one zero word = 96
    // bytes, not 64. Rust's `/` truncates toward zero just like Java's, so the
    // same expression reproduces the quirk exactly. This is consensus-critical:
    // the extra word changes RETURNDATASIZE (and downstream memory expansion)
    // in callers that copy the bridge's return data.
    let data_section = (((data.len() as i64 - 1) / 32 + 1) * 32) as usize;
    let mut result = Vec::with_capacity(64 + data_section);
    // Offset
    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    result.extend_from_slice(&offset);
    // Length
    let len = U256::from(data.len());
    result.extend_from_slice(&len.to_be_bytes::<32>());
    // Data (padded per rskj's BytesType formula)
    result.extend_from_slice(data);
    result.resize(64 + data_section, 0);
    result
}

/// ABI-encode an int256 result.
fn encode_int_result(gas_cost: u64, value: i64) -> PrecompileOutput {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        // Sign-extend for negative values
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    PrecompileOutput::new(gas_cost, output.to_vec().into())
}

// ---------------------------------------------------------------------------
// Hash conversion helpers
// ---------------------------------------------------------------------------

/// Convert a bitcoin `BlockHash` to an alloy `B256` in DISPLAY byte order
/// (bitcoinj `Sha256Hash` bytes — what rskj renders in storage, ABI values
/// and serialized hashes).
pub fn bitcoin_hash_to_b256(hash: &BlockHash) -> alloy_primitives::B256 {
    use bitcoin::hashes::Hash;
    let mut bytes = *hash.to_raw_hash().as_byte_array();
    bytes.reverse();
    alloy_primitives::B256::from(bytes)
}

/// Convert an alloy `B256` in DISPLAY byte order to a bitcoin `BlockHash`.
pub fn b256_to_bitcoin_hash(b: &alloy_primitives::B256) -> BlockHash {
    use bitcoin::hashes::Hash;
    let mut bytes = b.0;
    bytes.reverse();
    BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::{CompactTarget, TxMerkleNode};
    use std::collections::HashMap;

    /// Build a `StoredBlock` whose header points at `prev` and carries a
    /// distinguishing `nonce` (so sibling blocks at the same height get
    /// distinct hashes). `chain_work` is the cumulative work.
    fn link(prev: BlockHash, nonce: u32, height: u32, chain_work: u64) -> StoredBlock {
        let header = BtcHeader {
            version: Version::from_consensus(1),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        };
        StoredBlock::new(header, height, U256::from(chain_work))
    }

    /// A tiny in-memory block store: hash -> StoredBlock, mirroring what the
    /// Bridge persists via `put_stored_block`.
    fn store_of(blocks: &[StoredBlock]) -> HashMap<BlockHash, StoredBlock> {
        blocks
            .iter()
            .map(|b| (b.header.block_hash(), b.clone()))
            .collect()
    }

    /// bitcoinj `findSplit` + `getPartialChain`: a reorg of depth 3 must report
    /// the common ancestor as the split point and list every new-branch block
    /// above it, head-first. This is the core of the #3,622,582 fix (the BTC
    /// main-chain index must be rewritten for ALL reorganized heights).
    #[test]
    fn reorg_find_split_and_partial_chain() {
        // Common trunk: g(100) <- a(101). Then two branches fork at `a`:
        //   old:  a <- o2(102) <- o3(103)            (head: o3)
        //   new:  a <- n2(102) <- n3(103) <- n4(104) (head: n4, more work)
        let g = link(BlockHash::all_zeros(), 0, 100, 100);
        let a = link(g.header.block_hash(), 1, 101, 110);
        let o2 = link(a.header.block_hash(), 2, 102, 120);
        let o3 = link(o2.header.block_hash(), 3, 103, 130);
        let n2 = link(a.header.block_hash(), 12, 102, 121);
        let n3 = link(n2.header.block_hash(), 13, 103, 132);
        let n4 = link(n3.header.block_hash(), 14, 104, 143);

        let store = store_of(&[
            g.clone(),
            a.clone(),
            o2.clone(),
            o3.clone(),
            n2.clone(),
            n3.clone(),
            n4.clone(),
        ]);
        let get_prev = |h: &BlockHash| store.get(h).cloned();

        // Split point is the fork ancestor `a`.
        let split = find_split(&n4, &o3, get_prev).unwrap();
        assert_eq!(split.header.block_hash(), a.header.block_hash());
        assert_eq!(split.height, 101);

        // New branch above the split, head-first: [n4, n3, n2].
        let partial = get_partial_chain(&n4, &split, get_prev).unwrap();
        let hashes: Vec<_> = partial.iter().map(|b| b.header.block_hash()).collect();
        assert_eq!(
            hashes,
            vec![
                n4.header.block_hash(),
                n3.header.block_hash(),
                n2.header.block_hash(),
            ],
            "every reorganized height must be reindexed, not just the head"
        );
        // The split point itself is excluded.
        assert!(!hashes.contains(&a.header.block_hash()));
    }

    /// When the new head is a direct child of the old head (no fork), the split
    /// is the old head and the partial chain is just the new block.
    #[test]
    fn reorg_direct_extension_partial_chain_is_single_block() {
        let a = link(BlockHash::all_zeros(), 1, 101, 110);
        let b = link(a.header.block_hash(), 2, 102, 120);
        let store = store_of(&[a.clone(), b.clone()]);
        let get_prev = |h: &BlockHash| store.get(h).cloned();

        let split = find_split(&b, &a, get_prev).unwrap();
        assert_eq!(split.header.block_hash(), a.header.block_hash());

        let partial = get_partial_chain(&b, &a, get_prev).unwrap();
        assert_eq!(partial.len(), 1);
        assert_eq!(partial[0].header.block_hash(), b.header.block_hash());
    }

    /// bitcoinj's `findSplit` throws where either walk runs out of stored
    /// blocks; rustock's panicked.
    #[test]
    fn find_split_fails_where_a_walk_runs_out() {
        let a = link(BlockHash::all_zeros(), 1, 101, 110);
        let b = link(a.header.block_hash(), 2, 102, 120);
        // Its parent isn't stored.
        let stray = link(BlockHash::all_zeros(), 3, 5, 10);
        let store = store_of(&[a.clone(), b.clone(), stray.clone()]);
        let get_prev = |h: &BlockHash| store.get(h).cloned();
        assert!(find_split(&stray, &b, get_prev).is_none());
        assert!(find_split(&b, &stray, get_prev).is_none());
    }

    /// The inlined mainnet checkpoint must decode to the bitcoinj checkpoint
    /// rskj seeds from: BTC #499,968,
    /// 000000000000000000296e10eb4987c4eb9b7ba0841102dec4480e5d6b89acb5.
    #[test]
    fn mainnet_btc_checkpoint_decodes_to_expected_block() {
        let (header_hex, height, work_hex) =
            BridgeConstants::mainnet().btc_checkpoint.unwrap();
        assert_eq!(height, 499_968);
        let bytes = alloy_primitives::hex::decode(header_hex).unwrap();
        let header: BtcHeader = deserialize(&bytes).unwrap();
        assert_eq!(
            header.block_hash().to_string(),
            "000000000000000000296e10eb4987c4eb9b7ba0841102dec4480e5d6b89acb5"
        );
        let work = U256::from_be_slice(&alloy_primitives::hex::decode(work_hex).unwrap());
        assert!(!work.is_zero());
    }

    #[test]
    fn encode_int_positive() {
        let output = encode_int_result(0, 1);
        let bytes: &[u8] = &output.bytes;
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[30], 0);
    }

    #[test]
    fn encode_int_negative() {
        let output = encode_int_result(0, -1);
        let bytes: &[u8] = &output.bytes;
        assert_eq!(bytes.len(), 32);
        // -1 in two's complement is all 0xFF
        assert!(bytes.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn encode_int_negative_two() {
        let output = encode_int_result(0, -2);
        let bytes: &[u8] = &output.bytes;
        assert_eq!(bytes[31], 0xFE);
        for &b in &bytes[..24] {
            assert_eq!(b, 0xFF);
        }
    }

    #[test]
    fn abi_bytes_roundtrip() {
        let original = vec![1u8, 2, 3, 4, 5];
        let encoded = encode_abi_bytes(&original);
        let decoded = crate::abi::Args::new(&encoded).bytes(0).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn abi_bytes_80_byte_header() {
        let data = vec![0xABu8; 80];
        let encoded = encode_abi_bytes(&data);
        let decoded = crate::abi::Args::new(&encoded).bytes(0).unwrap();
        assert_eq!(decoded, data);
        // 80 bytes → offset + length + ceil(80/32)*32 = 32 + 32 + 96 = 160.
        assert_eq!(encoded.len(), 160);
    }

    /// Ground truth: rskj `SolidityType.BytesType.encode` allocates
    /// `((len - 1) / 32 + 1) * 32` data bytes with Java's truncating division.
    /// For an EMPTY `byte[]`, `-1 / 32 == 0`, so it still emits one 32-byte zero
    /// word — empty `bytes` encodes to 96 bytes (offset + length + one word),
    /// not 64. `getBtcBlockchainBlockHeaderByHeight` for an out-of-range height
    /// returns rskj's `EMPTY_BYTE_ARRAY`, which `Bridge.execute` ABI-encodes
    /// this way; the extra word changed RETURNDATASIZE and forked the caller at
    /// mainnet #8,417,579 (tx[0], 34912 vs 34401 gas).
    #[test]
    fn abi_bytes_empty_matches_rskj_96_bytes() {
        let encoded = encode_abi_bytes(&[]);
        assert_eq!(encoded.len(), 96, "empty bytes must encode to 96, not 64");
        // offset 0x20, length 0, one zero word.
        assert_eq!(encoded[31], 0x20);
        assert!(encoded[32..].iter().all(|&b| b == 0));
        assert_eq!(crate::abi::Args::new(&encoded).bytes(0), Some(&[][..]));
    }

    #[test]
    fn hash_conversion_roundtrip() {
        let hash_bytes = alloy_primitives::B256::repeat_byte(0x42);
        let btc_hash = b256_to_bitcoin_hash(&hash_bytes);
        let back = bitcoin_hash_to_b256(&btc_hash);
        assert_eq!(back, hash_bytes);
    }

    /// Ground truth: rskj `BridgeSupport` receiveHeader result codes
    /// (BridgeSupport.java:96-100 + the `return 0;` success). A from-scratch
    /// client that picked different values (rustock previously used SUCCESS=1,
    /// TOO_SOON=-2, ALREADY_KNOWN=-1, a bogus INVALID_POW=-5) forks because the
    /// calling contract branches on these integers (mainnet #6,223,768 tx[0]).
    #[test]
    fn receive_header_result_codes_match_rskj() {
        assert_eq!(SUCCESS, 0); // return 0
        assert_eq!(ERR_TOO_SOON, -1); // RECEIVE_HEADER_CALLED_TOO_SOON
        assert_eq!(ERR_BLOCK_TOO_OLD, -2); // RECEIVE_HEADER_BLOCK_TOO_OLD
        assert_eq!(ERR_PREV_NOT_FOUND, -3); // RECEIVE_HEADER_CANT_FOUND_PREVIOUS_BLOCK
        assert_eq!(ERR_ALREADY_KNOWN, -4); // RECEIVE_HEADER_BLOCK_PREVIOUSLY_SAVED
        assert_eq!(ERR_UNEXPECTED_EXCEPTION, -99); // RECEIVE_HEADER_UNEXPECTED_EXCEPTION
    }

    /// Ground truth: rskj `BtcTransactionFormatUtils.isBlockHeaderSize`.
    /// Exactly 80 bytes once RSKIP124 is active; 80..=85 before it, because
    /// bitcoinj's `makeBlock` tolerated a trailing transaction-count varint.
    /// Anything else makes `Bridge.receiveHeader` return -20 (Bridge.java:575).
    #[test]
    fn receive_header_size_rule_matches_rskj() {
        // RSKIP124 active (wasabi100 onward — every block that can reach
        // receiveHeader, which needs RSKIP200).
        assert!(is_block_header_size(80, true));
        for bad in [0usize, 1, 79, 81, 85, 86, 160] {
            assert!(!is_block_header_size(bad, true), "size {bad} must be rejected");
        }

        // Pre-RSKIP124: the MIN..=MAX window.
        for ok in 80usize..=85 {
            assert!(is_block_header_size(ok, false), "size {ok} accepted pre-RSKIP124");
        }
        for bad in [0usize, 79, 86] {
            assert!(!is_block_header_size(bad, false), "size {bad} rejected pre-RSKIP124");
        }

        assert_eq!(ERR_SIZE_MISMATCH, -20); // Bridge.RECEIVE_HEADER_ERROR_SIZE_MISTMATCH
    }

    fn empty_ctx() -> impl crate::RskContextTr {
        use revm::MainContext;
        revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default())
    }

    /// rskj's `getBtcBlockchainBlockHeaderByHash` serializes a block it does
    /// not have as the empty byte array, which encodes to 96 bytes.
    #[test]
    fn an_unknown_block_hash_answers_the_empty_bytes() {
        let (config, cfg) = (BridgeConstants::mainnet(), RskHardforkConfig::mainnet());
        let out =
            get_block_header_by_hash(&mut empty_ctx(), &[0x11; 32], 0, &config, &cfg).unwrap();
        assert_eq!(out.bytes.to_vec(), encode_abi_bytes(&[]));
    }

    /// rskj's `receiveHeaders` checks every header's size before it takes any,
    /// and refuses the whole call for one of the wrong size, or for one it
    /// can't parse. Both throw `BridgeIllegalArgumentException`, which
    /// `Bridge.execute` answers with null before RSKIP88: a success with no
    /// output, charged its gas. From RSKIP88 they throw.
    #[test]
    fn receive_headers_refuses_them_all_for_one_of_the_wrong_size() {
        use crate::abi::encode::{self, Arg};
        let (config, cfg) = (BridgeConstants::mainnet(), RskHardforkConfig::mainnet());
        assert!(!cfg.has_rskip88(0) && cfg.has_rskip88(729_000) && !cfg.has_rskip124(729_000));
        let wrong_size = encode::args(&[Arg::BytesArray(&[&[0u8; 80], &[0u8; 79]])]);
        // 81 bytes, a size bitcoinj took before RSKIP124, counting one
        // transaction that isn't there.
        let mut counted = [0u8; 81];
        counted[80] = 1;
        let unparsed = encode::args(&[Arg::BytesArray(&[&counted])]);
        let at = |number: u64, args: &[u8]| {
            use revm::MainContext;
            let mut ctx =
                revm::Context::mainnet().with_chain(crate::raw_storage::RskChainExt::default());
            ctx.block.number = alloy_primitives::U256::from(number);
            receive_headers(&mut ctx, args, 5_000, &config, false, &cfg)
        };
        for args in [&wrong_size, &unparsed] {
            let out = at(0, args).expect("before RSKIP88, a success");
            assert!(out.bytes.is_empty());
            assert_eq!(out.gas_used, 5_000);
            assert!(at(729_000, args).is_err(), "from RSKIP88, a throw");
        }
    }

    /// rskj runs `ensureBtcBlockStore` before every read of the BTC chain, so a
    /// getter on a store nothing has seeded yet seeds it, and answers from it:
    /// on mainnet the checkpoint is then the head. (Unseeded, the height was 0,
    /// the best header empty, and the depth and the locator failed.)
    #[test]
    fn the_btc_getters_seed_an_empty_store_and_answer_from_it() {
        use crate::abi::encode;
        /// The getter's answer on an empty store, and the head it leaves.
        fn seeded<CTX: crate::RskContextTr>(
            mut ctx: CTX,
            getter: impl FnOnce(&mut CTX) -> Result<PrecompileOutput, PrecompileError>,
        ) -> (Vec<u8>, Option<u32>) {
            let out = getter(&mut ctx).unwrap();
            (
                out.bytes.to_vec(),
                load_chain_head(&mut ctx).map(|head| head.height),
            )
        }
        let (config, cfg) = (BridgeConstants::mainnet(), RskHardforkConfig::mainnet());
        let (header_hex, height, _) = config.btc_checkpoint.unwrap();
        let header_bytes = alloy_primitives::hex::decode(header_hex).unwrap();
        let checkpoint: BtcHeader = deserialize(&header_bytes).unwrap();
        let hash = bitcoin_hash_to_b256(&checkpoint.block_hash());
        let (header, at) = (encode_abi_bytes(&header_bytes), Some(height));

        assert_eq!(
            seeded(empty_ctx(), |ctx| get_best_chain_height(
                ctx, 0, &config, &cfg
            )),
            (encode_int_result(0, i64::from(height)).bytes.to_vec(), at)
        );
        assert_eq!(
            seeded(empty_ctx(), |ctx| get_best_block_header(
                ctx, 0, &config, &cfg
            )),
            (header.clone(), at)
        );
        assert_eq!(
            seeded(empty_ctx(), |ctx| get_block_header_by_hash(
                ctx,
                hash.as_slice(),
                0,
                &config,
                &cfg
            )),
            (header.clone(), at)
        );
        assert_eq!(
            seeded(empty_ctx(), |ctx| {
                get_block_header_by_height(ctx, &encode::int(i64::from(height)), 0, &config, &cfg)
            }),
            (header, at)
        );
        assert_eq!(
            seeded(empty_ctx(), |ctx| get_parent_block_header_by_hash(
                ctx,
                hash.as_slice(),
                0,
                &config,
                &cfg
            )),
            (encode_abi_bytes(&[]), at),
            "the checkpoint's parent isn't held"
        );
        assert_eq!(
            seeded(empty_ctx(), |ctx| get_block_hash_at_depth(
                ctx,
                &encode::int(0),
                0,
                &config,
                &cfg
            )),
            (encode_abi_bytes(hash.as_slice()), at)
        );
        assert_eq!(
            seeded(empty_ctx(), |ctx| get_block_locator(ctx, 0, &config, &cfg)),
            (
                super::super::getters::abi_encode_string_array_pub(&[hex::encode(hash)]).to_vec(),
                at
            )
        );

        // In the block's layout and with its index: block 0 is before RSKIP199,
        // so the checkpoint's height isn't indexed.
        let mut ctx = empty_ctx();
        ensure_btc_block_store(&mut ctx, &config, &cfg);
        assert_eq!(
            crate::bridge::storage::bridge_load_btc_block_hash_by_height(&mut ctx, height),
            None
        );
    }

    /// With no checkpoint, as on regtest, the seeded store holds Bitcoin
    /// regtest's genesis alone, the head at height 0, found by its height.
    #[test]
    fn a_seeded_regtest_store_answers_its_genesis_by_height() {
        use crate::abi::encode;
        let (config, cfg) = (BridgeConstants::regtest(), RskHardforkConfig::regtest());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        let mut ctx = empty_ctx();
        let out = get_block_header_by_height(&mut ctx, &encode::int(0), 0, &config, &cfg).unwrap();
        assert_eq!(out.bytes.to_vec(), encode_abi_bytes(&serialize(&genesis)));
        assert_eq!(
            load_chain_head(&mut ctx).map(|head| head.header),
            Some(genesis)
        );
    }

    /// rskj seeds in two steps that each set the head: the genesis block
    /// (`checkIfInitialized`), then, on a store still at its genesis block,
    /// the checkpoint (`CheckpointManager.checkpoint`). So from RSKIP199 both
    /// are in the height index, and a store left at its genesis block takes
    /// the checkpoint when it's next seeded, but a seeded store isn't seeded
    /// again.
    #[test]
    fn seeding_heads_the_store_with_its_genesis_block_then_the_checkpoint() {
        use crate::bridge::storage::bridge_load_btc_block_hash_by_height as indexed;
        let config = BridgeConstants::mainnet();
        let height = config.btc_checkpoint.unwrap().1;
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin).header;

        let mut ctx = empty_ctx();
        ensure_btc_chain_seeded(&mut ctx, &config, true, true);
        let head = load_chain_head(&mut ctx).unwrap();
        assert_eq!(head.height, height);
        assert_eq!(
            indexed(&mut ctx, 0),
            Some(bitcoin_hash_to_b256(&genesis.block_hash()))
        );
        assert_eq!(
            indexed(&mut ctx, height),
            Some(bitcoin_hash_to_b256(&head.header.block_hash()))
        );

        let mut ctx = empty_ctx();
        ensure_btc_chain_seeded(&mut ctx, &config, true, false);
        assert_eq!(indexed(&mut ctx, 0), None, "no index before RSKIP199");

        let mut ctx = empty_ctx();
        let stored = StoredBlock::new(genesis, 0, compute_work(genesis.bits));
        put_stored_block(&mut ctx, &stored, true);
        crate::bridge::btc_store::store_chain_head(&mut ctx, &stored, true);
        ensure_btc_chain_seeded(&mut ctx, &config, true, true);
        assert_eq!(
            load_chain_head(&mut ctx).map(|head| head.height),
            Some(height)
        );

        // Regtest has no checkpoint: a store seeded before RSKIP199 stays at
        // its genesis block, and keeps it out of the index after.
        let regtest = BridgeConstants::regtest();
        let mut ctx = empty_ctx();
        ensure_btc_chain_seeded(&mut ctx, &regtest, true, false);
        ensure_btc_chain_seeded(&mut ctx, &regtest, true, true);
        assert_eq!(indexed(&mut ctx, 0), None);
    }

    /// rskj's BTC store writes straight into the repository its call was
    /// given, which a transaction's own call keeps however it ends: a seeding
    /// it made stays when its other writes go, but the height index, which
    /// goes through the storage provider, goes with them. A contract's call, a
    /// frame deeper, keeps nothing of a call that fails.
    #[test]
    fn a_transactions_own_call_keeps_the_seeding_its_failure_drops() {
        use revm::context_interface::JournalTr;
        let config = BridgeConstants::regtest();
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        // The head and the hash indexed at height 0 once a call `frames` deep
        // has seeded the store and then ended, well or not.
        let seeded = |frames: usize, ended_well: bool| {
            let mut ctx = empty_ctx();
            for _ in 0..frames {
                ctx.journal_mut().checkpoint();
            }
            ensure_btc_chain_seeded(&mut ctx, &config, true, true);
            let raw = &mut ctx.chain_mut().raw_storage;
            if ended_well {
                raw.commit_call();
            } else {
                raw.discard_call();
            }
            (
                load_chain_head(&mut ctx).map(|head| head.header),
                crate::bridge::storage::bridge_load_btc_block_hash_by_height(&mut ctx, 0),
            )
        };
        let indexed = Some(bitcoin_hash_to_b256(&genesis.block_hash()));
        assert_eq!(seeded(1, true), (Some(genesis), indexed));
        assert_eq!(
            seeded(1, false),
            (Some(genesis), None),
            "a transaction's own call"
        );
        assert_eq!(
            seeded(0, false),
            (Some(genesis), None),
            "its cost, before RSKIP136"
        );
        assert_eq!(seeded(2, false), (None, None), "a contract's call");
        assert_eq!(seeded(2, true), (Some(genesis), indexed));
    }

    /// A writable context at `block_number`, in a block whose time is well
    /// past any `receiveHeader` interval.
    fn ctx_at(block_number: u64) -> impl crate::RskContextTr {
        use revm::MainContext;
        let block = revm::context::BlockEnv {
            number: U256::from(block_number),
            timestamp: U256::from(1_700_000_000_u64),
            ..revm::context::BlockEnv::default()
        };
        revm::Context::mainnet()
            .with_block(block)
            .with_chain(crate::raw_storage::RskChainExt::default())
    }

    fn regtest_genesis() -> BlockHash {
        bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .block_hash()
    }

    /// A regtest header on `prev`, mined: at regtest's target about every
    /// other nonce does.
    fn mine_regtest(prev: BlockHash, seed: u8) -> BtcHeader {
        (0..)
            .map(|nonce| BtcHeader {
                version: Version::from_consensus(1),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([seed; 32]),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce,
            })
            .find(|header| verify_header(header, BtcNetwork::Regtest))
            .unwrap()
    }

    /// `length` regtest headers from the genesis block, each on the one
    /// before.
    fn regtest_chain(length: usize) -> Vec<BtcHeader> {
        let mut prev = regtest_genesis();
        (0..length)
            .map(|_| {
                let header = mine_regtest(prev, 0x11);
                prev = header.block_hash();
                header
            })
            .collect()
    }

    fn send_headers<CTX: crate::RskContextTr>(
        ctx: &mut CTX,
        headers: &[BtcHeader],
        config: &BridgeConstants,
        cfg: &RskHardforkConfig,
    ) {
        use crate::abi::encode::{self, Arg};
        let encoded: Vec<Vec<u8>> = headers.iter().map(serialize).collect();
        let slices: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        let args = encode::args(&[Arg::BytesArray(&slices)]);
        receive_headers(ctx, &args, 0, config, true, cfg).unwrap();
    }

    /// `receiveHeader`'s answer to `header`.
    fn send_header<CTX: crate::RskContextTr>(
        ctx: &mut CTX,
        header: &BtcHeader,
        config: &BridgeConstants,
        cfg: &RskHardforkConfig,
    ) -> Vec<u8> {
        use crate::abi::encode::{self, Arg};
        let args = encode::args(&[Arg::Bytes(&serialize(header))]);
        receive_header(ctx, &args, 0, config, true, cfg)
            .unwrap()
            .bytes
            .to_vec()
    }

    fn answer(code: i64) -> Vec<u8> {
        encode_int_result(0, code).bytes.to_vec()
    }

    /// rskj's `receiveHeaders` takes every header it's given: rustock stopped
    /// at 500.
    #[test]
    fn receive_headers_takes_every_header_it_is_given() {
        let (config, cfg) = (BridgeConstants::regtest(), RskHardforkConfig::regtest());
        let mut ctx = ctx_at(0);
        send_headers(&mut ctx, &regtest_chain(501), &config, &cfg);
        assert_eq!(load_chain_head(&mut ctx).map(|head| head.height), Some(501));
    }

    /// rskj's `receiveHeader` takes a header 25 below the head
    /// (`maxDepthBlockchainAccepted`) and refuses one 26 below: rustock took
    /// them down to 4,320.
    #[test]
    fn receive_header_takes_a_header_25_below_the_head_but_not_26() {
        let (config, cfg) = (BridgeConstants::regtest(), RskHardforkConfig::regtest());
        let chain = regtest_chain(27);
        // The head is at 27. A header on block 1 is at 2, 25 below it; one on
        // the genesis block is 26 below.
        for (prev, code) in [
            (chain[0].block_hash(), SUCCESS),
            (regtest_genesis(), ERR_BLOCK_TOO_OLD),
        ] {
            let mut ctx = ctx_at(0);
            send_headers(&mut ctx, &chain, &config, &cfg);
            let fork = mine_regtest(prev, 0xf0);
            assert_eq!(send_header(&mut ctx, &fork, &config, &cfg), answer(code));
        }
    }

    /// rskj's `receiveHeader` answers UNEXPECTED_EXCEPTION for a header
    /// bitcoinj's `add` throws on: one whose hash is above its target
    /// (`verifyHeader`), or one whose hash is under its target but whose target
    /// isn't the one its parent's chain calls for
    /// (`checkDifficultyTransitions`). rustock checked the hash alone, so
    /// anyone could add a header at a target of their choice through the
    /// public `receiveHeader`, where rskj refuses it.
    #[test]
    fn receive_header_refuses_a_header_bitcoinj_cant_add() {
        let (config, cfg) = (BridgeConstants::regtest(), RskHardforkConfig::regtest());
        let on_target = mine_regtest(regtest_genesis(), 0x11);
        let above_target = (0..)
            .map(|nonce| BtcHeader { nonce, ..on_target })
            .find(|header| !verify_header(header, BtcNetwork::Regtest))
            .unwrap();
        let easier = (0..)
            .map(|nonce| BtcHeader {
                bits: CompactTarget::from_consensus(0x2100_ffff),
                nonce,
                ..on_target
            })
            .find(|header| verify_header(header, BtcNetwork::Regtest))
            .unwrap();
        for refused in [above_target, easier] {
            let mut ctx = ctx_at(0);
            assert_eq!(
                send_header(&mut ctx, &refused, &config, &cfg),
                answer(ERR_UNEXPECTED_EXCEPTION)
            );
            assert!(get_stored_block(&mut ctx, &refused.block_hash()).is_none());
        }
        let mut ctx = ctx_at(0);
        assert_eq!(
            send_header(&mut ctx, &on_target, &config, &cfg),
            answer(SUCCESS)
        );
    }

    /// rskj's `receiveHeaders` looks a header's parent up first, and stops at
    /// the first header whose height would be past `cannotProcessNextBlock`'s
    /// limit, even one already stored, taking none after it; from RSKIP434 it
    /// goes on. Real mainnet headers 849,134 and 849,135, after a header
    /// stored on 849,137.
    #[test]
    fn receive_headers_stops_at_a_header_past_the_chain_work_limit_even_one_stored() {
        let config = BridgeConstants::mainnet();
        let limit = config.block_with_too_much_chain_work_height;
        let real = |hex: &str| {
            deserialize::<BtcHeader>(&alloy_primitives::hex::decode(hex).unwrap()).unwrap()
        };
        let h849134 = real("0080b92c24f123130ae29e899f0cab72653722e54cdf3b30445202000000000000000000c72ead65a3b78ab637d1876c00414a77e47bcc5b52667ac1e573633563bea5a695aa7766255d031728d182a8");
        let h849135 = real("00004020bf67910b5d3996ee594848b482ee84d0e28c97a9a2d601000000000000000000865e218552bb92df36c962f5163e84a6c2542584fb36be2fa8b2a4246c73a701f1ae7766255d031791836b22");
        let h849137 = real("00e00820925b77c9ff4d0036aa29f3238cde12e9af9d55c34ed30200000000000000000032a9fa3e12ef87a2327b55db6a16a1227bb381db8b269d90aa3a6e38cf39665f91b47766255d0317c1b1575f");
        let past_the_limit = BtcHeader {
            prev_blockhash: h849137.block_hash(),
            ..h849135
        };
        let takes_849135 = |block_number: u64| {
            let mut ctx = ctx_at(block_number);
            let head = StoredBlock::new(h849134, 849_134, U256::from(1));
            put_stored_block(&mut ctx, &head, true);
            store_chain_head(&mut ctx, &head, true);
            for (header, height) in [(h849137, limit - 1), (past_the_limit, limit)] {
                put_stored_block(
                    &mut ctx,
                    &StoredBlock::new(header, height, U256::from(1)),
                    true,
                );
            }
            let cfg = RskHardforkConfig::mainnet();
            send_headers(&mut ctx, &[past_the_limit, h849135], &config, &cfg);
            get_stored_block(&mut ctx, &h849135.block_hash()).is_some()
        };
        assert!(!takes_849135(0), "before RSKIP434");
        assert!(takes_849135(7_000_000), "from RSKIP434");
    }

    /// bitcoinj's `connectBlock` walks a fork back to the head's chain
    /// (`findSplit`) before it stores it, and throws where the walk runs out of
    /// stored blocks. Mainnet's store holds the genesis block and the chain from
    /// the checkpoint, so Bitcoin's block 1, on the genesis block, is refused,
    /// where rustock stored it. On regtest, whose chain is whole from the
    /// genesis block, a fork is stored, and becomes the head only with more
    /// work than the head, when every height on its branch is indexed to it.
    #[test]
    fn a_fork_that_cant_be_walked_back_to_the_heads_chain_is_refused() {
        let block_1: BtcHeader = deserialize(
            &alloy_primitives::hex::decode(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000\
                 982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e\
                 61bc6649ffff001d01e36299",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            block_1.block_hash().to_string(),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
        let (config, cfg) = (BridgeConstants::mainnet(), RskHardforkConfig::mainnet());
        let mut ctx = ctx_at(0);
        send_headers(&mut ctx, &[block_1], &config, &cfg);
        assert!(get_stored_block(&mut ctx, &block_1.block_hash()).is_none());

        let (config, cfg) = (BridgeConstants::regtest(), RskHardforkConfig::regtest());
        let chain = regtest_chain(1);
        let fork = mine_regtest(regtest_genesis(), 0xf1);
        let past = mine_regtest(fork.block_hash(), 0xf2);
        let mut ctx = ctx_at(0);
        let head = |ctx: &mut _| load_chain_head(ctx).map(|head| head.header);
        send_headers(&mut ctx, &[chain[0], fork], &config, &cfg);
        assert!(get_stored_block(&mut ctx, &fork.block_hash()).is_some());
        assert_eq!(head(&mut ctx), Some(chain[0]), "a tie keeps the head");
        send_headers(&mut ctx, &[past], &config, &cfg);
        assert_eq!(head(&mut ctx), Some(past));
        for (height, block) in [(1, fork), (2, past)] {
            assert_eq!(
                crate::bridge::storage::bridge_load_btc_block_hash_by_height(&mut ctx, height),
                Some(bitcoin_hash_to_b256(&block.block_hash()))
            );
        }
    }

    /// Before RSKIP124 up to five bytes may follow a header, which rskj's
    /// `makeBlock` parses as the block's transactions: a count of 0 parses, in
    /// any of `VarInt`'s widths, and anything else refuses the whole call.
    #[test]
    fn before_rskip124_what_follows_a_header_must_count_no_transactions() {
        let cases: [(&[u8], bool); 11] = [
            (&[], true),
            (&[0], true),
            (&[0, 0xab], true),
            (&[0xfd, 0, 0], true),
            (&[0xfe, 0, 0, 0, 0], true),
            (&[1], false),
            (&[0xfc], false),
            (&[0xfd, 0], false),
            (&[0xfd, 1, 0], false),
            (&[0xfe, 0, 0, 0, 0x80], false),
            (&[0xff, 0, 0, 0, 0], false),
        ];
        for (rest, parses) in cases {
            assert_eq!(no_transactions_follow(rest), parses, "{rest:02x?}");
        }

        use crate::abi::encode::{self, Arg};
        // Mainnet's ladder has RSKIP124 from wasabi100.
        let (config, cfg) = (BridgeConstants::regtest(), RskHardforkConfig::mainnet());
        let header = mine_regtest(regtest_genesis(), 0x11);
        let takes = |rest: &[u8]| {
            let mut bytes = serialize(&header);
            bytes.extend_from_slice(rest);
            let args = encode::args(&[Arg::BytesArray(&[&bytes])]);
            let mut ctx = ctx_at(0);
            receive_headers(&mut ctx, &args, 0, &config, false, &cfg).is_ok()
                && get_stored_block(&mut ctx, &header.block_hash()).is_some()
        };
        assert!(takes(&[0]));
        assert!(!takes(&[1]));
    }

    /// From RSKIP199 rskj finds a main-chain block below
    /// `btcHeightWhenBlockIndexActivates` only within
    /// `maxDepthToSearchBlocksBelowIndexActivation` of the head, and throws
    /// below that, so a getter's call fails where the lookup would go on. With
    /// the head more than 4,320 above it, that's below 696,022 on mainnet and
    /// below 2,039,594 on testnet.
    #[test]
    fn below_the_index_activation_rskj_looks_only_so_deep() {
        let any_header = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        for (config, limit) in [
            (BridgeConstants::mainnet(), 696_022),
            (BridgeConstants::testnet(), 2_039_594),
        ] {
            let mut ctx = empty_ctx();
            let head = StoredBlock::new(any_header, limit + 100_000, U256::ZERO);
            store_chain_head(&mut ctx, &head, true);
            let lookup =
                |ctx: &mut _, height| main_chain_block_at_height(ctx, height, true, Some(&config));
            assert!(matches!(
                lookup(&mut ctx, limit - 1),
                MainChainLookup::StoreError
            ));
            // From the limit on the lookup goes on, here to a head not stored.
            assert!(matches!(lookup(&mut ctx, limit), MainChainLookup::Absent));
        }
    }
}
