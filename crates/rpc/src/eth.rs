use crate::helpers::{
    parse_b256, parse_block_number, parse_hex_u32, to_hex_b256, to_hex_u256, to_hex_u64,
    BlockResultDto,
};
use crate::server::TxSubmitter;
use crate::types::*;
use rustock_core::config::ChainConfig;
use rustock_storage::BlockStore;
use serde_json::{json, Value};
use std::sync::Arc;

pub fn eth_protocol_version(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!("0x3e"))
}

pub fn eth_chain_id(id: Value, config: &ChainConfig) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(to_hex_u64(config.chain_id as u64)))
}

pub fn eth_block_number(id: Value, store: &BlockStore) -> JsonRpcResponse {
    match head_number(store) {
        Some(n) => JsonRpcResponse::success(id, json!(to_hex_u64(n))),
        None => JsonRpcResponse::error(id, INTERNAL_ERROR, "No head block"),
    }
}

pub async fn eth_syncing(
    id: Value,
    store: &BlockStore,
    peer_store: &rustock_networking::peers::PeerStore,
) -> JsonRpcResponse {
    // `currentBlock` is the executed head, not the best downloaded header.
    //
    // Those two diverge precisely when something is wrong. Header download and
    // block execution are separate pipelines, so if execution stalls the
    // downloaded head keeps climbing with the network while the state the node
    // can actually serve stays put. Reporting the downloaded head then makes a
    // wedged node indistinguishable from a healthy one: it answers `false`
    // -- fully synced -- while `eth_getBalance` serves state hundreds of blocks
    // stale. A node stuck this way went unnoticed for ~1,300 retries because
    // this method said it was fine.
    //
    // Callers reading `currentBlock` want the block whose state they will be
    // served, which is the executed one.
    let downloaded = head_number(store).unwrap_or(0);
    let current = executed_number(store).unwrap_or(downloaded);
    let peer_best = peer_store
        .best_peer()
        .await
        .map(|(_, meta)| meta.best_number)
        .unwrap_or(0);

    // The target is the highest block we know to exist. A block we have already
    // downloaded but not executed counts: with no peers, or with peers at our
    // own downloaded height, that is the only thing revealing the backlog.
    let highest = peer_best.max(downloaded);

    if highest > current {
        JsonRpcResponse::success(
            id,
            json!({
                "startingBlock": to_hex_u64(0),
                "currentBlock": to_hex_u64(current),
                "highestBlock": to_hex_u64(highest),
            }),
        )
    } else {
        JsonRpcResponse::success(id, json!(false))
    }
}

/// `eth_gasPrice` — what a transaction should pay to be **mined**.
///
/// This used to answer with the head block's `minimumGasPrice`, which is a
/// different question: that is the floor a transaction must clear to be
/// *valid*. During congestion the two diverge, and a wallet trusting the floor
/// underpays and waits.
///
/// rskj (`EthereumImpl.getGasPrice`) answers in two branches, and the gate
/// between them matters as much as the percentile does:
///
/// * **Fee market working** -- the last 50 blocks at least 90% full on
///   average -- `GasPriceTracker.getGasPrice()`: the 25th percentile of the
///   last 512 transactions' gas prices, floored at the best block's minimum
///   times 1.1.
/// * **Otherwise** the head's `minimumGasPrice` times 1.1. The percentile is
///   still computed; it is simply not an answer, because on a chain with
///   spare capacity nobody is bidding and the window describes whatever the
///   last 512 transactions happened to pay.
///
/// **Answering with the percentile unconditionally is not a smaller
/// difference than it looks.** The window is 512 transactions deep with no
/// age limit, so it long outlives the conditions that filled it. A node
/// seeded from a mainnet export and then run on a quiet chain keeps quoting
/// mainnet's prices while the minimum walks down underneath it: measured at
/// 26,065,600 wei against a minimum of 587, a factor of 44,000. Wallets that
/// trust it do not merely overpay -- they price themselves over RSKIP252's
/// 100x cap, and the transactions they produce cannot legally be mined.
pub fn eth_gas_price(id: Value, state: &crate::server::RpcState) -> JsonRpcResponse {
    if let Some(tracker) = &state.gas_price {
        if tracker.is_fee_market_working() {
            return JsonRpcResponse::success(
                id,
                json!(to_hex_u256(&alloy_primitives::U256::from(tracker.gas_price()))),
            );
        }
    }
    let price = head_header(&state.store)
        .map(|h| to_hex_u256(&head_minimum_times_multiplier(&h.minimum_gas_price)))
        .unwrap_or_else(|| "0x0".to_string());
    JsonRpcResponse::success(id, json!(price))
}

/// The head's `minimumGasPrice` times 1.1, which is what rskj answers when the
/// fee market is not working.
fn head_minimum_times_multiplier(minimum: &alloy_primitives::U256) -> alloy_primitives::U256 {
    minimum.saturating_mul(alloy_primitives::U256::from(GAS_PRICE_MULTIPLIER_NUM))
        / alloy_primitives::U256::from(GAS_PRICE_MULTIPLIER_DEN)
}

/// 1.1 as an exact ratio, so `x * 11 / 10` with truncation rather than a
/// float.
///
/// Two constants in rskj hold this value and both are 1.1, which is why one
/// pair serves here. They are not the same setting:
///
/// * `GasPriceTracker.DEFAULT_GAS_PRICE_MULTIPLIER` floors the percentile.
/// * `EthereumImpl.minGasPriceMultiplier` scales the head's minimum on the
///   branch below. It comes from the `gasPriceMultiplier` config key, whose
///   default in `reference.conf` is 1.1 -- so an rskj operator can retune it
///   and this node cannot. A divergence only reachable by changing that
///   setting, and recorded here rather than discovered later.
///
/// Duplicated from `rustock_sync::gas_price`, which has the same pair, and
/// deliberately: `rpc` does not depend on `sync` -- that is what
/// `GasPriceSource` exists to avoid -- so sharing them would mean adding the
/// dependency this trait was written to prevent.
const GAS_PRICE_MULTIPLIER_NUM: u64 = 11;
const GAS_PRICE_MULTIPLIER_DEN: u64 = 10;

pub fn eth_mining(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(false))
}



pub fn eth_accounts(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!([]))
}

/// Pending transactions **belonging to this node's own accounts** — always
/// empty here, because this node has no wallet.
///
/// The name misleads, and the misreading is worth spelling out because it is
/// the obvious one. This is not "the mempool". rskj filters the pool down to
/// senders the node's own wallet manages
/// (`EthModuleWalletEnabled.ethPendingTransactions`):
///
/// ```java
/// List<Transaction> pendingTxs = transactionPool.getPendingTransactions();
/// List<String> managedAccounts = Arrays.asList(accounts());
/// return pendingTxs.stream()
///         .filter(tx -> managedAccounts.contains(tx.getSender(...).toJsonString()))
///         .collect(Collectors.toList());
/// ```
///
/// and with the wallet off it returns `Collections.emptyList()` unconditionally
/// (`EthModuleWalletDisabled`). rustock is that case: `eth_accounts` is empty,
/// `personal_*` is unsupported and `eth_sendTransaction` refuses. So `[]` is
/// the faithful answer, not a stub.
///
/// Returning the whole pending pool instead would be worse than useless. Under
/// rskj's contract these are *the caller's own* transactions, so a wallet or
/// frontend would present every transaction in the public mempool as the
/// user's — wrong in a way the caller cannot detect.
///
/// **What you probably want is `txpool_content`** (issue #83), which reports
/// the pool without claiming the transactions belong to anyone in particular.
pub fn eth_pending_transactions(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!([]))
}

/// The address block rewards are paid to.
///
/// With mining off there is no such address and the zero address is the
/// honest answer. With mining on, answering zero would tell mining software
/// the rewards go nowhere, so the miner's configured address is reported --
/// which is what rskj does.
pub fn eth_coinbase(
    id: Value,
    miner: &Option<std::sync::Arc<dyn crate::mnr::MiningService>>,
) -> JsonRpcResponse {
    let addr = miner.as_ref().map(|m| m.coinbase()).unwrap_or([0u8; 20]);
    JsonRpcResponse::success(id, json!(format!("0x{}", hex::encode(addr))))
}

pub fn eth_get_block_by_hash(
    id: Value,
    params: &Value,
    store: &BlockStore,
    chain_id: u64,
) -> JsonRpcResponse {
    let Some(hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    let full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    match build_block_dto_with_full_txs(store, hash, full_txs, chain_id) {
        Some(dto) => JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap()),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_block_by_number(
    id: Value,
    params: &Value,
    store: &BlockStore,
    chain_id: u64,
) -> JsonRpcResponse {
    let Some(bn_str) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number parameter");
    };
    let head_num = head_number(store).unwrap_or(0);
    let Some(number) = parse_block_number(bn_str, head_num) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    let full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    let hash = match store.canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };

    match build_block_dto_with_full_txs(store, hash, full_txs, chain_id) {
        Some(dto) => JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap()),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_block_transaction_count_by_hash(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let Some(hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    JsonRpcResponse::success(id, transaction_count(store, hash))
}

/// `null` when the node does not have the block, otherwise how many
/// transactions it holds.
///
/// This used to answer `0x0` for a block it held only the header of, which is
/// the same wrong answer `eth_getBlockByHash` gave and for the same reason.
/// The two must agree: a caller that reads a count of zero here and an empty
/// `transactions` array there has been told twice that an unfetched block is
/// empty.
fn transaction_count(store: &BlockStore, hash: alloy_primitives::B256) -> Value {
    let Some(header) = store.header(hash).ok().flatten() else {
        return Value::Null;
    };
    match held_or_implied_body(store, hash, &header) {
        Some(Some((txs, _))) => json!(to_hex_u64(txs.len() as u64)),
        Some(None) => json!("0x0"),
        None => Value::Null,
    }
}

pub fn eth_get_block_transaction_count_by_number(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let Some(bn_str) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };
    let head_num = head_number(store).unwrap_or(0);
    let Some(number) = parse_block_number(bn_str, head_num) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    let hash = match store.canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };
    JsonRpcResponse::success(id, transaction_count(store, hash))
}

pub fn eth_get_uncle_count_by_block_hash(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let Some(hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    match store.header(hash) {
        Ok(Some(h)) => JsonRpcResponse::success(id, json!(to_hex_u64(h.uncle_count))),
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_uncle_count_by_block_number(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let Some(bn_str) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };
    let head_num = head_number(store).unwrap_or(0);
    let Some(number) = parse_block_number(bn_str, head_num) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    let hash = match store.canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };
    match store.header(hash) {
        Ok(Some(h)) => JsonRpcResponse::success(id, json!(to_hex_u64(h.uncle_count))),
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_uncle_by_block_hash_and_index(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let Some(hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    let Some(index) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex_u32) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid index");
    };

    match uncle_dto(store, hash, index) {
        Some(dto) => JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap()),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_uncle_by_block_number_and_index(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let Some(bn_str) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };
    let head_num = head_number(store).unwrap_or(0);
    let Some(number) = parse_block_number(bn_str, head_num) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    // The index is validated before the block is looked up, so a malformed
    // index is an error even when the block is unknown -- rskj rejects it in
    // parameter deserialisation, before the method body runs.
    let Some(index) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex_u32) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid index");
    };

    let hash = match store.canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };

    match uncle_dto(store, hash, index) {
        Some(dto) => JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap()),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

// -- internal helpers --------------------------------------------------------

/// One uncle of `block_hash`, rendered as a block. `None` means JSON `null`.
///
/// This mirrors rskj's `Web3Impl.getUncleResultDTO`, which has two behaviours
/// that are not the obvious ones:
///
/// 1. **An out-of-range index is `null`, not an error.** So is an unknown
///    parent block. Only a malformed index is an error, and that is rejected
///    earlier, during parameter parsing.
///
/// 2. **The uncle is rendered with its own body when the node happens to have
///    that block.** rskj calls `blockchain.getBlockByHash(uncleHeader.getHash())`
///    first and only falls back to `Block.createBlockFromHeader` -- an empty
///    block synthesised from the header -- when the lookup misses. An uncle
///    was a real block on a competing branch, so if this node downloaded that
///    branch it has the transactions, and rskj returns them.
///
///    go-ethereum does not do this: it always builds `NewBlockWithHeader(uncle)`
///    and so always answers with empty `transactions` and `uncles`. The
///    consequence is that on RSK the same call against two honest nodes can
///    return different `transactions` and `size` for the same uncle, depending
///    on what each node stored. See `docs/rskj-vs-geth.md`.
///
/// `totalDifficulty` gets the same treatment by accident of rskj's storage
/// layer: `getTotalDifficultyForHash` returns ZERO for a hash it does not
/// have, which is what an unstored uncle hits, and `unwrap_or_default()` here
/// gives the same `0x0`.
fn uncle_dto(
    store: &BlockStore,
    block_hash: alloy_primitives::B256,
    index: u32,
) -> Option<BlockResultDto> {
    // The uncle *headers* live in the parent's body. No body means the node
    // has at most a bare header for this block, which cannot name its uncles.
    let (_, ommers) = store.body(block_hash).ok().flatten()?;
    let uncle_header = ommers.get(index as usize)?;
    let uncle_hash = uncle_header.hash();

    let uncle_body = store.body(uncle_hash).ok().flatten();
    let td = store.total_difficulty(uncle_hash).ok().flatten().unwrap_or_default();

    Some(BlockResultDto::from_header_with_body(
        uncle_header,
        uncle_hash,
        td,
        uncle_body.as_ref(),
        // An uncle is never rendered with full transactions, so the chain id
        // is unused.
        false,
        30,
    ))
}


fn head_number(store: &BlockStore) -> Option<u64> {
    store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
}

/// Height of the last block the node has *executed*, i.e. the newest state it
/// can serve. Distinct from `head_number`, which is the newest header it has
/// downloaded.
fn executed_number(store: &BlockStore) -> Option<u64> {
    store.exec_head().ok()?
        .and_then(|(hash, _)| store.header(hash).ok().flatten())
        .map(|h| h.number)
}

fn head_header(store: &BlockStore) -> Option<rustock_core::types::header::Header> {
    store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
}

fn build_block_dto_with_full_txs(
    store: &BlockStore,
    hash: alloy_primitives::B256,
    full_txs: bool,
    chain_id: u64,
) -> Option<BlockResultDto> {
    let header = store.header(hash).ok()??;
    // A block that exists must not disappear because an auxiliary field will
    // not parse. `ok()?` on the total difficulty turned a decode failure into
    // "no such block", so a single bad value hid the header, the transactions
    // and everything else behind a bare `null` -- with no error to explain it.
    // An unknown total difficulty is reported as zero; the block is still
    // returned.
    let td = store.total_difficulty(hash).ok().flatten().unwrap_or_default();
    let body = held_or_implied_body(store, hash, &header)?;
    Some(BlockResultDto::from_header_with_body(&header, hash, td, body.as_ref(), full_txs, chain_id))
}

/// The block's body, or `None` when the node does not actually have the block.
///
/// Sync is header-first: headers arrive in batches and bodies are filled in
/// afterwards, so a block exists with a header and no body for as long as its
/// body takes to arrive. Rendering that as `transactions: []` answers a
/// question the node cannot answer -- and answers it *wrongly*, because the
/// block does have transactions. rskj cannot reach this state at all: it
/// stores `block.getEncoded()`, body included, under one key, so
/// `getBlockByHash` returns a complete block or `null`. `null` is therefore
/// both the truthful answer and the rskj-compatible one.
///
/// **A missing body is not the same as an empty one.** A block whose header
/// claims an empty transaction trie and no uncles has nothing to store, and
/// some such blocks are held without a body row at all -- genesis is written
/// by `setup_genesis`, which writes the header, total difficulty, canonical
/// entry and head, and no body. Those must still be served, so the header's
/// own claims decide: if it says there is nothing, the empty body is implied.
///
/// Returns `Some(None)` for "held, and genuinely empty", `Some(Some(body))`
/// for "held, with this body", and `None` for "not held".
#[allow(clippy::type_complexity)]
fn held_or_implied_body(
    store: &BlockStore,
    hash: alloy_primitives::B256,
    header: &rustock_core::types::header::Header,
) -> Option<Option<(Vec<rustock_core::Transaction>, Vec<rustock_core::types::header::Header>)>> {
    if let Some(body) = store.body(hash).ok().flatten() {
        return Some(Some(body));
    }
    // Genesis has no transactions, whatever its header says. It is built
    // locally by `setup_genesis`, never fetched from a peer, so "no body row"
    // cannot mean "body not arrived yet" the way it does at any other height.
    //
    // This is load-bearing rather than belt-and-braces. Only mainnet's genesis
    // header carries the real empty-list and empty-trie hashes; testnet's and
    // regtest's carry `B256::ZERO` for `ommers_hash` and `transactions_root`,
    // which is not a root any empty trie produces, so the claim check below
    // says "not empty" and the whole block came back `null` -- by number, by
    // tag and by hash alike. On a chain whose head *is* genesis that made
    // `eth_getBlockByNumber("latest")` answer `null` to every client, which is
    // the state of a fresh regtest node until something is mined.
    //
    // Fixed here rather than in the headers themselves: mainnet's and
    // testnet's genesis hashes are pinned by `known_genesis_hash`, so editing
    // their fields would leave a stored header that does not hash to the key
    // it is stored under.
    if header.number == 0 {
        return Some(None);
    }
    if header_claims_an_empty_body(header) {
        return Some(None);
    }
    None
}

/// Does this header claim a body with nothing in it?
///
/// Both eras of the transaction trie count: RSKIP126 changed the empty root
/// from the Ethereum keccak-of-empty-RLP to the unitrie's, and a node serves
/// blocks from both sides of that fork. Comparing against both avoids
/// threading the activation height through the RPC layer for a question whose
/// answer is two constants.
fn header_claims_an_empty_body(header: &rustock_core::types::header::Header) -> bool {
    use rustock_core::{ordered_tx_trie_root, Header};
    let empty_txs = header.transactions_root == ordered_tx_trie_root(&[], false)
        || header.transactions_root == ordered_tx_trie_root(&[], true);
    let empty_ommers =
        header.ommers_hash == rustock_execution::processor::compute_ommers_hash(&[] as &[Header]);
    empty_txs && empty_ommers
}

pub async fn eth_send_raw_transaction(
    id: Value,
    params: &Value,
    tx_submitter: &Option<Arc<dyn TxSubmitter>>,
) -> JsonRpcResponse {
    let Some(submitter) = tx_submitter else {
        return JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Transaction relay not available");
    };

    let Some(raw_hex) = params.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing raw transaction hex");
    };

    let raw_hex = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
    let Ok(raw_bytes) = hex::decode(raw_hex) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid hex");
    };

    match submitter
        .submit_transaction(alloy_primitives::Bytes::from(raw_bytes))
        .await
    {
        Ok(tx_hash) => JsonRpcResponse::success(id, json!(format!("0x{:x}", tx_hash))),
        Err(e) => JsonRpcResponse::error(id, INVALID_PARAMS, e),
    }
}

/// `eth_bridgeState` — two fields, not the whole Bridge.
///
/// The name and the `BridgeState` class both suggest a full dump. They are
/// misleading: `BridgeState` *holds* the UTXO set, the federation, the release
/// request queue and the pegouts waiting for confirmations, but
/// `stateToMap()` — which is what the RPC returns — exposes only two of them:
///
/// ```java
/// public Map<String, Object> stateToMap() {
///     Map<String, Object> result = new HashMap<>();
///     result.put("rskTxsWaitingForSignatures", this.toStringList(rskTxsWaitingForSignatures.keySet()));
///     result.put("btcBlockchainBestChainHeight", this.btcBlockchainBestChainHeight);
///     return result;
/// }
/// ```
///
/// The rest is only in `getEncoded()`, which the RPC never calls.
///
/// Two further details that are easy to get wrong:
///
/// * **No block parameter.** rskj reads `blockchain.getBestBlock()`
///   unconditionally (`EthModule.bridgeState`). A caller cannot ask about a
///   historical block, so neither does this.
/// * **The hashes carry no `0x` prefix.** `Keccak256.toHexString()` is
///   `Hex.toHexString(bytes)`, which is bare hex — unusual for JSON-RPC, where
///   almost everything else is prefixed, and the sort of difference a consumer
///   discovers by failing to parse.
pub fn eth_bridge_state(id: Value, state: &crate::server::RpcState) -> JsonRpcResponse {
    use rustock_execution::bridge::{btc_store, peg, storage as bridge_storage};

    let Some((root, _header)) = crate::state::resolve_state_root("latest", state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve the best block");
    };
    let Some(trie_store) = state.trie_store.clone() else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "No state available");
    };

    let mut ctx = rustock_execution::bridge_read_context(trie_store, root, None);

    let height = btc_store::load_chain_head(&mut ctx).map(|h| h.height).unwrap_or(0);

    // Keys only: rskj maps `rskTxsWaitingForSignatures.keySet()`, discarding the
    // Bitcoin transactions themselves.
    let key = bridge_storage::bridge_storage_key(
        bridge_storage::PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
    );
    let raw = bridge_storage::bridge_load_raw(&mut ctx, key).unwrap_or_default();
    let waiting = peg::deserialize_rsk_txs_waiting_for_signatures(&raw);
    let hashes: Vec<Value> = waiting.keys().map(|h| json!(hex::encode(h))).collect();

    JsonRpcResponse::success(
        id,
        json!({
            "rskTxsWaitingForSignatures": hashes,
            "btcBlockchainBestChainHeight": height,
        }),
    )
}

/// `eth_getBlocksByNumber(number)` — every block stored at a height, canonical
/// and not, each flagged with which it is.
///
/// rskj-specific (`Web3Impl.eth_getBlocksByNumber`), and it exists because on
/// a merged-mining chain competing blocks at one height are routine rather
/// than exceptional. It is also the question that is hardest to answer from
/// outside: a client that missed a reorg cannot reconstruct the sibling from
/// canonical data, because canonical data is exactly what no longer mentions
/// it.
///
/// Unlike every other block-taking method here, rskj parses this parameter
/// with `HexUtils.stringNumberAsBigInt`, which accepts a **decimal** height as
/// well as `0x`-prefixed hex — and accepts no tags. Its own doc-coverage test
/// calls that out as a property of the retrieval path rather than of the
/// parameter type, so it is reproduced rather than tidied.
pub fn eth_get_blocks_by_number(
    id: Value,
    params: &Value,
    store: &BlockStore,
) -> JsonRpcResponse {
    let Some(raw) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };

    let trimmed = raw.trim();
    let parsed = match trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => trimmed.parse::<u64>().ok(),
    };
    let Some(number) = parsed else {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            format!("invalid blocknumber {raw}"),
        );
    };

    let Ok(hashes) = store.hashes_at_height(number) else {
        return JsonRpcResponse::success(id, json!([]));
    };
    let canonical = store.canonical_hash(number).ok().flatten();

    let mut out = Vec::with_capacity(hashes.len());
    for hash in hashes {
        // Total difficulty is per block rather than per height: siblings sit
        // on different chains and a caller comparing them is exactly the point
        // of this method.
        let Ok(Some(td)) = store.total_difficulty(hash) else { continue };
        out.push(json!({
            "hash": to_hex_b256(&hash),
            "totalDifficulty": format!("0x{td:x}"),
            "inMainChain": Some(hash) == canonical,
        }));
    }

    JsonRpcResponse::success(id, Value::Array(out))
}

/// How long a window `eth_netHashrate` averages over. rskj uses one hour
/// (`Duration.ofHours(1)` in `Web3Impl.eth_netHashrate`), and the figure is
/// meaningless unless both nodes use the same one — people compare it across
/// clients.
const NET_HASHRATE_WINDOW_SECS: u64 = 3600;

/// `eth_netHashrate()` — the **network's** hash rate, not this node's.
///
/// Under merged mining this is the number that says how much Bitcoin hash
/// power is currently securing the chain, which is why it is worth having
/// even on a node that mines nothing.
///
/// Reproduces rskj's `HashRateCalculator.calculateNetHashRate`:
///
/// - walk back from the best block by parent hash;
/// - **stop at the first block whose timestamp falls outside the window** —
///   not skip it, stop. A block timestamped in the future therefore ends the
///   walk immediately, which is rskj's behaviour and is reproduced rather
///   than corrected;
/// - sum each counted block's own difficulty **plus its uncles'** — rskj sums
///   `Block.getCumulativeDifficulty()`, which despite the name is the block's
///   difficulty plus the sum of its uncles', not the chain total;
/// - divide by the window in seconds.
///
/// Counting uncle difficulty is not incidental: an uncle is real work that
/// secured the chain, and on a merged-mining network there are a lot of them.
pub fn eth_net_hashrate(id: Value, store: &BlockStore) -> JsonRpcResponse {
    // rskj declares this `BigInteger` and so answers with a JSON **number**,
    // not the `0x` quantity string every neighbouring method returns. That is
    // a real difference in the wire format and is reproduced, because a client
    // written against rskj parses a number here.
    //
    // It must be the **exact** integer, which is why this crate builds
    // serde_json with `arbitrary_precision`. Two cheaper representations were
    // tried and are both wrong: a `u64` clamps, and an `f64` renders as
    // `2.443e+20`, which a strict integer parser (Go's `big.Int`, Java's
    // `BigInteger`) rejects where rskj's plain digits are accepted.
    JsonRpcResponse::success(id, exact_number(hashrate_over_window(store, None)))
}

/// A `U256` as an exact JSON number.
///
/// Mainnet needs this: at the difficulty observed on 2026-09-27 the network
/// figure is about 2.4e20, **thirteen times `u64::MAX`**. An earlier version
/// clamped to `u64::MAX` on the reasoning that the ceiling was orders of
/// magnitude away; it was not, and the method returned that same wrong
/// constant on every call.
fn exact_number(v: alloy_primitives::U256) -> Value {
    serde_json::from_str::<Value>(&v.to_string()).unwrap_or_else(|_| json!(0))
}

/// `eth_hashrate()` — **this node's** share of recent work, not the network's.
///
/// rskj chooses between two calculators at startup on whether the miner server
/// is enabled (`RskContext:709-715`):
///
/// - `HashRateCalculatorNonMining` returns `BigInteger.ZERO`;
/// - `HashRateCalculatorMining` runs the same walk as the network figure with
///   one extra predicate, `coinbaseAddress.equals(header.getCoinbase())`.
///
/// So a node that does not mine answering zero is not a placeholder — it is
/// what rskj answers. See #176.
///
/// Unlike its neighbour this returns a `0x` quantity **string**: rskj declares
/// `eth_hashrate` as `String` via `toQuantityJsonHex` and `eth_netHashrate` as
/// `BigInteger`, one line apart. The two disagree upstream and the disagreement
/// is reproduced, because clients parse each the way rskj sends it.
pub fn eth_hashrate_for(
    id: Value,
    store: &BlockStore,
    coinbase: Option<alloy_primitives::Address>,
) -> JsonRpcResponse {
    let Some(coinbase) = coinbase else {
        // No miner configured: rskj's non-mining calculator, exactly.
        return JsonRpcResponse::success(id, json!("0x0"));
    };
    let rate = hashrate_over_window(store, Some(coinbase));
    JsonRpcResponse::success(id, json!(format!("0x{rate:x}")))
}

/// Difficulty produced per second over the window, optionally counting only
/// blocks mined to `coinbase`.
///
/// rskj's `HashRateCalculator.calculateHashRate` with its `countCondition`
/// predicate: `b -> true` for the network figure, an ownership test for this
/// node's. One walk, two callers, because two walks would eventually disagree.
fn hashrate_over_window(
    store: &BlockStore,
    coinbase: Option<alloy_primitives::Address>,
) -> alloy_primitives::U256 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let from = now.saturating_sub(NET_HASHRATE_WINDOW_SECS);

    let mut total = alloy_primitives::U256::ZERO;
    let mut cursor = match store.head() {
        Ok(Some(hash)) => Some(hash),
        // rskj returns zero when there is no best block rather than erroring.
        _ => return alloy_primitives::U256::ZERO,
    };

    // Bounded so a corrupt parent chain cannot spin here. One hour is ~120
    // blocks at 30s; the cap is far above any honest window and is a
    // stop-loss, not a policy.
    let mut budget = 10_000u32;
    while let Some(hash) = cursor {
        if budget == 0 {
            break;
        }
        budget -= 1;

        // The body is needed for the uncles' difficulties, which the header
        // does not carry -- it records only `uncle_count`.
        let Ok(Some(block)) = store.block(hash) else { break };
        let ts = block.header.timestamp;
        if ts < from || ts > now {
            break;
        }

        // The window decides which blocks are walked; the predicate decides
        // which are counted. An uncle is credited to the block that included
        // it, as rskj does -- `getCumulativeDifficulty` sums them into the
        // including block and the ownership test is applied to that block.
        let counts = coinbase.is_none_or(|want| block.header.beneficiary == want);
        if counts {
            total = total.saturating_add(block.header.difficulty);
            for uncle in &block.ommers {
                total = total.saturating_add(uncle.difficulty);
            }
        }

        if block.header.number == 0 {
            break;
        }
        cursor = Some(block.header.parent_hash);
    }

    total / alloy_primitives::U256::from(NET_HASHRATE_WINDOW_SECS)
}
