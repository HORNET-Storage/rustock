use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use rustock_core::config::ChainConfig;
use rustock_execution::RskHardforkConfig;
use rustock_networking::peers::PeerStore;
use rustock_storage::BlockStore;
use rustock_trie::TrieStore;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::evm;
use crate::txpool;
use crate::types::*;
use crate::{admin, call, debug, eth, logs, mnr, net, proof, rsk, sco, sign, state, trace, tx, web3};

/// Trait for submitting raw transactions, allowing the RPC layer to use
/// the P2P relay without depending on the sync crate directly.
#[async_trait::async_trait]
pub trait TxSubmitter: Send + Sync {
    async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> Result<alloy_primitives::B256, String>;
}

/// What `eth_gasPrice` needs, without the RPC crate depending on sync.
pub trait GasPriceSource: Send + Sync {
    /// rskj `GasPriceTracker.getGasPrice()`.
    fn gas_price(&self) -> alloy_primitives::U256;

    /// rskj `GasPriceTracker.isFeeMarketWorking()`: the last 50 blocks at
    /// least 90% full on average.
    ///
    /// `gas_price` is only an answer when this is true. The tracker computes
    /// its percentile either way, and on a chain with spare capacity that
    /// percentile describes a market that is not setting the price -- see
    /// [`crate::eth::eth_gas_price`] for what goes wrong when it is used
    /// anyway.
    fn is_fee_market_working(&self) -> bool;
}

/// Trait for reading from the transaction pool without depending on the sync crate.
pub trait TxPoolReader: Send + Sync {
    fn get_pending_tx(&self, hash: &alloy_primitives::B256) -> Option<(rustock_core::Transaction, alloy_primitives::Address, alloy_primitives::B256)>;
    fn pending_nonce(&self, addr: &alloy_primitives::Address) -> Option<u64>;
    fn pool_status(&self) -> (usize, usize);
    /// The whole pool, grouped the way `txpool_content` reports it.
    fn pool_content(&self) -> PoolContent;
    /// An address's rate-limiter quota: available virtual gas, and when it was
    /// last refreshed in epoch milliseconds. `None` when the limiter is not
    /// tracking the address, which is what rskj's map lookup returns.
    fn quota_report(&self, address: &alloy_primitives::Address) -> Option<(f64, u64)>;
}

/// The pool's contents, sender-major and nonce-ordered within each sender --
/// rskj's `groupTransactions` shape, produced once and rendered twice, by
/// `txpool_content` and `txpool_inspect`.
///
/// `pending` is what can execute now; `queued` is what waits on a nonce gap.
/// Keeping them apart is the informative part of the answer: a flat list
/// cannot say whether a transaction is stuck or merely unmined.
#[derive(Default)]
pub struct PoolContent {
    pub pending: Vec<(alloy_primitives::Address, Vec<(u64, rustock_core::Transaction)>)>,
    pub queued: Vec<(alloy_primitives::Address, Vec<(u64, rustock_core::Transaction)>)>,
}

/// Shared application state available to every RPC handler.
#[derive(Clone)]
pub struct RpcState {
    pub store: Arc<BlockStore>,
    pub peer_store: Arc<PeerStore>,
    pub config: Arc<ChainConfig>,
    pub tx_submitter: Option<Arc<dyn TxSubmitter>>,
    pub trie_store: Option<Arc<dyn TrieStore>>,
    pub hardfork_cfg: Option<RskHardforkConfig>,
    pub filter_store: Arc<logs::FilterStore>,
    pub tx_pool: Option<Arc<dyn TxPoolReader>>,
    /// Live depth of the inbound wire-message queue, for
    /// `debug_wireProtocolQueueSize`.
    pub wire_queue_depth: Option<Arc<std::sync::atomic::AtomicUsize>>,
    /// Supplies `eth_gasPrice`. `None` falls back to the head block's minimum.
    pub gas_price: Option<Arc<dyn GasPriceSource>>,
    /// Present only when the node runs the epoch trie backend.
    pub epoch_store: Option<Arc<rustock_storage::epoch_store::EpochTrieStore>>,
    /// Snapshot bookkeeping for the `evm_` namespace. `None` means the
    /// namespace is off, which is the default -- see `crate::evm`.
    pub snapshots: Option<Arc<crate::evm::SnapshotManager>>,
    /// The miner, present only when the node was started with mining enabled.
    /// Absent, the `mnr_*` namespace answers as it always did.
    pub miner: Option<Arc<dyn mnr::MiningService>>,
    /// Drives `evm_startMining`. Present whenever `miner` is, since it
    /// is that miner with a loop around it; `evm_mine` reaches the miner
    /// directly and does not need this.
    pub auto_miner: Option<Arc<crate::evm::AutoMiner>>,
    /// Keys the operator supplied with `--wallet-file`, and the only keys
    /// this node will ever sign with.
    ///
    /// `None` -- the default -- means `eth_accounts` is empty and
    /// `eth_sign`, `eth_signTransaction` and `eth_sendTransaction` are
    /// refused, which is how the node behaved before it could hold keys
    /// at all. Nothing here can reach the node identity key or a miner
    /// key: a signature is produced only for an account whose key was
    /// handed over on purpose.
    pub wallet: Option<Arc<crate::wallet::Wallet>>,
    /// Administrative methods are refused unless the operator enabled them.
    pub admin_enabled: bool,
    /// Burial depth used when an admin collection request names no block.
    pub gc_burial: u64,
    /// States a forced collection must keep beyond the collection root --
    /// the snapshot checkpoints this node serves, which sit far deeper than
    /// the burial depth (#143). A closure because the checkpoint moves, and
    /// the answer has to be the one true at the moment of the cycle. Absent,
    /// or empty, means nothing to pin.
    pub gc_pins: Option<Arc<dyn Fn() -> Vec<alloy_primitives::B256> + Send + Sync>>,
    /// Blocks kept below the head when a prune request names no block.
    pub prune_keep_depth: u64,
    /// Most blocks one prune sweep may remove.
    pub prune_max_batch: u64,
    /// Widest block range an `eth_getLogs` may span. rskj's
    /// `rpc.logs.maxBlocksToQuery`; see `logs::DEFAULT_MAX_BLOCK_RANGE`.
    pub logs_max_blocks: u64,
    /// Answer `eth_estimateGas` by binary search instead of in a single pass.
    /// False by default -- see `rustock_execution::gas_estimator`.
    pub gas_estimator_binary_search: bool,
    /// Peer scoring and banning. Absent, the `sco_*` namespace reports itself
    /// as unavailable rather than answering from an empty table.
    pub scoring: Option<Arc<rustock_networking::scoring::ScoringService>>,
    /// Chain events for `eth_subscribe`. Absent, a subscription is accepted
    /// and simply never fires -- which is the right shape for a node built
    /// without an event source, and keeps the WebSocket transport testable
    /// without one.
    pub events: Option<crate::subscribe::EventSender>,
}

/// Starts the JSON-RPC HTTP server on the given host and port.
pub async fn start_rpc_server(
    host: &str,
    port: u16,
    state: RpcState,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", post(handle_rpc))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    info!("RPC server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_rpc(
    State(state): State<RpcState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(_) => {
            let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Invalid UTF-8");
            return (StatusCode::OK, Json(json!(resp)));
        }
    };

    if body_str.starts_with('[') {
        let requests: Vec<JsonRpcRequest> = match serde_json::from_str(body_str) {
            Ok(r) => r,
            Err(_) => {
                let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Parse error");
                return (StatusCode::OK, Json(json!(resp)));
            }
        };

        if requests.is_empty() {
            let resp = JsonRpcResponse::error(Value::Null, INVALID_REQUEST, "Empty batch");
            return (StatusCode::OK, Json(json!(resp)));
        }

        let mut responses = Vec::with_capacity(requests.len());
        for req in requests {
            responses.push(dispatch(&state, req).await);
        }
        (StatusCode::OK, Json(json!(responses)))
    } else {
        let request: JsonRpcRequest = match serde_json::from_str(body_str) {
            Ok(r) => r,
            Err(_) => {
                let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Parse error");
                return (StatusCode::OK, Json(json!(resp)));
            }
        };
        let response = dispatch(&state, request).await;
        (StatusCode::OK, Json(json!(response)))
    }
}

async fn dispatch(state: &RpcState, req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.unwrap_or(Value::Null);
    let params = &req.params;

    match req.method.as_str() {
        // -- web3 --
        "web3_clientVersion" => web3::web3_client_version(id),
        "web3_sha3" => web3::web3_sha3(id, params),

        // -- net --
        "net_version" => net::net_version(id, &state.config),
        "net_peerCount" => net::net_peer_count(id, &state.peer_store).await,
        "net_listening" => net::net_listening(id),
        "net_peerList" => net::net_peer_list(id, &state.peer_store).await,

        // -- eth --
        "eth_protocolVersion" => eth::eth_protocol_version(id),
        "eth_syncing" => eth::eth_syncing(id, &state.store, &state.peer_store).await,
        "eth_chainId" => eth::eth_chain_id(id, &state.config),
        "eth_blockNumber" => eth::eth_block_number(id, &state.store),
        "eth_gasPrice" => eth::eth_gas_price(id, state),
        "eth_mining" => eth::eth_mining(id),
        "eth_hashrate" => eth::eth_hashrate_for(
            id,
            &state.store,
            state.miner.as_ref().map(|m| alloy_primitives::Address::from(m.coinbase())),
        ),
        "eth_accounts" => sign::eth_accounts(id, state),
        "eth_pendingTransactions" => eth::eth_pending_transactions(id),
        "eth_bridgeState" => eth::eth_bridge_state(id, state),
        "eth_coinbase" => eth::eth_coinbase(id, &state.miner),
        "eth_getBlockByHash" => eth::eth_get_block_by_hash(id, params, &state.store),
        "eth_getBlockByNumber" => eth::eth_get_block_by_number(id, params, &state.store),
        "eth_getProof" => proof::eth_get_proof(id, params, state),
        "eth_getBlockTransactionCountByHash" => eth::eth_get_block_transaction_count_by_hash(id, params, &state.store),
        "eth_getBlockTransactionCountByNumber" => eth::eth_get_block_transaction_count_by_number(id, params, &state.store),
        "eth_getUncleCountByBlockHash" => eth::eth_get_uncle_count_by_block_hash(id, params, &state.store),
        "eth_getUncleCountByBlockNumber" => eth::eth_get_uncle_count_by_block_number(id, params, &state.store),
        "eth_getUncleByBlockHashAndIndex" => eth::eth_get_uncle_by_block_hash_and_index(id, params, &state.store),
        "eth_getUncleByBlockNumberAndIndex" => eth::eth_get_uncle_by_block_number_and_index(id, params, &state.store),

        // -- rpc --
        // The answer decides what a client will even attempt: anything that
        // gates on `rpc_modules` skips a namespace that is missing here, so
        // omitting one this server dispatches makes working methods
        // unreachable. `debug`, `trace` and `sco` were absent despite being
        // answered unconditionally, and `evm` and `txpool` were absent even
        // when enabled. Each entry below is a namespace this match arm
        // actually serves, under the same condition it serves it.
        "rpc_modules" => {
            let mut modules = serde_json::Map::new();
            for name in ["eth", "net", "web3", "rpc", "rsk", "debug", "trace", "sco"] {
                modules.insert(name.to_string(), json!("1.0"));
            }
            if state.miner.is_some() {
                modules.insert("mnr".to_string(), json!("1.0"));
            }
            // `snapshots` is `Some` exactly when `--dev-rpc` is on, which is
            // what gates the `evm_` namespace.
            if state.snapshots.is_some() {
                modules.insert("evm".to_string(), json!("1.0"));
            }
            if state.tx_pool.is_some() {
                modules.insert("txpool".to_string(), json!("1.0"));
            }
            JsonRpcResponse::success(id, Value::Object(modules))
        }

        // -- mnr: merged mining --
        "mnr_getWork" | "mnr_submitBitcoinBlock" | "mnr_submitBitcoinBlockTransactions"
        | "mnr_submitBitcoinBlockPartialMerkle"
            if state.miner.is_none() =>
        {
            mining_not_enabled(id, &req.method)
        }
        "mnr_getWork" => mnr::mnr_get_work(id, state.miner.as_ref().expect("miner present")),
        "mnr_submitBitcoinBlock" => {
            mnr::mnr_submit_bitcoin_block(id, params, state.miner.as_ref().expect("miner present"))
        }
        "mnr_submitBitcoinBlockTransactions" => mnr::mnr_submit_bitcoin_block_transactions(
            id, params, state.miner.as_ref().expect("miner present"),
        ),
        "mnr_submitBitcoinBlockPartialMerkle" => mnr::mnr_submit_bitcoin_block_partial_merkle(
            id, params, state.miner.as_ref().expect("miner present"),
        ),

        "eth_getBlocksByNumber" => eth::eth_get_blocks_by_number(id, &req.params, &state.store),
        "eth_netHashrate" => eth::eth_net_hashrate(id, &state.store),

        // -- evm: development chain control, off unless --dev-rpc --
        "evm_snapshot" => evm::evm_snapshot(id, state),
        "evm_revert" => evm::evm_revert(id, &req.params, state),
        "evm_reset" => evm::evm_reset(id, state),
        "evm_mine" => evm::evm_mine(id, state),
        "evm_increaseTime" => evm::evm_increase_time(id, &req.params, state),
        "evm_startMining" => evm::evm_set_mining(id, state, true),
        "evm_stopMining" => evm::evm_set_mining(id, state, false),

        // -- rsk --
        "rsk_protocolVersion" => rsk::rsk_protocol_version(id),

        // Administrative. Refused outright unless --rpc-admin was passed, and
        // reported as unknown rather than forbidden so that a node without them
        // looks the same as one that never had them.
        "rsk_collectTrie" | "rsk_collectTrieStatus" | "rsk_pruneBlocks" | "rsk_storageStatus"
        | "rsk_flush" | "rsk_shutdown"
            if !state.admin_enabled =>
        {
            JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Method not found")
        }
        "rsk_collectTrie" => admin::rsk_collect_trie(
            id,
            &req.params,
            &state.store,
            &state.epoch_store,
            state.gc_burial,
            state.gc_pins.as_ref().map(|f| f()).unwrap_or_default(),
        ),
        "rsk_collectTrieStatus" => admin::rsk_collect_trie_status(id, &state.epoch_store),
        "rsk_flush" => admin::rsk_flush(id, state),
        "rsk_shutdown" => admin::rsk_shutdown(id, state),
        "rsk_pruneBlocks" => admin::rsk_prune_blocks(
            id, &req.params, &state.store, state.prune_keep_depth, state.prune_max_batch,
        ),
        "rsk_storageStatus" => admin::rsk_storage_status(id, &state.store, &state.epoch_store),
        "rsk_getStorageBytesAt" => rsk::rsk_get_storage_bytes_at(id, params, state),
        "rsk_getRawTransactionReceiptByHash" => {
            rsk::rsk_get_raw_transaction_receipt_by_hash(id, params, &state.store)
        }
        "rsk_getTransactionReceiptNodesByHash" => {
            rsk::rsk_get_transaction_receipt_nodes_by_hash(id, params, &state.store)
        }
        "rsk_getRawBlockHeaderByHash" => rsk::rsk_get_raw_block_header_by_hash(id, params, &state.store),
        "rsk_getRawBlockHeaderByNumber" => rsk::rsk_get_raw_block_header_by_number(id, params, &state.store),

        "eth_sendRawTransaction" => eth::eth_send_raw_transaction(id, params, &state.tx_submitter).await,

        // -- state queries --
        "eth_getBalance" => state::eth_get_balance(id, params, state),
        "eth_getTransactionCount" => state::eth_get_transaction_count(id, params, state),
        "eth_getCode" => state::eth_get_code(id, params, state),
        "eth_getStorageAt" => state::eth_get_storage_at(id, params, state),

        // -- execution calls --
        "eth_call" => call::eth_call(id, params, state),
        "eth_estimateGas" => call::eth_estimate_gas(id, params, state),

        // -- transaction and receipt lookup --
        "eth_getTransactionByHash" => tx::eth_get_transaction_by_hash(id, params, state),
        "eth_getTransactionByBlockHashAndIndex" => tx::eth_get_transaction_by_block_hash_and_index(id, params, state),
        "eth_getTransactionByBlockNumberAndIndex" => tx::eth_get_transaction_by_block_number_and_index(id, params, state),
        "eth_getTransactionReceipt" => tx::eth_get_transaction_receipt(id, params, state),

        // -- log filtering --
        "eth_getLogs" => logs::eth_get_logs(id, params, state),
        "eth_newFilter" => logs::eth_new_filter(id, params, state),
        "eth_newBlockFilter" => logs::eth_new_block_filter(id, state),
        "eth_newPendingTransactionFilter" => logs::eth_new_pending_transaction_filter(id, state),
        "eth_getFilterChanges" => logs::eth_get_filter_changes(id, params, state),
        "eth_getFilterLogs" => logs::eth_get_filter_logs(id, params, state),
        "eth_uninstallFilter" => logs::eth_uninstall_filter(id, params, state),

        // Answered out of the operator-supplied wallet, and refused with
        // METHOD_NOT_FOUND when there is none -- which is what they did
        // before a wallet was possible.
        "eth_sendTransaction" => sign::eth_send_transaction(id, params, state).await,
        "eth_sign" => sign::eth_sign(id, params, state),
        "eth_signTransaction" => sign::eth_sign_transaction(id, params, state),

        // -- unsupported methods --
        "eth_getCompilers" | "eth_compileSolidity" => {
            execution_not_available(id, &req.method)
        }

        "debug_wireProtocolQueueSize" => debug::debug_wire_protocol_queue_size(id, state),
        "debug_traceTransaction" => debug::debug_trace_transaction(id, params, state),
        "debug_traceBlockByHash" => debug::debug_trace_block_by_hash(id, params, state),
        "debug_traceBlockByNumber" => debug::debug_trace_block_by_number(id, params, state),
        "debug_accountTransactionQuota" => debug::debug_account_transaction_quota(id, params, state),

        "sco_banAddress" => sco::sco_ban_address(id, params, state),
        "sco_unbanAddress" => sco::sco_unban_address(id, params, state),
        "sco_bannedAddresses" => sco::sco_banned_addresses(id, state),
        "sco_peerList" => sco::sco_peer_list(id, state),
        "sco_clearPeerScoring" => sco::sco_clear_peer_scoring(id, params, state),
        "sco_reputationSummary" => sco::sco_reputation_summary(id, state),
        "sco_isWelcome" => sco::sco_is_welcome(id, params, state),

        "trace_transaction" => trace::trace_transaction(id, params, state),
        "trace_block" => trace::trace_block(id, params, state),
        "trace_get" => trace::trace_get(id, params, state),
        "trace_filter" => trace::trace_filter(id, params, state),

        "txpool_content" => txpool::txpool_content(id, state),
        "txpool_inspect" => txpool::txpool_inspect(id, state),
        "txpool_status" => txpool::txpool_status(id, state),

        m if m.starts_with("debug_")
            || m.starts_with("trace_")
            || m.starts_with("personal_")
            || m.starts_with("evm_")
            || m.starts_with("txpool_")
            || m.starts_with("db_") => {
            execution_not_available(id, m)
        }

        _ => JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Method not found"),
    }
}

/// Reported as a missing method rather than a refusal: a node built without a
/// miner should look the same to a pool as one that never had the namespace.
fn mining_not_enabled(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        METHOD_NOT_FOUND,
        format!("Method {} requires mining, which is not enabled on this node", method),
    )
}

pub(crate) fn execution_not_available(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        METHOD_NOT_FOUND,
        format!("Method {} requires execution engine (not yet available)", method),
    )
}

/// Dispatch one request. Used by the WebSocket transport, which speaks the
/// same JSON-RPC over a different socket, and by the tests.
pub async fn dispatch_rpc(state: &RpcState, req: JsonRpcRequest) -> JsonRpcResponse {
    dispatch(state, req).await
}

#[cfg(test)]
pub(crate) async fn dispatch_for_test(state: &RpcState, req: JsonRpcRequest) -> JsonRpcResponse {
    dispatch(state, req).await
}
