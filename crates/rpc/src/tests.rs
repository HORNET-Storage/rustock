use crate::server::{dispatch_for_test, RpcState};
use crate::types::*;
use alloy_primitives::{Address, Bloom, B256, U256, Bytes};
use rustock_core::config::ChainConfig;
use rustock_core::types::header::Header;
use rustock_networking::peers::PeerStore;
use rustock_storage::BlockStore;
use serde_json::{json, Value};
use std::sync::Arc;

fn test_header(number: u64) -> Header {
    Header {
        parent_hash: B256::ZERO,
        // A real header never carries ZERO here. An empty block's roots are
        // the empty-trie roots, and the block getters now rely on that to tell
        // "this block has nothing in it" from "we have not downloaded its body
        // yet" -- so a fixture using ZERO would be testing a header the chain
        // cannot produce. See `header_claims_an_empty_body`.
        ommers_hash: rustock_execution::processor::compute_ommers_hash(&[]),
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: rustock_core::ordered_tx_trie_root(&[], true),
        receipts_root: B256::ZERO,
        logs_bloom: Bloom::ZERO,
        extension_data: None,
        difficulty: U256::from(1000),
        number,
        gas_limit: U256::from(8_000_000),
        gas_used: 21000,
        timestamp: 1_600_000_000 + number,
        extra_data: Bytes::new(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::from(59_240_000),
        uncle_count: 0,
        umm_root: None,
        version_fields: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
    }
}

fn setup_state() -> (RpcState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let header = test_header(42);
    store.update_head(&header, U256::from(42_000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };
    (state, tmp)
}

fn make_request(method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        method: method.to_string(),
        params,
        id: Some(json!(1)),
    }
}

// ========== web3 ==========

#[tokio::test]
async fn test_web3_client_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("web3_clientVersion", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("Rustock/0.1.0"));
}

#[tokio::test]
async fn test_web3_sha3() {
    let (state, _tmp) = setup_state();
    let req = make_request("web3_sha3", json!(["0x68656c6c6f"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let hash = result.as_str().unwrap();
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66);
}

#[tokio::test]
async fn test_web3_sha3_invalid_hex() {
    let (state, _tmp) = setup_state();
    let req = make_request("web3_sha3", json!(["not_hex"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
}

// ========== net ==========

/// `net_version` is the chain id in decimal, not the network id -- see the
/// method's own comment for rskj's implementation. This test used to assert
/// `network_id`, which pinned the disagreement: the node answered 775 on
/// mainnet where rskj answers 30, and contradicted its own `eth_chainId`.
#[tokio::test]
async fn test_net_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_version", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let version = resp.result.unwrap();
    assert_eq!(version, json!(ChainConfig::mainnet().chain_id.to_string()));
    assert_eq!(version, json!("30"), "rskj answers 30 on mainnet");

    // And it must agree with eth_chainId, which reports the same number in hex.
    let chain_id = dispatch_for_test(&state, make_request("eth_chainId", json!([])))
        .await.result.unwrap();
    let as_dec = u64::from_str_radix(
        chain_id.as_str().unwrap().trim_start_matches("0x"), 16,
    ).unwrap();
    assert_eq!(
        version, json!(as_dec.to_string()),
        "net_version and eth_chainId must name the same chain"
    );
}

#[tokio::test]
async fn test_net_listening() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_listening", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(true));
}

#[tokio::test]
async fn test_net_peer_count() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_peerCount", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_net_peer_list_empty() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_peerList", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!([]));
}

// ========== eth ==========

#[tokio::test]
async fn test_eth_protocol_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_protocolVersion", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x3e"));
}

#[tokio::test]
async fn test_eth_chain_id() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_chainId", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x1e"));
}

#[tokio::test]
async fn test_eth_block_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_blockNumber", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x2a"));
}

#[tokio::test]
async fn test_eth_syncing_not_syncing() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_syncing", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(false));
}

#[tokio::test]
async fn test_eth_syncing_reports_execution_backlog() {
    // The failure this method used to hide. Header download and execution are
    // separate pipelines: when execution wedges, the downloaded head keeps
    // climbing with the network while the executed head stands still. Taking
    // `currentBlock` from the downloaded head made such a node answer `false`
    // -- fully synced -- while serving state 100 blocks stale.
    let (state, _tmp) = setup_state();

    let executed = test_header(42);
    state.store.put_header(&executed).unwrap();
    state
        .store
        .set_exec_head(executed.hash(), executed.state_root)
        .unwrap();

    // Headers ran ahead; nothing executed them.
    let downloaded = test_header(142);
    state
        .store
        .update_head(&downloaded, U256::from(142_000))
        .unwrap();

    let req = make_request("eth_syncing", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();

    assert_ne!(result, json!(false), "a 100-block execution backlog is not 'synced'");
    assert_eq!(
        result["currentBlock"],
        json!("0x2a"),
        "currentBlock must be the executed head, not the downloaded one"
    );
    assert_eq!(
        result["highestBlock"],
        json!("0x8e"),
        "downloaded-but-unexecuted blocks count towards the target even with no peers"
    );
}

#[tokio::test]
async fn test_eth_syncing_false_once_execution_catches_up() {
    // The complement: execution level with the downloaded head is synced, and
    // must not report a backlog just because there are no peers to compare to.
    let (state, _tmp) = setup_state();

    let head = test_header(42);
    state.store.put_header(&head).unwrap();
    state
        .store
        .set_exec_head(head.hash(), head.state_root)
        .unwrap();

    let req = make_request("eth_syncing", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(false));
}

#[tokio::test]
async fn test_eth_gas_price() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_gasPrice", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert!(result.as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn test_eth_mining() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_mining", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(false));
}

#[tokio::test]
async fn test_eth_accounts() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_accounts", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!([]));
}

#[tokio::test]
async fn test_eth_get_block_by_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0x2a", false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["number"], json!("0x2a"));
    assert_eq!(result["gasUsed"], json!("0x5208"));
    assert!(result["hash"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn test_eth_get_block_by_number_latest() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["latest", false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["number"], json!("0x2a"));
}

#[tokio::test]
async fn test_eth_get_block_by_number_with_importer_written_td() {
    // Every existing test writes total difficulty through
    // `put_total_difficulty`, which RLP-encodes it. The rskj import wrote the
    // same column family as raw 32 big-endian bytes, and nothing here ever
    // exercised that -- so `eth_getBlockByNumber` returned null for all 9.2M
    // imported blocks while the whole suite stayed green.
    let (state, _tmp) = setup_state();
    let header = test_header(43);
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_canonical_hash(43, hash).unwrap();
    state
        .store
        .put_total_difficulty_raw(hash, &U256::from(99_u64).to_be_bytes::<32>())
        .unwrap();

    let req = make_request("eth_getBlockByNumber", json!(["0x2b", false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_ne!(result, json!(null), "an imported block must not read as missing");
    assert_eq!(result["number"], json!("0x2b"));
    assert_eq!(result["totalDifficulty"], json!("0x63"));
}

#[tokio::test]
async fn test_eth_get_block_by_number_survives_an_unreadable_td() {
    // Defence in depth for the same failure: whatever the encoding, a block
    // that exists should still be returned. Losing the total difficulty is not
    // a reason to claim the block does not exist.
    let (state, _tmp) = setup_state();
    let header = test_header(44);
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_canonical_hash(44, hash).unwrap();
    state
        .store
        .put_total_difficulty_raw(hash, &[0xFF, 0xFF, 0xFF])
        .unwrap();

    let req = make_request("eth_getBlockByNumber", json!(["0x2c", false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_ne!(result, json!(null), "block must survive a corrupt total difficulty");
    assert_eq!(result["number"], json!("0x2c"));
    assert_eq!(result["totalDifficulty"], json!("0x0"), "unknown is reported as zero");
}

#[tokio::test]
async fn test_eth_get_block_by_number_not_found() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0xfffff", false]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_block_by_hash() {
    let (state, _tmp) = setup_state();

    let head_hash = state.store.head().unwrap().unwrap();
    let hash_str = format!("{:#x}", head_hash);

    let req = make_request("eth_getBlockByHash", json!([hash_str, false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["number"], json!("0x2a"));
}

#[tokio::test]
async fn test_eth_get_block_by_hash_not_found() {
    let (state, _tmp) = setup_state();
    let hash = format!("{:#x}", B256::repeat_byte(0xff));
    let req = make_request("eth_getBlockByHash", json!([hash, false]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_block_transaction_count_by_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockTransactionCountByNumber", json!(["0x2a"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_uncle_count_by_block_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getUncleCountByBlockNumber", json!(["0x2a"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

// ========== rpc ==========

#[tokio::test]
async fn test_rpc_modules() {
    let (state, _tmp) = setup_state();
    let req = make_request("rpc_modules", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let modules = resp.result.unwrap();
    assert_eq!(modules["eth"], json!("1.0"));
    assert_eq!(modules["net"], json!("1.0"));
    assert_eq!(modules["web3"], json!("1.0"));
    assert_eq!(modules["rsk"], json!("1.0"));
}

// ========== rsk ==========

#[tokio::test]
async fn test_rsk_protocol_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("rsk_protocolVersion", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x1"));
}

#[tokio::test]
async fn test_rsk_get_raw_block_header_by_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("rsk_getRawBlockHeaderByNumber", json!(["0x2a"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let rlp_hex = result.as_str().unwrap();
    assert!(rlp_hex.starts_with("0x"));
    assert!(rlp_hex.len() > 10);
}

#[tokio::test]
async fn test_rsk_get_raw_block_header_by_hash() {
    let (state, _tmp) = setup_state();
    let head_hash = state.store.head().unwrap().unwrap();
    let hash_str = format!("{:#x}", head_hash);
    let req = make_request("rsk_getRawBlockHeaderByHash", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert!(result.as_str().unwrap().starts_with("0x"));
}

// ========== dispatch / error handling ==========

#[tokio::test]
async fn test_method_not_found() {
    let (state, _tmp) = setup_state();
    let req = make_request("nonexistent_method", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
}

/// `eth_sendTransaction` moved out of this list when the node learned to
/// hold keys -- it is refused for want of a wallet now, not for want of
/// an execution engine. The compilation methods are what is left.
#[tokio::test]
async fn test_unsupported_eth_method() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getCompilers", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.code, METHOD_NOT_FOUND);
    assert!(err.message.contains("execution engine"));
}

#[tokio::test]
async fn test_debug_trace_transaction_rejects_a_malformed_hash() {
    let (state, _tmp) = setup_state();
    let req = make_request("debug_traceTransaction", json!(["0x1234"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some(), "not a 32-byte hash");
}

/// A transaction the node has never seen is `null`, not an error: the caller
/// asked a reasonable question and the answer is "not here".
#[tokio::test]
async fn test_debug_trace_transaction_unknown_is_null() {
    let (state, _tmp) = setup_state();
    let req = make_request(
        "debug_traceTransaction",
        json!([format!("{:#x}", B256::repeat_byte(0xab))]),
    );
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

/// A block with no body cannot be replayed, and replay is the only way to
/// reconstruct a transaction's pre-state.
#[tokio::test]
async fn test_debug_trace_block_without_a_body_is_null() {
    let (state, _tmp) = setup_state();
    let header = test_header(91);
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_canonical_hash(91, hash).unwrap();

    let resp = dispatch_for_test(
        &state,
        make_request("debug_traceBlockByHash", json!([format!("{:#x}", hash)])),
    )
    .await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_unsupported_personal_method() {
    let (state, _tmp) = setup_state();
    let req = make_request("personal_unlockAccount", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
}

#[tokio::test]
async fn test_txpool_status_without_a_pool_is_unavailable() {
    let (state, _tmp) = setup_state();
    let req = make_request("txpool_status", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
}

// ========== BlockResultDTO format ==========

#[tokio::test]
async fn test_block_dto_has_all_fields() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0x2a", false]));
    let resp = dispatch_for_test(&state, req).await;
    let block = resp.result.unwrap();

    let required_fields = [
        "number", "hash", "parentHash", "sha3Uncles", "miner",
        "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
        "difficulty", "totalDifficulty", "gasLimit", "gasUsed",
        "timestamp", "extraData", "minimumGasPrice",
        "transactions", "uncles", "size",
    ];
    for field in &required_fields {
        assert!(block.get(field).is_some(), "Missing field: {}", field);
    }
}

#[tokio::test]
async fn test_block_dto_hex_encoding() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0x2a", false]));
    let resp = dispatch_for_test(&state, req).await;
    let block = resp.result.unwrap();

    let hex_fields = [
        "number", "hash", "parentHash", "sha3Uncles", "miner",
        "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
        "difficulty", "totalDifficulty", "gasLimit", "gasUsed",
        "timestamp", "extraData", "minimumGasPrice", "size",
    ];
    for field in &hex_fields {
        let val = block[field].as_str().unwrap_or("");
        assert!(val.starts_with("0x"), "Field {} should be hex: {}", field, val);
    }
}

// ========== batch requests (dispatch-level) ==========

#[tokio::test]
async fn test_batch_dispatch() {
    let (state, _tmp) = setup_state();

    let requests = vec![
        make_request("eth_blockNumber", json!([])),
        make_request("web3_clientVersion", json!([])),
        make_request("nonexistent_method", json!([])),
    ];

    let mut responses = Vec::new();
    for req in requests {
        responses.push(dispatch_for_test(&state, req).await);
    }

    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0].result.as_ref().unwrap(), &json!("0x2a"));
    assert_eq!(responses[1].result.as_ref().unwrap(), &json!("Rustock/0.1.0"));
    assert!(responses[2].error.is_some());
}

// ========== eth_sendRawTransaction ==========

#[tokio::test]
async fn test_eth_send_raw_transaction_no_submitter() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_sendRawTransaction", json!(["0xdeadbeef"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some(), "Should error when tx_submitter is None");
}

#[tokio::test]
async fn test_eth_send_raw_transaction_with_submitter() {
    use crate::server::TxSubmitter;
    use alloy_primitives::B256;
    use sha3::Digest;

    struct MockSubmitter;

    #[async_trait::async_trait]
    impl TxSubmitter for MockSubmitter {
        async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> Result<B256, String> {
            Ok(B256::from_slice(&sha3::Keccak256::digest(&raw_tx)))
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let header = test_header(1);
    store.update_head(&header, U256::from(1000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: Some(Arc::new(MockSubmitter)),
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };

    let req = make_request("eth_sendRawTransaction", json!(["0xdeadbeef"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_none(), "Should succeed with a submitter");
    let result = resp.result.unwrap();
    let hash_str = result.as_str().unwrap();
    assert!(hash_str.starts_with("0x"));
    assert_eq!(hash_str.len(), 66);
}

#[tokio::test]
async fn test_eth_send_raw_transaction_invalid_hex() {
    use crate::server::TxSubmitter;
    use alloy_primitives::B256;

    struct MockSubmitter;

    #[async_trait::async_trait]
    impl TxSubmitter for MockSubmitter {
        async fn submit_transaction(&self, _raw_tx: alloy_primitives::Bytes) -> Result<B256, String> {
            Ok(B256::ZERO)
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let header = test_header(1);
    store.update_head(&header, U256::from(1000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: Some(Arc::new(MockSubmitter)),
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };

    let req = make_request("eth_sendRawTransaction", json!(["0xZZZZ"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some(), "Should error on invalid hex");
}

// ========== Phase 6: State queries with trie ==========

fn setup_state_with_trie() -> (RpcState, tempfile::TempDir) {
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode, account_key, code_key, storage_key};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let trie_store = Arc::new(MemoryTrieStore::new());

    // Create accounts in the trie
    let mut root = TrieNode::empty();

    // Account with 10000 balance (0x2710) and nonce 1
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826".parse::<alloy_primitives::Address>().unwrap();
    let acct = rustock_trie::AccountState::new(U256::from(1), U256::from(10000));
    let key = account_key(&addr);
    root = root.put(&TrieKeySlice::from_key(&key), &acct.encode(), &*trie_store);

    // Code for the account: [0x01, 0x02, 0x03]
    let ckey = code_key(&addr);
    root = root.put(&TrieKeySlice::from_key(&ckey), &[0x01, 0x02, 0x03], &*trie_store);

    // Storage slot 0x01 with value 42
    let mut slot_bytes = [0u8; 32];
    slot_bytes[31] = 1;
    let slot = B256::from(slot_bytes);
    let skey = storage_key(&addr, &slot);
    root = root.put(&TrieKeySlice::from_key(&skey), &[42], &*trie_store);

    // Slot 0x02: a 70-byte value, longer than one word. This is the shape
    // `rsk_getStorageBytesAt` exists for and `eth_getStorageAt` cannot return.
    let mut long_slot_bytes = [0u8; 32];
    long_slot_bytes[31] = 2;
    let long_slot = B256::from(long_slot_bytes);
    let long_value: Vec<u8> = (0u8..70).collect();
    let lkey = storage_key(&addr, &long_slot);
    root = root.put(&TrieKeySlice::from_key(&lkey), &long_value, &*trie_store);

    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);

    // Store the root node by its hash
    let root_data = root.to_message(&*trie_store);
    rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

    let header = Header {
        state_root,
        ..test_header(42)
    };
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, hash).unwrap();
    store.set_head(hash).unwrap();
    store.put_total_difficulty(hash, U256::from(42_000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: Some(trie_store),
        hardfork_cfg: Some(rustock_execution::RskHardforkConfig::mainnet()),
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };
    (state, tmp)
}

#[tokio::test]
async fn test_eth_get_balance_with_account() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let req = make_request("eth_getBalance", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x2710"));
}

#[tokio::test]
async fn test_eth_get_balance_missing_account() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0x0000000000000000000000000000000000000001";
    let req = make_request("eth_getBalance", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_transaction_count_with_account() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let req = make_request("eth_getTransactionCount", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x1"));
}

#[tokio::test]
async fn test_eth_get_transaction_count_missing() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0x0000000000000000000000000000000000000001";
    let req = make_request("eth_getTransactionCount", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_code_existing() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let req = make_request("eth_getCode", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x010203"));
}

#[tokio::test]
async fn test_eth_get_code_missing() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0x0000000000000000000000000000000000000001";
    let req = make_request("eth_getCode", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x"));
}

#[tokio::test]
async fn test_eth_get_storage_at_nonexistent_slot() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let slot = format!("{:#066x}", B256::ZERO);
    let req = make_request("eth_getStorageAt", json!([addr, slot, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    let expected = "0x0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(resp.result.unwrap(), json!(expected));
}

// ========== Phase 6: Transaction and Receipt Lookup ==========

fn setup_state_with_tx() -> (RpcState, tempfile::TempDir, B256) {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(20_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x12; 20]),
        value: U256::from(1_000_000),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(100),
        s: U256::from(200),
        cached_rlp: None,
    };

    let mut tx_buf = Vec::new();
    tx.encode(&mut tx_buf);
    let tx_hash = B256::from_slice(&Keccak256::digest(&tx_buf));

    let header = test_header(1);
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(1, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(1000)).unwrap();

    store.put_body(block_hash, std::slice::from_ref(&tx), &[]).unwrap();
    store.put_tx_index(tx_hash, block_hash, 0).unwrap();

    let receipt = rustock_core::Receipt {
        post_tx_state: vec![0x01],
        cumulative_gas_used: 21_000,
        gas_used: 21_000,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        logs: vec![],
        status: true,
    };
    store.put_receipts(block_hash, &[receipt]).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };
    (state, tmp, tx_hash)
}

/// The hash `eth_getBlockBy*` reports must be the hash `eth_getTransactionByHash`
/// can find -- a round trip through the production code, with nothing computed
/// by hand in the test.
///
/// This broke because three different hash implementations existed: the
/// canonical `Transaction::tx_hash()` (which hashes the ORIGINAL bytes when
/// cached at decode time) and two RPC-local helpers that re-encoded instead.
/// The index is keyed by the canonical hash, so for every transaction whose RLP
/// does not round-trip byte-for-byte -- about 42% of mainnet transactions when
/// measured on the production node -- the RPC handed out a hash that it could
/// not then resolve.
///
/// The fixture deliberately uses a transaction whose cached RLP differs from a
/// re-encoding, and indexes it with `index_block_transactions`, the function the
/// commit path uses, rather than calling `put_tx_index` by hand.
#[tokio::test]
async fn reported_tx_hash_is_the_one_that_can_be_looked_up() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let mut tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(1),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x12; 20]),
        value: U256::from(1_000_000),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(100),
        s: U256::from(200),
        cached_rlp: None,
    };
    // Non-canonical but perfectly decodable bytes: `r` carries a leading zero,
    // which is what Java's BigInteger.toByteArray() produces for a positive
    // number whose top bit is set. rustock decodes it leniently (see
    // rlp_compat) to the same value, but re-encoding drops the zero -- so the
    // stored bytes and a re-encoding hash differently. This is the real shape
    // of the divergence, not a synthetic one.
    let mut payload: Vec<u8> = Vec::new();
    payload.push(0x80);                                   // nonce 0
    payload.push(0x01);                                   // gas_price 1
    payload.extend_from_slice(&[0x82, 0x52, 0x08]);       // gas_limit 21000
    payload.push(0x94);                                   // to: 20-byte string
    payload.extend_from_slice(&[0x12; 20]);
    payload.extend_from_slice(&[0x83, 0x0f, 0x42, 0x40]); // value 1_000_000
    payload.push(0x80);                                   // input: empty
    payload.push(0x1b);                                   // v 27
    payload.extend_from_slice(&[0x82, 0x00, 0x80]);       // r 128, WITH a leading zero
    payload.extend_from_slice(&[0x81, 0xc8]);             // s 200
    let mut original = vec![0xc0 + payload.len() as u8];
    original.extend_from_slice(&payload);

    tx.r = U256::from(128);
    tx.cached_rlp = Some(original);

    let mut reencoded = Vec::new();
    alloy_rlp::Encodable::encode(&tx, &mut reencoded);
    assert_ne!(
        tx.tx_hash(),
        {
            use sha3::Digest;
            B256::from_slice(&sha3::Keccak256::digest(&reencoded))
        },
        "fixture is pointless unless the two hashes differ"
    );

    let header = test_header(1);
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(1, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(1000)).unwrap();
    store.put_body(block_hash, std::slice::from_ref(&tx), &[]).unwrap();
    // The production indexer, not a hand-written index entry.
    store.index_block_transactions(block_hash, std::slice::from_ref(&tx)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };

    // Ask the node for the block, take the hash it reports...
    let req = make_request("eth_getBlockByNumber", json!(["0x1", false]));
    let resp = dispatch_for_test(&state, req).await;
    let block = resp.result.clone();
    let reported = match resp.result.as_ref().and_then(|r| r["transactions"].get(0)).and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => panic!("block response had no transactions: {block:?} err={:?}", resp.error),
    };

    // ...and require that the same hash resolves.
    let req = make_request("eth_getTransactionByHash", json!([reported.clone()]));
    let resp = dispatch_for_test(&state, req).await;
    let found = resp.result.unwrap();
    assert!(
        !found.is_null(),
        "the hash reported by eth_getBlockByNumber ({reported}) must be resolvable"
    );
    assert_eq!(found["hash"], json!(reported));
    assert_eq!(found["blockNumber"], json!("0x1"));

    // Every RPC that reports a transaction hash must report the SAME one.
    // eth_getTransactionByBlockNumberAndIndex had its own third copy of the
    // hash computation and disagreed with eth_getBlockByNumber about the very
    // same transaction, handing out a hash that resolved to nothing.
    for method in ["eth_getTransactionByBlockNumberAndIndex", "eth_getTransactionByBlockHashAndIndex"] {
        let first = if method.ends_with("NumberAndIndex") {
            json!(["0x1", "0x0"])
        } else {
            json!([format!("{:#x}", block_hash), "0x0"])
        };
        let req = make_request(method, first);
        let resp = dispatch_for_test(&state, req).await;
        let got = resp.result.unwrap();
        assert_eq!(
            got["hash"], json!(reported),
            "{method} must agree with eth_getBlockByNumber on the transaction hash"
        );
    }
}

#[tokio::test]
async fn test_eth_get_transaction_by_hash() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionByHash", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["hash"], json!(hash_str));
    assert_eq!(result["nonce"], json!("0x0"));
    assert!(result["blockHash"].is_string());
    assert_eq!(result["blockNumber"], json!("0x1"));
    assert_eq!(result["transactionIndex"], json!("0x0"));
    assert_eq!(result["input"], json!("0x"));
    assert_eq!(result["type"], json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_transaction_by_hash_not_found() {
    let (state, _tmp, _) = setup_state_with_tx();
    let hash = format!("{:#x}", B256::repeat_byte(0xff));
    let req = make_request("eth_getTransactionByHash", json!([hash]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_transaction_by_block_number_and_index() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let req = make_request("eth_getTransactionByBlockNumberAndIndex", json!(["0x1", "0x0"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let hash_str = format!("{:#x}", tx_hash);
    assert_eq!(result["hash"], json!(hash_str));
    assert_eq!(result["transactionIndex"], json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_transaction_by_block_hash_and_index() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let block_hash = state.store.head().unwrap().unwrap();
    let block_hash_str = format!("{:#x}", block_hash);
    let req = make_request("eth_getTransactionByBlockHashAndIndex", json!([block_hash_str, "0x0"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let hash_str = format!("{:#x}", tx_hash);
    assert_eq!(result["hash"], json!(hash_str));
}

#[tokio::test]
async fn test_eth_get_transaction_receipt() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionReceipt", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["transactionHash"], json!(hash_str));
    assert_eq!(result["transactionIndex"], json!("0x0"));
    assert_eq!(result["blockNumber"], json!("0x1"));
    assert_eq!(result["status"], json!("0x1"));
    assert_eq!(result["gasUsed"], json!("0x5208"));
    assert_eq!(result["cumulativeGasUsed"], json!("0x5208"));
    assert_eq!(result["type"], json!("0x0"));
    assert!(result["contractAddress"].is_null());
}

#[tokio::test]
async fn test_eth_get_transaction_receipt_not_found() {
    let (state, _tmp, _) = setup_state_with_tx();
    let hash = format!("{:#x}", B256::repeat_byte(0xff));
    let req = make_request("eth_getTransactionReceipt", json!([hash]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

// ========== Phase 6: Log filtering ==========

fn setup_state_with_logs() -> (RpcState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let log_addr = "0x1111111111111111111111111111111111111111".parse::<alloy_primitives::Address>().unwrap();
    let topic1 = B256::repeat_byte(0xAA);

    for block_num in 1u64..=3 {
        // The header's bloom must be the OR of its receipts' blooms, as it is
        // on chain -- `eth_getLogs` now skips a block whose bloom cannot
        // match, and a fixture carrying `Bloom::ZERO` next to real logs is a
        // block that could not exist (`ProcessError::LogsBloomMismatch`).
        let mut logs_bloom = alloy_primitives::Bloom::ZERO;
        rustock_core::bloom::accrue_log(
            &mut logs_bloom,
            &rustock_core::Log {
                address: log_addr,
                topics: vec![topic1],
                data: vec![block_num as u8].into(),
            },
        );
        let header = Header { logs_bloom, ..test_header(block_num) };
        let hash = header.hash();
        store.put_header(&header).unwrap();
        store.put_canonical_hash(block_num, hash).unwrap();
        store.put_total_difficulty(hash, U256::from(block_num * 1000)).unwrap();

        store.put_body(hash, &[], &[]).unwrap();

        let receipt = rustock_core::Receipt {
            post_tx_state: vec![0x01],
            cumulative_gas_used: 21_000,
            gas_used: 21_000,
            logs_bloom,
            logs: vec![
                rustock_core::Log {
                    address: log_addr,
                    topics: vec![topic1],
                    data: vec![block_num as u8].into(),
                }
            ],
            status: true,
        };
        store.put_receipts(hash, &[receipt]).unwrap();

        if block_num == 3 {
            store.set_head(hash).unwrap();
        }
    }

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };
    (state, tmp)
}

#[tokio::test]
async fn test_eth_get_logs_by_range() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let logs = resp.result.unwrap();
    let logs = logs.as_array().unwrap();
    assert_eq!(logs.len(), 3);
}

/// **The range cap is the operator's, not a constant.**
///
/// rskj exposes the same limit as `rpc.logs.maxBlocksToQuery` and defaults it
/// to 5000; ours defaulted to a hard-coded 10,000 with no way to change it.
/// The cap is what actually bounds a wide `eth_getLogs` -- measured, the bloom
/// skip costs only 0.16 s over 10,000 blocks -- so it is the knob that matters
/// (#122).
#[tokio::test]
async fn the_get_logs_range_cap_is_configurable() {
    let (mut state, _tmp) = setup_state_with_logs();
    state.logs_max_blocks = 1;

    let too_wide = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
    }]));
    let resp = dispatch_for_test(&state, too_wide).await;
    let message = resp.error.expect("a span of 3 must be refused at a cap of 1").message;
    assert!(
        message.contains('1') && message.contains("exceeds"),
        "the refusal should name the configured cap, got: {message}"
    );

    // And the same request is served once the cap allows it, so the cap is
    // doing the refusing rather than something else about the query.
    state.logs_max_blocks = crate::logs::DEFAULT_MAX_BLOCK_RANGE;
    let ok = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
    }]));
    let resp = dispatch_for_test(&state, ok).await;
    assert_eq!(resp.result.unwrap().as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_eth_get_logs_by_address() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "address": "0x1111111111111111111111111111111111111111"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let logs = resp.result.unwrap().as_array().unwrap().len();
    assert_eq!(logs, 3);

    // Different address should return nothing
    let req2 = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "address": "0x2222222222222222222222222222222222222222"
    }]));
    let resp2 = dispatch_for_test(&state, req2).await;
    assert_eq!(resp2.result.unwrap().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_eth_get_logs_by_topic() {
    let (state, _tmp) = setup_state_with_logs();
    let topic = format!("{:#x}", B256::repeat_byte(0xAA));
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "topics": [topic]
    }]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap().as_array().unwrap().len(), 3);

    // Non-matching topic
    let wrong_topic = format!("{:#x}", B256::repeat_byte(0xBB));
    let req2 = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "topics": [wrong_topic]
    }]));
    let resp2 = dispatch_for_test(&state, req2).await;
    assert_eq!(resp2.result.unwrap().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_eth_new_filter_and_get_changes() {
    let (state, _tmp) = setup_state_with_logs();
    // Create a filter
    let req = make_request("eth_newFilter", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let filter_id = resp.result.unwrap();
    assert!(filter_id.is_string());

    // Get changes — since we just created it with last_polled = head (3), no new blocks
    let req2 = make_request("eth_getFilterChanges", json!([filter_id]));
    let resp2 = dispatch_for_test(&state, req2).await;
    let changes = resp2.result.unwrap().as_array().unwrap().len();
    assert_eq!(changes, 0);
}

#[tokio::test]
async fn test_eth_new_block_filter() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_newBlockFilter", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.result.unwrap().is_string());
}

#[tokio::test]
async fn test_eth_uninstall_filter() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_newFilter", json!([{"fromBlock": "0x1"}]));
    let resp = dispatch_for_test(&state, req).await;
    let filter_id = resp.result.unwrap();

    let req2 = make_request("eth_uninstallFilter", json!([filter_id]));
    let resp2 = dispatch_for_test(&state, req2).await;
    assert_eq!(resp2.result.unwrap(), json!(true));

    // Second uninstall should return false
    let req3 = make_request("eth_uninstallFilter", json!([filter_id]));
    let resp3 = dispatch_for_test(&state, req3).await;
    assert_eq!(resp3.result.unwrap(), json!(false));
}

/// A pool whose contents the test sets directly.
#[derive(Default)]
struct MutablePool {
    pending: std::sync::Mutex<Vec<rustock_core::Transaction>>,
}

impl MutablePool {
    fn set(&self, txs: Vec<rustock_core::Transaction>) {
        *self.pending.lock().unwrap() = txs;
    }
}

impl crate::server::TxPoolReader for MutablePool {
    fn get_pending_tx(
        &self,
        _hash: &B256,
    ) -> Option<(rustock_core::Transaction, alloy_primitives::Address, B256)> {
        None
    }
    fn pending_nonce(&self, _addr: &alloy_primitives::Address) -> Option<u64> {
        None
    }
    fn pool_status(&self) -> (usize, usize) {
        (self.pending.lock().unwrap().len(), 0)
    }
    fn pool_content(&self) -> crate::server::PoolContent {
        let txs = self.pending.lock().unwrap().clone();
        crate::server::PoolContent {
            pending: vec![(
                alloy_primitives::Address::ZERO,
                txs.into_iter().enumerate().map(|(i, t)| (i as u64, t)).collect(),
            )],
            queued: Vec::new(),
        }
    }
    fn quota_report(&self, _a: &alloy_primitives::Address) -> Option<(f64, u64)> {
        None
    }
}

fn filter_pool_tx(nonce: u64) -> rustock_core::Transaction {
    rustock_core::Transaction {
        nonce,
        gas_price: U256::from(20_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x12; 20]),
        value: U256::from(1_000_000),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(100),
        s: U256::from(200),
        cached_rlp: None,
    }
}

/// Two filters must be distinguishable, and a filter must be removable.
///
/// This used to assert `"0x0"` -- the stub's constant -- which pinned three
/// defects at once: every filter had the same id, the id was not a real
/// filter so `eth_uninstallFilter` answered false, and polling it always
/// returned empty.
#[tokio::test]
async fn test_eth_new_pending_transaction_filter() {
    let (state, _tmp) = setup_state();

    let one = dispatch_for_test(&state, make_request("eth_newPendingTransactionFilter", json!([])))
        .await.result.unwrap();
    let two = dispatch_for_test(&state, make_request("eth_newPendingTransactionFilter", json!([])))
        .await.result.unwrap();

    assert_ne!(one, json!("0x0"), "a filter id of zero is the old stub");
    assert_ne!(one, two, "two filters must have different ids");

    let gone = dispatch_for_test(
        &state,
        make_request("eth_uninstallFilter", json!([one.as_str().unwrap()])),
    ).await.result.unwrap();
    assert_eq!(gone, json!(true), "a real filter must be removable");
}

/// The filter reports transactions that arrive after it was created, once
/// each, and does not replay what was already pending when it was opened.
#[tokio::test]
async fn test_pending_transaction_filter_reports_new_transactions() {
    let (mut state, _tmp) = setup_state();
    let pool = std::sync::Arc::new(MutablePool::default());
    pool.set(vec![filter_pool_tx(0)]); // already pending before the filter exists
    state.tx_pool = Some(pool.clone());

    let fid = dispatch_for_test(&state, make_request("eth_newPendingTransactionFilter", json!([])))
        .await.result.unwrap();
    let fid = fid.as_str().unwrap().to_string();

    let first = dispatch_for_test(&state, make_request("eth_getFilterChanges", json!([&fid])))
        .await.result.unwrap();
    assert_eq!(first, json!([]), "what was already pending must not be replayed");

    // A new transaction arrives.
    pool.set(vec![filter_pool_tx(0), filter_pool_tx(1)]);
    let second = dispatch_for_test(&state, make_request("eth_getFilterChanges", json!([&fid])))
        .await.result.unwrap();
    assert_eq!(
        second.as_array().map(|a| a.len()),
        Some(1),
        "the newly pending transaction must be reported exactly once"
    );

    let third = dispatch_for_test(&state, make_request("eth_getFilterChanges", json!([&fid])))
        .await.result.unwrap();
    assert_eq!(third, json!([]), "and must not be reported again");
}

// ========== Phase 6: DTO field name compatibility with rskj ==========

#[tokio::test]
async fn test_transaction_dto_fields_match_rskj() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionByHash", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();

    let required_fields = [
        "hash", "nonce", "blockHash", "blockNumber", "transactionIndex",
        "from", "to", "gas", "gasPrice", "value", "input", "v", "r", "s", "type",
    ];
    for field in &required_fields {
        assert!(result.get(field).is_some(), "Missing TransactionDTO field: {}", field);
    }

    // Verify hex formatting matches rskj conventions
    assert!(result["nonce"].as_str().unwrap().starts_with("0x"));
    assert!(result["gas"].as_str().unwrap().starts_with("0x"));
    assert!(result["gasPrice"].as_str().unwrap().starts_with("0x"));
    assert!(result["value"].as_str().unwrap().starts_with("0x"));
    assert_eq!(result["type"], json!("0x0"));
    // v should be formatted as 0x%02x
    let v_str = result["v"].as_str().unwrap();
    assert!(v_str.starts_with("0x"));
    assert_eq!(v_str, "0x1b"); // v=27 -> 0x1b
}

#[tokio::test]
async fn test_receipt_dto_fields_match_rskj() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionReceipt", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();

    let required_fields = [
        "transactionHash", "transactionIndex", "blockHash", "blockNumber",
        "cumulativeGasUsed", "gasUsed", "contractAddress", "logs",
        "from", "to", "status", "logsBloom", "type",
    ];
    for field in &required_fields {
        assert!(result.get(field).is_some(), "Missing ReceiptDTO field: {}", field);
    }

    assert_eq!(result["type"], json!("0x0"));
    assert_eq!(result["status"], json!("0x1"));
}

#[tokio::test]
async fn test_receipt_dto_failed_status() {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(20_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x12; 20]),
        value: U256::from(1_000_000),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(100),
        s: U256::from(200),
        cached_rlp: None,
    };

    let mut tx_buf = Vec::new();
    tx.encode(&mut tx_buf);
    let tx_hash = B256::from_slice(&Keccak256::digest(&tx_buf));

    let header = test_header(1);
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(1, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(1000)).unwrap();
    store.put_body(block_hash, &[tx], &[]).unwrap();
    store.put_tx_index(tx_hash, block_hash, 0).unwrap();

    let receipt = rustock_core::Receipt {
        post_tx_state: vec![],
        cumulative_gas_used: 21_000,
        gas_used: 21_000,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        logs: vec![],
        status: false,
    };
    store.put_receipts(block_hash, &[receipt]).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };

    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionReceipt", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["status"], json!("0x0"));
}

// ========== Phase 6: Log DTO field names ==========

#[tokio::test]
async fn test_log_dto_fields_match_rskj() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x1"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let logs = resp.result.unwrap();
    let log = &logs.as_array().unwrap()[0];

    let required_fields = [
        "address", "topics", "data", "blockNumber", "blockHash",
        "transactionHash", "transactionIndex", "logIndex", "removed",
    ];
    for field in &required_fields {
        assert!(log.get(field).is_some(), "Missing LogDTO field: {}", field);
    }

    assert_eq!(log["removed"], json!(false));
    assert!(log["address"].as_str().unwrap().starts_with("0x"));
    assert!(log["blockNumber"].as_str().unwrap().starts_with("0x"));
    assert_eq!(log["logIndex"], json!("0x0"));
}

// ── mnr: merged mining ────────────────────────────────────────────────
//
// These check the wire contract rather than the mining itself: the JSON shapes
// are rskj's and the consumers are existing pool daemons, so a field that
// looks wrong here is a field that breaks a miner.


// --- block-count getters, and the header-only distinction --------------------
//
// rskj covers these in Web3ImplTest (getBlockTransactionCountByHash and
// friends). Both were named in no rustock test. The interesting case is not
// the happy path but the three-way answer: a count, zero for a block whose
// body is absent, and null for a block that is not here at all -- a caller
// cannot tell "no transactions" from "no block" unless those differ.

#[tokio::test]
async fn test_block_transaction_count_by_hash_distinguishes_absent_from_empty() {
    let (state, _tmp) = setup_state();
    let known = test_header(42).hash();

    let resp = dispatch_for_test(
        &state,
        make_request("eth_getBlockTransactionCountByHash", json!([format!("{known:?}")])),
    )
    .await;
    assert_eq!(
        resp.result.unwrap(),
        json!("0x0"),
        "a stored header with no body has zero transactions, not null"
    );

    let unknown = "0x".to_string() + &"11".repeat(32);
    let resp = dispatch_for_test(
        &state,
        make_request("eth_getBlockTransactionCountByHash", json!([unknown])),
    )
    .await;
    assert_eq!(
        resp.result.unwrap(),
        serde_json::Value::Null,
        "a block that is not stored must answer null, not zero"
    );
}

#[tokio::test]
async fn test_block_count_getters_reject_a_malformed_hash() {
    let (state, _tmp) = setup_state();
    for method in [
        "eth_getBlockTransactionCountByHash",
        "eth_getUncleCountByBlockHash",
    ] {
        let resp = dispatch_for_test(&state, make_request(method, json!(["not-a-hash"]))).await;
        assert!(resp.result.is_none(), "{method} must not answer a bad hash");
        assert_eq!(
            resp.error.expect("an error is expected").code,
            -32602,
            "{method} must report INVALID_PARAMS"
        );

        let resp = dispatch_for_test(&state, make_request(method, json!([]))).await;
        assert_eq!(
            resp.error.expect("an error is expected").code,
            -32602,
            "{method} must report INVALID_PARAMS when the hash is missing"
        );
    }
}

/// eth_hashrate is a fixed zero: rustock does not hash, it hands work to
/// merged-mining software that does. Pinned so it is not "improved" into
/// reporting a number the node cannot know.
#[tokio::test]
async fn test_eth_hashrate_is_zero() {
    let (state, _tmp) = setup_state();
    let resp = dispatch_for_test(&state, make_request("eth_hashrate", json!([]))).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

mod mnr_tests {
    use super::*;
    use crate::mnr::{MiningService, SUBMIT_BLOCK_ERROR};
    use rustock_execution::mining::{ImportResult, MinerWork, SubmitError, SubmittedBlockInfo};
    use std::sync::Mutex;

    /// A miner that answers from a script, so the RPC layer can be checked
    /// without a block processor, a trie and a chain behind it.
    #[derive(Default)]
    struct FakeMiner {
        work: Option<MinerWork>,
        /// The arguments the last submit call arrived with.
        last_call: Mutex<Option<(Vec<u8>, Vec<u8>, String, u32)>>,
        fail_with: Option<String>,
    }

    impl FakeMiner {
        fn ok(&self) -> Result<SubmittedBlockInfo, SubmitError> {
            if let Some(message) = &self.fail_with {
                return Err(SubmitError::Storage(message.clone()));
            }
            Ok(SubmittedBlockInfo {
                block_imported_result: ImportResult::ImportedBest,
                block_hash: B256::repeat_byte(0xAB),
                block_included_height: 0x2a,
            })
        }
    }

    impl MiningService for FakeMiner {
        fn mine_one_now(&self) -> Result<u64, String> {
            Err("the fake miner does not mine".into())
        }

        fn coinbase(&self) -> [u8; 20] {
            [0x5Au8; 20]
        }


        fn get_work(&self) -> Result<MinerWork, SubmitError> {
            self.work
                .clone()
                .ok_or_else(|| SubmitError::Storage("no work".into()))
        }

        fn submit_bitcoin_block(&self, raw: &[u8]) -> Result<SubmittedBlockInfo, SubmitError> {
            *self.last_call.lock().unwrap() = Some((raw.to_vec(), Vec::new(), String::new(), 0));
            self.ok()
        }

        fn submit_bitcoin_block_transactions(
            &self,
            header: &[u8],
            coinbase: &[u8],
            hashes: &str,
        ) -> Result<SubmittedBlockInfo, SubmitError> {
            *self.last_call.lock().unwrap() =
                Some((header.to_vec(), coinbase.to_vec(), hashes.to_string(), 0));
            self.ok()
        }

        fn submit_bitcoin_block_partial_merkle(
            &self,
            header: &[u8],
            coinbase: &[u8],
            hashes: &str,
            count: u32,
        ) -> Result<SubmittedBlockInfo, SubmitError> {
            *self.last_call.lock().unwrap() =
                Some((header.to_vec(), coinbase.to_vec(), hashes.to_string(), count));
            self.ok()
        }
    }

    fn sample_work() -> MinerWork {
        MinerWork {
            block_hash_for_merged_mining: B256::repeat_byte(0x11),
            // A target well under 32 bytes, to prove it is zero-padded rather
            // than sent as a quantity.
            target: U256::from(0x1234u64),
            fees_paid_to_miner: U256::from(123_456_789_u64),
            notify: true,
            parent_block_hash: B256::repeat_byte(0x22),
        }
    }

    fn state_with(miner: FakeMiner) -> (RpcState, tempfile::TempDir, Arc<FakeMiner>) {
        let (mut state, tmp) = setup_state();
        let miner = Arc::new(miner);
        state.miner = Some(miner.clone() as Arc<dyn MiningService>);
        (state, tmp, miner)
    }

    #[tokio::test]
    async fn get_work_returns_rskj_field_shapes() {
        let (state, _tmp, _miner) =
            state_with(FakeMiner { work: Some(sample_work()), ..Default::default() });

        let resp = dispatch_for_test(&state, make_request("mnr_getWork", json!([]))).await;
        let result = resp.result.expect("getWork must answer");

        assert_eq!(
            result["blockHashForMergedMining"],
            json!("0x1111111111111111111111111111111111111111111111111111111111111111")
        );
        // Padded to 32 bytes: this is a threshold a hash is compared against,
        // not a quantity, and trimming it would change its meaning.
        assert_eq!(
            result["target"],
            json!("0x0000000000000000000000000000000000000000000000000000000000001234")
        );
        // Decimal, not hex: rskj sends `String.valueOf(Coin)` here and pools
        // parse it as a number.
        assert_eq!(result["feesPaidToMiner"], json!("123456789"));
        assert_eq!(result["notify"], json!(true));
        assert_eq!(
            result["parentBlockHash"],
            json!("0x2222222222222222222222222222222222222222222222222222222222222222")
        );
    }

    /// `blockImportedResult` is the hex encoding of an ASCII status word --
    /// `HexUtils.toJsonHex(stringToByteArray(importResult.toString()))` in
    /// rskj. Sending the word itself would be more sensible and would break
    /// every client.
    #[tokio::test]
    async fn submit_returns_an_rskj_submitted_block_info() {
        let (state, _tmp, _miner) = state_with(FakeMiner::default());

        let resp = dispatch_for_test(
            &state,
            make_request("mnr_submitBitcoinBlock", json!(["0xdeadbeef"])),
        )
        .await;
        let result = resp.result.expect("submit must answer");

        assert_eq!(
            result["blockImportedResult"],
            json!(format!("0x{}", hex::encode("IMPORTED_BEST")))
        );
        assert_eq!(
            result["blockHash"],
            json!("0xabababababababababababababababababababababababababababababababab")
        );
        assert_eq!(result["blockIncludedHeight"], json!("0x2a"));
    }

    #[tokio::test]
    async fn submit_passes_the_raw_block_through() {
        let (state, _tmp, miner) = state_with(FakeMiner::default());

        dispatch_for_test(
            &state,
            make_request("mnr_submitBitcoinBlock", json!(["0x0102ff"])),
        )
        .await;

        let call = miner.last_call.lock().unwrap().clone().expect("submit reached the miner");
        assert_eq!(call.0, vec![0x01, 0x02, 0xff]);
    }

    /// rskj takes a block hash as the first argument of the two-part submits
    /// and ignores it -- the hash is recomputed from the header. The
    /// positional shape still has to match, or every argument lands one place
    /// out.
    #[tokio::test]
    async fn submit_transactions_reads_arguments_by_rskj_position() {
        let (state, _tmp, miner) = state_with(FakeMiner::default());

        dispatch_for_test(
            &state,
            make_request(
                "mnr_submitBitcoinBlockTransactions",
                json!(["0xdead", "0xaabb", "0xccdd", "hash1 hash2"]),
            ),
        )
        .await;

        let call = miner.last_call.lock().unwrap().clone().expect("submit reached the miner");
        assert_eq!(call.0, vec![0xaa, 0xbb], "header");
        assert_eq!(call.1, vec![0xcc, 0xdd], "coinbase");
        assert_eq!(call.2, "hash1 hash2");
    }

    #[tokio::test]
    async fn submit_partial_merkle_reads_arguments_by_rskj_position() {
        let (state, _tmp, miner) = state_with(FakeMiner::default());

        dispatch_for_test(
            &state,
            make_request(
                "mnr_submitBitcoinBlockPartialMerkle",
                json!(["0xdead", "0xaabb", "0xccdd", "hash1 hash2", "10"]),
            ),
        )
        .await;

        let call = miner.last_call.lock().unwrap().clone().expect("submit reached the miner");
        assert_eq!(call.0, vec![0xaa, 0xbb], "header");
        assert_eq!(call.1, vec![0xcc, 0xdd], "coinbase");
        assert_eq!(call.2, "hash1 hash2");
        // The transaction count arrives as hex without a prefix.
        assert_eq!(call.3, 16);
    }

    #[tokio::test]
    async fn submit_partial_merkle_rejects_an_empty_hash_list() {
        let (state, _tmp, _miner) = state_with(FakeMiner::default());

        let resp = dispatch_for_test(
            &state,
            make_request(
                "mnr_submitBitcoinBlockPartialMerkle",
                json!(["0xdead", "0xaabb", "0xccdd", "", "10"]),
            ),
        )
        .await;

        let error = resp.error.expect("an empty branch cannot be a proof");
        assert_eq!(error.code, SUBMIT_BLOCK_ERROR);
    }

    /// A refused submission carries rskj's application-defined code, so a
    /// miner can tell a rejected block from a malformed request.
    #[tokio::test]
    async fn a_refused_submission_uses_rskj_error_code() {
        let (state, _tmp, _miner) = state_with(FakeMiner {
            fail_with: Some("the chain moved on".into()),
            ..Default::default()
        });

        let resp = dispatch_for_test(
            &state,
            make_request("mnr_submitBitcoinBlock", json!(["0xdeadbeef"])),
        )
        .await;

        let error = resp.error.expect("the submission was refused");
        assert_eq!(error.code, SUBMIT_BLOCK_ERROR);
        assert!(error.message.contains("the chain moved on"), "{}", error.message);
    }

    #[tokio::test]
    async fn malformed_parameters_are_rejected_before_the_miner_is_reached() {
        let (state, _tmp, miner) = state_with(FakeMiner::default());

        for params in [json!([]), json!(["not hex"]), json!([42])] {
            let resp =
                dispatch_for_test(&state, make_request("mnr_submitBitcoinBlock", params.clone()))
                    .await;
            assert_eq!(
                resp.error.expect("bad params must be refused").code,
                INVALID_PARAMS,
                "{params}"
            );
        }
        assert!(miner.last_call.lock().unwrap().is_none());
    }

    /// Without a miner the namespace must look absent rather than refused: a
    /// node that is not mining should be indistinguishable from one built
    /// without the feature.
    #[tokio::test]
    async fn the_namespace_is_absent_when_mining_is_off() {
        let (state, _tmp) = setup_state();

        for method in [
            "mnr_getWork",
            "mnr_submitBitcoinBlock",
            "mnr_submitBitcoinBlockTransactions",
            "mnr_submitBitcoinBlockPartialMerkle",
        ] {
            let resp = dispatch_for_test(&state, make_request(method, json!([]))).await;
            assert_eq!(
                resp.error.unwrap_or_else(|| panic!("{method} must not answer")).code,
                METHOD_NOT_FOUND,
                "{method}"
            );
        }

        let resp = dispatch_for_test(&state, make_request("rpc_modules", json!([]))).await;
        assert!(resp.result.unwrap().get("mnr").is_none());
    }

    #[tokio::test]
    async fn rpc_modules_advertises_mnr_when_mining_is_on() {
        let (state, _tmp, _miner) =
            state_with(FakeMiner { work: Some(sample_work()), ..Default::default() });

        let resp = dispatch_for_test(&state, make_request("rpc_modules", json!([]))).await;
        assert_eq!(resp.result.unwrap()["mnr"], json!("1.0"));
    }

    /// eth_coinbase must report the miner's address once mining is on. With
    /// mining off the zero address is honest; with mining on it is a lie that
    /// mining software acts on, so both halves are pinned here.
    ///
    /// rskj answers this from the miner configuration in EthModule. rustock
    /// had it hard-coded to zero, which was correct only for a node that
    /// never mines -- and stopped being correct when mining landed.
    #[tokio::test]
    async fn test_eth_coinbase_reports_the_miner_address() {
        let (state, _tmp) = setup_state();
        assert!(state.miner.is_none(), "the default node does not mine");
        let resp = dispatch_for_test(&state, make_request("eth_coinbase", json!([]))).await;
        assert_eq!(
            resp.result.unwrap(),
            json!("0x0000000000000000000000000000000000000000"),
            "with no miner the zero address is the honest answer"
        );

        let (mut state, _tmp2) = setup_state();
        state.miner = Some(std::sync::Arc::new(FakeMiner::default()));
        let resp = dispatch_for_test(&state, make_request("eth_coinbase", json!([]))).await;
        assert_eq!(
            resp.result.unwrap(),
            json!("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
            "with a miner the configured coinbase must be reported"
        );
    }

}

// --- administrative methods -------------------------------------------------
//
// rskj gates its equivalents behind the `rsk` module being enabled in config
// and tests that in Web3ImplTest / ModuleDescriptionTest. rustock gates on
// --rpc-admin. These two methods were named in no test at all, which the
// coverage document calls the most uncomfortable gap in the RPC surface:
// rsk_collectTrie DELETES trie epochs.

/// Without --rpc-admin both admin methods must report as unknown, not as
/// forbidden. The distinction is deliberate: a node that never had them and a
/// node that has them switched off should be indistinguishable from outside,
/// so that probing cannot enumerate which nodes are worth attacking.
#[tokio::test]
async fn test_admin_methods_are_unknown_without_the_flag() {
    let (state, _tmp) = setup_state();
    assert!(!state.admin_enabled, "the default must be off");

    for method in ["rsk_collectTrie", "rsk_collectTrieStatus"] {
        let resp = dispatch_for_test(&state, make_request(method, json!([]))).await;
        assert!(resp.result.is_none(), "{method} must not answer when admin is off");
        let err = resp.error.expect("an error is expected");
        assert_eq!(err.code, -32601, "{method} must report METHOD_NOT_FOUND");
        assert_eq!(
            err.message, "Method not found",
            "{method} must not disclose that it exists but is disabled"
        );
    }
}

/// The gate is on the method name, not on the arguments: a request carrying
/// plausible parameters must be refused exactly the same way. Worth pinning
/// because rsk_collectTrie with a block number is the shape that deletes
/// something, and a gate that only covered the no-argument form would look
/// correct in every other test.
#[tokio::test]
async fn test_admin_gate_ignores_the_parameters() {
    let (state, _tmp) = setup_state();
    let resp = dispatch_for_test(
        &state,
        make_request("rsk_collectTrie", json!(["0x2a"])),
    )
    .await;
    assert!(resp.result.is_none(), "parameters must not open the gate");
    assert_eq!(resp.error.unwrap().code, -32601);
}

/// With admin on, the methods must actually dispatch -- otherwise the gate
/// test above would pass against a node where they were removed entirely, and
/// prove nothing. This node has no epoch store, so the call reaches the
/// handler and reports that rather than being refused by the gate.
#[tokio::test]
async fn test_admin_methods_dispatch_when_enabled() {
    let (mut state, _tmp) = setup_state();
    state.admin_enabled = true;

    let resp = dispatch_for_test(&state, make_request("rsk_collectTrieStatus", json!([]))).await;
    let refused_by_gate = resp
        .error
        .as_ref()
        .is_some_and(|e| e.code == -32601 && e.message == "Method not found");
    assert!(
        !refused_by_gate,
        "with admin enabled the method must reach its handler, not the gate"
    );
}

// --- key custody ------------------------------------------------------------
//
// rskj covers the signing surface in Web3ImplTest and the personal module
// tests, where the node DOES hold keys and unlocking is part of the contract.
// rustock holds none, and these tests pin that posture rather than the
// behaviour of a wallet it does not have. The property is worth a test because
// it is the kind that regresses quietly: someone implements eth_sign for a
// local tool, and a node that never had custody suddenly has it.

/// No key-holding method may answer. A node with no wallet must refuse to
/// sign rather than sign with something it happens to have -- the node
/// identity key, a miner key -- which would be a signature the operator never
/// authorised.
#[tokio::test]
async fn test_the_node_holds_no_keys_and_refuses_to_sign() {
    let (state, _tmp) = setup_state();

    for (method, params) in [
        ("eth_sign", json!(["0x0000000000000000000000000000000000000001", "0xdeadbeef"])),
        ("eth_signTransaction", json!([{"from": "0x0000000000000000000000000000000000000001"}])),
        ("eth_sendTransaction", json!([{"from": "0x0000000000000000000000000000000000000001"}])),
    ] {
        let resp = dispatch_for_test(&state, make_request(method, params)).await;
        assert!(resp.result.is_none(), "{method} must not return a result");
        assert_eq!(
            resp.error.expect("an error is expected").code,
            -32601,
            "{method} must be refused"
        );
    }
}

/// eth_accounts must be empty, and consistently so: a caller that trusts a
/// non-empty list would go on to call eth_sign, which cannot work. rskj
/// returns the wallet's accounts here; rustock has no wallet.
#[tokio::test]
async fn test_eth_accounts_is_empty_because_there_is_no_wallet() {
    let (state, _tmp) = setup_state();
    let resp = dispatch_for_test(&state, make_request("eth_accounts", json!([]))).await;
    assert_eq!(
        resp.result.unwrap(),
        json!([]),
        "a node with no wallet must report no accounts"
    );
}

/// `eth_pendingTransactions` is empty for the same reason `eth_accounts` is:
/// rskj scopes it to the node's own wallet, and this node has none.
///
/// It is emphatically NOT "the mempool". rskj filters the pool to senders the
/// wallet manages, and `EthModuleWalletDisabled` returns `Collections.emptyList()`
/// unconditionally. Returning the pending pool here would present every
/// transaction in the public mempool as the caller's own.
#[tokio::test]
async fn test_eth_pending_transactions_is_empty_because_there_is_no_wallet() {
    let (state, _tmp) = setup_state();
    let resp = dispatch_for_test(&state, make_request("eth_pendingTransactions", json!([]))).await;
    assert_eq!(
        resp.result.unwrap(),
        json!([]),
        "a node with no wallet has no transactions of its own"
    );
    assert!(resp.error.is_none(), "it answers, rather than refusing");
}

/// The one that would catch a future change of heart: a pool holding a real
/// pending transaction must not leak into `eth_pendingTransactions`.
///
/// Without this the other test proves nothing — an empty pool and an empty
/// answer agree for the wrong reason. If someone later decides the method
/// should report the mempool, this is what fails, and it names why.
#[tokio::test]
async fn test_eth_pending_transactions_ignores_a_populated_pool() {
    let (state, hash, _tmp) = setup_state_with_pending_tx();

    // The pool is genuinely reachable through the RPC layer, so a pass below is
    // about this method rather than about a disconnected fixture.
    let by_hash = dispatch_for_test(
        &state,
        make_request("eth_getTransactionByHash", json!([format!("0x{}", hex::encode(hash))])),
    )
    .await;
    assert!(
        by_hash.result.as_ref().is_some_and(|v| !v.is_null()),
        "precondition: the pending transaction is visible via eth_getTransactionByHash"
    );

    let resp = dispatch_for_test(&state, make_request("eth_pendingTransactions", json!([]))).await;
    assert_eq!(
        resp.result.unwrap(),
        json!([]),
        "the pool leaked into eth_pendingTransactions. These are not the caller's own \
         transactions -- rskj scopes this method to the node's wallet. Use txpool_content (#83)."
    );
}

/// A pool holding exactly one pending transaction.
///
/// A double rather than a real `TransactionPool`: the RPC crate talks to the
/// pool through `TxPoolReader` and does not depend on the sync crate, which is
/// the right shape and means this test needs no signing key and no funded
/// account to populate it.
struct OnePendingTx {
    tx: rustock_core::Transaction,
    hash: B256,
    sender: alloy_primitives::Address,
}

impl crate::server::TxPoolReader for OnePendingTx {
    fn get_pending_tx(
        &self,
        hash: &B256,
    ) -> Option<(rustock_core::Transaction, alloy_primitives::Address, B256)> {
        (*hash == self.hash).then(|| (self.tx.clone(), self.sender, self.hash))
    }
    fn pending_nonce(&self, _addr: &alloy_primitives::Address) -> Option<u64> {
        Some(self.tx.nonce + 1)
    }
    fn pool_status(&self) -> (usize, usize) {
        (1, 0)
    }
    fn pool_content(&self) -> crate::server::PoolContent {
        crate::server::PoolContent {
            pending: vec![(self.sender, vec![(self.tx.nonce, self.tx.clone())])],
            queued: Vec::new(),
        }
    }
    fn quota_report(&self, address: &alloy_primitives::Address) -> Option<(f64, u64)> {
        (*address == self.sender).then_some((1_234.5_f64, 1_700_000_000_000_u64))
    }
}

fn setup_state_with_pending_tx() -> (RpcState, B256, tempfile::TempDir) {
    let (mut state, tmp) = setup_state();

    let tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(1_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0xBBu8; 20]),
        value: U256::from(1_000u64),
        input: alloy_primitives::Bytes::new(),
        v: 27,
        r: U256::from(1u64),
        s: U256::from(2u64),
        cached_rlp: None,
    };
    let hash = B256::repeat_byte(0xA1);
    state.tx_pool = Some(Arc::new(OnePendingTx {
        tx,
        hash,
        sender: alloy_primitives::Address::repeat_byte(0x11),
    }));
    (state, hash, tmp)
}

/// The Solidity compiler methods are refused rather than answered with an
/// empty list. rskj removed these upstream; answering "no compilers" would
/// invite a caller to treat compilation as supported-but-unavailable.
#[tokio::test]
async fn test_compiler_methods_are_refused() {
    let (state, _tmp) = setup_state();
    for method in ["eth_getCompilers", "eth_compileSolidity"] {
        let resp = dispatch_for_test(&state, make_request(method, json!([]))).await;
        assert!(resp.result.is_none(), "{method} must not answer");
        assert_eq!(resp.error.unwrap().code, -32601);
    }
}

// ========== rsk_getStorageBytesAt ==========

/// The reason the method exists: a value longer than one word comes back
/// whole. `eth_getStorageAt` truncates it to 32 bytes and pads, which is
/// silently wrong for Bridge state.
#[tokio::test]
async fn test_rsk_get_storage_bytes_at_returns_a_multi_word_value_whole() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";

    let resp = dispatch_for_test(
        &state,
        make_request("rsk_getStorageBytesAt", json!([addr, "0x2", "latest"])),
    )
    .await;

    let expected: String = format!("0x{}", hex::encode((0u8..70).collect::<Vec<u8>>()));
    assert_eq!(resp.result.unwrap().as_str().unwrap(), expected, "the 70-byte value was not returned whole");
}

/// And the contrast that makes the point: the same key through
/// `eth_getStorageAt` comes back truncated to one word.
#[tokio::test]
async fn test_eth_get_storage_at_truncates_what_rsk_get_storage_bytes_at_returns_whole() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let slot = "0x0000000000000000000000000000000000000000000000000000000000000002";

    let word = dispatch_for_test(&state, make_request("eth_getStorageAt", json!([addr, slot, "latest"]))).await;
    let bytes = dispatch_for_test(&state, make_request("rsk_getStorageBytesAt", json!([addr, slot, "latest"]))).await;

    let word_s = word.result.unwrap().as_str().unwrap().to_string();
    let bytes_s = bytes.result.unwrap().as_str().unwrap().to_string();
    assert_eq!(word_s.len(), 66, "eth_getStorageAt must answer with exactly one word");
    assert!(bytes_s.len() > word_s.len(), "rsk_getStorageBytesAt must return more than one word");
}

/// An absent key answers `0x0`, which is rskj's
/// `Optional.ofNullable(...).orElse("0x0")` -- **not** null and not `0x`.
///
/// `0x` and `0x0` look alike and are different facts: the first is a key
/// holding a zero-length value, the second a key that is not there. For Bridge
/// state that is "the queue is empty" against "there is no queue".
#[tokio::test]
async fn test_rsk_get_storage_bytes_at_absent_key_is_0x0_not_null() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";

    let resp = dispatch_for_test(
        &state,
        make_request("rsk_getStorageBytesAt", json!([addr, "0xdead", "latest"])),
    )
    .await;
    let v = resp.result.unwrap();
    assert!(!v.is_null(), "an absent key must not answer null");
    assert_eq!(v.as_str().unwrap(), "0x0");
}

/// rskj takes the key through `strHexOrStrNumberToByteArray`, which accepts a
/// short hex string and left-pads it. A caller who writes `0x1` should get the
/// same answer as one who writes the full word.
#[tokio::test]
async fn test_rsk_get_storage_bytes_at_accepts_a_short_key() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let short = dispatch_for_test(&state, make_request("rsk_getStorageBytesAt", json!([addr, "0x2", "latest"]))).await;
    let full = dispatch_for_test(
        &state,
        make_request("rsk_getStorageBytesAt", json!([addr, "0x0000000000000000000000000000000000000000000000000000000000000002", "latest"])),
    )
    .await;
    assert_eq!(short.result.unwrap(), full.result.unwrap(), "a short key must resolve like the padded one");
}

#[tokio::test]
async fn test_rsk_get_storage_bytes_at_rejects_bad_input() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";

    for (params, what) in [
        (json!(["not-an-address", "0x1", "latest"]), "address"),
        (json!([addr, "0xZZ", "latest"]), "non-hex key"),
        (json!([addr]), "missing key"),
    ] {
        let resp = dispatch_for_test(&state, make_request("rsk_getStorageBytesAt", params)).await;
        assert!(resp.error.is_some(), "{what} should be rejected, not answered");
    }
}

/// Reading at a historical block reads that block's state, not the head's.
/// Bridge state you can only ask about at the tip is much less useful for
/// investigating something that already happened.
#[tokio::test]
async fn test_rsk_get_storage_bytes_at_reads_the_requested_block() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";

    let by_number = dispatch_for_test(&state, make_request("rsk_getStorageBytesAt", json!([addr, "0x2", "0x2a"]))).await;
    let latest = dispatch_for_test(&state, make_request("rsk_getStorageBytesAt", json!([addr, "0x2", "latest"]))).await;
    assert_eq!(
        by_number.result.unwrap(),
        latest.result.unwrap(),
        "block #42 is the head in this fixture, so the two must agree"
    );
}

// ========== rsk receipt proofs (#87) ==========

/// A block of `n` transactions with matching receipts, canonical, indexed.
/// Returns the state, the block hash, the transaction hashes and the receipts.
fn setup_state_with_receipts(
    n: usize,
) -> (RpcState, B256, Vec<B256>, Vec<rustock_core::Receipt>, tempfile::TempDir) {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let mut txs = Vec::new();
    let mut tx_hashes = Vec::new();
    let mut receipts = Vec::new();
    for i in 0..n {
        let tx = rustock_core::Transaction {
            nonce: i as u64,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: alloy_primitives::Bytes::from(vec![0x12u8; 20]),
            value: U256::from(1_000_000u64 + i as u64),
            input: alloy_primitives::Bytes::default(),
            v: 27,
            r: U256::from(100u64 + i as u64),
            s: U256::from(200u64),
            cached_rlp: None,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        tx_hashes.push(B256::from_slice(&Keccak256::digest(&buf)));
        receipts.push(rustock_core::Receipt {
            post_tx_state: vec![0x01],
            cumulative_gas_used: 21_000 * (i as u64 + 1),
            gas_used: 21_000,
            logs_bloom: alloy_primitives::Bloom::ZERO,
            logs: vec![],
            status: true,
        });
        txs.push(tx);
    }

    // The header carries the real receipts root, so a proof can be checked
    // against it rather than against something the test computed twice.
    let receipts_root = rustock_core::types::receipt::ordered_trie_root(&receipts, true);
    let header = Header { receipts_root, ..test_header(1) };
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(1, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(1000)).unwrap();
    store.put_body(block_hash, &txs, &[]).unwrap();
    for (i, h) in tx_hashes.iter().enumerate() {
        store.put_tx_index(*h, block_hash, i as u32).unwrap();
    }
    store.put_receipts(block_hash, &receipts).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };
    (state, block_hash, tx_hashes, receipts, tmp)
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("hex")
}

/// **The test that matters: verify the proof, do not just inspect its shape.**
///
/// A proof test that does not verify the proof is checking nothing. This takes
/// the returned nodes, loads them into an otherwise-empty trie store, rebuilds
/// the root from the last one, and asks it for the receipt — so a pass means
/// the nodes really are sufficient to reach the value from the root, and that
/// the root really is the block's `receiptsRoot`.
#[tokio::test]
async fn test_receipt_proof_verifies_against_the_blocks_receipts_root() {
    use rustock_core::types::receipt::receipt_trie_key;
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode, TrieStore};

    let (state, block_hash, tx_hashes, receipts, _tmp) = setup_state_with_receipts(8);
    let target = 5usize; // a deep path, not a single-entry trie

    let nodes_resp = dispatch_for_test(
        &state,
        make_request(
            "rsk_getTransactionReceiptNodesByHash",
            json!([format!("0x{}", hex::encode(block_hash)), format!("0x{}", hex::encode(tx_hashes[target]))]),
        ),
    )
    .await;
    let nodes: Vec<String> = serde_json::from_value(nodes_resp.result.unwrap()).unwrap();
    assert!(nodes.len() > 1, "a path through an 8-entry trie should be more than one node");

    let raw_resp = dispatch_for_test(
        &state,
        make_request("rsk_getRawTransactionReceiptByHash", json!([format!("0x{}", hex::encode(tx_hashes[target]))])),
    )
    .await;
    let raw = unhex(raw_resp.result.unwrap().as_str().unwrap());
    assert_eq!(raw, receipts[target].rlp_encode(), "the raw receipt is not the encoding that went into the trie");

    // Load only what the proof supplied, keyed by the hash of the bytes as
    // sent. A node hash is `keccak(to_message)`, and `to_message` consults the
    // store — so re-serialising a node whose siblings are absent, which is
    // exactly what a proof is, would produce different bytes and a different
    // hash. The message that arrived is the message that was hashed.
    use sha3::{Digest, Keccak256};
    let proof_store = MemoryTrieStore::new();
    let mut root_message = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        let bytes = unhex(n);
        let h = B256::from_slice(&Keccak256::digest(&bytes));
        TrieStore::put(&proof_store, h.as_slice(), &bytes);
        if i == nodes.len() - 1 {
            root_message = bytes; // leaf first, root LAST
        }
    }

    // 1. The root of the proof is the block's receipts root.
    let header = state.store.header(block_hash).unwrap().unwrap();
    assert_eq!(
        B256::from_slice(&Keccak256::digest(&root_message)),
        header.receipts_root,
        "the last node is not the block's receipts root -- is the order root-first?"
    );

    // The receipt is a *long value*: the leaf carries its hash, not its bytes,
    // so the nodes alone cannot yield it. That is precisely why these two
    // methods are a pair — `getNodes` gives the path, `getRawTransactionReceipt`
    // gives the value, and only together do they prove anything.
    TrieStore::put(
        &proof_store,
        B256::from_slice(&Keccak256::digest(&raw)).as_slice(),
        &raw,
    );

    let root = TrieNode::from_message(&root_message, &proof_store);

    // 2. Walking it with only the proof's nodes reaches the receipt.
    let key = TrieKeySlice::from_key(&receipt_trie_key(target as u32));
    assert_eq!(
        root.get(&key, &proof_store),
        Some(receipts[target].rlp_encode()),
        "the proof does not actually prove the receipt"
    );
}

/// Ordering is leaf-first, root-last — rskj's `findNodes` appends each level
/// *after* recursing. A consumer that assumes root-first silently fails to
/// verify, so it is pinned rather than left implicit.
#[tokio::test]
async fn test_receipt_proof_nodes_are_leaf_first_root_last() {
    let (state, block_hash, tx_hashes, _receipts, _tmp) = setup_state_with_receipts(8);
    let resp = dispatch_for_test(
        &state,
        make_request(
            "rsk_getTransactionReceiptNodesByHash",
            json!([format!("0x{}", hex::encode(block_hash)), format!("0x{}", hex::encode(tx_hashes[3]))]),
        ),
    )
    .await;
    let nodes: Vec<String> = serde_json::from_value(resp.result.unwrap()).unwrap();

    use sha3::{Digest, Keccak256};
    let header = state.store.header(block_hash).unwrap().unwrap();
    let last = B256::from_slice(&Keccak256::digest(unhex(nodes.last().unwrap())));
    let first = B256::from_slice(&Keccak256::digest(unhex(&nodes[0])));

    assert_eq!(last, header.receipts_root, "the ROOT must be last");
    assert_ne!(first, header.receipts_root, "the root must not be first");
}

#[tokio::test]
async fn test_receipt_proof_unknown_inputs_return_null() {
    let (state, block_hash, tx_hashes, _r, _tmp) = setup_state_with_receipts(3);
    let bogus = format!("0x{}", hex::encode(B256::repeat_byte(0xEE)));

    // A known transaction against the wrong block.
    let wrong_block = dispatch_for_test(
        &state,
        make_request("rsk_getTransactionReceiptNodesByHash", json!([bogus, format!("0x{}", hex::encode(tx_hashes[0]))])),
    )
    .await;
    assert!(wrong_block.result.unwrap().is_null(), "a transaction not in that block must be null");

    // An unknown transaction in a real block.
    let unknown_tx = dispatch_for_test(
        &state,
        make_request("rsk_getTransactionReceiptNodesByHash", json!([format!("0x{}", hex::encode(block_hash)), bogus])),
    )
    .await;
    assert!(unknown_tx.result.unwrap().is_null());

    // An unknown transaction hash for the raw receipt.
    let unknown_raw = dispatch_for_test(&state, make_request("rsk_getRawTransactionReceiptByHash", json!([bogus]))).await;
    assert!(unknown_raw.result.unwrap().is_null());
}

#[tokio::test]
async fn test_receipt_proof_rejects_malformed_input() {
    let (state, _b, _t, _r, _tmp) = setup_state_with_receipts(1);
    for params in [json!(["not-a-hash"]), json!([])] {
        let resp = dispatch_for_test(&state, make_request("rsk_getRawTransactionReceiptByHash", params)).await;
        assert!(resp.error.is_some(), "malformed input should be refused, not answered null");
    }
}


// ========== eth_bridgeState (#86) ==========

/// The shape is two fields, and only two.
///
/// `BridgeState` holds the UTXO set, the federation, the release request queue
/// and the pegouts waiting for confirmations — and `stateToMap()`, which is
/// what the RPC returns, exposes none of them. A caller expecting a full dump
/// is expecting something rskj never gave.
#[tokio::test]
async fn test_eth_bridge_state_returns_exactly_rskjs_two_fields() {
    let (state, _tmp) = setup_state_with_trie();
    let resp = dispatch_for_test(&state, make_request("eth_bridgeState", json!([]))).await;

    let v = resp.result.expect("should answer");
    let obj = v.as_object().expect("an object");

    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["btcBlockchainBestChainHeight", "rskTxsWaitingForSignatures"],
        "rskj's stateToMap() returns these two and nothing else"
    );
    assert!(obj["btcBlockchainBestChainHeight"].is_number());
    assert!(obj["rskTxsWaitingForSignatures"].is_array());
}

/// It takes no block parameter: rskj reads `blockchain.getBestBlock()`
/// unconditionally. A caller passing one must not be able to steer the answer
/// into believing it got a historical read.
#[tokio::test]
async fn test_eth_bridge_state_ignores_any_block_parameter() {
    let (state, _tmp) = setup_state_with_trie();
    let bare = dispatch_for_test(&state, make_request("eth_bridgeState", json!([]))).await;
    let with_block = dispatch_for_test(&state, make_request("eth_bridgeState", json!(["0x1"]))).await;
    assert_eq!(
        bare.result.unwrap(),
        with_block.result.unwrap(),
        "a block parameter must not change the answer -- rskj has none"
    );
}

/// An empty Bridge answers with an empty list, not null: the list is always
/// present even when there is nothing waiting.
#[tokio::test]
async fn test_eth_bridge_state_with_nothing_waiting_is_an_empty_list() {
    let (state, _tmp) = setup_state_with_trie();
    let resp = dispatch_for_test(&state, make_request("eth_bridgeState", json!([]))).await;
    let v = resp.result.unwrap();
    assert_eq!(v["rskTxsWaitingForSignatures"], json!([]));
    assert_eq!(v["btcBlockchainBestChainHeight"], json!(0), "no BTC chain head seeded in this fixture");
}

/// The hashes carry **no `0x` prefix**.
///
/// `Keccak256.toHexString()` is `Hex.toHexString(bytes)` — bare hex. Almost
/// everything else in JSON-RPC is `0x`-prefixed, so this is the kind of
/// difference a consumer finds by failing to parse, and it is worth a test
/// rather than a comment.
#[tokio::test]
async fn test_eth_bridge_state_hashes_have_no_0x_prefix() {
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode, storage_key};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let trie_store: Arc<dyn rustock_trie::TrieStore> = Arc::new(MemoryTrieStore::new());

    // rskTxsWaitingFS is an RLP list of (32-byte rsk tx hash, btc tx) pairs.
    let tx_hash = [0xABu8; 32];
    let mut payload = Vec::new();
    {
        use alloy_rlp::Encodable;
        let items: Vec<alloy_primitives::Bytes> = vec![
            alloy_primitives::Bytes::from(tx_hash.to_vec()),
            alloy_primitives::Bytes::from(vec![0x01u8, 0x02, 0x03]),
        ];
        items.encode(&mut payload);
    }

    let bridge_key = rustock_execution::bridge::storage::bridge_storage_key(
        rustock_execution::bridge::storage::PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
    );
    let trie_key = storage_key(
        &rustock_execution::precompiles::BRIDGE_ADDR,
        &B256::from(bridge_key),
    );

    let mut root = TrieNode::empty();
    root = root.put(&TrieKeySlice::from_key(&trie_key), &payload, &*trie_store);
    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);
    rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root.to_message(&*trie_store));

    let header = Header { state_root, ..test_header(42) };
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, hash).unwrap();
    store.set_head(hash).unwrap();
    store.put_total_difficulty(hash, U256::from(42_000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: Some(trie_store),
        hardfork_cfg: Some(rustock_execution::RskHardforkConfig::mainnet()),
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };

    let resp = dispatch_for_test(&state, make_request("eth_bridgeState", json!([]))).await;
    let v = resp.result.unwrap();
    let list = v["rskTxsWaitingForSignatures"].as_array().expect("a list");
    assert_eq!(list.len(), 1, "the seeded waiting transaction should appear");

    let s = list[0].as_str().unwrap();
    assert!(!s.starts_with("0x"), "rskj emits bare hex here, not 0x-prefixed: got {s}");
    assert_eq!(s, hex::encode(tx_hash));
}

// ========== eth_getUncleBy*AndIndex ==========
//
// Checked against rskj's `Web3Impl.getUncleResultDTO` at the revision pinned in
// docs/rskj-reference.md. Two of its behaviours are easy to get wrong and are
// each pinned by a test below: an out-of-range index is `null` rather than an
// error, and the uncle is rendered with its *own* transactions when the node
// has that block stored.

/// Builds a block at `number` with `uncles` ommers, stores header, body,
/// canonical index and total difficulty, and returns its hash.
fn store_block_with_uncles(
    store: &BlockStore,
    number: u64,
    uncles: &[Header],
) -> B256 {
    let mut header = test_header(number);
    header.uncle_count = uncles.len() as u64;
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_body(hash, &[], uncles).unwrap();
    store.put_canonical_hash(number, hash).unwrap();
    store.put_total_difficulty(hash, U256::from(1_000 * number)).unwrap();
    hash
}

/// A header distinguishable from every other in these tests by its timestamp,
/// so the hashes differ.
fn uncle_header(number: u64, tag: u64) -> Header {
    let mut h = test_header(number);
    h.timestamp += tag * 1_000;
    h.cached_hash = None;
    h
}

#[tokio::test]
async fn test_eth_get_uncle_by_block_hash_and_index() {
    let (state, _tmp) = setup_state();
    let u0 = uncle_header(100, 1);
    let u1 = uncle_header(100, 2);
    let block = store_block_with_uncles(&state.store, 101, &[u0.clone(), u1.clone()]);

    for (idx, uncle) in [(0u32, &u0), (1u32, &u1)] {
        let req = make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), format!("{:#x}", idx)]),
        );
        let resp = dispatch_for_test(&state, req).await;
        let result = resp.result.unwrap();
        assert_eq!(result["hash"], json!(format!("{:#x}", uncle.hash())), "index {idx}");
        assert_eq!(result["number"], json!("0x64"));
        assert_eq!(result["parentHash"], json!(format!("{:#x}", uncle.parent_hash)));
    }
}

#[tokio::test]
async fn test_eth_get_uncle_by_block_number_and_index_agrees_with_by_hash() {
    let (state, _tmp) = setup_state();
    let u0 = uncle_header(200, 7);
    let block = store_block_with_uncles(&state.store, 201, &[u0]);

    let by_hash = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), "0x0"]),
        ),
    )
    .await
    .result
    .unwrap();
    let by_number = dispatch_for_test(
        &state,
        make_request("eth_getUncleByBlockNumberAndIndex", json!(["0xc9", "0x0"])),
    )
    .await
    .result
    .unwrap();

    assert_ne!(by_hash, json!(null));
    assert_eq!(by_hash, by_number, "the two lookups must render the same uncle");
}

#[tokio::test]
async fn test_eth_get_uncle_out_of_range_index_is_null_not_an_error() {
    // rskj: `if (uncleIdx >= block.getUncleList().size()) return null;` -- a
    // caller walking indices until null must not get an error instead.
    let (state, _tmp) = setup_state();
    let block = store_block_with_uncles(&state.store, 301, &[uncle_header(300, 3)]);

    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), "0x1"]),
        ),
    )
    .await;
    assert!(resp.error.is_none(), "out of range must not be an error");
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_uncle_of_uncleless_block_is_null() {
    let (state, _tmp) = setup_state();
    let block = store_block_with_uncles(&state.store, 401, &[]);

    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), "0x0"]),
        ),
    )
    .await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_uncle_of_unknown_block_is_null() {
    let (state, _tmp) = setup_state();
    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", B256::repeat_byte(0xab)), "0x0"]),
        ),
    )
    .await;
    assert_eq!(resp.result.unwrap(), Value::Null);

    let resp = dispatch_for_test(
        &state,
        make_request("eth_getUncleByBlockNumberAndIndex", json!(["0xfffff", "0x0"])),
    )
    .await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_uncle_malformed_index_is_an_error() {
    // rskj rejects this in `HexIndexParam`, during parameter deserialisation,
    // so it is an error even though an out-of-range index is not.
    let (state, _tmp) = setup_state();
    let block = store_block_with_uncles(&state.store, 501, &[uncle_header(500, 5)]);

    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), "zz"]),
        ),
    )
    .await;
    assert!(resp.error.is_some(), "a malformed index is an invalid parameter");
}

#[tokio::test]
async fn test_eth_get_uncle_unstored_uncle_renders_as_an_empty_block() {
    // The common case: the node never downloaded the competing branch, so it
    // has the uncle's header (from the including block's body) and nothing
    // else. rskj synthesises `Block.createBlockFromHeader` -- empty lists --
    // and `getTotalDifficultyForHash` returns ZERO for a hash it lacks.
    let (state, _tmp) = setup_state();
    let block = store_block_with_uncles(&state.store, 601, &[uncle_header(600, 6)]);

    let result = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), "0x0"]),
        ),
    )
    .await
    .result
    .unwrap();

    assert_eq!(result["transactions"], json!([]));
    assert_eq!(result["uncles"], json!([]));
    assert_eq!(result["totalDifficulty"], json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_uncle_stored_uncle_renders_its_own_transactions() {
    // rskj looks the uncle up as a block first and only falls back to the
    // header. So when the node *does* have that block -- it downloaded the
    // competing branch during a reorg -- the answer carries the uncle's
    // transaction hashes and its real total difficulty.
    //
    // go-ethereum always answers with an empty block here. Returning `[]`
    // unconditionally would look right and be wrong; this test is what stops
    // that. See docs/rskj-vs-geth.md.
    let (state, _tmp) = setup_state();

    let uncle = uncle_header(700, 8);
    let uncle_hash = uncle.hash();
    let tx = rustock_core::Transaction {
        nonce: 3,
        gas_price: U256::from(20_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x34; 20]),
        value: U256::from(7),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(11),
        s: U256::from(22),
        cached_rlp: None,
    };
    state.store.put_header(&uncle).unwrap();
    state.store.put_body(uncle_hash, std::slice::from_ref(&tx), &[]).unwrap();
    state.store.put_total_difficulty(uncle_hash, U256::from(4242)).unwrap();

    let block = store_block_with_uncles(&state.store, 701, &[uncle]);

    let result = dispatch_for_test(
        &state,
        make_request(
            "eth_getUncleByBlockHashAndIndex",
            json!([format!("{:#x}", block), "0x0"]),
        ),
    )
    .await
    .result
    .unwrap();

    assert_eq!(
        result["transactions"],
        json!([format!("{:#x}", tx.tx_hash())]),
        "a stored uncle is rendered with its own transactions, as hashes"
    );
    assert_eq!(result["totalDifficulty"], json!("0x1092"));
}

#[tokio::test]
async fn test_block_size_counts_the_whole_block_not_just_the_header() {
    // rskj reports `block.getEncoded().length`: the RLP list
    // [header, transactions, uncles]. Measuring the header alone made `size`
    // independent of the transactions, which is the one thing callers use it
    // for.
    let (state, _tmp) = setup_state();

    let tx = rustock_core::Transaction {
        nonce: 1,
        gas_price: U256::from(1),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x56; 20]),
        value: U256::from(1),
        input: alloy_primitives::Bytes::from(vec![0xab; 500]),
        v: 27,
        r: U256::from(1),
        s: U256::from(2),
        cached_rlp: None,
    };
    let header = test_header(900);
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_body(hash, std::slice::from_ref(&tx), &[]).unwrap();
    state.store.put_canonical_hash(900, hash).unwrap();

    let result = dispatch_for_test(
        &state,
        make_request("eth_getBlockByHash", json!([format!("{:#x}", hash), false])),
    )
    .await
    .result
    .unwrap();

    let size = u64::from_str_radix(
        result["size"].as_str().unwrap().trim_start_matches("0x"),
        16,
    )
    .unwrap();

    let mut header_rlp = Vec::new();
    alloy_rlp::Encodable::encode(&header, &mut header_rlp);
    assert!(
        size > header_rlp.len() as u64 + 500,
        "size {size} must include the 500-byte payload on top of the {}-byte header",
        header_rlp.len()
    );
}

// ========== txpool_content / txpool_inspect / txpool_status ==========
//
// Every expected string here was read off rskj's `TxPoolModuleImpl` at the
// revision pinned in docs/rskj-reference.md. The formats are deliberately
// asserted literally: the ways this method differs from go-ethereum are all
// formatting, so a test that merely checked structure would pass against the
// wrong output.

/// A pool with whatever contents a test needs.
struct PoolDouble {
    pending: Vec<(alloy_primitives::Address, Vec<(u64, rustock_core::Transaction)>)>,
    queued: Vec<(alloy_primitives::Address, Vec<(u64, rustock_core::Transaction)>)>,
}

impl crate::server::TxPoolReader for PoolDouble {
    fn get_pending_tx(
        &self,
        _hash: &B256,
    ) -> Option<(rustock_core::Transaction, alloy_primitives::Address, B256)> {
        None
    }
    fn pending_nonce(&self, _addr: &alloy_primitives::Address) -> Option<u64> {
        None
    }
    fn pool_status(&self) -> (usize, usize) {
        let count = |g: &Vec<(alloy_primitives::Address, Vec<(u64, rustock_core::Transaction)>)>| {
            g.iter().map(|(_, txs)| txs.len()).sum::<usize>()
        };
        (count(&self.pending), count(&self.queued))
    }
    fn pool_content(&self) -> crate::server::PoolContent {
        crate::server::PoolContent {
            pending: self.pending.clone(),
            queued: self.queued.clone(),
        }
    }
    fn quota_report(&self, _address: &alloy_primitives::Address) -> Option<(f64, u64)> {
        None
    }
}

fn pool_tx(nonce: u64, to: Vec<u8>, value: U256, gas_price: U256) -> rustock_core::Transaction {
    rustock_core::Transaction {
        nonce,
        gas_price,
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(to),
        value,
        input: alloy_primitives::Bytes::new(),
        v: 27,
        r: U256::from(1u64),
        s: U256::from(2u64),
        cached_rlp: None,
    }
}

fn state_with_pool(pool: PoolDouble) -> (RpcState, tempfile::TempDir) {
    let (mut state, tmp) = setup_state();
    state.tx_pool = Some(Arc::new(pool));
    (state, tmp)
}

#[tokio::test]
async fn test_txpool_content_groups_by_sender_then_nonce() {
    let alice = alloy_primitives::Address::repeat_byte(0xa1);
    let bob = alloy_primitives::Address::repeat_byte(0xb2);
    let (state, _tmp) = state_with_pool(PoolDouble {
        pending: vec![
            (
                alice,
                vec![
                    (5, pool_tx(5, vec![0x11; 20], U256::from(1), U256::from(1))),
                    (6, pool_tx(6, vec![0x11; 20], U256::from(2), U256::from(1))),
                ],
            ),
            (bob, vec![(0, pool_tx(0, vec![0x22; 20], U256::from(3), U256::from(1)))]),
        ],
        queued: vec![(alice, vec![(9, pool_tx(9, vec![0x11; 20], U256::from(4), U256::from(1)))])],
    });

    let result = dispatch_for_test(&state, make_request("txpool_content", json!([])))
        .await
        .result
        .unwrap();

    // Sender keys are bare hex: rskj uses RskAddress.toString(), not toJsonString().
    let alice_key = "a1".repeat(20);
    let bob_key = "b2".repeat(20);
    assert!(
        result["pending"].get(&alice_key).is_some(),
        "sender keys must be bare hex with no 0x prefix, got {:?}",
        result["pending"].as_object().unwrap().keys().collect::<Vec<_>>()
    );
    assert!(result["pending"].get(format!("0x{alice_key}")).is_none());

    // Nonce keys are decimal, and each maps to an ARRAY.
    let alice_pending = &result["pending"][&alice_key];
    assert_eq!(
        alice_pending.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["5", "6"],
        "nonce keys are decimal"
    );
    assert!(alice_pending["5"].is_array(), "rskj emits an ArrayNode per nonce");
    assert_eq!(alice_pending["5"].as_array().unwrap().len(), 1);
    assert_eq!(alice_pending["5"][0]["nonce"], json!("0x5"));

    assert_eq!(result["pending"][&bob_key]["0"][0]["nonce"], json!("0x0"));
    assert_eq!(
        result["queued"][&alice_key]["9"][0]["nonce"],
        json!("0x9"),
        "a nonce gap belongs under queued"
    );
    assert!(result["queued"].get(&bob_key).is_none());
}

#[tokio::test]
async fn test_txpool_content_transaction_fields_match_rskj() {
    let alice = alloy_primitives::Address::repeat_byte(0xa1);
    let tx = pool_tx(
        7,
        vec![0xcd; 20],
        U256::from(1_000u64),
        U256::from(20_000_000_000u64),
    );
    let (state, _tmp) = state_with_pool(PoolDouble {
        pending: vec![(alice, vec![(7, tx.clone())])],
        queued: vec![],
    });

    let result = dispatch_for_test(&state, make_request("txpool_content", json!([])))
        .await
        .result
        .unwrap();
    let node = &result["pending"][&"a1".repeat(20)]["7"][0];

    // rskj writes the ZERO HASH here, not null -- while the two fields beside
    // it are null. go-ethereum nulls all three.
    assert_eq!(
        node["blockHash"],
        json!("0x0000000000000000000000000000000000000000000000000000000000000000")
    );
    assert_eq!(node["blockNumber"], json!(null));
    assert_eq!(node["transactionIndex"], json!(null));

    assert_eq!(node["from"], json!(format!("0x{}", "a1".repeat(20))));
    assert_eq!(node["to"], json!(format!("0x{}", "cd".repeat(20))));
    assert_eq!(node["hash"], json!(format!("{:#x}", tx.tx_hash())));
    assert_eq!(node["gas"], json!("0x5208"), "gas is a canonical quantity");
    assert_eq!(node["nonce"], json!("0x7"));
    assert_eq!(node["input"], json!("0x"), "empty data is 0x, not 0x00");
    assert_eq!(node["value"], json!("0x03e8"));
    assert_eq!(node["gasPrice"], json!("0x04a817c800"));

    // No signature or type fields: rskj's fullSerializer writes eleven keys.
    let keys: Vec<&String> = node.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 11, "unexpected fields: {keys:?}");
    for absent in ["v", "r", "s", "type", "chainId"] {
        assert!(node.get(absent).is_none(), "{absent} is a geth field");
    }
}

#[tokio::test]
async fn test_txpool_content_value_is_a_twos_complement_byte_dump() {
    // rskj renders value and gasPrice with HexUtils.toJsonHex(Coin.getBytes()),
    // and Coin.getBytes() is BigInteger.toByteArray(). A value whose top bit is
    // set therefore gains a leading 00 -- it is not a JSON-RPC quantity, even
    // though `gas` and `nonce` in the same object are.
    let alice = alloy_primitives::Address::repeat_byte(0xa1);
    let (state, _tmp) = state_with_pool(PoolDouble {
        pending: vec![(
            alice,
            vec![
                (0, pool_tx(0, vec![0x11; 20], U256::from(0xffu64), U256::ZERO)),
                (1, pool_tx(1, vec![0x11; 20], U256::ZERO, U256::from(0x7fu64))),
            ],
        )],
        queued: vec![],
    });

    let result = dispatch_for_test(&state, make_request("txpool_content", json!([])))
        .await
        .result
        .unwrap();
    let by_nonce = &result["pending"][&"a1".repeat(20)];

    assert_eq!(by_nonce["0"][0]["value"], json!("0x00ff"), "high bit set");
    assert_eq!(by_nonce["1"][0]["value"], json!("0x00"), "zero is one 0x00 byte");
    assert_eq!(by_nonce["1"][0]["gasPrice"], json!("0x7f"), "high bit clear");
}

#[tokio::test]
async fn test_txpool_content_contract_creation_has_no_recipient() {
    // rskj's getReceiveAddress() is the null address for a creation, whose
    // bytes are empty -- and toJsonHex turns an empty array into "0x00".
    let alice = alloy_primitives::Address::repeat_byte(0xa1);
    let (state, _tmp) = state_with_pool(PoolDouble {
        pending: vec![(alice, vec![(0, pool_tx(0, vec![], U256::from(1), U256::from(1)))])],
        queued: vec![],
    });

    let content = dispatch_for_test(&state, make_request("txpool_content", json!([])))
        .await
        .result
        .unwrap();
    assert_eq!(content["pending"][&"a1".repeat(20)]["0"][0]["to"], json!("0x00"));

    let inspect = dispatch_for_test(&state, make_request("txpool_inspect", json!([])))
        .await
        .result
        .unwrap();
    assert_eq!(
        inspect["pending"][&"a1".repeat(20)]["0"][0],
        json!(": 1 wei + 21000 x 1 gas"),
        "an empty recipient leaves the summary starting with a colon"
    );
}

#[tokio::test]
async fn test_txpool_inspect_summary_matches_rskj_format() {
    // String.format("%s: %s wei + %d x %s gas", to, value, gasLimit, gasPrice)
    //
    // Not geth's "%s: %v wei + %v gas × %v wei": ASCII x rather than the
    // multiplication sign, gas limit and price in the other order, and the
    // word `gas` last. The address is bare hex and all three numbers decimal.
    let alice = alloy_primitives::Address::repeat_byte(0xa1);
    let (state, _tmp) = state_with_pool(PoolDouble {
        pending: vec![(
            alice,
            vec![(
                3,
                pool_tx(
                    3,
                    vec![0xcd; 20],
                    U256::from(1_000_000_000_000_000_000u64),
                    U256::from(20_000_000_000u64),
                ),
            )],
        )],
        queued: vec![],
    });

    let result = dispatch_for_test(&state, make_request("txpool_inspect", json!([])))
        .await
        .result
        .unwrap();

    assert_eq!(
        result["pending"][&"a1".repeat(20)]["3"][0],
        json!(format!(
            "{}: 1000000000000000000 wei + 21000 x 20000000000 gas",
            "cd".repeat(20)
        ))
    );
}

#[tokio::test]
async fn test_txpool_status_is_numbers_and_agrees_with_content() {
    let alice = alloy_primitives::Address::repeat_byte(0xa1);
    let bob = alloy_primitives::Address::repeat_byte(0xb2);
    let (state, _tmp) = state_with_pool(PoolDouble {
        pending: vec![
            (alice, vec![(0, pool_tx(0, vec![0x11; 20], U256::from(1), U256::from(1)))]),
            (bob, vec![(0, pool_tx(0, vec![0x22; 20], U256::from(1), U256::from(1)))]),
        ],
        queued: vec![(alice, vec![(4, pool_tx(4, vec![0x11; 20], U256::from(1), U256::from(1)))])],
    });

    let status = dispatch_for_test(&state, make_request("txpool_status", json!([])))
        .await
        .result
        .unwrap();

    // rskj emits numberNode, go-ethereum emits hexutil.Uint ("0x2").
    assert_eq!(status["pending"], json!(2));
    assert_eq!(status["queued"], json!(1));
    assert!(status["pending"].is_number(), "rskj reports counts as JSON numbers");

    let content = dispatch_for_test(&state, make_request("txpool_content", json!([])))
        .await
        .result
        .unwrap();
    let total = |side: &Value| -> u64 {
        side.as_object()
            .unwrap()
            .values()
            .map(|by_nonce| by_nonce.as_object().unwrap().values()
                .map(|txs| txs.as_array().unwrap().len() as u64).sum::<u64>())
            .sum()
    };
    assert_eq!(total(&content["pending"]), 2, "status and content are the same pool");
    assert_eq!(total(&content["queued"]), 1);
}

#[tokio::test]
async fn test_txpool_empty_pool_returns_empty_objects() {
    let (state, _tmp) = state_with_pool(PoolDouble { pending: vec![], queued: vec![] });

    for method in ["txpool_content", "txpool_inspect"] {
        let result = dispatch_for_test(&state, make_request(method, json!([])))
            .await
            .result
            .unwrap();
        assert_eq!(result, json!({"pending": {}, "queued": {}}), "{method}");
    }

    let status = dispatch_for_test(&state, make_request("txpool_status", json!([])))
        .await
        .result
        .unwrap();
    assert_eq!(status, json!({"pending": 0, "queued": 0}));
}

// ========== a block is only served when the node has it ==========

/// Sync is header-first: headers arrive in batches and bodies follow. A block
/// in that window has a header claiming transactions and no body, and the node
/// used to render it as `transactions: []` -- a wrong answer, not merely an
/// incomplete one.
///
/// rskj cannot reach this state: `saveBlock` writes `block.getEncoded()`, body
/// included, under one key, so `getBlockByHash` returns a complete block or
/// null. `null` is both the truthful answer and the rskj-compatible one.
#[tokio::test]
async fn test_a_block_whose_body_is_missing_is_not_served() {
    let (state, _tmp) = setup_state();

    let mut header = test_header(77);
    // A header that claims transactions: the empty-trie root would mean there
    // is nothing to fetch.
    header.transactions_root = B256::repeat_byte(0x33);
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_canonical_hash(77, hash).unwrap();

    for (method, params) in [
        ("eth_getBlockByHash", json!([format!("{:#x}", hash), false])),
        ("eth_getBlockByNumber", json!(["0x4d", false])),
        ("eth_getBlockTransactionCountByHash", json!([format!("{:#x}", hash)])),
        ("eth_getBlockTransactionCountByNumber", json!(["0x4d"])),
    ] {
        let resp = dispatch_for_test(&state, make_request(method, params)).await;
        assert_eq!(
            resp.result.unwrap(),
            Value::Null,
            "{method} must not report a block whose body the node has not downloaded"
        );
    }
}

/// The other half of the same rule: a block whose header says there is nothing
/// to store is served even with no body row, because there is nothing missing.
///
/// This is not hypothetical -- genesis is written by `setup_genesis`, which
/// stores the header, total difficulty, canonical entry and head, and no body.
/// A rule of "no body, no block" would have made `eth_getBlockByNumber("0x0")`
/// answer null on every node.
#[tokio::test]
async fn test_a_genuinely_empty_block_is_served_without_a_body_row() {
    let (state, _tmp) = setup_state();

    let header = test_header(78); // empty-trie roots, as a real empty block has
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_canonical_hash(78, hash).unwrap();
    assert!(state.store.body(hash).unwrap().is_none(), "no body row at all");

    let result = dispatch_for_test(
        &state,
        make_request("eth_getBlockByHash", json!([format!("{:#x}", hash), false])),
    )
    .await
    .result
    .unwrap();
    assert_eq!(result["number"], json!("0x4e"), "the block is still served");
    assert_eq!(result["transactions"], json!([]));

    let count = dispatch_for_test(
        &state,
        make_request("eth_getBlockTransactionCountByHash", json!([format!("{:#x}", hash)])),
    )
    .await
    .result
    .unwrap();
    assert_eq!(count, json!("0x0"), "and the count agrees with it");
}

/// An uncle is the deliberate exception. rskj synthesises an empty block from
/// the uncle's header when it does not hold that block
/// (`Block.createBlockFromHeader`), so empty `transactions` there is the
/// correct answer rather than a missing one -- and the uncle getters must keep
/// doing it even though the block getters no longer do.
#[tokio::test]
async fn test_an_uncle_is_still_synthesised_from_its_header() {
    let (state, _tmp) = setup_state();

    let mut uncle = uncle_header(800, 9);
    uncle.transactions_root = B256::repeat_byte(0x44); // it did have transactions
    uncle.cached_hash = None;
    let block = store_block_with_uncles(&state.store, 801, &[uncle.clone()]);

    let result = dispatch_for_test(
        &state,
        make_request("eth_getUncleByBlockHashAndIndex", json!([format!("{:#x}", block), "0x0"])),
    )
    .await
    .result
    .unwrap();

    assert_ne!(result, Value::Null, "an uncle we lack the block for is still rendered");
    assert_eq!(result["transactions"], json!([]), "synthesised from the header, as rskj does");
    assert_eq!(result["hash"], json!(format!("{:#x}", uncle.hash())));
}

// ========== debug_* ==========
//
// Shapes are rskj's `Web3DebugModule` / `DebugModuleImpl`. go-ethereum has
// neither method, so there is nothing to be compatible with in that direction.

/// rskj: `HexUtils.toQuantityJsonHex(messageHandler.getMessageQueueSize())` --
/// a hex quantity **string**, not a number. `txpool_status` in the same server
/// answers with JSON numbers; that inconsistency is rskj's and both are
/// reproduced rather than harmonised.
#[tokio::test]
async fn test_debug_wire_protocol_queue_size_is_a_hex_string() {
    let (mut state, _tmp) = setup_state();
    let depth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    state.wire_queue_depth = Some(depth.clone());

    let r = dispatch_for_test(&state, make_request("debug_wireProtocolQueueSize", json!([]))).await;
    assert_eq!(r.result.unwrap(), json!("0x0"));

    depth.store(26, std::sync::atomic::Ordering::Relaxed);
    let r = dispatch_for_test(&state, make_request("debug_wireProtocolQueueSize", json!([]))).await;
    assert_eq!(r.result.unwrap(), json!("0x1a"), "a quantity, so no leading zeros");
}

/// Without a sync loop attached there is no queue to report, and zero is the
/// truthful answer rather than an error: nothing is waiting.
#[tokio::test]
async fn test_debug_wire_protocol_queue_size_without_a_sync_loop() {
    let (state, _tmp) = setup_state();
    let r = dispatch_for_test(&state, make_request("debug_wireProtocolQueueSize", json!([]))).await;
    assert_eq!(r.result.unwrap(), json!("0x0"));
}

/// rskj's `TxQuota` serialises exactly two `@JsonProperty` fields, and
/// `availableVirtualGas` is a **double**. The fractional part is not noise:
/// the virtual-gas cost of a transaction is a product of six fractional
/// factors, so rounding it would merge quotas that the limiter distinguishes.
#[tokio::test]
async fn test_debug_account_transaction_quota_shape() {
    let (state, _hash, _tmp) = setup_state_with_pending_tx();
    let tracked = format!("{:#x}", alloy_primitives::Address::repeat_byte(0x11));

    let result = dispatch_for_test(
        &state,
        make_request("debug_accountTransactionQuota", json!([tracked])),
    )
    .await
    .result
    .unwrap();

    assert_eq!(result["availableVirtualGas"], json!(1_234.5_f64), "a double, not rounded");
    assert_eq!(result["timestamp"], json!(1_700_000_000_000_u64));
    let keys: Vec<&String> = result.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 2, "rskj's TxQuota has exactly two JSON fields: {keys:?}");
}

/// An address the limiter has never admitted a transaction for has no entry,
/// and rskj's `accountQuotas.get(address)` returns null for it. That is the
/// common case, not an error.
#[tokio::test]
async fn test_debug_account_transaction_quota_untracked_is_null() {
    let (state, _hash, _tmp) = setup_state_with_pending_tx();
    let stranger = format!("{:#x}", alloy_primitives::Address::repeat_byte(0x77));

    let r = dispatch_for_test(
        &state,
        make_request("debug_accountTransactionQuota", json!([stranger])),
    )
    .await;
    assert_eq!(r.result.unwrap(), Value::Null);
    assert!(r.error.is_none(), "not tracked is an answer, not a failure");
}

#[tokio::test]
async fn test_debug_account_transaction_quota_rejects_a_bad_address() {
    let (state, _hash, _tmp) = setup_state_with_pending_tx();
    let r = dispatch_for_test(
        &state,
        make_request("debug_accountTransactionQuota", json!(["not-an-address"])),
    )
    .await;
    assert!(r.error.is_some());
}

// ========== eth_gasPrice ==========

/// A tracker's answer, and whether its fee market is working. The second
/// field is the gate `eth_gasPrice` applies; a tracker always has a price.
struct FixedGasPrice(u64, bool);
impl crate::server::GasPriceSource for FixedGasPrice {
    fn gas_price(&self) -> U256 {
        U256::from(self.0)
    }
    fn is_fee_market_working(&self) -> bool {
        self.1
    }
}

/// rskj `EthereumImplTest.getGasPrice_returns_trackerValue_when_feeMarketWorking_is_true`:
/// with the fee market working, the answer is `GasPriceTracker.getGasPrice()`
/// -- a percentile over recent transactions, floored at the block minimum
/// times 1.1 -- not the block's `minimumGasPrice`, which is the floor for
/// *validity* rather than the price to pay for inclusion. A wallet trusting
/// the floor during congestion underpays and waits.
#[tokio::test]
async fn test_eth_gas_price_uses_the_tracker() {
    let (mut state, _tmp) = setup_state();
    // The head's minimum is 59,240,000 (see `test_header`); with the fee
    // market working the tracker's answer must win.
    state.gas_price = Some(Arc::new(FixedGasPrice(123_456_789, true)));

    let r = dispatch_for_test(&state, make_request("eth_gasPrice", json!([]))).await;
    assert_eq!(r.result.unwrap(), json!("0x75bcd15"));
}

/// The gate, and the reason it exists.
///
/// rskj answers with the tracker **only** when the last 50 blocks averaged
/// 90% full. Without that check a tracker primed from a busy chain keeps
/// quoting its prices onto a quiet one long after the minimum has walked
/// down underneath them -- 26,065,600 wei against a minimum of 587 on the
/// run that found this, 44,000x, which is over RSKIP252's 100x cap and so
/// cannot be mined at all.
#[tokio::test]
async fn test_eth_gas_price_ignores_the_tracker_without_a_fee_market() {
    let (mut state, _tmp) = setup_state();
    state.gas_price = Some(Arc::new(FixedGasPrice(123_456_789, false)));

    let r = dispatch_for_test(&state, make_request("eth_gasPrice", json!([]))).await;
    assert_eq!(
        r.result.unwrap(),
        json!("0x3e252e0"),
        "the head's 59,240,000 times 1.1, not the tracker's 123,456,789"
    );
}

/// The number from the run that found this, pinned.
///
/// rsk-clients-lab's campaign `2026-10-28-c6` had a chain whose minimum had
/// walked down to 587 wei; rskj answered 645 and this node answered the
/// tracker's 26,065,600. 587 x 1.1 is 645.7, and rskj truncates it through
/// `BigDecimal.toBigInteger()`, so 645 is the answer and 646 would be wrong.
/// The exact ratio this node uses truncates identically here -- see
/// `GAS_PRICE_MULTIPLIER_NUM` for where the two forms part company, which is
/// nowhere a real chain reaches.
#[tokio::test]
async fn test_eth_gas_price_truncates_the_multiplier_like_rskj() {
    let (mut state, tmp) = setup_state();
    let _ = tmp;
    let mut header = state.store.header(state.store.head().unwrap().unwrap()).unwrap().unwrap();
    header.minimum_gas_price = U256::from(587u64);
    header.cached_hash = None;
    let hash = header.hash();
    state.store.put_header(&header).unwrap();
    state.store.put_canonical_hash(header.number, hash).unwrap();
    state.store.set_head(hash).unwrap();
    state.gas_price = Some(Arc::new(FixedGasPrice(26_065_600, false)));

    let r = dispatch_for_test(&state, make_request("eth_gasPrice", json!([]))).await;
    assert_eq!(r.result.unwrap(), json!("0x285"), "587 x 1.1 truncated is 645 (0x285), not 646");
}

/// Without a tracker -- a node built without sync -- the same branch answers,
/// which is rskj's: the head's minimum times 1.1, not the bare minimum.
#[tokio::test]
async fn test_eth_gas_price_falls_back_to_the_block_minimum() {
    let (state, _tmp) = setup_state();
    let r = dispatch_for_test(&state, make_request("eth_gasPrice", json!([]))).await;
    assert_eq!(r.result.unwrap(), json!("0x3e252e0"), "59,240,000 x 1.1");
}

// ========== trace_* namespace ==========

/// A parent block holding a funded sender and two contracts, and a child
/// block whose single transaction calls one contract which calls the other.
///
/// The replay needs the **parent's** state in the trie, which is what makes
/// this fixture bigger than the others: `trace_*` re-executes the block, so a
/// fixture that only stores a state root proves nothing.
fn setup_state_for_tracing() -> (RpcState, tempfile::TempDir, B256, Address, Address, Address) {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use rustock_trie::{account_key, code_key, MemoryTrieStore, TrieKeySlice, TrieNode};
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let trie_store = Arc::new(MemoryTrieStore::new());

    let key = SigningKey::from_slice(&[31u8; 32]).unwrap();
    let sender = {
        let point = key.verifying_key().to_encoded_point(false);
        Address::from_slice(&Keccak256::digest(&point.as_bytes()[1..])[12..])
    };

    // callee: PUSH1 2a PUSH1 00 MSTORE PUSH1 20 PUSH1 00 RETURN
    let callee_code = vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
    let callee = Address::repeat_byte(0xCE);
    // caller: CALL(gas, callee, 0, 0, 0, 0, 0) then STOP
    let mut caller_code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00];
    caller_code.push(0x73);
    caller_code.extend_from_slice(callee.as_slice());
    caller_code.extend_from_slice(&[0x5a, 0xf1, 0x00]);
    let caller = Address::repeat_byte(0xCA);

    let mut root = TrieNode::empty();
    let one_rbtc = U256::from(10u64).pow(U256::from(18));
    let acct = rustock_trie::AccountState::new(U256::ZERO, one_rbtc);
    root = root.put(&TrieKeySlice::from_key(&account_key(&sender)), &acct.encode(), &*trie_store);
    for (addr, code) in [(caller, &caller_code), (callee, &callee_code)] {
        let acct = rustock_trie::AccountState::new(U256::from(1), U256::ZERO);
        root = root.put(&TrieKeySlice::from_key(&account_key(&addr)), &acct.encode(), &*trie_store);
        root = root.put(&TrieKeySlice::from_key(&code_key(&addr)), code, &*trie_store);
    }
    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);
    rustock_trie::TrieStore::put(
        &*trie_store,
        state_root.as_slice(),
        &root.to_message(&*trie_store),
    );

    let parent = Header { state_root, ..test_header(41) };
    let parent_hash = parent.hash();
    store.put_header(&parent).unwrap();
    store.put_canonical_hash(41, parent_hash).unwrap();

    let mut tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::ZERO,
        gas_limit: U256::from(500_000),
        to: Bytes::copy_from_slice(caller.as_slice()),
        value: U256::ZERO,
        input: Bytes::default(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    };
    let chain_id = rustock_execution::RskHardforkConfig::mainnet().chain_id;
    let signing_hash = tx.signing_hash_eip155(chain_id);
    let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        key.sign_prehash(signing_hash.as_slice()).unwrap();
    let sig_bytes = sig.to_bytes();
    tx.r = U256::from_be_slice(&sig_bytes[..32]);
    tx.s = U256::from_be_slice(&sig_bytes[32..]);
    tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
    let tx_hash = tx.tx_hash();

    // `test_header`'s minimum gas price is non-zero, and a transaction below
    // it is not valid in the block -- the replay rejects it exactly as
    // consensus would. Zeroing the floor keeps the fixture about tracing.
    let header = Header { parent_hash, minimum_gas_price: U256::ZERO, ..test_header(42) };
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(42_000)).unwrap();
    store.put_body(block_hash, std::slice::from_ref(&tx), &[]).unwrap();
    store.put_tx_index(tx_hash, block_hash, 0).unwrap();
    store
        .put_receipts(
            block_hash,
            &[rustock_core::Receipt {
                post_tx_state: vec![0x01],
                cumulative_gas_used: 40_000,
                gas_used: 40_000,
                logs_bloom: Bloom::ZERO,
                logs: vec![],
                status: true,
            }],
        )
        .unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: Some(trie_store),
        hardfork_cfg: Some(rustock_execution::RskHardforkConfig::mainnet()),
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 1_000,
        scoring: None,
        events: None,
    };
    (state, tmp, tx_hash, sender, caller, callee)
}

/// `eth_getBlockBy*` with full transactions must name the real sender.
///
/// It used to hardcode `from` to the zero address, so every transaction in
/// every block reported the same impossible sender while
/// `eth_getTransactionByHash` reported the right one. Nothing errored: an
/// indexer reading blocks in bulk would simply attribute the whole chain to
/// 0x0. The fixture signs a real transaction, so the expected sender is a
/// known key rather than whatever the field happens to hold.
#[tokio::test]
async fn a_block_with_full_transactions_names_the_real_sender() {
    let (state, _tmp, tx_hash, sender, _caller, _callee) = setup_state_for_tracing();
    let expected = format!("{sender:#x}");

    for (method, arg) in [
        ("eth_getBlockByNumber", json!(["0x2a", true])),
        ("eth_getBlockByHash", json!([format!("{:#x}", state.store.canonical_hash(42).unwrap().unwrap()), true])),
    ] {
        let resp = dispatch_for_test(&state, make_request(method, arg)).await;
        let block = resp.result.expect("the block must be returned");
        let txs = block["transactions"].as_array().expect("full transaction objects");
        assert_eq!(txs.len(), 1, "{method}");
        assert_eq!(txs[0]["from"], expected, "{method} reported the wrong sender");
        assert_ne!(
            txs[0]["from"],
            json!("0x0000000000000000000000000000000000000000"),
            "{method} is back to the hardcoded zero sender"
        );
    }

    // The two endpoints must not disagree about the same transaction: that
    // disagreement is what made the original bug invisible.
    let by_hash = dispatch_for_test(
        &state,
        make_request("eth_getTransactionByHash", json!([format!("{tx_hash:#x}")])),
    )
    .await
    .result
    .unwrap();
    let by_block = dispatch_for_test(&state, make_request("eth_getBlockByNumber", json!(["0x2a", true])))
        .await
        .result
        .unwrap();
    assert_eq!(by_hash["from"], by_block["transactions"][0]["from"]);
}

/// Hash-only mode returns strings, and must keep doing so: the sender fix
/// touches the same branch.
#[tokio::test]
async fn a_block_without_full_transactions_still_returns_bare_hashes() {
    let (state, _tmp, tx_hash, _s, _c, _ce) = setup_state_for_tracing();
    let resp = dispatch_for_test(&state, make_request("eth_getBlockByNumber", json!(["0x2a", false]))).await;
    let txs = resp.result.unwrap()["transactions"].clone();
    assert_eq!(txs, json!([format!("{tx_hash:#x}")]));
}

/// `trace_transaction` returns the transaction's own trace followed by the
/// internal call, in rskj's flattened shape.
#[tokio::test]
async fn trace_transaction_renders_the_call_tree() {
    let (state, _tmp, tx_hash, sender, caller, callee) = setup_state_for_tracing();
    let resp = dispatch_for_test(
        &state,
        make_request("trace_transaction", json!([format!("{:#x}", tx_hash)])),
    )
    .await;
    assert!(resp.error.is_none(), "{:?}", resp.error);
    let traces = resp.result.unwrap();
    let traces = traces.as_array().expect("an array of traces");
    assert_eq!(traces.len(), 2, "the transaction plus its one internal call: {traces:#?}");

    let top = &traces[0];
    assert_eq!(top["type"], "call");
    assert_eq!(top["subtraces"], json!(1));
    // rskj's `traceAddress` for the top-level trace is the empty array.
    assert_eq!(top["traceAddress"], json!([]));
    assert_eq!(top["action"]["callType"], "call");
    assert_eq!(top["action"]["from"], format!("0x{}", hex::encode(sender.as_slice())));
    assert_eq!(top["action"]["to"], format!("0x{}", hex::encode(caller.as_slice())));
    // The receipt's gas, not the frame's: rskj builds the top-level result
    // from `txInfo.getReceipt().getGasUsed()`.
    assert_eq!(top["result"]["gasUsed"], "0x9c40");
    // A JSON number, because rskj's `blockNumber` is a Java `long`.
    assert_eq!(top["blockNumber"], json!(42));
    assert!(top["blockNumber"].is_number(), "blockNumber must not be a hex string");
    assert!(top.get("error").is_none(), "a successful trace carries no error key");

    let inner = &traces[1];
    assert_eq!(inner["type"], "call");
    assert_eq!(inner["traceAddress"], json!([0]));
    assert_eq!(inner["subtraces"], json!(0));
    assert_eq!(inner["action"]["from"], format!("0x{}", hex::encode(caller.as_slice())));
    assert_eq!(inner["action"]["to"], format!("0x{}", hex::encode(callee.as_slice())));
    assert_eq!(
        inner["result"]["output"].as_str().unwrap(),
        "0x000000000000000000000000000000000000000000000000000000000000002a"
    );
}

/// `trace_block` accepts a hash or a block id, and returns the same traces.
#[tokio::test]
async fn trace_block_accepts_a_number_or_a_hash() {
    let (state, _tmp, _tx, _sender, _caller, _callee) = setup_state_for_tracing();
    let by_number = dispatch_for_test(&state, make_request("trace_block", json!(["0x2a"]))).await;
    assert!(by_number.error.is_none(), "{:?}", by_number.error);
    let by_number = by_number.result.unwrap();

    let hash = state.store.canonical_hash(42).unwrap().unwrap();
    let by_hash =
        dispatch_for_test(&state, make_request("trace_block", json!([format!("{:#x}", hash)])))
            .await;
    assert!(by_hash.error.is_none(), "{:?}", by_hash.error);
    assert_eq!(by_number, by_hash.result.unwrap());
    assert_eq!(by_number.as_array().unwrap().len(), 2);
}

/// rskj's `trace_get` takes exactly one position and indexes the **block's**
/// flattened trace list, not a path down the transaction's call tree.
#[tokio::test]
async fn trace_get_takes_one_position_and_indexes_the_block() {
    let (state, _tmp, tx_hash, _sender, caller, callee) = setup_state_for_tracing();
    let tx = format!("{:#x}", tx_hash);

    let second =
        dispatch_for_test(&state, make_request("trace_get", json!([tx, ["0x1"]]))).await;
    let second = second.result.unwrap();
    assert_eq!(second["action"]["from"], format!("0x{}", hex::encode(caller.as_slice())));
    assert_eq!(second["action"]["to"], format!("0x{}", hex::encode(callee.as_slice())));

    // Past the end is null, not an error.
    let far = dispatch_for_test(&state, make_request("trace_get", json!([tx, ["0x9"]]))).await;
    assert_eq!(far.result.unwrap(), Value::Null);

    // rskj rejects a multi-element path by name rather than walking it.
    let two =
        dispatch_for_test(&state, make_request("trace_get", json!([tx, ["0x0", "0x0"]]))).await;
    assert!(two.error.unwrap().message.contains("only one index"));

    let none = dispatch_for_test(&state, make_request("trace_get", json!([tx, []]))).await;
    assert!(none.error.unwrap().message.contains("cannot be null or empty"));
}

/// `trace_filter` over the range, and its rskj-shaped guards.
#[tokio::test]
async fn trace_filter_returns_the_range_and_enforces_its_limits() {
    let (state, _tmp, _tx, sender, _caller, _callee) = setup_state_for_tracing();

    let all = dispatch_for_test(
        &state,
        make_request("trace_filter", json!([{"fromBlock": "0x2a", "toBlock": "0x2a"}])),
    )
    .await;
    assert!(all.error.is_none(), "{:?}", all.error);
    assert_eq!(all.result.unwrap().as_array().unwrap().len(), 2);

    // `after` skips, `count` limits -- and rskj applies both across the whole
    // range, so one block of two traces with `after: 1` leaves one.
    let windowed = dispatch_for_test(
        &state,
        make_request(
            "trace_filter",
            json!([{"fromBlock": "0x2a", "toBlock": "0x2a", "after": 1, "count": 1}]),
        ),
    )
    .await;
    assert_eq!(windowed.result.unwrap().as_array().unwrap().len(), 1);

    // The address filter selects whole transactions by their *own* sender, so
    // matching the sender yields the internal call as well.
    let by_sender = dispatch_for_test(
        &state,
        make_request(
            "trace_filter",
            json!([{
                "fromBlock": "0x2a", "toBlock": "0x2a",
                "fromAddress": [format!("0x{}", hex::encode(sender.as_slice()))]
            }]),
        ),
    )
    .await;
    assert_eq!(
        by_sender.result.unwrap().as_array().unwrap().len(),
        2,
        "rskj filters transactions, not traces, so the internal call comes along"
    );

    let other = dispatch_for_test(
        &state,
        make_request(
            "trace_filter",
            json!([{
                "fromBlock": "0x2a", "toBlock": "0x2a",
                "fromAddress": [format!("0x{}", hex::encode(Address::repeat_byte(0x99).as_slice()))]
            }]),
        ),
    )
    .await;
    assert!(other.result.unwrap().as_array().unwrap().is_empty());

    let backwards = dispatch_for_test(
        &state,
        make_request("trace_filter", json!([{"fromBlock": "0x2a", "toBlock": "0x1"}])),
    )
    .await;
    assert!(backwards.error.unwrap().message.contains("cannot be greater than"));

    let too_many = dispatch_for_test(
        &state,
        make_request("trace_filter", json!([{"count": 10_001}])),
    )
    .await;
    assert!(too_many.error.unwrap().message.contains("Count value too big"));
}

/// An unknown transaction is `null`, and the `trace_*` methods no longer
/// answer "execution engine not available".
#[tokio::test]
async fn trace_transaction_unknown_is_null() {
    let (state, _tmp) = setup_state();
    let resp = dispatch_for_test(
        &state,
        make_request("trace_transaction", json!([format!("{:#x}", B256::repeat_byte(0xcd))])),
    )
    .await;
    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert_eq!(resp.result.unwrap(), Value::Null);
}

// ========== sco_* namespace ==========

fn setup_state_with_scoring() -> (RpcState, tempfile::TempDir, tempfile::TempDir) {
    let (mut state, tmp) = setup_state();
    let scoring_dir = tempfile::tempdir().unwrap();
    state.scoring = Some(Arc::new(
        rustock_networking::scoring::ScoringService::open(
            scoring_dir.path(),
            &[],
            rustock_networking::scoring::DEFAULT_NODE_CAPACITY,
            true,
        ),
    ));
    (state, tmp, scoring_dir)
}

/// Banning, listing and unbanning, including a CIDR block.
#[tokio::test]
async fn sco_ban_and_unban_an_address_or_a_block() {
    let (state, _tmp, _dir) = setup_state_with_scoring();

    let ok = dispatch_for_test(&state, make_request("sco_banAddress", json!(["203.0.113.7"]))).await;
    assert!(ok.error.is_none(), "{:?}", ok.error);

    let ok = dispatch_for_test(
        &state,
        make_request("sco_banAddress", json!(["198.51.100.0/24"])),
    )
    .await;
    assert!(ok.error.is_none(), "{:?}", ok.error);

    let list = dispatch_for_test(&state, make_request("sco_bannedAddresses", json!([]))).await;
    let list = list.result.unwrap();
    let entries: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(entries.contains(&"203.0.113.7".to_string()), "{entries:?}");
    assert!(entries.contains(&"198.51.100.0/24".to_string()), "{entries:?}");

    // The block really covers its range.
    let inside =
        dispatch_for_test(&state, make_request("sco_isWelcome", json!(["198.51.100.99"]))).await;
    let inside = inside.result.unwrap();
    assert_eq!(inside["banned"], json!(true));
    assert_eq!(inside["welcome"], json!(false));

    let outside =
        dispatch_for_test(&state, make_request("sco_isWelcome", json!(["198.51.101.99"]))).await;
    assert_eq!(outside.result.unwrap()["banned"], json!(false));

    let ok = dispatch_for_test(
        &state,
        make_request("sco_unbanAddress", json!(["198.51.100.0/24"])),
    )
    .await;
    assert!(ok.error.is_none());
    let after =
        dispatch_for_test(&state, make_request("sco_isWelcome", json!(["198.51.100.99"]))).await;
    assert_eq!(after.result.unwrap()["banned"], json!(false));
}

/// rskj refuses to ban a loopback address, and so does this.
#[tokio::test]
async fn sco_ban_refuses_a_local_address() {
    let (state, _tmp, _dir) = setup_state_with_scoring();
    let resp =
        dispatch_for_test(&state, make_request("sco_banAddress", json!(["127.0.0.1"]))).await;
    let err = resp.error.expect("banning loopback must fail");
    assert!(err.message.contains("local address"), "{}", err.message);

    let resp =
        dispatch_for_test(&state, make_request("sco_banAddress", json!(["10.0.0.1/99"]))).await;
    assert!(resp.error.unwrap().message.contains("Invalid mask"));
}

/// The peer list and the summary reflect recorded events, and clearing a peer
/// empties them.
#[tokio::test]
async fn sco_peer_list_and_summary_report_what_was_recorded() {
    let (state, _tmp, _dir) = setup_state_with_scoring();
    let scoring = state.scoring.clone().unwrap();
    let address: std::net::IpAddr = "203.0.113.50".parse().unwrap();

    scoring.record(
        None,
        Some(address),
        rustock_networking::scoring::EventType::InvalidBlock,
    );
    scoring.record(
        None,
        Some(address),
        rustock_networking::scoring::EventType::FailedHandshake,
    );

    let list = dispatch_for_test(&state, make_request("sco_peerList", json!([]))).await;
    let list = list.result.unwrap();
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 1, "{entries:#?}");
    let entry = &entries[0];
    assert_eq!(entry["id"], "203.0.113.50");
    assert_eq!(entry["type"], "address");
    assert_eq!(entry["invalidBlocks"], json!(1));
    assert_eq!(entry["failedHandshakes"], json!(1));
    // An invalid block costs reputation; a failed handshake does not move the
    // score at all, which is rskj's rule.
    assert_eq!(entry["score"], json!(-1));
    assert_eq!(entry["goodReputation"], json!(false));
    assert_eq!(entry["punishments"], json!(1));
    assert!(entry["punishedUntil"].as_u64().unwrap() > 0);
    assert!(entry["score"].is_number(), "counters are JSON numbers, not hex");

    let summary = dispatch_for_test(&state, make_request("sco_reputationSummary", json!([]))).await;
    let summary = summary.result.unwrap();
    assert_eq!(summary["invalidBlocks"], json!(1));
    assert_eq!(summary["failedHandshakes"], json!(1));
    assert_eq!(summary["badReputationCount"], json!(1));
    assert_eq!(summary["goodReputationCount"], json!(0));
    assert_eq!(summary["peersTotalCount"], json!(1));

    let cleared = dispatch_for_test(
        &state,
        make_request("sco_clearPeerScoring", json!(["203.0.113.50"])),
    )
    .await;
    assert!(cleared.result.unwrap().as_array().unwrap().is_empty(), "the entry is gone");
}

/// `sco_clearPeerScoring` takes a node id when the argument is not an address.
#[tokio::test]
async fn sco_clear_peer_scoring_accepts_a_node_id() {
    let (state, _tmp, _dir) = setup_state_with_scoring();
    let scoring = state.scoring.clone().unwrap();
    let id = alloy_primitives::B512::repeat_byte(0xAB);
    scoring.record(
        Some(id),
        None,
        rustock_networking::scoring::EventType::InvalidHeader,
    );
    assert_eq!(
        dispatch_for_test(&state, make_request("sco_peerList", json!([])))
            .await
            .result
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let hex_id = format!("0x{}", hex::encode(id.as_slice()));
    let cleared =
        dispatch_for_test(&state, make_request("sco_clearPeerScoring", json!([hex_id]))).await;
    assert!(cleared.result.unwrap().as_array().unwrap().is_empty());

    // Neither an address nor a node id is a parameter error, not a silent
    // no-op.
    let bad =
        dispatch_for_test(&state, make_request("sco_clearPeerScoring", json!(["nonsense"]))).await;
    assert!(bad.error.is_some());
}

/// Without scoring the namespace says so, rather than answering from an empty
/// table as if every peer were spotless.
#[tokio::test]
async fn sco_reports_itself_unavailable_when_scoring_is_off() {
    let (state, _tmp) = setup_state();
    for method in [
        "sco_bannedAddresses",
        "sco_peerList",
        "sco_reputationSummary",
    ] {
        let resp = dispatch_for_test(&state, make_request(method, json!([]))).await;
        let err = resp.error.unwrap_or_else(|| panic!("{method} should report unavailable"));
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert!(err.message.contains("not enabled"), "{}", err.message);
    }
}

// ========== eth_getLogs bloom skipping (#122) ==========

/// A chain where each block's logs are different, so a query naming one
/// block's address or topic can only match that block.
///
/// Every header carries the OR of its receipts' blooms, as a real one does.
fn setup_state_with_varied_logs() -> (RpcState, tempfile::TempDir, Vec<Address>, Vec<B256>) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let mut addresses = Vec::new();
    let mut topics = Vec::new();

    for block_num in 1u64..=8 {
        let address = Address::repeat_byte(block_num as u8);
        let topic_a = B256::repeat_byte(0x10 + block_num as u8);
        let topic_b = B256::repeat_byte(0x80 + block_num as u8);
        addresses.push(address);
        topics.push(topic_a);

        let logs = vec![rustock_core::Log {
            address,
            topics: vec![topic_a, topic_b],
            data: vec![block_num as u8].into(),
        }];
        let mut logs_bloom = alloy_primitives::Bloom::ZERO;
        for log in &logs {
            rustock_core::bloom::accrue_log(&mut logs_bloom, log);
        }

        let header = Header { logs_bloom, ..test_header(block_num) };
        let hash = header.hash();
        store.put_header(&header).unwrap();
        store.put_canonical_hash(block_num, hash).unwrap();
        store.put_total_difficulty(hash, U256::from(block_num * 1000)).unwrap();
        store.put_body(hash, &[], &[]).unwrap();
        store
            .put_receipts(
                hash,
                &[rustock_core::Receipt {
                    post_tx_state: vec![0x01],
                    cumulative_gas_used: 21_000,
                    gas_used: 21_000,
                    logs_bloom,
                    logs,
                    status: true,
                }],
            )
            .unwrap();
        if block_num == 8 {
            store.set_head(hash).unwrap();
        }
    }

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
        wire_queue_depth: None,
        gas_price: None,
        epoch_store: None,
        miner: None,
        auto_miner: None,
        wallet: None,
        admin_enabled: false,
        gc_burial: 4000,
        gc_pins: None,
        snapshots: None,
        gas_estimator_binary_search: false,
        logs_max_blocks: crate::logs::DEFAULT_MAX_BLOCK_RANGE,
        prune_keep_depth: 100_000,
        prune_max_batch: 50_000,
        scoring: None,
        events: None,
    };
    (state, tmp, addresses, topics)
}

/// **The property the optimisation rests on: the answer never changes.**
///
/// A bloom filter has no false negatives, so skipping a block whose bloom
/// cannot match must be invisible. This runs a spread of filter shapes —
/// address-only, topic-only, both, alternatives, unmatchable, unconstrained —
/// and checks each against a brute-force scan of every log in range.
///
/// A one-bit disagreement between the bloom's build and its test would show
/// up here as silently missing logs, which is the worst failure this RPC can
/// have: the answer still looks like a valid answer.
#[tokio::test]
async fn bloom_skipping_never_changes_the_answer() {
    let (state, _tmp, addresses, topics) = setup_state_with_varied_logs();

    let hex_addr = |a: &Address| format!("0x{}", hex::encode(a.as_slice()));
    let hex_topic = |t: &B256| format!("{:#x}", t);

    let cases: Vec<(&str, Value)> = vec![
        ("unconstrained", json!({"fromBlock": "0x1", "toBlock": "0x8"})),
        (
            "one address",
            json!({"fromBlock": "0x1", "toBlock": "0x8", "address": hex_addr(&addresses[2])}),
        ),
        (
            "two addresses",
            json!({"fromBlock": "0x1", "toBlock": "0x8",
                   "address": [hex_addr(&addresses[0]), hex_addr(&addresses[5])]}),
        ),
        (
            "one topic",
            json!({"fromBlock": "0x1", "toBlock": "0x8", "topics": [hex_topic(&topics[4])]}),
        ),
        (
            "topic alternatives",
            json!({"fromBlock": "0x1", "toBlock": "0x8",
                   "topics": [[hex_topic(&topics[1]), hex_topic(&topics[6])]]}),
        ),
        (
            "address and topic that agree",
            json!({"fromBlock": "0x1", "toBlock": "0x8",
                   "address": hex_addr(&addresses[3]), "topics": [hex_topic(&topics[3])]}),
        ),
        (
            "address and topic that disagree",
            json!({"fromBlock": "0x1", "toBlock": "0x8",
                   "address": hex_addr(&addresses[3]), "topics": [hex_topic(&topics[4])]}),
        ),
        (
            "null first topic, real second",
            json!({"fromBlock": "0x1", "toBlock": "0x8",
                   "topics": [Value::Null, format!("{:#x}", B256::repeat_byte(0x82))]}),
        ),
        (
            "matches nothing",
            json!({"fromBlock": "0x1", "toBlock": "0x8",
                   "address": hex_addr(&Address::repeat_byte(0xEE))}),
        ),
    ];

    for (name, filter) in cases {
        let resp = dispatch_for_test(&state, make_request("eth_getLogs", json!([filter.clone()])))
            .await;
        assert!(resp.error.is_none(), "{name}: {:?}", resp.error);
        let got = resp.result.unwrap();
        let got = got.as_array().unwrap();

        let expected = brute_force_logs(&state, 1, 8, &filter);
        assert_eq!(
            got.len(),
            expected.len(),
            "{name}: bloom skipping changed the result ({} vs {} brute force)",
            got.len(),
            expected.len()
        );
        for (a, b) in got.iter().zip(expected.iter()) {
            assert_eq!(a["blockNumber"], b.0, "{name}: wrong block");
            assert_eq!(a["address"], b.1, "{name}: wrong address");
        }
    }
}

/// Every log in range that the filter matches, found without consulting any
/// bloom. Returns `(blockNumber, address)` pairs in order.
fn brute_force_logs(state: &RpcState, from: u64, to: u64, filter: &Value) -> Vec<(Value, Value)> {
    let want_addrs: Vec<Address> = match filter.get("address") {
        Some(Value::String(s)) => vec![s.parse().unwrap()],
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect(),
        _ => Vec::new(),
    };
    let want_topics: Vec<Option<Vec<B256>>> = match filter.get("topics") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| match v {
                Value::String(s) => Some(vec![s.parse().unwrap()]),
                Value::Array(alts) => {
                    Some(alts.iter().map(|x| x.as_str().unwrap().parse().unwrap()).collect())
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let mut out = Vec::new();
    for number in from..=to {
        let Some(hash) = state.store.canonical_hash(number).unwrap() else { continue };
        let Some(receipts) = state.store.receipts(hash).unwrap() else { continue };
        for receipt in &receipts {
            for log in &receipt.logs {
                if !want_addrs.is_empty() && !want_addrs.contains(&log.address) {
                    continue;
                }
                let mut ok = true;
                for (i, allowed) in want_topics.iter().enumerate() {
                    let Some(allowed) = allowed else { continue };
                    match log.topics.get(i) {
                        Some(t) if allowed.contains(t) => {}
                        None if allowed.is_empty() => {}
                        _ => ok = false,
                    }
                }
                if ok {
                    out.push((
                        json!(format!("{:#x}", number)),
                        json!(format!("0x{}", hex::encode(log.address.as_slice()))),
                    ));
                }
            }
        }
    }
    out
}

/// The gate must not fire when the query constrains nothing, because it could
/// never skip and would be a header read per block for no reason.
#[tokio::test]
async fn an_unconstrained_query_returns_every_log() {
    let (state, _tmp, _addrs, _topics) = setup_state_with_varied_logs();
    let resp = dispatch_for_test(
        &state,
        make_request("eth_getLogs", json!([{"fromBlock": "0x1", "toBlock": "0x8"}])),
    )
    .await;
    assert_eq!(resp.result.unwrap().as_array().unwrap().len(), 8);
}

/// An empty alternatives list at a topic position means "the log must have no
/// topic here" — there is nothing to look up, so the bloom must not be
/// allowed to reject the block on its behalf.
#[tokio::test]
async fn an_empty_topic_alternative_list_does_not_skip_blocks() {
    let (state, _tmp, addresses, _topics) = setup_state_with_varied_logs();
    // Position 0 is unconstrained; position 2 must be absent, which every log
    // here satisfies (each has exactly two topics).
    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_getLogs",
            json!([{
                "fromBlock": "0x1", "toBlock": "0x8",
                "address": format!("0x{}", hex::encode(addresses[1].as_slice())),
                "topics": [Value::Null, Value::Null, []]
            }]),
        ),
    )
    .await;
    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert_eq!(
        resp.result.unwrap().as_array().unwrap().len(),
        1,
        "the empty list must not let the bloom skip the matching block"
    );
}
// ========== eth_subscribe over WebSocket (#121) ==========

use crate::subscribe::{notifications_for, parse_subscription, LogsParams, Subscription};
use rustock_core::events::{BlockEvent, ChainEvent};

fn block_event(number: u64, logs: Vec<rustock_core::Log>, removed: bool) -> ChainEvent {
    let header = test_header(number);
    ChainEvent::Block(Arc::new(BlockEvent {
        hash: header.hash(),
        header,
        transactions: Vec::new(),
        receipts: vec![rustock_core::Receipt {
            post_tx_state: vec![0x01],
            cumulative_gas_used: 21_000,
            gas_used: 21_000,
            logs_bloom: Bloom::ZERO,
            logs,
            status: true,
        }],
        removed,
    }))
}

fn sample_log(address: Address, topic: B256) -> rustock_core::Log {
    rustock_core::Log { address, topics: vec![topic], data: Bytes::default() }
}

#[test]
fn subscription_types_parse_as_rskj_names_them() {
    assert!(matches!(
        parse_subscription(&json!(["newHeads"])).unwrap(),
        Subscription::NewHeads
    ));
    assert!(matches!(
        parse_subscription(&json!(["newPendingTransactions"])).unwrap(),
        Subscription::NewPendingTransactions
    ));
    assert!(matches!(parse_subscription(&json!(["syncing"])).unwrap(), Subscription::Syncing));

    let addr = Address::repeat_byte(0x11);
    let topic = B256::repeat_byte(0xAA);
    let sub = parse_subscription(&json!([
        "logs",
        {"address": format!("0x{}", hex::encode(addr.as_slice())),
         "topics": [format!("{:#x}", topic)]}
    ]))
    .unwrap();
    let Subscription::Logs(params) = sub else { panic!("expected a logs subscription") };
    assert_eq!(params.addresses, vec![addr]);
    assert!(params.matches(&sample_log(addr, topic)));
    assert!(!params.matches(&sample_log(Address::repeat_byte(0x22), topic)));

    assert!(parse_subscription(&json!(["nonsense"])).is_err());
    assert!(parse_subscription(&json!([])).is_err());
}

/// **A `newHeads` subscriber must not be told about a block that left the
/// chain.** The head notification has no `removed` field to carry the
/// retraction in, so emitting one would say the opposite of the truth.
#[test]
fn new_heads_ignores_removed_blocks() {
    let joined = notifications_for(&Subscription::NewHeads, "0x1", &block_event(7, vec![], false));
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0]["method"], "eth_subscription");
    assert_eq!(joined[0]["params"]["subscription"], "0x1");
    assert_eq!(joined[0]["params"]["result"]["number"], "0x7");

    let left = notifications_for(&Subscription::NewHeads, "0x1", &block_event(7, vec![], true));
    assert!(left.is_empty(), "a retracted block is not a new head");
}

/// The retraction a log subscriber depends on. This node sees a tip fork
/// several times an hour, so a subscriber that never heard `removed: true`
/// would accumulate logs from blocks that are no longer on the chain.
#[test]
fn a_removed_block_retracts_its_logs() {
    let addr = Address::repeat_byte(0x11);
    let topic = B256::repeat_byte(0xAA);
    let subscription = Subscription::Logs(LogsParams {
        addresses: vec![addr],
        topics: Vec::new(),
    });

    let joined = notifications_for(
        &subscription,
        "0x2",
        &block_event(9, vec![sample_log(addr, topic)], false),
    );
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0]["params"]["result"]["removed"], json!(false));

    let left = notifications_for(
        &subscription,
        "0x2",
        &block_event(9, vec![sample_log(addr, topic)], true),
    );
    assert_eq!(left.len(), 1, "the same log must come back as removed");
    assert_eq!(left[0]["params"]["result"]["removed"], json!(true));
    assert_eq!(left[0]["params"]["result"]["blockNumber"], "0x9");
}

/// A subscription hears only about what it asked for.
#[test]
fn a_subscription_ignores_events_it_did_not_ask_for() {
    let addr = Address::repeat_byte(0x11);
    let event = block_event(3, vec![sample_log(addr, B256::repeat_byte(0xAA))], false);

    assert!(notifications_for(&Subscription::NewPendingTransactions, "0x1", &event).is_empty());

    let tx_event = ChainEvent::PendingTransaction(B256::repeat_byte(0xEE));
    assert!(notifications_for(&Subscription::NewHeads, "0x1", &tx_event).is_empty());
    let pending = notifications_for(&Subscription::NewPendingTransactions, "0x1", &tx_event);
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0]["params"]["result"],
        json!(format!("{:#x}", B256::repeat_byte(0xEE)))
    );

    // A logs subscription whose address matches nothing in the block stays
    // quiet, rather than emitting an empty notification.
    let unrelated = Subscription::Logs(LogsParams {
        addresses: vec![Address::repeat_byte(0x99)],
        topics: Vec::new(),
    });
    assert!(notifications_for(&unrelated, "0x1", &event).is_empty());
}

// --- over a real socket ---

async fn start_test_ws(state: RpcState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route("/", axum::routing::any(crate::ws::upgrade_for_test))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("ws://{addr}/")
}

/// The transport itself: upgrade, subscribe, receive a pushed notification,
/// unsubscribe, and stop receiving.
///
/// Worth doing over a real socket rather than by calling the handler: the
/// upgrade, the framing and the `select!` between "client said something" and
/// "the chain moved" are the actual design, and none of them is exercised by
/// a direct call.
#[tokio::test]
async fn a_websocket_client_subscribes_and_is_pushed_to() {
    use futures_util::{SinkExt, StreamExt};

    let (mut state, _tmp) = setup_state();
    let events = rustock_core::events::channel();
    state.events = Some(events.clone());
    let url = start_test_ws(state).await;

    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    // An ordinary request works on the socket too.
    socket
        .send(tokio_tungstenite::tungstenite::Message::text(
            json!({"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}).to_string(),
        ))
        .await
        .unwrap();
    let reply = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert!(reply["result"].is_string(), "{reply}");

    // Subscribe.
    socket
        .send(tokio_tungstenite::tungstenite::Message::text(
            json!({"jsonrpc":"2.0","id":2,"method":"eth_subscribe","params":["newHeads"]})
                .to_string(),
        ))
        .await
        .unwrap();
    let reply = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    let sub_id = reply["result"].as_str().expect("a subscription id").to_string();

    // Wait until the connection has actually registered as a receiver, or the
    // publish below races the subscribe and is dropped with no receivers.
    for _ in 0..100 {
        if events.receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    events.send(block_event(42, vec![], false)).unwrap();
    let pushed = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let pushed: Value = serde_json::from_str(&pushed).unwrap();
    assert_eq!(pushed["method"], "eth_subscription");
    assert_eq!(pushed["params"]["subscription"], sub_id.as_str());
    assert_eq!(pushed["params"]["result"]["number"], "0x2a");

    // Unsubscribe, then prove nothing more arrives.
    socket
        .send(tokio_tungstenite::tungstenite::Message::text(
            json!({"jsonrpc":"2.0","id":3,"method":"eth_unsubscribe","params":[sub_id]})
                .to_string(),
        ))
        .await
        .unwrap();
    let reply = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["result"], json!(true), "unsubscribe should report success");

    events.send(block_event(43, vec![], false)).unwrap();
    let quiet = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        socket.next(),
    )
    .await;
    assert!(quiet.is_err(), "nothing should arrive after unsubscribing");
}

/// `eth_subscribe` on a node with no event source is accepted and simply
/// never fires, rather than failing — which is what lets the transport be
/// useful on a node built without one.
#[tokio::test]
async fn subscribing_without_an_event_source_is_accepted() {
    use futures_util::{SinkExt, StreamExt};

    let (state, _tmp) = setup_state();
    assert!(state.events.is_none());
    let url = start_test_ws(state).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    socket
        .send(tokio_tungstenite::tungstenite::Message::text(
            json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]})
                .to_string(),
        ))
        .await
        .unwrap();
    let reply = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert!(reply["result"].is_string(), "{reply}");
    assert!(reply.get("error").is_none());
}

/// An unknown subscription type is a parameter error, not a silent no-op that
/// leaves the client waiting forever for notifications that never come.
#[tokio::test]
async fn an_unknown_subscription_type_is_rejected() {
    use futures_util::{SinkExt, StreamExt};

    let (state, _tmp) = setup_state();
    let url = start_test_ws(state).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    socket
        .send(tokio_tungstenite::tungstenite::Message::text(
            json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newBlocks"]})
                .to_string(),
        ))
        .await
        .unwrap();
    let reply = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["error"]["code"], json!(INVALID_PARAMS));
}

// ── rskj parity: eth_getBlocksByNumber, eth_netHashrate, rsk_*, evm_* ──────

/// A chain of `n` linked headers, plus one sibling at `fork_at` that is stored
/// but not canonical.
fn chain_with_sibling(n: u64, fork_at: u64) -> (Arc<BlockStore>, tempfile::TempDir, B256) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let mut parent = B256::ZERO;
    for number in 0..=n {
        let header = Header { parent_hash: parent, ..test_header(number) };
        let hash = header.hash();
        store.put_header(&header).unwrap();
        store.put_canonical_hash(number, hash).unwrap();
        store.put_total_difficulty(hash, U256::from((number + 1) * 1000)).unwrap();
        store.put_body(hash, &[], &[]).unwrap();
        store.set_head(hash).unwrap();
        parent = hash;
    }

    // A sibling at `fork_at`: same height, different content, never canonical.
    let canonical_parent = store.canonical_hash(fork_at - 1).unwrap().unwrap();
    let sibling = Header {
        parent_hash: canonical_parent,
        timestamp: test_header(fork_at).timestamp + 7,
        ..test_header(fork_at)
    };
    let sibling_hash = sibling.hash();
    store.put_header(&sibling).unwrap();
    store.put_total_difficulty(sibling_hash, U256::from(999u64)).unwrap();

    (store, tmp, sibling_hash)
}

/// **Siblings are the point.** A client that missed a reorg cannot reconstruct
/// the block that lost from canonical data, because canonical data is exactly
/// what no longer mentions it.
#[tokio::test]
async fn get_blocks_by_number_returns_siblings_flagged() {
    let (store, _tmp, sibling) = chain_with_sibling(5, 3);
    let (mut state, _t) = setup_state();
    state.store = store.clone();

    let resp = dispatch_for_test(&state, make_request("eth_getBlocksByNumber", json!(["0x3"]))).await;
    let blocks = resp.result.unwrap();
    let blocks = blocks.as_array().unwrap();
    assert_eq!(blocks.len(), 2, "canonical block and its sibling");

    let canonical = store.canonical_hash(3).unwrap().unwrap();
    let on_chain: Vec<_> = blocks.iter().filter(|b| b["inMainChain"] == json!(true)).collect();
    let off_chain: Vec<_> = blocks.iter().filter(|b| b["inMainChain"] == json!(false)).collect();
    assert_eq!(on_chain.len(), 1, "exactly one block is canonical at a height");
    assert_eq!(on_chain[0]["hash"], json!(crate::helpers::to_hex_b256(&canonical)));
    assert_eq!(off_chain[0]["hash"], json!(crate::helpers::to_hex_b256(&sibling)));

    // Total difficulty is per block: comparing the two is why a caller asks.
    assert_ne!(on_chain[0]["totalDifficulty"], off_chain[0]["totalDifficulty"]);
}

/// rskj parses this parameter with `stringNumberAsBigInt`, which takes a
/// decimal height as well as hex — unlike every other block-taking method.
/// Reproduced rather than tidied, because a client written against rskj may
/// send either.
#[tokio::test]
async fn get_blocks_by_number_accepts_decimal_as_rskj_does() {
    let (store, _tmp, _) = chain_with_sibling(5, 3);
    let (mut state, _t) = setup_state();
    state.store = store;

    let hex = dispatch_for_test(&state, make_request("eth_getBlocksByNumber", json!(["0x3"]))).await;
    let dec = dispatch_for_test(&state, make_request("eth_getBlocksByNumber", json!(["3"]))).await;
    assert_eq!(hex.result, dec.result, "0x3 and 3 name the same height");

    let bad = dispatch_for_test(&state, make_request("eth_getBlocksByNumber", json!(["latest"]))).await;
    assert!(bad.error.is_some(), "this method takes no tags, unlike its neighbours");
}

/// **Uncle difficulty counts.** rskj sums `Block.getCumulativeDifficulty()`,
/// which despite its name is the block's own difficulty plus its uncles' — and
/// an uncle is real work that secured the chain.
#[tokio::test]
async fn net_hashrate_counts_uncle_difficulty_and_answers_with_a_number() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Two blocks inside the window; the second carries an uncle.
    let mut parent = B256::ZERO;
    for number in 0..2u64 {
        let header = Header {
            parent_hash: parent,
            timestamp: now - 60 + number,
            difficulty: U256::from(1_000_000u64),
            ..test_header(number)
        };
        let uncles: Vec<Header> = if number == 1 {
            vec![Header { difficulty: U256::from(500_000u64), ..test_header(0) }]
        } else {
            vec![]
        };
        let header = Header {
            ommers_hash: rustock_execution::processor::compute_ommers_hash(&uncles),
            ..header
        };
        store.put_header(&header).unwrap();
        store.put_canonical_hash(number, header.hash()).unwrap();
        store.put_total_difficulty(header.hash(), U256::from(1u64)).unwrap();
        store.put_body(header.hash(), &[], &uncles).unwrap();
        store.set_head(header.hash()).unwrap();
        parent = header.hash();
    }

    let (mut state, _t) = setup_state();
    state.store = store;
    let resp = dispatch_for_test(&state, make_request("eth_netHashrate", json!([]))).await;
    let value = resp.result.unwrap();

    // rskj declares this BigInteger, so the wire form is a JSON number, not
    // the `0x` quantity string every neighbouring method returns.
    assert!(value.is_number(), "rskj answers with a number here, got {value}");

    // (1,000,000 + 1,000,000 + 500,000 uncle) / 3600
    assert_eq!(value.as_u64().unwrap(), 2_500_000 / 3600);
}

/// **Mainnet overflows `u64`, and the first version of this clamped.**
///
/// At the difficulty observed on 2026-09-27 the network figure is ~2.4e20 —
/// thirteen times `u64::MAX` — so a clamped implementation returned the same
/// wrong constant on every call. It must also not render as `2.443e+20`,
/// which a strict integer parser rejects where rskj's plain digits are taken.
#[tokio::test]
async fn net_hashrate_survives_mainnet_magnitude_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Real mainnet difficulty (block #9,276,959). One block over an hour is
    // only ~2e18 per second, which is *under* u64::MAX -- the overflow comes
    // from the ~120 blocks an hour actually holds, so the fixture needs a run
    // of them. Twenty is enough to clear the ceiling with margin.
    let difficulty = U256::from_str_radix("7328367705921302411990", 10).unwrap();
    const BLOCKS: u64 = 20;
    let mut parent = B256::ZERO;
    for number in 0..BLOCKS {
        let header = Header {
            parent_hash: parent,
            timestamp: now - 600 + number,
            difficulty,
            ..test_header(number)
        };
        store.put_header(&header).unwrap();
        store.put_canonical_hash(number, header.hash()).unwrap();
        store.put_total_difficulty(header.hash(), U256::from(1u64)).unwrap();
        store.put_body(header.hash(), &[], &[]).unwrap();
        store.set_head(header.hash()).unwrap();
        parent = header.hash();
    }

    let (mut state, _t) = setup_state();
    state.store = store;
    let resp = dispatch_for_test(&state, make_request("eth_netHashrate", json!([]))).await;
    let value = resp.result.unwrap();

    assert!(value.is_number(), "rskj answers with a number here");
    let rendered = value.to_string();
    assert_eq!(
        rendered,
        (difficulty * U256::from(BLOCKS) / U256::from(3600u64)).to_string(),
        "the exact quotient, not a clamp and not a float"
    );
    assert!(
        !rendered.contains('e') && !rendered.contains('E'),
        "must be plain digits, not exponent notation: {rendered}"
    );
    assert!(
        rendered.parse::<u128>().unwrap() > u64::MAX as u128,
        "the fixture must actually exceed u64, or this proves nothing"
    );
}

/// **A non-mining node answering zero is rskj's answer, not a placeholder.**
/// `HashRateCalculatorNonMining.calculateNodeHashRate` returns
/// `BigInteger.ZERO`, so this is correct rather than unimplemented. See #176.
#[tokio::test]
async fn hashrate_is_zero_without_a_miner_and_counts_only_our_blocks_with_one() {
    use alloy_primitives::Address;

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ours = Address::repeat_byte(0xAA);
    let theirs = Address::repeat_byte(0xBB);

    // Two blocks in the window: one mined by us, one by somebody else.
    let mut parent = B256::ZERO;
    for (number, miner) in [(0u64, theirs), (1u64, ours)] {
        let header = Header {
            parent_hash: parent,
            timestamp: now - 60 + number,
            difficulty: U256::from(3_600_000u64),
            beneficiary: miner,
            ..test_header(number)
        };
        store.put_header(&header).unwrap();
        store.put_canonical_hash(number, header.hash()).unwrap();
        store.put_total_difficulty(header.hash(), U256::from(1u64)).unwrap();
        store.put_body(header.hash(), &[], &[]).unwrap();
        store.set_head(header.hash()).unwrap();
        parent = header.hash();
    }

    let (mut state, _t) = setup_state();
    state.store = store;

    // No miner configured: zero, and as a hex string rather than the number
    // eth_netHashrate answers with -- the two disagree upstream and here.
    let resp = dispatch_for_test(&state, make_request("eth_hashrate", json!([]))).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));

    // The network figure counts both blocks whatever the miner.
    let net = dispatch_for_test(&state, make_request("eth_netHashrate", json!([]))).await;
    assert_eq!(
        net.result.unwrap().as_u64().unwrap(),
        7_200_000 / 3600,
        "the network figure counts every block in the window"
    );

    // With our coinbase, only the block we mined counts.
    let mine = crate::eth::eth_hashrate_for(json!(1), &state.store, Some(ours));
    assert_eq!(
        mine.result.unwrap(),
        json!(format!("0x{:x}", 3_600_000u64 / 3600)),
        "only blocks paying our coinbase are ours"
    );

    // A coinbase that mined nothing in the window earns nothing.
    let none = crate::eth::eth_hashrate_for(json!(1), &state.store, Some(Address::repeat_byte(0xCC)));
    assert_eq!(none.result.unwrap(), json!("0x0"));
}

/// Administrative methods are reported as unknown rather than forbidden, so a
/// node without them looks the same as one that never had them.
#[tokio::test]
async fn flush_and_shutdown_are_invisible_without_rpc_admin() {
    let (state, _tmp) = setup_state();
    assert!(!state.admin_enabled);
    for method in ["rsk_flush", "rsk_shutdown"] {
        let resp = dispatch_for_test(&state, make_request(method, json!([]))).await;
        let err = resp.error.expect("must not be served");
        assert_eq!(err.message, "Method not found", "{method} leaked its existence");
    }
}

/// The whole `evm_` namespace stays invisible unless the node was started for
/// a development chain. A node that can be told to discard its own history has
/// no business advertising that on a network.
#[tokio::test]
async fn the_evm_namespace_is_off_by_default() {
    let (state, _tmp) = setup_state();
    assert!(state.snapshots.is_none());
    for method in [
        "evm_snapshot", "evm_revert", "evm_reset", "evm_mine",
        "evm_increaseTime", "evm_startMining", "evm_stopMining",
    ] {
        let resp = dispatch_for_test(&state, make_request(method, json!(["0x1"]))).await;
        assert!(resp.error.is_some(), "{method} answered with the namespace off");
    }
}

/// **A snapshot is a height, and reverting is a head move.** rskj's
/// `SnapshotManager` records `getBestBlock().getNumber()` and nothing else,
/// so taking one is free and reverting discards the heights above it.
#[tokio::test]
async fn evm_snapshot_and_revert_move_the_head_back() {
    let (store, _tmp, _) = chain_with_sibling(5, 3);
    let (mut state, _t) = setup_state();
    state.store = store.clone();
    state.snapshots = Some(Arc::new(crate::evm::SnapshotManager::new()));

    // Snapshot while the head is at #3.
    store.set_head(store.canonical_hash(3).unwrap().unwrap()).unwrap();
    let snap = dispatch_for_test(&state, make_request("evm_snapshot", json!([]))).await;
    assert_eq!(snap.result.unwrap(), json!("0x1"), "ids are 1-based");

    // The chain moves on to #5, then the test reverts.
    store.set_head(store.canonical_hash(5).unwrap().unwrap()).unwrap();
    let reverted = dispatch_for_test(&state, make_request("evm_revert", json!(["0x1"]))).await;
    assert_eq!(reverted.result.unwrap(), json!(true));

    let head = store.head().unwrap().unwrap();
    assert_eq!(
        store.header(head).unwrap().unwrap().number,
        3,
        "the head must be back at the snapshotted height"
    );
    assert!(
        store.canonical_hash(4).unwrap().is_none() && store.canonical_hash(5).unwrap().is_none(),
        "heights above the snapshot must no longer resolve"
    );

    // Reverting again to an id the truncation removed is false, not an error.
    let missing = dispatch_for_test(&state, make_request("evm_revert", json!(["0x9"]))).await;
    assert_eq!(missing.result.unwrap(), json!(false));
}

/// `evm_reset` returns to genesis and discards every snapshot and the clock
/// offset, so one test cannot leak into the next.
#[tokio::test]
async fn evm_reset_returns_to_genesis_and_clears_the_clock() {
    let (store, _tmp, _) = chain_with_sibling(5, 3);
    let (mut state, _t) = setup_state();
    state.store = store.clone();
    state.snapshots = Some(Arc::new(crate::evm::SnapshotManager::new()));

    let bumped = dispatch_for_test(&state, make_request("evm_increaseTime", json!(["0x64"]))).await;
    // Read what the call returned rather than the process-wide offset: the
    // offset is a static and other tests share it.
    assert!(bumped.result.is_some(), "increaseTime must answer with the new offset");

    let resp = dispatch_for_test(&state, make_request("evm_reset", json!([]))).await;
    assert_eq!(resp.result.unwrap(), json!(true));

    let head = store.head().unwrap().unwrap();
    assert_eq!(store.header(head).unwrap().unwrap().number, 0, "back to genesis");
    assert!(store.canonical_hash(5).unwrap().is_none(), "heights above are gone");
    assert_eq!(
        rustock_execution::mining::dev::time_offset(),
        0,
        "a clock offset must not survive a reset"
    );
}

// ---------------------------------------------------------------------
// The wallet
//
// Everything here checks the behaviour a load-testing harness depends on,
// and the two properties that matter more: that a node given no keys
// behaves exactly as it did before it could hold any, and that a node
// given keys will sign for those and nothing else.
// ---------------------------------------------------------------------

/// Two keys with known addresses. Fixed rather than random so a failure
/// names the same account twice.
fn test_wallet() -> crate::wallet::Wallet {
    let keys = [[0x11u8; 32], [0x22u8; 32]]
        .into_iter()
        .map(|b| secp256k1::SecretKey::from_byte_array(b).unwrap());
    crate::wallet::Wallet::from_keys(keys)
}

fn setup_state_with_wallet() -> (RpcState, tempfile::TempDir) {
    let (mut state, tmp) = setup_state();
    state.wallet = Some(Arc::new(test_wallet()));
    // Signing needs a chain id, which comes from the hardfork config.
    state.hardfork_cfg =
        Some(rustock_execution::hardfork::RskHardforkConfig::all_active_parallel(33));
    (state, tmp)
}

#[tokio::test]
async fn test_eth_accounts_lists_the_wallet_in_a_stable_order() {
    let (state, _tmp) = setup_state_with_wallet();

    let first = dispatch_for_test(&state, make_request("eth_accounts", json!([]))).await;
    let second = dispatch_for_test(&state, make_request("eth_accounts", json!([]))).await;

    let listed = first.result.clone().unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2, "both keys are reported");
    assert_eq!(listed, second.result.unwrap(), "the order must not vary between calls");

    // A harness picks accounts[0] as its sender and expects it to keep
    // being the same account.
    for entry in listed.as_array().unwrap() {
        let s = entry.as_str().expect("an address string");
        assert!(s.starts_with("0x") && s.len() == 42, "not an address: {s}");
    }
}

#[tokio::test]
async fn test_eth_sign_returns_sixty_five_bytes() {
    let (state, _tmp) = setup_state_with_wallet();
    let account = test_wallet().accounts()[0];

    let resp = dispatch_for_test(
        &state,
        make_request("eth_sign", json!([format!("{account:#x}"), "0xdeadbeef"])),
    )
    .await;

    let sig = resp.result.expect("a signature").as_str().unwrap().to_string();
    // The k6 suite asserts exactly this: 0x plus 130 hex characters.
    assert_eq!(sig.len(), 132, "a signature is 65 bytes: {sig}");
    assert!(sig.starts_with("0x"));

    let v = u8::from_str_radix(&sig[130..], 16).unwrap();
    assert!(v == 27 || v == 28, "eth_sign uses the 27/28 form, got {v}");
}

/// The signature must recover to the account that signed, which is the
/// only check that says the bytes mean anything.
#[tokio::test]
async fn test_eth_sign_recovers_to_the_signing_account() {
    let (state, _tmp) = setup_state_with_wallet();
    let account = test_wallet().accounts()[0];
    let message = b"hello rootstock";

    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_sign",
            json!([format!("{account:#x}"), format!("0x{}", hex::encode(message))]),
        ),
    )
    .await;
    let sig = hex::decode(
        resp.result.unwrap().as_str().unwrap().strip_prefix("0x").unwrap(),
    )
    .unwrap();

    let digest = crate::wallet::personal_digest(message);
    let secp = secp256k1::Secp256k1::new();
    let recid = secp256k1::ecdsa::RecoveryId::try_from(i32::from(sig[64]) - 27).unwrap();
    let recoverable =
        secp256k1::ecdsa::RecoverableSignature::from_compact(&sig[..64], recid).unwrap();
    let key = secp
        .recover_ecdsa(secp256k1::Message::from_digest(digest.0), &recoverable)
        .expect("the signature recovers");

    use sha3::{Digest, Keccak256};
    let hashed = Keccak256::digest(&key.serialize_uncompressed()[1..]);
    assert_eq!(
        Address::from_slice(&hashed[12..]),
        account,
        "the signature must recover to the account that produced it"
    );
}

/// The EIP-191 prefix is the reason `eth_sign` cannot be used to forge a
/// transaction signature, so check it is actually applied rather than
/// trusting that it was.
#[tokio::test]
async fn test_eth_sign_prefixes_the_message() {
    let message = b"abc";
    let digest = crate::wallet::personal_digest(message);

    use sha3::{Digest, Keccak256};
    let unprefixed = Keccak256::digest(message);
    assert_ne!(
        digest.as_slice(),
        &unprefixed[..],
        "eth_sign must not sign the raw message: a caller could hand over a \
         transaction's signing hash and be given a valid transaction signature"
    );

    let mut expected = Keccak256::new();
    expected.update(b"\x19Ethereum Signed Message:\n3");
    expected.update(message);
    assert_eq!(digest.as_slice(), &expected.finalize()[..]);
}

#[tokio::test]
async fn test_signing_is_refused_for_an_account_the_wallet_does_not_hold() {
    let (state, _tmp) = setup_state_with_wallet();
    let stranger = "0x00000000000000000000000000000000000000ff";

    for (method, params) in [
        ("eth_sign", json!([stranger, "0xdeadbeef"])),
        ("eth_signTransaction", json!([{"from": stranger}])),
        ("eth_sendTransaction", json!([{"from": stranger}])),
    ] {
        let resp = dispatch_for_test(&state, make_request(method, params)).await;
        assert!(resp.result.is_none(), "{method} must not sign for a stranger");
        let err = resp.error.expect("an error");
        assert_eq!(err.code, INVALID_PARAMS, "{method}");
        assert!(err.message.contains("No key for"), "{method}: {}", err.message);
    }
}

/// `eth_signTransaction` returns a transaction whose signature recovers
/// to the sender, which is what makes it usable by a caller that goes on
/// to submit it.
#[tokio::test]
async fn test_eth_sign_transaction_produces_a_transaction_from_the_sender() {
    let (state, _tmp) = setup_state_with_wallet();
    let account = test_wallet().accounts()[0];

    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_signTransaction",
            json!([{
                "from": format!("{account:#x}"),
                "to": "0x00000000000000000000000000000000000000aa",
                "value": "0x1",
                "gas": "0x5208",
                "gasPrice": "0x1",
                "nonce": "0x0",
            }]),
        ),
    )
    .await;

    let raw = hex::decode(
        resp.result.expect("signed rlp").as_str().unwrap().strip_prefix("0x").unwrap(),
    )
    .unwrap();

    use alloy_rlp::Decodable;
    let tx = rustock_core::Transaction::decode(&mut raw.as_slice()).expect("decodes");
    let chain_id = state.hardfork_cfg.as_ref().unwrap().chain_id;
    assert_eq!(
        tx.recover_sender(chain_id).expect("recovers"),
        account,
        "the signed transaction must come from the account asked for"
    );
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.value, U256::from(1));
}

/// `to: null` is how the suite asks for a contract creation, and it must
/// not become the zero address.
#[tokio::test]
async fn test_a_null_recipient_is_a_contract_creation() {
    let (state, _tmp) = setup_state_with_wallet();
    let account = test_wallet().accounts()[0];

    let resp = dispatch_for_test(
        &state,
        make_request(
            "eth_signTransaction",
            json!([{
                "from": format!("{account:#x}"),
                "to": Value::Null,
                "data": "0x6000",
                "gas": "0x100000",
                "gasPrice": "0x1",
                "nonce": "0x0",
            }]),
        ),
    )
    .await;

    let raw = hex::decode(
        resp.result.expect("signed rlp").as_str().unwrap().strip_prefix("0x").unwrap(),
    )
    .unwrap();
    use alloy_rlp::Decodable;
    let tx = rustock_core::Transaction::decode(&mut raw.as_slice()).unwrap();
    assert!(tx.to.is_empty(), "a creation has an empty recipient, not a zero address");
}

/// Reading a key file is the only way a key gets in, so the parsing has
/// to accept what an operator will actually write.
#[test]
fn test_a_wallet_file_is_read_forgivingly_but_not_loosely() {
    let dir = tempfile::tempdir().unwrap();

    let good = dir.path().join("keys");
    std::fs::write(
        &good,
        "# the funded sender\n\
         0x1111111111111111111111111111111111111111111111111111111111111111\n\
         \n\
         2222222222222222222222222222222222222222222222222222222222222222\n\
         # the same key again, which is the same account\n\
         0x1111111111111111111111111111111111111111111111111111111111111111\n",
    )
    .unwrap();
    let wallet = crate::wallet::Wallet::from_file(&good).expect("loads");
    assert_eq!(wallet.accounts().len(), 2, "comments, blanks and a repeat collapse to two");

    let bad = dir.path().join("bad");
    std::fs::write(&bad, "0xnothex\n").unwrap();
    assert!(crate::wallet::Wallet::from_file(&bad).is_err(), "a bad key must not be skipped");

    let empty = dir.path().join("empty");
    std::fs::write(&empty, "# nothing but a comment\n").unwrap();
    assert!(
        crate::wallet::Wallet::from_file(&empty).is_err(),
        "an empty wallet is a configuration mistake, not an empty account list"
    );

    assert!(crate::wallet::Wallet::from_file(dir.path().join("absent")).is_err());
}

/// A `Debug` of the state reaches logs and panic messages; it must not
/// carry key material.
#[test]
fn test_a_wallet_does_not_print_its_keys() {
    let rendered = format!("{:?}", test_wallet());
    assert!(rendered.contains("accounts"), "it should say how many: {rendered}");
    assert!(!rendered.contains("1111"), "key material must not be printable: {rendered}");
}


// ---------------------------------------------------------------------
// Continuous mining
// ---------------------------------------------------------------------

/// A miner that records what it was asked to do, and a pool whose
/// pending count the test drives.
struct CountingMiner {
    mined: Arc<std::sync::atomic::AtomicUsize>,
    pending: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::mnr::MiningService for CountingMiner {
    fn coinbase(&self) -> [u8; 20] {
        [0u8; 20]
    }
    fn get_work(&self) -> Result<rustock_execution::mining::MinerWork, rustock_execution::mining::SubmitError> {
        unimplemented!("not reached by these tests")
    }
    fn submit_bitcoin_block(
        &self,
        _raw: &[u8],
    ) -> Result<rustock_execution::mining::SubmittedBlockInfo, rustock_execution::mining::SubmitError> {
        unimplemented!("not reached by these tests")
    }
    fn submit_bitcoin_block_transactions(
        &self,
        _h: &[u8],
        _c: &[u8],
        _t: &str,
    ) -> Result<rustock_execution::mining::SubmittedBlockInfo, rustock_execution::mining::SubmitError> {
        unimplemented!("not reached by these tests")
    }
    fn submit_bitcoin_block_partial_merkle(
        &self,
        _h: &[u8],
        _c: &[u8],
        _m: &str,
        _n: u32,
    ) -> Result<rustock_execution::mining::SubmittedBlockInfo, rustock_execution::mining::SubmitError> {
        unimplemented!("not reached by these tests")
    }
    fn mine_one_now(&self) -> Result<u64, String> {
        use std::sync::atomic::Ordering;
        // Mining a block drains the pool, as a real one does now that a
        // locally mined block evicts what it included.
        self.pending.store(0, Ordering::Relaxed);
        Ok(self.mined.fetch_add(1, Ordering::Relaxed) as u64 + 1)
    }
}

struct CountingPool {
    pending: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::server::TxPoolReader for CountingPool {
    fn get_pending_tx(
        &self,
        _h: &B256,
    ) -> Option<(rustock_core::Transaction, Address, B256)> {
        None
    }
    fn pending_nonce(&self, _a: &Address) -> Option<u64> {
        None
    }
    fn pool_status(&self) -> (usize, usize) {
        (self.pending.load(std::sync::atomic::Ordering::Relaxed), 0)
    }
    fn pool_content(&self) -> crate::server::PoolContent {
        crate::server::PoolContent { pending: Vec::new(), queued: Vec::new() }
    }
    fn quota_report(&self, _a: &Address) -> Option<(f64, u64)> {
        None
    }
}

fn autominer() -> (crate::evm::AutoMiner, Arc<std::sync::atomic::AtomicUsize>, Arc<std::sync::atomic::AtomicUsize>) {
    let mined = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let auto = crate::evm::AutoMiner::new(
        Arc::new(CountingMiner { mined: mined.clone(), pending: pending.clone() }),
        Some(Arc::new(CountingPool { pending: pending.clone() })),
        std::time::Duration::from_millis(10),
    );
    (auto, mined, pending)
}

/// An idle chain must not fill with empty blocks.
///
/// This is the failure the pool-eviction bug produced: with mined
/// transactions never leaving the pool, the loop saw work forever and
/// mined four thousand empty blocks in ten seconds.
#[test]
fn an_idle_chain_is_not_mined() {
    use std::sync::atomic::Ordering;
    let (auto, mined, _pending) = autominer();
    auto.start();
    std::thread::sleep(std::time::Duration::from_millis(150));
    auto.stop();
    assert_eq!(mined.load(Ordering::Relaxed), 0, "nothing pending, nothing to mine");
}

#[test]
fn a_pending_transaction_is_mined_without_being_asked() {
    use std::sync::atomic::Ordering;
    let (auto, mined, pending) = autominer();
    auto.start();
    pending.store(1, Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(200));
    auto.stop();
    let n = mined.load(Ordering::Relaxed);
    assert!(n >= 1, "the pending transaction should have been mined");
    // And then stopped: draining the pool must end the mining, not
    // start a block-per-tick chain.
    assert!(n <= 3, "mined {n} blocks for one transaction");
}

/// `evm_startMining` is called once per scenario and there are eleven of
/// them. Starting twice must not give two threads mining one chain.
#[test]
fn starting_twice_runs_one_miner() {
    use std::sync::atomic::Ordering;
    let (auto, mined, pending) = autominer();
    for _ in 0..5 {
        auto.start();
    }
    assert!(auto.is_running());
    pending.store(1, Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(200));
    auto.stop();
    assert!(mined.load(Ordering::Relaxed) <= 3, "one transaction, one miner, one block");
}

#[test]
fn stopping_is_idempotent_and_reported() {
    let (auto, _mined, _pending) = autominer();
    assert!(!auto.is_running(), "off until asked");
    auto.start();
    assert!(auto.is_running());
    auto.stop();
    auto.stop();
    assert!(!auto.is_running());
    // And it can be started again, which a scenario that stops and
    // restarts mining depends on.
    auto.start();
    assert!(auto.is_running());
    auto.stop();
}


/// A receipt must name the account that signed the transaction, on
/// whatever chain the node is running.
///
/// The sender recovery here was hardcoded to chain id 30, so on testnet
/// and on every regtest chain the EIP-155 recovery failed and the
/// `unwrap_or` turned it into the zero address. Silent, because a
/// receipt with a plausible-looking zero address is not obviously
/// broken, and invisible on mainnet, which is the only chain whose id
/// matched the constant.
#[tokio::test]
async fn a_receipt_names_the_sender_on_a_chain_that_is_not_mainnet() {
    use rustock_core::types::receipt::Receipt;

    let (mut state, _tmp) = setup_state();
    // Regtest, deliberately: the bug was invisible wherever the chain
    // id happened to be 30.
    let chain_id = 33u64;
    state.hardfork_cfg =
        Some(rustock_execution::hardfork::RskHardforkConfig::all_active_parallel(chain_id));

    // A transaction signed for this chain, by a key whose address we know.
    let wallet = test_wallet();
    let signer = wallet.accounts()[0];
    let mut tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(1),
        gas_limit: U256::from(21_000),
        to: Bytes::copy_from_slice(&[0xAAu8; 20]),
        value: U256::from(1),
        input: Bytes::new(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    };
    assert!(wallet.sign_transaction(&signer, &mut tx, chain_id));

    // Put it in a block with a receipt, the way the store would hold it.
    let header = test_header(43);
    let hash = header.hash();
    state.store.put_header_with_hash(hash, &header).unwrap();
    state.store.put_body(hash, std::slice::from_ref(&tx), &[]).unwrap();
    state.store.put_canonical_hash(43, hash).unwrap();
    let tx_hash = crate::tx::compute_tx_hash(&tx);
    state.store.put_tx_index(tx_hash, hash, 0).unwrap();
    state
        .store
        .put_receipts(
            hash,
            &[Receipt {
                post_tx_state: vec![1],
                cumulative_gas_used: 21_000,
                gas_used: 21_000,
                logs_bloom: Default::default(),
                logs: Vec::new(),
                status: true,
            }],
        )
        .unwrap();

    let resp = dispatch_for_test(
        &state,
        make_request("eth_getTransactionReceipt", json!([format!("{tx_hash:#x}")])),
    )
    .await;

    let from = resp.result.expect("a receipt")["from"].as_str().unwrap().to_string();
    assert_eq!(
        from,
        format!("{signer:#x}"),
        "the receipt must name the signer, not the zero address"
    );
}

// ===== Findings from the rskj-k6-tests battery, 2026-10-25 =====

/// Genesis must be retrievable even though its header claims roots no empty
/// trie produces.
///
/// Only mainnet's genesis header carries the real empty-list and empty-trie
/// hashes. Testnet's and regtest's carry `B256::ZERO` for `ommers_hash` and
/// `transactions_root`, and `setup_genesis` writes no body row -- so the
/// "does this header claim an empty body?" test said no, the body lookup
/// failed, and block 0 came back `null` by number, by tag and by hash alike.
///
/// The consequence that reached past the test suite: while the head *is*
/// genesis, `eth_getBlockByNumber("latest")` answered `null` to every client.
/// That is the state of a fresh regtest node until something is mined.
#[tokio::test]
async fn genesis_is_served_even_with_zeroed_body_roots() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    // Regtest's genesis, as `ChainConfig::regtest().genesis_header()` builds it.
    let mut genesis = test_header(0);
    genesis.ommers_hash = B256::ZERO;
    genesis.transactions_root = B256::ZERO;
    let hash = genesis.hash();
    store.put_header_with_hash(hash, &genesis).unwrap();
    store.put_total_difficulty(hash, U256::from(1)).unwrap();
    store.put_canonical_hash(0, hash).unwrap();
    store.set_head(hash).unwrap();
    // Deliberately no `put_body` -- `setup_genesis` writes none.

    let (mut state, _tmp2) = setup_state();
    state.store = store;

    for params in [json!(["0x0", false]), json!(["earliest", false]), json!(["latest", false])] {
        let resp = dispatch_for_test(&state, make_request("eth_getBlockByNumber", params.clone()))
            .await.result.unwrap();
        assert!(resp.is_object(), "eth_getBlockByNumber({params}) returned {resp}");
        assert_eq!(resp["transactions"], json!([]), "genesis has no transactions");
    }

    let by_hash = dispatch_for_test(
        &state,
        make_request("eth_getBlockByHash", json!([format!("{hash:#x}"), false])),
    ).await.result.unwrap();
    assert!(by_hash.is_object(), "eth_getBlockByHash returned {by_hash}");

    let count = dispatch_for_test(
        &state,
        make_request("eth_getBlockTransactionCountByNumber", json!(["0x0"])),
    ).await.result.unwrap();
    assert_eq!(count, json!("0x0"), "genesis transaction count must be zero, not null");
}

/// `rpc_modules` must list every namespace this server dispatches, because a
/// client that gates on it will not call what is missing. `evm` and `txpool`
/// were absent even when enabled; `debug`, `trace` and `sco` were absent
/// despite being answered unconditionally.
#[tokio::test]
async fn rpc_modules_lists_the_namespaces_that_answer() {
    let (state, _tmp) = setup_state();
    let base = dispatch_for_test(&state, make_request("rpc_modules", json!([])))
        .await.result.unwrap();
    for name in ["eth", "net", "web3", "rpc", "rsk", "debug", "trace", "sco"] {
        assert!(base.get(name).is_some(), "{name} is dispatched but not listed: {base}");
    }
    // Off by default, and correctly absent.
    assert!(base.get("evm").is_none(), "evm must not be listed without --dev-rpc");
    assert!(base.get("txpool").is_none(), "txpool must not be listed without a pool");

    let (mut state, _tmp) = setup_state();
    state.snapshots = Some(Arc::new(crate::evm::SnapshotManager::new()));
    state.tx_pool = Some(Arc::new(MutablePool::default()));
    let on = dispatch_for_test(&state, make_request("rpc_modules", json!([])))
        .await.result.unwrap();
    assert!(on.get("evm").is_some(), "evm answers with --dev-rpc, so it must be listed: {on}");
    assert!(on.get("txpool").is_some(), "txpool answers with a pool, so it must be listed: {on}");
}

// ===== Single-pass gas estimation ("exactimator") =====

/// A chain state with two contracts, built for gas estimation:
///
/// - `caller` does `CALL(stipend, callee, value, 0,0,0,0)` then STOP
/// - `callee` is a bare STOP, so it costs almost nothing
///
/// The point is the gap between the two: the caller must *hold* `stipend` at
/// the CALL, but the callee spends none of it. Total consumption therefore
/// understates the limit the transaction needs, which is exactly the case
/// binary search discovers the slow way and the peak reports directly.
fn setup_estimation_state(
    stipend: u64,
    value: u64,
    binary_search: bool,
) -> (RpcState, tempfile::TempDir, Address, Address) {
    use rustock_trie::{account_key, code_key, MemoryTrieStore, TrieKeySlice, TrieNode};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let trie_store = Arc::new(MemoryTrieStore::new());
    let mut root = TrieNode::empty();

    let sender: Address = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826".parse().unwrap();
    let caller: Address = "0x1111111111111111111111111111111111111111".parse().unwrap();
    let callee: Address = "0x2222222222222222222222222222222222222222".parse().unwrap();

    for (addr, balance) in [(sender, U256::from(10u64).pow(U256::from(20))),
                            (caller, U256::from(10u64).pow(U256::from(18))),
                            (callee, U256::ZERO)] {
        let acct = rustock_trie::AccountState::new(U256::ZERO, balance);
        root = root.put(&TrieKeySlice::from_key(&account_key(&addr)), &acct.encode(), &*trie_store);
    }

    // CALL(gas=stipend, callee, value, 0, 0, 0, 0); STOP
    let mut code: Vec<u8> = Vec::new();
    for _ in 0..4 {
        code.extend_from_slice(&[0x60, 0x00]); // retSize, retOffset, argsSize, argsOffset
    }
    code.extend_from_slice(&[0x63]); // PUSH4 value
    code.extend_from_slice(&(value as u32).to_be_bytes());
    code.push(0x73); // PUSH20 callee
    code.extend_from_slice(callee.as_slice());
    code.push(0x63); // PUSH4 gas
    code.extend_from_slice(&(stipend as u32).to_be_bytes());
    code.extend_from_slice(&[0xF1, 0x00]); // CALL; STOP
    root = root.put(&TrieKeySlice::from_key(&code_key(&caller)), &code, &*trie_store);
    // The callee is a bare STOP.
    root = root.put(&TrieKeySlice::from_key(&code_key(&callee)), &[0x00], &*trie_store);

    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);
    rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root.to_message(&*trie_store));

    let header = Header { state_root, gas_limit: U256::from(6_800_000u64), ..test_header(42) };
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, hash).unwrap();
    store.set_head(hash).unwrap();
    store.put_total_difficulty(hash, U256::from(42_000)).unwrap();

    let (mut state, _discard) = setup_state();
    state.store = store;
    state.trie_store = Some(trie_store);
    state.hardfork_cfg = Some(rustock_execution::RskHardforkConfig::mainnet());
    state.gas_estimator_binary_search = binary_search;
    std::mem::forget(_discard);
    (state, tmp, sender, caller)
}

async fn estimate(state: &RpcState, from: Address, to: Address) -> u64 {
    let req = make_request(
        "eth_estimateGas",
        json!([{ "from": format!("{from:#x}"), "to": format!("{to:#x}") }, "latest"]),
    );
    let resp = dispatch_for_test(state, req).await;
    let v = resp.result.unwrap_or_else(|| panic!("estimateGas errored: {:?}", resp.error));
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// The guard on the whole change.
///
/// Not equality. The two estimators answer subtly different questions, and
/// the difference is real rather than a defect in either:
///
/// - binary search finds the smallest limit at which the transaction does
///   not revert;
/// - the single-pass estimator reports the limit at which it *behaves as it
///   did at the cap*.
///
/// They part company over a CALL with a generous fixed allowance. RSK has no
/// EIP-150 retention and `calleeGas = min(remaining, requested + stipend)`,
/// so a CALL asking for 100,000 with 11,000 left does not fail -- the callee
/// simply gets 11,000. The transaction therefore still succeeds at a limit
/// far below the peak, which is the answer binary search converges on. But
/// the inner call ran on different gas than it did at the cap, and a caller
/// that does not check the return value would carry on and do something
/// else. The peak is the limit that preserves the observed behaviour.
///
/// So what is required here is that the single-pass answer is *sufficient*
/// and never below the search's, and that the two agree wherever no such
/// allowance is in play.
#[tokio::test]
async fn the_exactimator_never_undercuts_binary_search() {
    for (stipend, value, agree, what) in [
        (100_000u64, 0u64, false, "a callee handed far more than it spends"),
        (3_000, 0, true, "a callee handed roughly what it needs"),
        (3_000, 1, true, "a value-bearing call, which carries the 2300 stipend"),
    ] {
        let (fast_state, _t1, from, to) = setup_estimation_state(stipend, value, false);
        let (slow_state, _t2, _, _) = setup_estimation_state(stipend, value, true);

        let fast = estimate(&fast_state, from, to).await;
        let slow = estimate(&slow_state, from, to).await;

        assert!(
            fast >= slow,
            "{what}: single pass said {fast}, below binary search's {slow} -- \
             an estimate that does not execute"
        );
        if agree {
            assert_eq!(fast, slow, "{what}: the two should agree here");
        }
    }
}

/// The binary search has to find the true minimum, including when that
/// minimum is the intrinsic cost itself.
///
/// Its invariant is "`lo` fails, `hi` succeeds", and it answers `hi`. `lo`
/// started at 21,000 and was never tested -- so for the commonest
/// transaction there is, a plain transfer costing exactly 21,000, the search
/// had assumed the answer away and returned 21,001. Found by comparing it
/// against the single-pass estimator, which answered 21,000.
///
/// Unrelated to the refund overshoot in #334: that one is inherited from
/// rskj's formula, this one was ours alone and is simply wrong.
#[tokio::test]
async fn binary_search_finds_the_intrinsic_cost_exactly() {
    let (state, _tmp, from, _) = setup_estimation_state(0, 0, true);
    let empty: Address = "0x3333333333333333333333333333333333333333".parse().unwrap();
    assert_eq!(
        estimate(&state, from, empty).await,
        21_000,
        "a plain transfer costs exactly 21,000; one more than that means the \
         search never tested its own lower bound"
    );
}

/// The property the peak exists for, and the one binary search cannot give:
/// the estimate has to be large enough for the caller to hand over the whole
/// allowance its CALL asks for.
///
/// At 100,000 the callee spends almost nothing, so the transaction's total
/// consumption is around 30k and binary search stops there -- a limit at
/// which the CALL would be silently truncated to whatever was left. The
/// single-pass estimate covers the allowance, which is what keeps the inner
/// call behaving as it did at the cap.
#[tokio::test]
async fn the_estimate_covers_the_allowance_a_call_asks_for() {
    let (fast_state, _t1, from, to) = setup_estimation_state(100_000, 0, false);
    let (slow_state, _t2, _, _) = setup_estimation_state(100_000, 0, true);

    let fast = estimate(&fast_state, from, to).await;
    let slow = estimate(&slow_state, from, to).await;

    assert!(
        fast >= 100_000,
        "the estimate {fast} cannot hand the callee the 100,000 it asks for, \
         so the inner call would run on different gas than it was estimated at"
    );
    assert!(
        slow < 100_000,
        "fixture no longer exercises the divergence: binary search returned \
         {slow}, which already covers the allowance"
    );
}

/// A contract that clears a storage slot (earning a refund) and then calls
/// out with `GAS` (handing over everything it has left). That lands on the
/// `movedRemainingGasToChild` branch *and* has a refund, which is the
/// combination where the two branches of rskj's formula disagree with each
/// other about whether a refund belongs in an estimate.
fn setup_refund_state(binary_search: bool) -> (RpcState, tempfile::TempDir, Address, Address) {
    use rustock_trie::{account_key, code_key, storage_key, MemoryTrieStore, TrieKeySlice, TrieNode};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let trie_store = Arc::new(MemoryTrieStore::new());
    let mut root = TrieNode::empty();

    let sender: Address = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826".parse().unwrap();
    let caller: Address = "0x4444444444444444444444444444444444444444".parse().unwrap();
    let callee: Address = "0x5555555555555555555555555555555555555555".parse().unwrap();

    for addr in [sender, caller, callee] {
        let acct = rustock_trie::AccountState::new(U256::ZERO, U256::from(10u64).pow(U256::from(20)));
        root = root.put(&TrieKeySlice::from_key(&account_key(&addr)), &acct.encode(), &*trie_store);
    }

    // Slot 1 starts non-zero, so storing zero into it earns the refund.
    let mut slot = [0u8; 32];
    slot[31] = 1;
    root = root.put(
        &TrieKeySlice::from_key(&storage_key(&caller, &B256::from(slot))),
        &[7u8],
        &*trie_store,
    );

    // SSTORE(1, 0); CALL(GAS, callee, 0, 0,0,0,0); STOP
    let mut code: Vec<u8> = vec![0x60, 0x00, 0x60, 0x01, 0x55];
    for _ in 0..5 {
        code.extend_from_slice(&[0x60, 0x00]); // retSize, retOffset, argsSize, argsOffset, value
    }
    code.push(0x73);
    code.extend_from_slice(callee.as_slice());
    code.extend_from_slice(&[0x5A, 0xF1, 0x00]); // GAS; CALL; STOP
    root = root.put(&TrieKeySlice::from_key(&code_key(&caller)), &code, &*trie_store);
    root = root.put(&TrieKeySlice::from_key(&code_key(&callee)), &[0x00], &*trie_store);

    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);
    rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root.to_message(&*trie_store));

    let header = Header { state_root, gas_limit: U256::from(6_800_000u64), ..test_header(42) };
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, hash).unwrap();
    store.set_head(hash).unwrap();
    store.put_total_difficulty(hash, U256::from(42_000)).unwrap();

    let (mut state, discard) = setup_state();
    state.store = store;
    state.trie_store = Some(trie_store);
    state.hardfork_cfg = Some(rustock_execution::RskHardforkConfig::mainnet());
    state.gas_estimator_binary_search = binary_search;
    std::mem::forget(discard);
    (state, tmp, sender, caller)
}

/// rskj's formula adds the refund back on the `movedRemainingGasToChild`
/// branch and not on the other, and this test pins the consequence: the
/// estimate comes out `deductedRefund` higher than the limit the transaction
/// actually needs -- here 40,089 against a demonstrated 26,726, which is the
/// `gasUsed/2` refund cap, so 50% high.
///
/// Kept as an assertion rather than fixed, because it is rskj's behaviour and
/// this estimator is meant to agree with rskj. See `docs/gas-estimation.md`
/// §2 -- if the rskj side ever drops the `+ deductedRefund`, this test is the
/// thing to update alongside.
///
/// Note the contrast with `the_estimate_covers_the_allowance_a_call_asks_for`:
/// *that* divergence from binary search is a deliberate, minimal answer to a
/// stricter question. This one buys nothing.
#[tokio::test]
async fn the_refund_branch_overshoots_by_the_refund() {
    let (fast_state, _t1, from, to) = setup_refund_state(false);
    let (slow_state, _t2, _, _) = setup_refund_state(true);

    let fast = estimate(&fast_state, from, to).await;
    let slow = estimate(&slow_state, from, to).await;

    assert!(
        fast > slow,
        "fixture no longer reaches the refund branch: {fast} vs {slow}"
    );
    // The gap is exactly the refund, capped at half the gas used.
    assert_eq!(
        fast - slow,
        slow / 2,
        "the overshoot should be the capped refund and nothing else"
    );
}

// ===== eth_getProof =====

/// A chain with one funded account that has code and two storage slots.
fn setup_proof_state() -> (RpcState, tempfile::TempDir, Address, B256) {
    use rustock_trie::{account_key, code_key, storage_key, MemoryTrieStore, TrieKeySlice, TrieNode};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let trie_store = Arc::new(MemoryTrieStore::new());
    let mut root = TrieNode::empty();

    let addr: Address = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826".parse().unwrap();
    let acct = rustock_trie::AccountState::new(U256::from(7u64), U256::from(1_000_000u64));
    root = root.put(&TrieKeySlice::from_key(&account_key(&addr)), &acct.encode(), &*trie_store);
    root = root.put(&TrieKeySlice::from_key(&code_key(&addr)), &[0x60, 0x00, 0x60, 0x00], &*trie_store);

    for (slot_byte, value) in [(1u8, 42u8), (2u8, 99u8)] {
        let mut s = [0u8; 32];
        s[31] = slot_byte;
        root = root.put(
            &TrieKeySlice::from_key(&storage_key(&addr, &B256::from(s))),
            &[value],
            &*trie_store,
        );
    }

    // Other accounts, so the trie actually branches. With only the four keys
    // above, path compression collapses the whole thing to a node or two and
    // a "proof" spanning one level proves nothing about chaining.
    for i in 1u8..=64 {
        let other = Address::repeat_byte(i);
        let a = rustock_trie::AccountState::new(U256::from(i), U256::from(i) * U256::from(1000u64));
        root = root.put(&TrieKeySlice::from_key(&account_key(&other)), &a.encode(), &*trie_store);
    }

    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);
    rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root.to_message(&*trie_store));

    let header = Header { state_root, ..test_header(42) };
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, hash).unwrap();
    store.set_head(hash).unwrap();
    store.put_total_difficulty(hash, U256::from(42_000)).unwrap();

    let (mut state, discard) = setup_state();
    state.store = store;
    state.trie_store = Some(trie_store);
    std::mem::forget(discard);
    (state, tmp, addr, state_root)
}

/// The envelope: the values a caller came for, and the shape EIP-1186 asks
/// for even though the proof arrays inside it are unitrie nodes.
#[tokio::test]
async fn get_proof_reports_the_account_and_its_slots() {
    let (state, _tmp, addr, _) = setup_proof_state();
    let req = make_request(
        "eth_getProof",
        json!([format!("{addr:#x}"), ["0x1", "0x2"], "latest"]),
    );
    let r = dispatch_for_test(&state, req).await.result.unwrap();

    assert_eq!(r["balance"], json!("0xf4240"), "1,000,000");
    assert_eq!(r["nonce"], json!("0x7"));
    assert_ne!(r["codeHash"], json!(format!("{:#x}", B256::ZERO)), "the account has code");
    assert_ne!(r["storageHash"], json!(format!("{:#x}", B256::ZERO)), "and storage");

    let sp = r["storageProof"].as_array().unwrap();
    assert_eq!(sp.len(), 2);
    assert_eq!(sp[0]["key"], json!("0x1"), "the key is echoed as the caller wrote it");
    assert_eq!(sp[0]["value"], json!("0x2a"), "42");
    assert_eq!(sp[1]["value"], json!("0x63"), "99");
    assert!(!sp[0]["proof"].as_array().unwrap().is_empty());
    assert!(!r["accountProof"].as_array().unwrap().is_empty());
}

/// The property that makes a proof a proof: the last node in the array is
/// the root, and its hash is the block's state root. Without this the
/// method returns bytes that merely look like evidence.
#[tokio::test]
async fn the_proof_chains_up_to_the_state_root() {
    use rustock_trie::TrieNode;

    let (state, _tmp, addr, state_root) = setup_proof_state();
    let trie_store = state.trie_store.clone().unwrap();
    let req = make_request("eth_getProof", json!([format!("{addr:#x}"), ["0x1"], "latest"]));
    let r = dispatch_for_test(&state, req).await.result.unwrap();

    for which in ["accountProof", "storageProof"] {
        let nodes: Vec<String> = if which == "accountProof" {
            r[which].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
        } else {
            r[which][0]["proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        };
        assert!(nodes.len() > 1, "{which} should span more than one level");

        let last = hex::decode(nodes.last().unwrap().trim_start_matches("0x")).unwrap();
        let root_node = TrieNode::from_message(&last, &*trie_store);
        assert_eq!(
            root_node.compute_hash(&*trie_store),
            state_root,
            "{which}: the last node must hash to the block's state root"
        );

        // And every node must parse -- a caller walking the array upward has
        // to be able to decode each one.
        for n in &nodes {
            let bytes = hex::decode(n.trim_start_matches("0x")).unwrap();
            let _ = TrieNode::from_message(&bytes, &*trie_store);
        }
    }
}

/// An address the trie never heard of still gets a well-formed answer,
/// rather than an error or a half-built path.
#[tokio::test]
async fn get_proof_answers_for_an_absent_account() {
    let (state, _tmp, _, _) = setup_proof_state();
    let absent: Address = "0x0000000000000000000000000000000000009999".parse().unwrap();
    let req = make_request("eth_getProof", json!([format!("{absent:#x}"), [], "latest"]));
    let r = dispatch_for_test(&state, req).await.result.unwrap();

    assert_eq!(r["balance"], json!("0x0"));
    assert_eq!(r["nonce"], json!("0x0"));
    assert_eq!(
        r["accountProof"].as_array().unwrap().len(),
        0,
        "absence is an empty array, not a truncated path that would read as inclusion"
    );
    assert_eq!(r["storageHash"], json!(format!("{:#x}", B256::ZERO)));
    assert_eq!(r["storageProof"].as_array().unwrap().len(), 0);
}

/// Slots are quantities, as `eth_getStorageAt` accepts them -- `0x1`, not a
/// 64-character hash. A wallet sends the short form (#179).
#[tokio::test]
async fn get_proof_accepts_a_slot_as_a_quantity() {
    let (state, _tmp, addr, _) = setup_proof_state();
    let padded = format!("{:#066x}", {
        let mut s = [0u8; 32];
        s[31] = 1;
        B256::from(s)
    });
    let short = dispatch_for_test(
        &state,
        make_request("eth_getProof", json!([format!("{addr:#x}"), ["0x1"], "latest"])),
    )
    .await
    .result
    .unwrap();
    let long = dispatch_for_test(
        &state,
        make_request("eth_getProof", json!([format!("{addr:#x}"), [padded], "latest"])),
    )
    .await
    .result
    .unwrap();

    assert_eq!(short["storageProof"][0]["value"], long["storageProof"][0]["value"]);
    assert_eq!(short["storageProof"][0]["proof"], long["storageProof"][0]["proof"]);
}

#[tokio::test]
async fn get_proof_rejects_a_missing_slot_array() {
    let (state, _tmp, addr, _) = setup_proof_state();
    let resp = dispatch_for_test(
        &state,
        make_request("eth_getProof", json!([format!("{addr:#x}")])),
    )
    .await;
    assert!(resp.error.is_some(), "the slot array is required, even when empty");
}
