//! `eth_subscribe` / `eth_unsubscribe` and the events that feed them.
//!
//! Source of truth: rskj's `co.rsk.rpc.modules.eth.subscribe` package —
//! `EthSubscribeRequest`, `BlockHeaderNotificationEmitter`,
//! `LogsNotificationEmitter`, `PendingTransactionsNotificationEmitter`.
//!
//! # The reorg question, which is the whole design
//!
//! A subscription is only useful if it tells you when it was wrong. rskj's
//! logs emitter does this properly: on every new best block it computes the
//! fork against the last block it emitted
//! (`BlockchainBranchComparator.calculateFork`) and sends the abandoned
//! branch's logs with `removed: true` before the new branch's with
//! `removed: false`. This does the same, driven by the rollbacks the sync
//! service already performs.
//!
//! It is not a corner case here. This node observes a tip fork several times
//! an hour — the I5 repair in `crates/sync/src/invariant.rs` fires that often
//! — so a subscriber that never heard about a removal would accumulate logs
//! from blocks that are no longer on the chain.
//!
//! # One deliberate difference from rskj, in `newHeads`
//!
//! rskj's `BlockHeaderNotificationEmitter` listens on `onBlock`, not
//! `onBestBlock`. In `BlockChainImpl.tryToConnect`, `onBlock` fires for
//! `IMPORTED_BEST` **and** `IMPORTED_NOT_BEST` — so **rskj sends `newHeads`
//! for blocks that never became the head**, including the losing side of a
//! fork. (Its logs emitter uses `onBestBlock` and does not have this.)
//!
//! rustock emits `newHeads` only for blocks that became the executed head,
//! which is geth's behaviour and what the subscription's name promises. The
//! reason is not only taste: rustock executes the canonical chain, so a
//! losing sibling is often stored and never executed, and there is no point
//! at which the node could describe it as a head. A client written against
//! rskj sees strictly fewer notifications here, never spurious ones.
//! Recorded in `docs/rskj-vs-geth.md`.

use crate::dto::LogDto;
use alloy_primitives::{Address, B256};
use rustock_core::types::header::Header;
use serde_json::{json, Map, Value};

// The event type itself lives in `rustock_core::events`, because the sync
// service publishes and this crate consumes and neither depends on the other.
// What stays here is the rendering: only the RPC layer should know what a
// subscriber's wire format looks like.
pub use rustock_core::events::{BlockEvent, ChainEvent, EventSender, SUBSCRIBER_LAG};

/// What a client asked to be told about.
#[derive(Debug, Clone)]
pub enum Subscription {
    NewHeads,
    Logs(LogsParams),
    NewPendingTransactions,
    /// rskj has this (`SyncNotificationEmitter`); it reports entering and
    /// leaving sync rather than a per-block position.
    Syncing,
}

/// `eth_subscribe("logs", {address, topics})` — the same filter object
/// `eth_getLogs` takes.
#[derive(Debug, Clone, Default)]
pub struct LogsParams {
    pub addresses: Vec<Address>,
    pub topics: Vec<Option<Vec<B256>>>,
}

impl LogsParams {
    pub fn matches(&self, log: &rustock_core::Log) -> bool {
        if !self.addresses.is_empty() && !self.addresses.contains(&log.address) {
            return false;
        }
        for (i, allowed) in self.topics.iter().enumerate() {
            let Some(allowed) = allowed else { continue };
            match log.topics.get(i) {
                Some(t) if allowed.contains(t) => {}
                None if allowed.is_empty() => {}
                _ => return false,
            }
        }
        true
    }
}

/// Parse `eth_subscribe`'s parameters.
///
/// `params[0]` names the kind; `params[1]` is the kind's options, which only
/// `logs` uses.
pub fn parse_subscription(params: &Value) -> Result<Subscription, String> {
    let Some(kind) = params.get(0).and_then(|v| v.as_str()) else {
        return Err("Missing subscription type".into());
    };
    match kind {
        "newHeads" => Ok(Subscription::NewHeads),
        "newPendingTransactions" => Ok(Subscription::NewPendingTransactions),
        "syncing" => Ok(Subscription::Syncing),
        "logs" => {
            let obj = params.get(1);
            Ok(Subscription::Logs(LogsParams {
                addresses: parse_addresses(obj.and_then(|o| o.get("address"))),
                topics: parse_topics(obj.and_then(|o| o.get("topics"))),
            }))
        }
        other => Err(format!("Unsupported subscription type: {other}")),
    }
}

fn parse_addresses(v: Option<&Value>) -> Vec<Address> {
    match v {
        Some(Value::String(s)) => s.parse().map(|a| vec![a]).unwrap_or_default(),
        Some(Value::Array(a)) => {
            a.iter().filter_map(|x| x.as_str()).filter_map(|s| s.parse().ok()).collect()
        }
        _ => Vec::new(),
    }
}

fn parse_topics(v: Option<&Value>) -> Vec<Option<Vec<B256>>> {
    let Some(Value::Array(items)) = v else { return Vec::new() };
    items
        .iter()
        .map(|item| match item {
            Value::String(s) => s.parse().ok().map(|t| vec![t]),
            Value::Array(alts) => {
                Some(alts.iter().filter_map(|x| x.as_str()).filter_map(|s| s.parse().ok()).collect())
            }
            // `null` at a position means "anything here".
            _ => None,
        })
        .collect()
}

/// The notifications one event produces for one subscription, already shaped
/// as JSON-RPC `eth_subscription` payloads.
///
/// Returns an empty vector when the event does not concern this subscription,
/// which is the common case and costs nothing.
pub fn notifications_for(
    subscription: &Subscription,
    id: &str,
    event: &ChainEvent,
) -> Vec<Value> {
    match (subscription, event) {
        (Subscription::NewHeads, ChainEvent::Block(block)) if !block.removed => {
            vec![notification(id, header_dto(&block.header, block.hash))]
        }
        (Subscription::Logs(params), ChainEvent::Block(block)) => {
            log_notifications(params, id, block)
        }
        (Subscription::NewPendingTransactions, ChainEvent::PendingTransaction(hash)) => {
            vec![notification(id, json!(format!("{hash:#x}")))]
        }
        _ => Vec::new(),
    }
}

fn log_notifications(params: &LogsParams, id: &str, block: &BlockEvent) -> Vec<Value> {
    let mut out = Vec::new();
    let mut log_index = 0u32;
    for (tx_index, receipt) in block.receipts.iter().enumerate() {
        let tx_hash = block
            .transactions
            .get(tx_index)
            .map(|tx| tx.tx_hash())
            .unwrap_or(B256::ZERO);
        for log in &receipt.logs {
            if params.matches(log) {
                let dto = LogDto::from_log(
                    log,
                    block.hash,
                    block.header.number,
                    tx_hash,
                    tx_index as u32,
                    log_index,
                );
                let mut value = serde_json::to_value(&dto).unwrap_or(Value::Null);
                // rskj's `LogsNotification` carries `removed`, and it is the
                // only way a subscriber learns a log it already acted on is
                // no longer on the chain.
                if let Value::Object(map) = &mut value {
                    map.insert("removed".into(), Value::Bool(block.removed));
                }
                out.push(notification(id, value));
            }
            log_index += 1;
        }
    }
    out
}

/// The JSON-RPC notification envelope: a *request* with no id, as the
/// subscription protocol specifies.
fn notification(id: &str, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": { "subscription": id, "result": result },
    })
}

/// A block header in the shape `eth_getBlockByNumber` returns, minus the
/// body-dependent fields a header notification has no business carrying.
pub(crate) fn header_dto(header: &Header, hash: B256) -> Value {
    use crate::helpers::{
        to_hex_b256, to_hex_bytes, to_hex_quantity_bytes, to_hex_u256, to_hex_u64,
    };
    let mut out = Map::new();
    out.insert("hash".into(), Value::String(to_hex_b256(&hash)));
    out.insert("parentHash".into(), Value::String(to_hex_b256(&header.parent_hash)));
    out.insert("sha3Uncles".into(), Value::String(to_hex_b256(&header.ommers_hash)));
    out.insert(
        "miner".into(),
        // `toJsonHex(getCoinbase().getBytes())`, which writes the null
        // address's no bytes as `0x00`.
        Value::String(header.coinbase().map_or_else(
            || "0x00".to_owned(),
            |coinbase| format!("0x{}", hex::encode(coinbase.as_slice())),
        )),
    );
    out.insert("stateRoot".into(), Value::String(to_hex_b256(&header.state_root)));
    out.insert(
        "transactionsRoot".into(),
        Value::String(to_hex_b256(&header.transactions_root)),
    );
    out.insert("receiptsRoot".into(), Value::String(to_hex_b256(&header.receipts_root)));
    out.insert(
        "logsBloom".into(),
        Value::String(format!("0x{}", hex::encode(header.logs_bloom.as_slice()))),
    );
    out.insert("difficulty".into(), Value::String(to_hex_u256(&header.difficulty)));
    out.insert("number".into(), Value::String(to_hex_u64(header.number)));
    out.insert(
        "gasLimit".into(),
        Value::String(to_hex_quantity_bytes(&header.gas_limit_bytes())),
    );
    out.insert("gasUsed".into(), Value::String(to_hex_u64(header.gas_used)));
    out.insert("timestamp".into(), Value::String(to_hex_u64(header.timestamp)));
    out.insert("extraData".into(), Value::String(to_hex_bytes(header.extra_data.as_ref())));
    out.insert(
        "minimumGasPrice".into(),
        Value::String(to_hex_quantity_bytes(&header.minimum_gas_price_bytes())),
    );
    Value::Object(out)
}
