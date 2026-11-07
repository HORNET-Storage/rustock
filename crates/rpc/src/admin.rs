//! Administrative methods.
//!
//! These act on the node rather than answering questions about the chain, so
//! they are disabled unless the operator passes `--rpc-admin`. The RPC server
//! binds to localhost by default, but "not reachable" is a deployment detail and
//! not an access control decision; a method that deletes a database should
//! require the operator to have asked for it.

use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::B256;
use rustock_storage::epoch_store::EpochTrieStore;
use rustock_storage::pruner::{PruneConfig, MIN_KEEP_DEPTH};
use rustock_storage::BlockStore;
use serde_json::{json, Value};
use std::sync::Arc;

/// Starts a trie collection cycle without stopping the node.
///
/// Collection is normally triggered by size and, on a chain writing ~40 KB of
/// trie per block, that means an epoch fills in days. This exists so a cycle can
/// be run on demand -- to verify the mechanism on real data, or to reclaim space
/// ahead of schedule.
///
/// The cycle runs on a blocking task and the call returns immediately: marking a
/// mainnet live set takes minutes, which is far longer than an RPC should hold a
/// connection. Poll `rsk_collectTrieStatus` for the result.
///
/// Params: `[]` to collect against the default buried block, or `[blockNumber]`
/// to choose the root explicitly.
pub fn rsk_collect_trie(
    id: Value,
    params: &Value,
    store: &Arc<BlockStore>,
    epoch_store: &Option<Arc<EpochTrieStore>>,
    burial: u64,
    pins: Vec<B256>,
) -> JsonRpcResponse {
    let Some(es) = epoch_store.clone() else {
        return JsonRpcResponse::error(
            id,
            METHOD_NOT_FOUND,
            "node is not running the epoch trie backend; start it with --trie-backend epoch",
        );
    };
    if es.is_collecting() {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "a collection cycle is already running");
    }

    // Resolve the root. An explicit block is taken at face value -- the operator
    // is assumed to know what they are asking for -- but the default follows the
    // same burial rule the background trigger uses, because collecting against
    // the head would leave nothing to fall back on after a reorg.
    let explicit = params.as_array().and_then(|a| a.first()).and_then(|v| {
        v.as_u64().or_else(|| {
            v.as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
    });

    let resolved = (|| -> Option<(B256, u64)> {
        let target = match explicit {
            Some(n) => n,
            None => {
                let head_hash = store.head().ok()??;
                let head = store.header(head_hash).ok()??;
                head.number.checked_sub(burial)?
            }
        };
        let hash = store.canonical_hash(target).ok()??;
        let header = store.header(hash).ok()??;
        Some((header.state_root, target))
    })();

    let Some((root, at)) = resolved else {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            "could not resolve a collection root; the chain may not yet be buried deep enough",
        );
    };

    let head_now = store
        .head()
        .ok()
        .flatten()
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(at);
    let store_for_task = es.clone();
    let pin_count = pins.len();
    tokio::spawn(async move {
        match tokio::task::spawn_blocking(move || {
            store_for_task.collect_pinned(root, &pins, at, head_now)
        })
        .await
        {
            Ok(Ok(s)) => {
                for lost in &s.unservable {
                    tracing::warn!(
                        target: "rustock::gc",
                        "Snapshot state {lost:?} is already incomplete; peers asking for it \
                         will be refused"
                    );
                }
                tracing::info!(
                    target: "rustock::gc",
                    "Forced collection complete: marked {} ({} held by {} pin(s)), drained {}, \
                     reclaimed {} MB",
                    s.marked, s.pinned, pin_count, s.drained,
                    s.reclaimed_bytes / (1 << 20)
                )
            }
            Ok(Err(e)) => tracing::error!(target: "rustock::gc", "Forced collection failed: {e:?}"),
            Err(join) => tracing::error!(target: "rustock::gc", "Forced collection panicked: {join}"),
        }
    });

    JsonRpcResponse::success(
        id,
        json!({
            "started": true,
            "block": at,
            "stateRoot": format!("{root:?}"),
        }),
    )
}

/// Reports whether a cycle is running and what the last one did.
pub fn rsk_collect_trie_status(
    id: Value,
    epoch_store: &Option<Arc<EpochTrieStore>>,
) -> JsonRpcResponse {
    let Some(es) = epoch_store else {
        return JsonRpcResponse::error(
            id,
            METHOD_NOT_FOUND,
            "node is not running the epoch trie backend",
        );
    };
    let last = es.last_collect().map(|s| {
        json!({
            "marked": s.marked,
            "scanned": s.scanned,
            "drained": s.drained,
            "drainedBytes": s.drained_bytes,
            "reclaimedBytes": s.reclaimed_bytes,
            "markSeconds": s.mark_secs,
            "drainSeconds": s.drain_secs,
            "sweepSeconds": s.sweep_secs,
        })
    });
    JsonRpcResponse::success(
        id,
        json!({
            "running": es.is_collecting(),
            "epochs": es.epoch_count(),
            "totalBytes": es.total_bytes(),
            "newestBytes": es.newest_bytes(),
            "lastCycle": last,
        }),
    )
}


/// Removes block data below the retention depth, without stopping the node.
///
/// Params: `[]` to let the node choose the boundary from its own head, or
/// `[blockNumber]` to prune everything below a chosen height. An explicit height
/// is still clamped: the node refuses to leave less than `MIN_KEEP_DEPTH` blocks
/// below the head, because Rootstock's block-info precompiles reach 4,000 blocks
/// back and a reorg may re-execute from 4,000 back.
///
/// Runs on a blocking task and returns immediately; poll `rsk_storageStatus`.
pub fn rsk_prune_blocks(
    id: Value,
    params: &Value,
    store: &Arc<BlockStore>,
    keep_depth: u64,
    max_batch: u64,
) -> JsonRpcResponse {
    let head = match store.head().ok().flatten().and_then(|h| store.header(h).ok().flatten()) {
        Some(h) => h.number,
        None => return JsonRpcResponse::error(id, INTERNAL_ERROR, "no chain head"),
    };

    let explicit = params.as_array().and_then(|a| a.first()).and_then(|v| {
        v.as_u64().or_else(|| {
            v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
    });

    // An explicit boundary is expressed as a depth so that the same clamp
    // applies however the caller asked.
    let depth = match explicit {
        Some(below) if below <= head => head - below,
        Some(_) => return JsonRpcResponse::error(id, INVALID_PARAMS, "block is above the head"),
        None => keep_depth,
    };
    let effective = depth.max(MIN_KEEP_DEPTH);
    let clamped = effective != depth;

    // An explicit prune through the admin API means the whole block: there is
    // no way to ask it for a part, and a partial sweep here would differ from
    // what the node's own flags were configured to do.
    let cfg = PruneConfig {
        keep_depth: effective,
        max_batch,
        ..PruneConfig::default()
    };
    // Await the join handle rather than firing and forgetting. A panic inside a
    // detached spawn_blocking is swallowed whole: the first run of this method
    // wrote a floor, deleted nothing, and reported nothing at all, which is
    // indistinguishable from success until someone reads the data back.
    let store_for_task = store.clone();
    tokio::spawn(async move {
        match tokio::task::spawn_blocking(move || store_for_task.prune_blocks(&cfg, head)).await {
            Ok(Ok(s)) => tracing::info!(
                target: "rustock::prune",
                "Forced prune complete: {} blocks removed (#{}..#{})", s.blocks, s.from, s.to
            ),
            Ok(Err(e)) => tracing::error!(target: "rustock::prune", "Forced prune failed: {e:?}"),
            Err(join) => tracing::error!(
                target: "rustock::prune", "Forced prune panicked: {join}"
            ),
        }
    });

    JsonRpcResponse::success(
        id,
        json!({
            "started": true,
            "head": head,
            "keepDepth": effective,
            "clampedToMinimum": clamped,
            "prunesBelow": head.saturating_sub(effective),
        }),
    )
}

/// One place to see what both reclamation mechanisms are doing.
///
/// They are unrelated -- the collector reclaims trie state, the pruner reclaims
/// chain history -- but an operator asking "what is this node deleting and how
/// much does it still hold" wants a single answer.
pub fn rsk_storage_status(
    id: Value,
    store: &Arc<BlockStore>,
    epoch_store: &Option<Arc<EpochTrieStore>>,
) -> JsonRpcResponse {
    let head = store
        .head()
        .ok()
        .flatten()
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number);

    let pruning = match store.prune_floor() {
        Ok(Some(f)) => json!({
            "pruned": true,
            "oldestBlock": f.number,
            "oldestHash": format!("{:?}", f.hash),
            "totalDifficultyAtFloor": f.total_difficulty.to_string(),
            "blocksRetained": head.map(|h| h.saturating_sub(f.number) + 1),
        }),
        Ok(None) => json!({ "pruned": false, "oldestBlock": 0 }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    let collection = match epoch_store {
        None => json!({ "enabled": false }),
        Some(es) => {
            let last = es.last_collect().map(|s| {
                json!({
                    "marked": s.marked,
                    "drained": s.drained,
                    "reclaimedBytes": s.reclaimed_bytes,
                    "markSeconds": s.mark_secs,
                    "sweepSeconds": s.sweep_secs,
                })
            });
            json!({
                "enabled": true,
                "running": es.is_collecting(),
                "epochs": es.epoch_count(),
                "totalBytes": es.total_bytes(),
                "newestBytes": es.newest_bytes(),
                "lastCycle": last,
            })
        }
    };

    JsonRpcResponse::success(
        id,
        json!({ "head": head, "blockPruning": pruning, "trieCollection": collection }),
    )
}

/// `rsk_flush()` — force buffered writes to disk.
///
/// rskj's `RskModuleImpl.flush` calls `flusher.forceFlush()`. Here the same
/// thing means flushing the trie store, which is the one that buffers: the
/// block store's writes go through RocksDB's WAL and are already durable.
///
/// Useful before copying the database, and before pointing a read-only tool at
/// a live store — such a tool sees what has been written, not what is still
/// buffered.
pub fn rsk_flush(id: Value, state: &RpcState) -> JsonRpcResponse {
    match &state.trie_store {
        Some(trie) => {
            trie.flush();
            tracing::info!(target: "rustock::rpc", "rsk_flush: trie store flushed");
            JsonRpcResponse::success(id, json!(true))
        }
        // Answer truthfully rather than claiming a flush that did not happen.
        None => JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            "node has no trie store to flush",
        ),
    }
}

/// `rsk_shutdown()` — stop the node cleanly.
///
/// rskj's `RskModuleImpl.shutdown` calls `nodeStopper.stop(0)`, which is
/// `System::exit`. The same is done here, with one addition that matters more
/// on this node than on rskj: the trie store is flushed **first**.
///
/// That ordering is the whole point of offering this at all. The node catches
/// no signal -- only an rskj import does -- so SIGTERM stops it as abruptly as
/// SIGKILL, and what the trie store holds unflushed is lost. Nothing is
/// corrupted by that: the executed head never advances past what a crash
/// keeps, so the node executes again from there. This gives automation an
/// ordered stop, with nothing to execute again, without needing signal access
/// to the process -- useful for orchestration, and for anything that can
/// reach the RPC port but not the process table.
///
/// The response is sent before the process exits, because a caller that gets
/// no reply cannot tell "shut down" from "crashed".
pub fn rsk_shutdown(id: Value, state: &RpcState) -> JsonRpcResponse {
    if let Some(trie) = &state.trie_store {
        trie.flush();
    }
    tracing::warn!(
        target: "rustock::rpc",
        "rsk_shutdown: stopping the node on RPC request"
    );

    // Exit after the response has had a chance to leave. A short detached
    // delay is crude, but the alternative -- threading a shutdown channel
    // through every task -- is a larger change than this method is worth, and
    // rskj itself simply calls System.exit.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(250));
        std::process::exit(0);
    });

    JsonRpcResponse::success(id, json!(true))
}
