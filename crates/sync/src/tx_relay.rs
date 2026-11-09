use std::num::NonZeroUsize;
use std::sync::{Mutex, PoisonError};

use alloy_primitives::{B256, B512, Bytes};
use lru::LruCache;
use rustock_networking::peers::PeerStore;
use rustock_networking::protocol::rsk::{RskMessage, RskSubMessage};
use rustock_networking::protocol::{P2pHandler, P2pMessage};
use rustock_networking::scoring::{EventType, ScoringService};
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tracing::{debug, trace};

use crate::txpool::TransactionPool;

const SEEN_CACHE_SIZE: usize = 32_768;

pub struct TxRelay {
    peer_store: Arc<PeerStore>,
    seen: Mutex<LruCache<B256, ()>>,
    pool: Option<Arc<TransactionPool>>,
    scoring: Option<Arc<ScoringService>>,
    events: Option<rustock_core::events::EventSender>,
}

impl TxRelay {
    pub fn new(peer_store: Arc<PeerStore>) -> Self {
        Self {
            peer_store,
            seen: Mutex::new(LruCache::new(
                NonZeroUsize::new(SEEN_CACHE_SIZE).expect("SEEN_CACHE_SIZE is non-zero"),
            )),
            pool: None,
            scoring: None,
            events: None,
        }
    }

    pub fn with_pool(peer_store: Arc<PeerStore>, pool: Arc<TransactionPool>) -> Self {
        Self {
            peer_store,
            seen: Mutex::new(LruCache::new(
                NonZeroUsize::new(SEEN_CACHE_SIZE).expect("SEEN_CACHE_SIZE is non-zero"),
            )),
            pool: Some(pool),
            scoring: None,
            events: None,
        }
    }

    fn tx_hash(data: &[u8]) -> B256 {
        B256::from_slice(&Keccak256::digest(data))
    }

    /// Attach peer scoring, so a peer flooding invalid transactions is
    /// counted. rskj records `VALID_TRANSACTION` / `INVALID_TRANSACTION` from
    /// `MessageVisitor.apply(TransactionsMessage)` for the same reason.
    pub fn with_scoring(mut self, scoring: Option<Arc<ScoringService>>) -> Self {
        self.scoring = scoring;
        self
    }

    /// Attach the chain-event channel, so `eth_subscribe("newPendingTransactions")`
    /// hears about transactions that enter the pool.
    pub fn with_events(mut self, events: Option<rustock_core::events::EventSender>) -> Self {
        self.events = events;
        self
    }

    /// Announce a transaction the pool accepted.
    ///
    /// Only accepted ones: a subscriber asked what is *pending*, and a
    /// transaction the pool refused never was.
    fn announce_pending(&self, hash: B256) {
        let Some(events) = &self.events else { return };
        if events.receiver_count() == 0 {
            return;
        }
        let _ = events.send(rustock_core::events::ChainEvent::PendingTransaction(hash));
    }

    fn filter_and_validate(&self, txs: &[Bytes], from: Option<B512>) -> Vec<Bytes> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let mut valid_txs = Vec::new();
        for tx_bytes in txs {
            let hash = Self::tx_hash(tx_bytes);
            if seen.get(&hash).is_some() {
                continue;
            }
            seen.put(hash, ());

            if let Some(pool) = &self.pool {
                let accepted = pool.add_transaction(tx_bytes);
                if let (Some(scoring), Some(from)) = (&self.scoring, from) {
                    // INVALID_TRANSACTION drives the score negative in rskj,
                    // but it is **not** one of the three counters that decide
                    // reputation -- so a peer relaying junk is recorded and
                    // scored down without being punished for it. That is
                    // rskj's choice: transaction validity depends on local
                    // state a peer may legitimately not share.
                    scoring.record_peer(
                        from,
                        if accepted.is_ok() {
                            EventType::ValidTransaction
                        } else {
                            EventType::InvalidTransaction
                        },
                    );
                }
                match accepted {
                    Ok(_) => {
                        self.announce_pending(hash);
                        valid_txs.push(tx_bytes.clone())
                    }
                    Err(e) => {
                        trace!(tx_hash = %hash, err = %e, "Rejected incoming transaction");
                    }
                }
            } else {
                valid_txs.push(tx_bytes.clone());
            }
        }
        valid_txs
    }

    /// Submit a raw transaction from the RPC layer. Returns the tx hash or an error.
    pub async fn submit_transaction(&self, raw_tx: Bytes) -> Result<B256, String> {
        let hash = if let Some(pool) = &self.pool {
            pool.add_transaction(&raw_tx).map_err(|e| format!("{e}"))?
        } else {
            Self::tx_hash(&raw_tx)
        };

        {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            seen.put(hash, ());
        }
        self.announce_pending(hash);

        let msg = P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::Transactions(vec![raw_tx]),
        ));
        let sent = self.peer_store.broadcast(msg, &[]).await;
        debug!(tx_hash = %hash, peers = sent, "Broadcast submitted transaction");
        Ok(hash)
    }

    pub fn pool(&self) -> Option<&Arc<TransactionPool>> {
        self.pool.as_ref()
    }
}

impl P2pHandler for TxRelay {
    fn handle_message(&self, id: B512, msg: &P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            if let RskSubMessage::Transactions(txs) = &m.sub_message {
                let valid_txs = self.filter_and_validate(txs, Some(id));
                if valid_txs.is_empty() {
                    trace!(from = %id, "No valid new transactions to relay");
                    return None;
                }

                debug!(
                    from = %id,
                    total = txs.len(),
                    valid = valid_txs.len(),
                    "Relaying validated transactions"
                );

                let relay_msg = P2pMessage::RskMessage(RskMessage::new(
                    RskSubMessage::Transactions(valid_txs),
                ));
                let peer_store = self.peer_store.clone();
                let sender = id;
                tokio::spawn(async move {
                    peer_store.broadcast(relay_msg, &[sender]).await;
                });
            }
        }
        None
    }
}
