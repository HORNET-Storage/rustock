use crate::node::{NodeConfig, register_and_run_session, HANDSHAKE_TIMEOUT};
use crate::discovery::table::NodeTable;
use crate::protocol::P2pHandler;
use crate::handshake::Handshake;
use crate::peers::PeerStore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration, Instant};
use tracing::{info, trace, warn, debug};
use tokio::net::TcpStream;

/// TCP connect timeout for an outbound dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an in-flight dial may stay "pending" before we assume the dial task
/// died without cleaning up (defensive; tasks normally clear their own entry).
/// Must exceed CONNECT_TIMEOUT + HANDSHAKE_TIMEOUT.
const PENDING_EXPIRY: Duration = Duration::from_secs(30);
/// Exponential backoff bounds for repeatedly-failing addresses.
const BACKOFF_BASE: u64 = 30;
const BACKOFF_MAX: u64 = 600;

/// Per-address failure backoff. Replaces the old blanket "failed" set: a node
/// that keeps failing is dialed exponentially less often, while a node that
/// fails once (e.g. a transient blip) is retried again quickly — so a network
/// hiccup no longer parks every good peer for a fixed cooldown.
#[derive(Clone)]
struct Backoff {
    fails: u32,
    retry_after: Instant,
}

/// Backoff delay after `fails` consecutive failures: 30s, 60s, 120s, 240s,
/// 480s, capped at 600s.
fn backoff_delay(fails: u32) -> Duration {
    let shift = fails.saturating_sub(1).min(5);
    Duration::from_secs((BACKOFF_BASE << shift).min(BACKOFF_MAX))
}

/// Whether `addr` may be dialed now: not already in-flight (pending) and not
/// within an active backoff window.
fn is_dialable(
    addr: &SocketAddr,
    pending: &HashMap<SocketAddr, Instant>,
    backoff: &HashMap<SocketAddr, Instant>,
    now: Instant,
) -> bool {
    if pending.contains_key(addr) {
        return false;
    }
    match backoff.get(addr) {
        Some(retry_after) => now >= *retry_after,
        None => true,
    }
}

/// Cumulative outbound-dial outcome counters, surfaced by the peer heartbeat to
/// make peer-replenishment problems diagnosable without per-dial debug logging.
#[derive(Default)]
struct DialStats {
    attempts: AtomicU64,
    successes: AtomicU64,
    handshake_failed: AtomicU64,
    handshake_timeout: AtomicU64,
    connect_failed: AtomicU64,
}

/// Service that proactively initiates connections to peers discovered in the network.
pub struct OutboundConnector {
    config: NodeConfig,
    table: Arc<RwLock<NodeTable>>,
    peer_store: Arc<PeerStore>,
    handlers: Vec<Arc<dyn P2pHandler>>,
    max_outbound: usize,
    scoring: Option<Arc<crate::scoring::ScoringService>>,
}

impl OutboundConnector {
    pub fn new(
        config: NodeConfig,
        table: Arc<RwLock<NodeTable>>,
        peer_store: Arc<PeerStore>,
        handlers: Vec<Arc<dyn P2pHandler>>,
        max_outbound: usize
    ) -> Self {
        Self { config, table, peer_store, handlers, max_outbound, scoring: None }
    }

    /// Attach peer scoring, so a banned or punished address is never dialed.
    pub fn with_scoring(mut self, scoring: Option<Arc<crate::scoring::ScoringService>>) -> Self {
        self.scoring = scoring;
        self
    }

    /// Starts the outbound connection loop.
    ///
    /// Dials toward `max_outbound` peers, using a short interval while below
    /// target and backing off once met. Tracks in-flight dials (so a node is
    /// never dialed twice at once) and applies per-address exponential backoff
    /// to repeatedly-failing nodes (rskj `SyncPool`: pendingConnections +
    /// node reputation).
    pub async fn start(self) {
        info!(target: "rustock::net", "Outbound connector started (target outbound: {})", self.max_outbound);

        const ACTIVE_INTERVAL: Duration = Duration::from_secs(10);
        const IDLE_INTERVAL: Duration = Duration::from_secs(60);

        // In-flight dials (addr -> dial start) and per-address failure backoff.
        let pending: Arc<Mutex<HashMap<SocketAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let backoff: Arc<Mutex<HashMap<SocketAddr, Backoff>>> = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(DialStats::default());

        // Throttling state for the "no dialable candidates" warning.

        let mut last_starved: Option<(usize, usize, usize, usize)> = None;

        // `None` until the first warning. Subtracting a minute from `now` would
        // panic on a machine booted less than a minute ago, since the clock
        // `Instant` reads starts at boot.
        let mut last_starved_at: Option<Instant> = None;


        loop {
            let current_count = self.peer_store.count().await;
            let table_size = self.table.read().await.len();

            // Drop stale pending entries whose dial task never cleaned up.
            {
                let now = Instant::now();
                pending.lock().await.retain(|_, started| now.duration_since(*started) < PENDING_EXPIRY);
            }
            let pending_count = pending.lock().await.len();
            let backoff_count = backoff.lock().await.len();

            // Heartbeat: peers vs. discovered-node pool vs. cumulative dial
            // outcomes. Logged every cycle (60s when healthy, 10s when below
            // target) so a stuck-below-target state is visible at DEBUG.
            debug!(
                target: "rustock::net",
                "Peer heartbeat: {}/{} peers | {} nodes ({} pending, {} backoff) | dials: {} ok / {} hs-fail / {} hs-timeout / {} conn-fail ({} attempts)",
                current_count, self.max_outbound, table_size, pending_count, backoff_count,
                stats.successes.load(Ordering::Relaxed),
                stats.handshake_failed.load(Ordering::Relaxed),
                stats.handshake_timeout.load(Ordering::Relaxed),
                stats.connect_failed.load(Ordering::Relaxed),
                stats.attempts.load(Ordering::Relaxed),
            );

            if current_count >= self.max_outbound {
                sleep(IDLE_INTERVAL).await;
                continue;
            }

            let needed = self.max_outbound - current_count;
            let nodes = self.table.read().await.all_nodes();

            // Try more candidates than needed since many will fail.
            let attempt_limit = std::cmp::min(needed * 3, nodes.len());

            // Snapshot pending + backoff retry times so we don't hold either lock
            // across the candidate loop.
            let now = Instant::now();
            let pending_snapshot = pending.lock().await.clone();
            let backoff_snapshot: HashMap<SocketAddr, Instant> = backoff
                .lock()
                .await
                .iter()
                .map(|(addr, b)| (*addr, b.retry_after))
                .collect();

            let mut attempted = 0;
            for node in nodes {
                if attempted >= attempt_limit {
                    break;
                }

                if self.peer_store.is_connected(&node.id).await {
                    continue;
                }

                let Some(ip) = crate::utils::bytes_to_ip(&node.ip) else { continue };
                let addr = SocketAddr::new(ip, node.tcp_port);

                if !is_dialable(&addr, &pending_snapshot, &backoff_snapshot, now) {
                    continue;
                }

                // Do not dial a peer we would refuse on arrival. Without this
                // the connector spends its attempt budget on hosts that will
                // be dropped, which is how a node ends up under target while
                // the discovery table looks full.
                if let Some(scoring) = &self.scoring {
                    if !scoring.address_is_welcome(ip) || !scoring.node_is_welcome(node.id) {
                        continue;
                    }
                }

                pending.lock().await.insert(addr, Instant::now());

                let scoring = self.scoring.clone();
                let config = self.config.clone();
                let handlers = self.handlers.clone();
                let peer_store = self.peer_store.clone();
                let remote_id = node.id;
                let pending = pending.clone();
                let backoff = backoff.clone();
                let stats = stats.clone();

                tokio::spawn(async move {
                    stats.attempts.fetch_add(1, Ordering::Relaxed);
                    let outcome = dial(addr, remote_id, config, handlers, peer_store, &stats, scoring).await;
                    pending.lock().await.remove(&addr);
                    let mut bo = backoff.lock().await;
                    match outcome {
                        DialOutcome::Connected => {
                            bo.remove(&addr); // recovered — clear any backoff
                        }
                        DialOutcome::Failed => {
                            let entry = bo.entry(addr).or_insert(Backoff { fails: 0, retry_after: Instant::now() });
                            entry.fails += 1;
                            entry.retry_after = Instant::now() + backoff_delay(entry.fails);
                        }
                    }
                });

                attempted += 1;
            }

            if attempted == 0 && current_count < self.max_outbound && table_size > 0 {
                // Everything is connected, in-flight, or backed off. No blanket
                // clear (that used to re-stampede dead nodes); backoff windows
                // expire on their own and good nodes return quickly.
                //
                // This is a standing condition, not an event: a node pinned to
                // one peer, or one whose table is entirely backed off, is in it
                // continuously. Logged every round it filled the log with the
                // same line every ten seconds and buried everything else, so
                // report a *change* immediately and an unchanged state only
                // once a minute -- often enough to show the node is still in
                // it, rare enough to read around.
                let now = (
                    current_count,
                    table_size,
                    pending_snapshot.len(),
                    backoff_snapshot.len(),
                );
                let changed = last_starved != Some(now);
                if changed || last_starved_at.is_none_or(|at| at.elapsed() >= STARVED_REPEAT) {
                    warn!(
                        target: "rustock::net",
                        "Below target ({}/{}) but no dialable candidates ({} nodes, {} pending, {} backed off)",
                        now.0, self.max_outbound, now.1, now.2, now.3
                    );
                    last_starved = Some(now);
                    last_starved_at = Some(Instant::now());
                }
            } else {
                // Out of the condition: say so next time it happens.
                last_starved = None;
            }

            sleep(ACTIVE_INTERVAL).await;
        }
    }
}

/// How often to repeat the "no dialable candidates" warning while nothing
/// about the situation changes.
const STARVED_REPEAT: Duration = Duration::from_secs(60);

/// Outcome of a single outbound dial, used to drive backoff.
enum DialOutcome {
    Connected,
    Failed,
}

/// Performs one outbound dial: TCP connect → handshake → run the session.
/// Returns `Connected` once a session was established (it ran to completion
/// inside this call), or `Failed` on any connect/handshake error or timeout.
async fn dial(
    addr: SocketAddr,
    remote_id: alloy_primitives::B512,
    config: NodeConfig,
    handlers: Vec<Arc<dyn P2pHandler>>,
    peer_store: Arc<PeerStore>,
    stats: &DialStats,
    scoring: Option<Arc<crate::scoring::ScoringService>>,
) -> DialOutcome {
    let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            debug!(target: "rustock::net", "Failed to connect to outbound peer {}: {:?}", addr, e);
            return DialOutcome::Failed;
        }
        Err(_) => {
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            trace!(target: "rustock::net", "TCP connect timed out for {}", addr);
            return DialOutcome::Failed;
        }
    };

    trace!(target: "rustock::net", "TCP connected to outbound peer: {}", addr);
    let handshake = Handshake::new(stream, config, Some(remote_id));
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake.run()).await {
        Ok(Ok((peer_id, rsk_status, caps, framed))) => {
            stats.successes.fetch_add(1, Ordering::Relaxed);
            debug!(target: "rustock::net", "Outbound handshake successful: {:?}", &peer_id.as_slice()[..4]);
            let _ = register_and_run_session(
                peer_id,
                rsk_status,
                caps,
                framed,
                handlers,
                peer_store,
                scoring,
                Some(addr.ip()),
            )
            .await;
            // Session ended (peer disconnected) — treat as a successful contact,
            // not a failure: it was a valid peer that may accept again later.
            DialOutcome::Connected
        }
        Ok(Err(e)) => {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            debug!(target: "rustock::net", "Outbound handshake failed for {}: {:?}", addr, e);
            DialOutcome::Failed
        }
        Err(_) => {
            stats.handshake_timeout.fetch_add(1, Ordering::Relaxed);
            debug!(target: "rustock::net", "Outbound handshake timed out for {}", addr);
            DialOutcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, n], 5050))
    }

    #[test]
    fn backoff_delay_grows_then_caps() {
        assert_eq!(backoff_delay(1), Duration::from_secs(30));
        assert_eq!(backoff_delay(2), Duration::from_secs(60));
        assert_eq!(backoff_delay(3), Duration::from_secs(120));
        assert_eq!(backoff_delay(4), Duration::from_secs(240));
        assert_eq!(backoff_delay(5), Duration::from_secs(480));
        // Capped at BACKOFF_MAX thereafter (30 << 5 = 960 -> 600).
        assert_eq!(backoff_delay(6), Duration::from_secs(600));
        assert_eq!(backoff_delay(100), Duration::from_secs(600));
    }

    #[test]
    fn dialable_skips_pending_and_active_backoff() {
        let now = Instant::now();
        let mut pending = HashMap::new();
        let mut backoff = HashMap::new();

        // Fresh address with no state: dialable.
        assert!(is_dialable(&addr(1), &pending, &backoff, now));

        // In-flight: not dialable.
        pending.insert(addr(1), now);
        assert!(!is_dialable(&addr(1), &pending, &backoff, now));

        // Backed off into the future: not dialable.
        backoff.insert(addr(2), now + Duration::from_secs(60));
        assert!(!is_dialable(&addr(2), &pending, &backoff, now));

        // Backoff window already elapsed: dialable again.
        backoff.insert(addr(3), now - Duration::from_secs(1));
        assert!(is_dialable(&addr(3), &pending, &backoff, now));
    }
}
