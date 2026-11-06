//! How much state a peer may pull, and how fast.
//!
//! # What is actually scarce
//!
//! Two resources, and only one of them is unbounded.
//!
//! **Computing a cell** is bounded by the cache. A server serves exactly one
//! state -- the checkpoint's; a request naming any other root is refused -- so
//! there are only ever about 9,200 distinct cells. Once they are computed they
//! are on disk, and every request after is a read. The most a peer can make a
//! server compute is one full cache, which is work that then benefits every
//! client after it. That is a bounded cost with a useful side effect, not an
//! attack.
//!
//! **Bytes out** is not bounded by anything. Measured: a peer with the three
//! concurrent requests it is allowed can pull cached cells at roughly
//! 300 MB/s. Nothing in the protocol stops it doing that indefinitely, and
//! egress is the one thing here an operator pays for directly.
//!
//! So the limit is on bytes, because bytes is what is being spent.
//!
//! # Why repeated requests are not tracked
//!
//! The obvious defence against a peer asking for the same cell forever is to
//! remember which cells it has already been given. That defence costs more
//! than the attack: the state is O(peers × cells) -- on mainnet, 9,200 cells
//! against every connected peer -- and a peer that asks for many different
//! cells inflates it deliberately. Turning a bandwidth problem into a memory
//! problem is a bad trade.
//!
//! It is also wrong on the merits. Re-requesting is legitimate: a response can
//! be lost, a client can re-ask a range after another peer's chunk failed
//! verification, and several peers downloading one state will naturally ask
//! for the same cells. A server that refused repeats would break honest
//! clients to inconvenience a dishonest one.
//!
//! Rate limiting subsumes the problem without any of that. A peer asking for
//! the same cell forever is spending its own allowance, exactly as if it had
//! asked for different ones, and the state needed to know that is one bucket
//! per peer -- O(peers), a few dozen bytes each.
//!
//! # Backpressure before refusal
//!
//! A peer over its rate is made to wait rather than told no. Waiting is what a
//! client should do anyway, it needs no protocol support, and because a peer
//! may only have three requests outstanding, one that is being slowed down
//! throttles itself without any further help.
//!
//! Refusal is kept for waits long enough that the client would rather ask
//! somebody else than hold a slot open.

use alloy_primitives::B512;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What to do about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allowance {
    /// Serve it now.
    Now,
    /// Serve it after this long.
    After(Duration),
    /// Tell the peer to go elsewhere; the wait would be longer than it is
    /// worth holding a request slot for.
    Refuse,
}

/// A bucket of bytes that refills at a fixed rate.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(capacity: f64) -> Self {
        Self { tokens: capacity, last: Instant::now() }
    }

    fn refill(&mut self, rate: f64, capacity: f64, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(capacity);
        self.last = now;
    }

    /// How long a taker would have to wait for `bytes`, changing nothing.
    fn wait_for(&self, bytes: f64, rate: f64) -> Duration {
        if self.tokens >= bytes {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((bytes - self.tokens) / rate)
        }
    }

    /// Spends `bytes`, which may put the bucket into debt -- the debt is what
    /// the wait pays off.
    fn charge(&mut self, bytes: f64) {
        self.tokens -= bytes;
    }

    fn is_full(&self, capacity: f64) -> bool {
        self.tokens >= capacity
    }
}

/// Per-peer and whole-server limits on state served.
pub struct RateLimiter {
    per_peer: f64,
    global: f64,
    /// How much unused allowance may accumulate, as seconds of rate. A little
    /// burst lets an honest client's parallel requests go out together
    /// instead of being spread into a stutter.
    burst_seconds: f64,
    /// Longer than this and the peer is refused instead of made to wait.
    max_wait: Duration,
    /// Beyond this many tracked peers, idle buckets are dropped. A full bucket
    /// carries no information -- it is indistinguishable from a peer that has
    /// never asked -- so dropping it costs nothing. When that frees no room,
    /// the bucket nearest full makes way for the newcomer, so the map never
    /// holds more than this.
    capacity: usize,
    state: Mutex<State>,
}

struct State {
    global: Bucket,
    peers: HashMap<B512, Bucket>,
}

impl RateLimiter {
    pub fn new(per_peer: u64, global: u64, max_wait: Duration, capacity: usize) -> Self {
        let per_peer = per_peer.max(1) as f64;
        let global = global.max(1) as f64;
        let burst_seconds = 2.0;
        Self {
            per_peer,
            global,
            burst_seconds,
            max_wait,
            capacity: capacity.max(16),
            state: Mutex::new(State {
                global: Bucket::full(global * burst_seconds),
                peers: HashMap::new(),
            }),
        }
    }

    /// May this peer be served `bytes`, and after how long?
    ///
    /// Both buckets are charged, so a peer cannot evade the whole-server limit
    /// by being well behaved on its own, and the wait is the longer of the
    /// two.
    pub fn allow(&self, peer: B512, bytes: u64) -> Allowance {
        let Ok(mut state) = self.state.lock() else { return Allowance::Now };
        let now = Instant::now();
        let bytes = bytes as f64;

        let peer_capacity = self.per_peer * self.burst_seconds;
        let global_capacity = self.global * self.burst_seconds;

        if state.peers.len() >= self.capacity {
            let cap = peer_capacity;
            state.peers.retain(|_, b| {
                b.refill(self.per_peer, cap, now);
                !b.is_full(cap)
            });
            // Dropping full buckets alone bounds nothing while peers arrive
            // faster than buckets refill: in a release build, 5,000 new peers
            // asking once each left about 150 behind against a bound of 64.
            // A newcomer that still finds no room takes the place of the peer
            // nearest to full, which forgives the smallest debt there is; the
            // whole-server bucket still holds everyone to the total.
            if !state.peers.contains_key(&peer) {
                while state.peers.len() >= self.capacity {
                    let Some(nearest) = state
                        .peers
                        .iter()
                        .max_by(|a, b| a.1.tokens.total_cmp(&b.1.tokens))
                        .map(|(p, _)| *p)
                    else {
                        break;
                    };
                    state.peers.remove(&nearest);
                }
            }
        }

        state.global.refill(self.global, global_capacity, now);
        let global_wait = state.global.wait_for(bytes, self.global);

        let bucket = state
            .peers
            .entry(peer)
            .or_insert_with(|| Bucket::full(peer_capacity));
        bucket.refill(self.per_peer, peer_capacity, now);
        let peer_wait = bucket.wait_for(bytes, self.per_peer);

        let wait = peer_wait.max(global_wait);
        if wait > self.max_wait {
            // Refused, and so not charged. Charging for an answer never sent
            // would let a peer dig itself deeper for nothing, and would
            // punish an honest client that happened to arrive while the
            // whole-server limit was binding.
            return Allowance::Refuse;
        }

        // Only what will actually be served is spent, which also bounds the
        // debt: at most one request's worth beyond empty, so the wait can
        // never exceed `max_wait`.
        bucket.charge(bytes);
        state.global.charge(bytes);

        if wait.is_zero() {
            Allowance::Now
        } else {
            Allowance::After(wait)
        }
    }

    /// Peers currently tracked, for tests and for knowing the map is bounded.
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.state.lock().map(|s| s.peers.len()).unwrap_or(0)
    }
}
