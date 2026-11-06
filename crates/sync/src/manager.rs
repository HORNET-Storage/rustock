use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::protocol::{
    BlockHeadersQuery, BlockHeadersRequest, BlockHeadersWithUnclesRequest, HeaderWithUncles,
    P2pMessage, RskMessage, RskSubMessage,
};
use alloy_primitives::{B256, B512, U256};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, trace, warn};

use crate::unlinked::{UnlinkedHeaders, Verdict};

/// Maximum skeleton chunks to process per round (rskj default: 20).
pub(crate) const MAX_SKELETON_CHUNKS: usize = 20;

/// What one batch of headers did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Ingested {
    /// Headers written to the store.
    pub stored: u64,
    /// Headers that failed verification against a parent we hold.
    pub rejected: u64,
    /// Headers with no parent to verify against, kept only as evidence.
    pub unlinked: u64,
}

/// Validates and stores headers.
pub struct SyncManager {
    pub store: Arc<BlockStore>,
    verifier: Arc<HeaderVerifier>,
    pub peer_store: Arc<rustock_networking::peers::PeerStore>,
    /// Headers whose named parent this node does not hold, counted per peer.
    ///
    /// Evidence that a peer is offering a chain we cannot connect to. Never a
    /// chain itself: see [`crate::unlinked`].
    unlinked: Mutex<UnlinkedHeaders>,
    /// The uncle lists seen so far, so the full uncle rule can run without
    /// bodies. See [`crate::uncle_guard`].
    uncle_guard: Mutex<crate::uncle_guard::UncleGuard>,
    /// Cumulative difficulties proved by uncles a peer sent with the header.
    ///
    /// A header alone cannot yield one: uncle difficulty counts toward total
    /// difficulty and uncle headers travel only in the body. When a peer at
    /// `rsk/63` supplies them, the figure is recorded here so the ordinary
    /// ingest path -- which receives only headers -- can use it instead of the
    /// header difficulty. Bounded, because it is an optimisation and a peer
    /// could otherwise grow it without limit.
    proven: Mutex<HashMap<B256, U256>>,
}

/// How many proved cumulative difficulties to keep. A skeleton chunk is 192
/// headers and several are in flight at once, so this holds many chunks'
/// worth while staying a fixed, small cost.
const MAX_PROVEN: usize = 8192;

impl SyncManager {
    pub fn new(
        store: Arc<BlockStore>,
        verifier: Arc<HeaderVerifier>,
        peer_store: Arc<rustock_networking::peers::PeerStore>,
    ) -> Self {
        Self {
            store,
            verifier,
            peer_store,
            unlinked: Mutex::new(UnlinkedHeaders::new()),
            uncle_guard: Mutex::new(crate::uncle_guard::UncleGuard::new()),
            proven: Mutex::new(HashMap::new()),
        }
    }

    /// Handles a batch of headers received from a peer.
    /// RSK peers return headers in descending order (from requested hash toward genesis).
    /// We reverse them, validate, and store in a single atomic RocksDB WriteBatch.
    pub fn handle_headers_response(&self, headers: Vec<Header>, peer: B512) -> Result<Ingested> {
        self.ingest_headers(headers, Some(peer))
    }

    /// Record the cumulative difficulties proved by `entries`, and hand back
    /// the bare headers for the ordinary ingest path.
    ///
    /// The decoder has already refused any entry whose uncle list does not
    /// match the trunk header's `ommers_hash`, so these figures are as sound
    /// as the header's own proof of work.
    pub fn note_proven_difficulties(&self, entries: Vec<HeaderWithUncles>) -> Vec<Header> {
        let mut proven = self.proven.lock().unwrap();
        if proven.len() + entries.len() > MAX_PROVEN {
            // Everything in here is re-derivable from a later request, so
            // dropping the lot is cheaper than tracking an eviction order.
            proven.clear();
        }
        entries
            .into_iter()
            .map(|entry| {
                // Record the proven figure only when it *is* proven. Two
                // things have to hold, and neither is implied by the other:
                //
                //  - `ommers_hash` is inside what the trunk header's proof of
                //    work commits to, so a list matching it cannot have been
                //    added to, dropped from or altered;
                //  - each uncle carries its own merged-mining proof of work,
                //    because a matching commitment only proves the block's
                //    miner *chose* this list, not that the difficulty each
                //    uncle states was ever performed.
                //
                // Without both, `cumulative_difficulty()` is whatever the
                // sender wrote. A peer could take real headers off the real
                // chain, attach fabricated uncles, and inflate the total
                // difficulty this node records for them -- the input to chain
                // selection -- by up to the consensus uncle limit, without
                // mining anything.
                //
                // A header that fails either check still goes through as a
                // bare header: it is a header like any other and the ordinary
                // path verifies it. Only the uncle-derived difficulty is
                // withheld, which leaves the total understated rather than
                // overstated, and understated is the safe direction.
                if self.uncles_are_proven(&entry) {
                    proven.insert(entry.header.hash(), entry.cumulative_difficulty());
                }
                entry.header
            })
            .collect()
    }

    /// Whether the uncles sent with a header are the ones it commits to, and
    /// each did the work it claims.
    fn uncles_are_proven(&self, entry: &HeaderWithUncles) -> bool {
        // The commitment binds the list to the trunk header's proof of work.
        // Everything after it is about a list the block really chose rather
        // than one the sender assembled.
        if !entry.commitment_matches() {
            warn!(
                target: "rustock::sync",
                "Block #{} came with uncles its header does not commit to; \
                 ignoring the difficulty they would have proved",
                entry.header.number
            );
            return false;
        }

        // Then the whole of rskj's uncle rule. Commitment and proof of work
        // alone would still let a miner reference one real uncle under
        // several of its own blocks and have the work counted each time --
        // capped only by `uncleListLimit`, so up to eleven times the trunk
        // work actually performed.
        let mut guard = self.uncle_guard.lock().unwrap();
        if let Err(why) = guard.uncles_are_admissible(
            &self.store,
            &self.verifier,
            &entry.header,
            &entry.uncles,
        ) {
            warn!(
                target: "rustock::sync",
                "Block #{}: uncles not admissible ({why}); ignoring the \
                 difficulty they would have proved",
                entry.header.number
            );
            return false;
        }
        guard.record(&entry.header, entry.uncles.clone());
        true
    }

    /// What a block adds to the chain's work from what this node holds: with
    /// its uncles in hand, its own difficulty and theirs once they pass the
    /// whole uncle rule; without, its own difficulty alone, the lower bound a
    /// bare header gives.
    fn held_contribution(&self, hash: B256, header: &Header) -> U256 {
        let Some(uncles) = crate::total_difficulty::held_uncles(&self.store, hash, header) else {
            return header.difficulty;
        };
        match crate::total_difficulty::credited_uncles(&self.store, &self.verifier, header, &uncles) {
            Ok(credited) => header.difficulty.saturating_add(credited),
            Err(why) => {
                debug!(
                    target: "rustock::sync",
                    "Block #{}: its uncles are not credited with their difficulty: {why}",
                    header.number
                );
                header.difficulty
            }
        }
    }

    /// Settle the total difficulty of each of `blocks`, oldest first, now that
    /// their bodies are held. See [`crate::total_difficulty`].
    ///
    /// Stops at the first it cannot settle, a block without its body or whose
    /// parent has no total, because every total above it would start from a
    /// bound. Returns how many it settled.
    pub(crate) fn settle_total_difficulties(&self, blocks: &[(B256, Header)]) -> usize {
        for (settled, (hash, header)) in blocks.iter().enumerate() {
            let Ok(Some(uncles)) = self.store.uncles(*hash) else {
                return settled;
            };
            if !self.settle_total_difficulty(*hash, header, &uncles) {
                return settled;
            }
        }
        blocks.len()
    }

    /// Settle one block's total difficulty from the uncles its body names.
    /// `false` when it cannot be settled: its parent has no total, or the
    /// store failed.
    pub(crate) fn settle_total_difficulty(&self, hash: B256, header: &Header, uncles: &[Header]) -> bool {
        match crate::total_difficulty::settle(&self.store, &self.verifier, hash, header, uncles) {
            Ok(settled) => settled.is_some(),
            Err(e) => {
                warn!(
                    target: "rustock::sync",
                    "Could not settle the total difficulty of #{} ({:?}): {e}",
                    header.number, hash
                );
                false
            }
        }
    }

    /// The body of [`Self::handle_headers_response`], with the peer optional so
    /// that paths without an attributable sender can still store headers. A
    /// header with no parent from such a path is dropped and charged to nobody,
    /// because evidence without an owner is what this design exists to avoid.
    fn ingest_headers(&self, mut headers: Vec<Header>, peer: Option<B512>) -> Result<Ingested> {
        if headers.is_empty() {
            trace!(target: "rustock::sync", "Received empty headers response");
            return Ok(Ingested::default());
        }

        // RSK returns headers in descending order; reverse for ascending processing
        if headers.len() > 1 && headers[0].number > headers[headers.len() - 1].number {
            headers.reverse();
        }

        let first_num = headers.first().map(|h| h.number).unwrap_or(0);
        let last_num = headers.last().map(|h| h.number).unwrap_or(0);
        trace!(
            target: "rustock::sync",
            "Processing {} headers (#{} -> #{})",
            headers.len(),
            first_num,
            last_num
        );

        // Read current head TD once (instead of per-header)
        let current_head_hash = self.store.head()?;
        let current_td = match current_head_hash {
            Some(h) => self.store.total_difficulty(h)?.unwrap_or_default(),
            None => U256::ZERO,
        };

        // Propagate total difficulty positionally through the chunk, but never
        // *identify the parent* positionally. Headers in a chunk are normally a
        // chain, so the previous entry is usually the parent -- but "usually" is
        // not a rule the consensus check may rely on. A chunk can carry a fork
        // header at a height it already covered, or arrive out of order, and
        // then the previous entry is a different block at the right height, or
        // the right block at the wrong height.
        //
        // Verifying a header against anything other than the block its own
        // `parent_hash` names produces a wrong expected difficulty and rejects
        // valid chain data. That was observed on mainnet: #9,236,893 was checked
        // against #9,236,891, whose timestamp is 34s earlier rather than 7s, so
        // the adjustment sign flipped and the expected difficulty came out 0.75%
        // low. A rejected header writes no canonical entry, and the resulting
        // hole in the index later wedged execution entirely.
        let mut prev_in_chunk: Option<(&Header, U256)> = None;
        let mut validated: Vec<(&Header, U256)> = Vec::with_capacity(headers.len());
        let mut skipped = 0u64;
        let mut unlinked_here = 0u64;
        let now = Instant::now();
        // Deduplicate by hash, not by block number. Two different blocks may
        // legitimately share a height -- that is what a fork is -- and dropping
        // the second means dropping whichever of them arrived last, which may be
        // the canonical one.
        let mut seen: std::collections::HashSet<B256> = std::collections::HashSet::new();

        for header in &headers {
            let hash = header.hash();
            if !seen.insert(hash) {
                continue;
            }

            let already_stored = self.store.header(hash)?.is_some();

            // What this block adds to the chain's work: its own difficulty and
            // its uncles', and uncle headers travel only in the body. In order
            // of what can be proved: the uncles this peer sent with the header;
            // then the uncles of a body this node holds, once they pass the
            // whole uncle rule; otherwise -- plain header-first sync from an
            // `rsk/62` peer, which is every rskj node -- the header difficulty
            // alone. That is a lower bound, and `crate::total_difficulty`
            // settles it once the body is in.
            let proven = self.proven.lock().unwrap().get(&hash).copied();
            let contribution = proven.unwrap_or_else(|| self.held_contribution(hash, header));

            // The parent is the block named by `parent_hash`, and nothing else.
            // Take it from the chunk when the previous entry *is* that block,
            // otherwise from the store.
            #[allow(unused_assignments)]
            let mut parent_from_store: Option<Header> = None;
            let parent_ref: Option<&Header>;
            let parent_td: U256;

            match prev_in_chunk {
                Some((prev_hdr, prev_td)) if prev_hdr.hash() == header.parent_hash => {
                    parent_ref = Some(prev_hdr);
                    parent_td = prev_td;
                }
                _ => {
                    parent_from_store = self.store.header(header.parent_hash)?;
                    if parent_from_store.is_some() {
                        parent_ref = parent_from_store.as_ref();
                        parent_td = self
                            .store
                            .total_difficulty(header.parent_hash)?
                            .unwrap_or_default();
                    } else if already_stored {
                        // Held already, so it was verified when it was first
                        // stored. Carry its committed total difficulty rather
                        // than recomputing one from a parent of zero, which
                        // would rewrite a real chain's weight downward. What
                        // the block adds is taken off here and added back
                        // below, so the total stays as stored; taking off its
                        // own difficulty alone would count its uncles twice
                        // once its total holds them.
                        parent_ref = None;
                        parent_td = self
                            .store
                            .total_difficulty(hash)?
                            .unwrap_or_default()
                            .saturating_sub(contribution);
                    } else {
                        // The named parent is not held, so there is nothing to
                        // verify this header against. Storing it anyway is how
                        // an unauthenticated header used to reach the store and
                        // take a total difficulty derived from a parent of
                        // zero -- that is, whatever the sender wrote in the
                        // `difficulty` field -- and on that basis move the head.
                        //
                        // Do not substitute the canonical block at `number - 1`
                        // either: it is a different block, and checking against
                        // it rejects valid headers.
                        //
                        // Keep it as evidence instead. A peer offering a chain
                        // we cannot connect to is a signal to go and find where
                        // the two diverge, and everything fetched after that
                        // search is verified normally.
                        unlinked_here += 1;
                        if let Some(p) = peer {
                            self.unlinked.lock().unwrap().record(p, hash, header.number, now);
                        }
                        // Deliberately leave `prev_in_chunk` alone. A refused
                        // header must not seed a total difficulty for the next
                        // one, or the whole disconnected segment inherits a
                        // base this node never verified.
                        continue;
                    }
                }
            }

            let new_td = parent_td + contribution;

            // For NEW headers with a known parent, run full verification.
            // Already-stored headers skip verification (they were validated on first store).
            if !already_stored {
                if let Some(p) = parent_ref {
                    if let Err(e) = self.verifier.verify(header, Some(p)) {
                        warn!(
                            target: "rustock::sync",
                            "Header #{} ({:?}) failed verification: {:?}",
                            header.number, hash, e
                        );
                        skipped += 1;
                        // Still propagate TD to the next header in the chunk
                        prev_in_chunk = Some((header, new_td));
                        continue;
                    }
                }
            }

            prev_in_chunk = Some((header, new_td));
            validated.push((header, new_td));
        }

        let stored = validated.len() as u64;

        // Commit all validated headers in a single atomic batch
        let _new_head = self.store.store_headers_batch(&validated, current_head_hash, current_td)?;

        if unlinked_here > 0 {
            // A chunk beginning above our head does this routinely while
            // catching up, and the node re-requests the same range every few
            // seconds, so this is not a warning.
            debug!(
                target: "rustock::sync",
                "Held {} of {} headers (#{} -> #{}) as unlinked evidence from peer {:?}: \
                 parent not held, nothing to verify against",
                unlinked_here, headers.len(), first_num, last_num,
                peer.map(|p| p.0[..4].to_vec()),
            );
        }

        if skipped > 0 {
            // A rejection is worth a warning: it leaves no canonical entry at
            // that height, and a hole in the canonical index halts execution
            // when it is reached.
            warn!(
                target: "rustock::sync",
                "Stored {} headers (#{} -> #{}), rejected {} invalid, {} stored \
                 held as unlinked evidence",
                stored, first_num, last_num, skipped, unlinked_here
            );
        } else {
            trace!(
                target: "rustock::sync",
                "Stored {} headers (#{} -> #{})",
                stored, first_num, last_num
            );
        }
        Ok(Ingested { stored, rejected: skipped, unlinked: unlinked_here })
    }

    /// Whether this peer's unlinked headers now justify a connection-point
    /// search, and where to start looking.
    ///
    /// Marks the search as taken, so the caller cannot forget to.
    pub fn consider_fork_search(&self, peer: &B512) -> Verdict {
        self.unlinked.lock().unwrap().consider(peer, Instant::now())
    }

    /// Whether this peer is still sending headers we cannot connect to after a
    /// search already resolved where its chain diverges — a peer not serving
    /// the chain it agreed on.
    pub fn unlinked_persisted_after_search(&self, peer: &B512) -> bool {
        self.unlinked.lock().unwrap().persisted_after_search(peer)
    }

    /// See [`UnlinkedHeaders::backdate`].
    #[cfg(test)]
    pub fn backdate_unlinked(&self, peer: &B512, by: std::time::Duration) {
        self.unlinked.lock().unwrap().backdate(peer, by);
    }

    /// Releases a disconnected peer's evidence.
    pub fn forget_peer(&self, peer: &B512) {
        self.unlinked.lock().unwrap().clear_peer(peer);
    }

    /// Helper to create a headers request message.
    pub fn create_headers_request(&self, start_hash: B256, count: u32) -> P2pMessage {
        let req = BlockHeadersRequest {
            id: rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF,
            query: BlockHeadersQuery {
                hash: start_hash,
                count,
            },
        };
        P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)))
    }

    /// The same request, asking for each header's uncles alongside it.
    ///
    /// Only for peers that negotiated `rsk/63`: an rskj node at `rsk/62`
    /// throws out of `MessageType.valueOfType` on an unknown id and drops the
    /// connection, so the caller checks capabilities first.
    pub fn create_headers_with_uncles_request(&self, start_hash: B256, count: u32) -> P2pMessage {
        let req = BlockHeadersWithUnclesRequest {
            id: rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF,
            query: BlockHeadersQuery { hash: start_hash, count },
        };
        P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersWithUnclesRequest(
            req,
        )))
    }
}
