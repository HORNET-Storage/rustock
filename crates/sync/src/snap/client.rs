//! Downloading a state trie from several peers at once.
//!
//! # The shape of the problem
//!
//! The trie has a single linear address space: every node sits at an offset
//! in the in-order traversal, and offsets come from sizes each node's hash
//! commits to. So "download the state" is "cover `0..total`", and any two
//! ranges can be fetched independently, from unrelated peers, in any order.
//!
//! That is the whole of the parallelism, and it needs no coordination between
//! peers: a chunk proves itself against the state root, so a peer serving the
//! middle of the trie neither knows nor affects what another is serving.
//!
//! # Not knowing `total` at the start
//!
//! The snap status message offers a trie size, but it is a peer's claim and
//! the download cannot rest on it. It is used only to fan out: the space is
//! split into as many slices as there are requests allowed in flight, and
//! workers start on each.
//!
//! The first chunk that verifies -- from any offset, from any peer -- carries
//! the root node, which commits to the size of the whole trie. At that point
//! the real total replaces the hint and the slices are trimmed or extended to
//! fit. A peer that overstates the size costs a few wasted requests at the
//! end; one that understates it cannot truncate the download, because the
//! last slice grows to the size the root proves.
//!
//! # What a bad peer can do
//!
//! Serve nothing, serve slowly, or serve something that fails verification.
//! All three end the same way: the range goes back in the queue and someone
//! else is asked. Nothing a peer sends is written to the store before it is
//! checked against the root, so a failed chunk leaves no trace.

use super::SnapConfig;

/// Workers for the state verification walk.
///
/// Cores, not `--read-threads`: see the comment in `verify_stored`.
fn verify_threads() -> usize {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    cores.min(rustock_storage::read_threads()).max(1)
}

// Verification uses the node's read concurrency: the walk is dominated by
// resolving trie nodes out of the store, which is the same question that
// setting answers. See `rustock_storage::set_read_threads`.
use alloy_primitives::{keccak256, B256};
use rustock_networking::protocol::snap::{ChunkPayload, SnapEntry};
use rustock_trie::snapshot::total_size;
use rustock_trie::snapshot_proof::{verify_chunk, ChunkProof, Entry, VerifyError};
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

/// What a slice asks for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ask {
    /// The cell holding the cursor. A cell is the unit a server can cache and
    /// share; asking for the cursor exactly would give every client a
    /// different range and every server a cache miss.
    Cell,
    /// The cursor itself, after a cell answer that did not move it -- a server
    /// that caps its responses below the grid size will do that -- because
    /// asking for the same cell again would produce the same answer forever.
    /// Costs a cache miss at that server, which is strictly better than a
    /// stall.
    Cursor,
    /// The offset just past the cursor, after every rskj chunk. An rskj server
    /// answers any offset, starting with the node that holds it, so asking
    /// just past the cursor picks up with the node that begins there, whatever
    /// size the server serves. Asked at the cursor itself, it starts with the
    /// node that ends there, which the last chunk brought; and when that node
    /// has an embedded right child and no separate left one, rskj's walk sets
    /// out from inside the child and counts the whole node from there, so a
    /// node longer than the window is never kept, and the walk stops at it at
    /// once: the same answer every time.
    JustPast,
}

/// A contiguous stretch of the traversal that one worker walks front to back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slice {
    /// First offset this slice is responsible for.
    start: u64,
    /// Next offset to ask for. Everything before this, within the slice, is
    /// downloaded and stored.
    cursor: u64,
    /// One past the last offset this slice is responsible for.
    end: u64,
    /// What it asks for next.
    next: Ask,
    /// The offset of the request outstanding for this slice, if one is.
    asked: Option<u64>,
}

impl Slice {
    fn wants_work(&self) -> bool {
        self.asked.is_none() && self.cursor < self.end
    }

    /// The offset this slice asks for next.
    fn asks(&self, grid: u64) -> u64 {
        match self.next {
            Ask::Cell => (self.cursor / grid) * grid,
            Ask::Cursor => self.cursor,
            Ask::JustPast => self.cursor + 1,
        }
    }
}

/// A range to ask some peer for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRequest {
    /// Offset to start at.
    pub from: u64,
    /// Bytes of nodes wanted. A server may send fewer.
    pub budget: u64,
}

/// What a verified chunk added to the download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Nodes written to the store.
    pub nodes: usize,
    /// Offset space newly covered.
    pub advanced: u64,
    /// Whether that was the last of it.
    pub complete: bool,
}

/// How much more than the requested budget a chunk may be before it is thrown
/// away unread.
///
/// A server is free to round up, and a straddling node at the end can push a
/// chunk over. What this stops is a peer answering a 100KB request with the
/// 16MB the transport allows, repeatedly, to spend the client's CPU on
/// verification. Rejecting on size costs nothing; verifying does not.
const OVERSIZE_FACTOR: u64 = 4;

/// A chunk that arrived in rskj's format, already rebuilt and checked.
///
/// Kept apart from [`ChunkProof`] because the two prove themselves
/// differently: a proved chunk is replayed against the trie's own traversal,
/// while this one is reconstructed and checked at the root. Both end with
/// nodes in consensus form, which is all the store cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuiltChunk {
    pub nodes: Vec<(B256, Vec<u8>)>,
    pub long_values: Vec<Vec<u8>>,
    /// The size of the whole trie, which the rebuilt root commits to.
    pub total: u64,
    /// Where the chunk's own nodes begin and end in the traversal, as the
    /// rebuild placed them. `None` when it carried none.
    pub span: Option<(u64, u64)>,
    /// Where the node rskj's walk stopped at sits, once the rebuild has placed
    /// it: the first that reached past the window, which rskj leaves out of
    /// the chunk's own nodes and sends whole all the same.
    pub stopped_at: Option<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    #[error("the chunk failed verification: {0}")]
    Invalid(#[from] VerifyError),
    #[error("no request for offset {0} was outstanding")]
    Unsolicited(u64),
    #[error("the peer's rskj-format chunk did not rebuild: {0}")]
    LegacyRebuild(String),
    #[error("the answer is {got} bytes against a {asked} byte request")]
    Oversized { asked: u64, got: u64 },
    #[error("the chunk begins at offset {starts}, after the offset {asked} it answers")]
    Misplaced { asked: u64, starts: u64 },
    #[error("the chunk placed no node, of its own or where the walk stopped")]
    Empty,
}

/// Downloading one state trie.
///
/// Holds no peers and does no I/O: it decides what to ask for and judges what
/// comes back. Which peer to ask is the caller's business, which keeps peer
/// selection, scoring and timeouts out of the part that has to be right.
pub struct StateDownload {
    root_hash: B256,
    store: Arc<dyn TrieStore>,
    budget: u64,
    /// The grid cells sit on. Requests are aligned to it so that every client
    /// asks for the same ranges and a server can answer from cache.
    grid: u64,
    /// The most requests to have outstanding at once.
    max_in_flight: usize,
    slices: Vec<Slice>,
    /// The size the root proves, once a chunk has carried it.
    total: Option<u64>,
    /// The size a peer claimed, used until then.
    hinted_total: u64,
    stored_nodes: u64,
    stored_bytes: u64,
}

impl StateDownload {
    pub fn new(
        root_hash: B256,
        hinted_total: u64,
        config: &SnapConfig,
        store: Arc<dyn TrieStore>,
    ) -> Self {
        Self::on_grid(root_hash, hinted_total, config, config.chunk_grid, store)
    }

    /// The same, but aligned to a grid the server advertised rather than our
    /// own. Asking on the server's grid is what makes its cache useful; a
    /// server that states no grid (rskj does not) leaves us on ours.
    pub fn on_grid(
        root_hash: B256,
        hinted_total: u64,
        config: &SnapConfig,
        grid: u64,
        store: Arc<dyn TrieStore>,
    ) -> Self {
        let workers = config.max_in_flight.max(1);
        let hinted_total = hinted_total.max(1);

        let mut download = Self {
            root_hash,
            store,
            budget: config.chunk_bytes,
            grid: if grid == 0 { config.chunk_grid.max(1) } else { grid },
            max_in_flight: workers,
            slices: Vec::new(),
            total: None,
            hinted_total,
            stored_nodes: 0,
            stored_bytes: 0,
        };
        download.slices = download.split(0, hinted_total, workers);
        download
    }

    /// Cuts `from..to` into `count` slices of roughly equal size.
    fn split(&self, from: u64, to: u64, count: usize) -> Vec<Slice> {
        let span = to.saturating_sub(from);
        let count = (count as u64).min(span.max(1)) as usize;
        let step = span / count as u64;

        (0..count)
            .map(|i| {
                let start = from + step * i as u64;
                let end = if i + 1 == count { to } else { from + step * (i as u64 + 1) };
                Slice { start, cursor: start, end, next: Ask::Cell, asked: None }
            })
            .collect()
    }

    /// The next range to ask a peer for, if any is free.
    ///
    /// Returns `None` when every slice is either finished or already out with
    /// someone -- meaning the caller should wait for an answer rather than
    /// open another request.
    pub fn next_request(&mut self) -> Option<ChunkRequest> {
        // The cap is on requests, not on slices. Those were the same number
        // until the trie turned out bigger than advertised and more slices
        // were cut; keeping the two separate means the limit stays the limit.
        if self.slices.iter().filter(|s| s.asked.is_some()).count() >= self.max_in_flight {
            return None;
        }
        let grid = self.grid;
        let slice = self.slices.iter_mut().find(|s| s.wants_work())?;
        let from = slice.asks(grid);
        slice.asked = Some(from);
        Some(ChunkRequest { from, budget: self.budget })
    }

    /// Give up on an outstanding request so someone else can be asked.
    ///
    /// The range is untouched: nothing was written, so there is nothing to
    /// undo. Called on a timeout, a disconnect, or a chunk that failed to
    /// verify.
    pub fn release(&mut self, from: u64) {
        if let Some(i) = self.slice_for(from) {
            self.slices[i].asked = None;
        }
    }

    /// Give back a request whose offset did not suit the server -- not on its
    /// grid, or past an end the hint had wrong -- and ask on the grid next.
    ///
    /// An exact offset is what an rskj server needs and what a rustock server
    /// refuses, and either may be asked next; the grid is the request every
    /// server takes.
    pub fn realign(&mut self, from: u64) {
        if let Some(i) = self.slice_for(from) {
            self.slices[i].asked = None;
            self.slices[i].next = Ask::Cell;
        }
    }

    /// The slice waiting on an answer for `from`.
    ///
    /// Each slice keeps the offset it asked. It used to be worked out again
    /// from the slice, as its cursor or the cell holding it, preferring a
    /// slice whose cursor was `from`. But a slice asking exactly is inside
    /// its cell too, and took the answer of a slice that had asked for that
    /// cell: that one waited for an answer already spent, and the first
    /// slice's own came back unsolicited, to be charged to the honest peer
    /// that sent it. And the first answer can reshape the slices, moving a
    /// cursor whose request is out. Two slices that asked the same offset get
    /// the same answer, so either may take it.
    fn slice_for(&self, from: u64) -> Option<usize> {
        self.slices.iter().position(|s| s.asked == Some(from))
    }

    /// Check a chunk and, if it holds up, keep it.
    ///
    /// The order matters: verify first, store second. A chunk that fails
    /// leaves the store exactly as it was.
    pub fn accept(&mut self, from: u64, proof: &ChunkProof) -> Result<Progress, ChunkError> {
        if self.slice_for(from).is_none() {
            return Err(ChunkError::Unsolicited(from));
        }

        // Judged on size before anything is read: an answer wildly larger than
        // the question is refused without paying to verify it.
        //
        // Only the node messages and the witness are counted, because they are
        // the only part a peer chooses. A long value's size is fixed by the
        // node that commits to it, and that node's hash chains to the state
        // root -- a peer cannot inflate one, it can only send the real bytes
        // or fail verification. Counting them here would refuse a genuine
        // account whose code is larger than the chunk, making it permanently
        // undownloadable: a worse failure than the one this guards against.
        //
        // A chunk of one node is exempt for the same reason: a server always
        // sends at least one, whatever the budget.
        let allowed = self.budget.saturating_mul(OVERSIZE_FACTOR).max(1 << 18);
        let got: u64 = proof.entries.iter().map(|e| e.message.len() as u64).sum::<u64>()
            + proof.witness.iter().map(|w| w.len() as u64).sum::<u64>();
        if got > allowed && proof.entries.len() > 1 {
            self.release(from);
            return Err(ChunkError::Oversized { asked: self.budget, got });
        }

        let verified = match verify_chunk(self.root_hash, from, proof) {
            Ok(v) => v,
            Err(e) => {
                self.release(from);
                return Err(ChunkError::Invalid(e));
            }
        };

        // The root proves the size of the whole trie. Once that is in hand
        // the peer's claim is no longer needed anywhere.
        if self.total.is_none() {
            self.adopt_total(verified.total);
        }

        for node in &verified.nodes {
            self.store.put(keccak256(&node.message).as_slice(), &node.message);
            self.stored_bytes += node.message.len() as u64;
            for value in &node.long_values {
                self.store.put(keccak256(value).as_slice(), value);
                self.stored_bytes += value.len() as u64;
            }
        }
        self.stored_nodes += verified.nodes.len() as u64;

        let reached = verified.nodes.last().expect("verified chunks are non-empty").end();
        let mut advanced = 0;
        if let Some(i) = self.slice_for(from) {
            let slice = &mut self.slices[i];
            advanced = reached
                .saturating_sub(slice.cursor)
                .min(slice.end.saturating_sub(slice.cursor));
            // A cell can begin before the cursor, so it never moves backwards:
            // the nodes before the cursor were already stored, and storing them
            // again is harmless but must not un-advance the slice.
            //
            // An answer that moved nothing means this server serves less than
            // a whole cell, so the next request names the cursor exactly
            // rather than asking the same cell again and again.
            slice.next = if reached <= slice.cursor {
                Ask::Cursor
            } else {
                Ask::Cell
            };
            slice.cursor = reached.max(slice.cursor);
            slice.asked = None;
        }

        trace!(
            target: "rustock::snap",
            "accepted {} nodes from offset {from}, reaching {reached}",
            verified.nodes.len()
        );

        Ok(Progress { nodes: verified.nodes.len(), advanced, complete: self.is_complete() })
    }

    /// Keep a chunk that arrived in rskj's format.
    ///
    /// It has already proved itself: the only way to read one is to rebuild
    /// it, and the rebuild is checked against the state root. The rebuild
    /// also placed it -- from the sizes the rebuilt tree commits to, where its
    /// first node begins, where its last ends, and that nothing between them
    /// was left out -- so the slice advances to where the chunk really
    /// reached.
    ///
    /// It used to advance by the cell it asked for, on the reasoning that
    /// rskj's format states no offsets. But an rskj server does not serve the
    /// cell asked for: it serves `from` to `from + 50 * 1024`, a constant on
    /// its side, whatever the request says. On rustock's 100,000-byte grid
    /// the last 48,800 bytes of every cell were marked done and never
    /// fetched. On mainnet that was 45.7% of the state, found only by the
    /// check after an hour's download, five attempts running.
    ///
    /// The next request then names the offset just past the cursor: an rskj
    /// server answers any offset, beginning with the node that holds it, so
    /// the next chunk picks up with the node that begins where this one
    /// stopped.
    ///
    /// What a chunk brings whole is its own nodes, and the node rskj's walk
    /// stopped at when it follows them. rskj keeps a node among a chunk's own
    /// only if it ends before `from + 50 * 1024`, and the first that does not
    /// it sends whole all the same, which the rebuild has checked against the
    /// root and placed. A node longer than that window is never among a
    /// chunk's own, however it is asked for, and comes only this way: asked
    /// where it begins, the chunk brings only the node before it, and asked
    /// inside it, nothing of its own. Counted by its own nodes alone,
    /// every answer was taken with the cursor where it was, and testnet's
    /// download stood at 94% for hours, asking again.
    pub fn accept_rebuilt(
        &mut self,
        from: u64,
        chunk: &RebuiltChunk,
    ) -> Result<Progress, ChunkError> {
        if self.slice_for(from).is_none() {
            return Err(ChunkError::Unsolicited(from));
        }

        // The rebuilt root commits to the size of the whole trie, as a proved
        // chunk's does. Taken before anything else, so that a range a peer's
        // overstated hint put past the end is trimmed away.
        if self.total.is_none() {
            self.adopt_total(chunk.total);
        }

        // Its own nodes and the node the walk stopped at, when that follows
        // them; with none of its own, the node it stopped at is the one
        // holding the offset asked.
        let covered = match (chunk.span, chunk.stopped_at) {
            (Some((starts, reached)), Some((begins, ends))) if begins == reached => {
                Some((starts, ends))
            }
            (None, stopped) => stopped,
            (span, _) => span,
        };
        // Nothing to count it for: none of its own, and the node it stopped
        // at not placed, as a node beside two children both left out cannot
        // be. Not a shape Rootstock's state has. Asked on the grid, the walk
        // may begin elsewhere.
        let Some((starts, reached)) = covered else {
            self.realign(from);
            return Err(ChunkError::Empty);
        };
        // An answer to `from` begins with the node that holds it. One that
        // begins after it is not an answer to the question, and taking it
        // would leave a gap behind the cursor.
        if starts > from {
            self.release(from);
            return Err(ChunkError::Misplaced {
                asked: from,
                starts,
            });
        }

        for (hash, message) in &chunk.nodes {
            self.store.put(hash.as_slice(), message);
            self.stored_bytes += message.len() as u64;
        }
        for value in &chunk.long_values {
            self.store.put(keccak256(value).as_slice(), value);
            self.stored_bytes += value.len() as u64;
        }
        self.stored_nodes += chunk.nodes.len() as u64;

        let mut advanced = 0;
        if let Some(i) = self.slice_for(from) {
            let slice = &mut self.slices[i];
            advanced = reached
                .saturating_sub(slice.cursor)
                .min(slice.end.saturating_sub(slice.cursor));
            slice.cursor = reached.max(slice.cursor);
            slice.next = Ask::JustPast;
            slice.asked = None;
        }

        trace!(
            target: "rustock::snap",
            "accepted {} rskj-format nodes from offset {from}, covering {starts}..{reached}",
            chunk.nodes.len()
        );

        Ok(Progress {
            nodes: chunk.nodes.len(),
            advanced,
            complete: self.is_complete(),
        })
    }

    /// Replace the hinted size with the one the root proves, and reshape the
    /// slices around it.
    fn adopt_total(&mut self, total: u64) {
        self.total = Some(total);
        if total == self.hinted_total {
            return;
        }
        debug!(
            target: "rustock::snap",
            "trie size is {total}, peer hinted {}; adjusting slices", self.hinted_total
        );

        // Smaller than advertised: anything wholly past the end is finished by
        // definition, and the slice straddling the end stops there.
        for slice in self.slices.iter_mut() {
            slice.end = slice.end.min(total);
            slice.start = slice.start.min(slice.end);
            slice.cursor = slice.cursor.clamp(slice.start, slice.end);
        }

        // Bigger than advertised: the extra space gets its own slices rather
        // than being tacked onto the last one. A peer that understates the
        // size would otherwise have left the tail of the trie to a single
        // worker -- a cheap way to make a parallel download serial.
        if total > self.hinted_total {
            let workers = self.max_in_flight.max(1);
            let extra = self.split(self.hinted_total, total, workers);
            self.slices.extend(extra);
        }
    }

    /// Every offset accounted for.
    pub fn is_complete(&self) -> bool {
        self.total.is_some() && self.slices.iter().all(|s| s.cursor >= s.end)
    }

    /// Offset space covered so far, and the total once it is known.
    pub fn progress(&self) -> (u64, Option<u64>) {
        // A slice's cursor can run past its end: the last chunk of a slice
        // usually straddles the boundary, and the whole node comes with it.
        // Those bytes belong to the next slice, which will fetch them again,
        // so counting them here would put progress over 100%.
        let covered: u64 = self
            .slices
            .iter()
            .map(|s| s.cursor.min(s.end).saturating_sub(s.start))
            .sum();
        (covered, self.total)
    }

    pub fn stored_nodes(&self) -> u64 {
        self.stored_nodes
    }

    pub fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    pub fn root_hash(&self) -> B256 {
        self.root_hash
    }

    /// The ranges the workers divide the trie into.
    #[cfg(test)]
    pub(crate) fn slice_bounds(&self) -> Vec<(u64, u64)> {
        self.slices.iter().map(|s| (s.start, s.end)).collect()
    }

    /// Walk the assembled trie in the local store and confirm it is all
    /// there.
    ///
    /// Each chunk was already proved against the root, so this is not a second
    /// opinion on the peers -- it is a check on this node: that every verified
    /// node reached the disk and can be read back. Cheap next to the download,
    /// and it fails here rather than during the first block that touches a
    /// missing node.
    pub fn verify_stored(&self) -> Result<u64, String> {
        let message = self
            .store
            .get(self.root_hash.as_slice())
            .ok_or_else(|| format!("state root {:?} is not in the store", self.root_hash))?;
        let root = TrieNode::try_from_message(&message, self.store.as_ref())
            .ok_or_else(|| "the stored state root does not parse".to_string())?;

        let total = total_size(&root, self.store.as_ref());
        if let Some(expected) = self.total {
            if total != expected {
                return Err(format!("stored trie spans {total} bytes, expected {expected}"));
            }
        }

        // One walk, strict and parallel.
        //
        // It used to be two: a parallel walk over byte ranges, which proved
        // the offsets added up, and then a sequential reachability descent
        // added to catch the missing nodes the first one skipped (#204).
        // Two passes over 10.6 million nodes, the stricter one single
        // threaded, which gave back most of what parallelising the first had
        // won.
        //
        // Reachability subsumes coverage -- a node that can be reached is a
        // node that is there -- so the byte-range walk proved nothing this
        // does not, and `total_size` above already checked the arithmetic.
        const REPORT_EVERY: Duration = Duration::from_secs(5);
        // Verification is CPU-bound and scales with cores, not with device
        // queue depth -- measured on a 4-core machine: 2.99x at 4 threads,
        // 3.02x at 8, and 1.69x at 16, which is *slower* than 4. That is the
        // opposite of the header and trie point lookups `--read-threads` was
        // sized for, which wait on RocksDB and want a deep queue.
        //
        // So it follows the cores, bounded by the configured read concurrency
        // so an operator who lowers that still gets a quieter node.
        let threads = verify_threads();
        let started = Instant::now();

        info!(
            target: "rustock::snap",
            "verifying the stored state: {} MB across {threads} thread(s)",
            total / (1 << 20)
        );

        // Ten minutes of silence is indistinguishable from a hang (#187), and
        // no single worker knows the whole picture. The node count is not
        // known in advance, so progress is reported as a rate rather than a
        // percentage -- honest about what is knowable.
        let last_report = Mutex::new(Instant::now());
        let report = move |seen: u64| {
            let mut last = last_report.lock().unwrap_or_else(PoisonError::into_inner);
            if last.elapsed() < REPORT_EVERY {
                return;
            }
            *last = Instant::now();
            let elapsed = started.elapsed().as_secs_f64();
            info!(
                target: "rustock::snap",
                "verifying the stored state: {} nodes, {:.0}s elapsed, {:.0} nodes/s",
                seen,
                elapsed,
                seen as f64 / elapsed.max(0.001)
            );
        };

        let nodes = rustock_trie::snapshot::verify_complete(
            &root,
            self.store.as_ref(),
            threads,
            &report,
        )
        .map_err(|missing| missing.to_string())?;

        info!(
            target: "rustock::snap",
            "stored state verified: {} nodes, {} MB, {:.0}s across {threads} thread(s)",
            nodes,
            total / (1 << 20),
            started.elapsed().as_secs_f64()
        );
        Ok(nodes)
    }
}

/// What a chunk turned out to be, whichever dialect it arrived in.
#[derive(Debug)]
pub enum Arrived {
    /// rustock's own format: nodes to replay against the traversal.
    Proved(ChunkProof),
    /// rskj's format: already rebuilt and checked against the root, because
    /// there is no way to check it that does not also rebuild it.
    Rebuilt(RebuiltChunk),
}

/// Turns a wire payload into something the download can use.
///
/// An rskj chunk is rebuilt here rather than later, because unlike a proved
/// chunk it cannot be examined without being reconstructed: its nodes are
/// missing the child hashes that would let them be checked one at a time.
pub fn chunk_from_payload(
    payload: &ChunkPayload,
    root_hash: B256,
) -> Result<Arrived, ChunkError> {
    match payload {
        ChunkPayload::Proved { entries, witness } => Ok(Arrived::Proved(ChunkProof {
            entries: entries.iter().map(entry_from_wire).collect(),
            witness: witness.iter().map(|w| w.to_vec()).collect(),
        })),
        ChunkPayload::Legacy(blob) => {
            let chunk = rustock_trie::snapshot_legacy::decode_blob(blob)
                .ok_or_else(|| ChunkError::LegacyRebuild("malformed blob".into()))?;
            let rebuilt = rustock_trie::snapshot_legacy::rebuild(&chunk, root_hash)
                .map_err(|e| ChunkError::LegacyRebuild(e.to_string()))?;
            Ok(Arrived::Rebuilt(RebuiltChunk {
                nodes: rebuilt.nodes,
                long_values: rebuilt.long_values,
                total: rebuilt.total,
                span: rebuilt.span,
                stopped_at: rebuilt.stopped_at,
            }))
        }
    }
}

/// Kept for callers that only handle rustock's own format.
pub fn proof_from_payload(payload: &ChunkPayload) -> Result<ChunkProof, ChunkError> {
    match payload {
        ChunkPayload::Legacy(_) => {
            Err(ChunkError::LegacyRebuild("a proved chunk was expected".into()))
        }
        ChunkPayload::Proved { entries, witness } => Ok(ChunkProof {
            entries: entries.iter().map(entry_from_wire).collect(),
            witness: witness.iter().map(|w| w.to_vec()).collect(),
        }),
    }
}

fn entry_from_wire(entry: &SnapEntry) -> Entry {
    Entry {
        message: entry.message.to_vec(),
        long_values: entry.long_values.iter().map(|v| v.to_vec()).collect(),
    }
}
