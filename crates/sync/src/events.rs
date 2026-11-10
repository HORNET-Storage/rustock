use alloy_primitives::{B256, B512};
use rustock_core::types::header::Header;
use rustock_core::types::header_extension::BlockHeaderExtension;
use rustock_core::types::transaction::Transaction;
use alloy_primitives::U256;
use rustock_core::types::block::Block;
use rustock_networking::protocol::HeaderWithUncles;
use rustock_networking::protocol::snap::{ChunkPayload, Refusal};
use rustock_networking::protocol::BlockIdentifier;

/// Forwarded from SyncHandler to the SyncService state machine.
#[derive(Debug)]
pub enum SyncEvent {
    BlockHashResponse { peer: B512, hash: B256 },
    SkeletonResponse {
        peer: B512,
        /// The id of the request this answers. Ordinary sync matches
        /// skeletons by content; snapshot sync uses the id to tell its own
        /// parallel walk apart from everything else in flight.
        id: u64,
        identifiers: Vec<BlockIdentifier>,
    },
    HeadersResponse {
        peer: B512,
        /// The id of the request this answers. Ordinary sync ignores it --
        /// headers are matched by content -- but snapshot sync uses it to
        /// tell its own header walk apart from everything else in flight.
        id: u64,
        headers: Vec<Header>,
    },
    /// Headers that arrived with the uncles they reference (`rsk/63`).
    ///
    /// Kept apart from [`Self::HeadersResponse`] because only this one can
    /// yield an exact total difficulty: uncle difficulty counts toward it and
    /// uncle headers travel nowhere but the body.
    HeadersWithUnclesResponse {
        peer: B512,
        id: u64,
        entries: Vec<HeaderWithUncles>,
    },
    BodyResponse {
        peer: B512,
        id: u64,
        transactions: Vec<Transaction>,
        uncles: Vec<Header>,
        /// The RSKIP-351 extension the peer sent beside the body, which a
        /// header that came compressed needs (`body_check::completed_header`).
        extension: Option<BlockHeaderExtension>,
    },
    NewBlockHashes {
        peer: B512,
        identifiers: Vec<BlockIdentifier>,
    },
    /// A whole block a peer sent unasked, as rskj sends one it mined
    /// (`BlockMessage`), or in answer to a `GetBlockMessage`.
    NewBlock {
        peer: B512,
        block: Box<Block>,
    },

    /// A peer's offer of a state it can serve. The blocks are unverified:
    /// their headers still have to be checked back to a block this node
    /// already trusts before the last one's state root means anything.
    SnapStatusResponse {
        peer: B512,
        id: u64,
        blocks: Vec<Block>,
        difficulties: Vec<U256>,
        trie_size: u64,
        /// The offset grid the server serves on, or zero if it did not say.
        chunk_grid: u64,
    },
    /// A chunk of state, still unverified. `from` is echoed by the peer and
    /// is a hint for routing only -- the request id is what says which range
    /// this answers.
    SnapChunkResponse {
        peer: B512,
        id: u64,
        from: u64,
        payload: ChunkPayload,
        /// Why the payload is empty, when it is.
        refusal: Refusal,
    },
    SnapBlocksResponse {
        peer: B512,
        id: u64,
        blocks: Vec<Block>,
        difficulties: Vec<U256>,
    },
}
