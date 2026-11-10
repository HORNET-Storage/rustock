use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, Header as RlpHeader};
use alloy_primitives::{B256, Bytes, U256};
use rustock_core::{Block, Header, Transaction};
use rustock_core::types::header::HeaderForm;
use rustock_core::types::header_extension::BlockHeaderExtension;
use rustock_core::rlp_compat::{decode_u8_lenient, decode_u64_lenient, decode_u256_lenient, decode_u32_lenient};
use super::snap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RskStatus {
    pub best_block_number: u64,
    pub best_block_hash: B256,
    pub best_block_parent_hash: Option<B256>,
    pub total_difficulty: Option<U256>,
    /// Lowest block this node can serve, as a fifth trailing element.
    ///
    /// Appended rather than replacing anything: rskj's decoder reads indices
    /// 0..3 and never consults the list length again, so a fifth element is
    /// accepted and ignored. Verified against rskj 9.1.0 by decoding 2-, 4-,
    /// 5- and 6-element messages through its own `MessageType.createMessage`;
    /// all four were accepted with the known fields intact.
    ///
    /// Total difficulty stays where it is. `eth/69` dropped it because it is
    /// meaningless after the merge, which is not true here.
    ///
    /// `None` means "did not say", and a reader must treat that as "serves
    /// everything" rather than "serves nothing" -- that is what every rskj
    /// peer will look like.
    pub earliest_block: Option<u64>,
}

impl Encodable for RskStatus {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut list = Vec::new();
        self.best_block_number.encode(&mut list);
        self.best_block_hash.encode(&mut list);
        
        if let (Some(parent), Some(td)) = (self.best_block_parent_hash, self.total_difficulty) {
            parent.encode(&mut list);
            encode_difficulty(td, &mut list);
            // Only after the four rskj knows about, and only when there is
            // something to say. A node serving the whole chain adds nothing.
            if let Some(earliest) = self.earliest_block {
                earliest.encode(&mut list);
            }
        }
        
        RlpHeader { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }

    fn length(&self) -> usize {
        let mut len = self.best_block_number.length() + self.best_block_hash.length();
        if let (Some(parent), Some(td)) = (self.best_block_parent_hash, self.total_difficulty) {
            len += parent.length() + difficulty_length(td);
        }
        RlpHeader { list: true, payload_length: len }.length() + len
    }
}

impl Decodable for RskStatus {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        let mut body = &buf[..header.payload_length];
        *buf = &buf[header.payload_length..];

        let best_block_number = decode_u64_lenient(&mut body)?;
        let best_block_hash = B256::decode(&mut body)?;

        let mut status = Self {
            best_block_number,
            best_block_hash,
            best_block_parent_hash: None,
            total_difficulty: None,
            earliest_block: None,
        };

        if !body.is_empty() {
            status.best_block_parent_hash = Some(B256::decode(&mut body)?);
            status.total_difficulty = Some(decode_u256_lenient(&mut body)?);
        }

        // A fifth element, if the peer speaks the extension. Anything beyond
        // it is left alone on purpose: this is the tolerance a later field
        // will rely on, and it is the same courtesy rskj extends to us.
        if !body.is_empty() {
            status.earliest_block = Some(decode_u64_lenient(&mut body)?);
        }

        Ok(status)
    }
}

/// Encode a difficulty the way rskj writes one.
///
/// rskj stores difficulties as `BigInteger` and puts them on the wire with
/// `BigInteger.toByteArray()`, which is **two's complement**: a value whose
/// top bit would otherwise be set gains a leading `0x00` sign byte. It reads
/// them back with `new BigInteger(bytes)` and rejects a negative outright --
/// `RLP.parseBlockDifficulty` throws "A block difficulty must be positive or
/// zero" and the connection is dropped during decoding.
///
/// Canonical RLP strips every leading zero, including that sign byte, so a
/// total difficulty large enough to set the top bit is read by rskj as
/// negative. Mainnet's total crossed 2^95 once uncle difficulty was counted,
/// which is when this stopped being theoretical.
///
/// Zero is written as a single `0x00`, as `BigInteger.ZERO.toByteArray()`
/// does; an empty string would make `new BigInteger` throw instead.
pub fn encode_difficulty(d: U256, out: &mut Vec<u8>) {
    Bytes::from(difficulty_bytes(d)).encode(out);
}

/// How many bytes [`encode_difficulty`] will write, for `Encodable::length`.
pub fn difficulty_length(d: U256) -> usize {
    Bytes::from(difficulty_bytes(d)).length()
}

fn difficulty_bytes(d: U256) -> Vec<u8> {
    let full = d.to_be_bytes::<32>();
    let start = full.iter().position(|b| *b != 0).unwrap_or(full.len());
    let magnitude = &full[start..];
    if magnitude.is_empty() {
        return vec![0];
    }
    if magnitude[0] >= 0x80 {
        let mut out = Vec::with_capacity(magnitude.len() + 1);
        out.push(0);
        out.extend_from_slice(magnitude);
        return out;
    }
    magnitude.to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersRequest {
    pub id: u64,
    pub query: BlockHeadersQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersQuery {
    pub hash: B256,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersResponse {
    pub id: u64,
    pub headers: Vec<Header>,
}

/// A request for trunk headers together with the uncle headers they reference.
///
/// Shaped exactly like [`BlockHeadersRequest`], so a node can substitute one
/// for the other without changing how it drives sync.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersWithUnclesRequest {
    pub id: u64,
    pub query: BlockHeadersQuery,
}

/// One trunk header and the uncle headers it references.
///
/// In RSK total difficulty advances by the trunk difficulty *plus* every
/// uncle's, and the uncle headers travel only in the body. Carrying them beside
/// the header is what lets a node that holds no bodies compute the chain's
/// work. The pairing is not taken on trust: `ommers_hash` commits to the uncle
/// list, so [`Self::commitment_matches`] decides whether the peer sent the list
/// the header actually names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderWithUncles {
    pub header: Header,
    pub uncles: Vec<Header>,
}

impl HeaderWithUncles {
    /// The RLP of the uncle list, as `ommers_hash` commits to it: rskj's
    /// `BlockHeader.getUnclesEncoded`.
    pub fn encoded_uncles(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for uncle in &self.uncles {
            uncle.encode(&mut payload);
        }
        let mut out = Vec::with_capacity(payload.len() + 9);
        RlpHeader { list: true, payload_length: payload.len() }.encode(&mut out);
        out.extend_from_slice(&payload);
        out
    }

    /// Whether the uncles are the ones the trunk header commits to.
    ///
    /// This is the whole security argument for the message. The receiver has
    /// already checked the trunk header's proof of work, and the header fixes
    /// the uncle list through `ommers_hash`, so a peer can neither add, drop
    /// nor alter an uncle. The difficulties that follow are therefore as
    /// trustworthy as the header itself.
    pub fn commitment_matches(&self) -> bool {
        self.uncles.len() as u64 == self.header.uncle_count
            && alloy_primitives::keccak256(self.encoded_uncles()) == self.header.ommers_hash
    }

    /// `difficulty + sum(uncle difficulties)`, rskj's
    /// `Block.getCumulativeDifficulty`.
    ///
    /// Only meaningful once [`Self::commitment_matches`] has passed; the proof
    /// of work on each uncle has to be checked separately, by the consensus
    /// layer, or a miner could claim cheap work by naming uncles that carry
    /// arbitrary difficulty.
    pub fn cumulative_difficulty(&self) -> alloy_primitives::U256 {
        let mut total = self.header.difficulty;
        for uncle in &self.uncles {
            total = total.saturating_add(uncle.difficulty);
        }
        total
    }
}

/// Trunk headers with their uncles. See [`HeaderWithUncles`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeadersWithUnclesResponse {
    pub id: u64,
    pub entries: Vec<HeaderWithUncles>,
}

/// A block identifier used in skeleton responses (hash + number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIdentifier {
    pub hash: B256,
    pub number: u64,
}

/// Request a block body by hash (type 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyRequest {
    pub id: u64,
    pub hash: B256,
}

/// Response containing a block body (type 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyResponse {
    pub id: u64,
    pub transactions: Vec<Transaction>,
    pub uncles: Vec<Header>,
    /// The RSKIP-351 extension of the block's header -- its logs bloom,
    /// execution edges and base event -- which rskj sends beside the body of
    /// a version-1 or version-2 block (`BodyResponseMessage`), whose header
    /// goes to peers holding only a commitment to it. `None` for a version-0
    /// block.
    pub extension: Option<BlockHeaderExtension>,
}

/// Request the hash of the block at a given height (type 8).
/// Used during connection-point binary search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashRequest {
    pub id: u64,
    pub height: u64,
}

/// Response with the block hash at the requested height (type 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashResponse {
    pub id: u64,
    pub hash: B256,
}

/// Request the skeleton (evenly-spaced block identifiers) from a starting height (type 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonRequest {
    pub id: u64,
    pub start_number: u64,
}

/// Response with a list of block identifiers forming the skeleton (type 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonResponse {
    pub id: u64,
    pub block_identifiers: Vec<BlockIdentifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RskMessageType {
    Status = 1,
    /// A whole block: rskj `BlockMessage`, which a node sends to some of its
    /// peers when it mines one (`ChannelManagerImpl.broadcastBlock`) and to a
    /// peer that asks for one by hash (`NodeBlockProcessor.processGetBlock`).
    Block = 2,
    /// A whole block asked for by its hash: rskj `GetBlockMessage`, which a
    /// node sends to the peer that announced a block it does not hold
    /// (`NodeBlockProcessor.processNewBlockHashesMessage`).
    GetBlock = 3,
    NewBlockHashes = 6,
    Transactions = 7,
    BlockHashRequest = 8,
    BlockHeadersRequest = 9,
    BlockHeadersResponse = 10,
    SkeletonResponse = 13,
    BodyRequest = 14,
    BodyResponse = 15,
    SkeletonRequest = 16,
    BlockHashResponse = 18,
    SnapStateChunkRequest = 20,
    SnapStateChunkResponse = 21,
    SnapStatusRequest = 22,
    SnapStatusResponse = 23,
    SnapBlocksRequest = 24,
    SnapBlocksResponse = 25,
    /// Announces a change to the range of blocks this node serves.
    ///
    /// 26 is the first type rskj does not define; its highest is 25. An rskj
    /// node that received this would throw `IllegalArgumentException` out of
    /// `MessageType.valueOfType` and close the connection, so it is sent only
    /// to peers that negotiated `rsk/63`.
    BlockRangeUpdate = 26,
    BlockHeadersWithUnclesRequest = 27,
    BlockHeadersWithUnclesResponse = 28,
}

/// The `rsk` subprotocol version that carries the served block range.
///
/// `62` is what rskj speaks today. A node negotiating `63` has agreed to read
/// a fifth element in the status message and to accept
/// [`RskSubMessage::BlockRangeUpdate`]; one at `62` has agreed to neither, and
/// sending it the update would close the connection -- rskj throws out of
/// `MessageType.valueOfType` for any type it does not know, and its netty
/// handler answers that with `ctx.close()`.
pub const RSK_RANGE_VERSION: u64 = 63;

/// The range of blocks a node can serve.
///
/// Shaped after `eth/69`'s `BlockRangeUpdatePacket`, so that an RSKIP
/// proposing it to rskj maps onto something already argued through upstream.
///
/// `earliest` is exact -- a node never holds blocks below it. `latest` trails
/// the real head, because an announcement is a snapshot taken at a moment and
/// the head moves on; a reader should treat the upper bound as loose and the
/// lower bound as firm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRange {
    /// Lowest block this node can serve. Zero on a node holding the whole
    /// chain, and the prune floor on one that does not.
    pub earliest_block: u64,
    pub latest_block: u64,
    pub latest_block_hash: B256,
}

impl Encodable for BlockRange {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut list = Vec::new();
        self.earliest_block.encode(&mut list);
        self.latest_block.encode(&mut list);
        self.latest_block_hash.encode(&mut list);
        RlpHeader { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }
}

impl Decodable for BlockRange {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        let mut body = &buf[..header.payload_length];
        *buf = &buf[header.payload_length..];
        Ok(Self {
            earliest_block: decode_u64_lenient(&mut body)?,
            latest_block: decode_u64_lenient(&mut body)?,
            latest_block_hash: B256::decode(&mut body)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum RskSubMessage {
    Status(RskStatus),
    Block(Box<Block>),
    GetBlock(B256),
    BlockHashRequest(BlockHashRequest),
    BlockHeadersRequest(BlockHeadersRequest),
    BlockHeadersResponse(BlockHeadersResponse),
    SkeletonRequest(SkeletonRequest),
    SkeletonResponse(SkeletonResponse),
    BlockHashResponse(BlockHashResponse),
    BodyRequest(BodyRequest),
    BodyResponse(BodyResponse),
    NewBlockHashes(Vec<BlockIdentifier>),
    Transactions(Vec<Bytes>),
    SnapStatusRequest(snap::SnapStatusRequest),
    SnapStatusResponse(Box<snap::SnapStatusResponse>),
    SnapChunkRequest(snap::SnapChunkRequest),
    SnapChunkResponse(Box<snap::SnapChunkResponse>),
    SnapBlocksRequest(snap::SnapBlocksRequest),
    SnapBlocksResponse(Box<snap::SnapBlocksResponse>),
    BlockRangeUpdate(BlockRange),
    BlockHeadersWithUnclesRequest(BlockHeadersWithUnclesRequest),
    BlockHeadersWithUnclesResponse(BlockHeadersWithUnclesResponse),
    Unknown(u8),
}

impl RskSubMessage {
    pub fn message_type(&self) -> RskMessageType {
        match self {
            RskSubMessage::Status(_) => RskMessageType::Status,
            RskSubMessage::Block(_) => RskMessageType::Block,
            RskSubMessage::GetBlock(_) => RskMessageType::GetBlock,
            RskSubMessage::BlockHashRequest(_) => RskMessageType::BlockHashRequest,
            RskSubMessage::BlockHeadersRequest(_) => RskMessageType::BlockHeadersRequest,
            RskSubMessage::BlockHeadersResponse(_) => RskMessageType::BlockHeadersResponse,
            RskSubMessage::SkeletonRequest(_) => RskMessageType::SkeletonRequest,
            RskSubMessage::SkeletonResponse(_) => RskMessageType::SkeletonResponse,
            RskSubMessage::BlockHashResponse(_) => RskMessageType::BlockHashResponse,
            RskSubMessage::BodyRequest(_) => RskMessageType::BodyRequest,
            RskSubMessage::BodyResponse(_) => RskMessageType::BodyResponse,
            RskSubMessage::NewBlockHashes(_) => RskMessageType::NewBlockHashes,
            RskSubMessage::Transactions(_) => RskMessageType::Transactions,
            RskSubMessage::SnapStatusRequest(_) => RskMessageType::SnapStatusRequest,
            RskSubMessage::SnapStatusResponse(_) => RskMessageType::SnapStatusResponse,
            RskSubMessage::SnapChunkRequest(_) => RskMessageType::SnapStateChunkRequest,
            RskSubMessage::SnapChunkResponse(_) => RskMessageType::SnapStateChunkResponse,
            RskSubMessage::SnapBlocksRequest(_) => RskMessageType::SnapBlocksRequest,
            RskSubMessage::SnapBlocksResponse(_) => RskMessageType::SnapBlocksResponse,
            RskSubMessage::BlockRangeUpdate(_) => RskMessageType::BlockRangeUpdate,
            RskSubMessage::BlockHeadersWithUnclesRequest(_) => {
                RskMessageType::BlockHeadersWithUnclesRequest
            }
            RskSubMessage::BlockHeadersWithUnclesResponse(_) => {
                RskMessageType::BlockHeadersWithUnclesResponse
            }
            RskSubMessage::Unknown(_) => RskMessageType::Status, // Not used for encoding
        }
    }

    /// Encodes parameters as a List. 
    /// Corresponds to Java's getEncodedMessage() [id + params] or [params for status]
    fn encode_params(&self, out: &mut Vec<u8>) {
        match self {
            RskSubMessage::Status(s) => {
                let mut list = Vec::new();
                s.best_block_number.encode(&mut list);
                s.best_block_hash.encode(&mut list);
                if let (Some(parent), Some(td)) = (s.best_block_parent_hash, s.total_difficulty) {
                    parent.encode(&mut list);
                    encode_difficulty(td, &mut list);
                    if let Some(earliest) = s.earliest_block {
                        earliest.encode(&mut list);
                    }
                }
                RlpHeader { list: true, payload_length: list.len() }.encode(out);
                out.extend_from_slice(&list);
            }
            RskSubMessage::BlockRangeUpdate(range) => {
                range.encode(out);
            }
            RskSubMessage::BlockHeadersRequest(r) => {
                // RLP([id, RLP([hash, count])])
                let mut query_params = Vec::new();
                r.query.hash.encode(&mut query_params);
                r.query.count.encode(&mut query_params);
                
                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: query_params.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&query_params);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                // The inner list is pre-encoded RLP, so it's just appended to the outer list
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHeadersWithUnclesRequest(r) => {
                // RLP([id, RLP([hash, count])]) -- the same shape as the plain
                // header request, so a peer may answer either from one code path.
                let mut query_params = Vec::new();
                r.query.hash.encode(&mut query_params);
                r.query.count.encode(&mut query_params);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                RlpHeader { list: true, payload_length: query_params.len() }.encode(&mut params);
                params.extend_from_slice(&query_params);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHeadersWithUnclesResponse(r) => {
                // RLP([id, [ [trunkHeader, [uncle...]], ... ]])
                let mut entries_payload = Vec::new();
                for entry in &r.entries {
                    let mut one = Vec::new();
                    // A header as this node holds it, in the store's form,
                    // which a header held compressed has too; its uncles in
                    // full, the form its uncles hash commits to.
                    one.extend_from_slice(&entry.header.encode_stored());
                    one.extend_from_slice(&entry.encoded_uncles());

                    RlpHeader { list: true, payload_length: one.len() }
                        .encode(&mut entries_payload);
                    entries_payload.extend_from_slice(&one);
                }

                let mut params = Vec::new();
                r.id.encode(&mut params);
                RlpHeader { list: true, payload_length: entries_payload.len() }
                    .encode(&mut params);
                params.extend_from_slice(&entries_payload);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHeadersResponse(r) => {
                // RLP([id, RLP([RLP([headers])])]), each header compressed, as
                // rskj sends and reads them (`getEncodedCompressed`).
                let mut headers_payload = Vec::new();
                for h in &r.headers {
                    headers_payload.extend_from_slice(&h.encode_compressed());
                }
                
                let mut headers_list = Vec::new();
                RlpHeader { list: true, payload_length: headers_payload.len() }.encode(&mut headers_list);
                headers_list.extend_from_slice(&headers_payload);

                let mut wrapped_headers = Vec::new();
                RlpHeader { list: true, payload_length: headers_list.len() }.encode(&mut wrapped_headers);
                wrapped_headers.extend_from_slice(&headers_list);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&wrapped_headers);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHashRequest(r) => {
                // RLP([id, RLP([height])])
                let mut inner = Vec::new();
                r.height.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHashResponse(r) => {
                // RLP([id, RLP([hash])])
                let mut inner = Vec::new();
                r.hash.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::SkeletonRequest(r) => {
                // RLP([id, RLP([startNumber])])
                let mut inner = Vec::new();
                r.start_number.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::SkeletonResponse(r) => {
                // RLP([id, RLP([RLP([bid_0, bid_1, ...])])])
                // Each bid = RLP([hash, number])
                let mut bids_payload = Vec::new();
                for bid in &r.block_identifiers {
                    let mut bid_elems = Vec::new();
                    bid.hash.encode(&mut bid_elems);
                    bid.number.encode(&mut bid_elems);
                    RlpHeader { list: true, payload_length: bid_elems.len() }.encode(&mut bids_payload);
                    bids_payload.extend_from_slice(&bid_elems);
                }

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: bids_payload.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&bids_payload);

                let mut outer = Vec::new();
                RlpHeader { list: true, payload_length: inner_list.len() }.encode(&mut outer);
                outer.extend_from_slice(&inner_list);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&outer);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BodyRequest(r) => {
                // RLP([id, RLP([hash])])
                let mut inner = Vec::new();
                r.hash.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BodyResponse(r) => {
                // RLP([id, RLP([txs_list, uncles_list, extension?])]), the
                // extension as rskj's `BlockHeaderExtension.toEncoded` writes it.
                let mut txs_payload = Vec::new();
                for tx in &r.transactions {
                    // As in `encode_block`: serve the bytes the header commits
                    // to, not a canonical re-encoding of the parsed fields.
                    txs_payload.extend_from_slice(&tx.rlp_for_trie());
                }
                let mut txs_list = Vec::new();
                RlpHeader { list: true, payload_length: txs_payload.len() }.encode(&mut txs_list);
                txs_list.extend_from_slice(&txs_payload);

                let mut uncles_payload = Vec::new();
                for uncle in &r.uncles {
                    uncle.encode(&mut uncles_payload);
                }
                let mut uncles_list = Vec::new();
                RlpHeader { list: true, payload_length: uncles_payload.len() }.encode(&mut uncles_list);
                uncles_list.extend_from_slice(&uncles_payload);

                let extension = r
                    .extension
                    .as_ref()
                    .map(BlockHeaderExtension::to_encoded)
                    .unwrap_or_default();
                let body_len = txs_list.len() + uncles_list.len() + extension.len();
                let mut body = Vec::new();
                RlpHeader { list: true, payload_length: body_len }.encode(&mut body);
                body.extend_from_slice(&txs_list);
                body.extend_from_slice(&uncles_list);
                body.extend_from_slice(&extension);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&body);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::Transactions(txs) => {
                let mut txs_payload = Vec::new();
                for tx in txs {
                    // A transaction is already a complete RLP list, so it goes
                    // in verbatim. Wrapping it in a string header made every
                    // transaction this node relayed undecodable to its peers,
                    // the mirror image of the decode bug above.
                    txs_payload.extend_from_slice(tx);
                }
                RlpHeader { list: true, payload_length: txs_payload.len() }.encode(out);
                out.extend_from_slice(&txs_payload);
            }
            // Snap bodies are built in `snap`, which owns their shape; here
            // they are already-encoded parameter lists.
            RskSubMessage::SnapStatusRequest(m) => out.extend_from_slice(&m.encode_body()),
            RskSubMessage::SnapStatusResponse(m) => out.extend_from_slice(&m.encode_body()),
            RskSubMessage::SnapChunkRequest(m) => out.extend_from_slice(&m.encode_body()),
            RskSubMessage::SnapChunkResponse(m) => out.extend_from_slice(&m.encode_body()),
            RskSubMessage::SnapBlocksRequest(m) => out.extend_from_slice(&m.encode_body()),
            RskSubMessage::SnapBlocksResponse(m) => out.extend_from_slice(&m.encode_body()),
            RskSubMessage::Block(block) => {
                // rskj `BlockMessage.getEncodedMessage`:
                // `RLP.encodeList(RLP.encode(block.getEncoded()))`, the block's own
                // encoding as the one string in a list.
                let mut payload = Vec::new();
                Bytes::from(snap::encode_block(block)).encode(&mut payload);
                RlpHeader {
                    list: true,
                    payload_length: payload.len(),
                }
                .encode(out);
                out.extend_from_slice(&payload);
            }
            RskSubMessage::GetBlock(hash) => {
                // rskj `GetBlockMessage.getEncodedMessage`: the hash, alone in a list.
                let mut payload = Vec::new();
                hash.encode(&mut payload);
                RlpHeader {
                    list: true,
                    payload_length: payload.len(),
                }
                .encode(out);
                out.extend_from_slice(&payload);
            }
            RskSubMessage::NewBlockHashes(identifiers) => {
                // rskj `NewBlockHashesMessage.encode`: a list of
                // `BlockIdentifier.getEncoded`, each `[hash, number]`.
                let mut payload = Vec::new();
                for identifier in identifiers {
                    let mut pair = Vec::new();
                    identifier.hash.encode(&mut pair);
                    identifier.number.encode(&mut pair);
                    RlpHeader {
                        list: true,
                        payload_length: pair.len(),
                    }
                    .encode(&mut payload);
                    payload.extend_from_slice(&pair);
                }
                RlpHeader {
                    list: true,
                    payload_length: payload.len(),
                }
                .encode(out);
                out.extend_from_slice(&payload);
            }
            RskSubMessage::Unknown(_) => {
                // A type this node does not know is never sent.
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RskMessage {
    pub sub_message: RskSubMessage,
}

impl RskMessage {
    pub const MESSAGE_ID: u8 = 0x08;

    pub fn new(sub_message: RskSubMessage) -> Self {
        Self { sub_message }
    }
}

impl Encodable for RskMessage {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut params_rlp = Vec::new();
        self.sub_message.encode_params(&mut params_rlp);
        
        // Java Message.getEncoded(): RLP([type, RLP_String(params_rlp)])
        let mut msg_rlp = Vec::new();
        (self.sub_message.message_type() as u8).encode(&mut msg_rlp);
        // encodeElement wraps in Rlp String (Blob)
        RlpHeader { list: false, payload_length: params_rlp.len() }.encode(&mut msg_rlp);
        msg_rlp.extend_from_slice(&params_rlp);
        
        let mut wrapped_msg = Vec::new();
        RlpHeader { list: true, payload_length: msg_rlp.len() }.encode(&mut wrapped_msg);
        wrapped_msg.extend_from_slice(&msg_rlp);

        // Java RskMessage.encode(): RLP([wrapped_msg])
        let mut final_rlp = Vec::new();
        RlpHeader { list: true, payload_length: wrapped_msg.len() }.encode(&mut final_rlp);
        final_rlp.extend_from_slice(&wrapped_msg);

        out.put_slice(&final_rlp);
    }

    fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }
}

impl Decodable for RskMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let h1 = RlpHeader::decode(buf)?;
        let mut b1 = &buf[..h1.payload_length];
        *buf = &buf[h1.payload_length..];

        let h2 = RlpHeader::decode(&mut b1)?;
        let mut b2 = &b1[..h2.payload_length];

        let type_byte = decode_u8_lenient(&mut b2)?;
        
        // Next is the body_blob (RLP String)
        let body_h = RlpHeader::decode(&mut b2)?;
        if body_h.list {
            return Err(alloy_rlp::Error::Custom("Expected RLP string for body blob"));
        }
        let mut body_params = &b2[..body_h.payload_length];

        let sub_message = match type_byte {
            1 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let best_block_number = decode_u64_lenient(&mut list_body)?;
                let best_block_hash = B256::decode(&mut list_body)?;
                let mut status = RskStatus {
                    best_block_number,
                    best_block_hash,
                    best_block_parent_hash: None,
                    total_difficulty: None,
                    earliest_block: None,
                };
                if !list_body.is_empty() {
                    status.best_block_parent_hash = Some(B256::decode(&mut list_body)?);
                    status.total_difficulty = Some(decode_u256_lenient(&mut list_body)?);
                }
                if !list_body.is_empty() {
                    status.earliest_block = Some(decode_u64_lenient(&mut list_body)?);
                }
                RskSubMessage::Status(status)
            }
            2 => {
                // rskj `MessageType.BLOCK_MESSAGE`: the block's own encoding, the
                // one string in a list, read whole (`BlockFactory.decodeBlock`).
                let list_h = RlpHeader::decode(&mut body_params)?;
                if !list_h.list || body_params.len() < list_h.payload_length {
                    return Err(alloy_rlp::Error::Custom("malformed block message"));
                }
                let mut list_body = &body_params[..list_h.payload_length];
                let encoded = Bytes::decode(&mut list_body)?;
                RskSubMessage::Block(Box::new(snap::decode_block(&mut encoded.as_ref())?))
            }
            3 => {
                // rskj `MessageType.GET_BLOCK_MESSAGE`: the hash, alone in a list.
                let list_h = RlpHeader::decode(&mut body_params)?;
                if !list_h.list || body_params.len() < list_h.payload_length {
                    return Err(alloy_rlp::Error::Custom("malformed get-block message"));
                }
                let mut list_body = &body_params[..list_h.payload_length];
                RskSubMessage::GetBlock(B256::decode(&mut list_body)?)
            }
            9 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;
                
                let query_h = RlpHeader::decode(&mut list_body)?;
                let mut query_body = &list_body[..query_h.payload_length];
                let hash = B256::decode(&mut query_body)?;
                let count = decode_u32_lenient(&mut query_body)?;

                RskSubMessage::BlockHeadersRequest(BlockHeadersRequest {
                    id,
                    query: BlockHeadersQuery { hash, count },
                })
            }
            10 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let outer_h = RlpHeader::decode(&mut list_body)?;
                let mut outer_body = &list_body[..outer_h.payload_length];
                
                let inner_h = RlpHeader::decode(&mut outer_body)?;
                let mut inner_body = &outer_body[..inner_h.payload_length];

                let mut headers = Vec::new();
                while !inner_body.is_empty() {
                    // rskj `decodeHeader(.., true)`: compressed.
                    headers.push(Header::decode_with_hash_in(
                        &mut inner_body,
                        rustock_core::config::ActivationHeights::current(),
                        HeaderForm::Compressed,
                    )?);
                }
                RskSubMessage::BlockHeadersResponse(BlockHeadersResponse { id, headers })
            }
            8 => {
                // BlockHashRequest: RLP([id, RLP([height])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let height = decode_u64_lenient(&mut inner_body)?;

                RskSubMessage::BlockHashRequest(BlockHashRequest { id, height })
            }
            13 => {
                // SkeletonResponse: RLP([id, RLP([RLP([bid_0, bid_1, ...])])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let outer_h = RlpHeader::decode(&mut list_body)?;
                let mut outer_body = &list_body[..outer_h.payload_length];

                let inner_h = RlpHeader::decode(&mut outer_body)?;
                let mut inner_body = &outer_body[..inner_h.payload_length];

                let mut block_identifiers = Vec::new();
                while !inner_body.is_empty() {
                    let bid_h = RlpHeader::decode(&mut inner_body)?;
                    let mut bid_body = &inner_body[..bid_h.payload_length];
                    inner_body = &inner_body[bid_h.payload_length..];
                    let hash = B256::decode(&mut bid_body)?;
                    let number = decode_u64_lenient(&mut bid_body)?;
                    block_identifiers.push(BlockIdentifier { hash, number });
                }

                RskSubMessage::SkeletonResponse(SkeletonResponse { id, block_identifiers })
            }
            16 => {
                // SkeletonRequest: RLP([id, RLP([startNumber])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let start_number = decode_u64_lenient(&mut inner_body)?;

                RskSubMessage::SkeletonRequest(SkeletonRequest { id, start_number })
            }
            18 => {
                // BlockHashResponse: RLP([id, RLP([hash])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let hash = B256::decode(&mut inner_body)?;

                RskSubMessage::BlockHashResponse(BlockHashResponse { id, hash })
            }
            14 => {
                // BodyRequest: RLP([id, RLP([hash])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let hash = B256::decode(&mut inner_body)?;

                RskSubMessage::BodyRequest(BodyRequest { id, hash })
            }
            15 => {
                // BodyResponse: RLP([id, RLP([txs_list, uncles_list, extension?])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let body_h = RlpHeader::decode(&mut list_body)?;
                let mut body_data = &list_body[..body_h.payload_length];

                // Decode transactions list
                let txs_h = RlpHeader::decode(&mut body_data)?;
                let mut txs_body = &body_data[..txs_h.payload_length];
                body_data = &body_data[txs_h.payload_length..];
                let mut transactions = Vec::new();
                while !txs_body.is_empty() {
                    transactions.push(Transaction::decode(&mut txs_body)?);
                }

                // Decode uncles list
                let uncles_h = RlpHeader::decode(&mut body_data)?;
                let mut uncles_body = &body_data[..uncles_h.payload_length];
                body_data = &body_data[uncles_h.payload_length..];
                let mut uncles = Vec::new();
                while !uncles_body.is_empty() {
                    uncles.push(Header::decode_with_hash(&mut uncles_body)?);
                }

                // rskj `MessageType.BODY_RESPONSE`: a third element is the
                // block header's RSKIP-351 extension, which
                // `BlockHeaderExtension.fromEncoded` reads whole, and a body of
                // any other length has none.
                //
                // From RSKIP-351 a header goes to peers with its bloom, execution
                // edges and base event folded into a commitment --
                // `RLP[version, keccak(extension)]` -- in the bloom's slot, and the
                // extension comes here, beside the block's body. It travels apart
                // from the header, so nothing in this message binds it to the
                // block: the sync takes it only once it matches the commitment
                // that the header's hash covers (`Header::with_extension`), and a
                // header that holds its own fields takes none.
                let mut rest = Vec::new();
                while !body_data.is_empty() {
                    let mut item = body_data;
                    let item_h = RlpHeader::decode(&mut item)?;
                    let length = body_data.len() - item.len() + item_h.payload_length;
                    let element = body_data
                        .get(..length)
                        .ok_or(alloy_rlp::Error::InputTooShort)?;
                    rest.push(element);
                    body_data = &body_data[length..];
                }
                let extension = match rest.as_slice() {
                    [extension] => {
                        Some(BlockHeaderExtension::from_encoded(extension).map_err(|_| {
                            alloy_rlp::Error::Custom("malformed block header extension")
                        })?)
                    }
                    _ => None,
                };

                RskSubMessage::BodyResponse(BodyResponse {
                    id,
                    transactions,
                    uncles,
                    extension,
                })
            }
            6 => {
                // NewBlockHashes: RLP list of [hash, number] pairs
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let mut identifiers = Vec::new();
                while !list_body.is_empty() {
                    let item_h = RlpHeader::decode(&mut list_body)?;
                    let mut item_body = &list_body[..item_h.payload_length];
                    list_body = &list_body[item_h.payload_length..];
                    let hash = B256::decode(&mut item_body)?;
                    let number = decode_u64_lenient(&mut item_body)?;
                    identifiers.push(BlockIdentifier { hash, number });
                }
                RskSubMessage::NewBlockHashes(identifiers)
            }
            7 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let mut txs = Vec::new();
                while !list_body.is_empty() {
                    // Each item is a COMPLETE transaction -- itself an RLP list
                    // -- and must be handed on whole. Decoding the header to
                    // find the item's length and then keeping only the payload
                    // strips the list header, and the pool cannot decode what
                    // is left: `Transaction::decode` needs a complete RLP list.
                    //
                    // Mainnet symptom: 19 transactions offered in five minutes,
                    // all 19 rejected `rlp-decode`.
                    let before = list_body;
                    let tx_h = RlpHeader::decode(&mut list_body)?;
                    let header_len = before.len() - list_body.len();
                    let total = header_len + tx_h.payload_length;
                    txs.push(Bytes::copy_from_slice(&before[..total]));
                    list_body = &before[total..];
                }
                RskSubMessage::Transactions(txs)
            }
            snap::message_type::STATUS_REQUEST => RskSubMessage::SnapStatusRequest(
                snap::SnapStatusRequest::decode_body(&mut body_params)?,
            ),
            snap::message_type::STATUS_RESPONSE => RskSubMessage::SnapStatusResponse(
                Box::new(snap::SnapStatusResponse::decode_body(&mut body_params)?),
            ),
            snap::message_type::STATE_CHUNK_REQUEST => RskSubMessage::SnapChunkRequest(
                snap::SnapChunkRequest::decode_body(&mut body_params)?,
            ),
            snap::message_type::STATE_CHUNK_RESPONSE => RskSubMessage::SnapChunkResponse(
                Box::new(snap::SnapChunkResponse::decode_body(&mut body_params)?),
            ),
            snap::message_type::BLOCKS_REQUEST => RskSubMessage::SnapBlocksRequest(
                snap::SnapBlocksRequest::decode_body(&mut body_params)?,
            ),
            snap::message_type::BLOCKS_RESPONSE => RskSubMessage::SnapBlocksResponse(
                Box::new(snap::SnapBlocksResponse::decode_body(&mut body_params)?),
            ),
            26 => RskSubMessage::BlockRangeUpdate(BlockRange::decode(&mut body_params)?),
            27 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let query_h = RlpHeader::decode(&mut list_body)?;
                let mut query_body = &list_body[..query_h.payload_length];
                let hash = B256::decode(&mut query_body)?;
                let count = decode_u32_lenient(&mut query_body)?;

                RskSubMessage::BlockHeadersWithUnclesRequest(BlockHeadersWithUnclesRequest {
                    id,
                    query: BlockHeadersQuery { hash, count },
                })
            }
            28 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let entries_h = RlpHeader::decode(&mut list_body)?;
                if list_body.len() < entries_h.payload_length {
                    return Err(alloy_rlp::Error::Custom("malformed headers-with-uncles list"));
                }
                let mut entries_body = &list_body[..entries_h.payload_length];

                let mut entries = Vec::new();
                while !entries_body.is_empty() {
                    let entry_h = RlpHeader::decode(&mut entries_body)?;
                    if !entry_h.list || entries_body.len() < entry_h.payload_length {
                        return Err(alloy_rlp::Error::Custom("malformed headers-with-uncles entry"));
                    }
                    let mut entry_body = &entries_body[..entry_h.payload_length];
                    entries_body = &entries_body[entry_h.payload_length..];

                    let header = Header::decode_with_hash_in(
                        &mut entry_body,
                        rustock_core::config::ActivationHeights::current(),
                        HeaderForm::Stored,
                    )?;

                    // Hash the uncle list exactly as it arrived. Re-encoding it
                    // and hashing that would compare our spelling of the bytes
                    // against a commitment the miner made over theirs, and the
                    // two need not agree -- the same hazard that makes
                    // `rlp_for_trie` keep original transaction bytes.
                    let uncles_raw = entry_body;
                    let uncles_h = RlpHeader::decode(&mut entry_body)?;
                    if !uncles_h.list || entry_body.len() < uncles_h.payload_length {
                        return Err(alloy_rlp::Error::Custom("malformed uncle list"));
                    }
                    let consumed = uncles_raw.len() - entry_body.len() + uncles_h.payload_length;
                    let committed = alloy_primitives::keccak256(&uncles_raw[..consumed]);
                    if committed != header.ommers_hash {
                        // The peer sent a list this header does not name. The
                        // difficulties in it are worthless, so the message is
                        // refused rather than partly believed.
                        return Err(alloy_rlp::Error::Custom(
                            "uncle list does not match the header's ommers hash",
                        ));
                    }

                    let mut uncles_body = &entry_body[..uncles_h.payload_length];
                    let mut uncles = Vec::new();
                    while !uncles_body.is_empty() {
                        uncles.push(Header::decode_with_hash(&mut uncles_body)?);
                    }
                    if uncles.len() as u64 != header.uncle_count {
                        return Err(alloy_rlp::Error::Custom(
                            "uncle count does not match the header",
                        ));
                    }

                    entries.push(HeaderWithUncles { header, uncles });
                }

                RskSubMessage::BlockHeadersWithUnclesResponse(BlockHeadersWithUnclesResponse {
                    id,
                    entries,
                })
            }
            other => {
                RskSubMessage::Unknown(other)
            }
        };

        Ok(RskMessage { sub_message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::{Encodable, Decodable};


    /// A REMASC transaction's zero gas price and gas limit are written as the
    /// byte 0x00, not RLP's empty string (`RemascTransaction`). Serving a
    /// canonical re-encoding would change the transaction root, and the
    /// receiving peer reject the body.
    #[test]
    fn a_remasc_body_keeps_the_bytes_its_header_commits_to() {
        use rustock_core::ordered_tx_trie_root;

        let raw = Transaction::remasc(9_263_832).rlp_for_trie();
        let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
        assert_eq!(
            tx.rlp_for_trie(),
            raw,
            "rskj's own encoding is the one kept"
        );
        let before = ordered_tx_trie_root(std::slice::from_ref(&tx), true);

        let mut buf = Vec::new();
        let msg = RskMessage::new(RskSubMessage::BodyResponse(BodyResponse {
            id: 7,
            transactions: vec![tx],
            uncles: Vec::new(),
            extension: None,
        }));
        msg.encode(&mut buf);
        let decoded = RskMessage::decode(&mut buf.as_slice()).expect("decodes");

        match decoded.sub_message {
            RskSubMessage::BodyResponse(r) => {
                assert_eq!(
                    before,
                    ordered_tx_trie_root(&r.transactions, true),
                    "the body wire must not change the transaction root"
                );
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn test_rsk_status_rlp() {
        let status = RskStatus {
            best_block_number: 1234,
            best_block_hash: B256::repeat_byte(0x11),
            best_block_parent_hash: Some(B256::repeat_byte(0x22)),
            total_difficulty: Some(U256::from(9999)),
        earliest_block: None,
        };

        let mut buf = Vec::new();
        status.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskStatus::decode(&mut decode_buf).unwrap();
        assert_eq!(status, decoded);
    }

    #[test]
    fn test_rsk_message_rlp_status() {
        let status = RskStatus {
            best_block_number: 1,
            best_block_hash: B256::repeat_byte(0xaa),
            best_block_parent_hash: None,
            total_difficulty: None,
        earliest_block: None,
        };
        let msg = RskMessage::new(RskSubMessage::Status(status));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();
        
        if let RskSubMessage::Status(s) = decoded.sub_message {
            assert_eq!(s.best_block_number, 1);
            assert_eq!(s.best_block_hash, B256::repeat_byte(0xaa));
        } else {
            panic!("Expected Status message");
        }
    }

    #[test]
    fn test_rsk_message_rlp_headers_request() {
        let req = BlockHeadersRequest {
            id: 42,
            query: BlockHeadersQuery {
                hash: B256::repeat_byte(0xbb),
                count: 10,
            },
        };
        let msg = RskMessage::new(RskSubMessage::BlockHeadersRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();
        
        if let RskSubMessage::BlockHeadersRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 42);
            assert_eq!(r.query.count, 10);
            assert_eq!(r.query.hash, B256::repeat_byte(0xbb));
        } else {
            panic!("Expected BlockHeadersRequest message");
        }
    }

    #[test]
    fn test_rsk_message_rlp_block_hash_request() {
        let req = BlockHashRequest { id: 7, height: 12345 };
        let msg = RskMessage::new(RskSubMessage::BlockHashRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BlockHashRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 7);
            assert_eq!(r.height, 12345);
        } else {
            panic!("Expected BlockHashRequest, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_block_hash_response() {
        let resp = BlockHashResponse { id: 7, hash: B256::repeat_byte(0xcc) };
        let msg = RskMessage::new(RskSubMessage::BlockHashResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BlockHashResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 7);
            assert_eq!(r.hash, B256::repeat_byte(0xcc));
        } else {
            panic!("Expected BlockHashResponse, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_skeleton_request() {
        let req = SkeletonRequest { id: 99, start_number: 5000 };
        let msg = RskMessage::new(RskSubMessage::SkeletonRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::SkeletonRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 99);
            assert_eq!(r.start_number, 5000);
        } else {
            panic!("Expected SkeletonRequest, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_skeleton_response() {
        let resp = SkeletonResponse {
            id: 99,
            block_identifiers: vec![
                BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
                BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
                BlockIdentifier { hash: B256::repeat_byte(0x03), number: 384 },
            ],
        };
        let msg = RskMessage::new(RskSubMessage::SkeletonResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::SkeletonResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 99);
            assert_eq!(r.block_identifiers.len(), 3);
            assert_eq!(r.block_identifiers[0].hash, B256::repeat_byte(0x01));
            assert_eq!(r.block_identifiers[0].number, 0);
            assert_eq!(r.block_identifiers[1].number, 192);
            assert_eq!(r.block_identifiers[2].number, 384);
        } else {
            panic!("Expected SkeletonResponse, got {:?}", decoded.sub_message);
        }
    }

    /// A `Transactions` message as it arrives on the wire: an outer RLP list
    /// whose items are each a COMPLETE transaction -- itself an RLP list.
    ///
    /// The round-trip test below cannot catch a mistake here, because it feeds
    /// our own encoder's output to our own decoder; if both are wrong in the
    /// same way it still passes. This one pins the format itself.
    ///
    /// Mainnet symptom: 19 transactions offered in five minutes, all 19
    /// rejected `rlp-decode`, because the decoder handed the pool each
    /// transaction's payload with its list header stripped off.
    #[test]
    fn transactions_decode_keeps_each_transaction_whole() {
        use alloy_primitives::Bytes;

        // A complete, self-contained RLP list: 0xc4 header + four items.
        // This stands for one transaction.
        let tx: Vec<u8> = vec![0xc4, 0x01, 0x02, 0x03, 0x04];

        // The wire message: an outer list containing that item verbatim.
        let mut inner = Vec::new();
        inner.extend_from_slice(&tx);
        let mut wire = Vec::new();
        RlpHeader { list: true, payload_length: inner.len() }.encode(&mut wire);
        wire.extend_from_slice(&inner);

        // Frame it exactly as rskj's Message.getEncoded does:
        //   RLP([ RLP([ type, RLP_String(params) ]) ])
        let mut msg_rlp = Vec::new();
        (RskMessageType::Transactions as u8).encode(&mut msg_rlp);
        RlpHeader { list: false, payload_length: wire.len() }.encode(&mut msg_rlp);
        msg_rlp.extend_from_slice(&wire);

        let mut wrapped = Vec::new();
        RlpHeader { list: true, payload_length: msg_rlp.len() }.encode(&mut wrapped);
        wrapped.extend_from_slice(&msg_rlp);

        let mut framed = Vec::new();
        RlpHeader { list: true, payload_length: wrapped.len() }.encode(&mut framed);
        framed.extend_from_slice(&wrapped);

        let mut slice = framed.as_slice();
        let decoded = RskMessage::decode(&mut slice).expect("decodes");
        let RskSubMessage::Transactions(txs) = decoded.sub_message else {
            panic!("expected Transactions");
        };
        assert_eq!(txs.len(), 1);
        assert_eq!(
            txs[0],
            Bytes::from(tx.clone()),
            "each item must survive whole, header included -- the pool decodes \
             it as a transaction, which is only valid as a complete RLP list"
        );
    }

    #[test]
    fn test_rsk_message_rlp_transactions() {
        use alloy_primitives::Bytes;

        // Complete RLP lists, as real transactions are. The previous values
        // were truncated fragments that only round-tripped because the encoder
        // wrapped them in a string header and the decoder unwrapped it again --
        // symmetric, and wrong in both directions.
        let tx1 = Bytes::from(vec![0xc4, 0x01, 0x02, 0x03, 0x04]);
        let tx2 = Bytes::from(vec![0xc6, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        let msg = RskMessage::new(RskSubMessage::Transactions(vec![tx1.clone(), tx2.clone()]));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::Transactions(txs) = decoded.sub_message {
            assert_eq!(txs.len(), 2);
            assert_eq!(txs[0], tx1);
            assert_eq!(txs[1], tx2);
        } else {
            panic!("Expected Transactions, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_body_request() {
        let req = BodyRequest { id: 55, hash: B256::repeat_byte(0xdd) };
        let msg = RskMessage::new(RskSubMessage::BodyRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BodyRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 55);
            assert_eq!(r.hash, B256::repeat_byte(0xdd));
        } else {
            panic!("Expected BodyRequest, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_body_response_empty() {
        let resp = BodyResponse {
            id: 55,
            transactions: vec![],
            uncles: vec![],
            extension: None,
        };
        let msg = RskMessage::new(RskSubMessage::BodyResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BodyResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 55);
            assert!(r.transactions.is_empty());
            assert!(r.uncles.is_empty());
        } else {
            panic!("Expected BodyResponse, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_body_response_with_data() {
        use rustock_core::Transaction;

        let tx = Transaction {
            nonce: 1,
            gas_price: U256::from(10),
            gas_limit: U256::from(21000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1000),
            input: Bytes::default(),
            v: 27,
            r: U256::from(88),
            s: U256::from(99),
            cached_rlp: None,
        };

        let resp = BodyResponse {
            id: 77,
            transactions: vec![tx],
            uncles: vec![],
            extension: None,
        };
        let msg = RskMessage::new(RskSubMessage::BodyResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BodyResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 77);
            assert_eq!(r.transactions.len(), 1);
            assert_eq!(r.transactions[0].nonce, 1);
            assert!(r.uncles.is_empty());
        } else {
            panic!("Expected BodyResponse, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_body_response_with_txs_and_uncles() {
        use rustock_core::Transaction;
        use alloy_primitives::Address;

        fn make_tx(nonce: u64) -> Transaction {
            Transaction {
                nonce,
                gas_price: U256::from(20_000_000_000u64),
                gas_limit: U256::from(21000),
                to: Bytes::from(Address::repeat_byte(0xAA).as_slice().to_vec()),
                value: U256::from(nonce * 1000 + 1000),
                input: Bytes::default(),
                v: 27,
                r: U256::from(nonce + 100),
                s: U256::from(nonce + 200),
                cached_rlp: None,
            }
        }

        fn make_uncle(number: u64) -> Header {
            Header {
                number,
                parent_hash: B256::repeat_byte(number as u8),
                ommers_hash: B256::ZERO,
                beneficiary: Address::ZERO,
                state_root: B256::ZERO,
                transactions_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(1000),
                gas_limit: U256::from(8_000_000),
                gas_used: 0,
                timestamp: number * 15,
                extra_data: Bytes::default(),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::ZERO,
                uncle_count: 0,
                umm_root: None,
                version_fields: None,
                bitcoin_merged_mining_header: None,
                bitcoin_merged_mining_merkle_proof: None,
                bitcoin_merged_mining_coinbase_transaction: None,
                cached_hash: None,
                cached_hash_for_merged_mining: None,
                kept: None,
            }
        }

        let transactions: Vec<Transaction> = (1..=10).map(make_tx).collect();
        let uncles: Vec<Header> = (1..=9).map(make_uncle).collect();

        let resp = BodyResponse {
            id: 100,
            transactions: transactions.clone(),
            uncles: uncles.clone(),
            extension: None,
        };
        let msg = RskMessage::new(RskSubMessage::BodyResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BodyResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 100);
            assert_eq!(r.transactions.len(), 10);
            assert_eq!(r.uncles.len(), 9);

            for (i, tx) in r.transactions.iter().enumerate() {
                let n = (i + 1) as u64;
                assert_eq!(tx.nonce, n, "tx {i} nonce mismatch");
                assert_eq!(tx.value, U256::from(n * 1000 + 1000));
            }

            for (i, uncle) in r.uncles.iter().enumerate() {
                let n = (i + 1) as u64;
                assert_eq!(uncle.number, n, "uncle {i} number mismatch");
                assert_eq!(uncle.parent_hash, B256::repeat_byte(n as u8));
            }
        } else {
            panic!("Expected BodyResponse, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_body_response_uncles_only() {
        use alloy_primitives::Address;

        let uncle = Header {
            number: 42,
            parent_hash: B256::repeat_byte(0x11),
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(500),
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: 630,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
            kept: None,
        };

        let resp = BodyResponse {
            id: 88,
            transactions: vec![],
            uncles: vec![uncle],
            extension: None,
        };
        let msg = RskMessage::new(RskSubMessage::BodyResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BodyResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 88);
            assert!(r.transactions.is_empty());
            assert_eq!(r.uncles.len(), 1);
            assert_eq!(r.uncles[0].number, 42);
            assert_eq!(r.uncles[0].difficulty, U256::from(500));
        } else {
            panic!("Expected BodyResponse, got {:?}", decoded.sub_message);
        }
    }

    /// A body response with these elements after its id, framed as rskj frames
    /// a message: `RLP([RLP([15, RLP_String(RLP([id, RLP(elements)]))])])`.
    fn body_frame(id: u64, elements: &[Vec<u8>]) -> Vec<u8> {
        let wrap = |list: bool, payload: &[u8]| {
            let mut out = Vec::new();
            RlpHeader {
                list,
                payload_length: payload.len(),
            }
            .encode(&mut out);
            out.extend_from_slice(payload);
            out
        };
        let mut params = Vec::new();
        id.encode(&mut params);
        params.extend_from_slice(&wrap(true, &elements.concat()));
        let mut message = Vec::new();
        15u8.encode(&mut message);
        message.extend_from_slice(&wrap(false, &wrap(true, &params)));
        wrap(true, &wrap(true, &message))
    }

    /// **The extension beside a body.** rskj sends a version-1 or version-2
    /// block's header extension as the body's third element
    /// (`BodyResponseMessage`), as `BlockHeaderExtension.toEncoded` writes it,
    /// and reads one only from a body of exactly three
    /// (`MessageType.BODY_RESPONSE`), refusing a third that isn't one.
    #[test]
    fn a_body_carries_its_header_extension_as_rskj_sends_it() {
        let empty = vec![0xc0];
        let mut bloom = vec![0u8; 256];
        bloom[3] = 0x40;
        let extensions = [
            BlockHeaderExtension::V1 {
                logs_bloom: bloom.clone(),
                edges: Some(vec![2, 5]),
            },
            BlockHeaderExtension::V2 {
                logs_bloom: bloom.clone(),
                edges: None,
                base_event: Some(vec![0xbe; 9]),
            },
            BlockHeaderExtension::V2 {
                logs_bloom: bloom,
                edges: Some(vec![]),
                base_event: Some(Vec::new()),
            },
        ];
        for extension in extensions {
            let msg = RskMessage::new(RskSubMessage::BodyResponse(BodyResponse {
                id: 9,
                transactions: vec![],
                uncles: vec![],
                extension: Some(extension.clone()),
            }));
            let mut buf = Vec::new();
            msg.encode(&mut buf);
            assert_eq!(
                buf,
                body_frame(9, &[empty.clone(), empty.clone(), extension.to_encoded()])
            );
            match RskMessage::decode(&mut buf.as_slice())
                .expect("decodes")
                .sub_message
            {
                RskSubMessage::BodyResponse(r) => assert_eq!(r.extension, Some(extension)),
                other => panic!("decoded as {other:?}"),
            }
        }

        // Without one, as for a version-0 block, the body has two elements.
        let msg = RskMessage::new(RskSubMessage::BodyResponse(BodyResponse {
            id: 9,
            transactions: vec![],
            uncles: vec![],
            extension: None,
        }));
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf, body_frame(9, &[empty.clone(), empty.clone()]));

        // With a fourth element, rskj reads no extension at all.
        let extension = BlockHeaderExtension::V1 {
            logs_bloom: vec![0; 256],
            edges: None,
        }
        .to_encoded();
        let four = body_frame(
            9,
            &[empty.clone(), empty.clone(), extension.clone(), extension],
        );
        match RskMessage::decode(&mut four.as_slice())
            .expect("decodes")
            .sub_message
        {
            RskSubMessage::BodyResponse(r) => assert_eq!(r.extension, None),
            other => panic!("decoded as {other:?}"),
        }

        // A string, an unknown version, a list of one: none is an extension.
        for bad in [
            vec![0x83, 1, 2, 3],
            vec![0xc2, 0x03, 0x80],
            vec![0xc1, 0x01],
        ] {
            let frame = body_frame(9, &[empty.clone(), empty.clone(), bad.clone()]);
            assert!(
                RskMessage::decode(&mut frame.as_slice()).is_err(),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn test_rsk_message_rlp_transactions_empty() {
        let msg = RskMessage::new(RskSubMessage::Transactions(vec![]));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::Transactions(txs) = decoded.sub_message {
            assert!(txs.is_empty());
        } else {
            panic!("Expected Transactions, got {:?}", decoded.sub_message);
        }
    }
}

#[cfg(test)]
mod block_range_tests {
    use super::*;

    fn status(earliest: Option<u64>) -> RskStatus {
        RskStatus {
            best_block_number: 9_000_000,
            best_block_hash: B256::repeat_byte(0x11),
            best_block_parent_hash: Some(B256::repeat_byte(0x22)),
            total_difficulty: Some(U256::from(123_456_789u64)),
            earliest_block: earliest,
        }
    }

    /// The fifth element goes after the four rskj reads, never instead of one.
    ///
    /// rskj's decoder takes indices 0..3 and never consults the length again,
    /// so an extra element is ignored — but only because it is *extra*.
    /// Replacing total difficulty, as `eth/69` did, would change what index 3
    /// means and make every rskj peer read a block number as a difficulty.
    #[test]
    fn the_extension_is_appended_and_displaces_nothing() {
        let mut plain = Vec::new();
        status(None).encode(&mut plain);
        let mut extended = Vec::new();
        status(Some(8_992_000)).encode(&mut extended);

        // Compare payloads, not whole messages: the list header carries the
        // length, so it differs by construction.
        let payload = |mut buf: &[u8]| -> Vec<u8> {
            let h = RlpHeader::decode(&mut buf).expect("header");
            buf[..h.payload_length].to_vec()
        };
        let plain = payload(&plain);
        let extended = payload(&extended);

        assert!(
            extended.len() > plain.len(),
            "the extension must add to the message, not rewrite it"
        );
        assert_eq!(
            &extended[..plain.len()],
            &plain[..],
            "the four fields rskj reads must be byte-identical and in place; \
             replacing one, as eth/69 did with total difficulty, would make every \
             rskj peer read this node's numbers as something else"
        );
    }

    #[test]
    fn a_status_with_the_extension_round_trips() {
        let original = status(Some(8_992_000));
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let decoded = RskStatus::decode(&mut buf.as_slice()).expect("decodes");
        assert_eq!(decoded.earliest_block, Some(8_992_000));
        assert_eq!(decoded.best_block_number, original.best_block_number);
        assert_eq!(decoded.total_difficulty, original.total_difficulty);
    }

    /// What an rskj peer sends: four elements, no range. It must read as
    /// "did not say", never as "serves nothing from zero".
    #[test]
    fn a_four_element_status_says_nothing_rather_than_zero() {
        let mut buf = Vec::new();
        status(None).encode(&mut buf);
        let decoded = RskStatus::decode(&mut buf.as_slice()).expect("decodes");
        assert_eq!(
            decoded.earliest_block, None,
            "silence must stay distinguishable from a stated floor of zero"
        );
    }

    /// And the two-element form rskj also emits.
    #[test]
    fn a_two_element_status_still_decodes() {
        let bare = RskStatus {
            best_block_number: 42,
            best_block_hash: B256::repeat_byte(0x33),
            best_block_parent_hash: None,
            total_difficulty: None,
            earliest_block: None,
        };
        let mut buf = Vec::new();
        bare.encode(&mut buf);
        let decoded = RskStatus::decode(&mut buf.as_slice()).expect("decodes");
        assert_eq!(decoded.best_block_number, 42);
        assert_eq!(decoded.earliest_block, None);
    }

    /// A sixth element, as some later extension would add, must not break
    /// this one — the same courtesy rskj extends to us.
    #[test]
    fn a_later_extension_does_not_break_this_one() {
        let mut list = Vec::new();
        9_000_000u64.encode(&mut list);
        B256::repeat_byte(0x11).encode(&mut list);
        B256::repeat_byte(0x22).encode(&mut list);
        U256::from(7u64).encode(&mut list);
        8_992_000u64.encode(&mut list);
        99u64.encode(&mut list); // whatever comes next
        let mut buf = Vec::new();
        RlpHeader { list: true, payload_length: list.len() }.encode(&mut buf);
        buf.extend_from_slice(&list);

        let decoded = RskStatus::decode(&mut buf.as_slice()).expect("decodes");
        assert_eq!(decoded.earliest_block, Some(8_992_000));
    }

    /// The update survives the full message framing, not just its own RLP:
    /// type byte 26, the blob wrapper, and the outer list rskj's
    /// `Eth62MessageFactory` unwraps.
    #[test]
    fn a_range_update_round_trips_through_the_whole_message() {
        let range = BlockRange {
            earliest_block: 9_278_157,
            latest_block: 9_286_156,
            latest_block_hash: B256::repeat_byte(0x55),
        };
        let msg = RskMessage::new(RskSubMessage::BlockRangeUpdate(range));
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(&msg, &mut buf);

        let decoded = RskMessage::decode(&mut buf.as_slice()).expect("decodes");
        match decoded.sub_message {
            RskSubMessage::BlockRangeUpdate(got) => assert_eq!(got, range),
            other => panic!("framed as {other:?}"),
        }
    }

    #[test]
    fn a_block_range_round_trips() {
        let range = BlockRange {
            earliest_block: 9_270_000,
            latest_block: 9_280_000,
            latest_block_hash: B256::repeat_byte(0x44),
        };
        let mut buf = Vec::new();
        range.encode(&mut buf);
        assert_eq!(BlockRange::decode(&mut buf.as_slice()).expect("decodes"), range);
    }

    /// 26 is free in rskj, whose highest message type is 25.
    #[test]
    fn the_new_message_type_does_not_collide() {
        assert_eq!(RskMessageType::BlockRangeUpdate as u8, 26);
        assert_eq!(RskMessageType::SnapBlocksResponse as u8, 25);
    }
}

#[cfg(test)]
mod rskj_interop {
    use super::*;

    /// Dumps the exact bytes this node puts on the wire for an extended
    /// status, so they can be fed to rskj's own decoder.
    ///
    /// Run with `cargo test -p rustock-networking rskj_interop -- --nocapture --ignored`.
    /// The companion Java probe decodes the output through
    /// `co.rsk.net.messages.Message.create`, which is what an rskj node runs.
    #[test]
    #[ignore = "produces input for the cross-implementation check"]
    fn dump_wire_bytes_for_rskj() {
        for (label, earliest) in [("four-element", None), ("extended", Some(8_992_000u64))] {
            let status = RskStatus {
                best_block_number: 9_000_000,
                best_block_hash: B256::repeat_byte(0x11),
                best_block_parent_hash: Some(B256::repeat_byte(0x22)),
                total_difficulty: Some(U256::from(123_456_789u64)),
                earliest_block: earliest,
            };
            let msg = RskMessage::new(RskSubMessage::Status(status));
            let mut buf = Vec::new();
            alloy_rlp::Encodable::encode(&msg, &mut buf);
            let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
            println!("{label} {hex}");
        }
    }
}


#[cfg(test)]
mod headers_with_uncles_tests {
    use super::*;
    use alloy_primitives::Address;

    pub(super) fn plain(number: u64, difficulty: u64) -> Header {
        Header {
            number,
            parent_hash: B256::repeat_byte(number as u8),
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(difficulty),
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: number * 15,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
            kept: None,
        }
    }

    /// Build a trunk header that genuinely commits to `uncles`.
    fn with_uncles(number: u64, difficulty: u64, uncles: Vec<Header>) -> HeaderWithUncles {
        let mut header = plain(number, difficulty);
        header.uncle_count = uncles.len() as u64;
        let entry = HeaderWithUncles { header, uncles };
        let commitment = alloy_primitives::keccak256(entry.encoded_uncles());
        let mut header = entry.header;
        header.ommers_hash = commitment;
        HeaderWithUncles { header, uncles: entry.uncles }
    }

    pub(super) fn roundtrip(sub: RskSubMessage) -> RskSubMessage {
        let mut buf = Vec::new();
        RskMessage::new(sub).encode(&mut buf);
        RskMessage::decode(&mut buf.as_slice()).expect("decodes").sub_message
    }

    #[test]
    fn request_roundtrips() {
        let req = BlockHeadersWithUnclesRequest {
            id: 42,
            query: BlockHeadersQuery { hash: B256::repeat_byte(7), count: 192 },
        };
        match roundtrip(RskSubMessage::BlockHeadersWithUnclesRequest(req.clone())) {
            RskSubMessage::BlockHeadersWithUnclesRequest(got) => assert_eq!(got, req),
            other => panic!("wrong message: {other:?}"),
        }
    }

    #[test]
    fn response_roundtrips_and_carries_the_uncles() {
        let entries = vec![
            with_uncles(10, 1000, vec![plain(9, 700), plain(8, 650)]),
            with_uncles(11, 1100, vec![]),
        ];
        let resp = BlockHeadersWithUnclesResponse { id: 5, entries: entries.clone() };

        match roundtrip(RskSubMessage::BlockHeadersWithUnclesResponse(resp)) {
            RskSubMessage::BlockHeadersWithUnclesResponse(got) => {
                assert_eq!(got.id, 5);
                assert_eq!(got.entries.len(), 2);
                assert_eq!(got.entries[0].uncles.len(), 2);
                assert_eq!(got.entries[1].uncles.len(), 0);
                for e in &got.entries {
                    assert!(e.commitment_matches(), "survives the wire");
                }
            }
            other => panic!("wrong message: {other:?}"),
        }
    }

    /// The whole point of the message: uncle difficulty joins the total.
    #[test]
    fn cumulative_difficulty_adds_the_uncles() {
        let entry = with_uncles(10, 1000, vec![plain(9, 700), plain(8, 650)]);
        assert_eq!(entry.cumulative_difficulty(), U256::from(2350u64));
    }

    /// A peer that swaps in a different uncle list is refused at the parse
    /// boundary: the trunk header's `ommers_hash` names the list, and the
    /// header's proof of work is what makes that name expensive to forge.
    #[test]
    fn a_substituted_uncle_list_is_rejected() {
        let honest = with_uncles(10, 1000, vec![plain(9, 700)]);
        // Keep the header, inflate the uncle's difficulty.
        let forged = HeaderWithUncles {
            header: honest.header.clone(),
            uncles: vec![plain(9, 9_000_000)],
        };
        assert!(!forged.commitment_matches());

        let mut buf = Vec::new();
        RskMessage::new(RskSubMessage::BlockHeadersWithUnclesResponse(
            BlockHeadersWithUnclesResponse { id: 1, entries: vec![forged] },
        ))
        .encode(&mut buf);

        let err = RskMessage::decode(&mut buf.as_slice()).unwrap_err();
        assert!(
            format!("{err:?}").contains("ommers hash"),
            "refused for the right reason: {err:?}"
        );
    }

    /// Dropping an uncle is the cheap way to understate a rival chain's work,
    /// and the count check plus the commitment both catch it.
    #[test]
    fn a_dropped_uncle_is_rejected() {
        let honest = with_uncles(10, 1000, vec![plain(9, 700), plain(8, 650)]);
        let stripped = HeaderWithUncles {
            header: honest.header.clone(),
            uncles: vec![honest.uncles[0].clone()],
        };
        assert!(!stripped.commitment_matches());

        let mut buf = Vec::new();
        RskMessage::new(RskSubMessage::BlockHeadersWithUnclesResponse(
            BlockHeadersWithUnclesResponse { id: 1, entries: vec![stripped] },
        ))
        .encode(&mut buf);
        assert!(RskMessage::decode(&mut buf.as_slice()).is_err());
    }

    /// **No message a peer sends panics the decoder.**
    ///
    /// Each RSK message is built as a peer would send it, with content of
    /// each kind in its body, and then varied byte by byte. Every type number
    /// is also sent with a random tree of RLP for its body, so that each
    /// message's field reads meet strings and lists of every shape. Only that
    /// each decode returns is asserted.
    #[test]
    fn no_variation_on_a_message_panics_the_decoder() {
        use rustock_core::Transaction;

        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
            fn below(&mut self, n: usize) -> usize {
                (self.next() % n.max(1) as u64) as usize
            }
        }

        // The bytes that start RLP's items, at the edges of each form.
        const EDGES: [u8; 12] = [
            0x00, 0x7f, 0x80, 0x81, 0x9f, 0xa0, 0xb7, 0xb8, 0xbf, 0xc0, 0xf7, 0xff,
        ];

        fn vary(bytes: &mut Vec<u8>, rng: &mut Rng) {
            for _ in 0..1 + rng.below(3) {
                let at = rng.below(bytes.len() + 1);
                match rng.below(6) {
                    0 if at < bytes.len() => bytes[at] ^= 1 << rng.below(8),
                    1 if at < bytes.len() => bytes[at] = EDGES[rng.below(EDGES.len())],
                    2 => bytes.insert(at, EDGES[rng.below(EDGES.len())]),
                    3 if at < bytes.len() => {
                        let n = 1 + rng.below(8.min(bytes.len() - at));
                        bytes.drain(at..at + n);
                    }
                    4 => bytes.truncate(at),
                    _ => bytes.insert(at, rng.next() as u8),
                }
            }
        }

        /// A random RLP item: a string of a size fields come in, or a list of
        /// up to five more items.
        fn tree(rng: &mut Rng, depth: u32, out: &mut Vec<u8>) {
            if depth == 0 || rng.below(3) == 0 {
                let len = [0, 1, 1, 2, 8, 20, 32, 33, 65, 100][rng.below(10)];
                let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                bytes.as_slice().encode(out);
            } else {
                let mut body = Vec::new();
                for _ in 0..rng.below(6) {
                    tree(rng, depth - 1, &mut body);
                }
                RlpHeader {
                    list: true,
                    payload_length: body.len(),
                }
                .encode(out);
                out.extend_from_slice(&body);
            }
        }

        /// `params` in the envelope `RskMessage::encode` writes: a list of a
        /// list of the type and the parameters as a string.
        fn envelope(kind: u8, params: &[u8]) -> Vec<u8> {
            let mut message = Vec::new();
            kind.encode(&mut message);
            RlpHeader {
                list: false,
                payload_length: params.len(),
            }
            .encode(&mut message);
            message.extend_from_slice(params);
            let mut wrapped = Vec::new();
            RlpHeader {
                list: true,
                payload_length: message.len(),
            }
            .encode(&mut wrapped);
            wrapped.extend_from_slice(&message);
            let mut out = Vec::new();
            RlpHeader {
                list: true,
                payload_length: wrapped.len(),
            }
            .encode(&mut out);
            out.extend_from_slice(&wrapped);
            out
        }

        let tx = Transaction {
            nonce: 1,
            gas_price: U256::from(10),
            gas_limit: U256::from(21000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1000),
            input: Bytes::from(vec![1, 2, 3]),
            v: 27,
            r: U256::from(88),
            s: U256::from(99),
            cached_rlp: None,
        };
        let identifier = |n: u8| BlockIdentifier {
            hash: B256::repeat_byte(n),
            number: 192 * n as u64,
        };
        let seeds = vec![
            RskSubMessage::Status(RskStatus {
                best_block_number: 9,
                best_block_hash: B256::repeat_byte(1),
                best_block_parent_hash: Some(B256::repeat_byte(2)),
                total_difficulty: Some(U256::from(1u64 << 63)),
                earliest_block: Some(3),
            }),
            RskSubMessage::BlockHashRequest(BlockHashRequest { id: 1, height: 192 }),
            RskSubMessage::BlockHashResponse(BlockHashResponse {
                id: 1,
                hash: B256::repeat_byte(4),
            }),
            RskSubMessage::BlockHeadersRequest(BlockHeadersRequest {
                id: 2,
                query: BlockHeadersQuery {
                    hash: B256::repeat_byte(5),
                    count: 192,
                },
            }),
            RskSubMessage::BlockHeadersResponse(BlockHeadersResponse {
                id: 2,
                headers: vec![plain(10, 1000), plain(9, 900)],
            }),
            RskSubMessage::SkeletonRequest(SkeletonRequest {
                id: 3,
                start_number: 5000,
            }),
            RskSubMessage::SkeletonResponse(SkeletonResponse {
                id: 3,
                block_identifiers: vec![identifier(1), identifier(2)],
            }),
            RskSubMessage::BodyRequest(BodyRequest {
                id: 4,
                hash: B256::repeat_byte(7),
            }),
            RskSubMessage::BodyResponse(BodyResponse {
                id: 4,
                transactions: vec![tx.clone()],
                uncles: vec![plain(8, 800)],
                extension: None,
            }),
            RskSubMessage::Transactions(vec![Bytes::from(alloy_rlp::encode(&tx))]),
            RskSubMessage::BlockRangeUpdate(BlockRange {
                earliest_block: 1,
                latest_block: 2,
                latest_block_hash: B256::repeat_byte(8),
            }),
            RskSubMessage::BlockHeadersWithUnclesRequest(BlockHeadersWithUnclesRequest {
                id: 5,
                query: BlockHeadersQuery {
                    hash: B256::repeat_byte(9),
                    count: 3,
                },
            }),
            RskSubMessage::BlockHeadersWithUnclesResponse(BlockHeadersWithUnclesResponse {
                id: 5,
                entries: vec![with_uncles(10, 1000, vec![plain(9, 700)])],
            }),
            RskSubMessage::Block(Box::new(rustock_core::Block {
                header: plain(11, 1100),
                transactions: vec![tx.clone()],
                ommers: vec![plain(10, 1000)],
            })),
            RskSubMessage::GetBlock(B256::repeat_byte(6)),
            RskSubMessage::NewBlockHashes(vec![identifier(1), identifier(2)]),
        ];

        let mut messages: Vec<(String, Vec<u8>)> = seeds
            .into_iter()
            .map(|seed| {
                let kind = format!("{:?}", seed.message_type());
                let mut bytes = Vec::new();
                RskMessage::new(seed).encode(&mut bytes);
                (kind, bytes)
            })
            .collect();
        // And the list of [hash, number] pairs an rskj node sends, built by
        // hand rather than by this node's encoder.
        let mut pairs = Vec::new();
        for n in 1..=3u8 {
            let mut pair = Vec::new();
            B256::repeat_byte(n).encode(&mut pair);
            (192 * n as u64).encode(&mut pair);
            RlpHeader {
                list: true,
                payload_length: pair.len(),
            }
            .encode(&mut pairs);
            pairs.extend_from_slice(&pair);
        }
        let mut params = Vec::new();
        RlpHeader {
            list: true,
            payload_length: pairs.len(),
        }
        .encode(&mut params);
        params.extend_from_slice(&pairs);
        messages.push(("NewBlockHashes".into(), envelope(6, &params)));

        // As the session reads them: the P2P message id, then the message.
        let rsk_id = {
            let mut framed = Vec::new();
            let probe = RskSubMessage::BodyRequest(BodyRequest {
                id: 0,
                hash: B256::ZERO,
            });
            crate::protocol::p2p::P2pMessage::RskMessage(RskMessage::new(probe))
                .encode(&mut framed);
            framed[0]
        };
        let mut rng = Rng(0x6A09_E667_F3BC_C908);
        for (kind, message) in messages {
            let mut honest = vec![rsk_id];
            honest.extend_from_slice(&message);
            let decoded = crate::protocol::p2p::P2pMessage::decode(&mut honest.as_slice());
            assert!(
                decoded.is_ok(),
                "the {kind} seed does not decode, so varying it tests nothing: {decoded:?}"
            );
            for _ in 0..1_500 {
                let mut bytes = honest.clone();
                vary(&mut bytes, &mut rng);
                let _ = crate::protocol::p2p::P2pMessage::decode(&mut bytes.as_slice());
                let _ = RskMessage::decode(&mut bytes.get(1..).unwrap_or_default());
            }
        }
        for kind in 0..=30u8 {
            for _ in 0..300 {
                let mut params = Vec::new();
                tree(&mut rng, 4, &mut params);
                let _ = RskMessage::decode(&mut envelope(kind, &params).as_slice());
            }
        }
        // Every P2P message id, each with a random body.
        for id in 0..=u8::MAX {
            for _ in 0..40 {
                let mut framed = vec![id];
                tree(&mut rng, 4, &mut framed);
                let _ = crate::protocol::p2p::P2pMessage::decode(&mut framed.as_slice());
            }
        }
    }
}

#[cfg(test)]
mod difficulty_encoding_tests {
    use super::*;

    /// rskj reads a difficulty with `new BigInteger(bytes)` -- signed, two's
    /// complement -- so a value whose top bit is set must carry a leading
    /// `0x00`, exactly as `BigInteger.toByteArray()` writes it. Without it
    /// rskj throws "A block difficulty must be positive or zero" while
    /// decoding and drops the connection.
    #[test]
    fn a_value_with_the_top_bit_set_carries_a_sign_byte() {
        // Mainnet's total difficulty at #9,288,884 once uncle difficulty was
        // counted. Its first byte is 0xc5, which Java reads as negative.
        let td = U256::from_str_radix("61049215127746862789732304263", 10).unwrap();
        let mut out = Vec::new();
        encode_difficulty(td, &mut out);

        // RLP string header, then the bytes.
        let payload = &out[1..];
        assert_eq!(payload[0], 0x00, "sign byte present");
        assert_eq!(payload[1], 0xc5, "magnitude follows it");
        assert_eq!(payload.len(), 13, "12 magnitude bytes plus the sign byte");
    }

    /// A value that does not set the top bit gains nothing -- matching
    /// `BigInteger.toByteArray()`, which only pads when it must.
    #[test]
    fn a_value_below_the_sign_bit_is_unpadded() {
        // The same chain's total before uncles were counted: first byte 0x70.
        let td = U256::from_str_radix("34690046850504217865101415175", 10).unwrap();
        let mut out = Vec::new();
        encode_difficulty(td, &mut out);

        let payload = &out[1..];
        assert_eq!(payload[0], 0x70);
        assert_eq!(payload.len(), 12);
    }

    /// `BigInteger.ZERO.toByteArray()` is a single zero byte, not an empty
    /// array; `new BigInteger(new byte[0])` would throw.
    #[test]
    fn zero_is_a_single_zero_byte() {
        let mut out = Vec::new();
        encode_difficulty(U256::ZERO, &mut out);
        assert_eq!(out, vec![0x00], "encodes as the single byte 0x00");
    }

    /// `length()` must agree with what `encode` writes, or the RLP list header
    /// says one thing and the body another.
    #[test]
    fn the_declared_length_matches_what_is_written() {
        for v in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(0x7fu64),
            U256::from(0x80u64),
            U256::from_str_radix("61049215127746862789732304263", 10).unwrap(),
            U256::MAX,
        ] {
            let mut out = Vec::new();
            encode_difficulty(v, &mut out);
            assert_eq!(difficulty_length(v), out.len(), "mismatch for {v}");
        }
    }

    /// A status message carrying such a total must still round-trip through
    /// our own decoder, which strips the sign byte back off.
    #[test]
    fn status_with_a_top_bit_total_round_trips() {
        let td = U256::from_str_radix("61049215127746862789732304263", 10).unwrap();
        let status = RskStatus {
            best_block_number: 9_288_884,
            best_block_hash: B256::repeat_byte(1),
            best_block_parent_hash: Some(B256::repeat_byte(2)),
            total_difficulty: Some(td),
            earliest_block: None,
        };
        let mut buf = Vec::new();
        status.encode(&mut buf);
        let back = RskStatus::decode(&mut buf.as_slice()).expect("decodes");
        assert_eq!(back.total_difficulty, Some(td));
    }
}

/// The three messages rskj announces and hands over new blocks with, as rskj
/// writes them: built here by hand from its encoders, not by this node's.
#[cfg(test)]
mod block_message_tests {
    use super::headers_with_uncles_tests::{plain, roundtrip};
    use super::*;

    /// RLP's string: one byte below 0x80 stands for itself.
    fn string(bytes: &[u8]) -> Vec<u8> {
        if let [byte] = bytes {
            if *byte < 0x80 {
                return vec![*byte];
            }
        }
        let mut out = Vec::new();
        RlpHeader {
            list: false,
            payload_length: bytes.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(bytes);
        out
    }

    fn list(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        RlpHeader {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(payload);
        out
    }

    /// `Message.getEncoded`: `[type, string(params)]`, inside the list
    /// `RskMessage.encode` adds.
    fn frame(kind: u8, params: &[u8]) -> Vec<u8> {
        let mut message = string(&[kind]);
        message.extend(string(params));
        list(&list(&message))
    }

    fn written(sub: RskSubMessage) -> Vec<u8> {
        let mut out = Vec::new();
        RskMessage::new(sub).encode(&mut out);
        out
    }

    /// `NewBlockHashesMessage.encode`: a list of `BlockIdentifier.getEncoded`,
    /// each `RLP.encodeList(encodeElement(hash), encodeBigInteger(number))`.
    #[test]
    fn new_block_hashes_are_written_as_rskj_writes_them() {
        let identifiers = vec![
            BlockIdentifier {
                hash: B256::repeat_byte(0x11),
                number: 0x7f,
            },
            BlockIdentifier {
                hash: B256::repeat_byte(0x22),
                number: 9_348_613,
            },
        ];
        let mut pairs = Vec::new();
        for identifier in &identifiers {
            let number = identifier.number.to_be_bytes();
            let first = number.iter().position(|b| *b != 0).unwrap_or(number.len());
            let mut pair = string(identifier.hash.as_slice());
            pair.extend(string(&number[first..]));
            pairs.extend(list(&pair));
        }
        assert_eq!(
            written(RskSubMessage::NewBlockHashes(identifiers.clone())),
            frame(6, &list(&pairs))
        );
        let RskSubMessage::NewBlockHashes(back) =
            roundtrip(RskSubMessage::NewBlockHashes(identifiers.clone()))
        else {
            panic!("read back as another message");
        };
        assert_eq!(back, identifiers);
    }

    /// `BlockMessage.getEncodedMessage`: `RLP.encodeList(RLP.encode(
    /// block.getEncoded()))`, the block as the one string in a list, which
    /// `MessageType.BLOCK_MESSAGE` hands whole to `BlockFactory.decodeBlock`.
    #[test]
    fn a_block_is_written_as_rskj_writes_it() {
        let block = Block {
            header: Header {
                uncle_count: 1,
                ..plain(7, 700)
            },
            transactions: Vec::new(),
            ommers: vec![plain(6, 600)],
        };
        assert_eq!(
            written(RskSubMessage::Block(Box::new(block.clone()))),
            frame(2, &list(&string(&snap::encode_block(&block))))
        );
        let RskSubMessage::Block(back) = roundtrip(RskSubMessage::Block(Box::new(block.clone())))
        else {
            panic!("read back as another message");
        };
        assert_eq!(back.hash(), block.hash());
        assert_eq!(back.ommers.len(), 1);
        assert_eq!(back.ommers[0].hash(), block.ommers[0].hash());
    }

    /// `GetBlockMessage.getEncodedMessage`: `RLP.encodeList(encodeElement(hash))`.
    #[test]
    fn a_block_request_is_written_as_rskj_writes_it() {
        let hash = B256::repeat_byte(0x33);
        assert_eq!(
            written(RskSubMessage::GetBlock(hash)),
            frame(3, &list(&string(hash.as_slice())))
        );
        let RskSubMessage::GetBlock(back) = roundtrip(RskSubMessage::GetBlock(hash)) else {
            panic!("read back as another message");
        };
        assert_eq!(back, hash);
    }

    /// rskj's numbers for the two types, which no other message uses.
    #[test]
    fn the_block_messages_have_rskjs_type_numbers() {
        assert_eq!(RskMessageType::Block as u8, 2);
        assert_eq!(RskMessageType::GetBlock as u8, 3);
        assert_eq!(RskMessageType::NewBlockHashes as u8, 6);
    }
}
