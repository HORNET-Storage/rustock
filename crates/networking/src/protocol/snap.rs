//! Snapshot sync messages (rskj message types 20-25).
//!
//! # Relationship to rskj
//!
//! The six commands, their type numbers, and the `RLP([id, body])` envelope
//! are rskj's. Two things differ, both in the direction of trusting the peer
//! less.
//!
//! **The chunk request names the state root.** rskj asks for "the state at
//! block N" and takes whatever the peer sends, having learned the root from
//! that same peer's snap status. Here the client, which has already verified
//! a header chain, says which root it wants. Peers then cannot disagree about
//! what is being downloaded, which is also what makes fetching one state from
//! several peers at once straightforward. The root is a fourth element
//! appended to rskj's three; rskj reads the first two and ignores the rest, so
//! the request stays readable by an rskj node.
//!
//! **The chunk response body carries proved nodes rather than an opaque
//! blob.** rskj's first element is an RLP *string* holding its own
//! serialization -- nodes with the child hashes stripped, to be rebuilt
//! client-side. Ours is an RLP *list* of nodes in consensus form, each
//! independently verifiable and directly storable (see
//! `rustock_trie::snapshot_proof`).
//!
//! The two are told apart by the RLP header alone: string means rskj, list
//! means rustock. So a rustock client that dials an rskj snap server gets a
//! clear "this peer speaks the older chunk format" instead of a
//! misinterpretation, and the older format can be added later as a decode
//! path without another protocol change. In practice they do not meet today:
//! rskj ships snapshot sync disabled on both sides with no snap boot nodes.

use alloy_primitives::{Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};
use rustock_core::rlp_compat::{decode_u64_lenient, decode_u256_lenient};
use rustock_core::{Block, Header, Transaction};

/// Snap message type numbers, as rskj assigns them.
pub mod message_type {
    pub const STATE_CHUNK_REQUEST: u8 = 20;
    pub const STATE_CHUNK_RESPONSE: u8 = 21;
    pub const STATUS_REQUEST: u8 = 22;
    pub const STATUS_RESPONSE: u8 = 23;
    pub const BLOCKS_REQUEST: u8 = 24;
    pub const BLOCKS_RESPONSE: u8 = 25;
}

/// "What state can you serve, and from which block?" (type 22, empty body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapStatusRequest {
    pub id: u64,
}

/// The checkpoint block, its recent ancestors, and the size of its state
/// (type 23).
///
/// `trie_size` is a hint for progress reporting. The client learns the real
/// size from the root node itself, which arrives in the first chunk's
/// witness and commits to its own subtree size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapStatusResponse {
    pub id: u64,
    /// Oldest first; the last is the checkpoint whose state root is synced.
    pub blocks: Vec<Block>,
    /// Cumulative difficulty of each block, positionally aligned.
    pub difficulties: Vec<U256>,
    pub trie_size: u64,
    /// The offset-space grid this server's chunks sit on.
    ///
    /// Clients align their requests to it so that everyone asks for the same
    /// cells and the server can answer from cache. Zero means unstated, which
    /// is what an rskj server sends -- it has a grid, but keeps it in local
    /// config and expects the client's to match, which is how a client and
    /// server with different settings silently leave holes in a download.
    pub chunk_grid: u64,
}

/// "Send me the state from this offset" (type 20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapChunkRequest {
    pub id: u64,
    /// The block whose state is wanted. Kept for rskj compatibility and for
    /// the server's own lookup; `state_root` is what binds the answer.
    pub block_number: u64,
    /// Offset into the in-order traversal to resume from.
    pub from: u64,
    /// Soft limit in bytes on the nodes in the answer. Zero means "your
    /// choice", which is what rskj always sends.
    pub chunk_size: u64,
    /// The state root the client expects, when it knows it.
    ///
    /// This is the field that lets a client ask several unrelated peers for
    /// parts of one state and know they are all answering the same question.
    pub state_root: Option<B256>,
}

/// One node in flight: its consensus message, and any values too long to sit
/// inside it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapEntry {
    pub message: Bytes,
    pub long_values: Vec<Bytes>,
}

/// The nodes of a chunk, in whichever serialization the server speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkPayload {
    /// Consensus-form nodes plus the witness that anchors them to the root.
    Proved { entries: Vec<SnapEntry>, witness: Vec<Bytes> },
    /// rskj's stripped-node blob, kept undecoded. Recognised so the peer can
    /// be told apart rather than misread.
    Legacy(Bytes),
}

/// Why a server would not serve a chunk.
///
/// An empty answer alone says "not this one" without saying why, and the
/// difference matters to the client: a peer on another chain should be dropped
/// from the rotation, a peer whose grid disagrees should be realigned with,
/// and neither is misbehaviour. Carried as a trailing element rskj never
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Refusal {
    /// Not a refusal: the chunk is in the payload.
    #[default]
    None = 0,
    /// No block at that number on this chain.
    UnknownBlock = 1,
    /// This chain has a different state root at that height.
    StateRootMismatch = 2,
    /// The state was known but is no longer stored.
    StateNotStored = 3,
    /// The offset is past the end of the trie.
    PastTheEnd = 4,
    /// The offset is not a multiple of this server's chunk granularity.
    OffsetNotOnGrid = 5,
}

impl Refusal {
    pub fn from_code(code: u64) -> Self {
        match code {
            1 => Refusal::UnknownBlock,
            2 => Refusal::StateRootMismatch,
            3 => Refusal::StateNotStored,
            4 => Refusal::PastTheEnd,
            5 => Refusal::OffsetNotOnGrid,
            _ => Refusal::None,
        }
    }

    /// Whether asking this peer for a different range is worth the round trip.
    ///
    /// None of these is misbehaviour, so none is charged; the question is only
    /// whether the peer can help with anything else. A grid disagreement is
    /// about the request, not the peer, so it is the one worth retrying.
    pub fn worth_asking_again(self) -> bool {
        matches!(self, Refusal::None | Refusal::OffsetNotOnGrid | Refusal::PastTheEnd)
    }
}

/// A chunk of state (type 21).
///
/// Only [`ChunkPayload`] is load-bearing. `from`, `to` and `complete` are the
/// peer's account of what it did, retained for rskj's message shape and for
/// logs: the client derives all three from the nodes themselves, and must
/// never take them on the peer's word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapChunkResponse {
    pub id: u64,
    pub payload: ChunkPayload,
    pub block_number: u64,
    pub from: u64,
    pub to: u64,
    pub complete: bool,
    /// Why the payload is empty, when it is. A sixth element beyond rskj's
    /// five, which rskj's decoder never reaches.
    pub refusal: Refusal,
}

/// "Send me the 400 blocks before this one" (type 24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapBlocksRequest {
    pub id: u64,
    pub block_number: u64,
}

/// Blocks with their cumulative difficulties (type 25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapBlocksResponse {
    pub id: u64,
    pub blocks: Vec<Block>,
    pub difficulties: Vec<U256>,
}

// ---------------------------------------------------------------- encoding

/// Wraps an already-encoded payload in an RLP list header.
fn as_list(payload: &[u8], out: &mut Vec<u8>) {
    RlpHeader { list: true, payload_length: payload.len() }.encode(out);
    out.extend_from_slice(payload);
}

fn list_of(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    as_list(&payload, &mut out);
    out
}

/// A block as rskj encodes it: `RLP([header, [txs], [uncles]])`.
pub fn encode_block(block: &Block) -> Vec<u8> {
    let mut header = Vec::new();
    block.header.encode(&mut header);

    let mut txs = Vec::new();
    for tx in &block.transactions {
        // The original bytes, not a re-encoding. rskj writes a zero field as a
        // literal 0x00 where canonical RLP writes 0x80, and the header commits
        // to a trie built over the bytes it actually signed. Re-encoding a
        // REMASC transaction canonically changes the transaction root, and the
        // peer -- correctly -- rejects the body as not the one its header
        // commits to.
        txs.extend_from_slice(&tx.rlp_for_trie());
    }
    let mut uncles = Vec::new();
    for uncle in &block.ommers {
        uncle.encode(&mut uncles);
    }

    let mut body = header;
    as_list(&txs, &mut body);
    as_list(&uncles, &mut body);
    list_of(body)
}

pub fn decode_block(buf: &mut &[u8]) -> alloy_rlp::Result<Block> {
    let h = RlpHeader::decode(buf)?;
    if !h.list || buf.len() < h.payload_length {
        return Err(alloy_rlp::Error::Custom("malformed block"));
    }
    let mut body = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];

    let header = Header::decode_with_hash(&mut body)?;

    let txs_h = RlpHeader::decode(&mut body)?;
    if body.len() < txs_h.payload_length {
        return Err(alloy_rlp::Error::Custom("malformed block transactions"));
    }
    let mut txs_body = &body[..txs_h.payload_length];
    body = &body[txs_h.payload_length..];
    let mut transactions = Vec::new();
    while !txs_body.is_empty() {
        transactions.push(Transaction::decode(&mut txs_body)?);
    }

    let uncles_h = RlpHeader::decode(&mut body)?;
    if body.len() < uncles_h.payload_length {
        return Err(alloy_rlp::Error::Custom("malformed block uncles"));
    }
    let mut uncles_body = &body[..uncles_h.payload_length];
    let mut ommers = Vec::new();
    while !uncles_body.is_empty() {
        ommers.push(Header::decode_with_hash(&mut uncles_body)?);
    }

    Ok(Block { header, transactions, ommers })
}

fn encode_blocks_and_difficulties(
    blocks: &[Block],
    difficulties: &[U256],
    out: &mut Vec<u8>,
) {
    let mut blocks_payload = Vec::new();
    for block in blocks {
        // rskj wraps each encoded block in an RLP string, so the list holds
        // blobs rather than nested lists.
        Bytes::from(encode_block(block)).encode(&mut blocks_payload);
    }
    as_list(&blocks_payload, out);

    let mut diffs_payload = Vec::new();
    for d in difficulties {
        // Exactly as rskj writes one: `BigInteger.toByteArray()`, two's
        // complement, so a value whose top bit is set carries a leading 0x00.
        // See `rsk::encode_difficulty`.
        super::rsk::encode_difficulty(*d, &mut diffs_payload);
    }
    as_list(&diffs_payload, out);
}

fn decode_blocks_and_difficulties(
    buf: &mut &[u8],
) -> alloy_rlp::Result<(Vec<Block>, Vec<U256>)> {
    let blocks_h = RlpHeader::decode(buf)?;
    if buf.len() < blocks_h.payload_length {
        return Err(alloy_rlp::Error::Custom("malformed block list"));
    }
    let mut blocks_body = &buf[..blocks_h.payload_length];
    *buf = &buf[blocks_h.payload_length..];
    let mut blocks = Vec::new();
    while !blocks_body.is_empty() {
        let encoded = Bytes::decode(&mut blocks_body)?;
        blocks.push(decode_block(&mut encoded.as_ref())?);
    }

    let diffs_h = RlpHeader::decode(buf)?;
    if buf.len() < diffs_h.payload_length {
        return Err(alloy_rlp::Error::Custom("malformed difficulty list"));
    }
    let mut diffs_body = &buf[..diffs_h.payload_length];
    *buf = &buf[diffs_h.payload_length..];
    let mut difficulties = Vec::new();
    while !diffs_body.is_empty() {
        difficulties.push(decode_u256_lenient(&mut diffs_body)?);
    }

    Ok((blocks, difficulties))
}

/// Encodes the body of a snap message: `RLP([id, RLP_string(params)])`.
///
/// This is rskj's `MessageWithId` shape, where the parameters are themselves
/// an RLP list carried as a blob.
/// `RLP([id, <the message's own fields, as rskj writes them>])`.
///
/// rskj's `MessageWithId.getEncodedMessage` is
/// `RLP.encodeList(rlpId, getEncodedMessageWithoutId())`, and every snap
/// subclass returns an `RLP.encodeList(...)` from the second call. So the
/// second element is that list itself.
///
/// This used to wrap it in an RLP **string** as well, making the same logical
/// message different bytes -- `[id, 0x81 0xc0]` where rskj writes `[id,
/// 0xc0]`. rustock talked to rustock because both ends were wrong in the same
/// way; an rskj snap request reached a rustock server, failed to decode, and
/// was dropped without a reply, so rskj retried until it gave up and started
/// over, forever.
fn with_id(id: u64, params: Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    id.encode(&mut body);
    body.extend_from_slice(&params);
    list_of(body)
}

/// Splits `RLP([id, params])` back into the two, where `params` is returned
/// as a complete RLP item for the caller to parse.
///
/// Accepts both framings. rskj writes the fields as a list; rustock used to
/// wrap that list in an RLP string, and nodes on the older encoding are still
/// out there. Reading either costs one header inspection and removes a
/// flag-day from a change that otherwise needs one.
///
/// Being lenient here is not symmetric with being lenient when writing: this
/// node now *writes* only rskj's form, so the two encodings do not propagate.
fn split_id(buf: &mut &[u8]) -> alloy_rlp::Result<(u64, Vec<u8>)> {
    let h = RlpHeader::decode(buf)?;
    if !h.list || buf.len() < h.payload_length {
        return Err(alloy_rlp::Error::Custom("malformed snap message"));
    }
    let body = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];

    let mut rest = body;
    let id = decode_u64_lenient(&mut rest)?;

    // Look at what follows without consuming it: a list is the message's
    // fields themselves, a string is the older wrapper around them.
    let mut peek = rest;
    let params_h = RlpHeader::decode(&mut peek)?;
    if params_h.list {
        return Ok((id, rest.to_vec()));
    }
    if peek.len() < params_h.payload_length {
        return Err(alloy_rlp::Error::Custom("truncated snap params"));
    }
    Ok((id, peek[..params_h.payload_length].to_vec()))
}

impl SnapStatusRequest {
    pub fn encode_body(&self) -> Vec<u8> {
        with_id(self.id, list_of(Vec::new()))
    }

    pub fn decode_body(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (id, _) = split_id(buf)?;
        Ok(Self { id })
    }
}

impl SnapStatusResponse {
    pub fn encode_body(&self) -> Vec<u8> {
        let mut params = Vec::new();
        encode_blocks_and_difficulties(&self.blocks, &self.difficulties, &mut params);
        self.trie_size.encode(&mut params);
        if self.chunk_grid != 0 {
            self.chunk_grid.encode(&mut params);
        }
        with_id(self.id, list_of(params))
    }

    pub fn decode_body(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (id, params) = split_id(buf)?;
        let mut p = params.as_slice();
        let h = RlpHeader::decode(&mut p)?;
        let mut body = &p[..h.payload_length.min(p.len())];

        let (blocks, difficulties) = decode_blocks_and_difficulties(&mut body)?;
        let trie_size = if body.is_empty() { 0 } else { decode_u64_lenient(&mut body)? };
        let chunk_grid = if body.is_empty() { 0 } else { decode_u64_lenient(&mut body)? };
        Ok(Self { id, blocks, difficulties, trie_size, chunk_grid })
    }
}

impl SnapChunkRequest {
    pub fn encode_body(&self) -> Vec<u8> {
        let mut params = Vec::new();
        self.block_number.encode(&mut params);
        self.from.encode(&mut params);
        self.chunk_size.encode(&mut params);
        // Appended beyond rskj's three elements. An rskj server reads the
        // first two and never looks this far, so naming the root costs
        // nothing in compatibility.
        if let Some(root) = self.state_root {
            root.encode(&mut params);
        }
        with_id(self.id, list_of(params))
    }

    pub fn decode_body(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (id, params) = split_id(buf)?;
        let mut p = params.as_slice();
        let h = RlpHeader::decode(&mut p)?;
        let mut body = &p[..h.payload_length.min(p.len())];

        let block_number = decode_u64_lenient(&mut body)?;
        let from = decode_u64_lenient(&mut body)?;
        let chunk_size = if body.is_empty() { 0 } else { decode_u64_lenient(&mut body)? };
        let state_root = if body.is_empty() { None } else { Some(B256::decode(&mut body)?) };

        Ok(Self { id, block_number, from, chunk_size, state_root })
    }
}

impl ChunkPayload {
    /// The payload on its own, for storing a computed cell.
    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Reads back what [`ChunkPayload::encode_bytes`] wrote.
    pub fn decode_bytes(bytes: &[u8]) -> alloy_rlp::Result<Self> {
        Self::decode(&mut &bytes[..])
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ChunkPayload::Legacy(blob) => blob.encode(out),
            ChunkPayload::Proved { entries, witness } => {
                let mut entries_payload = Vec::new();
                for entry in entries {
                    let mut e = Vec::new();
                    entry.message.encode(&mut e);
                    let mut values = Vec::new();
                    for v in &entry.long_values {
                        v.encode(&mut values);
                    }
                    as_list(&values, &mut e);
                    as_list(&e, &mut entries_payload);
                }

                let mut witness_payload = Vec::new();
                for w in witness {
                    w.encode(&mut witness_payload);
                }

                let mut payload = Vec::new();
                as_list(&entries_payload, &mut payload);
                as_list(&witness_payload, &mut payload);
                as_list(&payload, out);
            }
        }
    }

    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // The RLP header alone says which dialect this is: rskj wraps its
        // blob as a string, a proved chunk is a list.
        let h = RlpHeader::decode(buf)?;
        if buf.len() < h.payload_length {
            return Err(alloy_rlp::Error::Custom("malformed chunk payload"));
        }
        let mut body = &buf[..h.payload_length];
        *buf = &buf[h.payload_length..];

        if !h.list {
            return Ok(ChunkPayload::Legacy(Bytes::from(body.to_vec())));
        }

        let entries_h = RlpHeader::decode(&mut body)?;
        if !entries_h.list || body.len() < entries_h.payload_length {
            return Err(alloy_rlp::Error::Custom("malformed chunk entries"));
        }
        let mut entries_body = &body[..entries_h.payload_length];
        body = &body[entries_h.payload_length..];

        let mut entries = Vec::new();
        while !entries_body.is_empty() {
            let e_h = RlpHeader::decode(&mut entries_body)?;
            if !e_h.list || entries_body.len() < e_h.payload_length {
                return Err(alloy_rlp::Error::Custom("malformed chunk entry"));
            }
            let mut e = &entries_body[..e_h.payload_length];
            entries_body = &entries_body[e_h.payload_length..];

            let message = Bytes::decode(&mut e)?;
            let v_h = RlpHeader::decode(&mut e)?;
            if !v_h.list || e.len() < v_h.payload_length {
                return Err(alloy_rlp::Error::Custom("malformed long value list"));
            }
            let mut values_body = &e[..v_h.payload_length];
            let mut long_values = Vec::new();
            while !values_body.is_empty() {
                long_values.push(Bytes::decode(&mut values_body)?);
            }
            entries.push(SnapEntry { message, long_values });
        }

        let w_h = RlpHeader::decode(&mut body)?;
        if !w_h.list || body.len() < w_h.payload_length {
            return Err(alloy_rlp::Error::Custom("malformed witness"));
        }
        let mut witness_body = &body[..w_h.payload_length];
        let mut witness = Vec::new();
        while !witness_body.is_empty() {
            witness.push(Bytes::decode(&mut witness_body)?);
        }

        Ok(ChunkPayload::Proved { entries, witness })
    }
}

impl SnapChunkResponse {
    pub fn encode_body(&self) -> Vec<u8> {
        let mut params = Vec::new();
        self.payload.encode(&mut params);
        self.block_number.encode(&mut params);
        self.from.encode(&mut params);
        self.to.encode(&mut params);
        (self.complete as u8).encode(&mut params);
        if self.refusal != Refusal::None {
            (self.refusal as u8).encode(&mut params);
        }
        with_id(self.id, list_of(params))
    }

    pub fn decode_body(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (id, params) = split_id(buf)?;
        let mut p = params.as_slice();
        let h = RlpHeader::decode(&mut p)?;
        let mut body = &p[..h.payload_length.min(p.len())];

        let payload = ChunkPayload::decode(&mut body)?;
        let block_number = decode_u64_lenient(&mut body)?;
        let from = decode_u64_lenient(&mut body)?;
        let to = decode_u64_lenient(&mut body)?;
        let complete = !body.is_empty() && decode_u64_lenient(&mut body)? != 0;
        let refusal = if body.is_empty() {
            Refusal::None
        } else {
            Refusal::from_code(decode_u64_lenient(&mut body)?)
        };

        Ok(Self { id, payload, block_number, from, to, complete, refusal })
    }
}

impl SnapBlocksRequest {
    pub fn encode_body(&self) -> Vec<u8> {
        let mut params = Vec::new();
        self.block_number.encode(&mut params);
        with_id(self.id, list_of(params))
    }

    pub fn decode_body(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (id, params) = split_id(buf)?;
        let mut p = params.as_slice();
        let h = RlpHeader::decode(&mut p)?;
        let mut body = &p[..h.payload_length.min(p.len())];
        let block_number = decode_u64_lenient(&mut body)?;
        Ok(Self { id, block_number })
    }
}

impl SnapBlocksResponse {
    pub fn encode_body(&self) -> Vec<u8> {
        let mut params = Vec::new();
        encode_blocks_and_difficulties(&self.blocks, &self.difficulties, &mut params);
        with_id(self.id, list_of(params))
    }

    pub fn decode_body(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (id, params) = split_id(buf)?;
        let mut p = params.as_slice();
        let h = RlpHeader::decode(&mut p)?;
        let mut body = &p[..h.payload_length.min(p.len())];
        let (blocks, difficulties) = decode_blocks_and_difficulties(&mut body)?;
        Ok(Self { id, blocks, difficulties })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::rsk::{RskMessage, RskSubMessage};
    use alloy_primitives::Address;

    fn header(number: u64) -> Header {
        Header {
            parent_hash: B256::repeat_byte(number as u8),
            ommers_hash: B256::repeat_byte(2),
            beneficiary: Address::repeat_byte(3),
            state_root: B256::repeat_byte(4),
            transactions_root: B256::repeat_byte(5),
            receipts_root: B256::repeat_byte(6),
            difficulty: U256::from(1_000_000u64 + number),
            number,
            gas_limit: U256::from(6_800_000u64),
            gas_used: 21_000,
            timestamp: 1_700_000_000 + number,
            extra_data: Bytes::from_static(b"rustock"),
            paid_fees: U256::from(1234u64),
            minimum_gas_price: U256::from(59_240_000u64),
            uncle_count: 0,
            logs_bloom: Default::default(),
            extension_data: None,
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

#[test]
fn a_remasc_body_survives_the_snap_wire() {
    use rustock_core::{ordered_tx_trie_root, Transaction};
    use alloy_rlp::Decodable;

    // The REMASC transaction as rskj puts it on the wire (`RemascTransaction`
    // with `getEncoded`): gas price and gas limit the byte 0x00 rather than
    // RLP's empty string, which canonical RLP would write; value, data and
    // the absent signature empty.
    let raw = Transaction::remasc(9_263_832).rlp_for_trie();
    let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
    assert_eq!(tx.rlp_for_trie(), raw, "decoding keeps rskj's encoding");

    let before = ordered_tx_trie_root(std::slice::from_ref(&tx), true);

    // Put it through the snap block codec, exactly as the server does.
    let block = rustock_core::Block {
        header: header(1),
        transactions: vec![tx],
        ommers: Vec::new(),
    };
    let encoded = encode_block(&block);
    let decoded = decode_block(&mut encoded.as_slice()).unwrap();

    let after = ordered_tx_trie_root(&decoded.transactions, true);
    assert_eq!(before, after, "the snap wire must not change the transaction root");
}

    fn roundtrip(sub: RskSubMessage) -> RskSubMessage {
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(&RskMessage::new(sub), &mut buf);
        let decoded: RskMessage =
            alloy_rlp::Decodable::decode(&mut buf.as_slice()).expect("decodes");
        decoded.sub_message
    }

    #[test]
    fn a_status_request_survives_the_wire() {
        let out = roundtrip(RskSubMessage::SnapStatusRequest(SnapStatusRequest { id: 42 }));
        match out {
            RskSubMessage::SnapStatusRequest(r) => assert_eq!(r.id, 42),
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn a_status_response_survives_the_wire() {
        let blocks: Vec<Block> = (1..=3)
            .map(|n| Block {
                header: header(n),
                transactions: Vec::new(),
                ommers: Vec::new(),
            })
            .collect();
        let difficulties = vec![U256::from(10u64), U256::from(20u64), U256::from(30u64)];
        let sent = SnapStatusResponse {
            id: 7,
            blocks: blocks.clone(),
            difficulties: difficulties.clone(),
            trie_size: 130_000_000_000,
            chunk_grid: 100_000,
        };

        match roundtrip(RskSubMessage::SnapStatusResponse(Box::new(sent))) {
            RskSubMessage::SnapStatusResponse(got) => {
                assert_eq!(got.id, 7);
                assert_eq!(got.trie_size, 130_000_000_000);
                assert_eq!(got.chunk_grid, 100_000, "the grid must reach the client");
                assert_eq!(got.difficulties, difficulties);
                assert_eq!(got.blocks.len(), 3);
                for (a, b) in got.blocks.iter().zip(blocks.iter()) {
                    assert_eq!(a.header.hash(), b.header.hash());
                }
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    /// The state root is the point of the request: a client asks for a
    /// specific state, not for whatever a peer thinks a block number means.
    #[test]
    fn a_chunk_request_carries_the_state_root() {
        let root = B256::repeat_byte(0xAB);
        let sent = SnapChunkRequest {
            id: 9,
            block_number: 9_268_363,
            from: 4_294_967_296,
            chunk_size: 50_000,
            state_root: Some(root),
        };

        match roundtrip(RskSubMessage::SnapChunkRequest(sent.clone())) {
            RskSubMessage::SnapChunkRequest(got) => assert_eq!(got, sent),
            other => panic!("decoded as {other:?}"),
        }
    }

    /// And an rskj node's three-element request still decodes, with no root.
    #[test]
    fn a_chunk_request_without_a_root_still_decodes() {
        let sent = SnapChunkRequest {
            id: 1,
            block_number: 500,
            from: 0,
            chunk_size: 0,
            state_root: None,
        };
        match roundtrip(RskSubMessage::SnapChunkRequest(sent.clone())) {
            RskSubMessage::SnapChunkRequest(got) => assert_eq!(got, sent),
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn a_proved_chunk_survives_the_wire() {
        let entries = vec![
            SnapEntry {
                message: Bytes::from_static(&[0x40, 0x01, 0x02]),
                long_values: vec![Bytes::from(vec![0xAA; 64])],
            },
            SnapEntry { message: Bytes::from(vec![0x41; 70]), long_values: Vec::new() },
            SnapEntry {
                message: Bytes::from(vec![0x42; 5]),
                long_values: vec![Bytes::from(vec![1u8; 40]), Bytes::from(vec![2u8; 33])],
            },
        ];
        let witness = vec![Bytes::from(vec![0x50; 80]), Bytes::from(vec![0x51; 44])];
        let sent = SnapChunkResponse {
            id: 3,
            payload: ChunkPayload::Proved { entries: entries.clone(), witness: witness.clone() },
            block_number: 9_268_363,
            from: 1024,
            to: 2048,
            complete: false,
            refusal: Refusal::None,
        };

        match roundtrip(RskSubMessage::SnapChunkResponse(Box::new(sent.clone()))) {
            RskSubMessage::SnapChunkResponse(got) => assert_eq!(*got, sent),
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn an_empty_chunk_survives_the_wire() {
        let sent = SnapChunkResponse {
            id: 4,
            payload: ChunkPayload::Proved { entries: Vec::new(), witness: Vec::new() },
            block_number: 1,
            from: 0,
            to: 0,
            complete: true,
            refusal: Refusal::None,
        };
        match roundtrip(RskSubMessage::SnapChunkResponse(Box::new(sent.clone()))) {
            RskSubMessage::SnapChunkResponse(got) => assert_eq!(*got, sent),
            other => panic!("decoded as {other:?}"),
        }
    }

    /// An rskj server's blob is recognised for what it is rather than being
    /// misread as a proved chunk. A client can then say "this peer speaks the
    /// older format" instead of failing somewhere deep in verification.
    #[test]
    fn an_rskj_chunk_is_recognised_not_misread() {
        let blob = Bytes::from(vec![0xC1, 0x80, 0x99, 0x42]);
        let sent = SnapChunkResponse {
            id: 5,
            payload: ChunkPayload::Legacy(blob.clone()),
            block_number: 100,
            from: 0,
            to: 500,
            complete: false,
            refusal: Refusal::None,
        };
        match roundtrip(RskSubMessage::SnapChunkResponse(Box::new(sent))) {
            RskSubMessage::SnapChunkResponse(got) => {
                assert_eq!(got.payload, ChunkPayload::Legacy(blob));
                assert_eq!(got.to, 500);
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn snap_blocks_survive_the_wire() {
        let request = SnapBlocksRequest { id: 11, block_number: 9_000_000 };
        match roundtrip(RskSubMessage::SnapBlocksRequest(request.clone())) {
            RskSubMessage::SnapBlocksRequest(got) => assert_eq!(got, request),
            other => panic!("decoded as {other:?}"),
        }

        let blocks: Vec<Block> = (1..=2)
            .map(|n| Block { header: header(n), transactions: Vec::new(), ommers: Vec::new() })
            .collect();
        let response = SnapBlocksResponse {
            id: 12,
            blocks: blocks.clone(),
            difficulties: vec![U256::from(1u64), U256::from(2u64)],
        };
        match roundtrip(RskSubMessage::SnapBlocksResponse(Box::new(response))) {
            RskSubMessage::SnapBlocksResponse(got) => {
                assert_eq!(got.blocks.len(), 2);
                assert_eq!(got.blocks[1].header.hash(), blocks[1].header.hash());
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    /// Nothing a peer sends may panic the decoder.
    #[test]
    fn no_junk_body_can_panic_the_decoder() {
        let mut seed = 0x243F6A8885A308D3u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..4000 {
            let len = (next() % 120) as usize;
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = SnapStatusResponse::decode_body(&mut junk.as_slice());
            let _ = SnapChunkRequest::decode_body(&mut junk.as_slice());
            let _ = SnapChunkResponse::decode_body(&mut junk.as_slice());
            let _ = SnapBlocksResponse::decode_body(&mut junk.as_slice());
            let _ = decode_block(&mut junk.as_slice());
            let _: Result<RskMessage, _> = alloy_rlp::Decodable::decode(&mut junk.as_slice());
        }
    }
}

#[cfg(test)]
mod rskj_wire_tests {
    use super::*;

    /// Exactly the bytes rskj puts on the wire for `SNAP_STATUS_REQUEST`.
    ///
    /// `MessageWithId.getEncodedMessage` is
    /// `RLP.encodeList(rlpId, getEncodedMessageWithoutId())`, and a status
    /// request's body is `RLP.encodedEmptyList()` -- so `[id, 0xc0]`.
    fn rskj_status_request(id: u64) -> Vec<u8> {
        let mut body = Vec::new();
        id.encode(&mut body);
        body.push(0xc0);
        let mut out = Vec::new();
        RlpHeader { list: true, payload_length: body.len() }.encode(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// The older rustock framing: the same fields, wrapped in an RLP string.
    fn legacy_status_request(id: u64) -> Vec<u8> {
        let params = vec![0xc0u8];
        let mut body = Vec::new();
        id.encode(&mut body);
        RlpHeader { list: false, payload_length: params.len() }.encode(&mut body);
        body.extend_from_slice(&params);
        let mut out = Vec::new();
        RlpHeader { list: true, payload_length: body.len() }.encode(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// What this node writes is byte-for-byte what rskj writes.
    ///
    /// Not "decodes to the same thing" -- the same bytes. An rskj node reads
    /// these with its own decoder, so anything else is a guess about how
    /// forgiving that decoder is.
    #[test]
    fn this_node_writes_exactly_what_rskj_writes() {
        assert_eq!(
            SnapStatusRequest { id: 1 }.encode_body(),
            rskj_status_request(1),
            "the snap status request is not rskj's bytes"
        );
    }

    /// And reads what rskj writes. This is the direction that was broken: an
    /// rskj request reached the server, failed to decode, and was dropped
    /// without a reply or a log line.
    #[test]
    fn this_node_reads_what_rskj_writes() {
        let decoded = SnapStatusRequest::decode_body(&mut rskj_status_request(7).as_slice())
            .expect("an rskj snap request must decode");
        assert_eq!(decoded.id, 7);
    }

    /// And still reads the older rustock framing, so upgrading one end of a
    /// pair does not need a flag day.
    #[test]
    fn this_node_still_reads_the_older_rustock_framing() {
        let decoded = SnapStatusRequest::decode_body(&mut legacy_status_request(9).as_slice())
            .expect("the previous encoding must still decode");
        assert_eq!(decoded.id, 9);
    }

    /// Every message that carries an id round-trips through its own codec.
    ///
    /// The framing helpers are shared, so a mistake in them would show up
    /// here across the whole family rather than in one message.
    #[test]
    fn every_snap_message_round_trips() {
        let req = SnapChunkRequest {
            id: 3,
            block_number: 9_275_000,
            from: 1024,
            chunk_size: 4096,
            state_root: None,
        };
        let mut buf = req.encode_body();
        let back = SnapChunkRequest::decode_body(&mut buf.as_slice()).expect("chunk request");
        assert_eq!((back.id, back.block_number, back.from), (3, 9_275_000, 1024));

        let blocks = SnapBlocksRequest { id: 5, block_number: 9_274_000 };
        buf = blocks.encode_body();
        let back = SnapBlocksRequest::decode_body(&mut buf.as_slice()).expect("blocks request");
        assert_eq!((back.id, back.block_number), (5, 9_274_000));

        let status = SnapStatusRequest { id: 11 };
        buf = status.encode_body();
        assert_eq!(
            SnapStatusRequest::decode_body(&mut buf.as_slice()).expect("status").id,
            11
        );
    }
}
