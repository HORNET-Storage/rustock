use alloy_primitives::{Address, Bloom, B256, U256, Bytes};
use alloy_rlp::Encodable;
use serde::{Deserialize, Serialize};
use crate::rlp_compat::{decode_u64_lenient, decode_u256_lenient};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub parent_hash: B256,
    pub ommers_hash: B256,
    pub beneficiary: Address,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    /// Compressed extension data (RSKIP-351 V1/V2). When present, `logs_bloom`
    /// is set to default and this field contains `RLP([version, hash])`.
    pub extension_data: Option<Bytes>,
    pub difficulty: U256,
    pub number: u64,
    pub gas_limit: U256,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Bytes,
    
    // RSK Specific Fields
    pub paid_fees: U256,
    pub minimum_gas_price: U256,
    pub uncle_count: u64,
    
    // Optional / Advanced RSK fields (Merged Mining)
    pub umm_root: Option<Bytes>,
    /// RSKIP-351 trailing fields, present only on a versioned (V1/V2) header
    /// and only in its *wire* form.
    ///
    /// Kept verbatim because the wire form has to round-trip: the store
    /// re-encodes every header it writes, so anything dropped here is lost
    /// from the database rather than merely from one message. The hashed form
    /// does not carry these -- it commits to them through
    /// `extension_data` instead.
    pub version_fields: Option<HeaderVersionFields>,
    pub bitcoin_merged_mining_header: Option<Bytes>,
    pub bitcoin_merged_mining_merkle_proof: Option<Bytes>,
    pub bitcoin_merged_mining_coinbase_transaction: Option<Bytes>,

    /// The block hash, cached by `decode_with_hash` from the peer's own
    /// encoding of each field. Java's RLP encoding may differ from Rust's
    /// canonical encoding (e.g. leading zeros in BigInteger values), so the
    /// hash is taken at decode time instead of from re-encoded bytes. It is
    /// the hash of the form rskj hashes, which is not the form a versioned
    /// header is sent in.
    #[serde(skip)]
    pub cached_hash: Option<B256>,

    /// The merged-mining hash, cached the same way and for the same Java RLP
    /// reasons as `cached_hash`: the base fields and `ummRoot` only, without
    /// the bitcoin mining fields.
    #[serde(skip)]
    pub cached_hash_for_merged_mining: Option<B256>,
}

/// What a versioned (RSKIP-351) header carries beyond a version-0 one.
///
/// rskj appends these after `ummRoot` in the uncompressed encoding only
/// (`BlockHeaderV1/V2.addExtraFieldsToEncodedHeader`, guarded by
/// `!usingCompressedEncoding`). The compressed encoding -- the one that is
/// hashed -- replaces the bloom field with a commitment to them instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderVersionFields {
    /// 1 or 2. A version-0 header has no record of a version at all, which is
    /// why this lives behind an `Option` rather than defaulting to 0.
    pub version: u8,
    /// RSKIP-144 transaction execution sublist edges, when the block has any.
    /// rskj omits the field entirely when they are absent.
    pub edges: Option<Vec<i16>>,
    /// RSKIP-535 base event. V2 only, and empty rather than absent when the
    /// block carries none.
    pub base_event: Option<Bytes>,
}

/// Number of complete RLP items in `buf`, stopping at the first that does not
/// fit. Used to tell a header's trailing fields apart by position.
fn count_rlp_items(buf: &[u8]) -> usize {
    let mut count = 0usize;
    let mut rest = buf;
    while !rest.is_empty() {
        let mut temp = rest;
        match alloy_rlp::Header::decode(&mut temp) {
            Ok(h) if h.payload_length <= temp.len() => {
                rest = &temp[h.payload_length..];
                count += 1;
            }
            _ => break,
        }
    }
    count
}

/// The items of the RLP list `encoded`, each in its whole encoding, header
/// and payload, as the peer spelled it. `None` unless `encoded` is exactly
/// one list of complete items.
fn rlp_list_items(encoded: &[u8]) -> Option<Vec<&[u8]>> {
    let mut rest = encoded;
    let list = alloy_rlp::Header::decode(&mut rest).ok()?;
    if !list.list || rest.len() != list.payload_length {
        return None;
    }
    let mut items = Vec::new();
    while !rest.is_empty() {
        let mut temp = rest;
        let item = alloy_rlp::Header::decode(&mut temp).ok()?;
        let length = (rest.len() - temp.len()).checked_add(item.payload_length)?;
        items.push(rest.get(..length)?);
        rest = &rest[length..];
    }
    Some(items)
}

/// rskj reads a header's number, gas used and timestamp with
/// `longValueExact`, which throws past a Java `long`: it cannot read a header
/// with one over `i64::MAX`.
fn decode_java_long(buf: &mut &[u8]) -> alloy_rlp::Result<u64> {
    let value = decode_u64_lenient(buf)?;
    if value > i64::MAX as u64 {
        return Err(alloy_rlp::Error::Custom("a header field past a Java long"));
    }
    Ok(value)
}

/// And its uncle count with `intValueExact`, which throws past a Java `int`.
fn decode_java_int(buf: &mut &[u8]) -> alloy_rlp::Result<u64> {
    let value = decode_u64_lenient(buf)?;
    if value > i32::MAX as u64 {
        return Err(alloy_rlp::Error::Custom("an uncle count past a Java int"));
    }
    Ok(value)
}

/// rskj `ByteUtil.rlpToShorts`: little-endian pairs.
fn rlp_to_shorts(bytes: &[u8]) -> Vec<i16> {
    bytes.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect()
}

/// `BigInteger.toByteArray()` for a non-negative value: zero is the single
/// byte 0x00, and values whose top bit is set get a 0x00 sign prefix. rskj
/// encodes difficulty (`RLP.encodeBlockDifficulty`), gasLimit (raw bytes it
/// produced the same way) and minimumGasPrice
/// (`RLP.encodeSignedCoinNonNullZero`) with these semantics.
fn java_signed_bytes(value: &U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![0];
    }
    let be = value.to_be_bytes::<32>();
    let start = be.iter().position(|b| *b != 0).unwrap();
    let mut out = Vec::with_capacity(33 - start);
    if be[start] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&be[start..]);
    out
}

impl Header {
    /// The sixteen fields every RSK header carries, in wire order, encoded the
    /// way rskj encodes them.
    ///
    /// Both the block hash and the merged-mining hash are taken over a prefix
    /// of this same sequence, so it exists once: when the two disagreed on how
    /// to encode a single field, headers this node *built* hashed differently
    /// from the way every other node would hash them, while headers it
    /// *decoded* were unaffected (they hash from the original bytes). That is
    /// invisible until something builds a header -- which is to say, until
    /// mining.
    /// The RSKIP-351 extension this header commits to, if it is V1 or V2.
    ///
    /// `None` for a version-0 header, which carries a literal 256-byte bloom
    /// and has no extension. `Some(Err(..))` means the slot held something
    /// that is neither.
    pub fn extension_commitment(
        &self,
    ) -> Option<Result<crate::types::header_extension::ExtensionCommitment,
                       crate::types::header_extension::ExtensionError>> {
        // A wire header has no stored commitment; derive it from the fields
        // it does carry, so both forms answer this the same way.
        let owned;
        let data: &[u8] = match &self.extension_data {
            Some(d) => d,
            None => {
                owned = self.compressed_extension_field()?;
                &owned
            }
        };
        Some(crate::types::header_extension::ExtensionCommitment::from_extension_data(data))
    }

    /// Whether `extension` is the body this header commits to.
    ///
    /// False for a version-0 header whatever is offered: a header with a
    /// literal bloom commits to no extension, and accepting one would let a
    /// peer attach edges or a base event to a block that never had them.
    ///
    /// This is the gate an extension that arrives apart from its header must
    /// pass: the fields are bound to the block by the commitment its hash
    /// covers, so one that doesn't match it is not the block's.
    /// [`Header::with_extension`] passes through it.
    pub fn accepts_extension(
        &self,
        extension: &crate::types::header_extension::BlockHeaderExtension,
    ) -> bool {
        matches!(self.extension_commitment(), Some(Ok(c)) if c.matches(extension))
    }

    /// The bloom slot as the *hashed* form carries it: an RLP string wrapping
    /// `RLP([version, keccak(extension)])`.
    ///
    /// Built from the wire fields rather than stored, because the commitment
    /// is derived from the bloom, edges and base event the header already
    /// holds -- keeping a second copy would let the two disagree.
    fn compressed_extension_field(&self) -> Option<Vec<u8>> {
        let extension = self.literal_extension()?;
        let mut out = Vec::new();
        extension
            .create_extension_data()
            .as_slice()
            .encode(&mut out);
        Some(out)
    }

    /// The extension the fields of a versioned header make up: its bloom,
    /// edges and base event, whether or not the header also holds the
    /// commitment to them.
    fn literal_extension(&self) -> Option<crate::types::header_extension::BlockHeaderExtension> {
        use crate::types::header_extension::BlockHeaderExtension;
        let v = self.version_fields.as_ref()?;
        let bloom = self.logs_bloom.as_slice().to_vec();
        match v.version {
            1 => Some(BlockHeaderExtension::V1 {
                logs_bloom: bloom,
                edges: v.edges.clone(),
            }),
            // A V2 extension always has a base event; a header that omitted
            // the field still commits to an empty one, which is what rskj
            // substitutes when it accepts the short form.
            2 => Some(BlockHeaderExtension::V2 {
                logs_bloom: bloom,
                edges: v.edges.clone(),
                base_event: Some(v.base_event.as_ref().map(|b| b.to_vec()).unwrap_or_default()),
            }),
            _ => None,
        }
    }

    /// The RSKIP-351 extension this header holds, as rskj's `getExtension`
    /// gives it to send beside the block's body: its bloom, edges and base
    /// event. `None` for a version-0 header, which has none, and for one
    /// that holds only the commitment to its extension, as headers sent
    /// compressed do until a body brings it.
    pub fn extension(&self) -> Option<crate::types::header_extension::BlockHeaderExtension> {
        if self.extension_data.is_some() {
            return None;
        }
        self.literal_extension()
    }

    /// This header with the extension its commitment names, as rskj takes the
    /// one a peer sends beside a block's body (`DownloadingBodiesSyncState`
    /// `.newBody`, `header.setExtension`) before the block is checked and run:
    /// its bloom, edges and base event in place of the commitment. They hash
    /// back to the commitment, so the header's hash is the same.
    ///
    /// `None` unless this header holds only the commitment, as a compressed
    /// header does, and `extension` is the one it names, with a bloom of 256
    /// bytes. rskj sets whatever it is sent and lets execution find out; this
    /// takes only the extension the block's hash covers, which for every
    /// block a miner built is the one an honest peer sends.
    pub fn with_extension(
        &self,
        extension: &crate::types::header_extension::BlockHeaderExtension,
    ) -> Option<Header> {
        if self.extension_data.is_none() || !self.accepts_extension(extension) {
            return None;
        }
        let logs_bloom = <[u8; 256]>::try_from(extension.logs_bloom()).ok()?;
        Some(Header {
            logs_bloom: Bloom::from(logs_bloom),
            extension_data: None,
            version_fields: Some(HeaderVersionFields {
                version: extension.version(),
                edges: extension.edges().map(<[i16]>::to_vec),
                base_event: extension.base_event().map(Bytes::copy_from_slice),
            }),
            ..self.clone()
        })
    }

    fn encode_base_fields(&self, list: &mut Vec<u8>, compressed: bool) {
        self.parent_hash.encode(list);
        self.ommers_hash.encode(list);
        self.beneficiary.encode(list);
        self.state_root.encode(list);
        self.transactions_root.encode(list);
        self.receipts_root.encode(list);
        // RSKIP-351: a V1/V2 header carries `RLP([version, extension_hash])`
        // in the slot a V0 header fills with its 256-byte bloom. The bytes are
        // already RLP, so they are appended rather than re-encoded.
        //
        // Encoding the bloom here regardless was invisible for as long as the
        // decoder cached the hash from the peer's original bytes: nothing ever
        // asked this encoder to reproduce a versioned header. Re-deriving the
        // hash of a testnet V1 block is what surfaced it.
        // rskj: `compressed ? getExtensionData() : getLogsBloom()`. Only the
        // compressed form is hashed; the wire form keeps the literal bloom and
        // carries the version, edges and base event after `ummRoot` instead.
        match (compressed, &self.extension_data, &self.version_fields) {
            // Already-compressed input: the literal bloom was never received,
            // so this is all there is to emit either way.
            (_, Some(ext), _) => list.extend_from_slice(ext),
            (true, None, Some(_)) => match self.compressed_extension_field() {
                Some(field) => list.extend_from_slice(&field),
                // An extension that will not build cannot be hashed into a
                // commitment; emitting the bloom keeps this total, and the
                // hash it yields simply will not match, which is visible.
                None => self.logs_bloom.encode(list),
            },
            _ => self.logs_bloom.encode(list),
        }
        java_signed_bytes(&self.difficulty).as_slice().encode(list);
        self.number.encode(list);
        java_signed_bytes(&self.gas_limit).as_slice().encode(list);
        self.gas_used.encode(list);
        self.timestamp.encode(list);
        self.extra_data.encode(list);
        self.paid_fees.encode(list);
        java_signed_bytes(&self.minimum_gas_price).as_slice().encode(list);
        self.uncle_count.encode(list);
    }

    /// rskj BlockHeader.getEncoded(true, with_merkle_proof_and_coinbase):
    /// list payload of all header fields; the merkle proof and coinbase tx
    /// are excluded from RSKIP92 block hashes but kept on the wire.
    fn encode_payload(&self, with_merkle_proof_and_coinbase: bool, compressed: bool) -> Vec<u8> {
        let mut list = Vec::new();
        self.encode_base_fields(&mut list, compressed);

        if let Some(umm) = &self.umm_root {
            umm.encode(&mut list);
        }
        // rskj `BlockHeaderV1/V2.addExtraFieldsToEncodedHeader`: the version,
        // the edges when the block has any, and (V2) the base event, in that
        // order and only when not compressed.
        if !compressed {
            if let Some(v) = &self.version_fields {
                list.push(v.version);
                if let Some(edges) = &v.edges {
                    // Already an RLP string; appending rather than encoding,
                    // or `Vec<u8>` would go out as a list of single bytes.
                    list.extend_from_slice(
                        &crate::types::header_extension::shorts_to_rlp(edges),
                    );
                }
                if let Some(be) = &v.base_event {
                    be.encode(&mut list);
                }
            }
        }
        // rskj emits the merkle proof and coinbase tx whenever the mining
        // header is present — as empty elements if need be — rather than
        // omitting them (BlockHeader.getEncoded with merged mining fields).
        if let Some(btc) = &self.bitcoin_merged_mining_header {
            btc.encode(&mut list);
            if with_merkle_proof_and_coinbase {
                match &self.bitcoin_merged_mining_merkle_proof {
                    Some(proof) => proof.encode(&mut list),
                    None => list.push(0x80),
                }
                match &self.bitcoin_merged_mining_coinbase_transaction {
                    Some(tx) => tx.encode(&mut list),
                    None => list.push(0x80),
                }
            }
        }
        list
    }
}

impl Encodable for Header {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let list = self.encode_payload(true, false);
        alloy_rlp::Header { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }

    fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }
}

impl alloy_rlp::Decodable for Header {
    /// Decodes under the process-wide activation heights
    /// ([`ActivationHeights::current`](crate::config::ActivationHeights::current)).
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::decode_with_activations(buf, crate::config::ActivationHeights::current())
    }
}

impl Header {
    /// Decode a header under explicit activation heights. Only RSKIP-144's
    /// height is consulted: it decides what a lone item after a V2 version
    /// byte is (see below).
    pub fn decode_with_activations(
        buf: &mut &[u8],
        activations: &crate::config::ActivationHeights,
    ) -> alloy_rlp::Result<Self> {
        use alloy_rlp::Decodable;
        let h = alloy_rlp::Header::decode(buf)?;
        if !h.list { return Err(alloy_rlp::Error::UnexpectedString); }
        let mut body = &buf[..h.payload_length];
        *buf = &buf[h.payload_length..];

        let parent_hash = B256::decode(&mut body)?;
        let ommers_hash = B256::decode(&mut body)?;
        let beneficiary = Address::decode(&mut body)?;
        let state_root = B256::decode(&mut body)?;
        let transactions_root = B256::decode(&mut body)?;
        let receipts_root = B256::decode(&mut body)?;

        // Field 6: logs bloom (256 bytes) OR compressed extension data (shorter).
        // Peek at the RLP header to determine which one.
        let (logs_bloom, extension_data) = {
            let mut peek = body;
            let rlp_h = alloy_rlp::Header::decode(&mut peek)?;
            if !rlp_h.list && rlp_h.payload_length == 256 {
                // Standard logs bloom (256 bytes)
                (Bloom::decode(&mut body)?, None)
            } else {
                // Compressed extension data (V1/V2 RSKIP-351).
                // Could be an RLP list or string — read the raw bytes either way.
                let header_len = body.len() - peek.len();
                let total_len = header_len + rlp_h.payload_length;
                let raw = Bytes::copy_from_slice(&body[..total_len]);
                body = &body[total_len..];
                (Bloom::default(), Some(raw))
            }
        };

        let mut header = Self {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            extension_data,
            difficulty: decode_u256_lenient(&mut body)?,
            number: decode_java_long(&mut body)?,
            gas_limit: decode_u256_lenient(&mut body)?,
            gas_used: decode_java_long(&mut body)?,
            timestamp: decode_java_long(&mut body)?,
            extra_data: Bytes::decode(&mut body)?,
            paid_fees: decode_u256_lenient(&mut body)?,
            minimum_gas_price: decode_u256_lenient(&mut body)?,
            uncle_count: decode_java_int(&mut body)?,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };

        // What is left is told apart by count, since nothing here knows the
        // network: none is a header without merged-mining fields, three are
        // those fields, and four or more begin with a UMM root (RSKIPUMM,
        // papyrus200). `HeaderLayoutRule` holds what was read to the fields
        // rskj reads at the header's height.
        let remaining_items = count_rlp_items(body);

        if remaining_items >= 4 {
            header.umm_root = Some(Bytes::decode(&mut body)?);
        }

        // RSKIP-351: a versioned header puts its version, its RSKIP-144 edges
        // and (V2) its base event here, between `ummRoot` and the merged
        // mining fields. rskj picks them out by activation height; nothing
        // here knows the network, so the version byte is used as its own
        // marker instead. It is `RLP.encodeByte(1|2)`, a bare 0x01 or 0x02 --
        // a value no other field in this position can take. `ummRoot` is
        // empty or 32 bytes, edges are an even-length string, the base event
        // is empty or long, and a merged-mining header is 80 bytes.
        //
        // Dropping these was invisible for as long as nothing re-derived a
        // hash: the decoder cached the one the peer sent. It cost every
        // header from testnet reed810 on its correct hash, which first
        // surfaced as REMASC's selection rule comparing the wrong ones.
        if matches!(body.first(), Some(1 | 2)) {
            let version = body[0];
            body = &body[1..];

            // Whatever is left belongs to the merged mining fields, except
            // what the version says comes first. rskj emits the edges only
            // when the block has any, so their presence is positional: with a
            // base event to follow (V2) there is one more item here than
            // mining alone accounts for.
            let after_version = count_rlp_items(body);
            let mining_items = after_version.min(3);
            let extras = after_version - mining_items;

            // Edges come first and are emitted whenever RSKIP144 is active --
            // as an empty string when the block has no sublists -- so they are
            // present on every versioned header seen here. The base event
            // follows, and on testnet between vetiver900 and #7,800,000 it can
            // be missing altogether: rskj accepts a header one element short
            // there and supplies an empty base event for it
            // (`BlockFactory.isInBaseEventRecoveryWindow`). Reading the
            // trailing element as the base event in that case takes the edges
            // for it and hashes the header wrong.
            let mut edges = None;
            let mut base_event = None;
            //
            // Where RSKIP-144 is not active there are no edges, and a V2
            // header's one trailing item is its base event (rskj's regtest:
            // rskip144 = -1, rskip535 = 1). rskj tells the cases apart by
            // activation, and so does this.
            let rskip144 = activations.rskip144.is_some_and(|h| header.number >= h);
            if version >= 2 && extras == 1 && !rskip144 {
                base_event = Some(Bytes::decode(&mut body)?);
            } else {
                if extras >= 1 {
                    edges = Some(rlp_to_shorts(&Bytes::decode(&mut body)?));
                }
                if version >= 2 && extras >= 2 {
                    base_event = Some(Bytes::decode(&mut body)?);
                }
            }
            header.version_fields = Some(HeaderVersionFields { version, edges, base_event });
        }

        // rskj reads the three merged-mining fields together or not at all,
        // and `canBeDecoded` counts a header's fields exactly: with one or two
        // of them, or anything after them, it cannot read the header.
        if !body.is_empty() {
            header.bitcoin_merged_mining_header = Some(Bytes::decode(&mut body)?);
            header.bitcoin_merged_mining_merkle_proof = Some(Bytes::decode(&mut body)?);
            header.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::decode(&mut body)?);
            if !body.is_empty() {
                return Err(alloy_rlp::Error::Custom(
                    "a header with fields after its merged-mining fields",
                ));
            }
        }

        Ok(header)
    }
}

impl Header {
    /// RSKIP92 (orchid): the block hash is computed over the header encoding
    /// WITHOUT the merged-mining merkle proof and coinbase transaction
    /// (rskj BlockHeader.getHash → getEncodedForHash, useRskip92Encoding).
    fn rskip92_active(&self) -> bool {
        self.number >= crate::config::ActivationHeights::current().orchid
    }

    pub fn hash(&self) -> B256 {
        if let Some(h) = self.cached_hash {
            return h;
        }
        let payload = self.encode_payload(!self.rskip92_active(), true);
        let mut buffer = Vec::with_capacity(payload.len() + 4);
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut buffer);
        buffer.extend_from_slice(&payload);
        alloy_primitives::keccak256(&buffer)
    }

    /// The header as rskj sends a chain's headers to its peers
    /// (`BlockHeader.getEncodedCompressed`): every field and all three
    /// merged-mining fields, with a versioned header's commitment to its
    /// extension in slot 6 and none of its own fields after `ummRoot`. rskj
    /// reads a `BlockHeadersResponseMessage`'s headers so
    /// (`decodeHeader(.., true)`), and a header taken from one is held so here.
    /// A version-0 header has this one form.
    pub fn encode_compressed(&self) -> Vec<u8> {
        let payload = self.encode_payload(true, true);
        let mut out = Vec::with_capacity(payload.len() + 4);
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&payload);
        out
    }

    /// Decode a header from RLP bytes and cache both of its hashes from those
    /// bytes, since re-encoding need not reproduce a peer's Java spelling of
    /// every field.
    ///
    /// rskj does not hash the form it sends. It hashes the compressed form,
    /// which leaves out the merged-mining proof and coinbase (RSKIP-92) and,
    /// for a versioned (RSKIP-351) header, the version, edges and base event
    /// that follow `ummRoot` on the wire, whose commitment takes the bloom's
    /// place in slot 6. So both hashes are built from the items as sent,
    /// less those, with slot 6 swapped. Hashing a versioned header as sent
    /// gave every testnet header from reed810 on a hash no other node agrees
    /// with: no header named its parent, and the snapshot sync refused every
    /// chain it was offered.
    pub fn decode_with_hash(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::decode_with_hash_and_activations(buf, crate::config::ActivationHeights::current())
    }

    /// [`Self::decode_with_hash`] under explicit activation heights, which
    /// decide what a lone item after a V2 version byte is, as they do for
    /// [`Self::decode_with_activations`].
    pub fn decode_with_hash_and_activations(
        buf: &mut &[u8],
        activations: &crate::config::ActivationHeights,
    ) -> alloy_rlp::Result<Self> {
        let original = *buf;
        let mut header = Self::decode_with_activations(buf, activations)?;
        let encoded = &original[..original.len() - buf.len()];

        // `decode` has just read this list, so its items split; were one too
        // lenient for that, both hashes would be left to come from this
        // node's own encoding instead.
        let Some(items) = rlp_list_items(encoded) else {
            return Ok(header);
        };
        // The sixteen base fields and `ummRoot`, then on the wire a versioned
        // header's own fields, then the merged-mining fields.
        let base = 16 + usize::from(header.umm_root.is_some());
        let versioned = header.version_fields.as_ref().map_or(0, |v| {
            1 + usize::from(v.edges.is_some()) + usize::from(v.base_event.is_some())
        });
        let (Some(base_items), Some(mining)) = (items.get(..base), items.get(base + versioned..))
        else {
            return Ok(header);
        };
        // A versioned header that sent its literal bloom is hashed with its
        // commitment in slot 6, as `encode_base_fields` does.
        let commitment = if header.extension_data.is_none() {
            header.compressed_extension_field()
        } else {
            None
        };
        let hash_with = |mining: &[&[u8]]| {
            let mut payload = Vec::with_capacity(encoded.len());
            for (slot, item) in base_items.iter().enumerate() {
                match &commitment {
                    Some(field) if slot == 6 => payload.extend_from_slice(field),
                    _ => payload.extend_from_slice(item),
                }
            }
            for item in mining {
                payload.extend_from_slice(item);
            }
            let mut list = Vec::with_capacity(payload.len() + 9);
            alloy_rlp::Header {
                list: true,
                payload_length: payload.len(),
            }
            .encode(&mut list);
            list.extend_from_slice(&payload);
            alloy_primitives::keccak256(&list)
        };

        // RSKIP-92: the block hash keeps the merged-mining header and leaves
        // out the proof and the coinbase.
        let hashed_mining = if header.rskip92_active() {
            &mining[..mining.len().min(1)]
        } else {
            mining
        };
        header.cached_hash = Some(hash_with(hashed_mining));

        // The merged-mining hash leaves out all three, and a UMM block then
        // folds its root in: keccak(the first 20 bytes ++ ummRoot).
        let for_merged_mining = hash_with(&[]);
        header.cached_hash_for_merged_mining = Some(
            match header.umm_root.as_ref().filter(|umm| !umm.is_empty()) {
                Some(umm) => {
                    let mut input = Vec::with_capacity(20 + umm.len());
                    input.extend_from_slice(&for_merged_mining.as_slice()[..20]);
                    input.extend_from_slice(umm.as_ref());
                    alloy_primitives::keccak256(&input)
                }
                None => for_merged_mining,
            },
        );
        Ok(header)
    }

    /// Returns the hash used in the Bitcoin coinbase transaction for merged mining.
    /// Prefers the cached value computed from original (Java) RLP bytes at decode
    /// time; falls back to re-encoding with Rust RLP for programmatically built
    /// headers (e.g., in tests).
    pub fn hash_for_merged_mining(&self) -> B256 {
        if let Some(h) = self.cached_hash_for_merged_mining {
            return h;
        }

        let is_umm_block = self.umm_root.as_ref().is_some_and(|u| !u.is_empty());

        // The same encoder the block hash uses. Encoding difficulty, gas limit
        // and minimum gas price any other way produces a hash no other node
        // agrees with -- and since only a header this node built ever reaches
        // this path, nothing that merely replays the chain would notice.
        let mut payload = Vec::new();
        self.encode_base_fields(&mut payload, true);
        if let Some(umm) = &self.umm_root {
            umm.encode(&mut payload);
        }

        let mut out = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
        out.extend_from_slice(&payload);

        let base_hash = alloy_primitives::keccak256(&out);

        if is_umm_block {
            let umm_bytes = self.umm_root.as_ref().unwrap();
            let mut input = Vec::with_capacity(20 + umm_bytes.len());
            input.extend_from_slice(&base_hash.as_slice()[..20]);
            input.extend_from_slice(umm_bytes.as_ref());
            alloy_primitives::keccak256(&input)
        } else {
            base_hash
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256, Bytes, keccak256, b256, address, hex};
    use alloy_rlp::{Decodable, Encodable};

    fn standard_test_header() -> Header {
        Header {
            parent_hash: B256::repeat_byte(0x11),
            ommers_hash: B256::repeat_byte(0x22),
            beneficiary: Address::repeat_byte(0x33),
            state_root: B256::repeat_byte(0x44),
            transactions_root: B256::repeat_byte(0x55),
            receipts_root: B256::repeat_byte(0x66),
            logs_bloom: Bloom::repeat_byte(0x77),
            extension_data: None,
            difficulty: U256::from(1234567),
            number: 42,
            gas_limit: U256::from(10_000_000),
            gas_used: 123456,
            timestamp: 1700000000,
            extra_data: Bytes::from("extra"),
            paid_fees: U256::from(100),
            minimum_gas_price: U256::from(1),
            uncle_count: 0,
            umm_root: Some(Bytes::from("umm")),
            version_fields: None,
            bitcoin_merged_mining_header: Some(Bytes::from("btc_header")),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::from("proof")),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from("coinbase")),
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    #[test]
    fn test_header_rlp_roundtrip() {
        let header = standard_test_header();

        // Encode
        let mut buffer = Vec::new();
        header.encode(&mut buffer);

        // Decode
        let decoded_header = Header::decode(&mut buffer.as_slice()).expect("Failed to decode header");

        // Assert
        assert_eq!(header, decoded_header);
        
        // Hash check (just to ensure it doesn't panic)
        let hash = header.hash();
        assert_ne!(hash, B256::ZERO);
    }

    /// The items of an RLP list, each with its own header, as written.
    fn items_of(encoded: &[u8]) -> Vec<Vec<u8>> {
        let mut buf = encoded;
        let list = alloy_rlp::Header::decode(&mut buf).unwrap();
        assert!(list.list);
        let mut body = &buf[..list.payload_length];
        let mut items = Vec::new();
        while !body.is_empty() {
            let start = body;
            let item = alloy_rlp::Header::decode(&mut body).unwrap();
            let length = start.len() - body.len() + item.payload_length;
            items.push(start[..length].to_vec());
            body = &body[item.payload_length..];
        }
        items
    }

    /// An RLP list of items already written.
    fn list_of(items: &[Vec<u8>]) -> Vec<u8> {
        let payload = items.concat();
        let mut list = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut list);
        list.extend_from_slice(&payload);
        list
    }

    /// rskj reads a header's number, gas used and timestamp with
    /// `longValueExact`, and its uncle count with `intValueExact`: one past a
    /// Java `long`, or an `int`, and it cannot read the header at all.
    #[test]
    fn rskj_reads_no_header_past_a_java_long_or_int() {
        let decodes = |change: &dyn Fn(&mut Header)| {
            let mut header = standard_test_header();
            change(&mut header);
            let mut bytes = Vec::new();
            header.encode(&mut bytes);
            Header::decode(&mut bytes.as_slice()).is_ok()
        };
        let long = i64::MAX as u64;
        let int = i32::MAX as u64;
        assert!(decodes(&|h| h.number = long));
        assert!(!decodes(&|h| h.number = long + 1));
        assert!(decodes(&|h| h.gas_used = long));
        assert!(!decodes(&|h| h.gas_used = long + 1));
        assert!(decodes(&|h| h.timestamp = long));
        assert!(!decodes(&|h| h.timestamp = long + 1));
        assert!(decodes(&|h| h.uncle_count = int));
        assert!(!decodes(&|h| h.uncle_count = int + 1));
    }

    /// rskj reads the merged-mining fields all three or none, and
    /// `canBeDecoded` counts a header's fields exactly: with one or two of
    /// them, or a field after them, it cannot read the header.
    #[test]
    fn rskj_reads_the_merged_mining_fields_all_three_or_none() {
        let mut bytes = Vec::new();
        Header {
            umm_root: None,
            ..standard_test_header()
        }
        .encode(&mut bytes);
        let items = items_of(&bytes);
        assert_eq!(
            items.len(),
            19,
            "sixteen fields and three for merged mining"
        );
        // The sixteen fields, then `extra` items from the three.
        let read = |extra: usize| {
            let mut fields = items[..16].to_vec();
            fields.extend(items[16..].iter().cycle().take(extra).cloned());
            Header::decode(&mut list_of(&fields).as_slice())
        };
        assert!(read(0).is_ok(), "no merged-mining fields");
        assert!(read(1).is_err());
        assert!(read(2).is_err());
        assert!(read(3).is_ok(), "the three merged-mining fields");
        // Four are a UMM root and the three: which a header may carry is its
        // height's to say, in `HeaderLayoutRule`.
        assert!(read(4).is_ok_and(|header| header.umm_root.is_some()));
        assert!(read(5).is_err(), "a field after the merged-mining fields");
    }

    #[test]
    fn test_decode_with_hash_caches_hash() {
        let header = standard_test_header();
        let mut bytes = Vec::new();
        header.encode(&mut bytes);

        let mut slice = bytes.as_slice();
        let decoded = Header::decode_with_hash(&mut slice).expect("decode failed");

        assert!(decoded.cached_hash.is_some());
        assert_eq!(decoded.hash(), decoded.cached_hash.unwrap());
        // For canonical encoding, cached hash equals keccak256(original bytes)
        assert_eq!(decoded.cached_hash.unwrap(), keccak256(&bytes));
    }

    /// RSK mainnet block #729,024 (first skeleton anchor after orchid):
    /// post-RSKIP92 the block hash excludes the merged-mining merkle proof
    /// and coinbase tx. Groundtruth hash from public-node.rsk.co.
    #[test]
    fn test_rskip92_block_hash_excludes_proof_and_coinbase() {
        let header = Header {
            parent_hash: b256!("bc878751e68379e4bed22a803dd9b262939b857cd6bc1d665a767911ecc59697"),
            ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
            beneficiary: address!("07c5446adb392be116f4859a722589f3fa8223e4"),
            state_root: b256!("9353e92a109be8ea409972a9dc0b16eb8e6b03db731e26f84f5c007843dbb182"),
            transactions_root: b256!("59dcb4081ee7ca8a7d53532fbcdcba82b631f3e1489efde55c82a93b06c1aaac"),
            receipts_root: b256!("a70fc9a7d692ac80a46b23dcf81d5928dbdebc8ac097cfdbce2c03301d9e9406"),
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(0xa406a0050938ca1a7_u128),
            number: 729_024,
            gas_limit: U256::from(0x67c280),
            gas_used: 0,
            timestamp: 0x5b932ec1,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(0x387ee40),
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: Some(Bytes::from(hex::decode("00000020acdd4738e831d35ebe6645a87753b8b3f039e5f9c65c0400000000000000000085751e2e92e415c18a729c97da426024245e96dd2d79854549874cada2d2b50cc32e935ba11928170c066040").unwrap())),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::from(hex::decode("933662067ae81cd741330a5c016522ba48fb86623f060554ceaf7e22373cc12496524f3581c075e4b7515ef02c5618df17bf23b714f4f009de2ea39609e3b8f16ae54151c8e73358be6b287d1129df13fd32b128d3fc9b9f872d5a44f8a5ef2bb1254f0ff89566420ab6357c7e11c8607d6f4383b338b9c84191c50fc5e81475a643ee5a693f0116de61f1ff8823c25844416b1f1080d6017ac2a91b66b87bf3b777aa583044084d50a3b5b0902fba0e80b413a039037f353fe301c7c9862056fe78a6f14d21c663b2e556a8eb9c7b3e4b01eaa94e51fe55846d6e7151a72606ba69fa024ae827376734e89eb4e0f7a3f6e08f7cfef5ac21b9ae5fea70fe021d").unwrap())),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from(hex::decode("00000000000000c08c2bae9460a30c6a03f7a557813a68cebdc1d38c70ffd6363ac537fb20c15d4cbd3de0fd7404d31200000000000000002952534b424c4f434b3aa40e3d3aad7ee477a2f38bd83c6e22413b231f48e0b831214589ecde9fb7e24e00000000").unwrap())),
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };
        let expected = b256!("d444f85747420e624055e16285d2fd5a14a38fb1932a378a336d1e39e66e3db1");

        // Re-encode path (programmatically built header).
        assert_eq!(header.hash(), expected);

        // Wire-decode path: full encoding (with proof + coinbase, as rskj
        // transmits) must still hash without them.
        let mut bytes = Vec::new();
        header.encode(&mut bytes);
        let mut slice = bytes.as_slice();
        let decoded = Header::decode_with_hash(&mut slice).expect("decode failed");
        assert_eq!(decoded.cached_hash, Some(expected));
        // The wrong (pre-fix) value was keccak over the full encoding.
        assert_eq!(
            keccak256(&bytes),
            b256!("241f1473b749f420fc1dc1d9d398e478fba883c8b2b615ca4591cd3b2b352a8d")
        );
    }

    /// RSK mainnet block #9,257,552, fetched from public-node.rsk.co.
    ///
    /// The strongest single check on header encoding there is, because every
    /// field is real and three independent things have to agree: the block
    /// hash, the merged-mining hash (whose first 20 bytes the miner committed
    /// to in the coinbase, so mainnet's own hash rate attests to it), and the
    /// presence of `ummRoot`.
    ///
    /// `ummRoot` is the trap. From papyrus200 rskj writes it as the *empty*
    /// byte array -- never non-empty, since the UMM contracts were never
    /// deployed -- and nothing in the JSON-RPC representation of a block shows
    /// that the field is there at all. Omitting it changes both hashes, so a
    /// miner that left it out would produce blocks no peer accepts.
    #[test]
    fn mainnet_block_9257552_hashes_and_merged_mining_commitment() {
        let header = Header {
            parent_hash: b256!("8b46403b2df22f81f450bd631db76cb47fe104ed48ab9b94a441f64be823c292"),
            ommers_hash: b256!("e4d62e0f38c8a425952f64f56c6897c8fd4d9fdd09faeaddb904ec3a8362ae3b"),
            beneficiary: address!("4e5dabc28e4a0f5e5b19fcb56b28c5a1989352c1"),
            state_root: b256!("1f0d9418721c8a28c019e21a8af2af203ba43f68bfb8fa3b884642a55b5eedaf"),
            transactions_root: b256!("2af4a2f53589d9f78b09adfefe9dd8e34f22143743dd0d3b584af8f6ac4d21ad"),
            receipts_root: b256!("fa059fb22aad8c60ca36bc9d9820ae3c4310dc3d9363bcd2b2624eccb88ed1a6"),
            logs_bloom: Bloom::from_slice(&hex::decode("00000000000000000000301800100020000100000010000000000200000000100000000000010000000000000000000000000000000000000000800000000000000000000004000000000000400040000000000000000000200200000000000000000000000000000040000000000100000000020000000000000000000000000000400000000001000000000004000000000000000000000000000020000000000000000200000000000000000000000080400000000180000000000000000000000000000800000000040000008000000000000000000000000000000000000000000000000000002000000000000000000400000000000000200000000000").unwrap()),
            extension_data: None,
            difficulty: U256::from(0x175cf1ea6738d50d56au128),
            number: 9_257_552,
            gas_limit: U256::from(0x989680),
            gas_used: 0x22f96,
            timestamp: 0x6ab06c78,
            extra_data: Bytes::from(hex::decode("d30191564554495645522d643430323166636532").unwrap()),
            paid_fees: U256::from(0x3656c63bb76u64),
            minimum_gas_price: U256::from(0x1699280),
            uncle_count: 2,
            // Present and empty: papyrus200 activated at #2,392,700.
            umm_root: Some(Bytes::new()),
            version_fields: None,
            bitcoin_merged_mining_header: Some(Bytes::from(hex::decode("00e0f327307a19d17c1e20f51c1190b40d9fc53e7f056272a91d02000000000000000000cd81b87bdc182ac40f11daa46886c0b93b7e6497ca0e541ab5775f9c8fdd3d98936cb06ac51e02172a5c3c6e").unwrap())),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::from(hex::decode("c91bd5fe20d82da439eba4770fb50b6792cc06f083eb88b6795f0c89fc8ca427df7cc40dc64602e3fb3cf5c267664be19d148552f01cc28b6d3907d472008d15ba45ca54695cb6cbceac33003f9582450081de9ac6de608f0d49a78f2cae66c5c65cc0e8ac0674edfad8b00027c9d26b64ebe2476b5e91a95800b6786d91df004aa35390a8e996bf2cf9cc57555a12fcb76abcc376b20ebb5a441b1f94839653472ac163740f33c5e88a33003c73726de57da577d9e57d305937269421c1b0be94af8aa6a13a431fb5425ad871e9675edff825e8b49dc016ab6903bf63d376386dbb6c55d84d449f6147763855259dc20a09f72adfb25195c692bd8da719d1d8e9b227b874cbec4f58fb88dc6b21d810e995b4531346f37b0a3a7e54b3327d79450fa01b5a3420bd772f4f0605c829facdb88bc9f2945aa897aef9e6585c80fa62d683e84d1b8bd228f8c985a8269e312e7d0b135cf5aeb50132e1f2592a112db15c3e521d92fb7184af28a0adc8008fa3eb839d1b6d9e5d5c802160ffa7522649c18aa20502e09c50804448465889141227a0a82c85a0ce6876163ae60cc3ac").unwrap())),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from(hex::decode("000000000000014013a11ba36836286d0115b1c5c58a42ad692d3aeeaedae25686175928146d440f8931d770ea29b3d5f1dd2eabaf3724518831d656f447230000000000000000002b6a2952534b424c4f434b3afe829f5c494b038c03268d18d0e338bb162f06b69ebc2a5e8f871a1d008d425000000000").unwrap())),
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };

        assert_eq!(
            header.hash(),
            b256!("0e7f9744b001ec59e68f0d60e8bde08ae6e9b9b57113e9a372b2058cc144c9fa"),
            "block hash"
        );

        // What the miner actually committed to, read back out of the coinbase
        // this block carries: `RSKBLOCK:` then 20 bytes of merged-mining hash
        // and 12 of RSKIP110 fork-detection data.
        let coinbase = header.bitcoin_merged_mining_coinbase_transaction.clone().unwrap();
        let tag = b"RSKBLOCK:";
        let position = coinbase.windows(tag.len()).rposition(|w| w == tag).unwrap();
        let committed = &coinbase[position + tag.len()..position + tag.len() + 32];

        assert_eq!(
            &header.hash_for_merged_mining()[..20],
            &committed[..20],
            "merged-mining hash prefix"
        );
        // The remaining 12 bytes are not hash at all: seven bytes of
        // commit-to-parents vector, one uncle count, then the height.
        assert_eq!(&committed[28..32], &9_257_552u32.to_be_bytes(), "height in fork-detection data");

        // Omitting ummRoot is the mistake worth failing loudly on.
        let without_umm = Header { umm_root: None, ..header.clone() };
        assert_ne!(without_umm.hash(), header.hash());
        assert_ne!(without_umm.hash_for_merged_mining(), header.hash_for_merged_mining());
    }

    #[test]
    fn test_cached_hash_overrides_computed() {
        let mut header = standard_test_header();
        header.cached_hash = Some(B256::repeat_byte(0xAB));

        assert_eq!(header.hash(), B256::repeat_byte(0xAB));
    }

    #[test]
    fn test_hash_without_cache_computes_from_rlp() {
        let header = standard_test_header();
        assert_eq!(header.cached_hash, None);

        let hash1 = header.hash();
        assert_ne!(hash1, B256::ZERO);

        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_decode_with_hash_differs_from_noncanonical() {
        let header = standard_test_header();
        let mut bytes = Vec::new();
        header.encode(&mut bytes);

        let mut slice = bytes.as_slice();
        let decoded = Header::decode_with_hash(&mut slice).expect("decode failed");

        assert_eq!(decoded.cached_hash.unwrap(), keccak256(&bytes));
    }

    /// Groundtruth: the uncle of RSK MAINNET BLOCK #3397 (header #3395,
    /// hash 0xc1a82a82..., from public-node.rsk.co). Its zero
    /// minimumGasPrice encodes as a raw 0x00 byte (encodeSignedCoinNonNullZero)
    /// and its empty merged-mining proof/coinbase encode as 0x80 placeholders.
    /// Both the uncle's own hash and the block's sha3Uncles must match.
    #[test]
    fn test_mainnet_block_3397_uncle_encoding() {
        let header = Header {
            parent_hash: "0x6e2c4fc25852c65f06d2be44b702029f142d9ab89d5f5f21c24bb00ea890a4c6".parse().unwrap(),
            ommers_hash: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".parse().unwrap(),
            beneficiary: "0x14d3065c8eb89895f4df12450ec6b130049f8034".parse().unwrap(),
            state_root: "0x42536b117ad09ae74da25b5bc25dc1fc98fc1d995a2cba419673807966421624".parse().unwrap(),
            transactions_root: "0x1def8d2ff49af73e1abbb2c973a1af6f496b5e44bd7a93fbd1c0156090a50a9b".parse().unwrap(),
            receipts_root: "0x10494928db1d75522b131648096f37c5982db7ac4da9f0ab0d9820efafa3ecec".parse().unwrap(),
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(0x1ef082d0eba72au64),
            number: 0xd43,
            gas_limit: U256::from(0x4c4b40),
            gas_used: 0x4be3d0,
            timestamp: 0x5a4e720b,
            extra_data: Bytes::from_static(&[0x2a]),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: Some(Bytes::from(
                alloy_primitives::hex::decode("f8441ba100c98acd36a060dd25c8c8d46f42ededd98f7c2c7e5d460c3557a6ba0e693d4d50a053c04cb6bedfa59173811b3b1c2783f4328a7745f136abe58fcd1bac16de76e6").unwrap()
            )),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::new()),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::new()),
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };

        let mut encoded = Vec::new();
        header.encode(&mut encoded);
        let expected_hash: B256 =
            "0xc1a82a82e999490d8570ae9b80a3dcd29d143a65241d02db30e3d174988353d4".parse().unwrap();
        assert_eq!(keccak256(&encoded), expected_hash, "uncle header hash");

        // sha3Uncles of block #3397 = keccak(RLP([uncle_full_encoding]))
        let mut uncles_list = Vec::new();
        alloy_rlp::Header { list: true, payload_length: encoded.len() }.encode(&mut uncles_list);
        uncles_list.extend_from_slice(&encoded);
        let expected_sha3_uncles: B256 =
            "0xed488b69222610bae4c438b50d2472019e3efed77c654771025775d19d2ec648".parse().unwrap();
        assert_eq!(keccak256(&uncles_list), expected_sha3_uncles, "block #3397 sha3Uncles");
    }

    // ---- RSKIP-351 extension commitment ------------------------------------

    /// A version-0 header carries a literal bloom and commits to no extension.
    /// It must refuse every body offered to it: accepting one would let a peer
    /// attach sublist edges or a base event to a block that never had them,
    /// and both are consensus inputs.
    #[test]
    fn a_version_0_header_accepts_no_extension() {
        let header = standard_test_header();
        assert!(header.extension_data.is_none(), "fixture is not version 0");
        assert!(header.extension_commitment().is_none());

        let offered = crate::types::header_extension::BlockHeaderExtension::V1 {
            logs_bloom: vec![0x77; 256],
            edges: Some(vec![1, 2]),
        };
        assert!(
            !header.accepts_extension(&offered),
            "a header with a literal bloom must not adopt an extension"
        );
    }

    /// A header built from an extension accepts that extension and no other.
    #[test]
    fn a_versioned_header_accepts_only_its_own_extension() {
        let ext = crate::types::header_extension::BlockHeaderExtension::V2 {
            logs_bloom: vec![0x5A; 256],
            edges: Some(vec![3, 7]),
            base_event: Some(vec![0xBE, 0xEF]),
        };
        let mut header = standard_test_header();
        header.extension_data = Some(Bytes::from(ext.create_extension_data()));

        assert!(header.accepts_extension(&ext));

        // Same fields, one edge changed.
        let other = crate::types::header_extension::BlockHeaderExtension::V2 {
            logs_bloom: vec![0x5A; 256],
            edges: Some(vec![3, 8]),
            base_event: Some(vec![0xBE, 0xEF]),
        };
        assert!(!header.accepts_extension(&other));

        let c = header.extension_commitment().unwrap().unwrap();
        assert_eq!(c.version, 0x2);
    }

    /// Junk in the bloom slot is reported, not silently treated as version 0.
    #[test]
    fn an_unparseable_extension_slot_is_an_error_not_an_absence() {
        let mut header = standard_test_header();
        header.extension_data = Some(Bytes::from_static(&[0xC2, 0x05, 0x05]));
        assert!(
            matches!(header.extension_commitment(), Some(Err(_))),
            "an unreadable commitment must not read as 'no extension'"
        );
    }

    // ---- validated against real Rootstock testnet consensus ----------------

    /// A version-0 testnet header: no extension, the literal bloom in field 6.
    /// Pins the base layout -- ummRoot, merged mining, the RSKIP-92 rule --
    /// independently of anything versioned.
    #[test]
    fn testnet_block_6000000_v0_header_hash_matches_the_live_chain() {
        let header = Header {
            parent_hash: b256!("a3fae647e5b58890fd6067c7aef26f254bcb6c31c86d392d5e076af71668875c"),
            ommers_hash: b256!("8a4e3488f89383bcb3fddc898856c2955283e30d3b9231009face96507385c3b"),
            beneficiary: address!("1fab9a0e24ffc209b01faa5a61ad4366982d0b7f"),
            state_root: b256!("69839b3e54defe73551997a2be1bbb13d8834830e60803576e7010026dbe1bcc"),
            transactions_root: b256!("215a9d2bf259125a4758c61d53bab445848dff5e66e5798868c86f318d61b523"),
            receipts_root: b256!("d0904ea1cab441eb259b7de9ec3d37ea3cd15bb1b1d56dca5972ba8931cb3dd6"),
            logs_bloom: Bloom::from_slice(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000010000000000000000000000000080000000000000000000000800000000008000000000000000000000000000000000000200000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000400000004000000000000100000000000020010000000000000000000001000000000000000000001040000000000000000000000000020000001000080200000100000000000000000000000000000000000000000080000000000000000000000000000").unwrap()),
            extension_data: None,
            difficulty: U256::from(1228901524u64),
            number: 6000000,
            gas_limit: U256::from(6800000u64),
            gas_used: 135206,
            timestamp: 1737817791,
            extra_data: Bytes::from(hex::decode("d301914152524f57484541442d61333766656261").unwrap()),
            paid_fees: U256::from(8896554800000u64),
            minimum_gas_price: U256::from(4548441u64),
            uncle_count: 1,
            umm_root: Some(Bytes::new()),
            version_fields: None,
            bitcoin_merged_mining_header: Some(Bytes::from(hex::decode("000000200634d02c91a3516c8e83285791bbdc5b02fd31f38000006e43532a000000000060b2a8bb7560ce77fbe5d7292fcc708eec49fca8ace3f364e77433bc304d40bad50795679a0a0119c2eec753").unwrap())),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::from(hex::decode("fc29fbe26636c139458c602b0ff121d1017098500834d40e749f00448bfcaa181a42f80dfedf4a78a045936cbef21504b9dba52ec98f05b08840a469c1c2d8f9346ffde3a70182b3a6b8e737a2bf023458b890589f48f2e711ba631279bdd634bf9e4119806fcde6a0cdb03b3eca2ad4a48d963b8fed032fa6924746ed7f026da6c870ddcfd53f4a36636fcb61fd5eda5d3047f75c5cb13d6b8f755251331ef2").unwrap())),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from(hex::decode("000000000000008010685626cadc65f677c14b223755cfb6de56a4f933683312b254ee9307a397c46088ac0000000000000000266a24aa21a9ed401b9dfa5baf569d3af3b0e004a20541d5fb64a037d8670b764a7dbc40ad247500000000000000002a6a52534b424c4f434b3a92c99df0f40bcf1e4dc6c2d3ac5407b2caa26cfc09d51fa4e030f318005b8d8000000000").unwrap())),
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };
        assert_eq!(header.hash(), b256!("afe29f290437b18474a9d540ffe7379ee4f9d0149746644dc13de067d4cf13cd"));
    }



    /// Ground truth: the raw wire bytes of testnet block #8,160,760, captured
    /// from a peer by a node running against the live network.
    ///
    /// It is a **version 2** header. The RPC reports `baseEvent: null` for it,
    /// which is `BlockResultDTO` mapping an *empty* baseEvent to null -- the
    /// field is present and empty, not absent, and the version byte on the
    /// wire says 2.
    ///
    /// The wire layout, which no RSKIP documents:
    ///
    /// ```text
    ///   ... uncleCount, ummRoot, version, edges?, baseEvent, btcHeader, proof, coinbase
    /// ```
    ///
    /// The block hash is computed from a *different* encoding: field 6 carries
    /// `RLP.encodeElement(RLP([version, extensionHash]))` instead of the bloom,
    /// and the three trailing extension fields are dropped.
    #[test]
    fn testnet_block_8160760_v2_wire_header_hashes_correctly() {
        use crate::types::header_extension::BlockHeaderExtension;

        let raw = hex::decode("f9035fa07b2b4f40f1b6fbb42fef0e05fe41ceb25c9a4c96f5eb2380dbe94a4a9f664b93a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b774aa2876145b2f6f3de27e5e6ac970aa12d771a0303577f39639886ef50a22cd0081ff49f523f9aa9075f5e49f5ed3bb8e794902a0504fbb4f1f28b04002db231af48a0756d8ee3f32ab8277a935db5dec029ae37da07b365c9c464276bb79eca72d422017d9f4265db5a566ebe7e7c6a7d1395b872fb9010000000000000000000000000000000000000000000000000000000000000000000000400000040000000000000000000000000000010000000000000000000000000080000000000000000000000800000000008000000000000000000000000000000000000200000000000000000000000000000000000000000008000000000000000000000000000000000200000000000000040000000000000400000004000000000000100000000000020010000000000000000000001000000000000000000001040000000000000000000000000020000001000080200000100000000000000000000000000000000000000000080000000000000000000000000000844300f27b837c85f88400b71b008301dd80846ac754c592d1018f564554495645522d3733316239643885b3d72c0c008357a6e580800282010080b85000000020e9d0bbd3c80f25c84644090eaddec718fc2124750d3efc08c880630000000000050a1b6530ffc777c57368686608ce81fd092c8cae295ab15cd025eea12601b58a65c76a2c8c001a05db4a23b88003b86acbd6bedf92865e6f2056ef30a6417ca9b43fe69d1d1b1681f823e526ef55e71fc399143353d032d6b206527910efd62469502699d3f6b8d45b209731fe09d27bfc4607fdb5f4e6c7fb941b32117cf4d82091c131a0e992c11999e26cb1ba2da4adfb0795b1dc655e5b06184a38f16ed600f868b0caae492ff67ceb4f9cb891000000000000008070d305130080f23a1af12e807a11baa57931e43358b3b92c9b561ea42652191e6088ac0000000000000000266a24aa21a9ede00830d41e0043c7f6fdb871b79b0bb998fa93469ccb8a81e324d10e0129505500000000000000002a6a52534b424c4f434b3a1185e9e1e5eae04408c2ebb8037b8e6bea82becb58722b4d50299c15007c85f800000000").unwrap();
        let items = split_rlp_list(&raw);
        assert_eq!(items.len(), 23, "captured header item count");

        let logs_bloom = items[6].clone();
        assert_eq!(logs_bloom.len(), 256, "the wire carries the real bloom");
        assert_eq!(items[17], vec![0x02], "version byte on the wire");
        assert_eq!(items[18], vec![0x01, 0x00], "edges, little-endian [1]");
        assert!(items[19].is_empty(), "baseEvent present and empty");

        let extension = BlockHeaderExtension::V2 {
            logs_bloom: logs_bloom.clone(),
            edges: Some(vec![1]),
            base_event: Some(Vec::new()),
        };

        // Rebuild the compressed encoding: fields 0..=5, then the commitment
        // in the bloom's slot, then 7..=16 (through ummRoot), then only the
        // merged-mining header -- RSKIP-92 drops the proof and coinbase.
        let mut payload: Vec<u8> = Vec::new();
        for it in items.iter().take(6) {
            alloy_rlp::Encodable::encode(&it.as_slice(), &mut payload);
        }
        let commitment = extension.create_extension_data();
        alloy_rlp::Encodable::encode(&commitment.as_slice(), &mut payload);
        for it in items.iter().take(17).skip(7) {
            alloy_rlp::Encodable::encode(&it.as_slice(), &mut payload);
        }
        alloy_rlp::Encodable::encode(&items[20].as_slice(), &mut payload);

        let mut buf = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut buf);
        buf.extend_from_slice(&payload);

        assert_eq!(
            alloy_primitives::keccak256(&buf),
            b256!("a3403ff963cb87a3fb52371c690170f292e516d3ca367b73402f5c5900f140b1"),
            "must reproduce the hash testnet reached consensus on"
        );

        // The network's decoder reaches it from the bytes as sent, edges and
        // all, and the merged-mining hash the coinbase commits to.
        let decoded = Header::decode_with_hash(&mut raw.as_slice()).unwrap();
        assert_eq!(decoded.hash(), alloy_primitives::keccak256(&buf));
        let coinbase = decoded
            .bitcoin_merged_mining_coinbase_transaction
            .clone()
            .unwrap();
        let tag = b"RSKBLOCK:";
        let at = coinbase.windows(tag.len()).rposition(|w| w == tag).unwrap() + tag.len();
        assert_eq!(
            &decoded.hash_for_merged_mining()[..20],
            &coinbase[at..at + 20]
        );
    }

    /// Splits an RLP list into the payloads of its items.
    fn split_rlp_list(b: &[u8]) -> Vec<Vec<u8>> {
        let mut buf = b;
        let h = alloy_rlp::Header::decode(&mut buf).unwrap();
        assert!(h.list);
        let mut body = &buf[..h.payload_length];
        let mut out = Vec::new();
        while !body.is_empty() {
            let ih = alloy_rlp::Header::decode(&mut body).unwrap();
            out.push(body[..ih.payload_length].to_vec());
            body = &body[ih.payload_length..];
        }
        out
    }
}

#[cfg(test)]
mod versioned_wire_header_tests {
    use super::*;
    use alloy_rlp::Decodable;

    /// A testnet reed810 header, exactly as rskj stores it: the literal
    /// 256-byte bloom in the bloom slot and the version after `ummRoot`.
    const V1_WIRE: &str = concat!(
        "f90321a00252ae025d3339a92786e05618464665754ff688d5b1704282d0974712d0f77ca01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794905a918ba4e1c0eaa5e8186bdac1bd786f9f0c8aa0777ebf9d10",
        "066edefed3f70b492c226c84e6fe651c9e0ee24f7b470f4bf08b20a0b6edce5ae9e2df89eb8e8bb144e0d03ed885ea46",
        "c0ca72ea1a52a7b5384da7b5a08a048af6bf5bf016f24ee7452e68ce354f9b746dd036960cba1acbc65198fd63b90100",
        "000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000080000000000000000002000000",
        "000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000c000000000000000000001000000000000000100000000000010000000010010000000000",
        "000000810000000000020000000000000000200000000000842000001000000000000000000000000000000000000000",
        "000808000000000000000000000000008501ab902851836cf1108367c280830ebfc08469419ce688c70185524545442d",
        "8616ea1f215000840169928080800180b85000004020117749aef3c948db2669e7e4fe3acdc5e15497e0a4000a4f5fc5",
        "bd5700000000bb048d4ce30362e01fc594e252e99c2eda73d5d981dbca724f8bd987b9e3282e49a141699f1f031956e0",
        "a070b8605379889958ec3a9581629acf62b5d7f47488254e27aa666a138c8328ddcf8eb1a7660e42e11af681848e3d9d",
        "97207c30ca8a9d0b01b56c2ed630f2e59acd901ac92176a710bf86f05a48c92ff39d4c938ffbc6aa356baeeaf77e9d75",
        "565c9c2ab87e0000000000000100186b33f9239bea2ed26e2e899574775f136a2f1b43be664298a42b604b837ec501ad",
        "67ad0f32129ab431e6d18fda214e5b9f350ffc7b6cf3058b9026e76500000000000000002b6a2952534b424c4f434b3a",
        "0a82fd55469601ed22c406fb16f8cfc1834bbb83052c82075b86e91b006cf11000000000",
    );

    /// A testnet vetiver900 header -- version 2, so it carries a base event
    /// as well, empty because the block has none.
    const V2_WIRE: &str = concat!(
        "f9035ca0e6c6a8357e0755f07bd7e7ac44cab3404c182be237139be42f8e2e59ae551541a01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794ad418c1d48780005f6d847ef0a5e3bd93ea09090a0f0d72601cf",
        "2532977bf04dd50678b91ea880a81d0fcd60325007e5d9f0f801e1a0cea1f8d7a1652b6a738070c365405f04c3308c91",
        "154fe68aac124a12e8f4016fa0cdd9c5f3b359844415e82d68e3a8ec70cc277751fcf7cb8378851dae288538f5b90100",
        "000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000",
        "000000000100000000000000000000000000800000000000000000000008000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000",
        "000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000008447a40f2d837407e88367c28083016a4d8469f339f092d1018f564554495645",
        "522d6265343439313485948089f976835f64478080028080b85000000020ef145fde73d31abc4ba0e5b82e8afce729dc",
        "51c9562f50b392217822000000001def8ef1b0fdf43d53e4ef0bd826e52e19a7c9d505c34fb459370bb70fa2d13bfe3c",
        "f369c0f71a1bc1d1146eb880398f49964f5a77479f4244cbb2e9300ab003a8f510583e44be5e9fff9db9b02622033ae1",
        "224764d26e17972865081b7c56492881e25ff769137411ce440a0db80f4b690f53ce057116986345b8fff7a9cd43af03",
        "7e7f1be96e8c88c042824c118c77a5631f02db9d554555bceaeef77ec990d2beeca422cb3801a1008b259cb2b8910000",
        "0000000000806aac5c0a780d7c155e405262e52f39ca51b3f988f9f18be7dffe065e19007fbb6088ac00000000000000",
        "00266a24aa21a9edf883a036547b5e0374127de8a7dbcfdd3624e87f59af6b6cc0da5e3ac8bbecb60000000000000000",
        "2a6a52534b424c4f434b3aa299d0e6dcc89894d1897433dcfc94cb400657c925509283bf09a213007407e800000000",
    );

    /// Testnet #8,260,761 in full, as rustock's testnet node took it with its
    /// block, which rskj hashes to 0x9a1cfe09...0d47.
    const V2_FULL: &str = concat!(
        "f9029ba0285f7c3513c466f54fde5f1b73b2d93b35374515472192250bd3a56396dc649ea01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794b774aa2876145b2f6f3de27e5e6ac970aa12d771a04aa4b67c3e",
        "30508692f13e9e10758d907e7d851234cd6cd00d65aa49e5a1ac44a0f40c99e8151d350e30309fa0a74234c365961aa0",
        "81ad18e51a4281c513ec76d0a066cfdb731f620cd96e2c2cb0f7d3c3a2879c29b40014aa27efbbf3cf9cd3b0f6b90100",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000844edfab4b837e0c998400b71b0080846aec1a5c92d1018f564554495645522d",
        "3733316239643880835a74cf8080028080b8507111010000000000000000000000000000000000000000000000000000",
        "00000000000000135534881310aada94b2b5867af37e4e2fc48be028c35beeaa7f1dc4cf501e825d1aec6affff0f1d0d",
        "16caea80b85800000000000003c09e1ed89b4ab8f092a3dc3a4b852db4552dfd95136f298514ba947d076032a8f20bbe",
        "a052534b424c4f434b3a6e7fa68f56e3bc6085e7e02e325250f1c72ad9eef1a0d7693e516e10007e0c9900000000",
    );

    /// The same header compressed, as a converter written apart from this
    /// crate compressed it, following rskj's `getEncodedCompressed`.
    const V2_COMPRESSED: &str = concat!(
        "f901b9a0285f7c3513c466f54fde5f1b73b2d93b35374515472192250bd3a56396dc649ea01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794b774aa2876145b2f6f3de27e5e6ac970aa12d771a04aa4b67c3e",
        "30508692f13e9e10758d907e7d851234cd6cd00d65aa49e5a1ac44a0f40c99e8151d350e30309fa0a74234c365961aa0",
        "81ad18e51a4281c513ec76d0a066cfdb731f620cd96e2c2cb0f7d3c3a2879c29b40014aa27efbbf3cf9cd3b0f6a3e202",
        "a09aca8469839f117b1a26abbdea244a32cb0833e387cf6af9dc13eb336094d3c2844edfab4b837e0c998400b71b0080",
        "846aec1a5c92d1018f564554495645522d3733316239643880835a74cf8080b850711101000000000000000000000000",
        "000000000000000000000000000000000000000000135534881310aada94b2b5867af37e4e2fc48be028c35beeaa7f1d",
        "c4cf501e825d1aec6affff0f1d0d16caea80b85800000000000003c09e1ed89b4ab8f092a3dc3a4b852db4552dfd9513",
        "6f298514ba947d076032a8f20bbea052534b424c4f434b3a6e7fa68f56e3bc6085e7e02e325250f1c72ad9eef1a0d769",
        "3e516e10007e0c9900000000",
    );

    /// Testnet #8,260,720 as rskj's peers sent it to rustock's testnet node,
    /// compressed, which rskj hashes to 0xf343f40f...1bef.
    const V2_FROM_PEERS: &str = concat!(
        "f901f9a00bdcd28d517b22bc7b65bf669b05924ac8ba8a862ccb4b17d619fdbd8b9789f8a01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794ad418c1d48780005f6d847ef0a5e3bd93ea09090a0c545101cc3",
        "df462f9c369b22f722ec66ade0f031b528512f12fceca574d0ecc8a01db2709b879ae45385439bc35bc1ce8e821de8ae",
        "b4a4e8ec9c94cf9f3dc55f7ea01ddfe2c6ff70e83e21bc8a905eb71278aab2fc921dd08543c20451a2ccbf286da3e202",
        "a03c015999cbb7ab1fdb80e23b658a251e424af79a99262579f2fd59bd50fddc78844f476ad3837e0c708400b71b0082",
        "e8f8846aec16be92d1018f564554495645522d37333162396438855a76a29740835a5a088080b85000000020785e2a8b",
        "51231a7478b788a2427a2a4c190c0f4e418e25c4ca0c000000000000ba37f569d2f87d917d83e79d50af85497b7d35f0",
        "ebe4e7c57ddd76e80fb58dfca130ec6af0ff0f1a007dc5fa80b8910000000000000080f880b614920083ca51e27b69b7",
        "d6dba5262da24a347487e62e8406463eb94d6a6088ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999",
        "dfa36953755c690689799962b48bebd836974e8cf900000000000000002a6a52534b424c4f434b3a3d8461c1058c9db8",
        "352ad0c0b7e56a1ba4fcac4da0d7693e516ef40a007e0c7000000000",
    );

    /// rskj sends a chain's headers to its peers compressed
    /// (`getEncodedCompressed`), and reads them so: a versioned header's
    /// commitment in slot 6, none of its own fields after `ummRoot`, and all
    /// three merged-mining fields. A header taken in full compresses to what a
    /// converter written apart from this crate makes of it; one that rskj's
    /// peers sent compressed is held so, and written back the same in either
    /// form, with rskj's hash.
    #[test]
    fn a_versioned_header_compresses_as_rskj_sends_it_to_its_peers() {
        let hex = |text: &str| alloy_primitives::hex::decode(text).unwrap();
        let wire = |header: &Header| {
            let mut out = Vec::new();
            header.encode(&mut out);
            out
        };
        let hash: B256 = "0x9a1cfe099ff781afac37ad659654fd4c0e6fe400ba764be2f80bd3dec2600d47"
            .parse()
            .unwrap();
        let full = from_the_network(V2_FULL);
        assert_eq!((full.number, full.hash()), (8_260_761, hash));
        assert_eq!(full.encode_compressed(), hex(V2_COMPRESSED));
        assert_eq!(wire(&full), hex(V2_FULL));
        // Read back as rskj's peers send it: the same hashes, and held
        // compressed, no other form.
        let read = from_the_network(V2_COMPRESSED);
        assert_eq!(read.hash(), hash);
        assert_eq!(read.hash_for_merged_mining(), full.hash_for_merged_mining());
        assert_eq!(read.encode_compressed(), hex(V2_COMPRESSED));
        assert_eq!(wire(&read), hex(V2_COMPRESSED));
        // So for one that rskj's peers sent.
        let peers = from_the_network(V2_FROM_PEERS);
        let peers_hash: B256 = "0xf343f40fdd2152318c13fda9abdc80bb5e8a57a9166e831dfbdfb448f7821bef"
            .parse()
            .unwrap();
        assert_eq!((peers.number, peers.hash()), (8_260_720, peers_hash));
        assert_eq!(peers.encode_compressed(), hex(V2_FROM_PEERS));
        assert_eq!(wire(&peers), hex(V2_FROM_PEERS));
        // A version-0 header has one form.
        let mut v0 = decode(V1_WIRE);
        v0.version_fields = None;
        assert_eq!(v0.encode_compressed(), wire(&v0));
    }

    /// **The extension beside a body.** A header read compressed, as rskj's
    /// peers send a chain's headers, holds only the commitment to its
    /// extension. Given the extension it names, as rskj sets the one sent
    /// beside the block's body, it is the header the network sends whole: the
    /// same wire form byte for byte, the same hashes, the same extension. It
    /// takes no other -- another bloom, another version, a bloom not 256 bytes
    /// long -- and a header that holds its own fields, or none, takes none.
    #[test]
    fn a_compressed_header_takes_the_extension_its_commitment_names() {
        use crate::types::header_extension::BlockHeaderExtension;
        let wire = |header: &Header| {
            let mut out = Vec::new();
            header.encode(&mut out);
            out
        };
        for full_form in [V1_WIRE, V2_WIRE, V2_FULL] {
            let full = from_the_network(full_form);
            let extension = full
                .extension()
                .expect("a versioned header's own extension");
            let compressed =
                from_the_network(&alloy_primitives::hex::encode(full.encode_compressed()));
            assert!(compressed.extension_data.is_some());
            assert_eq!(compressed.extension(), None, "only the commitment");
            let mut both = compressed.clone();
            both.version_fields = full.version_fields.clone();
            assert_eq!(
                both.extension(),
                None,
                "its hash commits through the commitment alone"
            );
            assert_eq!(compressed.hash(), full.hash());

            let completed = compressed
                .with_extension(&extension)
                .expect("the one it names");
            assert_eq!(wire(&completed), wire(&full), "#{}", full.number);
            assert_eq!(completed.extension(), Some(extension.clone()));
            let derived = Header {
                cached_hash: None,
                cached_hash_for_merged_mining: None,
                ..completed.clone()
            };
            assert_eq!(
                (derived.hash(), derived.hash_for_merged_mining()),
                (full.hash(), full.hash_for_merged_mining())
            );

            let mut bloom = extension.logs_bloom().to_vec();
            bloom[0] ^= 1;
            let edges = extension.edges().map(<[i16]>::to_vec);
            let others = [
                match &extension {
                    BlockHeaderExtension::V1 { .. } => BlockHeaderExtension::V1 {
                        logs_bloom: bloom,
                        edges: edges.clone(),
                    },
                    BlockHeaderExtension::V2 { base_event, .. } => BlockHeaderExtension::V2 {
                        logs_bloom: bloom,
                        edges: edges.clone(),
                        base_event: base_event.clone(),
                    },
                },
                match &extension {
                    BlockHeaderExtension::V1 { logs_bloom, .. } => BlockHeaderExtension::V2 {
                        logs_bloom: logs_bloom.clone(),
                        edges: edges.clone(),
                        base_event: Some(Vec::new()),
                    },
                    BlockHeaderExtension::V2 { logs_bloom, .. } => BlockHeaderExtension::V1 {
                        logs_bloom: logs_bloom.clone(),
                        edges,
                    },
                },
            ];
            for other in &others {
                assert_eq!(compressed.with_extension(other), None, "#{}", full.number);
            }
            assert_eq!(
                full.with_extension(&extension),
                None,
                "it holds its own fields"
            );
        }

        // A bloom that isn't 256 bytes long, though the commitment names it.
        let short = BlockHeaderExtension::V2 {
            logs_bloom: vec![0; 255],
            edges: None,
            base_event: Some(Vec::new()),
        };
        let mut committed = from_the_network(V2_COMPRESSED);
        let mut slot = Vec::new();
        short.create_extension_data().as_slice().encode(&mut slot);
        committed.extension_data = Some(Bytes::from(slot));
        assert!(committed.accepts_extension(&short));
        assert_eq!(committed.with_extension(&short), None);

        // A version-0 header has none, and takes none.
        let mut v0 = decode(V1_WIRE);
        v0.version_fields = None;
        assert_eq!(v0.extension(), None);
        assert_eq!(v0.with_extension(&short), None);
    }

    /// A header decoded without caching either hash, so `hash()` and
    /// `hash_for_merged_mining()` derive them by encoding: the path a header
    /// built here takes.
    fn decode(hex: &str) -> Header {
        let bytes = alloy_primitives::hex::decode(hex).unwrap();
        let mut slice = bytes.as_slice();
        // Testnet headers, so testnet's RSKIP-144 height.
        let testnet = crate::config::ActivationHeights::testnet();
        let h = Header::decode_with_activations(&mut slice, &testnet).unwrap();
        assert_eq!((h.cached_hash, h.cached_hash_for_merged_mining), (None, None));
        h
    }

    /// Testnet #7,139,600 -- the reed810 activation block, the first header
    /// whose bloom moved into an extension.
    ///
    /// The hash has to come from the *compressed* encoding: the bloom slot
    /// holds `RLP([version, keccak(extension)])` and the trailing fields are
    /// dropped. Hashing the wire form instead gave every header from this
    /// block on a hash no other node agrees with, which surfaced as REMASC's
    /// selection rule comparing the wrong ones.
    #[test]
    fn a_v1_wire_header_hashes_to_what_the_chain_says() {
        let h = decode(V1_WIRE);
        assert_eq!(h.number, 7_139_600);
        assert_eq!(h.version_fields.as_ref().map(|v| v.version), Some(1));
        assert_eq!(
            h.hash(),
            "0xa44a88ce39fb3851d7f9b5ca9879b2c93b2544b12ac8239c034c6e589219c411"
                .parse::<B256>()
                .unwrap()
        );
    }

    /// Testnet #7,604,200 -- the vetiver900 activation block, version 2.
    #[test]
    fn a_v2_wire_header_hashes_to_what_the_chain_says() {
        let h = decode(V2_WIRE);
        assert_eq!(h.number, 7_604_200);
        assert_eq!(h.version_fields.as_ref().map(|v| v.version), Some(2));
        assert!(
            h.version_fields.as_ref().unwrap().base_event.is_some(),
            "a V2 header carries a base event even when the block has none"
        );
        assert_eq!(
            h.hash(),
            "0x27138ca46912bd08e1a9a942a5e81d0ec96fc91820f539f7e872239b3a1626bd"
                .parse::<B256>()
                .unwrap()
        );
    }

    /// The store re-encodes every header it writes, so anything the wire form
    /// cannot round-trip is lost from the database rather than from a single
    /// message. The first attempt at this encoded the edges with `Vec<u8>`,
    /// which alloy emits as a list of single bytes, and the result would not
    /// decode at all.
    #[test]
    fn a_versioned_header_survives_being_re_encoded() {
        for wire in [V1_WIRE, V2_WIRE] {
            let original = decode(wire);
            let mut buf = Vec::new();
            original.encode(&mut buf);
            assert_eq!(
                alloy_primitives::hex::encode(&buf),
                wire,
                "re-encoding must reproduce rskj's own bytes"
            );

            let mut slice = buf.as_slice();
            let mut again = Header::decode(&mut slice).unwrap();
            again.cached_hash = None;
            assert_eq!(again.hash(), original.hash());
            assert_eq!(again.version_fields, original.version_fields);
            assert_eq!(again.logs_bloom, original.logs_bloom);
            assert_eq!(
                again.bitcoin_merged_mining_header,
                original.bitcoin_merged_mining_header
            );
        }
    }


    /// A testnet V2 header from the base-event recovery window, where rskj
    /// accepts a header one element short and supplies an empty base event
    /// (`BlockFactory.isInBaseEventRecoveryWindow`, testnet only, below
    /// #7,800,000).
    ///
    /// Testnet #7,610,038 is one: version 2, an empty edges field, and no
    /// base event element at all. Reading that single trailing element as the
    /// base event takes the edges for it, and the header hashes wrong -- which
    /// put this block off the canonical chain as far as REMASC was concerned,
    /// and surfaced at #7,610,088 as a `brokenSelectionRule` computed from the
    /// wrong processing block.
    const V2_SHORT_WIRE: &str = concat!(
        "f9039ba0cc346a97c07829a8141fb4e05e3d23f34f22b516e7633443c29b63071f559549a01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794b774aa2876145b2f6f3de27e5e6ac970aa12d771a062b3e056cc",
        "c2a82da98835b4f97332be60dd932f32f39210244feb3cc6c7cd4fa0fda7a5d4416d23e24de57f56a2a2e1c0b2f66529",
        "2bf869abca1545c702b4f134a0ee88aad6351b56e1ba187f3622b45708f038cbffde58ecf9226b8cef4ae2f6f6b90100",
        "000000000000000000000000000000000000000000000000000000000000000000004000000400000000000000000000",
        "000000000100000000000000000000000000800000000000000000000008000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000",
        "000000000400000000000004000000040000000000001000000000000000100000000000000000000010000000000000",
        "000000010400000000000000000000000000200000000000802000001000000000000000000000000000000000000000",
        "000000000000000000000000000000008444fe47ef83741eb68367c28083016a3c8469f56ec692d1018f564554495645",
        "522d626534343931348590809c57a0835cd6e880800280b8500000002068365e8e5ccff1319164e71ccd01087044ff1a",
        "39706ce65c677c14f6000000001a9208cbd76abc95b0dc4a68b18a32fa64b11af432121393f513269bf6c0b4821e70f5",
        "69f0bd061b46301295b8c0fa8111aca10ab53448dbdf1c4573a2caa47cad2d71f67bc463e5f9e209c253cb8ede63c8ab",
        "d0cb2b7db5c12a2ca8f1408c81afca9e1476249a06cfc5911266f19fb5c9e5502a49bf1875b0e5680627fedc99d8a8dc",
        "be38738a31e59e410b9b29668de54fa4e877fe1296506a9439b9cd1b01a0c0ce48df8af374ced199c2578d4e20fb262f",
        "9320a0b682ad7838b84e13e07e067188399fa314d822b0e62feacf9a77787d3382698ac1780705a2a31cb4bd433845c7",
        "cbb4ae56a0df5e54152e04b89100000000000000806186026de2b34cd6af8d9a404c455ad350422e347ec41790944c51",
        "497baa779b6088ac0000000000000000266a24aa21a9ed0e17800cbbd43be92cf60aab5b68a25d2e5ef1da482dda1bbd",
        "2057fd1bd4a59300000000000000002a6a52534b424c4f434b3a992f0beca2dc21b0d1d9348b8a459bfebab19e1a0697",
        "d50308ca8a1200741eb600000000",
    );

    /// Block 1 of a chain rskj's regtest mined (regtest.conf: rskip144 = -1,
    /// rskip351 = 1, rskip535 = 1), in rskj's full encoding as `ExportBlocks`
    /// writes it. Its one trailing item after the version byte is an empty
    /// base event, not edges: there are no edges without RSKIP-144.
    const RSKJ_REGTEST_V2_FULL: &str = concat!(
        "f902b1a0227d8e8d835f5e7290e333f4177e551ef1222dde4704f677ba4a120051c31cc2a01dcc4de8dec75d7aab85b5",
        "67b6ccd41ad312451b948a7413f0a142fd40d4934794916d3652976d82540412b561bf674f72cf5174f7a095f20004ac",
        "91b058db01cac465f2bee87bae91843d454d578422a0346296b349a05c993f19d5d0ce9a0575e4913550d1587be7adbd",
        "4343d82641f000cd48fa36dfa09cc84f42988b259d422bf9d9689c5d19440453c1f5ec60b7c97b85e88bf6ad58b90100",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000840ffe00000184017d7840830393b8846ad918ef95d40192534e415053484f54",
        "2d333932616535353036800080800280b850711101000000000000000000000000000000000000000000000000000000",
        "0000000000006e8e9b9f5085479cb2c000d55a1fef80a1113178f6fa983d2b71fb8c02ab5e3efd18d96affff7f210000",
        "000080b86f00000000000001007d81c84537d4c647fe4c852f3013ebc7ecd9bb197b87be6c2e5fb1f26af9ffd7e2d050",
        "014ad8faf650ba1fdf18e8fd47e9e7034abdd27633792952534b424c4f434b3a766b7c6c7a3ba90d710c30e44d81ccd2",
        "a0fab6e1939acd3e8cd8feda1568dc8600000000",
    );

    #[test]
    fn a_v2_header_without_rskip144_carries_a_base_event_not_edges() {
        let bytes = alloy_primitives::hex::decode(RSKJ_REGTEST_V2_FULL).unwrap();
        let regtest = crate::config::ActivationHeights::regtest();
        let h = Header::decode_with_activations(&mut bytes.as_slice(), &regtest).unwrap();
        let v = h.version_fields.as_ref().unwrap();
        assert_eq!(v.version, 2);
        assert_eq!(v.edges, None, "no RSKIP-144, no edges");
        assert_eq!(v.base_event.as_ref().map(|b| b.len()), Some(0));
        // Its hash (rskj's 0x5cfa0726...) depends on RSKIP-92 being active,
        // which `hash()` reads from the process-wide heights; the import test
        // in rustock-cli checks it under regtest's.
        // And the full encoding round-trips.
        let mut again = Vec::new();
        h.encode(&mut again);
        assert_eq!(again, bytes);
    }

    #[test]
    fn a_v2_header_without_a_base_event_element_still_hashes_right() {
        let h = decode(V2_SHORT_WIRE);
        assert_eq!(h.number, 7_610_038);
        let v = h.version_fields.as_ref().unwrap();
        assert_eq!(v.version, 2);
        assert_eq!(v.edges.as_deref(), Some(&[][..]), "the edges field is present and empty");
        assert_eq!(v.base_event, None, "no base event element on the wire");
        assert_eq!(
            h.hash(),
            "0x119296ea9d8d7efa82550bfb447ae9441ea75f9537f47917f1ca38e0b8982c05"
                .parse::<B256>()
                .unwrap()
        );
    }

    /// And the short form must round-trip as the short form: re-emitting an
    /// empty base event would add an element rskj never wrote.
    #[test]
    fn the_short_v2_form_is_re_encoded_as_the_short_form() {
        let original = decode(V2_SHORT_WIRE);
        let mut buf = Vec::new();
        original.encode(&mut buf);
        assert_eq!(alloy_primitives::hex::encode(&buf), V2_SHORT_WIRE);
    }

    /// The schedule perf-lab's mainnet seed runs under puts RSKIP-144 at
    /// #9,002,504. Above it, a V2 header with one trailing item carries
    /// edges (rskj in the base-event recovery window); under mainnet's own
    /// schedule the same bytes carry a base event. The override reaches the
    /// decoder through `rskip144`, the way regtest's does.
    #[test]
    fn a_reed810_override_turns_a_lone_trailing_item_into_edges() {
        let mut h = decode(V2_SHORT_WIRE);
        h.number = 9_003_580;
        h.cached_hash = None;
        let v = h.version_fields.as_mut().unwrap();
        assert_eq!((v.version, v.base_event.as_ref()), (2, None));
        v.edges = Some(vec![]);
        let mut buf = Vec::new();
        h.encode(&mut buf);

        let mut seed = crate::config::ActivationHeights::mainnet();
        seed.set_rskj_hardfork("reed810", Some(9_002_504));
        assert_eq!(seed.rskip144, Some(9_002_504));
        let under_seed = Header::decode_with_activations(&mut buf.as_slice(), &seed).unwrap();
        let v = under_seed.version_fields.as_ref().unwrap();
        assert_eq!(v.edges.as_deref(), Some(&[][..]));
        assert_eq!(v.base_event, None);

        let mainnet = crate::config::ActivationHeights::mainnet();
        assert_eq!(mainnet.rskip144, None);
        let under_mainnet = Header::decode_with_activations(&mut buf.as_slice(), &mainnet).unwrap();
        let v = under_mainnet.version_fields.as_ref().unwrap();
        assert_eq!(v.edges, None);
        assert_eq!(v.base_event.as_ref().map(|b| b.len()), Some(0));
    }

    /// A version-0 header must stay untouched by any of this: mainnet is
    /// entirely V0, so a decoder that invented version fields for it would
    /// change hashes on a chain that has none.
    #[test]
    fn a_v0_header_gains_no_version_fields() {
        let mut h = decode(V1_WIRE);
        h.version_fields = None;
        h.cached_hash = None;
        let mut buf = Vec::new();
        h.encode(&mut buf);
        let mut slice = buf.as_slice();
        let again = Header::decode(&mut slice).unwrap();
        assert_eq!(again.version_fields, None);
    }

    /// A header decoded as the network decodes one: `decode_with_hash`, over
    /// the whole of `hex`, under testnet's heights, whose headers these are.
    fn from_the_network(hex: &str) -> Header {
        let bytes = alloy_primitives::hex::decode(hex).unwrap();
        let mut rest = bytes.as_slice();
        let testnet = crate::config::ActivationHeights::testnet();
        let h = Header::decode_with_hash_and_activations(&mut rest, &testnet).unwrap();
        assert!(rest.is_empty(), "bytes after the header");
        h
    }

    /// What the miner committed to in the coinbase after `RSKBLOCK:`: the
    /// first 20 bytes of the merged-mining hash.
    fn committed(h: &Header) -> Vec<u8> {
        let coinbase = h
            .bitcoin_merged_mining_coinbase_transaction
            .as_ref()
            .unwrap();
        let tag = b"RSKBLOCK:";
        let at = coinbase.windows(tag.len()).rposition(|w| w == tag).unwrap() + tag.len();
        coinbase[at..at + 20].to_vec()
    }

    /// The network decodes headers with `decode_with_hash`, which caches
    /// both hashes from the bytes sent. It used to hash those bytes whole,
    /// and for a versioned header they are not what rskj hashes: every
    /// testnet header from reed810 on got a hash no other node agrees with,
    /// so none named its parent, and the snapshot sync refused every chain it
    /// was offered as not forming one.
    #[test]
    fn the_network_decoder_hashes_a_versioned_header_as_rskj_does() {
        for (wire, hash) in [
            (
                V1_WIRE,
                "0xa44a88ce39fb3851d7f9b5ca9879b2c93b2544b12ac8239c034c6e589219c411",
            ),
            (
                V2_WIRE,
                "0x27138ca46912bd08e1a9a942a5e81d0ec96fc91820f539f7e872239b3a1626bd",
            ),
            (
                V2_SHORT_WIRE,
                "0x119296ea9d8d7efa82550bfb447ae9441ea75f9537f47917f1ca38e0b8982c05",
            ),
        ] {
            let hash: B256 = hash.parse().unwrap();
            let h = from_the_network(wire);
            assert_eq!(h.cached_hash, Some(hash), "#{}", h.number);
            // What testnet's miners committed to, so its hash rate attests to it.
            let merged = h.cached_hash_for_merged_mining.unwrap();
            assert_eq!(&merged[..20], committed(&h).as_slice(), "#{}", h.number);
            // And a header built here derives both the same way.
            let built = decode(wire);
            assert_eq!(built.hash(), hash, "#{}", h.number);
            assert_eq!(built.hash_for_merged_mining(), merged, "#{}", h.number);
        }
    }

    /// Every layout the decoder reads, built here and read back as the
    /// network reads it: what `decode_with_hash` caches from the items sent
    /// is what this node derives by encoding. The captured headers above tie
    /// both paths to rskj; this ties down where `ummRoot`, a versioned
    /// header's own fields and the mining fields sit, across layouts no
    /// captured header has: a UMM root, edges, a base event, no mining
    /// fields, a header from before RSKIP-92.
    #[test]
    fn every_layout_caches_the_hashes_it_would_encode_to() {
        let real = decode(V1_WIRE);
        let umm = [None, Some(Bytes::new()), Some(Bytes::from(vec![0xab; 20]))];
        let fields = |version, edges: Option<Vec<i16>>, base_event: Option<Bytes>| {
            Some(HeaderVersionFields {
                version,
                edges,
                base_event,
            })
        };
        // RSKIP-144 decides what a lone item after a V2 version byte is: the
        // edges where it is active, the base event where it is not. Each
        // layout is read under heights that make it one rskj reads.
        let with_144 = crate::config::ActivationHeights {
            rskip144: Some(0),
            ..crate::config::ActivationHeights::testnet()
        };
        let without_144 = crate::config::ActivationHeights {
            rskip144: None,
            ..crate::config::ActivationHeights::testnet()
        };
        let versions = [
            (None, &with_144),
            (fields(1, None, None), &with_144),
            (fields(1, Some(vec![1, 3]), None), &with_144),
            (fields(2, Some(vec![]), Some(Bytes::new())), &with_144),
            (fields(2, Some(vec![2]), None), &with_144),
            (fields(2, Some(vec![2]), Some(Bytes::from_static(b"base event"))), &with_144),
            (fields(2, None, Some(Bytes::from_static(b"base event"))), &without_144),
        ];
        let mut layouts = 0;
        for number in [100, real.number] {
            for umm_root in &umm {
                for (version_fields, activations) in &versions {
                    for mining in [true, false] {
                        // The decoder tells `ummRoot` from the mining fields
                        // by count, so it reads one only beside them, and
                        // the version fields only after one.
                        if (umm_root.is_some() || version_fields.is_some()) && !mining {
                            continue;
                        }
                        if version_fields.is_some() && umm_root.is_none() {
                            continue;
                        }
                        let mut header = Header {
                            number,
                            umm_root: umm_root.clone(),
                            version_fields: version_fields.clone(),
                            ..real.clone()
                        };
                        if !mining {
                            header.bitcoin_merged_mining_header = None;
                            header.bitcoin_merged_mining_merkle_proof = None;
                            header.bitcoin_merged_mining_coinbase_transaction = None;
                        }
                        let mut wire = Vec::new();
                        header.encode(&mut wire);
                        assert_eq!(
                            Header::decode_with_activations(&mut wire.as_slice(), activations).unwrap(),
                            header,
                            "the layout reads back"
                        );
                        let cached =
                            Header::decode_with_hash_and_activations(&mut wire.as_slice(), activations)
                                .unwrap();
                        assert_eq!(cached.cached_hash, Some(header.hash()), "{header:?}");
                        assert_eq!(
                            cached.cached_hash_for_merged_mining,
                            Some(header.hash_for_merged_mining()),
                            "{header:?}"
                        );
                        layouts += 1;
                    }
                }
            }
        }
        // Per height: four version-0 layouts, and six versioned ones on
        // each of two UMM roots.
        assert_eq!(layouts, 2 * (4 + 6 * 2));
    }
}
