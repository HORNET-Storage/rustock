//! The `extraData` of a mined block, in rskj's shape.
//!
//! rskj `MinerServerImpl.buildExtraData` and `setExtraData`: an RLP list of
//! a version byte, the node's identity (`<version>-<commit>`) and, when the
//! operator configured one, a client string, cut so the whole field stays
//! within the 32 bytes `ExtraDataRule` allows. Written this way so a block
//! explorer reading rskj's format reads this node's blocks too.

use alloy_primitives::Bytes;
use alloy_rlp::Encodable;

/// rskj `MinerServerImpl.EXTRA_DATA_MAX_SIZE`, `Constants.getMaximumExtraDataSize()`.
pub const EXTRA_DATA_MAX_SIZE: usize = 32;
/// rskj `MinerServerImpl.EXTRA_DATA_VERSION`.
pub const EXTRA_DATA_VERSION: u8 = 1;
/// rskj `rlpClientExtraDataEncodingOverhead`: the list header, the version
/// byte and the client item's own header.
const RLP_CLIENT_EXTRA_DATA_ENCODING_OVERHEAD: usize = 3;

/// `[version, identity]`, or `[version, identity, client]` when `client` is
/// not empty, with `client` cut to what fits in 32 bytes. An identity that
/// would not leave room for the version alone is cut too: rskj trusts its
/// build to keep it short, and a header over 32 bytes is one no peer takes.
pub fn build(identity: &str, client: &[u8]) -> Bytes {
    let identity_room = EXTRA_DATA_MAX_SIZE - RLP_CLIENT_EXTRA_DATA_ENCODING_OVERHEAD - 1;
    let identity = &identity.as_bytes()[..identity.len().min(identity_room)];
    let client_room = EXTRA_DATA_MAX_SIZE
        - 1
        - identity.len()
        - RLP_CLIENT_EXTRA_DATA_ENCODING_OVERHEAD;
    let client = &client[..client.len().min(client_room)];

    let mut payload = Vec::new();
    EXTRA_DATA_VERSION.encode(&mut payload);
    identity.encode(&mut payload);
    if !client.is_empty() {
        client.encode(&mut payload);
    }
    let mut out = Vec::with_capacity(payload.len() + 1);
    alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    Bytes::from(out)
}

/// The list's items, decoded, for tests and for anyone reading a header.
pub fn decode(extra_data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut buf = extra_data;
    let header = alloy_rlp::Header::decode(&mut buf).ok()?;
    if !header.list {
        return None;
    }
    let mut body = &buf[..header.payload_length];
    let mut items = Vec::new();
    while !body.is_empty() {
        // `Bytes`, not `Vec<u8>`: alloy-rlp reads the latter as a list of
        // integers, and these items are byte strings.
        let item: Bytes = alloy_rlp::Decodable::decode(&mut body).ok()?;
        items.push(item.to_vec());
    }
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = "0.1.0-cb7f28e";

    /// rskj `MinerServerTest.extraDataNotInitializedWithClientData`.
    #[test]
    fn extra_data_not_initialized_with_client_data() {
        let items = decode(&build(IDENTITY, b"")).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], vec![1]);
        assert_eq!(items[1], IDENTITY.as_bytes());
    }

    /// rskj `MinerServerTest.extraDataWithClientData`.
    #[test]
    fn extra_data_with_client_data() {
        let items = decode(&build(IDENTITY, b"tincho")).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], vec![1]);
        assert_eq!(items[1], IDENTITY.as_bytes());
        assert_eq!(items[2], b"tincho");
    }

    /// rskj `MinerServerTest.extraDataWithClientDataMoreThan32Bytes`: the
    /// client string is cut so the field is exactly 32 bytes.
    #[test]
    fn extra_data_with_client_data_more_than_32_bytes() {
        let extra = build(IDENTITY, b"tincho is the king of mining");
        assert_eq!(extra.len(), 32);
        let items = decode(&extra).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], vec![1]);
        assert_eq!(items[1], IDENTITY.as_bytes());
        assert!(b"tincho is the king of mining".starts_with(&items[2]));
        assert!(!items[2].is_empty());
    }

    /// Whatever is configured, the field passes `ExtraDataRule`.
    #[test]
    fn extra_data_never_exceeds_32_bytes() {
        for client_len in [0usize, 1, 10, 28, 29, 100] {
            let extra = build(IDENTITY, &vec![0x41; client_len]);
            assert!(extra.len() <= 32, "client of {client_len}: {}", extra.len());
        }
        assert!(build(&"x".repeat(100), b"abc").len() <= 32);
    }
}
