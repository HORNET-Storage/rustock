//! Testnet's headers over the wire, under testnet's heights. The message
//! decoder reads headers under the process's heights, as a testnet node's
//! does under those it installs at startup; this test binary is its own
//! process, and installs testnet's.

use alloy_primitives::hex;
use alloy_rlp::{Decodable, Encodable};
use rustock_core::config::ActivationHeights;
use rustock_core::types::header::{HeaderForm, HeaderVersionFields};
use rustock_core::Header;
use rustock_networking::protocol::rsk::{
    BlockHeadersResponse, BlockHeadersWithUnclesResponse, HeaderWithUncles,
};
use rustock_networking::{RskMessage, RskSubMessage};

/// Testnet #8,260,761 in full, as its block carries it (core's `V2_FULL`).
const FULL: &str = concat!(
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

/// Testnet #8,260,720 as rskj's peers sent it, compressed (core's
/// `V2_FROM_PEERS`).
const FROM_PEERS: &str = concat!(
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

/// Testnet's heights, installed for this process before anything reads
/// the process's.
fn testnet() -> &'static ActivationHeights {
    ActivationHeights::testnet().install();
    let heights = ActivationHeights::current();
    assert_eq!(
        heights.rskip351,
        ActivationHeights::testnet().rskip351,
        "testnet's heights"
    );
    heights
}

/// A header read as testnet's nodes read one in `form`.
fn read(hex: &str, form: HeaderForm) -> Header {
    let bytes = hex::decode(hex).unwrap();
    Header::decode_with_hash_in(&mut bytes.as_slice(), testnet(), form).unwrap()
}

/// `sub` sent and read back.
fn roundtrip(sub: RskSubMessage) -> RskSubMessage {
    testnet();
    let mut buf = Vec::new();
    RskMessage::new(sub).encode(&mut buf);
    RskMessage::decode(&mut buf.as_slice())
        .expect("decodes")
        .sub_message
}

/// A header without the hashes a decoder caches.
fn uncached(header: &Header) -> Header {
    Header {
        cached_hash: None,
        cached_hash_for_merged_mining: None,
        ..header.clone()
    }
}

/// **A chain's headers go to a peer compressed** (`BlockHeadersResponse`),
/// as rskj sends and reads them: one held in full arrives with only the
/// commitment to its extension, and the block's hash; one held compressed
/// arrives as held.
#[test]
fn a_chains_headers_go_to_a_peer_compressed() {
    let full = read(FULL, HeaderForm::Full);
    let peers = read(FROM_PEERS, HeaderForm::Compressed);
    let sent = BlockHeadersResponse {
        id: 7,
        headers: vec![full.clone(), peers.clone()],
    };
    let RskSubMessage::BlockHeadersResponse(got) =
        roundtrip(RskSubMessage::BlockHeadersResponse(sent))
    else {
        panic!("another message");
    };
    let [arrived, held] = got.headers.as_slice() else {
        panic!("two headers");
    };
    assert_eq!(arrived.hash(), full.hash());
    assert!(arrived.extension_data.is_some() && arrived.version_fields.is_none());
    assert_eq!(arrived.encode_compressed(), full.encode_compressed());
    let extension = full.extension().expect("a versioned header's own");
    assert_eq!(
        arrived.with_extension(&extension).map(|h| h.hash()),
        Some(full.hash())
    );
    assert_eq!(held, &peers);
}

/// **Trunk headers and their uncles go between rustock nodes as held**
/// (`BlockHeadersWithUnclesResponse`): each header in the store's form, so
/// a header held compressed arrives so, and a version-0 header from
/// RSKIP-351 on, whose full encoding rskj can't read back, arrives whole.
#[test]
fn headers_with_uncles_carry_each_header_as_held() {
    let full = read(FULL, HeaderForm::Full);
    let peers = read(FROM_PEERS, HeaderForm::Compressed);
    let v0 = Header {
        version_fields: Some(HeaderVersionFields {
            version: 0,
            ..full.version_fields.clone().expect("a versioned header")
        }),
        ..uncached(&full)
    };
    let entries: Vec<HeaderWithUncles> = [full, peers, v0]
        .into_iter()
        .map(|header| HeaderWithUncles {
            header,
            uncles: Vec::new(),
        })
        .collect();
    let sent = BlockHeadersWithUnclesResponse {
        id: 8,
        entries: entries.clone(),
    };
    let RskSubMessage::BlockHeadersWithUnclesResponse(got) =
        roundtrip(RskSubMessage::BlockHeadersWithUnclesResponse(sent))
    else {
        panic!("another message");
    };
    let held = |entries: &[HeaderWithUncles]| -> Vec<Header> {
        entries
            .iter()
            .map(|entry| uncached(&entry.header))
            .collect()
    };
    assert_eq!(held(&got.entries), held(&entries));
}
