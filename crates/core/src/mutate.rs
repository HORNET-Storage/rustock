//! Variations on real bytes, for showing that what decodes and checks
//! untrusted input answers each one with a value or an error, never a panic.
//!
//! Seeded from encodings the chain really holds, so the variations land
//! where a decoder does its work rather than failing at the first byte.

use crate::config::{ActivationHeights, ChainConfig};
use crate::types::header::Header;
use crate::types::header_extension::{BlockHeaderExtension, ExtensionCommitment};
use crate::validation::HeaderVerifier;
use std::sync::Arc;

/// A xorshift, so that a failure names the variation that caused it.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// From 0 up to, not including, `n`; 0 when `n` is.
    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Bytes the encodings treat apart: the edges of RLP's prefix ranges, and
/// Bitcoin's varint markers.
const EDGES: [u8; 14] = [
    0x00, 0x01, 0x7f, 0x80, 0x81, 0xb7, 0xb8, 0xbf, 0xc0, 0xf7, 0xf8, 0xfd, 0xfe, 0xff,
];

/// One edit: a bit flipped, a byte set to an edge or to anything, a byte
/// put in, bytes taken out, repeated elsewhere or run to 0xff, or the end
/// cut off.
fn edit(bytes: &mut Vec<u8>, rng: &mut Rng) {
    let len = bytes.len();
    if len == 0 {
        bytes.push(rng.next() as u8);
        return;
    }
    let at = rng.below(len);
    match rng.below(8) {
        0 => bytes[at] ^= 1 << rng.below(8),
        1 => bytes[at] = EDGES[rng.below(EDGES.len())],
        2 => bytes[at] = rng.next() as u8,
        3 => bytes.insert(rng.below(len + 1), EDGES[rng.below(EDGES.len())]),
        4 => {
            let n = 1 + rng.below(8.min(len - at));
            bytes.drain(at..at + n);
        }
        5 => bytes.truncate(at),
        6 => {
            let n = 1 + rng.below(16.min(len - at));
            let piece = bytes[at..at + n].to_vec();
            let to = rng.below(len + 1);
            bytes.splice(to..to, piece);
        }
        _ => {
            let n = (1 + rng.below(8)).min(len - at);
            bytes[at..at + n].fill(0xff);
        }
    }
}

/// `count` variations on `seed`, each of one to three edits.
pub(crate) fn mutants(seed: &[u8], count: usize, rng_seed: u64) -> Vec<Vec<u8>> {
    let mut rng = Rng::new(rng_seed);
    (0..count)
        .map(|_| {
            let mut bytes = seed.to_vec();
            for _ in 0..1 + rng.below(3) {
                edit(&mut bytes, &mut rng);
            }
            bytes
        })
        .collect()
}

/// What this crate does with a header's bytes a peer sends, done to `bytes`
/// under each network's heights and rules: decoded in each form, the hash
/// cached or not, hashed both ways, encoded every way, and checked by every
/// rule, a header's own, an uncle's and against a parent. Only that none of
/// it panics is checked.
pub(crate) fn decode_and_check_header(bytes: &[u8]) {
    use crate::types::header::HeaderForm;
    let networks = [
        (ActivationHeights::mainnet(), ChainConfig::mainnet()),
        (ActivationHeights::testnet(), ChainConfig::testnet()),
        (ActivationHeights::regtest(), ChainConfig::regtest()),
    ];
    for (activations, config) in networks {
        let verifier = HeaderVerifier::default_rsk(Arc::new(config));
        let decoded = [HeaderForm::Full, HeaderForm::Compressed, HeaderForm::Stored]
            .into_iter()
            .flat_map(|form| {
                [
                    Header::decode_with_hash_in(&mut &bytes[..], &activations, form),
                    Header::decode_in(&mut &bytes[..], &activations, form),
                ]
            });
        for header in decoded.flatten() {
            let _ = header.hash();
            let _ = header.hash_for_merged_mining();
            let _ = header.extension_commitment();
            let _ = header.extension();
            let _ = alloy_rlp::encode(&header);
            let _ = header.encode_compressed();
            let _ = header.encode_stored();
            let _ = verifier.verify(&header, None);
            let _ = verifier.verify_uncle(&header);
            let _ = verifier.verify_against_parent(&header, &header);
            for rule in verifier.uncle_parent_rules() {
                let _ = rule.validate_with_parent(&header, &header);
            }
            let _ = crate::validation::merged_mining::extract_fork_detection_data(&header);
        }
    }
    if let Ok(extension) = BlockHeaderExtension::from_encoded(bytes) {
        let _ = extension.hash();
        let _ = extension.encoded();
    }
    let _ = ExtensionCommitment::from_extension_data(bytes);
}
