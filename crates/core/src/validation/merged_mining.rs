use super::fork_detection::REQUIRED_BLOCKS;
use super::{HeaderValidator, ValidationError};
use crate::btc_block;
use crate::partial_merkle_tree::{self, PartialMerkleTree};
use crate::types::header::Header;
use crate::config::ChainConfig;

/// The marker a merged-mining coinbase carries, immediately followed by the
/// RSK block's merged-mining hash. rskj `RskMiningConstants.RSK_TAG`.
pub const RSK_TAG: &[u8] = b"RSKBLOCK:";
/// Length of the BouncyCastle SHA-256 encoded state with `xBuf`/`xBufOff`
/// (its first eight bytes) stripped: an 8-byte byte count plus H1..H8.
pub const MIDSTATE_SIZE_TRIMMED: usize = 40;
/// The merged-mining hash written after the tag is always 32 bytes, whether or
/// not its tail carries fork-detection data.
pub const BLOCK_HEADER_HASH_SIZE: usize = 32;
/// A coinbase may carry at most this much after the tag and hash.
pub const MAX_BYTES_AFTER_MERGED_MINING_HASH: usize = 128;
/// From wasabi100 on, only this much of the merged-mining hash is the hash
/// itself; the remaining 12 bytes are RSKIP110 fork-detection data.
pub const HASH_FOR_MERGED_MINING_PREFIX_LENGTH: usize = 20;
/// The tag must begin within the first SHA-256 block of the compressed tail,
/// which bounds how much of the coinbase a verifier has to be handed.
pub const MAX_RSK_TAG_POSITION_IN_TAIL: usize = 64;

/// rskj `Constants.getMaxBitcoinMergedMiningMerkleProofLength()` = 960 bytes
/// (30 SHA-256 hashes), enforced by `Rskip92MerkleProofValidator` from
/// RSKIP180 (iris300).
pub const MAX_MERGED_MINING_MERKLE_PROOF_LENGTH: usize = 960;

/// The length of a Bitcoin block header, and from RSKIP98 (orchid) the only
/// length rskj accepts for the field that carries one, block 0 excepted: rskj
/// `RskMiningConstants.BTC_HEADER_SIZE`, enforced by `BtcHeaderSizeRule`.
pub const BTC_HEADER_SIZE: usize = 80;

/// The length of a UMM root when a header has one: rskj
/// `BlockHeader.UMM_LEAVES_LENGTH`. Any other length but none makes rskj's
/// `getHashRootForMergedMining` throw, so the header has no merged-mining
/// hash and its proof of work cannot be checked.
pub const UMM_ROOT_LENGTH: usize = 20;

pub struct MergedMiningRule {
    pub config: std::sync::Arc<ChainConfig>,
}

/// rskj `BlockTimeStampValidationRule.isBitcoinTimestampValid` (RSKIP179,
/// iris300): the Bitcoin block a header was merged-mined in and the header
/// itself must be timestamped within `max_timestamps_diff` seconds of each
/// other, strictly. rskj's `Constants.getMaxTimestampsDiffInSecs`: 5 minutes,
/// or 2 hours on testnet and testnet2 from RSKIP297 (hop400) on.
///
/// From the activation on a header without a decodable merged-mining header
/// is invalid outright, as it is in rskj. The rule does not depend on
/// `skip_pow_validation`: rskj's `miner.server.skipPowValidation` reaches
/// `ProofOfWorkRule` only.
///
/// It is part of rskj's timestamp rule, and goes with it where the chain's
/// `max_future_block_time` is zero (regtest): rskj's `isValid` returns
/// before `isBitcoinTimestampValid` when `validPeriodLength` is zero.
pub struct BitcoinTimestampRule {
    pub config: std::sync::Arc<ChainConfig>,
}

impl BitcoinTimestampRule {
    /// rskj `Constants.DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS`.
    pub const DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS: u64 = 5 * 60;
    /// rskj `Constants.TESTNET_MAX_TIMESTAMPS_DIFF_IN_SECS`.
    pub const TESTNET_MAX_TIMESTAMPS_DIFF_IN_SECS: u64 = 120 * 60;
    /// rskj `Constants.getMaxTimestampsDiffInSecs` for a block at `number`.
    pub fn max_timestamps_diff(&self, number: u64) -> u64 {
        // rskj's TESTNET_CHAIN_ID and TESTNET2_CHAIN_ID.
        let testnet = matches!(self.config.chain_id, 31 | 34);
        if testnet && number >= self.config.activation_heights.hop400 {
            Self::TESTNET_MAX_TIMESTAMPS_DIFF_IN_SECS
        } else {
            Self::DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS
        }
    }
}

impl HeaderValidator for BitcoinTimestampRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        use bitcoin::block::Header as BtcHeader;
        use bitcoin::consensus::Decodable;

        if self.config.max_future_block_time == 0
            || header.number < self.config.activation_heights.iris300
        {
            return Ok(());
        }
        let btc_header_bytes = header
            .bitcoin_merged_mining_header
            .as_ref()
            .ok_or(ValidationError::BitcoinHeaderDecodeError)?;
        let mut reader = &btc_header_bytes[..];
        let btc_header: BtcHeader = Decodable::consensus_decode(&mut reader)
            .map_err(|_| ValidationError::BitcoinHeaderDecodeError)?;

        let btc = u64::from(btc_header.time);
        let rsk = header.timestamp;
        let max = self.max_timestamps_diff(header.number);
        if rsk.abs_diff(btc) >= max {
            return Err(ValidationError::BitcoinTimestampTooFar { rsk, btc, max });
        }
        Ok(())
    }
}

/// rskj `DifficultyUtils.difficultyToTarget`: 2^256 over the difficulty, or
/// over 3 where the difficulty is 2 or less, so that the target never needs
/// bit 255. A merge-mining Bitcoin header's hash, read as a number, must not
/// exceed it.
///
/// 2^256 is past a `U256`. floor(2^256 / d) is floor((2^256 - 1) / d) except
/// where d divides 2^256, a power of two, where it is one more.
pub fn difficulty_to_target(difficulty: alloy_primitives::U256) -> alloy_primitives::U256 {
    use alloy_primitives::U256;
    let divisor = difficulty.max(U256::from(3));
    let below = U256::MAX / divisor;
    if divisor.is_power_of_two() {
        below + U256::from(1)
    } else {
        below

    }
}

/// rskj `Constants.FALLBACKMINING_PUBKEY_0` and `_1`, uncompressed: the key
/// that signs a fallback-mined block at an even height, and the one at an
/// odd height.
pub const FALLBACK_MINING_PUBKEYS: [[u8; 65]; 2] = [
    hex_literal::hex!(
        "041e2b148c024770e19c4f31db2233cac791583df95b4d14a5e9fd4b38dc8254b3"
        "048f937f169446b19d2eca40db1dd93fab34c0cd8a310afd6e6211f9a89e4bca"
    ),
    hex_literal::hex!(
        "04b55031870df5de88bdb84f65bd1c6f8331c633e759caa5ac7cad3fa4f8a36791"
        "e995804bba1558ddcf330a67ff5bfa253fa1d8789735f97a97e849686527976e"
    ),
];

/// rskj `ProofOfWorkRule.isFallbackMiningPossibleAndBlockSigned`: below
/// RSKIP98 (orchid), a block with no coinbase and no Merkle proof, of no
/// greater difficulty than the network's fallback-mining difficulty,
/// answers for its proof of work with a signature in the Bitcoin-header
/// field instead. rskj reads an empty coinbase as none, and an empty proof
/// counts as none.
pub fn is_fallback_mined(header: &Header, config: &ChainConfig) -> bool {
    use alloy_primitives::Bytes;
    let none = |field: &Option<Bytes>| field.as_ref().is_none_or(|f| f.is_empty());
    header.number < config.activation_heights.orchid
        && none(&header.bitcoin_merged_mining_coinbase_transaction)
        && none(&header.bitcoin_merged_mining_merkle_proof)
        && header.difficulty <= config.fallback_mining_difficulty
}

/// rskj `ProofOfWorkRule.validFallbackBlockSignature`: the Bitcoin-header
/// field holds the RLP list `[v, r, s]`, a signature of the header's
/// merged-mining hash by `keys[0]` at an even height or `keys[1]` at an odd
/// one.
///
/// Read as rskj reads it: by its lenient RLP, with `r` and `s` exactly as
/// Java's `BigInteger.toByteArray` writes them, `v` from 27 to 30, `s` below
/// half the curve order, and the key recovered by libsecp256k1, which is
/// rskj's default `native` crypto library. Where rskj throws, as where it
/// answers false, the signature does not stand.
pub fn fallback_signature_is_valid(header: &Header, keys: &[[u8; 65]; 2]) -> bool {
    use alloy_primitives::U256;
    let key = &keys[(header.number % 2) as usize];
    let field = header
        .bitcoin_merged_mining_header
        .as_ref()
        .map_or(&[][..], |f| f.as_ref());
    let Ok(elements) = crate::rskj_rlp::decode2(field) else {
        return false;
    };
    let [signature] = elements.as_slice() else {
        return false;
    };
    let Ok(parts) = signature.elements() else {
        return false;
    };
    let [v, r, s] = parts.as_slice() else {
        return false;
    };
    let (Some(v), Some(r), Some(s)) = (v.data(), r.data(), s.data()) else {
        return false;
    };
    let &[v] = v else { return false };
    if r != java_unsigned(r) || s != java_unsigned(s) {
        return false;
    }
    // `getV` is a Java byte, negative from 0x80. From 31 the recovery id
    // passes 3, where rskj's `check` throws.
    let v = v as i8;
    if !(27..=30).contains(&v) {
        return false;
    }
    let (Some(r), Some(s)) = (magnitude(r), magnitude(s)) else {
        return false;
    };
    if s >= U256::from_be_bytes(secp256k1::constants::CURVE_ORDER) >> 1 {
        return false;
    }
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&r.to_be_bytes::<32>());
    compact[32..].copy_from_slice(&s.to_be_bytes::<32>());
    // `validateComponentsWithoutV` holds r and s to 1 through n - 1, as
    // libsecp256k1 does in parsing and recovering. The id is 0 to 3 here.
    let id = secp256k1::ecdsa::RecoveryId::from_u8_masked((v - 27) as u8);
    let Ok(signature) = secp256k1::ecdsa::RecoverableSignature::from_compact(&compact, id) else {
        return false;
    };
    let message = secp256k1::Message::from_digest(header.hash_for_merged_mining().0);
    crate::types::transaction::secp_context()
        .recover_ecdsa(message, &signature)
        .is_ok_and(|found| found.serialize_uncompressed() == *key)
}

/// `new BigInteger(1, bytes).toByteArray()`: the magnitude without leading
/// zeros, with one zero byte back in front where its high bit is set, which
/// also writes zero as a single zero byte.
fn java_unsigned(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let magnitude = &bytes[start..];
    match magnitude.first() {
        Some(b) if b & 0x80 == 0 => magnitude.to_vec(),
        _ => [&[0u8][..], magnitude].concat(),
    }
}

/// The unsigned number in `bytes`, if it fits 256 bits.
fn magnitude(bytes: &[u8]) -> Option<alloy_primitives::U256> {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    (bytes.len() - start <= 32).then(|| alloy_primitives::U256::from_be_slice(&bytes[start..]))
}

impl HeaderValidator for MergedMiningRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        use bitcoin::consensus::Decodable;
        use bitcoin::block::Header as BtcHeader;
        use bitcoin::hashes::Hash;
        use alloy_primitives::{B256, U256};

        // rskj `ProofOfWorkRule.isValid` asks first whether the block was
        // mined without Bitcoin, which RSKIP98 (orchid) ended.
        if is_fallback_mined(header, &self.config) {
            if fallback_signature_is_valid(header, &FALLBACK_MINING_PUBKEYS) {
                return Ok(());
            }
            return Err(ValidationError::FallbackMiningSignatureInvalid {
                number: header.number,
            });
        }
        // rskj `ProofOfWorkRule` with `miner.server.skipPowValidation`: the
        // whole rule passes, merkle proof and coinbase included.
        if self.config.skip_pow_validation {
            return Ok(());
        }
        // RSKIP92 and RSKIP98 arrive together, at orchid. Below them the
        // Bitcoin-header field may carry its block's transactions after the
        // header, and the merkle proof is a bitcoinj partial merkle tree.
        let orchid = header.number >= self.config.activation_heights.orchid;

        let btc_header_bytes = header.bitcoin_merged_mining_header.as_ref()
            .ok_or(ValidationError::BitcoinHeaderDecodeError)?;
        // rskj `BtcHeaderSizeRule`: from RSKIP98, exactly a Bitcoin header,
        // block 0 excepted. Otherwise any bytes bitcoinj makes a block of,
        // whose header is their first 80. The decoder below reads those 80 alone.
        let readable = if orchid && header.number != 0 {
            btc_header_bytes.len() == BTC_HEADER_SIZE
        } else {
            btc_block::bitcoinj_reads(btc_header_bytes)
        };
        if !readable {
            return Err(ValidationError::BitcoinHeaderDecodeError);
        }
        let mut reader = &btc_header_bytes[..];
        let btc_header: BtcHeader = Decodable::consensus_decode(&mut reader)
            .map_err(|_| ValidationError::BitcoinHeaderDecodeError)?;

        // 1. Bitcoin PoW vs RSK difficulty
        let target = difficulty_to_target(header.difficulty);
        let btc_hash = btc_header.block_hash();
        let btc_hash_u256 = U256::from_le_slice(btc_hash.as_byte_array());
        if btc_hash_u256 > target {
            return Err(ValidationError::BitcoinPowInvalid {
                hash: B256::from_slice(btc_hash.as_byte_array()),
                target,
            });
        }

        // 2. Validate compressed coinbase RSK tag
        let compressed = header.bitcoin_merged_mining_coinbase_transaction.as_ref()
            .ok_or(ValidationError::BitcoinCoinbaseDecodeError)?;

        if compressed.len() < MIDSTATE_SIZE_TRIMMED + 1 {
            return Err(ValidationError::BitcoinCoinbaseDecodeError);
        }

        let tail = &compressed[MIDSTATE_SIZE_TRIMMED..];

        // rskj `BlockHeader.getHashRootForMergedMining`: a UMM root is empty or
        // exactly 20 bytes, and any other length throws before there is a hash
        // to look for.
        if let Some(umm_root) = &header.umm_root {
            if !umm_root.is_empty() && umm_root.len() != UMM_ROOT_LENGTH {
                return Err(ValidationError::UmmRootInvalid { len: umm_root.len() });
            }
        }
        let rsk_hash = header.hash_for_merged_mining();

        // rskj `BlockFactory`: the merged-mining hash carries fork-detection
        // data from RSKIP110 (wasabi100) on, but never below block 449, where
        // there is not yet the chain to compute it from. Testnet and regtest
        // have RSKIP110 from genesis, so there it is the second bound that
        // decides: their first 449 blocks commit to the whole hash.
        let include_fork_detection = header.number >= self.config.activation_heights.wasabi100
            && header.number >= REQUIRED_BLOCKS;
        let expected_tag: Vec<u8> = if include_fork_detection {
            [RSK_TAG, &rsk_hash.as_slice()[..HASH_FOR_MERGED_MINING_PREFIX_LENGTH]].concat()
        } else {
            [RSK_TAG, rsk_hash.as_slice()].concat()
        };

        let rsk_tag_position = find_last_subsequence(tail, &expected_tag)
            .ok_or(ValidationError::BitcoinCoinbaseTagInvalid)?;

        if rsk_tag_position >= MAX_RSK_TAG_POSITION_IN_TAIL {
            return Err(ValidationError::BitcoinCoinbaseTagInvalid);
        }

        let last_tag = find_last_subsequence(tail, RSK_TAG)
            .ok_or(ValidationError::BitcoinCoinbaseTagInvalid)?;
        if rsk_tag_position != last_tag {
            return Err(ValidationError::BitcoinCoinbaseTagInvalid);
        }

        if tail.len() < rsk_tag_position + RSK_TAG.len() + BLOCK_HEADER_HASH_SIZE {
            return Err(ValidationError::BitcoinCoinbaseTagInvalid);
        }
        let remaining = tail.len() - rsk_tag_position - RSK_TAG.len() - BLOCK_HEADER_HASH_SIZE;
        if remaining > MAX_BYTES_AFTER_MERGED_MINING_HASH {
            return Err(ValidationError::BitcoinCoinbaseTagInvalid);
        }

        // rskj: the whole coinbase -- the bytes the midstate absorbed, a Java
        // `long` read from its first eight, and the tail -- must run past 64
        // bytes. 64 bytes is the shape of an inner node of the Bitcoin merkle
        // tree, which must not pass for a transaction.
        let absorbed = i64::from_be_bytes(compressed[..8].try_into().expect("eight bytes"));
        let length = (tail.len() as i64).wrapping_add(absorbed);
        if length <= 64 {
            return Err(ValidationError::CoinbaseTooShort { length });
        }

        // 3. Compute coinbase hash from SHA-256 midstate + tail, verify Merkle proof
        let coinbase_hash = compute_coinbase_hash(compressed);

        let merkle_proof_bytes = header.bitcoin_merged_mining_merkle_proof.as_ref()
            .ok_or(ValidationError::BitcoinMerkleProofDecodeError)?;
        if !orchid {
            return genesis_merkle_proof(merkle_proof_bytes, &btc_header, &coinbase_hash);
        }

        // RSKIP180 (iris300): rskj `Rskip92MerkleProofValidator` rejects a
        // merged-mining merkle proof longer than
        // `Constants.getMaxBitcoinMergedMiningMerkleProofLength()` (960 bytes,
        // i.e. 30 hashes) before the format check.
        if header.number >= self.config.activation_heights.iris300
            && merkle_proof_bytes.len() > MAX_MERGED_MINING_MERKLE_PROOF_LENGTH
        {
            return Err(ValidationError::MerkleProofTooLarge {
                max: MAX_MERGED_MINING_MERKLE_PROOF_LENGTH,
                got: merkle_proof_bytes.len(),
            });
        }

        if merkle_proof_bytes.len() % 32 != 0 {
            return Err(ValidationError::BitcoinMerkleProofDecodeError);
        }

        // rskj compares in bitcoinj's display order, reversed from the wire,
        // which is the order the computed root is in; the header holds its
        // root in wire order. Either order matching used to pass, so a proof
        // folding to the root's byte reversal did too.
        let mut computed_root = rskip92_merkle_root(&coinbase_hash, merkle_proof_bytes)
            .ok_or(ValidationError::MerkleNodesFormTransaction)?;
        computed_root.reverse();
        if computed_root != btc_header.merkle_root.to_byte_array() {
            return Err(ValidationError::BitcoinMerkleProofInvalid);
        }

        Ok(())
    }
}

/// rskj `GenesisMerkleProofValidator`, merged mining's proof below RSKIP92: a
/// bitcoinj partial merkle tree of exactly the size its counts declare, which
/// walks to the Bitcoin header's merkle root and matches the coinbase, both
/// compared in bitcoinj's display order.
fn genesis_merkle_proof(
    proof: &[u8],
    btc_header: &bitcoin::block::Header,
    coinbase_hash: &[u8; 32],
) -> Result<(), ValidationError> {
    use bitcoin::hashes::Hash;
    if !partial_merkle_tree::has_expected_size(proof) {
        return Err(ValidationError::BitcoinMerkleProofDecodeError);
    }
    let (matched, root) = PartialMerkleTree::parse(proof)
        .and_then(|tree| tree.txn_hashes_and_merkle_root())
        .map_err(ValidationError::PartialMerkleTreeInvalid)?;
    let mut header_root = btc_header.merkle_root.to_byte_array();
    header_root.reverse();
    if root != header_root || !matched.contains(coinbase_hash) {
        return Err(ValidationError::BitcoinMerkleProofInvalid);
    }
    Ok(())
}

/// The 12 fork-detection bytes a header commits to, read out of its
/// merged-mining coinbase.
///
/// rskj `BlockHeader.getMiningForkDetectionData`: locate
/// `RSK_TAG || hashForMergedMining[0..20]` in the coinbase and take the 12
/// bytes that follow. Returns `None` when the tag is absent or the coinbase is
/// too short — rskj throws `IllegalStateException` in both cases.
pub fn extract_fork_detection_data(header: &Header) -> Option<[u8; 12]> {
    let compressed = header.bitcoin_merged_mining_coinbase_transaction.as_ref()?;
    if compressed.len() < MIDSTATE_SIZE_TRIMMED + 1 {
        return None;
    }
    let tail = &compressed[MIDSTATE_SIZE_TRIMMED..];
    let rsk_hash = header.hash_for_merged_mining();
    let prefix: Vec<u8> = [
        RSK_TAG,
        &rsk_hash.as_slice()[..HASH_FOR_MERGED_MINING_PREFIX_LENGTH],
    ]
    .concat();
    let position = find_last_subsequence(tail, &prefix)?;
    let from = position + prefix.len();
    let to = from + FORK_DETECTION_DATA_LENGTH;
    if tail.len() < to {
        return None;
    }
    let mut out = [0u8; FORK_DETECTION_DATA_LENGTH];
    out.copy_from_slice(&tail[from..to]);
    Some(out)
}

/// rskj `BlockHeader.FORK_DETECTION_DATA_LENGTH`.
pub const FORK_DETECTION_DATA_LENGTH: usize = 12;

pub fn find_last_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len())
        .rposition(|w| w == needle)
}

/// Computes the coinbase transaction hash from the compressed coinbase.
///
/// The compressed format is: [trimmed_midstate (40 bytes)] [tail (variable)].
/// The trimmed midstate contains bytes 8-47 of BouncyCastle's SHA256Digest
/// encoded state (xBuf and xBufOff at bytes 0-7 are stripped):
///   trimmed[0..8]   = byteCount (big-endian u64, bytes already hashed)
///   trimmed[8..12]  = H1 (big-endian u32)
///   trimmed[12..16] = H2 (big-endian u32)
///   trimmed[16..20] = H3 (big-endian u32)
///   trimmed[20..24] = H4 (big-endian u32)
///   trimmed[24..28] = H5 (big-endian u32)
///   trimmed[28..32] = H6 (big-endian u32)
///   trimmed[32..36] = H7 (big-endian u32)
///   trimmed[36..40] = H8 (big-endian u32)
pub fn compute_coinbase_hash(compressed: &[u8]) -> [u8; 32] {
    let trimmed = &compressed[..MIDSTATE_SIZE_TRIMMED];
    let tail = &compressed[MIDSTATE_SIZE_TRIMMED..];

    let byte_count = u64::from_be_bytes(trimmed[0..8].try_into().unwrap());

    let state: [u32; 8] = [
        u32::from_be_bytes(trimmed[8..12].try_into().unwrap()),
        u32::from_be_bytes(trimmed[12..16].try_into().unwrap()),
        u32::from_be_bytes(trimmed[16..20].try_into().unwrap()),
        u32::from_be_bytes(trimmed[20..24].try_into().unwrap()),
        u32::from_be_bytes(trimmed[24..28].try_into().unwrap()),
        u32::from_be_bytes(trimmed[28..32].try_into().unwrap()),
        u32::from_be_bytes(trimmed[32..36].try_into().unwrap()),
        u32::from_be_bytes(trimmed[36..40].try_into().unwrap()),
    ];

    let one_round = sha256_from_midstate(state, byte_count, tail);

    use sha2::{Sha256, Digest};
    let second_round = Sha256::digest(one_round);

    let mut result = [0u8; 32];
    result.copy_from_slice(&second_round);
    // Reverse to match rskj's Sha256Hash.wrapReversed convention
    result.reverse();
    result
}

/// Why a coinbase cannot be compressed: the constraints
/// [`MergedMiningRule`] enforces, stated from the producing side.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoinbaseCompressionError {
    #[error("coinbase carries no {} tag", String::from_utf8_lossy(RSK_TAG))]
    TagNotFound,
    /// The tag has to land in the first SHA-256 block of whatever is left
    /// unhashed, and compression absorbs whole 64-byte blocks only -- so this
    /// cannot actually happen, and a failure here means the arithmetic below
    /// stopped agreeing with the verifier's.
    #[error("tag at offset {offset} in the tail, must be below {max}")]
    TagTooDeepInTail { offset: usize, max: usize },
    #[error("tag and hash are truncated: {available} bytes follow the tag, need {needed}")]
    HashTruncated { available: usize, needed: usize },
    #[error("{trailing} bytes follow the merged-mining hash, at most {max} allowed")]
    TooMuchTrailingData { trailing: usize, max: usize },
}

/// The inverse of [`compute_coinbase_hash`]: turn a whole Bitcoin coinbase
/// transaction into the compressed form an RSK header carries.
///
/// rskj `MinerServerImpl.compressCoinbase`. Whole 64-byte blocks up to the
/// last boundary at or before the tag are absorbed into a SHA-256 midstate and
/// dropped; everything from that boundary on is kept verbatim as the tail. A
/// verifier resumes from the midstate, so it never has to see the bytes that
/// were dropped -- which is the point, since a coinbase can be large and every
/// RSK header would otherwise have to carry all of it.
///
/// `last_occurrence` picks which `RSKBLOCK:` tag to compress around when a
/// coinbase carries several (a miner merge-mining more than one RSK fork).
/// The verifier insists the tag it matched is the last one in the tail, so
/// production uses `true`; `false` exists to build the coinbase a
/// two-tag rejection test needs.
pub fn compress_coinbase(
    coinbase: &[u8],
    last_occurrence: bool,
) -> Result<Vec<u8>, CoinbaseCompressionError> {
    let tag_position = if last_occurrence {
        find_last_subsequence(coinbase, RSK_TAG)
    } else {
        find_first_subsequence(coinbase, RSK_TAG)
    }
    .ok_or(CoinbaseCompressionError::TagNotFound)?;

    let after_tag = tag_position + RSK_TAG.len();
    let available = coinbase.len().saturating_sub(after_tag);
    if available < BLOCK_HEADER_HASH_SIZE {
        return Err(CoinbaseCompressionError::HashTruncated {
            available,
            needed: BLOCK_HEADER_HASH_SIZE,
        });
    }
    let trailing = available - BLOCK_HEADER_HASH_SIZE;
    if trailing > MAX_BYTES_AFTER_MERGED_MINING_HASH {
        return Err(CoinbaseCompressionError::TooMuchTrailingData {
            trailing,
            max: MAX_BYTES_AFTER_MERGED_MINING_HASH,
        });
    }

    // Absorb up to the last 64-byte boundary at or before the tag, so the tag
    // itself always survives into the tail.
    let bytes_to_hash = (tag_position / 64) * 64;
    let tail_tag_position = tag_position - bytes_to_hash;
    if tail_tag_position >= MAX_RSK_TAG_POSITION_IN_TAIL {
        return Err(CoinbaseCompressionError::TagTooDeepInTail {
            offset: tail_tag_position,
            max: MAX_RSK_TAG_POSITION_IN_TAIL,
        });
    }

    let mut state = SHA256_INITIAL_STATE;
    for chunk in coinbase[..bytes_to_hash].chunks_exact(64) {
        sha256_compress(&mut state, chunk.try_into().unwrap());
    }

    let mut out = Vec::with_capacity(MIDSTATE_SIZE_TRIMMED + coinbase.len() - bytes_to_hash);
    out.extend_from_slice(&(bytes_to_hash as u64).to_be_bytes());
    for word in state {
        out.extend_from_slice(&word.to_be_bytes());
    }
    debug_assert_eq!(out.len(), MIDSTATE_SIZE_TRIMMED);
    out.extend_from_slice(&coinbase[bytes_to_hash..]);
    Ok(out)
}

/// The SHA-256 IV, the state a digest starts from before absorbing anything.
pub const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn find_first_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Completes a SHA-256 hash from a midstate, as BouncyCastle's `SHA256Digest`
/// does when rskj restores one.
///
/// Restoring a state starts BouncyCastle's word and block offsets at zero,
/// so the tail is absorbed from a block boundary whatever the byte count
/// says; the count only feeds the length in the padding, which is the count
/// plus the tail's length, times eight, in a Java `long`. For a coinbase
/// compressed honestly the count is whole blocks and none of this shows. A
/// count that is not is the miner's to write, and rskj hashes it this way,
/// so it is hashed this way here too: laying the padding out from the count
/// instead left the length block short, and `chunks_exact` dropped it.
pub fn sha256_from_midstate(state: [u32; 8], byte_count: u64, tail: &[u8]) -> [u8; 32] {
    let mut h = state;
    let total_bits = byte_count.wrapping_add(tail.len() as u64).wrapping_mul(8);

    let mut padded = tail.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&total_bits.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let block: &[u8; 64] = chunk.try_into().unwrap();
        sha256_compress(&mut h, block);
    }

    let mut output = [0u8; 32];
    for (i, &w) in h.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    output
}

/// RSKIP92 Merkle proof: the proof is a flat sequence of 32-byte sibling
/// hashes. Starting from the coinbase hash, combine left-to-right with each
/// sibling using Bitcoin's double-SHA256 Merkle tree construction, matching
/// rskj's `combineLeftRight`.
///
/// `None` when two nodes it would combine parse as a 64-byte Bitcoin
/// transaction, where rskj's `combineLeftRight` throws instead.
pub fn rskip92_merkle_root(coinbase_hash: &[u8; 32], proof_bytes: &[u8]) -> Option<[u8; 32]> {
    let mut current = *coinbase_hash;

    for chunk in proof_bytes.chunks_exact(32) {
        let sibling: [u8; 32] = chunk.try_into().unwrap();
        if parses_as_a_64_byte_transaction(&current, &sibling) {
            return None;
        }
        current = combine_left_right(&current, &sibling);
    }

    Some(current)
}

/// The most a single output can carry, in satoshis: 21 million bitcoin.
const MAX_SATOSHIS: i64 = 21_000_000 * 100_000_000;

/// rskj `MerkleTreeUtils.checkNotAValid64ByteTransaction`, its guard against
/// the leaf-node weakness of Bitcoin's merkle tree: an inner node is the hash
/// of 64 bytes, and 64 bytes that also parse as a transaction would let a
/// proof stop at a node and present it as a leaf.
///
/// True when `left || right` passes every test rskj applies -- one input, an
/// output index of at most a million or the coinbase's `0xffffffff`, one
/// output worth between one satoshi and 21 million bitcoin, and scripts of
/// four bytes between them -- which is when rskj throws. It reads the nodes
/// in the order it holds them, display order, the reverse of the bytes the
/// tree hashes. That is rskj's rule, so it is this one.
pub fn parses_as_a_64_byte_transaction(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut tx = [0u8; 64];
    tx[..32].copy_from_slice(left);
    tx[32..].copy_from_slice(right);

    // Four bytes of version, then the input count.
    if tx[4] != 1 {
        return false;
    }
    // The outpoint's 32-byte hash, then its index: an unsigned little-endian
    // 32-bit integer.
    let output_index = u32::from_le_bytes(tx[37..41].try_into().unwrap());
    if output_index > 1_000_000 && output_index != u32::MAX {
        return false;
    }
    // A Java byte: from 0x80 it is negative, refused with the rest over four.
    let input_script_length = tx[41];
    if input_script_length > 4 {
        return false;
    }
    // The script, four bytes of sequence, then the output count.
    let mut at = 42 + usize::from(input_script_length) + 4;
    if tx[at] != 1 {
        return false;
    }
    at += 1;
    let value = i64::from_le_bytes(tx[at..at + 8].try_into().unwrap());
    if !(1..=MAX_SATOSHIS).contains(&value) {
        return false;
    }
    at += 8;
    let output_script_length = tx[at];
    if output_script_length > 4 {
        return false;
    }
    input_script_length + output_script_length == 4
}

/// Matches rskj's MerkleTreeUtils.combineLeftRight:
///   reverseBytes(left) || reverseBytes(right) → SHA256d → wrapReversed
pub fn combine_left_right(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut left_rev = *left;
    let mut right_rev = *right;
    left_rev.reverse();
    right_rev.reverse();

    let mut hasher = Sha256::new();
    hasher.update(left_rev);
    hasher.update(right_rev);
    let first = hasher.finalize();

    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result.reverse();
    result
}

// ── SHA-256 compression function ──────────────────────────────────────

#[rustfmt::skip]
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    /// A coinbase-shaped buffer with the tag at a chosen offset.
    fn coinbase_with_tag_at(tag_offset: usize, trailing: usize) -> Vec<u8> {
        let mut out = vec![0xABu8; tag_offset];
        out.extend_from_slice(RSK_TAG);
        out.extend_from_slice(&[0xCD; BLOCK_HEADER_HASH_SIZE]);
        out.extend(std::iter::repeat_n(0xEF, trailing));
        out
    }

    fn double_sha256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
        // The verifier works in display order throughout.
        out.reverse();
        out
    }

    /// The single most error-prone piece: compression has to be the exact
    /// inverse of the hash the verifier computes, for every alignment of the
    /// tag against the 64-byte block boundary the midstate is taken at.
    #[test]
    fn compression_inverts_the_verifier() {
        for tag_offset in [0, 1, 63, 64, 65, 127, 128, 129, 200, 511, 512] {
            for trailing in [0, 1, 128] {
                let coinbase = coinbase_with_tag_at(tag_offset, trailing);
                let compressed = compress_coinbase(&coinbase, true)
                    .unwrap_or_else(|e| panic!("offset {tag_offset}, trailing {trailing}: {e}"));

                assert_eq!(
                    compute_coinbase_hash(&compressed),
                    double_sha256(&coinbase),
                    "offset {tag_offset}, trailing {trailing}"
                );
            }
        }
    }

    /// Compression drops whole 64-byte blocks and no more, so the tag always
    /// survives into the tail and always lands within its first block --
    /// which is exactly the bound the verifier enforces.
    #[test]
    fn compression_leaves_the_tag_inside_the_first_tail_block() {
        for tag_offset in [0, 63, 64, 65, 1000] {
            let coinbase = coinbase_with_tag_at(tag_offset, 0);
            let compressed = compress_coinbase(&coinbase, true).unwrap();
            let tail = &compressed[MIDSTATE_SIZE_TRIMMED..];
            let position = find_last_subsequence(tail, RSK_TAG).expect("tag survives");
            assert!(
                position < MAX_RSK_TAG_POSITION_IN_TAIL,
                "offset {tag_offset} put the tag at tail position {position}"
            );
            assert_eq!(position, tag_offset % 64);
        }
    }

    #[test]
    fn compression_rejects_a_coinbase_without_a_tag() {
        assert_eq!(
            compress_coinbase(&[0u8; 100], true),
            Err(CoinbaseCompressionError::TagNotFound)
        );
    }

    #[test]
    fn compression_rejects_a_truncated_hash() {
        let mut coinbase = vec![0xAB; 10];
        coinbase.extend_from_slice(RSK_TAG);
        coinbase.extend_from_slice(&[0xCD; 31]);
        assert_eq!(
            compress_coinbase(&coinbase, true),
            Err(CoinbaseCompressionError::HashTruncated { available: 31, needed: 32 })
        );
    }

    /// The verifier allows at most 128 bytes after the hash; the compressor
    /// refuses to build what would be rejected rather than emitting it and
    /// letting the failure surface as an invalid block.
    #[test]
    fn compression_rejects_too_much_trailing_data() {
        assert!(compress_coinbase(&coinbase_with_tag_at(10, 128), true).is_ok());
        assert_eq!(
            compress_coinbase(&coinbase_with_tag_at(10, 129), true),
            Err(CoinbaseCompressionError::TooMuchTrailingData { trailing: 129, max: 128 })
        );
    }

    /// With two tags the verifier matches the last one, so that is the one
    /// compression must keep in range -- and choosing the first, which a
    /// miner merge-mining two forks might, produces a coinbase this node
    /// would reject.
    #[test]
    fn compression_picks_the_requested_tag_of_two() {
        let mut coinbase = vec![0xAB; 8];
        coinbase.extend_from_slice(RSK_TAG);
        coinbase.extend_from_slice(&[0x11; BLOCK_HEADER_HASH_SIZE]);
        let second_tag_offset = coinbase.len();
        coinbase.extend_from_slice(RSK_TAG);
        coinbase.extend_from_slice(&[0x22; BLOCK_HEADER_HASH_SIZE]);

        let last = compress_coinbase(&coinbase, true).unwrap();
        let last_tail = &last[MIDSTATE_SIZE_TRIMMED..];
        let last_position = find_last_subsequence(last_tail, RSK_TAG).unwrap();
        assert_eq!(
            &last_tail[last_position + RSK_TAG.len()..last_position + RSK_TAG.len() + 32],
            &[0x22; 32]
        );

        let first = compress_coinbase(&coinbase, false).unwrap();
        // Both tags are inside the first block here, so choosing the first one
        // changes only the byte count, not which bytes survive.
        // `(8 / 64) * 64` is the same round-down-to-a-64-byte-block formula as
        // the assertion below, with the first tag's offset of 8 substituted. It
        // is zero because that tag sits inside the first block -- written out
        // rather than as `0` so both assertions read as the same rule.
        // Bound to a local because the attribute does not reach inside the
        // `assert_eq!` expansion.
        #[allow(clippy::erasing_op)]
        let first_tag_block_start: u64 = (8 / 64) * 64;
        assert_eq!(
            u64::from_be_bytes(first[0..8].try_into().unwrap()),
            first_tag_block_start
        );
        assert_eq!(
            u64::from_be_bytes(last[0..8].try_into().unwrap()),
            (second_tag_offset as u64 / 64) * 64
        );
        // Whichever tag was chosen, the coinbase still hashes to the same thing.
        assert_eq!(compute_coinbase_hash(&first), compute_coinbase_hash(&last));
    }

    /// The midstate the compressor exports is BouncyCastle's encoded state
    /// with its first eight bytes stripped, which is only well defined because
    /// compression stops on a block boundary: `xBuf` is empty, so the bytes
    /// that were stripped held nothing.
    #[test]
    fn exported_midstate_starts_at_a_block_boundary() {
        let coinbase = coinbase_with_tag_at(200, 0);
        let compressed = compress_coinbase(&coinbase, true).unwrap();
        let byte_count = u64::from_be_bytes(compressed[0..8].try_into().unwrap());
        assert_eq!(byte_count % 64, 0);
        assert_eq!(byte_count, 192);
        assert_eq!(&compressed[MIDSTATE_SIZE_TRIMMED..], &coinbase[192..]);
    }

    #[test]
    fn sha256_compress_produces_correct_hash() {
        let input = b"hello world";
        let expected = Sha256::digest(input);

        let state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        let result = sha256_from_midstate(state, 0, input);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn sha256_midstate_continuation() {
        let data = [0x42u8; 128]; // 2 full blocks
        let expected = Sha256::digest(data);

        // Process first block normally to get midstate
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        let block: &[u8; 64] = data[..64].try_into().unwrap();
        sha256_compress(&mut state, block);

        // Complete from midstate with second block
        let result = sha256_from_midstate(state, 64, &data[64..]);
        assert_eq!(&result[..], &expected[..]);
    }
}
