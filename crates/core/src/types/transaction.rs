use alloy_primitives::{Address, B256, U256, Bytes};
use alloy_rlp::{Decodable, Encodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::rlp_compat::{decode_u64_lenient, decode_u256_lenient};

#[derive(Clone, Debug, Serialize, Deserialize, RlpEncodable)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: Bytes,
    pub value: U256,
    pub input: Bytes,
    pub v: u64,
    pub r: U256,
    pub s: U256,

    /// Original RLP bytes received from the peer. Java's RLP encoding differs
    /// from Rust's canonical encoding (leading-zero BigIntegers), so we cache
    /// the original bytes and use them for transactions_root computation.
    #[serde(skip)]
    #[rlp(skip)]
    pub cached_rlp: Option<Vec<u8>>,
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.gas_price == other.gas_price
            && self.gas_limit == other.gas_limit
            && self.to == other.to
            && self.value == other.value
            && self.input == other.input
            && self.v == other.v
            && self.r == other.r
            && self.s == other.s
    }
}

impl Eq for Transaction {}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        }
    }
}

impl Decodable for Transaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let original = *buf;
        let h = alloy_rlp::Header::decode(buf)?;
        if !h.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut body = &buf[..h.payload_length];
        *buf = &buf[h.payload_length..];

        let consumed = original.len() - buf.len();
        let cached = original[..consumed].to_vec();

        Ok(Self {
            nonce: decode_u64_lenient(&mut body)?,
            gas_price: decode_u256_lenient(&mut body)?,
            gas_limit: decode_u256_lenient(&mut body)?,
            to: Bytes::decode(&mut body)?,
            value: decode_u256_lenient(&mut body)?,
            input: Bytes::decode(&mut body)?,
            v: decode_u64_lenient(&mut body)?,
            r: decode_u256_lenient(&mut body)?,
            s: decode_u256_lenient(&mut body)?,
            cached_rlp: Some(cached),
        })
    }
}

impl Transaction {
    /// Returns the RLP encoding to use for trie root computation.
    /// Prefers the original bytes (from peer) to match Java's encoding;
    /// falls back to re-encoding if no cached bytes are available.
    pub fn rlp_for_trie(&self) -> Vec<u8> {
        if let Some(ref cached) = self.cached_rlp {
            return cached.clone();
        }
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl Transaction {
    /// Compute the signing hash for this transaction, dispatching based on `v`.
    ///
    /// EIP-155 transactions include `[chainId, 0, 0]` in the RLP; legacy ones do not.
    pub fn signing_hash(&self, chain_id: u64) -> B256 {
        if let Some(hash) = self.signing_hash_from_cached(chain_id) {
            return hash;
        }
        if self.is_eip155(chain_id) {
            self.signing_hash_eip155(chain_id)
        } else {
            self.signing_hash_legacy()
        }
    }

    /// Signing hash built from the ORIGINAL (network) encoding. rskj signs
    /// over the raw decoded byte arrays (Transaction.getEncodedRaw), which
    /// may use non-canonical zero encodings — e.g. a literal 0x00 byte for a
    /// zero gasLimit. Re-encoding the parsed fields canonically changes the
    /// hash and recovers the wrong sender, so the first six item encodings
    /// are reused verbatim.
    fn signing_hash_from_cached(&self, chain_id: u64) -> Option<B256> {
        let cached = self.cached_rlp.as_ref()?;
        let mut buf = cached.as_slice();
        let header = alloy_rlp::Header::decode(&mut buf).ok()?;
        if !header.list || buf.len() < header.payload_length {
            return None;
        }
        let mut rest = &buf[..header.payload_length];
        let mut inner = Vec::with_capacity(header.payload_length + 8);
        for _ in 0..6 {
            let item = take_rlp_item(&mut rest)?;
            inner.extend_from_slice(item);
        }
        if self.is_eip155(chain_id) {
            chain_id.encode(&mut inner);
            0u8.encode(&mut inner);
            0u8.encode(&mut inner);
        }
        Some(Self::rlp_wrap_and_hash(&inner))
    }

    /// EIP-155 signing hash: `keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))`.
    pub fn signing_hash_eip155(&self, chain_id: u64) -> B256 {
        let mut inner = Vec::with_capacity(256);
        self.nonce.encode(&mut inner);
        self.gas_price.encode(&mut inner);
        self.gas_limit.encode(&mut inner);
        self.to.encode(&mut inner);
        self.value.encode(&mut inner);
        self.input.encode(&mut inner);
        chain_id.encode(&mut inner);
        0u8.encode(&mut inner);
        0u8.encode(&mut inner);

        Self::rlp_wrap_and_hash(&inner)
    }

    /// Legacy (pre-EIP-155) signing hash: `keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data]))`.
    pub fn signing_hash_legacy(&self) -> B256 {
        let mut inner = Vec::with_capacity(256);
        self.nonce.encode(&mut inner);
        self.gas_price.encode(&mut inner);
        self.gas_limit.encode(&mut inner);
        self.to.encode(&mut inner);
        self.value.encode(&mut inner);
        self.input.encode(&mut inner);

        Self::rlp_wrap_and_hash(&inner)
    }

    fn rlp_wrap_and_hash(inner: &[u8]) -> B256 {
        let mut buf = Vec::with_capacity(inner.len() + 5);
        alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut buf);
        buf.extend_from_slice(inner);
        B256::from_slice(&Keccak256::digest(&buf))
    }
}

/// Advance past one RLP item, returning its full encoding (header + payload).
fn take_rlp_item<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let start = *buf;
    let mut peek = *buf;
    let header = alloy_rlp::Header::decode(&mut peek).ok()?;
    let total = (start.len() - peek.len()) + header.payload_length;
    if start.len() < total {
        return None;
    }
    let (item, rest) = start.split_at(total);
    *buf = rest;
    Some(item)
}

/// The verification context libsecp256k1 wants, built once per process.
///
/// Creating one fills in precomputed multiplication tables, which costs far
/// more than a recovery does -- so a per-call context would spend the whole
/// advantage of using this library and then some. Verification-only because
/// nothing here signs: the signing half of the tables is not built.
pub(crate) fn secp_context() -> &'static secp256k1::Secp256k1<secp256k1::VerifyOnly> {
    static CTX: std::sync::OnceLock<secp256k1::Secp256k1<secp256k1::VerifyOnly>> =
        std::sync::OnceLock::new();
    CTX.get_or_init(secp256k1::Secp256k1::verification_only)
}

/// The sender rskj gives a transaction whose signature recovers the point at
/// infinity rather than a key: the last 20 bytes of keccak256 of nothing.
///
/// libsecp256k1 refuses such a signature, and rskj takes it. Bouncy Castle
/// encodes the point at infinity as the one byte `00`, and rskj's native
/// service, its default, answers that same byte when libsecp256k1 refuses a
/// key that would have been the point at infinity
/// (`Secp256k1ServiceNative.recoverFromSignature`). `ECKey.getAddress` then
/// hashes the encoding past its first byte, which is nothing. Testnet holds
/// such transactions: the first in #8,269,754 is one, from an account that
/// had sent ten before it.
pub const INFINITY_SENDER: Address =
    alloy_primitives::address!("dcc703c0e500b653ca82273b7bfad8045d85a470");

/// The key a transaction's signature recovers, as rskj recovers it.
enum Recovered {
    /// A point on the curve.
    Key(secp256k1::PublicKey),
    /// The point at infinity, whose encoding to rskj, compressed or not, is
    /// the one byte `00`: see [`INFINITY_SENDER`].
    Infinity,
}

/// Whether a signature whose key libsecp256k1 refused to recover would have
/// recovered the point at infinity, which is what rskj's native service asks
/// when its recovery fails (`NativeSecp256k1.isInfinity`).
///
/// The key is r⁻¹(sR − eG), where R is the point whose x is r and whose y has
/// the parity of the recovery ID, and e is the signing hash modulo the
/// curve's order: it's the point at infinity just when R exists and sR = eG.
/// `from_compact` has already held r and s below the order; rskj refuses
/// either at zero before it recovers anything
/// (`ECDSASignature.validateComponentsWithoutV`), and so does this.
fn recovers_infinity(signature: &[u8; 64], recovery_id: u8, hash: &[u8; 32]) -> bool {
    let (r, s) = signature.split_at(32);
    if r.iter().all(|byte| *byte == 0) || s.iter().all(|byte| *byte == 0) {
        return false;
    }
    let mut point = [0_u8; 33];
    point[0] = 0x02 | recovery_id;
    point[1..].copy_from_slice(r);
    let Ok(point) = secp256k1::PublicKey::from_byte_array_compressed(point) else {
        return false;
    };
    let order = U256::from_be_bytes(secp256k1::constants::CURVE_ORDER);
    let e = U256::from_be_bytes(*hash);
    let e = if e >= order { e - order } else { e };
    // eG at e = 0 is no point, and sR always is one.
    if e.is_zero() {
        return false;
    }
    // The generator, whose y is even.
    let mut generator = [0x02_u8; 33];
    generator[1..].copy_from_slice(&secp256k1::constants::GENERATOR_X);
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(s);
    let (Ok(generator), Ok(s), Ok(e)) = (
        secp256k1::PublicKey::from_byte_array_compressed(generator),
        secp256k1::Scalar::from_be_bytes(s_bytes),
        secp256k1::Scalar::from_be_bytes(e.to_be_bytes::<32>()),
    ) else {
        return false;
    };
    match (
        point.mul_tweak(secp_context(), &s),
        generator.mul_tweak(secp_context(), &e),
    ) {
        (Ok(sr), Ok(eg)) => sr == eg,
        _ => false,
    }
}

impl Transaction {

    /// Recover the sender address from the transaction signature.
    ///
    /// RSK chain IDs: mainnet=30, testnet=31, regtest=33.
    ///
    /// Through libsecp256k1 rather than the pure-Rust `k256`, which is
    /// 4.3x slower at exactly this: 248 us against 59 us, medians of five
    /// rounds over three hundred real mainnet transactions, both backends
    /// agreeing on every address. A node pays this once per transaction,
    /// so at a full block it was the single largest cost outside execution
    /// -- 50 ms of a 205 ms block. See `cargo run --release --example
    /// validation_cost` and `docs/execution-performance.md`.
    ///
    /// A signature that recovers the point at infinity has the sender rskj
    /// gives it, [`INFINITY_SENDER`].
    pub fn recover_sender(&self, chain_id: u64) -> anyhow::Result<Address> {
        Ok(match self.recover_key(chain_id)? {
            // The leading byte is the uncompressed-form marker and is not part
            // of the key the address is taken from.
            Recovered::Key(key) => {
                let pubkey_hash = Keccak256::digest(&key.serialize_uncompressed()[1..]);
                Address::from_slice(&pubkey_hash[12..])
            }
            Recovered::Infinity => INFINITY_SENDER,
        })
    }

    /// The key this transaction's signature recovers, as rskj recovers it.
    /// `recover_sender` and `btc_sender_hash160` both take it from here, so
    /// they cannot drift apart on what a signature means.
    fn recover_key(&self, chain_id: u64) -> anyhow::Result<Recovered> {
        let hash = self.signing_hash(chain_id);

        let recovery_id = if self.is_eip155(chain_id) {
            // `is_eip155` holds `v` at `chain_id * 2 + 35` or more, so this is
            // the id, or past 1. Unsigned: in an `i64`, a `v` of 2^63 or more
            // went negative, and the subtraction overflowed.
            let rid = self.v - (chain_id * 2 + 35);
            if rid > 1 {
                anyhow::bail!("invalid EIP-155 v value: {} for chain_id {}", self.v, chain_id);
            }
            rid as u8
        } else {
            if self.v != 27 && self.v != 28 {
                anyhow::bail!("invalid legacy v value: {}", self.v);
            }
            (self.v - 27) as u8
        };

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig_bytes[32..].copy_from_slice(&self.s.to_be_bytes::<32>());

        // `from_u8_masked` takes the low two bits rather than rejecting an
        // out-of-range id, which is safe only because the branches above
        // have already confined `recovery_id` to 0 or 1.
        let recid = secp256k1::ecdsa::RecoveryId::from_u8_masked(recovery_id);
        let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes, recid)
            .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;
        let message = secp256k1::Message::from_digest(hash.0);

        match secp_context().recover_ecdsa(message, &signature) {
            Ok(key) => Ok(Recovered::Key(key)),
            Err(_) if recovers_infinity(&sig_bytes, recovery_id, &hash.0) => {
                Ok(Recovered::Infinity)
            }
            Err(e) => Err(anyhow::anyhow!("ECDSA recovery failed: {e}")),
        }
    }

    pub fn is_eip155(&self, chain_id: u64) -> bool {
        self.v != 27 && self.v != 28 && self.v >= chain_id * 2 + 35
    }

    /// Recover the compressed (33-byte) secp256k1 public key from the transaction signature.
    ///
    /// Returns `None` if the signature is invalid or missing, or recovers the
    /// point at infinity, which has no such encoding: `btc_sender_hash160`
    /// hashes rskj's one byte for it instead.
    pub fn recover_compressed_pubkey(&self, chain_id: u64) -> Option<[u8; 33]> {
        match self.recover_key(chain_id).ok()? {
            Recovered::Key(key) => Some(key.serialize()),
            Recovered::Infinity => None,
        }
    }

    /// Compute the Keccak256 hash of this transaction's RLP bytes.
    /// This is the standard Ethereum/RSK transaction hash.
    pub fn tx_hash(&self) -> B256 {
        let rlp = self.rlp_for_trie();
        B256::from_slice(&Keccak256::digest(&rlp))
    }

    /// Derive the BTC P2PKH destination hash160 for this transaction's sender.
    ///
    /// Matches rskj's `BridgeUtils.recoverBtcAddressFromEthTransaction`:
    /// recovers the compressed public key from the ECDSA signature, then computes
    /// `RIPEMD160(SHA256(compressed_pubkey))`. To rskj the point at infinity's
    /// compressed encoding is the one byte `00` too, so a peg-out from
    /// [`INFINITY_SENDER`] pays that byte's hash160.
    pub fn btc_sender_hash160(&self, chain_id: u64) -> Option<[u8; 20]> {
        use sha2::Digest as Sha2Digest;
        let sha256_hash = match self.recover_key(chain_id).ok()? {
            Recovered::Key(key) => sha2::Sha256::digest(key.serialize()),
            Recovered::Infinity => sha2::Sha256::digest([0u8]),
        };
        let hash160 = ripemd::Ripemd160::digest(sha256_hash);
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&hash160);
        Some(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_rlp::Decodable;

    #[test]
    fn test_transaction_rlp_roundtrip() {
        let tx = Transaction {
            nonce: 42,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1_000_000_000_000_000_000u64),
            input: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            v: 1,
            r: U256::from(123),
            s: U256::from(456),
            cached_rlp: None,
        };

        let mut buffer = Vec::new();
        tx.encode(&mut buffer);

        let decoded = Transaction::decode(&mut buffer.as_slice()).expect("Failed to decode transaction");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_signing_hash_eip155() {
        let tx = Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(1000),
            input: Bytes::new(),
            v: 95, // chain_id=30: 30*2+35=95
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };
        assert!(tx.is_eip155(30));

        let hash1 = tx.signing_hash(30);
        let hash2 = tx.signing_hash(30);
        assert_eq!(hash1, hash2, "signing hash should be deterministic");

        let hash_direct = tx.signing_hash_eip155(31);
        assert_ne!(hash1, hash_direct, "different chain_id should produce different hash");

        let legacy = tx.signing_hash_legacy();
        assert_ne!(hash1, legacy, "EIP-155 hash differs from legacy hash");
    }

    #[test]
    fn test_signing_hash_legacy() {
        let tx = Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(1000),
            input: Bytes::new(),
            v: 27,
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };

        let hash = tx.signing_hash(30);
        assert_ne!(hash, B256::ZERO);
    }

    /// Two transactions that differ only in `v` must hash differently.
    ///
    /// The sender cache in `rustock_execution::sender_cache` is keyed by
    /// `tx_hash()`, and `v` selects both the signing hash (legacy or
    /// EIP-155) and the recovery id -- so two wire forms that hashed alike
    /// but recovered differently would let whichever was seen first decide
    /// the sender of the second.
    ///
    /// Two things keep them apart, and this checks both. `v` is stored
    /// verbatim and re-encoded verbatim, so nothing reconstructs it from a
    /// chain id and folds two values onto one; and `tx_hash` prefers
    /// `cached_rlp`, the bytes as received, which differ anyway.
    #[test]
    fn the_hash_separates_transactions_that_differ_only_in_v() {
        let base = Transaction {
            nonce: 1,
            gas_price: U256::from(1u64),
            gas_limit: U256::from(21_000u64),
            to: Bytes::from(vec![0x11; 20]),
            value: U256::from(1_000u64),
            input: Bytes::default(),
            v: 28,
            r: U256::from(0x1234u64),
            s: U256::from(0x5678u64),
            cached_rlp: None,
        };

        // Every `v` a legacy or near-legacy wire form could carry, including
        // the values either side of the canonical pair.
        let mut seen = std::collections::HashMap::new();
        for v in [0u64, 26, 27, 28, 29, 35, 36, 37, 38] {
            let tx = Transaction { v, ..base.clone() };
            if let Some(other) = seen.insert(tx.tx_hash(), v) {
                panic!("v={v} and v={other} produce the same transaction hash");
            }
        }

        // And again through a real decode, so the cached-bytes path is
        // covered rather than only the re-encoding one.
        let mut encoded = Vec::new();
        base.encode(&mut encoded);
        let decoded = Transaction::decode(&mut encoded.as_slice()).unwrap();
        assert!(decoded.cached_rlp.is_some(), "decode must record the wire bytes");
        assert_eq!(decoded.v, 28, "v must survive the round trip unchanged");
        assert_eq!(
            decoded.tx_hash(),
            base.tx_hash(),
            "the same bytes must hash the same whether decoded or built"
        );
    }

    #[test]
    fn test_recover_sender_roundtrip() {
        use k256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let chain_id = 33u64; // regtest

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(100),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        // Compute signing hash before v/r/s are set — use EIP-155 variant directly
        let hash = tx.signing_hash_eip155(chain_id);

        let (signature, recid) = signing_key
            .sign_prehash_recoverable(hash.as_slice())
            .unwrap();

        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;

        // Now recover_sender uses signing_hash(chain_id) which checks v → EIP-155
        let recovered = tx.recover_sender(chain_id).unwrap();

        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let expected_addr = Address::from_slice(
            &Keccak256::digest(&pubkey.as_bytes()[1..])[12..],
        );

        assert_eq!(recovered, expected_addr, "recovered sender should match signing key");
    }

    /// Regression for mainnet block #457: rskj signs over the ORIGINAL field
    /// byte arrays, which may use non-canonical zero encodings (the free
    /// bridge txs encode gasLimit as a literal 0x00 byte). The signing hash
    /// must reuse the original encoding, not a canonical re-encoding.
    #[test]
    fn test_recover_sender_with_noncanonical_zero_gas_limit() {
        use k256::ecdsa::SigningKey;

        // [nonce=empty, gasPrice=0x01, gasLimit=0x00 (raw zero byte), to, value=empty, data=empty]
        let mut fields = vec![0x80, 0x01, 0x00, 0x94];
        fields.extend_from_slice(&[0x11u8; 20]);
        fields.extend_from_slice(&[0x80, 0x80]);

        // rskj getEncodedRaw with chainId 30: fields ++ [chainId, empty, empty]
        let mut sign_inner = fields.clone();
        sign_inner.extend_from_slice(&[30, 0x80, 0x80]);
        let mut sign_buf = Vec::new();
        alloy_rlp::Header { list: true, payload_length: sign_inner.len() }.encode(&mut sign_buf);
        sign_buf.extend_from_slice(&sign_inner);
        let sign_hash: [u8; 32] = Keccak256::digest(&sign_buf).into();

        // Sign with private key 0x...01 (address 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf)
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let sk = SigningKey::from_slice(&key_bytes).unwrap();
        let (sig, rid) = sk.sign_prehash_recoverable(&sign_hash).unwrap();

        // Assemble the signed tx: fields ++ [v, r, s] (EIP-155, chainId 30)
        let mut inner = fields;
        let v = 35u64 + 60 + rid.to_byte() as u64;
        v.encode(&mut inner);
        U256::from_be_slice(&sig.r().to_bytes()).encode(&mut inner);
        U256::from_be_slice(&sig.s().to_bytes()).encode(&mut inner);
        let mut raw = Vec::new();
        alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut raw);
        raw.extend_from_slice(&inner);

        let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
        assert_eq!(tx.gas_limit, U256::ZERO);
        let sender = tx.recover_sender(30).unwrap();
        let expected: Address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".parse().unwrap();
        assert_eq!(sender, expected, "sender must recover from the original encoding");
    }

    /// Testnet block #8,269,754's first transaction, where the testnet node
    /// stopped on 8 November: a transfer for chain 31 (v = 97) whose signature
    /// recovers the point at infinity. rskj takes it, from 0xdcc703c0...a470
    /// as the public node reports, and would pay a peg-out from it to the
    /// hash160 of the one byte 00.
    #[test]
    fn a_testnet_transfer_whose_key_is_the_point_at_infinity_has_rskjs_sender() {
        let hex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        };
        let mut inner = vec![0x0a];
        inner.extend(hex("8405f5e100"));
        inner.extend(hex("825208"));
        inner.extend(hex("947e5f4552091a69125d5dfcb7b8c2659029395bdf"));
        inner.extend(hex("871c02a6fbc95200"));
        inner.extend([0x80, 0x61]);
        inner.extend(hex(
            "a0cbe5079c44265dba4b8e6bb935f6ae95b7ba00df33ee4e27cdd709929de43037",
        ));
        inner.extend(hex(
            "a05196f13a0727e24f3312944740d1a7c13ff62a61eae43840efb0869ce8f4bc93",
        ));
        let mut raw = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: inner.len(),
        }
        .encode(&mut raw);
        raw.extend_from_slice(&inner);

        let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
        assert_eq!(
            tx.tx_hash(),
            B256::from_slice(&hex(
                "574c3ba99e8f4cee089e984d18ff4ef82fd737c08857836a053d187fb095d5d9"
            )),
            "the bytes are the transaction on chain"
        );
        let expected: Address = "0xdcc703c0e500b653ca82273b7bfad8045d85a470"
            .parse()
            .unwrap();
        assert_eq!(tx.recover_sender(31).unwrap(), expected);
        assert_eq!(tx.recover_compressed_pubkey(31), None);
        let hash160: [u8; 20] = hex("9f7fd096d37ed2c0e3f7f0cfc924beef4ffceb68")
            .try_into()
            .unwrap();
        assert_eq!(tx.btc_sender_hash160(31), Some(hash160));
    }

    #[test]
    fn the_infinity_sender_is_the_address_of_an_empty_key() {
        assert_eq!(INFINITY_SENDER.as_slice(), &Keccak256::digest(b"")[12..]);
    }

    /// A signature made so that sR = eG, with R the generator and s the
    /// signing hash, recovers the point at infinity whatever the transaction;
    /// the same r with y's other parity recovers an ordinary key.
    #[test]
    fn a_signature_made_so_that_sr_is_eg_recovers_the_infinity_sender() {
        let mut tx = Transaction {
            nonce: 3,
            gas_price: U256::from(60_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x22; 20]),
            value: U256::from(1),
            input: Bytes::new(),
            v: 33 * 2 + 35,
            r: U256::from_be_bytes(secp256k1::constants::GENERATOR_X),
            s: U256::ZERO,
            cached_rlp: None,
        };
        let order = U256::from_be_bytes(secp256k1::constants::CURVE_ORDER);
        tx.s = U256::from_be_bytes(tx.signing_hash_eip155(33).0) % order;
        assert_eq!(tx.recover_sender(33).unwrap(), INFINITY_SENDER);

        tx.v += 1;
        let other = tx.recover_sender(33).unwrap();
        assert_ne!(other, INFINITY_SENDER);
        assert!(tx.recover_compressed_pubkey(33).is_some());
    }

    /// A signature whose R isn't on the curve, or whose s is zero, recovers no
    /// key: rskj's native service, its default, recovers none from either, and
    /// this refuses both, as it did before it took the point at infinity.
    #[test]
    fn a_signature_that_recovers_no_key_is_refused() {
        let mut tx = Transaction {
            nonce: 3,
            gas_price: U256::from(60_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x22; 20]),
            value: U256::from(1),
            input: Bytes::new(),
            v: 33 * 2 + 35,
            // 5³ + 7 has no square root modulo p.
            r: U256::from(5),
            s: U256::from(1),
            cached_rlp: None,
        };
        let error = tx.recover_sender(33).unwrap_err().to_string();
        assert!(error.contains("ECDSA recovery failed"), "{error}");
        assert_eq!(tx.btc_sender_hash160(33), None);

        tx.r = U256::from_be_bytes(secp256k1::constants::GENERATOR_X);
        tx.s = U256::ZERO;
        assert!(tx.recover_sender(33).is_err());
    }
}

impl Transaction {
    /// The synthetic REMASC transaction a block of this height carries.
    ///
    /// Every RSK block ends with one, and it is a pure function of the
    /// height: nonce `number - 1`, zero gas price, gas limit and value, the
    /// fixed REMASC recipient, no data and no signature. Nothing outside the
    /// header is needed to rebuild it, which is what lets a body consisting
    /// of this transaction alone be derived rather than requested.
    ///
    /// The encoding is built here rather than left to the derive, because
    /// this transaction is not canonical RLP: gas price and gas limit are
    /// written as the one-byte array `{0}`, encoding as `0x00`, where
    /// canonical RLP writes the empty string. Value is zero too and *is*
    /// written empty, which is the asymmetry that makes this worth pinning
    /// rather than reasoning about. A single wrong byte changes the
    /// transaction hash and so the transactions root, so the bytes are held
    /// against real blocks in the tests below.
    pub fn remasc(block_number: u64) -> Self {
        use crate::validation::block_rules::REMASC_ADDR;

        let nonce = block_number.saturating_sub(1);
        let mut payload = Vec::with_capacity(40);
        // Minimal big-endian, and the empty string for zero -- ordinary RLP
        // for an integer. Not the signed `BigInteger.toByteArray` form some
        // header fields use: #9,000,001's nonce is `83 895440`, with no
        // leading zero though its top bit is set.
        nonce.encode(&mut payload);
        // gasPrice, gasLimit: `{0}`, not the empty string.
        [0u8].as_slice().encode(&mut payload);
        [0u8].as_slice().encode(&mut payload);
        REMASC_ADDR.as_slice().encode(&mut payload);
        // value, data, and the absent signature: empty.
        //
        // Note the asymmetry, which is not guessable and is why these bytes
        // are pinned against real blocks: gas price and gas limit are the
        // one-byte array `{0}`, but value is the empty string, though all
        // three are zero.
        for _ in 0..5 {
            [].as_slice().encode(&mut payload);
        }

        let mut encoded = Vec::with_capacity(payload.len() + 3);
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut encoded);
        encoded.extend_from_slice(&payload);

        Self {
            nonce,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(&REMASC_ADDR),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: Some(encoded),
        }
    }
}

#[cfg(test)]
mod remasc_derivation_tests {
    use super::*;

    /// Real mainnet blocks whose body is REMASC alone: height and the hash
    /// that transaction actually has on chain. Spread across the chain and
    /// straddling wasabi100 (#1,591,000), since the transaction-trie
    /// encoding changes there even though this transaction does not.
    const VECTORS: &[(u64, &str)] = &[
        // Block 1 is the zero-nonce case: the nonce is the empty string.
        (1, "4aa0649fdc1a4b0e07b64c26e43138400c84d6a127d0242027226b7ade17a53e"),
        (100_000, "10dde225116990b51234fbb2f888f554593e09ffc0805f470bf8dea2f0e26143"),
        (500_000, "44ecae85b8d95be83941927f3fa555b5eb96e10695c9932ada7fadd4761abba8"),
        (1_000_009, "4e422483d083ef8158313a5de3e650d84016f7ba921c19349343fc8899f4ef87"),
        (1_590_002, "837dde1f15815d5b42a59435b5daa1eb4a299dde0a0d65e93c1bd13364a10003"),
        (1_591_500, "2e6ae619557544c2c1d11f89839fa0735bac4fadcd0bc51f96d643ad622b443c"),
        (3_000_003, "65116b495c01dc810b7936bc8f6c8a7a6bce19981f89893a433baa0efd396efd"),
        (6_000_005, "8fad0d8167a8d8c83b5d7d3c98619e019ad3b7da5a4e8b5d6c43e41e6ade8c38"),
        (9_000_001, "5771471f2fa38695fc333b24e3fab2fc9ed96413d143f8d352978c4e151c7dc9"),
    ];

    /// The derived transaction must be the one the chain carries, byte for
    /// byte. A hash is the only honest test of that: it fails for a single
    /// wrong byte, which is exactly the failure mode the encoding invites.
    #[test]
    fn the_derived_transaction_is_the_one_on_chain() {
        for (number, want) in VECTORS {
            let tx = Transaction::remasc(*number);
            let got = hex_of(&Keccak256::digest(tx.rlp_for_trie()));
            assert_eq!(&got, want, "REMASC transaction of #{number}");
            assert_eq!(tx.nonce, number - 1);
        }
    }

    /// The transactions root each of those blocks carries in its header.
    ///
    /// The transaction hash matching is necessary but not sufficient: what
    /// sync compares is the root of a one-entry trie, and that encoding
    /// changes at wasabi100 (#1,591,000). #1,590,002 and #1,591,500 sit on
    /// either side of it.
    const ROOTS: &[(u64, &str)] = &[
        (1, "1b4008e6fba070d33fb937e369ddbea5c2b66e5bcb12cfc829f15e1f25e568d0"),
        (100_000, "0024d978787b6f2d0c0a8ee07fc4d5599436469bc7cbf05b422cf4836ed71aa0"),
        (500_000, "c5076a2d77b91b2a523e1a16b186691504d5722f10ed0bc59afbde3fbce70c74"),
        (1_000_009, "f0ab86d3621fd5f2054f2c6de8e5bb7ea017930f5ffbf443f7a8d5199bc49bc4"),
        (1_590_002, "d22fcb9e7311436b1792048f1b31be0cecfb35748b3483e1e0822001b7c5a24a"),
        (1_591_500, "4987cd9d0b4bd806e31d25b7f2792a5b7055084895938471b74520c217db1a2b"),
        (3_000_003, "aac82defd679098fb9e0e58e3dff84f1c7b2e375264e721acc6d2a6ee488d9d3"),
        (6_000_005, "84423ab7162c3862535b61f51a678a570f5726d15776ddb588fd5f9f581c7e22"),
        (9_000_001, "5c679a76060a344c027188942fe17d2a3033d0f43de235c7a088db05574bb7e1"),
    ];

    /// A body of this transaction alone must hash to the root its header
    /// commits to. This is the test derivation actually rests on: it is what
    /// lets the body be used without asking a peer for it.
    #[test]
    fn the_derived_body_matches_the_committed_transactions_root() {
        use crate::types::receipt::ordered_tx_trie_root;

        for (number, want) in ROOTS {
            let body = [Transaction::remasc(*number)];
            // Either era's encoding is accepted, as sync does: the root is a
            // commitment, so matching one of them proves the transaction set
            // whichever era it belongs to.
            let orchid = hex_of(ordered_tx_trie_root(&body, false).as_slice());
            let unitrie = hex_of(ordered_tx_trie_root(&body, true).as_slice());
            assert!(
                &orchid == want || &unitrie == want,
                "#{number}: neither encoding gave the header root\n  want    {want}\n  orchid  {orchid}\n  unitrie {unitrie}"
            );
        }
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod untrusted_input_tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_rlp::Decodable;

    /// No variation on a signed transaction's bytes makes decoding it, or
    /// working out who sent it, panic; and no `v` at all does.
    #[test]
    fn no_variation_on_a_transaction_panics() {
        use k256::ecdsa::SigningKey;
        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let mut seeds = Vec::new();
        for (chain_id, eip155) in [(33u64, true), (30, true), (31, false)] {
            let mut tx = Transaction {
                nonce: 7,
                gas_price: U256::from(60_000_000u64),
                gas_limit: U256::from(21_000u64),
                to: Bytes::from(vec![0xbb; 20]),
                value: U256::from(100u64),
                input: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]),
                ..Default::default()
            };
            let hash = if eip155 {
                tx.signing_hash_eip155(chain_id)
            } else {
                tx.signing_hash_legacy()
            };
            let (signature, id) = key.sign_prehash_recoverable(hash.as_slice()).unwrap();
            let rs = signature.to_bytes();
            tx.r = U256::from_be_slice(&rs[..32]);
            tx.s = U256::from_be_slice(&rs[32..]);
            tx.v = if eip155 { chain_id * 2 + 35 } else { 27 } + u64::from(id.to_byte());
            assert!(tx.recover_sender(chain_id).is_ok());
            seeds.push(alloy_rlp::encode(&tx));
        }
        for (i, seed) in seeds.iter().enumerate() {
            for bytes in crate::mutate::mutants(seed, 1_000, 300 + i as u64) {
                let Ok(tx) = Transaction::decode(&mut bytes.as_slice()) else {
                    continue;
                };
                for chain_id in [30, 31, 33] {
                    let _ = tx.recover_sender(chain_id);
                    let _ = tx.recover_compressed_pubkey(chain_id);
                    let _ = tx.btc_sender_hash160(chain_id);
                }
                let _ = tx.tx_hash();
                let _ = tx.rlp_for_trie();
            }
        }
        // None of these is a recovery id on any network; 2^63 and up once
        // overflowed the sum that finds it.
        for v in [0, 26, 29, 34, 94, 99, 100, 103, 1 << 31, 1 << 63, u64::MAX] {
            let tx = Transaction {
                v,
                r: U256::from(1u64),
                s: U256::from(1u64),
                ..Default::default()
            };
            for chain_id in [30, 31, 33] {
                assert!(
                    tx.recover_sender(chain_id).is_err(),
                    "v {v} on chain {chain_id}"
                );
            }
        }
    }
}
