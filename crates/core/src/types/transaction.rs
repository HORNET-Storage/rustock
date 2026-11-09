use alloy_primitives::{Address, B256, U256, Bytes};
use alloy_rlp::{Decodable, Encodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

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

    /// The encoding rskj hashes a decoded transaction by and serves it in
    /// (`Transaction.getEncoded`), which rskj rebuilds from the fields as it
    /// holds them rather than keeping the bytes that came: see
    /// [`Transaction::from_rskj`]. A transaction built here has none, and
    /// encodes canonically, as rskj would.
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
    /// The next transaction of a stream, as rskj reads a block's
    /// (`BlockFactory.parseTxs`): the next RLP element as `RLP.decode2` cuts
    /// it, whose `getRLPData` rskj hands to `new ImmutableTransaction(..)`.
    /// That is a list's whole encoding but an item's payload, so a
    /// transaction may come wrapped in a byte string; an empty item, rskj's
    /// null, is refused.
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (element, next) = crate::rskj_rlp::first_element(buf)
            .map_err(|_| alloy_rlp::Error::Custom("malformed transaction RLP"))?;
        let raw = element
            .data()
            .ok_or(alloy_rlp::Error::Custom("an empty transaction"))?;
        let tx = Self::from_rskj(raw)?;
        *buf = &buf[next..];
        Ok(tx)
    }
}

impl Transaction {
    /// The encoding the transactions root takes, and the hash: rskj's
    /// (`getEncoded`) for a decoded transaction, and the canonical one, which
    /// rskj's agrees with, for one built here.
    pub fn rlp_for_trie(&self) -> Vec<u8> {
        if let Some(ref cached) = self.cached_rlp {
            return cached.clone();
        }
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    /// A transaction as rskj reads `raw` (`Transaction(byte[] rawData)`), with
    /// the encoding rskj hashes it by.
    ///
    /// rskj reads `raw` as exactly one RLP list (`RLP.decodeList`) of exactly
    /// nine elements, each by `getRLPData`. Nonce, gas limit and data keep
    /// their bytes; gas price and value are unsigned numbers, the gas price
    /// remembering whether it came empty; `to` is empty or 20 bytes; and `v`
    /// is absent, for no signature, when r and s go unread, or one byte, when
    /// r and s must be there.
    ///
    /// Refused here as well is what rskj reads but no block can carry, since
    /// every transaction of a block passes `BlockTxsFieldsValidationRule`, and
    /// no pool takes either:
    /// - what `validate()` refuses: a nonce or gas limit of more than 32
    ///   bytes, a gas price or value of 2^255 or more (`BigInteger
    ///   .toByteArray` in 32 bytes), and r or s of more than 32 significant
    ///   bytes; and an empty gas limit, on which it throws;
    /// - a `v` that names a negative chain, below 34 but for 27 and 28, whose
    ///   signature `acceptTransactionSignature` never takes;
    /// - a nonce past 64 bits, which no account reaches.
    ///
    /// So a `v` here is never 0, which keeps meaning no signature.
    ///
    /// rskj hashes a transaction by an encoding it rebuilds from those fields
    /// (`getEncoded`) rather than by `raw`, and that is the one kept: a nonce
    /// of the one byte 0 goes empty and any other stays as it came; the gas
    /// price stays empty if it came empty, and is otherwise minimal, or 0x00
    /// for zero; the gas limit and data stay as they came; the value is
    /// minimal, and empty for zero; `v` is rebuilt from the chain and
    /// recovery id it names; r and s are minimal; and every length prefix is
    /// canonical. The transaction's `v` is the one in that encoding, which
    /// names the same chain and recovery id.
    pub fn from_rskj(raw: &[u8]) -> alloy_rlp::Result<Self> {
        use crate::rskj_rlp::Element;
        let refuse = alloy_rlp::Error::Custom;
        let elements = crate::rskj_rlp::decode2(raw).map_err(|_| refuse("malformed RLP"))?;
        let [list] = elements.as_slice() else {
            return Err(refuse("Expected one RLP item"));
        };
        let fields = list
            .elements()
            .map_err(|_| refuse("The decoded element wasn't a list"))?;
        let [nonce, gas_price, gas_limit, to, value, input, v, r, s] = fields.as_slice() else {
            return Err(refuse("A transaction must have exactly 9 elements"));
        };
        let nonce_bytes = nonce.data().unwrap_or_default();
        if nonce_bytes.len() > 32 {
            return Err(refuse("Nonce is not valid"));
        }
        let nonce = unsigned(nonce_bytes)
            .and_then(|nonce| u64::try_from(nonce).ok())
            .ok_or(refuse("a nonce past 64 bits"))?;
        let gas_limit_bytes = match gas_limit.data() {
            Some(bytes) if bytes.len() <= 32 => bytes,
            _ => return Err(refuse("Gas Limit is not valid")),
        };
        let coin = |element: &Element, why| match element.data() {
            None => Ok(U256::ZERO),
            Some(bytes) => unsigned(bytes)
                .filter(|coin| coin.bit_len() < 256)
                .ok_or(refuse(why)),
        };
        let gas_price_came_empty = gas_price.data().is_none();
        let gas_price = coin(gas_price, "Gas Price is not valid")?;
        let value = coin(value, "Value is not valid")?;
        let to = match to.data() {
            None => Bytes::new(),
            Some(address) if address.len() == 20 => Bytes::copy_from_slice(address),
            Some(_) => return Err(refuse("An RSK address must be 20 bytes long")),
        };
        let input = input.data().unwrap_or_default();
        let component =
            |element: &Element, why| element.data().and_then(unsigned).ok_or(refuse(why));
        let (v, r, s) = match v.data() {
            None => (0, U256::ZERO, U256::ZERO),
            Some(&[v]) => {
                let (chain, recovery_id) =
                    read_v(v).ok_or(refuse("a v that names a negative chain"))?;
                (
                    encoded_v(chain, recovery_id),
                    component(r, "Signature R is not valid")?,
                    component(s, "Signature S is not valid")?,
                )
            }
            Some(_) => return Err(refuse("Signature V is invalid")),
        };

        // `getEncoded`: `Transaction.encode`, field by field.
        let mut payload = Vec::with_capacity(raw.len());
        let nonce_kept: &[u8] = if nonce_bytes == [0] { &[] } else { nonce_bytes };
        nonce_kept.encode(&mut payload);
        if gas_price_came_empty {
            payload.push(alloy_rlp::EMPTY_STRING_CODE);
        } else {
            unsigned_bytes(gas_price).as_slice().encode(&mut payload);
        }
        gas_limit_bytes.encode(&mut payload);
        to.as_ref().encode(&mut payload);
        value
            .to_be_bytes_trimmed_vec()
            .as_slice()
            .encode(&mut payload);
        input.encode(&mut payload);
        if v == 0 {
            payload.extend_from_slice(&[alloy_rlp::EMPTY_STRING_CODE; 3]);
        } else {
            v.encode(&mut payload);
            unsigned_bytes(r).as_slice().encode(&mut payload);
            unsigned_bytes(s).as_slice().encode(&mut payload);
        }
        let mut encoding = Vec::with_capacity(payload.len() + 9);
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut encoding);
        encoding.extend_from_slice(&payload);

        Ok(Self {
            nonce,
            gas_price,
            gas_limit: U256::from_be_slice(gas_limit_bytes),
            to,
            value,
            input: Bytes::copy_from_slice(input),
            v,
            r,
            s,
            cached_rlp: Some(encoding),
        })
    }
}

impl Transaction {
    /// What this transaction's signature signs, rskj's `getRawHash`: by the
    /// chain its `v` names, or by none.
    pub fn signing_hash(&self) -> B256 {
        match self.chain_and_recovery_id() {
            Some((chain, _)) if chain != 0 => self.signing_hash_eip155(u64::from(chain)),
            _ => self.signing_hash_legacy(),
        }
    }

    /// What a signature for the chain `chain_id` signs, rskj's
    /// `getEncodedRaw` hashed: the six fields as rskj writes them, then the
    /// chain id (`RLP.encodeByte`) and two empty items.
    pub fn signing_hash_eip155(&self, chain_id: u64) -> B256 {
        let mut inner = self.signed_fields();
        chain_id.encode(&mut inner);
        0u8.encode(&mut inner);
        0u8.encode(&mut inner);
        Self::rlp_wrap_and_hash(&inner)
    }

    /// What a signature for no chain in particular signs, rskj's
    /// `getEncodedRaw` hashed at chain 0: the six fields as rskj writes them.
    pub fn signing_hash_legacy(&self) -> B256 {
        Self::rlp_wrap_and_hash(&self.signed_fields())
    }

    /// The six fields a signature covers, each the RLP item rskj writes for it
    /// (`Transaction.encode`): `cached_rlp`'s, for a transaction read from
    /// bytes, and otherwise the fields' own, which are rskj's for fields that
    /// came canonical. A zero gas limit of the one byte 0, which canonical RLP
    /// writes empty, is why: mainnet's early bridge transactions carry one.
    fn signed_fields(&self) -> Vec<u8> {
        if let Some(fields) = self
            .cached_rlp
            .as_deref()
            .and_then(|rlp| first_items(rlp, 6))
        {
            return fields.to_vec();
        }
        let mut inner = Vec::with_capacity(128 + self.input.len());
        self.nonce.encode(&mut inner);
        self.gas_price.encode(&mut inner);
        self.gas_limit.encode(&mut inner);
        self.to.encode(&mut inner);
        self.value.encode(&mut inner);
        self.input.encode(&mut inner);
        inner
    }

    fn rlp_wrap_and_hash(inner: &[u8]) -> B256 {
        let mut buf = Vec::with_capacity(inner.len() + 5);
        alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut buf);
        buf.extend_from_slice(inner);
        B256::from_slice(&Keccak256::digest(&buf))
    }

    /// The chain this transaction's signature is for, 0 for none, and its
    /// recovery id, as rskj reads them from `v` ([`read_v`]). `None` for no
    /// signature, and for a `v` rskj takes no signature by: past a byte, or
    /// naming a negative chain.
    pub fn chain_and_recovery_id(&self) -> Option<(u8, u8)> {
        u8::try_from(self.v).ok().and_then(read_v)
    }

    /// The gas this transaction gives, as rskj reads its gas limit's bytes
    /// (`GasCost.toGas`): more than eight bytes, leading zeros or not, read
    /// as `Long.MAX_VALUE`, which no block's gas fits
    /// (`TransactionExecutor.gasIsValid`). `None` for eight bytes with the
    /// top bit set, a negative `long`, on which rskj throws.
    pub fn gas(&self) -> Option<u64> {
        let bytes = self.gas_limit_bytes();
        if bytes.len() > 8 {
            return Some(i64::MAX as u64);
        }
        let gas = bytes
            .iter()
            .fold(0u64, |gas, byte| gas << 8 | u64::from(*byte));
        i64::try_from(gas).is_ok().then_some(gas)
    }

    /// The gas limit's bytes as rskj holds them (`getGasLimit`): as they came,
    /// leading zeros and all, for a transaction read from bytes.
    fn gas_limit_bytes(&self) -> Vec<u8> {
        self.cached_rlp
            .as_deref()
            .and_then(|rlp| list_item(rlp, 2))
            .map_or_else(|| self.gas_limit.to_be_bytes_trimmed_vec(), <[u8]>::to_vec)
    }

    /// Whether this is the REMASC transaction of a block of `count`
    /// transactions, at `index` (rskj: `Transaction.isRemascTransaction`): the
    /// last, to REMASC, with no data and no signature, and value, gas limit
    /// and gas price zero. Its gas limit has bytes, zero or not: rskj reads it
    /// by `new BigInteger(1, getGasLimit())`, which throws on none, and the
    /// block with it (`BlockFactory.parseTxs`).
    pub fn is_remasc(&self, index: usize, count: usize) -> bool {
        index + 1 == count
            && self.to.as_ref() == crate::validation::block_rules::REMASC_ADDR
            && self.input.is_empty()
            && self.v == 0
            && self.value.is_zero()
            && self.gas_price.is_zero()
            && self.gas_limit.is_zero()
            && !self.gas_limit_bytes().is_empty()
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

/// The payload of the RLP list `encoding`.
fn list_payload(encoding: &[u8]) -> Option<&[u8]> {
    let mut buf = encoding;
    let header = alloy_rlp::Header::decode(&mut buf).ok()?;
    if !header.list {
        return None;
    }
    buf.get(..header.payload_length)
}

/// The first `count` items of the RLP list `encoding`, prefixes and all.
fn first_items(encoding: &[u8], count: usize) -> Option<&[u8]> {
    let payload = list_payload(encoding)?;
    let mut rest = payload;
    for _ in 0..count {
        take_rlp_item(&mut rest)?;
    }
    Some(&payload[..payload.len() - rest.len()])
}

/// The payload of item `index` of the RLP list `encoding`.
fn list_item(encoding: &[u8], index: usize) -> Option<&[u8]> {
    let mut rest = list_payload(encoding)?;
    for _ in 0..index {
        take_rlp_item(&mut rest)?;
    }
    let mut item = take_rlp_item(&mut rest)?;
    let header = alloy_rlp::Header::decode(&mut item).ok()?;
    if header.list {
        return None;
    }
    item.get(..header.payload_length)
}

/// A number from big-endian bytes, as Java's `new BigInteger(1, bytes)` reads
/// them, where it fits 256 bits.
fn unsigned(bytes: &[u8]) -> Option<U256> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let significant = &bytes[first..];
    (significant.len() <= 32).then(|| U256::from_be_slice(significant))
}

/// Bouncy Castle's `BigIntegers.asUnsignedByteArray`: a number's minimal
/// big-endian bytes, and the one byte 0 for zero.
fn unsigned_bytes(value: U256) -> Vec<u8> {
    if value.is_zero() {
        vec![0]
    } else {
        value.to_be_bytes_trimmed_vec()
    }
}

/// What rskj reads from a signature's `v`: the chain the signature is for
/// (`extractChainIdFromV`), 0 for none, which every network takes; and the
/// recovery id, `getRealV` less 27. 27 and 28 name no chain; otherwise the
/// chain is `(v - 35) / 2` in Java's `int` division, which truncates toward
/// zero, so 34 to 36 name none either, and the real v is 28 for an even `v`
/// and 27 for an odd one. `None` below 34 but for 27 and 28: a negative
/// chain, which no network is.
fn read_v(v: u8) -> Option<(u8, u8)> {
    let recovery_id = u8::from(v.is_multiple_of(2));
    match v {
        27 | 28 | 34..=255 => Some((v.saturating_sub(35) / 2, recovery_id)),
        _ => None,
    }
}

/// The `v` rskj writes for a signature (`Transaction.rlpEncode`): its
/// recovery id plus 27, or plus `chain * 2 + 35` for a chain.
fn encoded_v(chain: u8, recovery_id: u8) -> u64 {
    let base = if chain == 0 {
        27
    } else {
        u64::from(chain) * 2 + 35
    };
    base + u64::from(recovery_id)
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

/// The key a signature recovers, as rskj recovers it: libsecp256k1's key, or
/// the point at infinity where libsecp256k1 refuses a key that would have
/// been it. `signature` is r then s, big-endian, and `recovery_id` 0 or 1.
fn recover(hash: &[u8; 32], signature: &[u8; 64], recovery_id: u8) -> anyhow::Result<Recovered> {
    // `from_u8_masked` takes the low two bits rather than rejecting an
    // out-of-range id, which is safe only because every caller has already
    // confined `recovery_id` to 0 or 1.
    let recid = secp256k1::ecdsa::RecoveryId::from_u8_masked(recovery_id);
    let compact = secp256k1::ecdsa::RecoverableSignature::from_compact(signature, recid)
        .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;
    let message = secp256k1::Message::from_digest(*hash);
    match secp_context().recover_ecdsa(message, &compact) {
        Ok(key) => Ok(Recovered::Key(key)),
        Err(_) if recovers_infinity(signature, recovery_id, hash) => Ok(Recovered::Infinity),
        Err(e) => Err(anyhow::anyhow!("ECDSA recovery failed: {e}")),
    }
}

/// The address of a key: the last 20 bytes of the keccak256 of its
/// uncompressed encoding, past the leading byte that marks the form.
fn address_of(key: &secp256k1::PublicKey) -> Address {
    let pubkey_hash = Keccak256::digest(&key.serialize_uncompressed()[1..]);
    Address::from_slice(&pubkey_hash[12..])
}

/// The address a signature recovers, as rskj's ECRecover precompile answers
/// it: `ECDSASignature.validateComponents` holds r and s from 1 to below the
/// curve's order, then `ECKey.getAddress` of `Secp256k1Service
/// .signatureToKey`, which is [`INFINITY_SENDER`] for the point at infinity.
/// `None` where rskj answers no address. `signature` is r then s,
/// big-endian; `recovery_id` is `v - 27`, so 0 or 1.
pub fn recover_address(hash: &[u8; 32], signature: &[u8; 64], recovery_id: u8) -> Option<Address> {
    let order = U256::from_be_bytes(secp256k1::constants::CURVE_ORDER);
    let (r, s) = signature.split_at(32);
    let in_range = |half: &[u8]| {
        let value = U256::from_be_slice(half);
        !value.is_zero() && value < order
    };
    if recovery_id > 1 || !in_range(r) || !in_range(s) {
        return None;
    }
    Some(match recover(hash, signature, recovery_id).ok()? {
        Recovered::Key(key) => address_of(&key),
        Recovered::Infinity => INFINITY_SENDER,
    })
}

impl Transaction {

    /// The sender of a transaction the network `chain_id` takes, as rskj
    /// finds it: refused unless rskj would take the signature there
    /// (`acceptTransactionSignature`, see [`Transaction::recover_key`]).
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
            Recovered::Key(key) => address_of(&key),
            Recovered::Infinity => INFINITY_SENDER,
        })
    }

    /// The key this transaction's signature recovers, as rskj recovers it,
    /// where the network `chain_id` takes the signature, as rskj's
    /// `acceptTransactionSignature` takes it from every transaction of a
    /// block but REMASC (`BlockTxsFieldsValidationRule`) and from every one
    /// it is sent: a signature for no chain or for `chain_id`, with r from 1
    /// to below the curve's order and s from 1 to below half of it.
    /// `recover_sender` and `btc_sender_hash160` both take it from here, so
    /// they cannot drift apart on what a signature means.
    ///
    /// A sender found here depends on nothing but the transaction's hash: the
    /// encoding hashed holds the six fields and r and s, and its `v` names
    /// the chain and recovery id, the same two for every `v` read here
    /// ([`Transaction::from_rskj`]). So a cache of senders by hash is sound.
    fn recover_key(&self, chain_id: u64) -> anyhow::Result<Recovered> {
        let Some((chain, recovery_id)) = self.chain_and_recovery_id() else {
            anyhow::bail!("no signature rskj takes: v {}", self.v);
        };
        if chain != 0 && u64::from(chain) != chain_id {
            anyhow::bail!("a signature for chain {chain}, not {chain_id}");
        }
        let order = U256::from_be_bytes(secp256k1::constants::CURVE_ORDER);
        if self.r.is_zero() || self.r >= order {
            anyhow::bail!("signature r out of range");
        }
        if self.s.is_zero() || self.s >= order >> 1 {
            anyhow::bail!("signature s out of range, or in the curve order's upper half");
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig_bytes[32..].copy_from_slice(&self.s.to_be_bytes::<32>());
        recover(&self.signing_hash().0, &sig_bytes, recovery_id)
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
            v: 27,
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
        assert_eq!(tx.chain_and_recovery_id(), Some((30, 0)));

        let hash = tx.signing_hash();
        assert_eq!(hash, tx.signing_hash_eip155(30), "v 95 signs for chain 30");
        let hash_direct = tx.signing_hash_eip155(31);
        assert_ne!(
            hash, hash_direct,
            "different chain_id should produce different hash"
        );

        let legacy = tx.signing_hash_legacy();
        assert_ne!(hash, legacy, "EIP-155 hash differs from legacy hash");
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

        assert_eq!(
            tx.signing_hash(),
            tx.signing_hash_legacy(),
            "v 27 signs for no chain"
        );
    }

    /// A transaction's hash is rskj's (`getHash`, of `getEncoded`), whose `v`
    /// rskj rebuilds from the chain and recovery id it reads there. So every
    /// `v` that names the same two hashes alike, as 35 does with 27, and any
    /// two that name different ones hash apart.
    ///
    /// The sender cache in `rustock_execution::sender_cache` is keyed by this
    /// hash: a hash that came with two readings of `v` would let whichever
    /// was seen first decide the sender of the other.
    #[test]
    fn the_hash_follows_what_v_names() {
        let mut readings = std::collections::HashMap::new();
        for v in 0..=255u8 {
            let mut payload = vec![0x01, 0x01, 0x82, 0x52, 0x08, 0x94];
            payload.extend_from_slice(&[0x11; 20]);
            payload.extend_from_slice(&[0x82, 0x03, 0xe8, 0x80]);
            // As a one-byte string, so that 0 is the byte 00, not empty.
            [v].as_slice().encode(&mut payload);
            payload.extend_from_slice(&[0x82, 0x12, 0x34, 0x82, 0x56, 0x78]);
            let mut raw = Vec::new();
            alloy_rlp::Header {
                list: true,
                payload_length: payload.len(),
            }
            .encode(&mut raw);
            raw.extend_from_slice(&payload);

            let read = Transaction::decode(&mut raw.as_slice());
            let named = read_v(v);
            assert_eq!(read.is_ok(), named.is_some(), "v {v}");
            let Ok(tx) = read else { continue };
            assert_eq!(
                tx.chain_and_recovery_id(),
                named,
                "v {v} keeps what it names"
            );
            if let Some(other) = readings.insert(tx.tx_hash(), named) {
                assert_eq!(other, named, "v {v} hashes as a v that names otherwise");
            }
        }
        // 27 and 28, and 34 to 36, name no chain; 37 to 255 one each, two
        // recovery ids apiece.
        assert_eq!(readings.len(), 2 + 219);

        // A transaction built here hashes as rskj would its encoding.
        let built = Transaction {
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
        let mut encoded = Vec::new();
        built.encode(&mut encoded);
        let decoded = Transaction::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.cached_rlp.as_deref(), Some(encoded.as_slice()));
        assert_eq!(decoded, built);
        assert_eq!(
            decoded.tx_hash(),
            built.tx_hash(),
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

        // v names chain 33, so recover_sender checks the signature for it.
        let recovered = tx.recover_sender(chain_id).unwrap();

        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let expected_addr = Address::from_slice(
            &Keccak256::digest(&pubkey.as_bytes()[1..])[12..],
        );

        assert_eq!(recovered, expected_addr, "recovered sender should match signing key");
    }

    /// Regression for mainnet block #457: rskj signs over the fields as it
    /// holds them, and keeps a gas limit's bytes as they came, so the free
    /// bridge transactions' zero gas limit, the one byte 0, is signed as that
    /// byte, where canonical RLP writes zero empty.
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

    /// A signature made so that sR = eG recovers the point at infinity
    /// whatever the transaction: R the generator, whose y is even, and s the
    /// signing hash e; or, where that s would be in the upper half rskj
    /// refuses, R the generator's negation, whose y is odd, and s the order
    /// less e. The same r with y's other parity recovers an ordinary key.
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
        let e = U256::from_be_bytes(tx.signing_hash_eip155(33).0) % order;
        if e < order >> 1 {
            tx.s = e;
        } else {
            tx.v += 1;
            tx.s = order - e;
        }
        assert_eq!(tx.recover_sender(33).unwrap(), INFINITY_SENDER);

        tx.v = if tx.v == 101 { 102 } else { 101 };
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

    /// `recover_address`, as rskj's ECRecover answers: a key's address; the
    /// infinity sender where sR = eG; and nothing for an r or s of 0 or the
    /// curve's order or more, an id past 1, or an R that isn't on the curve.
    #[test]
    fn recover_address_answers_as_rskjs_ecrecover() {
        use k256::ecdsa::SigningKey;
        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        // Below the curve's order, so the hash is its own value modulo it.
        let hash = [0x11_u8; 32];
        let (signature, id) = key.sign_prehash_recoverable(&hash).unwrap();
        let id = id.to_byte();
        let mut ordinary = [0_u8; 64];
        ordinary.copy_from_slice(&signature.to_bytes());
        let point = key.verifying_key().to_encoded_point(false);
        let address = Address::from_slice(&Keccak256::digest(&point.as_bytes()[1..])[12..]);
        assert_eq!(recover_address(&hash, &ordinary, id), Some(address));
        assert_eq!(recover_address(&hash, &ordinary, 2), None);

        // R the generator, whose y is even, and s the hash: sR = eG.
        let mut infinity = [0_u8; 64];
        infinity[..32].copy_from_slice(&secp256k1::constants::GENERATOR_X);
        infinity[32..].copy_from_slice(&hash);
        assert_eq!(recover_address(&hash, &infinity, 0), Some(INFINITY_SENDER));
        // With y odd R is -G, and the key an ordinary one.
        let other = recover_address(&hash, &infinity, 1);
        assert!(other.is_some_and(|other| other != INFINITY_SENDER));

        let order = secp256k1::constants::CURVE_ORDER;
        for (at, bad) in [(0, [0_u8; 32]), (32, [0_u8; 32]), (0, order), (32, order)] {
            let mut signature = ordinary;
            signature[at..at + 32].copy_from_slice(&bad);
            assert_eq!(recover_address(&hash, &signature, id), None);
        }
        // 5³ + 7 has no square root modulo p.
        let mut off_curve = [0_u8; 64];
        off_curve[31] = 5;
        off_curve[63] = 1;
        assert_eq!(recover_address(&hash, &off_curve, 0), None);
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
        // No network takes a signature by any of these: rskj reads no chain
        // from 0, 26, 29 or past a byte (2^63 and up once overflowed the sum
        // that found the recovery id), and 94, 99, 100 and 103 name chains
        // 29, 32, 32 and 34.
        for v in [0, 26, 29, 94, 99, 100, 103, 1 << 31, 1 << 63, u64::MAX] {
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

#[cfg(test)]
mod rskj_reading_tests {
    use super::*;
    use crate::validation::block_rules::REMASC_ADDR;
    use alloy_primitives::U256;
    use alloy_rlp::Decodable;

    /// A list of items, each already its RLP.
    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload = items.concat();
        let mut raw = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut raw);
        raw.extend_from_slice(&payload);
        raw
    }

    /// A byte string's canonical RLP.
    fn item(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        bytes.encode(&mut out);
        out
    }

    /// A transfer's nine items as canonical RLP writes them, signed with v 27.
    fn fields() -> Vec<Vec<u8>> {
        vec![
            item(&[0x05]),
            item(&[0x01]),
            item(&[0x52, 0x08]),
            item(&[0x11; 20]),
            item(&[0x03, 0xe8]),
            item(&[]),
            item(&[27]),
            item(&[0x12, 0x34]),
            item(&[0x56, 0x78]),
        ]
    }

    fn with(at: usize, field: Vec<u8>) -> Vec<Vec<u8>> {
        let mut fields = fields();
        fields[at] = field;
        fields
    }

    fn read(fields: &[Vec<u8>]) -> alloy_rlp::Result<Transaction> {
        Transaction::decode(&mut list(fields).as_slice())
    }

    /// What rskj's `Transaction(byte[])` throws on, and what `validate()`
    /// refuses in every block, is refused when read.
    #[test]
    fn what_rskj_cannot_take_is_refused_when_read() {
        assert!(read(&fields()).is_ok());
        let mut eight = fields();
        eight.pop();
        assert!(read(&eight).is_err(), "eight fields");
        let mut ten = fields();
        ten.push(item(&[]));
        assert!(read(&ten).is_err(), "ten fields");
        assert!(read(&with(3, item(&[0x11; 19]))).is_err(), "a 19-byte to");
        assert!(read(&with(3, item(&[0x11; 21]))).is_err(), "a 21-byte to");
        assert!(
            read(&with(3, item(&[]))).unwrap().to.is_empty(),
            "no to: a creation"
        );
        assert!(read(&with(6, item(&[0x00, 27]))).is_err(), "a two-byte v");
        assert!(read(&with(7, item(&[]))).is_err(), "a v with no r");
        assert!(read(&with(8, item(&[]))).is_err(), "a v with no s");
        // No signature: r and s go unread.
        let mut unsigned = with(6, item(&[]));
        unsigned[7] = item(&[0xff; 40]);
        let unsigned = read(&unsigned).unwrap();
        assert_eq!(
            (unsigned.v, unsigned.r, unsigned.s),
            (0, U256::ZERO, U256::ZERO)
        );

        // `validate()`'s limits, and the nonce an account can reach.
        assert!(
            read(&with(0, item(&[0x01; 33]))).is_err(),
            "a 33-byte nonce"
        );
        assert!(
            read(&with(0, item(&[0x01; 9]))).is_err(),
            "a nonce past 64 bits"
        );
        assert!(
            read(&with(2, item(&[0x00; 33]))).is_err(),
            "a 33-byte gas limit"
        );
        assert!(read(&with(2, item(&[]))).is_err(), "no gas limit");
        let mut half = [0u8; 32];
        half[0] = 0x80;
        let mut below = [0xff; 32];
        below[0] = 0x7f;
        for (at, what) in [(1, "gas price"), (4, "value")] {
            assert!(read(&with(at, item(&half))).is_err(), "a {what} of 2^255");
            assert!(
                read(&with(at, item(&below))).is_ok(),
                "a {what} just below 2^255"
            );
        }
        assert!(
            read(&with(7, item(&[0x01; 33]))).is_err(),
            "r of 33 significant bytes"
        );
        let padded = [&[0u8][..], &[0x01; 32]].concat();
        assert!(
            read(&with(7, item(&padded))).is_ok(),
            "33 bytes, the first zero"
        );

        // A v that names a negative chain.
        for v in [0u8, 1, 26, 29, 32, 33] {
            assert!(read(&with(6, item(&[v]))).is_err(), "v {v}");
        }
    }

    /// rskj hashes a transaction by an encoding it rebuilds from the fields
    /// it holds (`getEncoded`), and that is the one kept.
    #[test]
    fn the_encoding_kept_is_the_one_rskj_hashes() {
        assert_eq!(read(&fields()).unwrap().rlp_for_trie(), list(&fields()));
        let cases = [
            (
                0,
                item(&[0x00]),
                item(&[]),
                "a nonce of the one byte 0 goes empty",
            ),
            (
                0,
                item(&[0x00, 0x05]),
                item(&[0x00, 0x05]),
                "any other nonce stays",
            ),
            (1, item(&[0x00]), item(&[0x00]), "a zero gas price stays 00"),
            (1, item(&[]), item(&[]), "an empty gas price stays empty"),
            (
                1,
                item(&[0x00, 0x01]),
                item(&[0x01]),
                "a gas price is minimal",
            ),
            (
                2,
                item(&[0x00, 0x52, 0x08]),
                item(&[0x00, 0x52, 0x08]),
                "a gas limit stays",
            ),
            (
                2,
                item(&[0x00]),
                item(&[0x00]),
                "a zero gas limit of the one byte 0 stays",
            ),
            (4, item(&[0x00]), item(&[]), "a zero value goes empty"),
            (
                4,
                item(&[0x00, 0x03, 0xe8]),
                item(&[0x03, 0xe8]),
                "a value is minimal",
            ),
            (
                6,
                item(&[35]),
                item(&[27]),
                "v 35 names no chain and recovery id 0",
            ),
            (
                6,
                item(&[34]),
                item(&[28]),
                "v 34 names no chain and recovery id 1",
            ),
            (6, item(&[36]), item(&[28]), "and so does 36"),
            (
                7,
                item(&[0x00, 0x12, 0x34]),
                item(&[0x12, 0x34]),
                "r is minimal",
            ),
            (
                8,
                vec![0x81, 0x05],
                item(&[0x05]),
                "a single byte written long",
            ),
            (
                5,
                vec![0xb8, 0x02, 0xaa, 0xbb],
                item(&[0xaa, 0xbb]),
                "a long prefix, short data",
            ),
        ];
        for (at, came, kept, what) in cases {
            let tx = read(&with(at, came)).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(tx.rlp_for_trie(), list(&with(at, kept)), "{what}");
        }
        // And the list's own prefix: a long one on a short list.
        let payload = fields().concat();
        let long = [&[0xf8, payload.len() as u8][..], &payload].concat();
        let tx = Transaction::decode(&mut long.as_slice()).unwrap();
        assert_eq!(tx.rlp_for_trie(), list(&fields()));
    }

    /// rskj reads each of a block's transactions by `getRLPData`, which for a
    /// byte string is its payload: a transaction may come wrapped in one.
    #[test]
    fn a_transaction_may_come_wrapped_in_a_byte_string() {
        let raw = list(&fields());
        let stream = [item(&raw), raw].concat();
        let mut buf = stream.as_slice();
        let wrapped = Transaction::decode(&mut buf).unwrap();
        let plain = Transaction::decode(&mut buf).unwrap();
        assert!(buf.is_empty());
        assert_eq!(wrapped.tx_hash(), plain.tx_hash());
        assert!(
            Transaction::decode(&mut [0x80].as_slice()).is_err(),
            "an empty item"
        );
    }

    /// rskj takes a signature (`acceptTransactionSignature`) for no chain or
    /// for its own, with r from 1 to below the curve's order and s from 1 to
    /// below half of it.
    #[test]
    fn a_signature_is_taken_as_rskj_takes_it() {
        use k256::ecdsa::SigningKey;
        let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let sender = Address::from_slice(&Keccak256::digest(&point.as_bytes()[1..])[12..]);
        let unsigned = Transaction {
            nonce: 5,
            gas_price: U256::from(1u64),
            gas_limit: U256::from(21_000u64),
            to: Bytes::from(vec![0x11; 20]),
            value: U256::from(1_000u64),
            ..Default::default()
        };
        let sign = |hash: B256, base: u64| {
            let (signature, id) = key.sign_prehash_recoverable(hash.as_slice()).unwrap();
            let rs = signature.to_bytes();
            Transaction {
                v: base + u64::from(id.to_byte()),
                r: U256::from_be_slice(&rs[..32]),
                s: U256::from_be_slice(&rs[32..]),
                ..unsigned.clone()
            }
        };
        let order = U256::from_be_bytes(secp256k1::constants::CURVE_ORDER);

        // For chain 30: taken there, and only there.
        let for_30 = sign(unsigned.signing_hash_eip155(30), 95);
        assert_eq!(for_30.recover_sender(30).unwrap(), sender);
        assert!(for_30.recover_sender(31).is_err());
        assert!(for_30.recover_sender(33).is_err());

        // For no chain: taken on every network, by 27 or 28 and by 34 to 36.
        let legacy = sign(unsigned.signing_hash_legacy(), 27);
        for chain_id in [30, 31, 33] {
            assert_eq!(legacy.recover_sender(chain_id).unwrap(), sender);
        }
        let others: &[u64] = if legacy.v == 27 { &[35] } else { &[34, 36] };
        for &v in others {
            let mut raw = Vec::new();
            Transaction {
                v,
                ..legacy.clone()
            }
            .encode(&mut raw);
            let read = Transaction::decode(&mut raw.as_slice()).unwrap();
            assert_eq!(read.v, legacy.v, "v {v} is written as {}", legacy.v);
            assert_eq!(read.tx_hash(), legacy.tx_hash());
            assert_eq!(read.recover_sender(30).unwrap(), sender, "v {v}");
        }

        // The same signature with s in the upper half and the other
        // recovery id: refused, though it is the same key's.
        let high = Transaction {
            v: 55 - legacy.v,
            s: order - legacy.s,
            ..legacy.clone()
        };
        assert!(high.recover_sender(30).is_err(), "s in the upper half");
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&high.r.to_be_bytes::<32>());
        signature[32..].copy_from_slice(&high.s.to_be_bytes::<32>());
        let hash = unsigned.signing_hash_legacy().0;
        assert_eq!(
            recover_address(&hash, &signature, (high.v - 27) as u8),
            Some(sender)
        );

        // Half the order, rounded down, is already too high; r and s of 0, and
        // r of the order, are refused too.
        let half = Transaction {
            s: order >> 1,
            ..legacy.clone()
        };
        assert!(half.recover_sender(30).is_err());
        for (r, s) in [
            (U256::ZERO, legacy.s),
            (order, legacy.s),
            (legacy.r, U256::ZERO),
        ] {
            assert!(Transaction {
                r,
                s,
                ..legacy.clone()
            }
            .recover_sender(30)
            .is_err());
        }
        assert!(unsigned.recover_sender(30).is_err(), "no signature");
    }

    /// A transaction's gas is its gas limit's bytes as rskj's `GasCost.toGas`
    /// reads them.
    #[test]
    fn gas_is_read_as_rskjs_to_gas() {
        let gas = |bytes: &[u8]| read(&with(2, item(bytes))).unwrap().gas();
        assert_eq!(gas(&[0x52, 0x08]), Some(21_000));
        assert_eq!(gas(&[0x00]), Some(0));
        assert_eq!(
            gas(&[0, 0, 0, 0, 0, 0, 0x52, 0x08]),
            Some(21_000),
            "eight bytes"
        );
        let nine = [0, 0, 0, 0, 0, 0, 0, 0x52, 0x08];
        assert_eq!(
            gas(&nine),
            Some(i64::MAX as u64),
            "nine, though the number is small"
        );
        let max = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(gas(&max), Some(i64::MAX as u64));
        assert_eq!(gas(&[0x80, 0, 0, 0, 0, 0, 0, 0]), None, "a negative long");
        let built = Transaction {
            gas_limit: U256::from(21_000u64),
            ..Default::default()
        };
        assert_eq!(built.gas(), Some(21_000));
    }

    /// rskj's `TransactionIsRemascTest`, on transactions read from bytes: the
    /// REMASC transaction is a block's last, to the REMASC address, with no
    /// data and no signature, and value, gas price and gas limit zero.
    #[test]
    fn remasc_is_rskjs_is_remasc_transaction() {
        let remasc = |edit: &dyn Fn(&mut Vec<Vec<u8>>)| {
            let mut fields = vec![
                item(&[]),
                item(&[0x00]),
                item(&[0x00]),
                item(&REMASC_ADDR),
                item(&[]),
                item(&[]),
                item(&[]),
                item(&[]),
                item(&[]),
            ];
            edit(&mut fields);
            read(&fields).unwrap()
        };
        assert!(
            remasc(&|_| {}).is_remasc(6, 7),
            "validRemascTransactionNullData"
        );
        assert!(
            !remasc(&|_| {}).is_remasc(3, 7),
            "notRemascTransactionNotLastTx"
        );
        let data = remasc(&|f| f[5] = item(&[1, 2, 3, 4]));
        assert!(!data.is_remasc(6, 7), "notRemascTransactionNotEmptyData");
        let signed = remasc(&|f| {
            f[6] = item(&[27]);
            f[7] = item(&[1]);
            f[8] = item(&[1]);
        });
        assert!(!signed.is_remasc(6, 7), "notRemascTransactionNotNullSig");
        let elsewhere = remasc(&|f| f[3] = item(&[0x22; 20]));
        assert!(
            !elsewhere.is_remasc(6, 7),
            "notRemascTransactionReceiverIsNotRemasc"
        );
        let value = remasc(&|f| f[4] = item(&[10]));
        assert!(!value.is_remasc(6, 7), "notRemascTransactionValueIsNotZero");
        let price = remasc(&|f| f[1] = item(&[10]));
        assert!(
            !price.is_remasc(6, 7),
            "notRemascTransactionGasPriceIsNotZero"
        );
        let limit = remasc(&|f| f[2] = item(&[10]));
        assert!(
            !limit.is_remasc(6, 7),
            "notRemascTransactionGasLimitIsNotZero"
        );

        // An empty gas price reads as zero (`getGasPrice`); a gas limit with
        // no bytes can't be read at all.
        assert!(remasc(&|f| f[1] = item(&[])).is_remasc(6, 7));
        assert!(Transaction::remasc(9).is_remasc(0, 1));
        let built = Transaction {
            to: Bytes::copy_from_slice(&REMASC_ADDR),
            ..Default::default()
        };
        assert!(!built.is_remasc(0, 1), "a gas limit with no bytes");
    }
}
