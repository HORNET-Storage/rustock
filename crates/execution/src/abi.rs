//! A call's arguments, read as rskj reads them for its own contracts.
//!
//! rskj decodes the arguments of a call to the Bridge or to a native contract
//! (HDWalletUtils, BlockHeader, Environment) once, in `Bridge.parseData` or
//! `NativeContract.parseData`, through `CallTransaction.Function.decode` and
//! the decoders of `org.ethereum.solidity.SolidityType`; a payload they cannot
//! decode is a parse failure. Each method then converts the `BigInteger`s it
//! gets as Java does. Those rules are not the ABI's, and a transaction can
//! reach every place they differ:
//!
//! - an offset or a length is a word's `intValue()`: its low 32 bits as a
//!   signed int, whatever the other 28 bytes hold;
//! - an integer is a signed `BigInteger`, a `uint` parameter's too;
//! - an empty payload reads as zero wherever an integer is read, so a method
//!   whose parameters are all integers, `bool`s or `address`es can be called
//!   with no arguments at all, and an empty payload is an empty array;
//! - an array element's offset may be negative, if it still lands inside the
//!   payload;
//! - a `bool` is true when the word's low 32 bits are not all zero;
//! - an `address` is `DataWord.valueOf(BigInteger.toByteArray())`, which
//!   drops a negative word's leading 0xFF bytes and pads with zeros;
//! - a `string` is UTF-8 with bad sequences replaced, never refused.
//!
//! Every reader returns `None` exactly where rskj's decoder throws, and none
//! of them can panic, whatever the payload.

use alloy_primitives::{Address, I256, U256};

/// An integer parameter as `IntType.decodeInt` leaves it: the word, read as
/// a signed `BigInteger`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Int(pub(crate) [u8; 32]);

impl Int {
    pub(crate) const ZERO: Int = Int([0; 32]);

    /// `BigInteger.intValue()`: the low 32 bits, as a signed int.
    pub(crate) fn int_value(&self) -> i32 {
        let w = &self.0;
        i32::from_be_bytes([w[28], w[29], w[30], w[31]])
    }

    /// `BigInteger.longValue()`: the low 64 bits, as a signed long.
    pub(crate) fn long_value(&self) -> i64 {
        let mut low = [0u8; 8];
        low.copy_from_slice(&self.0[24..]);
        i64::from_be_bytes(low)
    }

    /// `BigInteger.intValueExact()`: the number, if an int holds it.
    pub(crate) fn int_value_exact(&self) -> Option<i32> {
        self.fits(4).then(|| self.int_value())
    }

    /// `BigInteger.longValueExact()`: the number, if a long holds it.
    pub(crate) fn long_value_exact(&self) -> Option<i64> {
        self.fits(8).then(|| self.long_value())
    }

    /// `BigInteger.shortValueExact()`: the number, if a short holds it.
    pub(crate) fn short_value_exact(&self) -> Option<i16> {
        self.fits(2)
            .then(|| i16::from_be_bytes([self.0[30], self.0[31]]))
    }

    /// The number itself.
    pub(crate) fn signed(&self) -> I256 {
        I256::from_raw(U256::from_be_bytes(self.0))
    }

    /// Whether the word is its low `bytes` bytes, sign-extended.
    fn fits(&self, bytes: usize) -> bool {
        let fill = if self.0[32 - bytes] & 0x80 != 0 {
            0xFF
        } else {
            0
        };
        self.0[..32 - bytes].iter().all(|b| *b == fill)
    }
}

/// A call's payload after its selector, read as `Function.decode` reads it:
/// parameter `i`'s head is the word at `32 * i`, and a dynamic parameter's
/// head holds the offset of its data.
#[derive(Clone, Copy)]
pub(crate) struct Args<'a>(&'a [u8]);

impl<'a> Args<'a> {
    pub(crate) fn new(payload: &'a [u8]) -> Self {
        Args(payload)
    }

    /// An integer parameter: `IntType.decode`.
    pub(crate) fn int(&self, i: usize) -> Option<Int> {
        self.int_at(head(i))
    }

    /// A `bool` parameter: `BoolType.decode`, true when `intValue() != 0`.
    pub(crate) fn bool(&self, i: usize) -> Option<bool> {
        Some(self.int(i)?.int_value() != 0)
    }

    /// An `address` parameter: `AddressType.decode`, then
    /// `new RskAddress(DataWord)`, the word's last 20 bytes.
    pub(crate) fn address(&self, i: usize) -> Option<Address> {
        let word = data_word(&self.int(i)?);
        Some(Address::from_slice(&word[12..]))
    }

    /// A `bytes32` parameter: `Bytes32Type.decode`, which, unlike an
    /// integer, has no empty-payload case.
    pub(crate) fn bytes32(&self, i: usize) -> Option<[u8; 32]> {
        self.word_at(head(i))
    }

    /// A `bytes` parameter: `BytesType.decode` at the offset its head holds.
    pub(crate) fn bytes(&self, i: usize) -> Option<&'a [u8]> {
        self.bytes_at(self.offset(i)?)
    }

    /// A `string` parameter: `StringType.decode`, the bytes read as UTF-8
    /// with bad sequences replaced.
    pub(crate) fn string(&self, i: usize) -> Option<String> {
        self.bytes(i)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// A `bytes[]` parameter: `DynamicArrayType.decode` of `bytes`. Each
    /// element's head holds its offset from the first head, and
    /// `Math.addExact` lets that offset be negative.
    pub(crate) fn bytes_array(&self, i: usize) -> Option<Vec<&'a [u8]>> {
        self.array_at(self.offset(i)?, |args, heads, at| {
            args.bytes_at(heads + i64::from(args.int_at(at)?.int_value()))
        })
    }

    /// A `bytes32[]` parameter: `DynamicArrayType.decode` of `bytes32`.
    pub(crate) fn bytes32_array(&self, i: usize) -> Option<Vec<[u8; 32]>> {
        self.array_at(self.offset(i)?, |args, _, at| args.word_at(at))
    }

    /// Whether every parameter of `signature` decodes: `Function.decode`
    /// returning rather than throwing. `None` for a parameter type none of
    /// rskj's contracts use.
    pub(crate) fn decode(&self, signature: &str) -> Option<bool> {
        let mut decodes = true;
        for (i, param) in params(signature).enumerate() {
            decodes &= match param {
                "bool" => self.bool(i).is_some(),
                "address" => self.address(i).is_some(),
                "bytes" | "string" => self.bytes(i).is_some(),
                "bytes32" => self.bytes32(i).is_some(),
                "bytes[]" => self.bytes_array(i).is_some(),
                "bytes32[]" => self.bytes32_array(i).is_some(),
                "int256" | "uint256" => self.int(i).is_some(),
                _ => return None,
            };
        }
        Some(decodes)
    }

    /// Where a dynamic parameter's data starts: its head's `intValue()`.
    fn offset(&self, i: usize) -> Option<i64> {
        Some(i64::from(self.int(i)?.int_value()))
    }

    /// `Utils.safeCopyOfRange(encoded, from, size)`: throws unless both are
    /// non-negative and the range ends inside the payload.
    fn range(&self, from: i64, size: i64) -> Option<&'a [u8]> {
        let from = usize::try_from(from).ok()?;
        let size = usize::try_from(size).ok()?;
        self.0.get(from..from.checked_add(size)?)
    }

    fn word_at(&self, at: i64) -> Option<[u8; 32]> {
        self.range(at, 32)?.try_into().ok()
    }

    /// `IntType.decodeInt(encoded, at)`: an empty payload is zero wherever
    /// it is read.
    fn int_at(&self, at: i64) -> Option<Int> {
        if self.0.is_empty() {
            return Some(Int::ZERO);
        }
        self.word_at(at).map(Int)
    }

    /// `BytesType.decode(encoded, at)`: a length word, then that many bytes.
    fn bytes_at(&self, at: i64) -> Option<&'a [u8]> {
        let len = self.int_at(at)?.int_value();
        self.range(at + 32, i64::from(len))
    }

    /// `DynamicArrayType.decode(encoded, at)`: a count, then that many
    /// element heads, each read by `element(args, heads, head)`.
    fn array_at<T>(
        &self,
        at: i64,
        element: impl Fn(&Self, i64, i64) -> Option<T>,
    ) -> Option<Vec<T>> {
        if self.0.is_empty() {
            return Some(Vec::new());
        }
        let len = i64::from(self.int_at(at)?.int_value());
        let heads = at + 32;
        // `validateArrayAllegedSize`, a bound that only allows each element
        // a byte, and `new Object[len]`, which throws when len is negative.
        if len < 0 || heads + len > self.0.len() as i64 {
            return None;
        }
        (0..len)
            .map(|n| element(self, heads, heads + 32 * n))
            .collect()
    }
}

/// The head of parameter `i`. Every parameter's head is one word.
fn head(i: usize) -> i64 {
    32 * i as i64
}

/// The parameter types of a signature such as `name(bytes,int256)`.
fn params(signature: &str) -> impl Iterator<Item = &str> {
    let inner = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or("");
    inner.split(',').filter(|p| !p.is_empty())
}

/// `DataWord.valueOf(value.toByteArray())`. `toByteArray` gives a number's
/// shortest two's-complement form, so a negative word loses its leading 0xFF
/// bytes while the byte after each still has its top bit set, and
/// `DataWord.valueOf` pads what is left with zeros.
fn data_word(value: &Int) -> [u8; 32] {
    let word = value.0;
    if word[0] & 0x80 == 0 {
        return word;
    }
    let mut start = 0;
    while start < 31 && word[start] == 0xFF && word[start + 1] & 0x80 != 0 {
        start += 1;
    }
    let mut padded = [0u8; 32];
    padded[start..].copy_from_slice(&word[start..]);
    padded
}

/// `Function.encodeSignature()`: the first four bytes of the signature's
/// Keccak-256, as a call's payload starts.
pub(crate) fn selector(signature: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// `Function.encodeOutputs` of a single `bytes` or `string` result: the
/// offset of its data, its length, then the data padded to whole words.
///
/// `BytesType.encode` pads to `((len - 1) / 32 + 1) * 32` bytes, and Java's
/// `-1 / 32 == 0` gives an empty value a zero word of its own: 96 bytes, not
/// the ABI's 64. The word is consensus, since a caller's `RETURNDATACOPY`
/// pays for it (mainnet #1,669,062).
pub(crate) fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let padded = data.len().div_ceil(32).max(1) * 32;
    let mut out = Vec::with_capacity(64 + padded);
    out.extend_from_slice(&U256::from(32u8).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
    out.extend_from_slice(data);
    out.resize(64 + padded, 0);
    out
}

/// Arguments encoded as rskj's `CallTransaction` encodes them, for tests.
#[cfg(test)]
pub(crate) mod encode {
    use alloy_primitives::{I256, U256};

    /// One argument.
    pub(crate) enum Arg<'a> {
        Word([u8; 32]),
        Bytes(&'a [u8]),
        BytesArray(&'a [&'a [u8]]),
        /// `bytes32[]`.
        Words(&'a [[u8; 32]]),
    }

    /// A signed integer's word.
    pub(crate) fn int(n: i64) -> [u8; 32] {
        I256::try_from(n).unwrap().into_raw().to_be_bytes()
    }

    /// The arguments, heads then tails, each dynamic one's head its offset.
    pub(crate) fn args(args: &[Arg]) -> Vec<u8> {
        fn word(n: usize) -> [u8; 32] {
            U256::from(n).to_be_bytes()
        }
        fn bytes(data: &[u8]) -> Vec<u8> {
            let mut out = word(data.len()).to_vec();
            out.extend_from_slice(data);
            out.resize(32 + data.len().div_ceil(32) * 32, 0);
            out
        }
        let (mut heads, mut tails) = (Vec::new(), Vec::new());
        for arg in args {
            let tail = match arg {
                Arg::Word(w) => {
                    heads.extend_from_slice(w);
                    continue;
                }
                Arg::Bytes(data) => bytes(data),
                Arg::BytesArray(items) => {
                    let mut out = word(items.len()).to_vec();
                    let mut body = Vec::new();
                    for item in items.iter() {
                        out.extend_from_slice(&word(32 * items.len() + body.len()));
                        body.extend(bytes(item));
                    }
                    out.extend(body);
                    out
                }
                Arg::Words(words) => {
                    let mut out = word(words.len()).to_vec();
                    words.iter().for_each(|w| out.extend_from_slice(w));
                    out
                }
            };
            heads.extend_from_slice(&word(32 * args.len() + tails.len()));
            tails.extend(tail);
        }
        heads.extend(tails);
        heads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(n: u64) -> [u8; 32] {
        U256::from(n).to_be_bytes()
    }

    fn payload(words: &[[u8; 32]], tail: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = words.iter().flatten().copied().collect();
        out.extend_from_slice(tail);
        out
    }

    /// A negative number's word, as rskj's encoder writes it.
    fn negative(n: i64) -> [u8; 32] {
        I256::try_from(n).unwrap().into_raw().to_be_bytes()
    }

    #[test]
    fn an_offset_is_read_from_its_low_32_bits() {
        let mut offset = word(32);
        offset[0] = 0xFF;
        offset[23] = 1;
        let p = payload(&[offset, word(3)], b"abc");
        assert_eq!(Args::new(&p).bytes(0), Some(&b"abc"[..]));
    }

    #[test]
    fn a_length_is_read_from_its_low_32_bits() {
        let mut len = word(3);
        len[4] = 0x7F;
        let p = payload(&[word(32), len], b"abc");
        assert_eq!(Args::new(&p).bytes(0), Some(&b"abc"[..]));
    }

    #[test]
    fn a_negative_offset_or_length_throws() {
        assert_eq!(Int(negative(-32)).int_value(), -32);
        let p = payload(&[negative(-32), word(0)], &[]);
        assert_eq!(Args::new(&p).bytes(0), None);
        let p = payload(&[word(32), [0xFF; 32]], &[]);
        assert_eq!(Args::new(&p).bytes(0), None);
    }

    #[test]
    fn bytes_must_end_inside_the_payload() {
        let p = payload(&[word(32), word(4)], b"abc");
        assert_eq!(Args::new(&p).bytes(0), None);
        let p = payload(&[word(32)], &[]);
        assert_eq!(Args::new(&p).bytes(0), None, "no length word");
    }

    #[test]
    fn an_empty_payload_reads_as_zero_for_integers_and_nothing_else() {
        let args = Args::new(&[]);
        assert_eq!(args.int(0), Some(Int::ZERO));
        assert_eq!(args.int(3), Some(Int::ZERO));
        assert_eq!(args.bool(1), Some(false));
        assert_eq!(args.address(0), Some(Address::ZERO));
        assert_eq!(args.bytes32(0), None);
        assert_eq!(args.bytes(0), None);
        assert_eq!(args.bytes_array(0), Some(Vec::new()));
        assert_eq!(args.bytes32_array(0), Some(Vec::new()));
    }

    #[test]
    fn a_short_payload_is_not_an_empty_one() {
        let args = Args::new(&[0u8; 31]);
        assert_eq!(args.int(0), None);
        assert_eq!(args.bool(0), None);
    }

    #[test]
    fn an_array_elements_offset_may_be_negative() {
        // The heads start at 64. Element 0's offset, 64, puts its length at
        // 128; element 1's, -32, puts it at 32, the array's count word, so
        // element 1 is the two bytes after it.
        let p = payload(
            &[word(32), word(2), word(64), negative(-32), word(1)],
            &[0xAB; 32],
        );
        let elements = Args::new(&p).bytes_array(0).unwrap();
        assert_eq!(elements[0], &[0xAB][..]);
        assert_eq!(elements[1], &p[64..66]);
    }

    #[test]
    fn an_array_count_must_be_non_negative_and_fit() {
        let p = payload(&[word(32), [0xFF; 32]], &[]);
        assert_eq!(Args::new(&p).bytes32_array(0), None);
        let p = payload(&[word(32), word(2)], &[0u8; 32]);
        assert_eq!(Args::new(&p).bytes32_array(0), None, "one element of two");
        let p = payload(&[word(32), word(2), word(7), word(9)], &[]);
        assert_eq!(Args::new(&p).bytes32_array(0), Some(vec![word(7), word(9)]));
    }

    #[test]
    fn a_bool_looks_only_at_the_low_32_bits() {
        let mut high = [0u8; 32];
        high[27] = 1;
        assert_eq!(Args::new(&high).bool(0), Some(false));
        assert_eq!(Args::new(&word(1 << 31)).bool(0), Some(true));
    }

    #[test]
    fn a_negative_address_word_loses_its_leading_ff_bytes() {
        let mut w = [0xFF; 32];
        w[13] = 0xAB;
        let address = Args::new(&w).address(0).unwrap();
        assert_eq!(address.as_slice()[0], 0, "the 0xFF before 0xAB is dropped");
        assert_eq!(&address.as_slice()[1..], &w[13..]);
        let mut w = [0xFF; 32];
        w[12] = 0x12;
        assert_eq!(Args::new(&w).address(0).unwrap().as_slice(), &w[12..]);
        assert_eq!(
            Args::new(&[0xFF; 32]).address(0).unwrap(),
            Address::with_last_byte(0xFF)
        );
    }

    #[test]
    fn a_string_with_bad_utf8_still_decodes() {
        let p = payload(&[word(32), word(2)], &[0xFF, b'a']);
        assert_eq!(Args::new(&p).string(0).as_deref(), Some("\u{FFFD}a"));
    }

    #[test]
    fn conversions_are_javas() {
        let minus_one = Int([0xFF; 32]);
        assert_eq!(minus_one.int_value(), -1);
        assert_eq!(minus_one.long_value_exact(), Some(-1));
        assert_eq!(minus_one.signed(), I256::MINUS_ONE);
        let mut big = word(5);
        big[0] = 1;
        assert_eq!(Int(big).int_value(), 5);
        assert_eq!(Int(big).long_value(), 5);
        assert_eq!(Int(big).long_value_exact(), None);
        assert_eq!(Int(word(1 << 31)).int_value_exact(), None);
        assert_eq!(Int(word(1 << 31)).int_value(), i32::MIN);
        assert_eq!(Int(word((1 << 31) - 1)).int_value_exact(), Some(i32::MAX));
        assert_eq!(Int(word(1 << 63)).long_value_exact(), None);
        assert_eq!(Int(word(32_767)).short_value_exact(), Some(i16::MAX));
        assert_eq!(Int(word(32_768)).short_value_exact(), None);
        assert_eq!(Int(negative(-32_768)).short_value_exact(), Some(i16::MIN));
        assert_eq!(Int(negative(-32_769)).short_value_exact(), None);
        assert_eq!(minus_one.short_value_exact(), Some(-1));
    }

    #[test]
    fn decode_walks_every_parameter() {
        let p = payload(&[word(64), word(9), word(1)], &[0x11]);
        assert_eq!(Args::new(&p).decode("f(bytes,int256)"), Some(true));
        assert_eq!(Args::new(&p).decode("f(bytes,int256,bytes32)"), Some(true));
        assert_eq!(
            Args::new(&p).decode("f(bytes,int256,bytes32,bytes32)"),
            Some(false)
        );
        assert_eq!(Args::new(&[]).decode("f()"), Some(true));
        assert_eq!(Args::new(&[]).decode("f(int256,bool,address)"), Some(true));
        assert_eq!(Args::new(&[]).decode("f(bytes32)"), Some(false));
        assert_eq!(Args::new(&[]).decode("f(int256[])"), None);
    }

    /// Both selectors as solc compiled them into rskj's own test contracts
    /// (`dsl/nested_environment_calls.txt`).
    #[test]
    fn a_selector_is_keccak_of_the_signature() {
        assert_eq!(selector("getCallStackDepth()"), [0xe8, 0xce, 0x22, 0x74]);
        assert_eq!(
            selector("callGetCallStackDepth()"),
            [0x6e, 0xad, 0x0b, 0x33]
        );
    }

    #[test]
    fn an_empty_bytes_result_takes_a_zero_word_of_its_own() {
        let empty = encode_bytes(&[]);
        assert_eq!(empty, payload(&[word(32), word(0), word(0)], &[]));
        let mut one = payload(&[word(32), word(1)], &[0xAB]);
        one.resize(96, 0);
        assert_eq!(encode_bytes(&[0xAB]), one);
        assert_eq!(encode_bytes(&[1; 32]).len(), 96);
        assert_eq!(encode_bytes(&[1; 33]).len(), 128);
        assert_eq!(&encode_bytes(&[1; 33])[32..64], &word(33));
    }
}
