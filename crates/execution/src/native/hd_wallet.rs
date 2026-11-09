//! HDWalletUtils (0x01000009, RSKIP106): rskj's `co.rsk.pcc.bto`, on
//! bitcoinj's BIP32 and base58 code.

use bitcoin::hashes::{hash160, hmac, sha512, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, VerifyOnly};

use super::{Failure, NativeContract};
use crate::abi::{encode_bytes, Args, Int};

/// The contract. It reads nothing but its arguments.
pub(crate) struct HdWalletUtils;

/// A method with its arguments.
pub(crate) enum Call {
    /// `toBase58Check(bytes hash, int256 version) returns (string)`
    ToBase58Check { hash: Vec<u8>, version: Int },
    /// `deriveExtendedPublicKey(string xpub, string path) returns (string)`
    DeriveExtendedPublicKey { xpub: String, path: String },
    /// `extractPublicKeyFromExtendedPublicKey(string xpub) returns (bytes)`
    ExtractPublicKey { xpub: String },
    /// `getMultisigScriptHash(int256 minimumSignatures, bytes[] keys)
    /// returns (bytes)`
    GetMultisigScriptHash {
        minimum_signatures: Int,
        keys: Vec<Vec<u8>>,
    },
}

#[derive(Clone, Copy)]
enum Method {
    ToBase58Check,
    DeriveExtendedPublicKey,
    ExtractPublicKey,
    GetMultisigScriptHash,
}

/// `HDWalletUtils.getMethods`, by signature.
const METHODS: [(&str, Method); 4] = [
    ("toBase58Check(bytes,int256)", Method::ToBase58Check),
    (
        "deriveExtendedPublicKey(string,string)",
        Method::DeriveExtendedPublicKey,
    ),
    (
        "extractPublicKeyFromExtendedPublicKey(string)",
        Method::ExtractPublicKey,
    ),
    (
        "getMultisigScriptHash(int256,bytes[])",
        Method::GetMultisigScriptHash,
    ),
];

impl NativeContract for HdWalletUtils {
    type Call = Call;

    fn parse(&self, selector: [u8; 4], args: &[u8]) -> Option<Call> {
        let args = Args::new(args);
        Some(match super::method(&METHODS, selector)? {
            Method::ToBase58Check => Call::ToBase58Check {
                hash: args.bytes(0)?.to_vec(),
                version: args.int(1)?,
            },
            Method::DeriveExtendedPublicKey => Call::DeriveExtendedPublicKey {
                xpub: args.string(0)?,
                path: args.string(1)?,
            },
            Method::ExtractPublicKey => Call::ExtractPublicKey {
                xpub: args.string(0)?,
            },
            Method::GetMultisigScriptHash => Call::GetMultisigScriptHash {
                minimum_signatures: args.int(0)?,
                keys: args
                    .bytes_array(1)?
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
            },
        })
    }

    fn gas(&self, call: &Call, _input: &[u8]) -> u64 {
        match call {
            Call::ToBase58Check { .. } => 13_000,
            Call::DeriveExtendedPublicKey { .. } => 107_000,
            Call::ExtractPublicKey { .. } => 11_300,
            // 20,000 covers the two keys a script needs, and each one more is
            // 700, however many the call names.
            Call::GetMultisigScriptHash { keys, .. } => (keys.len() as u64)
                .saturating_sub(2)
                .saturating_mul(700)
                .saturating_add(20_000),
        }
    }

    fn execute(&self, call: Call) -> Result<Vec<u8>, Failure> {
        match call {
            Call::ToBase58Check { hash, version } => to_base58_check(&hash, version),
            Call::DeriveExtendedPublicKey { xpub, path } => {
                let secp = Secp256k1::verification_only();
                let mut key = ExtendedKey::from_base58(&xpub)?;
                for index in derivation_path(&path)? {
                    key = key.child(&secp, index)?;
                }
                Ok(encode_bytes(key.to_base58().as_bytes()))
            }
            Call::ExtractPublicKey { xpub } => Ok(encode_bytes(
                &ExtendedKey::from_base58(&xpub)?.key.serialize(),
            )),
            Call::GetMultisigScriptHash {
                minimum_signatures,
                keys,
            } => multisig_script_hash(minimum_signatures, &keys),
        }
    }
}

/// `ToBase58Check.execute`: a 20-byte hash behind a version byte, in
/// base58check.
fn to_base58_check(hash: &[u8], version: Int) -> Result<Vec<u8>, Failure> {
    if hash.len() != 20 {
        return Err(Failure::threw("a hash160 is 20 bytes"));
    }
    // `intValueExact`, then a check for 0 to 255.
    let version = version
        .int_value_exact()
        .and_then(|version| u8::try_from(version).ok())
        .ok_or_else(|| Failure::threw("a version is a number from 0 to 255"))?;
    let mut payload = vec![version];
    payload.extend_from_slice(hash);
    Ok(encode_bytes(
        bitcoin::base58::encode_check(&payload).as_bytes(),
    ))
}

/// `GetMultisigScriptHash.execute`: the hash160 of the redeem script bitcoinj's
/// `ScriptBuilder.createRedeemScript` builds, `OP_m`, the keys compressed and
/// sorted by their bytes, `OP_n` and `OP_CHECKMULTISIG`.
fn multisig_script_hash(minimum_signatures: Int, keys: &[Vec<u8>]) -> Result<Vec<u8>, Failure> {
    const OP_0: u8 = 0x50;
    const OP_CHECKMULTISIG: u8 = 0xAE;
    let required = minimum_signatures
        .int_value_exact()
        .filter(|required| *required > 0)
        .ok_or_else(|| Failure::threw("at least one signature is required"))?;
    if keys.len() < 2 {
        return Err(Failure::threw("at least 2 public keys are required"));
    }
    if (keys.len() as u64) < u64::from(required.unsigned_abs()) {
        return Err(Failure::threw("fewer keys than required signatures"));
    }
    if keys.len() > 15 {
        return Err(Failure::threw("at most 15 public keys are allowed"));
    }
    let mut compressed = keys
        .iter()
        .map(|key| compressed_key(key))
        .collect::<Result<Vec<_>, _>>()?;
    compressed.sort_unstable();
    // Both counts are 1 to 15 here, so each is a single opcode.
    let mut script = vec![OP_0 + required.unsigned_abs() as u8];
    for key in &compressed {
        script.push(33);
        script.extend_from_slice(key);
    }
    script.push(OP_0 + compressed.len() as u8);
    script.push(OP_CHECKMULTISIG);
    Ok(encode_bytes(hash160::Hash::hash(&script).as_byte_array()))
}

/// A key as `BtcECKey.fromPublicOnly` reads it, compressed: 33 bytes, or 65
/// uncompressed or hybrid, and a point on the curve. BouncyCastle's
/// `decodePoint` and libsecp256k1 take the same encodings.
fn compressed_key(key: &[u8]) -> Result<[u8; 33], Failure> {
    if key.len() != 33 && key.len() != 65 {
        return Err(Failure::threw("a public key is 33 or 65 bytes"));
    }
    PublicKey::from_slice(key)
        .map(|key| key.serialize())
        .map_err(|_| Failure::threw("not a public key"))
}

/// `getBip32HeaderPub` of bitcoinj's MainNet and TestNet3, the networks an
/// `xpub` and a `tpub` prefix name.
const MAINNET: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const TESTNET: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];

/// An extended public key, as bitcoinj's `DeterministicKey` reads and writes
/// one.
struct ExtendedKey {
    /// The network's public header, which the key is read with and written
    /// with.
    header: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: [u8; 4],
    chain_code: [u8; 32],
    key: PublicKey,
}

impl ExtendedKey {
    /// `validateAndExtractNetworkFromExtendedPublicKey`, then
    /// `DeterministicKey.deserializeB58` and the point its key bytes encode.
    /// bitcoinj takes any depth, fingerprint and child number.
    fn from_base58(text: &str) -> Result<Self, Failure> {
        let header = if text.starts_with("xpub") {
            MAINNET
        } else if text.starts_with("tpub") {
            TESTNET
        } else {
            return Err(Failure::threw(
                "an extended public key starts with xpub or tpub",
            ));
        };
        let data =
            bitcoin::base58::decode_check(text).map_err(|_| Failure::threw("not base58check"))?;
        let data: [u8; 78] = data
            .try_into()
            .map_err(|_| Failure::threw("an extended key is 78 bytes"))?;
        // bitcoinj would take the network's private header too, but a key
        // written with it is spelled xprv or tprv, never xpub or tpub.
        if data[..4] != header {
            return Err(Failure::threw("not an extended public key of the network"));
        }
        let key =
            PublicKey::from_slice(&data[45..]).map_err(|_| Failure::threw("not a public key"))?;
        Ok(Self {
            header,
            depth: data[4],
            parent_fingerprint: field(&data, 5),
            child_number: field(&data, 9),
            chain_code: field(&data, 13),
            key,
        })
    }

    /// `HDKeyDerivation.deriveChildKey` from the public key alone: BIP32's
    /// CKDpub, at an index below 2^31.
    fn child(&self, secp: &Secp256k1<VerifyOnly>, index: u32) -> Result<Self, Failure> {
        let parent = self.key.serialize();
        let mut engine = hmac::HmacEngine::<sha512::Hash>::new(&self.chain_code);
        engine.input(&parent);
        engine.input(&index.to_be_bytes());
        let i = hmac::Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
        let tweak = Scalar::from_be_bytes(field(&i, 0))
            .map_err(|_| Failure::threw("I_L is not below the curve's order"))?;
        let key = self
            .key
            .add_exp_tweak(secp, &tweak)
            .map_err(|_| Failure::threw("the derived key is the point at infinity"))?;
        Ok(Self {
            header: self.header,
            // bitcoinj counts the depth in an int and writes its low byte.
            depth: self.depth.wrapping_add(1),
            parent_fingerprint: field(hash160::Hash::hash(&parent).as_byte_array(), 0),
            child_number: index.to_be_bytes(),
            chain_code: field(&i, 32),
            key,
        })
    }

    /// `DeterministicKey.serializePubB58`.
    fn to_base58(&self) -> String {
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&self.header);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number);
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&self.key.serialize());
        bitcoin::base58::encode_check(&data)
    }
}

/// The `N` bytes of `data` from `at`, a fixed place inside it.
fn field<const N: usize>(data: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&data[at..at + N]);
    out
}

/// The path checks of `DeriveExtendedPublicKey.execute`, then bitcoinj's
/// `HDUtils.parsePath`: one to ten indices with slashes between them, each a
/// string Java's `Integer.parseInt` reads as 0 or more.
///
/// Java sees the path as UTF-16. Its first and last code units must each be
/// a digit, so neither end of `split("/")` is empty.
fn derivation_path(path: &str) -> Result<Vec<u32>, Failure> {
    let invalid = || Failure::threw("invalid path");
    let units: Vec<u16> = path.encode_utf16().collect();
    let (Some(first), Some(last)) = (units.first(), units.last()) else {
        return Err(invalid());
    };
    if !is_decimal(&[*first]) || !is_decimal(&[*last]) {
        return Err(invalid());
    }
    let chunks: Vec<&[u16]> = units.split(|unit| *unit == u16::from(b'/')).collect();
    if chunks.len() > 10 {
        return Err(Failure::threw("a path has 10 levels at most"));
    }
    chunks
        .into_iter()
        .map(|chunk| {
            parse_int(chunk)
                .and_then(|index| u32::try_from(index).ok())
                .ok_or_else(invalid)
        })
        .collect()
}

/// `DeriveExtendedPublicKey.isDecimal`: `Integer.parseInt(s) >= 0`.
fn is_decimal(units: &[u16]) -> bool {
    parse_int(units).is_some_and(|n| n >= 0)
}

/// Java's `Integer.parseInt(s)`: an optional sign, when more follows it, then
/// decimal digits of any script, the value fitting an int.
fn parse_int(units: &[u16]) -> Option<i32> {
    let (negative, digits) = match units.split_first()? {
        (sign, rest) if *sign == u16::from(b'-') => (true, rest),
        (sign, rest) if *sign == u16::from(b'+') => (false, rest),
        _ => (false, units),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for unit in digits {
        value = value * 10 + i64::from(digit(*unit)?);
        if value > 1 << 31 {
            return None;
        }
    }
    i32::try_from(if negative { -value } else { value }).ok()
}

/// `Character.digit(char, 10)`: the value of a decimal digit of any script in
/// the Basic Multilingual Plane. A digit beyond it is two `char`s to Java, and
/// neither is a digit.
fn digit(unit: u16) -> Option<u32> {
    ZEROS
        .iter()
        .find_map(|zero| unit.checked_sub(*zero).filter(|value| *value < 10))
        .map(u32::from)
}

/// The first of each run of ten decimal digits (Unicode's Nd) in the Basic
/// Multilingual Plane. Unicode 13 to 16 have the same ones, so every Java
/// rskj runs on does.
const ZEROS: [u16; 37] = [
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
    0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
    0xFF10,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::encode::{self, Arg};
    use crate::native::{call, Outcome};

    /// The keys of rskj's own tests.
    const TPUB: &str = "tpubD6NzVbkrYhZ4YHQqwWz3Tm1ESZ9AidobeyLG4mEezB6hN8gFFWrcjczyF77Lw3HEs6Rjd2R11BEJ8Y9ptfxx9DFknkdujp58mFMx9H5dc1r";
    const XPUB: &str = "xpub661MyMwAqRbcFMGNG2YcHvj3x63bAZN9U5cKikaiQ4zu2D1cvpnZYyXNR9nH62sGp4RR39Ui7SVQSq1PY4JbPuEuu5prVJJC3d5Pogft712";

    fn input(signature: &str, args: &[Arg]) -> Vec<u8> {
        let mut input = crate::abi::selector(signature).to_vec();
        input.extend(encode::args(args));
        input
    }

    fn run(input: &[u8]) -> Outcome {
        call(&HdWalletUtils, input, u64::MAX)
    }

    /// The one `bytes` or `string` a call returned.
    fn returned(outcome: Outcome) -> Vec<u8> {
        match outcome {
            Outcome::Returned { output, .. } => crate::abi::Args::new(&output)
                .bytes(0)
                .expect("a bytes result")
                .to_vec(),
            other => panic!("expected a result, got {other:?}"),
        }
    }

    /// Whether a call threw after it was charged `gas`.
    fn threw(gas: u64, outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Threw { gas: charged, .. } if *charged == gas)
    }

    fn derive(xpub: &str, path: &str) -> Outcome {
        run(&input(
            "deriveExtendedPublicKey(string,string)",
            &[Arg::Bytes(xpub.as_bytes()), Arg::Bytes(path.as_bytes())],
        ))
    }

    fn derived(xpub: &str, path: &str) -> String {
        String::from_utf8(returned(derive(xpub, path))).unwrap()
    }

    fn extract(xpub: &[u8]) -> Outcome {
        run(&input(
            "extractPublicKeyFromExtendedPublicKey(string)",
            &[Arg::Bytes(xpub)],
        ))
    }

    fn base58_check(hash: &[u8], version: i64) -> Outcome {
        run(&input(
            "toBase58Check(bytes,int256)",
            &[Arg::Bytes(hash), Arg::Word(encode::int(version))],
        ))
    }

    fn multisig(required: i64, keys: &[Vec<u8>]) -> Outcome {
        let keys: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        run(&input(
            "getMultisigScriptHash(int256,bytes[])",
            &[Arg::Word(encode::int(required)), Arg::BytesArray(&keys)],
        ))
    }

    /// rskj's `GetMultisigScriptHashTest` keys.
    fn keys() -> Vec<Vec<u8>> {
        [
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
            "027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344",
            "0355a2e9bf100c00fc0a214afd1bf272647c7824eb9cb055480962f0c382596a70",
            "02566d5ded7c7db1aa7ee4ef6f76989fb42527fcfdcddcd447d6793b7d869e46f7",
            "0294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc",
            "0372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6",
            "0340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44",
            "02ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eb",
            "031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26",
            "0245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeea",
            "02550cc87fa9061162b1dd395a16662529c9d8094c0feca17905a3244713d65fe8",
            "02481f02b7140acbf3fcdd9f72cf9a7d9484d8125e6df7c9451cfa55ba3b077265",
            "03f909ae15558c70cc751aff9b1f495199c325b13a9e5b934fd6299cd30ec50be8",
            "02c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259",
            "03b65694ccccda83cbb1e56b31308acd08e993114c33f66a456b627c2c1c68bed6",
        ]
        .iter()
        .map(|key| hex::decode(key).unwrap())
        .collect()
    }

    #[test]
    fn a_hash_and_a_version_make_a_base58check_address() {
        let hash = hex::decode("0d3bf5f30dda7584645546079318e97f0e1d044f").unwrap();
        let outcome = base58_check(&hash, 111);
        assert!(matches!(outcome, Outcome::Returned { gas: 13_000, .. }));
        assert_eq!(returned(outcome), b"mgivuh9jErcGdRr81cJ3A7YfgbJV7WNyZV");
        let (short, zero) = ([0xAA; 19], [0; 20]);
        for (hash, version) in [
            (&short[..], 111),
            (&zero[..], -1),
            (&zero[..], 256),
            (&zero[..], 1 << 40),
        ] {
            assert!(threw(13_000, &base58_check(hash, version)), "{version}");
        }
    }

    /// rskj's `DeriveExtendedPublicKeyTest`.
    #[test]
    fn a_tpub_derives_as_rskjs_tests_say() {
        assert_eq!(
            derived(TPUB, "2/3/4"),
            "tpubDCGMkPKredy7oh6zw8f4ExWFdTgQCrAHToF1ytny3gbVy9GkUNK2Nqh7NbKbh8dkd5VtjUiLJPkbEkeg29NVHwxYwzHJFt9SazGLZrrU4Y4"
        );
        assert_eq!(
            derived(TPUB, "0/0/0/0/0/0"),
            "tpubDJ28nwFGUypUD6i8eGCQfMkwNGxzzabA5Mh7AcUdwm6ziFxCSWjy4HyhPXH5uU2ovdMMYLT9W3g3MrGo52TrprMvX8o1dzT2ZGz1pwCPTNv"
        );
        assert_eq!(
            derived(TPUB, "2147483647"),
            "tpubD8fY35uPCY1rUjMUZwhkGUFi33pwkffMEBaCsTSw1he2AbM6DMbPaRR2guvk5qTWDfE9ubFB5pzuUNnMtsqbCeKAAjfepSvEWyetyF9Q4fG"
        );
        assert!(matches!(
            derive(TPUB, "2/3/4"),
            Outcome::Returned { gas: 107_000, .. }
        ));
        assert!(derived(XPUB, "0/9").starts_with("xpub"));
        assert!(threw(
            107_000,
            &derive("this-is-not-an-xpub", "this-doesnt-matter")
        ));
    }

    /// Java's `Integer.parseInt` takes a sign before an index that is not the
    /// first, leading zeros, and decimal digits of any script in the Basic
    /// Multilingual Plane.
    #[test]
    fn a_path_is_read_as_javas_parse_int_reads_it() {
        assert_eq!(derived(TPUB, "1/-0"), derived(TPUB, "1/0"));
        assert_eq!(derived(TPUB, "1/+5"), derived(TPUB, "1/5"));
        assert_eq!(derived(TPUB, "00/007"), derived(TPUB, "0/7"));
        assert_eq!(derived(TPUB, "\u{0661}/\u{0662}"), derived(TPUB, "1/2"));
        assert_eq!(derived(TPUB, "\u{FF11}"), derived(TPUB, "1"));
        assert!(matches!(
            derive(TPUB, "0/1/2/3/4/5/6/7/8/9"),
            Outcome::Returned { .. }
        ));
        for path in [
            "this-is-not-a-path",
            "",
            "M/0/1/2",
            "/0",
            "0/",
            "4'/5",
            "0/-1",
            "-0",
            "+5",
            "1//2",
            "1/ 2",
            "0/1/2/2147483648",
            "0/1/2/3/4/5/6/7/8/9/10",
            "\u{1D7CF}",
            "1/\u{1D7CF}",
        ] {
            assert!(threw(107_000, &derive(TPUB, path)), "{path:?}");
        }
    }

    /// bitcoinj writes a depth's low byte, so the child of a depth-255 key has
    /// depth 0.
    #[test]
    fn a_depth_past_255_wraps() {
        let mut data = bitcoin::base58::decode_check(TPUB).unwrap();
        data[4] = 255;
        let deep = bitcoin::base58::encode_check(&data);
        assert!(deep.starts_with("tpub"));
        let child = bitcoin::base58::decode_check(&derived(&deep, "0")).unwrap();
        let mut expected = bitcoin::base58::decode_check(&derived(TPUB, "0")).unwrap();
        assert_eq!(expected[4], 1);
        expected[4] = 0;
        assert_eq!(child, expected);
    }

    /// rskj's `ExtractPublicKeyFromExtendedPublicKeyTest`, and keys it refuses.
    #[test]
    fn an_xpub_gives_its_compressed_key() {
        let outcome = extract(XPUB.as_bytes());
        assert!(matches!(outcome, Outcome::Returned { gas: 11_300, .. }));
        assert_eq!(
            hex::encode(returned(outcome)),
            "02be517550b9e3be7fe42c80932d51e88e698663b4926e598b269d050e87e34d8c"
        );
        let mut header = bitcoin::base58::decode_check(XPUB).unwrap();
        header[3] += 1;
        let mut point = bitcoin::base58::decode_check(XPUB).unwrap();
        point[45] = 0x04;
        for xpub in [
            "this-is-not-an-xpub".to_string(),
            TPUB.replace("dc1r", "dc1s"),
            "xpub".to_string(),
            bitcoin::base58::encode_check(&header),
            bitcoin::base58::encode_check(&point),
        ] {
            assert!(threw(11_300, &extract(xpub.as_bytes())), "{xpub}");
        }
        // A string that is not UTF-8 still decodes, and then is no key.
        assert!(threw(11_300, &extract(&[b'x', b'p', b'u', b'b', 0xFF])));
    }

    /// rskj's `GetMultisigScriptHashTest`.
    #[test]
    fn fifteen_keys_hash_as_rskjs_test_says() {
        let outcome = multisig(8, &keys());
        assert!(matches!(outcome, Outcome::Returned { gas: 29_100, .. }));
        assert_eq!(
            hex::encode(returned(outcome)),
            "51f103320b435b5fe417b3f3e0f18972ccc710a0"
        );
    }

    /// A key may also come uncompressed, or in the hybrid form whose prefix
    /// says whether y is odd; either is compressed first.
    #[test]
    fn every_encoding_of_a_key_hashes_the_same() {
        let mut keys = keys();
        keys[0] = hex::decode("04b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2aafaaa2611606699ec4f82777a268b708dab346de4880cd223969f7bbe5422bf").unwrap();
        keys[4] = hex::decode("0694c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adcb17171aa9ec8d8587098e0771f686ee61ac35279f9e5aadf9b06b738aa6d3720").unwrap();
        keys[6] = hex::decode("0740df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44e1abebaea4c3c57c6e9e39e205b4df046f7110a8d3477c0d8e26a28be9692c29").unwrap();
        keys[9] = hex::decode("0445ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeeae024d50312de76a7950f8c6268fbf454335cf252f961a67c47e67dc06fa590ba").unwrap();
        assert_eq!(
            hex::encode(returned(multisig(8, &keys))),
            "51f103320b435b5fe417b3f3e0f18972ccc710a0"
        );
        // A hybrid prefix that names the wrong parity is no key.
        keys[4][0] = 0x07;
        assert!(threw(29_100, &multisig(8, &keys)));
    }

    #[test]
    fn a_multisig_needs_2_to_15_keys_and_at_least_m() {
        let keys = keys();
        assert!(matches!(
            multisig(1, &keys[..2]),
            Outcome::Returned { gas: 20_000, .. }
        ));
        for (required, keys) in [
            (0, &keys[..2]),
            (-1, &keys[..2]),
            (1 << 40, &keys[..2]),
            (1, &keys[..1]),
            (3, &keys[..2]),
        ] {
            assert!(threw(20_000, &multisig(required, keys)), "{required}");
        }
        let mut sixteen = keys.clone();
        sixteen.push(keys[0].clone());
        assert!(threw(29_800, &multisig(3, &sixteen)));
        let mut odd = keys[..2].to_vec();
        odd[1] = vec![0xAA, 0xBB, 0xCC];
        assert!(threw(20_000, &multisig(1, &odd)));
        odd[1] = keys[0].clone();
        odd[1][0] = 0x08;
        assert!(threw(20_000, &multisig(1, &odd)));
    }

    /// Offsets and counts are a word's low 32 bits to rskj: the offsets that
    /// once wrapped here, a count of 2^32 that was once allocated, and an
    /// offset with its high bytes set.
    #[test]
    fn a_crafted_offset_or_count_reads_as_rskj_reads_it() {
        let mut wrap = [0u8; 32];
        wrap[24..].copy_from_slice(&(u64::MAX - 31).to_be_bytes());
        let mut payload = crate::abi::selector("toBase58Check(bytes,int256)").to_vec();
        payload.extend_from_slice(&wrap);
        payload.extend_from_slice(&encode::int(111));
        assert!(threw(0, &run(&payload)), "an offset of -32 holds nothing");
        let multisig_at = |offset: [u8; 32], tail: &[[u8; 32]]| {
            let mut payload =
                crate::abi::selector("getMultisigScriptHash(int256,bytes[])").to_vec();
            payload.extend_from_slice(&encode::int(1));
            payload.extend_from_slice(&offset);
            tail.iter().for_each(|word| payload.extend_from_slice(word));
            run(&payload)
        };
        assert!(threw(0, &multisig_at(wrap, &[])));
        assert!(
            threw(
                20_000,
                &multisig_at(encode::int(64), &[encode::int(1 << 32)])
            ),
            "no keys at all"
        );
        let hash = hex::decode("0d3bf5f30dda7584645546079318e97f0e1d044f").unwrap();
        let mut payload = input(
            "toBase58Check(bytes,int256)",
            &[Arg::Bytes(&hash), Arg::Word(encode::int(111))],
        );
        payload[4] = 0xFF;
        assert_eq!(
            returned(run(&payload)),
            b"mgivuh9jErcGdRr81cJ3A7YfgbJV7WNyZV"
        );
    }

    /// No payload makes a method panic, whatever its words hold.
    #[test]
    fn no_payload_panics() {
        let mut wrap = [0u8; 32];
        wrap[24..].copy_from_slice(&(u64::MAX - 31).to_be_bytes());
        let words: Vec<[u8; 32]> = [
            0,
            1,
            20,
            32,
            33,
            64,
            96,
            -1,
            -32,
            i64::from(i32::MAX),
            i64::from(i32::MIN),
            1 << 32,
            (1 << 32) + 64,
        ]
        .into_iter()
        .map(encode::int)
        .chain([[0xFF; 32], wrap])
        .collect();
        for (signature, _) in METHODS {
            for a in &words {
                for b in &words {
                    for c in &words {
                        let mut payload = crate::abi::selector(signature).to_vec();
                        [a, b, c]
                            .iter()
                            .for_each(|word| payload.extend_from_slice(*word));
                        payload.extend_from_slice(b"tpubD6NzVbkrYhZ4Y");
                        for len in [36, 68, payload.len()] {
                            let _ = run(&payload[..len]);
                        }
                    }
                }
            }
        }
    }
}
