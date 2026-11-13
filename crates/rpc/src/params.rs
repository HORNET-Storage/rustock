//! rskj's typed parameters (`org.ethereum.rpc.parameters`): what each takes,
//! and the error rskj answers for what it doesn't.
//!
//! jsonrpc4j converts a call's parameters to the method's parameter types
//! before the method runs (`JsonRpcBasicServer.convertJsonToParameters`), so
//! these refusals come before anything the method itself says. What a
//! parameter's constructor throws is an `RskJsonRpcRequestException`, which
//! `RskErrorResolver` answers with its own code and message; anything else
//! thrown on the way is `-32603 Internal server error`, but for what Jackson
//! itself throws where it can't make a parameter of its type, which
//! jsonrpc4j takes for a request it couldn't parse ([`unparsed`]).
//!
//! Each answer here is the release's own: its parameter classes and its
//! error resolver were run on the values the tests use, and so was its
//! server, over its `Web3RskImpl`, on whole requests.

use alloy_primitives::{Address, U256};
use serde_json::Value;

use crate::helpers::{abbreviated, hex_to_bytes, is_lower_hex};
use crate::types::{INTERNAL_ERROR, INVALID_PARAMS, PARSE_ERROR};

/// The code and message rskj answers in place of a result.
pub type Refusal = (i64, String);

fn invalid(message: impl Into<String>) -> Refusal {
    (INVALID_PARAMS, message.into())
}

/// What rskj answers where something is thrown that nothing catches.
pub fn uncaught() -> Refusal {
    (INTERNAL_ERROR, "Internal server error".to_string())
}

/// What rskj answers where Jackson can't make a parameter of its type: a
/// `JsonMappingException`, which jsonrpc4j takes for a request it couldn't
/// parse (`JsonRpcBasicServer.handleRequest`). The answer names no request:
/// its id is the string [`UNPARSED_ID`], whatever the request's was.
pub fn unparsed() -> Refusal {
    (PARSE_ERROR, "JSON parse error".to_string())
}

/// The id of jsonrpc4j's answer to a request it couldn't parse: the word
/// `null` as a string, not a JSON `null`.
pub const UNPARSED_ID: &str = "null";

/// The text a parameter's deserializer reads (`jp.getText()`): a string as it
/// is, a number as Jackson prints it back ([`number_text`]), a boolean as
/// written, and of an object or an array its opening bracket. `None` for
/// `null`, which reaches the method as no parameter at all, unchecked.
pub fn text(value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => return None,
        Value::String(s) => s.clone(),
        Value::Number(n) => number_text(&n.to_string()),
        Value::Bool(b) => b.to_string(),
        Value::Array(_) => "[".to_string(),
        Value::Object(_) => "{".to_string(),
    })
}

/// A JSON number as Jackson's tree holds it and prints it back: a whole
/// number as its digits, and one written with a fraction or an exponent as
/// the double it reads as, printed by `Double.toString`. So `1e5` is
/// `100000.0`, which no parameter takes for a number.
///
/// `written` is the number as the request wrote it, which is how this
/// crate's `serde_json` keeps one (`arbitrary_precision`).
fn number_text(written: &str) -> String {
    if written.contains(['.', 'e', 'E']) {
        let double = written.parse().unwrap_or(f64::NAN);
        return crate::java::double_to_string(double);
    }
    match written {
        "-0" => "0".to_string(),
        whole => whole.to_string(),
    }
}

/// The text of a field of an object (`JsonNode.asText()`): as [`text`], but
/// an object or an array is the empty string.
pub fn field_text(value: &Value) -> Option<String> {
    match value {
        Value::Array(_) | Value::Object(_) => Some(String::new()),
        other => text(other),
    }
}

/// A string's length as Java counts it: its UTF-16 units.
fn java_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// A `String` parameter as Jackson reads one: a scalar is its text, and an
/// object or an array is none ([`unparsed`]). `None` for `null`.
pub fn string(value: &Value) -> Result<Option<String>, Refusal> {
    match value {
        Value::Array(_) | Value::Object(_) => Err(unparsed()),
        scalar => Ok(text(scalar)),
    }
}

/// `HexAddressParam`: 40 to 42 characters that `RskAddress` reads as 20
/// bytes -- with the prefix or without, in either case, and 39 digits behind
/// a prefix, which are padded.
pub fn hex_address(text: &str) -> Result<Address, Refusal> {
    if !(40..=42).contains(&java_length(text)) {
        return Err(invalid(
            "Invalid address: null, empty or invalid hex value.",
        ));
    }
    hex_to_bytes(text)
        .filter(|bytes| bytes.len() == 20)
        .map(|bytes| Address::from_slice(&bytes))
        .ok_or_else(|| invalid("Invalid address format: invalid hex value."))
}

/// `HexNumberParam`, which checks a number and doesn't read it: at most 66
/// characters, of hex in either case, with the prefix or without, or what
/// `new BigInteger(String)` reads, a decimal with or without a sign.
pub fn hex_number(text: &str) -> Result<(), Refusal> {
    if java_length(text) > 66 {
        return Err(invalid(format!("Invalid param: {}", abbreviated(text))));
    }
    let digits = text.strip_prefix("0x").unwrap_or(text);
    let hex = digits.bytes().all(|b| b.is_ascii_hexdigit());
    if hex || is_decimal(text) {
        return Ok(());
    }
    Err(invalid(format!(
        "Invalid param {text}: value must be a valid hex or string number."
    )))
}

/// What `new BigInteger(String)` reads: digits, behind a sign or not.
///
/// Java reads the digits of every script there (`Character.digit`), so that
/// rskj takes `"\u{665}"`, an Arabic-Indic five, for 5. That isn't followed:
/// a digit here is one of `0` to `9`.
fn is_decimal(text: &str) -> bool {
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `HexDataParam`: what `HexUtils.stringHexToByteArray` decodes.
pub fn hex_data(text: &str) -> Result<Vec<u8>, Refusal> {
    hex_to_bytes(text).ok_or_else(|| invalid("Invalid data format: invalid hex value."))
}

/// `HexKeyParam`: hex in either case, with the prefix or without, and
/// nothing at all.
pub fn hex_key(text: &str) -> Result<(), Refusal> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(invalid(format!(
        "Invalid param {text}: value must be a valid hex."
    )))
}

/// `HexDurationParam`: nothing at all, or a `0x` and lower-case hex digits
/// (`HexStringParam`) that `Long.parseLong` reads.
pub fn hex_duration(text: &str) -> Result<(), Refusal> {
    if text.is_empty() {
        return Ok(());
    }
    if java_length(text) > 66 {
        return Err(invalid(format!("Invalid argument: {}", abbreviated(text))));
    }
    let Some(digits) = text
        .strip_prefix("0x")
        .filter(|digits| is_lower_hex(digits))
    else {
        return Err(invalid(format!(
            "Invalid argument \"{text}\": param should be a hex value string."
        )));
    };
    match i64::from_str_radix(digits, 16) {
        Ok(_) => Ok(()),
        Err(_) => Err(invalid(
            "Invalid duration param: value must be a valid hex number.",
        )),
    }
}

/// The bytes of a number as rskj reads one a [`hex_number`] let through
/// (`HexUtils.strHexOrStrNumberToByteArray`): behind a `0x` the bytes its
/// digits write, leading zeros and all, and without one a decimal in the
/// bytes `ByteUtil.bigIntegerToBytes` gives it, so `"10"` is ten. Hex without
/// its prefix passed the check and is no decimal: `-32602`.
///
/// A decimal below zero comes through `BigInteger.toByteArray`, its two's
/// complement in as few bytes as hold it, so -1 is the byte `0xff`: 255.
/// One of more digits than [`hex_number`] lets through isn't read.
pub fn number_bytes(text: &str) -> Result<Vec<u8>, Refusal> {
    let unreadable =
        || invalid("Number values should not contain letters or hex values should start with 0x.");
    if text.starts_with("0x") {
        // Nothing catches what the decoder throws here.
        return hex_to_bytes(text).ok_or_else(uncaught);
    }
    if !is_decimal(text) {
        return Err(unreadable());
    }
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    let size = U256::from_str_radix(digits, 10).map_err(|_| unreadable())?;
    if !text.starts_with('-') || size.is_zero() {
        let bytes = size.to_be_bytes_trimmed_vec();
        return Ok(if bytes.is_empty() { vec![0] } else { bytes });
    }
    // -n is the low k bytes of its two's complement, where k bytes are the
    // fewest whose sign bit is set for it: n - 1 has to fit below that bit.
    let count = (size - U256::from(1)).bit_len() / 8 + 1;
    if count > 32 {
        return Err(unreadable());
    }
    Ok(size.wrapping_neg().to_be_bytes::<32>()[32 - count..].to_vec())
}

/// [`number_bytes`] as the number they write.
pub fn number(text: &str) -> Result<U256, Refusal> {
    U256::try_from_be_slice(&number_bytes(text)?).ok_or_else(uncaught)
}

/// A number as rskj reads one for a transaction it signs
/// (`HexUtils.strHexOrStrNumberToBigInteger`, then the bytes its builder
/// makes of it): as [`number`], but that a bare `0x` leaves `new BigInteger`
/// no digits to read, which nothing catches. Nothing written is no decimal:
/// `-32602`.
pub fn transaction_number(text: &str) -> Result<U256, Refusal> {
    if text == "0x" {
        return Err(uncaught());
    }
    number(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `strHexOrStrNumberToByteArray`, number by number, as rskj's release
    /// answers each.
    #[test]
    fn a_number_is_hex_behind_its_prefix_and_a_decimal_without() {
        for (text, bytes) in [
            ("0x10", "10"),
            ("0x000a", "000a"),
            ("0xfff", "0fff"),
            ("0xFf", "ff"),
            ("0x", ""),
            ("10", "0a"),
            ("+7", "07"),
            ("007", "07"),
            ("0", "00"),
            ("-0", "00"),
            ("20000000000000000000", "01158e460913d00000"),
            ("9223372036854775808", "8000000000000000"),
            // Two's complement, in the fewest bytes.
            ("-1", "ff"),
            ("-5", "fb"),
            ("-128", "80"),
            ("-129", "ff7f"),
            ("-256", "ff00"),
            ("-32768", "8000"),
            ("-32769", "ff7fff"),
        ] {
            assert_eq!(
                number_bytes(text).map(hex::encode),
                Ok(bytes.to_string()),
                "{text}"
            );
        }
        assert_eq!(number("-1"), Ok(U256::from(255)));
        assert_eq!(number("0x"), Ok(U256::ZERO));
        // An upper-case prefix is no prefix, an underscore no digit, and a
        // digit of another script isn't read.
        for text in ["ff", "1f", "", "-", "5.5", "0X10", "1_0", " 5", "\u{665}"] {
            assert_eq!(
                number(text).map_err(|(code, _)| code),
                Err(-32602),
                "{text}"
            );
        }
        // Behind a prefix, what the decoder throws nothing catches.
        for text in ["0x-5", "0x1_0", "0xzz"] {
            assert_eq!(number(text), Err(uncaught()), "{text}");
        }
    }

    /// A parameter's text as Jackson gives it: a number with a fraction or an
    /// exponent is the double it reads as, printed as Java prints one.
    #[test]
    fn a_json_number_is_read_back_as_jackson_prints_it() {
        for (written, printed) in [
            ("5", "5"),
            ("-0", "0"),
            ("-5", "-5"),
            (
                "123456789012345678901234567890",
                "123456789012345678901234567890",
            ),
            ("5.5", "5.5"),
            ("5.0", "5.0"),
            ("1e5", "100000.0"),
            ("1E5", "100000.0"),
            ("1e30", "1.0E30"),
            ("0.001", "0.001"),
            ("0.0001", "1.0E-4"),
            ("12345678.9", "1.23456789E7"),
            ("-0.0", "-0.0"),
            ("1e999", "Infinity"),
            ("-1e999", "-Infinity"),
            ("1e-999", "0.0"),
        ] {
            let value: Value = serde_json::from_str(written).unwrap();
            assert_eq!(text(&value).as_deref(), Some(printed), "{written}");
        }
        assert_eq!(text(&Value::Null), None);
        assert_eq!(text(&serde_json::json!({"a": 1})).as_deref(), Some("{"));
        assert_eq!(field_text(&serde_json::json!([1])).as_deref(), Some(""));
    }

    /// `HexDataParam`: bouncycastle's decoder passes over a space, a tab and
    /// the two line ends, and the zero in front goes by the count of
    /// characters.
    #[test]
    fn data_is_hex_with_its_blanks_passed_over() {
        for (text, bytes) in [
            ("0x1234", "1234"),
            ("abc", "0abc"),
            ("5", "05"),
            ("", ""),
            ("0x", ""),
            ("0x12 34 ", "1234"),
            ("0x1234 \n", "1234"),
            ("0x12\n34\n", "1234"),
            ("0x12\t34\r", "1234"),
            ("12 34 ", "1234"),
            ("  ", ""),
        ] {
            assert_eq!(
                hex_data(text).map(hex::encode),
                Ok(bytes.to_string()),
                "{text:?}"
            );
        }
        for text in [
            "0x12 34",
            "0x1234\n",
            " 0x1234",
            " ",
            "0xzz",
            "zz",
            "0x1234\u{b}\u{b}",
            "0x1234\u{a0}\u{a0}",
        ] {
            assert_eq!(
                hex_data(text).map_err(|(code, _)| code),
                Err(-32602),
                "{text:?}"
            );
        }
    }

    /// An address in the forms `RskAddress` reads.
    #[test]
    fn an_address_is_twenty_bytes_however_it_is_written() {
        let one = Address::with_last_byte(1);
        let digits = format!("{}1", "0".repeat(39));
        for text in [
            format!("0x{digits}"),
            digits.clone(),
            format!("0x{}", &digits[1..]),
            // 40 digits and two blanks, which the decoder passes over.
            format!("{digits}  "),
            format!(" {digits}\n"),
        ] {
            assert_eq!(hex_address(&text), Ok(one), "{text}");
        }
        assert_eq!(
            hex_address(&"AB".repeat(20)),
            Ok(Address::repeat_byte(0xab))
        );
        for (text, message) in [
            (
                "0x1".to_string(),
                "Invalid address: null, empty or invalid hex value.",
            ),
            (
                String::new(),
                "Invalid address: null, empty or invalid hex value.",
            ),
            // 38 digits behind a prefix are 19 bytes, and 41 without one are
            // padded to 21.
            (
                format!("0x{}", &digits[2..]),
                "Invalid address format: invalid hex value.",
            ),
            (
                format!("{digits}0"),
                "Invalid address format: invalid hex value.",
            ),
            (
                format!("0x{}", "zz".repeat(20)),
                "Invalid address format: invalid hex value.",
            ),
            (
                format!("0X{digits}"),
                "Invalid address format: invalid hex value.",
            ),
            // 40 digits and one blank are padded to 41 digits.
            (
                format!("{digits} "),
                "Invalid address format: invalid hex value.",
            ),
            (
                format!("0x{digits}\n"),
                "Invalid address: null, empty or invalid hex value.",
            ),
        ] {
            assert_eq!(
                hex_address(&text),
                Err((-32602, message.to_string())),
                "{text}"
            );
        }
    }
}
