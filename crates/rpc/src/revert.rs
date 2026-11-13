//! What `eth_call` and `eth_estimateGas` answer where the program they ran
//! ended with REVERT, as rskj answers it
//! (`EthModule.handleTransactionRevertIfHappens`).

use crate::helpers::to_hex_bytes;
use crate::params::{uncaught, Refusal};
use crate::types::{JsonRpcResponse, EXECUTION_ERROR};
use serde_json::{json, Value};

/// The selector of Solidity's `Error(string)`, rskj's
/// `ERROR_ABI_FUNCTION_SIGNATURE`.
const ERROR_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];

/// rskj's answer to a revert: its own error, -32015, whose `data` is what the
/// program reverted with, in hex. The message is "transaction reverted", or
/// "revert " and the reason where the data is an `Error(string)`. Where the
/// data says it is one and can't be read as one, rskj's decoder throws, which
/// nothing catches.
pub fn answer(id: Value, data: &[u8]) -> JsonRpcResponse {
    let said = match reason(data) {
        Ok(Some(reason)) => format!("revert {reason}"),
        Ok(None) => "transaction reverted".to_string(),
        Err((code, message)) => return JsonRpcResponse::error(id, code, message),
    };
    JsonRpcResponse::error_with_data(
        id,
        EXECUTION_ERROR,
        format!("VM Exception while processing transaction: {said}"),
        json!(to_hex_bytes(data)),
    )
}

/// The reason a revert gives, as rskj's `EthModule.decodeProgramRevert` reads
/// it: none unless the data begins with `Error(string)`'s selector, and then
/// what `CallTransaction.Function.decode` makes of the rest.
///
/// That decoder reads the string's offset, and at the offset its length, each
/// as the low 32 bits of a 32-byte word (`BigInteger.intValue`), and then the
/// string's bytes. A read throws where the data doesn't hold all of it, or
/// where the offset or the length is below zero (`Utils.safeCopyOfRange`).
/// The data need not be padded, and what follows the string is not read.
///
/// (With no data at all after the selector rskj reads both words as 0,
/// `IntType.decodeInt`, and throws all the same, for the string's bytes.)
fn reason(data: &[u8]) -> Result<Option<String>, Refusal> {
    if data.len() < 4 || data[..4] != ERROR_SELECTOR {
        return Ok(None);
    }
    let encoded = &data[4..];
    let read = |from: i32, size: i32| -> Result<&[u8], Refusal> {
        let (start, length) = (usize::try_from(from), usize::try_from(size));
        let end = from
            .checked_add(size)
            .and_then(|end| usize::try_from(end).ok());
        match (start, length, end) {
            (Ok(start), Ok(_), Some(end)) if end <= encoded.len() => Ok(&encoded[start..end]),
            _ => Err(uncaught()),
        }
    };
    let word = |at: i32| -> Result<i32, Refusal> {
        let word = read(at, 32)?;
        Ok(i32::from_be_bytes([word[28], word[29], word[30], word[31]]))
    };
    let offset = word(0)?;
    let length = word(offset)?;
    // No overflow: a word was read at the offset.
    let text = read(offset + 32, length)?;
    Ok(Some(java_utf8(text)))
}

/// `new String(bytes, StandardCharsets.UTF_8)`, as the JDK reads bytes that
/// aren't all UTF-8: each run it can't read becomes one U+FFFD.
///
/// Its runs are those of `String::from_utf8_lossy` but for a surrogate
/// written as three bytes (`ED A0 80` to `ED BF BF`), which the JDK reads as
/// one run, and its first two bytes as one where the third is missing or
/// isn't a continuation. `from_utf8_lossy` replaces each byte of them.
fn java_utf8(bytes: &[u8]) -> String {
    let continues = |byte: u8| byte & 0xc0 == 0x80;
    let mut text = String::new();
    let mut rest = bytes;
    while let [b1, after @ ..] = rest {
        let b1 = *b1;
        // Whether `b2` can follow a `b1` that leads four bytes.
        let second_of_four = |b2: u8| match b1 {
            0xf0 => (0x90..=0xbf).contains(&b2),
            0xf1..=0xf3 => continues(b2),
            0xf4 => b2 & 0xf0 == 0x80,
            _ => false,
        };
        // The character at the head, where there is one, and the bytes it or
        // the run in its place takes.
        let (made, taken) = match (b1, after) {
            (0x00..=0x7f, _) => (Some(b1 as char), 1),
            (0xc2..=0xdf, [b2, ..]) if continues(*b2) => {
                let point = (u32::from(b1) & 0x1f) << 6 | (u32::from(*b2) & 0x3f);
                (char::from_u32(point), 2)
            }
            (0xe0..=0xef, [b2, b3, ..]) => {
                if (b1 == 0xe0 && b2 & 0xe0 == 0x80) || !continues(*b2) {
                    (None, 1)
                } else if !continues(*b3) {
                    (None, 2)
                } else {
                    // None for a surrogate, which takes its three bytes.
                    let point = (u32::from(b1) & 0x0f) << 12
                        | (u32::from(*b2) & 0x3f) << 6
                        | (u32::from(*b3) & 0x3f);
                    (char::from_u32(point), 3)
                }
            }
            (0xe0..=0xef, [b2]) if (b1 == 0xe0 && b2 & 0xe0 == 0x80) || !continues(*b2) => {
                (None, 1)
            }
            // Cut short by the end, with what there is of it.
            (0xe0..=0xef, _) => (None, rest.len()),
            (0xf0..=0xf7, [b2, ..]) if !second_of_four(*b2) => (None, 1),
            (0xf5..=0xf7, []) => (None, 1),
            (0xf0..=0xf7, [_, b3, ..]) if !continues(*b3) => (None, 2),
            (0xf0..=0xf7, [b2, b3, b4, ..]) => {
                if continues(*b4) {
                    let point = (u32::from(b1) & 0x07) << 18
                        | (u32::from(*b2) & 0x3f) << 12
                        | (u32::from(*b3) & 0x3f) << 6
                        | (u32::from(*b4) & 0x3f);
                    (char::from_u32(point), 4)
                } else {
                    (None, 3)
                }
            }
            (0xf0..=0xf7, _) => (None, rest.len()),
            // A byte that leads nothing: a continuation, C0, C1, F8 and up,
            // or a lead of two that nothing continues.
            _ => (None, 1),
        };
        text.push(made.unwrap_or(char::REPLACEMENT_CHARACTER));
        rest = &rest[taken..];
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the JDK's runs of unreadable bytes are not `from_utf8_lossy`'s,
    /// and a few where they are. Each was read by a JVM
    /// (`testdata/rskj_local_calls.txt`, the scenario `utf8`, has rskj's own
    /// answers for the same bytes).
    #[test]
    fn bytes_that_are_not_utf8_read_as_the_jdk_reads_them() {
        let read = |bytes: &[u8]| java_utf8(bytes);
        assert_eq!(
            read(b"h\xc3\xa9llo \xe2\x9c\x93 \xf0\x9f\x98\x80"),
            "h\u{e9}llo \u{2713} \u{1f600}"
        );
        // A surrogate in three bytes is one run; so are its first two.
        assert_eq!(read(b"a\xed\xa0\x80b"), "a\u{fffd}b");
        assert_eq!(read(b"a\xed\xbf\xbfb"), "a\u{fffd}b");
        assert_eq!(read(b"a\xed\xa0b"), "a\u{fffd}b");
        assert_eq!(read(b"a\xed\xa0"), "a\u{fffd}");
        assert_eq!(
            String::from_utf8_lossy(b"a\xed\xa0\x80b"),
            "a\u{fffd}\u{fffd}\u{fffd}b"
        );
        // The rest are `from_utf8_lossy`'s.
        for bytes in [
            &b"a\xffb"[..],
            b"a\xc0\xafb",
            b"a\xe2\x82",
            b"a\xe0\x80\x80b",
            b"a\xe0\x9f",
            b"a\xf4\x90\x80\x80b",
            b"a\xf8\x88\x80\x80\x80b",
            b"a\x80b",
            b"a\xf0\x9f\x98",
            b"a\xf0\x9f\x98b",
            b"a\xf0\x9f",
            b"a\xf0",
            b"a\xf5",
            b"a\xc2",
            b"a\xc2b",
            b"a\xf4\x8f\xbf\xbf",
            b"a\xed\x9f\xbf\xee\x80\x80",
        ] {
            assert_eq!(read(bytes), String::from_utf8_lossy(bytes), "{bytes:02x?}");
        }
    }

    /// An `Error(string)` is read as rskj's decoder reads one, and what it
    /// can't read is an exception nobody catches.
    #[test]
    fn a_reverts_reason_is_read_as_rskj_reads_it() {
        let word = |number: u64| {
            let mut word = [0u8; 32];
            word[24..].copy_from_slice(&number.to_be_bytes());
            word
        };
        let error = |parts: &[&[u8]]| [&ERROR_SELECTOR[..], &parts.concat()].concat();

        assert_eq!(reason(&[]), Ok(None));
        assert_eq!(reason(&ERROR_SELECTOR[..3]), Ok(None));
        assert_eq!(reason(&[0x4e, 0x48, 0x7b, 0x71, 0, 0, 0, 0x11]), Ok(None));
        let hello = error(&[&word(32), &word(5), b"hello"]);
        assert_eq!(reason(&hello), Ok(Some("hello".into())));
        assert_eq!(
            reason(&error(&[&word(32), &word(0)])),
            Ok(Some(String::new()))
        );
        // The offset's low 32 bits, wherever they point.
        let high = error(&[&word((1 << 32) + 32), &word(5), b"hello"]);
        assert_eq!(reason(&high), Ok(Some("hello".into())));
        assert_eq!(
            reason(&error(&[&word(0), &word(0)])),
            Ok(Some(String::new()))
        );

        for unread in [
            error(&[]),
            error(&[&word(32)]),
            error(&[&word(32), &word(6), b"hello"]),
            error(&[&[0xff; 32], &word(0)]),
            error(&[&word(32), &word(0xffff_ffff), &word(0)]),
            error(&[&word(0x7fff_ffff)]),
        ] {
            assert_eq!(reason(&unread), Err(uncaught()), "{unread:02x?}");
        }
    }
}
