use alloy_primitives::{U256, B256};
use rustock_core::types::header::Header;
use serde::Serialize;

/// Formats a u64 as a hex string with 0x prefix (no leading zeros except for 0x0).
pub fn to_hex_u64(v: u64) -> String {
    format!("{:#x}", v)
}

/// Formats a U256 as a hex string with 0x prefix.
pub fn to_hex_u256(v: &U256) -> String {
    if v.is_zero() {
        "0x0".to_string()
    } else {
        format!("{:#x}", v)
    }
}

/// Formats a B256 as a 0x-prefixed lowercase hex string.
pub fn to_hex_b256(v: &B256) -> String {
    format!("{:#x}", v)
}

/// Formats raw bytes as 0x-prefixed hex.
pub fn to_hex_bytes(v: &[u8]) -> String {
    format!("0x{}", hex::encode(v))
}

/// Formats raw bytes as a quantity, as rskj's `HexUtils.toQuantityJsonHex`
/// does: their hex without its leading zero digits, and `0x0` for none.
/// rskj prints the gas limit so, from the bytes it holds.
pub fn to_hex_quantity_bytes(v: &[u8]) -> String {
    let digits = hex::encode(v);
    match digits.trim_start_matches('0') {
        "" => "0x0".to_string(),
        digits => format!("0x{digits}"),
    }
}

/// Parses a 0x-prefixed hex string to a B256. Returns None on failure.
pub fn parse_b256(s: &str) -> Option<B256> {
    s.parse::<B256>().ok()
}

/// Parses a storage slot: any `0x`-prefixed hex quantity up to 32 bytes,
/// left-padded into a full word.
///
/// Distinct from [`parse_b256`], which demands all 64 hex characters. That
/// strictness is right for a hash -- a 32-byte hash is always written in full
/// -- and wrong for a slot, which is a **quantity**: EIP-1474 quantities are
/// minimal-length, so every client sends `0x0` for slot zero and `0x1` for
/// slot one. Rejecting those made `eth_getStorageAt` unusable from any
/// ordinary wallet or library. See #179.
///
/// An odd number of hex digits is accepted and padded, as rskj's
/// `stringHexToByteArray` does.
///
/// **Unprefixed decimal is refused**, and that is a deliberate difference from
/// rskj rather than an oversight. rskj reads an unprefixed slot as decimal
/// (`strHexOrStrNumberToByteArray` falls through to `new BigInteger(s)`) while
/// reading an unprefixed *transaction index* as hex (`HexIndexParam` always
/// parses base 16) -- so `"10"` is slot 10 in one method and index 16 in its
/// neighbour, silently. Reproducing that means importing the trap; refusing
/// means a caller gets an error rather than the wrong slot. #179 tracks the
/// question and the upstream report recommends rskj converge the two.
pub fn parse_storage_slot(s: &str) -> Option<B256> {
    let trimmed = s.trim();
    let hex = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))?;
    if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Right-align into the word: a quantity's value sits at the low end.
    let mut padded = [0u8; 64];
    padded[..64 - hex.len()].fill(b'0');
    padded[64 - hex.len()..].copy_from_slice(hex.as_bytes());
    let text = std::str::from_utf8(&padded).ok()?;
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(B256::from(out))
}

/// Resolves a block parameter: `latest`, `pending` or `earliest` as written,
/// or a `0x`-prefixed hex height.
///
/// # The `0x` prefix is required, and that is the whole point
///
/// This used to strip an optional prefix and then parse base 16 regardless, so
/// an unprefixed decimal height was read as hex: `"100"` resolved to block
/// **256**, silently, with no error. A caller asking about one block was
/// answered about another. See #177.
///
/// rskj rejects an unprefixed height for every method that reaches
/// `Web3InformationRetriever` -- `HexUtils.stringHexToBigInteger` demands the
/// prefix and answers `-32602 invalid blocknumber`. `eth_call` and
/// `eth_estimateGas` read a decimal height too, through
/// `ExecutionBlockRetriever` ([`execution_block`]), and so does
/// `eth_getBlocksByNumber`, which parses its own parameter (see
/// `eth::eth_get_blocks_by_number`).
///
/// # Tags are matched as written
///
/// As every path of rskj's matches them but a log filter's: `getBlock`
/// switches on the string, `BlockRefParam` lists the three tags,
/// `ExecutionBlockRetriever` compares with `BlockTag.tagEquals`
/// (`contentEquals`) and `Web3Impl.getBlockByNumberOrStr` with `equals`.
/// `BlockIdentifierParam` lets `LATEST`, `finalized` and `safe` through
/// (`BlockTag.fromString` ignores case), but nothing it hands them to resolves
/// them but a log filter (upstream #178), which reads its blocks with
/// [`parse_filter_block`].
pub fn parse_block_number(s: &str, head_number: u64) -> Option<u64> {
    match s {
        "latest" | "pending" => Some(head_number),
        "earliest" => Some(0),
        // No prefix, no answer. Guessing the base is what produced #177.
        _ if is_hex_number(s) => u64::from_str_radix(&s[2..], 16).ok(),
        _ => None,
    }
}

/// rskj's decimal number in a block parameter, `^\d+$`
/// (`Utils.isDecimalString`).
fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// rskj's hex number in a block parameter, `^0x[\da-fA-F]+$`
/// (`Utils.isHexadecimalString`).
fn is_hex_number(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// rskj's block tags, in any case (`BlockTag.fromString`).
fn is_block_tag(s: &str) -> bool {
    ["pending", "latest", "earliest", "finalized", "safe"]
        .iter()
        .any(|tag| tag.eq_ignore_ascii_case(s))
}

/// What rskj answers a block reference it refuses before it looks a block up,
/// for `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`,
/// `eth_getTransactionCount` and `rsk_getStorageBytesAt`. `BlockRefParam`
/// passes `earliest`, `latest` and `pending` as written, a decimal and a `0x`
/// hex number, and refuses the rest -- `LATEST` among them -- with `-32602
/// Invalid block identifier`. A decimal goes on to
/// `Web3InformationRetriever.getBlock`, which reads only hex: `-32602 invalid
/// blocknumber`.
pub fn refused_block_ref(id: &serde_json::Value, s: &str) -> Option<crate::types::JsonRpcResponse> {
    let message =
        if !(matches!(s, "earliest" | "latest" | "pending") || is_decimal(s) || is_hex_number(s)) {
            format!("Invalid block identifier '{s}'")
        } else if is_decimal(s) {
            format!("invalid blocknumber {s}")
        } else {
            return None;
        };
    Some(crate::types::JsonRpcResponse::error(
        id.clone(),
        crate::types::INVALID_PARAMS,
        message,
    ))
}

/// The block `eth_call` (`estimate` false) or `eth_estimateGas` (true) runs
/// on, as rskj reads it: in a form `state::resolve_state_root` reads, or the
/// error code and message rskj answers.
///
/// The parameter is checked first: `eth_call`'s is a `BlockRefParam`
/// (`earliest`, `latest` and `pending` as written), `eth_estimateGas`'s a
/// `BlockIdentifierParam` (rskj's tags in any case); either passes a decimal and
/// a `0x` hex number and refuses the rest, `-32602 Invalid block identifier`.
/// Then `ExecutionBlockRetriever.retrieveExecutionBlock` matches the tags as
/// written and reads a number in hex or decimal as a long, throwing past one
/// (`Utils.hexadecimalStringToLong`, `decimalStringToLong`), which nothing
/// catches: `-32603 Internal server error`. A tag in another case, or
/// `finalized` or `safe`, it refuses: `-32602 Unsupported block specifier`.
pub fn execution_block(s: &str, estimate: bool) -> Result<String, (i64, String)> {
    use crate::types::{INTERNAL_ERROR, INVALID_PARAMS};
    let tag = if estimate {
        is_block_tag(s)
    } else {
        matches!(s, "earliest" | "latest" | "pending")
    };
    if estimate && s.is_empty() {
        return Err((
            INVALID_PARAMS,
            "Invalid block identifier: empty or null.".into(),
        ));
    }
    if !(tag || is_decimal(s) || is_hex_number(s)) {
        return Err((INVALID_PARAMS, format!("Invalid block identifier '{s}'")));
    }
    let number = if is_hex_number(s) {
        i64::from_str_radix(&s[2..], 16)
    } else if is_decimal(s) {
        s.parse::<i64>()
    } else if matches!(s, "earliest" | "latest" | "pending") {
        return Ok(s.to_string());
    } else {
        return Err((
            INVALID_PARAMS,
            format!(
                "Unsupported block specifier '{s}'. Can only be either 'earliest', 'latest', \
                 'pending' or a specific block number (either hex - prepending '0x' or decimal)."
            ),
        ));
    };
    number
        .map(|number| format!("{number:#x}"))
        .map_err(|_| (INTERNAL_ERROR, "Internal server error".into()))
}

/// A log filter's `fromBlock` or `toBlock`, as rskj reads it: the height, or
/// the error code and message rskj answers.
///
/// `FilterRequestParam` takes the value's text (Jackson's `asText`) into a
/// `BlockIdentifierParam`, which refuses all but rskj's tags in any case, a
/// decimal and a `0x` hex number: `-32602 Invalid block identifier`. Then
/// `LogFilter` matches `latest`, `pending` and `earliest` ignoring case
/// (`isBlockWord`), and reads the rest with `Web3Impl.getBlockByNumberOrStr`,
/// whose `jsonHexToLong` throws on anything not hex that fits a long --
/// `finalized`, `safe`, a decimal -- which nothing catches: `-32603 Internal
/// server error`.
pub fn parse_filter_block(
    value: &serde_json::Value,
    head_number: u64,
) -> Result<u64, (i64, String)> {
    use crate::types::{INTERNAL_ERROR, INVALID_PARAMS};
    use serde_json::Value;
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(_) | Value::Object(_) => String::new(),
    };
    if text.is_empty() {
        return Err((
            INVALID_PARAMS,
            "Invalid block identifier: empty or null.".into(),
        ));
    }
    if !(is_block_tag(&text) || is_decimal(&text) || is_hex_number(&text)) {
        return Err((INVALID_PARAMS, format!("Invalid block identifier '{text}'")));
    }
    if text.eq_ignore_ascii_case("latest") || text.eq_ignore_ascii_case("pending") {
        return Ok(head_number);
    }
    if text.eq_ignore_ascii_case("earliest") {
        return Ok(0);
    }
    text.strip_prefix("0x")
        .and_then(|hex| i64::from_str_radix(hex, 16).ok())
        .and_then(|number| u64::try_from(number).ok())
        .ok_or((INTERNAL_ERROR, "Internal server error".into()))
}

/// Parses a 0x-prefixed hex index. Returns None on anything malformed, which
/// callers report as an invalid parameter -- rskj's `HexIndexParam` throws
/// `invalidParamError` for the same inputs, before the method body runs.
pub fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).ok()
}

/// Block result DTO matching rskj's `BlockResultDTO` JSON format.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockResultDto {
    pub number: String,
    pub hash: String,
    pub parent_hash: String,
    #[serde(rename = "sha3Uncles")]
    pub sha3_uncles: String,
    pub miner: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub difficulty: String,
    pub total_difficulty: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub timestamp: String,
    pub extra_data: String,
    pub minimum_gas_price: String,
    pub transactions: Vec<serde_json::Value>,
    pub uncles: Vec<serde_json::Value>,
    pub size: String,
}

impl BlockResultDto {
    pub fn from_header(header: &Header, hash: B256, total_difficulty: U256) -> Self {
        // No body, so no transaction will be rendered and the chain id is
        // never consulted.
        Self::from_header_with_body(header, hash, total_difficulty, None, false, 30)
    }

    pub fn from_header_with_body(
        header: &Header,
        hash: B256,
        total_difficulty: U256,
        body: Option<&(Vec<rustock_core::Transaction>, Vec<Header>)>,
        full_txs: bool,
        chain_id: u64,
    ) -> Self {
        let size = encoded_block_len(header, body);

        let transactions = if let Some((txs, _)) = body {
            txs.iter()
                .enumerate()
                .map(|(i, tx)| {
                    if full_txs {
                        tx_to_json(tx, &hash, header.number, i, chain_id)
                    } else {
                        let h = tx_hash(tx);
                        serde_json::Value::String(to_hex_b256(&h))
                    }
                })
                .collect()
        } else {
            vec![]
        };

        let uncles = if let Some((_, ommers)) = body {
            ommers.iter().map(|o| {
                serde_json::Value::String(to_hex_b256(&o.hash()))
            }).collect()
        } else {
            vec![]
        };

        Self {
            number: to_hex_u64(header.number),
            hash: to_hex_b256(&hash),
            parent_hash: to_hex_b256(&header.parent_hash),
            sha3_uncles: to_hex_b256(&header.ommers_hash),
            // `toUnformattedJsonHex(getCoinbase().getBytes())`: `0x` for the
            // null address an empty coinbase reads as.
            miner: header
                .coinbase()
                .map_or_else(|| "0x".to_owned(), |coinbase| format!("{coinbase:#x}")),
            state_root: to_hex_b256(&header.state_root),
            transactions_root: to_hex_b256(&header.transactions_root),
            receipts_root: to_hex_b256(&header.receipts_root),
            logs_bloom: to_hex_bytes(header.logs_bloom.as_ref()),
            difficulty: to_hex_u256(&header.difficulty),
            total_difficulty: to_hex_u256(&total_difficulty),
            gas_limit: to_hex_quantity_bytes(&header.gas_limit_bytes()),
            gas_used: to_hex_u64(header.gas_used),
            timestamp: to_hex_u64(header.timestamp),
            extra_data: to_hex_bytes(&header.extra_data),
            minimum_gas_price: to_hex_quantity_bytes(&header.minimum_gas_price_bytes()),
            transactions,
            uncles,
            size: to_hex_u64(size),
        }
    }
}

/// Length of the block's RLP encoding, which is what `size` reports.
///
/// rskj answers with `block.getEncoded().length` -- the whole block, i.e. the
/// RLP list `[header, transactions, uncles]`, not the header alone. Measuring
/// only the header made `size` short by the entire transaction list, so a
/// block carrying 40 KB of transactions reported ~600 bytes. Callers use this
/// to budget bandwidth and to sanity-check a block they have fetched, and both
/// uses are defeated by a number that ignores the payload.
///
/// A block whose body is absent (header-only, or an uncle the node never
/// stored) encodes as `[header, [], []]`, which is what rskj also produces for
/// that case: it synthesises a body-less block from the header.
fn encoded_block_len(
    header: &Header,
    body: Option<&(Vec<rustock_core::Transaction>, Vec<Header>)>,
) -> u64 {
    use alloy_rlp::{Encodable, Header as RlpHeader};

    let mut header_rlp = Vec::new();
    header.encode(&mut header_rlp);

    let (txs_payload, ommers_payload) = match body {
        Some((txs, ommers)) => {
            let txs_len: usize = txs.iter().map(|tx| tx.rlp_for_trie().len()).sum();
            let mut ommers_len = 0usize;
            for o in ommers {
                let mut buf = Vec::new();
                o.encode(&mut buf);
                ommers_len += buf.len();
            }
            (txs_len, ommers_len)
        }
        None => (0, 0),
    };

    let payload = header_rlp.len()
        + RlpHeader { list: true, payload_length: txs_payload }.length()
        + txs_payload
        + RlpHeader { list: true, payload_length: ommers_payload }.length()
        + ommers_payload;

    (RlpHeader { list: true, payload_length: payload }.length() + payload) as u64
}

/// Compute the keccak256 hash of a transaction's RLP encoding.
/// The canonical transaction hash.
///
/// Must be `Transaction::tx_hash()`, which hashes `rlp_for_trie()` -- the
/// ORIGINAL bytes when they were cached at decode time. Re-encoding here
/// instead produced a different hash for every transaction whose RLP does not
/// round-trip byte-for-byte (~42% of mainnet transactions when measured), so
/// `eth_getBlockBy*` reported hashes that `eth_getTransactionByHash` and
/// `eth_getTransactionReceipt` could not then find, because the index is keyed
/// by the canonical hash.
fn tx_hash(tx: &rustock_core::Transaction) -> B256 {
    tx.tx_hash()
}

/// rskj's chain id, which EIP-155 sender recovery needs.
///
/// One copy, because the default is a trap: a hardcoded 30 recovers the wrong
/// sender on every chain that is not mainnet, and the failure is silent --
/// `recover_sender` returns a perfectly well-formed address for the wrong
/// chain id. That bug has already been fixed once here; a second copy of the
/// constant is how it comes back.
pub fn chain_id_of(state: &crate::server::RpcState) -> u64 {
    state.hardfork_cfg.as_ref().map(|c| c.chain_id).unwrap_or(30)
}

/// Format a transaction as a JSON object for `eth_getBlockBy*` (full tx mode).
///
/// `from` is recovered here rather than left at zero. It costs one ECDSA
/// recovery per transaction, which is what rskj pays too: the sender is not
/// stored anywhere, it only exists in the signature. A transaction whose
/// signature does not recover -- REMASC has none at all -- reports the zero
/// address, matching `eth_getTransactionByHash`.
fn tx_to_json(
    tx: &rustock_core::Transaction,
    block_hash: &B256,
    block_number: u64,
    index: usize,
    chain_id: u64,
) -> serde_json::Value {
    let hash = tx_hash(tx);
    let from = tx.recover_sender(chain_id).unwrap_or(alloy_primitives::Address::ZERO);
    serde_json::json!({
        "hash": to_hex_b256(&hash),
        "nonce": to_hex_u64(tx.nonce),
        "blockHash": to_hex_b256(block_hash),
        "blockNumber": to_hex_u64(block_number),
        "transactionIndex": to_hex_u64(index as u64),
        "from": format!("{from:#x}"),
        "to": to_hex_bytes(&tx.to),
        "value": to_hex_u256(&tx.value),
        "gasPrice": to_hex_u256(&tx.gas_price),
        "gas": to_hex_u256(&tx.gas_limit),
        "input": to_hex_bytes(&tx.input),
        "v": to_hex_u64(tx.v),
        "r": to_hex_u256(&tx.r),
        "s": to_hex_u256(&tx.s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_hex_u64() {
        assert_eq!(to_hex_u64(0), "0x0");
        assert_eq!(to_hex_u64(255), "0xff");
        assert_eq!(to_hex_u64(4444), "0x115c");
    }

    #[test]
    fn test_to_hex_u256() {
        assert_eq!(to_hex_u256(&U256::ZERO), "0x0");
        assert_eq!(to_hex_u256(&U256::from(0xff)), "0xff");
    }

    /// rskj's `HexUtils.toQuantityJsonHex`: leading zero digits go, a sign
    /// byte's included, and nothing left is `0x0`.
    #[test]
    fn bytes_print_as_a_quantity() {
        assert_eq!(to_hex_quantity_bytes(&[]), "0x0");
        assert_eq!(to_hex_quantity_bytes(&[0, 0]), "0x0");
        assert_eq!(to_hex_quantity_bytes(&[0x00, 0xb7, 0x1b, 0x00]), "0xb71b00");
        assert_eq!(to_hex_quantity_bytes(&[0x09, 0x00]), "0x900");
        let mut past = vec![1];
        past.extend_from_slice(&[0; 32]);
        assert_eq!(
            to_hex_quantity_bytes(&past),
            format!("0x1{}", "0".repeat(64))
        );
    }

    #[test]
    fn test_parse_block_number() {
        assert_eq!(parse_block_number("latest", 100), Some(100));
        assert_eq!(parse_block_number("earliest", 100), Some(0));
        assert_eq!(parse_block_number("pending", 100), Some(100));
        assert_eq!(parse_block_number("0x0", 100), Some(0));
        assert_eq!(parse_block_number("0xff", 100), Some(255));
    }

    /// **An unprefixed height must not be guessed at.** It used to be parsed
    /// as hex, so `"100"` answered about block 256 -- a plausible answer about
    /// the wrong block, which is worse than any error. See #177.
    #[test]
    fn an_unprefixed_block_number_is_refused_rather_than_read_as_hex() {
        assert_eq!(parse_block_number("100", 999), None, "must not resolve to 256");
        assert_eq!(parse_block_number("64", 999), None);
        assert_eq!(parse_block_number("0", 999), None);
        // The prefixed forms still mean what they always meant.
        assert_eq!(parse_block_number("0x100", 999), Some(256));
        assert_eq!(parse_block_number("0x64", 999), Some(100));
    }

    /// Tags are matched as written, as rskj matches them everywhere but in a
    /// log filter: `LATEST` resolves to nothing, nor does a tag with space
    /// around it or an upper-case prefix (upstream #178).
    #[test]
    fn block_tags_are_matched_as_written() {
        assert_eq!(parse_block_number("LATEST", 100), None);
        assert_eq!(parse_block_number("Earliest", 100), None);
        assert_eq!(parse_block_number("PENDING", 100), None);
        assert_eq!(parse_block_number(" latest", 100), None);
        assert_eq!(parse_block_number("0X10", 100), None);
    }

    /// Neither a bare prefix nor rubbish resolves to a block.
    #[test]
    fn malformed_block_numbers_resolve_to_nothing() {
        assert_eq!(parse_block_number("0x", 100), None);
        assert_eq!(parse_block_number("", 100), None);
        assert_eq!(parse_block_number("finalized", 100), None);
        assert_eq!(parse_block_number("0xzz", 100), None);
        assert_eq!(parse_block_number("0x+5", 100), None);
    }

    /// A block reference rskj refuses before it looks anything up: anything
    /// but the three tags as written, a decimal and a hex number, and then a
    /// decimal, which `getBlock` can't read.
    #[test]
    fn a_block_reference_is_refused_as_rskj_refuses_it() {
        let refused = |s: &str| {
            refused_block_ref(&serde_json::json!(1), s)
                .and_then(|resp| resp.error)
                .map(|error| (error.code, error.message))
        };
        for fine in ["latest", "pending", "earliest", "0x0", "0x1F"] {
            assert_eq!(refused(fine), None, "{fine}");
        }
        for (s, message) in [
            ("LATEST", "Invalid block identifier 'LATEST'"),
            ("finalized", "Invalid block identifier 'finalized'"),
            ("0x", "Invalid block identifier '0x'"),
            ("12", "invalid blocknumber 12"),
        ] {
            assert_eq!(refused(s), Some((-32602, message.to_string())), "{s}");
        }
    }

    /// The block a call or an estimate runs on: rskj's tags as written, a hex
    /// or decimal long; `eth_call` refuses another tag's spelling as an
    /// identifier and `eth_estimateGas` as a specifier, both `-32602`, and a
    /// number past a long is `-32603`.
    #[test]
    fn a_calls_block_is_read_as_rskj_reads_it() {
        for estimate in [false, true] {
            assert_eq!(execution_block("latest", estimate), Ok("latest".into()));
            assert_eq!(execution_block("pending", estimate), Ok("pending".into()));
            assert_eq!(execution_block("0x1F", estimate), Ok("0x1f".into()));
            assert_eq!(execution_block("100", estimate), Ok("0x64".into()));
            assert_eq!(
                execution_block("0x8000000000000000", estimate),
                Err((-32603, "Internal server error".into()))
            );
            assert_eq!(
                execution_block("9223372036854775808", estimate),
                Err((-32603, "Internal server error".into()))
            );
            assert_eq!(
                execution_block("foo", estimate),
                Err((-32602, "Invalid block identifier 'foo'".into()))
            );
        }
        assert_eq!(
            execution_block("", false),
            Err((-32602, "Invalid block identifier ''".into()))
        );
        assert_eq!(
            execution_block("", true),
            Err((-32602, "Invalid block identifier: empty or null.".into()))
        );
        assert_eq!(
            execution_block("LATEST", false),
            Err((-32602, "Invalid block identifier 'LATEST'".into()))
        );
        let (code, message) = execution_block("safe", true).unwrap_err();
        assert_eq!(code, -32602);
        assert!(
            message.starts_with("Unsupported block specifier 'safe'."),
            "{message}"
        );
    }

    /// A log filter's block: rskj's three tags in any case, a hex long; a
    /// value that isn't one of rskj's tags or numbers is `-32602`, and
    /// `finalized`, `safe`, a decimal or a number past a long `-32603`.
    #[test]
    fn a_log_filters_block_is_read_as_rskj_reads_it() {
        use serde_json::json;
        assert_eq!(parse_filter_block(&json!("LATEST"), 100), Ok(100));
        assert_eq!(parse_filter_block(&json!("Pending"), 100), Ok(100));
        assert_eq!(parse_filter_block(&json!("EARLIEST"), 100), Ok(0));
        assert_eq!(parse_filter_block(&json!("0x1F"), 100), Ok(31));
        let internal = Err((-32603, "Internal server error".to_string()));
        for value in [
            json!("finalized"),
            json!("SAFE"),
            json!("12"),
            json!(12),
            json!("0x8000000000000000"),
        ] {
            assert_eq!(parse_filter_block(&value, 100), internal, "{value}");
        }
        for (value, message) in [
            (json!("foo"), "Invalid block identifier 'foo'"),
            (json!(null), "Invalid block identifier 'null'"),
            (json!(true), "Invalid block identifier 'true'"),
            (json!(""), "Invalid block identifier: empty or null."),
            (json!({}), "Invalid block identifier: empty or null."),
        ] {
            assert_eq!(
                parse_filter_block(&value, 100),
                Err((-32602, message.to_string())),
                "{value}"
            );
        }
    }

    /// **A slot is a quantity.** Clients send `0x0`, not 64 zeros, and
    /// rejecting the short form made `eth_getStorageAt` unusable from any
    /// ordinary wallet. See #179.
    #[test]
    fn a_storage_slot_accepts_the_short_hex_every_client_sends() {
        assert_eq!(parse_storage_slot("0x0"), Some(B256::ZERO));
        assert_eq!(
            parse_storage_slot("0x1"),
            Some(B256::from(alloy_primitives::U256::from(1u64)))
        );
        // Odd digit counts are padded, as rskj's stringHexToByteArray does.
        assert_eq!(
            parse_storage_slot("0xabc"),
            Some(B256::from(alloy_primitives::U256::from(0xabcu64)))
        );
        // The long form still means what it meant.
        assert_eq!(
            parse_storage_slot(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ),
            Some(B256::from(alloy_primitives::U256::from(1u64)))
        );
        // Value sits at the low end of the word, not the high end.
        assert_eq!(parse_storage_slot("0xff").unwrap()[31], 0xff);
        assert_eq!(parse_storage_slot("0xff").unwrap()[0], 0x00);
    }

    /// Unprefixed decimal is refused on purpose: rskj reads it as decimal here
    /// but as hex for a transaction index, so accepting it would import the
    /// ambiguity. Refusing gives an error rather than the wrong slot. See #179.
    #[test]
    fn an_unprefixed_storage_slot_is_refused() {
        assert_eq!(parse_storage_slot("10"), None);
        assert_eq!(parse_storage_slot("0"), None);
        assert_eq!(parse_storage_slot("0x"), None);
        assert_eq!(parse_storage_slot("0xzz"), None);
        // Wider than a word is not a slot.
        assert_eq!(parse_storage_slot(&format!("0x{}", "1".repeat(65))), None);
    }

    #[test]
    fn test_parse_b256() {
        let hash = B256::repeat_byte(0xaa);
        let parsed = parse_b256(&format!("{:#x}", hash));
        assert_eq!(parsed, Some(hash));
        assert_eq!(parse_b256("not_a_hash"), None);
    }
}

