//! A genesis block read from an rskj genesis JSON file (`genesis = <file>` in
//! an rskj config, loaded by rskj's `GenesisLoaderImpl`).
//!
//! The point is to start a regtest chain on exactly the block an rskj node
//! started on, so that the blocks it mined connect here: block 1's parent hash
//! is the genesis hash, and the genesis hash commits to every field below.
//!
//! Two details make that hash rskj's and not merely plausible:
//!
//! - the difficulty is hashed as the file's bytes (`GenesisHeader` keeps them
//!   verbatim), so `0x0010000000` and `0x10000000` are different genesis
//!   blocks with the same difficulty;
//! - the state root is not in the file. rskj builds the genesis state and
//!   writes its root into the header, so the caller does the same:
//!   [`GenesisSpec::with_state_root`].
//!
//! Only plain accounts are read (`balance`, `nonce`). An `alloc` entry with a
//! `contract` is refused rather than silently funded without its code.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::Encodable;
use anyhow::{anyhow, bail, Context, Result};

use crate::config::GenesisAlloc;
use crate::types::header::Header;

const EMPTY_LIST_HASH: B256 = B256::new(hex_literal::hex!(
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
));
const EMPTY_TRIE_HASH: B256 = B256::new(hex_literal::hex!(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
));

/// A genesis block as an rskj genesis JSON file describes it.
#[derive(Clone, Debug)]
pub struct GenesisSpec {
    pub parent_hash: B256,
    pub coinbase: Address,
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    /// The `difficulty` field's exact bytes, leading zeros included.
    pub difficulty_bytes: Bytes,
    pub minimum_gas_price: U256,
    pub bitcoin_merged_mining_header: Bytes,
    pub bitcoin_merged_mining_merkle_proof: Bytes,
    pub bitcoin_merged_mining_coinbase_transaction: Bytes,
    /// The `alloc` accounts, in file order.
    pub alloc: Vec<GenesisAlloc>,
    /// The root of the genesis state, once the caller has built it.
    pub state_root: Option<B256>,
}

/// rskj `org.ethereum.json.Utils.parseData`: optional `0x`, odd length padded.
fn parse_data(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded;
    let s = if s.len() % 2 == 1 {
        padded = format!("0{s}");
        padded.as_str()
    } else {
        s
    };
    hex::decode(s).with_context(|| format!("invalid hex '{s}'"))
}

fn u256_from_be(bytes: &[u8]) -> Result<U256> {
    if bytes.len() > 32 {
        bail!("value longer than 32 bytes");
    }
    Ok(U256::from_be_slice(bytes))
}

fn decimal(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).with_context(|| format!("invalid decimal '{s}'"))
}

impl GenesisSpec {
    /// Parse an rskj genesis JSON document.
    pub fn from_json(json: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(json).context("not valid JSON")?;
        let text = |key: &str| v.get(key).and_then(|x| x.as_str());
        let field = |key: &str| -> Result<Vec<u8>> {
            parse_data(text(key).ok_or_else(|| anyhow!("genesis lacks '{key}'"))?)
                .with_context(|| format!("in '{key}'"))
        };
        let optional = |key: &str| -> Result<Vec<u8>> {
            text(key).map(parse_data).unwrap_or_else(|| Ok(Vec::new()))
        };

        let mut alloc = Vec::new();
        if let Some(entries) = v.get("alloc").and_then(|a| a.as_object()) {
            for (key, entry) in entries {
                // rskj's loader skips this key.
                if key == "00" {
                    continue;
                }
                let address = parse_data(key)?;
                if address.len() != 20 {
                    bail!("alloc address '{key}' is not 20 bytes");
                }
                if entry.get("contract").is_some() {
                    bail!("alloc {key} has a contract; only plain accounts are supported");
                }
                let balance = entry
                    .get("balance")
                    .and_then(|b| b.as_str())
                    .ok_or_else(|| anyhow!("alloc {key} lacks a balance"))?;
                // rskj: the network's initial nonce, zero everywhere, when absent.
                let nonce = match entry.get("nonce").and_then(|n| n.as_str()) {
                    Some(n) => decimal(n)?,
                    None => U256::ZERO,
                };
                alloc.push(GenesisAlloc {
                    address: Address::from_slice(&address),
                    balance: decimal(balance)?,
                    nonce,
                });
            }
        }

        let coinbase = field("coinbase")?;
        let timestamp = u256_from_be(&field("timestamp")?)?;
        Ok(Self {
            parent_hash: B256::try_from(field("parentHash")?.as_slice())
                .context("parentHash is not 32 bytes")?,
            coinbase: if coinbase.is_empty() {
                Address::ZERO
            } else {
                Address::try_from(coinbase.as_slice()).context("coinbase is not 20 bytes")?
            },
            timestamp: u64::try_from(timestamp).context("timestamp out of range")?,
            extra_data: Bytes::from(field("extraData")?),
            gas_limit: u256_from_be(&field("gasLimit")?)?,
            difficulty_bytes: Bytes::from(field("difficulty")?),
            minimum_gas_price: u256_from_be(&optional("minimumGasPrice")?)?,
            bitcoin_merged_mining_header: Bytes::from(optional("bitcoinMergedMiningHeader")?),
            bitcoin_merged_mining_merkle_proof: Bytes::from(optional(
                "bitcoinMergedMiningMerkleProof",
            )?),
            bitcoin_merged_mining_coinbase_transaction: Bytes::from(optional(
                "bitcoinMergedMiningCoinbaseTransaction",
            )?),
            alloc,
            state_root: None,
        })
    }

    /// Read and parse an rskj genesis JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read genesis file {}", path.display()))?;
        Self::from_json(&json).with_context(|| format!("in genesis file {}", path.display()))
    }

    /// The same genesis with its state root filled in.
    pub fn with_state_root(mut self, root: B256) -> Self {
        self.state_root = Some(root);
        self
    }

    fn has_mining_fields(&self) -> bool {
        !self.bitcoin_merged_mining_header.is_empty()
            || !self.bitcoin_merged_mining_merkle_proof.is_empty()
            || !self.bitcoin_merged_mining_coinbase_transaction.is_empty()
    }

    /// The genesis hash, as rskj's `GenesisHeader.getEncoded` produces it: a
    /// version-0 header with the difficulty bytes as given and RSKIP92's
    /// encoding (only the merged-mining header, no proof or coinbase), which
    /// is what every regtest chain since Orchid uses.
    pub fn hash(&self) -> B256 {
        let mut list = Vec::new();
        self.parent_hash.encode(&mut list);
        EMPTY_LIST_HASH.encode(&mut list);
        if self.coinbase == Address::ZERO {
            // RLP.encodeRskAddress: the zero address is an empty element.
            list.push(0x80);
        } else {
            self.coinbase.encode(&mut list);
        }
        self.state_root.unwrap_or_default().encode(&mut list);
        EMPTY_TRIE_HASH.encode(&mut list);
        EMPTY_TRIE_HASH.encode(&mut list);
        alloy_primitives::Bloom::ZERO.encode(&mut list);
        self.difficulty_bytes.encode(&mut list);
        0u64.encode(&mut list); // number
        let gas_limit = self.gas_limit.to_be_bytes::<32>();
        let start = gas_limit.iter().position(|b| *b != 0).unwrap_or(32);
        gas_limit[start..].encode(&mut list);
        0u64.encode(&mut list); // gasUsed
        self.timestamp.encode(&mut list);
        self.extra_data.encode(&mut list);
        U256::ZERO.encode(&mut list); // paidFees
                                      // RLP.encodeSignedCoinNonNullZero: zero is the single byte 0x00.
        let mgp = self.minimum_gas_price.to_be_bytes::<32>();
        match mgp.iter().position(|b| *b != 0) {
            None => list.push(0x00),
            Some(i) if mgp[i] & 0x80 != 0 => [&[0u8][..], &mgp[i..]].concat().encode(&mut list),
            Some(i) => mgp[i..].encode(&mut list),
        }
        0u64.encode(&mut list); // uncleCount
        if self.has_mining_fields() {
            self.bitcoin_merged_mining_header.encode(&mut list);
        }
        let mut out = Vec::with_capacity(list.len() + 4);
        alloy_rlp::Header {
            list: true,
            payload_length: list.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(&list);
        alloy_primitives::keccak256(&out)
    }

    /// The genesis header, carrying [`GenesisSpec::hash`]: it cannot be
    /// recomputed from the fields, because the difficulty bytes are not
    /// canonical.
    pub fn header(&self) -> Header {
        let some = |b: &Bytes| (!b.is_empty()).then(|| b.clone());
        Header {
            parent_hash: self.parent_hash,
            ommers_hash: EMPTY_LIST_HASH,
            beneficiary: self.coinbase,
            state_root: self.state_root.unwrap_or_default(),
            transactions_root: EMPTY_TRIE_HASH,
            receipts_root: EMPTY_TRIE_HASH,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from_be_slice(&self.difficulty_bytes),
            number: 0,
            gas_limit: self.gas_limit,
            gas_used: 0,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            paid_fees: U256::ZERO,
            minimum_gas_price: self.minimum_gas_price,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: some(&self.bitcoin_merged_mining_header),
            bitcoin_merged_mining_merkle_proof: some(&self.bitcoin_merged_mining_merkle_proof),
            bitcoin_merged_mining_coinbase_transaction: some(
                &self.bitcoin_merged_mining_coinbase_transaction,
            ),
            cached_hash: Some(self.hash()),
            cached_hash_for_merged_mining: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: &str = r#"{
      "alloc": {
        "0000000000000000000000000000000001000006": { "balance": "21000000000000000000000000" },
        "cd2a3d9f938e13cd947ec05abc7fe734df8dd826": { "balance": "1000", "nonce": "7" },
        "00": { "balance": "1" }
      },
      "nonce": "0xdeadbeefdeadbeef",
      "mixhash": "0x00",
      "bitcoinMergedMiningHeader": "0x00",
      "bitcoinMergedMiningMerkleProof": "0x00",
      "bitcoinMergedMiningCoinbaseTransaction": "0x00",
      "timestamp": "0x00",
      "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "extraData": "0x686f727365",
      "gasLimit": "0x017D7840",
      "difficulty": "0x0010000000",
      "coinbase": "0x3333333333333333333333333333333333333333",
      "minimumGasPrice": "0x00"
    }"#;

    #[test]
    fn reads_an_rskj_genesis_file() {
        let g = GenesisSpec::from_json(GENESIS).unwrap();
        assert_eq!(g.alloc.len(), 2, "the 00 key is skipped, as rskj does");
        let funded = g.alloc.iter().find(|a| a.nonce == U256::from(7)).unwrap();
        assert_eq!(funded.balance, U256::from(1000));
        assert_eq!(g.gas_limit, U256::from(25_000_000));
        assert_eq!(g.difficulty_bytes.as_ref(), &[0x00, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(g.header().difficulty, U256::from(0x1000_0000u64));
        assert_eq!(g.extra_data.as_ref(), b"horse");
        assert!(g.state_root.is_none());
    }

    #[test]
    fn the_hash_keeps_the_difficulty_bytes_as_written() {
        let g = GenesisSpec::from_json(GENESIS)
            .unwrap()
            .with_state_root(B256::repeat_byte(1));
        let mut canonical = g.clone();
        canonical.difficulty_bytes = Bytes::from(vec![0x10, 0x00, 0x00, 0x00]);
        assert_ne!(g.hash(), canonical.hash(), "same value, different bytes");
        assert_eq!(
            g.header().hash(),
            g.hash(),
            "the header carries the cached hash"
        );
    }

    #[test]
    fn a_contract_in_the_alloc_is_refused() {
        let json = GENESIS.replace(
            r#"{ "balance": "1000", "nonce": "7" }"#,
            r#"{ "balance": "0", "contract": { "code": "0x00" } }"#,
        );
        assert!(GenesisSpec::from_json(&json).is_err());
    }
}
