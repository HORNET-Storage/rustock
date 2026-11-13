use alloy_primitives::{Address, B256, U256};
use rustock_core::{Receipt, Transaction};
use serde::Serialize;
use serde_json::Value;

use crate::helpers::{to_hex_b256, to_hex_bytes, to_hex_u256, to_hex_u64};

/// Transaction result DTO matching rskj's `TransactionResultDTO`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDto {
    pub hash: String,
    pub nonce: String,
    pub block_hash: Value,
    pub block_number: Value,
    pub transaction_index: Value,
    pub from: String,
    pub to: Value,
    pub gas: String,
    pub gas_price: String,
    pub value: String,
    pub input: String,
    pub v: String,
    pub r: String,
    pub s: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

impl TransactionDto {
    pub fn from_tx(
        tx: &Transaction,
        tx_hash: B256,
        block_hash: Option<B256>,
        block_number: Option<u64>,
        tx_index: Option<u32>,
        sender: Address,
    ) -> Self {
        let to_value = if tx.to.is_empty() {
            Value::Null
        } else if tx.to.len() == 20 {
            Value::String(format!("{:#x}", Address::from_slice(&tx.to)))
        } else {
            Value::String(to_hex_bytes(&tx.to))
        };

        Self {
            hash: to_hex_b256(&tx_hash),
            nonce: to_hex_u256(&U256::from(tx.nonce)),
            block_hash: block_hash.map(|h| Value::String(to_hex_b256(&h))).unwrap_or(Value::Null),
            block_number: block_number.map(|n| Value::String(to_hex_u64(n))).unwrap_or(Value::Null),
            transaction_index: tx_index.map(|i| Value::String(to_hex_u64(i as u64))).unwrap_or(Value::Null),
            from: format!("{:#x}", sender),
            to: to_value,
            gas: to_hex_u256(&tx.gas_limit),
            gas_price: to_hex_u256(&tx.gas_price),
            value: to_hex_u256(&tx.value),
            input: if tx.input.is_empty() { "0x".to_string() } else { to_hex_bytes(&tx.input) },
            v: format!("0x{:02x}", tx.v),
            r: to_hex_u256(&tx.r),
            s: to_hex_u256(&tx.s),
            tx_type: "0x0".to_string(),
        }
    }
}

/// Transaction receipt DTO matching rskj's `TransactionReceiptDTO`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptDto {
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub block_number: String,
    pub cumulative_gas_used: String,
    pub gas_used: String,
    pub contract_address: Value,
    pub logs: Vec<LogDto>,
    pub from: String,
    pub to: Value,
    pub status: String,
    pub logs_bloom: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

impl ReceiptDto {
    #[allow(clippy::too_many_arguments)]
    pub fn from_receipt(
        receipt: &Receipt,
        tx: &Transaction,
        tx_hash: B256,
        block_hash: B256,
        block_number: u64,
        tx_index: u32,
        sender: Address,
        log_index_start: u32,
    ) -> Self {
        let to_value = if tx.to.is_empty() {
            Value::Null
        } else if tx.to.len() == 20 {
            Value::String(format!("{:#x}", Address::from_slice(&tx.to)))
        } else {
            Value::String(to_hex_bytes(&tx.to))
        };

        let contract_address = if tx.to.is_empty() && receipt.status {
            let sender_bytes = sender.as_slice();
            let nonce = tx.nonce;
            let contract = compute_contract_address(sender_bytes, nonce);
            Value::String(format!("{:#x}", contract))
        } else {
            Value::Null
        };

        let logs: Vec<LogDto> = receipt.logs.iter().enumerate().map(|(i, log)| {
            LogDto::from_log(
                log,
                block_hash,
                block_number,
                tx_hash,
                tx_index,
                log_index_start + i as u32,
            )
        }).collect();

        Self {
            transaction_hash: to_hex_b256(&tx_hash),
            transaction_index: to_hex_u64(tx_index as u64),
            block_hash: to_hex_b256(&block_hash),
            block_number: to_hex_u64(block_number),
            cumulative_gas_used: to_hex_u64(receipt.cumulative_gas_used),
            gas_used: to_hex_u64(receipt.gas_used),
            contract_address,
            logs,
            from: format!("{:#x}", sender),
            to: to_value,
            status: if receipt.status { "0x1".to_string() } else { "0x0".to_string() },
            logs_bloom: to_hex_bytes(receipt.logs_bloom.as_ref()),
            tx_type: "0x0".to_string(),
        }
    }
}

/// Log DTO matching rskj's log format in receipts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogDto {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub block_hash: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub log_index: String,
    pub removed: bool,
}

impl LogDto {
    pub fn from_log(
        log: &rustock_core::Log,
        block_hash: B256,
        block_number: u64,
        tx_hash: B256,
        tx_index: u32,
        log_index: u32,
    ) -> Self {
        Self {
            address: format!("{:#x}", log.address),
            topics: log.topics.iter().map(to_hex_b256).collect(),
            data: if log.data.is_empty() { "0x".to_string() } else { to_hex_bytes(&log.data) },
            block_number: to_hex_u64(block_number),
            block_hash: to_hex_b256(&block_hash),
            transaction_hash: to_hex_b256(&tx_hash),
            transaction_index: to_hex_u64(tx_index as u64),
            log_index: to_hex_u64(log_index as u64),
            removed: false,
        }
    }
}

/// A call's arguments as rskj's `CallArgumentsParam` holds them: each field
/// checked, and the numbers still as they were written.
///
/// rskj reads a call's arguments in two steps. Its deserializer checks every
/// field it knows, in its own order whatever the order written, and what a
/// field's type refuses is `-32602`: an address that isn't one, a number that
/// isn't hex or a decimal, data that isn't hex. A field that is absent or
/// `null` is not there, and what isn't an object has no fields. Then, with the
/// block in hand, `CallArgumentsToByteArray` reads the numbers
/// ([`CallArguments::request`]). A transaction the node is to sign has them
/// read another way ([`CallArguments::transaction`]).
#[derive(Debug)]
pub struct CallArguments {
    from: Option<Address>,
    to: Option<Address>,
    gas: Option<String>,
    gas_price: Option<String>,
    gas_limit: Option<String>,
    nonce: Option<String>,
    chain_id: Option<String>,
    value: Option<String>,
    data: Option<Vec<u8>>,
}

/// What rskj makes of a call's arguments to build a transaction it signs
/// (`TransactionArgumentsUtil.processArguments`).
#[derive(Debug)]
pub struct TransactionArguments {
    pub to: Option<Address>,
    /// `None` where the arguments name none: the sender's next.
    pub nonce: Option<U256>,
    pub value: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub data: Vec<u8>,
    /// The chain the arguments name, and how they wrote it. `None` where they
    /// name none, or name 0: the node's own.
    pub chain_id: Option<(u8, String)>,
}

/// The gas a sent transaction names when the caller names none: rskj's
/// `GasCost.TRANSACTION_DEFAULT`.
const TRANSACTION_DEFAULT_GAS: u64 = 90_000;

/// The chain a transaction's arguments name (`TransactionArgumentsUtil
/// .hexToChainId`): the one byte their `chainId` writes, read as a call's
/// numbers are ([`crate::params::number_bytes`]). `None` for 0, which is the
/// node's own chain. Anything that isn't one byte, and anything thrown on the
/// way, is `-32602 Invalid chainId`.
fn named_chain(written: String) -> Result<Option<(u8, String)>, crate::params::Refusal> {
    match crate::params::number_bytes(&written).as_deref() {
        Ok([0]) => Ok(None),
        Ok(&[chain]) => Ok(Some((chain, written))),
        _ => Err((
            crate::types::INVALID_PARAMS,
            format!("Invalid chainId: {written}"),
        )),
    }
}

impl CallArguments {
    /// `CallArgumentsParam.Deserializer`. `arguments` is not `null`: that
    /// reaches the method as no arguments at all, and what the method makes of
    /// that is its own.
    pub fn read(arguments: &serde_json::Value) -> Result<Self, crate::params::Refusal> {
        use crate::params::{field_text, hex_address, hex_data, hex_number};
        let field = |name: &str| arguments.get(name).and_then(field_text);
        let number = |name: &str| match field(name) {
            Some(text) => hex_number(&text).map(|()| Some(text)),
            None => Ok(None),
        };
        let from = field("from").map(|text| hex_address(&text)).transpose()?;
        let to = field("to").map(|text| hex_address(&text)).transpose()?;
        let gas = number("gas")?;
        let gas_price = number("gasPrice")?;
        // Checked, and read only for a transaction the node signs.
        let gas_limit = number("gasLimit")?;
        let nonce = number("nonce")?;
        let chain_id = number("chainId")?;
        let value = number("value")?;
        let data = field("data").map(|text| hex_data(&text)).transpose()?;
        let input = field("input").map(|text| hex_data(&text)).transpose()?;
        Ok(Self {
            from,
            to,
            gas,
            gas_price,
            gas_limit,
            nonce,
            chain_id,
            value,
            // `CallArguments.setInput` writes over what `setData` wrote.
            data: input.or(data),
        })
    }

    /// The sender the arguments name.
    pub fn from(&self) -> Option<Address> {
        self.from
    }

    /// `TransactionArgumentsUtil.processArguments`: the arguments of a
    /// transaction the node is to sign, read in rskj's order -- the nonce,
    /// the value, the gas price, the gas, the chain -- each number as
    /// [`crate::params::transaction_number`] reads it.
    ///
    /// The defaults are rskj's: no value, a gas price of 0, and the gas
    /// named as `gas`, or else as `gasLimit`, which is read only then, or
    /// else 90,000.
    pub fn transaction(self) -> Result<TransactionArguments, crate::params::Refusal> {
        use crate::params::transaction_number;
        let read = |text: Option<String>| text.map(|text| transaction_number(&text)).transpose();
        let nonce = read(self.nonce)?;
        let value = read(self.value)?.unwrap_or_default();
        let gas_price = read(self.gas_price)?.unwrap_or_default();
        let gas_limit = match read(self.gas)? {
            Some(gas) => gas,
            None => read(self.gas_limit)?.unwrap_or(U256::from(TRANSACTION_DEFAULT_GAS)),
        };
        let chain_id = match self.chain_id {
            Some(written) => named_chain(written)?,
            None => None,
        };
        Ok(TransactionArguments {
            to: self.to,
            nonce,
            value,
            gas_price,
            gas_limit,
            data: self.data.unwrap_or_default(),
            chain_id,
        })
    }

    /// `CallArgumentsToByteArray`: the gas price, the gas and the value read
    /// as numbers, in that order ([`crate::params::number_bytes`]). One
    /// written as nothing is not there.
    ///
    /// A call's gas is held to `rpc.callGasCap` whatever it names, and one
    /// written in more than eight bytes is an error nobody catches
    /// (`ByteUtil.byteArrayToLong`). A gas of 2^63 or more in eight bytes
    /// gets past rskj's own cap, which compares it as a `long`
    /// (`gasLimitForCall`): a contract then runs on 2^63 - 1 gas, and a call
    /// to anything else is an error. That isn't followed. It is held to the
    /// cap like any other.
    pub fn request(self) -> Result<CallRequest, crate::params::Refusal> {
        use crate::params::{number, number_bytes, uncaught};
        let written = |text: Option<String>| text.filter(|text| !text.is_empty());
        let gas_price = written(self.gas_price)
            .map(|text| number(&text))
            .transpose()?;
        let gas = match written(self.gas)
            .map(|text| number_bytes(&text))
            .transpose()?
        {
            Some(bytes) if bytes.len() > 8 => return Err(uncaught()),
            Some(bytes) => Some(
                bytes
                    .iter()
                    .fold(0u64, |gas, byte| gas << 8 | u64::from(*byte)),
            ),
            None => None,
        };
        let value = written(self.value).map(|text| number(&text)).transpose()?;
        Ok(CallRequest {
            from: self.from,
            to: self.to,
            gas,
            gas_price,
            value,
            data: self.data,
        })
    }

    /// [`CallArguments::request`] for an estimate, which reads the gas price
    /// and the value and not the gas (`EthModule.estimateGas` runs every
    /// estimate at its cap).
    pub fn estimate_request(mut self) -> Result<CallRequest, crate::params::Refusal> {
        self.gas = None;
        self.request()
    }
}

/// Call request object for eth_call / eth_estimateGas.
#[derive(Debug)]
pub struct CallRequest {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas: Option<u64>,
    pub gas_price: Option<U256>,
    pub value: Option<U256>,
    pub data: Option<Vec<u8>>,
}

fn compute_contract_address(sender: &[u8], nonce: u64) -> Address {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let mut payload = Vec::new();
    sender.encode(&mut payload);
    U256::from(nonce).encode(&mut payload);

    let mut buf = Vec::new();
    alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut buf);
    buf.extend_from_slice(&payload);

    let hash = Keccak256::digest(&buf);
    Address::from_slice(&hash[12..])
}
