/// Block and transaction environment construction for revm.
///
/// Translates RSK block headers and transactions into revm's `BlockEnv`
/// and `TxEnv` structures, accounting for RSK-specific fields like
/// `minimum_gas_price` and merged-mining difficulty.
use alloy_primitives::{Address, B256, Bytes, U256};
use revm::context::{BlockEnv, TxEnv};
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;
use rustock_core::Header;
use crate::executor::ExecutionError;
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::REMASC_ADDR;

/// Build a revm `BlockEnv` from an RSK block header.
///
/// In RSK, transaction fees are credited to the REMASC contract rather than the
/// miner directly. REMASC later distributes rewards with delayed maturity. We
/// set `beneficiary` to `REMASC_ADDR` so revm routes all gas-fee payments to
/// the REMASC account; the actual miner (`header.beneficiary`) is paid later
/// when REMASC runs.
pub fn block_env_from_header(header: &Header, hardfork_cfg: &RskHardforkConfig) -> BlockEnv {
    let spec = hardfork_cfg.spec_id(header.number);
    let prevrandao = if spec.is_enabled_in(SpecId::MERGE) {
        Some(B256::from(header.difficulty.to_be_bytes::<32>()))
    } else {
        None
    };

    BlockEnv {
        number: U256::from(header.number),
        beneficiary: REMASC_ADDR,
        timestamp: U256::from(header.timestamp),
        // revm reads this for GASLIMIT, which `rsk_instructions` replaces to
        // push the whole value, and to hold a transaction's gas limit to the
        // block's. rskj holds it to the gas limit read as gas
        // (`GasCost.toGas`), or to its sublist's, which the executor checks
        // first. A gas limit that isn't gas fails its block before any
        // transaction runs.
        gas_limit: header.gas_limit_as_gas().unwrap_or(u64::MAX),
        difficulty: header.difficulty,
        // RSK uses minimum_gas_price instead of EIP-1559 basefee. revm reads
        // it for BASEFEE, which `rsk_instructions` replaces to push the
        // whole value, and to hold a transaction's gas price to at least
        // this: cut to fit, it is still no more than a valid one's.
        basefee: header.minimum_gas_price.saturating_to(),
        prevrandao,
        blob_excess_gas_and_price: None,
        ..Default::default()
    }
}

/// Whether rskj can build a program's invocation from this header, as it
/// does for each transaction that runs code (`ProgramInvokeFactoryImpl`).
/// It puts the gas limit's bytes, and the difficulty's and the minimum gas
/// price's `toByteArray`, each in a `DataWord`, and `DataWord.valueOf`
/// throws past 32 bytes: a gas limit written in more than 32, or a
/// difficulty or minimum gas price of 2^255 or more, which takes a sign
/// byte. Nothing catches it: the block is not imported, and a miner leaves
/// the transaction out.
pub fn header_fits_program_invoke(header: &Header) -> bool {
    header.gas_limit_bytes().len() <= 32
        && header.difficulty.bit_len() < 256
        && header.minimum_gas_price.bit_len() < 256
}

/// Build a revm `TxEnv` from an RSK transaction.
///
/// RSK transactions are legacy-only (no EIP-1559/EIP-2930/EIP-4844).
///
/// Two transactions are refused rather than cut to fit. One whose gas limit
/// rskj cannot read as gas: `GasCost.toGas` throws on eight bytes with the
/// top bit set. And one priced at 2^128 or more, which revm's `TxEnv` cannot
/// hold; rskj carries the price as a `BigInteger`, but no balance on mainnet
/// or testnet covers it even at 21,000 gas, so there rskj refuses the
/// transaction too ("Not enough cash").
pub fn tx_env_from_rsk_tx(
    tx: &rustock_core::Transaction,
    sender: Address,
    _hardfork_cfg: &RskHardforkConfig,
) -> Result<TxEnv, ExecutionError> {
    let gas_price = u128::try_from(tx.gas_price)
        .map_err(|_| ExecutionError::Evm(format!("gas price {} is 2^128 or more", tx.gas_price)))?;
    tx_env(tx, sender, gas_price)
}

/// A local call's `TxEnv`, and its gas price where that is 2^128 or more.
///
/// rskj runs a call at whatever price it names: a local call is charged no
/// gas, so no balance has to cover it (`TransactionExecutor.execute`), and
/// GASPRICE pushes the price whole. revm's `TxEnv` can't hold such a price, so
/// its own is 0 then and the whole one goes beside it, in
/// `RskChainExt::whole_gas_price`, where GASPRICE finds it.
pub fn local_call_env(
    tx: &rustock_core::Transaction,
    sender: Address,
) -> Result<(TxEnv, Option<U256>), ExecutionError> {
    match u128::try_from(tx.gas_price) {
        Ok(gas_price) => Ok((tx_env(tx, sender, gas_price)?, None)),
        Err(_) => Ok((tx_env(tx, sender, 0)?, Some(tx.gas_price))),
    }
}

/// The `TxEnv` of `tx` at `gas_price`. See [`tx_env_from_rsk_tx`].
fn tx_env(
    tx: &rustock_core::Transaction,
    sender: Address,
    gas_price: u128,
) -> Result<TxEnv, ExecutionError> {
    let gas_limit = tx.gas().ok_or_else(|| {
        ExecutionError::Evm(format!(
            "gas limit {} is not gas: eight bytes with the top bit set",
            tx.gas_limit
        ))
    })?;
    let kind = if tx.to.is_empty() {
        TxKind::Create
    } else {
        let mut addr_bytes = [0u8; 20];
        let len = tx.to.len().min(20);
        addr_bytes[20 - len..].copy_from_slice(&tx.to[..len]);
        TxKind::Call(Address::from(addr_bytes))
    };

    Ok(TxEnv {
        tx_type: 0, // legacy
        caller: sender,
        gas_limit,
        gas_price,
        kind,
        value: tx.value,
        data: Bytes::copy_from_slice(&tx.input),
        nonce: tx.nonce,
        chain_id: None, // RSK legacy transactions may or may not include chain_id in v
        access_list: Default::default(),
        gas_priority_fee: None,
        blob_hashes: Vec::new(),
        max_fee_per_blob_gas: 0,
        authorization_list: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bloom, B256, Bytes as AlBytes};

    fn dummy_header(number: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::repeat_byte(0x01),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(1_000_000),
            number,
            gas_limit: U256::from(6_800_000),
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: AlBytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(59_240_000),
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
            kept: None,
        }
    }

    #[test]
    fn test_block_env_from_header() {
        let cfg = RskHardforkConfig::mainnet();
        let header = dummy_header(7_500_000);
        let env = block_env_from_header(&header, &cfg);

        assert_eq!(env.number, U256::from(7_500_000u64));
        assert_eq!(env.beneficiary, REMASC_ADDR);
        assert_eq!(env.gas_limit, 6_800_000);
        assert_eq!(env.difficulty, U256::from(1_000_000u64));
        assert_eq!(env.basefee, 59_240_000);
        // Block 7_500_000 is post-Lovell (SHANGHAI), so prevrandao is set to difficulty
        assert_eq!(
            env.prevrandao,
            Some(B256::from(U256::from(1_000_000u64).to_be_bytes::<32>()))
        );
    }

    #[test]
    fn test_block_env_pre_merge_no_prevrandao() {
        let cfg = RskHardforkConfig::mainnet();
        let header = dummy_header(1_000_000); // pre-Papyrus, maps to BYZANTIUM
        let env = block_env_from_header(&header, &cfg);
        assert!(env.prevrandao.is_none());
    }

    /// Past 64 bits nothing panics: the gas limit is held as gas
    /// (`GasCost.toGas`) and the minimum gas price cut to fit, while GASLIMIT
    /// and BASEFEE push both whole (`rsk_instructions`).
    #[test]
    fn header_values_past_64_bits_are_held_as_revm_can() {
        let cfg = RskHardforkConfig::mainnet();
        let past = U256::from(1) << 64;
        let header = Header {
            gas_limit: past,
            minimum_gas_price: past,
            ..dummy_header(7_500_000)
        };
        let env = block_env_from_header(&header, &cfg);
        assert_eq!(env.gas_limit, i64::MAX as u64);
        assert_eq!(env.basefee, u64::MAX);
    }

    /// rskj's program holds the gas limit's bytes, and the difficulty's and
    /// the minimum gas price's `toByteArray`, each in a `DataWord` of 32.
    #[test]
    fn a_program_holds_the_headers_words_in_32_bytes() {
        let one = U256::from(1);
        let below = (one << 255) - one;
        let fits = |header: Header| header_fits_program_invoke(&header);
        assert!(fits(Header {
            gas_limit: below,
            difficulty: below,
            minimum_gas_price: below,
            ..dummy_header(1)
        }));
        // 2^255 takes a sign byte, which makes 33.
        assert!(!fits(Header {
            gas_limit: one << 255,
            ..dummy_header(1)
        }));
        assert!(!fits(Header {
            difficulty: one << 255,
            ..dummy_header(1)
        }));
        assert!(!fits(Header {
            minimum_gas_price: one << 255,
            ..dummy_header(1)
        }));
        // The gas limit counts as written: one in 33 bytes is past.
        let mut written = vec![0; 33];
        written[32] = 1;
        assert!(!fits(Header {
            gas_limit: one,
            kept: Some(Box::new(rustock_core::types::header::KeptFields {
                gas_limit: Some(written.into()),
                ..Default::default()
            })),
            ..dummy_header(1)
        }));
    }

    #[test]
    fn test_tx_env_call() {
        let cfg = RskHardforkConfig::mainnet();
        let mut to_bytes = vec![0u8; 20];
        to_bytes[19] = 0xAA;
        let tx = rustock_core::Transaction {
            nonce: 5,
            gas_price: U256::from(1_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: AlBytes::from(to_bytes),
            value: U256::from(1_000),
            input: AlBytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let sender = Address::repeat_byte(0xBB);
        let env = tx_env_from_rsk_tx(&tx, sender, &cfg).unwrap();

        assert_eq!(env.caller, sender);
        assert_eq!(env.nonce, 5);
        assert_eq!(env.gas_limit, 21_000);
        assert_eq!(env.value, U256::from(1_000));
        assert!(matches!(env.kind, TxKind::Call(_)));
    }

    #[test]
    fn test_tx_env_create() {
        let cfg = RskHardforkConfig::mainnet();
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1_000_000_000u64),
            gas_limit: U256::from(100_000),
            to: AlBytes::new(), // empty = contract creation
            value: U256::ZERO,
            input: AlBytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xF3]), // dummy initcode
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let sender = Address::repeat_byte(0xCC);
        let env = tx_env_from_rsk_tx(&tx, sender, &cfg).unwrap();

        assert!(matches!(env.kind, TxKind::Create));
        assert_eq!(env.data.len(), 5);
    }

    /// What revm's `TxEnv` cannot hold is refused, never cut to fit and
    /// never a panic: a gas limit rskj cannot read as gas, and a price of
    /// 2^128 or more. A gas limit past eight bytes reads as rskj reads it,
    /// `Long.MAX_VALUE`, which no block's gas then fits.
    #[test]
    fn what_the_evm_cannot_carry_is_refused() {
        let cfg = RskHardforkConfig::mainnet();
        let tx = |gas_limit: U256, gas_price: U256| rustock_core::Transaction {
            nonce: 0,
            gas_price,
            gas_limit,
            to: AlBytes::from(vec![0xAA; 20]),
            value: U256::ZERO,
            input: AlBytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        let env = |gas_limit, gas_price| {
            tx_env_from_rsk_tx(&tx(gas_limit, gas_price), Address::ZERO, &cfg)
        };
        let one = U256::from(1u64);

        assert!(env(one << 63, one).is_err(), "eight bytes, top bit set");
        assert_eq!(
            env((one << 63) - one, one).unwrap().gas_limit,
            i64::MAX as u64
        );
        assert_eq!(
            env(one << 64, one).unwrap().gas_limit,
            i64::MAX as u64,
            "nine bytes"
        );
        assert_eq!(env(U256::MAX, one).unwrap().gas_limit, i64::MAX as u64);

        assert!(env(U256::from(21_000), one << 128).is_err());
        assert!(env(U256::from(21_000), U256::MAX).is_err());
        assert_eq!(
            env(U256::from(21_000), U256::from(u128::MAX))
                .unwrap()
                .gas_price,
            u128::MAX
        );
    }

    /// A local call runs at any price, as rskj's does: one revm's `TxEnv`
    /// can't hold goes beside it, whole, and the `TxEnv`'s own is 0. The gas
    /// limit is read as a transaction's is.
    #[test]
    fn a_local_call_carries_any_gas_price() {
        let tx = |gas_limit: U256, gas_price: U256| rustock_core::Transaction {
            nonce: 0,
            gas_price,
            gas_limit,
            to: AlBytes::from(vec![0xAA; 20]),
            value: U256::ZERO,
            input: AlBytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        let env = |gas_limit, gas_price| local_call_env(&tx(gas_limit, gas_price), Address::ZERO);
        let (one, gas) = (U256::from(1u64), U256::from(21_000));

        let (held, whole) = env(gas, U256::from(u128::MAX)).unwrap();
        assert_eq!((held.gas_price, whole), (u128::MAX, None));
        for price in [one << 128, (one << 255) - one, U256::MAX] {
            let (held, whole) = env(gas, price).unwrap();
            assert_eq!((held.gas_price, whole), (0, Some(price)));
        }
        assert!(env(one << 63, one).is_err(), "eight bytes, top bit set");
    }
}
