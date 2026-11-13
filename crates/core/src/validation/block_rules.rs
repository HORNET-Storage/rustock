//! Block-level consensus rules — the ones that need the block body, not just
//! its header.
//!
//! rskj composes these in `RskContext.getBlockValidationRule` alongside the
//! header rules. Each one *rejects a block*: rustock computing the same state
//! root as rskj for every block rskj accepts is necessary but not sufficient,
//! because a validator that never rejects follows any chain it is given.

use super::{BlockValidator, HeaderValidator, ParentHeaderValidator, ValidationError};
use crate::types::block::Block;
use crate::types::header::Header;
use alloy_primitives::U256;
use num_bigint::BigUint;

/// The REMASC contract address (`…01000008`), which the synthetic last
/// transaction of every RSK block is sent to. Mirrors
/// `rustock_execution::precompiles::REMASC_ADDR`, duplicated here because
/// `rustock-core` sits below the execution crate.
pub(crate) const REMASC_ADDR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x08,
];

/// Whether `block`'s transaction at `index` is its REMASC transaction, which
/// rskj makes a `RemascTransaction` (`Transaction.isRemascTransaction`): only
/// the last can be.
fn is_remasc(block: &Block, index: usize) -> bool {
    block.transactions[index].is_remasc(index, block.transactions.len())
}

/// rskj `TxsMinGasPriceRule`: every non-REMASC transaction must pay at least
/// the block's `minimumGasPrice`. Unconditional — no activation gate.
///
/// A minimum past 256 bits is `U256::MAX` here. No transaction's price
/// reaches either, since a block's transactions pay under 2^255
/// (`Transaction::from_rskj`), so the rule decides as rskj's does.
pub struct TxsMinGasPriceRule;

impl BlockValidator for TxsMinGasPriceRule {
    fn validate_block(&self, block: &Block) -> Result<(), ValidationError> {
        let min = block.header.minimum_gas_price;
        for (index, tx) in block.transactions.iter().enumerate() {
            if is_remasc(block, index) {
                continue;
            }
            if tx.gas_price < min {
                return Err(ValidationError::TxGasPriceBelowMinimum {
                    tx_gas_price: tx.gas_price,
                    block_minimum: block.header.minimum_gas_price_value(),
                });
            }
        }
        Ok(())
    }
}

/// rskj `BlockTxsMaxGasPriceRule` + `TxGasPriceCap.FOR_BLOCK` (RSKIP252,
/// fingerroot500): no transaction may pay more than 100x the block's
/// `minimumGasPrice`.
///
/// `TxGasPriceCap.isSurpassed` short-circuits on two cases before comparing:
/// a REMASC transaction never surpasses the cap, and neither does anything
/// when the block's minimum gas price is zero.
pub struct BlockTxsMaxGasPriceRule {
    /// First block at which RSKIP252 applies (`fingerroot500`).
    pub rskip252_height: u64,
}

impl BlockTxsMaxGasPriceRule {
    /// `TxGasPriceCap.FOR_BLOCK`.
    pub const FOR_BLOCK_MULTIPLIER: u64 = 100;
}

impl BlockValidator for BlockTxsMaxGasPriceRule {
    fn validate_block(&self, block: &Block) -> Result<(), ValidationError> {
        if block.header.number < self.rskip252_height {
            return Ok(());
        }
        let min = block.header.minimum_gas_price;
        if min.is_zero() {
            return Ok(());
        }
        let cap = min.saturating_mul(U256::from(Self::FOR_BLOCK_MULTIPLIER));
        for (index, tx) in block.transactions.iter().enumerate() {
            if is_remasc(block, index) {
                continue;
            }
            if tx.gas_price > cap {
                return Err(ValidationError::TxGasPriceAboveCap {
                    tx_gas_price: tx.gas_price,
                    cap,
                });
            }
        }
        Ok(())
    }
}

/// rskj `RemascValidationRule`: the block's transaction list must be non-empty
/// and its **last** entry must be the REMASC transaction.
pub struct RemascValidationRule;

impl BlockValidator for RemascValidationRule {
    fn validate_block(&self, block: &Block) -> Result<(), ValidationError> {
        match block.transactions.len().checked_sub(1) {
            Some(last) if is_remasc(block, last) => Ok(()),
            _ => Err(ValidationError::RemascTxMissing),
        }
    }
}

/// rskj `ExtraDataRule`: `extraData` may not exceed
/// `Constants.getMaximumExtraDataSize()` (32 on every RSK network).
pub struct ExtraDataRule {
    pub max_size: usize,
}

impl Default for ExtraDataRule {
    fn default() -> Self {
        Self { max_size: 32 }
    }
}

impl HeaderValidator for ExtraDataRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        if header.extra_data.len() > self.max_size {
            return Err(ValidationError::ExtraDataTooLarge {
                max: self.max_size,
                got: header.extra_data.len(),
            });
        }
        Ok(())
    }
}

/// rskj `PrevMinGasPriceRule` + `BlockGasPriceRange`: a block's
/// `minimumGasPrice` may move by at most 1% of its parent's, in either
/// direction, per block.
///
/// `BlockGasPriceRange(center)`:
/// ```text
///   delta = center * 1 / 100        (integer division)
///   delta = 1 when that is zero     (so a zero parent can still rise to 1)
///   upper = center + delta
///   lower = max(0, center - delta)
/// ```
/// and the header's value must lie in `[lower, upper]` inclusive. rskj
/// computes it in `Coin`, a `BigInteger`, and nothing bounds the price from
/// above, so both are read whole, of any size.
pub struct PrevMinGasPriceRule;

impl PrevMinGasPriceRule {
    /// The inclusive `[lower, upper]` band a child's minimum gas price may
    /// occupy, given the parent's.
    pub fn range(parent_min_gas_price: &BigUint) -> (BigUint, BigUint) {
        let center = parent_min_gas_price;
        let mut delta = center / 100u32;
        if delta == BigUint::ZERO {
            delta = BigUint::from(1u32);
        }
        let upper = center + &delta;
        let lower = if *center >= delta {
            center - &delta
        } else {
            BigUint::ZERO
        };
        (lower, upper)
    }
}

impl ParentHeaderValidator for PrevMinGasPriceRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        if header.number == 0 {
            return Ok(());
        }
        let (lower, upper) = Self::range(&parent.minimum_gas_price_value());
        let got = header.minimum_gas_price_value();
        if got < lower || got > upper {
            return Err(ValidationError::MinGasPriceOutOfRange { lower, upper, got });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transaction::Transaction;
    use alloy_primitives::{Address, Bytes, B256};

    fn bare_header(number: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::ZERO,
            number,
            gas_limit: U256::from(10_000_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
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

    fn remasc_tx() -> Transaction {
        Transaction::remasc(9_000_000)
    }

    fn user_tx(gas_price: u64) -> Transaction {
        Transaction {
            nonce: 0,
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(&[0xBBu8; 20]),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 27,
            r: U256::from(1u64),
            s: U256::from(1u64),
            cached_rlp: None,
        }
    }

    fn block_at(number: u64, min_gas_price: u64, txs: Vec<Transaction>) -> Block {
        let mut header = bare_header(number);
        header.minimum_gas_price = U256::from(min_gas_price);
        Block { header, transactions: txs, ommers: vec![] }
    }

    /// rskj `TxsMinGasPriceRule`.
    #[test]
    fn txs_min_gas_price_rejects_an_underpriced_tx() {
        let ok = block_at(9_000_000, 100, vec![user_tx(100), remasc_tx()]);
        assert!(TxsMinGasPriceRule.validate_block(&ok).is_ok());

        let under = block_at(9_000_000, 100, vec![user_tx(99), remasc_tx()]);
        assert!(matches!(
            TxsMinGasPriceRule.validate_block(&under),
            Err(ValidationError::TxGasPriceBelowMinimum { .. })
        ));

        // The REMASC transaction pays nothing and is exempt; one of its shape
        // before the last is no REMASC transaction, and is not.
        let only_remasc = block_at(9_000_000, 100, vec![remasc_tx()]);
        assert!(TxsMinGasPriceRule.validate_block(&only_remasc).is_ok());
        let early = block_at(9_000_000, 100, vec![remasc_tx(), user_tx(100), remasc_tx()]);
        assert!(matches!(
            TxsMinGasPriceRule.validate_block(&early),
            Err(ValidationError::TxGasPriceBelowMinimum { .. })
        ));
    }

    /// rskj `BlockTxsMaxGasPriceRule` + `TxGasPriceCap.FOR_BLOCK` (RSKIP252).
    #[test]
    fn block_txs_max_gas_price_enforces_the_100x_cap_from_rskip252() {
        let rule = BlockTxsMaxGasPriceRule { rskip252_height: 5_468_000 };

        // At the cap exactly: allowed (`compareTo(cap) > 0`).
        let at_cap = block_at(9_000_000, 100, vec![user_tx(10_000), remasc_tx()]);
        assert!(rule.validate_block(&at_cap).is_ok());

        let over = block_at(9_000_000, 100, vec![user_tx(10_001), remasc_tx()]);
        assert!(matches!(
            rule.validate_block(&over),
            Err(ValidationError::TxGasPriceAboveCap { .. })
        ));

        // One block before fingerroot500 the rule does not apply.
        let pre = block_at(5_467_999, 100, vec![user_tx(10_001), remasc_tx()]);
        assert!(rule.validate_block(&pre).is_ok());

        // `isSurpassed` short-circuits when the block's minimum is zero.
        let zero_min = block_at(9_000_000, 0, vec![user_tx(u64::MAX), remasc_tx()]);
        assert!(rule.validate_block(&zero_min).is_ok());
    }

    /// rskj `RemascValidationRule`.
    #[test]
    fn remasc_rule_requires_remasc_as_the_last_transaction() {
        let ok = block_at(9_000_000, 0, vec![user_tx(0), remasc_tx()]);
        assert!(RemascValidationRule.validate_block(&ok).is_ok());

        // Present but not last.
        let misplaced = block_at(9_000_000, 0, vec![remasc_tx(), user_tx(0)]);
        assert!(matches!(
            RemascValidationRule.validate_block(&misplaced),
            Err(ValidationError::RemascTxMissing)
        ));

        // Absent entirely, and the empty block.
        let absent = block_at(9_000_000, 0, vec![user_tx(0)]);
        assert!(RemascValidationRule.validate_block(&absent).is_err());
        let empty = block_at(9_000_000, 0, vec![]);
        assert!(RemascValidationRule.validate_block(&empty).is_err());
    }

    /// rskj `ExtraDataRule` with `Constants.getMaximumExtraDataSize()` = 32.
    #[test]
    fn extra_data_rule_caps_at_32_bytes() {
        let rule = ExtraDataRule::default();
        assert_eq!(rule.max_size, 32);

        let mut header = bare_header(9_000_000);
        header.extra_data = Bytes::from(vec![0u8; 32]);
        assert!(rule.validate(&header).is_ok());

        header.extra_data = Bytes::from(vec![0u8; 33]);
        assert!(matches!(
            rule.validate(&header),
            Err(ValidationError::ExtraDataTooLarge { max: 32, got: 33 })
        ));
    }

    /// rskj `PrevMinGasPriceRule` + `BlockGasPriceRange`.
    #[test]
    fn prev_min_gas_price_allows_one_percent_either_way() {
        // center 1000 -> delta 10 -> [990, 1010] inclusive.
        let (lower, upper) = PrevMinGasPriceRule::range(&BigUint::from(1000u32));
        assert_eq!(lower, BigUint::from(990u32));
        assert_eq!(upper, BigUint::from(1010u32));

        // A zero parent still gets delta 1, so it can rise to 1 (and the lower
        // bound is clamped at zero rather than going negative).
        let (lower, upper) = PrevMinGasPriceRule::range(&BigUint::ZERO);
        assert_eq!(lower, BigUint::ZERO);
        assert_eq!(upper, BigUint::from(1u32));

        let mut parent = bare_header(8_999_999);
        parent.minimum_gas_price = U256::from(1000u64);

        let check = |mgp: u64| {
            let mut header = bare_header(9_000_000);
            header.minimum_gas_price = U256::from(mgp);
            PrevMinGasPriceRule.validate_with_parent(&header, &parent)
        };

        assert!(check(990).is_ok());
        assert!(check(1010).is_ok());
        assert!(check(1000).is_ok());
        assert!(matches!(
            check(989),
            Err(ValidationError::MinGasPriceOutOfRange { .. })
        ));
        assert!(matches!(
            check(1011),
            Err(ValidationError::MinGasPriceOutOfRange { .. })
        ));
    }

    /// rskj computes the range in `BigInteger`, so it holds past 256 bits,
    /// where the typed field holds `U256::MAX`: 1% either way, exactly.
    #[test]
    fn prev_min_gas_price_is_exact_past_256_bits() {
        let two = BigUint::from(2u8);
        let at = |number: u64, price: &BigUint| {
            let mut header = bare_header(number);
            header.set_minimum_gas_price(price);
            header
        };
        let check = |parent: &BigUint, price: &BigUint| {
            PrevMinGasPriceRule.validate_with_parent(&at(9_000_000, price), &at(8_999_999, parent))
        };
        // 1% of 100 * 2^294 + 12,345 is 2^294 + 123.
        let parent = two.pow(294) * 100u32 + 12_345u32;
        let lower = two.pow(294) * 99u32 + 12_222u32;
        let upper = two.pow(294) * 101u32 + 12_468u32;
        assert_eq!(
            PrevMinGasPriceRule::range(&parent),
            (lower.clone(), upper.clone())
        );
        for price in [&lower, &parent, &upper] {
            assert_eq!(check(&parent, price), Ok(()));
        }
        assert_eq!(
            check(&parent, &(&lower - 1u8)),
            Err(ValidationError::MinGasPriceOutOfRange {
                lower: lower.clone(),
                upper: upper.clone(),
                got: &lower - 1u8,
            })
        );
        assert!(check(&parent, &(&upper + 1u8)).is_err());
        // A parent under 2^256 that 100 divides: its child may rise past
        // 2^256 by exactly 1%, and no further.
        let parent = two.pow(256) - 36u8;
        let upper = &parent / 100u32 * 101u32;
        assert!(upper > two.pow(256));
        assert_eq!(check(&parent, &upper), Ok(()));
        assert!(check(&parent, &(&upper + 1u8)).is_err());
    }

    /// A minimum past 256 bits refuses every transaction but REMASC, as rskj's
    /// does, and the refusal names the minimum whole.
    #[test]
    fn a_minimum_gas_price_past_256_bits_refuses_all_but_remasc() {
        let minimum = BigUint::from(2u8).pow(300);
        let mut block = block_at(9_000_000, 0, vec![remasc_tx()]);
        block.header.set_minimum_gas_price(&minimum);
        assert_eq!(TxsMinGasPriceRule.validate_block(&block), Ok(()));
        let mut highest = user_tx(0);
        highest.gas_price = (U256::from(1) << 255) - U256::from(1);
        block.transactions.insert(0, highest.clone());
        assert_eq!(
            TxsMinGasPriceRule.validate_block(&block),
            Err(ValidationError::TxGasPriceBelowMinimum {
                tx_gas_price: highest.gas_price,
                block_minimum: minimum,
            })
        );
    }
}

/// rskj `ValidTxExecutionSublistsEdgesRule` (RSKIP144 + RSKIP351).
///
/// The header's `txExecutionSublistsEdges` say where each parallel sublist
/// ends. A miner chooses them, so consensus has to bound them: an edge past
/// the end of the transaction list, or out of order, would partition a block
/// in a way no node could reproduce.
///
/// rskj applies this only when **both** RSKIP144 and RSKIP351 are active, and
/// returns true otherwise — which is why the caller passes `active` rather
/// than the rule deciding for itself.
///
/// Note the bound: rskj's `Constants.TX_EXECUTION_THREADS` is **2**, while
/// RSKIP-144 specifies `maxTransactionExecutionThreads = 4`. The code is the
/// stricter of the two, and the code is what the network agreed on — a node
/// following the document would accept three-edge blocks that rskj rejects.
/// See `docs/rskip-spec-vs-rskj-code.md`.
pub const TX_EXECUTION_THREADS: usize = 2;

/// Validates the sublist edges against the block's transaction count.
///
/// `Some(&[])` means "all transactions in the sequential sublist", and is
/// valid. `edges` is `None` for a header that has none: one from before the
/// rule, or one whose extension came beside the block's body without them
/// (rskj `BlockHeaderExtensionV1.fromEncoded`, `BlockHeaderExtensionV2`
/// alike). rskj's rule reads `edges.length` with no null check, so where it
/// is active a header without edges makes it throw, and the block is not
/// imported. The distinction from empty is preserved because the two encode
/// differently and therefore hash differently.
pub fn validate_tx_execution_sublists_edges(
    edges: Option<&[i16]>,
    transaction_count: usize,
    active: bool,
) -> Result<(), ValidationError> {
    if !active {
        return Ok(());
    }
    let Some(edges) = edges else {
        return Err(ValidationError::InvalidSublistEdges {
            reason: "the header has no execution list edges".to_string(),
        });
    };
    if edges.is_empty() {
        return Ok(());
    }

    if edges.len() > TX_EXECUTION_THREADS {
        return Err(ValidationError::InvalidSublistEdges { reason: format!(
            "number of execution list edges is greater than the number of execution \
             threads ({} vs {TX_EXECUTION_THREADS})",
            edges.len()
        ) });
    }

    if edges[0] <= 0 {
        return Err(ValidationError::InvalidSublistEdges { reason: format!(
            "execution list edge is out of bounds: first edge {} must be positive",
            edges[0]
        ) });
    }

    for pair in edges.windows(2) {
        if pair[0] >= pair[1] {
            return Err(ValidationError::InvalidSublistEdges { reason: format!(
                "execution list edges are not in ascending order: {} >= {}",
                pair[0], pair[1]
            ) });
        }
    }

    // rskj compares against `size() - 1` on a signed int. An empty
    // transaction list makes that -1, so any edge at all is out of bounds --
    // which is the intended answer, and is reproduced here rather than
    // underflowing.
    let last = *edges.last().expect("non-empty");
    let max_index = transaction_count as i64 - 1;
    if i64::from(last) > max_index {
        return Err(ValidationError::InvalidSublistEdges { reason: format!(
            "execution list edge is out of bounds: {last} > {max_index}"
        ) });
    }

    Ok(())
}

#[cfg(test)]
mod sublist_edges_tests {
    use super::*;

    /// Ported from rskj `ValidTxExecutionSublistsEdgesTest`, which fixes the
    /// transaction list at 10. Each test keeps the Java name so a disagreement
    /// can be taken back to the case it came from.
    const TXS: usize = 10;

    fn check(edges: Option<&[i16]>) -> Result<(), ValidationError> {
        validate_tx_execution_sublists_edges(edges, TXS, true)
    }

    /// rskj `blockWithRSKIP144Deactivated`: before activation the rule passes
    /// whatever the header says, including nothing at all.
    #[test]
    fn before_activation_anything_is_accepted() {
        assert!(validate_tx_execution_sublists_edges(None, TXS, false).is_ok());
        // Even edges that would be rejected once the rule is live.
        assert!(validate_tx_execution_sublists_edges(Some(&[99, 1]), TXS, false).is_ok());
    }

    /// rskj `blockWithValidEdges`
    #[test]
    fn two_ascending_in_bounds_edges_are_valid() {
        assert!(check(Some(&[2, 5])).is_ok());
    }

    /// rskj `blockWithEmptyEdges`: an empty list means every transaction goes
    /// in the sequential sublist, which is valid.
    #[test]
    fn empty_edges_are_valid() {
        assert!(check(Some(&[])).is_ok());
    }

    /// Not in rskj's suite. A header has no edges at all where its extension
    /// came without them (`BlockHeaderExtensionV1.fromEncoded` gives null for
    /// an extension of one element, `V2` for one of two). rskj's rule reads
    /// `edges.length` with no null check, so it throws and the block is not
    /// imported. Distinct from empty, which is every transaction in the
    /// sequential sublist and valid.
    #[test]
    fn absent_edges_are_refused_and_distinct_from_empty() {
        assert!(matches!(
            check(None),
            Err(ValidationError::InvalidSublistEdges { .. })
        ));
        assert!(check(Some(&[])).is_ok());
    }

    /// rskj `blockWithTooManyEdges`. The bound is rskj's
    /// `TX_EXECUTION_THREADS = 2`, **not** RSKIP-144's stated
    /// `maxTransactionExecutionThreads = 4`; a node following the document
    /// would accept three edges here and diverge.
    #[test]
    fn more_edges_than_execution_threads_is_rejected() {
        assert!(check(Some(&[1, 2, 3, 4, 5])).is_err());
        assert!(check(Some(&[1, 2, 3])).is_err(), "three edges exceed the bound of two");
        assert!(check(Some(&[1, 2])).is_ok(), "two is the limit, not one short of it");
    }

    /// rskj `blockWithOutOfBoundsEdgesBecauseOfRemascTx`: with 10
    /// transactions the last index is 9, so 10 is out of bounds. The REMASC
    /// transaction occupies the final slot and cannot start a sublist.
    #[test]
    fn an_edge_at_the_transaction_count_is_out_of_bounds() {
        assert!(check(Some(&[10])).is_err());
        assert!(check(Some(&[9])).is_ok(), "the last valid index is size - 1");
    }

    /// rskj `blockWithOutOfBoundsEdges`
    #[test]
    fn an_edge_past_the_transaction_list_is_rejected() {
        assert!(check(Some(&[12])).is_err());
    }

    /// rskj `blockWithNegativeEdge`. Java's `short` is signed, so a negative
    /// value is representable on the wire and has to be rejected explicitly
    /// rather than being impossible by type.
    #[test]
    fn a_negative_edge_is_rejected() {
        assert!(check(Some(&[-2])).is_err());
    }

    /// rskj `blockWithEdgeZero`: the first edge must be strictly positive --
    /// a sublist ending at 0 would be empty.
    #[test]
    fn a_first_edge_of_zero_is_rejected() {
        assert!(check(Some(&[0, 2])).is_err());
    }

    /// rskj `blockWithRepeatedEdge`: ascending means *strictly* ascending.
    #[test]
    fn a_repeated_edge_is_rejected() {
        assert!(check(Some(&[2, 2])).is_err());
    }

    /// rskj `blockWithEdgesNotInOrder`
    #[test]
    fn edges_out_of_order_are_rejected() {
        assert!(check(Some(&[2, 4, 3])).is_err());
    }

    /// Not in rskj's suite. An empty transaction list makes `size() - 1`
    /// equal -1 in Java, so every edge is out of bounds; reproduced here
    /// without underflowing an unsigned subtraction.
    #[test]
    fn any_edge_is_out_of_bounds_for_an_empty_block() {
        assert!(validate_tx_execution_sublists_edges(Some(&[1]), 0, true).is_err());
        assert!(validate_tx_execution_sublists_edges(Some(&[]), 0, true).is_ok());
    }
}
