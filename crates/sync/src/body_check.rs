//! Does this body belong to that header?
//!
//! A peer answers a body request with transactions and uncles, and nothing in
//! the message ties them to the header they were asked for. The header commits
//! to both -- `transactions_root` and `ommers_hash` -- so the tie is one hash
//! away, and checking it **at receipt** is the only moment the supplying peer
//! is unambiguous. By the time the block reaches execution it has been through
//! a store and a buffer, and the answer to "who sent this" is gone.
//!
//! Cheap, too: two hashes against a body already in memory, versus discovering
//! the same thing after execution has built a state from it.

use rustock_core::types::header_extension::BlockHeaderExtension;
use rustock_core::{Header, Transaction};

/// What about this body fails to match the header, if anything.
///
/// `None` means the body is the one the header commits to. The string is for
/// the log and is deliberately coarse -- a peer learns nothing from it that it
/// did not already know, having constructed the mismatch.
pub(crate) fn body_mismatch(
    header: &Header,
    transactions: &[Transaction],
    ommers: &[Header],
) -> Option<&'static str> {
    use rustock_core::ordered_tx_trie_root;

    // The transaction root's encoding changed at the unitrie fork, and this
    // has no hardfork table to consult, so either encoding is accepted: both
    // are genuine, and matching one of them is what proves the transaction
    // set. The question is "are these the right transactions", not "which era
    // is this" -- the executor checks the era-correct one later, against the
    // hardfork table it does have.
    let wanted = header.transactions_root;
    if ordered_tx_trie_root(transactions, true) != wanted
        && ordered_tx_trie_root(transactions, false) != wanted
    {
        return Some("transactions");
    }

    if rustock_execution::processor::compute_ommers_hash(ommers) != header.ommers_hash {
        return Some("uncles");
    }

    None
}

/// The header to keep with a body that fits it, and the RSKIP-351 extension
/// the peer sent beside the body.
///
/// A version-1 or version-2 header that came compressed, as rskj sends a
/// chain's headers to its peers, holds only a commitment to its extension:
/// its logs bloom, execution edges and base event. rskj sends the extension
/// beside the block's body (`BodyResponseMessage`), and
/// `DownloadingBodiesSyncState.newBody` sets it on the header before the
/// block is checked and run. Such a header is completed here, with the
/// extension its commitment names (`Header::with_extension`); a body without
/// that extension is refused, since without its bloom a block that logs
/// anything fails execution. `Ok(None)` means the header holds its own fields
/// and keeps them, whatever was sent beside the body.
pub(crate) fn completed_header(
    header: &Header,
    extension: Option<&BlockHeaderExtension>,
) -> Result<Option<Header>, &'static str> {
    if header.extension_data.is_none() {
        return Ok(None);
    }
    extension
        .and_then(|extension| header.with_extension(extension))
        .map(Some)
        .ok_or("RSKIP-351 extension fields")
}

/// The body this header determines, when it determines one.
///
/// A block is `[header, transactions, uncles]`. The uncle list cannot be
/// recovered -- `ommers_hash` is a one-way commitment -- but a block with no
/// uncles carrying only its REMASC transaction has a body that follows from
/// its height alone, and REMASC is a pure function of that height.
///
/// The test is [`body_mismatch`] itself, which is the point: a derived body
/// is accepted on exactly the evidence a peer's answer would have to satisfy,
/// the transactions root and the uncles hash. Derivation therefore cannot
/// admit anything a peer could not have sent; it can only fail to produce
/// something a peer would have.
///
/// Costs one small serialisation and a one-entry trie hash. No disk read, no
/// network, no state lookup -- which matters, because this runs against every
/// header in a sync, and a test more expensive than a request would eat the
/// saving it exists to create.
///
/// Not for a header that holds only the commitment to its RSKIP-351
/// extension: the extension comes only beside a peer's body
/// ([`completed_header`]), and nothing in it follows from the height. Not
/// even an empty block's bloom does, since REMASC logs each fee it pays
/// (`RemascFeesPayer.logPayment`).
pub(crate) fn derivable_body(header: &Header) -> Option<Vec<Transaction>> {
    if header.extension_data.is_some() {
        return None;
    }
    let transactions = vec![Transaction::remasc(header.number)];
    body_mismatch(header, &transactions, &[]).is_none().then_some(transactions)
}

#[cfg(test)]
mod derivation_tests {
    use super::*;
    use rustock_core::ordered_tx_trie_root;

    fn header_committing_to(txs: &[Transaction], rskip126: bool, number: u64) -> Header {
        let mut h = crate::tests::dummy_header(number, Default::default(), Default::default());
        h.transactions_root = ordered_tx_trie_root(txs, rskip126);
        h.ommers_hash = rustock_execution::processor::compute_ommers_hash(&[]);
        h
    }

    /// The ordinary case: an empty block, both trie eras.
    #[test]
    fn an_empty_block_yields_its_body() {
        for rskip126 in [false, true] {
            let number = 4_000_000;
            let txs = vec![Transaction::remasc(number)];
            let header = header_committing_to(&txs, rskip126, number);
            assert_eq!(derivable_body(&header), Some(txs), "rskip126={rskip126}");
        }
    }

    /// A block whose header commits to uncles cannot be derived, however its
    /// transactions look: the uncle headers are not recoverable.
    #[test]
    fn a_block_with_uncles_is_not_derivable() {
        let number = 4_000_000;
        let txs = vec![Transaction::remasc(number)];
        let mut header = header_committing_to(&txs, true, number);
        header.ommers_hash = alloy_primitives::B256::repeat_byte(0x11);
        assert_eq!(derivable_body(&header), None);
    }

    /// A block carrying real transactions is not derivable: its root commits
    /// to a set that is not REMASC alone.
    #[test]
    fn a_block_with_transactions_is_not_derivable() {
        let number = 4_000_000;
        let mut header = header_committing_to(&[Transaction::remasc(number)], true, number);
        header.transactions_root = alloy_primitives::B256::repeat_byte(0x22);
        assert_eq!(derivable_body(&header), None);
    }

    /// The REMASC transaction depends on the height, so a body derived for
    /// the wrong one must not satisfy the header.
    #[test]
    fn the_body_of_another_height_does_not_satisfy_this_header() {
        let number = 4_000_000;
        let txs = vec![Transaction::remasc(number)];
        let header = header_committing_to(&txs, true, number);
        let wrong = vec![Transaction::remasc(number + 1)];
        assert!(body_mismatch(&header, &wrong, &[]).is_some());
    }

    /// A version-2 extension whose bloom starts with `first`.
    fn extension(first: u8) -> BlockHeaderExtension {
        let mut logs_bloom = vec![0; 256];
        logs_bloom[0] = first;
        BlockHeaderExtension::V2 {
            logs_bloom,
            edges: Some(vec![1]),
            base_event: Some(Vec::new()),
        }
    }

    /// The bloom's slot of a header that commits to `extension`, as rskj
    /// writes it.
    fn commitment(extension: &BlockHeaderExtension) -> alloy_primitives::Bytes {
        let mut slot = Vec::new();
        alloy_rlp::Encodable::encode(&extension.create_extension_data().as_slice(), &mut slot);
        slot.into()
    }

    /// A header that holds only the commitment to its RSKIP-351 extension is
    /// not derivable, though its transactions are REMASC's alone: the
    /// extension comes only beside a peer's body.
    #[test]
    fn a_header_holding_only_its_extension_commitment_is_not_derivable() {
        let number = 4_000_000;
        let txs = vec![Transaction::remasc(number)];
        let mut header = header_committing_to(&txs, true, number);
        assert_eq!(derivable_body(&header), Some(txs));
        header.extension_data = Some(commitment(&extension(1)));
        assert_eq!(derivable_body(&header), None);
    }

    /// A header that came compressed is completed only by the extension its
    /// commitment names, and a body sent without it, or with another, is
    /// refused. A header that holds its own fields keeps them, whatever comes.
    #[test]
    fn a_compressed_header_is_completed_only_by_the_extension_it_names() {
        let mut header = crate::tests::dummy_header(7, Default::default(), Default::default());
        header.extension_data = Some(commitment(&extension(1)));
        assert_eq!(
            completed_header(&header, None),
            Err("RSKIP-351 extension fields")
        );
        assert_eq!(
            completed_header(&header, Some(&extension(2))),
            Err("RSKIP-351 extension fields")
        );
        let completed = completed_header(&header, Some(&extension(1)))
            .expect("the extension it names")
            .expect("a completed header");
        assert_eq!(completed.extension(), Some(extension(1)));
        assert_eq!(completed_header(&completed, Some(&extension(2))), Ok(None));
        assert_eq!(completed_header(&completed, None), Ok(None));
    }
}
