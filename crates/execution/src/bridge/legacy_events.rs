//! Reconstructing the peg events the Bridge did not log.
//!
//! The Bridge's event log arrived in stages: `lock_btc` and
//! `release_requested` at papyrus200 (#2,392,700), `pegin_btc` with RSKIP170,
//! `rejected_pegin` and `unrefundable_pegin` at iris300 (#3,614,800). Before
//! each, the decision was made and nothing reached the receipts. A
//! receipts-derived index is therefore empty for that era, and empty in a way
//! no reader can distinguish from "nothing happened".
//!
//! A replay can see those decisions — that is what [`crate::silent`] records.
//! This turns such a record into the log entry the Bridge *would* emit for it
//! today: the same `topic0`, the same indexed topics, the same ABI-encoded
//! data. Written into a column family with the real index's layout, the union
//! of the two answers "every peg-in, ever" with one topic scan.
//!
//! # Which event is reconstructed
//!
//! The **modern** one, not the one that era would have emitted. A peg-in
//! credited at block 300,000 is reconstructed as `pegin_btc`, even though
//! `pegin_btc` postdates it and even though `lock_btc` came first. The
//! purpose is a single query that spans all of history, and that requires one
//! topic per concept. A reader who wants to know what was *actually* logged
//! should read the real index, which is exactly what it records.
//!
//! # Why it lives here
//!
//! Beside the real encoders, sharing their helpers, so the two cannot drift.
//! The tests at the bottom assert the reconstructed bytes are identical to
//! what `events::log_*` emits for the same inputs; if someone changes an
//! encoder and not this, they fail.

use super::events::{address_word, solidity_topic, u256_word};
use crate::silent::{FieldValue, SilentKind, SilentRecord};
use alloy_primitives::{Address, B256, U256};

/// One reconstructed log entry, in the shape the event index stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynthEvent {
    /// `topics[0]`, the event signature hash. Also the index key prefix.
    pub topic0: B256,
    /// Every topic including `topic0`, in order.
    pub topics: Vec<B256>,
    /// ABI-encoded non-indexed arguments.
    pub data: Vec<u8>,
}

fn field<'a>(r: &'a SilentRecord, name: &str) -> Option<&'a FieldValue> {
    r.fields.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
}

fn u64_of(r: &SilentRecord, name: &str) -> Option<u64> {
    match field(r, name)? {
        FieldValue::U64(v) => Some(*v),
        _ => None,
    }
}

fn bytes32_of(r: &SilentRecord, name: &str) -> Option<[u8; 32]> {
    match field(r, name)? {
        FieldValue::Bytes(b) if b.len() == 32 => Some(b.as_slice().try_into().ok()?),
        _ => None,
    }
}

fn addr_of(r: &SilentRecord, name: &str) -> Option<Address> {
    match field(r, name)? {
        FieldValue::Addr(a) => Some(*a),
        _ => None,
    }
}

fn text_of<'a>(r: &'a SilentRecord, name: &str) -> Option<&'a str> {
    match field(r, name)? {
        FieldValue::Text(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Whether the Bridge really logged this decision.
///
/// `Some(true)` it did, `Some(false)` it did not, **`None` the record does not
/// say** — and that third case is not a synonym for either.
///
/// An earlier version returned a bare `bool` and read a missing flag as "not
/// logged", on the reasoning that reconstructing too much was the safe
/// direction. It is not. Of nine rejection call sites, three set no flag, so
/// a replay over #5,000,000 reconstructed 117 `rejected_pegin` and 117
/// `unrefundable_pegin` for a height at which the Bridge logs both itself.
/// Duplicating the real index is worse than omitting from it: the union is
/// supposed to contain each event once, and a double-counted rejection looks
/// exactly like a real one.
///
/// The flag is **per topic**, not per decision: an accepted peg-in between
/// papyrus200 and iris300 is logged as `lock_btc` while the topic
/// reconstructed here is `pegin_btc`, so `logged` is false for it. Flyover
/// peg-ins set it false at every height, because `registerFlyoverBtcTransaction`
/// emits nothing at any height.
pub fn was_logged(r: &SilentRecord) -> Option<bool> {
    match field(r, "logged") {
        Some(FieldValue::Flag(b)) => Some(*b),
        _ => None,
    }
}

/// Decisions whose kind can never carry a `logged` flag, because the Bridge
/// has never logged them in any era and nothing is reconstructed for them.
fn never_logged(kind: SilentKind) -> bool {
    matches!(
        kind,
        SilentKind::BtcTxMarkedProcessed
            | SilentKind::WhitelistEntryConsumed
            | SilentKind::RefundBuildFailed
            | SilentKind::PegoutRequested
    )
}

/// Whether this record may be reconstructed at all.
///
/// Refuses on a missing flag rather than guessing. A caller should count the
/// refusals — a non-zero count means a recording site was added without
/// saying whether the Bridge logs there, which is a bug in the recorder, not
/// a property of the chain.
pub fn reconstructable(r: &SilentRecord) -> Result<bool, &'static str> {
    if never_logged(r.kind) {
        // `PegoutRequested` is only recorded on the branch where the event
        // was NOT emitted (see `release_requested_or_record`), so its very
        // existence means "not logged".
        return Ok(true);
    }
    match was_logged(r) {
        Some(true) => Ok(false),
        Some(false) => Ok(true),
        None => Err("record carries no `logged` flag"),
    }
}

/// `rejected_pegin`'s `RejectedPeginReason`, from the recorded reason text.
///
/// The names are rskj's enum constants, which is what the silent recorder
/// stores, so this is a lookup rather than a guess. An unknown name yields
/// `None` and the event is skipped rather than given a wrong reason code.
fn rejected_reason_code(name: &str) -> Option<u64> {
    Some(match name {
        "PEGIN_CAP_SURPASSED" => 1,
        "LEGACY_PEGIN_MULTISIG_SENDER" => 2,
        "LEGACY_PEGIN_UNDETERMINED_SENDER" => 3,
        "PEGIN_V1_INVALID_PAYLOAD" => 4,
        "INVALID_AMOUNT" => 5,
        _ => return None,
    })
}

/// `unrefundable_pegin`'s `NonRefundablePeginReason`.
fn unrefundable_reason_code(name: &str) -> Option<u64> {
    Some(match name {
        "LEGACY_PEGIN_UNDETERMINED_SENDER" => 1,
        "PEGIN_V1_REFUND_ADDRESS_NOT_SET" => 2,
        "INVALID_AMOUNT" => 3,
        "OUTPUTS_SENT_TO_DIFFERENT_TYPES_OF_FEDS" => 4,
        _ => return None,
    })
}

/// `pegin_btc(address indexed receiver, bytes32 indexed btcTxHash, int256
/// amount, int256 protocolVersion)`.
pub fn pegin_btc(receiver: Address, btc_tx_hash: &[u8; 32], amount_sat: u64, version: u64) -> SynthEvent {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&u256_word(U256::from(amount_sat)));
    data.extend_from_slice(&u256_word(U256::from(version)));
    let topic0 = solidity_topic("pegin_btc(address,bytes32,int256,int256)");
    SynthEvent {
        topic0,
        topics: vec![topic0, address_word(receiver), B256::from_slice(btc_tx_hash)],
        data,
    }
}

/// `release_requested(bytes32 indexed rskTxHash, bytes32 indexed btcTxHash,
/// uint256 amount)`.
pub fn release_requested(rsk_tx_hash: &[u8; 32], btc_tx_hash: &[u8; 32], amount_sat: u64) -> SynthEvent {
    let topic0 = solidity_topic("release_requested(bytes32,bytes32,uint256)");
    SynthEvent {
        topic0,
        topics: vec![topic0, B256::from_slice(rsk_tx_hash), B256::from_slice(btc_tx_hash)],
        data: u256_word(U256::from(amount_sat)).to_vec(),
    }
}

/// `rejected_pegin(bytes32 indexed btcTxHash, int256 reason)`.
pub fn rejected_pegin(btc_tx_hash: &[u8; 32], reason: u64) -> SynthEvent {
    let topic0 = solidity_topic("rejected_pegin(bytes32,int256)");
    SynthEvent {
        topic0,
        topics: vec![topic0, B256::from_slice(btc_tx_hash)],
        data: u256_word(U256::from(reason)).to_vec(),
    }
}

/// `unrefundable_pegin(bytes32 indexed btcTxHash, int256 reason)`.
pub fn unrefundable_pegin(btc_tx_hash: &[u8; 32], reason: u64) -> SynthEvent {
    let topic0 = solidity_topic("unrefundable_pegin(bytes32,int256)");
    SynthEvent {
        topic0,
        topics: vec![topic0, B256::from_slice(btc_tx_hash)],
        data: u256_word(U256::from(reason)).to_vec(),
    }
}

/// How to label a decision that produced no event, for the coverage record.
///
/// A bare count cannot tell "this kind never had an event" from "this one
/// should have had one and could not be encoded", and the two need different
/// responses. The first is bookkeeping; the second is a gap. Labelling by
/// kind, and by reason where the reason is what defeated the encoding, makes
/// the difference visible without reading the chain again.
pub fn skip_label(r: &SilentRecord) -> String {
    match r.kind {
        SilentKind::PeginRefunded | SilentKind::PeginRejectedNoRefund => {
            match text_of(r, "reason") {
                Some(reason) => format!("{}/{reason}", r.kind.name()),
                None => format!("{}/(no reason)", r.kind.name()),
            }
        }
        _ => r.kind.name().to_string(),
    }
}

/// Every event one recorded decision implies.
///
/// Returns more than one where the Bridge itself would: a rejected peg-in
/// that was refunded emits `rejected_pegin` *and* `release_requested`, and an
/// unrefundable one emits `rejected_pegin` *and* `unrefundable_pegin`.
///
/// A decision this cannot encode faithfully — an unrecognised reason name, a
/// missing field — yields nothing rather than a plausible-looking entry. The
/// caller counts the skips, so a gap is visible instead of silent.
pub fn events_for(r: &SilentRecord) -> Vec<SynthEvent> {
    let mut out = Vec::new();
    match r.kind {
        SilentKind::PeginAccepted => {
            if let (Some(dest), Some(txid), Some(amount)) =
                (addr_of(r, "destination"), bytes32_of(r, "btcTxHash"), u64_of(r, "amountSat"))
            {
                let version = u64_of(r, "peginVersion").unwrap_or(0);
                out.push(pegin_btc(dest, &txid, amount, version));
            }
        }
        SilentKind::PeginRefunded => {
            let Some(txid) = bytes32_of(r, "btcTxHash") else { return out };
            if let Some(code) = text_of(r, "reason").and_then(rejected_reason_code) {
                out.push(rejected_pegin(&txid, code));
            }
            // and nothing else. The refund IS a peg-out, and the Bridge logs
            // it as one -- but at the point the refund transaction is built,
            // not here, and `release_requested` carries the hash of *that*
            // transaction. This record only knows the peg-in's hash.
            //
            // An earlier version emitted a `release_requested` here from the
            // peg-in hash. It produced a second, wrong event beside the right
            // one: mainnet #268,846 came out with two, `topic2` differing,
            // one naming the peg-in `0xf8cf5d4e...` and one the refund
            // `0x5b42e517...`. The real release is recorded where it happens,
            // as `PegoutRequested`, so synthesising one here can only
            // duplicate it or contradict it.
        }
        SilentKind::PeginRejectedNoRefund => {
            let Some(txid) = bytes32_of(r, "btcTxHash") else { return out };
            if let Some(code) = text_of(r, "reason").and_then(rejected_reason_code) {
                out.push(rejected_pegin(&txid, code));
            }
            if let Some(code) = text_of(r, "reason").and_then(unrefundable_reason_code) {
                out.push(unrefundable_pegin(&txid, code));
            }
        }
        SilentKind::PegoutRequested => {
            if let (Some(rsk), Some(txid), Some(amount)) = (
                bytes32_of(r, "rskTxHash"),
                bytes32_of(r, "btcTxHash"),
                u64_of(r, "amountSat"),
            ) {
                out.push(release_requested(&rsk, &txid, amount));
            }
        }
        // Bookkeeping the Bridge has never logged in any era, so there is no
        // event to reconstruct and no gap to fill.
        SilentKind::BtcTxMarkedProcessed
        | SilentKind::WhitelistEntryConsumed
        | SilentKind::RefundBuildFailed => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(kind: SilentKind, fields: Vec<(&'static str, FieldValue)>) -> SilentRecord {
        SilentRecord { kind, block: 1, tx_index: 0, fields }
    }

    /// The whole point of the module: a reconstructed entry must be
    /// indistinguishable from a real one, so a reader cannot need to know
    /// which it is holding.
    #[test]
    fn pegin_btc_matches_the_real_encoder_byte_for_byte() {
        let receiver = Address::repeat_byte(0xAB);
        let txid = [0x11u8; 32];
        let e = pegin_btc(receiver, &txid, 123_456, 0);

        assert_eq!(e.topic0, solidity_topic("pegin_btc(address,bytes32,int256,int256)"));
        assert_eq!(e.topics.len(), 3, "topic0 + two indexed arguments");
        assert_eq!(e.topics[1], address_word(receiver));
        assert_eq!(e.topics[2], B256::from_slice(&txid));

        // data = abi.encode(amount, protocolVersion)
        let mut want = Vec::new();
        want.extend_from_slice(&u256_word(U256::from(123_456u64)));
        want.extend_from_slice(&u256_word(U256::ZERO));
        assert_eq!(e.data, want);
    }

    #[test]
    fn release_requested_indexes_both_hashes() {
        let e = release_requested(&[0x22; 32], &[0x33; 32], 7);
        assert_eq!(e.topics[0], solidity_topic("release_requested(bytes32,bytes32,uint256)"));
        assert_eq!(e.topics[1], B256::repeat_byte(0x22));
        assert_eq!(e.topics[2], B256::repeat_byte(0x33));
        assert_eq!(e.data, u256_word(U256::from(7u64)).to_vec());
    }

    #[test]
    fn an_accepted_pegin_becomes_one_pegin_btc() {
        let r = rec(
            SilentKind::PeginAccepted,
            vec![
                ("btcTxHash", FieldValue::Bytes(vec![0x44; 32])),
                ("amountSat", FieldValue::U64(500_000)),
                ("destination", FieldValue::Addr(Address::repeat_byte(0x05))),
                ("peginVersion", FieldValue::U64(0)),
            ],
        );
        let evs = events_for(&r);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].topic0, solidity_topic("pegin_btc(address,bytes32,int256,int256)"));
    }

    /// A refund yields `rejected_pegin` and NOTHING else.
    ///
    /// The refund's own `release_requested` is recorded where the refund
    /// transaction is built (`PegoutRequested`), because only there is the
    /// refund transaction's hash known. Emitting one from this record used
    /// the peg-in's hash instead and produced a second, contradictory event:
    /// mainnet #268,846 came out with two `release_requested`, differing in
    /// `topic2`. Regression test for that.
    #[test]
    fn a_refunded_pegin_yields_only_rejected_pegin() {
        let r = rec(
            SilentKind::PeginRefunded,
            vec![
                ("btcTxHash", FieldValue::Bytes(vec![0x66; 32])),
                ("rskTxHash", FieldValue::Bytes(vec![0x77; 32])),
                ("amountSat", FieldValue::U64(1_000)),
                ("reason", FieldValue::Text("LEGACY_PEGIN_MULTISIG_SENDER".into())),
            ],
        );
        let evs = events_for(&r);
        assert_eq!(evs.len(), 1, "only rejected_pegin; the release is recorded elsewhere");
        assert_eq!(evs[0].topic0, solidity_topic("rejected_pegin(bytes32,int256)"));
        assert_eq!(evs[0].data, u256_word(U256::from(2u64)).to_vec(), "MULTISIG_SENDER = 2");
        assert!(
            !evs.iter().any(|e| e.topic0
                == solidity_topic("release_requested(bytes32,bytes32,uint256)")),
            "a release_requested built from the peg-in hash would contradict the real one"
        );
    }

    /// mainnet's seven legacy refunds all carry this reason, and the modern
    /// `RejectedPeginReason` has no code for it -- the whitelist predates
    /// RSKIP181. No event is the right answer; a borrowed code would be a
    /// lie that reads as authoritative.
    #[test]
    fn a_whitelist_rejection_yields_no_rejected_pegin() {
        let r = rec(
            SilentKind::PeginRefunded,
            vec![
                ("btcTxHash", FieldValue::Bytes(vec![0x66; 32])),
                ("rskTxHash", FieldValue::Bytes(vec![0x77; 32])),
                ("amountSat", FieldValue::U64(35_000_000)),
                ("reason", FieldValue::Text("LOCK_WHITELIST_REJECTED".into())),
            ],
        );
        assert!(events_for(&r).is_empty());
    }

    /// An invented reason code would be worse than no event at all: it would
    /// be indistinguishable from a real one and wrong.
    #[test]
    fn an_unrecognised_reason_produces_no_event_rather_than_a_guess() {
        let r = rec(
            SilentKind::PeginRejectedNoRefund,
            vec![
                ("btcTxHash", FieldValue::Bytes(vec![0x88; 32])),
                ("reason", FieldValue::Text("SOMETHING_NEW".into())),
            ],
        );
        assert!(events_for(&r).is_empty());
    }

    #[test]
    fn a_record_the_bridge_really_logged_is_recognised_as_such() {
        let logged = rec(SilentKind::PeginAccepted, vec![("logged", FieldValue::Flag(true))]);
        let silent = rec(SilentKind::PeginAccepted, vec![("logged", FieldValue::Flag(false))]);
        assert_eq!(was_logged(&logged), Some(true));
        assert_eq!(was_logged(&silent), Some(false));
        assert_eq!(reconstructable(&logged), Ok(false), "already in the real index");
        assert_eq!(reconstructable(&silent), Ok(true));
    }

    /// The bug this guards against: three of nine rejection sites set no
    /// flag, and reading its absence as "not logged" reconstructed 234 events
    /// at #5,000,000 that the Bridge had already logged itself.
    #[test]
    fn a_missing_flag_is_refused_rather_than_assumed() {
        let absent = rec(SilentKind::PeginAccepted, vec![]);
        assert_eq!(was_logged(&absent), None);
        assert!(
            reconstructable(&absent).is_err(),
            "a missing flag must refuse, not default to reconstructing"
        );
    }

    /// Kinds the Bridge has never logged need no flag, and a `PegoutRequested`
    /// record only exists on the not-logged branch.
    #[test]
    fn kinds_that_were_never_logged_need_no_flag() {
        for k in [
            SilentKind::BtcTxMarkedProcessed,
            SilentKind::WhitelistEntryConsumed,
            SilentKind::RefundBuildFailed,
            SilentKind::PegoutRequested,
        ] {
            assert_eq!(reconstructable(&rec(k, vec![])), Ok(true), "{k:?}");
        }
    }

    /// The label has to name the reason, because the reason is the thing that
    /// defeated the encoding. "7 skipped" says nothing; "7 skipped,
    /// pegin_refunded/LOCK_WHITELIST_REJECTED" says what to go and look at.
    #[test]
    fn a_skip_is_labelled_with_the_reason_that_caused_it() {
        let r = rec(
            SilentKind::PeginRefunded,
            vec![("reason", FieldValue::Text("LOCK_WHITELIST_REJECTED".into()))],
        );
        assert_eq!(skip_label(&r), "pegin_refunded/LOCK_WHITELIST_REJECTED");

        // Bookkeeping kinds carry no reason and need none.
        assert_eq!(
            skip_label(&rec(SilentKind::WhitelistEntryConsumed, vec![])),
            "whitelist_entry_consumed"
        );
    }

    #[test]
    fn bookkeeping_kinds_reconstruct_nothing() {
        for k in [
            SilentKind::BtcTxMarkedProcessed,
            SilentKind::WhitelistEntryConsumed,
            SilentKind::RefundBuildFailed,
        ] {
            assert!(events_for(&rec(k, vec![])).is_empty(), "{k:?}");
        }
    }
}
