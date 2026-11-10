//! Bridge decisions that reach consensus but emit no event.
//!
//! The Bridge logs a lot, but not everything, and what it does log has grown
//! over time behind activations. A question like "has a peg-in ever been
//! refunded" is answered in seconds where an event exists and needs a full
//! historical replay where one does not -- mainnet's only two refunds predate
//! `rejected_pegin` by 760,000 blocks, so the event-based answer is "none".
//!
//! This module lets a replay record those decisions as they are made, so the
//! replay is paid for once. Records are **derived, not consensus**: nothing
//! here is read back during execution, and deleting them loses no state.
//!
//! The sink is off unless a tool turns it on, so ordinary block processing
//! pays one thread-local boolean check per decision point.

use alloy_primitives::{Address, U256};
use std::cell::RefCell;

/// What kind of decision a record describes.
///
/// The name is hashed into the storage key, exactly as an event's topic is,
/// so a reader can scan one kind without decoding the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SilentKind {
    /// A peg-in was refused and its bitcoin sent back. The Bridge logs
    /// `rejected_pegin` from RSKIP181 and `release_requested` from RSKIP146,
    /// but neither carries the sender type, the derived refund address or the
    /// peg-in version, and before those activations it logs nothing at all.
    PeginRefunded,
    /// A peg-in was refused with nothing returned.
    PeginRejectedNoRefund,
    /// A peg-in was credited. `pegin_btc` covers this from RSKIP146; the
    /// sender type and derived address are still not in it.
    PeginAccepted,
    /// A Bitcoin transaction was marked processed, which is what stops it
    /// being registered twice. Never logged, in any era.
    BtcTxMarkedProcessed,
    /// A one-off whitelist entry was consumed by a peg-in. Never logged.
    WhitelistEntryConsumed,
    /// A refund was due but the pegout could not be built, so nothing was
    /// returned. rskj records this as a panic line and no event.
    RefundBuildFailed,
    /// A peg-out was queued for confirmations. `release_requested` covers this
    /// from RSKIP146 (papyrus200); before it the request was made and left no
    /// trace in the receipts. Recorded with the fields that event carries, so
    /// the legacy-event store can reconstruct it exactly.
    PegoutRequested,
}

impl SilentKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::PeginRefunded => "pegin_refunded",
            Self::PeginRejectedNoRefund => "pegin_rejected_no_refund",
            Self::PeginAccepted => "pegin_accepted",
            Self::BtcTxMarkedProcessed => "btc_tx_marked_processed",
            Self::WhitelistEntryConsumed => "whitelist_entry_consumed",
            Self::RefundBuildFailed => "refund_build_failed",
            Self::PegoutRequested => "pegout_requested",
        }
    }

    pub fn all() -> &'static [SilentKind] {
        &[
            Self::PeginRefunded,
            Self::PeginRejectedNoRefund,
            Self::PeginAccepted,
            Self::BtcTxMarkedProcessed,
            Self::WhitelistEntryConsumed,
            Self::RefundBuildFailed,
            Self::PegoutRequested,
        ]
    }
}

/// One recorded decision. `fields` is rendered to JSON by the writer: these
/// are rare, derived and read by people as often as by programs, so an
/// evolvable self-describing form is worth more than a compact one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilentRecord {
    pub kind: SilentKind,
    pub block: u64,
    pub tx_index: u32,
    pub fields: Vec<(&'static str, FieldValue)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    U64(u64),
    Big(U256),
    Bytes(Vec<u8>),
    Addr(Address),
    Text(String),
    Flag(bool),
}

impl FieldValue {
    /// JSON scalar. Byte strings become `0x…` so a reader can paste them
    /// straight into an explorer.
    pub fn to_json(&self) -> String {
        match self {
            Self::U64(v) => v.to_string(),
            Self::Big(v) => format!("\"{v}\""),
            Self::Bytes(b) => format!("\"0x{}\"", alloy_primitives::hex::encode(b)),
            Self::Addr(a) => format!("\"{a}\""),
            Self::Text(s) => format!("{s:?}"),
            Self::Flag(b) => b.to_string(),
        }
    }
}

impl SilentRecord {
    pub fn to_json(&self) -> String {
        let body = self
            .fields
            .iter()
            .map(|(k, v)| format!("\"{k}\":{}", v.to_json()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"kind\":\"{}\",\"block\":{},\"txIndex\":{},{body}}}",
            self.kind.name(),
            self.block,
            self.tx_index
        )
    }
}

thread_local! {
    /// `None` means nobody is recording, which is the normal case.
    static SINK: RefCell<Option<Vec<SilentRecord>>> = const { RefCell::new(None) };
    /// Where execution currently is, as `(block, tx_index)`.
    ///
    /// Decisions are made several calls deep inside the Bridge, in functions
    /// that have no reason to know their own block. Carrying the position in
    /// a thread-local keeps that plumbing out of consensus code, which is the
    /// code least worth disturbing for the sake of a diagnostic.
    static POSITION: RefCell<(u64, u32)> = const { RefCell::new((0, 0)) };
}

/// Sets the position later [`record_here`] calls are attributed to.
pub fn set_position(block: u64, tx_index: u32) {
    POSITION.with(|p| *p.borrow_mut() = (block, tx_index));
}

pub fn position() -> (u64, u32) {
    POSITION.with(|p| *p.borrow())
}

/// Starts recording on this thread, discarding anything already held.
pub fn start() {
    SINK.with(|s| *s.borrow_mut() = Some(Vec::new()));
}

/// Stops recording and returns what was collected.
pub fn finish() -> Vec<SilentRecord> {
    SINK.with(|s| s.borrow_mut().take()).unwrap_or_default()
}

/// Takes what has been collected so far, leaving recording on.
pub fn drain() -> Vec<SilentRecord> {
    SINK.with(|s| match s.borrow_mut().as_mut() {
        Some(v) => std::mem::take(v),
        None => Vec::new(),
    })
}

/// Append records collected on another thread.
///
/// A sublist executing on a worker records into that thread's sink, and the
/// coordinator's sink is where the tool is looking. Without this a parallel
/// block would quietly record nothing.
pub fn absorb(records: Vec<SilentRecord>) {
    if records.is_empty() {
        return;
    }
    SINK.with(|s| {
        if let Some(v) = s.borrow_mut().as_mut() {
            v.extend(records);
        }
    });
}

pub fn is_recording() -> bool {
    SINK.with(|s| s.borrow().is_some())
}

/// Records one decision. A no-op unless a tool called [`start`].
pub fn record(
    kind: SilentKind,
    block: u64,
    tx_index: u32,
    fields: Vec<(&'static str, FieldValue)>,
) {
    SINK.with(|s| {
        if let Some(v) = s.borrow_mut().as_mut() {
            v.push(SilentRecord {
                kind,
                block,
                tx_index,
                fields,
            });
        }
    });
}

/// Records one decision at the current [`position`].
pub fn record_here(kind: SilentKind, fields: Vec<(&'static str, FieldValue)>) {
    if !is_recording() {
        return;
    }
    let (block, tx_index) = position();
    record(kind, block, tx_index, fields);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_is_off_until_asked_for() {
        assert!(!is_recording());
        record(SilentKind::PeginRefunded, 1, 0, vec![]);
        assert!(finish().is_empty(), "a record made while off is dropped");
    }

    #[test]
    fn records_survive_until_drained() {
        start();
        record(
            SilentKind::PeginRefunded,
            7,
            2,
            vec![("amount", FieldValue::U64(5))],
        );
        record(SilentKind::PeginAccepted, 8, 0, vec![]);
        let first = drain();
        assert_eq!(first.len(), 2);
        assert!(is_recording(), "drain leaves recording on");
        assert!(drain().is_empty(), "drain takes what it returned");
        assert!(finish().is_empty());
        assert!(!is_recording());
    }

    #[test]
    fn a_record_takes_the_position_set_for_it() {
        start();
        set_position(2_745_770, 4);
        record_here(SilentKind::PeginRefunded, vec![]);
        let r = finish();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].block, r[0].tx_index), (2_745_770, 4));
    }

    /// The JSON is the stored form, so its shape is pinned.
    #[test]
    fn a_record_renders_as_json() {
        let r = SilentRecord {
            kind: SilentKind::PeginRefunded,
            block: 2_851_909,
            tx_index: 3,
            fields: vec![
                (
                    "reason",
                    FieldValue::Text("LEGACY_PEGIN_MULTISIG_SENDER".into()),
                ),
                ("refundAddress", FieldValue::Text("35JUi1Fxab".into())),
                ("amountSat", FieldValue::U64(1_970_976_990)),
                ("senderTypeKnown", FieldValue::Flag(true)),
                ("btcTxHash", FieldValue::Bytes(vec![0xab, 0xcd])),
            ],
        };
        assert_eq!(
            r.to_json(),
            r#"{"kind":"pegin_refunded","block":2851909,"txIndex":3,"reason":"LEGACY_PEGIN_MULTISIG_SENDER","refundAddress":"35JUi1Fxab","amountSat":1970976990,"senderTypeKnown":true,"btcTxHash":"0xabcd"}"#
        );
    }

    #[test]
    fn every_kind_has_a_distinct_name() {
        let mut seen = std::collections::HashSet::new();
        for k in SilentKind::all() {
            assert!(seen.insert(k.name()), "duplicate name {}", k.name());
        }
        assert_eq!(seen.len(), SilentKind::all().len());
    }
}
