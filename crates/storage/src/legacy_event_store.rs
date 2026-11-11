//! The peg events the Bridge never logged, in the layout of the ones it did.
//!
//! # Why this exists
//!
//! The Bridge's event log arrived in stages: `lock_btc` and
//! `release_requested` at papyrus200 (#2,392,700), `pegin_btc` with RSKIP170,
//! `rejected_pegin` and `unrefundable_pegin` at iris300 (#3,614,800). Before
//! each, the peg went on working and wrote nothing to the receipts. The node's
//! `bridge_events` index is built from receipts, so for that era it is empty —
//! and empty in a way no reader can tell apart from "nothing happened".
//!
//! A replay can see those decisions. This is where the reconstructed events
//! are kept.
//!
//! # Why a separate database
//!
//! Two reasons, and the second is the decisive one.
//!
//! These events are **derived, not observed**. They are not in any receipt,
//! and folding them into the node's own index would make that index assert
//! something about the chain that is not true of it.
//!
//! And the node holds its database's write lock for as long as it runs.
//! Building this takes a replay of millions of blocks; requiring the node be
//! stopped for it would make the thing unbuildable in practice. A store of its
//! own can be written while the node serves traffic, and read afterwards by
//! anything, including while it is itself being extended.
//!
//! # Layout
//!
//! Deliberately identical to the node's `CF_BRIDGE_EVENTS`:
//!
//! ```text
//!   key   = topic0 (32) || block (8 BE) || tx_index (4 BE) || log_index (4 BE)
//!   value = tx_hash (32) || n_topics (1) || topics (n*32) || data
//! ```
//!
//! so one decoder reads both, and "every occurrence of this event in block
//! order" is a prefix scan here exactly as it is there. Concatenating a scan
//! of each and sorting by `(block, tx_index, log_index)` gives the complete
//! history of an event across all eras. Nothing is written here for a height
//! where the Bridge really logged, so the union never double-counts.
//!
//! # Coverage
//!
//! Recorded in `meta`, because an empty scan is otherwise ambiguous: "no
//! peg-ins in this range" and "nobody has reconstructed this range" are
//! different answers and it matters not to confuse them. [`Self::covers`]
//! answers the second question before a caller trusts the first.

use anyhow::{Context, Result};
use alloy_primitives::B256;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};

const CF_EVENTS: &str = "legacy_events";
const CF_META: &str = "meta";

/// One reconstructed log entry, ready to store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub topic0: B256,
    pub block: u64,
    pub tx_index: u32,
    pub log_index: u32,
    pub tx_hash: B256,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

/// One decoded entry, in the same shape the node's index returns.
pub type DecodedEvent = (u64, u32, u32, B256, Vec<B256>, Vec<u8>);

/// A range that has been reconstructed, and what came of it.
#[derive(Clone, Debug)]
pub struct Coverage {
    pub from: u64,
    pub to: u64,
    pub build: String,
    /// Blocks executed while building this span.
    pub blocks: u64,
    /// Of those, how many had their state root actually compared against the
    /// chain. Below wasabi100 (#1,591,000) a header carries an ORCHID root,
    /// which is not a unitrie node hash, so without rskj's translation table
    /// most blocks are executed and carried forward but never checked. Those
    /// events are reconstructed from an execution nothing corroborated, and
    /// a reader is entitled to know it.
    pub verified: u64,
    pub events: u64,
    /// Decisions seen but not encodable as an event — an unrecognised reason
    /// code, a missing field. Stored so a gap is visible rather than silent.
    pub skipped: u64,
    /// The skips broken down, as a JSON object: `{"kind/reason": count}`.
    /// A bare total cannot distinguish bookkeeping that never had an event
    /// from a decision that should have had one and could not be encoded.
    pub skip_detail: String,
}

pub struct LegacyEventStore {
    db: DB,
}

impl LegacyEventStore {
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_EVENTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];
        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .with_context(|| format!("opening legacy event store at {path}"))?;
        Ok(Self { db })
    }

    /// Opens without taking the write lock, so a store can be read while it
    /// is still being built.
    pub fn open_read_only(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        let db = DB::open_cf_for_read_only(&opts, path, [CF_EVENTS, CF_META], false)
            .with_context(|| format!("opening legacy event store read-only at {path}"))?;
        Ok(Self { db })
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| anyhow::anyhow!("column family {name} missing"))
    }

    /// Encodes one row into the shared key/value layout.
    fn encode(row: &EventRow) -> (Vec<u8>, Vec<u8>) {
        let mut key = Vec::with_capacity(48);
        key.extend_from_slice(row.topic0.as_slice());
        key.extend_from_slice(&row.block.to_be_bytes());
        key.extend_from_slice(&row.tx_index.to_be_bytes());
        key.extend_from_slice(&row.log_index.to_be_bytes());

        let mut val = Vec::with_capacity(33 + row.topics.len() * 32 + row.data.len());
        val.extend_from_slice(row.tx_hash.as_slice());
        val.push(row.topics.len() as u8);
        for t in &row.topics {
            val.extend_from_slice(t.as_slice());
        }
        val.extend_from_slice(&row.data);
        (key, val)
    }

    /// Writes a batch of reconstructed events.
    pub fn put_events(&self, rows: &[EventRow]) -> Result<()> {
        let cf = self.cf(CF_EVENTS)?;
        let mut batch = WriteBatch::default();
        for row in rows {
            let (k, v) = Self::encode(row);
            batch.put_cf(cf, k, v);
        }
        self.db.write(batch).context("writing legacy events")
    }

    /// Every occurrence of one event type, in block order.
    ///
    /// Same return shape as the node's `scan_bridge_events`, so a caller can
    /// chain the two and sort.
    pub fn scan(&self, topic0: B256, from_block: u64, to_block: u64) -> Result<Vec<DecodedEvent>> {
        let cf = self.cf(CF_EVENTS)?;
        let mut start = Vec::with_capacity(40);
        start.extend_from_slice(topic0.as_slice());
        start.extend_from_slice(&from_block.to_be_bytes());

        let mut out = Vec::new();
        let iter = self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward));
        for item in iter {
            let (k, v) = item?;
            if k.len() < 48 || &k[..32] != topic0.as_slice() {
                break; // past this event type
            }
            let block = u64::from_be_bytes(k[32..40].try_into().unwrap());
            if block > to_block {
                break;
            }
            let tx_index = u32::from_be_bytes(k[40..44].try_into().unwrap());
            let log_index = u32::from_be_bytes(k[44..48].try_into().unwrap());
            if v.len() < 33 {
                continue;
            }
            let tx_hash = B256::from_slice(&v[..32]);
            let n = v[32] as usize;
            let mut topics = Vec::with_capacity(n);
            let mut off = 33;
            for _ in 0..n {
                if off + 32 > v.len() {
                    break;
                }
                topics.push(B256::from_slice(&v[off..off + 32]));
                off += 32;
            }
            out.push((block, tx_index, log_index, tx_hash, topics, v[off..].to_vec()));
        }
        Ok(out)
    }

    /// Every distinct event type present, with its count and block span.
    pub fn topics(&self) -> Result<Vec<(B256, u64, u64, u64)>> {
        use std::collections::BTreeMap;
        let cf = self.cf(CF_EVENTS)?;
        let mut acc: BTreeMap<[u8; 32], (u64, u64, u64)> = BTreeMap::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (k, _) = item?;
            if k.len() < 40 {
                continue;
            }
            let mut t = [0u8; 32];
            t.copy_from_slice(&k[..32]);
            let block = u64::from_be_bytes(k[32..40].try_into().unwrap());
            let e = acc.entry(t).or_insert((0, u64::MAX, 0));
            e.0 += 1;
            e.1 = e.1.min(block);
            e.2 = e.2.max(block);
        }
        Ok(acc
            .into_iter()
            .map(|(t, (c, first, last))| (B256::from(t), c, first, last))
            .collect())
    }

    pub fn add_coverage(&self, c: &Coverage) -> Result<()> {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let val = format!(
            r#"{{"from":{},"to":{},"build":"{}","recordedAt":{at},"blocks":{},"verified":{},"events":{},"skipped":{},"skipDetail":{}}}"#,
            c.from, c.to, c.build, c.blocks, c.verified, c.events, c.skipped,
            if c.skip_detail.is_empty() { "{}" } else { c.skip_detail.as_str() }
        );
        self.db
            .put_cf(self.cf(CF_META)?, c.from.to_be_bytes(), val.as_bytes())
            .context("writing legacy event coverage")
    }

    /// Every coverage span, in block order, as stored JSON.
    pub fn coverage(&self) -> Result<Vec<String>> {
        let cf = self.cf(CF_META)?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            if k.len() != 8 {
                continue;
            }
            out.push(String::from_utf8_lossy(&v).into_owned());
        }
        Ok(out)
    }

    /// Whether `from..=to` is wholly covered by recorded spans.
    ///
    /// The question to ask before believing an empty scan. Spans are merged
    /// as they are walked, so adjacent ranges recorded separately still count
    /// as contiguous.
    pub fn covers(&self, from: u64, to: u64) -> Result<bool> {
        let mut spans: Vec<(u64, u64)> = Vec::new();
        for json in self.coverage()? {
            let g = |k: &str| -> Option<u64> {
                let i = json.find(&format!("\"{k}\":"))? + k.len() + 3;
                let rest = &json[i..];
                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                rest[..end].parse().ok()
            };
            if let (Some(f), Some(t)) = (g("from"), g("to")) {
                spans.push((f, t));
            }
        }
        spans.sort_unstable();
        let mut want = from;
        for (f, t) in spans {
            if f > want {
                return Ok(false);
            }
            if t >= want {
                want = t.saturating_add(1);
            }
            if want > to {
                return Ok(true);
            }
        }
        Ok(want > to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn row(topic: u8, block: u64, log_index: u32) -> EventRow {
        EventRow {
            topic0: B256::repeat_byte(topic),
            block,
            tx_index: 0,
            log_index,
            tx_hash: B256::repeat_byte(0xEE),
            topics: vec![B256::repeat_byte(topic), B256::repeat_byte(0x01)],
            data: vec![7u8; 32],
        }
    }

    #[test]
    fn a_stored_event_round_trips_exactly() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        let r = row(0xAA, 100, 0);
        s.put_events(std::slice::from_ref(&r)).unwrap();

        let got = s.scan(r.topic0, 0, u64::MAX).unwrap();
        assert_eq!(got.len(), 1);
        let (block, tx_index, log_index, tx_hash, topics, data) = &got[0];
        assert_eq!(*block, 100);
        assert_eq!(*tx_index, 0);
        assert_eq!(*log_index, 0);
        assert_eq!(*tx_hash, r.tx_hash);
        assert_eq!(*topics, r.topics);
        assert_eq!(*data, r.data);
    }

    #[test]
    fn a_scan_is_bounded_by_topic_and_by_block() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        for b in [10u64, 20, 30] {
            s.put_events(&[row(0xAA, b, 0), row(0xBB, b, 0)]).unwrap();
        }
        assert_eq!(s.scan(B256::repeat_byte(0xAA), 0, u64::MAX).unwrap().len(), 3);
        assert_eq!(s.scan(B256::repeat_byte(0xAA), 15, 25).unwrap().len(), 1);
        assert_eq!(s.scan(B256::repeat_byte(0xCC), 0, u64::MAX).unwrap().len(), 0);
    }

    /// Block order is what makes the union with the real index sortable.
    #[test]
    fn events_come_back_in_block_then_log_order() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        s.put_events(&[row(0xAA, 30, 0), row(0xAA, 10, 1), row(0xAA, 10, 0)]).unwrap();
        let got = s.scan(B256::repeat_byte(0xAA), 0, u64::MAX).unwrap();
        let order: Vec<(u64, u32)> = got.iter().map(|e| (e.0, e.2)).collect();
        assert_eq!(order, vec![(10, 0), (10, 1), (30, 0)]);
    }

    #[test]
    fn topics_enumerates_what_is_there() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        s.put_events(&[row(0xAA, 5, 0), row(0xAA, 9, 0), row(0xBB, 7, 0)]).unwrap();
        let t = s.topics().unwrap();
        assert_eq!(t.len(), 2);
        let aa = t.iter().find(|x| x.0 == B256::repeat_byte(0xAA)).unwrap();
        assert_eq!((aa.1, aa.2, aa.3), (2, 5, 9));
    }

    /// The distinction the store exists to preserve: nothing found, versus
    /// nobody looked.
    #[test]
    fn coverage_separates_no_events_from_never_built() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        assert!(!s.covers(1, 100).unwrap(), "nothing recorded yet");

        s.add_coverage(&Coverage {
            from: 1, to: 100, build: "abc".into(), blocks: 100, verified: 100, events: 0, skipped: 0, skip_detail: String::new(),
        })
        .unwrap();
        assert!(s.covers(1, 100).unwrap());
        assert!(s.covers(10, 50).unwrap());
        assert!(!s.covers(1, 101).unwrap(), "one block past the end is not covered");
    }

    #[test]
    fn adjacent_spans_join_up() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        for (f, t) in [(1u64, 50u64), (51, 100)] {
            s.add_coverage(&Coverage {
                from: f, to: t, build: "b".into(), blocks: t - f + 1, verified: t - f + 1, events: 0, skipped: 0, skip_detail: String::new(),
            })
            .unwrap();
        }
        assert!(s.covers(1, 100).unwrap(), "51 follows 50 with no gap");
    }

    #[test]
    fn a_hole_between_spans_is_not_covered() {
        let d = tmp();
        let s = LegacyEventStore::open(d.path().to_str().unwrap()).unwrap();
        for (f, t) in [(1u64, 40u64), (60, 100)] {
            s.add_coverage(&Coverage {
                from: f, to: t, build: "b".into(), blocks: t - f + 1, verified: t - f + 1, events: 0, skipped: 0, skip_detail: String::new(),
            })
            .unwrap();
        }
        assert!(!s.covers(1, 100).unwrap());
        assert!(s.covers(60, 100).unwrap());
    }
}
