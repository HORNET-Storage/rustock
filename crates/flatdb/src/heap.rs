//! The value store: an append-only sequence of records over memory-mapped
//! segments, addressed by a flat byte offset.
//!
//! Records are never moved, never rewritten and never reclaimed, so an
//! offset handed out once stays valid forever and offsets only increase.
//! Those two properties are what let the index address a record with a bare
//! integer and let the checkpoint express "what is committed" as a single
//! watermark. Space comes back by discarding a whole database, not by
//! collecting inside one.
//!
//! Record layout, unchanged from the Java original so the formats stay
//! comparable:
//!
//! ```text
//! [magic 2B] [length 1B or 4B] [key 32B, optional] [data]
//! ```
//!
//! A one-byte length is a short record and never stores its key. A
//! four-byte length has bit 31 set to mark the long form and bit 30 set
//! when the key precedes the data. The leading magic is what turns a wild
//! offset into a miss instead of arbitrary bytes.

use memmap2::{MmapOptions, MmapRaw};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

/// One mapped file per segment. Large enough that files stay few, small
/// enough that mapping one is not an event.
///
/// Java needed 512 MiB because `MappedByteBuffer` is indexed by `int`.
/// Rust has no such cap, and the porting notes suggest 4–16 GiB. It is kept
/// at 512 MiB anyway so that a gigabyte of state crosses two boundaries:
/// the "a record must not straddle a segment" path is then exercised by
/// every real run rather than only by a unit test.
pub const DEFAULT_SEGMENT_SIZE: u64 = 1 << 29;

/// Highest addressable offset. 8-byte slots could address the whole of
/// `u64`; this is a sanity bound, not a format limit.
pub const MAX_SIZE: u64 = (1 << 48) - 1;

const MAGIC: u16 = 0x654A;
const MAGIC_LENGTH: usize = 2;
const SHORT_LENGTH_MAX: usize = 127;
const LONG_FORM_BIT: u32 = 1 << 31;
const KEY_STORED_BIT: u32 = 1 << 30;
const LENGTH_MASK: u32 = KEY_STORED_BIT - 1;

/// A record borrowed straight out of the mapping.
///
/// No allocation: this is the single largest win the Rust port has over the
/// Java one, where every probe step — including the ones that miss —
/// allocated a byte array for the key and another for the data.
pub struct Record<'a> {
    /// Present only for long records, which carry their key. For short ones
    /// the key is `H(data)` and the caller recomputes it.
    pub key: Option<&'a [u8]>,
    pub data: &'a [u8],
    /// Bytes this record occupies, header included. What a sequential scan
    /// adds to reach the next one.
    pub total: usize,
}

pub struct Heap {
    dir: PathBuf,
    read_only: bool,
    /// Grown only by `append`, which its caller serialises. Read under the
    /// shared lock, so a grow cannot move the `Vec` under a reader.
    segments: RwLock<Vec<MmapRaw>>,
    segment_size: u64,
    /// One past the last byte **reserved**. Writers move this; readers
    /// never look at it.
    ///
    /// Split from `size` on purpose. `size` is the publication barrier —
    /// `with_record` rejects anything at or beyond it, and the
    /// release/acquire pair with it is the only thing making lock-free
    /// reads sound. Moving that barrier to claim space would expose a
    /// range while it is still being written, so claiming happens here
    /// and publication happens there, in that order.
    alloc: AtomicU64,
    /// One past the last byte **written and published**. Monotonic, and
    /// what every reader checks against.
    size: AtomicU64,
    /// Lowest segment touched since the last `force`.
    first_dirty: AtomicUsize,
}

const NOTHING_DIRTY: usize = usize::MAX;

impl Heap {
    pub fn open(
        dir: &Path,
        read_only: bool,
        committed_size: u64,
        segment_size: u64,
    ) -> io::Result<Self> {
        if !segment_size.is_power_of_two() {
            return Err(io::Error::other(format!(
                "segment size {segment_size} must be a power of two"
            )));
        }
        std::fs::create_dir_all(dir)?;
        let heap = Self {
            dir: dir.to_path_buf(),
            read_only,
            segments: RwLock::new(Vec::new()),
            segment_size,
            alloc: AtomicU64::new(committed_size),
            size: AtomicU64::new(committed_size),
            first_dirty: AtomicUsize::new(NOTHING_DIRTY),
        };
        // Map enough to cover what the checkpoint says is committed. Bytes
        // beyond that may exist on disk from an interrupted flush; the
        // frontier starts below them and the next append overwrites them.
        let needed = committed_size.div_ceil(segment_size).max(1) as usize;
        {
            let mut segments = heap.segments.write().expect("heap segments");
            for index in 0..needed {
                segments.push(heap.map_segment(index)?);
            }
        }
        Ok(heap)
    }

    fn segment_path(&self, index: usize) -> PathBuf {
        self.dir.join(format!("heap.{index}.dat"))
    }

    fn map_segment(&self, index: usize) -> io::Result<MmapRaw> {
        let path = self.segment_path(index);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(!self.read_only)
            .create(!self.read_only)
            .open(&path)?;
        if !self.read_only && file.metadata()?.len() < self.segment_size {
            // Reserve the blocks rather than leaving a hole. Writing into a
            // hole on a full disk faults at access time and arrives as
            // SIGBUS, which no `Result` can carry; failing here instead
            // turns that into an error at open.
            reserve(&file, self.segment_size)?;
        }
        // `map_raw` is safe because `MmapRaw` hands out pointers rather
        // than slices; the obligation lands on every `unsafe` block below
        // that dereferences one. What discharges it for the file as a whole
        // is the exclusive directory lock (see `DbLock`): no cooperating
        // process truncates or rewrites this file while it is mapped. That
        // is an argument about cooperating processes and does not defend
        // against a hostile one, which this store is not asked to handle.
        let mut options = MmapOptions::new();
        options.len(self.segment_size as usize);
        let map = if self.read_only {
            options.map_raw_read_only(&file)?
        } else {
            options.map_raw(&file)?
        };
        Ok(map)
    }

    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    pub fn segment_size(&self) -> u64 {
        self.segment_size
    }

    pub fn segment_count(&self) -> usize {
        self.segments.read().expect("heap segments").len()
    }

    fn length_field_size(data_length: usize, store_key: bool) -> usize {
        if data_length <= SHORT_LENGTH_MAX && !store_key {
            1
        } else {
            4
        }
    }

    pub fn record_size(data_length: usize, store_key: bool, key_length: usize) -> usize {
        MAGIC_LENGTH
            + Self::length_field_size(data_length, store_key)
            + if store_key { key_length } else { 0 }
            + data_length
    }

    /// Claim a contiguous range for as many of `sizes` as fit in one
    /// segment, atomically.
    ///
    /// Returns the frontier it claimed **from**, where the records
    /// actually start, how many the run covers, and the new frontier.
    ///
    /// `from` and `start` differ when the run had to skip a segment,
    /// because a record may not straddle one. The skipped tail belongs to
    /// the reservation and publication has to cover it -- publishing from
    /// `start` instead would wait for a value the frontier never takes,
    /// and every later writer would spin behind it. That is a deadlock,
    /// and it is how this was first written.
    fn reserve_run(&self, sizes: &[usize]) -> io::Result<(u64, u64, usize, u64)> {
        let segment_size = self.segment_size;
        loop {
            let from = self.alloc.load(Ordering::Acquire);
            let mut start = from;
            let mut room = segment_size - (start % segment_size);
            if sizes[0] as u64 > room {
                // Not even the first record fits: skip to the next segment.
                start = (start / segment_size + 1) * segment_size;
                room = segment_size;
            }
            let mut used = 0u64;
            let mut count = 0usize;
            for size in sizes {
                if used + *size as u64 > room {
                    break;
                }
                used += *size as u64;
                count += 1;
            }
            let end = start + used;
            if end > MAX_SIZE {
                return Err(io::Error::other(format!(
                    "heap would exceed the addressable limit of {MAX_SIZE} bytes"
                )));
            }
            if self
                .alloc
                .compare_exchange_weak(from, end, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok((from, start, count, end));
            }
        }
    }

    /// Advance the published frontier from `from` to `to`, in order.
    ///
    /// Reservations complete out of order; publication must not, or
    /// `size` would run ahead of a range still being written. A writer
    /// that reserved earlier publishes earlier, so waiting for `size` to
    /// reach this writer's own start is exactly the condition that every
    /// byte below `to` is written.
    ///
    /// The wait is bounded by how long it takes the predecessor to copy
    /// its own records, which is why batching matters here: a block
    /// produces a handful of reservations rather than thousands.
    fn publish(&self, from: u64, to: u64) {
        let mut spins = 0u32;
        while self
            .size
            .compare_exchange_weak(from, to, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }

    /// Appends many records at once and returns their offsets, in order.
    ///
    /// Space for the whole batch is claimed in one atomic step; the bytes
    /// are then copied with **no lock held**, so several writers overlap;
    /// and the range is published once, in reservation order.
    pub fn append_many(&self, records: &[(&[u8], &[u8], bool)]) -> io::Result<Vec<u64>> {
        let sizes: Vec<usize> = records
            .iter()
            .map(|(key, data, store_key)| Self::record_size(data.len(), *store_key, key.len()))
            .collect();
        for (size, (_, data, _)) in sizes.iter().zip(records) {
            if *size as u64 > self.segment_size {
                return Err(io::Error::other(format!(
                    "record of {size} bytes ({} of data) exceeds the segment size of {}",
                    data.len(),
                    self.segment_size
                )));
            }
        }

        let mut offsets = Vec::with_capacity(records.len());
        let mut done = 0usize;
        while done < records.len() {
            let (from, start, count, end) = self.reserve_run(&sizes[done..])?;
            debug_assert!(count > 0, "a reservation that fits nothing cannot make progress");

            let segment = (start / self.segment_size) as usize;
            // Mapping can fail, and returning here without publishing
            // would strand every writer queued behind this reservation.
            // The range is released as written-but-empty: nothing points
            // into it, so it is dead space and not a wrong answer.
            if let Err(e) = self.map_up_to(segment) {
                self.publish(from, end);
                return Err(e);
            }

            let segments = self.segments.read().expect("heap segments");
            let base = segments[segment].as_mut_ptr();
            let mut at = start;
            for index in done..done + count {
                let (key, data, store_key) = records[index];
                // SAFETY: this range was claimed by this thread alone and
                // lies wholly inside one mapped segment, so no other
                // thread writes it and no reader can reach it -- `size`
                // still sits at or below `start`.
                unsafe {
                    self.write_record(base, (at % self.segment_size) as usize, key, data, store_key);
                }
                offsets.push(at);
                at += sizes[index] as u64;
            }
            drop(segments);

            self.first_dirty.fetch_min(segment, Ordering::Relaxed);
            self.publish(from, end);
            done += count;
        }
        Ok(offsets)
    }

    fn map_up_to(&self, segment: usize) -> io::Result<()> {
        let mut segments = self.segments.write().expect("heap segments");
        while segment >= segments.len() {
            let next = segments.len();
            segments.push(self.map_segment(next)?);
        }
        Ok(())
    }

    /// # Safety
    ///
    /// `offset` plus the record's size must lie inside the segment `base`
    /// maps, and the range must be claimed by this thread alone.
    unsafe fn write_record(
        &self,
        base: *mut u8,
        offset: usize,
        key: &[u8],
        data: &[u8],
        store_key: bool,
    ) {
        let mut p = base.add(offset);
        std::ptr::copy_nonoverlapping(MAGIC.to_be_bytes().as_ptr(), p, MAGIC_LENGTH);
        p = p.add(MAGIC_LENGTH);
        if Self::length_field_size(data.len(), store_key) == 1 {
            *p = data.len() as u8;
            p = p.add(1);
        } else {
            let header =
                LONG_FORM_BIT | if store_key { KEY_STORED_BIT } else { 0 } | data.len() as u32;
            std::ptr::copy_nonoverlapping(header.to_be_bytes().as_ptr(), p, 4);
            p = p.add(4);
        }
        if store_key {
            std::ptr::copy_nonoverlapping(key.as_ptr(), p, key.len());
            p = p.add(key.len());
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
    }

    /// Appends a record and returns its offset.
    ///
    /// A record never straddles a segment boundary: if it does not fit in
    /// the current segment the frontier skips to the next one. That keeps
    /// offsets monotonic and lets a read resolve an offset to exactly one
    /// mapping.
    ///
    /// Safe to call concurrently: see [`Self::append_many`], which this
    /// is a one-record case of.
    pub fn append(&self, key: &[u8], data: &[u8], store_key: bool) -> io::Result<u64> {
        Ok(self.append_many(&[(key, data, store_key)])?[0])
    }

    /// Reads the record at `offset` and hands it to `f`, or returns `None`
    /// when the offset does not point at a record boundary.
    ///
    /// The closure keeps the borrow inside the mapping's guard, so the
    /// record never has to be copied to be examined. A probe step that
    /// rejects a candidate therefore costs a hash and a compare rather than
    /// two allocations — which is where "the index stores no keys" is
    /// actually paid for.
    pub fn with_record<R>(
        &self,
        offset: u64,
        key_length: usize,
        f: impl FnOnce(Record<'_>) -> R,
    ) -> Option<R> {
        let size = self.size.load(Ordering::Acquire);
        // The bounds check against the *committed* frontier is load-bearing,
        // not defensive. It is what makes a slot left behind by an
        // interrupted flush read as a miss, which is what lets probing
        // continue past it and the next insertion reclaim it. Without it
        // every probe step would need its own validity check, which is the
        // machinery this design exists to delete.
        if offset >= size {
            return None;
        }
        let segment_index = (offset / self.segment_size) as usize;
        let start = (offset % self.segment_size) as usize;
        let mut p = start;

        let segments = self.segments.read().expect("heap segments");
        let segment = segments.get(segment_index)?;
        let base = segment.as_ptr();
        let limit = self.segment_size as usize;

        // SAFETY: every read below is bounds-checked against `limit` before
        // it happens, and the bytes were written before the slot that led
        // here was published with a release store. The acquire load of that
        // slot, paired with it, is what makes those writes visible; the
        // append-only invariant is what guarantees they are not being
        // rewritten now.
        unsafe {
            if p + MAGIC_LENGTH > limit {
                return None;
            }
            let magic = u16::from_be_bytes([*base.add(p), *base.add(p + 1)]);
            if magic != MAGIC {
                return None;
            }
            p += MAGIC_LENGTH;

            if p >= limit {
                return None;
            }
            let first = *base.add(p);
            let (data_length, key_stored) = if first & 0x80 == 0 {
                p += 1;
                (first as usize, false)
            } else {
                if p + 4 > limit {
                    return None;
                }
                let header = u32::from_be_bytes([
                    *base.add(p),
                    *base.add(p + 1),
                    *base.add(p + 2),
                    *base.add(p + 3),
                ]);
                p += 4;
                ((header & LENGTH_MASK) as usize, header & KEY_STORED_BIT != 0)
            };

            let key_bytes = if key_stored { key_length } else { 0 };
            if p + key_bytes + data_length > limit {
                return None;
            }
            // And the record must lie entirely below the frontier, or it is
            // a half-written tail rather than a record.
            let total = (p - start) + key_bytes + data_length;
            if offset + total as u64 > size {
                return None;
            }

            let key = if key_stored {
                let slice = std::slice::from_raw_parts(base.add(p), key_length);
                p += key_length;
                Some(slice)
            } else {
                None
            };
            let data = std::slice::from_raw_parts(base.add(p), data_length);
            Some(f(Record { key, data, total }))
        }
    }

    /// Walks every record from the start of the heap to the frontier.
    ///
    /// For an append-only store this is the natural iteration and it beats
    /// going through the index: it is sequential, it reads each page once,
    /// and it needs no probe. The sweep wants exactly this — a scan of the
    /// oldest epoch, filtered against the live set.
    ///
    /// A record never straddles a segment, so the frontier skips to the
    /// next segment rather than splitting one. Those gaps hold no magic
    /// and the scan jumps over them.
    ///
    /// The scan may yield records the index can no longer reach: a batch
    /// whose slots were rolled back leaves its bytes behind. For a
    /// content-addressed store that is harmless to a consumer that filters
    /// by key, which is why this is the iteration the sweep uses.
    pub fn scan(
        &self,
        key_length: usize,
        visit: &mut dyn FnMut(Option<&[u8]>, &[u8]),
    ) -> usize {
        let size = self.size.load(Ordering::Acquire);
        let mut offset = 0u64;
        let mut seen = 0usize;
        while offset < size {
            match self.with_record(offset, key_length, |record| {
                visit(record.key, record.data);
                record.total
            }) {
                Some(total) if total > 0 => {
                    seen += 1;
                    offset += total as u64;
                }
                // No record here: the tail of a segment the frontier
                // skipped over. The next one starts at the segment base.
                _ => offset = (offset / self.segment_size + 1) * self.segment_size,
            }
        }
        seen
    }

    /// Forces every segment written since the previous call.
    pub fn force(&self) -> io::Result<()> {
        if self.read_only {
            return Ok(());
        }
        let first = self.first_dirty.swap(NOTHING_DIRTY, Ordering::Relaxed);
        if first == NOTHING_DIRTY {
            return Ok(());
        }
        let segments = self.segments.read().expect("heap segments");
        for segment in segments.iter().skip(first) {
            segment.flush()?;
        }
        Ok(())
    }

    /// Drops the frontier back to a committed position, discarding appends
    /// that no checkpoint ever made real.
    ///
    /// Both cursors move: leaving `alloc` ahead would make the next
    /// reservation skip the space being reclaimed, and leaving it behind
    /// would hand out a range that is already published.
    pub fn truncate_to(&self, committed_size: u64) {
        self.alloc.store(committed_size, Ordering::Release);
        self.size.store(committed_size, Ordering::Release);
    }
}

/// Reserve blocks so a later write cannot fail with SIGBUS on a full disk.
///
/// `fallocate` is Linux-specific and some filesystems refuse it; falling
/// back to `set_len` leaves a sparse file, which is the behaviour the Java
/// version has unconditionally.
#[cfg(unix)]
fn reserve(file: &std::fs::File, len: u64) -> io::Result<()> {
    match rustix::fs::fallocate(file, rustix::fs::FallocateFlags::empty(), 0, len) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::OPNOTSUPP) | Err(rustix::io::Errno::NOSYS) => file.set_len(len),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// Windows has no `fallocate`: `set_len`, the fallback above, is what it gets.
#[cfg(not(unix))]
fn reserve(file: &std::fs::File, len: u64) -> io::Result<()> {
    file.set_len(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small segment, so the boundary paths run in milliseconds instead
    /// of reserving half a gigabyte per segment. The size is part of the
    /// on-disk format and recorded in the checkpoint, so a test using one
    /// is testing the same code a production segment would.
    const TEST_SEGMENT: u64 = 1 << 16;

    fn heap(dir: &Path) -> Heap {
        Heap::open(dir, false, 0, TEST_SEGMENT).unwrap()
    }

    fn read_data(heap: &Heap, offset: u64) -> Option<Vec<u8>> {
        heap.with_record(offset, 32, |r| r.data.to_vec())
    }

    #[test]
    fn a_short_record_round_trips_without_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        let data = vec![7u8; 50];
        let offset = heap.append(&[1u8; 32], &data, false).unwrap();
        let (key, got) = heap.with_record(offset, 32, |r| (r.key.map(<[u8]>::to_vec), r.data.to_vec())).unwrap();
        assert_eq!(got, data);
        assert_eq!(key, None, "a short record stores no key");
    }

    #[test]
    fn a_long_record_round_trips_with_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        let data = vec![3u8; 2000];
        let key = [9u8; 32];
        let offset = heap.append(&key, &data, true).unwrap();
        let (got_key, got) = heap.with_record(offset, 32, |r| (r.key.map(<[u8]>::to_vec), r.data.to_vec())).unwrap();
        assert_eq!(got, data);
        assert_eq!(got_key.as_deref(), Some(&key[..]));
    }

    /// The magic is what makes a wild offset a miss instead of garbage.
    #[test]
    fn an_offset_that_is_not_a_record_reads_as_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        let offset = heap.append(&[1u8; 32], &[7u8; 50], false).unwrap();
        assert!(read_data(&heap, offset + 3).is_none(), "mid-record");
        assert!(read_data(&heap, heap.size()).is_none(), "at the frontier");
        assert!(read_data(&heap, heap.size() + 10_000).is_none(), "beyond it");
    }

    /// The property the whole recovery story rests on: a record written but
    /// never committed is invisible once the frontier is put back.
    #[test]
    fn records_beyond_the_frontier_are_invisible() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        let first = heap.append(&[1u8; 32], &[1u8; 50], false).unwrap();
        let committed = heap.size();
        let second = heap.append(&[2u8; 32], &[2u8; 50], false).unwrap();
        assert!(read_data(&heap, second).is_some());

        heap.truncate_to(committed);
        assert!(read_data(&heap, first).is_some(), "the committed one stays");
        assert!(read_data(&heap, second).is_none(), "the uncommitted one goes");
    }

    /// A record must not straddle a segment, and the offsets must stay
    /// monotonic across the skip.
    #[test]
    fn a_record_that_would_straddle_a_segment_starts_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        // Fill to within a hair of the boundary.
        let big = vec![0xABu8; 10_000];
        let mut last = 0;
        while heap.size() % TEST_SEGMENT < TEST_SEGMENT - 10_000 {
            last = heap.append(&[0u8; 32], &big, false).unwrap();
        }
        let before = heap.size();
        let crossing = heap.append(&[1u8; 32], &big, false).unwrap();
        assert!(crossing >= before, "offsets stay monotonic");
        assert_eq!(crossing / TEST_SEGMENT, 1, "it went to the next segment");
        assert_eq!(crossing % TEST_SEGMENT, 0, "and started at its base");
        assert_eq!(read_data(&heap, crossing).unwrap(), big);
        assert_eq!(read_data(&heap, last).unwrap(), big);
        assert_eq!(heap.segment_count(), 2);
    }

    #[test]
    fn records_survive_close_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (offset, committed) = {
            let heap = heap(dir.path());
            let offset = heap.append(&[1u8; 32], &[42u8; 60], false).unwrap();
            heap.force().unwrap();
            (offset, heap.size())
        };
        let reopened = Heap::open(dir.path(), false, committed, TEST_SEGMENT).unwrap();
        assert_eq!(read_data(&reopened, offset).unwrap(), vec![42u8; 60]);
    }

    /// Both length forms, right at the boundary where the encoding changes.
    #[test]
    fn both_length_forms_round_trip_at_their_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        for length in [0usize, 1, 126, 127, 128, 129, 1023, 1024, 1025, 40_000] {
            let data = vec![(length % 251) as u8; length];
            let store_key = length > 1024;
            let offset = heap.append(&[5u8; 32], &data, store_key).unwrap();
            assert_eq!(read_data(&heap, offset).unwrap(), data, "length {length}");
        }
    }

    /// A batch that does not fit in the current segment reserves across
    /// the skip, and publication has to cover the skipped tail. Getting
    /// that wrong deadlocks: the frontier waits for a value it never
    /// takes. This is the test that caught it.
    #[test]
    fn a_batch_that_skips_a_segment_still_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let heap = heap(dir.path());
        let big = vec![0xCDu8; 20_000];

        // Fill until only a little of the first segment is left.
        while heap.size() % TEST_SEGMENT < TEST_SEGMENT - 25_000 {
            heap.append(&[0u8; 32], &big, false).unwrap();
        }
        let before = heap.size();

        // A batch that cannot fit in what remains.
        let records: Vec<(&[u8], &[u8], bool)> =
            (0..4).map(|_| (&[1u8; 32][..], &big[..], false)).collect();
        let offsets = heap.append_many(&records).unwrap();

        assert_eq!(offsets.len(), 4);
        assert!(heap.size() > before, "the frontier moved past the skip");
        // The point of the test: a skip must actually have happened, or
        // it is exercising the ordinary path and would not have caught
        // the deadlock.
        let segments: std::collections::BTreeSet<u64> =
            offsets.iter().map(|o| o / TEST_SEGMENT).collect();
        assert!(
            segments.len() > 1 || offsets[0].is_multiple_of(TEST_SEGMENT),
            "no segment boundary was crossed: offsets {offsets:?}"
        );
        for offset in &offsets {
            assert_eq!(read_data(&heap, *offset).unwrap(), big, "offset {offset}");
        }
    }

    /// Several threads appending at once must get disjoint ranges, and
    /// every record must be readable afterwards. The frontier is the only
    /// thing they share.
    #[test]
    fn concurrent_batches_do_not_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let heap = Heap::open(dir.path(), false, 0, 1 << 22).unwrap();

        let per_thread = 200usize;
        let all: Vec<Vec<Vec<u8>>> = (0..4u8)
            .map(|t| {
                (0..per_thread)
                    .map(|i| {
                        let mut v = vec![t; 60];
                        v[..8].copy_from_slice(&(i as u64).to_le_bytes());
                        v
                    })
                    .collect()
            })
            .collect();

        let results: Vec<Vec<u64>> = std::thread::scope(|scope| {
            let handles: Vec<_> = all
                .iter()
                .map(|mine| {
                    let heap = &heap;
                    scope.spawn(move || {
                        let records: Vec<(&[u8], &[u8], bool)> =
                            mine.iter().map(|v| (&[7u8; 32][..], v.as_slice(), false)).collect();
                        heap.append_many(&records).unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        // Every record reads back as itself: no two writers shared a byte.
        for (offsets, mine) in results.iter().zip(&all) {
            for (offset, expected) in offsets.iter().zip(mine) {
                assert_eq!(read_data(&heap, *offset).as_ref(), Some(expected));
            }
        }
        // And every offset handed out is distinct.
        let mut flat: Vec<u64> = results.iter().flatten().copied().collect();
        let handed = flat.len();
        flat.sort_unstable();
        flat.dedup();
        assert_eq!(flat.len(), handed, "two writers were given the same offset");
    }

    /// The published frontier never runs ahead of the written bytes, which
    /// is what makes a lock-free read sound. After every batch it must
    /// equal the reservation cursor, with nothing in flight.
    #[test]
    fn publication_catches_up_to_every_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let heap = Heap::open(dir.path(), false, 0, 1 << 22).unwrap();
        let value = vec![3u8; 80];
        let records: Vec<(&[u8], &[u8], bool)> =
            (0..500).map(|_| (&[2u8; 32][..], value.as_slice(), false)).collect();
        for _ in 0..5 {
            heap.append_many(&records).unwrap();
        }
        assert_eq!(
            heap.size(),
            heap.alloc.load(Ordering::Acquire),
            "a reservation was never published"
        );
    }
}
