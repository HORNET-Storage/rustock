//! Read and write key sets per parallel sublist, and the collision rule
//! RSKIP-144 makes a condition of a block's validity.
//!
//! From RSKIP-144, where sublists execute in parallel:
//!
//! > When all parallel sublists have finished processing, the `readMap`s and
//! > `writeMap`s are scanned to find connections between transactions of
//! > different threads.
//! > - If a key belongs to a `writeMap` and a `readMap` of another parallel
//! >   sublist, then the block is considered invalid.
//! > - If a key belongs to a `writeMap` and a `writeMap` of another parallel
//! >   sublist, then the block is also invalid.
//!
//! This is a rule a validator applies, not a property it may assume the
//! miner established. The distinction matters because the obvious shortcut
//! is wrong: executing the sublists sequentially does *not* stand in for the
//! check. Where sublists conflict, sequential and parallel execution agree
//! in some interleavings and differ in others, so a sequential executor that
//! skips this accepts blocks rskj rejects -- and does so silently, having
//! computed a state root nobody else would reach.
//!
//! Read against read is not a collision. Two sublists may read the same key
//! freely; only a write makes an ordering observable.

use alloy_primitives::{Address, B256};
use revm::context::JournalEntry;
use revm::state::{AccountStatus, EvmState};
use rustock_trie::{account_key, code_key, storage_key, storage_prefix_key};
use std::cell::RefCell;
use std::collections::HashSet;

/// Which sublist a key belongs to. rskj keys these by thread id, since each
/// sublist runs on its own thread; here they are the sublist's index, which
/// is the same thing said without reference to how execution is scheduled.
pub type SublistId = usize;

/// The keys each sublist read and wrote.
///
/// Keys are whole unitrie keys, not storage keys alone. rskj records every
/// key passing through its repository's `internalGet`, `internalGetValueLength`
/// and `internalGetValueHash` as a read, everything through `internalPut` as
/// a write, and an account's key as a write when the account is deleted. So
/// an account's balance or nonce counts, and two sublists crediting the same
/// address collide -- which is the intended reading, and stricter than
/// RSKIP-144's prose, which says "storage key" throughout.
#[derive(Debug, Default, Clone)]
pub struct SublistKeys {
    read: HashSet<Vec<u8>>,
    written: HashSet<Vec<u8>>,
}

impl SublistKeys {
    pub fn read(&self) -> &HashSet<Vec<u8>> {
        &self.read
    }

    pub fn written(&self) -> &HashSet<Vec<u8>> {
        &self.written
    }
}

/// Per-sublist key sets for one block.
#[derive(Debug, Default, Clone)]
pub struct CollisionTracker {
    sublists: Vec<SublistKeys>,
    /// Which sublist is executing. Reads and writes are attributed here.
    current: SublistId,
}

impl CollisionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Directs subsequent reads and writes at `id`.
    pub fn set_sublist(&mut self, id: SublistId) {
        if self.sublists.len() <= id {
            self.sublists.resize_with(id + 1, SublistKeys::default);
        }
        self.current = id;
    }

    pub fn note_read(&mut self, key: &[u8]) {
        self.ensure(self.current);
        self.sublists[self.current].read.insert(key.to_vec());
    }

    pub fn note_write(&mut self, key: &[u8]) {
        self.ensure(self.current);
        self.sublists[self.current].written.insert(key.to_vec());
    }

    fn ensure(&mut self, id: SublistId) {
        if self.sublists.len() <= id {
            self.sublists.resize_with(id + 1, SublistKeys::default);
        }
    }

    /// Union another tracker's sublists into this one, sublist by sublist.
    pub fn absorb(&mut self, other: CollisionTracker) {
        for (id, keys) in other.sublists.into_iter().enumerate() {
            self.ensure(id);
            self.sublists[id].read.extend(keys.read);
            self.sublists[id].written.extend(keys.written);
        }
    }

    pub fn clear(&mut self) {
        self.sublists.clear();
        self.current = 0;
    }

    pub fn sublist_count(&self) -> usize {
        self.sublists.len()
    }

    /// What bucket `id` read and wrote, if it exists.
    pub fn keys(&self, id: SublistId) -> Option<&SublistKeys> {
        self.sublists.get(id)
    }

    /// The first collision between two sublists, if there is one.
    ///
    /// Every unordered pair is compared, so a collision is reported once.
    /// Within a sublist nothing collides: a sublist may read and write the
    /// same key as much as it likes, because its own transactions are
    /// ordered with respect to each other.
    pub fn first_collision(&self) -> Option<Collision> {
        for (a, ka) in self.sublists.iter().enumerate() {
            for (b, kb) in self.sublists.iter().enumerate().skip(a + 1) {
                if let Some(key) = intersect(&ka.written, &kb.written) {
                    return Some(Collision { kind: CollisionKind::WriteWrite, a, b, key });
                }
                if let Some(key) = intersect(&ka.written, &kb.read) {
                    return Some(Collision { kind: CollisionKind::WriteRead, a, b, key });
                }
                if let Some(key) = intersect(&ka.read, &kb.written) {
                    return Some(Collision { kind: CollisionKind::WriteRead, a: b, b: a, key });
                }
            }
        }
        None
    }

    pub fn detect_collision(&self) -> bool {
        self.first_collision().is_some()
    }
}

/// Which key, between which sublists, and in which direction. Carried rather
/// than reduced to a boolean because a block rejected for this is a block
/// somebody has to diagnose, and "collision" alone names nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    pub kind: CollisionKind,
    /// For `WriteRead`, the sublist that wrote.
    pub a: SublistId,
    pub b: SublistId,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionKind {
    WriteWrite,
    WriteRead,
}

impl std::fmt::Display for Collision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = alloy_primitives::hex::encode(&self.key);
        match self.kind {
            CollisionKind::WriteWrite => write!(
                f, "sublists {} and {} both write 0x{key}", self.a, self.b
            ),
            CollisionKind::WriteRead => write!(
                f, "sublist {} writes 0x{key}, which sublist {} reads", self.a, self.b
            ),
        }
    }
}

/// Smaller set outside, so the scan is bounded by the smaller of the two.
///
/// The *smallest* common key rather than the first one found: a block
/// rejected for this has to be diagnosed, and two nodes comparing notes
/// should name the same key. `HashSet` iteration order would not.
fn intersect(x: &HashSet<Vec<u8>>, y: &HashSet<Vec<u8>>) -> Option<Vec<u8>> {
    let (small, large) = if x.len() <= y.len() { (x, y) } else { (y, x) };
    small.iter().filter(|k| large.contains(*k)).min().cloned()
}


// ---------------------------------------------------------------------------
// Which writes count
// ---------------------------------------------------------------------------

/// Which writes a sublist's `writeMap` holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSemantics {
    /// Every write the sublist **attempted**, including ones it reverted and
    /// ones that stored a value the cell already held. This is the deployed
    /// consensus rule.
    Attempted,
    /// Only the cells the sublist actually **changed**. Not consensus; see
    /// [`write_semantics`].
    NetChanges,
}

/// Which rule applies at `block_number`. Always [`WriteSemantics::Attempted`].
///
/// # The other mode is implemented, tested, and deliberately unreachable
///
/// [`WriteSemantics::NetChanges`] is a complete, exercised code path. It is
/// not reachable because it is **not the rule the network runs**, and a node
/// that applied it would accept blocks rskj rejects and follow a chain the
/// network does not.
///
/// ## To activate it
///
/// Return `NetChanges` from here **gated on a consensus rule**, never
/// unconditionally:
///
/// ```ignore
/// pub fn write_semantics(block_number: u64, cfg: &RskHardforkConfig) -> WriteSemantics {
///     if cfg.has_rskipXXX(block_number) { WriteSemantics::NetChanges }
///     else { WriteSemantics::Attempted }
/// }
/// ```
///
/// Flipping it without a gate would re-judge every historical block under a
/// rule that was not in force when it was mined. The signature takes the
/// block number precisely so that the gate has somewhere to go.
///
/// Then: delete the SSTORE wrapper's `Attempted` guard in
/// [`crate::rsk_instructions`] only if the gate is permanent, and leave the
/// journal-entry capture points alone — under `NetChanges` they become no-ops
/// on their own.
///
/// ## Why it exists
///
/// A write that the transaction reverted **cannot** make parallel execution
/// differ from sequential execution. Each parallel sublist runs against the
/// block's parent state on an isolated repository; rskj's `detectCollision`
/// runs after every sublist finishes and *before* any of them is merged, and
/// only then are the tracks committed in sublist order. No sublist ever
/// observes another's uncommitted work, and a reverted write is not in its
/// own sublist's commit either. Every other sublist therefore reads the same
/// value in both execution modes.
///
/// So `Attempted` rejects valid blocks. It is not a simplification RSKIP-144
/// chose -- the document does not mention reverts at all. rskj's tracker
/// lives in `MutableRepository`, `startTracking()` hands the *same* tracker
/// to every nested repository, and a rollback discards only the state cache.
/// The behaviour is where the tracker happened to be placed, and it became
/// consensus.
///
/// ## Why we match it anyway
///
/// Being right is not the same as being compatible. Until the rule changes
/// for everyone at a fork, a node applying `NetChanges` forks itself off the
/// chain. The proposal to change it is
/// `/home/paseo/doc/RSKIP-sublist-net-writes.md`; this mode is kept working
/// so that adopting it is a one-line gate rather than a reimplementation.
pub fn write_semantics(_block_number: u64) -> WriteSemantics {
    WriteSemantics::Attempted
}

// ---------------------------------------------------------------------------
// Recording the sets from execution
// ---------------------------------------------------------------------------

/// Which sublist transaction `index` belongs to, or `None` for the
/// **sequential** set.
///
/// `edges` is the header's `txExecutionSublistsEdges`: with edges
/// `[e0, e1]` rskj builds two parallel sublists, `[0, e0)` and `[e0, e1)`,
/// and runs `[e1, n)` afterwards on the main thread
/// (`BlockExecutor.executeParallel`). The sequential set is deliberately
/// outside the check -- `detectCollision` is called before it runs, which is
/// the whole point of having it: it is where a miner puts the transactions
/// that *do* conflict.
pub fn sublist_of(index: usize, edges: &[i16]) -> Option<SublistId> {
    let id = edges.iter().filter(|&&e| (e as usize) <= index).count();
    (id < edges.len()).then_some(id)
}

/// The block's transactions partitioned as its header declares: the parallel
/// sublists in order, then the sequential set.
///
/// Kept beside [`sublist_of`] because the two must agree about where the
/// boundaries are -- one decides what executes together, the other decides
/// what is checked against what, and a disagreement would check the wrong
/// pairs.
pub fn sublist_ranges(
    edges: &[i16],
    tx_count: usize,
) -> (Vec<std::ops::Range<usize>>, std::ops::Range<usize>) {
    let mut parallel = Vec::with_capacity(edges.len());
    let mut start = 0usize;
    for &edge in edges {
        let end = (edge.max(0) as usize).min(tx_count);
        if end > start {
            parallel.push(start..end);
        }
        start = start.max(end);
    }
    (parallel, start..tx_count)
}

/// How a recorder was configured, so a worker thread can be given the same.
///
/// The thread-local is per thread by design -- it is how rskj keys its own
/// tracker -- which means a worker starts with nothing and the coordinator
/// has to hand it the block's configuration.
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    edges: Vec<i16>,
    excluded: Vec<Address>,
    semantics: WriteSemantics,
}

/// This thread's recorder configuration, if it has one.
pub fn config() -> Option<RecorderConfig> {
    RECORDER.with(|r| {
        r.borrow().as_ref().and_then(|rec| match &rec.attribution {
            Attribution::Sublists(edges) => Some(RecorderConfig {
                edges: edges.clone(),
                excluded: rec.excluded.clone(),
                semantics: rec.semantics,
            }),
            // Per-transaction recording belongs to the thread building the
            // block; there is nothing for a worker to inherit.
            Attribution::PerTransaction => None,
        })
    })
}

/// Start recording on this thread with a configuration taken from another.
pub fn start_from(config: RecorderConfig) {
    start(&config.edges, &config.excluded, config.semantics);
}

/// Fold a worker's key sets into this thread's recorder.
///
/// Each worker only ever writes the sublist it ran, so the fold is a union
/// over disjoint sublists. It is written as a union anyway, because a fold
/// that silently depended on that would be a bad thing to be wrong about.
pub fn absorb(other: CollisionTracker) {
    RECORDER.with(|r| {
        if let Some(rec) = r.borrow_mut().as_mut() {
            rec.tracker.absorb(other);
        }
    });
}

/// Per-thread recorder, off unless a block asks for it.
///
/// The thread-local follows [`crate::silent`]: the alternative is a tracker
/// threaded through `execute_block`, the handler and every precompile, and
/// the consensus path is the code least worth disturbing for the sake of a
/// check that is inert on every block mainnet has ever produced.
/// What a recorded key is attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attribution {
    /// The sublist running the transaction, as the header declares them.
    /// This is validation: the question is whether two sublists collide.
    Sublists(Vec<i16>),
    /// One bucket per transaction. This is mining: the question is what each
    /// transaction touched, because that is what decides where it goes, and
    /// the partition does not exist yet to attribute to.
    PerTransaction,
}

struct Recorder {
    tracker: CollisionTracker,
    attribution: Attribution,
    semantics: WriteSemantics,
    /// Addresses whose account cell is written outside any sublist, so
    /// attributing it to one would invent a collision. See [`start`].
    excluded: Vec<Address>,
    /// The sublist running the current transaction, or `None` when it is in
    /// the sequential set and nothing should be recorded.
    sublist: Option<SublistId>,
    /// How many of the current transaction's journal entries have been read.
    ///
    /// The entry vector only ever grows, except at a revert, which truncates
    /// it. [`note_journal_entries`] reads from this mark and
    /// [`forget_entries_above`] pulls it back down afterwards, so each entry
    /// is read once and a transaction with many frames stays linear.
    entries_seen: usize,
}

thread_local! {
    static RECORDER: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

/// Starts recording this block's sublists, discarding anything already held.
///
/// `excluded` are addresses rskj's parallel path does not write from inside a
/// sublist, and which must therefore not be recorded as sublist writes:
///
/// - **the fee recipient.** rustock credits it once per transaction, from
///   inside the transaction. rskj does not: `TransactionListExecutor` builds
///   every executor with `postponeFeePayment = true`, so under RSKIP-144 the
///   fees are accumulated per sublist and settled afterwards. Recording the
///   per-transaction credit would make every sublist write REMASC's account
///   cell, and *every* split block would collide write-write.
/// - **precompiles maintained at an activation block.** rskj's
///   `maintainPrecompiledContractStorageRoots` runs on the block's own
///   repository before any sublist starts, so those writes belong to no
///   sublist either.
///
/// Excluding an address drops its genuine accesses too -- a transaction that
/// really does send value to REMASC stops being recorded. That is the safe
/// direction: a missed collision leaves the block accepted, which is what
/// this node did before the check existed, whereas an invented one rejects a
/// block the network considers valid.
pub fn start(edges: &[i16], excluded: &[Address], semantics: WriteSemantics) {
    RECORDER.with(|r| {
        *r.borrow_mut() = Some(Recorder {
            tracker: CollisionTracker::new(),
            attribution: Attribution::Sublists(edges.to_vec()),
            semantics,
            excluded: excluded.to_vec(),
            sublist: None,
            entries_seen: 0,
        })
    });
}

/// Adds an address to the exclusion list of an in-progress recording.
pub fn exclude(addr: Address) {
    RECORDER.with(|r| {
        if let Some(rec) = r.borrow_mut().as_mut() {
            if !rec.excluded.contains(&addr) {
                rec.excluded.push(addr);
            }
        }
    });
}

pub fn is_recording() -> bool {
    RECORDER.with(|r| r.borrow().is_some())
}

/// Whether attempted writes are being collected, which is the only reason
/// anything on the hot path needs to look at an opcode or a journal entry.
pub fn records_attempted_writes() -> bool {
    RECORDER.with(|r| {
        r.borrow()
            .as_ref()
            .is_some_and(|rec| rec.semantics == WriteSemantics::Attempted)
    })
}

/// Stops recording and returns what was collected, or `None` if nobody
/// called [`start`].
pub fn finish() -> Option<CollisionTracker> {
    RECORDER.with(|r| r.borrow_mut().take()).map(|r| r.tracker)
}

/// Attributes everything recorded until the next call to the sublist running
/// transaction `index`, and forgets the previous transaction's entry mark.
///
/// Must be called before each transaction. A transaction in the sequential
/// set records nothing.
pub fn begin_transaction(index: usize) {
    RECORDER.with(|r| {
        if let Some(rec) = r.borrow_mut().as_mut() {
            rec.sublist = match &rec.attribution {
                Attribution::Sublists(edges) => sublist_of(index, edges),
                Attribution::PerTransaction => Some(index),
            };
            rec.entries_seen = 0;
            if let Some(id) = rec.sublist {
                rec.tracker.set_sublist(id);
            }
        }
    });
}

/// Start recording with one bucket per transaction, for the miner.
///
/// The partition is what the miner is about to decide, so there is nothing
/// to attribute to yet. [`CollisionTracker::keys`] then reads back what each
/// transaction touched, indexed by its position in the block.
pub fn start_per_transaction(semantics: WriteSemantics) {
    RECORDER.with(|r| {
        *r.borrow_mut() = Some(Recorder {
            tracker: CollisionTracker::new(),
            attribution: Attribution::PerTransaction,
            semantics,
            excluded: Vec::new(),
            sublist: None,
            entries_seen: 0,
        })
    });
}

/// Runs `f` against the recorder when one is attributing to a sublist.
fn with_sublist(f: impl FnOnce(&mut Recorder)) {
    RECORDER.with(|r| {
        let mut slot = r.borrow_mut();
        let Some(rec) = slot.as_mut() else { return };
        if rec.sublist.is_none() {
            return;
        }
        f(rec);
    });
}

/// Records what the current transaction read, and the cells it changed.
///
/// `transaction_id` is the journal's id for this transaction, captured before
/// it ran. revm stamps it onto every account and slot the transaction first
/// touches -- including one merely *read*, because a warm entry left by an
/// earlier transaction is cold again to this one
/// (`JournalInner::load_account_mut_optional`) -- so the stamp is exactly
/// "accessed here", and an entry carrying an older id was not touched.
///
/// **Reads are complete here, including reads inside frames that reverted.**
/// Reverting an entry restores values and flips flags but never removes the
/// account or the slot, and `Account::mark_cold` leaves `transaction_id`
/// alone, so the evidence of the access survives its own rollback. Reads are
/// never netted in either mode: the value a sublist read determined what it
/// computed, including whether the frame reverted at all.
///
/// Writes recorded here are the **net** ones -- `info` against the
/// `original_info` baseline revm resets at each transaction's first touch,
/// and `present_value` against `original_value` per slot. Under
/// [`WriteSemantics::Attempted`] they are a subset of what
/// [`note_journal_entries`] contributes and cost nothing to keep; under
/// [`WriteSemantics::NetChanges`] they are the whole write set.
pub fn record_transaction(transaction_id: usize, state: &EvmState) {
    with_sublist(|rec| {
        for (addr, account) in state {
            if account.transaction_id != transaction_id {
                continue; // untouched by this transaction
            }
            if rec.excluded.contains(addr) {
                continue;
            }

            let account_key = account_key(addr);
            rec.tracker.note_read(&account_key);

            let destroyed = account.status.contains(AccountStatus::SelfDestructed)
                || account.is_selfdestructed_locally();
            // An account that did not exist and has been touched is created
            // by the touch alone, under RSK's frontier account rules. rskj
            // writes the cell through `getAccountStateOrCreateNew`, and
            // RSKIP-144 says so outright: "Sending 0 balance to a
            // non-existent account creates that account. Hence, a key is
            // considered written."
            let materialised = account.is_loaded_as_not_existing() && account.is_touched();
            if destroyed || materialised || account.info != *account.original_info {
                rec.tracker.note_write(&account_key);
            }

            // A contract deployed here writes its code cell and the
            // storage-prefix marker (rskj `setupContract`). Both are plain
            // unitrie cells under the same account. Gated on there being
            // code, which is what `apply_state_changes` gates the same two
            // writes on: a CREATE that returns nothing gets neither cell in
            // rskj either (`TransactionExecutor.create`: "without code nor
            // storage. It doesn't even call setupContract()").
            if account.is_created_locally()
                && account.info.code.as_ref().is_some_and(|c| !c.is_empty())
            {
                rec.tracker.note_write(&code_key(addr));
                rec.tracker.note_write(&storage_prefix_key(addr));
            }

            for (slot_key, cell) in &account.storage {
                if cell.transaction_id != transaction_id {
                    continue;
                }
                let key = storage_key(addr, &B256::from(*slot_key));
                rec.tracker.note_read(&key);
                if cell.present_value != cell.original_value {
                    rec.tracker.note_write(&key);
                }
            }
        }
    });
}

/// Records the writes the current transaction has **attempted** since the
/// last call, from revm's own journal of state changes.
///
/// A no-op under [`WriteSemantics::NetChanges`].
///
/// Call this immediately **before** anything that can revert a checkpoint:
/// revm undoes an entry by popping it, so a write is only visible here while
/// it still stands. Call [`forget_entries_above`] with the new length
/// afterwards.
///
/// `state` is consulted for the one entry whose meaning depends on it:
/// touching an account is a write when the account did not exist and a read
/// when it did (`MutableRepository.addBalance` returns early on a zero value,
/// but `getAccountStateOrCreateNew` has already created an absent account).
pub fn note_journal_entries(entries: &[JournalEntry], state: &EvmState) {
    with_sublist(|rec| {
        if rec.semantics != WriteSemantics::Attempted {
            return;
        }
        let from = rec.entries_seen.min(entries.len());
        for entry in &entries[from..] {
            note_entry(rec, entry, state);
        }
        rec.entries_seen = entries.len();
    });
}

/// Pulls the entry mark down after a revert truncated the journal.
pub fn forget_entries_above(len: usize) {
    RECORDER.with(|r| {
        if let Some(rec) = r.borrow_mut().as_mut() {
            rec.entries_seen = rec.entries_seen.min(len);
        }
    });
}

/// One journal entry's contribution to the attempted-write set.
///
/// Reads are not taken from here. `AccountWarmed` and `StorageWarmed` are the
/// only read-ish entries and [`record_transaction`] already has them, from
/// evidence that survives a rollback -- whereas these entries do not, and the
/// pre-warmed accounts (precompiles, the coinbase) never produce one at all.
fn note_entry(rec: &mut Recorder, entry: &JournalEntry, state: &EvmState) {
    let write_account = |rec: &mut Recorder, addr: &Address| {
        if !rec.excluded.contains(addr) {
            rec.tracker.note_write(&account_key(addr));
        }
    };
    match entry {
        // Every shape of account-cell mutation: rskj funnels all of them
        // through `updateAccountState` -> `internalPut(accountKey)`.
        JournalEntry::BalanceChange { address, .. }
        | JournalEntry::NonceChange { address, .. }
        | JournalEntry::NonceBump { address }
        | JournalEntry::AccountDestroyed { address, .. } => write_account(rec, address),
        JournalEntry::BalanceTransfer { from, to, .. } => {
            write_account(rec, from);
            write_account(rec, to);
        }
        // A real CREATE: rskj's `TransactionExecutor` calls `createAccount`
        // and then `setupContract`, which writes the storage-prefix cell.
        JournalEntry::AccountCreated { address, .. } => {
            write_account(rec, address);
            if !rec.excluded.contains(address) {
                rec.tracker.note_write(&storage_prefix_key(address));
            }
        }
        JournalEntry::CodeChange { address } => {
            if !rec.excluded.contains(address) {
                rec.tracker.note_write(&code_key(address));
            }
        }
        JournalEntry::StorageChanged { address, key, .. } => {
            if !rec.excluded.contains(address) {
                rec.tracker
                    .note_write(&storage_key(address, &B256::from(*key)));
            }
        }
        // Touching an account that exists changes nothing -- rskj's
        // `addBalance` returns before `updateAccountState` on a zero value.
        // Touching one that does not exist creates it.
        JournalEntry::AccountTouched { address } => {
            if state
                .get(address)
                .is_some_and(|a| a.is_loaded_as_not_existing())
            {
                write_account(rec, address);
            }
        }
        // Transient storage is per-transaction, lives in its own trie and is
        // not part of the world state; rskj's `addTransientStorageBytes`
        // writes it without going through the tracked `internalPut`.
        JournalEntry::TransientStorageChange { .. } => {}
        // Reads; see the note above.
        JournalEntry::AccountWarmed { .. } | JournalEntry::StorageWarmed { .. } => {}
    }
}

/// Records a storage cell an `SSTORE` named, whatever value it stored.
///
/// A no-op under [`WriteSemantics::NetChanges`].
///
/// revm journals an `SSTORE` only when the new value differs from the present
/// one (`JournaledAccount::sstore_concrete_error`: `if slot.present_value !=
/// new`), so storing the value a cell already holds leaves no trace for
/// [`note_journal_entries`] to find. rskj has no such check --
/// `Program.storageSave` calls `addStorageRow` unconditionally -- and counts
/// the cell as written. Hooked at the opcode in [`crate::rsk_instructions`].
pub fn note_storage_write_attempt(addr: Address, key: B256) {
    with_sublist(|rec| {
        if rec.semantics != WriteSemantics::Attempted || rec.excluded.contains(&addr) {
            return;
        }
        rec.tracker.note_write(&storage_key(&addr, &key));
    });
}

/// Records the raw-bytes cells the current transaction wrote.
///
/// Bridge and REMASC byte-array state bypasses revm's journal entirely
/// (see [`crate::raw_storage`]), so neither [`record_transaction`] nor
/// [`note_journal_entries`] can see it, and two sublists that both drove the
/// Bridge into writing one of its cells would otherwise look independent.
///
/// Writes only: the read side of that overlay has no hook, which leaves a
/// sublist that merely *reads* Bridge state unrecorded. That is the one
/// remaining place where our sets are narrower than rskj's.
pub fn record_raw_writes<'a>(writes: impl IntoIterator<Item = &'a crate::raw_storage::RawWrite>) {
    with_sublist(|rec| {
        for (addr, cell, _) in writes {
            if rec.excluded.contains(addr) {
                continue;
            }
            rec.tracker.note_write(&storage_key(addr, &B256::from(*cell)));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from rskj's `ReadWrittenKeysTrackerTest`, which is the
    /// authority on what counts as a collision. The names say the rule, so
    /// they are kept close to the originals.
    fn key(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    fn tracker(f: impl Fn(&mut CollisionTracker)) -> CollisionTracker {
        let mut t = CollisionTracker::new();
        f(&mut t);
        t
    }

    #[test]
    fn a_new_tracker_has_no_keys_and_no_collision() {
        let t = CollisionTracker::new();
        assert_eq!(t.sublist_count(), 0);
        assert!(!t.detect_collision());
    }

    #[test]
    fn if_a_sublist_reads_and_writes_the_same_key_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_read(&key(1));
            t.note_write(&key(1));
        });
        assert!(!t.detect_collision(), "a sublist is ordered with respect to itself");
    }

    #[test]
    fn if_a_sublist_writes_the_same_key_twice_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_write(&key(1));
            t.note_write(&key(1));
        });
        assert!(!t.detect_collision());
    }

    #[test]
    fn if_a_sublist_reads_the_same_key_twice_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_read(&key(1));
            t.note_read(&key(1));
        });
        assert!(!t.detect_collision());
    }

    #[test]
    fn if_two_sublists_write_nothing_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_read(&key(1));
            t.set_sublist(1);
            t.note_read(&key(2));
        });
        assert!(!t.detect_collision());
    }

    #[test]
    fn if_two_sublists_read_different_keys_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_read(&key(1));
            t.set_sublist(1);
            t.note_read(&key(2));
        });
        assert!(!t.detect_collision());
    }

    /// The one that is easy to get wrong by symmetry: two sublists reading
    /// the same key is fine. Only a write makes an order observable.
    #[test]
    fn if_two_sublists_read_the_same_key_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_read(&key(1));
            t.set_sublist(1);
            t.note_read(&key(1));
        });
        assert!(!t.detect_collision(), "read against read is not a collision");
    }

    #[test]
    fn if_two_sublists_write_different_keys_there_is_no_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_write(&key(1));
            t.set_sublist(1);
            t.note_write(&key(2));
        });
        assert!(!t.detect_collision());
    }

    #[test]
    fn if_two_sublists_write_the_same_key_there_is_a_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_write(&key(1));
            t.set_sublist(1);
            t.note_write(&key(1));
        });
        let c = t.first_collision().expect("write against write collides");
        assert_eq!(c.kind, CollisionKind::WriteWrite);
        assert_eq!(c.key, key(1));
    }

    #[test]
    fn if_one_sublist_writes_what_another_reads_there_is_a_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_write(&key(1));
            t.set_sublist(1);
            t.note_read(&key(1));
        });
        let c = t.first_collision().expect("write against read collides");
        assert_eq!(c.kind, CollisionKind::WriteRead);
        assert_eq!((c.a, c.b), (0, 1), "the writer is named first");
    }

    /// The same pair in the other order must also collide, and must still
    /// name the writer first. A check written only one way round passes the
    /// test above and misses half the real cases.
    #[test]
    fn if_one_sublist_reads_what_another_writes_there_is_a_collision() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_read(&key(1));
            t.set_sublist(1);
            t.note_write(&key(1));
        });
        let c = t.first_collision().expect("read against write collides");
        assert_eq!(c.kind, CollisionKind::WriteRead);
        assert_eq!((c.a, c.b), (1, 0), "sublist 1 wrote, sublist 0 read");
    }

    /// rskj's `collisionWithLongerSets`: four sublists, ten distinct read
    /// keys each, then ten distinct written keys each -- all disjoint, so
    /// nothing collides however large the sets get. Then one shared write
    /// makes it collide.
    #[test]
    fn disjoint_sets_do_not_collide_however_large() {
        let mut t = CollisionTracker::new();
        let per = 10u8;
        for sublist in 0..4u8 {
            t.set_sublist(sublist as usize);
            for i in 0..per {
                t.note_read(&[sublist, 0, i]);
            }
        }
        assert!(!t.detect_collision(), "distinct reads do not collide");

        for sublist in 0..4u8 {
            t.set_sublist(sublist as usize);
            for i in 0..per {
                t.note_write(&[sublist, 1, i]);
            }
        }
        assert!(!t.detect_collision(), "distinct writes do not collide either");

        // One key written by two sublists is enough.
        t.set_sublist(0);
        t.note_write(&[9, 9, 9]);
        t.set_sublist(3);
        t.note_write(&[9, 9, 9]);
        assert!(t.detect_collision());
    }

    #[test]
    fn clearing_empties_every_sublist() {
        let mut t = tracker(|t| {
            t.set_sublist(0);
            t.note_write(&key(1));
            t.set_sublist(1);
            t.note_write(&key(1));
        });
        assert!(t.detect_collision());
        t.clear();
        assert_eq!(t.sublist_count(), 0);
        assert!(!t.detect_collision());
    }

    // -----------------------------------------------------------------
    // Attribution and recording
    // -----------------------------------------------------------------

    /// With edges `[3, 5]` rskj runs `[0,3)` and `[3,5)` in parallel and
    /// `[5, n)` afterwards -- so index 5 onwards belongs to no sublist the
    /// collision check covers.
    #[test]
    fn transactions_are_attributed_to_the_sublist_that_runs_them() {
        let edges = [3i16, 5];
        let of = |i| sublist_of(i, &edges);
        assert_eq!((of(0), of(1), of(2)), (Some(0), Some(0), Some(0)));
        assert_eq!((of(3), of(4)), (Some(1), Some(1)));
        assert_eq!(of(5), None, "the sequential set is not checked");
        assert_eq!(of(99), None);
    }

    /// A block with no edges declares no split, so nothing is attributed.
    #[test]
    fn a_block_that_does_not_split_has_no_sublists() {
        assert_eq!(sublist_of(0, &[]), None);
    }

    /// The REMASC transaction is the block's last, so it always lands in the
    /// sequential set and never collides with anything.
    #[test]
    fn the_last_transaction_is_always_sequential() {
        assert_eq!(sublist_of(7, &[2i16, 5]), None);
    }

    fn account(tid: usize, balance: u64, original: u64) -> revm::state::Account {
        let mut acct = revm::state::Account {
            info: revm::state::AccountInfo {
                balance: alloy_primitives::U256::from(balance),
                ..Default::default()
            },
            original_info: Box::new(revm::state::AccountInfo {
                balance: alloy_primitives::U256::from(original),
                ..Default::default()
            }),
            transaction_id: tid,
            storage: Default::default(),
            status: AccountStatus::Touched,
        };
        acct.storage.clear();
        acct
    }

    fn state_of(addr: Address, acct: revm::state::Account) -> EvmState {
        let mut st = EvmState::default();
        st.insert(addr, acct);
        st
    }

    const A: Address = Address::new([0xaa; 20]);
    const B: Address = Address::new([0xbb; 20]);

    /// One transaction: attribute it to its sublist, then hand over what the
    /// journal holds afterwards.
    fn tx(index: usize, tid: usize, state: &EvmState) {
        begin_transaction(index);
        record_transaction(tid, state);
    }

    fn raw(index: usize, writes: &[crate::raw_storage::RawWrite]) {
        begin_transaction(index);
        record_raw_writes(writes);
    }

    #[test]
    fn two_sublists_crediting_the_same_account_collide() {
        start(&[1, 2], &[], WriteSemantics::Attempted);
        // Sublist 0's transaction moves A's balance.
        tx(0, 10, &state_of(A, account(10, 7, 5)));
        // Sublist 1's transaction moves it again.
        tx(1, 11, &state_of(A, account(11, 9, 7)));
        let t = finish().expect("recording was started");
        let c = t.first_collision().expect("both sublists write A");
        assert_eq!(c.kind, CollisionKind::WriteWrite);
        assert_eq!(c.key, account_key(&A));
    }

    #[test]
    fn two_sublists_merely_reading_the_same_account_do_not_collide() {
        start(&[1, 2], &[], WriteSemantics::Attempted);
        tx(0, 10, &state_of(A, account(10, 5, 5)));
        tx(1, 11, &state_of(A, account(11, 5, 5)));
        let t = finish().unwrap();
        assert!(!t.detect_collision(), "a balance that did not move is a read");
    }

    #[test]
    fn a_write_in_one_sublist_against_a_read_in_another_collides() {
        start(&[1, 2], &[], WriteSemantics::Attempted);
        tx(0, 10, &state_of(A, account(10, 5, 5))); // read
        tx(1, 11, &state_of(A, account(11, 9, 5))); // write
        let t = finish().unwrap();
        let c = t.first_collision().expect("sublist 1 writes what sublist 0 read");
        assert_eq!((c.kind, c.a, c.b), (CollisionKind::WriteRead, 1, 0));
    }

    #[test]
    fn different_accounts_in_different_sublists_do_not_collide() {
        start(&[1, 2], &[], WriteSemantics::Attempted);
        tx(0, 10, &state_of(A, account(10, 9, 5)));
        tx(1, 11, &state_of(B, account(11, 9, 5)));
        assert!(!finish().unwrap().detect_collision());
    }

    /// An entry left over from an earlier transaction carries that
    /// transaction's id, and must not be attributed to this one -- otherwise
    /// every account the block ever touched would appear in every sublist.
    #[test]
    fn entries_stamped_by_an_earlier_transaction_are_skipped() {
        start(&[1, 2], &[], WriteSemantics::Attempted);
        let mut st = state_of(A, account(10, 9, 5));
        st.insert(B, account(3, 9, 5)); // touched by transaction 3, not 10
        tx(0, 10, &st);
        tx(1, 11, &state_of(B, account(11, 9, 5)));
        assert!(
            !finish().unwrap().detect_collision(),
            "sublist 0 did not touch B in this transaction"
        );
    }

    /// Transactions in the sequential set run after the check, so what they
    /// touch cannot invalidate the block.
    #[test]
    fn the_sequential_set_is_not_recorded() {
        start(&[1, 2], &[], WriteSemantics::Attempted);
        tx(0, 10, &state_of(A, account(10, 9, 5)));
        tx(2, 12, &state_of(A, account(12, 11, 9)));
        assert!(!finish().unwrap().detect_collision());
    }

    /// Why the fee beneficiary is excluded: rustock credits it inside every
    /// transaction, rskj (with `postponeFeePayment`) does not. Without the
    /// exclusion every split block would collide write-write on it.
    #[test]
    fn an_excluded_address_is_not_recorded_at_all() {
        start(&[1, 2], &[A], WriteSemantics::Attempted);
        tx(0, 10, &state_of(A, account(10, 9, 5)));
        tx(1, 11, &state_of(A, account(11, 13, 9)));
        let t = finish().unwrap();
        assert!(!t.detect_collision());
        assert_eq!(t.sublist_count(), 2, "the sublists still exist, just empty");
    }

    #[test]
    fn storage_cells_collide_on_their_own_key() {
        let slot = alloy_primitives::U256::from(42u64);
        let cell = |tid, present: u64, original: u64| revm::state::EvmStorageSlot {
            original_value: alloy_primitives::U256::from(original),
            present_value: alloy_primitives::U256::from(present),
            transaction_id: tid,
            is_cold: false,
        };
        start(&[1, 2], &[], WriteSemantics::Attempted);
        let mut a0 = account(10, 5, 5);
        a0.storage.insert(slot, cell(10, 1, 0)); // written
        tx(0, 10, &state_of(A, a0));
        let mut a1 = account(11, 5, 5);
        a1.storage.insert(slot, cell(11, 0, 0)); // only read
        tx(1, 11, &state_of(A, a1));
        let t = finish().unwrap();
        let c = t.first_collision().expect("one writes the slot the other reads");
        assert_eq!(c.kind, CollisionKind::WriteRead);
        assert_eq!(c.key, storage_key(&A, &B256::from(slot)));
    }

    /// Bridge state does not go through revm's journal, so without this the
    /// two sublists below would look independent.
    #[test]
    fn two_sublists_writing_the_same_bridge_cell_collide() {
        let cell = alloy_primitives::U256::from(7u64);
        let write = |v: u8| vec![(A, cell, Some(vec![v]))];
        start(&[1, 2], &[], WriteSemantics::Attempted);
        raw(0, &write(1));
        raw(1, &write(2));
        let t = finish().unwrap();
        let c = t.first_collision().expect("both sublists write the cell");
        assert_eq!(c.kind, CollisionKind::WriteWrite);
        assert_eq!(c.key, storage_key(&A, &B256::from(cell)));
    }

    #[test]
    fn a_bridge_cell_written_only_by_the_sequential_set_does_not_collide() {
        let cell = alloy_primitives::U256::from(7u64);
        start(&[1, 2], &[], WriteSemantics::Attempted);
        raw(0, &[(A, cell, Some(vec![1]))]);
        raw(2, &[(A, cell, Some(vec![2]))]);
        assert!(!finish().unwrap().detect_collision());
    }

    // -----------------------------------------------------------------
    // Attempted versus net writes
    // -----------------------------------------------------------------

    /// A sublist that wrote a cell and then reverted. The journal entry
    /// existed while the write stood; the post-transaction state shows no
    /// change, because revm has already undone it.
    fn a_reverted_storage_write(slot: alloy_primitives::U256) -> Vec<JournalEntry> {
        vec![JournalEntry::StorageChanged {
            address: A,
            key: slot,
            had_value: alloy_primitives::U256::ZERO,
        }]
    }

    /// The deployed rule. rskj's tracker is monotonic -- `startTracking`
    /// hands the *same* tracker to every nested repository and a rollback
    /// discards only the state cache -- so a write that was undone still
    /// connects the two sublists.
    #[test]
    fn under_the_deployed_rule_a_reverted_write_collides() {
        let slot = alloy_primitives::U256::from(1u64);
        start(&[1, 2], &[], WriteSemantics::Attempted);

        begin_transaction(0);
        note_journal_entries(&a_reverted_storage_write(slot), &EvmState::default());
        record_transaction(10, &state_of(A, account(10, 5, 5)));

        // Sublist 1 only reads the cell.
        begin_transaction(1);
        let mut a1 = account(11, 5, 5);
        a1.storage.insert(
            slot,
            revm::state::EvmStorageSlot {
                original_value: alloy_primitives::U256::ZERO,
                present_value: alloy_primitives::U256::ZERO,
                transaction_id: 11,
                is_cold: false,
            },
        );
        record_transaction(11, &state_of(A, a1));

        let c = finish().unwrap().first_collision().expect("rskj rejects this block");
        assert_eq!(c.kind, CollisionKind::WriteRead);
        assert_eq!(c.key, storage_key(&A, &B256::from(slot)));
    }

    /// The same block under the dormant rule. It is a valid block -- neither
    /// sublist changed the cell, so both read the parent value in parallel
    /// and in sequential execution alike -- which is the whole argument for
    /// the proposal, and the reason this mode is kept working.
    #[test]
    fn under_net_changes_the_same_reverted_write_does_not_collide() {
        let slot = alloy_primitives::U256::from(1u64);
        start(&[1, 2], &[], WriteSemantics::NetChanges);

        begin_transaction(0);
        note_journal_entries(&a_reverted_storage_write(slot), &EvmState::default());
        record_transaction(10, &state_of(A, account(10, 5, 5)));

        begin_transaction(1);
        record_transaction(11, &state_of(A, account(11, 5, 5)));

        assert!(!finish().unwrap().detect_collision());
    }

    /// `write_semantics` must keep returning the deployed rule. If this test
    /// fails, a consensus change has been made; read the note on that
    /// function before changing the assertion.
    #[test]
    fn the_deployed_rule_is_the_one_in_force() {
        for block in [0u64, 1, 7_139_600, 7_690_876, u64::MAX] {
            assert_eq!(write_semantics(block), WriteSemantics::Attempted);
        }
    }

    /// revm journals nothing when an `SSTORE` stores the value already
    /// present; rskj's `addStorageRow` records the cell regardless.
    #[test]
    fn storing_an_unchanged_value_still_counts_as_a_write() {
        let slot = B256::from(alloy_primitives::U256::from(3u64));
        start(&[1, 2], &[], WriteSemantics::Attempted);
        begin_transaction(0);
        note_storage_write_attempt(A, slot);
        begin_transaction(1);
        record_transaction(11, &{
            let mut a = account(11, 5, 5);
            a.storage.insert(
                alloy_primitives::U256::from(3u64),
                revm::state::EvmStorageSlot {
                    original_value: alloy_primitives::U256::ZERO,
                    present_value: alloy_primitives::U256::ZERO,
                    transaction_id: 11,
                    is_cold: false,
                },
            );
            state_of(A, a)
        });
        let c = finish().unwrap().first_collision().expect("the cell was written");
        assert_eq!(c.key, storage_key(&A, &slot));
    }

    #[test]
    fn storing_an_unchanged_value_is_not_a_write_under_net_changes() {
        let slot = B256::from(alloy_primitives::U256::from(3u64));
        start(&[1, 2], &[], WriteSemantics::NetChanges);
        begin_transaction(0);
        note_storage_write_attempt(A, slot);
        begin_transaction(1);
        note_storage_write_attempt(A, slot);
        assert!(!finish().unwrap().detect_collision());
    }

    /// RSKIP-144: "Sending 0 balance to a non-existent account creates that
    /// account. Hence, a key is considered written." rskj's `addBalance`
    /// returns early on zero, but `getAccountStateOrCreateNew` has already
    /// created the absent account.
    #[test]
    fn touching_an_account_that_does_not_exist_is_a_write() {
        let mut absent = account(10, 0, 0);
        absent.status = AccountStatus::LoadedAsNotExisting | AccountStatus::Touched;
        start(&[1, 2], &[], WriteSemantics::Attempted);
        begin_transaction(0);
        let st = state_of(B, absent);
        note_journal_entries(&[JournalEntry::AccountTouched { address: B }], &st);
        begin_transaction(1);
        record_transaction(11, &state_of(B, account(11, 5, 5)));
        let c = finish().unwrap().first_collision().expect("the account was created");
        assert_eq!(c.key, account_key(&B));
    }

    /// Touching one that already exists is not: rskj never reaches
    /// `updateAccountState`.
    #[test]
    fn touching_an_account_that_exists_is_not_a_write() {
        let mut present = account(10, 5, 5);
        present.status = AccountStatus::Touched;
        start(&[1, 2], &[], WriteSemantics::Attempted);
        begin_transaction(0);
        let st = state_of(B, present);
        note_journal_entries(&[JournalEntry::AccountTouched { address: B }], &st);
        begin_transaction(1);
        record_transaction(11, &state_of(B, account(11, 5, 5)));
        assert!(!finish().unwrap().detect_collision());
    }

    /// Entries are read once. A revert truncates the journal, the mark comes
    /// back down with it, and the entries appended afterwards are new.
    #[test]
    fn the_entry_mark_follows_the_journal_back_down_after_a_revert() {
        let st = EvmState::default();
        let entry = |n: u8| JournalEntry::BalanceChange {
            address: Address::new([n; 20]),
            old_balance: alloy_primitives::U256::ZERO,
        };
        start(&[1, 2], &[], WriteSemantics::Attempted);
        begin_transaction(0);
        note_journal_entries(&[entry(1), entry(2), entry(3)], &st);
        // A frame reverted: two entries survive.
        forget_entries_above(2);
        // New work appends a fourth; it must be seen even though the journal
        // is no longer than it was at the last reading.
        note_journal_entries(&[entry(1), entry(2), entry(9)], &st);

        begin_transaction(1);
        record_transaction(11, &state_of(Address::new([9u8; 20]), account(11, 5, 5)));
        let c = finish().unwrap().first_collision().expect("entry 9 was recorded");
        assert_eq!(c.key, account_key(&Address::new([9u8; 20])));
    }

    /// Reads are never netted, in either mode: the value a sublist read
    /// determined what it computed, including whether the frame reverted.
    #[test]
    fn a_read_counts_in_both_modes() {
        for mode in [WriteSemantics::Attempted, WriteSemantics::NetChanges] {
            start(&[1, 2], &[], mode);
            tx(0, 10, &state_of(A, account(10, 5, 5))); // read only
            tx(1, 11, &state_of(A, account(11, 9, 5))); // genuine write
            let c = finish().unwrap().first_collision().expect("write against read");
            assert_eq!((c.kind, c.a, c.b), (CollisionKind::WriteRead, 1, 0), "{mode:?}");
        }
    }

    #[test]
    fn nothing_is_recorded_until_a_block_asks_for_it() {
        assert!(!is_recording());
        tx(0, 10, &state_of(A, account(10, 9, 5)));
        assert!(finish().is_none());
    }

    /// Non-adjacent sublists must be compared too: a loop that only checks
    /// neighbours passes everything above and misses this.
    #[test]
    fn sublists_that_are_not_adjacent_are_still_compared() {
        let t = tracker(|t| {
            t.set_sublist(0);
            t.note_write(&key(7));
            t.set_sublist(1);
            t.note_read(&key(8));
            t.set_sublist(2);
            t.note_write(&key(7));
        });
        let c = t.first_collision().expect("0 and 2 collide");
        assert_eq!((c.a, c.b), (0, 2));
    }
}
