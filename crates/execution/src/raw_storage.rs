//! Raw-bytes contract storage, mirroring rskj `Repository.addStorageBytes`.
//!
//! rskj stores precompile byte-array entries (Bridge state, REMASC siblings)
//! as a single variable-length value at one unitrie key. revm storage slots
//! only hold `U256`, so these entries bypass the revm journal entirely:
//! writes accumulate here and are projected into the unitrie by
//! `apply_state_changes`; reads fall through to the parent block's trie.
//!
//! The overlay travels in the revm `Context`'s chain slot (`RskChainExt`), so
//! every bridge/remasc function reaches it through `ctx.chain_mut()`.
//!
//! Commit discipline mirrors rskj's repository tracks:
//! - per precompile call: `commit_call` on method success, `discard_call` on
//!   failure (rskj commits the call's child track only on success);
//! - per frame of contract code: `RskHandler` takes `frame_start` as a frame
//!   opens and calls `revert_frame` if it fails, since rskj rolls back the
//!   track of a call or create that reverts or fails, with what the
//!   precompiles it called committed into it;
//! - per transaction: `begin_tx` / `discard_tx` (a failed tx reverts all of
//!   its calls' committed writes);
//! - but a kept write (`put_kept`) stays through all of these: what rskj
//!   writes straight into the repository a transaction's own call to a
//!   precompile was given, which `TransactionExecutor.go` commits however
//!   the call ended, even after a throw or running out of gas. That call
//!   runs no frame, so no frame takes one back.
use alloy_primitives::{Address, B256, U256};
use rustock_trie::{storage_key, TrieKeySlice, TrieNode, TrieStore};
use std::sync::Arc;

/// One raw storage write: `None` deletes the trie node (rskj
/// `addStorageBytes` with a null/empty value).
pub type RawWrite = (Address, U256, Option<Vec<u8>>);

/// revm `Context` chain-slot extension carrying RSK-specific execution state.
#[derive(Default)]
pub struct RskChainExt {
    pub raw_storage: RawStorage,
    /// Node-wide cache of BTC stored blocks, shared across blocks.
    ///
    /// `RskChainExt` is rebuilt for every block, so this has to be handed in
    /// from outside to survive; `None` disables caching entirely, which is
    /// what tests and one-shot tools use.
    pub btc_block_cache: Option<Arc<crate::bridge::btc_block_cache::BtcBlockCache>>,
    /// What REMASC paid rskj's null address in this block, if it paid it:
    /// the account of a header whose coinbase is empty. The null address
    /// has no bytes, so revm can't hold its account, and the trie is
    /// credited at the block's end instead (`ContractMarkers::null_account`).
    pub null_account: Option<U256>,
    /// The value transfers rskj's Bridge and REMASC each report as a CALL
    /// subtrace (`BridgeSupport.transferTo`, `RemascFeesPayer.transferPayment`),
    /// in order: from, to, value. Trace-only: the executor takes it after every
    /// transaction and hangs it under the transaction's trace when the
    /// transaction called the precompile itself
    /// (`crate::tracer::record_precompile_transfer`).
    pub precompile_transfers: Vec<(Address, Address, U256)>,
    /// rskj's `deletedAccounts`: what the block's earlier transactions
    /// destroyed (`TransactionExecutor.finalization` deletes each as its
    /// transaction ends). From RSKIP125 a creation at one of them fails
    /// (`Program.createContract`). A sequential sublist starts with what the
    /// parallel ones deleted, as rskj's `BlockExecutor` hands it on.
    pub deleted_in_block: std::collections::HashSet<Address>,
    /// The contracts the block's earlier transactions created and left
    /// standing. Each holds rskj's storage-prefix marker (`setupContract`
    /// writes it as the creation begins), whatever code it ended with.
    pub created_in_block: std::collections::HashSet<Address>,
    /// The logs a contract's call to the Bridge wrote before the call failed.
    /// rskj's Bridge writes its logs straight into the list of the program
    /// that called it (`Program.callToPrecompiledAddress` hands it
    /// `result.getLogInfoList()`), and `executePrecompiledAndHandleError`
    /// rolls back the call's track and nothing else, so the logs stay with
    /// the caller. revm drops them with the call's checkpoint; they wait here
    /// for `RskHandler` to write them again once that checkpoint is gone.
    pub kept_logs: Vec<revm::primitives::Log>,
    /// The programs of the transaction that is running and the internal
    /// transactions each has made, for the hash of the one rskj hands the
    /// Bridge when a contract calls it. `RskHandler` follows the programs,
    /// and the precompiles tell it of the calls that reach them.
    pub internal_txs: crate::internal_tx::InternalTxs,
    /// What a local call has taken accounts below zero by ([`Debts`]).
    /// Nothing in a block's run.
    pub debts: Debts,
    /// A local call's gas price where revm's transaction can't hold it, at
    /// 2^128 or more. rskj carries whatever price a call names, and GASPRICE
    /// pushes it whole.
    pub whole_gas_price: Option<U256>,
}

/// What accounts owe: each one's balance in rskj is what the journal holds
/// for it less what it owes here, and is below zero where it owes the more.
///
/// rskj's `Repository.transfer` takes what it moves off the sender whatever
/// the sender holds, and where it is called without a check of the balance a
/// sender that held less is left below zero: a local call's own sender
/// (`TransactionExecutor.call`), and the Bridge as it pays
/// (`BridgeSupport.transferTo`). No balance here can show that, so the
/// account is lifted to what it sends before that moves, and what it was
/// lifted by is kept here (`RskHandler`, `bridge::storage::bridge_transfer`).
/// BALANCE and SELFBALANCE read the account less that
/// (`rsk_instructions::LocalCallWords`), an account that holds less than it
/// owes can call and create nothing (`rsk_handler::unpaid_by_debtor`), and
/// one that destroys itself hands what it still owes to its beneficiary
/// (`rsk_instructions::hand_on_debt`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Debts(Vec<(Address, U256)>);

impl Debts {
    /// What `address` owes, which is nothing unless it is below zero.
    pub fn of(&self, address: Address) -> U256 {
        self.0
            .iter()
            .find(|(debtor, _)| *debtor == address)
            .map_or(U256::ZERO, |(_, owed)| *owed)
    }

    /// `address` owes `amount` more, which is more than nothing.
    pub fn add(&mut self, address: Address, amount: U256) {
        match self.0.iter_mut().find(|(debtor, _)| *debtor == address) {
            Some((_, owed)) => *owed = owed.saturating_add(amount),
            None => self.0.push((address, amount)),
        }
    }

    /// `address` owes nothing from here on. What it owed.
    pub fn take(&mut self, address: Address) -> U256 {
        match self.0.iter().position(|(debtor, _)| *debtor == address) {
            Some(at) => self.0.swap_remove(at).1,
            None => U256::ZERO,
        }
    }
}

/// Raw-bytes storage overlay for the block being executed.
#[derive(Default)]
pub struct RawStorage {
    /// Writes committed by successful precompile calls, in write order.
    committed: Vec<RawWrite>,
    /// Writes of the in-flight precompile call.
    pending: Vec<RawWrite>,
    /// `committed` length when the current transaction started.
    tx_start: usize,
    /// The current transaction's kept writes ([`RawStorage::put_kept`]), in
    /// write order.
    kept: Vec<RawWrite>,
    /// How many of `kept` are in `committed` already.
    kept_committed: usize,
    /// The current transaction's writes that a failed frame took back
    /// ([`RawStorage::revert_frame`]): gone from the state, but written all
    /// the same as far as RSKIP-144 is concerned ([`RawStorage::tx_writes`]).
    reverted: Vec<RawWrite>,
    /// Read-through to the parent block's state.
    reader: Option<(Arc<dyn TrieStore>, TrieNode)>,
}

impl RawStorage {
    /// Install the parent-state read-through (block start).
    pub fn set_reader(&mut self, store: Arc<dyn TrieStore>, root: TrieNode) {
        self.reader = Some((store, root));
    }

    /// Read the raw bytes at `(addr, key)`: pending call writes first, then
    /// writes committed earlier in the block, then the parent trie.
    pub fn get(&self, addr: Address, key: U256) -> Option<Vec<u8>> {
        match self.get_overlay(addr, key) {
            Some(v) => v,
            None => self.get_from_trie(addr, key),
        }
    }

    /// Only this block's own writes: `Some(v)` when the overlay has an entry
    /// for the key (`v` is `None` for a delete), `None` when it does not.
    ///
    /// Split out from [`RawStorage::get`] so a caller that caches trie reads
    /// can keep the two layers in the right order. A cache must never be
    /// consulted ahead of the overlay: the overlay is what this block has
    /// written and has not yet committed, and it always wins.
    pub fn get_overlay(&self, addr: Address, key: U256) -> Option<Option<Vec<u8>>> {
        for (a, k, v) in self.pending.iter().rev().chain(self.committed.iter().rev()) {
            if *a == addr && *k == key {
                return Some(v.clone());
            }
        }
        None
    }

    /// Only the parent block's committed state. This is the read a cache may
    /// stand in front of, because what it returns is fixed for the life of the
    /// entry it reads.
    pub fn get_from_trie(&self, addr: Address, key: U256) -> Option<Vec<u8>> {
        let (store, root) = self.reader.as_ref()?;
        let trie_key = storage_key(&addr, &B256::from(key));
        root.get(&TrieKeySlice::from_key(&trie_key), store.as_ref())
    }

    /// Write raw bytes at `(addr, key)`. Empty bytes delete the entry
    /// (rskj `MutableRepository.addStorageBytes`).
    pub fn put(&mut self, addr: Address, key: U256, value: Option<Vec<u8>>) {
        let value = value.filter(|v| !v.is_empty());
        self.pending.push((addr, key, value));
    }

    /// [`RawStorage::put`] a write that stays however the in-flight call and
    /// its transaction end: neither [`RawStorage::discard_call`] nor
    /// [`RawStorage::discard_tx`] drops it. The call reads it in order with
    /// its other writes.
    pub fn put_kept(&mut self, addr: Address, key: U256, value: Option<Vec<u8>>) {
        let write = (addr, key, value.filter(|v| !v.is_empty()));
        self.pending.push(write.clone());
        self.kept.push(write);
    }

    /// Promote the in-flight call's writes (precompile method succeeded).
    pub fn commit_call(&mut self) {
        self.committed.append(&mut self.pending);
        self.kept_committed = self.kept.len();
    }

    /// Drop the in-flight call's writes (precompile method failed), but its
    /// kept ones.
    pub fn discard_call(&mut self) {
        self.pending.clear();
        self.committed
            .extend_from_slice(&self.kept[self.kept_committed..]);
        self.kept_committed = self.kept.len();
    }

    /// Where the writes made under a frame of contract code that opens now
    /// begin, for [`RawStorage::revert_frame`].
    pub fn frame_start(&self) -> usize {
        self.committed.len()
    }

    /// Take back what the calls under a frame that failed committed since its
    /// [`RawStorage::frame_start`]: rskj rolls back the frame's track, with
    /// what they committed into it. Only the current transaction's writes
    /// can go, whatever `start` says.
    pub fn revert_frame(&mut self, start: usize) {
        let start = start.clamp(self.tx_start, self.committed.len());
        self.reverted.extend(self.committed.drain(start..));
    }

    /// Mark the start of a transaction.
    pub fn begin_tx(&mut self) {
        debug_assert!(self.pending.is_empty());
        self.tx_start = self.committed.len();
        self.kept.clear();
        self.kept_committed = 0;
        self.reverted.clear();
    }

    /// Revert every write of the current transaction (tx failed), but its
    /// kept ones.
    pub fn discard_tx(&mut self) {
        self.committed.truncate(self.tx_start);
        self.pending.clear();
        self.committed.extend_from_slice(&self.kept);
        self.kept_committed = self.kept.len();
        self.reverted.clear();
    }

    /// The writes the current transaction's calls have committed so far, with
    /// those a failed frame took back.
    ///
    /// Valid between [`RawStorage::begin_tx`] and the next one, which is
    /// where RSKIP-144 collision tracking reads it: these are unitrie cells
    /// like any other, and two parallel sublists that both drive the Bridge
    /// into writing one have collided. rskj's tracker counts a key as it's
    /// written, so a frame's failure doesn't take a write back from it.
    /// Already net of [`RawStorage::discard_tx`], so a failed transaction
    /// reports only its kept writes, which are made all the same.
    pub fn tx_writes(&self) -> impl Iterator<Item = &RawWrite> {
        self.committed[self.tx_start..].iter().chain(&self.reverted)
    }

    /// Take all committed writes for trie projection (block end).
    pub fn drain(&mut self) -> Vec<RawWrite> {
        self.pending.clear();
        self.tx_start = 0;
        self.kept.clear();
        self.kept_committed = 0;
        self.reverted.clear();
        std::mem::take(&mut self.committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_trie::MemoryTrieStore;

    const ADDR: Address = Address::new([0xBB; 20]);

    fn key(n: u64) -> U256 {
        U256::from(n)
    }

    #[test]
    fn pending_read_back_and_call_commit() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1, 2, 3]));
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1, 2, 3]));
        raw.commit_call();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1, 2, 3]));
        assert_eq!(raw.drain().len(), 1);
    }

    #[test]
    fn discard_call_drops_pending_only() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.put(ADDR, key(1), Some(vec![2]));
        raw.discard_call();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1]));
    }

    #[test]
    fn discard_tx_reverts_committed_calls() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.begin_tx();
        raw.put(ADDR, key(2), Some(vec![2]));
        raw.commit_call();
        raw.discard_tx();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1]));
        assert_eq!(raw.get(ADDR, key(2)), None);
    }

    #[test]
    fn empty_value_means_delete() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.put(ADDR, key(1), Some(vec![]));
        raw.commit_call();
        assert_eq!(raw.get(ADDR, key(1)), None);
        let writes = raw.drain();
        assert_eq!(writes[1].2, None);
    }

    #[test]
    fn reader_fallthrough_to_trie() {
        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let trie_key = storage_key(&ADDR, &B256::from(key(7)));
        let root = TrieNode::empty().put(
            &TrieKeySlice::from_key(&trie_key),
            &[9, 9, 9],
            store.as_ref(),
        );
        let mut raw = RawStorage::default();
        raw.set_reader(store, root);
        assert_eq!(raw.get(ADDR, key(7)), Some(vec![9, 9, 9]));
        // An overlay delete shadows the trie value.
        raw.put(ADDR, key(7), None);
        assert_eq!(raw.get(ADDR, key(7)), None);
    }

    /// A kept write reads in order with its call's other writes, and stays
    /// when the call and then its transaction are discarded, where an
    /// ordinary write goes.
    #[test]
    fn a_kept_write_stays_however_its_call_and_transaction_end() {
        let mut raw = RawStorage::default();
        raw.begin_tx();
        raw.put_kept(ADDR, key(1), Some(vec![1]));
        raw.put(ADDR, key(1), Some(vec![2]));
        raw.put(ADDR, key(2), Some(vec![3]));
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![2]), "the later write wins");
        raw.discard_call();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1]));
        assert_eq!(raw.get(ADDR, key(2)), None);

        // Once committed, a kept write is like any other: a later write
        // wins, and a later call's failure doesn't bring it back.
        raw.put_kept(ADDR, key(2), Some(vec![4]));
        raw.commit_call();
        raw.put(ADDR, key(2), Some(vec![5]));
        raw.commit_call();
        raw.put(ADDR, key(3), Some(vec![6]));
        raw.discard_call();
        assert_eq!(raw.get(ADDR, key(2)), Some(vec![5]));

        raw.discard_tx();
        let kept = [(ADDR, key(1), Some(vec![1])), (ADDR, key(2), Some(vec![4]))];
        assert_eq!(raw.tx_writes().cloned().collect::<Vec<_>>(), kept);

        // The next transaction keeps its own and nothing of this one's: what
        // a discarded call kept, and what its unfinished call kept, once.
        raw.begin_tx();
        raw.put_kept(ADDR, key(3), Some(vec![7]));
        raw.discard_call();
        raw.put_kept(ADDR, key(4), Some(vec![8]));
        raw.put(ADDR, key(1), Some(vec![9]));
        raw.discard_tx();
        raw.discard_call();
        let mut all = kept.to_vec();
        all.extend([(ADDR, key(3), Some(vec![7])), (ADDR, key(4), Some(vec![8]))]);
        assert_eq!(raw.drain(), all);

        // A drained overlay starts afresh, and keeps a write once however
        // often its call is discarded.
        raw.put_kept(ADDR, key(5), Some(vec![10]));
        raw.discard_call();
        raw.discard_call();
        assert_eq!(raw.drain(), [(ADDR, key(5), Some(vec![10]))]);
    }

    /// A frame that fails takes back what the calls under it committed, a
    /// frame under it that returned included, and nothing from before it.
    /// What it took back stays written for RSKIP-144, and leaves the block.
    #[test]
    fn a_failed_frame_takes_back_what_the_calls_under_it_committed() {
        let mut raw = RawStorage::default();
        raw.begin_tx();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();

        let outer = raw.frame_start();
        raw.put(ADDR, key(1), Some(vec![2]));
        raw.commit_call();
        // A frame under it fails: only its own writes go.
        let inner = raw.frame_start();
        raw.put(ADDR, key(2), Some(vec![3]));
        raw.commit_call();
        raw.revert_frame(inner);
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![2]));
        assert_eq!(raw.get(ADDR, key(2)), None);
        // Another one returns, then the outer frame fails and takes it along.
        raw.frame_start();
        raw.put(ADDR, key(3), Some(vec![4]));
        raw.commit_call();
        raw.revert_frame(outer);
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1]));
        assert_eq!(raw.get(ADDR, key(3)), None);

        let mut written: Vec<_> = raw.tx_writes().map(|(_, cell, _)| *cell).collect();
        written.sort();
        assert_eq!(written, [key(1), key(1), key(2), key(3)]);
        assert_eq!(raw.drain(), [(ADDR, key(1), Some(vec![1]))]);
        assert_eq!(
            raw.tx_writes().count(),
            0,
            "a drained overlay starts afresh"
        );
    }

    /// What a failed frame took back is its transaction's: the next one
    /// doesn't report it, nor does its own once it fails. And a frame takes
    /// back only its own transaction's writes, whatever start it's given.
    #[test]
    fn what_a_failed_frame_took_back_ends_with_its_transaction() {
        let mut raw = RawStorage::default();
        raw.begin_tx();
        let frame = raw.frame_start();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.revert_frame(frame);
        assert_eq!(raw.tx_writes().count(), 1);
        raw.begin_tx();
        assert_eq!(raw.tx_writes().count(), 0);

        let frame = raw.frame_start();
        raw.put(ADDR, key(2), Some(vec![2]));
        raw.commit_call();
        raw.revert_frame(frame);
        raw.discard_tx();
        assert_eq!(raw.tx_writes().count(), 0);

        raw.begin_tx();
        raw.put(ADDR, key(3), Some(vec![3]));
        raw.commit_call();
        raw.begin_tx();
        raw.revert_frame(0);
        raw.revert_frame(usize::MAX);
        assert_eq!(raw.get(ADDR, key(3)), Some(vec![3]));
    }
}
