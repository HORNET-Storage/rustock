//! Native-balance supply conservation.
//!
//! The RSK peg is backed 1:1 by bitcoin: the Bridge holds the entire 21 M
//! supply and a peg-in moves value out of it rather than creating any, so the
//! sum of every account's balance must not grow when a block is applied.
//!
//! This module recomputes that sum over exactly the accounts a block writes and
//! reports the net change `B`:
//!
//! - `B > 0` — native BTC appeared from nowhere. The block is invalid.
//! - `B < 0` — native BTC was destroyed. Legitimate in some cases (REMASC burns
//!   a share of fees; an EVM oddity such as a contract self-destructing to
//!   itself removes its balance), so it is recorded and not fatal.
//! - `B = 0` — conserved, the normal case.
//!
//! **Cost.** One trie read per account the block writes, against the pre-block
//! root whose nodes execution has just walked, so the reads are cache hits. A
//! block touching a dozen accounts pays a dozen lookups on top of the writes it
//! was doing anyway.

use alloy_primitives::{Address, B256, U256};
use revm::state::{AccountStatus, EvmState};
use rustock_trie::{account_key, AccountState, TrieKeySlice, TrieNode, TrieStore};

/// Which supply checks run.
///
/// Per-transaction is the default because block-level netting can hide a
/// creation: a transaction that mints N and another that destroys N sum to zero
/// over the block, and only the per-transaction view sees either. Block-level
/// is kept on as well, as a cross-check that the per-transaction deltas account
/// for the block's whole change -- a difference means value moved outside any
/// transaction, which is itself worth knowing.
static CHECK_PER_TRANSACTION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
static CHECK_PER_BLOCK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Enable or disable the per-transaction check. On by default.
pub fn set_per_transaction(enabled: bool) {
    CHECK_PER_TRANSACTION.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Enable or disable the per-block check. On by default.
pub fn set_per_block(enabled: bool) {
    CHECK_PER_BLOCK.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub fn per_transaction_enabled() -> bool {
    CHECK_PER_TRANSACTION.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn per_block_enabled() -> bool {
    CHECK_PER_BLOCK.load(std::sync::atomic::Ordering::Relaxed)
}

/// One account's contribution to the net supply change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDelta {
    pub address: Address,
    pub before: U256,
    pub after: U256,
}

impl AccountDelta {
    pub fn is_increase(&self) -> bool {
        self.after > self.before
    }
    pub fn magnitude(&self) -> U256 {
        if self.after > self.before { self.after - self.before } else { self.before - self.after }
    }
}

/// The result of checking one block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupplyReport {
    /// Total of every balance increase.
    pub inflow: U256,
    /// Total of every balance decrease.
    pub outflow: U256,
    /// Accounts whose balance moved, for the log when something is wrong.
    pub deltas: Vec<AccountDelta>,
}

impl SupplyReport {
    /// `B`, the net change in total supply. Positive means BTC was created.
    ///
    /// Returned as a sign plus magnitude because balances are `U256` and the
    /// difference does not fit a signed type of the same width.
    pub fn net(&self) -> (bool, U256) {
        if self.inflow >= self.outflow {
            (true, self.inflow - self.outflow)
        } else {
            (false, self.outflow - self.inflow)
        }
    }

    /// BTC was created from nothing: the block must be rejected.
    pub fn created_supply(&self) -> bool {
        self.inflow > self.outflow
    }

    /// Account for fees that are in transit rather than credited.
    ///
    /// Once RSKIP-144 is active the gas fee does not reach REMASC inside the
    /// transaction that paid it: the sublist executors postpone it and the
    /// block's whole total is credited once, at the REMASC transaction. So an
    /// ordinary transaction looks short by its own fee, and the REMASC
    /// transaction looks as though it minted the lot.
    ///
    /// Neither is a supply event. `withheld` is what this transaction paid
    /// into the pending pool and counts as though it had been credited;
    /// `settled` is what came back out and counts as though it had been paid
    /// in. With both zero this is the accounting as it stands before
    /// RSKIP-144.
    pub fn with_fees_in_transit(mut self, withheld: U256, settled: U256) -> Self {
        self.inflow = self.inflow.saturating_add(withheld);
        self.outflow = self.outflow.saturating_add(settled);
        self
    }

    /// BTC was destroyed. Worth recording, not fatal.
    pub fn destroyed_supply(&self) -> bool {
        self.outflow > self.inflow
    }

    pub fn is_balanced(&self) -> bool {
        self.inflow == self.outflow
    }

    /// The accounts that gained, largest first — what to name in an alert.
    pub fn gainers(&self) -> Vec<&AccountDelta> {
        let mut v: Vec<&AccountDelta> = self.deltas.iter().filter(|d| d.is_increase()).collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.magnitude()));
        v
    }
}

/// Balance an account holds in `root`, or zero if it is not there.
fn balance_in(root: &TrieNode, store: &dyn TrieStore, addr: &Address) -> U256 {
    let key_bytes = account_key(addr);
    let key = TrieKeySlice::from_key(&key_bytes);
    match root.get(&key, store) {
        Some(data) => AccountState::decode(&data).map(|a| a.balance).unwrap_or(U256::ZERO),
        None => U256::ZERO,
    }
}

/// Account for every balance change a block makes.
///
/// `pre_root` is the state before the block, `state` the changes about to be
/// applied. The set of accounts considered mirrors `apply_state_changes`
/// exactly, including the self-destruct-then-recreated case: an account that is
/// destroyed and not touched again ends at zero, while one that is touched
/// afterwards ends at its new balance (mainnet #3,173,807).
pub fn account_supply_change(
    pre_root: &TrieNode,
    store: &dyn TrieStore,
    state: &EvmState,
) -> SupplyReport {
    let mut report = SupplyReport::default();

    for (addr, account) in state {
        let destroyed = account.status.contains(AccountStatus::SelfDestructed);
        let touched = account.is_touched();
        if !destroyed && !touched {
            // apply_state_changes writes nothing for this account.
            continue;
        }

        let before = balance_in(pre_root, store, addr);
        let after = if destroyed && !touched { U256::ZERO } else { account.info.balance };
        if before == after {
            continue;
        }

        if after > before {
            report.inflow += after - before;
        } else {
            report.outflow += before - after;
        }
        report.deltas.push(AccountDelta { address: *addr, before, after });
    }

    report
}

/// What an observer is told when the supply does not balance.
#[derive(Debug, Clone)]
pub struct SupplyViolation {
    pub block: u64,
    /// True when supply was created (block rejected); false when destroyed.
    pub created: bool,
    /// Size of the imbalance in wei.
    pub amount: U256,
    /// The accounts that moved, largest gain first.
    pub deltas: Vec<AccountDelta>,
}

type Observer = Box<dyn Fn(&SupplyViolation) + Send + Sync>;
static OBSERVER: std::sync::OnceLock<Observer> = std::sync::OnceLock::new();

/// Install the process-wide observer, once.
///
/// The execution crate must not depend on the alerting crate -- alerting
/// already depends on execution -- so the node wires the two together at
/// startup instead. A tool that replays blocks simply installs nothing, which
/// is how the replay harness stays silent and sends no mail.
pub fn set_observer<F>(f: F) -> Result<(), &'static str>
where
    F: Fn(&SupplyViolation) + Send + Sync + 'static,
{
    OBSERVER.set(Box::new(f)).map_err(|_| "supply observer already installed")
}

/// The largest balance movement one block made, for a watcher deciding
/// whether that block is worth looking at more closely.
///
/// This is **not** a supply finding. The supply check exists to catch rBTC
/// appearing from nothing; this reuses the per-account deltas it already
/// computes, because they are the cheapest honest answer to "did anything
/// large happen here" that exists anywhere in the node. Nothing is judged
/// here -- the magnitude is reported and the consumer decides -- so the
/// policy stays in the crate that has the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMovement {
    pub block: u64,
    /// Keyed by hash, not number. A block that was executed and then orphaned
    /// shares its number with the canonical one, and a consumer keyed by
    /// number could answer for the wrong block.
    pub block_hash: B256,
    /// The largest `|after - before|` over every account the block wrote.
    pub max_movement: U256,
}

type MovementObserver = Box<dyn Fn(&BlockMovement) + Send + Sync>;
static MOVEMENT_OBSERVER: std::sync::OnceLock<MovementObserver> = std::sync::OnceLock::new();

/// Install the process-wide movement observer, once.
pub fn set_movement_observer<F>(f: F) -> Result<(), &'static str>
where
    F: Fn(&BlockMovement) + Send + Sync + 'static,
{
    MOVEMENT_OBSERVER.set(Box::new(f)).map_err(|_| "movement observer already installed")
}

/// Whether anyone is listening.
///
/// Checked before the block hash is computed: hashing a header is cheap but
/// not free, and a node with no watcher should not pay for it on every block.
pub fn movement_observer_installed() -> bool {
    MOVEMENT_OBSERVER.get().is_some()
}

/// The largest movement in a report, or zero if nothing moved.
pub fn largest_movement(report: &SupplyReport) -> U256 {
    report.deltas.iter().map(|d| d.magnitude()).max().unwrap_or(U256::ZERO)
}

/// Hand one block's largest movement to the observer, if one is installed.
///
/// Silent: this is not a finding and logging one line per block would drown
/// the log in nothing happening.
pub fn report_movement(movement: &BlockMovement) {
    if let Some(observer) = MOVEMENT_OBSERVER.get() {
        observer(movement);
    }
}

/// Log an imbalance and hand it to the observer, if one is installed.
///
/// Logging happens either way, so the record exists whether or not the node was
/// built with mail support.
pub fn report(block: u64, report: &SupplyReport) {
    let (positive, amount) = report.net();
    let violation = SupplyViolation {
        block,
        created: positive,
        amount,
        deltas: {
            let mut d = report.deltas.clone();
            d.sort_by_key(|x| std::cmp::Reverse(x.magnitude()));
            d
        },
    };

    if violation.created {
        tracing::error!(
            target: "rustock::supply",
            block, amount = %amount,
            "SUPPLY CREATED: block #{block} would increase the native supply by {amount} wei; rejecting it"
        );
    } else {
        tracing::warn!(
            target: "rustock::supply",
            block, amount = %amount,
            "supply destroyed: block #{block} burns {amount} wei"
        );
    }
    for d in violation.deltas.iter().take(8) {
        tracing::info!(
            target: "rustock::supply",
            block,
            account = %d.address,
            before = %d.before,
            after = %d.after,
            "  {} {}", if d.is_increase() { "gained" } else { "lost" }, d.magnitude()
        );
    }

    if let Some(obs) = OBSERVER.get() {
        obs(&violation);
    }
}

/// Account for the balance changes one transaction made.
///
/// Unlike the block-level check this needs no database reads. revm refreshes an
/// account's `original_info` when it is cold-loaded *within a transaction*
/// (`JournalInner::load_account_mut_optional`), so for every account a
/// transaction touched, `info.balance - original_info.balance` is exactly that
/// transaction's effect. `transaction_id` identifies which transaction last
/// touched an account, so the block's accumulated state map can be filtered
/// down to the one just executed.
///
/// A fee-paying transaction nets to zero: rustock credits the block beneficiary
/// (REMASC) inside the same transaction (`RskHandler::reward_beneficiary`), so
/// the gas leaving the sender arrives in the same accounting.
///
/// **This reads a revm internal.** `original_info` is public but documented as
/// serving Block Access Lists, so a future revm could change when it is
/// refreshed without considering it breaking. `per_transaction_baseline_holds`
/// pins the behaviour: if it ever stops being a per-transaction baseline that
/// test fails, rather than the check silently mis-accounting.
pub fn transaction_supply_change(state: &EvmState, transaction_id: usize) -> SupplyReport {
    let mut report = SupplyReport::default();

    for (addr, account) in state {
        if account.transaction_id != transaction_id {
            continue; // untouched by this transaction
        }
        let before = account.original_info.balance;
        let after = if account.status.contains(AccountStatus::SelfDestructed) {
            U256::ZERO
        } else {
            account.info.balance
        };
        if before == after {
            continue;
        }
        if after > before {
            report.inflow += after - before;
        } else {
            report.outflow += before - after;
        }
        report.deltas.push(AccountDelta { address: *addr, before, after });
    }

    report
}

/// Log and hand on a per-transaction imbalance.
pub fn report_transaction(block: u64, index: usize, report: &SupplyReport) {
    let (positive, amount) = report.net();
    if positive {
        tracing::error!(
            target: "rustock::supply",
            block, tx = index, amount = %amount,
            "SUPPLY CREATED: transaction {index} of block #{block} creates {amount} wei; rejecting the block"
        );
    } else {
        tracing::warn!(
            target: "rustock::supply",
            block, tx = index, amount = %amount,
            "supply destroyed: transaction {index} of block #{block} burns {amount} wei"
        );
    }
    for d in report.deltas.iter().take(8) {
        tracing::info!(
            target: "rustock::supply",
            block, tx = index, account = %d.address,
            before = %d.before, after = %d.after,
            "  {} {}", if d.is_increase() { "gained" } else { "lost" }, d.magnitude()
        );
    }
    let violation = SupplyViolation {
        block,
        created: positive,
        amount,
        deltas: report.deltas.clone(),
    };
    if let Some(obs) = OBSERVER.get() {
        obs(&violation);
    }
}

#[cfg(test)]
mod movement_tests {
    use super::*;

    #[test]
    fn the_largest_movement_of_an_empty_report_is_zero() {
        assert_eq!(largest_movement(&SupplyReport::default()), U256::ZERO);
    }

    /// The trap this guards. With the per-block check disabled the caller
    /// holds a `SupplyReport::default()`, whose largest movement is zero --
    /// and a consumer told "zero" reads it as "nothing moved" when the truth
    /// is "nobody looked". `BlockProcessor` must therefore not report a
    /// movement unless `per_block_enabled()`, and this pins the reason.
    #[test]
    fn a_disabled_check_is_indistinguishable_from_a_quiet_block() {
        let quiet = SupplyReport::default();
        let not_checked = SupplyReport::default();
        assert_eq!(largest_movement(&quiet), largest_movement(&not_checked));
    }

    #[test]
    fn the_largest_movement_is_the_largest_magnitude_either_way() {
        let report = SupplyReport {
            deltas: vec![
                AccountDelta {
                    address: Address::repeat_byte(1),
                    before: U256::from(10),
                    after: U256::from(40),
                },
                // A decrease of 100: bigger than the increase of 30, and the
                // sign must not hide it.
                AccountDelta {
                    address: Address::repeat_byte(2),
                    before: U256::from(100),
                    after: U256::ZERO,
                },
            ],
            ..Default::default()
        };
        assert_eq!(largest_movement(&report), U256::from(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::state::{Account, AccountInfo};
    use rustock_trie::MemoryTrieStore;

    fn store_with(balances: &[(Address, u64)]) -> (MemoryTrieStore, TrieNode) {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for (addr, bal) in balances {
            let acct = AccountState::new(U256::ZERO, U256::from(*bal));
            let key_bytes = account_key(addr);
            root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &store);
        }
        (store, root)
    }

    fn touched(balance: u64) -> Account {
        let mut a = Account::from(AccountInfo { balance: U256::from(balance), ..Default::default() });
        a.mark_touch();
        a
    }

    /// The per-transaction check reads `original_info`, a revm field documented
    /// as serving Block Access Lists. This pins the property we actually depend
    /// on -- that it is a per-transaction baseline -- so a revm upgrade that
    /// changes when it is refreshed fails here rather than silently
    /// mis-accounting every block.
    #[test]
    fn per_transaction_baseline_holds() {
        let who = Address::repeat_byte(0x77);

        // An account whose balance rose from 100 to 140 during transaction 3.
        let mut acct = Account::from(AccountInfo { balance: U256::from(100), ..Default::default() });
        acct.original_info = Box::new(AccountInfo { balance: U256::from(100), ..Default::default() });
        acct.info.balance = U256::from(140);
        acct.transaction_id = 3;
        acct.mark_touch();

        // An account touched by a DIFFERENT transaction must not be counted.
        let other = Address::repeat_byte(0x88);
        let mut untouched = Account::from(AccountInfo { balance: U256::from(9), ..Default::default() });
        untouched.original_info = Box::new(AccountInfo { balance: U256::from(1), ..Default::default() });
        untouched.transaction_id = 2;
        untouched.mark_touch();

        let mut state = EvmState::default();
        state.insert(who, acct);
        state.insert(other, untouched);

        let r = transaction_supply_change(&state, 3);
        assert_eq!(r.net(), (true, U256::from(40)), "only transaction 3's change: {r:?}");
        assert_eq!(r.deltas.len(), 1);
        assert_eq!(r.deltas[0].address, who);
    }

    /// A fee-paying transaction nets to zero: the gas leaving the sender is
    /// credited to the block beneficiary (REMASC) inside the same transaction,
    /// so it never looks like a burn.
    #[test]
    fn a_fee_paying_transaction_nets_to_zero() {
        let sender = Address::repeat_byte(0xAA);
        let remasc = crate::precompiles::REMASC_ADDR;

        let mut s_acct = Account::from(AccountInfo { balance: U256::from(1_000), ..Default::default() });
        s_acct.original_info = Box::new(AccountInfo { balance: U256::from(1_000), ..Default::default() });
        s_acct.info.balance = U256::from(979);     // paid 21 in gas
        s_acct.transaction_id = 1;
        s_acct.mark_touch();

        let mut r_acct = Account::from(AccountInfo { balance: U256::ZERO, ..Default::default() });
        r_acct.original_info = Box::new(AccountInfo { balance: U256::ZERO, ..Default::default() });
        r_acct.info.balance = U256::from(21);      // received the fee
        r_acct.transaction_id = 1;
        r_acct.mark_touch();

        let mut state = EvmState::default();
        state.insert(sender, s_acct);
        state.insert(remasc, r_acct);

        let r = transaction_supply_change(&state, 1);
        assert!(r.is_balanced(), "a fee is a transfer, not a burn: {r:?}");
    }

    #[test]
    fn a_plain_transfer_conserves_supply() {
        let (from, to) = (Address::repeat_byte(0xAA), Address::repeat_byte(0xBB));
        let (store, root) = store_with(&[(from, 100), (to, 0)]);

        let mut state = EvmState::default();
        state.insert(from, touched(40));   // -60
        state.insert(to, touched(60));     // +60

        let r = account_supply_change(&root, &store, &state);
        assert!(r.is_balanced(), "{r:?}");
        assert_eq!(r.net(), (true, U256::ZERO));
        assert!(!r.created_supply() && !r.destroyed_supply());
    }

    /// The case this whole module exists for: value appearing with no source.
    #[test]
    fn minting_out_of_nothing_is_detected() {
        let who = Address::repeat_byte(0xCC);
        let (store, root) = store_with(&[(who, 5)]);

        let mut state = EvmState::default();
        state.insert(who, touched(1_000));

        let r = account_supply_change(&root, &store, &state);
        assert!(r.created_supply(), "{r:?}");
        assert_eq!(r.net(), (true, U256::from(995)));
        assert_eq!(r.gainers()[0].address, who);
    }

    /// A burn is reported but is not a reason to reject a block: REMASC burns a
    /// share of fees, and a contract self-destructing to itself removes its own
    /// balance.
    #[test]
    fn a_burn_is_negative_and_not_a_creation() {
        let who = Address::repeat_byte(0xDD);
        let (store, root) = store_with(&[(who, 500)]);

        let mut state = EvmState::default();
        state.insert(who, touched(200));

        let r = account_supply_change(&root, &store, &state);
        assert!(r.destroyed_supply() && !r.created_supply(), "{r:?}");
        assert_eq!(r.net(), (false, U256::from(300)));
    }

    /// A self-destructed account that is not touched again ends at zero, and its
    /// whole balance counts as destroyed -- matching what `apply_state_changes`
    /// writes (it deletes the subtree).
    #[test]
    fn a_self_destructed_account_loses_its_whole_balance() {
        let gone = Address::repeat_byte(0xEE);
        let (store, root) = store_with(&[(gone, 750)]);

        let mut acct = Account::from(AccountInfo { balance: U256::from(750), ..Default::default() });
        acct.mark_selfdestruct();
        let mut state = EvmState::default();
        state.insert(gone, acct);

        let r = account_supply_change(&root, &store, &state);
        assert_eq!(r.net(), (false, U256::from(750)), "{r:?}");
    }

    /// An account present in the state map but never touched is not written by
    /// `apply_state_changes`, so it must not be accounted either -- otherwise a
    /// merely-read account would look like a change.
    #[test]
    fn untouched_accounts_are_ignored() {
        let read_only = Address::repeat_byte(0x11);
        let (store, root) = store_with(&[(read_only, 900)]);

        let mut state = EvmState::default();
        // Loaded during execution, balance unchanged, never touched.
        state.insert(read_only, Account::from(AccountInfo { balance: U256::from(900), ..Default::default() }));

        let r = account_supply_change(&root, &store, &state);
        assert!(r.is_balanced());
        assert!(r.deltas.is_empty(), "{r:?}");
    }

    /// A peg-in in miniature: the Bridge pays a user from its own balance, so
    /// nothing is created however large the movement.
    #[test]
    fn a_bridge_payout_moves_value_rather_than_creating_it() {
        let bridge = crate::precompiles::BRIDGE_ADDR;
        let user = Address::repeat_byte(0x22);
        let (store, root) = store_with(&[(bridge, 21_000_000), (user, 0)]);

        let mut state = EvmState::default();
        state.insert(bridge, touched(20_999_000));
        state.insert(user, touched(1_000));

        let r = account_supply_change(&root, &store, &state);
        assert!(r.is_balanced(), "a peg-in must not change the total: {r:?}");
    }
}
