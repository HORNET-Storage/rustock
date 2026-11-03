//! Large value transfers that involve a smart contract.
//!
//! The peg-out watcher reads receipts, because a peg-out announces itself with
//! an event. A plain value transfer announces nothing: moving rBTC emits no
//! log, writes no receipt field and leaves nothing behind but two changed
//! balances. So this watch cannot be done by reading what the node stored; the
//! block has to be **re-executed with the call tracer attached**, exactly as
//! `trace_block` does, and the call tree read for value movements.
//!
//! That is the whole cost of this feature and it is worth stating plainly:
//! every block with at least one transaction is executed a second time. It
//! still cannot affect consensus — the replay runs against a trie node handed
//! to it, writes nothing, and lives on the watcher's own task — but it is not
//! free the way reading receipts is. See `docs/alerts-contract-value.md`.
//!
//! # What counts as a transfer
//!
//! | source | moves value | reported as |
//! |---|---|---|
//! | the transaction itself | `tx.value`, to `tx.to` or to the contract it creates | `Transaction` |
//! | `CALL` | yes | `Call` |
//! | `CALLCODE` | **no** — the value is apparent; the frame pays itself | — |
//! | `DELEGATECALL` | **no** — value is inherited, nothing moves | — |
//! | `STATICCALL` | **no** — value is always zero | — |
//! | `CREATE` / `CREATE2` | the endowment, to the new contract | `Create` |
//! | `SELFDESTRUCT` | the dying contract's whole balance, to the beneficiary | `SelfDestruct` |
//!
//! The three excluded call kinds are the easiest thing to get wrong here. A
//! `DELEGATECALL` carries a non-zero `value` in the trace — the caller's
//! apparent value, which the callee sees through `CALLVALUE` — and reporting
//! it would invent a transfer that never happened. `the_three_call_kinds_that_move_nothing`
//! pins all three.
//!
//! # Reverted frames moved nothing
//!
//! A frame that reverted or halted is undone, **and so is everything beneath
//! it**. The walk therefore skips a reverted frame's whole subtree rather than
//! just the frame, and a failed transaction contributes nothing at all — not
//! even its own top-level `tx.value`, which reverts with the rest.

use alloy_primitives::{Address, U256};
use rustock_execution::tracer::{CallKind, ProgramTrace, Subtrace, SubtraceKind};

/// Where a transfer came from in the call tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    /// The transaction's own `value`, paid to `to` or to the created contract.
    Transaction,
    /// A `CALL` with a non-zero value.
    Call,
    /// The endowment of a `CREATE` or `CREATE2`.
    Create,
    /// A `SELFDESTRUCT` paying its beneficiary.
    SelfDestruct,
}

impl TransferKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransferKind::Transaction => "transaction",
            TransferKind::Call => "call",
            TransferKind::Create => "create",
            TransferKind::SelfDestruct => "selfdestruct",
        }
    }

    /// Whether the sender is a contract by construction.
    ///
    /// Only running code can originate a `CALL`, a `CREATE` or a
    /// `SELFDESTRUCT`, so for those three the sending side needs no lookup.
    /// A transaction's sender has to be checked, even though on this chain it
    /// is an externally owned account in every case anyone has seen.
    fn sender_is_necessarily_a_contract(self) -> bool {
        !matches!(self, TransferKind::Transaction)
    }

    /// Whether the recipient is a contract by construction.
    fn recipient_is_necessarily_a_contract(self) -> bool {
        matches!(self, TransferKind::Create)
    }
}

/// Which side of the transfer is the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Into a contract from something that is not one.
    In,
    /// Out of a contract to something that is not one.
    Out,
    /// Contract to contract.
    Between,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "into a contract",
            Direction::Out => "out of a contract",
            Direction::Between => "between contracts",
        }
    }
}

/// One movement of rBTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub kind: TransferKind,
    /// Position in the call tree: empty for the transaction's own transfer,
    /// then `0`, `0.1`, `0.1.3` for nested frames. Printed in the alert so an
    /// operator can find the frame with `trace_transaction`.
    pub path: String,
}

impl Transfer {
    /// How this reads in the alert, given what each side turned out to be.
    pub fn direction(&self, from_is_contract: bool, to_is_contract: bool) -> Direction {
        match (from_is_contract, to_is_contract) {
            (true, true) => Direction::Between,
            (true, false) => Direction::Out,
            _ => Direction::In,
        }
    }
}

/// Every value movement one transaction actually made.
///
/// `destination` is `tx.to`, or the address the transaction created. `success`
/// comes from the receipt: a failed transaction moved nothing.
pub fn transfers_in_transaction(
    sender: Address,
    destination: Address,
    tx_value: U256,
    success: bool,
    trace: &ProgramTrace,
) -> Vec<Transfer> {
    if !success {
        return Vec::new();
    }
    let mut out = Vec::new();
    if !tx_value.is_zero() && sender != destination {
        out.push(Transfer {
            from: sender,
            to: destination,
            value: tx_value,
            kind: TransferKind::Transaction,
            path: String::new(),
        });
    }
    walk(&trace.subtraces, "", &mut out);
    out
}

fn walk(subtraces: &[Subtrace], prefix: &str, out: &mut Vec<Transfer>) {
    for (i, sub) in subtraces.iter().enumerate() {
        let path =
            if prefix.is_empty() { i.to_string() } else { format!("{prefix}.{i}") };

        // Undone, along with every frame it opened. Skipping the subtree is
        // the point: a successful transfer inside a frame that later reverted
        // did not happen either.
        if sub.reverted || sub.error.is_some() {
            continue;
        }

        if let Some((from, to)) = moved(sub) {
            // A frame paying itself is not a movement. SELFDESTRUCT to self
            // burns the balance and CALLCODE-shaped self-sends net to zero.
            if from != to {
                out.push(Transfer {
                    from,
                    to,
                    value: sub.value,
                    kind: match sub.kind {
                        SubtraceKind::Call => TransferKind::Call,
                        SubtraceKind::Create => TransferKind::Create,
                        SubtraceKind::Suicide => TransferKind::SelfDestruct,
                    },
                    path: path.clone(),
                });
            }
        }
        walk(&sub.subtraces, &path, out);
    }
}

/// The two addresses a frame moved value between, if it moved any.
fn moved(sub: &Subtrace) -> Option<(Address, Address)> {
    if sub.value.is_zero() {
        return None;
    }
    match sub.kind {
        // Only a plain CALL transfers. CALLCODE and DELEGATECALL run foreign
        // code in the caller's own context and move nothing; STATICCALL cannot
        // carry value at all. DELEGATECALL in particular reports the caller's
        // apparent value here, so treating it as a transfer would invent one.
        SubtraceKind::Call => {
            (sub.call_kind == Some(CallKind::Call)).then_some((sub.caller, sub.owner))
        }
        // `owner` is the new contract; `created_address` says the same thing
        // and is the field documented for it.
        SubtraceKind::Create => Some((sub.caller, sub.created_address.unwrap_or(sub.owner))),
        // `caller` is the dying contract, `owner` the beneficiary.
        SubtraceKind::Suicide => Some((sub.caller, sub.owner)),
    }
}

/// A transfer that breached the threshold, with both sides classified.
#[derive(Debug, Clone)]
pub struct Breach {
    pub transfer: Transfer,
    pub direction: Direction,
}

/// Apply the threshold and the "a contract is involved" rule.
///
/// `is_contract` is called at most twice per transfer and only for transfers
/// already above the threshold, so the trie reads it performs are rare.
pub fn breaches(
    transfers: &[Transfer],
    threshold_wei: U256,
    mut is_contract: impl FnMut(&Address) -> bool,
) -> Vec<Breach> {
    let mut out = Vec::new();
    for t in transfers {
        // Strictly above, matching every other threshold in this crate: a
        // transfer of exactly the configured amount does not alert.
        if t.value <= threshold_wei {
            continue;
        }
        let from_is_contract =
            t.kind.sender_is_necessarily_a_contract() || is_contract(&t.from);
        let to_is_contract =
            t.kind.recipient_is_necessarily_a_contract() || is_contract(&t.to);
        if !from_is_contract && !to_is_contract {
            // Someone sent someone else a lot of money. Real, and not what
            // this watch is for.
            continue;
        }
        out.push(Breach {
            direction: t.direction(from_is_contract, to_is_contract),
            transfer: t.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::repeat_byte(b)
    }

    fn sub(kind: SubtraceKind, call_kind: Option<CallKind>, caller: u8, owner: u8, value: u64) -> Subtrace {
        Subtrace {
            kind,
            call_kind,
            is_create2: false,
            caller: addr(caller),
            owner: addr(owner),
            code_address: None,
            gas: 0,
            gas_used: 0,
            value: U256::from(value),
            input: Vec::new(),
            output: Vec::new(),
            created_address: None,
            error: None,
            reverted: false,
            subtraces: Vec::new(),
        }
    }

    fn call(caller: u8, owner: u8, value: u64) -> Subtrace {
        sub(SubtraceKind::Call, Some(CallKind::Call), caller, owner, value)
    }

    fn trace(subtraces: Vec<Subtrace>) -> ProgramTrace {
        ProgramTrace { subtraces, ..Default::default() }
    }

    #[test]
    fn the_transactions_own_value_is_a_transfer() {
        let t = transfers_in_transaction(addr(1), addr(2), U256::from(5), true, &trace(vec![]));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].kind, TransferKind::Transaction);
        assert_eq!(t[0].path, "");
    }

    #[test]
    fn a_failed_transaction_moved_nothing_not_even_its_own_value() {
        let t = transfers_in_transaction(
            addr(1), addr(2), U256::from(5), false, &trace(vec![call(2, 3, 9)]),
        );
        assert!(t.is_empty(), "a reverted transaction's value reverts with it");
    }

    #[test]
    fn a_zero_value_transaction_contributes_no_top_level_transfer() {
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![]));
        assert!(t.is_empty());
    }

    /// The three call kinds that carry a `value` in the trace but move no
    /// balance. Reporting any of them would invent a transfer.
    #[test]
    fn the_three_call_kinds_that_move_nothing() {
        for kind in [CallKind::CallCode, CallKind::DelegateCall, CallKind::StaticCall] {
            let s = sub(SubtraceKind::Call, Some(kind), 2, 3, 1_000);
            let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![s]));
            assert!(t.is_empty(), "{kind:?} was reported as a transfer");
        }
        // The control: a plain CALL with the same shape IS one.
        let t = transfers_in_transaction(
            addr(1), addr(2), U256::ZERO, true, &trace(vec![call(2, 3, 1_000)]),
        );
        assert_eq!(t.len(), 1, "a plain CALL must still be reported");
    }

    #[test]
    fn a_create_endowment_goes_to_the_created_address() {
        let mut s = sub(SubtraceKind::Create, None, 2, 3, 77);
        s.created_address = Some(addr(9));
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![s]));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].to, addr(9), "the endowment goes to the new contract");
        assert_eq!(t[0].kind, TransferKind::Create);
    }

    #[test]
    fn a_selfdestruct_pays_its_beneficiary() {
        let s = sub(SubtraceKind::Suicide, None, 7, 8, 500);
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![s]));
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].from, t[0].to), (addr(7), addr(8)));
        assert_eq!(t[0].kind, TransferKind::SelfDestruct);
    }

    #[test]
    fn a_frame_paying_itself_is_not_a_movement() {
        let s = sub(SubtraceKind::Suicide, None, 7, 7, 500);
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![s]));
        assert!(t.is_empty(), "selfdestruct to self burns, it does not transfer");
    }

    /// The rule that is easiest to get half right: a reverted frame undoes its
    /// children too, so the walk must skip the subtree and not just the frame.
    #[test]
    fn a_reverted_frame_takes_its_whole_subtree_with_it() {
        let mut outer = call(2, 3, 10);
        outer.reverted = true;
        outer.subtraces = vec![call(3, 4, 999)]; // succeeded, but its parent did not
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![outer]));
        assert!(t.is_empty(), "a transfer under a reverted frame did not happen");
    }

    #[test]
    fn a_halted_frame_is_treated_like_a_reverted_one() {
        let mut s = call(2, 3, 10);
        s.error = Some("Out of gas".into());
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![s]));
        assert!(t.is_empty());
    }

    #[test]
    fn a_sibling_of_a_reverted_frame_still_counts() {
        let mut bad = call(2, 3, 10);
        bad.reverted = true;
        let good = call(2, 4, 20);
        let t = transfers_in_transaction(
            addr(1), addr(2), U256::ZERO, true, &trace(vec![bad, good]),
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].to, addr(4));
    }

    #[test]
    fn nested_frames_are_numbered_by_their_path() {
        let mut outer = call(2, 3, 1);
        let mut middle = call(3, 4, 2);
        middle.subtraces = vec![call(4, 5, 3)];
        outer.subtraces = vec![call(3, 9, 0), middle];
        let t = transfers_in_transaction(addr(1), addr(2), U256::ZERO, true, &trace(vec![outer]));
        let paths: Vec<&str> = t.iter().map(|x| x.path.as_str()).collect();
        // "0.0" carries zero value, so it is not a transfer and not listed.
        assert_eq!(paths, vec!["0", "0.1", "0.1.0"]);
    }

    // -- the threshold and the contract rule ---------------------------------

    fn transfer(kind: TransferKind, from: u8, to: u8, value: u64) -> Transfer {
        Transfer {
            from: addr(from),
            to: addr(to),
            value: U256::from(value),
            kind,
            path: String::new(),
        }
    }

    #[test]
    fn a_transfer_at_the_threshold_does_not_alert_but_above_it_does() {
        let at = transfer(TransferKind::Transaction, 1, 2, 100);
        let above = transfer(TransferKind::Transaction, 1, 2, 101);
        let contract = |a: &Address| *a == addr(2);
        assert!(breaches(&[at], U256::from(100), contract).is_empty());
        assert_eq!(breaches(&[above], U256::from(100), contract).len(), 1);
    }

    #[test]
    fn a_large_transfer_between_two_plain_accounts_is_not_reported() {
        let t = transfer(TransferKind::Transaction, 1, 2, 10_000);
        let b = breaches(&[t], U256::from(100), |_| false);
        assert!(b.is_empty(), "this watch is about contracts, not about large transfers");
    }

    #[test]
    fn a_transaction_paying_a_contract_is_reported_as_going_in() {
        let t = transfer(TransferKind::Transaction, 1, 2, 10_000);
        let b = breaches(&[t], U256::from(100), |a: &Address| *a == addr(2));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].direction, Direction::In);
    }

    /// Every internal transfer has a contract on the sending side, because
    /// only running code can originate one. No lookup should be needed for it.
    #[test]
    fn an_internal_call_needs_no_lookup_to_know_its_sender_is_a_contract() {
        let t = transfer(TransferKind::Call, 7, 8, 10_000);
        let mut asked = Vec::new();
        let b = breaches(&[t], U256::from(100), |a: &Address| {
            asked.push(*a);
            false
        });
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].direction, Direction::Out);
        assert_eq!(asked, vec![addr(8)], "only the recipient should have been looked up");
    }

    #[test]
    fn a_create_needs_no_lookup_at_all() {
        let t = transfer(TransferKind::Create, 7, 8, 10_000);
        let mut asked = 0;
        let b = breaches(&[t], U256::from(100), |_| {
            asked += 1;
            false
        });
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].direction, Direction::Between);
        assert_eq!(asked, 0, "both sides of a CREATE are known structurally");
    }

    #[test]
    fn a_contract_paying_a_contract_reads_as_between() {
        let t = transfer(TransferKind::Call, 7, 8, 10_000);
        let b = breaches(&[t], U256::from(100), |_| true);
        assert_eq!(b[0].direction, Direction::Between);
    }
}
