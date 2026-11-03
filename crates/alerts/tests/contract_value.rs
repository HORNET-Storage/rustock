//! End to end: a real block, really re-executed, and the alerts that fall out.
//!
//! The unit tests in `value.rs` hand the walk a call tree built by hand. That
//! proves the rules but not the mapping onto what the tracer actually emits --
//! which of `caller` and `owner` is the payer, whether a `CALL`'s value
//! survives into the subtrace, whether the post-state really has the code.
//! Those are the parts most likely to be wrong, so this test builds a chain
//! with a contract that forwards money and runs the watcher over it.
//!
//! The fixture is one transaction that does both halves of what this watch is
//! for at once:
//!
//! ```text
//!   sender (EOA) --100 RBTC--> forwarder (contract) --60 RBTC--> recipient (EOA)
//!                   into a contract          out of a contract
//! ```

use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
use rustock_alerts::movement::MovementLog;
use rustock_alerts::{alert::Alert, sink::AlertSink, ContractValueAlerts, PegoutAlerts, Watcher};
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{account_key, code_key, MemoryTrieStore, TrieKeySlice, TrieNode, TrieStore};
use std::sync::{Arc, Mutex};

/// Collects what it is handed, so a test can assert on delivery rather than
/// on an internal.
#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<Alert>>>);

impl AlertSink for Recorder {
    fn deliver(&self, alert: &Alert) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(alert.clone());
        Ok(())
    }
    fn name(&self) -> &'static str {
        "recorder"
    }
}

fn rbtc(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(18u64))
}

fn header(number: u64) -> Header {
    Header {
        parent_hash: B256::ZERO,
        ommers_hash: rustock_execution::processor::compute_ommers_hash(&[]),
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: rustock_core::ordered_tx_trie_root(&[], true),
        receipts_root: B256::ZERO,
        logs_bloom: Bloom::ZERO,
        extension_data: None,
        difficulty: U256::from(1000),
        number,
        gas_limit: U256::from(8_000_000),
        gas_used: 0,
        timestamp: 1_600_000_000 + number,
        extra_data: Bytes::new(),
        paid_fees: U256::ZERO,
        // Zero, so the fixture is about tracing rather than about the
        // minimum-gas-price rule rejecting a zero-priced transaction.
        minimum_gas_price: U256::ZERO,
        uncle_count: 0,
        umm_root: None,
        version_fields: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
    }
}

/// `CALL(gas, recipient, value, 0, 0, 0, 0)` then `STOP`.
///
/// CALL takes its arguments with gas on top, so they are pushed in reverse:
/// retLength, retOffset, argsLength, argsOffset, value, address, gas.
fn forwarding_code(recipient: Address, value: U256) -> Vec<u8> {
    let mut code = vec![
        0x60, 0x00, // PUSH1 0  retLength
        0x60, 0x00, // PUSH1 0  retOffset
        0x60, 0x00, // PUSH1 0  argsLength
        0x60, 0x00, // PUSH1 0  argsOffset
    ];
    code.push(0x7f); // PUSH32 value
    code.extend_from_slice(&value.to_be_bytes::<32>());
    code.push(0x73); // PUSH20 recipient
    code.extend_from_slice(recipient.as_slice());
    code.extend_from_slice(&[
        0x5a, // GAS
        0xf1, // CALL
        0x00, // STOP
    ]);
    code
}

struct Fixture {
    _tmp: tempfile::TempDir,
    store: Arc<BlockStore>,
    trie: Arc<dyn TrieStore>,
    sender: Address,
    forwarder: Address,
    recipient: Address,
    block_hash: B256,
}

/// One executed block, stored the way the node stores one.
fn build(tx_value: U256, forwarded: U256, tx_succeeds: bool) -> Fixture {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

    let key = SigningKey::from_slice(&[31u8; 32]).unwrap();
    let sender = {
        let point = key.verifying_key().to_encoded_point(false);
        Address::from_slice(&Keccak256::digest(&point.as_bytes()[1..])[12..])
    };
    let forwarder = Address::repeat_byte(0xCA);
    let recipient = Address::repeat_byte(0xEE);

    let code = forwarding_code(recipient, forwarded);

    let mut root = TrieNode::empty();
    let acct = rustock_trie::AccountState::new(U256::ZERO, rbtc(1_000));
    root = root.put(&TrieKeySlice::from_key(&account_key(&sender)), &acct.encode(), &*trie_store);
    // The contract is funded in its own right, so that what it pays out does
    // not depend on what the transaction brought in. That separation is the
    // point of `a_contract_paying_out_is_found_even_when_the_transaction_declares_little`:
    // the money a contract moves is not the money the transaction declares.
    let contract = rustock_trie::AccountState::new(U256::from(1), rbtc(1_000));
    root = root.put(
        &TrieKeySlice::from_key(&account_key(&forwarder)),
        &contract.encode(),
        &*trie_store,
    );
    root = root.put(&TrieKeySlice::from_key(&code_key(&forwarder)), &code, &*trie_store);
    root.save(&*trie_store, true);
    let parent_state_root = root.compute_hash(&*trie_store);
    trie_store.put(parent_state_root.as_slice(), &root.to_message(&*trie_store));

    let parent = Header { state_root: parent_state_root, ..header(41) };
    let parent_hash = parent.hash();
    store.put_header(&parent).unwrap();
    store.put_canonical_hash(41, parent_hash).unwrap();

    let mut tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::ZERO,
        gas_limit: U256::from(500_000),
        to: Bytes::copy_from_slice(forwarder.as_slice()),
        value: tx_value,
        input: Bytes::default(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    };
    let chain_id = rustock_execution::RskHardforkConfig::mainnet().chain_id;
    let signing_hash = tx.signing_hash_eip155(chain_id);
    let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        key.sign_prehash(signing_hash.as_slice()).unwrap();
    let sig_bytes = sig.to_bytes();
    tx.r = U256::from_be_slice(&sig_bytes[..32]);
    tx.s = U256::from_be_slice(&sig_bytes[32..]);
    tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
    let tx_hash = tx.tx_hash();

    // The post-state the watcher classifies accounts against. The fixture does
    // not need it to be the true post-state -- nothing here checks a root --
    // only to hold the code, which is what `is_contract` reads.
    let head = Header { parent_hash, state_root: parent_state_root, ..header(42) };
    let block_hash = head.hash();
    store.put_header(&head).unwrap();
    store.put_canonical_hash(42, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_body(block_hash, std::slice::from_ref(&tx), &[]).unwrap();
    store.put_tx_index(tx_hash, block_hash, 0).unwrap();

    let receipt = rustock_core::Receipt {
        post_tx_state: if tx_succeeds { vec![1] } else { Vec::new() },
        cumulative_gas_used: 100_000,
        gas_used: 100_000,
        logs_bloom: Bloom::ZERO,
        logs: Vec::new(),
        status: tx_succeeds,
    };
    store.put_receipts(block_hash, &[receipt]).unwrap();
    store.set_exec_head(block_hash, parent_state_root).unwrap();

    Fixture { _tmp: tmp, store, trie: trie_store, sender, forwarder, recipient, block_hash }
}

fn run_watch(f: &Fixture, threshold_rbtc: f64) -> Vec<Alert> {
    // No movement recorded: the fixture stores an executed block rather than
    // executing one, so the filter sees nothing and falls back to looking,
    // which is the safe answer it is supposed to give.
    run_watch_with(f, threshold_rbtc, 0.1, &MovementLog::default())
}

fn run_watch_with(
    f: &Fixture,
    threshold_rbtc: f64,
    filter_rbtc: f64,
    movements: &MovementLog,
) -> Vec<Alert> {
    let movements = {
        // The log is shared with the watcher by Arc, and the caller needs to
        // have populated it first.
        let shared = Arc::new(MovementLog::default());
        if let Some(v) = movements.largest_movement(&f.block_hash) {
            shared.record(f.block_hash, v);
        }
        shared
    };
    let recorder = Recorder::default();
    let hardfork = rustock_execution::RskHardforkConfig::mainnet();
    let chain_id = hardfork.chain_id;
    let processor =
        Arc::new(rustock_execution::BlockProcessor::new(hardfork, f.store.clone()));

    let mut watcher = Watcher::new(
        f.store.clone(),
        f.trie.clone(),
        // The peg-out watch off: this test is about the other one, and a
        // disabled section must not stop the watcher from running.
        PegoutAlerts { enabled: false, start_block: Some(42), ..Default::default() },
        vec![Box::new(recorder.clone())],
        Vec::new(),
    )
    .unwrap()
    .with_contract_value(
        ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: threshold_rbtc,
            max_catchup_blocks: 128,
            replay_filter_btc: filter_rbtc,
        },
        processor,
        chain_id,
        movements,
    );

    watcher.sweep().expect("the sweep must not fail");
    let out = recorder.0.lock().unwrap().clone();
    out
}

fn transfer_of(alerts: &[Alert], direction: &str) -> Option<Alert> {
    alerts
        .iter()
        .find(|a| matches!(a, Alert::LargeContractTransfer { direction: d, .. } if *d == direction))
        .cloned()
}

/// Both halves of the requirement, in one transaction, through a real
/// execution: money going into a contract and money coming out of it.
#[test]
fn a_payment_into_a_contract_and_the_contracts_own_payment_out_both_alert() {
    let f = build(rbtc(100), rbtc(60), true);
    let alerts = run_watch(&f, 50.0);

    assert_eq!(alerts.len(), 2, "expected one in and one out: {alerts:#?}");

    let into = transfer_of(&alerts, "into a contract").expect("the 100 RBTC payment in");
    match into {
        Alert::LargeContractTransfer { from, to, amount_rbtc, kind, path, .. } => {
            assert_eq!(from, f.sender.to_string());
            assert_eq!(to, f.forwarder.to_string());
            assert_eq!(amount_rbtc, "100.00000000");
            assert_eq!(kind, "transaction");
            assert_eq!(path, "", "the transaction's own transfer has no call-tree position");
        }
        other => panic!("unexpected {other:?}"),
    }

    let out = transfer_of(&alerts, "out of a contract").expect("the 60 RBTC payment out");
    match out {
        Alert::LargeContractTransfer { from, to, amount_rbtc, kind, path, .. } => {
            // The part a hand-built call tree cannot prove: that the tracer's
            // `caller` really is the paying contract and `owner` the payee.
            assert_eq!(from, f.forwarder.to_string(), "the contract is the payer");
            assert_eq!(to, f.recipient.to_string());
            assert_eq!(amount_rbtc, "60.00000000");
            assert_eq!(kind, "call", "an internal CALL, not the transaction");
            assert_eq!(path, "0", "the transaction's first internal frame");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn nothing_alerts_when_both_transfers_are_below_the_threshold() {
    let f = build(rbtc(100), rbtc(60), true);
    let alerts = run_watch(&f, 500.0);
    assert!(alerts.is_empty(), "{alerts:#?}");
}

/// The internal transfer alone, with the transaction's own value too small to
/// report. This is the case that cannot be seen from stored data at all: no
/// log, no receipt field, and a transaction whose own `value` says nothing.
#[test]
fn a_contract_paying_out_is_found_even_when_the_transaction_declares_little() {
    let f = build(rbtc(1), rbtc(60), true);
    let alerts = run_watch(&f, 50.0);
    assert_eq!(alerts.len(), 1, "{alerts:#?}");
    assert!(transfer_of(&alerts, "out of a contract").is_some());
}

#[test]
fn a_failed_transaction_reports_nothing() {
    let f = build(rbtc(100), rbtc(60), false);
    let alerts = run_watch(&f, 50.0);
    assert!(alerts.is_empty(), "a reverted transaction moved nothing: {alerts:#?}");
}

/// The filter doing its job: execution recorded that nothing moved, so the
/// block is never re-executed and the 60 RBTC transfer inside it is never
/// looked for. This is the trade the filter makes, and it has to be visible
/// in a test rather than only in a comment.
#[test]
fn a_block_execution_recorded_as_quiet_is_not_re_examined() {
    let f = build(rbtc(100), rbtc(60), true);
    let quiet = MovementLog::default();
    quiet.record(f.block_hash, U256::from(1_000u64)); // a thousand wei
    let alerts = run_watch_with(&f, 50.0, 0.1, &quiet);
    assert!(alerts.is_empty(), "the filter should have skipped the replay: {alerts:#?}");
}

/// The same block, with execution reporting that something did move. The
/// control for the test above: it proves the silence there came from the
/// filter and not from the fixture being broken.
#[test]
fn the_same_block_is_examined_once_execution_says_something_moved() {
    let f = build(rbtc(100), rbtc(60), true);
    let busy = MovementLog::default();
    busy.record(f.block_hash, rbtc(100));
    let alerts = run_watch_with(&f, 50.0, 0.1, &busy);
    assert_eq!(alerts.len(), 2, "{alerts:#?}");
}

/// A block with no record at all -- imported rather than executed, or
/// executed before the hook existed -- must still be examined. Treating
/// "nobody looked" as "nothing happened" is the one failure that would make
/// this watch quietly useless.
#[test]
fn a_block_with_no_movement_record_is_examined_anyway() {
    let f = build(rbtc(100), rbtc(60), true);
    let alerts = run_watch_with(&f, 50.0, 0.1, &MovementLog::default());
    assert_eq!(alerts.len(), 2, "{alerts:#?}");
}
