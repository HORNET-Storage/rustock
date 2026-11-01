//! Tests for merged mining.
//!
//! The load-bearing ones are the round trip (build a template, mine it, submit
//! it, have it accepted) and the replay (a template, put back through
//! `process_block`, validates against every root it filled in). Between them
//! they check the whole path with the same code a peer would use, rather than
//! checking the builder against a restatement of what the builder does.

use alloy_primitives::{Address, B256, Bytes, U256, address, b256};
use bitcoin::hashes::Hash as _;
use rustock_core::config::{ActivationHeights, ChainConfig};
use rustock_core::validation::merged_mining::{compress_coinbase, compute_coinbase_hash};
use rustock_core::validation::{HeaderValidator, MergedMiningRule};
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{MemoryTrieStore, TrieNode, TrieStore};
use std::sync::Arc;

use super::*;
use crate::hardfork::RskHardforkConfig;
use crate::processor::BlockProcessor;

// ── fixtures ──────────────────────────────────────────────────────────

/// Activation heights with merged mining live from block 0 and UMM never, so
/// tests can work at low block numbers. `papyrus200` is raised out of reach
/// deliberately: a separate test covers the `ummRoot` a real chain carries.
fn test_chain_config() -> Arc<ChainConfig> {
    Arc::new(ChainConfig {
        chain_id: 33,
        network_id: 7771,
        duration_limit: 10,
        difficulty_divisor: U256::from(2048),
        min_difficulty: U256::from(1),
        max_future_block_time: 0,
        gas_limit_bound_divisor: 1024,
        min_gas_limit: 1,
        max_gas_limit: 10_000_000,
        // regtest's, as rskj's own partitioner tests use.
        min_sequential_set_gas_limit: 6_800_000,
        activation_heights: ActivationHeights {
            orchid: 0,
            wasabi100: 0,
            papyrus200: u64::MAX,
            iris300: 0,
            fingerroot500: 0,
            // Active from genesis: this fixture mines blocks back to back,
            // so the ten-minute drop would only add noise.
            rskip97: Some(0),
        },
    })
}

fn header_at(number: u64, parent_hash: B256, state_root: B256) -> Header {
    Header {
        parent_hash,
        ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
        beneficiary: Address::repeat_byte(0x11),
        state_root,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        // Small enough that every Bitcoin hash clears the target, so the tests
        // never have to search for a nonce.
        difficulty: U256::from(2),
        number,
        gas_limit: U256::from(6_800_000),
        gas_used: 0,
        timestamp: 1_700_000_000 + number,
        extra_data: Bytes::new(),
        paid_fees: U256::ZERO,
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

/// A node with a short chain already in its store, ready to mine on top.
struct MiningFixture {
    server: MinerServer,
    store: Arc<BlockStore>,
    trie_store: Arc<dyn TrieStore>,
    chain_config: Arc<ChainConfig>,
    parent: Header,
    _dir: tempfile::TempDir,
}

impl MiningFixture {
    /// The template the miner would hand out right now.
    fn build(&self) -> Result<BlockTemplate, TemplateError> {
        self.build_on(&self.parent)
    }

    /// A template on an arbitrary parent, for the cases that need a parent the
    /// store does not have (a timestamp far in the future, say).
    fn build_on(&self, parent: &Header) -> Result<BlockTemplate, TemplateError> {
        self.server
            .builder_for_test()
            .build(std::slice::from_ref(parent), Vec::new(), &NoPendingTransactions)
    }
}

/// Builds a chain of `height` empty headers, all canonical, and a miner on
/// top of it.
///
/// The chain is not decorative: REMASC reaches back `maturity` blocks for the
/// block whose fees it distributes, so a template built over an empty store
/// fails inside execution with an error that says nothing about mining.
fn fixture(height: u64) -> MiningFixture {
    fixture_with(height, test_chain_config(), U256::from(2))
}

fn fixture_with_papyrus_at(papyrus200: u64, height: u64) -> MiningFixture {
    let mut config = (*test_chain_config()).clone();
    config.activation_heights.papyrus200 = papyrus200;
    fixture_with(height, Arc::new(config), U256::from(2))
}

fn fixture_with_wasabi_at(wasabi100: u64, height: u64) -> MiningFixture {
    let mut config = (*test_chain_config()).clone();
    config.activation_heights.wasabi100 = wasabi100;
    fixture_with(height, Arc::new(config), U256::from(2))
}

/// A chain whose difficulty is so high that no Bitcoin block clears the
/// target, for checking that the node refuses a solution that misses.
fn fixture_with_difficulty(difficulty: U256, height: u64) -> MiningFixture {
    let mut config = (*test_chain_config()).clone();
    // The difficulty rule clamps up to the minimum, which is how the built
    // header ends up carrying it.
    config.min_difficulty = difficulty;
    fixture_with(height, Arc::new(config), difficulty)
}

fn fixture_with(
    height: u64,
    chain_config: Arc<ChainConfig>,
    parent_difficulty: U256,
) -> MiningFixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
    let empty_root = TrieNode::empty().compute_hash(trie_store.as_ref());

    let mut parent_hash = B256::ZERO;
    let mut parent = header_at(0, parent_hash, empty_root);
    for number in 0..=height {
        let mut header = header_at(number, parent_hash, empty_root);
        header.difficulty = parent_difficulty;
        let hash = header.hash();
        store.put_header_with_hash(hash, &header).unwrap();
        store.put_canonical_hash(number, hash).unwrap();
        // Not `difficulty * height`: the difficulty-refusal fixture uses
        // U256::MAX, and multiplying that overflows.
        store
            .put_total_difficulty(hash, U256::from(number + 1))
            .unwrap();
        parent_hash = hash;
        parent = header;
    }
    store.set_head(parent_hash).unwrap();
    store.set_exec_head(parent_hash, empty_root).unwrap();

    let hardfork_cfg = RskHardforkConfig::all_active(33);
    let builder = BlockTemplateBuilder::new(
        Arc::new(BlockProcessor::new(hardfork_cfg.clone(), store.clone())),
        trie_store.clone(),
        chain_config.clone(),
        hardfork_cfg,
        MiningConfig {
            coinbase_address: address!("00000000000000000000000000000000c0117b45"),
            ..Default::default()
        },
    );
    let chain = Arc::new(StoreChainAccess {
        on_committed: None,
        store: store.clone(),
        trie_store: trie_store.clone(),
    });
    let server = MinerServer::new(
        builder,
        chain,
        Arc::new(NoPendingTransactions),
        chain_config.clone(),
    );

    MiningFixture { server, store, trie_store, chain_config, parent, _dir: dir }
}

/// A Bitcoin block committing to `work_hash` whose hash clears `target` --
/// which is to say, actually mined.
///
/// The search is the point: RSK compares the Bitcoin block hash, read
/// little-endian, against `U256::MAX / difficulty`, so a block built with a
/// fixed nonce clears the target only by luck. At these difficulties a handful
/// of nonces suffice, which is what makes the round trip a unit test.
fn solve(work: &MinerWork) -> bitcoin::Block {
    let coinbase = coinbase::build_coinbase(&work.block_hash_for_merged_mining, 0xDEAD_BEEF);
    for nonce in 0..100_000u32 {
        let block = coinbase::build_bitcoin_block(coinbase.clone(), nonce);
        let hash = block.header.block_hash();
        if U256::from_le_slice(hash.as_byte_array()) <= work.target {
            return block;
        }
    }
    panic!("no nonce cleared target {}", work.target);
}

/// A Bitcoin block committing to `work_hash` that was never actually mined:
/// correctly formed in every respect except the proof of work.
fn unmined(work_hash: B256) -> bitcoin::Block {
    coinbase::build_bitcoin_block(coinbase::build_coinbase(&work_hash, 0xDEAD_BEEF), 0)
}

// ── the REMASC transaction ────────────────────────────────────────────

/// Groundtruth: the REMASC transaction of RSK mainnet block #9,257,552
/// (`0xafbe23...`, from public-node.rsk.co).
///
/// Every zero field in it is encoded the way rskj encodes it and not the way
/// canonical RLP would: the gas price and gas limit are a literal `0x00` byte,
/// the value is `0x80`. Re-encode it canonically and the transaction hashes
/// differently, which moves the transactions root, which fails the block --
/// with an error about roots rather than about encoding.
#[test]
fn remasc_transaction_matches_mainnet() {
    let tx = remasc_transaction(9_257_552);

    assert_eq!(
        alloy_primitives::hex::encode(tx.rlp_for_trie()),
        "e0838d424f00009400000000000000000000000000000000010000088080808080"
    );
    assert_eq!(
        tx.tx_hash(),
        b256!("afbe2397d46addffea824f9964498e7f3eec79c9c540811bcc8b825224af8889")
    );
    // The nonce is the *parent's* height, not the block's.
    assert_eq!(tx.nonce, 9_257_551);
}

#[test]
fn remasc_transaction_of_block_one_has_an_empty_nonce() {
    let tx = remasc_transaction(1);
    assert_eq!(tx.nonce, 0);
    // rskj writes a zero nonce as the empty string, not as `0x00`.
    assert_eq!(tx.rlp_for_trie()[1], 0x80);
}

/// It has to be recognisable to the executor, which detects it by shape
/// rather than by position.
#[test]
fn remasc_transaction_is_recognised_as_remasc() {
    let tx = remasc_transaction(4_242);
    assert_eq!(tx.to.as_ref(), crate::precompiles::REMASC_ADDR.as_slice());
    assert!(tx.gas_limit.is_zero());
    assert_eq!(tx.v, 0);
    assert!(tx.r.is_zero() && tx.s.is_zero());
}

// ── merkle proofs ─────────────────────────────────────────────────────

/// A proof is only correct if it folds back to the root the Bitcoin header
/// carries, so that is what is checked -- for every transaction count from one
/// to sixteen, which covers both the odd levels (where Bitcoin duplicates the
/// last hash) and the even ones.
#[test]
fn merkle_proofs_fold_back_to_the_root() {
    for count in 1..=16usize {
        let txids: Vec<[u8; 32]> = (0..count).map(|i| [i as u8 + 1; 32]).collect();
        let proof = merkle::proof_from_txids(&txids).unwrap();
        assert_eq!(proof.len() % 32, 0);

        let root = merkle::root_from_proof(&txids[0], &proof);
        assert_eq!(root, reference_merkle_root(&txids), "{count} transactions");
    }
}

/// Bitcoin's merkle root, computed the long way round for comparison.
fn reference_merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    use rustock_core::validation::merged_mining::combine_left_right;
    let mut level = txids.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(combine_left_right(&pair[0], right));
        }
        level = next;
    }
    level[0]
}

#[test]
fn a_single_transaction_block_needs_no_proof() {
    let proof = merkle::proof_from_txids(&[[7u8; 32]]).unwrap();
    assert!(proof.is_empty());
    assert_eq!(merkle::root_from_proof(&[7u8; 32], &proof), [7u8; 32]);
}

#[test]
fn a_block_with_no_transactions_has_no_coinbase() {
    assert_eq!(
        merkle::proof_from_txids(&[]),
        Err(merkle::MerkleProofError::NoTransactions)
    );
}

/// A partial-merkle submission hands over the branch including the coinbase;
/// the verifier starts from a coinbase hash it computes itself, so folding the
/// supplied one in as well would double-count it.
#[test]
fn a_partial_merkle_proof_drops_the_coinbase() {
    let hashes = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let proof = merkle::proof_from_merkle_hashes(&hashes).unwrap();
    assert_eq!(proof, [[2u8; 32], [3u8; 32]].concat());
}

/// The wire carries these hashes in consensus (little-endian) order, and
/// everything past this point works in display order.
#[test]
fn wire_hashes_are_reversed_on_the_way_in() {
    let mut wire = [0u8; 32];
    wire[0] = 0xAA;
    let hex = alloy_primitives::hex::encode(wire);
    let parsed = merkle::parse_wire_hashes(&format!("{hex} 0x{hex}")).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0][31], 0xAA);
    assert_eq!(parsed[0], parsed[1]);
}

#[test]
fn a_malformed_wire_hash_is_rejected() {
    assert!(merkle::parse_wire_hashes("abcd").is_err());
    assert!(merkle::parse_wire_hashes("zz").is_err());
}

// ── fork-detection data ───────────────────────────────────────────────

/// Below 449 mainchain blocks there is nothing to commit to, and rskj's own
/// rule rejects a header that carries fork-detection data anyway.
#[test]
fn fork_detection_data_is_empty_on_a_short_chain() {
    let chain: Vec<Header> = (0..448)
        .map(|i| header_at(448 - i, B256::ZERO, B256::ZERO))
        .collect();
    assert!(fork_detection::calculate(&chain).is_empty());
}

#[test]
fn fork_detection_data_commits_to_height_and_uncles() {
    let mut chain: Vec<Header> = (0..fork_detection::REQUIRED_MAINCHAIN_BLOCKS)
        .map(|i| header_at(5_000 - i as u64, B256::ZERO, B256::ZERO))
        .collect();
    // Uncles are summed over the last 32 blocks only.
    for header in chain.iter_mut().take(32) {
        header.uncle_count = 1;
    }
    chain[32].uncle_count = 99;

    let data = fork_detection::calculate(&chain);
    assert_eq!(data.len(), fork_detection::FORK_DETECTION_DATA_LENGTH);
    assert_eq!(data[7], 32, "uncles outside the 32-block window must not count");
    assert_eq!(&data[8..12], &5_001u32.to_be_bytes(), "the height being mined");
}

/// The uncle count is one byte, and a chain busy enough to overflow it must
/// saturate rather than wrap -- a wrapped count would read as a *lower* uncle
/// rate, which is the opposite of what happened.
#[test]
fn fork_detection_uncle_count_saturates() {
    let chain: Vec<Header> = (0..fork_detection::REQUIRED_MAINCHAIN_BLOCKS)
        .map(|i| {
            let mut h = header_at(5_000 - i as u64, B256::ZERO, B256::ZERO);
            h.uncle_count = 10;
            h
        })
        .collect();
    assert_eq!(fork_detection::calculate(&chain)[7], 255);
}

/// The overlay replaces the last 12 bytes and nothing else: the first 20 are
/// the only part of the hash a verifier ever compares.
#[test]
fn fork_detection_data_overlays_only_the_tail_of_the_hash() {
    let base = B256::repeat_byte(0xAA);
    let overlaid = fork_detection::apply_to_hash(base, &[0xBB; 12]);
    assert_eq!(&overlaid[..20], &[0xAA; 20]);
    assert_eq!(&overlaid[20..], &[0xBB; 12]);

    // Empty data -- a chain too short to have any -- leaves the hash whole,
    // which is also the pre-wasabi100 form.
    assert_eq!(fork_detection::apply_to_hash(base, &[]), base);
}

// ── the template builder ──────────────────────────────────────────────

/// The strongest single test available: everything the builder filled in --
/// transactions root, ommers hash, gas used, paid fees, state root, receipts
/// root, logs bloom -- put back through the validating path that a peer
/// receiving this block would run.
///
/// It is worth more than checking each field against a restatement of how the
/// builder computes it, because it fails for the one reason that matters: the
/// block would not be accepted.
#[test]
fn a_template_validates_against_the_processing_path() {
    let fx = fixture(20);
    let template = fx.build().unwrap();

    assert_eq!(template.block.header.number, fx.parent.number + 1);
    assert_eq!(template.block.header.parent_hash, fx.parent.hash());
    // REMASC and nothing else: the pool is empty.
    assert_eq!(template.block.transactions.len(), 1);
    assert_eq!(
        template.block.transactions[0].to.as_ref(),
        crate::precompiles::REMASC_ADDR.as_slice()
    );

    let processor = BlockProcessor::new(RskHardforkConfig::all_active(33), fx.store.clone());
    let parent_state = TrieNode::empty();
    processor
        .process_block(&template.block, &parent_state, fx.trie_store.clone())
        .expect("a freshly built template must satisfy every root it filled in");
}

/// A template without the REMASC transaction executes to a different state
/// root. Worth pinning because the failure gives no hint of its cause: the
/// executor does not append REMASC, so the block simply computes different
/// state and the error names a root.
#[test]
fn a_template_without_remasc_would_not_validate() {
    let fx = fixture(20);
    let template = fx.build().unwrap();

    let mut stripped = template.block.clone();
    stripped.transactions.clear();

    let processor = BlockProcessor::new(RskHardforkConfig::all_active(33), fx.store.clone());
    let err = processor
        .process_block(&stripped, &TrieNode::empty(), fx.trie_store.clone())
        .expect_err("a block missing REMASC must not validate");
    assert!(
        matches!(err, crate::processor::ProcessError::TransactionsRootMismatch { .. }),
        "unexpected error: {err}"
    );
}

/// The open question from the handover: `paid_fees` is filled in after
/// execution, and REMASC reads a `paid_fees` during execution -- but from the
/// *matured* block it fetches from storage, not from the block being built.
/// If that were wrong, the builder would need a two-pass fixed point.
///
/// Re-executing with the field filled in and comparing the roots settles it.
#[test]
fn filling_paid_fees_does_not_change_what_the_block_executes_to() {
    let fx = fixture(20);
    let template = fx.build().unwrap();

    let processor = BlockProcessor::new(RskHardforkConfig::all_active(33), fx.store.clone());
    let first = processor
        .execute_block(&template.block, &TrieNode::empty(), fx.trie_store.clone())
        .unwrap();

    // Execute again from a header whose paid_fees and gas_used are zeroed, the
    // way they were when the template was first executed.
    let mut zeroed = template.block.clone();
    zeroed.header.paid_fees = U256::ZERO;
    zeroed.header.gas_used = 0;
    zeroed.header.state_root = B256::ZERO;
    zeroed.header.receipts_root = B256::ZERO;
    let second = processor
        .execute_block(&zeroed, &TrieNode::empty(), fx.trie_store.clone())
        .unwrap();

    assert_eq!(first.state_root_hash, second.state_root_hash);
    assert_eq!(first.receipts_root, second.receipts_root);
    assert_eq!(first.paid_fees, second.paid_fees);
}

/// RSKIP92 keeps the merkle proof and coinbase out of the hashed prefix so a
/// solution can be attached to a block that was already committed to. If
/// filling them moved the merged-mining hash, every submitted proof would be
/// against a hash the finished header no longer has.
#[test]
fn filling_the_mining_fields_does_not_move_the_merged_mining_hash() {
    let fx = fixture(20);
    let template = fx.build().unwrap();
    let before = template.block.header.hash_for_merged_mining();

    let mut header = template.block.header.clone();
    header.bitcoin_merged_mining_header = Some(Bytes::from(vec![0xAA; 80]));
    header.bitcoin_merged_mining_merkle_proof = Some(Bytes::from(vec![0xBB; 64]));
    header.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::from(vec![0xCC; 100]));

    assert_eq!(before, header.hash_for_merged_mining());
}

/// From papyrus200 rskj puts an empty `ummRoot` in every header it builds.
/// Its presence changes both hashes, so a miner that decided by activation
/// height differently from its peers produces blocks nobody accepts.
#[test]
fn umm_root_appears_once_papyrus_is_active() {
    let fx = fixture(20);
    assert!(fx.build().unwrap().block.header.umm_root.is_none());

    let fx = fixture_with_papyrus_at(0, 20);
    assert_eq!(fx.build().unwrap().block.header.umm_root, Some(Bytes::new()));
}

/// Inheriting the parent's gas limit and minimum gas price is always valid --
/// both rules are bounds around the parent's value, and the parent's own value
/// is in range. This is what the builder does when no target is configured.
#[test]
fn a_template_inherits_gas_limit_and_minimum_gas_price() {
    let fx = fixture(20);
    let header = fx.build().unwrap().block.header;
    assert_eq!(header.gas_limit, fx.parent.gas_limit);
    assert_eq!(header.minimum_gas_price, fx.parent.minimum_gas_price);
}

#[test]
fn a_template_is_never_timestamped_at_or_before_its_parent() {
    // The parent is dated far in the future, so wall-clock time cannot satisfy
    // the rule on its own.
    let mut fx = fixture(20);
    fx.parent.timestamp = u64::MAX / 2;
    let header = fx.build_on(&fx.parent).unwrap().block.header;
    assert!(header.timestamp > fx.parent.timestamp);
}

// ── transaction selection ─────────────────────────────────────────────

#[test]
fn transactions_are_ordered_by_price_but_never_out_of_nonce_order() {
    let rich = Address::repeat_byte(0xA1);
    let poor = Address::repeat_byte(0xB2);

    // The rich sender's cheap transaction comes first by nonce; ordering
    // purely by price would put its expensive nonce-1 ahead of nonce-0 and
    // strand both.
    let pending = vec![
        pending_tx(rich, 1, 1_000, 1),
        pending_tx(rich, 0, 10, 2),
        pending_tx(poor, 0, 500, 3),
    ];

    let ordered = super::template::order_by_price_sender_and_nonce_for_test(pending);
    let keys: Vec<(Address, u64)> = ordered.iter().map(|p| (p.sender, p.tx.nonce)).collect();
    assert_eq!(keys, vec![(poor, 0), (rich, 0), (rich, 1)]);
}

#[test]
fn transaction_ordering_is_stable_for_equal_prices() {
    let a = Address::repeat_byte(0xA1);
    let b = Address::repeat_byte(0xB2);
    let pending = vec![pending_tx(a, 0, 100, 1), pending_tx(b, 0, 100, 2)];

    let first = super::template::order_by_price_sender_and_nonce_for_test(pending.clone());
    // Reversed input, same output: a HashMap hands senders back in whatever
    // order it likes, and two rebuilds of the same template must agree.
    let mut reversed = pending;
    reversed.reverse();
    let second = super::template::order_by_price_sender_and_nonce_for_test(reversed);

    let key = |v: &Vec<PendingTransaction>| -> Vec<B256> { v.iter().map(|p| p.hash).collect() };
    assert_eq!(key(&first), key(&second));
}

fn pending_tx(sender: Address, nonce: u64, gas_price: u64, seed: u8) -> PendingTransaction {
    PendingTransaction {
        tx: rustock_core::Transaction {
            nonce,
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0u8; 20]),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 27,
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        },
        sender,
        hash: B256::repeat_byte(seed),
    }
}

// ── work and submission ───────────────────────────────────────────────

/// The round trip, end to end: ask for work, build the Bitcoin block a miner
/// would build, submit it, and have the node accept the result as its own new
/// head -- with the completed header passing the very rule it would apply to a
/// block arriving from a peer.
#[test]
fn a_solution_completes_a_block_and_is_imported() {
    let fx = fixture(20);
    let work = fx.server.get_work().unwrap();
    assert_eq!(work.parent_block_hash, fx.parent.hash());
    assert!(work.notify, "the first work on a new parent is always a notify");

    let btc_block = solve(&work);
    let info = fx
        .server
        .submit_bitcoin_block(&bitcoin::consensus::serialize(&btc_block))
        .expect("a correctly tagged solution must be accepted");

    assert_eq!(info.block_imported_result, ImportResult::ImportedBest);
    assert_eq!(info.block_included_height, fx.parent.number + 1);

    let stored = fx.store.block(info.block_hash).unwrap().expect("block stored");
    assert_eq!(stored.header.number, fx.parent.number + 1);

    // The three fields a solution supplies are all there...
    assert!(stored.header.bitcoin_merged_mining_header.is_some());
    assert!(stored.header.bitcoin_merged_mining_coinbase_transaction.is_some());
    assert!(stored.header.bitcoin_merged_mining_merkle_proof.is_some());

    // ...and the completed header satisfies the merged-mining rule, which is
    // the only thing that decides whether a peer keeps it.
    MergedMiningRule { config: fx.chain_config.clone() }
        .validate(&stored.header)
        .expect("the completed header must satisfy the rule this node applies to peers");

    // The chain moved: the node now builds on its own block.
    assert_eq!(fx.store.head().unwrap(), Some(info.block_hash));
    assert_eq!(
        fx.store.exec_head().unwrap().map(|(h, _)| h),
        Some(info.block_hash),
        "the executed head must advance too, or the next template builds on stale state"
    );
}

/// Submitting the same solution twice is a race, not an error: two workers of
/// the same pool can both report it. The second must say so rather than claim
/// the work was never handed out.
#[test]
fn a_repeated_solution_reports_the_block_as_already_present() {
    let fx = fixture(20);
    let work = fx.server.get_work().unwrap();
    let raw = bitcoin::consensus::serialize(&solve(&work));

    assert_eq!(
        fx.server.submit_bitcoin_block(&raw).unwrap().block_imported_result,
        ImportResult::ImportedBest
    );
    // The head moved, so the work is now for a parent that is no longer the
    // executed head -- which is exactly what a duplicate looks like from here.
    let err = fx.server.submit_bitcoin_block(&raw).unwrap_err();
    assert!(
        matches!(err, SubmitError::ParentNoLongerHead { .. }),
        "unexpected error: {err}"
    );
}

/// A coinbase tagged with a hash this node never handed out cannot be matched
/// to a block, and the message has to say which of the two reasons it is.
#[test]
fn a_solution_to_unknown_work_is_refused() {
    let fx = fixture(20);
    // Real work, so the solution is a genuine one -- only the hash it commits
    // to was never handed out.
    let unknown = MinerWork {
        block_hash_for_merged_mining: B256::repeat_byte(0x77),
        ..fx.server.get_work().unwrap()
    };

    let raw = bitcoin::consensus::serialize(&solve(&unknown));
    let err = fx.server.submit_bitcoin_block(&raw).unwrap_err();
    match err {
        SubmitError::UnknownWork { hash } => assert_eq!(hash, B256::repeat_byte(0x77)),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn a_coinbase_without_a_tag_is_refused() {
    let fx = fixture(20);
    let work = fx.server.get_work().unwrap();

    let mut block = solve(&work);
    block.txdata[0].output.truncate(1); // drop the tagged output
    let err = fx
        .server
        .submit_bitcoin_block(&bitcoin::consensus::serialize(&block))
        .unwrap_err();
    assert!(matches!(err, SubmitError::NoTagInCoinbase), "unexpected error: {err}");
}

/// Work is cached, not just held: a solution arrives minutes after the work it
/// answers, by which time several newer templates exist. Keeping only the
/// newest would lose a block that was legitimately found.
#[test]
fn work_handed_out_earlier_can_still_be_answered() {
    let fx = fixture(20);
    let first = fx.server.get_work().unwrap();

    // Several rebuilds later -- same parent, so the templates differ only by
    // timestamp -- the original is still answerable.
    for _ in 0..5 {
        fx.server.build_work().unwrap();
    }

    let raw = bitcoin::consensus::serialize(&solve(&first));
    let info = fx.server.submit_bitcoin_block(&raw).expect("stale work is still work");
    assert_eq!(info.block_imported_result, ImportResult::ImportedBest);
}

/// Bounded, though: the cache is 20 deep, so work older than that is gone and
/// has to be reported as unknown rather than silently matched to something else.
#[test]
fn work_older_than_the_cache_is_forgotten() {
    let fx = fixture(20);
    let first = fx.server.get_work().unwrap();
    let mut seen = std::collections::HashSet::new();
    seen.insert(first.block_hash_for_merged_mining);

    // Each rebuild must produce a distinct template, or this proves nothing.
    while seen.len() <= MiningConfig::default().work_cache_size + 1 {
        let work = fx.server.build_work().unwrap();
        if !seen.insert(work.block_hash_for_merged_mining) {
            // Same second, same template: nudge the clock forward.
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
    }

    let raw = bitcoin::consensus::serialize(&solve(&first));
    assert!(matches!(
        fx.server.submit_bitcoin_block(&raw).unwrap_err(),
        SubmitError::UnknownWork { .. }
    ));
}

/// `notify` marks the transition to new work, not the work itself: a pool that
/// polls twice must not be told twice to push to its miners.
#[test]
fn notify_is_reported_once() {
    let fx = fixture(20);
    assert!(fx.server.get_work().unwrap().notify);
    assert!(!fx.server.get_work().unwrap().notify);
}

/// The three submit methods differ only in how much of the Bitcoin block the
/// miner sends; they must all complete the same header.
#[test]
fn all_three_submit_forms_accept_the_same_solution() {
    for form in ["block", "transactions", "partial"] {
        let fx = fixture(20);
        let work = fx.server.get_work().unwrap();
        let btc_block = solve(&work);

        let header = coinbase::encode_header(&btc_block.header);
        let raw_coinbase = coinbase::encode_transaction(&btc_block.txdata[0]);
        // The wire carries hashes little-endian; display order is the reverse.
        let wire_hashes: Vec<String> = coinbase::txids_display_order(&btc_block)
            .iter()
            .map(|h| {
                let mut wire = *h;
                wire.reverse();
                alloy_primitives::hex::encode(wire)
            })
            .collect();

        let info = match form {
            "block" => fx.server.submit_bitcoin_block(&bitcoin::consensus::serialize(&btc_block)),
            "transactions" => fx.server.submit_bitcoin_block_transactions(
                &header,
                &raw_coinbase,
                &wire_hashes.join(" "),
            ),
            _ => fx.server.submit_bitcoin_block_partial_merkle(
                &header,
                &raw_coinbase,
                &wire_hashes.join(" "),
                wire_hashes.len() as u32,
            ),
        }
        .unwrap_or_else(|e| panic!("{form}: {e}"));

        assert_eq!(info.block_imported_result, ImportResult::ImportedBest, "{form}");
        let stored = fx.store.block(info.block_hash).unwrap().unwrap();
        MergedMiningRule { config: fx.chain_config.clone() }
            .validate(&stored.header)
            .unwrap_or_else(|e| panic!("{form}: completed header rejected: {e}"));
    }
}

/// Before wasabi100 the coinbase carries the whole 32-byte hash and the
/// verifier compares all of it; from wasabi100 it compares only the first 20.
/// A miner must not hardcode either -- regtest and historical replay use the
/// other one.
#[test]
fn both_tag_forms_verify() {
    for wasabi100 in [0u64, u64::MAX] {
        let fx = fixture_with_wasabi_at(wasabi100, 20);
        let work = fx.server.get_work().unwrap();
        let raw = bitcoin::consensus::serialize(&solve(&work));
        let info = fx
            .server
            .submit_bitcoin_block(&raw)
            .unwrap_or_else(|e| panic!("wasabi100={wasabi100}: {e}"));

        let stored = fx.store.block(info.block_hash).unwrap().unwrap();
        MergedMiningRule { config: fx.chain_config.clone() }
            .validate(&stored.header)
            .unwrap_or_else(|e| panic!("wasabi100={wasabi100}: {e}"));
    }
}

/// The coinbase this node compresses must hash to what the verifier recomputes
/// from the compressed form -- checked here on a real completed header rather
/// than on a synthetic buffer.
#[test]
fn the_stored_coinbase_hashes_to_the_submitted_one() {
    let fx = fixture(20);
    let work = fx.server.get_work().unwrap();
    let btc_block = solve(&work);
    let raw_coinbase = coinbase::encode_transaction(&btc_block.txdata[0]);

    let info = fx
        .server
        .submit_bitcoin_block(&bitcoin::consensus::serialize(&btc_block))
        .unwrap();
    let stored = fx.store.block(info.block_hash).unwrap().unwrap();
    let compressed = stored.header.bitcoin_merged_mining_coinbase_transaction.unwrap();

    let mut expected = btc_block.txdata[0].compute_txid().to_byte_array();
    expected.reverse();
    assert_eq!(compute_coinbase_hash(&compressed), expected);
    // And the compression is the one the format prescribes.
    assert_eq!(&compressed[..], &compress_coinbase(&raw_coinbase, true).unwrap()[..]);
}

/// A Bitcoin block whose hash does not clear RSK's target is not a solution.
/// The node checks this itself before storing, rather than finding out when a
/// peer rejects the block.
#[test]
fn a_solution_that_misses_the_target_is_refused() {
    // A difficulty no Bitcoin block will ever satisfy, so the submission below
    // is a correctly formed solution to the wrong amount of work.
    let fx = fixture_with_difficulty(U256::MAX, 20);
    let work = fx.server.get_work().unwrap();
    let raw = bitcoin::consensus::serialize(&unmined(work.block_hash_for_merged_mining));

    let err = fx.server.submit_bitcoin_block(&raw).unwrap_err();
    assert!(matches!(err, SubmitError::SelfCheck(_)), "unexpected error: {err}");
    // Nothing was stored: a refused solution must not leave a block behind.
    assert_eq!(fx.store.head().unwrap(), Some(fx.parent.hash()));
}

/// `mnr_getWork` hands out the target the Bitcoin hash is compared against,
/// and it has to be the same number the verifier derives from the difficulty.
#[test]
fn the_advertised_target_matches_the_difficulty() {
    let fx = fixture(20);
    let template = fx.build().unwrap();
    assert_eq!(template.target, U256::MAX / template.block.header.difficulty);
    assert_eq!(difficulty_to_target(U256::from(1)), U256::MAX);
}

/// A mined block that loses the total-difficulty comparison is still stored --
/// it may win a later reorganisation -- but it must not take the canonical
/// pointer for its height. Storing a block and making it canonical are
/// separate decisions, and conflating them leaves the canonical chain naming a
/// block that is not on it.
#[test]
fn a_losing_block_is_stored_but_not_made_canonical() {
    let fx = fixture(20);
    let work = fx.server.get_work().unwrap();
    let mined_height = fx.parent.number + 1;

    // A competing head with far more work behind it. The executed head is
    // still our parent, so the submission is accepted and executed; only the
    // comparison at the end goes the other way.
    let rival = header_at(mined_height, B256::repeat_byte(0x99), B256::ZERO);
    let rival_hash = rival.hash();
    fx.store.put_header_with_hash(rival_hash, &rival).unwrap();
    fx.store.put_total_difficulty(rival_hash, U256::from(1_000_000)).unwrap();
    fx.store.set_head(rival_hash).unwrap();

    let raw = bitcoin::consensus::serialize(&solve(&work));
    let info = fx.server.submit_bitcoin_block(&raw).expect("a valid solution is still valid");

    assert_eq!(info.block_imported_result, ImportResult::ImportedNotBest);
    assert!(
        fx.store.header(info.block_hash).unwrap().is_some(),
        "the block is kept: it may yet win a reorganisation"
    );
    assert_eq!(
        fx.store.canonical_hash(mined_height).unwrap(),
        None,
        "a block that lost must not hold the canonical pointer for its height"
    );
    assert_eq!(fx.store.head().unwrap(), Some(rival_hash), "the head must not move");
}

/// The round trip again, but deep enough that REMASC actually pays out.
///
/// Everywhere else these tests mine block #21, and REMASC's
/// `process_miners_fees` returns immediately there: the executor is built with
/// `RemascConfig::mainnet()`, whose maturity is 4,000, so a chain that short
/// has no matured block to distribute. That leaves the interesting half of
/// REMASC -- fetching the matured header, collecting siblings, paying the
/// miner -- unexercised, while the test still passes and looks like it covers
/// block production.
///
/// Mining above both the maturity window and the synthetic span runs it for
/// real. Kept separate because seeding four thousand headers costs a second.
#[test]
fn a_solution_is_imported_on_a_chain_deep_enough_for_remasc_to_pay() {
    // maturity 4,000 + synthetic span 10, so the matured block is #11.
    let fx = fixture(4_010);
    let work = fx.server.get_work().unwrap();

    let raw = bitcoin::consensus::serialize(&solve(&work));
    let info = fx
        .server
        .submit_bitcoin_block(&raw)
        .expect("a solution must be accepted on a chain deep enough for REMASC to pay out");

    assert_eq!(info.block_imported_result, ImportResult::ImportedBest);
    assert_eq!(info.block_included_height, 4_011);

    let stored = fx.store.block(info.block_hash).unwrap().unwrap();
    MergedMiningRule { config: fx.chain_config.clone() }
        .validate(&stored.header)
        .expect("the completed header must satisfy the rule this node applies to peers");
}

/// And the round trip with `ummRoot` present, which is what mainnet actually
/// carries. Elsewhere these tests keep papyrus200 out of reach so they can
/// work at low block numbers, which means the field every real header has is
/// absent from the block they mine.
#[test]
fn a_solution_is_imported_with_umm_root_present() {
    let fx = fixture_with_papyrus_at(0, 20);
    let work = fx.server.get_work().unwrap();

    let raw = bitcoin::consensus::serialize(&solve(&work));
    let info = fx.server.submit_bitcoin_block(&raw).expect("solution accepted");

    let stored = fx.store.block(info.block_hash).unwrap().unwrap();
    assert_eq!(stored.header.umm_root, Some(Bytes::new()));
    MergedMiningRule { config: fx.chain_config.clone() }
        .validate(&stored.header)
        .expect("a header carrying ummRoot must still verify");
}

// ── uncle selection ───────────────────────────────────────────────────

mod uncle_tests {
    use super::*;
    use crate::mining::uncles::{UNCLE_LIST_LIMIT, select_uncles};

    /// Build a chain of `height` canonical blocks and return the store.
    fn chain(height: u64) -> (Arc<BlockStore>, Vec<Header>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let mut headers = Vec::new();
        let mut parent_hash = B256::ZERO;
        for number in 0..=height {
            let header = header_at(number, parent_hash, B256::ZERO);
            let hash = header.hash();
            store.put_header_with_hash(hash, &header).unwrap();
            store.put_body(hash, &[], &[]).unwrap();
            store.put_canonical_hash(number, hash).unwrap();
            parent_hash = hash;
            headers.push(header);
        }
        (store, headers, dir)
    }

    /// A block that lost at `number`, sharing the canonical parent. `tag`
    /// makes it differ from the winner.
    fn sibling_of(parent: &Header, number: u64, tag: u8) -> Header {
        let mut header = header_at(number, parent.hash(), B256::ZERO);
        header.beneficiary = Address::repeat_byte(tag);
        header
    }

    fn store_orphan(store: &BlockStore, header: &Header) -> B256 {
        let hash = header.hash();
        store.put_header_with_hash(hash, header).unwrap();
        store.put_body(hash, &[], &[]).unwrap();
        hash
    }

    /// The whole point: a block that lost is not named by the canonical
    /// pointer, and before the height index there was no way to find it.
    #[test]
    fn a_losing_sibling_is_selected_as_an_uncle() {
        let (store, headers, _dir) = chain(10);
        let orphan = sibling_of(&headers[9], 10, 0xAA);
        let orphan_hash = store_orphan(&store, &orphan);

        // It is not canonical...
        assert_ne!(store.canonical_hash(10).unwrap(), Some(orphan_hash));
        // ...but it is findable by height, which is what makes this possible.
        assert_eq!(store.hashes_at_height(10).unwrap().len(), 2);

        let uncles = select_uncles(&store, 11, headers[10].hash());
        assert_eq!(uncles.len(), 1, "the losing sibling must be offered");
        assert_eq!(uncles[0].hash(), orphan_hash);
    }

    /// Ancestors are not uncles of their own descendant, however findable
    /// they are.
    #[test]
    fn ancestors_are_never_selected() {
        let (store, headers, _dir) = chain(10);
        let uncles = select_uncles(&store, 11, headers[10].hash());
        assert!(uncles.is_empty(), "a chain with no forks has no uncles");
    }

    /// A block older than the generation limit cannot be included: the
    /// validator rejects `uncle.number - 1 < blockNumber - 7`.
    #[test]
    fn uncles_older_than_the_generation_limit_are_not_selected() {
        let (store, headers, _dir) = chain(20);

        // Mining #21. The oldest includable uncle is #15 (21 - 7 + 1).
        let just_inside = sibling_of(&headers[14], 15, 0xAA);
        let too_old = sibling_of(&headers[13], 14, 0xBB);
        let inside_hash = store_orphan(&store, &just_inside);
        store_orphan(&store, &too_old);

        let uncles = select_uncles(&store, 21, headers[20].hash());
        let selected: Vec<B256> = uncles.iter().map(|u| u.hash()).collect();

        assert!(selected.contains(&inside_hash), "#15 is inside the window");
        assert_eq!(selected.len(), 1, "#14 is one generation too old: {selected:?}");
    }

    /// An uncle an ancestor already included may not be included again.
    #[test]
    fn already_used_uncles_are_not_offered_twice() {
        let (store, headers, _dir) = chain(10);
        let orphan = sibling_of(&headers[8], 9, 0xAA);
        let orphan_hash = store_orphan(&store, &orphan);

        // Without anyone having used it, it is a candidate.
        assert_eq!(select_uncles(&store, 11, headers[10].hash()).len(), 1);

        // Now let #10 have included it: rewrite #10's body with the uncle.
        store.put_body(headers[10].hash(), &[], std::slice::from_ref(&orphan)).unwrap();

        let uncles = select_uncles(&store, 11, headers[10].hash());
        assert!(
            uncles.iter().all(|u| u.hash() != orphan_hash),
            "an uncle #10 already used must not be offered again"
        );
    }

    /// The case that distinguishes selecting by parentage from selecting by
    /// height: a multi-block fork that was orphaned.
    ///
    /// A fork diverging at #7 puts blocks at #8, #9 and #10 in the store, all
    /// at heights the block being mined would look at. Only the first is an
    /// uncle -- it is a direct child of #7, which is on our chain. Its
    /// descendants hang off the fork, not off any ancestor, so including them
    /// would produce a block every peer rejects (rskj `validateUncleParent`).
    #[test]
    fn only_the_first_block_of_an_orphaned_fork_is_an_uncle() {
        let (store, headers, _dir) = chain(10);

        // Fork off #7: 8' -> 9' -> 10', none of them canonical.
        let forked_8 = sibling_of(&headers[7], 8, 0xF1);
        let forked_8_hash = store_orphan(&store, &forked_8);

        let mut forked_9 = header_at(9, forked_8_hash, B256::ZERO);
        forked_9.beneficiary = Address::repeat_byte(0xF2);
        let forked_9_hash = store_orphan(&store, &forked_9);

        let mut forked_10 = header_at(10, forked_9_hash, B256::ZERO);
        forked_10.beneficiary = Address::repeat_byte(0xF3);
        let forked_10_hash = store_orphan(&store, &forked_10);

        // All three sit at heights the search covers, so height alone would
        // offer all three.
        assert_eq!(store.hashes_at_height(8).unwrap().len(), 2);
        assert_eq!(store.hashes_at_height(9).unwrap().len(), 2);
        assert_eq!(store.hashes_at_height(10).unwrap().len(), 2);

        let selected: Vec<B256> = select_uncles(&store, 11, headers[10].hash())
            .iter()
            .map(|u| u.hash())
            .collect();

        assert_eq!(
            selected,
            vec![forked_8_hash],
            "only the fork's first block is a child of our chain"
        );
        assert!(!selected.contains(&forked_9_hash), "9' hangs off 8', not off our chain");
        assert!(!selected.contains(&forked_10_hash), "10' hangs off 9', not off our chain");
    }

    /// The same principle one level up: a fork whose divergence point is
    /// itself outside the generation window contributes nothing at all, even
    /// though its blocks sit at heights the search covers.
    #[test]
    fn a_fork_diverging_before_the_window_contributes_no_uncles() {
        let (store, headers, _dir) = chain(20);

        // Mining #21, so the window reaches back to #15. Fork off #10, well
        // below it, and run the fork up through the window.
        let mut parent_hash = headers[10].hash();
        let mut forked_hashes = Vec::new();
        for number in 11..=20u64 {
            let mut forked = header_at(number, parent_hash, B256::ZERO);
            forked.beneficiary = Address::repeat_byte(0xD0 + (number - 11) as u8);
            parent_hash = store_orphan(&store, &forked);
            forked_hashes.push(parent_hash);
        }

        let selected: Vec<B256> = select_uncles(&store, 21, headers[20].hash())
            .iter()
            .map(|u| u.hash())
            .collect();

        assert!(
            selected.is_empty(),
            "every block of this fork hangs off the fork, not off our chain: {selected:?}"
        );
        for hash in forked_hashes {
            assert!(!selected.contains(&hash));
        }
    }

    /// A block at the right height on a different fork is not family: its
    /// parent is not one of our ancestors.
    #[test]
    fn a_block_from_an_unrelated_fork_is_not_an_uncle() {
        let (store, headers, _dir) = chain(10);

        let mut stranger = header_at(10, B256::repeat_byte(0xEE), B256::ZERO);
        stranger.beneficiary = Address::repeat_byte(0xCC);
        store_orphan(&store, &stranger);

        let uncles = select_uncles(&store, 11, headers[10].hash());
        assert!(uncles.is_empty(), "a block whose parent is not an ancestor is not family");
    }

    /// The list is capped: a longer one is rejected outright rather than
    /// trimmed by the validator.
    #[test]
    fn the_uncle_list_is_capped() {
        let (store, headers, _dir) = chain(10);
        for tag in 0..(UNCLE_LIST_LIMIT as u8 + 5) {
            store_orphan(&store, &sibling_of(&headers[9], 10, tag));
        }

        let uncles = select_uncles(&store, 11, headers[10].hash());
        assert_eq!(uncles.len(), UNCLE_LIST_LIMIT);
    }

    /// Two nodes building the same block must choose the same uncles in the
    /// same order, or they compute different ommer hashes for what should be
    /// the same block. The index returns hashes in column-family order, which
    /// is not an ordering anyone should rely on.
    #[test]
    fn selection_is_deterministic() {
        let (store, headers, _dir) = chain(10);
        for tag in 0..5u8 {
            store_orphan(&store, &sibling_of(&headers[9], 10, tag));
        }

        let first: Vec<B256> = select_uncles(&store, 11, headers[10].hash())
            .iter()
            .map(|u| u.hash())
            .collect();
        for _ in 0..5 {
            let again: Vec<B256> = select_uncles(&store, 11, headers[10].hash())
                .iter()
                .map(|u| u.hash())
                .collect();
            assert_eq!(first, again);
        }
        // Sorted by height then hash, so the order is a property of the set
        // rather than of how it was stored.
        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(first, sorted);
    }

    /// A database without the index must yield nothing rather than fail --
    /// and the miner warns, so an operator is not left wondering why their
    /// blocks never carry uncles.
    #[test]
    fn selection_finds_nothing_without_the_index() {
        let (store, headers, _dir) = chain(10);
        let orphan = sibling_of(&headers[9], 10, 0xAA);
        // Store the header the way a pre-index build did: no index entry.
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(&orphan, &mut buf);
        store
            .db()
            .put_cf(store.cf_headers().unwrap(), orphan.hash().as_slice(), &buf)
            .unwrap();

        assert!(
            select_uncles(&store, 11, headers[10].hash()).is_empty(),
            "an unindexed orphan cannot be found by height"
        );

        // After the upgrade it can.
        store.build_height_index(0, |_| {}).unwrap();
        assert_eq!(select_uncles(&store, 11, headers[10].hash()).len(), 1);
    }
}

// ── RSKIP-144: the miner's partition ──────────────────────────────────

mod partitioned_templates {
    use super::*;
    use crate::mining::template::{PendingTransaction, PendingTransactionSource};
    use k256::ecdsa::SigningKey;
    use rustock_core::Transaction;
    use sha3::Digest;

    /// A pool that hands out exactly what it was given.
    struct Pool(Vec<PendingTransaction>);

    impl PendingTransactionSource for Pool {
        fn pending(&self) -> Vec<PendingTransaction> {
            self.0.clone()
        }
    }

    fn signing_key(n: u8) -> SigningKey {
        SigningKey::from_slice(&[n; 32]).unwrap()
    }

    fn address_of(key: &SigningKey) -> Address {
        let pubkey = key.verifying_key().to_encoded_point(false);
        let hash: [u8; 32] = sha3::Keccak256::digest(&pubkey.as_bytes()[1..]).into();
        Address::from_slice(&hash[12..])
    }

    /// A plain transfer from `from` to `to`, signed.
    fn transfer(from: &SigningKey, to: Address, nonce: u64, chain_id: u64) -> PendingTransaction {
        let mut tx = Transaction {
            nonce,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(to.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign(&mut tx, from, chain_id);
        let sender = address_of(from);
        let hash = B256::from_slice(&sha3::Keccak256::digest(tx.rlp_for_trie()));
        PendingTransaction { tx, sender, hash }
    }

    fn sign(tx: &mut Transaction, key: &SigningKey, chain_id: u64) {
        let hash = tx.signing_hash_eip155(chain_id);
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            key.sign_prehash_recoverable(hash.as_slice()).unwrap();
        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
        tx.cached_rlp = None;
    }

    /// A builder on a chain where RSKIP-144 is active from genesis, with
    /// `senders` funded accounts.
    ///
    /// Not testnet at its real reed810 height: REMASC reaches back
    /// `maturity` blocks and the fixture would have to store seven million
    /// headers to satisfy it. Scheduling Reed810 at zero asks the same
    /// question of the miner for the price of a twenty-block chain.
    #[allow(clippy::type_complexity)]
    fn partitioning_fixture(
        senders: u8,
    ) -> (BlockTemplateBuilder, Header, Vec<SigningKey>, Arc<dyn TrieStore>, Arc<BlockStore>) {
        fixture_with_forks(senders, RskHardforkConfig::all_active_parallel(33))
    }

    /// The same fixture, for the RSKIP-252 tests next door. They need the
    /// funded senders and the short chain; what they vary is the head's
    /// minimum gas price, which they rewrite themselves.
    #[allow(clippy::type_complexity)]
    pub(super) fn fixture_for_cap_test(
        senders: u8,
    ) -> (BlockTemplateBuilder, Header, Vec<SigningKey>, Arc<dyn TrieStore>, Arc<BlockStore>) {
        fixture_with_forks(senders, RskHardforkConfig::all_active_parallel(33))
    }

    #[allow(clippy::type_complexity)]
    fn fixture_with_forks(
        senders: u8,
        hardfork_cfg: RskHardforkConfig,
    ) -> (BlockTemplateBuilder, Header, Vec<SigningKey>, Arc<dyn TrieStore>, Arc<BlockStore>) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let keys: Vec<SigningKey> = (1..=senders).map(signing_key).collect();
        let mut root = TrieNode::empty();
        for key in &keys {
            let addr = address_of(key);
            let acct = rustock_trie::AccountState::new(
                U256::ZERO,
                U256::from(10u64).pow(U256::from(18)),
            );
            let k = rustock_trie::TrieKeySlice::from_key(&rustock_trie::account_key(&addr));
            root = root.put(&k, &acct.encode(), trie_store.as_ref());
        }
        let state_root = root.compute_hash(trie_store.as_ref());
        root.save(trie_store.as_ref(), true);
        // The seeding is the fixture's whole premise; a silent failure here
        // shows up much later as "balance: 0" from the EVM.
        for key in &keys {
            let addr = address_of(key);
            let probe = rustock_trie::TrieKeySlice::from_key(&rustock_trie::account_key(&addr));
            assert!(root.get(&probe, trie_store.as_ref()).is_some(), "{addr} not seeded");
        }

        let height = 20u64;
        let mut parent_hash = B256::ZERO;
        let mut parent = header_at(0, parent_hash, state_root);
        for number in 0..=height {
            let mut header = header_at(number, parent_hash, state_root);
            header.difficulty = U256::from(2);
            header.gas_limit = U256::from(10_000_000u64);
            let hash = header.hash();
            store.put_header_with_hash(hash, &header).unwrap();
            store.put_canonical_hash(number, hash).unwrap();
            store.put_total_difficulty(hash, U256::from(number + 1)).unwrap();
            parent_hash = hash;
            parent = header;
        }
        store.set_head(parent_hash).unwrap();
        store.set_exec_head(parent_hash, state_root).unwrap();

        let builder = BlockTemplateBuilder::new(
            Arc::new(BlockProcessor::new(hardfork_cfg.clone(), store.clone())),
            trie_store.clone(),
            test_chain_config(),
            hardfork_cfg,
            MiningConfig {
                coinbase_address: address!("00000000000000000000000000000000c0117b45"),
                ..Default::default()
            },
        );
        (builder, parent, keys, trie_store, store)
    }

    /// Four transfers between eight distinct accounts: nothing touches
    /// anything else, so the miner should split them across the parallel
    /// sublists and the block should declare it.
    #[test]
    fn independent_transfers_are_split_across_parallel_sublists() {
        let (builder, parent, keys, trie_store, store) = partitioning_fixture(4);
        let chain_id = 33;
        let pool = Pool(
            keys.iter()
                .enumerate()
                .map(|(i, k)| transfer(k, Address::repeat_byte(0xA0 + i as u8), 0, chain_id))
                .collect(),
        );

        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &pool)
            .expect("the template builds");

        let edges = template
            .block
            .header
            .version_fields
            .as_ref()
            .and_then(|v| v.edges.clone())
            .expect("a block of independent transfers declares a partition");
        assert!(!edges.is_empty(), "and the partition is not empty");
        assert_eq!(
            edges.len(),
            2,
            "four independent transfers fill both parallel sublists: {edges:?}"
        );

        // The partition has to survive the validator, which is the only
        // opinion that counts.
        let processor = BlockProcessor::new(RskHardforkConfig::all_active_parallel(33), store);
        let parent_state = builder.load_state_root(parent.state_root).unwrap();
        processor
            .process_block(&template.block, &parent_state, trie_store)
            .expect("a block this miner built must be one this node would accept");
    }

    /// Every transfer from one sender. They are connected by the nonce, so
    /// they must all land in one sublist -- and with only one parallel
    /// sublist used, the block still declares a partition naming it.
    #[test]
    fn transfers_from_a_single_sender_share_one_sublist() {
        let (builder, parent, keys, trie_store, store) = partitioning_fixture(1);
        let chain_id = 33;
        let pool = Pool(
            (0..3)
                .map(|n| transfer(&keys[0], Address::repeat_byte(0xB0 + n as u8), n, chain_id))
                .collect(),
        );

        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &pool)
            .expect("the template builds");

        let edges = template
            .block
            .header
            .version_fields
            .as_ref()
            .and_then(|v| v.edges.clone())
            .expect("a partition is declared");
        assert_eq!(edges, vec![3], "all three in the first parallel sublist");

        let processor = BlockProcessor::new(RskHardforkConfig::all_active_parallel(33), store);
        let parent_state = builder.load_state_root(parent.state_root).unwrap();
        processor
            .process_block(&template.block, &parent_state, trie_store)
            .expect("the block validates");
    }

    /// A chain of transfers -- a pays b, b pays c -- is connected all the way
    /// down, so it collapses into one sublist rather than being split.
    #[test]
    fn a_chain_of_transfers_does_not_split() {
        let (builder, parent, keys, trie_store, store) = partitioning_fixture(3);
        let chain_id = 33;
        // a -> b, b -> c: the recipient of each is the sender of the next.
        let pool = Pool(vec![
            transfer(&keys[0], address_of(&keys[1]), 0, chain_id),
            transfer(&keys[1], address_of(&keys[2]), 0, chain_id),
        ]);

        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &pool)
            .expect("the template builds");

        let edges = template
            .block
            .header
            .version_fields
            .as_ref()
            .and_then(|v| v.edges.clone())
            .unwrap_or_default();
        assert!(
            edges.len() <= 1,
            "connected transfers cannot be split into two parallel sublists: {edges:?}"
        );

        let processor = BlockProcessor::new(RskHardforkConfig::all_active_parallel(33), store);
        let parent_state = builder.load_state_root(parent.state_root).unwrap();
        processor
            .process_block(&template.block, &parent_state, trie_store)
            .expect("the block validates");
    }

    /// A chain that does not schedule reed810 declares no partition,
    /// whatever the pool looks like. This is mainnet's shape: `all_active`
    /// names Vetiver900, which outranks Reed810 in the enum and schedules
    /// neither RSKIP-144 nor RSKIP-351.
    #[test]
    fn a_chain_without_reed810_declares_no_partition() {
        let (builder, parent, keys, trie_store, store) =
            fixture_with_forks(2, RskHardforkConfig::all_active(33));
        let chain_id = 33;
        let pool = Pool(
            keys.iter()
                .enumerate()
                .map(|(i, k)| transfer(k, Address::repeat_byte(0xC0 + i as u8), 0, chain_id))
                .collect(),
        );
        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &pool)
            .expect("the template builds");
        assert!(
            template.block.header.version_fields.is_none(),
            "RSKIP-144 is not scheduled, so the header carries no extension"
        );
        assert_eq!(
            template.block.transactions.len(),
            3,
            "and the transactions are all there, just unpartitioned"
        );

        let processor = BlockProcessor::new(RskHardforkConfig::all_active(33), store);
        let parent_state = builder.load_state_root(parent.state_root).unwrap();
        processor
            .process_block(&template.block, &parent_state, trie_store)
            .expect("the block validates");
    }
}

// ── RSKIP-252: the miner's own price ceiling ──────────────────────────

/// The cap the miner has to apply to itself.
///
/// `BlockTxsMaxGasPriceRule` rejects any block whose transactions pay more
/// than 100x its `minimumGasPrice`, and until this was fixed the miner only
/// applied the *floor*. The result is the worst shape a miner bug takes: the
/// node seals a block, spends the work, and every validator on the network
/// refuses it. A run that primed `eth_gasPrice` from a mainnet export and
/// then mined on a quiet chain produced 138 such blocks.
///
/// The import-side rule is the assertion here, not a hand-written
/// expectation: whatever the miner selects has to satisfy the same validator
/// a peer would run.
mod rskip252_cap {
    use super::*;
    use crate::mining::template::{PendingTransaction, PendingTransactionSource};
    use k256::ecdsa::SigningKey;
    use rustock_core::Transaction;
    use rustock_core::validation::BlockValidator;
    use rustock_core::validation::block_rules::BlockTxsMaxGasPriceRule;
    use sha3::Digest;

    struct Pool(Vec<PendingTransaction>);
    impl PendingTransactionSource for Pool {
        fn pending(&self) -> Vec<PendingTransaction> {
            self.0.clone()
        }
    }

    fn address_of(key: &SigningKey) -> Address {
        let pubkey = key.verifying_key().to_encoded_point(false);
        let hash: [u8; 32] = sha3::Keccak256::digest(&pubkey.as_bytes()[1..]).into();
        Address::from_slice(&hash[12..])
    }

    fn sign(tx: &mut Transaction, key: &SigningKey, chain_id: u64) {
        let hash = tx.signing_hash_eip155(chain_id);
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            key.sign_prehash_recoverable(hash.as_slice()).unwrap();
        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
        tx.cached_rlp = None;
    }

    /// A signed transfer at an explicit gas price, which is the whole point.
    fn transfer_at(from: &SigningKey, to: Address, gas_price: u64) -> PendingTransaction {
        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(to.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign(&mut tx, from, 33);
        let sender = address_of(from);
        let hash = B256::from_slice(&sha3::Keccak256::digest(tx.rlp_for_trie()));
        PendingTransaction { tx, sender, hash }
    }

    /// The partitioning fixture leaves every header at a zero minimum gas
    /// price, and `TxGasPriceCap` short-circuits on zero -- so a fixture that
    /// did not set one would pass whatever the miner did. Rewrite the head
    /// with `minimum`, keeping the store consistent with it.
    fn fixture_with_minimum(
        senders: u8,
        minimum: u64,
    ) -> (BlockTemplateBuilder, Header, Vec<SigningKey>, Arc<dyn TrieStore>, Arc<BlockStore>) {
        let (builder, parent, keys, trie_store, store) =
            super::partitioned_templates::fixture_for_cap_test(senders);
        let mut head = parent.clone();
        head.minimum_gas_price = U256::from(minimum);
        head.cached_hash = None;
        head.cached_hash_for_merged_mining = None;
        let hash = head.hash();
        store.put_header_with_hash(hash, &head).unwrap();
        store.put_canonical_hash(head.number, hash).unwrap();
        store.put_total_difficulty(hash, U256::from(head.number + 1)).unwrap();
        store.set_head(hash).unwrap();
        store.set_exec_head(hash, head.state_root).unwrap();
        (builder, head, keys, trie_store, store)
    }

    #[test]
    fn transactions_over_the_cap_are_not_mined() {
        const MINIMUM: u64 = 1_000;
        const CAP: u64 = MINIMUM * BlockTxsMaxGasPriceRule::FOR_BLOCK_MULTIPLIER;

        let (builder, parent, keys, trie_store, store) = fixture_with_minimum(3, MINIMUM);

        // One comfortably inside the range, one exactly at the ceiling --
        // the rule rejects `>` the cap, so this one is legal and a miner
        // that dropped it would be leaving money on the table -- and one a
        // single wei over, which no validator will accept.
        let under = transfer_at(&keys[0], Address::repeat_byte(0xA1), MINIMUM * 50);
        let at_cap = transfer_at(&keys[1], Address::repeat_byte(0xA2), CAP);
        let over = transfer_at(&keys[2], Address::repeat_byte(0xA3), CAP + 1);
        let over_hash = over.hash;
        let pool = Pool(vec![under.clone(), at_cap.clone(), over]);

        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &pool)
            .expect("the template builds");

        let mined: Vec<U256> =
            template.block.transactions.iter().map(|t| t.gas_price).collect();
        assert!(
            mined.contains(&U256::from(MINIMUM * 50)),
            "a transaction well inside the range is mined: {mined:?}"
        );
        assert!(
            mined.contains(&U256::from(CAP)),
            "so is one exactly at the cap -- the rule rejects only what exceeds it: {mined:?}"
        );
        assert!(
            !mined.contains(&U256::from(CAP + 1)),
            "the one a wei over the cap is not: {mined:?}"
        );
        assert!(
            !template.block.transactions.iter().any(|t| {
                B256::from_slice(&sha3::Keccak256::digest(t.rlp_for_trie())) == over_hash
            }),
            "and it is gone by identity, not merely by price"
        );

        // The assertion that matters: the block the miner produced is one the
        // import path accepts. This is the rule that rejected the 138 blocks.
        BlockTxsMaxGasPriceRule { rskip252_height: 0 }
            .validate_block(&template.block)
            .expect("a block this miner seals must be one the network accepts");

        let processor = BlockProcessor::new(RskHardforkConfig::all_active_parallel(33), store);
        let parent_state = builder.load_state_root(parent.state_root).unwrap();
        processor
            .process_block(&template.block, &parent_state, trie_store)
            .expect("and one it can execute");
    }

    /// `TxGasPriceCap.isSurpassed` short-circuits on a zero minimum, so a
    /// chain without a fee market has no ceiling. Regtest runs this way, and
    /// a cap derived from zero would drop every transaction in the pool.
    #[test]
    fn a_zero_minimum_imposes_no_ceiling() {
        let (builder, parent, keys, _trie_store, _store) = fixture_with_minimum(1, 0);
        assert!(parent.minimum_gas_price.is_zero(), "the premise");

        let rich = transfer_at(&keys[0], Address::repeat_byte(0xB1), 26_065_600);
        let pool = Pool(vec![rich]);

        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &pool)
            .expect("the template builds");

        let mined: Vec<U256> =
            template.block.transactions.iter().map(|t| t.gas_price).collect();
        assert!(
            mined.contains(&U256::from(26_065_600u64)),
            "with no minimum there is nothing to be 100x of: {mined:?}"
        );
    }
}
