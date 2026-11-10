//! Tests for the ascending header sync.
//!
//! The ones that matter are the three ways a peer can lie about uncle work,
//! because that is the whole reason this walk exists: it totals cumulative
//! difficulty *exactly* where the descending walk can only bound it.

use super::forward::{AscentError, ForwardSync, Want, HEADER_CHUNK};
use alloy_primitives::{Address, B256, U256};
use rustock_core::validation::{HeaderValidator, HeaderVerifier, ValidationError};
use rustock_core::Header;
use rustock_networking::protocol::{BlockIdentifier, HeaderWithUncles};
use rustock_storage::BlockStore;
use std::sync::Arc;

fn header(number: u64, parent: B256, difficulty: u64) -> Header {
    Header {
        parent_hash: parent,
        ommers_hash: rustock_execution::processor::compute_ommers_hash(&[]),
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: rustock_core::ordered_tx_trie_root(&[], true),
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(difficulty),
        number,
        gas_limit: U256::from(6_800_000u64),
        gas_used: 0,
        timestamp: 1_700_000_000 + number,
        extra_data: Default::default(),
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
        kept: None,
    }
}

/// An entry whose header honestly commits to the uncles beside it.
fn with_uncles(mut h: Header, uncles: Vec<Header>) -> HeaderWithUncles {
    h.uncle_count = uncles.len() as u64;
    h.ommers_hash = rustock_execution::processor::compute_ommers_hash(&uncles);
    h.cached_hash = None;
    HeaderWithUncles { header: h, uncles }
}

/// `n` headers ascending from `parent`, returned newest-first as the wire
/// delivers them. `uncles_at` decides what each block references.
fn run_of(
    first_number: u64,
    n: usize,
    parent: B256,
    difficulty: u64,
    mut uncles_at: impl FnMut(u64) -> Vec<Header>,
) -> Vec<HeaderWithUncles> {
    let mut out = Vec::new();
    let mut prev = parent;
    for i in 0..n {
        let number = first_number + i as u64;
        let e = with_uncles(header(number, prev, difficulty), uncles_at(number));
        prev = e.header.hash();
        out.push(e);
    }
    out.reverse();
    out
}

fn sync(anchor: &Header, target: u64, verifier: HeaderVerifier) -> (ForwardSync, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    (
        ForwardSync::new(
            anchor.number,
            anchor.hash(),
            U256::ZERO,
            target,
            B256::repeat_byte(0xff),
            true,
            store,
            Arc::new(verifier),
        ),
        dir,
    )
}

/// A clean ascent links and totals trunk *plus* uncle difficulty exactly.
#[test]
fn an_honest_run_advances_the_prefix_and_totals_the_uncles() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 4, HeaderVerifier::new());

    // Two uncles on block 2, worth 50 each.
    let entries = run_of(1, 4, anchor.hash(), 100, |n| {
        if n == 2 { vec![header(1, B256::repeat_byte(9), 50), header(1, B256::repeat_byte(8), 50)] }
        else { Vec::new() }
    });
    s.on_headers_with_uncles(4, &entries).expect("honest run");

    assert_eq!(s.frontier(), 4, "the prefix absorbs the whole run");
    assert!(s.done());
    assert_eq!(
        s.work(),
        U256::from(4 * 100 + 2 * 50),
        "cumulative difficulty counts the uncles, which is the point of the walk"
    );
}

/// Uncles the trunk header does not commit to are refused.
///
/// `ommers_hash` is inside what the header's proof of work covers, so a
/// mismatch means the peer altered the list. Without this check the difficulty
/// is whatever the peer says it is.
#[test]
fn uncles_the_header_does_not_commit_to_are_refused() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 2, HeaderVerifier::new());

    let mut entries = run_of(1, 2, anchor.hash(), 100, |_| Vec::new());
    // Bolt a fat uncle onto a header that commits to an empty list.
    entries[0].uncles.push(header(1, B256::repeat_byte(7), 1_000_000));

    assert!(
        matches!(
            s.on_headers_with_uncles(2, &entries),
            Err(AscentError::UncleCommitment { .. })
        ),
        "a forged uncle list must not reach the total"
    );
    assert_eq!(s.frontier(), 0, "and the prefix does not move");
}

/// Rejects a header whose difficulty marks it as having no proof of work, so
/// the uncle-proof path can be exercised without a merged-mining fixture.
struct RejectMarked;
impl HeaderValidator for RejectMarked {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        if header.difficulty == U256::from(666u64) {
            return Err(ValidationError::BitcoinPowInvalid {
                hash: header.hash(),
                target: U256::ZERO,
            });
        }
        Ok(())
    }
}

/// An uncle with a valid commitment but no valid proof of work is refused.
///
/// The commitment only proves the block's miner chose this list. What makes an
/// uncle's difficulty *work* is its own merged-mining proof, and a miner is
/// free to commit to an uncle that never had one.
#[test]
fn an_uncle_without_proof_of_work_is_refused() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 2, HeaderVerifier::new().with_uncle_rule(RejectMarked));

    let entries = run_of(1, 2, anchor.hash(), 100, |n| {
        if n == 1 { vec![header(0, B256::repeat_byte(5), 666)] } else { Vec::new() }
    });

    assert!(
        matches!(
            s.on_headers_with_uncles(2, &entries),
            Err(AscentError::UncleProofOfWork { .. })
        ),
        "a committed uncle still has to have done the work it claims"
    );
}

/// The same uncle counted under two blocks is refused.
///
/// Consensus forbids reuse; without the check one uncle's difficulty is
/// counted as many times as a miner cares to reference it.
#[test]
fn an_uncle_counted_twice_is_refused() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 3, HeaderVerifier::new());

    let twice = header(1, B256::repeat_byte(4), 500);
    let entries = run_of(1, 3, anchor.hash(), 100, |n| {
        if n == 2 || n == 3 { vec![twice.clone()] } else { Vec::new() }
    });

    assert!(
        matches!(s.on_headers_with_uncles(3, &entries), Err(AscentError::UncleReused { .. })),
        "one uncle, one contribution"
    );
}

/// Reuse is caught across runs too, not just inside one.
#[test]
fn an_uncle_counted_in_an_earlier_run_is_refused() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 4, HeaderVerifier::new());

    let shared = header(1, B256::repeat_byte(3), 500);
    let first = run_of(1, 2, anchor.hash(), 100, |n| {
        if n == 2 { vec![shared.clone()] } else { Vec::new() }
    });
    s.on_headers_with_uncles(2, &first).expect("first run is honest");
    assert_eq!(s.frontier(), 2);

    let top = first[0].header.hash();
    let second = run_of(3, 2, top, 100, |n| {
        if n == 4 { vec![shared.clone()] } else { Vec::new() }
    });
    assert!(
        matches!(s.on_headers_with_uncles(4, &second), Err(AscentError::UncleReused { .. })),
        "the ledger of counted uncles outlives the run that filled it"
    );
}

/// A run at the right height from the wrong chain does not move the prefix.
///
/// Height alone is not a link: a peer can answer at exactly the height wanted
/// with headers from somewhere else, and the parent hash is what catches it.
#[test]
fn a_run_from_another_chain_does_not_advance_the_prefix() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 4, HeaderVerifier::new());

    let elsewhere = run_of(1, 2, B256::repeat_byte(0xaa), 100, |_| Vec::new());
    s.on_headers_with_uncles(2, &elsewhere).expect("internally consistent");

    assert_eq!(s.frontier(), 0, "it links to nothing this node trusts");
    assert_eq!(s.work(), U256::ZERO, "and contributes no work");
}

/// Requests go out lowest-first and never reach below the proven prefix.
#[test]
fn requests_are_lowest_first_and_do_not_overlap_the_prefix() {
    let anchor = header(100, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 100 + 3 * HEADER_CHUNK, HeaderVerifier::new());

    s.on_skeleton(&[
        BlockIdentifier { number: 100 + 2 * HEADER_CHUNK, hash: B256::repeat_byte(2) },
        BlockIdentifier { number: 100 + HEADER_CHUNK, hash: B256::repeat_byte(1) },
    ]);

    let wants = s.wants(2);
    let points: Vec<u64> = wants
        .iter()
        .filter_map(|w| match w {
            Want::Headers { point, .. } => Some(*point),
            _ => None,
        })
        .collect();
    assert_eq!(
        points,
        vec![100 + HEADER_CHUNK, 100 + 2 * HEADER_CHUNK],
        "the prefix grows from the bottom, so the bottom is asked for first"
    );

    // The first chunk must stop exactly at the anchor, not run past it.
    match wants[0] {
        Want::Headers { count, .. } => assert_eq!(count as u64, HEADER_CHUNK),
        _ => panic!("expected headers"),
    }
}

/// The target need not sit on the chunk grid, and the ascent must still reach
/// it.
///
/// Skeleton identifiers land on multiples of `HEADER_CHUNK`, so for a target
/// that is not one, no identifier ever names it. The first real run stalled at
/// 99.96% for exactly this reason: it had every header up to the last grid
/// point and no way to ask for the 72 blocks above it.
#[test]
fn a_target_off_the_grid_is_still_asked_for() {
    let anchor = header(0, B256::ZERO, 100);
    let target = HEADER_CHUNK * 3 + 72; // deliberately not a multiple of 192
    let (mut s, _d) = sync(&anchor, target, HeaderVerifier::new());

    let wants = s.wants(8);
    let bespoke: Vec<&Want> = wants
        .iter()
        .filter(|w| matches!(w, Want::Headers { point, .. } if *point == target))
        .collect();
    assert_eq!(bespoke.len(), 1, "the stretch above the grid must be asked for: {wants:?}");

    match bespoke[0] {
        Want::Headers { count, from, .. } => {
            assert_eq!(*count as u64, 72, "exactly the remainder above the last grid point");
            assert_eq!(*from, B256::repeat_byte(0xff), "asked for by the target's own hash");
        }
        _ => unreachable!(),
    }
}

/// A target *on* the grid is asked for by its own hash too: a skeleton names it
/// only if the peer answering reaches that far.
#[test]
fn a_target_on_the_grid_is_asked_for_by_its_own_hash_too() {
    let anchor = header(0, B256::ZERO, 100);
    let target = HEADER_CHUNK * 3;
    let (mut s, _d) = sync(&anchor, target, HeaderVerifier::new());

    let by_hash: Vec<Want> = s
        .wants(8)
        .into_iter()
        .filter(|w| matches!(w, Want::Headers { from, .. } if *from == B256::repeat_byte(0xff)))
        .collect();
    assert_eq!(
        by_hash,
        vec![Want::Headers {
            from: B256::repeat_byte(0xff),
            count: HEADER_CHUNK as u32,
            point: target,
        }],
        "the whole chunk under the target, from the target's own hash"
    );

    // Once answered it waits for the prefix, and is not asked for again.
    let top = run_of(
        HEADER_CHUNK * 2 + 1,
        HEADER_CHUNK as usize,
        B256::repeat_byte(0xaa),
        100,
        |_| Vec::new(),
    );
    s.on_headers_with_uncles(target, &top)
        .expect("internally valid");
    assert!(
        !s.wants(8)
            .iter()
            .any(|w| matches!(w, Want::Headers { point, .. } if *point == target)),
        "an answered chunk is not asked for again while it waits"
    );
}

/// A request nobody answers is asked again after it is released.
///
/// This is what actually stalled the first real run: the session released only
/// the descending walk, so during an ascent a dropped response left its
/// request outstanding for ever and the frontier stopped where it stood.
#[test]
fn a_released_request_is_asked_again() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, HEADER_CHUNK * 4, HeaderVerifier::new());
    s.on_skeleton(&[BlockIdentifier { number: HEADER_CHUNK, hash: B256::repeat_byte(1) }]);

    // The point the skeleton named. The chunk under the target is asked for
    // too, from the target's own hash, and is not what this is about.
    let headers_in = |ws: Vec<Want>| -> Vec<Want> {
        ws.into_iter()
            .filter(|w| matches!(w, Want::Headers { point, .. } if *point == HEADER_CHUNK))
            .collect()
    };

    let first = headers_in(s.wants(8));
    assert_eq!(first.len(), 1, "one known point, one header request");
    assert!(
        headers_in(s.wants(8)).is_empty(),
        "and it is not asked for again while it is outstanding"
    );

    s.release(&first[0]);
    assert_eq!(headers_in(s.wants(8)), first, "but it is once released");
}

/// A skeleton nobody answers is re-queued too, not just a header request.
#[test]
fn a_released_skeleton_is_asked_again() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, HEADER_CHUNK * 4, HeaderVerifier::new());

    let skeletons: Vec<Want> = s
        .wants(8)
        .into_iter()
        .filter(|w| matches!(w, Want::Skeleton { .. }))
        .collect();
    assert!(!skeletons.is_empty(), "a fresh ascent asks for a skeleton");

    s.release(&skeletons[0]);
    let again = s.wants(8);
    assert!(
        again.iter().any(|w| *w == skeletons[0]),
        "a released skeleton comes back round"
    );
}

/// A run that does not link gives its height back, so another peer can answer.
///
/// Dropping the run alone is not enough: the identifier that produced it is
/// also wrong, so the point and the skeleton that named it must go too, or the
/// height is unreachable for the rest of the sync.
#[test]
fn a_non_linking_run_releases_its_height() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, HEADER_CHUNK * 4, HeaderVerifier::new());
    s.on_skeleton(&[BlockIdentifier { number: HEADER_CHUNK, hash: B256::repeat_byte(1) }]);
    let _ = s.wants(8);

    // Internally consistent, but rooted somewhere this node does not trust.
    let elsewhere = run_of(1, HEADER_CHUNK as usize, B256::repeat_byte(0xaa), 100, |_| Vec::new());
    s.on_headers_with_uncles(HEADER_CHUNK, &elsewhere).expect("internally valid");
    assert_eq!(s.frontier(), 0, "it links to nothing, so the prefix stands still");

    let skeletons: Vec<Want> = s
        .wants(8)
        .into_iter()
        .filter(|w| matches!(w, Want::Skeleton { start: 0 }))
        .collect();
    assert!(
        !skeletons.is_empty(),
        "the skeleton naming that height must be asked again, or it is unreachable"
    );
}

/// A consumed run is committed, so a restart resumes instead of starting over.
///
/// The whole argument for ascending is that a chunk is permanently valuable the
/// moment it links. Keeping that only in memory throws the argument away: the
/// first run of this against mainnet stored 8.9 GB of headers and would have
/// re-fetched every one of them, because the head was still genesis.
#[test]
fn a_consumed_run_is_committed_so_the_next_start_resumes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let anchor = header(0, B256::ZERO, 100);
    store.put_header_with_hash(anchor.hash(), &anchor).expect("anchor");
    store.put_canonical_hash(0, anchor.hash()).expect("index");
    store.set_head(anchor.hash()).expect("head");

    let mut s = ForwardSync::new(
        0,
        anchor.hash(),
        U256::ZERO,
        8,
        B256::repeat_byte(0xff),
        true,
        store.clone(),
        Arc::new(HeaderVerifier::new()),
    );

    let entries = run_of(1, 4, anchor.hash(), 100, |n| {
        if n == 2 { vec![header(1, B256::repeat_byte(9), 50)] } else { Vec::new() }
    });
    s.on_headers_with_uncles(4, &entries).expect("honest run");
    assert_eq!(s.frontier(), 4);

    // The canonical index names every block of the run...
    for e in entries.iter() {
        assert_eq!(
            store.canonical_hash(e.header.number).unwrap(),
            Some(e.header.hash()),
            "#{} must be indexed once the prefix reaches it",
            e.header.number
        );
    }

    // ...and the head and the work moved with it, which is what the next start
    // reads to know where to pick up.
    let head = store.head().unwrap().expect("a head");
    assert_eq!(head, entries[0].header.hash(), "the head is the top of the proven prefix");
    assert_eq!(
        store.total_difficulty(head).unwrap(),
        Some(U256::from(4 * 100 + 50)),
        "and carries the work counted so far, uncles included"
    );
}

/// Every block of a committed run gets its own total difficulty: its parent's
/// plus its own difficulty and its uncles', as rskj's
/// `BlockChainImpl.internalTryToConnect` gives every block it connects. The
/// BlockHeader contract's `getCumulativeWork` reads it for any of the last
/// 4,000 blocks and stops the node at a block without one, and the commit used
/// to write the newest block's alone.
#[test]
fn every_committed_block_gets_its_own_total() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let anchor = header(0, B256::ZERO, 100);

    let mut s = ForwardSync::new(
        0,
        anchor.hash(),
        U256::from(1_000),
        8,
        B256::repeat_byte(0xff),
        true,
        store.clone(),
        Arc::new(HeaderVerifier::new()),
    );

    // An uncle worth 50 on #2 and one worth 30 on #6. The upper run arrives
    // first and waits, so both are consumed in one pass, each from where the
    // one below it ended.
    let lower = run_of(1, 4, anchor.hash(), 100, |n| {
        if n == 2 {
            vec![header(1, B256::repeat_byte(9), 50)]
        } else {
            Vec::new()
        }
    });
    let upper = run_of(5, 4, lower[0].header.hash(), 100, |n| {
        if n == 6 {
            vec![header(5, B256::repeat_byte(7), 30)]
        } else {
            Vec::new()
        }
    });
    s.on_headers_with_uncles(8, &upper)
        .expect("internally valid");
    assert_eq!(s.frontier(), 0, "the upper run waits for the lower one");
    s.on_headers_with_uncles(4, &lower).expect("honest run");
    assert_eq!(s.frontier(), 8);

    let mut blocks: Vec<&Header> = lower.iter().chain(&upper).map(|e| &e.header).collect();
    blocks.sort_by_key(|h| h.number);
    let totals = [1_100u64, 1_250, 1_350, 1_450, 1_550, 1_680, 1_780, 1_880];
    for (block, total) in blocks.into_iter().zip(totals) {
        assert_eq!(
            store.total_difficulty(block.hash()).unwrap(),
            Some(U256::from(total)),
            "#{} carries its parent's total plus its own work",
            block.number
        );
    }
}

/// A run that has not linked yet is *not* committed.
///
/// Until it links it is only a peer's word, and publishing it would put an
/// unproven chain in the canonical index for everything else to read.
#[test]
fn an_unlinked_run_is_not_committed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let anchor = header(0, B256::ZERO, 100);

    let mut s = ForwardSync::new(
        0,
        anchor.hash(),
        U256::ZERO,
        8,
        B256::repeat_byte(0xff),
        true,
        store.clone(),
        Arc::new(HeaderVerifier::new()),
    );

    // Rooted somewhere this node does not trust: internally valid, never links.
    let elsewhere = run_of(1, 4, B256::repeat_byte(0xaa), 100, |_| Vec::new());
    s.on_headers_with_uncles(4, &elsewhere).expect("internally valid");

    assert_eq!(s.frontier(), 0, "the prefix does not move");
    assert_eq!(
        store.canonical_hash(1).unwrap(),
        None,
        "and nothing unproven reaches the canonical index"
    );
    assert_eq!(store.head().unwrap(), None, "nor the head");
}

/// A gap the skeleton never covered is bridged from the run above it.
///
/// The prefix can only absorb a run beginning at `have + 1`, which needs a
/// point exactly 192 above. If that one point never arrives, every run above is
/// misaligned by 192 and none of them can ever link: they pile up marked
/// satisfied, `wants` empties, and the sync stops with a peer still connected
/// and no error. The mainnet run of 2026-10-05 sat at #9,281,664 for three
/// hours that way, 3,336 blocks short of its target.
///
/// Every run carries its oldest header's parent hash, which is the one hash
/// known for the block below it. That is the way out.
#[test]
fn a_gap_the_skeleton_missed_is_bridged_from_the_run_above() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, HEADER_CHUNK * 4, HeaderVerifier::new());

    // Build two chunks, but only ever tell the sync about the upper one --
    // as if the skeleton naming the lower point was lost.
    let lower = run_of(1, HEADER_CHUNK as usize, anchor.hash(), 100, |_| Vec::new());
    let lower_top = lower[0].header.hash();
    let upper = run_of(
        HEADER_CHUNK + 1,
        HEADER_CHUNK as usize,
        lower_top,
        100,
        |_| Vec::new(),
    );

    s.on_skeleton(&[BlockIdentifier {
        number: HEADER_CHUNK * 2,
        hash: upper[0].header.hash(),
    }]);
    let _ = s.wants(8);
    s.on_headers_with_uncles(HEADER_CHUNK * 2, &upper).expect("internally valid");

    // It cannot link -- its oldest is #193, the prefix is at #0.
    assert_eq!(s.frontier(), 0, "the upper run is 192 blocks too high to absorb");

    // The sync must still have something to ask for: the bridge, addressed by
    // the upper run's oldest parent.
    let bridge: Vec<Want> = s
        .wants(8)
        .into_iter()
        .filter(|w| matches!(w, Want::Headers { from, .. } if *from == upper.last().unwrap().header.parent_hash))
        .collect();
    assert_eq!(
        bridge.len(),
        1,
        "the gap below an unlinked run must be asked for, or the sync stops dead"
    );
    match bridge[0] {
        Want::Headers { count, point, .. } => {
            assert_eq!(point, HEADER_CHUNK, "the block immediately below the stranded run");
            assert_eq!(count as u64, HEADER_CHUNK, "closing as much of the gap as a chunk allows");
        }
        _ => unreachable!(),
    }

    // And once it lands, everything above it absorbs in one go.
    s.on_headers_with_uncles(HEADER_CHUNK, &lower).expect("the bridge");
    assert_eq!(
        s.frontier(),
        HEADER_CHUNK * 2,
        "the bridge links the prefix through both runs"
    );
}

/// A peer still behind the target does not stop the ascent.
///
/// Its skeleton ends at its own best block, below the target, so nothing names
/// a block above that, and the run asked for from the best block itself lies
/// across the grid the prefix climbs by. With the target on the grid the ascent
/// was then left with no point above its prefix, no run to bridge down from,
/// and nothing to ask for. The chunk under the target is asked for from the
/// target's own hash, and the ascent bridges down from it.
#[test]
fn a_peer_behind_the_target_does_not_stop_the_ascent() {
    let anchor = header(0, B256::ZERO, 100);
    // On the grid. The chain is newest first: `chain[k]` is block #target - k.
    let target = HEADER_CHUNK * 4;
    let chain = run_of(1, target as usize, anchor.hash(), 100, |_| Vec::new());
    let at = |number: u64| chain[(target - number) as usize].header.hash();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let mut s = ForwardSync::new(
        0,
        anchor.hash(),
        U256::ZERO,
        target,
        at(target),
        true,
        store,
        Arc::new(HeaderVerifier::new()),
    );

    // The peer's best block is #400: its skeleton names the grid points under
    // it and then #400 itself, as rskj's `processSkeletonRequest` builds one.
    let skeleton: Vec<BlockIdentifier> = [HEADER_CHUNK, 2 * HEADER_CHUNK, 400]
        .into_iter()
        .map(|number| BlockIdentifier {
            number,
            hash: at(number),
        })
        .collect();

    for _ in 0..32 {
        let wants = s.wants(8);
        if wants.is_empty() {
            break;
        }
        for want in wants {
            match want {
                Want::Skeleton { .. } => s.on_skeleton(&skeleton),
                Want::Headers { from, count, point } => {
                    let newest = chain
                        .iter()
                        .position(|e| e.header.hash() == from)
                        .expect("a block of the chain");
                    let end = (newest + count as usize).min(chain.len());
                    s.on_headers_with_uncles(point, &chain[newest..end])
                        .expect("honest run");
                }
            }
        }
    }
    assert_eq!(s.frontier(), target, "the ascent reaches the target");
    assert!(s.done());
}

/// The uncle-reuse ledger is a window, not a ledger.
///
/// Consensus lets a block reference an uncle only within
/// `UNCLE_GENERATION_LIMIT` generations of it, so nothing older can ever
/// collide. Keeping every hash instead is one `B256` per uncle for the whole
/// chain -- on mainnet about 8.4 million of them.
#[test]
fn the_uncle_ledger_does_not_grow_with_the_chain() {
    let anchor = header(0, B256::ZERO, 100);
    let (mut s, _d) = sync(&anchor, 400, HeaderVerifier::new());

    // 400 blocks, each referencing its own distinct uncle.
    let entries = run_of(1, 400, anchor.hash(), 100, |n| {
        vec![header(n - 1, B256::repeat_byte((n % 251) as u8), 50)]
    });
    s.on_headers_with_uncles(400, &entries).expect("honest run");
    assert_eq!(s.frontier(), 400);

    assert!(
        s.counted_uncles_len() <= 64,
        "the ledger must stay inside the consensus window, not grow with the \
         chain; held {} after 400 blocks",
        s.counted_uncles_len()
    );
}

/// Uncles are kept, not merely counted.
///
/// They arrive once, over the wire, and nothing else will ever hand them to a
/// node with no bodies. Dropping them leaves a node that cannot sum its own
/// chain's work and cannot serve `rsk/63` — that is, cannot serve the sync it
/// just performed. The first ascending sync against mainnet produced exactly
/// that: 9.28M headers on disk and no uncles, unusable as a server.
#[test]
fn committed_uncles_reach_the_freezer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    let fdir = dir.path().join("freezer");
    let freezer = Arc::new(
        rustock_storage::freezer::Freezer::open(&fdir).expect("freezer"),
    );
    store.set_freezer(freezer.clone());

    let anchor = header(0, B256::ZERO, 100);
    store.put_header_with_hash(anchor.hash(), &anchor).expect("anchor");
    store.set_head(anchor.hash()).expect("head");

    // A target far enough above that the run sits below the freeze horizon.
    let target = rustock_storage::freezer::FREEZE_DEPTH + 1_000;
    let mut s = ForwardSync::new(
        0,
        anchor.hash(),
        U256::ZERO,
        target,
        B256::repeat_byte(0xff),
        true,
        store.clone(),
        Arc::new(HeaderVerifier::new()),
    );

    let the_uncle = header(1, B256::repeat_byte(7), 50);
    let entries = run_of(1, 4, anchor.hash(), 100, |n| {
        if n == 2 { vec![the_uncle.clone()] } else { Vec::new() }
    });
    s.on_headers_with_uncles(4, &entries).expect("honest run");
    assert_eq!(s.frontier(), 4);

    let stored = freezer.uncles(2).expect("read").expect("block #2 was frozen");
    assert_eq!(stored.len(), 1, "the uncle #2 referenced must be on disk");
    assert_eq!(
        stored[0].hash(),
        the_uncle.hash(),
        "and it must be the one that arrived, byte for byte"
    );

    // A block that referenced none records an empty list, which is not the
    // same answer as "not frozen".
    assert_eq!(
        freezer.uncles(3).expect("read"),
        Some(Vec::new()),
        "no uncles is a recorded fact, not a gap"
    );
}
