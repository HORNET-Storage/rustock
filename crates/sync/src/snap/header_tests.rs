//! The pipelined header walk, and what it refuses.
//!
//! The walk is what makes a checkpoint worth downloading state for, so these
//! are written from the attacker's side: a skeleton that points at the wrong
//! chain, a run that does not link, a chain back to a genesis nobody has seen.

use super::headers::{HeaderWalk, Want, WalkError, HEADER_CHUNK};
use alloy_primitives::{Address, B256, U256};
use rustock_core::validation::{HeaderValidator, HeaderVerifier, ValidationError};
use rustock_core::Header;
use rustock_networking::protocol::BlockIdentifier;
use rustock_storage::BlockStore;
use std::sync::Arc;

fn header(number: u64, parent: B256) -> Header {
    Header {
        parent_hash: parent,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::repeat_byte(4),
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::from(100u64),
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
    }
}

/// A chain of `n+1` headers, 0..=n, each linked to the last.
fn chain(n: u64) -> Vec<Header> {
    let mut out = vec![header(0, B256::ZERO)];
    for i in 1..=n {
        let parent = out[(i - 1) as usize].hash();
        out.push(header(i, parent));
    }
    out
}

struct Fixture {
    store: Arc<BlockStore>,
    chain: Vec<Header>,
    _dir: tempfile::TempDir,
}

/// A node that knows only its genesis, and a chain it has never seen.
fn fixture(n: u64) -> Fixture {
    fixture_of(chain(n))
}

/// The same, with a chain of any shape.
fn fixture_of(chain: Vec<Header>) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));

    // As `setup_genesis` records it: genesis's total difficulty is its own.
    let genesis = &chain[0];
    store.put_header_with_hash(genesis.hash(), genesis).expect("genesis");
    store.put_total_difficulty(genesis.hash(), genesis.difficulty).expect("td");
    store.put_canonical_hash(0, genesis.hash()).expect("index");

    Fixture { store, chain, _dir: dir }
}

impl Fixture {
    fn walk(&self, top: u64, verifier: HeaderVerifier) -> HeaderWalk {
        HeaderWalk::new(
            self.chain[top as usize].clone(),
            self.store.clone(),
            Arc::new(verifier),
        )
    }

    /// What an honest peer answers a skeleton request with.
    fn skeleton(&self, start: u64) -> Vec<BlockIdentifier> {
        let mut out = Vec::new();
        let mut n = (start / HEADER_CHUNK) * HEADER_CHUNK;
        for _ in 0..20 {
            if n as usize >= self.chain.len() {
                break;
            }
            out.push(BlockIdentifier { hash: self.chain[n as usize].hash(), number: n });
            n += HEADER_CHUNK;
        }
        out
    }

    /// What an honest peer answers a header request with: newest first.
    fn headers(&self, point: u64, count: u32) -> Vec<Header> {
        let mut out = Vec::new();
        let mut n = point as i64;
        for _ in 0..count {
            if n < 0 {
                break;
            }
            out.push(self.chain[n as usize].clone());
            n -= 1;
        }
        out
    }

    /// Drive a walk to completion against honest answers, returning how many
    /// requests it took and the most it ever had outstanding.
    fn run(&self, walk: &mut HeaderWalk, budget: usize) -> (usize, usize) {
        let mut requests = 0;
        let mut widest = 0;
        for _ in 0..10_000 {
            if walk.is_done() {
                break;
            }
            let wants = walk.wants(budget);
            if wants.is_empty() {
                break;
            }
            widest = widest.max(wants.len());
            requests += wants.len();
            for want in wants {
                match want {
                    Want::Skeleton { start } => walk.on_skeleton(&self.skeleton(start)),
                    Want::Headers { point, count, .. } => {
                        walk.on_headers(point, &self.headers(point, count), &Default::default()).expect("honest")
                    }
                }
            }
            walk.advance().expect("honest answers link");
        }
        (requests, widest)
    }

    /// The same honest drive, recording every request and where the walk's
    /// frontier stood when it was made.
    fn run_logged(&self, walk: &mut HeaderWalk, budget: usize) -> Vec<(u64, Want)> {
        let mut log = Vec::new();
        for _ in 0..10_000 {
            if walk.is_done() {
                break;
            }
            let wants = walk.wants(budget);
            if wants.is_empty() {
                break;
            }
            let frontier = walk.frontier();
            for want in wants {
                log.push((frontier, want));
                match want {
                    Want::Skeleton { start } => walk.on_skeleton(&self.skeleton(start)),
                    Want::Headers { point, count, .. } => {
                        walk.on_headers(point, &self.headers(point, count), &Default::default()).expect("honest")
                    }
                }
            }
            walk.advance().expect("honest answers link");
        }
        log
    }
}

/// A chain of the same shape as `chain(n)` from a different genesis, so that
/// every hash differs while each run of it is internally perfect.
fn another_chain(n: u64) -> Vec<Header> {
    let mut out = vec![header(0, B256::repeat_byte(0x99))];
    for i in 1..=n {
        let parent = out[(i - 1) as usize].hash();
        out.push(header(i, parent));
    }
    out
}

/// A chain of `n+1` headers, 0..=n, whose block `i` has the difficulty and
/// uncle count that `shape(i)` gives.
fn shaped_chain(n: u64, shape: impl Fn(u64) -> (u64, u64)) -> Vec<Header> {
    let mut out = vec![header(0, B256::ZERO)];
    for i in 1..=n {
        let mut next = header(i, out[(i - 1) as usize].hash());
        let (difficulty, uncles) = shape(i);
        next.difficulty = U256::from(difficulty);
        next.uncle_count = uncles;
        out.push(next);
    }
    out
}

/// The most the uncles of `blocks` can weigh under rskj's rules: each hangs
/// from the trunk two to seven blocks below the block that includes it, with at
/// most its parent's difficulty and a fiftieth more.
fn heaviest_uncles(chain: &[Header], blocks: std::ops::RangeInclusive<usize>) -> U256 {
    let mut total = U256::ZERO;
    for n in blocks {
        let parents = n.saturating_sub(7)..=n.saturating_sub(2);
        let heaviest = chain[parents].iter().map(|h| h.difficulty).max().expect("a parent");
        total += U256::from(chain[n].uncle_count) * (heaviest + heaviest / U256::from(50u64));
    }
    total
}

fn sum(headers: &[Header]) -> U256 {
    headers.iter().fold(U256::ZERO, |sum, h| sum + h.difficulty)
}

#[test]
fn an_honest_walk_reaches_our_genesis() {
    for top in [1u64, 191, 192, 193, 500, 2000] {
        let f = fixture(top);
        let mut walk = f.walk(top, HeaderVerifier::new());
        f.run(&mut walk, 8);
        assert!(walk.is_done(), "top={top}: the walk did not anchor");
        assert_eq!(walk.frontier(), 0, "top={top}: did not reach genesis");
    }
}

/// **The point of the change.** More than one request goes out at a time,
/// which the serial walk could never do.
#[test]
fn the_walk_asks_for_many_things_at_once() {
    let f = fixture(4000);
    let mut walk = f.walk(4000, HeaderVerifier::new());
    let (_, widest) = f.run(&mut walk, 8);
    assert!(walk.is_done());
    assert!(widest >= 8, "only {widest} requests were ever in flight at once");
}

/// **A skeleton identifier is never believed.** It says where to ask; a run
/// that does not link is discarded however confidently it was pointed at.
///
/// The fork is offered at exactly the height the walk is waiting for, so this
/// tests the rejection rather than the walk merely not having got there.
#[test]
fn a_skeleton_pointing_at_another_chain_does_not_move_the_walk() {
    let f = fixture(1000);

    // A different chain of the same shape: different genesis, so every hash
    // below differs, but each run is internally perfect.
    let mut forked = chain(1000);
    forked[0] = header(0, B256::repeat_byte(0x99));
    for i in 1..=1000usize {
        let parent = forked[i - 1].hash();
        forked[i] = header(i as u64, parent);
    }
    assert_ne!(forked[960].hash(), f.chain[960].hash());

    let mut walk = f.walk(1000, HeaderVerifier::new());

    // Take the honest run above the grid, so the walk is now waiting for the
    // header at 960 and naming the hash it must have.
    walk.on_headers(1000, &f.headers(1000, (1000 - 960) as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");
    assert_eq!(walk.frontier(), 960, "the walk should be waiting at the grid top");

    // Now answer 960 from the fork: right height, wrong chain.
    let run: Vec<Header> = (769..=960).rev().map(|i| forked[i as usize].clone()).collect();
    walk.on_headers(960, &run, &Default::default()).expect("internally valid");
    walk.advance().expect("no error, just no progress");

    assert_eq!(walk.frontier(), 960, "a foreign run moved the walk");
    assert!(!walk.is_done());

    // And the honest run for the same height is still accepted afterwards.
    walk.on_headers(960, &f.headers(960, HEADER_CHUNK as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");
    assert_eq!(walk.frontier(), 768, "the honest run was not taken after the fork");
}

/// A run whose headers do not link to each other is refused outright.
#[test]
fn a_run_that_is_not_a_chain_is_refused() {
    let f = fixture(500);
    let mut walk = f.walk(500, HeaderVerifier::new());

    let mut run = f.headers(384, 192);
    run[5] = header(379, B256::repeat_byte(0x55));

    assert!(matches!(
        walk.on_headers(384, &run, &Default::default()),
        Err(WalkError::BrokenChunk { point: 384 })
    ));
}

/// Refuses everything, standing in for proof of work failing.
struct RefuseEverything;

impl HeaderValidator for RefuseEverything {
    fn validate(&self, _header: &Header) -> Result<(), ValidationError> {
        Err(ValidationError::BitcoinPowInvalid { hash: B256::ZERO, target: U256::ZERO })
    }
}

/// Every header still faces the full consensus rules. Pipelining changes when
/// the questions are asked, not which answers are accepted.
#[test]
fn every_header_is_still_validated() {
    let f = fixture(500);
    let mut walk = f.walk(500, HeaderVerifier::new().with_static_rule(RefuseEverything));

    assert!(matches!(
        walk.on_headers(384, &f.headers(384, 192), &Default::default()),
        Err(WalkError::InvalidHeader { .. })
    ));
}

/// A chain that links all the way down to a genesis this node has never seen
/// is refused, not accepted for having reached the bottom.
#[test]
fn a_foreign_genesis_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(BlockStore::open(dir.path()).expect("open"));
    // This node has a genesis, but not the one the chain leads to.
    let ours = header(0, B256::repeat_byte(0x11));
    store.put_header_with_hash(ours.hash(), &ours).expect("genesis");
    store.put_canonical_hash(0, ours.hash()).expect("index");

    let theirs = chain(300);
    let f = Fixture { store: store.clone(), chain: theirs, _dir: dir };
    let mut walk = f.walk(300, HeaderVerifier::new());

    let mut error = None;
    for _ in 0..200 {
        if walk.is_done() {
            break;
        }
        let wants = walk.wants(8);
        if wants.is_empty() {
            break;
        }
        for want in wants {
            match want {
                Want::Skeleton { start } => walk.on_skeleton(&f.skeleton(start)),
                Want::Headers { point, count, .. } => {
                    walk.on_headers(point, &f.headers(point, count), &Default::default()).expect("valid")
                }
            }
        }
        if let Err(e) = walk.advance() {
            error = Some(e);
            break;
        }
    }

    assert_eq!(error, Some(WalkError::ForeignGenesis), "walked into another network");
    assert!(!walk.is_done());
}

/// A released request comes back to be asked again, so a peer that never
/// answers costs a retry rather than the walk.
#[test]
fn a_released_request_is_asked_again() {
    let f = fixture(2000);
    let mut walk = f.walk(2000, HeaderVerifier::new());

    let first = walk.wants(4);
    assert!(!first.is_empty());
    for want in &first {
        walk.release(want);
    }
    let again = walk.wants(4);
    assert_eq!(again.len(), first.len(), "released work was not offered again");
}

/// Answers may arrive in any order; the walk links what it can and waits for
/// the rest.
#[test]
fn answers_may_arrive_out_of_order() {
    let f = fixture(1000);
    let mut walk = f.walk(1000, HeaderVerifier::new());

    // Learn every point first.
    for start in (0..=960).step_by((HEADER_CHUNK * 20) as usize) {
        walk.on_skeleton(&f.skeleton(start as u64));
    }
    walk.wants(64);

    // Feed the runs bottom-up, the opposite of the order the walk needs.
    let mut points: Vec<u64> = (0..=1000).step_by(HEADER_CHUNK as usize).collect();
    points.push(1000);
    points.sort_unstable();
    for point in points {
        if point == 0 {
            continue;
        }
        let count = if point == 1000 { 1000 - 960 } else { HEADER_CHUNK };
        let _ = walk.on_headers(point, &f.headers(point, count as u32), &Default::default());
    }
    walk.advance().expect("links");

    assert!(walk.is_done(), "out-of-order answers did not assemble");
}
/// The walk stops at the first block this node already holds, which on a node
/// that already has part of the chain is not genesis.
///
/// `walked_difficulty` is then the work of the walked *segment* only. The
/// claim it gets checked against -- a peer's cumulative difficulty at the
/// checkpoint -- is measured from genesis, so the two are different quantities
/// and comparing them directly refuses an honest peer by everything this node
/// already had below the anchor. On a real node that is nearly the whole chain.
#[test]
fn the_established_difficulty_counts_from_genesis_not_from_the_anchor() {
    let f = fixture(1000);

    // This node already holds the chain up to the grid point at #768, with the
    // total difficulties it established for it.
    let anchor = 768u64;
    let mut td = U256::from(100u64); // genesis
    for i in 1..=anchor as usize {
        let h = &f.chain[i];
        td += h.difficulty;
        f.store.put_header_with_hash(h.hash(), h).expect("header");
        f.store.put_canonical_hash(h.number, h.hash()).expect("index");
        f.store.put_total_difficulty(h.hash(), td).expect("td");
    }
    let anchor_td = td;

    let mut walk = f.walk(1000, HeaderVerifier::new());
    assert_eq!(walk.established_difficulty(), None, "nothing is established yet");

    walk.on_headers(1000, &f.headers(1000, (1000 - 960) as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");
    walk.on_headers(960, &f.headers(960, HEADER_CHUNK as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");

    assert!(walk.is_done(), "the walk should have anchored at #{anchor}");

    let walked = walk.walked_difficulty();
    let established = walk.established_difficulty().expect("anchored");

    assert_eq!(
        established,
        anchor_td + walked,
        "established work must include what this node already had at the anchor"
    );
    assert!(
        established > walked * U256::from(3),
        "the segment walked ({walked}) is a small part of the work established \
         ({established}); using it alone would refuse an honest peer"
    );
}

/// **Top down.** The walk descends from the checkpoint, so it asks for the
/// skeletons from the top down, and its frontier comes a good part of the way
/// before it asks for the bottom of the chain.
///
/// Asked for from genesis up, the frontier could not move until everything
/// had arrived: on mainnet, 0.0% for the two hours of the walk.
#[test]
fn the_walk_asks_from_the_top_down() {
    let f = fixture(20_000);
    let mut walk = f.walk(20_000, HeaderVerifier::new());
    let log = f.run_logged(&mut walk, 4);
    assert!(walk.is_done());

    let starts: Vec<u64> = log
        .iter()
        .filter_map(|(_, w)| match w {
            Want::Skeleton { start } => Some(*start),
            Want::Headers { .. } => None,
        })
        .collect();
    assert_eq!(starts.first(), Some(&19_200), "the first skeleton is the one under the checkpoint");
    assert!(starts.windows(2).all(|w| w[0] > w[1]), "not asked from the top down: {starts:?}");

    let (frontier, _) = log
        .iter()
        .find(|(_, w)| *w == Want::Skeleton { start: 0 })
        .expect("the bottom is asked for in the end");
    assert!(
        *frontier < 20_000 * 2 / 3,
        "the frontier was still at #{frontier} when the bottom of the chain was asked for"
    );
}

/// **Nothing is fetched twice.** A stretch that has linked is behind the
/// frontier, and the walk never asks for it again.
#[test]
fn a_linked_stretch_is_never_asked_for_again() {
    let f = fixture(20_000);
    let mut walk = f.walk(20_000, HeaderVerifier::new());
    let log = f.run_logged(&mut walk, 8);
    assert!(walk.is_done());

    let mut asked = std::collections::HashSet::new();
    for (_, want) in &log {
        if let Want::Headers { point, .. } = want {
            assert!(asked.insert(*point), "#{point} was asked for twice");
        }
    }
    // Every grid point above genesis, and the checkpoint's own stretch.
    assert_eq!(asked.len() as u64, 20_000 / HEADER_CHUNK + 1);
}

/// **The frontier is never lost.** A peer answers the walk's frontier from
/// another chain. The run does not link and is dropped, and the walk asks for
/// that height again, from the hash its own chain names for it, which no
/// peer chose. Once nothing asked for it again, and the walk stopped there.
#[test]
fn a_frontier_answered_from_another_chain_is_asked_for_again() {
    let f = fixture(1000);
    let forked = another_chain(1000);
    let mut walk = f.walk(1000, HeaderVerifier::new());
    walk.on_headers(1000, &f.headers(1000, (1000 - 960) as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");
    assert_eq!(walk.frontier(), 960);

    let frontier = Want::Headers { from: f.chain[960].hash(), count: HEADER_CHUNK as u32, point: 960 };
    assert!(walk.wants(8).contains(&frontier), "the walk asks for its frontier from the hash it holds");

    // Right height, wrong chain.
    let run: Vec<Header> = (769..=960).rev().map(|i| forked[i as usize].clone()).collect();
    walk.on_headers(960, &run, &Default::default()).expect("internally valid");
    walk.advance().expect("no error, just no progress");
    assert_eq!(walk.frontier(), 960, "a foreign run moved the walk");

    assert!(walk.wants(8).contains(&frontier), "the frontier was not asked for again");
    walk.on_headers(960, &f.headers(960, HEADER_CHUNK as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");
    assert_eq!(walk.frontier(), 768);
}

/// **Work counts once, and only for the chain.** The walk adds up what each
/// run is worth, to bound the peer's claim. Counted as answers arrived, a
/// frontier answered twice from another chain before the right answer came
/// added two runs of foreign work to what the walk said it had established --
/// raising the very ceiling a claim is checked against.
#[test]
fn work_counts_once_and_only_for_the_chain() {
    let f = fixture(1000);
    let forked = another_chain(1000);
    let mut walk = f.walk(1000, HeaderVerifier::new());
    walk.on_headers(1000, &f.headers(1000, 40), &Default::default()).expect("honest");
    walk.advance().expect("links");
    let foreign: Vec<Header> = (769..=960).rev().map(|i| forked[i as usize].clone()).collect();
    for _ in 0..2 {
        walk.on_headers(960, &foreign, &Default::default()).expect("internally valid");
        walk.advance().expect("no progress, and no error");
    }
    f.run(&mut walk, 8);
    assert!(walk.is_done());

    // Genesis's own 100, and #1 to #1000 at 100 each, the checkpoint among them.
    let work = U256::from(100_100u64);
    assert_eq!(walk.established_difficulty(), Some(work));
    assert_eq!(walk.work_ceiling(U256::ZERO), Some(work), "without uncles the work is exact");
}

/// **The ceiling covers the heaviest uncles the rules allow.** rskj peers send
/// no uncles with headers, so the walk counts each block's own difficulty and
/// bounds what its uncles add: an uncle hangs from the trunk two to seven
/// blocks down, at most a fiftieth heavier than its parent. Here every block
/// from #8 has uncles, on a sawtooth trunk, so that the heaviest possible
/// parent sits anywhere in the stretch; and the trunk just below #769, the
/// bottom of the run under the checkpoint's, is ten times heavier than the
/// rest, so a bound taken from each run alone comes out under what the chain
/// can carry.
#[test]
fn the_ceiling_covers_the_heaviest_uncles_the_rules_allow() {
    let chain = shaped_chain(1000, |n| {
        let difficulty = if (762..=767).contains(&n) { 10_000_000 } else { 1_000_000 + (n % 10) * 50_000 };
        (difficulty, if n >= 8 { n % 3 } else { 0 })
    });
    let f = fixture_of(chain);
    let mut walk = f.walk(1000, HeaderVerifier::new());
    f.run(&mut walk, 8);
    assert!(walk.is_done());

    let seen = sum(&f.chain);
    let carried = seen + heaviest_uncles(&f.chain, 1..=1000);
    assert_eq!(walk.established_difficulty(), Some(seen), "the walk counts the trunk it sees");
    let ceiling = walk.work_ceiling(U256::ZERO).expect("anchored");
    assert!(ceiling >= carried, "the ceiling {ceiling} is under the {carried} the chain can carry");
    assert!(
        ceiling * U256::from(100u64) <= carried * U256::from(101u64),
        "the ceiling {ceiling} is loose against {carried}"
    );
}

/// The same where the walk anchors above genesis: the lowest uncles it walks
/// hang partly from this node's own chain under the anchor, whose heavy
/// stretch only the store can show.
#[test]
fn the_ceiling_reaches_under_the_anchor() {
    let chain = shaped_chain(1000, |n| {
        let difficulty = if (762..=767).contains(&n) { 10_000_000 } else { 1_000_000 };
        (difficulty, u64::from(n >= 8))
    });
    let f = fixture_of(chain);
    // This node already holds the chain to #768, with its totals.
    let anchor = 768usize;
    let mut td = f.chain[0].difficulty;
    for header in &f.chain[1..=anchor] {
        td += header.difficulty * U256::from(1 + header.uncle_count);
        f.store.put_header_with_hash(header.hash(), header).expect("header");
        f.store.put_canonical_hash(header.number, header.hash()).expect("index");
        f.store.put_total_difficulty(header.hash(), td).expect("td");
    }
    let mut walk = f.walk(1000, HeaderVerifier::new());
    f.run(&mut walk, 8);
    assert!(walk.is_done());

    let carried = td + sum(&f.chain[anchor + 1..]) + heaviest_uncles(&f.chain, anchor + 1..=1000);
    assert_eq!(walk.established_difficulty(), Some(td + sum(&f.chain[anchor + 1..])));
    let ceiling = walk.work_ceiling(U256::ZERO).expect("anchored");
    assert!(ceiling >= carried, "the ceiling {ceiling} is under the {carried} the chain can carry");
    assert!(
        ceiling * U256::from(100u64) <= carried * U256::from(101u64),
        "the ceiling {ceiling} is loose against {carried}"
    );
}

/// Where a header under the anchor is missing from the store, the uncles that
/// may hang from it cannot be bounded, and the walk says so rather than
/// guessing: it puts no ceiling on the claim.
#[test]
fn a_missing_header_under_the_anchor_leaves_the_uncles_unbounded() {
    let chain = shaped_chain(1000, |n| (1_000_000, u64::from(n >= 8)));
    let f = fixture_of(chain);
    // This node holds #768 as canonical, but none of the headers under it.
    let anchor = &f.chain[768];
    f.store.put_header_with_hash(anchor.hash(), anchor).expect("header");
    f.store.put_canonical_hash(768, anchor.hash()).expect("index");
    f.store.put_total_difficulty(anchor.hash(), U256::from(1_000_000_000u64)).expect("td");
    let mut walk = f.walk(1000, HeaderVerifier::new());
    // One request at a time, so that the walk asks only for its frontier and
    // never fetches, and stores, the run under the anchor itself.
    f.run(&mut walk, 1);
    assert!(walk.is_done());
    assert_eq!(walk.work_ceiling(U256::ZERO), Some(U256::MAX));
}

/// **A short answer costs a request, not the walk.** A peer may send fewer
/// headers than were asked for -- rskj stops at the first parent it lacks --
/// which leaves the frontier between grid points, where no skeleton point
/// will ever sit. The walk asks from there to the next grid point down, and
/// is back on the grid.
#[test]
fn a_short_answer_does_not_strand_the_walk() {
    let f = fixture(1000);
    let mut walk = f.walk(1000, HeaderVerifier::new());
    walk.on_headers(1000, &f.headers(1000, (1000 - 960) as u32), &Default::default()).expect("honest");
    walk.advance().expect("links");

    // 100 of the 192 asked for.
    walk.on_headers(960, &f.headers(960, 100), &Default::default()).expect("honest, if short");
    walk.advance().expect("links");
    assert_eq!(walk.frontier(), 860);

    let rest = Want::Headers { from: f.chain[860].hash(), count: 860 - 768, point: 860 };
    assert!(walk.wants(8).contains(&rest), "the walk did not ask for the rest of the stretch");
    walk.on_headers(860, &f.headers(860, 860 - 768), &Default::default()).expect("honest");
    walk.advance().expect("links");
    assert_eq!(walk.frontier(), 768, "not back on the grid");

    f.run(&mut walk, 8);
    assert!(walk.is_done());
    assert_eq!(walk.frontier(), 0);
}

/// **The anchor is the floor.** A node that already holds most of the chain
/// walks only the part above it. Asked for from genesis up, the walk began
/// with exactly the part the node had.
#[test]
fn a_walk_that_anchors_above_genesis_leaves_the_chain_below_alone() {
    let f = fixture(20_000);
    let anchor = 15_360u64;
    for h in &f.chain[1..=anchor as usize] {
        f.store.put_header_with_hash(h.hash(), h).expect("header");
        f.store.put_canonical_hash(h.number, h.hash()).expect("index");
    }

    let mut walk = f.walk(20_000, HeaderVerifier::new());
    let log = f.run_logged(&mut walk, 4);
    assert!(walk.is_done());
    assert_eq!(walk.frontier(), anchor);

    for (_, want) in &log {
        if let Want::Headers { point, .. } = want {
            assert!(*point > anchor, "asked for #{point}, which this node holds");
        }
    }
    assert!(
        !log.iter().any(|(_, w)| *w == Want::Skeleton { start: 0 }),
        "asked for the bottom of a chain this node holds"
    );
}

/// An rskj skeleton ends with the peer's best block, wherever that sits. Off
/// the grid no run from it can link, so it is never asked for.
#[test]
fn an_identifier_off_the_grid_is_not_asked_for() {
    let f = fixture(1000);
    let mut walk = f.walk(1000, HeaderVerifier::new());
    walk.on_skeleton(&[
        BlockIdentifier { number: 768, hash: f.chain[768].hash() },
        BlockIdentifier { number: 900, hash: f.chain[900].hash() },
    ]);

    let wants = walk.wants(8);
    assert!(wants.iter().any(|w| matches!(w, Want::Headers { point: 768, .. })), "{wants:?}");
    assert!(!wants.iter().any(|w| matches!(w, Want::Headers { point: 900, .. })), "{wants:?}");
}
