//! Cross-checks against rskj's own code.
//!
//! The vectors in `rskj-vectors/chunks.txt` were produced by running rskj's
//! `TrieDTO` and `TrieDTOInOrderIterator` (see `Chunk.java` beside them), so a
//! disagreement here is a disagreement with the implementation that defines
//! the format, not with a reading of it.

use rustock_trie::snapshot::total_size;
use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode};

/// The same trie the Java generator builds.
fn trie(keys: usize) -> (TrieNode, MemoryTrieStore) {
    let store = MemoryTrieStore::new();
    let mut root = TrieNode::empty();
    for i in 0..keys {
        let key = [(i >> 8) as u8, i as u8, (i * 7) as u8, (i * 13) as u8];
        let value: Vec<u8> = if i % 4 == 0 {
            (0..64u8).map(|j| j.wrapping_add(i as u8)).collect()
        } else {
            vec![i as u8, 2, 3]
        };
        root = root.put(&TrieKeySlice::from_key(&key), &value, &store);
    }
    root.save(&store, true);
    (root, store)
}

fn vectors() -> Vec<(usize, u64, String, u64)> {
    let text = include_str!("rskj-vectors/chunks.txt");
    let mut out = Vec::new();
    #[allow(unused_assignments)] // the initialiser is required; the file supplies the value
    let (mut keys, mut root, mut total) = (0usize, String::new(), 0u64);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            keys = rest.split_whitespace().next().unwrap().parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("ROOT ") {
            root = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("TOTAL ") {
            total = rest.trim().parse().unwrap();
            out.push((keys, 0, root.clone(), total));
        }
    }
    out
}

/// **The same keys must give the same trie.** If rustock and rskj disagree
/// here, nothing downstream -- offsets, chunks, proofs -- can agree either.
#[test]
fn rustock_builds_the_same_trie_as_rskj() {
    let mut checked = 0;
    for (keys, _, expected_root, expected_total) in vectors() {
        let (root, store) = trie(keys);
        let got = root.compute_hash(&store);
        assert_eq!(
            format!("{:x}", got),
            expected_root,
            "{keys} keys: rustock's root differs from rskj's"
        );
        assert_eq!(
            total_size(&root, &store),
            expected_total,
            "{keys} keys: rustock's trie size differs from rskj's"
        );
        checked += 1;
    }
    assert!(checked >= 4, "the vector file should hold several tries");
}

/// **Byte-for-byte against rskj's own encoder.**
///
/// The stripped format has two traps a careful reading of the spec would not
/// catch: an embedded child's length becomes three bytes where the consensus
/// format uses one, and a long value stops being a 32-byte reference and
/// becomes the value itself. Vectors from rskj decide the matter.
#[test]
fn stripped_nodes_match_rskj_byte_for_byte() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::strip;

    let text = include_str!("rskj-vectors/nodes.txt");
    let mut expected: std::collections::HashMap<usize, Vec<(String, String)>> =
        std::collections::HashMap::new();
    let mut keys = 0usize;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            keys = rest.trim().parse().unwrap();
        } else if line.starts_with("NODE ") {
            let field = |name: &str| -> String {
                line.split_whitespace()
                    .find_map(|t| t.strip_prefix(name))
                    .unwrap_or_default()
                    .to_string()
            };
            expected.entry(keys).or_default().push((field("source="), field("encoded=")));
        }
    }
    assert!(expected.len() >= 3, "expected vectors for several tries");

    let mut compared = 0;
    for (keys, nodes) in &expected {
        let (root, store) = trie(*keys);
        let ours = chunk_from(&root, 0, u64::MAX, &store);
        assert_eq!(
            ours.len(),
            nodes.len(),
            "{keys} keys: rustock walks {} nodes, rskj walks {}",
            ours.len(),
            nodes.len()
        );

        for (i, (entry, (src, enc))) in ours.iter().zip(nodes.iter()).enumerate() {
            // The consensus message first: if these differ, nothing else can
            // be compared meaningfully.
            assert_eq!(
                hex(&entry.message),
                *src,
                "{keys} keys, node {i}: consensus message differs from rskj's"
            );

            let stripped = strip(&entry.message, &store)
                .unwrap_or_else(|| panic!("{keys} keys, node {i}: could not strip"));
            assert_eq!(
                hex(&stripped),
                *enc,
                "{keys} keys, node {i}: stripped form differs from rskj's"
            );
            compared += 1;
        }
    }
    assert!(compared >= 50, "only {compared} nodes compared");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// **The whole chunk, byte for byte against rskj's.**
///
/// The node encoding is only half of it: the walk also decides which
/// ancestors land in which list, what counts as a node's offset, and when the
/// node straddling the far boundary is dropped. None of that is visible until
/// an rskj client rejects a chunk, so it is checked against blobs rskj
/// produced.
#[test]
fn legacy_chunks_match_rskj_byte_for_byte() {
    use rustock_trie::snapshot_legacy::legacy_chunk;

    let text = include_str!("rskj-vectors/chunks.txt");
    let (mut keys, mut from, mut to) = (0usize, 0u64, 0u64);
    let mut checked = 0;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            let f: Vec<&str> = rest.split_whitespace().collect();
            keys = f[0].parse().unwrap();
            from = f[2].parse().unwrap();
            to = f[4].parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("BLOB ") {
            let (root, store) = trie(keys);
            let root_hash: [u8; 32] = root.compute_hash(&store).into();

            let chunk = legacy_chunk(&root_hash, from, to, &store)
                .unwrap_or_else(|| panic!("{keys} keys {from}..{to}: could not build"));

            assert_eq!(
                hex(&rustock_trie::snapshot_legacy::encode_blob(&chunk)),
                rest.trim(),
                "{keys} keys, {from}..{to}: blob differs from rskj's"
            );
            checked += 1;
        }
    }
    assert!(checked >= 6, "only {checked} blobs compared");
}


/// **Reading rskj's chunks.** Take the blob rskj produced, rebuild it, and
/// require the nodes to be exactly what our own trie holds.
///
/// This is the direction that needs the child hashes rskj dropped to be
/// recomputed, and the tree shape to be derived rather than replayed. If the
/// rebuild were wrong in any way -- a hash in the wrong slot, a subtree the
/// wrong shape, a long value mis-handled -- the root would not match, and if
/// it somehow did, the messages would not.
#[test]
fn rskj_chunks_rebuild_to_the_nodes_we_hold() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{decode_blob, rebuild};

    let text = include_str!("rskj-vectors/chunks.txt");
    let (mut keys, mut from, mut to) = (0usize, 0u64, 0u64);
    let mut checked = 0;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            let f: Vec<&str> = rest.split_whitespace().collect();
            keys = f[0].parse().unwrap();
            from = f[2].parse().unwrap();
            to = f[4].parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("BLOB ") {
            let (root, store) = trie(keys);
            let root_hash = root.compute_hash(&store);

            let blob = unhex(rest.trim());
            let chunk = decode_blob(&blob)
                .unwrap_or_else(|| panic!("{keys} keys {from}..{to}: blob did not decode"));

            let rebuilt = rebuild(&chunk, root_hash)
                .unwrap_or_else(|e| panic!("{keys} keys {from}..{to}: {e}"));

            assert_eq!(rebuilt.root, root_hash);

            // Every node rebuilt must be a node the trie actually holds, and
            // hash to the key it is filed under.
            let truth: std::collections::HashMap<String, Vec<u8>> =
                chunk_from(&root, 0, u64::MAX, &store)
                    .into_iter()
                    .map(|e| (hex(&alloy_primitives::keccak256(&e.message).0), e.message))
                    .collect();

            for (hash, message) in &rebuilt.nodes {
                assert_eq!(
                    alloy_primitives::keccak256(message),
                    *hash,
                    "{keys} keys {from}..{to}: a rebuilt node does not hash to its key"
                );
                // Every rebuilt node must be one the trie really holds --
                // the stubs included, since they are ancestors of the range
                // and not inventions of the rebuild.
                let expected = truth.get(&hex(&hash.0)).unwrap_or_else(|| {
                    panic!("{keys} keys {from}..{to}: rebuilt a node the trie does not hold")
                });
                assert_eq!(
                    message, expected,
                    "{keys} keys {from}..{to}: rebuilt node differs from ours"
                );
            }

            // The chunk's own nodes must all be there, not only the stubs.
            assert!(
                rebuilt.nodes.len() >= chunk.nodes.len(),
                "{keys} keys {from}..{to}: rebuilt {} nodes from {} sent",
                rebuilt.nodes.len(),
                chunk.nodes.len()
            );
            checked += 1;
        }
    }
    assert!(checked >= 6, "only {checked} chunks rebuilt");
}

/// A chunk that does not rebuild to the expected root is refused, which is the
/// whole of the security argument for this format.
#[test]
fn a_chunk_that_rebuilds_to_the_wrong_root_is_refused() {
    use rustock_trie::snapshot_legacy::{decode_blob, rebuild, RebuildError};
    use alloy_primitives::B256;

    let text = include_str!("rskj-vectors/chunks.txt");
    let blob = text
        .lines()
        .find_map(|l| l.strip_prefix("BLOB "))
        .map(|h| unhex(h.trim()))
        .expect("a vector");
    let chunk = decode_blob(&blob).expect("decodes");

    let wrong = B256::repeat_byte(0xAB);
    match rebuild(&chunk, wrong) {
        Err(RebuildError::WrongRoot { expected, .. }) => assert_eq!(expected, wrong),
        other => panic!("a chunk verified against the wrong root: {other:?}"),
    }
}

/// Nothing an rskj peer sends may panic the rebuild.
#[test]
fn no_junk_blob_can_panic_the_rebuild() {
    use rustock_trie::snapshot_legacy::{decode_blob, rebuild};
    use alloy_primitives::B256;

    let mut seed = 0x853C49E6748FEA9Bu64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for _ in 0..4000 {
        let len = (next() % 160) as usize;
        let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if let Some(chunk) = decode_blob(&junk) {
            let _ = rebuild(&chunk, B256::repeat_byte(1));
        }
    }
}

/// Nor may any variation on a chunk an rskj node really sent, rebuilt
/// against the root it really belongs to. Random bytes seldom decode at all,
/// so these are what reach the rebuild.
#[test]
fn no_variation_on_an_rskj_chunk_can_panic_the_rebuild() {
    use rustock_trie::snapshot_legacy::{decode_blob, rebuild};

    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut next = move |below: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % below.max(1) as u64) as usize
    };
    let text = include_str!("rskj-vectors/chunks.txt");
    let mut keys = 0usize;
    let mut seeds = 0;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            keys = rest.split_whitespace().next().unwrap().parse().unwrap();
            continue;
        }
        let Some(rest) = line.strip_prefix("BLOB ") else {
            continue;
        };
        let (root, store) = trie(keys);
        let root_hash = root.compute_hash(&store);
        let blob = unhex(rest.trim());
        seeds += 1;
        for _ in 0..800 {
            let mut bytes = blob.clone();
            for _ in 0..1 + next(3) {
                let at = next(bytes.len());
                match next(6) {
                    0 if !bytes.is_empty() => bytes[at] ^= 1 << next(8),
                    1 if !bytes.is_empty() => bytes[at] = [0x00, 0x7f, 0x80, 0xff][next(4)],
                    2 if !bytes.is_empty() => bytes[at] = next(256) as u8,
                    3 => bytes.insert(at, next(256) as u8),
                    4 if !bytes.is_empty() => {
                        let n = 1 + next(8.min(bytes.len() - at));
                        bytes.drain(at..at + n);
                    }
                    _ => bytes.truncate(at),
                }
            }
            if let Some(chunk) = decode_blob(&bytes) {
                let _ = rebuild(&chunk, root_hash);
            }
        }
    }
    assert!(seeds >= 6, "only {seeds} chunks to vary");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The sizes `docs/snapshot-sync.md` states are the sizes the code computes,
/// and they are rskj's too.
///
/// A document that drifts from the code is worse than no document, and these
/// two numbers are the ones every offset in the protocol is built from.
#[test]
fn the_documented_size_formulas_hold() {
    use rustock_trie::snapshot::{chunk_from, stream_size, total_size};
    use rustock_trie::TrieStore;

    let (root, store) = trie(12);

    // total_size(root) is the whole trie, and rskj said 915 for this one.
    let total = total_size(&root, &store);
    assert_eq!(total, 915, "rskj's TrieDTO.getTotalSize() for this trie");

    // A node's offset is the sum of stream_size over everything before it,
    // and the run ends exactly at the total.
    let nodes = chunk_from(&root, 0, u64::MAX, &store);
    let mut at = 0u64;
    for entry in &nodes {
        assert_eq!(entry.offset, at, "offsets are not the running sum of stream_size");
        let node = rustock_trie::TrieNode::from_message(&entry.message, &store);
        assert_eq!(
            entry.span,
            stream_size(&node, &store),
            "a node's span is not its stream_size"
        );
        at += entry.span;
    }
    assert_eq!(at, total, "the traversal does not span the trie exactly");

    // total_size = children_size + external + message_len, as documented.
    for entry in &nodes {
        let node = rustock_trie::TrieNode::from_message(&entry.message, &store);
        let external =
            if node.has_long_value() { node.value_length() as u64 } else { 0 };
        assert_eq!(
            total_size(&node, &store),
            node.children_size + external + node.message_length(&store) as u64
        );
    }
    let _ = store.get(&[0u8; 32]);
}

/// Where a chunk's own nodes sit in rustock's traversal of the same trie: the
/// index of the first.
///
/// rskj begins a chunk with the node holding the offset asked for -- the one
/// it falls inside, or ends at -- and the chunk's stripped nodes must follow
/// from there in order. Not found by searching for the run: stripped forms
/// leave out every hash, so the same shapes repeat across a trie.
fn locate(
    chunk: &rustock_trie::snapshot_legacy::LegacyChunk,
    stream: &[rustock_trie::snapshot::StreamNode],
    store: &rustock_trie::MemoryTrieStore,
    asked: u64,
) -> usize {
    use rustock_trie::snapshot_legacy::strip;
    let k = if asked == 0 {
        0
    } else {
        stream
            .iter()
            .position(|n| n.offset < asked && asked <= n.end())
            .expect("the offset asked for is inside the trie")
    };
    for (j, body) in chunk.nodes.iter().enumerate() {
        assert_eq!(
            strip(&stream[k + j].message, store).expect("strips"),
            *body,
            "node {j} of the chunk asked at {asked} is not the trie's"
        );
    }
    k
}

/// **rskj's chunks say where they sit, without saying so.**
///
/// rskj's format carries no offsets, so a client that wants to know how far
/// a chunk reached works it out from the sizes the rebuilt tree commits to.
/// Checked against rskj's own blobs: the span must be exactly where rustock's
/// traversal puts those nodes, begin at or before the offset asked for, and
/// stop short of the end of the range asked for -- where the next chunk,
/// asked for there, begins.
#[test]
fn rskj_chunks_place_themselves_where_the_trie_has_them() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{decode_blob, rebuild};

    let text = include_str!("rskj-vectors/chunks.txt");
    let (mut keys, mut from, mut to) = (0usize, 0u64, 0u64);
    // The previous chunk of the same trie: where its range ended, and where
    // its nodes did.
    let mut previous: Option<(usize, u64, u64)> = None;
    let mut placed = 0;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            let f: Vec<&str> = rest.split_whitespace().collect();
            keys = f[0].parse().unwrap();
            from = f[2].parse().unwrap();
            to = f[4].parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("BLOB ") {
            let (root, store) = trie(keys);
            let root_hash = root.compute_hash(&store);
            let total = total_size(&root, &store);

            let chunk = decode_blob(&unhex(rest.trim())).expect("rskj's blob decodes");
            let rebuilt = rebuild(&chunk, root_hash)
                .unwrap_or_else(|e| panic!("{keys} keys {from}..{to}: {e}"));
            assert_eq!(rebuilt.total, total, "{keys} keys: the root's size");

            let (start, end) = rebuilt
                .span
                .unwrap_or_else(|| panic!("{keys} keys {from}..{to}: no span"));
            let stream = chunk_from(&root, 0, u64::MAX, &store);
            let k = locate(&chunk, &stream, &store, from);
            let last = &stream[k + chunk.nodes.len() - 1];
            assert_eq!(start, stream[k].offset, "{keys} keys {from}..{to}: where it begins");
            assert_eq!(end, last.end(), "{keys} keys {from}..{to}: where it ends");

            assert!(start <= from, "{keys} keys {from}..{to}: begins at {start}, after {from}");
            assert!(
                end < to || end == total,
                "{keys} keys {from}..{to}: runs to {end}, past the range"
            );
            if let Some((was, until, reached)) = previous {
                if was == keys && until == from {
                    assert_eq!(start, reached, "{keys} keys: {from}.. does not pick up at {reached}");
                }
            }
            previous = Some((keys, to, end));
            placed += 1;
        }
    }
    assert!(placed >= 6, "only {placed} chunks placed");
}

/// **Asked for just past where the last one stopped, rskj's chunks tile the
/// trie** -- each beginning at or before that point, the last ending at the
/// trie's end -- which is how rustock's client asks for them.
///
/// Not how rskj's own client asks. It steps by its cell, trusting the chunk
/// for `k * cell` to begin where the one before ended, and rskj's iterator
/// breaks that. An offset landing in a node's embedded right child puts the
/// walk's position at that child rather than at the node, so everything
/// after it in the chunk is counted too far along and the chunk stops short
/// of its cell. The nodes in the shortfall belong to no chunk at all. It
/// happens at mainnet's 51,200-byte cells as well, so it is rskj's own snap
/// sync that loses them; asking just past the cursor, nothing is lost: the
/// next answer begins with the node that begins there.
#[test]
fn asked_where_they_stopped_rskj_chunks_tile_the_trie() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{legacy_chunk, rebuild};

    let (root, store) = trie(400);
    let root_hash = root.compute_hash(&store);
    let root_bytes: [u8; 32] = root_hash.into();
    let total = total_size(&root, &store);
    let stream = chunk_from(&root, 0, u64::MAX, &store);

    let mut stepping_by_the_cell_loses = false;
    for cell in [300u64, 777, 1024, 5000, total] {
        let mut reached = 0u64;
        let mut asked = 0u64;
        let mut requests = 0;
        while reached < total {
            requests += 1;
            assert!(requests < 10_000, "cell {cell}: no progress from {reached}");
            let chunk = legacy_chunk(&root_bytes, asked, asked + cell, &store).expect("builds");
            let rebuilt = rebuild(&chunk, root_hash)
                .unwrap_or_else(|e| panic!("cell {cell} at {asked}: {e}"));
            let (start, end) = rebuilt
                .span
                .unwrap_or_else(|| panic!("cell {cell} at {asked}: nothing of its own"));
            assert!(start <= asked, "cell {cell} at {asked}: begins at {start}, after the offset");
            let k = locate(&chunk, &stream, &store, asked);
            assert_eq!(start, stream[k].offset, "cell {cell} at {asked}");
            assert_eq!(end, stream[k + chunk.nodes.len() - 1].end(), "cell {cell} at {asked}");
            assert!(end > reached, "cell {cell} at {asked}: no progress");
            reached = end;
            asked = reached + 1;
        }
        assert_eq!(reached, total, "cell {cell}: ran past the end");

        // rskj's own stepping, for contrast: does every node land in a chunk?
        let mut covered = 0u64;
        let mut from = 0u64;
        while from < total {
            let chunk = legacy_chunk(&root_bytes, from, from + cell, &store).expect("builds");
            if let Some((start, end)) = rebuild(&chunk, root_hash).expect("rebuilds").span {
                stepping_by_the_cell_loses |= start > covered;
                covered = covered.max(end);
            }
            from += cell;
        }
    }
    assert!(
        stepping_by_the_cell_loses,
        "rskj's stepping lost nothing here, so this trie no longer shows why the client asks where it stopped"
    );
}

/// **A chunk that leaves out a stretch is refused**, even though it rebuilds
/// to the right root.
///
/// rskj sends both hashes of a chunk's last node, so a server can drop the
/// whole left subtree of that node and the rebuild still reaches the root: the
/// hash stands in for the subtree. What it cannot keep is the arithmetic --
/// the nodes it did send no longer fill the stretch from the first to the
/// last -- and a client advancing by that stretch would mark the missing
/// subtree done.
#[test]
fn a_chunk_that_leaves_out_a_stretch_is_refused() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{legacy_chunk, rebuild, RebuildError};
    use rustock_trie::NodeRef;

    let (root, store) = trie(400);
    let root_hash = root.compute_hash(&store);
    let root_bytes: [u8; 32] = root_hash.into();
    let total = total_size(&root, &store);
    let stream = chunk_from(&root, 0, u64::MAX, &store);

    let (mut tampered_with, mut placement_caught) = (0, 0);
    for cell in [300u64, 700, 1500, 4000] {
        let mut from = 0u64;
        while from < total {
            let asked = from;
            let chunk = legacy_chunk(&root_bytes, asked, asked + cell, &store).expect("builds");
            from += cell;
            let n = chunk.nodes.len();
            if n < 2 {
                continue;
            }
            let k = locate(&chunk, &stream, &store, asked);
            let last = &stream[k + n - 1];
            let node = rustock_trie::TrieNode::from_message(&last.message, &store);
            let NodeRef::Hash(left) = node.left.clone() else { continue };
            let left_size = total_size(&NodeRef::Hash(left).resolve(&store).expect("held"), &store);
            // The last node's left subtree, wholly inside the chunk and not
            // the whole of what precedes the last node.
            let begins = last.offset - left_size;
            if stream[k].offset >= begins {
                continue;
            }
            assert_eq!(
                chunk.last.and_then(|(l, _)| l),
                Some(left.0),
                "rskj names the last node's left hash"
            );

            let mut tampered = chunk.clone();
            tampered.nodes = chunk
                .nodes
                .iter()
                .zip(&stream[k..k + n])
                .filter(|(_, s)| s.offset < begins || s.offset >= last.offset)
                .map(|(body, _)| body.clone())
                .collect();
            tampered_with += 1;
            match rebuild(&tampered, root_hash) {
                Err(RebuildError::Unplaced) => placement_caught += 1,
                Err(_) => {}
                Ok(r) => panic!(
                    "a chunk without the {left_size} bytes at {begins} was taken, spanning {:?}",
                    r.span
                ),
            }
        }
    }
    assert!(tampered_with > 0, "no chunk had a subtree to leave out");
    assert!(
        placement_caught > 0,
        "the root caught every tampering, so the placement check was never reached"
    );
}

/// **A node hung where its parent has no child is refused.** The rebuild
/// derives the tree from `children_size`, so a node appended after the
/// chunk's last becomes its right child when it is no larger -- and when the
/// last node's right child is embedded or absent, its message has no slot for
/// one, so nothing ties the new node to the root, which still matches. Kept,
/// it would be stored, and placed: it would stretch the chunk past where it
/// ends.
#[test]
fn a_node_hung_where_its_parent_has_none_is_refused() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{legacy_chunk, rebuild, strip, RebuildError};
    use rustock_trie::{NodeRef, TrieNode};

    let (root, store) = trie(400);
    let root_hash = root.compute_hash(&store);
    let root_bytes: [u8; 32] = root_hash.into();
    let total = total_size(&root, &store);
    let stream = chunk_from(&root, 0, u64::MAX, &store);
    // The smallest node there is, so that it hangs under whatever precedes it.
    let (hung, hung_size) = stream
        .iter()
        .map(|s| (s, TrieNode::from_message(&s.message, &store).children_size))
        .min_by_key(|(_, size)| *size)
        .map(|(s, size)| (strip(&s.message, &store).expect("strips"), size))
        .expect("a trie has nodes");

    let (mut tampered_with, mut dangling) = (0, 0);
    for cell in [500u64, 1300] {
        let mut from = 0u64;
        while from < total {
            let asked = from;
            let chunk = legacy_chunk(&root_bytes, asked, asked + cell, &store).expect("builds");
            from += cell;
            let n = chunk.nodes.len();
            if n == 0 || chunk.post_root.is_empty() {
                continue;
            }
            let k = locate(&chunk, &stream, &store, asked);
            let last = TrieNode::from_message(&stream[k + n - 1].message, &store);
            if matches!(last.right, NodeRef::Hash(_)) || last.children_size < hung_size {
                continue;
            }
            let mut tampered = chunk.clone();
            tampered.nodes.push(hung.clone());
            tampered_with += 1;
            match rebuild(&tampered, root_hash) {
                Err(RebuildError::Dangling { .. }) => dangling += 1,
                Err(_) => {}
                Ok(r) => panic!("a node hung where there is no child was taken, spanning {:?}", r.span),
            }
        }
    }
    assert!(tampered_with > 0, "no chunk ended in a node without a separate right child");
    assert!(dangling > 0, "the root caught every tampering, so the link check was never reached");
}

/// A trie in the shape Rootstock's state has: accounts, and under a contract's
/// account its storage to the left (`0x00`) and its code to the right (`0x80`).
///
/// The shape matters because of what embeds. A contract's code is a long
/// value whose leaf -- a one-byte path, the value's hash and length -- is small
/// enough to sit inside the account node, while two or more storage slots make
/// a subtree that cannot. So a contract's account node has a separate left and
/// an embedded right, the shape a trie of same-length keys never makes.
fn unitrie(accounts: usize) -> (TrieNode, MemoryTrieStore) {
    use alloy_primitives::{Address, B256};
    use rustock_trie::{account_key, code_key, storage_key};

    let store = MemoryTrieStore::new();
    let mut root = TrieNode::empty();
    let put = |root: TrieNode, key: Vec<u8>, value: Vec<u8>| -> TrieNode {
        root.put(&TrieKeySlice::from_key(&key), &value, &store)
    };
    for i in 0..accounts {
        let address = Address::from_word(B256::from(alloy_primitives::U256::from(i as u64 + 1)));
        // An account state: nonce and balance, well under 32 bytes.
        root = put(root, account_key(&address), vec![0xc4, (i as u8).wrapping_add(1), 0x82, 0x03, 0xe8]);
        if i % 3 == 0 {
            continue;
        }
        let code: Vec<u8> = (0..(40 + i % 90) as u8).map(|b| b.wrapping_mul(i as u8 | 1)).collect();
        root = put(root, code_key(&address), code);
        for slot in 0..(i % 6) as u64 {
            let value = vec![(slot as u8).wrapping_add(i as u8) | 1; 1 + (slot as usize * 7) % 32];
            root = put(root, storage_key(&address, &B256::from(alloy_primitives::U256::from(slot))), value);
        }
    }
    root.save(&store, true);
    (root, store)
}

/// **Any node can begin a chunk, and the chunk is placed where that node
/// sits.** A chunk's first node never brings its left subtree -- the chunk
/// names only its hash -- so where the node begins is arithmetic on
/// `children_size`, and each shape of node takes its own branch of it: a
/// separate left beside a carried right, beside an embedded right, beside
/// none. Every node of a trie is made a first node in turn.
#[test]
fn every_node_can_begin_a_chunk_where_it_sits() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{legacy_chunk, rebuild};
    use rustock_trie::{NodeRef, TrieNode};

    let kind = |child: &NodeRef| match child {
        NodeRef::Empty => "none",
        NodeRef::Hash(_) => "separate",
        NodeRef::Node(_) => "embedded",
    };
    let (root, store) = unitrie(300);
    let root_hash = root.compute_hash(&store);
    let root_bytes: [u8; 32] = root_hash.into();
    let stream = chunk_from(&root, 0, u64::MAX, &store);

    let mut shapes = std::collections::BTreeSet::new();
    for (i, entry) in stream.iter().enumerate() {
        // rskj begins a chunk with the node that ends at the offset asked.
        let asked = entry.end();
        let chunk = legacy_chunk(&root_bytes, asked, asked + 2_000, &store).expect("builds");
        let rebuilt = rebuild(&chunk, root_hash).unwrap_or_else(|e| panic!("node {i}: {e}"));
        let (start, end) = rebuilt.span.unwrap_or_else(|| panic!("node {i}: nothing of its own"));
        let k = locate(&chunk, &stream, &store, asked);
        assert_eq!(k, i, "the chunk asked at the end of node {i} begins elsewhere");
        assert_eq!(start, entry.offset, "node {i} is placed at {start}, not {}", entry.offset);
        assert_eq!(end, stream[k + chunk.nodes.len() - 1].end(), "node {i}: where the chunk ends");
        let node = TrieNode::from_message(&entry.message, &store);
        shapes.insert((kind(&node.left), kind(&node.right)));
    }
    for shape in [("separate", "separate"), ("separate", "embedded"), ("embedded", "embedded")] {
        assert!(shapes.contains(&shape), "no first node shaped {shape:?} among {shapes:?}");
    }
}

/// The long values a rebuilt chunk's nodes name -- their own, and their
/// embedded children's -- and how many of those were embedded, if each is
/// among the values the rebuild kept. Panics on one that is not.
fn long_values_named(rebuilt: &rustock_trie::snapshot_legacy::Rebuilt, what: &str) -> (usize, usize) {
    use rustock_trie::{MemoryTrieStore, NodeRef, TrieNode};
    let kept: std::collections::HashSet<[u8; 32]> =
        rebuilt.long_values.iter().map(|v| alloy_primitives::keccak256(v).0).collect();
    let nothing = MemoryTrieStore::new();
    let (mut named, mut embedded) = (0, 0);
    for (_, message) in &rebuilt.nodes {
        let node = TrieNode::try_from_message(message, &nothing).expect("a rebuilt node parses");
        let children = [&node.left, &node.right].into_iter().filter_map(|c| match c {
            NodeRef::Node(n) => Some(n.as_ref()),
            _ => None,
        });
        for (n, inside) in std::iter::once((&node, false)).chain(children.map(|n| (n, true))) {
            if n.has_long_value() {
                let hash = n.value_hash.expect("a long value is named by its hash");
                assert!(kept.contains(&hash.0), "{what}: a long value named and not kept");
                named += 1;
                embedded += usize::from(inside);
            }
        }
    }
    (named, embedded)
}

/// **Every long value a chunk names comes with it**, an embedded child's
/// included.
///
/// rskj's format inlines a long value in the stripped node that names it,
/// and an embedded child is stripped inside its parent. A rebuild that kept
/// only each node's own value left an embedded child's value behind -- and
/// on Rootstock that is a contract's code: a long value whose leaf, a one-byte
/// path with the value's hash and length, embeds in the account node.
#[test]
fn every_long_value_a_chunk_names_comes_with_it() {
    use rustock_trie::snapshot_legacy::{decode_blob, legacy_chunk, rebuild};

    // rskj's own blobs.
    let text = include_str!("rskj-vectors/chunks.txt");
    let mut keys = 0usize;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("KEYS ") {
            keys = rest.split_whitespace().next().unwrap().parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("BLOB ") {
            let (root, store) = trie(keys);
            let chunk = decode_blob(&unhex(rest.trim())).expect("decodes");
            let rebuilt = rebuild(&chunk, root.compute_hash(&store)).expect("rebuilds");
            long_values_named(&rebuilt, &format!("rskj's blob of {keys} keys"));
        }
    }

    // And a trie wide enough to embed plenty, cut every way.
    let (root, store) = trie(400);
    let root_hash = root.compute_hash(&store);
    let root_bytes: [u8; 32] = root_hash.into();
    let total = total_size(&root, &store);
    let (mut named, mut embedded) = (0, 0);
    for cell in [300u64, 1024, total] {
        let mut from = 0u64;
        while from < total {
            let chunk = legacy_chunk(&root_bytes, from, from + cell, &store).expect("builds");
            let rebuilt = rebuild(&chunk, root_hash).expect("rebuilds");
            let (n, e) = long_values_named(&rebuilt, &format!("cell {cell} at {from}"));
            named += n;
            embedded += e;
            from += cell;
        }
    }
    assert!(embedded > 0, "no embedded long value was exercised ({named} named in all)");
}

/// The Rootstock-shaped trie of [`unitrie`], with long code under some
/// contracts and long values in some storage slots, longer than the windows
/// the tests below ask with: as long as a contract's code, or a value of the
/// Bridge's storage, is against rskj's 50 KiB.
fn unitrie_with_long_values(accounts: usize) -> (TrieNode, MemoryTrieStore) {
    use alloy_primitives::{Address, B256};
    use rustock_trie::{account_key, code_key, storage_key};

    let store = MemoryTrieStore::new();
    let mut root = TrieNode::empty();
    let put = |root: TrieNode, key: Vec<u8>, value: Vec<u8>| -> TrieNode {
        root.put(&TrieKeySlice::from_key(&key), &value, &store)
    };
    for i in 0..accounts {
        let address = Address::from_word(B256::from(alloy_primitives::U256::from(i as u64 + 1)));
        root = put(
            root,
            account_key(&address),
            vec![0xc4, (i as u8).wrapping_add(1), 0x82, 0x03, 0xe8],
        );
        if i % 3 == 0 {
            continue;
        }
        let code_len = if i % 7 == 1 {
            9_000 + i * 13
        } else {
            40 + i % 90
        };
        let code: Vec<u8> = (0..code_len)
            .map(|b| (b as u8).wrapping_mul(i as u8 | 1))
            .collect();
        root = put(root, code_key(&address), code);
        for slot in 0..(i % 6) as u64 {
            let len = if slot == 0 && i % 11 == 2 {
                12_000 + i * 7
            } else {
                1 + (slot as usize * 7) % 32
            };
            let value = vec![(slot as u8).wrapping_add(i as u8) | 1; len];
            root = put(
                root,
                storage_key(&address, &B256::from(alloy_primitives::U256::from(slot))),
                value,
            );
        }
    }
    root.save(&store, true);
    (root, store)
}

/// What an rskj chunk covers, as rustock's client counts it: its own nodes,
/// and the node its walk stopped at when that follows them; with none of its
/// own, the node it stopped at, which holds the offset asked.
fn covered(rebuilt: &rustock_trie::snapshot_legacy::Rebuilt) -> Option<(u64, u64)> {
    match (rebuilt.span, rebuilt.stopped_at) {
        (Some((start, end)), Some((begins, ends))) if begins == end => Some((start, ends)),
        (None, stopped) => stopped,
        (span, _) => span,
    }
}

/// **Asked just past where the last one stopped, rskj's chunks tile any
/// trie**, nodes longer than the window included, the way rustock's client
/// asks for them: just past the cursor, the walk begins with the node that
/// begins there, and each chunk covers what [`covered`] says. The node a walk
/// stopped at is always the one after the chunk's own, where rustock's
/// traversal has it.
#[test]
fn asked_just_past_where_they_stopped_rskj_chunks_tile_any_trie() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{legacy_chunk, rebuild};

    let tries = [
        (
            "rskj's generator's",
            trie(400),
            vec![300u64, 777, 1024, 5000],
        ),
        ("Rootstock-shaped", unitrie(300), vec![300, 777, 1024, 5000]),
        (
            "with long values",
            unitrie_with_long_values(200),
            vec![2_000, 5_000],
        ),
    ];
    for (name, (root, store), cells) in tries {
        let root_hash = root.compute_hash(&store);
        let root_bytes: [u8; 32] = root_hash.into();
        let total = total_size(&root, &store);
        let stream = chunk_from(&root, 0, u64::MAX, &store);
        for cell in cells.into_iter().chain([total]) {
            let (mut reached, mut requests) = (0u64, 0);
            while reached < total {
                requests += 1;
                assert!(
                    requests < 10_000,
                    "{name}, cell {cell}: no progress from {reached}"
                );
                let asked = if reached == 0 { 0 } else { reached + 1 };
                let chunk = legacy_chunk(&root_bytes, asked, asked + cell, &store).expect("builds");
                let rebuilt = rebuild(&chunk, root_hash)
                    .unwrap_or_else(|e| panic!("{name}, cell {cell} at {asked}: {e}"));
                if let Some((begins, ends)) = rebuilt.stopped_at {
                    let at = stream.iter().position(|n| n.offset == begins).unwrap_or_else(|| {
                        panic!("{name}, cell {cell} at {asked}: stopped at {begins}, where no node begins")
                    });
                    assert_eq!(
                        stream[at].end(),
                        ends,
                        "{name}, cell {cell} at {asked}: where it ends"
                    );
                    if let Some((_, end)) = rebuilt.span {
                        assert_eq!(
                            begins, end,
                            "{name}, cell {cell} at {asked}: not the node after the chunk's own"
                        );
                    }
                }
                let (start, end) = covered(&rebuilt)
                    .unwrap_or_else(|| panic!("{name}, cell {cell} at {asked}: nothing at all"));
                assert!(
                    start <= reached,
                    "{name}, cell {cell} at {asked}: a gap from {reached} to {start}"
                );
                assert!(end > reached, "{name}, cell {cell} at {asked}: no progress");
                reached = end;
            }
            assert_eq!(reached, total, "{name}, cell {cell}: ran past the end");
        }
    }
}

/// **A node longer than the window arrives whole where the walk stops.** Asked
/// where it begins, rskj's chunk is only the node that ends there, when that
/// one is short; asked inside it, a window or more from its end, nothing of
/// its own. Either way it stopped at the long node, which leads the nodes it
/// hands back, and the rebuild places it. With nothing of its own, the long
/// node takes the first node's left hash, without which a contract's account
/// over its storage, with its long code inside it, would not rebuild.
#[test]
fn a_node_longer_than_the_window_arrives_whole_where_the_walk_stops() {
    use rustock_trie::snapshot::chunk_from;
    use rustock_trie::snapshot_legacy::{legacy_chunk, rebuild};
    use rustock_trie::NodeRef;

    let (root, store) = unitrie_with_long_values(200);
    let root_hash = root.compute_hash(&store);
    let root_bytes: [u8; 32] = root_hash.into();
    let stream = chunk_from(&root, 0, u64::MAX, &store);
    let cell = 2_000u64;

    let (mut long, mut after_short, mut over_storage) = (0, 0, 0);
    for (i, node) in stream
        .iter()
        .enumerate()
        .filter(|(i, n)| *i > 0 && n.span > cell)
    {
        long += 1;
        let parsed = TrieNode::from_message(&node.message, &store);
        over_storage += usize::from(matches!(parsed.left, NodeRef::Hash(_)));

        if stream[i - 1].span < cell {
            after_short += 1;
            let at_start =
                legacy_chunk(&root_bytes, node.offset, node.offset + cell, &store).expect("builds");
            let rebuilt =
                rebuild(&at_start, root_hash).unwrap_or_else(|e| panic!("at {}: {e}", node.offset));
            assert_eq!(
                rebuilt.span.map(|(_, end)| end),
                Some(node.offset),
                "asked at {}",
                node.offset
            );
            assert_eq!(
                rebuilt.stopped_at,
                Some((node.offset, node.end())),
                "asked at {}",
                node.offset
            );
        }

        let inside = node.offset + node.span - cell;
        let within = legacy_chunk(&root_bytes, inside, inside + cell, &store).expect("builds");
        assert!(
            within.nodes.is_empty(),
            "asked at {inside}, inside the node at {}",
            node.offset
        );
        let rebuilt = rebuild(&within, root_hash).unwrap_or_else(|e| panic!("at {inside}: {e}"));
        assert_eq!(rebuilt.span, None);
        assert_eq!(
            rebuilt.stopped_at,
            Some((node.offset, node.end())),
            "asked at {inside}"
        );
    }
    assert!(
        long >= 10 && after_short >= 5,
        "only {long} nodes longer than the window, {after_short} after a short one"
    );
    assert!(
        over_storage > 0,
        "no long node with a separate left child: the left hash went untested"
    );
}
