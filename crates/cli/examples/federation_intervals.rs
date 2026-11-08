//! Which PowPeg functionary keys were active over which block range.
//!
//! An ad-hoc database, built from the Bridge event index rather than from
//! state. The Bridge logs `commit_federation` every time a federation is
//! handed over, and the event carries **both** the outgoing and the incoming
//! public keys plus the height the new one activates at. Sixteen of those
//! events cover the whole of mainnet, so the entire history of the PowPeg is
//! reconstructable without replaying a block or reading the trie — which
//! matters, because a pruning node no longer holds the state most of those
//! heights would need.
//!
//! The first event's *outgoing* key set is the genesis federation, so the
//! table reaches back to block 0 without a special case.
//!
//! Two encodings, because the event changed shape at RSKIP146 (iris300):
//!
//! - legacy `commit_federation_topic`: RLP of
//!   `[[oldHash160, [oldKeys…]], [newHash160, [newKeys…]], activationHeight]`
//!   where the height is a **decimal ASCII string**, not an integer;
//! - `commit_federation(bytes,string,bytes,string,int256)`: ABI, the key sets
//!   flat-concatenated 33 bytes each.
//!
//! Usage:
//!   federation_intervals <data-dir> [out.json]

use rustock_storage::BlockStore;
use std::collections::BTreeMap;

const LEGACY_TOPIC: &str = "0x000000000000000000636f6d6d69745f66656465726174696f6e5f746f706963";
const SOLIDITY_SIG: &str = "commit_federation(bytes,string,bytes,string,int256)";

fn keccak_topic(sig: &str) -> alloy_primitives::B256 {
    alloy_primitives::keccak256(sig.as_bytes())
}

/// One federation, and the blocks over which it could sign.
#[derive(Debug, Clone)]
struct Interval {
    from: u64,
    to: Option<u64>,
    keys: Vec<[u8; 33]>,
    /// The block whose `commit_federation` announced this set, for audit.
    committed_at: Option<u64>,
}

// --- minimal RLP, enough for the legacy event -------------------------------

/// `(payload, is_list, rest)` for the item at the head of `b`.
fn rlp_item(b: &[u8]) -> Option<(&[u8], bool, &[u8])> {
    let first = *b.first()?;
    match first {
        0x00..=0x7f => Some((&b[..1], false, &b[1..])),
        0x80..=0xb7 => {
            let n = (first - 0x80) as usize;
            (b.len() > n).then(|| (&b[1..1 + n], false, &b[1 + n..]))?.into()
        }
        0xb8..=0xbf => {
            let l = (first - 0xb7) as usize;
            let n = be_usize(b.get(1..1 + l)?);
            (b.len() >= 1 + l + n).then(|| (&b[1 + l..1 + l + n], false, &b[1 + l + n..]))?.into()
        }
        0xc0..=0xf7 => {
            let n = (first - 0xc0) as usize;
            (b.len() > n).then(|| (&b[1..1 + n], true, &b[1 + n..]))?.into()
        }
        0xf8..=0xff => {
            let l = (first - 0xf7) as usize;
            let n = be_usize(b.get(1..1 + l)?);
            (b.len() >= 1 + l + n).then(|| (&b[1 + l..1 + l + n], true, &b[1 + l + n..]))?.into()
        }
    }
}

fn be_usize(b: &[u8]) -> usize {
    b.iter().fold(0usize, |a, x| (a << 8) | *x as usize)
}

fn rlp_items(mut payload: &[u8]) -> Vec<(&[u8], bool)> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let Some((item, is_list, rest)) = rlp_item(payload) else { break };
        out.push((item, is_list));
        payload = rest;
    }
    out
}

fn keys_from_rlp(fed_payload: &[u8]) -> Vec<[u8; 33]> {
    // [hash160, [keys...]]
    let parts = rlp_items(fed_payload);
    let Some((keylist, true)) = parts.get(1).copied() else { return Vec::new() };
    rlp_items(keylist)
        .into_iter()
        .filter_map(|(k, _)| <[u8; 33]>::try_from(k).ok())
        .collect()
}

fn decode_legacy(data: &[u8]) -> Option<(Vec<[u8; 33]>, Vec<[u8; 33]>, u64)> {
    let (outer, true, _) = rlp_item(data)? else { return None };
    let parts = rlp_items(outer);
    let (old_fed, true) = parts.first().copied()? else { return None };
    let (new_fed, true) = parts.get(1).copied()? else { return None };
    let (height_ascii, false) = parts.get(2).copied()? else { return None };
    let height: u64 = std::str::from_utf8(height_ascii).ok()?.trim().parse().ok()?;
    Some((keys_from_rlp(old_fed), keys_from_rlp(new_fed), height))
}

// --- minimal ABI, enough for the solidity event -----------------------------

fn abi_word(data: &[u8], i: usize) -> Option<u64> {
    let w = data.get(i * 32..i * 32 + 32)?;
    Some(u64::from_be_bytes(w[24..32].try_into().ok()?))
}

fn abi_bytes(data: &[u8], head_index: usize) -> Option<Vec<u8>> {
    let off = abi_word(data, head_index)? as usize;
    let len = u64::from_be_bytes(data.get(off + 24..off + 32)?.try_into().ok()?) as usize;
    Some(data.get(off + 32..off + 32 + len)?.to_vec())
}

fn split_keys(flat: &[u8]) -> Vec<[u8; 33]> {
    flat.chunks_exact(33).filter_map(|c| <[u8; 33]>::try_from(c).ok()).collect()
}

fn decode_solidity(data: &[u8]) -> Option<(Vec<[u8; 33]>, Vec<[u8; 33]>, u64)> {
    // (bytes oldKeys, string oldAddr, bytes newKeys, string newAddr, int256 activation)
    let old = split_keys(&abi_bytes(data, 0)?);
    let new = split_keys(&abi_bytes(data, 2)?);
    let activation = abi_word(data, 4)?;
    Some((old, new, activation))
}

fn hex33(k: &[u8; 33]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: federation_intervals <data-dir> [out.json]");
    let out = args.next();
    let store = BlockStore::open_read_only(&dir)?;

    // (committed_at, activation_height, old_keys, new_keys)
    let mut commits: Vec<(u64, u64, Vec<[u8; 33]>, Vec<[u8; 33]>)> = Vec::new();

    for (block, _tx, _log, data) in events(&store, LEGACY_TOPIC.parse()?)? {
        match decode_legacy(&data) {
            Some((old, new, h)) => commits.push((block, h, old, new)),
            None => eprintln!("warning: #{block}: legacy commit_federation did not decode"),
        }
    }
    for (block, _tx, _log, data) in events(&store, keccak_topic(SOLIDITY_SIG))? {
        match decode_solidity(&data) {
            Some((old, new, h)) => commits.push((block, h, old, new)),
            None => eprintln!("warning: #{block}: commit_federation did not decode"),
        }
    }
    commits.sort_by_key(|c| c.1);

    anyhow::ensure!(!commits.is_empty(), "no commit_federation events in {dir}");

    // The first commit's outgoing set is what signed before any handover.
    let mut intervals: Vec<Interval> = vec![Interval {
        from: 0,
        to: None,
        keys: commits[0].2.clone(),
        committed_at: None,
    }];
    for (committed_at, activation, _old, new) in &commits {
        if let Some(last) = intervals.last_mut() {
            last.to = Some(activation.saturating_sub(1));
        }
        intervals.push(Interval {
            from: *activation,
            to: None,
            keys: new.clone(),
            committed_at: Some(*committed_at),
        });
    }

    // The chain has to close: every commit's OUTGOING set must be the set
    // that was active before it. Checked rather than assumed, because a
    // decoding slip in either event format would otherwise produce a
    // plausible-looking table of the wrong keys, and every later answer
    // about who was a functionary would inherit it.
    let mut broken = 0usize;
    for i in 0..commits.len() {
        let expected: &Vec<[u8; 33]> = if i == 0 { &commits[0].2 } else { &commits[i - 1].3 };
        if &commits[i].2 != expected {
            broken += 1;
            eprintln!(
                "INCONSISTENT at #{}: outgoing set ({} keys) is not the set committed before it ({} keys)",
                commits[i].0,
                commits[i].2.len(),
                expected.len()
            );
        }
    }
    if broken == 0 {
        println!(
            "chain check: all {} handovers close -- each outgoing set is the previous incoming set\n",
            commits.len()
        );
    } else {
        eprintln!("chain check: {broken} of {} handovers do not close", commits.len());
    }

    println!("{:<10} {:<10} {:>5}  {:<10}", "from", "to", "keys", "committed");
    for iv in &intervals {
        println!(
            "{:<10} {:<10} {:>5}  {}",
            iv.from,
            iv.to.map(|t| t.to_string()).unwrap_or_else(|| "head".into()),
            iv.keys.len(),
            iv.committed_at.map(|c| format!("#{c}")).unwrap_or_else(|| "genesis".into())
        );
    }

    // Every key ever a functionary, and over which ranges.
    let mut per_key: BTreeMap<String, Vec<(u64, Option<u64>)>> = BTreeMap::new();
    for iv in &intervals {
        for k in &iv.keys {
            per_key.entry(hex33(k)).or_default().push((iv.from, iv.to));
        }
    }
    println!("\n{} distinct functionary keys across {} intervals", per_key.len(), intervals.len());

    if let Some(path) = out {
        let mut j = String::from("{\n  \"intervals\": [\n");
        for (i, iv) in intervals.iter().enumerate() {
            j.push_str(&format!(
                "    {{\"from\": {}, \"to\": {}, \"committed_at\": {}, \"keys\": [{}]}}{}\n",
                iv.from,
                iv.to.map(|t| t.to_string()).unwrap_or_else(|| "null".into()),
                iv.committed_at.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
                iv.keys.iter().map(|k| format!("\"{}\"", hex33(k))).collect::<Vec<_>>().join(", "),
                if i + 1 == intervals.len() { "" } else { "," }
            ));
        }
        j.push_str("  ]\n}\n");
        std::fs::write(&path, j)?;
        println!("written to {path}");
    }
    Ok(())
}

type Event = (u64, u32, u32, Vec<u8>);

/// `scan_bridge_events` yields `(block, tx_index, log_index, tx_hash, topics, data)`.
fn events(store: &BlockStore, topic: alloy_primitives::B256) -> anyhow::Result<Vec<Event>> {
    Ok(store
        .scan_bridge_events(topic, 0, u64::MAX)?
        .into_iter()
        .map(|(block, tx, log, _hash, _topics, data)| (block, tx, log, data))
        .collect())
}
