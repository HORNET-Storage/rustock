//! Did the Bridge register this flyover address, and under which derivation?
//!
//! A flyover peg-in leaves no event (`registerFlyoverBtcTransaction` calls no
//! `eventLogger` in rskj, and nor does our port), so the usual index cannot
//! answer "was this address a flyover peg-in". The Bridge's own state can:
//! `saveFlyoverFederationInformation` stores
//! `RLP[derivationHash(32), federationRedeemScriptHash(20)]` under
//! `keccak("fastBridgeFederationInformation-" || hex(flyoverP2shHash160))`.
//!
//! That slot is keyed by the **derived address's hash160**, which is exactly
//! what a list of flyover addresses gives us. So membership can be tested
//! directly, with no replay and no execution -- one trie read per address.
//!
//! It cannot be *enumerated*: the slot is a keccak of the key string, so
//! there is no prefix to scan. Candidates have to come from somewhere else
//! (a peg-out-derived list, or the live UTXO set). What this gives is an
//! exact yes/no for each candidate, which is what turns a heuristic scan into
//! a checkable one.
//!
//! Usage:
//!   flyover_registry <data-dir> <trie-dir> [block|head-N] <addr-or-hash160>...
//!   flyover_registry <data-dir> <trie-dir> [block|head-N] --file <list>

use alloy_primitives::B256;
use rustock_execution::bridge::storage::{compound_key, FAST_BRIDGE_FEDERATION_INFO_KEY};
use rustock_storage::epoch_backend::FlatFactory;
use rustock_storage::epoch_store::{EpochConfig, EpochTrieStore};
use rustock_storage::BlockStore;
use rustock_trie::{storage_key, TrieKeySlice, TrieNode, TrieStore};
use std::sync::Arc;

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// base58check -> the 20-byte payload, for a P2SH address.
fn b58_hash160(s: &str) -> Option<[u8; 20]> {
    let mut n = [0u8; 25];
    for ch in s.bytes() {
        let d = B58.iter().position(|&c| c == ch)? as u32;
        let mut carry = d;
        for b in n.iter_mut().rev() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&n[1..21]);
    Some(out)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        anyhow::bail!(
            "usage: flyover_registry <data-dir> <trie-dir> [block|head-N] \
             (<addr-or-hash160>... | --file <list>)"
        );
    }
    let blocks = BlockStore::open_read_only(&a[0])?;
    let trie: Arc<dyn TrieStore> = Arc::new(EpochTrieStore::open_read_only_with(
        &a[1],
        EpochConfig::default(),
        Arc::new(FlatFactory::new(0)),
    )?);

    let head = blocks
        .head()?
        .and_then(|h| blocks.header(h).ok().flatten())
        .map(|h| h.number)
        .ok_or_else(|| anyhow::anyhow!("no head"))?;
    let (number, rest): (u64, &[String]) = match a.get(2).map(String::as_str) {
        Some(s) if s.starts_with("head-") => (head.saturating_sub(s[5..].parse::<u64>()?), &a[3..]),
        Some(s) if s.chars().all(|c| c.is_ascii_digit()) => (s.parse()?, &a[3..]),
        _ => (head, &a[2..]),
    };

    let mut candidates: Vec<String> = Vec::new();
    let mut it = rest.iter();
    while let Some(x) = it.next() {
        if x == "--file" {
            let p = it.next().ok_or_else(|| anyhow::anyhow!("--file needs a path"))?;
            for line in std::fs::read_to_string(p)?.lines() {
                let t = line.split(',').next().unwrap_or("").trim().to_string();
                if !t.is_empty() && t != "address" {
                    candidates.push(t);
                }
            }
        } else {
            candidates.push(x.clone());
        }
    }
    anyhow::ensure!(!candidates.is_empty(), "no addresses given");

    let hash = blocks.canonical_hash(number)?.ok_or_else(|| anyhow::anyhow!("#{number} not canonical"))?;
    let header = blocks.header(hash)?.ok_or_else(|| anyhow::anyhow!("no header #{number}"))?;
    let root_bytes = trie
        .get(header.state_root.as_slice())
        .ok_or_else(|| anyhow::anyhow!("state for #{number} not in this trie store"))?;
    let root = TrieNode::from_message(&root_bytes, trie.as_ref());

    println!("block #{number}  stateRoot {:?}", header.state_root);
    println!("{} candidate(s)\n", candidates.len());

    let (mut found, mut missing, mut bad, mut unknown) = (0usize, 0usize, 0usize, 0usize);
    for c in &candidates {
        let h160 = if c.len() == 40 {
            match alloy_primitives::hex::decode(c) {
                Ok(v) if v.len() == 20 => {
                    let mut x = [0u8; 20];
                    x.copy_from_slice(&v);
                    Some(x)
                }
                _ => None,
            }
        } else {
            b58_hash160(c)
        };
        let Some(h160) = h160 else {
            println!("  {c:<36} BAD ADDRESS");
            bad += 1;
            continue;
        };
        let slot = compound_key(FAST_BRIDGE_FEDERATION_INFO_KEY, "-", &hexs(&h160));
        let key = storage_key(
            &rustock_execution::precompiles::BRIDGE_ADDR,
            &B256::from(slot),
        );
        // `try_get`, not `get`: a plain get answers None both when the key
        // is absent and when the walk hit a node the store cannot produce.
        // Those are opposite answers -- "the Bridge never registered this"
        // versus "this database has been pruned and cannot say" -- and
        // conflating them is how a collected store reads as a negative
        // result. `Err(hash)` is the second case.
        match root.try_get(&TrieKeySlice::from_key(&key), trie.as_ref()) {
            Ok(Some(v)) if !v.is_empty() => {
                found += 1;
                // RLP[derivationHash(32), fedRedeemScriptHash(20)] -- the
                // derivation hash is the 32 bytes after the two headers.
                let d = if v.len() >= 35 { hexs(&v[2..34]) } else { hexs(&v) };
                println!("  {c:<36} REGISTERED  derivation 0x{d}");
            }
            Ok(_) => {
                missing += 1;
                println!("  {c:<36} ABSENT (trie complete here: never registered)");
            }
            Err(h) => {
                unknown += 1;
                println!("  {c:<36} UNKNOWN -- store cannot resolve node 0x{}", hexs(h.as_slice()));
            }
        }
    }
    println!("\n{found} registered, {missing} absent, {unknown} unknown (pruned store), {bad} unparseable");
    if unknown > 0 {
        println!(
            "\nUNKNOWN is not a negative answer. This store could not follow the trie to\n\
             those keys -- collected, pruned or damaged -- so it cannot say whether the\n\
             Bridge registered them. Re-run against an archival store before concluding."
        );
    }
    Ok(())
}
