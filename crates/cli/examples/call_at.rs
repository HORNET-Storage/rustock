//! Run an `eth_call` against the state at any past block.
//!
//! # Why this exists
//!
//! A node serves `eth_call` at a historical block only while it still holds
//! that block's state. An epoch backend keeps a window — a few days — so a
//! question about last December gets `state for #N is not in this trie store`
//! rather than an answer.
//!
//! The state is not gone, though: an archival trie holds every root. This
//! points the same executor at it. **Nothing is synchronised, nothing is
//! executed beyond the one call, and nothing is written** — both stores are
//! opened read-only and the call runs with `execute_local_call`, which is the
//! same path `eth_call` takes and discards its state changes.
//!
//! # Why not replay the history
//!
//! Recovering a past ERC-20 balance by replaying the blocks between then and
//! now, summing transfers, costs months of execution and gets the answer
//! wrong whenever a token does anything a `Transfer` event does not describe
//! — rebasing, admin burns, a proxy upgrade that moves the storage. The state
//! at that block already holds the answer; reconstructing it from the deltas
//! is both slower and less reliable than reading it.
//!
//! # Usage
//!
//! ```text
//! call_at <data-dir> <trie-dir> <block|head-N> <to-address> <0xcalldata>
//!         [--from ADDR] [--trie-format rustock|epoch] [--decimals N]
//! ```
//!
//! `--decimals` only formats the result; it does not affect the call.
//!
//! Example — an ERC-20 balance at the last block of 2025:
//!
//! ```sh
//! call_at /var/lib/rustock /mnt/import/rustock-trie 8372606 \
//!     0x3a15461d8ae0f0fb5fa2629e9da7d66a794a6e37 \
//!     0x70a08231000000000000000000000000<holder> --decimals 18
//! ```

use alloy_primitives::{Address, Bytes, U256};
use rustock_core::Transaction;
use rustock_execution::{RskExecutor, RskHardforkConfig};
use rustock_storage::{BlockStore, RocksDbTrieStore};
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;

fn opt(a: &[String], name: &str) -> Option<String> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned()
}

/// Renders an integer as a decimal with `d` fractional digits, without f64.
fn scaled(v: U256, d: u32) -> String {
    let s = v.to_string();
    let d = d as usize;
    if d == 0 {
        return s;
    }
    if s.len() <= d {
        format!("0.{:0>width$}", s, width = d)
    } else {
        format!("{}.{}", &s[..s.len() - d], &s[s.len() - d..])
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let pos: Vec<&String> = a
        .iter()
        .enumerate()
        .filter(|(i, s)| !s.starts_with("--") && (*i == 0 || !a[i - 1].starts_with("--")))
        .map(|(_, s)| s)
        .collect();
    if pos.len() < 5 {
        anyhow::bail!(
            "usage: call_at <data-dir> <trie-dir> <block|head-N> <to-address> <0xcalldata> \
             [--from ADDR] [--trie-format rustock|epoch] [--decimals N]"
        );
    }

    let blocks = BlockStore::open_read_only(pos[0])?;
    let fmt = opt(&a, "--trie-format").unwrap_or_else(|| "rustock".into());
    let trie: Arc<dyn TrieStore> = match fmt.as_str() {
        "rustock" => Arc::new(
            RocksDbTrieStore::open_read_only(pos[1])
                .map_err(|e| anyhow::anyhow!("opening {} read-only: {e}", pos[1]))?,
        ),
        "epoch" => Arc::new(
            rustock_storage::epoch_store::EpochTrieStore::open_read_only_with(
                pos[1],
                rustock_storage::epoch_store::EpochConfig::default(),
                Arc::new(rustock_storage::epoch_backend::FlatFactory::new(0)),
            )
            .map_err(|e| anyhow::anyhow!("opening epoch store {}: {e}", pos[1]))?,
        ),
        other => anyhow::bail!("--trie-format must be rustock or epoch, not {other:?}"),
    };

    let head = blocks
        .head()?
        .and_then(|h| blocks.header(h).ok().flatten())
        .map(|h| h.number)
        .ok_or_else(|| anyhow::anyhow!("no head"))?;
    let number = match pos[2].as_str() {
        s if s.starts_with("head-") => head.saturating_sub(s[5..].parse::<u64>()?),
        s => s.parse::<u64>()?,
    };

    let to = Address::parse_checksummed(pos[3], None)
        .or_else(|_| pos[3].parse::<Address>())
        .map_err(|_| anyhow::anyhow!("bad --to address {:?}", pos[3]))?;
    let data = alloy_primitives::hex::decode(pos[4].trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("calldata is not hex: {e}"))?;
    let sender: Address = match opt(&a, "--from") {
        Some(s) => s.parse().map_err(|_| anyhow::anyhow!("bad --from"))?,
        None => Address::ZERO,
    };

    let hash = blocks
        .canonical_hash(number)?
        .ok_or_else(|| anyhow::anyhow!("#{number} is not canonical here"))?;
    let header = blocks.header(hash)?.ok_or_else(|| anyhow::anyhow!("no header for #{number}"))?;
    let root_bytes = trie.get(header.state_root.as_slice()).ok_or_else(|| {
        anyhow::anyhow!(
            "state for #{number} is not in this trie store. An epoch backend keeps \
             only a window; use an archival trie for an older height."
        )
    })?;
    let root = TrieNode::from_message(&root_bytes, trie.as_ref());

    eprintln!("block     #{number}  ({hash})");
    eprintln!("stateRoot {:?}", header.state_root);
    eprintln!("timestamp {} UTC", header.timestamp);

    // A local call: no signature, nonce taken from the caller's account, and
    // the state changes discarded. `execute_local_call` is the same entry
    // `eth_call` uses.
    let tx = Transaction {
        nonce: 0,
        gas_price: header.minimum_gas_price,
        gas_limit: header.gas_limit,
        to: Bytes::copy_from_slice(to.as_slice()),
        value: U256::ZERO,
        input: Bytes::from(data),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        cached_rlp: None,
    };

    let executor = RskExecutor::new(
        RskHardforkConfig::for_network(30),
        Arc::new(BlockStore::open_read_only(pos[0])?),
    );
    let out = executor
        .execute_local_call(&header, &tx, sender, &root, trie.clone())
        .map_err(|e| anyhow::anyhow!("call failed: {e:?}"))?;

    if !out.success {
        eprintln!("note: the call reverted; the output below is the revert data");
    }
    let ret = out.output.to_vec();
    println!("0x{}", alloy_primitives::hex::encode(&ret));
    if ret.len() >= 32 {
        let v = U256::from_be_slice(&ret[..32]);
        println!("uint256   {v}");
        if let Some(d) = opt(&a, "--decimals") {
            println!("scaled    {}", scaled(v, d.parse()?));
        }
    }
    Ok(())
}
