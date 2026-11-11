//! How much bitcoin does the peg hold, and where does it actually sit?
//!
//! Not a question the federation address answers. A Flyover peg-in pays a
//! **derived** P2SH -- `P2SH(PUSH(derivationHash) OP_DROP <federationRedeem>)`,
//! a different address for every quote -- and nothing ever sweeps it into the
//! federation address. The coins stay where the user sent them until a pegout
//! spends them.
//!
//! What unifies them is the Bridge's own bookkeeping: a Flyover UTXO is
//! appended to the same `newFederationBtcUTXOs` list as an ordinary one
//! (`register_federation_outputs(.., flyover_script, active_utxo_key)`), and a
//! pegout selects from that list, signing each input with whichever redeem
//! that input needs. So the authoritative answer is a sum over two storage
//! keys, not a reconstruction from peg-in history -- and it needs no tracking
//! of individual Flyover quotes, which would in any case drift the moment one
//! of them is spent.
//!
//! Read straight from the unitrie at a block's state root. No execution.
//!
//! Usage:
//!   bridge_btc_holdings <data-dir> <trie-dir> [block|head-N] [fed-hash160...]
//!
//! `fed-hash160` is optional and only labels the output: pass the hash160 of
//! the active (and retiring) federation P2SH and those scripts are named
//! rather than counted among the derived ones. Without it everything is
//! reported by script, which is still complete, just unlabelled.
//!
//! Example, against this node:
//!   bridge_btc_holdings /var/lib/rustock /var/lib/rustock/trie-epochs-flat head-20

use rustock_execution::bridge::storage::{
    bridge_storage_key, deserialize_utxo_list, new_federation_utxos_key, BridgeUtxo,
    OLD_FEDERATION_BTC_UTXOS_KEY,
};
use rustock_execution::hardfork::RskHardforkConfig;
use rustock_storage::epoch_backend::FlatFactory;
use rustock_storage::epoch_store::{EpochConfig, EpochTrieStore};
use rustock_storage::BlockStore;
use rustock_trie::{TrieKeySlice, TrieNode, TrieStore};
use std::collections::BTreeMap;
use std::sync::Arc;

const SAT: f64 = 100_000_000.0;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The 20-byte hash of a P2SH script `a9 14 <20> 87`, if it is one.
fn p2sh_hash160(script: &[u8]) -> Option<&[u8]> {
    (script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87)
        .then(|| &script[2..22])
}

fn read_bridge_slot(root: &TrieNode, store: &dyn TrieStore, name: &str) -> Vec<u8> {
    let slot = alloy_primitives::B256::from(bridge_storage_key(name));
    let key = rustock_trie::storage_key(&rustock_execution::precompiles::BRIDGE_ADDR, &slot);
    root.get(&TrieKeySlice::from_key(&key), store).unwrap_or_default()
}

fn report(label: &str, utxos: &[BridgeUtxo], known: &BTreeMap<String, String>) {
    let total: u64 = utxos.iter().map(|u| u.value_satoshis).sum();
    println!("\n## {label}");
    if utxos.is_empty() {
        println!("  empty");
        return;
    }
    println!("  {:.8} BTC across {} UTXO(s)", total as f64 / SAT, utxos.len());

    // By scriptPubKey: the federation's own script holds most of it, and each
    // Flyover derivation is a script of its own.
    let mut by_script: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    for u in utxos {
        let e = by_script.entry(hexs(&u.script)).or_insert((0, 0));
        e.0 += u.value_satoshis;
        e.1 += 1;
    }
    let mut rows: Vec<_> = by_script.into_iter().collect();
    rows.sort_by_key(|(_, (v, _))| std::cmp::Reverse(*v));

    let (mut fed_sat, mut fed_n, mut der_sat, mut der_n, mut der_scripts) = (0u64, 0usize, 0u64, 0usize, 0usize);
    println!("  {:<44} {:>18} {:>7}  what", "scriptPubKey (hash160 if P2SH)", "BTC", "UTXOs");
    for (script, (sat, n)) in &rows {
        let raw = (0..script.len() / 2)
            .map(|i| u8::from_str_radix(&script[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect::<Vec<u8>>();
        let h160 = p2sh_hash160(&raw).map(hexs);
        let shown = h160.clone().unwrap_or_else(|| script.clone());
        let what = match h160.as_ref().and_then(|h| known.get(h)) {
            Some(name) => { fed_sat += sat; fed_n += n; name.clone() }
            None => { der_sat += sat; der_n += n; der_scripts += 1; "derived (Flyover)".into() }
        };
        if *sat > 0 || *n > 0 {
            println!("  {:<44} {:>18.8} {:>7}  {}", shown, *sat as f64 / SAT, n, what);
        }
    }
    // Every outpoint, so the set can be diffed against the address's unspent
    // outputs on the Bitcoin side.  tx_hash is stored in display order.
    println!("  ---");
    println!("  {:<64} {:>5} {:>18} {:>9}", "txid", "vout", "BTC", "btcHeight");
    let mut listed: Vec<&BridgeUtxo> = utxos.iter().collect();
    listed.sort_by_key(|u| std::cmp::Reverse(u.value_satoshis));
    for u in listed {
        println!("  {:<64} {:>5} {:>18.8} {:>9}",
                 hexs(&u.tx_hash), u.vout, u.value_satoshis as f64 / SAT, u.height);
    }

    if !known.is_empty() {
        println!("  ---");
        println!("  federation-held : {:>18.8} BTC  {fed_n} UTXO(s)", fed_sat as f64 / SAT);
        println!("  Flyover-derived : {:>18.8} BTC  {der_n} UTXO(s) across {der_scripts} address(es)",
                 der_sat as f64 / SAT);
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        anyhow::bail!("usage: bridge_btc_holdings <data-dir> <trie-dir> [block|head-N] [fed-hash160...]");
    }
    let blocks = Arc::new(BlockStore::open_read_only(&a[0])?);
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
    let number = match a.get(2).map(String::as_str) {
        None => head,
        Some(s) if s.starts_with("head-") => head.saturating_sub(s[5..].parse::<u64>()?),
        Some(s) => s.parse::<u64>()?,
    };
    let known: BTreeMap<String, String> = a
        .iter()
        .skip(3)
        .enumerate()
        .map(|(i, h)| (h.to_lowercase(), if i == 0 { "ACTIVE federation".into() } else { format!("federation #{}", i + 1) }))
        .collect();

    let hash = blocks
        .canonical_hash(number)?
        .ok_or_else(|| anyhow::anyhow!("#{number} is not canonical here"))?;
    let header = blocks.header(hash)?.ok_or_else(|| anyhow::anyhow!("no header for #{number}"))?;
    let root_bytes = trie.get(header.state_root.as_slice()).ok_or_else(|| {
        anyhow::anyhow!(
            "state for #{number} is not in this trie store -- an epoch node keeps a window, \
             so old heights need an archive"
        )
    })?;
    let root = TrieNode::from_message(&root_bytes, trie.as_ref());

    println!("block     #{number}  ({hash})");
    println!("stateRoot {:?}", header.state_root);

    let cfg = RskHardforkConfig::for_network(30);
    let active_key = new_federation_utxos_key(&cfg, number);
    let active_raw = read_bridge_slot(&root, trie.as_ref(), active_key);
    let active = deserialize_utxo_list(&active_raw);
    let retiring = deserialize_utxo_list(&read_bridge_slot(
        &root,
        trie.as_ref(),
        OLD_FEDERATION_BTC_UTXOS_KEY,
    ));

    report(&format!("active federation set ({active_key})"), &active, &known);
    report(&format!("retiring federation set ({OLD_FEDERATION_BTC_UTXOS_KEY})"), &retiring, &known);

    let total: u64 = active.iter().chain(&retiring).map(|u| u.value_satoshis).sum();
    println!("\n## the peg holds {:.8} BTC at #{number}", total as f64 / SAT);
    println!("   ({} UTXOs; every one of them spendable by the federation, wherever it sits)",
             active.len() + retiring.len());
    Ok(())
}
