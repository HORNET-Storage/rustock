//! What the watcher can find, and how it reads to a human.

use crate::config::sats_to_btc_string;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    /// A single peg-out request above the configured threshold.
    LargePegout {
        block: u64,
        rsk_tx_hash: [u8; 32],
        btc_tx_hash: [u8; 32],
        amount_sats: u64,
        threshold_sats: u64,
    },
    /// An output of a peg-out BTC transaction, above the per-output threshold
    /// and not recognised as federation change.
    LargeOutput {
        block: u64,
        btc_txid: String,
        output_index: usize,
        script_hex: String,
        amount_sats: u64,
        threshold_sats: u64,
    },
    /// A block whose balance changes do not conserve the native supply.
    ///
    /// Not a peg-out finding, but it travels the same delivery path: it is the
    /// most serious thing the node can notice, and the operator wants it by
    /// mail for the same reason.
    SupplyNotConserved {
        block: u64,
        /// True when rBTC was created (block rejected), false when destroyed.
        created: bool,
        /// Imbalance in wei.
        amount_wei: String,
        /// The accounts that moved most, as `address before -> after`.
        top_accounts: Vec<String>,
    },
    /// A peg-in used the rskj-compatible multisig sender-detection path.
    ///
    /// Not a threat in itself: it means a peg-in arrived from a multisig
    /// address, was classified only because this node emulates rskj's
    /// redeem-script parsing, and will be refunded. It is worth mail because
    /// that emulation is scheduled for removal, and this is the evidence that
    /// removing it would change someone's outcome.
    LegacyMultisigPegin {
        block: u64,
        btc_txid: String,
        shape: String,
        refund_hash160: String,
    },
    /// Total value of peg-outs requested but not yet confirmed.
    InTransitAboveThreshold {
        block: u64,
        total_sats: u64,
        threshold_sats: u64,
        pegout_count: usize,
    },
    /// The executed head has not moved for `stalled_secs`.
    NodeStalled {
        executed: u64,
        best: u64,
        stalled_secs: u64,
        peer_count: usize,
        best_peer: Option<u64>,
    },
    /// A peer is well ahead, and has been for a while.
    NodeBehindPeers {
        best: u64,
        executed: u64,
        best_peer: u64,
        behind_by: u64,
        peer_count: usize,
        for_secs: u64,
    },
    /// This node is well ahead of every peer it has.
    NodeAheadOfPeers {
        best: u64,
        executed: u64,
        best_peer: u64,
        ahead_by: u64,
        peer_count: usize,
        for_secs: u64,
    },
    /// A value transfer above the configured threshold with a smart contract
    /// on at least one side of it.
    ///
    /// Found by re-executing the block with the call tracer, so this covers
    /// internal transfers -- a contract paying out -- and not only what a
    /// transaction declares. See [`crate::value`].
    LargeContractTransfer {
        block: u64,
        tx_hash: [u8; 32],
        /// `0x`-prefixed, already rendered: the alert carries text because
        /// its only consumers are a log line and an email.
        from: String,
        to: String,
        /// Which side is the contract, as [`crate::value::Direction`] reads it.
        direction: &'static str,
        /// `transaction`, `call`, `create` or `selfdestruct`.
        kind: &'static str,
        /// Position in the call tree: empty for the transaction's own
        /// transfer, `0.1.3` for a nested frame.
        path: String,
        amount_wei: String,
        amount_rbtc: String,
        threshold_rbtc: String,
    },
}

impl Alert {
    pub fn subject(&self) -> String {
        match self {
            Alert::LargePegout { amount_sats, block, .. } => format!(
                "Large peg-out: {} BTC at block #{block}",
                sats_to_btc_string(*amount_sats)
            ),
            Alert::LargeOutput { amount_sats, block, output_index, .. } => format!(
                "Large peg-out output: {} BTC (output {output_index}) at block #{block}",
                sats_to_btc_string(*amount_sats)
            ),
            Alert::SupplyNotConserved { block, created: true, amount_wei, .. } => format!(
                "REJECTED BLOCK #{block}: {amount_wei} wei of rBTC created from nothing"
            ),
            Alert::SupplyNotConserved { block, created: false, amount_wei, .. } => format!(
                "Block #{block} destroyed {amount_wei} wei of rBTC"
            ),
            Alert::LegacyMultisigPegin { block, shape, .. } => format!(
                "Peg-in from a {shape} sender at block #{block} (path scheduled for removal)"
            ),
            Alert::NodeStalled { executed, stalled_secs, .. } => format!(
                "Node stalled at #{executed} for {} minutes",
                stalled_secs / 60
            ),
            Alert::NodeBehindPeers { behind_by, best_peer, .. } => format!(
                "Node is {behind_by} blocks behind the network (best peer #{best_peer})"
            ),
            Alert::NodeAheadOfPeers { ahead_by, peer_count, .. } => format!(
                "Node is {ahead_by} blocks ahead of all {peer_count} peers"
            ),
            Alert::InTransitAboveThreshold { total_sats, block, .. } => format!(
                "Peg-outs in transit: {} BTC at block #{block}",
                sats_to_btc_string(*total_sats)
            ),
            Alert::LargeContractTransfer { amount_rbtc, direction, block, .. } => format!(
                "Large transfer {direction}: {amount_rbtc} RBTC at block #{block}"
            ),
        }
    }

    pub fn body(&self) -> String {
        match self {
            Alert::LargePegout { block, rsk_tx_hash, btc_tx_hash, amount_sats, threshold_sats } => {
                format!(
"A peg-out was requested above the configured threshold.

  RSK block      #{block}
  amount         {} BTC
  threshold      {} BTC
  RSK tx hash    0x{}
  BTC tx hash    0x{}

This is the release_requested event: the Bridge has built the Bitcoin
transaction, which now waits for confirmations before it is handed to the
signers.",
                    sats_to_btc_string(*amount_sats),
                    sats_to_btc_string(*threshold_sats),
                    hex::encode(rsk_tx_hash),
                    hex::encode(btc_tx_hash))
            }
            Alert::LargeOutput { block, btc_txid, output_index, script_hex, amount_sats, threshold_sats } => {
                format!(
"An output of a peg-out Bitcoin transaction awaiting signature is above the
configured per-output threshold.

  RSK block      #{block}
  BTC txid       {btc_txid}
  output index   {output_index}
  amount         {} BTC
  threshold      {} BTC
  scriptPubKey   {script_hex}

This transaction is in pegoutsWaitingForSignatures — the set handed to the
signers. Outputs matching a configured federation change script are excluded
from this check; if this output IS federation change, add its scriptPubKey to
`pegout_alerts.federation_change_scripts` to stop alerting on it.",
                    sats_to_btc_string(*amount_sats),
                    sats_to_btc_string(*threshold_sats))
            }
            Alert::SupplyNotConserved { block, created, amount_wei, top_accounts } => {
                let what = if *created {
                    "MORE rBTC exists after this block than before it. The peg is backed 1:1 by\n                     bitcoin and the Bridge holds the entire supply, so no legitimate block can\n                     do this. The block was REJECTED and not applied."
                } else {
                    "Less rBTC exists after this block than before it. This is not necessarily\n                     wrong -- REMASC burns a share of fees, and some EVM cases destroy balance --\n                     so the block was accepted and this is a record, not a failure."
                };
                format!(
"Native supply changed in block #{block}.

{what}

  imbalance   {amount_wei} wei

Accounts that moved most:
{}
",
                    top_accounts.iter().map(|a| format!("  {a}")).collect::<Vec<_>>().join("\n")
                )
            }
            Alert::LegacyMultisigPegin { block, btc_txid, shape, refund_hash160 } => {
                format!(
"A peg-in was classified using the rskj-compatible multisig sender path.

  RSK block      #{block}
  BTC tx         {btc_txid}
  sender shape   {shape}
  refund to      hash160 {refund_hash160} (P2SH)

This peg-in cannot be credited -- a multisig sender exposes no single public
key, so no RSK destination exists -- and will be refunded to the address above,
less the miner fee. That is rskj's behaviour and this node is matching it.

You are being told because the code that produced this classification is
proposed for deletion. Until now it had never been exercised on mainnet. If
that proposal is adopted, a peg-in like this one would no longer be refunded
automatically, so this message is a data point about who that would affect."
                )
            }
            Alert::NodeStalled { executed, best, stalled_secs, peer_count, best_peer } => {
                let network = match best_peer {
                    Some(p) => format!("#{p}"),
                    None => "unknown (no peer has reported a height)".to_string(),
                };
                let downloading = if best > executed {
                    format!(
                        "\n\nBlocks ARE still arriving -- the best block held is #{best}, {} ahead of\nwhat has executed -- so this is execution stopping rather than the network\ngoing quiet.",
                        best - executed
                    )
                } else {
                    "\n\nNo new blocks are arriving either, so this may be the network rather than\nthis node. Check peer count and connectivity before assuming a local fault."
                        .to_string()
                };
                format!(
"The executed head has not moved for {} minutes.

  executed       #{executed}
  best held      #{best}
  best peer      {network}
  peers          {peer_count}{downloading}

This alarm will not fire again for 24 hours, whether or not the node recovers.",
                    stalled_secs / 60
                )
            }
            Alert::NodeBehindPeers { best, executed, best_peer, behind_by, peer_count, for_secs } => {
                format!(
"This node has been {behind_by} blocks behind the network for {} minutes.

  best held      #{best}
  executed       #{executed}
  best peer      #{best_peer}
  behind by      {behind_by} blocks
  peers          {peer_count}

A node that is catching up on purpose will trip this too -- the alarm cannot
tell an intentional resync from a stuck one. If this node was restarted or
reseeded recently, that is the likely cause.

This alarm will not fire again for 24 hours, whether or not the node recovers.",
                    for_secs / 60
                )
            }
            Alert::NodeAheadOfPeers { best, executed, best_peer, ahead_by, peer_count, for_secs } => {
                format!(
"This node has been more than {ahead_by} blocks ahead of EVERY peer for {} minutes.

  best held      #{best}
  executed       #{executed}
  best peer      #{best_peer}
  ahead by       {ahead_by} blocks
  peers          {peer_count}

Being ahead of the whole network is not good news. It means one of two things,
and both look like health from inside this node:

  - it is following a chain the network rejected, in which case its state is
    diverging and every answer it gives is about a fork; or
  - every peer it has is stale, in which case it is effectively blind and its
    own height says nothing about where the chain is.

Compare the block at #{best_peer} against a public node before trusting either
reading.

This alarm will not fire again for 24 hours, whether or not the node recovers.",
                    for_secs / 60
                )
            }
            Alert::InTransitAboveThreshold { block, total_sats, threshold_sats, pegout_count } => {
                format!(
"The total value of peg-outs in transit is above the configured threshold.

  RSK block      #{block}
  in transit     {} BTC across {pegout_count} peg-out transaction(s)
  threshold      {} BTC

\"In transit\" is the set of peg-outs whose Bitcoin transactions have been built
but have not yet reached the required confirmations, so they have not yet been
handed to the signers.",
                    sats_to_btc_string(*total_sats),
                    sats_to_btc_string(*threshold_sats))
            }
            Alert::LargeContractTransfer {
                block, tx_hash, from, to, direction, kind, path, amount_wei, amount_rbtc,
                threshold_rbtc,
            } => {
                let where_ = if path.is_empty() {
                    "the transaction's own value transfer".to_string()
                } else {
                    format!("an internal transfer, at call-tree position {path}")
                };
                format!(
"A value transfer {direction} is above the configured threshold.

  RSK block      #{block}
  transaction    0x{}
  from           {from}
  to             {to}
  amount         {amount_rbtc} RBTC
  threshold      {threshold_rbtc} RBTC
  exact amount   {amount_wei} wei
  moved by       {kind}

This is {where_}.

The transfer succeeded: frames that reverted, and everything beneath them, are
excluded, so this is value that actually moved. To see it in context:

  trace_transaction(\"0x{}\")",
                    hex::encode(tx_hash),
                    hex::encode(tx_hash))
            }
        }
    }

    /// Alerts about the same thing at the same block are the same alert; the
    /// watcher uses this to avoid mailing once per poll while a condition
    /// persists.
    pub fn dedup_key(&self) -> String {
        match self {
            Alert::LargePegout { rsk_tx_hash, btc_tx_hash, .. } =>
                format!("pegout:{}:{}", hex::encode(rsk_tx_hash), hex::encode(btc_tx_hash)),
            Alert::LargeOutput { btc_txid, output_index, .. } =>
                format!("output:{btc_txid}:{output_index}"),
            // Raised only for a block that requested a new peg-out (see
            // Watcher::process_block), so the block number is the event: one
            // alert per new peg-out, never a re-alert as the total drifts.
            Alert::InTransitAboveThreshold { block, .. } =>
                format!("intransit:{block}"),
            // The monitor's own cooldown decides when these repeat, so the key
            // must not also suppress them: a second stall a week later is news.
            // Including the height keeps that true without disabling dedup for
            // two identical readings in one poll.
            Alert::NodeStalled { executed, stalled_secs, .. } =>
                format!("stalled:{executed}:{stalled_secs}"),
            Alert::NodeBehindPeers { best, best_peer, .. } =>
                format!("behind:{best}:{best_peer}"),
            Alert::NodeAheadOfPeers { best, best_peer, .. } =>
                format!("ahead:{best}:{best_peer}"),
            // One per block: a block is either conserved or it is not.
            Alert::SupplyNotConserved { block, .. } => format!("supply:{block}"),
            // One per Bitcoin transaction: registering it twice is the same event.
            Alert::LegacyMultisigPegin { btc_txid, .. } => format!("multisig-pegin:{btc_txid}"),
            // The transaction and the position within its call tree identify
            // the transfer exactly. Two transfers of the same size between the
            // same pair in one transaction are different frames and different
            // news, so the path has to be in the key.
            Alert::LargeContractTransfer { tx_hash, path, .. } =>
                format!("contract-transfer:{}:{path}", hex::encode(tx_hash)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_and_bodies_report_btc_not_satoshis() {
        let a = Alert::LargePegout {
            block: 100, rsk_tx_hash: [0xAB; 32], btc_tx_hash: [0xCD; 32],
            amount_sats: 15_000_000_000, threshold_sats: 10_000_000_000,
        };
        assert!(a.subject().contains("150.00000000 BTC"), "{}", a.subject());
        assert!(a.body().contains("150.00000000"));
        assert!(a.body().contains("100.00000000"));
        assert!(a.body().contains(&hex::encode([0xABu8; 32])));
    }

    #[test]
    fn in_transit_is_keyed_by_the_block_that_requested_a_new_pegout() {
        // The alert is only ever raised for a block that requested a new
        // peg-out, so one key per block is one alert per new peg-out. Keying
        // by the total instead would re-alert every time the running total
        // drifted -- including downwards, as peg-outs reach confirmation.
        let a = Alert::InTransitAboveThreshold { block: 9, total_sats: 5, threshold_sats: 1, pegout_count: 2 };
        let same_block_bigger_total = Alert::InTransitAboveThreshold { block: 9, total_sats: 6, threshold_sats: 1, pegout_count: 3 };
        let later_block = Alert::InTransitAboveThreshold { block: 10, total_sats: 5, threshold_sats: 1, pegout_count: 2 };
        assert_eq!(a.dedup_key(), same_block_bigger_total.dedup_key());
        assert_ne!(a.dedup_key(), later_block.dedup_key());
    }

    #[test]
    fn the_output_alert_says_how_to_silence_a_change_output() {
        let a = Alert::LargeOutput {
            block: 7, btc_txid: "ab".into(), output_index: 1,
            script_hex: "a914deadbeef87".into(),
            amount_sats: 200 * 100_000_000, threshold_sats: 100 * 100_000_000,
        };
        assert!(a.body().contains("federation_change_scripts"));
    }
}
