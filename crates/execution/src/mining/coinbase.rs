//! Building the Bitcoin side of a merged-mining solution: a coinbase carrying
//! the `RSKBLOCK:` tag, and a Bitcoin block around it.
//!
//! A real mining pool builds these itself and only hands the result back
//! through `mnr_submitBitcoinBlock*`. This exists so the node can mine on its
//! own -- regtest, and the round-trip tests -- and so the shape a submission
//! must have is written down somewhere executable.

use alloy_primitives::B256;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header as BtcHeader, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, Block as BtcBlock, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence,
              Transaction as BtcTransaction, TxIn, TxMerkleNode, TxOut, Witness};
use rustock_core::validation::merged_mining::RSK_TAG;

/// A coinbase transaction committing to `tag_payload` -- the 32 bytes that
/// follow `RSKBLOCK:`, which post-wasabi100 are 20 bytes of merged-mining hash
/// and 12 of fork-detection data.
///
/// `extra_nonce` goes in the input script, giving the miner a cheap way to
/// change the coinbase (and so the merkle root) without rebuilding the RSK
/// block. Shaped after rskj `MinerUtils.getBitcoinMergedMiningCoinbaseTransaction`:
/// the tag rides in a second, zero-value output rather than in the input
/// script, which keeps it clear of the extra-nonce the miner rolls.
pub fn build_coinbase(tag_payload: &B256, extra_nonce: u64) -> BtcTransaction {
    let mut tag_script = Vec::with_capacity(2 + RSK_TAG.len() + 32);
    tag_script.push(bitcoin::opcodes::all::OP_RETURN.to_u8());
    tag_script.push((RSK_TAG.len() + 32) as u8);
    tag_script.extend_from_slice(RSK_TAG);
    tag_script.extend_from_slice(tag_payload.as_slice());

    BtcTransaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(extra_nonce.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(tag_script),
            },
        ],
    }
}

/// A Bitcoin block whose only transaction is `coinbase`.
///
/// `bits` is not consulted by RSK -- merged mining checks the Bitcoin hash
/// against *RSK's* difficulty, not Bitcoin's, so a block here need not be a
/// valid Bitcoin block at all. It is carried because the field exists.
///
/// `time` is consulted: RSKIP179 requires it within five minutes of the RSK
/// header's timestamp, so it is the same clock the template was stamped
/// from (rskj `MinerUtils.getBitcoinMergedMiningBlock` uses the wall clock;
/// this one adds whatever `evm_increaseTime` has accumulated, as the
/// template does, so a development chain moved into the future still mines).
pub fn build_bitcoin_block(coinbase: BtcTransaction, nonce: u32) -> BtcBlock {
    let merkle_root = TxMerkleNode::from_byte_array(coinbase.compute_txid().to_byte_array());
    BtcBlock {
        header: BtcHeader {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root,
            time: u32::try_from(super::dev::now_with_offset()).unwrap_or(u32::MAX),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        },
        txdata: vec![coinbase],
    }
}

/// Transaction ids of a Bitcoin block's transactions, in display order --
/// which is what the merkle-proof builder takes.
pub fn txids_display_order(block: &BtcBlock) -> Vec<[u8; 32]> {
    block
        .txdata
        .iter()
        .map(|tx| {
            let mut id = tx.compute_txid().to_byte_array();
            id.reverse();
            id
        })
        .collect()
}

/// Consensus-encode a Bitcoin block header: the 80 bytes an RSK header stores
/// in `bitcoin_merged_mining_header`.
pub fn encode_header(header: &BtcHeader) -> Vec<u8> {
    bitcoin::consensus::serialize(header)
}

/// Serialize a Bitcoin transaction the way a coinbase must be given to the
/// compressor: the plain consensus encoding.
pub fn encode_transaction(tx: &BtcTransaction) -> Vec<u8> {
    bitcoin::consensus::serialize(tx)
}
