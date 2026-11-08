//! Building the RSKIP92 merkle proof that links the coinbase to the Bitcoin
//! block's merkle root.
//!
//! The verifier ([`rustock_core::validation::merged_mining::rskip92_merkle_root`])
//! folds the coinbase hash with each 32-byte sibling in order. Because the
//! coinbase is always transaction 0, it is always the left operand, so the
//! proof is nothing but the sibling path bottom-up -- no direction bits, no
//! partial-merkle-tree framing. That is the whole of RSKIP92: the older format
//! serialized a full Bitcoin partial merkle tree, and the flag bits and
//! transaction count in it were redundant for a path that is known to start at
//! index 0.
//!
//! Every hash here is in *display* order (the reverse of Bitcoin's consensus
//! encoding), matching bitcoinj's `Sha256Hash` and the verifier's
//! `combine_left_right`.

use rustock_core::validation::merged_mining::combine_left_right;

/// Why a merkle proof could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleProofError {
    #[error("the Bitcoin block has no transactions, so it has no coinbase")]
    NoTransactions,
    #[error("merkle hash {index} is {len} bytes, expected 32")]
    BadHashLength { index: usize, len: usize },
    #[error("a partial merkle proof needs at least one hash")]
    EmptyMerkleHashes,
}

/// The sibling path from transaction 0 to the merkle root of a Bitcoin block
/// with these transaction ids (display order, index 0 the coinbase).
///
/// Bitcoin duplicates the final hash when a level has an odd number of nodes;
/// that never affects the coinbase's own sibling (index 1 always exists while
/// a level has more than one node) but it does affect the hashes computed
/// above it.
pub fn proof_from_txids(txids: &[[u8; 32]]) -> Result<Vec<u8>, MerkleProofError> {
    if txids.is_empty() {
        return Err(MerkleProofError::NoTransactions);
    }

    let mut proof = Vec::new();
    let mut level: Vec<[u8; 32]> = txids.to_vec();

    while level.len() > 1 {
        // The coinbase is index 0, so its sibling is index 1 at every level.
        proof.extend_from_slice(&level[1]);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(combine_left_right(&pair[0], right));
        }
        level = next;
    }

    Ok(proof)
}

/// The proof for a submission that supplied only the block's transaction
/// hashes rather than the whole block. rskj
/// `Rskip92MerkleProofBuilder.buildFromTxHashes`.
pub fn proof_from_tx_hashes(tx_hashes: &[[u8; 32]]) -> Result<Vec<u8>, MerkleProofError> {
    proof_from_txids(tx_hashes)
}

/// The proof for a submission that already carries the partial merkle branch.
///
/// The first hash is the coinbase itself -- the verifier starts from a coinbase
/// hash it computes, so a coinbase hash in the proof would be folded in twice.
/// rskj `Rskip92MerkleProofBuilder.buildFromMerkleHashes`.
pub fn proof_from_merkle_hashes(hashes: &[[u8; 32]]) -> Result<Vec<u8>, MerkleProofError> {
    if hashes.is_empty() {
        return Err(MerkleProofError::EmptyMerkleHashes);
    }
    Ok(hashes[1..].concat())
}

/// Parse a whitespace-separated list of 32-byte hex hashes as the JSON-RPC
/// submit methods deliver them, reversing each into display order.
///
/// rskj takes these fields as one space-separated string and reverses every
/// entry (`Utils.reverseBytes`), so the wire carries consensus (little-endian)
/// order and everything past this point is display order.
pub fn parse_wire_hashes(joined: &str) -> Result<Vec<[u8; 32]>, MerkleProofError> {
    let mut out = Vec::new();
    for (index, token) in joined.split_whitespace().enumerate() {
        let token = token.strip_prefix("0x").unwrap_or(token);
        let bytes = hex::decode(token)
            .map_err(|_| MerkleProofError::BadHashLength { index, len: token.len() / 2 })?;
        if bytes.len() != 32 {
            return Err(MerkleProofError::BadHashLength { index, len: bytes.len() });
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        hash.reverse();
        out.push(hash);
    }
    Ok(out)
}

/// The merkle root a proof folds to, for checking a proof before it is put in
/// a header. Mirrors the verifier exactly, `None` included: two nodes on the
/// path that parse as a 64-byte Bitcoin transaction, which rskj refuses.
pub fn root_from_proof(coinbase_hash: &[u8; 32], proof: &[u8]) -> Option<[u8; 32]> {
    rustock_core::validation::merged_mining::rskip92_merkle_root(coinbase_hash, proof)
}
