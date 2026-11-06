//! The Bridge's proofs that a Bitcoin transaction is in a Bitcoin block.
//!
//! A partial Merkle tree is read and walked by `rustock_core`'s port of
//! bitcoinj-thin's `PartialMerkleTree`, the one rskj's Bridge shares with its
//! check of merged mining below RSKIP92. The Bridge compares in wire order,
//! the bytes a Bitcoin block hashes, so the tree's results, which bitcoinj
//! gives in display order, are turned round here.
//!
//! A Merkle branch is rskj's `MerkleBranch`, for
//! `getBtcTransactionConfirmations`. It works in display order, as rskj's
//! does, since that is the order two of its nodes are tested in for a
//! 64-byte transaction.

use rustock_core::partial_merkle_tree as bitcoinj;
use rustock_core::validation::merged_mining::{
    combine_left_right, parses_as_a_64_byte_transaction,
};

/// A partial Merkle tree, as bitcoinj reads one.
#[derive(Debug)]
pub struct PartialMerkleTree(bitcoinj::PartialMerkleTree);

/// What a tree walks to: the root and the transactions it matches, in wire
/// order.
#[derive(Debug)]
pub struct PmtResult {
    pub merkle_root: [u8; 32],
    pub matched_hashes: Vec<[u8; 32]>,
}

impl PartialMerkleTree {
    /// `new PartialMerkleTree(params, data, 0)`; `None` where bitcoinj throws.
    pub fn parse(data: &[u8]) -> Option<Self> {
        bitcoinj::PartialMerkleTree::parse(data).ok().map(Self)
    }

    /// rskj `PartialMerkleTreeFormatUtils.hasExpectedSize`.
    pub fn has_expected_size(data: &[u8]) -> bool {
        bitcoinj::has_expected_size(data)
    }

    /// The block's transaction count, as the Java `int` bitcoinj reads it into.
    pub fn transaction_count(&self) -> i32 {
        self.0.transaction_count()
    }

    /// `getTxnHashAndMerkleRoot`, in wire order; `None` where bitcoinj throws
    /// a `VerificationException`.
    pub fn extract_matches(&self) -> Option<PmtResult> {
        let (matched, root) = self.0.txn_hashes_and_merkle_root().ok()?;
        Some(PmtResult {
            merkle_root: reversed(root),
            matched_hashes: matched.into_iter().map(reversed).collect(),
        })
    }
}

fn reversed(mut hash: [u8; 32]) -> [u8; 32] {
    hash.reverse();
    hash
}

// ---------------------------------------------------------------------------
// Merkle Branch (for getBtcTransactionConfirmations)
// ---------------------------------------------------------------------------

/// rskj `MerkleBranch`: the hashes beside a transaction's on its way up the
/// tree, and its path, whose bit `i` is set where, `i` levels up, the
/// transaction's side is the right one. The hashes are in display order, as
/// rskj wraps the ones it is given.
#[derive(Debug)]
pub struct MerkleBranch {
    hashes: Vec<[u8; 32]>,
    path: i32,
}

impl MerkleBranch {
    /// rskj's constructor: no more than 32 hashes, and no more significant
    /// bits in the path than there are hashes. rskj's `significantBitCount`
    /// counts none in a path below zero. Where rskj throws, `None`.
    pub fn new(hashes: Vec<[u8; 32]>, path: i32) -> Option<Self> {
        let significant = if path > 0 {
            32 - path.leading_zeros() as usize
        } else {
            0
        };
        (hashes.len() <= 32 && significant <= hashes.len()).then_some(Self { hashes, path })
    }

    /// Parse from ABI-encoded arguments:
    /// `(bytes32 btcTxHash, bytes32 btcBlockHash, uint256 merkleBranchPath, bytes32[] merkleBranchHashes)`.
    /// The transaction and block hashes come back as given, in display order,
    /// and the path as rskj's `BigInteger.intValue` reads it, its low 32 bits.
    pub fn from_abi_args(args: &[u8]) -> Option<(Self, [u8; 32], [u8; 32])> {
        if args.len() < 128 {
            return None;
        }
        let tx_hash: [u8; 32] = args[0..32].try_into().ok()?;
        let block_hash: [u8; 32] = args[32..64].try_into().ok()?;
        let path = i32::from_be_bytes(args[92..96].try_into().ok()?);

        // The array's offset and, there, its length, each in its word's low
        // four bytes.
        let word = |at: usize| -> Option<usize> {
            Some(u32::from_be_bytes(args.get(at + 28..at + 32)?.try_into().ok()?) as usize)
        };
        let array_offset = word(96)?;
        let count = word(array_offset)?;
        let data_start = array_offset + 32;
        let mut hashes = Vec::new();
        for i in 0..count {
            let at = data_start + i * 32;
            hashes.push(args.get(at..at + 32)?.try_into().ok()?);
        }
        Some((MerkleBranch::new(hashes, path)?, tx_hash, block_hash))
    }

    /// `reduceFrom`: the root the branch climbs to from `tx_hash`, in display
    /// order. `None` where two of the nodes form a 64-byte transaction, where
    /// rskj's `MerkleTreeUtils.combineLeftRight` throws.
    pub fn reduce_from(&self, tx_hash: &[u8; 32]) -> Option<[u8; 32]> {
        let mut current = *tx_hash;
        for (index, sibling) in self.hashes.iter().enumerate() {
            // `(path >> index) & 1`, the constructor holding `index` below 32.
            let (left, right) = if (self.path >> index) & 1 == 1 {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            if parses_as_a_64_byte_transaction(&left, &right) {
                return None;
            }
            current = combine_left_right(&left, &right);
        }
        Some(current)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        alloy_primitives::hex::decode(hex.replace(char::is_whitespace, "")).unwrap()
    }

    fn hex_to_32(hex: &str) -> [u8; 32] {
        hex_to_bytes(hex).try_into().unwrap()
    }

    #[test]
    fn has_expected_size_rejects_short() {
        assert!(!PartialMerkleTree::has_expected_size(&[]));
        assert!(!PartialMerkleTree::has_expected_size(&[0, 0, 0]));
    }

    /// A block of one transaction, matched: the tree is its hash alone, and
    /// so is the root.
    #[test]
    fn simple_pmt_single_tx() {
        let mut data = 1u32.to_le_bytes().to_vec();
        data.push(1);
        data.extend_from_slice(&[0xAA; 32]);
        data.push(1);
        data.push(0x01);

        assert!(PartialMerkleTree::has_expected_size(&data));
        let pmt = PartialMerkleTree::parse(&data).unwrap();
        assert_eq!(pmt.transaction_count(), 1);
        let result = pmt.extract_matches().unwrap();
        assert_eq!(result.matched_hashes, [[0xAA; 32]]);
        assert_eq!(result.merkle_root, [0xAA; 32]);
    }

    /// Ported from rskj PartialMerkleTreeFormatUtilsTest: the canonical blob
    /// has its expected size, with a byte gone it has not, and with a hash
    /// count that overflows no size can be worked out.
    #[test]
    fn rskj_pmt_format_vectors() {
        let canonical = "030000000279e7c0da739df8a00f12c0bff55e5438f530aa5859ff98\
                         74258cd7bad3fe709746aff897e6a851faa80120d6ae99db30883699\
                         ac0428fc7192d6c3fec0ca6409010d";
        let data = hex_to_bytes(canonical);
        assert!(PartialMerkleTree::has_expected_size(&data));
        assert_eq!(
            PartialMerkleTree::parse(&data).unwrap().transaction_count(),
            3
        );

        let short = canonical.replace("ca6409010d", "ca64010d");
        assert!(!PartialMerkleTree::has_expected_size(&hex_to_bytes(&short)));
        let overflow = canonical.replacen("0300000002", "0300ffffff", 1);
        assert!(!PartialMerkleTree::has_expected_size(&hex_to_bytes(
            &overflow
        )));
    }

    /// rskj's MerkleBranchTest vectors, display order as rskj gives them: one,
    /// two and three hashes climb to their roots, and a wrong path does not.
    #[test]
    fn rskj_merkle_branch_vectors() {
        let cases: [(&[&str], i32, &str, &str); 4] = [
            (
                &["3709934297f8bfd8a1cfcf82514bbfdcc910cf4d934e0eabd58b6eb955954b45"],
                1,
                "444f6714a6010b452d705531fb9ed850f2578ef28c364676d7e9f3f436c25554",
                "71306e0f38f1f606d7a4eadf22814432321b2a6d6f40c94fdc8e7dd2bbcef47f",
            ),
            (
                &[
                    "bfc0770be0c8bc9d06714b00c89cc769286968c28632aa7768f9525a0287d5e6",
                    "ad13c3242a67436e8958c0b1a76ff017d1e0c36ab7b38b98d7fb3df9ebea2bff",
                ],
                3,
                "9f4c1131e3dfab1b0413f97d53cab183f48f4ed0003387e7cbadea0c1f4ce365",
                "14fd0a443ebba0fe62e323b5250fb13042e7840701058fb025032f1527f8f6f5",
            ),
            (
                &[
                    "81aa2c77c201daab3868da9a4c2e29bc1e42bdc804c7c8a4d84c5e7f3866fb3f",
                    "bed5ecce0c0ffa58236271d4ca49767c968fb6aba6aa3c10abe31170ca826404",
                    "f733ca23def34db37b79af4c65d5929be741b79a1d74006153892b87487d1137",
                ],
                5,
                "807d74e37d9c39a315eb74955889c9be83ba33eaaf9735a9617211870cde22b2",
                "f7f0eb7ba33dd6f37ad11153d1bc803cd6f932051d72fa73343bff59d270e9ef",
            ),
            (
                &[
                    "807d74e37d9c39a315eb74955889c9be83ba33eaaf9735a9617211870cde22b2",
                    "bed5ecce0c0ffa58236271d4ca49767c968fb6aba6aa3c10abe31170ca826404",
                    "f733ca23def34db37b79af4c65d5929be741b79a1d74006153892b87487d1137",
                ],
                4,
                "81aa2c77c201daab3868da9a4c2e29bc1e42bdc804c7c8a4d84c5e7f3866fb3f",
                "f7f0eb7ba33dd6f37ad11153d1bc803cd6f932051d72fa73343bff59d270e9ef",
            ),
        ];
        for (hashes, path, tx, root) in cases {
            let hashes: Vec<_> = hashes.iter().map(|h| hex_to_32(h)).collect();
            let branch = MerkleBranch::new(hashes.clone(), path).unwrap();
            assert_eq!(
                branch.reduce_from(&hex_to_32(tx)),
                Some(hex_to_32(root)),
                "path {path}"
            );
            if path == 4 {
                let wrong = MerkleBranch::new(hashes, 3).unwrap();
                assert_ne!(wrong.reduce_from(&hex_to_32(tx)), Some(hex_to_32(root)));
            }
        }
    }

    /// rskj's MerkleBranch takes at most 32 hashes and a path with no more
    /// significant bits than hashes, counting none in a negative path.
    #[test]
    fn a_merkle_branch_is_held_to_rskjs_constructor() {
        let hashes = |n: usize| vec![[0x5a; 32]; n];
        assert!(MerkleBranch::new(hashes(32), 0).is_some());
        assert!(MerkleBranch::new(hashes(33), 0).is_none());
        assert!(MerkleBranch::new(hashes(3), 0b111).is_some());
        assert!(MerkleBranch::new(hashes(3), 0b1000).is_none());
        assert!(MerkleBranch::new(hashes(0), 0).is_some());
        assert!(MerkleBranch::new(hashes(0), 1).is_none());
        assert!(MerkleBranch::new(hashes(1), i32::MIN).is_some());
        assert!(MerkleBranch::new(hashes(31), i32::MAX).is_some());
        assert!(MerkleBranch::new(hashes(30), i32::MAX).is_none());
    }

    /// Two nodes that read, in display order, as a 64-byte Bitcoin
    /// transaction stop the climb, on whichever side the transaction sits.
    #[test]
    fn a_merkle_branch_through_a_transaction_shaped_pair_fails() {
        let transaction = [
            &[1u8, 0, 0, 0][..],
            &[1],
            &[0x11; 32],
            &[0, 0, 0, 0],
            &[2, 0xaa, 0xbb],
            &[0xff; 4],
            &[1],
            &1i64.to_le_bytes(),
            &[2, 0xcc, 0xdd],
            &[0; 4],
        ]
        .concat();
        let left: [u8; 32] = transaction[..32].try_into().unwrap();
        let right: [u8; 32] = transaction[32..].try_into().unwrap();
        let on_the_left = MerkleBranch::new(vec![right], 0).unwrap();
        assert_eq!(on_the_left.reduce_from(&left), None);
        let on_the_right = MerkleBranch::new(vec![left], 1).unwrap();
        assert_eq!(on_the_right.reduce_from(&right), None);
        // The other way round they are no transaction.
        assert!(MerkleBranch::new(vec![left], 0)
            .unwrap()
            .reduce_from(&right)
            .is_some());
    }

    /// The ABI's path is read as rskj's `BigInteger.intValue` reads it, and the
    /// branch is held to rskj's constructor.
    #[test]
    fn merkle_branch_abi_args() {
        let args = |path: [u8; 32], count: usize| {
            let mut args = [[0x01; 32], [0x02; 32], path].concat();
            let mut offset = [0u8; 32];
            offset[31] = 128;
            args.extend(offset);
            let mut length = [0u8; 32];
            length[31] = count as u8;
            args.extend(length);
            for i in 0..count {
                args.extend([i as u8; 32]);
            }
            args
        };
        let mut path = [0u8; 32];
        path[31] = 0b10;
        let (branch, tx, block) = MerkleBranch::from_abi_args(&args(path, 2)).unwrap();
        assert_eq!(
            (branch.path, branch.hashes.len(), tx, block),
            (2, 2, [0x01; 32], [0x02; 32])
        );
        // Only the low 32 bits count: this path is -1, of no significant bits.
        let high = [0xff; 32];
        assert_eq!(
            MerkleBranch::from_abi_args(&args(high, 1)).unwrap().0.path,
            -1
        );
        path[31] = 0b100;
        assert!(MerkleBranch::from_abi_args(&args(path, 2)).is_none());
        assert!(MerkleBranch::from_abi_args(&args([0; 32], 33)).is_none());
    }

    /// Ported from rskj MerkleTreeUtilsTest.combineLeftRight: three vectors
    /// from bitcoind regtest, display order.
    #[test]
    fn rskj_combine_left_right_vectors() {
        for (left, right, expected) in [
            (
                "b945b008fbc3f357db745909958b570773fc14575a36af8bbc195b484e21f366",
                "9880f57b6735152a8c6d4c7e1b3bc6434ee75e459511a642bbb8cb71d3a6b6d8",
                "ceea4835dd23fae1978a3f6f3f0aa0171e018360272dd5b98d37550fbc978d01",
            ),
            (
                "083eafdf670bb1bbc83b63262887e3cf519c3e252fac29adfb92c1e857b37f91",
                "5740915e973a211c71655d10e4c672301c27c287843dcfa97b7aafc04992ec5e",
                "107857d7233c41d4c37ecaa9ad9d9ab15371f643074866cd23d657e6e99676be",
            ),
            (
                "c960ed36a67318cd562d384bfbf41499db1312835e2bfe86805d9465afe9736f",
                "120196be3b0ca6ba07d3cfee53f8dc883781e82afdfba11181184f41a67b9898",
                "71a12c9bd54735864dd6e12640e6d00d60a42a2e92e4cd0bde3f9f268b7d4345",
            ),
        ] {
            let combined = combine_left_right(&hex_to_32(left), &hex_to_32(right));
            assert_eq!(combined, hex_to_32(expected));
        }
    }

    /// Groundtruth: the PMT from the first mainnet peg-in (RSK #6916,
    /// registerBtcTransaction at BTC block #502,572). The extracted root must
    /// equal the real block merkle root
    /// 794bc781118b3bbe2c6a3a6ae21128bb50756e2dabe36e8225aacc133375835d
    /// (display order) and the matches must include the peg-in txid
    /// b4b31c7c486d1e2594f8fb96962d023a7b1eadf322862eed098deee0464394b5.
    #[test]
    fn mainnet_6916_pegin_pmt_extracts_real_root() {
        let pmt_bytes = alloy_primitives::hex::decode("630800000d14e6e59463afbfd4155db84d7592b5af577ef5dc0e9d906676e9ec81f37401d472706346992d8220d9138dc144077bdbf5522de323024c2cf3d74e239fc11fb2afc6543956e6fb6f0cc43c5dd4c66fd271eff5f9309768dd7c267d767725f4538a093bb1fa025a85c0cd4967119bc286d9a951a828a7c413e4a8994ded5b9077b5944346e0ee8d09ed2e8622f3ad1e7b3a022d9696fbf894251e6d487c1cb3b4522650fec9201f035d965ce42cfcc157b388470b6f6ff15dd72fd5651a57586cab8bac3b5531b3f490a97b2363a2ef18121a43873753a08e35991732fb789265cd9dd43584dbe701bb953f21af68029a30d8b6327cd57d2dd242327c1b135d4c8f5e36b8bf09f6e52420834e8e0e0b1a6df563aba550cf7f99e9724264187c45dcf3d73e8585a0e351963062f66fa39895750a0f0c651f2fc736d69b746ed77319d5c0ecab6539d3655f163f3eccf325846b1c1244e17b6464d5b85c3cd06587cf992067f37c086d17ab6dd35ee7aef6de22ac59ed37468ee5eb15948db42c438fdfb4c5b08d6316a203bcecd9713b9a2b150614ee116dcff986c29c2246745704bbdb0100").unwrap();
        assert!(PartialMerkleTree::has_expected_size(&pmt_bytes));
        let pmt = PartialMerkleTree::parse(&pmt_bytes).expect("parse");
        let result = pmt.extract_matches().expect("extract");

        // Internal (little-endian) byte order, as stored in BTC headers.
        let mut expected_root = alloy_primitives::hex::decode(
            "794bc781118b3bbe2c6a3a6ae21128bb50756e2dabe36e8225aacc133375835d",
        )
        .unwrap();
        expected_root.reverse();
        assert_eq!(result.merkle_root.to_vec(), expected_root, "merkle root");

        let mut expected_txid = alloy_primitives::hex::decode(
            "b4b31c7c486d1e2594f8fb96962d023a7b1eadf322862eed098deee0464394b5",
        )
        .unwrap();
        expected_txid.reverse();
        let contains = result
            .matched_hashes
            .iter()
            .any(|h| h.to_vec() == expected_txid);
        assert!(contains, "matched hashes must include the peg-in txid");
    }
}
