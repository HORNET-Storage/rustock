//! A Bitcoin partial Merkle tree, as bitcoinj-thin's `PartialMerkleTree`
//! (`v0.14.4-rsk-20`) reads and walks it, and as rskj's
//! `PartialMerkleTreeFormatUtils.hasExpectedSize` sizes it.
//!
//! rskj reads one wherever it has to be shown that a Bitcoin transaction is
//! in a Bitcoin block: below RSKIP92, a merge-mined block's coinbase
//! (`GenesisMerkleProofValidator`), and in the Bridge, a peg-in or a coinbase
//! registered for its witness root. Each goes through the one bitcoinj
//! class, so each goes through this.
//!
//! bitcoinj holds every hash in display order, the reverse of the bytes a
//! Bitcoin block hashes, and so does this. The hashes a tree matches and its
//! root come back that way, and two nodes are tested for a 64-byte
//! transaction that way, as bitcoinj tests them.
//!
//! A tree is the block's transaction count, four bytes little-endian, read
//! into a Java `int`; a varint count of hashes, then the hashes, 32 bytes
//! each; and a varint count of flag bytes, then the flag bytes, whose bits
//! are read least significant first.

use crate::validation::merged_mining::{combine_left_right, parses_as_a_64_byte_transaction};

/// bitcoinj `BtcBlock.MAX_BLOCK_SIZE / 60`: no more transactions than a
/// block of a million bytes holds at 60 bytes each, the least one takes.
pub const MAX_TRANSACTIONS: i32 = 1_000_000 / 60;

/// bitcoinj `Message.MAX_SIZE`: the longest array it reads, 32 MiB.
const MAX_ARRAY: i32 = 0x0200_0000;

/// Where bitcoinj throws: a `ProtocolException` reading a tree, or a
/// `VerificationException` walking it. rskj takes them alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PmtError {
    #[error("the partial merkle tree runs past its bytes, or counts below zero")]
    Unreadable,
    #[error("the partial merkle tree has no transactions")]
    NoTransactions,
    #[error("the partial merkle tree has more transactions than a block holds")]
    TooManyTransactions,
    #[error("the partial merkle tree has more hashes than transactions")]
    MoreHashesThanTransactions,
    #[error("the partial merkle tree has fewer flag bits than hashes")]
    FewerBitsThanHashes,
    #[error("the partial merkle tree runs out of flag bits")]
    OutOfBits,
    #[error("the partial merkle tree runs out of hashes")]
    OutOfHashes,
    #[error("the partial merkle tree repeats a branch")]
    DuplicatedBranches,
    #[error("two nodes of the partial merkle tree form a Bitcoin transaction")]
    NodesFormTransaction,
    #[error("the partial merkle tree has flag bits or hashes it does not use")]
    UnusedData,
}

/// A partial Merkle tree as bitcoinj reads one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMerkleTree {
    transaction_count: i32,
    /// In display order: bitcoinj's `readHash` reverses each.
    hashes: Vec<[u8; 32]>,
    matched_child_bits: Vec<u8>,
}

impl PartialMerkleTree {
    /// `new PartialMerkleTree(params, payload, 0)`, which reads a tree from the
    /// start of `payload` and leaves whatever follows it unread.
    pub fn parse(payload: &[u8]) -> Result<Self, PmtError> {
        let count = payload.get(..4).ok_or(PmtError::Unreadable)?;
        // `(int) readUint32()`: from 2^31 on, negative.
        let transaction_count = u32::from_le_bytes(count.try_into().expect("four bytes")) as i32;
        let mut cursor = 4;

        // `(int) readVarInt()` keeps a varint's low 32 bits, and a count
        // below zero sizes the list bitcoinj makes for the hashes below zero,
        // which throws.
        let (hash_count, size) = var_int(payload, cursor).ok_or(PmtError::Unreadable)?;
        cursor += size;
        let hash_count = hash_count as i32;
        if hash_count < 0 {
            return Err(PmtError::Unreadable);
        }
        let mut hashes = Vec::new();
        for _ in 0..hash_count {
            let wire = payload
                .get(cursor..cursor + 32)
                .ok_or(PmtError::Unreadable)?;
            let mut hash: [u8; 32] = wire.try_into().expect("32 bytes");
            hash.reverse();
            hashes.push(hash);
            cursor += 32;
        }

        // `readBytes((int) readVarInt())`, which refuses more than 32 MiB or
        // more than is left, and below zero cannot make the array.
        let (flag_bytes, size) = var_int(payload, cursor).ok_or(PmtError::Unreadable)?;
        cursor += size;
        let flag_bytes = flag_bytes as i32;
        if !(0..=MAX_ARRAY).contains(&flag_bytes) {
            return Err(PmtError::Unreadable);
        }
        let bits = payload
            .get(cursor..cursor + flag_bytes as usize)
            .ok_or(PmtError::Unreadable)?;

        Ok(Self {
            transaction_count,
            hashes,
            matched_child_bits: bits.to_vec(),
        })
    }

    /// The block's transaction count, as the Java `int` bitcoinj holds it in.
    pub fn transaction_count(&self) -> i32 {
        self.transaction_count
    }

    /// The tree's hashes, in display order.
    pub fn hashes(&self) -> &[[u8; 32]] {
        &self.hashes
    }

    /// The flag bytes.
    pub fn matched_child_bits(&self) -> &[u8] {
        &self.matched_child_bits
    }

    /// `getTxnHashAndMerkleRoot`: the transactions the tree matches and the
    /// root it walks up to, both in display order.
    pub fn txn_hashes_and_merkle_root(&self) -> Result<(Vec<[u8; 32]>, [u8; 32]), PmtError> {
        let count = self.transaction_count;
        if count == 0 {
            return Err(PmtError::NoTransactions);
        }
        if count > MAX_TRANSACTIONS {
            return Err(PmtError::TooManyTransactions);
        }
        // Java `int`s, so a count below zero fails here.
        if self.hashes.len() as i64 > i64::from(count) {
            return Err(PmtError::MoreHashesThanTransactions);
        }
        // At least a bit for every node, and a node for every hash.
        if self.matched_child_bits.len() * 8 < self.hashes.len() {
            return Err(PmtError::FewerBitsThanHashes);
        }

        let mut height = 0;
        while tree_width(count, height) > 1 {
            height += 1;
        }
        let mut walk = Walk {
            tree: self,
            bits_used: 0,
            hashes_used: 0,
            matched: Vec::new(),
        };
        let root = walk.extract(height, 0)?;

        // Every bit, but for the last byte's padding, and every hash.
        if walk.bits_used.div_ceil(8) != self.matched_child_bits.len()
            || walk.hashes_used != self.hashes.len()
        {
            return Err(PmtError::UnusedData);
        }
        Ok((walk.matched, root))
    }
}

/// bitcoinj `getTreeWidth`: how many nodes the tree of `count` transactions
/// has `height` levels up.
fn tree_width(count: i32, height: u32) -> i32 {
    (count + (1 << height) - 1) >> height
}

/// bitcoinj's `recursiveExtractHashes`, with its `ValuesUsed` and the list it
/// gathers the matched hashes in.
struct Walk<'a> {
    tree: &'a PartialMerkleTree,
    bits_used: usize,
    hashes_used: usize,
    matched: Vec<[u8; 32]>,
}

impl Walk<'_> {
    /// The hash of the node `height` levels up at `pos`, depth first.
    fn extract(&mut self, height: u32, pos: i32) -> Result<[u8; 32], PmtError> {
        let bits = &self.tree.matched_child_bits;
        if self.bits_used >= bits.len() * 8 {
            return Err(PmtError::OutOfBits);
        }
        let bit = self.bits_used;
        self.bits_used += 1;
        let parent_of_match = bits[bit / 8] & (1 << (bit % 8)) != 0;

        if height == 0 || !parent_of_match {
            // A leaf, or nothing matched below: the node's hash is given.
            let Some(&hash) = self.tree.hashes.get(self.hashes_used) else {
                return Err(PmtError::OutOfHashes);
            };
            self.hashes_used += 1;
            if height == 0 && parent_of_match {
                self.matched.push(hash);
            }
            return Ok(hash);
        }

        let left = self.extract(height - 1, pos * 2)?;
        let right = if pos * 2 + 1 < tree_width(self.tree.transaction_count, height - 1) {
            let right = self.extract(height - 1, pos * 2 + 1)?;
            if right == left {
                return Err(PmtError::DuplicatedBranches);
            }
            right
        } else {
            left
        };
        if parses_as_a_64_byte_transaction(&left, &right) {
            return Err(PmtError::NodesFormTransaction);
        }
        Ok(combine_left_right(&left, &right))
    }
}

/// rskj `PartialMerkleTreeFormatUtils.hasExpectedSize`: whether `pmt` is
/// exactly the tree its two counts declare, nothing short and nothing over.
/// rskj works the sizes out in Java's exact `int` arithmetic, where an
/// overflow throws, and takes any throw for a no; so does this.
pub fn has_expected_size(pmt: &[u8]) -> bool {
    declared_size(pmt).is_some_and(|size| i64::from(size) == pmt.len() as i64)
}

/// The size `pmt`'s counts declare, where rskj can work it out.
fn declared_size(pmt: &[u8]) -> Option<i32> {
    // `getHashesCount`, the varint after the transaction count, and
    // `Math.multiplyExact(Math.toIntExact(count), 32)`.
    let (hashes, hashes_size) = var_int(pmt, 4)?;
    let hash_bytes = i32::try_from(hashes).ok()?.checked_mul(32)?;
    // `getFlagBitsCount`, the varint after the hashes, at an offset
    // `Math.addExact` works out; one below zero is outside the array.
    let flags_at = (4 + hashes_size as i32).checked_add(hash_bytes)?;
    let (flags, flags_size) = var_int(pmt, usize::try_from(flags_at).ok()?)?;
    let flags = i32::try_from(flags).ok()?;
    (4 + hashes_size as i32 + flags_size as i32)
        .checked_add(flags)?
        .checked_add(hash_bytes)
}

/// bitcoinj `new VarInt(buf, offset)`: the value in the Java `long` it is
/// read into, where a nine-byte one can be negative, and how many bytes it
/// took. `None` where it runs past the end, where bitcoinj throws.
pub fn var_int(buf: &[u8], offset: usize) -> Option<(i64, usize)> {
    let first = *buf.get(offset)?;
    let rest = |n: usize| buf.get(offset + 1..offset + 1 + n);
    Some(match first {
        0..=252 => (i64::from(first), 1),
        253 => (i64::from(u16::from_le_bytes(rest(2)?.try_into().ok()?)), 3),
        254 => (i64::from(u32::from_le_bytes(rest(4)?.try_into().ok()?)), 5),
        255 => (i64::from_le_bytes(rest(8)?.try_into().ok()?), 9),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaf for the tests, in display order.
    fn leaf(i: usize) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest((i as u64).to_le_bytes()).into()
    }

    fn var_int_bytes(n: usize) -> Vec<u8> {
        match n {
            0..=252 => vec![n as u8],
            253..=0xffff => [vec![0xfd], (n as u16).to_le_bytes().to_vec()].concat(),
            _ => [vec![0xfe], (n as u32).to_le_bytes().to_vec()].concat(),
        }
    }

    /// bitcoinj `buildFromLeaves` and `bitcoinSerializeToStream`: the tree over
    /// `leaves`, in display order, that matches those `include` marks.
    fn build(leaves: &[[u8; 32]], include: &[bool]) -> Vec<u8> {
        fn width(n: usize, height: u32) -> usize {
            (n + (1 << height) - 1) >> height
        }
        fn hash(height: u32, pos: usize, leaves: &[[u8; 32]]) -> [u8; 32] {
            if height == 0 {
                return leaves[pos];
            }
            let left = hash(height - 1, pos * 2, leaves);
            let right = if pos * 2 + 1 < width(leaves.len(), height - 1) {
                hash(height - 1, pos * 2 + 1, leaves)
            } else {
                left
            };
            combine_left_right(&left, &right)
        }
        struct Built {
            bits: Vec<bool>,
            hashes: Vec<[u8; 32]>,
        }
        fn traverse(
            height: u32,
            pos: usize,
            leaves: &[[u8; 32]],
            include: &[bool],
            out: &mut Built,
        ) {
            let below = pos << height..((pos + 1) << height).min(leaves.len());
            let parent_of_match = below.into_iter().any(|p| include[p]);
            out.bits.push(parent_of_match);
            if height == 0 || !parent_of_match {
                out.hashes.push(hash(height, pos, leaves));
            } else {
                traverse(height - 1, pos * 2, leaves, include, out);
                if pos * 2 + 1 < width(leaves.len(), height - 1) {
                    traverse(height - 1, pos * 2 + 1, leaves, include, out);
                }
            }
        }

        let mut height = 0;
        while width(leaves.len(), height) > 1 {
            height += 1;
        }
        let mut built = Built {
            bits: Vec::new(),
            hashes: Vec::new(),
        };
        traverse(height, 0, leaves, include, &mut built);
        let mut flags = vec![0u8; built.bits.len().div_ceil(8)];
        for (i, bit) in built.bits.iter().enumerate() {
            if *bit {
                flags[i / 8] |= 1 << (i % 8);
            }
        }
        let mut out = (leaves.len() as u32).to_le_bytes().to_vec();
        out.extend(var_int_bytes(built.hashes.len()));
        for hash in &built.hashes {
            out.extend(hash.iter().rev());
        }
        out.extend(var_int_bytes(flags.len()));
        out.extend(flags);
        out
    }

    /// The root of the whole tree over `leaves`, level by level, the last
    /// node of an odd level paired with itself.
    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| combine_left_right(&pair[0], pair.get(1).unwrap_or(&pair[0])))
                .collect();
        }
        level[0]
    }

    fn walked(tree: &[u8]) -> Result<(Vec<[u8; 32]>, [u8; 32]), PmtError> {
        PartialMerkleTree::parse(tree)?.txn_hashes_and_merkle_root()
    }

    /// A tree bitcoinj builds walks back to the root of the whole tree, and
    /// matches the leaves it was built to, whatever their number and wherever
    /// they sit.
    #[test]
    fn a_tree_walks_back_to_the_whole_trees_root() {
        for n in (1..=40).chain([63, 64, 65, 255, 1000]) {
            let leaves: Vec<_> = (0..n).map(leaf).collect();
            let root = merkle_root(&leaves);
            let mut patterns: Vec<Vec<bool>> = vec![
                (0..n).map(|i| i == 0).collect(),
                (0..n).map(|i| i == n - 1).collect(),
                (0..n).map(|i| i % 3 == 1).collect(),
                vec![true; n],
            ];
            if n <= 40 {
                patterns.extend((0..n).map(|k| (0..n).map(|i| i == k).collect()));
            }
            for include in patterns {
                let tree = build(&leaves, &include);
                assert!(has_expected_size(&tree), "{n} leaves");
                let want: Vec<_> = (0..n).filter(|i| include[*i]).map(|i| leaves[i]).collect();
                assert_eq!(walked(&tree), Ok((want, root)), "{n} leaves, {include:?}");
            }
        }
    }

    /// rskj's `PartialMerkleTreeFormatUtilsTest`: a tree of three transactions
    /// and two hashes has the size its counts declare; with a byte lost from
    /// the middle it has not, and with a hash count that overflows no size
    /// can be worked out.
    #[test]
    fn rskjs_format_vectors() {
        let tree = hex::decode(
            "030000000279e7c0da739df8a00f12c0bff55e5438f530aa5859ff9874258cd7bad3fe70\
             9746aff897e6a851faa80120d6ae99db30883699ac0428fc7192d6c3fec0ca6409010d",
        )
        .unwrap();
        assert!(has_expected_size(&tree));
        let parsed = PartialMerkleTree::parse(&tree).unwrap();
        assert_eq!(parsed.transaction_count(), 3);
        assert_eq!(parsed.hashes().len(), 2);
        assert_eq!(parsed.matched_child_bits(), [0x0d]);

        let short = [&tree[..tree.len() - 3], &tree[tree.len() - 2..]].concat();
        assert!(!has_expected_size(&short));
        // rskj's `overflowSize`: "0300ffffff79e7c0...", a nine-byte hash count.
        let overflow = [&[0x03, 0x00, 0xff, 0xff, 0xff][..], &tree[5..]].concat();
        assert!(!has_expected_size(&overflow));
    }

    /// The first peg-in on mainnet, at RSK #6916, proves Bitcoin transaction
    /// b4b31c7c...94b5 in Bitcoin block #502,572, whose Merkle root is
    /// 794bc781...835d.
    #[test]
    fn mainnets_first_peg_in_walks_to_its_blocks_root() {
        let tree = hex::decode(
            "630800000d14e6e59463afbfd4155db84d7592b5af577ef5dc0e9d906676e9ec81f37401\
             d472706346992d8220d9138dc144077bdbf5522de323024c2cf3d74e239fc11fb2afc654\
             3956e6fb6f0cc43c5dd4c66fd271eff5f9309768dd7c267d767725f4538a093bb1fa025a\
             85c0cd4967119bc286d9a951a828a7c413e4a8994ded5b9077b5944346e0ee8d09ed2e86\
             22f3ad1e7b3a022d9696fbf894251e6d487c1cb3b4522650fec9201f035d965ce42cfcc1\
             57b388470b6f6ff15dd72fd5651a57586cab8bac3b5531b3f490a97b2363a2ef18121a43\
             873753a08e35991732fb789265cd9dd43584dbe701bb953f21af68029a30d8b6327cd57d\
             2dd242327c1b135d4c8f5e36b8bf09f6e52420834e8e0e0b1a6df563aba550cf7f99e972\
             4264187c45dcf3d73e8585a0e351963062f66fa39895750a0f0c651f2fc736d69b746ed7\
             7319d5c0ecab6539d3655f163f3eccf325846b1c1244e17b6464d5b85c3cd06587cf9920\
             67f37c086d17ab6dd35ee7aef6de22ac59ed37468ee5eb15948db42c438fdfb4c5b08d63\
             16a203bcecd9713b9a2b150614ee116dcff986c29c2246745704bbdb0100",
        )
        .unwrap();
        assert!(has_expected_size(&tree));
        let (matched, root) = walked(&tree).unwrap();
        let display = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        assert_eq!(
            root,
            display("794bc781118b3bbe2c6a3a6ae21128bb50756e2dabe36e8225aacc133375835d")
        );
        assert_eq!(
            matched,
            [display(
                "b4b31c7c486d1e2594f8fb96962d023a7b1eadf322862eed098deee0464394b5"
            )]
        );
    }

    /// A tree as bitcoinj writes it, with its count, its hashes and its flags.
    fn tree(count: u32, hashes: &[[u8; 32]], flags: &[u8]) -> Vec<u8> {
        let mut out = count.to_le_bytes().to_vec();
        out.extend(var_int_bytes(hashes.len()));
        for hash in hashes {
            out.extend(hash.iter().rev());
        }
        out.extend(var_int_bytes(flags.len()));
        out.extend(flags);
        out
    }

    /// Each of bitcoinj's refusals, at the first thing it checks that fails.
    #[test]
    fn bitcoinj_refuses_what_it_refuses() {
        let (a, b) = (leaf(1), leaf(2));
        let cases: [(&str, Vec<u8>, PmtError); 9] = [
            (
                "no transactions",
                tree(0, &[a], &[1]),
                PmtError::NoTransactions,
            ),
            (
                "a count past 2^31",
                tree(u32::MAX, &[], &[]),
                PmtError::MoreHashesThanTransactions,
            ),
            (
                "two hashes, one transaction",
                tree(1, &[a, b], &[1]),
                PmtError::MoreHashesThanTransactions,
            ),
            (
                "nine hashes, eight bits",
                tree(9, &[a; 9], &[0xff]),
                PmtError::FewerBitsThanHashes,
            ),
            ("no bits", tree(4, &[], &[]), PmtError::OutOfBits),
            ("no hashes", tree(2, &[], &[0]), PmtError::OutOfHashes),
            (
                "a byte of flags unused",
                tree(1, &[a], &[1, 0]),
                PmtError::UnusedData,
            ),
            (
                "a hash unused",
                tree(2, &[a, b], &[0]),
                PmtError::UnusedData,
            ),
            (
                "a branch repeated",
                build(&[a, a], &[true, false]),
                PmtError::DuplicatedBranches,
            ),
        ];
        for (what, tree, error) in cases {
            assert_eq!(walked(&tree), Err(error), "{what}");
        }
    }

    /// bitcoinj walks a tree of 16,666 transactions and no more.
    #[test]
    fn a_tree_holds_at_most_16666_transactions() {
        for (n, walks) in [(16_666, true), (16_667, false)] {
            let leaves: Vec<_> = (0..n).map(leaf).collect();
            let include: Vec<_> = (0..n).map(|i| i == n / 2).collect();
            let result = walked(&build(&leaves, &include));
            if walks {
                assert_eq!(result.map(|r| r.1), Ok(merkle_root(&leaves)));
            } else {
                assert_eq!(result, Err(PmtError::TooManyTransactions));
            }
        }
    }

    /// Two nodes that read, in display order, as a 64-byte Bitcoin
    /// transaction stop the walk where they would be combined.
    #[test]
    fn two_nodes_that_form_a_transaction_stop_the_walk() {
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
        assert!(parses_as_a_64_byte_transaction(&left, &right));
        assert_eq!(
            walked(&build(&[left, right], &[true, false])),
            Err(PmtError::NodesFormTransaction)
        );
        // The same two the other way round are no transaction.
        assert!(walked(&build(&[right, left], &[true, false])).is_ok());
    }

    /// bitcoinj reads a tree from the start and leaves the rest. It casts each
    /// varint to an `int`, so a nine-byte count keeps its low 32 bits, and
    /// it refuses a count that is negative there, or a flag count over
    /// 32 MiB, or bytes that are not there.
    #[test]
    fn bitcoinj_reads_a_tree_as_java_does() {
        let one = tree(1, &[leaf(1)], &[1]);
        assert_eq!(walked(&[one.clone(), vec![0xee; 3]].concat()), walked(&one));
        for cut in 0..one.len() {
            assert_eq!(
                PartialMerkleTree::parse(&one[..cut]),
                Err(PmtError::Unreadable),
                "{cut} bytes"
            );
        }

        let count = &one[..4];
        let hash = &one[5..37];
        let nine_bytes_for_one = [0xff, 1, 0, 0, 0, 1, 0, 0, 0];
        let wrapped = [count, &nine_bytes_for_one, hash, &[1, 1]].concat();
        assert_eq!(
            PartialMerkleTree::parse(&wrapped).unwrap().hashes().len(),
            1
        );
        assert!(!has_expected_size(&wrapped), "toIntExact refuses it");

        let minus_one = [0xfe, 0xff, 0xff, 0xff, 0xff];
        let negative_hashes = [count, &minus_one[..], hash, &[1, 1]].concat();
        assert_eq!(
            PartialMerkleTree::parse(&negative_hashes),
            Err(PmtError::Unreadable)
        );
        // Below zero, where what follows would read as flags, and at 2^31.
        for negative in [&minus_one[..], &[0xfe, 0, 0, 0, 0x80]] {
            let then_flags = [count, negative, &[1, 1]].concat();
            assert_eq!(
                PartialMerkleTree::parse(&then_flags),
                Err(PmtError::Unreadable)
            );
        }
        let negative_flags = [count, &[1], hash, &minus_one[..], &[1]].concat();
        assert_eq!(
            PartialMerkleTree::parse(&negative_flags),
            Err(PmtError::Unreadable)
        );
        let over_32_mib = [count, &[1], hash, &[0xfe, 1, 0, 0, 2], &[1]].concat();
        assert_eq!(
            PartialMerkleTree::parse(&over_32_mib),
            Err(PmtError::Unreadable)
        );
        // 32 MiB of flags are bitcoinj's most, there or not.
        let flags = |n: u32| {
            [
                count,
                &[0],
                &[0xfe],
                &n.to_le_bytes(),
                &vec![0u8; n as usize][..],
            ]
            .concat()
        };
        assert!(PartialMerkleTree::parse(&flags(0x0200_0000)).is_ok());
        assert_eq!(
            PartialMerkleTree::parse(&flags(0x0200_0001)),
            Err(PmtError::Unreadable)
        );
    }

    /// rskj takes a varint in any of its widths and counts the bytes it
    /// took, refuses one past what an `int` holds, and takes no tree whose
    /// sizes cannot be worked out without overflowing one.
    #[test]
    fn the_size_is_worked_out_as_rskj_does() {
        let count = 1u32.to_le_bytes();
        let hash = leaf(1);
        let wide = [&count[..], &[0xfd, 1, 0], &hash, &[0xfe, 1, 0, 0, 0], &[1]].concat();
        assert!(has_expected_size(&wide));
        assert!(walked(&wide).is_ok());
        let after = [wide.clone(), vec![0]].concat();
        assert!(!has_expected_size(&after));
        assert!(!has_expected_size(&wide[..wide.len() - 1]));

        // A nine-byte flag count of -1 declares a byte fewer than its own.
        let minus_one = [0xff; 9];
        let negative = [&count[..], &[1], &hash, &minus_one[..]].concat();
        assert!(!has_expected_size(&negative));
        // A flag count past an `int`, its low 32 bits the one byte there.
        let past_an_int = [
            &count[..],
            &[1],
            &hash,
            &[0xff, 1, 0, 0, 0, 1, 0, 0, 0],
            &[1],
        ]
        .concat();
        assert!(
            PartialMerkleTree::parse(&past_an_int).is_ok(),
            "bitcoinj keeps the low 32 bits"
        );
        assert!(!has_expected_size(&past_an_int), "toIntExact refuses it");
        // 2^26 hashes are 2^31 bytes, past an `int`; one fewer are not, but
        // the flag count would sit past the end.
        assert!(!has_expected_size(
            &[&count[..], &[0xfe, 0, 0, 0, 4]].concat()
        ));
        assert!(!has_expected_size(
            &[&count[..], &[0xfe, 0xff, 0xff, 0xff, 3]].concat()
        ));
        assert!(!has_expected_size(&[]));
        assert!(!has_expected_size(&count));
    }

    /// No variation on a tree's bytes makes reading, sizing or walking it
    /// panic: a peer's merge-mined header carries one below orchid, and a
    /// peg-in carries one to the Bridge.
    #[test]
    fn no_variation_on_a_tree_panics() {
        let leaves: Vec<[u8; 32]> = (0..33).map(leaf).collect();
        let shapes: [(usize, &[usize]); 4] =
            [(1, &[0]), (7, &[2, 5]), (16, &[15]), (33, &[0, 17, 32])];
        for (i, (count, matched)) in shapes.into_iter().enumerate() {
            let include: Vec<bool> = (0..count).map(|n| matched.contains(&n)).collect();
            let seed = build(&leaves[..count], &include);
            assert!(walked(&seed).is_ok());
            for bytes in crate::mutate::mutants(&seed, 2_000, 500 + i as u64) {
                let _ = has_expected_size(&bytes);
                let _ = walked(&bytes);
            }
        }
    }
}
