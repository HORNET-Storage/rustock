//! Whether bitcoinj-thin's `BtcBlock` (`v0.14.4-rsk-20`) makes a Bitcoin
//! block of some bytes, or throws.
//!
//! Below RSKIP98 (orchid), rskj's `ProofOfWorkRule` takes a merge-mined
//! block's Bitcoin-header field at any length and makes a bitcoinj block of
//! it: the 80 bytes of a header and, if anything follows, the block's
//! transactions. Nothing after the header is used, but where bitcoinj cannot
//! read it, it throws, and the block is refused. Every merge-mined header on
//! mainnet below orchid is the 80 bytes alone; this decides the rest as
//! bitcoinj does.
//!
//! bitcoinj reads each input and output twice: once into its own message, and
//! once to step the transaction past it, in Java `long`s narrowed into an
//! `int` cursor. Wherever the first reading returns, the second lands where it
//! stopped, since each length it narrows was read whole the first time. So
//! only the first is followed here.

use crate::partial_merkle_tree::var_int;

/// bitcoinj `BtcBlock.HEADER_SIZE`.
pub const HEADER_SIZE: usize = 80;
/// bitcoinj `Message.MAX_SIZE`: the longest array `readBytes` makes, 32 MiB.
const MAX_SIZE: i32 = 0x0200_0000;
/// bitcoinj `TransactionOutPoint.MESSAGE_LENGTH`: a hash and an index.
const OUTPOINT_LENGTH: usize = 36;
/// bitcoinj `Utils.MAX_INITIAL_ARRAY_LENGTH`.
const MAX_INITIAL_ARRAY_LENGTH: i32 = 20;

/// Whether `new BtcBlock(params, payload, 0, serializer, payload.length)`
/// returns rather than throws.
pub fn bitcoinj_reads(payload: &[u8]) -> bool {
    Reader { payload, cursor: 0 }.block().is_some()
}

struct Reader<'a> {
    payload: &'a [u8],
    cursor: usize,
}

impl Reader<'_> {
    /// `BtcBlock.parse` and `parseTransactions`, which reads none where the
    /// header is all there is, and leaves unread whatever follows the last.
    fn block(&mut self) -> Option<()> {
        // Version, the previous block's hash, the merkle root, time, target
        // and nonce.
        self.skip(HEADER_SIZE)?;
        if self.cursor == self.payload.len() {
            return Some(());
        }
        let count = self.var_int()? as i32;
        list(count)?;
        for _ in 0..count {
            self.transaction()?;
        }
        Some(())
    }

    /// `BtcTransaction.parse`: with no inputs, a byte of flags follows, and
    /// its lowest bit, the only one known, says there are witnesses.
    fn transaction(&mut self) -> Option<()> {
        self.skip(4)?;
        let mut inputs = self.inputs()?;
        let mut flags = 0;
        if inputs == 0 {
            flags = self.bytes(1)?[0];
            if flags != 0 {
                inputs = self.inputs()?;
                self.outputs()?;
            }
        } else {
            self.outputs()?;
        }
        if flags & 1 != 0 {
            flags ^= 1;
            self.witnesses(inputs)?;
        }
        if flags != 0 {
            return None;
        }
        // The lock time.
        self.skip(4)
    }

    /// `readInputs`, each input read by `TransactionInput.parse`: its outpoint,
    /// its script and its sequence. How many it read.
    fn inputs(&mut self) -> Option<usize> {
        let count = self.var_int()?;
        list(count as i32)?;
        let mut read = 0;
        // A `long` loop, so a count below zero reads none.
        while (read as i64) < count {
            self.skip(OUTPOINT_LENGTH)?;
            let script = self.var_int()? as i32;
            self.bytes(script)?;
            self.skip(4)?;
            read += 1;
        }
        Some(read)
    }

    /// `readOutputs`, each output read by `TransactionOutput.parse`: its value
    /// and its script.
    fn outputs(&mut self) -> Option<()> {
        let count = self.var_int()?;
        list(count as i32)?;
        let mut read = 0;
        while read < count {
            self.skip(8)?;
            let script = self.var_int()? as i32;
            self.bytes(script)?;
            read += 1;
        }
        Some(())
    }

    /// `readWitness`: for each input, a count of pushes and the pushes, the
    /// count first sizing the list `TransactionWitness` keeps them in.
    fn witnesses(&mut self, inputs: usize) -> Option<()> {
        for _ in 0..inputs {
            let pushes = self.var_int()?;
            list(pushes as i32)?;
            let mut read = 0;
            while read < pushes {
                let push = self.var_int()? as i32;
                self.bytes(push)?;
                read += 1;
            }
        }
        Some(())
    }

    /// `readUint32`, `readInt64` and `readHash`: that many bytes, or a throw.
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self
            .cursor
            .checked_add(n)
            .filter(|&end| end <= self.payload.len())?;
        self.cursor = end;
        Some(())
    }

    /// `readBytes`, which refuses more than 32 MiB or more than is left, and
    /// cannot make an array below zero.
    fn bytes(&mut self, n: i32) -> Option<&[u8]> {
        if !(0..=MAX_SIZE).contains(&n) {
            return None;
        }
        let start = self.cursor;
        self.skip(n as usize)?;
        Some(&self.payload[start..self.cursor])
    }

    /// `readVarInt`, the value in a Java `long`.
    fn var_int(&mut self) -> Option<i64> {
        let (value, size) = var_int(self.payload, self.cursor)?;
        self.cursor += size;
        Some(value)
    }
}

/// `new ArrayList<>(Math.min(n, Utils.MAX_INITIAL_ARRAY_LENGTH))`, which
/// throws for a capacity below zero.
fn list(n: i32) -> Option<()> {
    (n.min(MAX_INITIAL_ARRAY_LENGTH) >= 0).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::serialize;

    /// Bitcoin's genesis block: its header, one transaction, the coinbase.
    fn genesis() -> Vec<u8> {
        serialize(&bitcoin::constants::genesis_block(
            bitcoin::Network::Bitcoin,
        ))
    }

    /// A header, then `count` and the transactions given.
    fn block(count: &[u8], transactions: &[&[u8]]) -> Vec<u8> {
        [&genesis()[..HEADER_SIZE], count, &transactions.concat()].concat()
    }

    /// A transaction of one input, its script two bytes, and one output, its
    /// script three, the two lengths written as given.
    fn transaction(input_length: &[u8], output_length: &[u8]) -> Vec<u8> {
        [
            &1u32.to_le_bytes()[..],
            &[1],
            &[0x11; 32],
            &[0; 4],
            input_length,
            &[0x51; 2],
            &[0xff; 4],
            &[1],
            &5_000u64.to_le_bytes(),
            output_length,
            &[0x52; 3],
            &[0; 4],
        ]
        .concat()
    }

    /// A header, its transactions, both whole, and a byte past them.
    #[test]
    fn bitcoinj_reads_a_block_and_ignores_what_follows() {
        let genesis = genesis();
        assert_eq!(genesis.len(), 285);
        assert!(bitcoinj_reads(&genesis));
        assert!(bitcoinj_reads(&genesis[..HEADER_SIZE]));
        assert!(bitcoinj_reads(&[genesis.clone(), vec![0xee]].concat()));
        for cut in (0..HEADER_SIZE).chain(HEADER_SIZE + 1..genesis.len()) {
            assert!(!bitcoinj_reads(&genesis[..cut]), "{cut} bytes");
        }
        // No transactions after all.
        assert!(bitcoinj_reads(&block(&[0], &[])));
        let two = transaction(&[2], &[3]);
        assert!(bitcoinj_reads(&block(&[2], &[&two, &two])));
        assert!(!bitcoinj_reads(&block(&[3], &[&two, &two])));
    }

    /// With no inputs, bitcoinj reads a byte of flags: zero for none, one for
    /// witnesses after the outputs, anything else refused.
    #[test]
    fn bitcoinj_reads_witnesses_after_a_flag() {
        let version = 2u32.to_le_bytes();
        let lock_time = [0; 4];
        let input = [&[0x22; 36][..], &[0], &[0xff; 4]].concat();
        let output = [&7u64.to_le_bytes()[..], &[1, 0x51]].concat();
        // Two pushes: three bytes, then none.
        let witness = [2, 3, 1, 2, 3, 0];
        let segwit = |flags: u8, witness: &[u8]| {
            [
                &version[..],
                &[0, flags, 1],
                &input,
                &[1],
                &output,
                witness,
                &lock_time,
            ]
            .concat()
        };
        assert!(bitcoinj_reads(&block(&[1], &[&segwit(1, &witness)])));
        assert!(!bitcoinj_reads(&block(&[1], &[&segwit(3, &witness)])));
        assert!(!bitcoinj_reads(&block(&[1], &[&segwit(2, &witness)])));
        // Flags of zero: no inputs, no outputs.
        let bare = [&version[..], &[0, 0], &lock_time].concat();
        assert!(bitcoinj_reads(&block(&[1], &[&bare])));
        // A push of nine bytes, with seven left in all.
        assert!(!bitcoinj_reads(&block(
            &[1],
            &[&segwit(1, &[1, 9, 1, 2, 3])]
        )));
    }

    /// bitcoinj casts each count to an `int` to size its list, which throws
    /// below zero, and loops on the `long` for inputs and outputs.
    #[test]
    fn bitcoinj_counts_as_java_does() {
        let two = transaction(&[2], &[3]);
        // Transactions: 2^31 is below zero as an `int`.
        assert!(!bitcoinj_reads(&block(&[0xfe, 0, 0, 0, 0x80], &[&two])));
        // 2^32 + 1 is one, as an `int`.
        let wide_one = [0xff, 1, 0, 0, 0, 1, 0, 0, 0];
        assert!(bitcoinj_reads(&block(&wide_one, &[&two])));
        // Inputs: -1 sizes a list below zero; -2^32, a `long` below zero whose
        // `int` is zero, reads none, so the flags byte comes next.
        let tail = |count: &[u8]| [&1u32.to_le_bytes()[..], count, &[0], &[0; 4]].concat();
        assert!(!bitcoinj_reads(&block(&[1], &[&tail(&[0xff; 9])])));
        let below_zero = [0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        assert!(bitcoinj_reads(&block(&[1], &[&tail(&below_zero)])));
        // A script length whose low 32 bits are 2 reads two bytes, and the
        // next transaction starts after them.
        let wide_two = [0xff, 2, 0, 0, 0, 1, 0, 0, 0];
        let wide = transaction(&wide_two, &[3]);
        assert!(bitcoinj_reads(&block(&[2], &[&wide, &two])));
        // And one below zero cannot be read.
        let minus_two = [0xfe, 0xfe, 0xff, 0xff, 0xff];
        assert!(!bitcoinj_reads(&block(
            &[1],
            &[&transaction(&minus_two, &[3])]
        )));
        assert!(!bitcoinj_reads(&block(
            &[1],
            &[&transaction(&[2], &minus_two)]
        )));
        // Outputs: -1 sizes a list below zero, where a `long` loop would read
        // none.
        let input = [&[0x22; 36][..], &[0], &[0xff; 4]].concat();
        let version = 1u32.to_le_bytes();
        let no_outputs = |count: &[u8]| [&version[..], &[1], &input, count, &[0; 4]].concat();
        assert!(bitcoinj_reads(&block(&[1], &[&no_outputs(&[0])])));
        assert!(!bitcoinj_reads(&block(&[1], &[&no_outputs(&[0xff; 9])])));
        // A witness's push count below zero, as an `int`: 2^31, and -1, where
        // a `long` loop would read none.
        let witnessed =
            |pushes: &[u8]| [&version[..], &[0, 1, 1], &input, &[0], pushes, &[0; 4]].concat();
        assert!(bitcoinj_reads(&block(&[1], &[&witnessed(&[0])])));
        assert!(!bitcoinj_reads(&block(
            &[1],
            &[&witnessed(&[0xfe, 0, 0, 0, 0x80])]
        )));
        assert!(!bitcoinj_reads(&block(&[1], &[&witnessed(&[0xff; 9])])));
    }

    /// `readBytes` makes no array over 32 MiB, whatever is there.
    #[test]
    fn bitcoinj_reads_no_script_over_32_mib() {
        let script = |n: u32| {
            let length = [&[0xfe][..], &n.to_le_bytes()].concat();
            let output = [&5u64.to_le_bytes()[..], &length, &vec![0u8; n as usize]].concat();
            let input = [&[0x22; 36][..], &[0], &[0xff; 4]].concat();
            let version = 1u32.to_le_bytes();
            [&version[..], &[1], &input, &[1], &output, &[0; 4]].concat()
        };
        assert!(bitcoinj_reads(&block(&[1], &[&script(0x0200_0000)])));
        assert!(!bitcoinj_reads(&block(&[1], &[&script(0x0200_0001)])));
    }
}
