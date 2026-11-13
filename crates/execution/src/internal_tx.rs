//! rskj's internal transactions, as far as consensus reads them.
//!
//! rskj records every call a contract makes, and every contract it creates,
//! as an `InternalTransaction` of the program that made it
//! (`Program.addInternalTx`), and the program a call or a creation starts
//! runs with that internal transaction as its own. Consensus reads them in
//! one place. A Bridge method a contract calls is handed the call's internal
//! transaction (`Program.callToPrecompiledAddress`), and
//! `registerBtcTransaction` names the refund of a payment it turns down by
//! that transaction's hash (`BridgeSupport.registerBtcTransaction`,
//! `rskTx.getHash()`): in the pegouts waiting for confirmations, and in
//! `release_requested`.
//!
//! The hash is over the internal transaction's place as much as over what it
//! carries (`InternalTransaction.getEncoded`): the hash of the transaction of
//! the program that made it, that program's depth, and how many internal
//! transactions that program had made before this one. So [`InternalTxs`]
//! follows a transaction's programs as they open and close, counts what each
//! makes, and works a hash out only when the Bridge is reached.
//!
//! What counts as one (`Program`, read at VETIVER-9.0.4, and its release run:
//! `bridge/testdata/rskj_refunded_pegins.txt`):
//!
//! - a call that passes rskj's checks of depth and balance, to a contract or
//!   to an account without code (`callToAddress`). CALLCODE and DELEGATECALL
//!   go to the caller itself;
//! - a creation that passes its checks, of an address in use among them
//!   (`createContract`);
//! - a call to the Bridge, to REMASC or to a native contract, and to no other
//!   precompile (`callToPrecompiledAddress`);
//! - a SELFDESTRUCT of an account with a balance (`suicide`).
//!
//! When a call's program ends, what it made is added to what its caller made,
//! whether it failed or not (`ProgramResult.merge`). A creation's is not
//! (`finalizeContractCreation`).

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable;

/// What an internal transaction that starts a program carries of its own.
#[derive(Clone, Debug)]
pub struct InternalTx {
    /// The program that made it, by the address it runs as (rskj
    /// `getOwnerRskAddress`).
    pub sender: Address,
    /// The sender's nonce as it was made.
    pub nonce: u64,
    /// Where it goes: the callee, for CALLCODE and DELEGATECALL the sender
    /// itself, and nowhere for a creation.
    pub receiver: Option<Address>,
    /// What it carries. A DELEGATECALL carries nothing.
    pub value: U256,
    /// The code the program it starts runs: the callee's, or a creation's
    /// init code.
    pub code: Bytes,
    /// Whether it creates a contract, with rskj's note `create`, or calls,
    /// with `call`.
    pub creates: bool,
}

/// A program of the transaction that is running or waiting on one it called.
struct Program {
    /// The internal transaction that started it, and that one's index among
    /// those of the program that made it. `None` for the program the
    /// transaction itself starts.
    started_by: Option<(InternalTx, usize)>,
    /// The hash of the internal transaction that started it, once the Bridge
    /// has needed it.
    hash: Option<B256>,
    /// How many internal transactions it has made: the size of rskj's
    /// `getResult().getInternalTransactions()`.
    made: usize,
}

/// The programs of the transaction that is running, innermost last.
#[derive(Default)]
pub struct InternalTxs {
    /// The transaction's gas price, which every one of its internal
    /// transactions carries (`Program.getTxGasPrice`).
    gas_price: U256,
    /// The block's gas limit, which each carries as its own
    /// (`Program.getGasLimit`).
    block_gas_limit: U256,
    programs: Vec<Program>,
}

impl InternalTxs {
    /// A transaction starts.
    pub fn begin(&mut self, gas_price: U256, block_gas_limit: U256) {
        *self = Self {
            gas_price,
            block_gas_limit,
            programs: Vec::new(),
        };
    }

    /// A program opens: the transaction's own, with nothing to start it, or
    /// one the running program made `started_by` for, which counts as one it
    /// made.
    pub fn enter(&mut self, started_by: Option<InternalTx>) {
        let started_by = match (self.programs.last_mut(), started_by) {
            (Some(maker), Some(tx)) => {
                maker.made += 1;
                Some((tx, maker.made - 1))
            }
            _ => None,
        };
        self.programs.push(Program {
            started_by,
            hash: None,
            made: 0,
        });
    }

    /// The running program made an internal transaction that starts no
    /// program: a call to an account without code, to REMASC or to a native
    /// contract, or the balance its SELFDESTRUCT moved.
    pub fn count(&mut self) {
        if let Some(program) = self.programs.last_mut() {
            program.made += 1;
        }
    }

    /// The running program ends. A call's program hands what it made to the
    /// one that called it (`merges`); a creation's doesn't.
    pub fn leave(&mut self, merges: bool) {
        let Some(ended) = self.programs.pop() else {
            return;
        };
        if let (true, Some(maker)) = (merges, self.programs.last_mut()) {
            maker.made += ended.made;
        }
    }

    /// The running program reaches the Bridge, as `sender` with `nonce`, for
    /// `receiver` and with `value`: the hash of the internal transaction rskj
    /// hands the Bridge, which counts as one the program made. `None` where
    /// no program runs: the transaction calls the Bridge itself, and the
    /// Bridge is handed the transaction.
    pub fn reach_bridge(
        &mut self,
        tx_hash: B256,
        sender: Address,
        nonce: u64,
        receiver: Address,
        value: U256,
    ) -> Option<B256> {
        let depth = self.programs.len().checked_sub(1)?;
        let parent = self.transaction_hash(depth, tx_hash);
        let index = self.programs[depth].made;
        self.programs[depth].made += 1;
        Some(hash(
            nonce,
            &parent,
            &sender,
            Some(&receiver),
            value,
            self.gas_price,
            Some(self.block_gas_limit),
            &[],
            "call",
            depth,
            index,
        ))
    }

    /// The hash of the transaction the program at `level` runs: the block's
    /// transaction for the outermost, and for any other the internal
    /// transaction that started it, whose hash is over that of the program
    /// below.
    fn transaction_hash(&mut self, level: usize, tx_hash: B256) -> B256 {
        let mut parent = tx_hash;
        for at in 0..=level {
            let program = &self.programs[at];
            parent = match (program.hash, &program.started_by) {
                (Some(known), _) => known,
                (None, None) => parent,
                (None, Some((tx, index))) => {
                    let worked_out = hash(
                        tx.nonce,
                        &parent,
                        &tx.sender,
                        tx.receiver.as_ref(),
                        tx.value,
                        self.gas_price,
                        Some(self.block_gas_limit),
                        &tx.code,
                        if tx.creates { "create" } else { "call" },
                        at - 1,
                        *index,
                    );
                    self.programs[at].hash = Some(worked_out);
                    worked_out
                }
            };
        }
        parent
    }
}

/// The hash of an internal transaction: the Keccak-256 of rskj's
/// `InternalTransaction.getEncoded`, while the transaction isn't rejected.
/// rskj keeps the first hash it works out (`Transaction.getHash`), and works
/// out a call's while the call still runs, so a rejection that comes later
/// changes none that anything reads.
///
/// `gas_limit` is a 32-byte word where there is one, and a SELFDESTRUCT's
/// internal transaction has none.
#[allow(clippy::too_many_arguments)]
fn hash(
    nonce: u64,
    parent: &B256,
    sender: &Address,
    receiver: Option<&Address>,
    value: U256,
    gas_price: U256,
    gas_limit: Option<U256>,
    data: &[u8],
    note: &str,
    depth: usize,
    index: usize,
) -> B256 {
    let mut fields = Vec::with_capacity(192 + data.len());
    nonce_bytes(nonce).as_slice().encode(&mut fields);
    parent.encode(&mut fields);
    sender.encode(&mut fields);
    match receiver {
        Some(receiver) => receiver.encode(&mut fields),
        None => fields.push(alloy_rlp::EMPTY_STRING_CODE),
    }
    value.encode(&mut fields);
    gas_price.encode(&mut fields);
    match gas_limit {
        Some(limit) => B256::from(limit).encode(&mut fields),
        None => fields.push(alloy_rlp::EMPTY_STRING_CODE),
    }
    data.encode(&mut fields);
    note.as_bytes().encode(&mut fields);
    (depth as u64).encode(&mut fields);
    (index as u64).encode(&mut fields);
    // Not rejected.
    fields.push(alloy_rlp::EMPTY_STRING_CODE);
    let mut encoded = Vec::with_capacity(fields.len() + 4);
    alloy_rlp::Header {
        list: true,
        payload_length: fields.len(),
    }
    .encode(&mut encoded);
    encoded.extend_from_slice(&fields);
    keccak256(encoded)
}

/// A nonce as rskj writes it into an internal transaction: the bytes of
/// `BigInteger.toByteArray()`, which are big-endian, as few as hold it, and
/// led by a zero byte where the first would have its top bit set (128 is
/// `00 80`). Zero is written as no bytes.
fn nonce_bytes(nonce: u64) -> Vec<u8> {
    let bytes = nonce.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let mut written = Vec::with_capacity(9);
    if bytes.get(first).is_some_and(|byte| *byte >= 0x80) {
        written.push(0);
    }
    written.extend_from_slice(&bytes[first..]);
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(field: &str) -> Vec<u8> {
        if field == "-" {
            Vec::new()
        } else {
            hex::decode(field).unwrap()
        }
    }

    /// The file's `enc` lines are internal transactions rskj's release built
    /// by themselves, each with the hash it gave: every length a nonce, a
    /// value, a gas price, a depth and an index take, a SELFDESTRUCT's with
    /// no gas limit, a creation's with no receiver, and the zero address,
    /// which is twenty bytes and not none.
    #[test]
    fn hashes_as_rskj_hashes_them() {
        let vectors = include_str!("bridge/testdata/rskj_refunded_pegins.txt");
        let mut read = 0;
        for line in vectors.lines().filter(|line| line.starts_with("enc ")) {
            let fields: Vec<&str> = line.split(' ').collect();
            let number = |field: &str| U256::from_str_radix(field, 16).unwrap();
            let receiver = (fields[5] != "-").then(|| Address::from_slice(&bytes(fields[5])));
            let ours = hash(
                fields[1].parse().unwrap(),
                &B256::from_slice(&bytes(fields[11])),
                &Address::from_slice(&bytes(fields[4])),
                receiver.as_ref(),
                number(fields[6]),
                number(fields[2]),
                (fields[3] != "-").then(|| number(fields[3])),
                &bytes(fields[7]),
                fields[8],
                fields[9].parse().unwrap(),
                fields[10].parse().unwrap(),
            );
            assert_eq!(ours, B256::from_slice(&bytes(fields[12])), "{line}");
            read += 1;
        }
        assert_eq!(read, 59);
    }

    /// A program's internal transactions are numbered as it makes them, and a
    /// call's are added to its caller's when it ends, where a creation's are
    /// not. The Bridge's hash is over the hash of what started the program
    /// that reaches it, and through that over every program below.
    #[test]
    fn counts_what_each_program_makes() {
        let (a, b, bridge) = (
            Address::repeat_byte(0xa1),
            Address::repeat_byte(0xb1),
            Address::repeat_byte(0x06),
        );
        let tx_hash = B256::repeat_byte(0x77);
        let (price, limit) = (U256::from(3), U256::from(6_800_000));
        let started = |sender, receiver, creates| InternalTx {
            sender,
            nonce: 1,
            receiver,
            value: U256::ZERO,
            code: Bytes::from_static(&[0x00]),
            creates,
        };
        let mut txs = InternalTxs::default();
        txs.begin(price, limit);
        // The transaction calls the Bridge itself: no program, no hash.
        assert_eq!(txs.reach_bridge(tx_hash, a, 1, bridge, U256::ZERO), None);

        txs.enter(None);
        txs.count();
        // A call's program makes two and ends: the caller has made four.
        txs.enter(Some(started(a, Some(b), false)));
        txs.count();
        txs.count();
        txs.leave(true);
        // A creation's makes one and ends: the creator has made five.
        txs.enter(Some(started(a, None, true)));
        txs.count();
        txs.leave(false);
        let from_the_first = txs.reach_bridge(tx_hash, a, 1, bridge, U256::ZERO);
        let at = |parent: &B256, depth, index| {
            hash(
                1,
                parent,
                &a,
                Some(&bridge),
                U256::ZERO,
                price,
                Some(limit),
                &[],
                "call",
                depth,
                index,
            )
        };
        assert_eq!(from_the_first, Some(at(&tx_hash, 0, 5)));

        // From a program the first one called, its seventh.
        txs.enter(Some(started(a, Some(b), false)));
        let starting = hash(
            1,
            &tx_hash,
            &a,
            Some(&b),
            U256::ZERO,
            price,
            Some(limit),
            &[0x00],
            "call",
            0,
            6,
        );
        let from_the_second = txs.reach_bridge(tx_hash, b, 1, bridge, U256::ZERO);
        let expected = hash(
            1,
            &starting,
            &b,
            Some(&bridge),
            U256::ZERO,
            price,
            Some(limit),
            &[],
            "call",
            1,
            0,
        );
        assert_eq!(from_the_second, Some(expected));
    }

    #[test]
    fn a_nonce_is_written_as_java_writes_a_big_integer() {
        let cases: [(u64, &[u8]); 7] = [
            (0, &[]),
            (1, &[1]),
            (127, &[0x7f]),
            (128, &[0, 0x80]),
            (255, &[0, 0xff]),
            (256, &[1, 0]),
            (
                u64::MAX,
                &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (nonce, written) in cases {
            assert_eq!(nonce_bytes(nonce), written, "{nonce}");
        }
    }
}
