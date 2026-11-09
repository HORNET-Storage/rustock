//! BlockHeader (0x01000010, RSKIP119): rskj's `co.rsk.pcc.blockheader`, which
//! answers questions about the executing block's ancestors.

use alloy_primitives::{Bytes, B256, U256};
use rustock_core::Header;
use rustock_storage::BlockStore;

use super::{Failure, NativeContract};
use crate::abi::{encode_bytes, Args, Int};

/// `BlockHeaderContract.MAX_DEPTH`, REMASC's maturity: nothing this deep or
/// deeper is answered for.
const MAX_DEPTH: i16 = 4000;

/// The tag a merged-mining coinbase carries before the RSK block's hash.
const RSK_TAG: &[u8] = b"RSKBLOCK:";

/// The contract, reading the chain the executing block extends.
pub(crate) struct BlockHeader<'a> {
    pub(crate) blocks: &'a BlockStore,
    /// The executing block's parent, where rskj starts looking
    /// (`getBlockAtDepthStartingAt`).
    pub(crate) parent: B256,
    /// RSKIP536, which adds `getDifficultyWithUncles` and `getCumulativeWork`.
    pub(crate) rskip536: bool,
}

/// The contract's methods, each taking a block depth and returning `bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    CoinbaseAddress,
    BlockHash,
    MergedMiningTags,
    MinGasPrice,
    GasLimit,
    GasUsed,
    Difficulty,
    BitcoinHeader,
    /// The only one with a second argument, the uncle's index.
    UncleCoinbaseAddress,
    DifficultyWithUncles,
    CumulativeWork,
}

/// Every method's selector, for tests that call each.
#[cfg(test)]
pub(crate) fn every_selector() -> Vec<[u8; 4]> {
    METHODS
        .iter()
        .map(|(signature, _)| crate::abi::selector(signature))
        .collect()
}

/// `BlockHeaderContract.getMethods`, by signature.
const METHODS: [(&str, Method); 11] = [
    ("getCoinbaseAddress(int256)", Method::CoinbaseAddress),
    ("getBlockHash(int256)", Method::BlockHash),
    ("getMergedMiningTags(int256)", Method::MergedMiningTags),
    ("getMinGasPrice(int256)", Method::MinGasPrice),
    ("getGasLimit(int256)", Method::GasLimit),
    ("getGasUsed(int256)", Method::GasUsed),
    ("getDifficulty(int256)", Method::Difficulty),
    ("getBitcoinHeader(int256)", Method::BitcoinHeader),
    (
        "getUncleCoinbaseAddress(int256,int256)",
        Method::UncleCoinbaseAddress,
    ),
    (
        "getDifficultyWithUncles(int256)",
        Method::DifficultyWithUncles,
    ),
    ("getCumulativeWork(int256)", Method::CumulativeWork),
];

/// A method with its arguments.
pub(crate) struct Call {
    method: Method,
    depth: Int,
    /// `getUncleCoinbaseAddress`'s index.
    uncle: Option<Int>,
}

impl NativeContract for BlockHeader<'_> {
    type Call = Call;

    fn parse(&self, selector: [u8; 4], args: &[u8]) -> Option<Call> {
        let method = super::method(&METHODS, selector)?;
        // `isEnabled`: before RSKIP536 its two methods are not there.
        if matches!(
            method,
            Method::DifficultyWithUncles | Method::CumulativeWork
        ) && !self.rskip536
        {
            return None;
        }
        let args = Args::new(args);
        let depth = args.int(0)?;
        let uncle = match method {
            Method::UncleCoinbaseAddress => Some(args.int(1)?),
            _ => None,
        };
        Some(Call {
            method,
            depth,
            uncle,
        })
    }

    /// `BlockHeaderContractMethod.getGas`: 4000, and two for each byte of the
    /// payload.
    fn gas(&self, _call: &Call, input: &[u8]) -> u64 {
        (input.len() as u64).saturating_mul(2).saturating_add(4_000)
    }

    fn execute(&self, call: Call) -> Result<Vec<u8>, Failure> {
        // `BlockHeaderContractMethod.execute`: a depth no short holds names no
        // block, and neither does one `getBlock` finds nothing at.
        let block = match call.depth.short_value_exact() {
            Some(depth) => self.block_at(depth)?,
            None => None,
        };
        let Some((hash, header)) = block else {
            return Ok(encode_bytes(&[]));
        };
        Ok(match self.read(&call, hash, &header)? {
            Some(value) => encode_bytes(&value),
            // A method's `null`: `NativeContract.execute` returns no bytes at all.
            None => Vec::new(),
        })
    }
}

impl BlockHeader<'_> {
    /// `BlockAccessor.getBlock`: the block `depth` above the executing block's
    /// parent, found as `IndexedBlockStore.getBlockAtDepthStartingAt` finds
    /// it. That walks up from the parent by hash until it reaches a block of
    /// the main chain, whose index then names the rest, so a block on a fork
    /// reads its own ancestors.
    fn block_at(&self, depth: i16) -> Result<Option<(B256, Header)>, Failure> {
        if depth < 0 {
            return Err(Failure::threw("a block depth cannot be negative"));
        }
        if depth >= MAX_DEPTH {
            return Ok(None);
        }
        let depth = u64::from(depth.unsigned_abs());
        // The genesis block's parent is not there.
        let Some(start) = self.header(self.parent)? else {
            return Ok(None);
        };
        if depth == 0 {
            return Ok(Some((self.parent, start)));
        }
        // Past depth 0, a parent numbered `depth` or lower has no such
        // ancestor, not even when it would be the genesis block.
        if start.number <= depth {
            return Ok(None);
        }
        let target = start.number - depth;
        let (mut hash, mut block) = (self.parent, start);
        for _ in 0..depth {
            if self.canonical(block.number)? == Some(hash) {
                let hash = self
                    .canonical(target)?
                    .ok_or_else(|| missing(format!("main-chain block #{target}")))?;
                let header = self
                    .header(hash)?
                    .ok_or_else(|| missing(format!("header for block #{target}")))?;
                return Ok(Some((hash, header)));
            }
            let child = block.number;
            hash = block.parent_hash;
            block = self
                .header(hash)?
                .ok_or_else(|| missing(format!("parent for block #{child}")))?;
        }
        Ok(Some((hash, block)))
    }

    fn header(&self, hash: B256) -> Result<Option<Header>, Failure> {
        self.blocks.header(hash).map_err(fatal)
    }

    /// The main chain's block at `number`.
    fn canonical(&self, number: u64) -> Result<Option<B256>, Failure> {
        self.blocks.canonical_hash(number).map_err(fatal)
    }

    /// The block's uncles: none if its header says so, else its body's, or,
    /// once the body is pruned, the freezer's, which keeps them by number
    /// for the main chain only.
    fn uncles(&self, hash: B256, header: &Header) -> Result<Vec<Header>, Failure> {
        if header.uncle_count == 0 {
            return Ok(Vec::new());
        }
        if let Some(uncles) = self.blocks.uncles(hash).map_err(fatal)? {
            return Ok(uncles);
        }
        if self.canonical(header.number)? == Some(hash) {
            if let Some(freezer) = self.blocks.freezer() {
                if let Some(uncles) = freezer.uncles(header.number).map_err(fatal)? {
                    return Ok(uncles);
                }
            }
        }
        Err(missing(format!("uncles for block #{}", header.number)))
    }

    /// The method's `internalExecute` on the block it names. `None` is rskj's
    /// `null`.
    fn read(&self, call: &Call, hash: B256, header: &Header) -> Result<Option<Vec<u8>>, Failure> {
        let value = match call.method {
            Method::CoinbaseAddress => header.beneficiary.to_vec(),
            Method::BlockHash => hash.to_vec(),
            Method::MergedMiningTags => merged_mining_tags(header)?,
            Method::MinGasPrice => big_integer_bytes(header.minimum_gas_price),
            // The bytes as the header holds them: rskj never holds the gas
            // limit as a number (`KeptFields::gas_limit`).
            Method::GasLimit => header.gas_limit_bytes().into_owned(),
            Method::GasUsed => big_integer_bytes(U256::from(header.gas_used)),
            Method::Difficulty => big_integer_bytes(header.difficulty),
            Method::BitcoinHeader => {
                // A header field rskj read from an empty RLP item is null too.
                return Ok(non_empty(&header.bitcoin_merged_mining_header).map(<[u8]>::to_vec));
            }
            Method::UncleCoinbaseAddress => {
                // The index is read first: one no short holds names no uncle,
                // and a negative one throws.
                let Some(index) = call.uncle.and_then(|index| index.short_value_exact()) else {
                    return Ok(Some(Vec::new()));
                };
                let index = usize::try_from(index)
                    .map_err(|_| Failure::threw("an uncle index cannot be negative"))?;
                self.uncles(hash, header)?
                    .get(index)
                    .map(|uncle| uncle.beneficiary.to_vec())
                    .unwrap_or_default()
            }
            // `Block.getCumulativeDifficulty`.
            Method::DifficultyWithUncles => big_integer_bytes(
                self.uncles(hash, header)?
                    .iter()
                    .fold(header.difficulty, |sum, uncle| {
                        sum.saturating_add(uncle.difficulty)
                    }),
            ),
            // `getTotalDifficultyForHash`, which rskj holds for every block.
            Method::CumulativeWork => big_integer_bytes(
                self.blocks
                    .total_difficulty(hash)
                    .map_err(fatal)?
                    .ok_or_else(|| {
                        missing(format!("total difficulty for block #{}", header.number))
                    })?,
            ),
        };
        Ok(Some(value))
    }
}

/// A store that fails to read leaves the node with no answer.
fn fatal(error: impl std::fmt::Display) -> Failure {
    Failure::Fatal(format!("BlockHeader: {error}"))
}

/// rskj's store holds every block, body and total difficulty it is asked
/// for, so one this node lacks is no answer, not an empty one.
fn missing(what: String) -> Failure {
    Failure::Fatal(format!("BlockHeader: the store has no {what}"))
}

/// `GetMergedMiningTags.internalExecute`: what follows the block's hash
/// after the merged-mining coinbase's last `RSKBLOCK:` tag.
fn merged_mining_tags(header: &Header) -> Result<Vec<u8>, Failure> {
    // rskj reads a block without a coinbase into a NullPointerException.
    let coinbase = non_empty(&header.bitcoin_merged_mining_coinbase_transaction)
        .ok_or_else(|| Failure::threw("the block has no merged-mining coinbase"))?;
    let Some(tag) = coinbase
        .windows(RSK_TAG.len())
        .rposition(|window| window == RSK_TAG)
    else {
        return Ok(Vec::new());
    };
    // `Arrays.copyOfRange` throws when the hash runs past the end.
    coinbase
        .get(tag + RSK_TAG.len() + 32..)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Failure::threw("the coinbase ends inside the block's hash"))
}

/// A merged-mining field as rskj holds it: `RLPItem.getRLPData` reads an
/// empty item as null, so an empty field is no field.
fn non_empty(field: &Option<Bytes>) -> Option<&[u8]> {
    field
        .as_ref()
        .map(|bytes| &bytes[..])
        .filter(|bytes| !bytes.is_empty())
}

/// `BigInteger.toByteArray()` of a non-negative number: its shortest
/// big-endian form, with a leading zero byte when the first one's top bit
/// is set, and `[0]` for zero.
fn big_integer_bytes(value: U256) -> Vec<u8> {
    let mut bytes = shortest_bytes(value);
    if bytes.first().is_none_or(|first| first & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

/// The shortest big-endian form, empty for zero.
fn shortest_bytes(value: U256) -> Vec<u8> {
    let bytes = value.to_be_bytes::<32>();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{call, Outcome};
    use alloy_primitives::{Address, Bloom};

    fn header(number: u64, parent_hash: B256) -> Header {
        Header {
            parent_hash,
            ommers_hash: B256::ZERO,
            beneficiary: Address::with_last_byte(number as u8),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(1),
            number,
            gas_limit: U256::from(6_800_000),
            gas_used: 0,
            timestamp: number,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: Some(Bytes::from(vec![number as u8; 80])),
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
            kept: None,
        }
    }

    /// A chain of blocks 0 to `top`, each canonical and block `n`'s coinbase
    /// ending in `n`, as `edit` leaves them; and their hashes.
    fn chain_with(
        top: u64,
        edit: impl Fn(&mut Header),
    ) -> (tempfile::TempDir, BlockStore, Vec<B256>) {
        let dir = tempfile::tempdir().unwrap();
        let blocks = BlockStore::open(dir.path()).unwrap();
        let mut hashes = Vec::new();
        for number in 0..=top {
            let mut block = header(number, hashes.last().copied().unwrap_or(B256::ZERO));
            edit(&mut block);
            blocks.put_header(&block).unwrap();
            blocks.put_canonical_hash(number, block.hash()).unwrap();
            hashes.push(block.hash());
        }
        (dir, blocks, hashes)
    }

    fn chain(top: u64) -> (tempfile::TempDir, BlockStore, Vec<B256>) {
        chain_with(top, |_| {})
    }

    /// The contract as block `number` of the chain sees it.
    fn at<'a>(blocks: &'a BlockStore, hashes: &[B256], number: usize) -> BlockHeader<'a> {
        let parent = number
            .checked_sub(1)
            .map_or(B256::ZERO, |parent| hashes[parent]);
        BlockHeader {
            blocks,
            parent,
            rskip536: false,
        }
    }

    fn input(signature: &str, args: &[[u8; 32]]) -> Vec<u8> {
        let mut input = crate::abi::selector(signature).to_vec();
        args.iter().for_each(|word| input.extend_from_slice(word));
        input
    }

    fn int(n: i64) -> [u8; 32] {
        crate::abi::encode::int(n)
    }

    /// `getCoinbaseAddress(depth)`: the coinbase's last byte, which is the
    /// block's number, or `None` for an empty answer.
    fn coinbase(contract: &BlockHeader, depth: [u8; 32]) -> Option<u8> {
        match call(
            contract,
            &input("getCoinbaseAddress(int256)", &[depth]),
            1_000_000,
        ) {
            Outcome::Returned { output, .. } if output[..] == encode_bytes(&[])[..] => None,
            Outcome::Returned { output, .. } => Some(output[64 + 19]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn depth_zero_is_the_parent() {
        let (_dir, blocks, hashes) = chain(10);
        let contract = at(&blocks, &hashes, 11);
        assert_eq!(coinbase(&contract, int(0)), Some(10));
        assert_eq!(coinbase(&contract, int(3)), Some(7));
    }

    /// `getBlockAtDepthStartingAt`: past depth 0, a parent numbered `depth`
    /// has no such ancestor, so the genesis block is reachable only as some
    /// block's parent.
    #[test]
    fn past_depth_zero_the_genesis_block_is_out_of_reach() {
        let (_dir, blocks, hashes) = chain(10);
        assert_eq!(coinbase(&at(&blocks, &hashes, 6), int(4)), Some(1));
        assert_eq!(coinbase(&at(&blocks, &hashes, 6), int(5)), None);
        assert_eq!(coinbase(&at(&blocks, &hashes, 1), int(0)), Some(0));
        assert_eq!(coinbase(&at(&blocks, &hashes, 0), int(0)), None);
    }

    /// A block on a fork reads its own ancestors, by hash, until its branch
    /// meets the main chain.
    #[test]
    fn a_block_on_a_fork_reads_its_own_ancestors() {
        let (_dir, blocks, hashes) = chain(10);
        // Blocks 6' and 7' branch off block 5 and are not canonical.
        let mut parent = hashes[5];
        for number in 6..=7 {
            let mut block = header(number, parent);
            block.beneficiary = Address::with_last_byte(0xF0 + number as u8);
            blocks.put_header(&block).unwrap();
            parent = block.hash();
        }
        // Block 8' executes on top of 7'.
        let contract = BlockHeader {
            blocks: &blocks,
            parent,
            rskip536: false,
        };
        assert_eq!(coinbase(&contract, int(0)), Some(0xF7));
        assert_eq!(coinbase(&contract, int(1)), Some(0xF6));
        assert_eq!(coinbase(&contract, int(2)), Some(5));
        assert_eq!(coinbase(&contract, int(6)), Some(1));
        assert_eq!(coinbase(&contract, int(7)), None);
    }

    #[test]
    fn a_depth_no_short_holds_is_an_empty_answer_and_a_negative_one_throws() {
        let (_dir, blocks, hashes) = chain(10);
        let contract = at(&blocks, &hashes, 11);
        assert_eq!(coinbase(&contract, int(4000)), None);
        assert_eq!(coinbase(&contract, int(1 << 16)), None);
        assert_eq!(coinbase(&contract, int(-40_000)), None, "no short holds it");
        let negative = input("getCoinbaseAddress(int256)", &[int(-1)]);
        assert_eq!(
            call(&contract, &negative, 1_000_000),
            Outcome::Threw {
                gas: 4_072,
                reason: "a block depth cannot be negative".into()
            }
        );
    }

    /// rskj's decoder reads an empty payload as zero but refuses a short one.
    #[test]
    fn no_arguments_is_depth_zero_but_a_short_argument_is_no_call() {
        let (_dir, blocks, hashes) = chain(10);
        let contract = at(&blocks, &hashes, 11);
        let bare = crate::abi::selector("getCoinbaseAddress(int256)");
        assert!(matches!(
            call(&contract, &bare, 1_000_000),
            Outcome::Returned { gas: 4_008, .. }
        ));
        let mut short = bare.to_vec();
        short.extend_from_slice(&[0; 31]);
        assert!(matches!(
            call(&contract, &short, 1_000_000),
            Outcome::Threw { gas: 0, .. }
        ));
    }

    #[test]
    fn the_gas_is_4000_and_two_a_byte() {
        let (_dir, blocks, hashes) = chain(10);
        let contract = at(&blocks, &hashes, 11);
        let get = input("getBlockHash(int256)", &[int(0)]);
        assert_eq!(call(&contract, &get, 4_071), Outcome::OutOfGas);
        assert!(matches!(
            call(&contract, &get, 4_072),
            Outcome::Returned { gas: 4_072, .. }
        ));
    }

    #[test]
    fn an_uncle_is_read_by_an_index_that_must_decode() {
        let (_dir, blocks, hashes) = chain_with(10, |block| {
            block.uncle_count = u64::from(block.number == 10)
        });
        let mut uncle = header(9, hashes[8]);
        uncle.beneficiary = Address::repeat_byte(0xD1);
        blocks.put_body(hashes[10], &[], &[uncle]).unwrap();
        let contract = at(&blocks, &hashes, 11);
        let get = |args: &[[u8; 32]]| {
            call(
                &contract,
                &input("getUncleCoinbaseAddress(int256,int256)", args),
                1_000_000,
            )
        };
        let returned = |value: &[u8]| Outcome::Returned {
            gas: 4_136,
            output: encode_bytes(value).into(),
        };
        assert_eq!(get(&[int(0), int(0)]), returned(&[0xD1; 20]));
        assert_eq!(get(&[int(0), int(1)]), returned(&[]));
        assert_eq!(
            get(&[int(0), int(1 << 15)]),
            returned(&[]),
            "no short holds it"
        );
        assert!(matches!(
            get(&[int(0), int(-1)]),
            Outcome::Threw { gas: 4_136, .. }
        ));
        // Block 9 has no uncles, and needs no body to say so.
        assert_eq!(get(&[int(1), int(0)]), returned(&[]));
        // A missing index does not decode.
        assert!(matches!(get(&[int(0)]), Outcome::Threw { gas: 0, .. }));
        // A block that is not there has no uncles to ask about, negative or not.
        assert!(matches!(
            get(&[int(4_000), int(-1)]),
            Outcome::Returned { .. }
        ));
    }

    #[test]
    fn the_rskip536_methods_are_not_there_before_it() {
        let (_dir, blocks, hashes) = chain_with(10, |block| {
            block.uncle_count = u64::from(block.number == 10)
        });
        blocks
            .put_total_difficulty(hashes[10], U256::from(11_996))
            .unwrap();
        let mut uncle = header(9, hashes[8]);
        uncle.difficulty = U256::from(2);
        blocks.put_body(hashes[10], &[], &[uncle]).unwrap();
        for (signature, value) in [
            ("getDifficultyWithUncles(int256)", vec![3]),
            ("getCumulativeWork(int256)", vec![0x2E, 0xDC]),
        ] {
            let get = input(signature, &[int(0)]);
            let before = at(&blocks, &hashes, 11);
            assert!(matches!(
                call(&before, &get, 1_000_000),
                Outcome::Threw { gas: 0, .. }
            ));
            let after = BlockHeader {
                rskip536: true,
                ..before
            };
            assert_eq!(
                call(&after, &get, 1_000_000),
                Outcome::Returned {
                    gas: 4_072,
                    output: encode_bytes(&value).into()
                }
            );
        }
    }

    /// rskj's store holds every block, body and total difficulty, so one this
    /// store lacks stops the node rather than answering empty.
    #[test]
    fn what_the_store_lacks_is_no_answer() {
        let (_dir, blocks, hashes) = chain_with(10, |block| {
            block.uncle_count = u64::from(block.number == 10)
        });
        let contract = BlockHeader {
            rskip536: true,
            ..at(&blocks, &hashes, 11)
        };
        let get = |signature: &str, args: &[[u8; 32]]| {
            call(&contract, &input(signature, args), 1_000_000)
        };
        let fatal = |outcome: Outcome| matches!(outcome, Outcome::Fatal(_));
        // Block 10 has an uncle, and the store has no body for it.
        assert!(fatal(get("getDifficultyWithUncles(int256)", &[int(0)])));
        assert!(fatal(get(
            "getUncleCoinbaseAddress(int256,int256)",
            &[int(0), int(0)]
        )));
        // Block 9 has none, so it needs no body.
        assert_eq!(
            get("getDifficultyWithUncles(int256)", &[int(1)]),
            Outcome::Returned {
                gas: 4_072,
                output: encode_bytes(&[1]).into()
            }
        );
        // No block's total difficulty is stored.
        assert!(fatal(get("getCumulativeWork(int256)", &[int(1)])));
        // A hole in the main chain's index.
        blocks.delete_canonical_hash(4).unwrap();
        assert!(fatal(get("getCoinbaseAddress(int256)", &[int(6)])));
    }

    #[test]
    fn a_block_without_a_bitcoin_header_answers_with_no_bytes_at_all() {
        let (_dir, blocks, hashes) = chain_with(12, |block| match block.number {
            11 => block.bitcoin_merged_mining_header = None,
            // Stored and read back as an empty field, which rskj reads as null.
            12 => block.bitcoin_merged_mining_header = Some(Bytes::new()),
            _ => {}
        });
        let get = input("getBitcoinHeader(int256)", &[int(0)]);
        for number in [12, 13] {
            assert_eq!(
                call(&at(&blocks, &hashes, number), &get, 1_000_000),
                Outcome::Returned {
                    gas: 4_072,
                    output: Bytes::new()
                },
                "block {}",
                number - 1
            );
        }
        assert_eq!(
            call(&at(&blocks, &hashes, 11), &get, 1_000_000),
            Outcome::Returned {
                gas: 4_072,
                output: encode_bytes(&[10; 80]).into()
            }
        );
    }

    #[test]
    fn merged_mining_tags_follow_the_last_tag_and_its_hash() {
        let mut block = header(1, B256::ZERO);
        assert!(
            matches!(merged_mining_tags(&block), Err(Failure::Threw(_))),
            "no coinbase"
        );
        block.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::new());
        assert!(
            matches!(merged_mining_tags(&block), Err(Failure::Threw(_))),
            "an empty one"
        );
        block.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::from(vec![1, 2, 3]));
        assert_eq!(merged_mining_tags(&block), Ok(Vec::new()), "no tag");
        let mut coinbase = b"prefix".to_vec();
        coinbase.extend_from_slice(RSK_TAG);
        coinbase.extend_from_slice(&[0xAA; 32]);
        coinbase.extend_from_slice(b"ALTBLOCK:extra");
        block.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::from(coinbase.clone()));
        assert_eq!(merged_mining_tags(&block), Ok(b"ALTBLOCK:extra".to_vec()));
        // A tag whose hash runs past the end: `Arrays.copyOfRange` throws.
        coinbase.extend_from_slice(RSK_TAG);
        coinbase.extend_from_slice(&[0xAA; 31]);
        block.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::from(coinbase));
        assert!(matches!(merged_mining_tags(&block), Err(Failure::Threw(_))));
    }

    /// rskj's `BlockHeaderContractTest` constants (no gas used, a minimum gas
    /// price and difficulty of 1, 3 with uncles), and the sign byte
    /// `BigInteger` adds before a set top bit.
    #[test]
    fn numbers_are_written_as_java_writes_them() {
        assert_eq!(big_integer_bytes(U256::ZERO), vec![0]);
        assert_eq!(big_integer_bytes(U256::from(1)), vec![1]);
        assert_eq!(big_integer_bytes(U256::from(3)), vec![3]);
        assert_eq!(big_integer_bytes(U256::from(127)), vec![0x7F]);
        assert_eq!(big_integer_bytes(U256::from(128)), vec![0, 0x80]);
        assert_eq!(big_integer_bytes(U256::from(255)), vec![0, 0xFF]);
        assert_eq!(big_integer_bytes(U256::from(256)), vec![1, 0]);
        assert_eq!(big_integer_bytes(U256::from(32_768)), vec![0, 0x80, 0]);
        assert_eq!(
            big_integer_bytes(U256::from(500_000_000_000_000_000u64)),
            vec![0x06, 0xF0, 0x5B, 0x59, 0xD3, 0xB2, 0x00, 0x00]
        );
        assert_eq!(
            big_integer_bytes(U256::from(10_000_000)),
            vec![0, 0x98, 0x96, 0x80]
        );
        let mut max = vec![0];
        max.extend_from_slice(&[0xFF; 32]);
        assert_eq!(big_integer_bytes(U256::MAX), max);
        assert_eq!(
            shortest_bytes(U256::from(10_000_000)),
            vec![0x98, 0x96, 0x80]
        );
        assert_eq!(shortest_bytes(U256::ZERO), Vec::<u8>::new());
    }

    /// `getGasLimit` returns the gas limit's bytes as the header holds them:
    /// 12,000,000 as rskj's miner writes it, with a sign byte, as testnet's
    /// blocks carry it, and bytes another miner wrote as they were written.
    #[test]
    fn the_gas_limit_comes_back_as_its_bytes() {
        let nine = vec![0, 0, 0, 0, 0, 0, 0xB7, 0x1B, 0x00];
        for (kept, bytes) in [
            (None, vec![0x00, 0xB7, 0x1B, 0x00]),
            (Some(nine.clone()), nine),
        ] {
            let (_dir, blocks, hashes) = chain_with(2, |block| {
                block.gas_limit = U256::from(12_000_000);
                block.kept = kept.clone().map(|gas_limit: Vec<u8>| {
                    Box::new(rustock_core::types::header::KeptFields {
                        gas_limit: Some(gas_limit.into()),
                        ..Default::default()
                    })
                });
            });
            let get = input("getGasLimit(int256)", &[int(0)]);
            assert!(matches!(
                call(&at(&blocks, &hashes, 2), &get, 1_000_000),
                Outcome::Returned { output, .. } if output[..] == encode_bytes(&bytes)[..]
            ));
        }
    }
}
