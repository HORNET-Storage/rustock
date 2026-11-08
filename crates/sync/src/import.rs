//! Import of an rskj `ExportBlocks` file into an empty node, through the same
//! validation and execution follow mode uses:
//!
//! 1. the header against its parent with the node's [`HeaderVerifier`], as
//!    [`SyncManager`](crate::SyncManager) does for every header it accepts;
//! 2. [`BlockProcessor::validate_block`], the body rules follow mode runs
//!    before executing;
//! 3. [`BlockProcessor::process_block`]: transactions root, ommers hash,
//!    execution, then gas used, paid fees, state root, receipts root and logs
//!    bloom against the header;
//! 4. header, total difficulty and canonical index stored with
//!    [`BlockStore::store_headers_batch`], the body with
//!    [`BlockStore::put_body`], then the receipts and indexes with
//!    [`BlockProcessor::commit_receipts`], which is the second half of
//!    `process_and_commit`;
//! 5. every `flush_every` blocks the trie flushed and the executed head
//!    recorded, through the same [`ExecutionCommitter`] follow mode uses.
//!
//! The order is rskj's (`BlockChainImpl.internalTryToConnect`): validate,
//! execute, check the results, then store, so that nothing is written for a
//! block that fails.
//!
//! Unlike sync, a block that does not extend the best block, or that fails
//! any check, ends the import: the file is one chain, and the first block
//! that does not connect is the answer the caller wants.

use alloy_primitives::{B256, U256};
use alloy_rlp::Decodable;
use rustock_core::validation::{HeaderVerifier, ValidationError};
use rustock_core::{Block, Header, Transaction};
use rustock_execution::{BlockProcessor, ProcessError};
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;

use crate::execution_commit::ExecutionCommitter;

/// Blocks between flushes when the caller does not say: rskj's
/// `blockchain.flushNumberOfBlocks` default.
pub const DEFAULT_IMPORT_FLUSH_EVERY: u64 = 10;

/// Why a block was not imported.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(
        "not the next block: parent {parent}, number {number}, \
         but the best block is #{best_number} {best_hash}"
    )]
    NotNextBlock {
        number: u64,
        parent: B256,
        best_number: u64,
        best_hash: B256,
    },
    #[error("header validation failed: {0}")]
    Header(ValidationError),
    #[error("block validation failed: {0}")]
    Block(ValidationError),
    #[error("{0}")]
    Process(#[from] ProcessError),
    #[error("recording the executed head failed")]
    ExecHead,
    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),
}

impl ImportError {
    /// Short name of the check that failed, for the exit message.
    pub fn check(&self) -> &'static str {
        match self {
            ImportError::NotNextBlock { .. } => "parent",
            ImportError::Header(_) => "header",
            ImportError::Block(_) => "blockRules",
            ImportError::Process(e) => match e {
                ProcessError::GasUsedMismatch { .. } => "gasUsed",
                ProcessError::PaidFeesMismatch { .. } => "paidFees",
                ProcessError::StateRootMismatch { .. } => "stateRoot",
                ProcessError::ReceiptsRootMismatch { .. } => "receiptsRoot",
                ProcessError::TransactionsRootMismatch { .. } => "transactionsRoot",
                ProcessError::OmmersHashMismatch { .. } => "ommersHash",
                ProcessError::LogsBloomMismatch => "logsBloom",
                _ => "execution",
            },
            ImportError::ExecHead | ImportError::Storage(_) => "storage",
        }
    }
}

/// A block imported as the new best block.
#[derive(Debug, Clone)]
pub struct ImportedBlock {
    pub number: u64,
    pub hash: B256,
    pub tx_count: usize,
    pub gas_used: u64,
    /// Whether this block ended with a flush.
    pub flushed: bool,
    /// Where the time went, when the importer measures it
    /// ([`BlockImporter::measure`]).
    pub timings: Option<ImportTimings>,
}

/// The phase clock and the timings of one import, shared with the mined
/// path: [`rustock_execution::breakdown`].
pub use rustock_execution::breakdown::{ConnectTimings as ImportTimings, Laps};

/// Imports a chain block by block on top of the store's best block.
pub struct BlockImporter {
    store: Arc<BlockStore>,
    verifier: HeaderVerifier,
    processor: BlockProcessor,
    trie_store: Arc<dyn TrieStore>,
    state_root: TrieNode,
    best: Header,
    best_hash: B256,
    best_td: U256,
    committer: ExecutionCommitter,
    last_executed: Option<(B256, B256)>,
    measure: bool,
}

impl BlockImporter {
    /// An importer continuing from the store's head, whose state is
    /// `state_root`.
    pub fn new(
        store: Arc<BlockStore>,
        verifier: HeaderVerifier,
        processor: BlockProcessor,
        trie_store: Arc<dyn TrieStore>,
        state_root: TrieNode,
        flush_every: u64,
    ) -> anyhow::Result<Self> {
        let best_hash = store
            .head()?
            .ok_or_else(|| anyhow::anyhow!("the store has no head block"))?;
        let best = store
            .header(best_hash)?
            .ok_or_else(|| anyhow::anyhow!("head header {best_hash} missing"))?;
        let best_td = store.total_difficulty(best_hash)?.unwrap_or_default();
        Ok(Self {
            store,
            verifier,
            processor,
            trie_store,
            state_root,
            best,
            best_hash,
            best_td,
            committer: ExecutionCommitter::new(flush_every),
            last_executed: None,
            measure: false,
        })
    }

    /// Measure each import ([`ImportedBlock::timings`]). Off by default, and
    /// then no clock is read.
    pub fn measure(mut self, measure: bool) -> Self {
        self.measure = measure;
        self
    }

    /// Number and hash of the best block.
    pub fn best(&self) -> (u64, B256) {
        (self.best.number, self.best_hash)
    }

    /// Validate, execute and store `block` as the new best block.
    pub fn import(&mut self, block: Block) -> Result<ImportedBlock, ImportError> {
        let mut laps = Laps::new(self.measure);
        let mut t = ImportTimings::default();
        let mut process = rustock_execution::ProcessTimings::default();
        let header = &block.header;
        let hash = header.hash();
        if header.parent_hash != self.best_hash || header.number != self.best.number + 1 {
            return Err(ImportError::NotNextBlock {
                number: header.number,
                parent: header.parent_hash,
                best_number: self.best.number,
                best_hash: self.best_hash,
            });
        }
        t.preamble = laps.lap();

        self.verifier
            .verify(header, Some(&self.best))
            .map_err(ImportError::Header)?;
        self.processor
            .validate_block(&block)
            .map_err(ImportError::Block)?;
        t.initial_validation = laps.lap();
        let trie_store = self.trie_store.clone();
        let processed = if self.measure {
            self.processor
                .process_block_timed(&block, &self.state_root, trie_store, &mut process)
        } else {
            self.processor
                .process_block(&block, &self.state_root, trie_store)
        };
        let result = match processed {
            Ok(result) => result,
            Err(e) => {
                // Keep the trie nodes the failed block wrote: its computed
                // state can then be diffed against the reference client's.
                self.trie_store.flush();
                return Err(e.into());
            }
        };
        laps.lap();
        t.initial_validation += process.pre_validation;
        t.execute = process.execute;
        t.trie_save = process.trie_save;
        t.post_execute_validation = process.post_validation;

        let td = self.best_td + rustock_execution::mining::cumulative_difficulty(&block);
        self.store
            .store_headers_batch(&[(header, td)], Some(self.best_hash), self.best_td)?;
        self.store
            .put_body(hash, &block.transactions, &block.ommers)?;
        t.switch_chain = laps.lap();
        self.processor.commit_receipts(&block, &result)?;
        t.save_receipts = laps.lap();
        self.state_root = result.new_state_root;
        self.last_executed = Some((hash, result.state_root_hash));

        let store = &self.store;
        let root = result.state_root_hash;
        let flushed = match self
            .committer
            .after_block(self.trie_store.as_ref(), false, || {
                crate::service::record_execution(store, hash, root)
            }) {
            None => false,
            Some(true) => true,
            Some(false) => return Err(ImportError::ExecHead),
        };
        t.on_best_block = laps.lap();
        t.total = laps.total();

        let imported = ImportedBlock {
            number: header.number,
            hash,
            tx_count: block.transactions.len(),
            gas_used: header.gas_used,
            flushed,
            timings: self.measure.then_some(t),
        };
        self.best_hash = hash;
        self.best_td = td;
        self.best = block.header;
        Ok(imported)
    }

    /// Flush whatever the last blocks left in memory and record the head.
    pub fn finish(mut self) -> Result<(), ImportError> {
        let Some((hash, root)) = self.last_executed else {
            return Ok(());
        };
        let store = &self.store;
        match self.committer.finish(self.trie_store.as_ref(), || {
            crate::service::record_execution(store, hash, root)
        }) {
            Some(false) => Err(ImportError::ExecHead),
            _ => Ok(()),
        }
    }
}

/// One line of rskj's `ExportBlocks` format:
/// `number,hashHex,totalDifficultyHex,blockRlpHex`.
#[derive(Debug, Clone)]
pub struct ExportedBlock {
    pub number: u64,
    pub hash: B256,
    pub block: Block,
}

/// Decode one header of an exported block.
///
/// `ExportBlocks` writes `Block.getEncoded()`, whose headers are in rskj's
/// full encoding. For a version-0 header that is the hashed encoding too, so
/// the hash is taken from the bytes, as the wire decoders do. A versioned
/// (RSKIP-351) header is hashed in its compressed encoding, where the bloom
/// slot holds the extension commitment and the version fields are left out,
/// so its hash is recomputed from the decoded fields instead.
///
fn decode_exported_header(buf: &mut &[u8]) -> alloy_rlp::Result<Header> {
    let mut header = Header::decode_with_hash(buf)?;
    if header.version_fields.is_some() {
        header.cached_hash = None;
        header.cached_hash_for_merged_mining = None;
        header.cached_hash = Some(header.hash());
    }
    Ok(header)
}

/// Decode a block in rskj's encoding, `RLP([header, transactions, uncles])`,
/// with each header's hash computed as rskj computes it.
pub fn decode_block(mut rlp: &[u8]) -> anyhow::Result<Block> {
    let buf = &mut rlp;
    let list = alloy_rlp::Header::decode(buf)?;
    anyhow::ensure!(list.list, "block is not an RLP list");
    let mut body = &buf[..list.payload_length];
    let header = decode_exported_header(&mut body)?;
    let transactions = Vec::<Transaction>::decode(&mut body)?;
    let uncles = alloy_rlp::Header::decode(&mut body)?;
    anyhow::ensure!(uncles.list, "uncles are not an RLP list");
    let (mut uncles_rlp, rest) = body.split_at(uncles.payload_length);
    let mut ommers = Vec::new();
    while !uncles_rlp.is_empty() {
        ommers.push(decode_exported_header(&mut uncles_rlp)?);
    }
    anyhow::ensure!(rest.is_empty(), "unexpected fields after the uncles");
    Ok(Block {
        header,
        transactions,
        ommers,
    })
}

/// Encode a block as rskj's `Block.getEncoded()` does, the inverse of
/// [`decode_block`]: `RLP([header, transactions, uncles])` with the header
/// in its full wire form (version fields and all) and each transaction in
/// the bytes it was received or built with (`rlp_for_trie`, which is what
/// its hash and the transactions root are computed over; rskj keeps a zero
/// gas price as a literal `00` byte there, which re-encoding would
/// canonicalise away).
pub fn encode_block(block: &Block) -> Vec<u8> {
    use alloy_rlp::Encodable;
    let mut header = Vec::new();
    block.header.encode(&mut header);
    let mut transactions = Vec::new();
    for tx in &block.transactions {
        transactions.extend_from_slice(&tx.rlp_for_trie());
    }
    let mut uncles = Vec::new();
    for uncle in &block.ommers {
        uncle.encode(&mut uncles);
    }
    let list = |payload: &[u8], out: &mut Vec<u8>| {
        alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(out);
        out.extend_from_slice(payload);
    };
    let mut body = header;
    list(&transactions, &mut body);
    list(&uncles, &mut body);
    let mut out = Vec::with_capacity(body.len() + 4);
    list(&body, &mut out);
    out
}

/// Write one line of rskj's `ExportBlocks` format, the inverse of
/// [`parse_export_line`]: `number,hashHex,totalDifficultyHex,blockRlpHex`,
/// as `co.rsk.cli.tools.ExportBlocks.exportBlocks` writes it. The hash is
/// the one the block is stored under; the total difficulty is
/// `BigInteger.toByteArray()` (a leading zero byte when the top bit is set,
/// `00` for zero); the RLP is [`encode_block`].
pub fn encode_export_line(hash: B256, total_difficulty: U256, block: &Block) -> String {
    let rlp = encode_block(block);
    format!(
        "{},{},{},{}",
        block.header.number,
        alloy_primitives::hex::encode(hash),
        alloy_primitives::hex::encode(java_big_integer_bytes(total_difficulty)),
        alloy_primitives::hex::encode(rlp)
    )
}

/// `BigInteger.toByteArray()` of a non-negative value: the shortest
/// two's-complement big-endian form, so a leading zero byte keeps a value
/// whose top bit is set positive, and zero is one zero byte.
fn java_big_integer_bytes(value: U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![0];
    }
    let be = value.to_be_bytes::<32>();
    let start = be.iter().position(|b| *b != 0).unwrap_or(31);
    let mut out = Vec::with_capacity(33 - start);
    if be[start] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&be[start..]);
    out
}

/// Parse one `ExportBlocks` line. `Ok(None)` for a line rskj's
/// `ConnectBlocks` skips (fewer than four fields). The decoded block must
/// have the number and hash the line states.
pub fn parse_export_line(line: &str) -> anyhow::Result<Option<ExportedBlock>> {
    let parts: Vec<&str> = line.trim().split(',').collect();
    if parts.len() < 4 {
        return Ok(None);
    }
    let number: u64 = parts[0]
        .parse()
        .map_err(|e| anyhow::anyhow!("block number '{}': {e}", parts[0]))?;
    let hash: B256 = parts[1]
        .parse()
        .map_err(|e| anyhow::anyhow!("block hash '{}': {e}", parts[1]))?;
    let rlp = alloy_primitives::hex::decode(parts[3])?;
    let block = decode_block(&rlp)?;
    anyhow::ensure!(
        block.header.number == number,
        "the line says block {number}, the block is #{}",
        block.header.number
    );
    anyhow::ensure!(
        block.header.hash() == hash,
        "block #{number}: the line's hash is {hash}, rustock computes {}",
        block.header.hash()
    );
    Ok(Some(ExportedBlock {
        number,
        hash,
        block,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_lines_are_skipped_like_rskj_connect_blocks() {
        assert!(parse_export_line("").unwrap().is_none());
        assert!(parse_export_line("1,abc,01").unwrap().is_none());
    }

    #[test]
    fn total_difficulty_is_written_as_java_writes_a_big_integer() {
        let hex = |v: u64| alloy_primitives::hex::encode(java_big_integer_bytes(U256::from(v)));
        assert_eq!(hex(0), "00");
        assert_eq!(hex(1), "01");
        assert_eq!(hex(0x7f), "7f");
        assert_eq!(hex(0x80), "0080");
        assert_eq!(hex(0x1ffe_0000), "1ffe0000");
        assert_eq!(hex(0xff00_0000), "00ff000000");
    }

    /// A block built here, written and read back, is the same block on the
    /// same line; and a line that names the wrong hash is refused.
    #[test]
    fn an_exported_line_parses_back_to_the_same_block() {
        let header = Header {
            parent_hash: B256::repeat_byte(0x11),
            ommers_hash: B256::repeat_byte(0x22),
            beneficiary: alloy_primitives::Address::repeat_byte(0x33),
            state_root: B256::repeat_byte(0x44),
            transactions_root: B256::repeat_byte(0x55),
            receipts_root: B256::repeat_byte(0x66),
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(0x8000_0000u64),
            number: 42,
            gas_limit: U256::from(6_800_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: alloy_primitives::Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            version_fields: None,
            bitcoin_merged_mining_header: Some(alloy_primitives::Bytes::from(vec![0u8; 80])),
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };
        let block = Block {
            header,
            transactions: Vec::new(),
            ommers: Vec::new(),
        };
        let hash = block.header.hash();
        let line = encode_export_line(hash, U256::from(0x8000_0001u64), &block);
        assert!(line.starts_with(&format!(
            "42,{},0080000001,f9",
            alloy_primitives::hex::encode(hash)
        )));

        let parsed = parse_export_line(&line).unwrap().unwrap();
        assert_eq!(parsed.number, 42);
        assert_eq!(parsed.hash, hash);
        assert_eq!(parsed.block.header.hash(), hash);
        assert_eq!(parsed.block.header.number, 42);
        assert_eq!(parsed.block.header.difficulty, U256::from(0x8000_0000u64));
        assert_eq!(
            encode_export_line(parsed.hash, U256::from(0x8000_0001u64), &parsed.block),
            line
        );

        let wrong = encode_export_line(B256::repeat_byte(0xee), U256::ONE, &block);
        assert!(parse_export_line(&wrong).is_err());
    }

    #[test]
    fn malformed_lines_are_errors() {
        let hash = "00".repeat(32);
        assert!(parse_export_line(&format!("x,{hash},01,c0")).is_err());
        assert!(parse_export_line(&format!("1,{hash},01,zz")).is_err());
        // An empty list is not a block.
        assert!(parse_export_line(&format!("1,{hash},01,c0")).is_err());
    }
}
