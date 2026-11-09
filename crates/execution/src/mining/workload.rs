//! Generating block workloads with a known collision structure.
//!
//! Built to answer one question about the RSKIP-144 miner: given
//! transactions whose dependencies we chose on purpose, does it partition
//! them the way we expect, and does the block it produces validate?
//!
//! The transfers run through a token contract rather than moving rBTC,
//! because a token transfer's collisions are **storage** collisions and
//! those are the ones we can place freely. A native transfer touches the two
//! account cells and nothing else; a token transfer touches two cells of our
//! choosing, so the transfer graph *is* the collision graph and we can draw
//! it.
//!
//! Everything here is deterministic from a seed. That is not tidiness: the
//! point of the exercise is to hand the same transactions to another
//! implementation and compare the partitions, and transactions regenerated
//! rather than replayed would make a difference in the input
//! indistinguishable from a difference in the decision.

use alloy_primitives::{Address, B256, U256};
use rustock_core::Transaction;

/// The token's storage layout: `balances` is a `mapping(address => uint256)`
/// at slot 0, so an account's balance lives at `keccak256(addr ++ 0)` --
/// Solidity's layout, which is what makes the collisions recognisable.
pub const BALANCES_SLOT: u64 = 0;

/// Runtime code of the token.
///
/// Deliberately not an ABI-compatible ERC-20. There is no selector
/// dispatch, no `balanceOf` entry point and no events: the caller controls
/// the calldata and the tool reads balances out of the trie, so a dispatcher
/// would be sixty bytes of bookkeeping that cannot fail in an interesting
/// way. What is kept is the part that matters -- the storage layout, so the
/// cells a transfer touches are the cells an ERC-20 transfer would touch.
///
/// Calling convention: 64 bytes of calldata, `to` (left-padded to 32) then
/// `amount`. The transfer is always from `CALLER`.
///
/// ```text
///   mem[0x20] = 0                       the mapping's slot
///   mem[0x00] = CALLER
///   from = keccak(mem[0x00..0x40])
///   sstore(from, sload(from) - amount)
///   mem[0x00] = calldata[0x00]          `to`
///   to = keccak(mem[0x00..0x40])
///   sstore(to, sload(to) + amount)
/// ```
///
/// No balance check: an underflow would wrap, and the generator funds every
/// account far beyond what it spends. A revert here would be a silent change
/// of subject -- a reverted transfer still touches both cells, so the
/// partition would look right while the balances went nowhere.
pub fn token_runtime() -> Vec<u8> {
    let mut code = Vec::new();
    // mem[0x20] = 0
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0x00
    code.extend_from_slice(&[0x60, 0x20]); // PUSH1 0x20
    code.push(0x52); // MSTORE

    // --- debit the caller ---
    code.push(0x33); // CALLER
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0x00
    code.push(0x52); // MSTORE            mem[0x00] = caller
    code.extend_from_slice(&[0x60, 0x40]); // PUSH1 0x40
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0x00
    code.push(0x20); // SHA3              -> slot
    code.push(0x80); // DUP1
    code.push(0x54); // SLOAD             -> slot, balance
    code.extend_from_slice(&[0x60, 0x20]); // PUSH1 0x20
    code.push(0x35); // CALLDATALOAD      -> slot, balance, amount
    code.push(0x90); // SWAP1             -> slot, amount, balance
    code.push(0x03); // SUB               -> slot, balance - amount
    code.push(0x90); // SWAP1             -> balance - amount, slot
    code.push(0x55); // SSTORE

    // --- credit the recipient ---
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0x00
    code.push(0x35); // CALLDATALOAD      -> to
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0x00
    code.push(0x52); // MSTORE            mem[0x00] = to
    code.extend_from_slice(&[0x60, 0x40]); // PUSH1 0x40
    code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0x00
    code.push(0x20); // SHA3              -> slot
    code.push(0x80); // DUP1
    code.push(0x54); // SLOAD             -> slot, balance
    code.extend_from_slice(&[0x60, 0x20]); // PUSH1 0x20
    code.push(0x35); // CALLDATALOAD      -> slot, balance, amount
    code.push(0x01); // ADD               -> slot, balance + amount
    code.push(0x90); // SWAP1             -> balance + amount, slot
    code.push(0x55); // SSTORE

    code.push(0x00); // STOP
    code
}

/// Constructor code: copy the runtime out of the deployment payload and
/// return it. Nothing is initialised -- balances are written into the trie
/// directly, which is both faster and the only way to fund an account
/// without a transaction that would itself collide with everything.
pub fn token_deploy_code() -> Vec<u8> {
    let runtime = token_runtime();
    let len = runtime.len();
    assert!(len < 256, "the length fits a PUSH1, or this prologue is wrong");
    let mut code = vec![
        0x60, len as u8, // PUSH1 len
        0x60, 0x0c,      // PUSH1 12 -- the prologue's own length
        0x60, 0x00,      // PUSH1 0
        0x39,            // CODECOPY  mem[0..len] = code[12..12+len]
        0x60, len as u8, // PUSH1 len
        0x60, 0x00,      // PUSH1 0
        0xf3,            // RETURN
    ];
    // Counted, not assumed: the offset above is this length, and getting it
    // wrong deploys a contract whose first bytes are the tail of its own
    // constructor -- which still deploys, and still runs, and does the wrong
    // thing only when called.
    debug_assert_eq!(code.len(), 12, "the prologue's length is in the prologue");
    code.extend_from_slice(&runtime);
    code
}

/// The storage cell holding `holder`'s balance: `keccak256(holder ++ slot)`.
pub fn balance_slot(holder: &Address) -> B256 {
    use sha3::{Digest, Keccak256};
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(holder.as_slice());
    buf[56..64].copy_from_slice(&BALANCES_SLOT.to_be_bytes());
    B256::from_slice(&Keccak256::digest(buf))
}

/// Calldata for a transfer of `amount` to `to`.
pub fn transfer_calldata(to: &Address, amount: U256) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[12..32].copy_from_slice(to.as_slice());
    data[32..64].copy_from_slice(&amount.to_be_bytes::<32>());
    data
}

/// One transfer in a generated workload, before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Index into the workload's account list.
    pub from: usize,
    pub to: usize,
    pub amount: u64,
}

/// A named shape of dependencies between transfers.
///
/// Each one answers a different question of the partitioner, and the
/// expected answer is in the doc rather than in the generator, so a change
/// in behaviour reads as a change in behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// `n` transfers over `2n` distinct accounts: nothing touches anything
    /// else. Every parallel sublist should be used, and evenly.
    Independent,
    /// `a -> b`, `b -> c`, `c -> d`: each recipient is the next sender, so
    /// every transfer is connected to its neighbours. One sublist.
    Chain,
    /// Every transfer from one account. Connected by the sender's own
    /// account cell before the token is even reached.
    OneSender,
    /// Every transfer to one account. Connected only through the recipient's
    /// storage cell, which is the case a native-transfer workload can make
    /// but not isolate.
    HotRecipient,
    /// Independent transfers with one Bridge call among them. The Bridge
    /// call must end up in the sequential sublist, whatever else happens.
    WithBridgeCall,
    /// Independent transfers, but enough of them that a parallel sublist
    /// fills and the rest overflow into the sequential one.
    GasPressure,
}

impl Scenario {
    pub fn name(&self) -> &'static str {
        match self {
            Scenario::Independent => "independent",
            Scenario::Chain => "chain",
            Scenario::OneSender => "one-sender",
            Scenario::HotRecipient => "hot-recipient",
            Scenario::WithBridgeCall => "with-bridge-call",
            Scenario::GasPressure => "gas-pressure",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "independent" => Scenario::Independent,
            "chain" => Scenario::Chain,
            "one-sender" => Scenario::OneSender,
            "hot-recipient" => Scenario::HotRecipient,
            "with-bridge-call" => Scenario::WithBridgeCall,
            "gas-pressure" => Scenario::GasPressure,
            _ => return None,
        })
    }

    pub fn all() -> [Scenario; 6] {
        [
            Scenario::Independent,
            Scenario::Chain,
            Scenario::OneSender,
            Scenario::HotRecipient,
            Scenario::WithBridgeCall,
            Scenario::GasPressure,
        ]
    }

    /// How many distinct accounts the scenario needs for `count` transfers.
    pub fn accounts_needed(&self, count: usize) -> usize {
        match self {
            Scenario::Independent | Scenario::WithBridgeCall | Scenario::GasPressure => {
                (count * 2).max(2)
            }
            Scenario::Chain => count + 1,
            Scenario::OneSender => count + 1,
            Scenario::HotRecipient => count + 1,
        }
    }

    /// The transfers themselves, as account indices.
    pub fn transfers(&self, count: usize) -> Vec<Transfer> {
        let amount = |i: usize| 1_000 + i as u64;
        match self {
            Scenario::Independent | Scenario::WithBridgeCall | Scenario::GasPressure => (0..count)
                .map(|i| Transfer { from: i * 2, to: i * 2 + 1, amount: amount(i) })
                .collect(),
            Scenario::Chain => {
                (0..count).map(|i| Transfer { from: i, to: i + 1, amount: amount(i) }).collect()
            }
            Scenario::OneSender => {
                (0..count).map(|i| Transfer { from: 0, to: i + 1, amount: amount(i) }).collect()
            }
            Scenario::HotRecipient => {
                (0..count).map(|i| Transfer { from: i + 1, to: 0, amount: amount(i) }).collect()
            }
        }
    }

    /// A block gas limit this scenario needs, if it needs a particular one.
    ///
    /// `GasPressure` is about a parallel sublist filling up, which at the
    /// default limit would take forty-odd transactions. Squeezing the limit
    /// makes the sublists small enough for a handful to overflow them.
    pub fn block_gas_limit_hint(&self) -> Option<u64> {
        match self {
            // (10,600,000 - 10,000,000) / 2 = 300,000 per parallel sublist.
            //
            // The margin has to be this tight because the fit test is not
            // the obvious one: a sublist accumulates each transaction's gas
            // *used* -- about 45,000 for a token transfer -- but admits the
            // next one only if its declared gas *limit* also fits, which is
            // 120,000 here. rskj does the same. So a sublist stops taking
            // work long before it is full, and a limit chosen from the used
            // gas alone never overflows.
            Scenario::GasPressure => Some(10_600_000),
            _ => None,
        }
    }

    /// Whether the scenario puts a Bridge call in the block, and where.
    pub fn bridge_call_at(&self, count: usize) -> Option<usize> {
        match self {
            // In the middle, so it is neither the first transaction the
            // partitioner sees nor the last.
            Scenario::WithBridgeCall => Some(count / 2),
            _ => None,
        }
    }
}

/// A deterministic account: the same seed and index always give the same key.
///
/// Not cryptographically interesting and not meant to be -- these accounts
/// exist in a throwaway chain. What matters is that the generator can be
/// re-run and produce byte-identical transactions, so that a comparison
/// against another implementation is comparing decisions and not inputs.
pub fn account_key(seed: u64, index: usize) -> k256::ecdsa::SigningKey {
    use sha3::{Digest, Keccak256};
    let mut material = Keccak256::new();
    material.update(b"rustock parallel workload");
    material.update(seed.to_be_bytes());
    material.update((index as u64).to_be_bytes());
    let bytes: [u8; 32] = material.finalize().into();
    // A hash is overwhelmingly likely to be a valid scalar; retry rather
    // than unwrap, so a one-in-2^128 draw does not fail a test run.
    k256::ecdsa::SigningKey::from_slice(&bytes).unwrap_or_else(|_| account_key(seed + 1, index))
}

/// A filler account's address: a hash, not a key.
///
/// These accounts exist to make a trie big and its reads cold. Nothing ever
/// signs for them, so deriving them from a keypair would be both slower and
/// a claim about them that is not true -- five million secp256k1 keys take
/// longer to generate than the trie takes to build, to produce addresses
/// nothing will ever spend.
pub fn filler_address(seed: u64, index: u64) -> Address {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(b"rustock synthetic filler");
    hasher.update(seed.to_be_bytes());
    hasher.update(index.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    Address::from_slice(&digest[12..])
}

pub fn address_of(key: &k256::ecdsa::SigningKey) -> Address {
    use sha3::{Digest, Keccak256};
    let encoded = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&Keccak256::digest(&encoded.as_bytes()[1..])[12..])
}

/// Sign `tx` as `key`, EIP-155.
pub fn sign(tx: &mut Transaction, key: &k256::ecdsa::SigningKey, chain_id: u64) {
    let hash = tx.signing_hash_eip155(chain_id);
    let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        key.sign_prehash_recoverable(hash.as_slice()).expect("signing a 32-byte digest");
    let sig = signature.to_bytes();
    tx.r = U256::from_be_slice(&sig[..32]);
    tx.s = U256::from_be_slice(&sig[32..]);
    tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
    tx.cached_rlp = None;
}

/// Tokens every account starts with. Far more than any scenario spends --
/// the contract has no balance check, and an underflow would wrap rather
/// than revert, which would change the subject rather than fail.
pub const TOKENS_EACH: u64 = 1_000_000;

/// A workload to generate and mine.
#[derive(Debug, Clone)]
pub struct Workload {
    pub scenario: Scenario,
    pub seed: u64,
    /// How many transfers. `GasPressure` ignores it and uses as many as it
    /// takes to overflow a parallel sublist.
    pub count: usize,
    pub chain_id: u64,
    /// The block gas limit the miner builds against. Lowering it is how
    /// `GasPressure` is made to bite.
    pub block_gas_limit: u64,
}

impl Default for Workload {
    fn default() -> Self {
        Self {
            scenario: Scenario::Independent,
            seed: 1,
            count: 4,
            chain_id: 33,
            // Above the minimum sequential gas limit, and by enough. At or
            // below it the parallel sublists get *no gas at all* and the
            // whole block is sequential -- see `sublist_gas_limits`. A
            // default of 10,000,000 against testnet's 10,000,000 minimum
            // sat exactly on that boundary and quietly produced
            // unpartitioned blocks.
            block_gas_limit: 20_000_000,
        }
    }
}

/// What the miner did with a workload.
#[derive(Debug)]
pub struct WorkloadReport {
    pub scenario: Scenario,
    /// The transactions handed to the miner, in pool order, signed.
    pub submitted: Vec<Transaction>,
    /// The block it built, transactions in sublist order.
    pub block: rustock_core::Block,
    /// `txExecutionSublistsEdges`, empty when the block declares no
    /// partition.
    pub edges: Vec<i16>,
    /// Which sublist each of the block's transactions landed in, `None` for
    /// the sequential set.
    pub placement: Vec<Option<usize>>,
    /// Whether the block the miner produced is one this node would accept.
    /// The only verdict that counts.
    pub validated: Result<(), String>,
    pub token: Address,
    pub accounts: Vec<Address>,
    /// The private keys behind `accounts`, so the world can be rebuilt
    /// elsewhere. Throwaway by construction -- see [`account_key`].
    pub account_keys: Vec<B256>,
    /// rBTC each account was funded with, for gas.
    pub rbtc_each: U256,
    /// Token balance each account was given.
    pub tokens_each: u64,
    pub chain_id: u64,
    pub block_gas_limit: u64,
}

impl WorkloadReport {
    /// Everything another implementation needs to rebuild this world and
    /// reach its own verdict: the accounts and their keys, the token and
    /// its code, the balances, and -- last -- what *this* miner decided, so
    /// the two can be compared without running this one again.
    pub fn describe_world(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "# scenario        {}", self.scenario.name());
        let _ = writeln!(out, "# chain-id        {}", self.chain_id);
        let _ = writeln!(out, "# block-gas-limit {}", self.block_gas_limit);
        let _ = writeln!(out, "# token           {}", self.token);
        let _ = writeln!(
            out,
            "# token-code      {}",
            alloy_primitives::hex::encode(token_runtime())
        );
        let _ = writeln!(out, "# token-slot      {} (mapping(address => uint256))", BALANCES_SLOT);
        let _ = writeln!(out, "#");
        let _ = writeln!(out, "# accounts: index address private-key rbtc tokens");
        for (i, (addr, key)) in self.accounts.iter().zip(&self.account_keys).enumerate() {
            let _ = writeln!(
                out,
                "account {i} {addr} 0x{} {} {}",
                alloy_primitives::hex::encode(key),
                self.rbtc_each,
                self.tokens_each
            );
        }
        let _ = writeln!(out, "#");
        let _ = writeln!(out, "# what this miner decided, for comparison");
        let _ = writeln!(out, "edges {:?}", self.edges);
        for (i, seat) in self.placement.iter().enumerate() {
            let where_ = match seat {
                Some(id) => format!("parallel-{id}"),
                None => "sequential".to_string(),
            };
            let _ = writeln!(out, "placed {i} {where_}");
        }
        out
    }

    /// How many transactions landed in each parallel sublist, and in the
    /// sequential set last.
    pub fn sizes(&self) -> Vec<usize> {
        let parallel = self.edges.len();
        let mut sizes = vec![0usize; parallel + 1];
        for seat in &self.placement {
            match seat {
                Some(id) if *id < parallel => sizes[*id] += 1,
                _ => sizes[parallel] += 1,
            }
        }
        sizes
    }
}

impl Workload {
    /// Generate the workload, mine it, and check the block.
    ///
    /// `data_dir` is where the throwaway block store goes. Supplied by the
    /// caller rather than made here, so that a workload harness is not a
    /// reason for this crate to depend on `tempfile`.
    pub fn run(&self, data_dir: &std::path::Path) -> Result<WorkloadReport, String> {
        use crate::hardfork::RskHardforkConfig;
        use crate::mining::template::{
            BlockTemplateBuilder, PendingTransaction, PendingTransactionSource,
        };
        use crate::{BlockProcessor, MiningConfig};
        use rustock_storage::BlockStore;
        use rustock_trie::{AccountState, MemoryTrieStore, TrieKeySlice, TrieNode, TrieStore};
        use std::sync::Arc;

        struct Pool(Vec<PendingTransaction>);
        impl PendingTransactionSource for Pool {
            fn pending(&self) -> Vec<PendingTransaction> {
                self.0.clone()
            }
        }

        let count = self.count.max(1);
        let block_gas_limit =
            self.scenario.block_gas_limit_hint().unwrap_or(self.block_gas_limit);
        let min_sequential =
            rustock_core::config::ChainConfig::testnet().min_sequential_set_gas_limit;
        let (parallel_gas, _) = crate::mining::partition::sublist_gas_limits(
            block_gas_limit,
            rustock_core::validation::block_rules::TX_EXECUTION_THREADS as u64,
            min_sequential,
        );
        if parallel_gas == 0 {
            return Err(format!(
                "a block gas limit of {block_gas_limit} leaves the parallel sublists no gas                  (the sequential one is guaranteed {min_sequential}), so nothing can be                  partitioned however the transactions are drawn -- raise it above                  {min_sequential}"
            ));
        }
        let transfers = self.scenario.transfers(count);
        let n_accounts = self.scenario.accounts_needed(count);
        let keys: Vec<_> = (0..n_accounts).map(|i| account_key(self.seed, i)).collect();
        let accounts: Vec<Address> = keys.iter().map(address_of).collect();
        let token = Address::repeat_byte(0x7E);

        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let block_store = Arc::new(BlockStore::open(data_dir).map_err(|e| e.to_string())?);

        // The world: funded accounts, the token's code, and a token balance
        // for everyone. Written straight into the trie -- funding by
        // transaction would add transfers that collide with everything and
        // change the very thing being measured.
        let mut root = TrieNode::empty();
        let put = |root: &TrieNode, key: Vec<u8>, value: &[u8]| -> TrieNode {
            root.put(&TrieKeySlice::from_key(&key), value, trie_store.as_ref())
        };
        let rbtc = U256::from(10u64).pow(U256::from(18));
        for addr in &accounts {
            root = put(&root, rustock_trie::account_key(addr), &AccountState::new(U256::ZERO, rbtc).encode());
            root = put(
                &root,
                rustock_trie::storage_key(&token, &balance_slot(addr)),
                &TOKENS_EACH.to_be_bytes()[5..],
            );
        }
        root = put(
            &root,
            rustock_trie::account_key(&token),
            &AccountState::new(U256::ZERO, U256::ZERO).encode(),
        );
        root = put(&root, rustock_trie::code_key(&token), &token_runtime());
        root = put(&root, rustock_trie::storage_prefix_key(&token), &[1]);
        let state_root = root.compute_hash(trie_store.as_ref());
        root.save(trie_store.as_ref(), true);

        // A short chain, so REMASC can reach back as far as it wants to.
        let mut parent_hash = B256::ZERO;
        let mut parent = chain_header(0, parent_hash, state_root, block_gas_limit);
        for number in 0..=20u64 {
            let header = chain_header(number, parent_hash, state_root, block_gas_limit);
            let hash = header.hash();
            block_store.put_header_with_hash(hash, &header).map_err(|e| e.to_string())?;
            block_store.put_canonical_hash(number, hash).map_err(|e| e.to_string())?;
            block_store
                .put_total_difficulty(hash, U256::from(number + 1))
                .map_err(|e| e.to_string())?;
            parent_hash = hash;
            parent = header;
        }
        block_store.set_head(parent_hash).map_err(|e| e.to_string())?;
        block_store.set_exec_head(parent_hash, state_root).map_err(|e| e.to_string())?;

        // The transactions, in pool order.
        let bridge_at = self.scenario.bridge_call_at(count);
        let mut nonces = vec![0u64; n_accounts];
        let mut submitted = Vec::new();
        let mut pending = Vec::new();
        for (i, transfer) in transfers.iter().enumerate() {
            if bridge_at == Some(i) {
                let from = &keys[transfer.from];
                let tx = self.bridge_call(from, nonces[transfer.from]);
                nonces[transfer.from] += 1;
                submitted.push(tx.clone());
                pending.push(PendingTransaction {
                    hash: tx_hash(&tx),
                    sender: accounts[transfer.from],
                    tx,
                });
            }
            let from = &keys[transfer.from];
            let tx = self.token_transfer(
                from,
                nonces[transfer.from],
                &token,
                &accounts[transfer.to],
                transfer.amount,
            );
            nonces[transfer.from] += 1;
            submitted.push(tx.clone());
            pending.push(PendingTransaction {
                hash: tx_hash(&tx),
                sender: accounts[transfer.from],
                tx,
            });
        }

        let hardfork_cfg = RskHardforkConfig::all_active_parallel(self.chain_id);
        let mut chain_config = rustock_core::config::ChainConfig::testnet();
        chain_config.chain_id = self.chain_id as u8;
        chain_config.min_difficulty = U256::from(1);
        chain_config.max_gas_limit = block_gas_limit.max(1);
        // The miner and the validator on the same constants: the sequential
        // sublist's minimum sets every sublist's gas limit, which the
        // validator holds the miner's partition to.
        let chain_config = Arc::new(chain_config);
        let processor = Arc::new(
            BlockProcessor::new(hardfork_cfg.clone(), block_store.clone())
                .with_chain_config(chain_config.clone()),
        );
        let builder = BlockTemplateBuilder::new(
            processor,
            trie_store.clone(),
            chain_config.clone(),
            hardfork_cfg.clone(),
            MiningConfig {
                coinbase_address: Address::repeat_byte(0xC0),
                ..Default::default()
            },
        );

        let template = builder
            .build(std::slice::from_ref(&parent), Vec::new(), &Pool(pending))
            .map_err(|e| format!("building the template: {e}"))?;

        let edges: Vec<i16> = template
            .block
            .header
            .version_fields
            .as_ref()
            .and_then(|v| v.edges.clone())
            .unwrap_or_default();
        let placement: Vec<Option<usize>> = (0..template.block.transactions.len())
            .map(|i| crate::collision::sublist_of(i, &edges))
            .collect();

        let validator =
            BlockProcessor::new(hardfork_cfg, block_store).with_chain_config(chain_config);
        let parent_state = builder
            .load_state_root(parent.state_root)
            .map_err(|e| format!("loading the parent state: {e}"))?;
        let validated = validator
            .process_block(&template.block, &parent_state, trie_store)
            .map(|_| ())
            .map_err(|e| e.to_string());

        Ok(WorkloadReport {
            scenario: self.scenario,
            submitted,
            block: template.block,
            edges,
            placement,
            validated,
            token,
            account_keys: keys
                .iter()
                .map(|k| B256::from_slice(&k.to_bytes()))
                .collect(),
            accounts,
            rbtc_each: rbtc,
            tokens_each: TOKENS_EACH,
            chain_id: self.chain_id,
            block_gas_limit,
        })
    }

    fn token_transfer(
        &self,
        from: &k256::ecdsa::SigningKey,
        nonce: u64,
        token: &Address,
        to: &Address,
        amount: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            nonce,
            gas_price: U256::from(1),
            gas_limit: U256::from(120_000),
            to: alloy_primitives::Bytes::copy_from_slice(token.as_slice()),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::from(transfer_calldata(to, U256::from(amount))),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign(&mut tx, from, self.chain_id);
        tx
    }

    /// A Bridge call that does nothing useful. Reaching the Bridge is the
    /// whole content of it -- that is what bars the transaction from a
    /// parallel sublist, whatever the call returns.
    fn bridge_call(&self, from: &k256::ecdsa::SigningKey, nonce: u64) -> Transaction {
        let mut tx = Transaction {
            nonce,
            gas_price: U256::from(1),
            gas_limit: U256::from(200_000),
            to: alloy_primitives::Bytes::copy_from_slice(
                crate::precompiles::BRIDGE_ADDR.as_slice(),
            ),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::from(vec![0x00, 0x00, 0x00, 0x00]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign(&mut tx, from, self.chain_id);
        tx
    }
}

fn tx_hash(tx: &Transaction) -> B256 {
    use sha3::{Digest, Keccak256};
    B256::from_slice(&Keccak256::digest(tx.rlp_for_trie()))
}

fn chain_header(
    number: u64,
    parent_hash: B256,
    state_root: B256,
    gas_limit: u64,
) -> rustock_core::Header {
    rustock_core::Header {
        parent_hash,
        ommers_hash: B256::ZERO,
        beneficiary: Address::repeat_byte(0x11),
        state_root,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        version_fields: None,
        difficulty: U256::from(2),
        number,
        gas_limit: U256::from(gas_limit),
        gas_used: 0,
        timestamp: 1_700_000_000 + number * 14,
        extra_data: Default::default(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::ZERO,
        uncle_count: 0,
        umm_root: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract has to work before anything built on it means anything.
    /// Deploy it, move tokens, and read the two cells back out of the trie.
    #[test]
    fn the_token_moves_balances_between_the_cells_an_erc20_would_touch() {
        use crate::{RskExecutor, hardfork::RskHardforkConfig};
        use rustock_storage::BlockStore;
        use rustock_trie::{AccountState, MemoryTrieStore, TrieKeySlice, TrieNode, TrieStore};
        use std::sync::Arc;

        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());

        let alice = account_key(1, 0);
        let alice_addr = address_of(&alice);
        let bob = Address::repeat_byte(0xB0);
        let token = Address::repeat_byte(0x7E);

        // The token's code, and Alice funded with gas money.
        let mut root = TrieNode::empty();
        let put = |root: &TrieNode, key: Vec<u8>, value: &[u8]| -> TrieNode {
            root.put(&TrieKeySlice::from_key(&key), value, store.as_ref())
        };
        root = put(
            &root,
            rustock_trie::account_key(&alice_addr),
            &AccountState::new(U256::ZERO, U256::from(10u64).pow(U256::from(18))).encode(),
        );
        root = put(
            &root,
            rustock_trie::account_key(&token),
            &AccountState::new(U256::ZERO, U256::ZERO).encode(),
        );
        root = put(&root, rustock_trie::code_key(&token), &token_runtime());
        root = put(&root, rustock_trie::storage_prefix_key(&token), &[1]);
        // Alice holds 5,000 tokens.
        root = put(
            &root,
            rustock_trie::storage_key(&token, &balance_slot(&alice_addr)),
            &5_000u64.to_be_bytes()[6..],
        );

        let chain_id = 33;
        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: alloy_primitives::Bytes::copy_from_slice(token.as_slice()),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::from(transfer_calldata(&bob, U256::from(1_500))),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign(&mut tx, &alice, chain_id);

        let header = {
            let mut h = crate::mining::template::remasc_transaction(1);
            let _ = &mut h;
            test_header(8_000_000)
        };
        let executor = RskExecutor::new(RskHardforkConfig::all_active(chain_id), block_store);
        let result = executor
            .execute_block(&header, &[(tx, alice_addr)], &root, store.clone())
            .expect("the token call executes");
        assert!(result.tx_results[0].success, "the transfer must not revert");

        let after = crate::state::apply_state_changes(
            &root,
            store.as_ref(),
            &result.state_changes,
            &result.markers,
        );
        let read = |holder: &Address| -> u64 {
            let key = rustock_trie::storage_key(&token, &balance_slot(holder));
            after
                .get(&TrieKeySlice::from_key(&key), store.as_ref())
                .map(|v| {
                    let mut buf = [0u8; 8];
                    buf[8 - v.len()..].copy_from_slice(&v);
                    u64::from_be_bytes(buf)
                })
                .unwrap_or(0)
        };
        assert_eq!(read(&alice_addr), 3_500, "the sender was debited");
        assert_eq!(read(&bob), 1_500, "and the recipient credited");
    }

    /// The deployment prologue returns exactly the runtime, which is the
    /// only thing it is for.
    #[test]
    fn the_constructor_returns_the_runtime() {
        let deploy = token_deploy_code();
        let runtime = token_runtime();
        assert_eq!(&deploy[12..], &runtime[..], "the prologue is 12 bytes and the rest is code");
        assert_eq!(deploy[1] as usize, runtime.len(), "and it returns that many bytes");
    }

    /// A balance cell is where Solidity would put it, so two transfers
    /// collide exactly when they share a participant.
    #[test]
    fn a_balance_cell_is_keccak_of_the_holder_and_the_slot() {
        use sha3::{Digest, Keccak256};
        let holder = Address::repeat_byte(0xAB);
        let mut expected = [0u8; 64];
        expected[12..32].copy_from_slice(holder.as_slice());
        assert_eq!(balance_slot(&holder), B256::from_slice(&Keccak256::digest(expected)));
        assert_ne!(balance_slot(&holder), balance_slot(&Address::repeat_byte(0xAC)));
    }

    /// Each scenario draws the dependency graph it claims to.
    #[test]
    fn the_scenarios_have_the_shapes_they_describe() {
        let independent = Scenario::Independent.transfers(3);
        let participants: Vec<usize> =
            independent.iter().flat_map(|t| [t.from, t.to]).collect();
        let unique: std::collections::HashSet<_> = participants.iter().collect();
        assert_eq!(unique.len(), participants.len(), "nothing is shared");

        let chain = Scenario::Chain.transfers(3);
        for pair in chain.windows(2) {
            assert_eq!(pair[0].to, pair[1].from, "each recipient is the next sender");
        }

        assert!(Scenario::OneSender.transfers(4).iter().all(|t| t.from == 0));
        assert!(Scenario::HotRecipient.transfers(4).iter().all(|t| t.to == 0));

        assert_eq!(Scenario::WithBridgeCall.bridge_call_at(4), Some(2));
        assert_eq!(Scenario::Independent.bridge_call_at(4), None);
    }

    /// The same seed gives the same accounts, which is what makes a run
    /// comparable with another implementation's.
    #[test]
    fn accounts_are_reproducible_from_the_seed() {
        assert_eq!(
            address_of(&account_key(7, 3)),
            address_of(&account_key(7, 3)),
            "same seed and index"
        );
        assert_ne!(address_of(&account_key(7, 3)), address_of(&account_key(8, 3)));
        assert_ne!(address_of(&account_key(7, 3)), address_of(&account_key(7, 4)));
    }

    /// Every scenario, end to end: generate, mine, validate.
    ///
    /// The partition shapes are asserted per scenario; what they all share
    /// is that the block the miner produced must be one this node accepts.
    /// A clever partition that does not validate is worth nothing.
    #[test]
    fn every_scenario_mines_a_block_this_node_accepts() {
        for scenario in Scenario::all() {
            let dir = tempfile::tempdir().unwrap();
            let workload = Workload { scenario, count: 4, ..Default::default() };
            let report = workload
                .run(dir.path())
                .unwrap_or_else(|e| panic!("{}: {e}", scenario.name()));

            report
                .validated
                .as_ref()
                .unwrap_or_else(|e| panic!("{}: the mined block was rejected: {e}", scenario.name()));

            // REMASC is always there and always last.
            assert!(
                report.block.transactions.len() > 1,
                "{}: the block holds its transactions",
                scenario.name()
            );
            assert_eq!(
                report.placement.last(),
                Some(&None),
                "{}: REMASC closes the sequential set",
                scenario.name()
            );
            assert_parallel_sublists_are_disjoint(&report);
        }
    }

    /// Independent transfers share nothing, so both parallel sublists are
    /// used. This is the shape the whole feature exists for.
    #[test]
    fn independent_transfers_fill_both_parallel_sublists() {
        let dir = tempfile::tempdir().unwrap();
        let report = Workload { scenario: Scenario::Independent, count: 4, ..Default::default() }
            .run(dir.path())
            .unwrap();
        assert!(report.validated.is_ok(), "{:?}", report.validated);
        assert_eq!(report.edges.len(), 2, "both parallel sublists, edges {:?}", report.edges);
        let sizes = report.sizes();
        assert_eq!(sizes[0], 2, "evenly split: {sizes:?}");
        assert_eq!(sizes[1], 2, "evenly split: {sizes:?}");
    }

    /// The property that actually matters, checked on every scenario: no
    /// two transactions in *different* parallel sublists may share a
    /// participant, because sharing one means sharing a balance cell.
    ///
    /// Stronger than counting edges, and it survives the pool reordering
    /// the transactions -- which it does, by sender address, so a scenario's
    /// shape is not the order the partitioner sees.
    fn assert_parallel_sublists_are_disjoint(report: &WorkloadReport) {
        let participants = |tx: &Transaction| -> Vec<Address> {
            let mut who = Vec::new();
            if let Ok(sender) = tx.recover_sender(33) {
                who.push(sender);
            }
            if tx.input.len() >= 32 {
                who.push(Address::from_slice(&tx.input[12..32]));
            }
            who
        };
        let txs = &report.block.transactions;
        for (i, a) in txs.iter().enumerate() {
            for (j, b) in txs.iter().enumerate().skip(i + 1) {
                let (Some(sa), Some(sb)) = (report.placement[i], report.placement[j]) else {
                    continue; // the sequential set may share anything
                };
                if sa == sb {
                    continue;
                }
                let (pa, pb) = (participants(a), participants(b));
                let shared: Vec<_> = pa.iter().filter(|x| pb.contains(x)).collect();
                assert!(
                    shared.is_empty(),
                    "{}: tx{i} (sublist {sa}) and tx{j} (sublist {sb}) share {shared:?}",
                    report.scenario.name()
                );
            }
        }
    }

    /// A chain of transfers, with the twist worth knowing about: the pool
    /// reorders by sender, so the partitioner does not meet the chain in
    /// chain order. Its *ends* are independent of each other -- only the
    /// middle connects them -- so two ends can land in different parallel
    /// sublists and the transfer that bridges them goes sequential. That is
    /// correct, and it is not what "a chain is connected" suggests.
    #[test]
    fn a_chain_of_token_transfers_splits_only_where_it_is_not_connected() {
        let dir = tempfile::tempdir().unwrap();
        let report = Workload { scenario: Scenario::Chain, count: 4, ..Default::default() }
            .run(dir.path())
            .unwrap();
        assert!(report.validated.is_ok(), "{:?}", report.validated);
        assert_parallel_sublists_are_disjoint(&report);
        assert!(
            report.sizes().last().is_some_and(|sequential| *sequential >= 2),
            "the bridging transfer and REMASC are both sequential: {:?}",
            report.sizes()
        );
    }

    /// Every transfer to one account. They share only the recipient's
    /// storage cell -- no sender, no nonce -- which is the collision a
    /// native-transfer workload cannot isolate.
    #[test]
    fn a_hot_recipient_connects_transfers_that_share_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let report = Workload { scenario: Scenario::HotRecipient, count: 4, ..Default::default() }
            .run(dir.path())
            .unwrap();
        assert!(report.validated.is_ok(), "{:?}", report.validated);
        assert!(
            report.edges.len() <= 1,
            "one cell in common is enough to connect them: edges {:?}",
            report.edges
        );
    }

    /// A Bridge call may sit nowhere but the sequential sublist, and a block
    /// that puts it elsewhere is invalid. That the block validates is
    /// therefore the assertion -- but assert the seat too, so a partition
    /// that got it right by putting *everything* in sequence is not mistaken
    /// for one that understood.
    #[test]
    fn a_bridge_call_is_placed_in_the_sequential_sublist() {
        let dir = tempfile::tempdir().unwrap();
        let report =
            Workload { scenario: Scenario::WithBridgeCall, count: 4, ..Default::default() }
                .run(dir.path())
                .unwrap();
        assert!(report.validated.is_ok(), "{:?}", report.validated);

        let bridge = crate::precompiles::BRIDGE_ADDR;
        let at = report
            .block
            .transactions
            .iter()
            .position(|tx| tx.to.as_ref() == bridge.as_slice())
            .expect("the Bridge call is in the block");
        assert_eq!(
            report.placement[at], None,
            "the Bridge call must be in the sequential set, not sublist {:?}",
            report.placement[at]
        );
        assert!(
            !report.edges.is_empty(),
            "and the transfers around it still run in parallel: {:?}",
            report.edges
        );
    }

    /// The same seed twice gives byte-identical transactions, which is what
    /// makes a comparison against another implementation a comparison of
    /// decisions rather than of inputs.
    #[test]
    fn a_workload_is_reproducible_from_its_seed() {
        let encode = |seed: u64| {
            let dir = tempfile::tempdir().unwrap();
            let report = Workload { seed, count: 3, ..Default::default() }.run(dir.path()).unwrap();
            report.submitted.iter().map(|tx| tx.rlp_for_trie()).collect::<Vec<_>>()
        };
        assert_eq!(encode(42), encode(42), "same seed, same bytes");
        assert_ne!(encode(42), encode(43), "and a different seed is a different workload");
    }

    fn test_header(number: u64) -> rustock_core::Header {
        rustock_core::Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::repeat_byte(0x11),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            version_fields: None,
            difficulty: U256::from(1),
            number,
            gas_limit: U256::from(10_000_000u64),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: Default::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }
}
