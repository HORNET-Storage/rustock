/// revm Database adapter over the RSK Unitrie.
///
/// revm reads account state, code, and storage through the `Database` trait.
/// This adapter translates those queries into Unitrie key lookups using the
/// key_mapper module from rustock-trie.
use alloy_primitives::{Address, B256, U256};
use revm::database_interface::DBErrorMarker;
use revm::database_interface::DatabaseRef;
use revm::bytecode::Bytecode;
use revm::state::AccountInfo;
use rustock_trie::{
    TrieNode, TrieStore, TrieKeySlice,
    account_key, code_key, storage_key, storage_prefix_key,
    AccountState,
};
use rustock_storage::BlockStore;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use sha3::{Digest, Keccak256};

#[derive(Debug, thiserror::Error)]
pub enum RskDbError {
    #[error("trie lookup failed: {0}")]
    TrieError(String),
    #[error("RLP decode error: {0}")]
    RlpDecode(String),
    #[error("block store error: {0}")]
    BlockStore(String),
    /// The trie referred to a node the store does not hold.
    ///
    /// Distinct from "the account does not exist", which is an ordinary answer.
    /// Without this the two were the same `None`, and a hole in the trie read
    /// back as an empty account -- mainnet 2026-09-23, where it surfaced as
    /// `NonceTooHigh { state: 0 }` several layers away from the cause.
    #[error(
        "trie is incomplete: node {node} is referenced but not in the store \
         (reading key {key}). {attribution}"
    )]
    MissingTrieNode { node: B256, key: String, attribution: String },
}

impl DBErrorMarker for RskDbError {}

/// Read-only view into the RSK world state at a particular trie root.
pub struct RskDatabase {
    root: TrieNode,
    store: Arc<dyn TrieStore>,
    block_store: Arc<BlockStore>,
    /// Cache of code by hash, populated during `basic_ref` calls.
    /// Uses `RefCell` because `DatabaseRef` methods take `&self`.
    code_cache: RefCell<HashMap<B256, Bytecode>>,
}

impl RskDatabase {
    pub fn new(
        root: TrieNode,
        store: Arc<dyn TrieStore>,
        block_store: Arc<BlockStore>,
    ) -> Self {
        Self { root, store, block_store, code_cache: RefCell::new(HashMap::new()) }
    }

    /// rskj `MutableRepository.isContract`: whether `address` holds the
    /// storage-prefix marker `setupContract` writes, in the state this
    /// database reads.
    pub fn has_contract_marker(&self, address: &Address) -> Result<bool, RskDbError> {
        Ok(self.trie_get(&storage_prefix_key(address))?.is_some())
    }

    /// Reads one key, distinguishing "not in the trie" from "the trie is
    /// incomplete here".
    ///
    /// `Ok(None)` is an answer: nothing is stored under that key. An error
    /// means the walk hit a reference the store could not resolve, so the
    /// value is unknown -- and must not be reported as absent, because an
    /// absent account reads as balance 0 and nonce 0 and executes happily
    /// against state the node does not have.
    fn trie_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RskDbError> {
        let expanded = TrieKeySlice::from_key(key);
        self.root.try_get(&expanded, self.store.as_ref()).map_err(|node| {
            RskDbError::MissingTrieNode {
                node,
                key: alloy_primitives::hex::encode_prefixed(key),
                attribution: missing_node_attribution(self.store.as_ref()),
            }
        })
    }
}

/// Why a node might be absent, in the store's own terms.
///
/// A missing node has two causes needing opposite responses: the collector took
/// it, which is expected and unrecoverable here, or the store is damaged. The
/// store knows how deep its collector has reached (`collected_below`, recorded
/// by each completed sweep), so it can say which rather than listing both.
fn missing_node_attribution(store: &dyn TrieStore) -> String {
    match store.collected_below() {
        Some(w) => format!(
            "The trie collector has swept epochs holding blocks up to #{w}. If this \
             state belongs to a block at or below that height it was collected and is \
             not recoverable from this store; above it, the store is damaged."
        ),
        None => "This store has never completed a collection, so nothing was swept: \
                 the store is damaged."
            .to_string(),
    }
}

impl DatabaseRef for RskDatabase {
    type Error = RskDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let key = account_key(&address);
        let Some(data) = self.trie_get(&key)? else {
            return Ok(None);
        };

        let acct = AccountState::decode(&data)
            .map_err(|e| RskDbError::RlpDecode(e.to_string()))?;

        let code_key = code_key(&address);
        let code = self.trie_get(&code_key)?;

        let code_hash = match &code {
            Some(c) => B256::from_slice(&Keccak256::digest(c)),
            None => revm::primitives::KECCAK_EMPTY,
        };

        let bytecode = match code {
            Some(c) => Bytecode::new_raw(c.into()),
            None => Bytecode::default(),
        };

        if code_hash != revm::primitives::KECCAK_EMPTY {
            self.code_cache
                .borrow_mut()
                .insert(code_hash, bytecode.clone());
        }

        Ok(Some(AccountInfo {
            balance: acct.balance,
            nonce: acct.nonce.to::<u64>(),
            code_hash,
            code: Some(bytecode),
            account_id: None,
        }))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.code_cache.borrow().get(&code_hash) {
            return Ok(code.clone());
        }
        Ok(Bytecode::default())
    }

    fn storage_ref(
        &self,
        address: Address,
        index: U256,
    ) -> Result<U256, Self::Error> {
        let slot = B256::from(index);
        let key = storage_key(&address, &slot);

        // Divergence-hunt diagnostic (env-gated): compare every storage read
        // against public-node groundtruth to find receipts-invisible state
        // divergences (mainnet #892,228).
        static TRACE_SLOAD: std::sync::LazyLock<bool> =
            std::sync::LazyLock::new(|| std::env::var_os("RUSTOCK_TRACE_SLOAD").is_some());
        if *TRACE_SLOAD {
            tracing::debug!(
                "SLOAD {} {:x} = 0x{}",
                address,
                index,
                self.trie_get(&key)
                    .ok()
                    .flatten()
                    .as_deref()
                    .map(alloy_primitives::hex::encode)
                    .unwrap_or_default()
            );
        }

        match self.trie_get(&key)? {
            Some(data) => {
                if data.len() > 32 {
                    return Err(RskDbError::TrieError(
                        format!("storage value too long: {} bytes", data.len()),
                    ));
                }
                let mut padded = [0u8; 32];
                padded[32 - data.len()..].copy_from_slice(&data);
                Ok(U256::from_be_bytes(padded))
            }
            None => Ok(U256::ZERO),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.block_store
            .canonical_hash(number)
            .map_err(|e| RskDbError::BlockStore(e.to_string()))?
            .ok_or_else(|| RskDbError::BlockStore(format!("block {} not found", number)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_trie::{MemoryTrieStore, TrieNode, TrieKeySlice};

    fn make_store_and_root() -> (Arc<MemoryTrieStore>, TrieNode) {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        (store, root)
    }

    fn put_account(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        nonce: u64,
        balance: U256,
    ) -> TrieNode {
        let key_bytes = account_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        let acct = AccountState::new(U256::from(nonce), balance);
        root.put(&key, &acct.encode(), store)
    }

    fn put_code(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        code: &[u8],
    ) -> TrieNode {
        let key_bytes = code_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        root.put(&key, code, store)
    }

    fn put_storage(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        slot: U256,
        value: U256,
    ) -> TrieNode {
        let slot_b256 = B256::from(slot);
        let key_bytes = storage_key(addr, &slot_b256);
        let key = TrieKeySlice::from_key(&key_bytes);
        let val_bytes: Vec<u8> = {
            let be = value.to_be_bytes::<32>();
            let start = be.iter().position(|&b| b != 0).unwrap_or(32);
            be[start..].to_vec()
        };
        if val_bytes.is_empty() {
            root.delete(&key, store)
        } else {
            root.put(&key, &val_bytes, store)
        }
    }

    #[test]
    fn test_basic_account_not_found() {
        let (store, root) = make_store_and_root();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let result = db.basic_ref(Address::ZERO).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_basic_account_found() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xAA);
        let root = put_account(&root, store.as_ref(), &addr, 42, U256::from(1_000_000));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(info.nonce, 42);
        assert_eq!(info.balance, U256::from(1_000_000));
        assert_eq!(info.code_hash, revm::primitives::KECCAK_EMPTY);
    }

    #[test]
    fn test_account_with_code() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xBB);
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xFD]; // PUSH0 PUSH0 REVERT

        let root = put_account(&root, store.as_ref(), &addr, 0, U256::ZERO);
        let root = put_code(&root, store.as_ref(), &addr, &code);

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_ne!(info.code_hash, revm::primitives::KECCAK_EMPTY);
        assert!(info.code.is_some());
        assert_eq!(info.code.unwrap().original_bytes().as_ref(), &code);
    }

    #[test]
    fn test_storage_read() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xCC);
        let root = put_account(&root, store.as_ref(), &addr, 0, U256::ZERO);
        let root = put_storage(&root, store.as_ref(), &addr, U256::from(0), U256::from(42));
        let root = put_storage(&root, store.as_ref(), &addr, U256::from(1), U256::from(100));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        assert_eq!(db.storage_ref(addr, U256::from(0)).unwrap(), U256::from(42));
        assert_eq!(db.storage_ref(addr, U256::from(1)).unwrap(), U256::from(100));
        assert_eq!(db.storage_ref(addr, U256::from(2)).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_storage_not_found_returns_zero() {
        let (store, root) = make_store_and_root();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let val = db.storage_ref(Address::repeat_byte(0xFF), U256::from(99)).unwrap();
        assert_eq!(val, U256::ZERO);
    }

    // -----------------------------------------------------------------------
    // Code-by-hash cache tests — inspired by rskj RepositoryTest.testGetCodeHash
    // -----------------------------------------------------------------------

    /// Ported from rskj RepositoryTest.testGetCodeHash
    /// Verifies that code_by_hash_ref returns cached bytecode after basic_ref
    /// populates the cache.
    #[test]
    fn rskj_code_by_hash_cache_populated_by_basic_ref() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xDD);
        let code = b"a-great-code".to_vec(); // same string as rskj test

        let root = put_account(&root, store.as_ref(), &addr, 0, U256::ZERO);
        let root = put_code(&root, store.as_ref(), &addr, &code);

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info = db.basic_ref(addr).unwrap().unwrap();
        let code_hash = info.code_hash;
        assert_ne!(code_hash, revm::primitives::KECCAK_EMPTY);

        let expected_hash = B256::from_slice(&Keccak256::digest(&code));
        assert_eq!(code_hash, expected_hash);

        let cached = db.code_by_hash_ref(code_hash).unwrap();
        assert_eq!(cached.original_bytes().as_ref(), &code,
            "code_by_hash_ref should return cached code after basic_ref");
    }

    /// Ported from rskj: code_by_hash for an account without code returns empty.
    /// Matches rskj's behavior where getCodeHashNonStandard on a non-contract
    /// account returns KECCAK_EMPTY.
    #[test]
    fn rskj_code_by_hash_no_code_returns_default() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xEE);
        let root = put_account(&root, store.as_ref(), &addr, 0, U256::from(1000));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info = db.basic_ref(addr).unwrap().unwrap();
        assert_eq!(info.code_hash, revm::primitives::KECCAK_EMPTY);

        let cached = db.code_by_hash_ref(revm::primitives::KECCAK_EMPTY).unwrap();
        assert!(cached.original_bytes().is_empty(),
            "KECCAK_EMPTY should return default (empty) bytecode");
    }

    /// Ported from rskj: code_by_hash for non-existent hash returns default.
    /// Matches rskj behavior where repository has no entry for a random hash.
    #[test]
    fn rskj_code_by_hash_unknown_hash_returns_default() {
        let (store, root) = make_store_and_root();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let random_hash = B256::repeat_byte(0x42);
        let result = db.code_by_hash_ref(random_hash).unwrap();
        assert!(result.original_bytes().is_empty());
    }

    #[test]
    fn test_multiple_accounts() {
        let (store, root) = make_store_and_root();
        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);
        let addr3 = Address::repeat_byte(0x33);

        let root = put_account(&root, store.as_ref(), &addr1, 1, U256::from(100));
        let root = put_account(&root, store.as_ref(), &addr2, 2, U256::from(200));
        let root = put_account(&root, store.as_ref(), &addr3, 3, U256::from(300));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info1 = db.basic_ref(addr1).unwrap().unwrap();
        let info2 = db.basic_ref(addr2).unwrap().unwrap();
        let info3 = db.basic_ref(addr3).unwrap().unwrap();

        assert_eq!(info1.nonce, 1);
        assert_eq!(info2.nonce, 2);
        assert_eq!(info3.nonce, 3);
        assert_eq!(info1.balance, U256::from(100));
        assert_eq!(info2.balance, U256::from(200));
        assert_eq!(info3.balance, U256::from(300));
    }

    // ---- a hole in the trie is not an empty account (issue #275) ----------

    /// The failure this exists to prevent: with a node missing from under it,
    /// the adapter used to answer `Ok(None)` -- "no such account" -- which the
    /// EVM reads as balance 0, nonce 0, no code, and executes against happily.
    /// Mainnet 2026-09-23 surfaced that as `NonceTooHigh { state: 0 }`, several
    /// layers from the cause.
    #[test]
    fn a_missing_trie_node_is_an_error_not_an_empty_account() {
        let store = Arc::new(MemoryTrieStore::new());
        let mut root = TrieNode::empty();
        // Enough accounts that the trie has interior nodes to remove.
        let addrs: Vec<Address> = (1u8..=16).map(|i| Address::from([i; 20])).collect();
        for (i, a) in addrs.iter().enumerate() {
            root = put_account(&root, store.as_ref(), a, i as u64 + 1, U256::from(1000 + i));
        }
        root.save(store.as_ref(), true);

        // Read back from the store, as a node executing a block does.
        let root_hash = root.compute_hash(store.as_ref());
        let data = store.get(root_hash.as_slice()).expect("root was saved");
        let root = TrieNode::from_message(&data, store.as_ref());

        // Remove one interior node on the path to a known account.
        let target = &addrs[7];
        let key = TrieKeySlice::from_key(&account_key(target));
        let path = root.nodes_on_path(&key, store.as_ref()).expect("account is in the trie");
        let victim = path
            .iter()
            .rev()
            .skip(1)
            .find(|n| !n.is_terminal())
            .expect("no interior node on the path")
            .compute_hash(store.as_ref());
        assert!(store.remove(victim.as_slice()), "an interior node must be stored by hash");

        let db = RskDatabase::new(
            root,
            store.clone() as Arc<dyn TrieStore>,
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap()),
        );

        match db.basic_ref(*target) {
            Err(RskDbError::MissingTrieNode { node, .. }) => {
                assert_eq!(node, victim, "the error must name the node that is gone");
            }
            Ok(None) => panic!(
                "a hole in the trie reported as an absent account -- this is the bug: \
                 the EVM would execute against balance 0 / nonce 0"
            ),
            other => panic!("expected MissingTrieNode, got {other:?}"),
        }
    }

    /// Strictness must not turn ordinary absence into a failure, or every
    /// account that genuinely does not exist becomes a failed block.
    #[test]
    fn an_account_that_does_not_exist_is_still_reported_absent() {
        let (store, root) = make_store_and_root();
        let mut root = put_account(&root, store.as_ref(), &Address::from([1u8; 20]), 1, U256::from(5));
        root.save(store.as_ref(), true);

        let db = RskDatabase::new(
            root,
            store.clone() as Arc<dyn TrieStore>,
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap()),
        );

        assert!(
            matches!(db.basic_ref(Address::from([9u8; 20])), Ok(None)),
            "an account absent from a complete trie is an answer, not an error"
        );
    }

    /// A store that never collects must not let a missing node be excused as
    /// collection. Saying "it was probably collected" about a store with no
    /// collector turns damage into something that looks expected.
    #[test]
    fn a_store_that_never_collects_attributes_a_missing_node_to_damage() {
        let store = MemoryTrieStore::new();
        assert_eq!(store.collected_below(), None, "a plain store does not collect");
        let text = missing_node_attribution(&store);
        assert!(text.contains("damaged"), "got: {text}");
        assert!(
            !text.contains("collected and is not recoverable"),
            "a store with no collector must not blame the collector: {text}"
        );
    }

    /// With a collector, the message has to carry the floor, because that is
    /// the number the reader compares the block height against.
    #[test]
    fn a_collecting_store_reports_the_floor_it_reached() {
        struct Collecting(MemoryTrieStore);
        impl TrieStore for Collecting {
            fn get(&self, k: &[u8]) -> Option<Vec<u8>> { self.0.get(k) }
            fn put(&self, k: &[u8], v: &[u8]) { self.0.put(k, v) }
            fn collected_below(&self) -> Option<u64> { Some(9_240_000) }
        }
        let text = missing_node_attribution(&Collecting(MemoryTrieStore::new()));
        assert!(text.contains("9240000"), "the floor must be in the message: {text}");
        assert!(
            text.contains("at or below") && text.contains("damaged"),
            "both verdicts must be stated so the reader can tell which applies: {text}"
        );
    }
}
