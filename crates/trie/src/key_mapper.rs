/// Unitrie key derivation matching rskj's TrieKeyMapper.
///
/// All keys share a unified keyspace in the single trie:
/// - Account: `0x00 || keccak256(addr)[0:10] || addr`  (31 bytes for 20-byte addr)
/// - Code:    `account_key || 0x80`
/// - Storage: `account_key || 0x00 || keccak256(slot)[0:10] || strip_leading_zeros(slot)`
use alloy_primitives::{Address, B256};
use sha3::{Digest, Keccak256};

const SECURE_KEY_SIZE: usize = 10;
const DOMAIN_PREFIX: u8 = 0x00;
const STORAGE_PREFIX: u8 = 0x00;
const CODE_PREFIX: u8 = 0x80;

fn secure_prefix(data: &[u8]) -> [u8; SECURE_KEY_SIZE] {
    let hash = Keccak256::digest(data);
    let mut prefix = [0u8; SECURE_KEY_SIZE];
    prefix.copy_from_slice(&hash[..SECURE_KEY_SIZE]);
    prefix
}

/// rskj `ByteUtil.stripLeadingZeroes` with the default `valueForZero =
/// ZERO_BYTE_ARRAY`: a leading run of zeros is removed, but an ALL-zero input
/// returns a single `0x00` byte (not empty). The storage slot 0x00..00 must
/// keep that trailing byte or its unitrie key (hence the state root) diverges.
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    match data.iter().position(|&b| b != 0) {
        Some(start) => &data[start..],
        None if data.is_empty() => data,
        None => &data[data.len() - 1..], // all zeros → single 0x00 byte
    }
}

/// Computes the trie key for an account address.
/// Result: `0x00 || keccak256(addr)[0:10] || addr` (31 bytes for standard 20-byte addresses).
pub fn account_key(addr: &Address) -> Vec<u8> {
    account_key_from_bytes(addr.as_slice())
}

/// Computes the trie key for an account from raw address bytes.
/// REMASC uses a 1-byte address `[0x00]`, producing a 12-byte key.
pub fn account_key_from_bytes(addr_bytes: &[u8]) -> Vec<u8> {
    let prefix = secure_prefix(addr_bytes);
    let mut key = Vec::with_capacity(1 + SECURE_KEY_SIZE + addr_bytes.len());
    key.push(DOMAIN_PREFIX);
    key.extend_from_slice(&prefix);
    key.extend_from_slice(addr_bytes);
    key
}

/// Computes the trie key of an account's storage-prefix node.
/// Result: `account_key || 0x00`. rskj `setupContract` stores `[0x01]` here
/// for every contract; the node is consensus-relevant (part of the unitrie
/// state root) even though no RPC exposes it.
pub fn storage_prefix_key(addr: &Address) -> Vec<u8> {
    let mut key = account_key(addr);
    key.push(STORAGE_PREFIX);
    key
}

/// Computes the trie key for an account's code.
/// Result: `account_key || 0x80`.
pub fn code_key(addr: &Address) -> Vec<u8> {
    code_key_from_bytes(addr.as_slice())
}

pub fn code_key_from_bytes(addr_bytes: &[u8]) -> Vec<u8> {
    let mut key = account_key_from_bytes(addr_bytes);
    key.push(CODE_PREFIX);
    key
}

/// Computes the trie key for a storage slot.
/// Result: `account_key || 0x00 || keccak256(slot)[0:10] || strip_leading_zeros(slot)`.
pub fn storage_key(addr: &Address, slot: &B256) -> Vec<u8> {
    storage_key_from_bytes(addr.as_slice(), slot.as_slice())
}

pub fn storage_key_from_bytes(addr_bytes: &[u8], slot_bytes: &[u8]) -> Vec<u8> {
    let acct_key = account_key_from_bytes(addr_bytes);
    let stripped = strip_leading_zeros(slot_bytes);
    let slot_prefix = secure_prefix(slot_bytes);

    let mut key = Vec::with_capacity(acct_key.len() + 1 + SECURE_KEY_SIZE + stripped.len());
    key.extend_from_slice(&acct_key);
    key.push(STORAGE_PREFIX);
    key.extend_from_slice(&slot_prefix);
    key.extend_from_slice(stripped);
    key
}

/// What a unitrie key names, recovered from the key itself.
///
/// The unitrie keyspace is unified and self-describing: every key carries its
/// address in the clear after a 10-byte keccak prefix, so a key picked out of
/// a trie diff can be named without consulting the state. That is what makes
/// an offline "what did this block write?" report readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieKeyKind {
    /// `0x00 || keccak(addr)[0:10] || addr`. The address is raw bytes because
    /// RSK has short addresses: REMASC's sender is the single byte `0x00`,
    /// and the null address, which REMASC pays where a block's coinbase is
    /// empty, has none.
    Account { address: Vec<u8> },
    /// `account_key || 0x80`.
    Code { address: Vec<u8> },
    /// `account_key || 0x00`, the `setupContract` marker.
    StoragePrefix { address: Vec<u8> },
    /// `account_key || 0x00 || keccak(slot)[0:10] || strip_leading_zeros(slot)`.
    ///
    /// `slot` is the recovered 32-byte word when the stripped tail re-pads to
    /// a word whose keccak prefix matches; otherwise `None` and only the
    /// stored `tail` is known.
    Storage { address: Vec<u8>, slot: Option<B256>, tail: Vec<u8> },
    /// Not a key this mapper produces.
    Unknown,
}

/// Longest address RSK uses. Addresses are tried longest-first so a 20-byte
/// address is never mis-read as a shorter one that happens to collide.
const MAX_ADDR_LEN: usize = 20;

/// Recovers the address by trusting the 10-byte keccak prefix rather than
/// guessing from the key length: `account_key || 0x80` for a 1-byte address is
/// 13 bytes, which no length rule distinguishes from some other key's prefix.
/// Verifying the digest makes the decode exact.
fn recover_address(key: &[u8]) -> Option<&[u8]> {
    if key.first() != Some(&DOMAIN_PREFIX) || key.len() < 1 + SECURE_KEY_SIZE {
        return None;
    }
    let body = &key[1 + SECURE_KEY_SIZE..];
    let claimed = &key[1..1 + SECURE_KEY_SIZE];
    let max = MAX_ADDR_LEN.min(body.len());
    // Down to no bytes, the null address's.
    (0..=max)
        .rev()
        .find(|&len| secure_prefix(&body[..len]) == claimed)
        .map(|len| &body[..len])
}

/// Recovers the full 32-byte slot from the stripped tail. Storage slots are
/// always `DataWord`s in rskj, so left-padding to 32 and checking the digest
/// recovers exactly the word that was hashed — including slot zero, which
/// `strip_leading_zeros` stores as the single byte `0x00`.
fn recover_slot(claimed: &[u8], tail: &[u8]) -> Option<B256> {
    if tail.len() > 32 {
        return None;
    }
    let mut word = [0u8; 32];
    word[32 - tail.len()..].copy_from_slice(tail);
    (secure_prefix(&word) == claimed).then_some(B256::from(word))
}

/// Inverse of the key builders above: names what a raw unitrie key refers to.
///
/// Unrecognised keys are reported as [`TrieKeyKind::Unknown`] rather than
/// guessed at, so a diagnostic built on this never invents an address.
pub fn classify_key(key: &[u8]) -> TrieKeyKind {
    let Some(address) = recover_address(key) else {
        return TrieKeyKind::Unknown;
    };
    let address = address.to_vec();
    let rest = &key[1 + SECURE_KEY_SIZE + address.len()..];
    match rest {
        [] => TrieKeyKind::Account { address },
        [CODE_PREFIX] => TrieKeyKind::Code { address },
        [STORAGE_PREFIX] => TrieKeyKind::StoragePrefix { address },
        [STORAGE_PREFIX, slot_part @ ..] if slot_part.len() > SECURE_KEY_SIZE => {
            let (claimed, tail) = slot_part.split_at(SECURE_KEY_SIZE);
            let slot = recover_slot(claimed, tail);
            TrieKeyKind::Storage { address, slot, tail: tail.to_vec() }
        }
        _ => TrieKeyKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_key_length() {
        let addr = Address::ZERO;
        let key = account_key(&addr);
        // 1 (domain) + 10 (secure) + 20 (addr) = 31
        assert_eq!(key.len(), 31);
        assert_eq!(key[0], 0x00); // domain prefix
    }

    #[test]
    fn test_code_key_length() {
        let addr = Address::ZERO;
        let key = code_key(&addr);
        assert_eq!(key.len(), 32); // account key + 0x80
        assert_eq!(*key.last().unwrap(), 0x80);
    }

    #[test]
    fn test_storage_key() {
        let addr = Address::ZERO;
        let slot = B256::ZERO;
        let key = storage_key(&addr, &slot);
        // account_key (31) + 1 (storage prefix) + 10 (secure) + 1 (all-zero slot
        // strips to a single 0x00 byte, rskj ByteUtil.stripLeadingZeroes) = 43
        assert_eq!(key.len(), 43);
        assert_eq!(*key.last().unwrap(), 0x00);
    }

    #[test]
    fn test_storage_key_with_nonzero_slot() {
        let addr = Address::ZERO;
        let mut slot_bytes = [0u8; 32];
        slot_bytes[31] = 1; // slot = 1
        let slot = B256::from(slot_bytes);
        let key = storage_key(&addr, &slot);
        // account_key (31) + 1 (storage prefix) + 10 (secure) + 1 (stripped) = 43
        assert_eq!(key.len(), 43);
    }

    /// Ground truth from rskj's unitrie (mainnet #3397 dump): the REMASC
    /// `siblings` storage cell (`addStorageBytes(REMASC, DataWord("siblings"),
    /// ...)`) lives at this exact 50-byte unitrie key.
    #[test]
    fn rskj_remasc_siblings_storage_key() {
        let remasc: Address = "0x0000000000000000000000000000000001000008".parse().unwrap();
        // DataWord.fromString("siblings"): UTF-8 right-aligned in 32 bytes.
        let mut slot = [0u8; 32];
        let name = b"siblings";
        slot[32 - name.len()..].copy_from_slice(name);
        let key = storage_key(&remasc, &B256::from(slot));
        assert_eq!(
            alloy_primitives::hex::encode(key),
            "00611cb96d0a346b10bab90000000000000000000000000000000001000008005a7de95ffc33d519294c7369626c696e6773"
        );
    }

    #[test]
    fn test_remasc_account_key() {
        // REMASC address is a single byte [0x00]
        let key = account_key_from_bytes(&[0x00]);
        // 1 (domain) + 10 (secure) + 1 (addr) = 12
        assert_eq!(key.len(), 12);
    }

    #[test]
    fn test_deterministic_keys() {
        let addr = Address::from([0xAB; 20]);
        let k1 = account_key(&addr);
        let k2 = account_key(&addr);
        assert_eq!(k1, k2);
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;
    use alloy_primitives::U256;

    const ADDR: Address = Address::new([
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);

    #[test]
    fn every_key_the_mapper_builds_classifies_back_to_itself() {
        assert_eq!(
            classify_key(&account_key(&ADDR)),
            TrieKeyKind::Account { address: ADDR.to_vec() }
        );
        assert_eq!(classify_key(&code_key(&ADDR)), TrieKeyKind::Code { address: ADDR.to_vec() });
        assert_eq!(
            classify_key(&storage_prefix_key(&ADDR)),
            TrieKeyKind::StoragePrefix { address: ADDR.to_vec() }
        );
    }

    #[test]
    fn a_storage_key_gives_back_the_whole_32_byte_slot() {
        // The key stores the slot with leading zeros stripped, but the secure
        // prefix is over the full word, so the word is recoverable.
        let slot = B256::from(U256::from(0x1234u64));
        match classify_key(&storage_key(&ADDR, &slot)) {
            TrieKeyKind::Storage { address, slot: recovered, tail } => {
                assert_eq!(address, ADDR.to_vec());
                assert_eq!(recovered, Some(slot));
                assert_eq!(tail, vec![0x12, 0x34]);
            }
            other => panic!("expected storage, got {other:?}"),
        }
    }

    #[test]
    fn slot_zero_survives_the_round_trip() {
        // strip_leading_zeros keeps one 0x00 byte for the all-zero word; if
        // the recovery re-padded from an empty tail it would still produce
        // the zero word, so this pins the tail too.
        let slot = B256::ZERO;
        match classify_key(&storage_key(&ADDR, &slot)) {
            TrieKeyKind::Storage { slot: recovered, tail, .. } => {
                assert_eq!(recovered, Some(B256::ZERO));
                assert_eq!(tail, vec![0x00]);
            }
            other => panic!("expected storage, got {other:?}"),
        }
    }

    #[test]
    fn a_full_width_slot_is_recovered() {
        let slot = B256::repeat_byte(0xA7);
        match classify_key(&storage_key(&ADDR, &slot)) {
            TrieKeyKind::Storage { slot: recovered, tail, .. } => {
                assert_eq!(recovered, Some(slot));
                assert_eq!(tail.len(), 32);
            }
            other => panic!("expected storage, got {other:?}"),
        }
    }

    #[test]
    fn remascs_one_byte_address_is_not_mistaken_for_a_longer_one() {
        // REMASC's sender is the single byte 0x00, so its account key is 12
        // bytes and its code key 13 — lengths no 20-byte-address rule covers.
        let acct = account_key_from_bytes(&[0x00]);
        assert_eq!(acct.len(), 12);
        assert_eq!(classify_key(&acct), TrieKeyKind::Account { address: vec![0x00] });

        let code = code_key_from_bytes(&[0x00]);
        assert_eq!(classify_key(&code), TrieKeyKind::Code { address: vec![0x00] });

        let storage = storage_key_from_bytes(&[0x00], B256::from(U256::from(7u64)).as_slice());
        match classify_key(&storage) {
            TrieKeyKind::Storage { address, slot, .. } => {
                assert_eq!(address, vec![0x00]);
                assert_eq!(slot, Some(B256::from(U256::from(7u64))));
            }
            other => panic!("expected storage, got {other:?}"),
        }
    }

    #[test]
    fn the_null_addresss_account_key_names_no_address_bytes() {
        // rskj's null address, which REMASC pays where a block's coinbase is
        // empty, has no bytes: its account key is the domain byte and the
        // secure prefix of nothing.
        let account = account_key_from_bytes(&[]);
        assert_eq!(account.len(), 11);
        assert_eq!(
            classify_key(&account),
            TrieKeyKind::Account { address: vec![] }
        );
        // The prefix is checked, as for any address.
        let mut forged = account.clone();
        forged[1] ^= 0xff;
        assert_eq!(classify_key(&forged), TrieKeyKind::Unknown);
    }

    #[test]
    fn keys_this_mapper_never_builds_are_reported_unknown_not_guessed() {
        // Wrong domain byte.
        assert_eq!(classify_key(&[0x01; 31]), TrieKeyKind::Unknown);
        // Too short to carry a secure prefix.
        assert_eq!(classify_key(&[]), TrieKeyKind::Unknown);
        assert_eq!(classify_key(&[0x00; 10]), TrieKeyKind::Unknown);
        // Right shape, but the secure prefix does not hash to the address, so
        // the address is not invented.
        let mut forged = account_key(&ADDR);
        forged[1] ^= 0xff;
        assert_eq!(classify_key(&forged), TrieKeyKind::Unknown);
        // A trailing byte that is neither the code nor the storage prefix.
        let mut odd = account_key(&ADDR);
        odd.push(0x42);
        assert_eq!(classify_key(&odd), TrieKeyKind::Unknown);
    }
}
