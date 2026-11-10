//! A minimal local wallet: keys held in memory, used only to sign.
//!
//! The node has deliberately had no wallet. `eth_accounts` returned an
//! empty list and `eth_sign`, `eth_signTransaction` and
//! `eth_sendTransaction` were refused, on the reasoning that a node asked
//! to sign should refuse rather than sign with something it happens to
//! have -- its identity key, a miner key -- producing a signature the
//! operator never authorised.
//!
//! That reasoning still holds, and this does not weaken it: **a wallet
//! exists only when the operator supplies one.** Without
//! `--wallet-file`, `RpcState::wallet` is `None`, `eth_accounts` is empty
//! and the three signing methods are refused, as rskj refuses them with its
//! wallet off. The keys are
//! the ones in the file and nothing else; nothing here can reach the node
//! identity key or a miner key.
//!
//! # What this is not
//!
//! Not a keystore. There is no encryption, no passphrase, no
//! `personal_newAccount`, no `personal_unlockAccount`, and nothing is
//! written to disk. Keys are read once at startup and held in memory for
//! the life of the process. This is what a load-testing harness needs --
//! funded senders it can drive through `eth_sendTransaction` -- and
//! deliberately not more, because the next step up is encrypted key
//! management, which is a real thing to get right and should not be
//! approximated.
//!
//! # Why a file and not a flag
//!
//! A private key passed as `--unlock-key 0x...` is visible in `ps` to
//! every user on the machine, and lands in shell history. A file can be
//! given 0600.

use alloy_primitives::{Address, B256};
use secp256k1::{Message, Secp256k1, SecretKey, SignOnly};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::path::Path;

/// EIP-191 personal-message prefix, which `eth_sign` applies before
/// hashing so that a signature over a message can never be replayed as a
/// signature over a transaction.
const PERSONAL_PREFIX: &str = "\x19Ethereum Signed Message:\n";

pub struct Wallet {
    /// Ordered, so `eth_accounts` answers the same way twice. A caller
    /// that picks `accounts[0]` as its sender gets the same sender on
    /// every call, which is what a test harness assumes.
    keys: BTreeMap<Address, SecretKey>,
    secp: Secp256k1<SignOnly>,
}

impl std::fmt::Debug for Wallet {
    /// Hand-written so that a `Debug` of `RpcState` -- in a log line, in a
    /// panic message -- cannot print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet").field("accounts", &self.keys.len()).finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("reading {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("{path} line {line}: not 32 bytes of hex")]
    BadKey { path: String, line: usize },
    #[error("{path} holds no keys")]
    Empty { path: String },
}

impl Wallet {
    /// Load keys from a file, one 32-byte hex private key per line.
    ///
    /// Blank lines and lines beginning with `#` are skipped, so a file can
    /// say which account is which. A `0x` prefix is accepted.
    ///
    /// Duplicate keys collapse into one account rather than erroring: the
    /// same key twice is the same account, and refusing would be a
    /// confusing way to report a copy-paste.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path_str = path.as_ref().display().to_string();
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|source| WalletError::Read { path: path_str.clone(), source })?;

        let mut keys = BTreeMap::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let hex_str = line.strip_prefix("0x").unwrap_or(line);
            let bytes = hex::decode(hex_str)
                .map_err(|_| WalletError::BadKey { path: path_str.clone(), line: i + 1 })?;
            let secret = SecretKey::from_byte_array(
                bytes
                    .try_into()
                    .map_err(|_| WalletError::BadKey { path: path_str.clone(), line: i + 1 })?,
            )
            .map_err(|_| WalletError::BadKey { path: path_str.clone(), line: i + 1 })?;
            keys.insert(address_of(&secret), secret);
        }

        if keys.is_empty() {
            return Err(WalletError::Empty { path: path_str });
        }
        Ok(Self { keys, secp: Secp256k1::signing_only() })
    }

    /// Build from keys already in hand. For tests.
    pub fn from_keys(secrets: impl IntoIterator<Item = SecretKey>) -> Self {
        let keys = secrets.into_iter().map(|s| (address_of(&s), s)).collect();
        Self { keys, secp: Secp256k1::signing_only() }
    }

    /// The accounts this wallet can sign for, in a stable order.
    pub fn accounts(&self) -> Vec<Address> {
        self.keys.keys().copied().collect()
    }

    pub fn holds(&self, address: &Address) -> bool {
        self.keys.contains_key(address)
    }

    /// `eth_sign`: a 65-byte signature over the EIP-191 digest of
    /// `message`.
    ///
    /// The prefix is the whole point of the method and is not optional.
    /// Signing the raw bytes a caller supplies would let a caller hand
    /// over the signing hash of a transaction and be given a valid
    /// transaction signature in return. Prefixing puts the two in
    /// different domains.
    ///
    /// `v` is 27 or 28, which is what callers expect from `eth_sign`;
    /// EIP-155's chain-id form belongs to transactions, not to messages.
    pub fn sign_message(&self, address: &Address, message: &[u8]) -> Option<[u8; 65]> {
        let secret = self.keys.get(address)?;
        let mut hasher = Keccak256::new();
        hasher.update(PERSONAL_PREFIX.as_bytes());
        hasher.update(message.len().to_string().as_bytes());
        hasher.update(message);
        let digest: [u8; 32] = hasher.finalize().into();

        let (recid, sig) = self
            .secp
            .sign_ecdsa_recoverable(Message::from_digest(digest), secret)
            .serialize_compact();

        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig);
        out[64] = 27 + i32::from(recid) as u8;
        Some(out)
    }

    /// Sign a transaction in place, EIP-155 style.
    ///
    /// Returns `false` when this wallet does not hold the key, so the
    /// caller can tell "unknown account" from "signed".
    pub fn sign_transaction(
        &self,
        address: &Address,
        tx: &mut rustock_core::Transaction,
        chain_id: u64,
    ) -> bool {
        let Some(secret) = self.keys.get(address) else { return false };
        let hash = tx.signing_hash_eip155(chain_id);
        let (recid, sig) = self
            .secp
            .sign_ecdsa_recoverable(Message::from_digest(hash.0), secret)
            .serialize_compact();

        tx.r = alloy_primitives::U256::from_be_slice(&sig[..32]);
        tx.s = alloy_primitives::U256::from_be_slice(&sig[32..]);
        tx.v = chain_id * 2 + 35 + i32::from(recid) as u64;
        // The cached encoding was of the unsigned transaction; leaving it
        // would hand the pool a body that does not match the signature.
        tx.cached_rlp = None;
        true
    }
}

/// The address a secret key controls: keccak of the uncompressed public
/// key without its leading form byte, last twenty bytes.
fn address_of(secret: &SecretKey) -> Address {
    let secp = Secp256k1::new();
    let public = secp256k1::PublicKey::from_secret_key(&secp, secret);
    let digest = Keccak256::digest(&public.serialize_uncompressed()[1..]);
    Address::from_slice(&digest[12..])
}

/// Keccak of a message, for callers that need the digest `eth_sign` signs.
pub fn personal_digest(message: &[u8]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(PERSONAL_PREFIX.as_bytes());
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);
    B256::from_slice(&hasher.finalize())
}
