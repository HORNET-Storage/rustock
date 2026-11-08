use alloy_primitives::{Address, B256, Bytes, U256, address};

use crate::types::header::Header;

/// Pre-funded account in the genesis state.
#[derive(Debug, Clone)]
pub struct GenesisAlloc {
    pub address: Address,
    pub balance: U256,
    pub nonce: U256,
}

/// Pre-initialized storage entry in the genesis state.
#[derive(Debug, Clone)]
pub struct GenesisStorage {
    pub address: Address,
    pub key: B256,
    pub value: Vec<u8>,
}

/// Hardfork activation heights for a given network.
/// A value of `u64::MAX` means "not yet activated".
#[derive(Clone, Debug)]
pub struct ActivationHeights {
    /// Orchid hardfork – enables RSKIP92/98 (merged mining PoW, no 10-min reset).
    pub orchid: u64,
    /// Wasabi100 hardfork – enables RSKIP110 (fork detection data in merged mining hash).
    pub wasabi100: u64,
    /// Papyrus200 hardfork – enables RSKIP156 (difficulty divisor 50 -> 400).
    pub papyrus200: u64,
    /// Iris300 hardfork – enables RSKIP180 (960-byte merged-mining merkle
    /// proof cap).
    pub iris300: u64,
    /// Fingerroot500 hardfork – enables RSKIP252 (transaction gas price cap).
    pub fingerroot500: u64,
    /// Hop400 hardfork – enables RSKIP297, which widens the RSKIP179
    /// Bitcoin-to-RSK timestamp window on testnet (5 minutes to 2 hours).
    /// Read only on testnet; mainnet keeps 5 minutes at every height.
    pub hop400: u64,
    /// Height at which RSKIP97 -- "no 10-minute difficulty drop" -- activates,
    /// or `None` where it never does.
    ///
    /// Modelled separately from `orchid` because it is *not* the same switch.
    /// `reference.conf` defaults it to `orchid`, which is what mainnet uses,
    /// but `testnet.conf` and `regtest.conf` both override it to `-1`. On
    /// those chains the drop is permanent: a block more than ten minutes
    /// after its parent falls to the minimum difficulty, forever.
    ///
    /// Tying it to `orchid` made rustock reject testnet block #1, whose
    /// difficulty is the 131,072 floor because its parent is genesis at
    /// timestamp 0.
    pub rskip97: Option<u64>,
    /// Height at which RSKIP-144 (parallel transaction sublists) activates,
    /// or `None` where it never does. rskj gates it on `reed810`.
    ///
    /// The header decoder needs it: after an RSKIP-351 version byte, one
    /// trailing item is the sublist edges where RSKIP-144 is active and the
    /// V2 base event where it is not (rskj `BlockFactory` decides by the same
    /// activation). rskj's own regtest is the second case: `rskip144 = -1`
    /// with `rskip535 = 1`.
    pub rskip144: Option<u64>,
}

/// Process-wide activation heights, consulted by block-hash computation
/// (RSKIP92 changes which header fields are hashed). Mirrors rskj's injected
/// ActivationConfig singleton. Defaults to mainnet if never installed.
static ACTIVATIONS: std::sync::OnceLock<ActivationHeights> = std::sync::OnceLock::new();

impl ActivationHeights {
    /// Install the process-wide activation heights. Call once at startup
    /// before any header decoding; later calls are ignored.
    pub fn install(self) {
        let _ = ACTIVATIONS.set(self);
    }

    /// The installed activation heights (mainnet if none installed).
    pub fn current() -> &'static ActivationHeights {
        ACTIVATIONS.get_or_init(Self::mainnet)
    }

    /// Set the height this struct carries for an rskj upgrade name, for the
    /// names it carries: `orchid`, `wasabi100`, `papyrus200`, `iris300`,
    /// `fingerroot500`, and `reed810`, which is RSKIP-144's height. `None`
    /// is rskj's `-1`. Any other name is the execution ladder's to judge and
    /// is left alone here.
    pub fn set_rskj_hardfork(&mut self, name: &str, height: Option<u64>) {
        let never = u64::MAX;
        match name {
            "orchid" => self.orchid = height.unwrap_or(never),
            "wasabi100" => self.wasabi100 = height.unwrap_or(never),
            "papyrus200" => self.papyrus200 = height.unwrap_or(never),
            "iris300" => self.iris300 = height.unwrap_or(never),
            "fingerroot500" => self.fingerroot500 = height.unwrap_or(never),
            "reed810" => self.rskip144 = height,
            _ => {}
        }
    }

    pub fn mainnet() -> Self {
        Self {
            orchid: 729_000,
            wasabi100: 1_591_000,
            papyrus200: 2_392_700,
            iris300: 3_614_800,
            fingerroot500: 5_468_000,
            hop400: 4_598_500,
            // reference.conf: `rskip97 = orchid`, not overridden by main.conf.
            rskip97: Some(729_000),
            // main.conf: reed810 = -1.
            rskip144: None,
        }
    }

    pub fn testnet() -> Self {
        // rskj config/testnet.conf. Testnet starts on wasabi100, but papyrus200
        // is a real height there (863,000), not genesis.
        Self {
            orchid: 0,
            wasabi100: 0,
            papyrus200: 863_000,
            iris300: 2_060_500,
            fingerroot500: 4_015_800,
            hop400: 3_103_000,
            // testnet.conf: `rskip97 = -1  # disable orchid difficulty drop`.
            rskip97: None,
            // testnet.conf: reed810.
            rskip144: Some(7_139_600),
        }
    }

    pub fn regtest() -> Self {
        Self {
            orchid: 0,
            wasabi100: 0,
            papyrus200: u64::MAX,
            iris300: 0,
            fingerroot500: 0,
            hop400: 0,
            // regtest.conf: `rskip97 = -1`, same as testnet.
            rskip97: None,
            // regtest.conf: `rskip144 = -1`; rustock's regtest ladder does
            // not schedule reed810 either.
            rskip144: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub chain_id: u8,
    pub network_id: u64,
    pub duration_limit: u64,
    pub difficulty_divisor: U256,
    pub min_difficulty: U256,
    /// rskj `Constants.newBlockMaxSecondsInTheFuture`: how far past the
    /// node's clock a header may be timestamped. 60 on mainnet, 540 on
    /// testnet, 0 on regtest, where zero turns the timestamp rule off
    /// altogether (parent comparison included), as it does in rskj.
    pub max_future_block_time: u64,
    pub gas_limit_bound_divisor: u64,
    /// rskj `Constants.getMinGasLimit()`: 3,000,000 on every network
    /// (`GasLimitRule`). Every rskj genesis declares more.
    pub min_gas_limit: u64,
    pub max_gas_limit: u64,
    /// The gas the sequential sublist is guaranteed under RSKIP-144
    /// (rskj `Constants.getMinSequentialSetGasLimit`). Absent from the
    /// RSKIP, which says every sublist gets `block gas limit / (N + 1)`;
    /// the real formula has three branches around this constant, and below
    /// it the parallel sublists get no gas at all.
    pub min_sequential_set_gas_limit: u64,
    pub activation_heights: ActivationHeights,
    /// A genesis read from an rskj genesis file, replacing the built-in one
    /// (regtest only). Its state root must be filled in before the genesis
    /// header is used; see [`crate::rskj_genesis`].
    pub genesis_spec: Option<crate::rskj_genesis::GenesisSpec>,
    /// Accept headers without checking their merged-mining proof of work,
    /// as rskj does with `miner.server.skipPowValidation = true`. For
    /// replaying a regtest chain mined without real proof of work; off by
    /// default, and refused on mainnet and testnet.
    pub skip_pow_validation: bool,
    /// rskj `blockchain.config.hardforkActivationHeights` overrides, by
    /// rskj's names, `None` for `-1`. The heights this struct carries are
    /// already set from them; the execution ladder applies them itself.
    /// Empty on every built-in chain.
    pub hardfork_overrides: Vec<(String, Option<u64>)>,
    /// rskj `consensusRules` overrides for the execution ladder (`rskip351`,
    /// `rskip535`, `rskip536`, `rskipUMM`). `rskip97` is not here: it is
    /// applied to `activation_heights` directly.
    pub consensus_rule_overrides: Vec<(String, Option<u64>)>,
}

impl ChainConfig {
    pub fn mainnet() -> Self {
        Self {
            chain_id: 30,
            network_id: 775,
            duration_limit: 14,
            difficulty_divisor: U256::from(50),
            min_difficulty: U256::from(7_000_000_000_000_000u64), // 7e15, FALLBACK_MINING_DIFFICULTY / 2
            max_future_block_time: 60,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 3_000_000,
            max_gas_limit: 1_000_000_000,
            min_sequential_set_gas_limit: 10_000_000,
            activation_heights: ActivationHeights::mainnet(),
            genesis_spec: None,
            skip_pow_validation: false,
            hardfork_overrides: Vec::new(),
            consensus_rule_overrides: Vec::new(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            chain_id: 31,
            network_id: 8100,
            duration_limit: 14,
            difficulty_divisor: U256::from(50),
            min_difficulty: U256::from(131072),
            max_future_block_time: 540,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 3_000_000,
            max_gas_limit: 1_000_000_000,
            min_sequential_set_gas_limit: 10_000_000,
            activation_heights: ActivationHeights::testnet(),
            genesis_spec: None,
            skip_pow_validation: false,
            hardfork_overrides: Vec::new(),
            consensus_rule_overrides: Vec::new(),
        }
    }

    pub fn regtest() -> Self {
        Self {
            chain_id: 33,
            network_id: 7771,
            duration_limit: 10,
            difficulty_divisor: U256::from(2048),
            min_difficulty: U256::from(1),
            max_future_block_time: 0,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 3_000_000,
            max_gas_limit: 10_000_000,
            min_sequential_set_gas_limit: 6_800_000,
            activation_heights: ActivationHeights::regtest(),
            genesis_spec: None,
            skip_pow_validation: false,
            hardfork_overrides: Vec::new(),
            consensus_rule_overrides: Vec::new(),
        }
    }

    /// Returns the well-known genesis hash for this network, if one exists.
    /// Mainnet and testnet have hardcoded hashes because Java's RLP encoding
    /// of the genesis difficulty includes a leading zero byte that differs
    /// from standard encoding, producing a different hash.
    pub fn known_genesis_hash(&self) -> Option<B256> {
        if let Some(spec) = &self.genesis_spec {
            return Some(spec.hash());
        }
        match self.chain_id {
            30 => Some("0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0".parse().unwrap()),
            31 => Some("0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42".parse().unwrap()),
            _ => None,
        }
    }

    /// Constructs the genesis header for this network.
    pub fn genesis_header(&self) -> Header {
        let empty_list_hash: B256 = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".parse().unwrap();
        let empty_trie_hash: B256 = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".parse().unwrap();

        if let Some(spec) = &self.genesis_spec {
            return spec.header();
        }

        match self.chain_id {
            30 => Header {
                parent_hash: B256::ZERO,
                ommers_hash: empty_list_hash,
                beneficiary: "0x3333333333333333333333333333333333333333".parse().unwrap(),
                state_root: "0x9fa70f12726ac738640a86754741bb3f5680520ccc7e6ae9d95ace566a67fe01".parse().unwrap(),
                transactions_root: empty_trie_hash,
                receipts_root: empty_trie_hash,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(0x00100000),
                number: 0,
                gas_limit: U256::from(0x67c280),
                gas_used: 0,
                timestamp: 0x5a4af5b0,
                extra_data: Bytes::from_static(&hex_literal::hex!("486170707920426974636f696e20446179212030332f4a616e2f32303138202d2052534b20746563686e6f6c6f6779206174207468652073657276696365206f6620736f6369657479")),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::from(0x0AE85BC0),
                uncle_count: 0,
                umm_root: None,
                version_fields: None,
                bitcoin_merged_mining_header: Some(Bytes::from_static(&[0x00])),
                bitcoin_merged_mining_merkle_proof: Some(Bytes::from_static(&[0x00])),
                bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from_static(&[0x00])),
                cached_hash: None,
                cached_hash_for_merged_mining: None,
            },
            31 => Header {
                parent_hash: B256::ZERO,
                ommers_hash: B256::ZERO,
                beneficiary: Address::ZERO,
                state_root: "0x45bce5168430c42b3d568331753f900a32457b4f3748697cbd8375ff4da72641".parse().unwrap(),
                transactions_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(0x00100000),
                number: 0,
                gas_limit: U256::from(0x4c4b40),
                gas_used: 0,
                timestamp: 0,
                extra_data: Bytes::from_static(&hex_literal::hex!("434d272841")),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::ZERO,
                uncle_count: 0,
                umm_root: None,
                version_fields: None,
                bitcoin_merged_mining_header: None,
                bitcoin_merged_mining_merkle_proof: None,
                bitcoin_merged_mining_coinbase_transaction: None,
                cached_hash: None,
                cached_hash_for_merged_mining: None,
            },
            _ => Header {
                parent_hash: B256::ZERO,
                ommers_hash: B256::ZERO,
                beneficiary: Address::ZERO,
                // The root of `genesis_alloc()` for this chain: the Bridge and
                // the ten funded test accounts. Zero until regtest funded
                // nobody, and zero was wrong the moment it did -- the header
                // is what every state lookup resolves through, so a header
                // claiming an empty state makes the funded accounts
                // unreachable and every transaction fail for want of funds.
                //
                // Hardcoded as mainnet's and testnet's are, and checked the
                // same way: `regtest_genesis_state_root_matches_the_header`
                // builds the allocation and compares.
                state_root: "0xa8775bf8dcbdc856680b62089a632e8f389a18cf51dc2c9aee3918792989fc4b"
                    .parse()
                    .unwrap(),
                transactions_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(0x20000),
                number: 0,
                gas_limit: U256::from(10_000_000),
                gas_used: 0,
                timestamp: 0,
                extra_data: Bytes::from("rustock-genesis"),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::ZERO,
                uncle_count: 0,
                umm_root: None,
                version_fields: None,
                bitcoin_merged_mining_header: None,
                bitcoin_merged_mining_merkle_proof: None,
                bitcoin_merged_mining_coinbase_transaction: None,
                cached_hash: None,
                cached_hash_for_merged_mining: None,
            },
        }
    }

/// The ten accounts rskj's regtest genesis funds, in its own order.
///
/// `keccak256("cow")`, then `keccak256("cow1")` through
/// `keccak256("cow9")`. Addresses rather than seeds because the address
/// is what the genesis commits to; the seeds are recorded here so the
/// private keys can be re-derived rather than kept anywhere:
///
/// | seed | address |
/// |---|---|
/// | cow  | cd2a3d9f938e13cd947ec05abc7fe734df8dd826 |
/// | cow1 | 7986b3df570230288501eea3d890bd66948c9b79 |
/// | cow2 | 0a3aa774752ec2042c46548456c094a76c7f3a79 |
/// | cow3 | cf7cdbbb5f7ba79d3ffe74a0bba13fc0295f6036 |
/// | cow4 | 39b12c05e8503356e3a7df0b7b33efa4c054c409 |
/// | cow5 | c354d97642faa06781b76ffb6786f72cd7746c97 |
/// | cow6 | debe71e1de41fc77c44df4b6db940026e31b0e71 |
/// | cow7 | 7857288e171c6159c5576d1bd9ac40c0c48a771c |
/// | cow8 | a4dea4d5c954f5fd9e87f0e9752911e83a3d18b3 |
/// | cow9 | 09a1eda29f664ac8f68106f6567276df0c65d859 |
    const REGTEST_TEST_ACCOUNTS: [&'static str; 10] = [
    "cd2a3d9f938e13cd947ec05abc7fe734df8dd826",
    "7986b3df570230288501eea3d890bd66948c9b79",
    "0a3aa774752ec2042c46548456c094a76c7f3a79",
    "cf7cdbbb5f7ba79d3ffe74a0bba13fc0295f6036",
    "39b12c05e8503356e3a7df0b7b33efa4c054c409",
    "c354d97642faa06781b76ffb6786f72cd7746c97",
    "debe71e1de41fc77c44df4b6db940026e31b0e71",
    "7857288e171c6159c5576d1bd9ac40c0c48a771c",
    "a4dea4d5c954f5fd9e87f0e9752911e83a3d18b3",
    "09a1eda29f664ac8f68106f6567276df0c65d859",
];

    fn address_bytes(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .expect("REGTEST_TEST_ACCOUNTS holds hex");
    }
    out
}

    /// Returns the genesis state allocations for this network.
    ///
    /// For mainnet/testnet, the Bridge contract (0x01000006) is pre-funded with
    /// 21 million RBTC (matching Bitcoin's total supply). This is the only
    /// genesis allocation; all other accounts start empty.
    pub fn genesis_alloc(&self) -> Vec<GenesisAlloc> {
        const BRIDGE: Address = address!("0000000000000000000000000000000001000006");
        // 21_000_000 RBTC = 21_000_000 * 10^18 wei
        let twenty_one_million_rbtc = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));

        if let Some(spec) = &self.genesis_spec {
            return spec.alloc.clone();
        }

        let bridge = GenesisAlloc {
            address: BRIDGE,
            balance: twenty_one_million_rbtc,
            nonce: U256::ZERO,
        };

        match self.chain_id {
            30 | 31 => vec![bridge],
            // Regtest funds ten test accounts as well, because a chain
            // where nobody holds anything cannot be used to test
            // anything: the first transaction fails for want of funds
            // and no amount of mining fixes it, since regtest starts at
            // genesis with no coinbase history.
            //
            // The addresses and the balance are rskj's
            // `genesis/rsk-dev.json` verbatim, so a contract or a test
            // suite written against rskj's regtest finds the same
            // accounts holding the same amounts here. Each is
            // `keccak256(seed)` for seed "cow", "cow1" .. "cow9", which
            // is how rskj's own tooling derives them -- verified, not
            // assumed: all ten derivations reproduce the listed
            // addresses.
            //
            // The *genesis hash* is still ours rather than rskj's: the
            // header fields it hashes over have not been compared, and
            // the state root now differs from the empty one it was. A
            // regtest chain is local by definition, so nothing peers
            // across the difference, but do not read a matching hash
            // into this.
            _ => {
                let mut alloc = vec![bridge];
                alloc.extend(Self::REGTEST_TEST_ACCOUNTS.iter().map(|hex| GenesisAlloc {
                    address: Address::from_slice(&Self::address_bytes(hex)),
                    // 10^30 wei, rskj's figure. Deliberately absurd: a
                    // load test should never be measuring what happens
                    // when a sender runs out.
                    balance: U256::from(10u64).pow(U256::from(30)),
                    nonce: U256::ZERO,
                }));
                alloc
            }
        }
    }

    /// Returns genesis Bridge storage entries for this network.
    ///
    /// rskj initializes the Bridge with federation data, feePerKb, and
    /// lockingCap at genesis. Without these, Bridge getters return empty
    /// and the first `updateCollections` starts from a blank slate.
    ///
    /// Returns `(slot_key_as_U256, raw_value_bytes)` pairs.
    pub fn genesis_bridge_storage(&self) -> Vec<(U256, Vec<u8>)> {
        match self.chain_id {
            30 | 31 => {
                // Default fee per KB: 10000 satoshis (matching rskj)
                let fee_per_kb_key = bridge_storage_key_ascii("feePerKb");
                let fee_per_kb_value = U256::from(10_000u64);

                // Default locking cap: 21M RBTC in wei
                let locking_cap_key = bridge_storage_key_ascii("lockingCap");
                let locking_cap_value = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));

                vec![
                    (fee_per_kb_key, u256_to_storage_bytes(fee_per_kb_value)),
                    (locking_cap_key, u256_to_storage_bytes(locking_cap_value)),
                ]
            }
            _ => vec![],
        }
    }

    /// Returns the bootstrap peer addresses for this network, as `host:port`
    /// strings matching rskj's `peer.discovery.ip.list` (main.conf / testnet.conf).
    /// Node IDs are not known upfront; discovery learns them from signed pongs.
    pub fn bootnodes(&self) -> Vec<String> {
        match self.chain_id {
            30 => (1..=16).map(|n| format!("bootstrap{n:02}.rsk.co:5050")).collect(),
            31 => (1..=8).map(|n| format!("bootstrap{n:02}.testnet.rsk.co:50505")).collect(),
            _ => vec![],
        }
    }
}

/// Encode a short storage key name (≤32 bytes) as rskj's `DataWord.fromString`.
fn bridge_storage_key_ascii(name: &str) -> U256 {
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 32);
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

/// Convert a U256 to trimmed big-endian bytes for storage.
fn u256_to_storage_bytes(val: U256) -> Vec<u8> {
    let be = val.to_be_bytes::<32>();
    let start = be.iter().position(|&b| b != 0).unwrap_or(32);
    be[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    /// The regtest accounts must be the ones rskj funds, and they must be
    /// what their seeds derive to.
    ///
    /// Addresses are listed rather than computed, so without this the
    /// list is a row of magic constants nobody can check. Deriving them
    /// here means a typo in the table fails the build rather than
    /// quietly funding an account nobody holds the key to -- which would
    /// look exactly like a working configuration until the first
    /// transaction.
    #[test]
    fn regtest_funds_the_accounts_rskj_funds() {
        use sha3::{Digest, Keccak256};

        let alloc = ChainConfig::regtest().genesis_alloc();
        assert_eq!(alloc.len(), 11, "the Bridge and ten test accounts");

        let expected = U256::from(10u64).pow(U256::from(30));
        for (i, entry) in alloc.iter().skip(1).enumerate() {
            let seed = if i == 0 { "cow".to_string() } else { format!("cow{i}") };

            // keccak(seed) is the private key; the address is the last
            // twenty bytes of keccak of the uncompressed public key.
            let secret = Keccak256::digest(seed.as_bytes());
            let key = secp256k1::SecretKey::from_byte_array(secret.into())
                .expect("a valid secp256k1 key");
            let public = secp256k1::PublicKey::from_secret_key(
                &secp256k1::Secp256k1::new(),
                &key,
            );
            let hashed = Keccak256::digest(&public.serialize_uncompressed()[1..]);
            let derived = alloy_primitives::Address::from_slice(&hashed[12..]);

            assert_eq!(
                entry.address, derived,
                "entry {i} should be keccak256(\"{seed}\")"
            );
            assert_eq!(entry.balance, expected, "{seed} is funded with 10^30 wei");
            assert_eq!(entry.nonce, U256::ZERO);
        }
    }

    /// Mainnet and testnet fund the Bridge and nobody else. A test
    /// account reachable on a real network would be a live private key
    /// published in this file.
    #[test]
    fn only_regtest_funds_test_accounts() {
        for config in [ChainConfig::mainnet(), ChainConfig::testnet()] {
            let alloc = config.genesis_alloc();
            assert_eq!(alloc.len(), 1, "chain {} funds only the Bridge", config.chain_id);
        }
    }

    #[test]
    fn test_mainnet_activation_heights() {
        let heights = ActivationHeights::mainnet();
        assert_eq!(heights.orchid, 729_000);
        assert_eq!(heights.wasabi100, 1_591_000);
        assert_eq!(heights.papyrus200, 2_392_700);
        assert_eq!(heights.iris300, 3_614_800);
        assert_eq!(heights.fingerroot500, 5_468_000);
    }

    /// rskj `rskj-core/src/main/resources/config/testnet.conf`. Testnet begins
    /// already on wasabi100 (bahamas, orchid, orchid060 and wasabi100 are all
    /// height 0 there), but papyrus200 and everything after it are real
    /// heights. This previously asserted `papyrus200 == 0`, which made RSKIP156
    /// -- the difficulty divisor moving from 50 to 400 -- active from testnet
    /// genesis instead of from #863,000.
    #[test]
    fn test_testnet_activation_heights() {
        let heights = ActivationHeights::testnet();
        assert_eq!(heights.orchid, 0);
        assert_eq!(heights.wasabi100, 0);
        assert_eq!(heights.papyrus200, 863_000);
        assert_eq!(heights.iris300, 2_060_500);
        assert_eq!(heights.fingerroot500, 4_015_800);
    }

    #[test]
    fn test_regtest_activation_heights() {
        let heights = ActivationHeights::regtest();
        assert_eq!(heights.orchid, 0);
        assert_eq!(heights.wasabi100, 0);
        assert_eq!(heights.papyrus200, u64::MAX);
    }

    #[test]
    fn test_mainnet_chain_config() {
        let config = ChainConfig::mainnet();
        assert_eq!(config.chain_id, 30);
        assert_eq!(config.network_id, 775);
        assert_eq!(config.duration_limit, 14);
        assert_eq!(config.difficulty_divisor, U256::from(50));
        assert_eq!(config.min_difficulty, U256::from(7_000_000_000_000_000u64));
    }

    #[test]
    fn test_regtest_chain_config() {
        let config = ChainConfig::regtest();
        assert_eq!(config.chain_id, 33);
        assert_eq!(config.network_id, 7771); // rskj regtest.conf networkId
        assert_eq!(config.duration_limit, 10);
        assert_eq!(config.difficulty_divisor, U256::from(2048));
        assert_eq!(config.min_difficulty, U256::from(1));
    }

    #[test]
    fn test_mainnet_genesis_header() {
        let config = ChainConfig::mainnet();
        let genesis = config.genesis_header();
        assert_eq!(genesis.number, 0);
        assert_eq!(genesis.parent_hash, B256::ZERO);
        assert_eq!(genesis.difficulty, U256::from(0x00100000));
        assert!(genesis.bitcoin_merged_mining_header.is_some());
    }

    /// The mainnet genesis header's stateRoot (0x9fa70f12...) was produced by
    /// the original 2018 client's account trie; converting our genesis unitrie
    /// must reproduce it (the pre-RSKIP126 root format is the same from
    /// genesis through wasabi).
    #[test]
    fn test_mainnet_genesis_orchid_state_root_matches_header() {
        use rustock_trie::{
            account_key, orchid_state_root, AccountState, MemoryTrieStore, TrieKeySlice, TrieNode,
        };

        let config = ChainConfig::mainnet();
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for entry in config.genesis_alloc() {
            let key = TrieKeySlice::from_key(&account_key(&entry.address));
            let acct = AccountState::new(entry.nonce, entry.balance);
            root = root.put(&key, &acct.encode(), &store);
        }
        assert_eq!(orchid_state_root(&root, &store), config.genesis_header().state_root);
    }

    #[test]
    fn test_testnet_genesis_header() {
        let config = ChainConfig::testnet();
        let genesis = config.genesis_header();
        assert_eq!(genesis.number, 0);
        assert_eq!(genesis.difficulty, U256::from(0x00100000));
        assert!(genesis.bitcoin_merged_mining_header.is_none());
    }

    #[test]
    fn test_regtest_genesis_header() {
        let config = ChainConfig::regtest();
        let genesis = config.genesis_header();
        assert_eq!(genesis.number, 0);
        assert_eq!(genesis.difficulty, U256::from(0x20000));
    }

    #[test]
    fn test_known_genesis_hash() {
        let mainnet = ChainConfig::mainnet();
        assert!(mainnet.known_genesis_hash().is_some());

        let testnet = ChainConfig::testnet();
        assert!(testnet.known_genesis_hash().is_some());

        let regtest = ChainConfig::regtest();
        assert!(regtest.known_genesis_hash().is_none());
    }

    #[test]
    fn test_mainnet_bootnodes() {
        // rskj main.conf peer.discovery.ip.list: bootstrap01..16.rsk.co:5050
        let nodes = ChainConfig::mainnet().bootnodes();
        assert_eq!(nodes.len(), 16);
        assert_eq!(nodes[0], "bootstrap01.rsk.co:5050");
        assert_eq!(nodes[15], "bootstrap16.rsk.co:5050");
    }

    #[test]
    fn test_testnet_bootnodes() {
        // rskj testnet.conf peer.discovery.ip.list: bootstrap01..08.testnet.rsk.co:50505
        let nodes = ChainConfig::testnet().bootnodes();
        assert_eq!(nodes.len(), 8);
        assert_eq!(nodes[0], "bootstrap01.testnet.rsk.co:50505");
        assert_eq!(nodes[7], "bootstrap08.testnet.rsk.co:50505");
    }

    #[test]
    fn test_regtest_bootnodes() {
        let config = ChainConfig::regtest();
        assert!(config.bootnodes().is_empty());
    }

    // -----------------------------------------------------------------------
    // Genesis allocation tests — ported from rskj genesis JSON + GenesisJsonTest
    // -----------------------------------------------------------------------

    /// Ported from rskj rsk-mainnet.json + BridgeSupportIT.
    /// The Bridge (0x01000006) receives exactly 21M RBTC at genesis.
    #[test]
    fn rskj_genesis_bridge_balance_21m() {
        let config = ChainConfig::mainnet();
        let alloc = config.genesis_alloc();

        assert_eq!(alloc.len(), 1, "mainnet genesis should have exactly 1 allocation");

        let bridge = &alloc[0];
        let expected_addr: Address = address!("0000000000000000000000000000000001000006");
        assert_eq!(bridge.address, expected_addr, "allocation should go to Bridge");

        let expected_balance = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));
        assert_eq!(bridge.balance, expected_balance,
            "Bridge should receive 21000000000000000000000000 wei (21M RBTC)");
        assert_eq!(bridge.nonce, U256::ZERO);
    }

    /// Ported from rskj: testnet uses the same 21M alloc.
    #[test]
    fn rskj_genesis_bridge_balance_testnet() {
        let config = ChainConfig::testnet();
        let alloc = config.genesis_alloc();
        assert_eq!(alloc.len(), 1);
        assert_eq!(
            alloc[0].balance,
            U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18))
        );
    }

    /// Regtest *does* have pre-funded allocations, and the assertion that
    /// stood here saying otherwise was wrong about rskj.
    ///
    /// It read "regtest has no pre-funded allocations (tests build their
    /// own state)" and sat among tests labelled as ported from rskj --
    /// but rskj's `genesis/rsk-dev.json` funds the Bridge and ten test
    /// accounts. A unit test can indeed build its own state and never
    /// notice; a node cannot, and a chain where nobody holds anything
    /// fails its first transaction for want of funds with no way to
    /// acquire any.
    ///
    /// What the allocation is, and that the addresses are the ones their
    /// seeds derive to, is checked by
    /// `regtest_funds_the_accounts_rskj_funds`.
    #[test]
    fn rskj_genesis_regtest_funds_the_bridge_and_ten_accounts() {
        let alloc = ChainConfig::regtest().genesis_alloc();
        assert_eq!(alloc.len(), 11);
        assert_eq!(
            alloc[0].balance,
            U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18)),
            "the Bridge holds the same 21M here as on every other chain"
        );
    }

    /// Ported from rskj: genesis Bridge storage includes feePerKb and lockingCap.
    #[test]
    fn rskj_genesis_bridge_storage_fee_and_cap() {
        let config = ChainConfig::mainnet();
        let storage = config.genesis_bridge_storage();

        assert_eq!(storage.len(), 2, "should have feePerKb and lockingCap");

        let fee_per_kb_value = U256::from_be_slice(&storage[0].1);
        assert_eq!(fee_per_kb_value, U256::from(10_000u64),
            "feePerKb should be 10000 satoshis");

        let locking_cap_value = U256::from_be_slice(&storage[1].1);
        let expected_cap = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));
        assert_eq!(locking_cap_value, expected_cap,
            "lockingCap should be 21M RBTC in wei");
    }

    /// Ported from rskj GenesisHashesTest: verify known mainnet genesis hash.
    #[test]
    fn rskj_known_mainnet_genesis_hash() {
        let config = ChainConfig::mainnet();
        let expected: B256 = "0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0".parse().unwrap();
        assert_eq!(config.known_genesis_hash(), Some(expected),
            "mainnet genesis hash must match rskj GenesisHashesTest");
    }

    /// Ported from rskj GenesisHashesTest: verify known testnet genesis hash.
    #[test]
    fn rskj_known_testnet_genesis_hash() {
        let config = ChainConfig::testnet();
        let expected: B256 = "0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42".parse().unwrap();
        assert_eq!(config.known_genesis_hash(), Some(expected),
            "testnet genesis hash must match rskj GenesisHashesTest");
    }
}

