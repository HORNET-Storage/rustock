/// RSK hardfork configuration and mapping to revm SpecId.
///
/// RSK activates EVM features individually via RSKIPs rather than bundling
/// them into Ethereum-style hardforks. We map each RSK network upgrade to
/// the closest Ethereum SpecId that captures the same EVM semantics:
///
/// | RSK Upgrade      | Height    | Closest SpecId    | Key changes                          |
/// |------------------|-----------|-------------------|--------------------------------------|
/// | genesis–orchid   | 0–728999  | BYZANTIUM         | REVERT, STATICCALL, RETURNDATASIZE   |
/// | orchid           | 729000    | BYZANTIUM         | (RSK-specific fixes)                 |
/// | wasabi100        | 1591000   | BYZANTIUM         | (RSK-specific fixes)                 |
/// | papyrus200       | 2392700   | PETERSBURG        | SHL/SHR/SAR, CHAINID, CREATE2        |
/// | iris300          | 3614800   | PETERSBURG        | (RSK-specific fixes)                 |
/// | hop400           | 4598500   | PETERSBURG        | (RSK-specific fixes)                 |
/// | fingerroot500    | 5468000   | PETERSBURG        | (RSK-specific fixes)                 |
/// | arrowhead600     | 6223700   | ISTANBUL          | Calldata cost reduction (RSKIP400)   |
/// | lovell700        | 7338024   | SHANGHAI          | Initcode metering (RSKIP438), PUSH0  |
/// | reed800          | 8052200   | SHANGHAI          | (RSK-specific fixes)                 |
use revm::primitives::hardfork::SpecId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RskNetworkUpgrade {
    Genesis,
    Orchid,
    Wasabi100,
    /// rskj "twoToThree" (mainnet 2,018,000): RSKIP150 only.
    TwoToThree,
    Papyrus200,
    Iris300,
    Hop400,
    Fingerroot500,
    Arrowhead600,
    Arrowhead631,
    Lovell700,
    Reed800,
    /// Testnet-only on mainnet config (height -1 in rskj main.conf).
    Reed810,
    Vetiver900,
}

pub const RSK_MAINNET_CHAIN_ID: u64 = 30;
pub const RSK_TESTNET_CHAIN_ID: u64 = 31;

/// Mainnet activation heights.
pub const MAINNET_ACTIVATIONS: &[(u64, RskNetworkUpgrade)] = &[
    (0, RskNetworkUpgrade::Genesis),
    (729_000, RskNetworkUpgrade::Orchid),
    (1_591_000, RskNetworkUpgrade::Wasabi100),
    (2_018_000, RskNetworkUpgrade::TwoToThree),
    (2_392_700, RskNetworkUpgrade::Papyrus200),
    (3_614_800, RskNetworkUpgrade::Iris300),
    (4_598_500, RskNetworkUpgrade::Hop400),
    (5_468_000, RskNetworkUpgrade::Fingerroot500),
    (6_223_700, RskNetworkUpgrade::Arrowhead600),
    (6_549_300, RskNetworkUpgrade::Arrowhead631),
    (7_338_024, RskNetworkUpgrade::Lovell700),
    (8_052_200, RskNetworkUpgrade::Reed800),
    // reed810 = -1 on mainnet (testnet-only); vetiver900 skips over it.
    (8_804_200, RskNetworkUpgrade::Vetiver900),
];

/// Testnet activation heights.
///
/// Ground truth is rskj `rskj-core/src/main/resources/config/testnet.conf`
/// (rskj 9.1.0). Testnet starts already on wasabi100: bahamas, orchid,
/// orchid060 and wasabi100 are all height 0 there, unlike mainnet.
pub const TESTNET_ACTIVATIONS: &[(u64, RskNetworkUpgrade)] = &[
    (0, RskNetworkUpgrade::Genesis),
    (0, RskNetworkUpgrade::Orchid),
    (0, RskNetworkUpgrade::Wasabi100),
    (504_000, RskNetworkUpgrade::TwoToThree),
    (863_000, RskNetworkUpgrade::Papyrus200),
    (2_060_500, RskNetworkUpgrade::Iris300),
    (3_103_000, RskNetworkUpgrade::Hop400),
    (4_015_800, RskNetworkUpgrade::Fingerroot500),
    (4_927_100, RskNetworkUpgrade::Arrowhead600),
    // arrowhead631 = -1 on testnet (rskj testnet.conf)
    (6_110_487, RskNetworkUpgrade::Lovell700),
    (6_835_700, RskNetworkUpgrade::Reed800),
    (7_139_600, RskNetworkUpgrade::Reed810),
    (7_604_200, RskNetworkUpgrade::Vetiver900),
];

/// A consensus rule rskj can schedule apart from the upgrade that carries it
/// (`blockchain.config.consensusRules`). Only the rules this ladder reads
/// by name are here; every other rule follows its upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusRule {
    Rskip351,
    Rskip535,
    Rskip536,
}

impl ConsensusRule {
    /// The rule rskj calls `name` in `consensusRules`.
    pub fn from_rskj_name(name: &str) -> Option<Self> {
        Some(match name {
            "rskip351" => Self::Rskip351,
            "rskip535" => Self::Rskip535,
            "rskip536" => Self::Rskip536,
            _ => return None,
        })
    }
}

impl RskNetworkUpgrade {
    /// The upgrade rskj calls `name` in `hardforkActivationHeights`, for the
    /// upgrades this ladder models. `bahamas`, `afterBridgeSync`, `orchid060`,
    /// `hop401` and `tbd1000` are rskj names too, but not rungs here; see
    /// [`RskHardforkConfig::with_rskj_overrides`].
    pub fn from_rskj_name(name: &str) -> Option<Self> {
        Some(match name {
            "orchid" => Self::Orchid,
            "wasabi100" => Self::Wasabi100,
            "twoToThree" => Self::TwoToThree,
            "papyrus200" => Self::Papyrus200,
            "iris300" => Self::Iris300,
            "hop400" => Self::Hop400,
            "fingerroot500" => Self::Fingerroot500,
            "arrowhead600" => Self::Arrowhead600,
            "arrowhead631" => Self::Arrowhead631,
            "lovell700" => Self::Lovell700,
            "reed800" => Self::Reed800,
            "reed810" => Self::Reed810,
            "vetiver900" => Self::Vetiver900,
            _ => return None,
        })
    }
}

/// Configuration that determines which RSK features are active at a given block.
#[derive(Debug, Clone)]
pub struct RskHardforkConfig {
    activations: Vec<(u64, RskNetworkUpgrade)>,
    pub chain_id: u64,
    /// Rules scheduled apart from their upgrade (`consensusRules`). `None`
    /// is rskj's `-1`: never. Empty on every built-in chain.
    rule_overrides: Vec<(ConsensusRule, Option<u64>)>,
}

impl RskHardforkConfig {
    pub fn mainnet() -> Self {
        Self {
            activations: MAINNET_ACTIVATIONS.to_vec(),
            chain_id: RSK_MAINNET_CHAIN_ID,
            rule_overrides: Vec::new(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            activations: TESTNET_ACTIVATIONS.to_vec(),
            chain_id: RSK_TESTNET_CHAIN_ID,
            rule_overrides: Vec::new(),
        }
    }

    pub fn regtest() -> Self {
        Self {
            activations: vec![(0, RskNetworkUpgrade::Vetiver900)],
            chain_id: 33,
            rule_overrides: Vec::new(),
        }
    }

    pub fn for_network(network_id: u64) -> Self {
        match network_id {
            30 => Self::mainnet(),
            31 => Self::testnet(),
            _ => Self::regtest(),
        }
    }

    /// Creates a config where all upgrades are active from genesis (useful for testing).
    ///
    /// Note what this does **not** turn on: RSKIP-144 and RSKIP-351 are
    /// gated on `reed810` being *scheduled*, and naming Vetiver900 alone
    /// does not schedule it -- see `has_rskip144`. A test that wants
    /// parallel sublists wants [`RskHardforkConfig::all_active_parallel`].
    pub fn all_active(chain_id: u64) -> Self {
        Self {
            activations: vec![(0, RskNetworkUpgrade::Vetiver900)],
            chain_id,
            rule_overrides: Vec::new(),
        }
    }

    /// `all_active`, and RSKIP-144 with it.
    ///
    /// Scheduling reed810 at zero is what mainnet does not do, so this is
    /// the shape of a chain that partitions its blocks: everything on, and
    /// the parallel sublists among it.
    pub fn all_active_parallel(chain_id: u64) -> Self {
        Self {
            activations: vec![
                (0, RskNetworkUpgrade::Reed810),
                (0, RskNetworkUpgrade::Vetiver900),
            ],
            chain_id,
            rule_overrides: Vec::new(),
        }
    }

    /// First block at which `upgrade` activates, if it activates on this network.
    ///
    /// `None` is rskj's activation height of `-1`: the upgrade is not
    /// scheduled here at all. The distinction matters for any upgrade a
    /// network skips, because an ordinal `active_upgrade() >= X` reads a
    /// *later* upgrade as implying `X` -- right for a chain that passed
    /// through `X`, wrong for one that never scheduled it. See
    /// `has_rskip144`.
    pub fn activation_height(&self, upgrade: RskNetworkUpgrade) -> Option<u64> {
        self.activations.iter().find(|(_, u)| *u == upgrade).map(|(h, _)| *h)
    }

    /// rskj `ActivationConfig.ForBlock.isActivating`: the upgrade activates
    /// exactly at this block.
    pub fn is_activating(&self, upgrade: RskNetworkUpgrade, block_number: u64) -> bool {
        self.activation_height(upgrade) == Some(block_number)
    }

    /// Returns the active RSK network upgrade at the given block height: the
    /// highest rung scheduled at or below it.
    ///
    /// The built-in tables are ordered by height and by rung alike, so this
    /// is the last rung reached. An overridden ladder can schedule a lower
    /// rung above a higher one (reed810 above vetiver900, say), and then the
    /// highest rung reached is still the one that names the rules in force.
    pub fn active_upgrade(&self, block_number: u64) -> RskNetworkUpgrade {
        self.activations
            .iter()
            .filter(|(height, _)| block_number >= *height)
            .map(|(_, upgrade)| *upgrade)
            .max()
            .unwrap_or(RskNetworkUpgrade::Genesis)
    }

    /// Schedule `upgrade` at `height`, or take it off the ladder with `None`
    /// (rskj's `-1`). Activations stay ordered by height.
    pub fn with_hardfork(mut self, upgrade: RskNetworkUpgrade, height: Option<u64>) -> Self {
        self.activations.retain(|(_, u)| *u != upgrade);
        if let Some(h) = height {
            self.activations.push((h, upgrade));
            self.activations.sort_by_key(|(h, _)| *h);
        }
        self
    }

    /// Schedule `rule` apart from its upgrade, at `height` or never
    /// (`None`), as rskj's `consensusRules` does.
    pub fn with_consensus_rule(mut self, rule: ConsensusRule, height: Option<u64>) -> Self {
        self.rule_overrides.retain(|(r, _)| *r != rule);
        self.rule_overrides.push((rule, height));
        self
    }

    fn rule_override(&self, rule: ConsensusRule) -> Option<Option<u64>> {
        self.rule_overrides.iter().find(|(r, _)| *r == rule).map(|(_, h)| *h)
    }

    /// A rung this ladder does not model as such but reads at one height
    /// per chain: rskj's `bahamas`, `afterBridgeSync` and `hop401`.
    fn fixed_rskj_height(&self, name: &str) -> Option<u64> {
        let (mainnet, testnet) = match name {
            "bahamas" => (3_397, 0),
            "afterBridgeSync" => (370_000, 114_000),
            "hop401" => (4_976_300, 3_362_200),
            _ => return None,
        };
        Some(match self.chain_id {
            RSK_MAINNET_CHAIN_ID => mainnet,
            RSK_TESTNET_CHAIN_ID => testnet,
            _ => 0,
        })
    }

    /// Apply rskj's `hardforkActivationHeights` and `consensusRules`, by
    /// rskj's names, with `None` for `-1`. For replaying blocks mined on a
    /// copy of a chain under rules it has not activated.
    ///
    /// What each name does here:
    ///
    /// - A rung of this ladder (`orchid` to `vetiver900`): scheduled at the
    ///   height, or removed.
    /// - `bahamas`, `afterBridgeSync`, `hop401`: read at one fixed height per
    ///   chain, so they are accepted at that height and refused at any other.
    /// - `orchid060` and `tbd1000`: nothing here reads them. `tbd1000` only
    ///   turns on RSKIP-559 (deterministic pegout sorting in the Bridge),
    ///   which this node does not implement. Accepted and reported as such.
    /// - `rskip351`, `rskip535`, `rskip536`: scheduled apart from their
    ///   upgrade.
    /// - `rskipUMM`: follows papyrus200 here, so it is accepted at that height
    ///   and refused at any other.
    ///
    /// Returns the names that were accepted without effect, for the log.
    pub fn with_rskj_overrides(
        mut self,
        hardforks: &[(String, Option<u64>)],
        rules: &[(String, Option<u64>)],
    ) -> Result<(Self, Vec<String>), String> {
        let mut unmodelled = Vec::new();
        for (name, height) in hardforks {
            if let Some(upgrade) = RskNetworkUpgrade::from_rskj_name(name) {
                self = self.with_hardfork(upgrade, *height);
            } else if let Some(fixed) = self.fixed_rskj_height(name) {
                if *height != Some(fixed) {
                    return Err(format!(
                        "hardfork {name}: this node reads it at #{fixed} on this chain and \
                         cannot move it"
                    ));
                }
            } else if matches!(name.as_str(), "orchid060" | "tbd1000") {
                unmodelled.push(name.clone());
            } else {
                return Err(format!("hardfork {name}: not an rskj upgrade name"));
            }
        }
        for (name, height) in rules {
            if let Some(rule) = ConsensusRule::from_rskj_name(name) {
                self = self.with_consensus_rule(rule, *height);
            } else if name == "rskipUMM" {
                let papyrus200 = self.activation_height(RskNetworkUpgrade::Papyrus200);
                if *height != papyrus200 {
                    return Err(format!(
                        "consensus rule rskipUMM: this node reads it at papyrus200 \
                         ({papyrus200:?}) and cannot move it"
                    ));
                }
            } else {
                return Err(format!(
                    "consensus rule {name}: not one this node schedules on its own \
                     (rskip351, rskip535, rskip536, rskipUMM)"
                ));
            }
        }
        Ok((self, unmodelled))
    }

    /// Maps the RSK network upgrade to the closest revm SpecId.
    pub fn spec_id(&self, block_number: u64) -> SpecId {
        upgrade_to_spec_id(self.active_upgrade(block_number))
    }

    /// Whether the Unitrie state root is used in headers (RSKIP126, Wasabi100).
    /// Before this, headers contain a legacy Ethereum-style state root that
    /// doesn't match the Unitrie hash.
    pub fn has_unitrie_state_root(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// Whether CHAINID opcode is available (RSKIP152, activated at Papyrus200).
    pub fn has_chainid(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// Whether calldata cost is reduced from 68 to 16 (RSKIP400, Arrowhead600).
    pub fn has_reduced_calldata_cost(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// Whether the PUSH0 opcode (0x5f) is available (RSKIP398, Arrowhead600).
    /// rskj enables PUSH0 at arrowhead600, NOT at the Shanghai-equivalent
    /// lovell700; revm only bundles PUSH0 into SHANGHAI, so arrowhead600..
    /// lovell700 needs it installed explicitly (see rsk_instructions::install).
    pub fn has_push0(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// RSKIP91 (Orchid, mainnet #729,000): the STATICCALL opcode (0xfa).
    /// rskj's `VM.java` OP_STATICCALL throws `invalidOpCode` while RSKIP91 is
    /// inactive (`reference.conf`: `rskip91 = orchid`). rustock maps Genesis to
    /// `SpecId::BYZANTIUM`, where revm already has STATICCALL, so it must be
    /// disabled explicitly before Orchid.
    pub fn has_rskip91(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Orchid
    }

    /// Whether the BASEFEE opcode (0x48) is available (RSKIP412, Arrowhead600).
    /// rskj gates it on RSKIP412 (`reference.conf`: `rskip412 = arrowhead600`)
    /// and pushes `program.getMinimumGasPrice()` (`VM.doBASEFEE`). revm bundles
    /// BASEFEE into LONDON, and arrowhead600..lovell700 maps to ISTANBUL, so it
    /// must be installed explicitly (see `rsk_instructions::install`).
    pub fn has_basefee(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// Whether initcode metering is active (RSKIP438, Lovell700).
    pub fn has_initcode_metering(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP428 (Lovell700): the Bridge emits `pegout_transaction_created` for
    /// every settled release (BridgeSupport.processReleaseTransactionInfo).
    pub fn has_rskip428(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP445 (Lovell700): the MCOPY opcode (0x5e, EIP-5656). revm gates it on
    /// the CANCUN spec, but lovell700 maps to SHANGHAI, so it is installed
    /// explicitly (see `rsk_instructions::install`).
    pub fn has_rskip445(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP446 (Lovell700): transient storage TLOAD/TSTORE (0x5c/0x5d,
    /// EIP-1153). Same SHANGHAI-vs-CANCUN gap as MCOPY — installed explicitly.
    pub fn has_rskip446(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// Whether StoredBlock V2 format is active (RSKIP454, Lovell700).
    pub fn has_stored_block_v2(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP87: unlimited lock whitelist entries (Orchid, mainnet 729_000).
    pub fn has_rskip87(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Orchid
    }

    /// RSKIP88: invalid Bridge calldata throws instead of silently returning
    /// null (Orchid, mainnet 729_000).
    pub fn has_rskip88(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Orchid
    }

    /// RSKIP123: multikey federation members; disables the single-key "add"
    /// federation-change function (Wasabi100).
    pub fn has_rskip123(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// RSKIP125 (wasabi): a contract created by the CREATE/CREATE2 opcode has
    /// its nonce initialized to 1.
    pub fn has_rskip125(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// RSKIP140 (papyrus): the EXTCODEHASH opcode becomes available.
    pub fn has_rskip140(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP150 (twoToThree, mainnet 2_018_000): a precompile's return value
    /// is written to the caller's memory bounded by the CALL's outSize.
    /// Before it, rskj `Program.memorySave` writes the FULL output at
    /// outOffs, silently (gas-free) extending the caller's memory.
    pub fn has_rskip150(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::TwoToThree
    }

    /// RSKIP90 (orchid): EXTCODESIZE of an active precompile reports 2^256-1
    /// (and EXTCODEHASH the empty-code hash post-RSKIP140).
    pub fn has_rskip90(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Orchid
    }

    /// RSKIP383: longer federation activation age (Fingerroot500).
    pub fn has_rskip383(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP146: release request queue stores RSK tx hash (Papyrus200, mainnet 2_392_700).
    pub fn has_rskip146(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP176: use updateCollections tx hash as pegouts-waiting-for-signatures key (Iris300).
    pub fn has_rskip176(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP199: BTC main-chain height -> hash index in bridge storage (Iris300).
    pub fn has_rskip199(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP200: singular `receiveHeader` + `receiveHeaders` becomes
    /// federation-only (`receiveHeadersIsPublic` flips false) (Iris300).
    pub fn has_rskip200(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP134: per-hash processed-peg-in entries replace the single
    /// btcTxHashesAP map (Papyrus200).
    pub fn has_rskip134(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP143: segwit/P2SH peg-in sender types become processable
    /// (Papyrus200).
    pub fn has_rskip143(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP185: peg-out refund to sender on rejection (Iris300).
    pub fn has_rskip185(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP197: a failing precompile CALL is handled (push 0, refund the
    /// surplus, continue) instead of propagating an exception that aborts the
    /// calling frame and burns all its gas (Iris300). Post-197 a failed
    /// precompile costs exactly its `getGasForData` requiredGas.
    pub fn has_rskip197(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP219: updated minimum peg-in tx value (Iris300).
    pub fn has_rskip219(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP201: peg-out BTC transactions use version 2 (Iris300).
    pub fn has_rskip201(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP271: peg-out batching and nextPegoutHeight tracking (Hop400, mainnet 4_598_500).
    pub fn has_rskip271(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Hop400
    }

    /// RSKIP284: BTC address-with-version serialization uses a single version
    /// byte instead of `BigInteger.toByteArray()` (Hop400, mainnet 4_598_500).
    pub fn has_rskip284(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Hop400
    }

    /// RSKIP293: flyover peg-ins also credit the retiring federation, and the
    /// per-UTXO minimum applies to flyover value validation (Hop400).
    pub fn has_rskip293(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Hop400
    }

    /// RSKIP294: the retiring/active federation spend wallet caps its UTXO set
    /// to `maxInputsPerPegoutTransaction` (mainnet 50), so funds migration and
    /// pegouts only ever see the first N UTXOs (Hop400, mainnet 4_598_500).
    pub fn has_rskip294(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Hop400
    }

    /// RSKIP353: committed federations become P2SH-ERP federations instead of
    /// non-standard ERP (mainnet hop401 = 4,976,300; testnet 3,362,200;
    /// regtest 0). rustock collapses hop401 into Hop400 in the upgrade ladder,
    /// so this consensus boundary needs an explicit per-chain height.
    pub fn has_rskip353(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 4_976_300,
            RSK_TESTNET_CHAIN_ID => 3_362_200,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP357: the funds-migration window end takes its special-case value
    /// (mainnet 172,800 instead of 10,585). Activates at hop401 (same height as
    /// RSKIP353); the special case applies only while RSKIP357 is active and
    /// RSKIP374 is not (i.e. hop401 .. fingerroot500).
    pub fn has_rskip357(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 4_976_300,
            RSK_TESTNET_CHAIN_ID => 3_362_200,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP374: ends the special-case funds-migration window, restoring the
    /// normal `fundsMigrationAgeSinceActivationEnd` (Fingerroot500).
    pub fn has_rskip374(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP385 (fingerroot500): `getEstimatedFeesForNextPegOutEvent` stops
    /// short-circuiting to zero when the peg-out queue is empty
    /// (`BridgeSupport.shouldReturnZeroEstimatedFees`).
    pub fn has_rskip385(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP305: committed federations become P2SH-P2WSH-ERP federations
    /// instead of P2SH-ERP (mainnet reed800 = 8,052,200; testnet 6,835,700;
    /// regtest 0).
    pub fn has_rskip305(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 8_052_200,
            RSK_TESTNET_CHAIN_ID => 6_835_700,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP375: pegouts-waiting-for-signatures keyed by the pegout creation
    /// RSK tx hash again (Fingerroot500).
    pub fn has_rskip375(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP453: internal creates with an unpayable code deposit (or
    /// over-max-size code) FAIL instead of deploying with empty code
    /// (Lovell700).
    pub fn has_rskip453(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP434: lifts the BTC chainwork-overflow header block (Arrowhead631).
    pub fn has_rskip434(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead631
    }

    /// RSKIP415: the `add_signature` event's `federatorRskAddress` topic is
    /// derived from the federation member's RSK public key instead of its BTC
    /// public key (Arrowhead600). rskj `BridgeEventLoggerImpl.getFederatorRskPublicKey`.
    pub fn has_rskip415(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// RSKIP170: pegin_btc event replaces lock_btc (Iris300).
    pub fn has_rskip170(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP186: on a federation handover, persist
    /// `nextFederationCreationBlockHeight` and `lastRetiredFederationP2SHScript`
    /// (Iris300). Enables the funds-migration / active-federation-block-height
    /// bookkeeping read on later blocks.
    pub fn has_rskip186(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP181: peg-in rejection events rejected_pegin / unrefundable_pegin
    /// (Iris300).
    pub fn has_rskip181(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP171: a CALL/CREATE that runs no new frame resets the caller's
    /// returnDataBuffer (canonical EIP-211), instead of preserving the prior
    /// call's output as pre-iris rskj did (Iris300).
    pub fn has_rskip171(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP174: a top-level contract creation carries over the balance an
    /// address already held, instead of destroying it (Iris300).
    ///
    /// rskj `TransactionExecutor.create`:
    ///
    /// ```java
    /// cacheTrack.createAccount(newContractAddress,
    ///     activations.isActive(RSKIP174) && cacheTrack.isExist(newContractAddress));
    /// ```
    ///
    /// `createAccount(addr, false)` writes a fresh `AccountState` over
    /// whatever was there, so before this activation a deployment onto a
    /// pre-funded address silently burns the funds.
    pub fn has_rskip174(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP326: add_signature is only logged when a signature is actually
    /// applied (Fingerroot500).
    pub fn has_rskip326(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP377: on a federation handover the retiring federation's
    /// `lastRetiredFederationP2SHScript` is stored as its members' P2SH script —
    /// for an ERP federation this is the *default* (standard multisig branch)
    /// P2SH, not the full ERP P2SH (Fingerroot500). See
    /// `FederationSupportImpl.getFederationMembersP2SHScript`.
    pub fn has_rskip377(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP379 (Arrowhead600): the peg-in evaluation moves to
    /// `PegUtils.evaluatePegin`. Among other changes it INVERTS the empty
    /// fed-output edge case of `allUTXOsToFedAreAboveMinimumPeginValue`: an empty
    /// set is explicitly NOT all-above-minimum (`if (fedUtxos.isEmpty()) return
    /// false;`), so it is rejected as INVALID_AMOUNT — the opposite of the
    /// pre-379 legacy `!isAnyUTXOAmountBelowMinimum` (vacuously true on empty).
    pub fn has_rskip379(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// RSKIP376 (Arrowhead600): segwit-compatible (P2SH-P2WSH) federations. As a
    /// side effect it also drops the `buildMigrationTransaction` version override:
    /// once RSKIP201 set the default release-tx version to 2, only migration txs
    /// were forced back to version 1; from RSKIP376 on they stay version 2 like
    /// every other pegout (ReleaseTransactionBuilder.buildMigrationTransaction).
    pub fn has_rskip376(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// RSKIP427: the RSKIP185 peg-out event amounts (release_request_received,
    /// release_request_rejected) switch from satoshis to full wei (Lovell700).
    pub fn has_rskip427(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP419 (Lovell700): the Sign Validation Protocol (SVP) for federation
    /// changes. `commitFederation` no longer rotates the active/retiring
    /// federations immediately; it stores a *proposed* federation that must
    /// prove it can sign (an on-chain SVP fund tx + spend tx) within
    /// `validationPeriodDurationInBlocks`. Only after the spend tx is registered
    /// is the proposed federation promoted (`commitProposedFederation`).
    pub fn has_rskip419(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP459: mark rejected non-refundable peg-ins as processed (Lovell700).
    /// Disabled again by RSKIP551 at Vetiver900.
    pub fn has_rskip459(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP136 (bahamas — mainnet 3_397, testnet/regtest genesis): correct
    /// gas accounting for direct precompile calls. Before it, rskj checked
    /// the tx gas limit against the precompile cost alone and recorded
    /// gasUsed = precompileCost + intrinsicCost, which can EXCEED the limit.
    pub fn has_rskip136(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 3_397,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP124: header-count-based cost for `receiveHeaders`, and the
    /// start of the only window in which that method is public
    /// (Wasabi100).
    ///
    /// **This flag alone does not make `receiveHeaders` public.** rskj
    /// computes `receiveHeadersIsPublic() = RSKIP124 && !RSKIP200`, so
    /// the public window is Wasabi100 up to Iris300 and no further:
    /// RSKIP200 introduced the singular, permissionless
    /// `receiveHeader` and closed the plural one again, back to
    /// `activeAndRetiringFederationOnly`. On any chain past Iris300 —
    /// which is every live network — `receiveHeaders` is federation
    /// members only.
    ///
    /// Reading this comment without that second half is an easy
    /// mistake and has been made: it reads as "anyone may relay a
    /// batch of headers", which is true only of a window that closed
    /// in 2021. `bridge/mod.rs` has the gate; [`Self::has_rskip200`]
    /// has the other half of the formula.
    pub fn has_rskip124(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// RSKIP132: recalculated receiveHeaders cost (Wasabi100; testnet
    /// overrides the height to 43_550 in testnet.conf consensusRules).
    pub fn has_rskip132(&self, block_number: u64) -> bool {
        if self.chain_id == RSK_TESTNET_CHAIN_ID {
            return block_number >= 43_550;
        }
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// areBridgeTxsPaid (rskj reference.conf: afterBridgeSync — mainnet
    /// 370_000, testnet 114_000). Before activation, federation/authorized
    /// transactions to the Bridge execute for free with zero gas
    /// (BridgeUtils.isFreeBridgeTx).
    pub fn has_are_bridge_txs_paid(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 370_000,
            RSK_TESTNET_CHAIN_ID => 114_000,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP144: parallel transaction execution, and the
    /// `txExecutionSublistsEdges` header field that carries the sublist
    /// boundaries.
    ///
    /// **Not an ordinal comparison**, unlike most of its neighbours. rskj
    /// maps `rskip144` to `reed810` (`reference.conf`), and `reed810` is
    /// `-1` in `main.conf` against `7_139_600` in `testnet.conf`. Mainnet
    /// never schedules it, and `main.conf`'s `consensusRules` overrides only
    /// `rskip536` -- so no later mainnet upgrade turns this on.
    ///
    /// `active_upgrade() >= Reed810` would: mainnet's table jumps Reed800 to
    /// Vetiver900, which outranks Reed810, so this would have gone true at
    /// mainnet #8,804,200 -- a height the chain passed months ago. It was
    /// inert only because nothing read this predicate yet and mainnet headers
    /// carry no sublist edges. The first thing to depend on it would have
    /// forked the node.
    pub fn has_rskip144(&self, block_number: u64) -> bool {
        self.activation_height(RskNetworkUpgrade::Reed810)
            .is_some_and(|h| block_number >= h)
    }

    /// RSKIP351: the compressed ("mini") block header, where the logs-bloom
    /// slot carries `RLP([version, extension_hash])` instead of the bloom.
    ///
    /// Same gate as RSKIP144, and not an ordinal comparison for the same
    /// reason. rskj's `ValidTxExecutionSublistsEdgesRule` requires *both*
    /// before it validates anything, so they are kept as two predicates even
    /// though they coincide.
    pub fn has_rskip351(&self, block_number: u64) -> bool {
        if let Some(height) = self.rule_override(ConsensusRule::Rskip351) {
            return height.is_some_and(|h| block_number >= h);
        }
        self.activation_height(RskNetworkUpgrade::Reed810)
            .is_some_and(|h| block_number >= h)
    }

    /// RSKIP535: the `baseEvent` header-extension field, which makes the
    /// header version 2.
    ///
    /// `testnet.conf` sets `rskip535 = 7604200`, the vetiver900 height, with
    /// the comment "To be activated in testnet only". Mainnet does not set it.
    pub fn has_rskip535(&self, block_number: u64) -> bool {
        if let Some(height) = self.rule_override(ConsensusRule::Rskip535) {
            return height.is_some_and(|h| block_number >= h);
        }
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP536: additional BlockHeader precompile methods. Maps to reed810 in
    /// reference.conf; mainnet overrides it to the vetiver900 height (8_804_200)
    /// via main.conf consensusRules. `>= Reed810` is exact on both networks
    /// because mainnet jumps Reed800 -> Vetiver900 at that height.
    ///
    /// So this one *is* an ordinal comparison, deliberately, and differs from
    /// `has_rskip144` right above it: both map to reed810 in reference.conf,
    /// but mainnet overrides this one and not that one.
    pub fn has_rskip536(&self, block_number: u64) -> bool {
        if let Some(height) = self.rule_override(ConsensusRule::Rskip536) {
            return height.is_some_and(|h| block_number >= h);
        }
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Reed810
    }

    /// RSKIP540: min pegout value as extra pegout in fee estimation;
    /// enables getEstimatedFeesForPegOutAmount (Vetiver900).
    pub fn has_rskip540(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP544: EIP-3541, reject new contract code starting with 0xEF (Vetiver900).
    pub fn has_rskip544(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP551: disables RSKIP459 (Vetiver900).
    pub fn has_rskip551(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP552: Blake2F data handling improvements (Vetiver900).
    pub fn has_rskip552(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }
}

fn upgrade_to_spec_id(upgrade: RskNetworkUpgrade) -> SpecId {
    match upgrade {
        RskNetworkUpgrade::Genesis
        | RskNetworkUpgrade::Orchid => SpecId::BYZANTIUM,

        // Wasabi enables the Constantinople shift opcodes (RSKIP120) and
        // CREATE2 (RSKIP125), but NOT EXTCODEHASH (RSKIP140, papyrus).
        // PETERSBURG is the closest spec (Constantinople minus EIP-1283 SSTORE
        // gas, which RSK never adopted); EXTCODEHASH is gated off separately
        // until papyrus in rsk_instructions::install.
        RskNetworkUpgrade::Wasabi100
        | RskNetworkUpgrade::TwoToThree
        | RskNetworkUpgrade::Papyrus200
        | RskNetworkUpgrade::Iris300
        | RskNetworkUpgrade::Hop400
        | RskNetworkUpgrade::Fingerroot500 => SpecId::PETERSBURG,

        // Arrowhead600 maps to ISTANBUL for the ONE Istanbul change RSK adopted —
        // RSKIP400 (EIP-2028: non-zero calldata 68→16), which revm's intrinsic
        // gas (`calculate_initial_tx_gas_for_tx`) keys off the SpecId. RSK did NOT
        // adopt the rest of Istanbul's EVM gas repricings: its `GasCost` constants
        // are fork-independent, so SLOAD stays 200 (EIP-1884 would be 800), BALANCE
        // 400 (700), EXTCODEHASH 400 (700), and SSTORE keeps Petersburg metering
        // (no EIP-2200 net metering / reentrancy sentry). Those four are pinned
        // back to their rskj values in `rsk_instructions::install` so only the
        // calldata reduction survives the ISTANBUL mapping.
        RskNetworkUpgrade::Arrowhead600
        | RskNetworkUpgrade::Arrowhead631 => SpecId::ISTANBUL,

        RskNetworkUpgrade::Lovell700
        | RskNetworkUpgrade::Reed800
        | RskNetworkUpgrade::Reed810
        | RskNetworkUpgrade::Vetiver900 => SpecId::SHANGHAI,
    }
}

#[cfg(test)]
mod fee_settlement_tests {
    use super::*;

    /// Postponing the gas fee to the REMASC transaction is gated on
    /// RSKIP-144, and RSKIP-144 is unscheduled on mainnet. So every mainnet
    /// block credits the fee inside the transaction that paid it, as it
    /// always has, and this change cannot reach the chain this node follows.
    #[test]
    fn mainnet_never_postpones_the_fee() {
        let cfg = RskHardforkConfig::mainnet();
        for block in [0u64, 1, 2_392_700, 7_338_024, 9_000_000, u64::MAX] {
            assert!(
                !cfg.has_rskip144(block),
                "RSKIP-144 must stay unscheduled on mainnet (block {block})"
            );
        }
    }

    /// Testnet does postpone, from reed810 and not before.
    #[test]
    fn testnet_postpones_from_reed810() {
        let cfg = RskHardforkConfig::testnet();
        assert!(!cfg.has_rskip144(7_139_599));
        assert!(cfg.has_rskip144(7_139_600));
        assert!(cfg.has_rskip144(8_000_000));
    }

    /// The trap this nearly fell into. Mainnet's table jumps Reed800 to
    /// Vetiver900, and Vetiver900 outranks Reed810, so an ordinal
    /// `active_upgrade() >= Reed810` reads as "RSKIP-144 is on" from
    /// #8,804,200 -- a height mainnet passed months ago. rskj never turns it
    /// on there: `reed810 = -1` in `main.conf`, whose `consensusRules`
    /// override only `rskip536`.
    #[test]
    fn a_later_mainnet_upgrade_does_not_imply_an_unscheduled_one() {
        let cfg = RskHardforkConfig::mainnet();
        let vetiver900 = cfg
            .activation_height(RskNetworkUpgrade::Vetiver900)
            .expect("mainnet schedules vetiver900");
        assert_eq!(
            cfg.activation_height(RskNetworkUpgrade::Reed810),
            None,
            "mainnet must never schedule reed810"
        );
        assert!(
            cfg.active_upgrade(vetiver900) >= RskNetworkUpgrade::Reed810,
            "the ordinal comparison does read as active -- which is the trap"
        );
        assert!(!cfg.has_rskip144(vetiver900), "and the predicate must not");
        assert!(!cfg.has_rskip351(vetiver900));
    }

    /// RSKIP536 keeps the ordinal comparison on purpose: mainnet overrides it
    /// to the vetiver900 height, so there it really is active from then.
    #[test]
    fn rskip536_is_the_one_mainnet_does_schedule() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip536(8_804_199));
        assert!(cfg.has_rskip536(8_804_200));
    }
}

#[cfg(test)]
mod tests {

    /// Audit finding FRCR-674.
    ///
    /// rskj gates STATICCALL (0xfa) on RSKIP91 — `VM.java` OP_STATICCALL
    /// throws `invalidOpCode` while it is inactive, and `reference.conf` sets
    /// `rskip91 = orchid` (mainnet #729,000). rustock maps Genesis to
    /// `SpecId::BYZANTIUM`, where revm already provides STATICCALL, so before
    /// this gate rustock executed the opcode for the first 729,000 blocks,
    /// where rskj aborts the frame and consumes all its gas.
    #[test]
    fn test_staticcall_gated_on_orchid_rskip91() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip91(0));
        assert!(!cfg.has_rskip91(728_999));
        assert!(cfg.has_rskip91(729_000));
        assert!(cfg.has_rskip91(9_000_000));

        // rskj testnet.conf: orchid = 0, so STATICCALL is live from genesis.
        let testnet = RskHardforkConfig::testnet();
        assert!(testnet.has_rskip91(0));
    }

    /// rskj `rskj-core/src/main/resources/config/testnet.conf` (rskj 9.1.0),
    /// transcribed as a block. rustock's testnet ladder had drifted: wasabi100
    /// was 863,000 (rskj: 0 — that number is rskj's *papyrus200*), papyrus200
    /// was 1,580,000 (a value that appears nowhere in rskj), twoToThree was
    /// folded into wasabi, and lovell700/reed800 were both wrong. Mainnet was
    /// and is exact; this pins both so neither can drift again.
    #[test]
    fn activation_heights_match_rskj_config() {
        let m = RskHardforkConfig::mainnet();
        // rskj config/main.conf
        for (height, upgrade) in [
            (729_000u64, RskNetworkUpgrade::Orchid),
            (1_591_000, RskNetworkUpgrade::Wasabi100),
            (2_018_000, RskNetworkUpgrade::TwoToThree),
            (2_392_700, RskNetworkUpgrade::Papyrus200),
            (3_614_800, RskNetworkUpgrade::Iris300),
            (4_598_500, RskNetworkUpgrade::Hop400),
            (5_468_000, RskNetworkUpgrade::Fingerroot500),
            (6_223_700, RskNetworkUpgrade::Arrowhead600),
            (6_549_300, RskNetworkUpgrade::Arrowhead631),
            (7_338_024, RskNetworkUpgrade::Lovell700),
            (8_052_200, RskNetworkUpgrade::Reed800),
            (8_804_200, RskNetworkUpgrade::Vetiver900),
        ] {
            assert!(
                m.active_upgrade(height) >= upgrade,
                "mainnet {upgrade:?} must be active at {height}"
            );
            assert!(
                m.active_upgrade(height - 1) < upgrade,
                "mainnet {upgrade:?} must NOT be active at {}",
                height - 1
            );
        }

        let t = RskHardforkConfig::testnet();
        // rskj config/testnet.conf. bahamas/orchid/orchid060/wasabi100 = 0.
        assert!(t.active_upgrade(0) >= RskNetworkUpgrade::Wasabi100);
        for (height, upgrade) in [
            (504_000u64, RskNetworkUpgrade::TwoToThree),
            (863_000, RskNetworkUpgrade::Papyrus200),
            (2_060_500, RskNetworkUpgrade::Iris300),
            (3_103_000, RskNetworkUpgrade::Hop400),
            (4_015_800, RskNetworkUpgrade::Fingerroot500),
            (4_927_100, RskNetworkUpgrade::Arrowhead600),
            (6_110_487, RskNetworkUpgrade::Lovell700),
            (6_835_700, RskNetworkUpgrade::Reed800),
            (7_139_600, RskNetworkUpgrade::Reed810),
            (7_604_200, RskNetworkUpgrade::Vetiver900),
        ] {
            assert!(
                t.active_upgrade(height) >= upgrade,
                "testnet {upgrade:?} must be active at {height}"
            );
            assert!(
                t.active_upgrade(height - 1) < upgrade,
                "testnet {upgrade:?} must NOT be active at {}",
                height - 1
            );
        }
        // arrowhead631 = -1 on testnet: the ladder must never report it.
        assert!(t.active_upgrade(u64::MAX) >= RskNetworkUpgrade::Vetiver900);
    }
    use super::*;

    #[test]
    fn test_mainnet_genesis_is_byzantium() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(0), SpecId::BYZANTIUM);
        assert_eq!(cfg.spec_id(728_999), SpecId::BYZANTIUM);
    }

    #[test]
    fn test_mainnet_rskip150_at_two_to_three() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip150(2_017_999));
        assert!(cfg.has_rskip150(2_018_000));
        // twoToThree keeps the PETERSBURG spec and wasabi features.
        assert_eq!(cfg.spec_id(2_018_000), SpecId::PETERSBURG);
        assert!(cfg.has_rskip125(2_018_000));
        // ...but not papyrus features.
        assert!(!cfg.has_rskip140(2_018_000));
        assert!(cfg.has_rskip150(2_392_700));
    }

    #[test]
    fn test_mainnet_papyrus_is_petersburg() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(2_392_700), SpecId::PETERSBURG);
        assert!(!cfg.has_chainid(2_392_699));
        assert!(cfg.has_chainid(2_392_700));
    }

    #[test]
    fn test_mainnet_arrowhead_is_istanbul() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(6_223_700), SpecId::ISTANBUL);
        assert!(cfg.has_reduced_calldata_cost(6_223_700));
        assert!(!cfg.has_reduced_calldata_cost(6_223_699));
    }

    #[test]
    fn test_mainnet_push0_activates_at_arrowhead600() {
        // RSKIP398: rskj enables PUSH0 at arrowhead600, NOT at lovell700.
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_push0(6_223_699));
        assert!(cfg.has_push0(6_223_700));
        assert!(cfg.has_push0(7_338_024)); // still on at lovell700+
    }

    #[test]
    fn test_mainnet_lovell_is_shanghai() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(7_338_024), SpecId::SHANGHAI);
        assert!(cfg.has_initcode_metering(7_338_024));
    }

    #[test]
    fn test_all_active() {
        let cfg = RskHardforkConfig::all_active(33);
        assert_eq!(cfg.spec_id(0), SpecId::SHANGHAI);
        assert!(cfg.has_chainid(0));
        assert!(cfg.has_reduced_calldata_cost(0));
        assert!(cfg.has_initcode_metering(0));
        assert_eq!(cfg.chain_id, 33);
    }

    #[test]
    fn test_upgrade_ordering() {
        assert!(RskNetworkUpgrade::Genesis < RskNetworkUpgrade::Orchid);
        assert!(RskNetworkUpgrade::Orchid < RskNetworkUpgrade::Papyrus200);
        assert!(RskNetworkUpgrade::Papyrus200 < RskNetworkUpgrade::Arrowhead600);
        assert!(RskNetworkUpgrade::Arrowhead600 < RskNetworkUpgrade::Lovell700);
        assert!(RskNetworkUpgrade::Lovell700 < RskNetworkUpgrade::Reed800);
    }

    // -----------------------------------------------------------------------
    // RSKIP activation tests — ported from rskj activation height tables
    // -----------------------------------------------------------------------

    /// RSKIP87 (unlimited whitelist) activates at Orchid (mainnet 729_000).
    #[test]
    fn test_rskip87_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip87(728_999));
        assert!(cfg.has_rskip87(729_000));
    }

    /// RSKIP146 (queue with tx hash) activates at Papyrus200 (mainnet 2_392_700).
    #[test]
    fn test_rskip146_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip146(2_392_699));
        assert!(cfg.has_rskip146(2_392_700));
    }

    /// RSKIP271 (peg-out batching) activates at Hop400 (mainnet 4_598_500).
    #[test]
    fn test_rskip271_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip271(4_598_499));
        assert!(cfg.has_rskip271(4_598_500));
    }

    /// RSKIP376 activates at Arrowhead600 (mainnet 6_223_700). Migration txs
    /// switch from version 1 to version 2 at that boundary (the
    /// buildMigrationTransaction version override is dropped). First mainnet
    /// migration after the boundary: #7,069,808 (groundtruth txids d2ca62b5… and
    /// 7befa0dd… are version 2).
    #[test]
    fn test_rskip376_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip376(6_223_699));
        assert!(cfg.has_rskip376(6_223_700));
        assert!(cfg.has_rskip376(7_069_808));
    }

    /// RSKIP445 (MCOPY) and RSKIP446 (TLOAD/TSTORE) activate at Lovell700
    /// (mainnet 7_338_024). First mainnet use: #7,338,135 (a TSTORE in tx[11]).
    #[test]
    fn test_rskip445_rskip446_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip445(7_338_023));
        assert!(cfg.has_rskip445(7_338_024));
        assert!(!cfg.has_rskip446(7_338_023));
        assert!(cfg.has_rskip446(7_338_024));
    }

    /// RSKIP185 and RSKIP176 activate at Iris300 (mainnet 3_614_800).
    #[test]
    fn test_rskip185_rskip176_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip185(3_614_799));
        assert!(cfg.has_rskip185(3_614_800));
        assert!(!cfg.has_rskip176(3_614_799));
        assert!(cfg.has_rskip176(3_614_800));
    }

    /// All RSKIPs active with all_active config.
    #[test]
    fn test_all_rskips_active() {
        let cfg = RskHardforkConfig::all_active(33);
        assert!(cfg.has_rskip87(0));
        assert!(cfg.has_rskip146(0));
        assert!(cfg.has_rskip176(0));
        assert!(cfg.has_rskip185(0));
        assert!(cfg.has_rskip219(0));
        assert!(cfg.has_rskip271(0));
        assert!(cfg.has_rskip536(0));
        assert!(cfg.has_rskip540(0));
        assert!(cfg.has_rskip544(0));
        assert!(cfg.has_rskip551(0));
        assert!(cfg.has_rskip552(0));
    }

    /// Vetiver900 activates at mainnet 8_804_200 (rskj main.conf), skipping
    /// reed810 which is -1 on mainnet.
    #[test]
    fn test_vetiver900_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.active_upgrade(8_804_199), RskNetworkUpgrade::Reed800);
        assert_eq!(cfg.active_upgrade(8_804_200), RskNetworkUpgrade::Vetiver900);
        for has in [
            RskHardforkConfig::has_rskip540,
            RskHardforkConfig::has_rskip544,
            RskHardforkConfig::has_rskip551,
            RskHardforkConfig::has_rskip552,
        ] {
            assert!(!has(&cfg, 8_804_199));
            assert!(has(&cfg, 8_804_200));
        }
        // rskip536 is overridden to the vetiver900 height on mainnet
        // (main.conf consensusRules: rskip536 = 8804200).
        assert!(!cfg.has_rskip536(8_804_199));
        assert!(cfg.has_rskip536(8_804_200));
    }

    /// Testnet: reed810 at 7_139_600, vetiver900 at 7_604_200 (rskj testnet.conf).
    #[test]
    fn test_vetiver900_testnet() {
        let cfg = RskHardforkConfig::testnet();
        assert_eq!(cfg.active_upgrade(7_139_599), RskNetworkUpgrade::Reed800);
        assert_eq!(cfg.active_upgrade(7_139_600), RskNetworkUpgrade::Reed810);
        assert_eq!(cfg.active_upgrade(7_604_200), RskNetworkUpgrade::Vetiver900);
        // rskip536 maps to reed810 on testnet (reference.conf).
        assert!(!cfg.has_rskip536(7_139_599));
        assert!(cfg.has_rskip536(7_139_600));
        // vetiver900-mapped rskips activate later.
        assert!(!cfg.has_rskip544(7_604_199));
        assert!(cfg.has_rskip544(7_604_200));
    }

    /// RSKIP357 (hop401 #4,976,300) / RSKIP374 (fingerroot500 #5,468,000) gate
    /// the special-case funds-migration window end on mainnet. Regression for
    /// #5,009,384: a retiring-federation migration spanning this window must use
    /// the extended end (172,800), not the normal 10,585.
    #[test]
    fn test_special_case_funds_migration_window_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip357(4_976_299));
        assert!(cfg.has_rskip357(4_976_300));
        assert!(!cfg.has_rskip374(5_467_999));
        assert!(cfg.has_rskip374(5_468_000));
        // The special case applies exactly on [hop401, fingerroot500).
        let special = |n: u64| cfg.has_rskip357(n) && !cfg.has_rskip374(n);
        assert!(!special(4_976_299));
        assert!(special(4_976_300));
        assert!(special(5_009_384)); // the divergent block
        assert!(special(5_467_999));
        assert!(!special(5_468_000));
    }
}

#[cfg(test)]
mod override_tests {
    use super::*;

    fn h(name: &str, height: i64) -> (String, Option<u64>) {
        (name.to_string(), u64::try_from(height).ok())
    }

    /// The schedule perf-lab's mainnet seed runs under: mainnet's heights,
    /// plus reed810, tbd1000, rskip351 and rskip535 at #9,002,504 and
    /// rskip536 at #8,804,200.
    fn seed_ladder() -> (RskHardforkConfig, Vec<String>) {
        let hardforks = [
            h("bahamas", 3397), h("afterBridgeSync", 370_000), h("orchid", 729_000),
            h("orchid060", 1_052_700), h("wasabi100", 1_591_000), h("twoToThree", 2_018_000),
            h("papyrus200", 2_392_700), h("iris300", 3_614_800), h("hop400", 4_598_500),
            h("hop401", 4_976_300), h("fingerroot500", 5_468_000),
            h("arrowhead600", 6_223_700), h("arrowhead631", 6_549_300),
            h("lovell700", 7_338_024), h("reed800", 8_052_200), h("reed810", 9_002_504),
            h("vetiver900", 8_804_200), h("tbd1000", 9_002_504),
        ];
        let rules = [
            h("rskipUMM", 2_392_700), h("rskip351", 9_002_504),
            h("rskip535", 9_002_504), h("rskip536", 8_804_200),
        ];
        RskHardforkConfig::mainnet().with_rskj_overrides(&hardforks, &rules).unwrap()
    }

    #[test]
    fn the_seed_schedule_turns_reed810_on_above_vetiver900() {
        let (cfg, unmodelled) = seed_ladder();
        assert_eq!(unmodelled, vec!["orchid060".to_string(), "tbd1000".to_string()]);
        assert_eq!(cfg.activation_height(RskNetworkUpgrade::Reed810), Some(9_002_504));
        assert!(!cfg.has_rskip144(9_002_503));
        assert!(cfg.has_rskip144(9_002_504));
        assert!(cfg.has_rskip351(9_003_580));
        assert!(!cfg.has_rskip535(9_002_503), "rskip535 moved off vetiver900");
        assert!(cfg.has_rskip535(9_002_504));
        assert!(cfg.has_rskip536(8_804_200));
        assert!(cfg.is_activating(RskNetworkUpgrade::Reed810, 9_002_504));
        // A lower rung scheduled above a higher one does not demote the chain.
        assert_eq!(cfg.active_upgrade(9_003_580), RskNetworkUpgrade::Vetiver900);
        assert_eq!(cfg.spec_id(9_003_580), SpecId::SHANGHAI);
        assert!(cfg.has_rskip544(9_003_580));
        // Everything below the seed's fork point is mainnet's.
        let main = RskHardforkConfig::mainnet();
        for n in [0, 729_000, 2_392_700, 6_549_300, 8_804_200, 9_002_503] {
            assert_eq!(cfg.active_upgrade(n), main.active_upgrade(n), "at #{n}");
            assert_eq!(cfg.has_rskip536(n), main.has_rskip536(n), "rskip536 at #{n}");
        }
    }

    #[test]
    fn mainnet_without_overrides_is_unchanged() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.rule_overrides, Vec::new());
        assert_eq!(cfg.activation_height(RskNetworkUpgrade::Reed810), None);
        assert!(!cfg.has_rskip144(9_003_580));
        assert!(!cfg.has_rskip351(9_003_580));
        assert!(cfg.has_rskip535(8_804_200));
        assert!(!cfg.has_rskip535(8_804_199));
        assert!(cfg.has_rskip536(8_804_200));
        assert_eq!(cfg.active_upgrade(8_804_200), RskNetworkUpgrade::Vetiver900);
        assert_eq!(cfg.active_upgrade(8_804_199), RskNetworkUpgrade::Reed800);
        assert_eq!(cfg.active_upgrade(0), RskNetworkUpgrade::Genesis);
        let testnet = RskHardforkConfig::testnet();
        assert_eq!(testnet.active_upgrade(0), RskNetworkUpgrade::Wasabi100);
        assert_eq!(testnet.active_upgrade(7_139_600), RskNetworkUpgrade::Reed810);
    }

    #[test]
    fn a_fixed_rung_is_accepted_only_where_this_node_reads_it() {
        let ok = RskHardforkConfig::mainnet()
            .with_rskj_overrides(&[h("hop401", 4_976_300)], &[]);
        assert!(ok.is_ok());
        let moved = RskHardforkConfig::mainnet()
            .with_rskj_overrides(&[h("hop401", 5_000_000)], &[]);
        assert!(moved.is_err());
        let umm = RskHardforkConfig::mainnet()
            .with_rskj_overrides(&[], &[h("rskipUMM", 1)]);
        assert!(umm.is_err());
        let unknown = RskHardforkConfig::mainnet()
            .with_rskj_overrides(&[h("quartz", 1)], &[]);
        assert!(unknown.is_err());
        let rule = RskHardforkConfig::mainnet()
            .with_rskj_overrides(&[], &[h("rskip97", 1)]);
        assert!(rule.is_err());
    }

    #[test]
    fn minus_one_takes_a_rung_off_the_ladder() {
        let (cfg, _) = RskHardforkConfig::testnet()
            .with_rskj_overrides(&[h("reed810", -1)], &[h("rskip535", -1)])
            .unwrap();
        assert_eq!(cfg.activation_height(RskNetworkUpgrade::Reed810), None);
        assert!(!cfg.has_rskip144(8_000_000));
        assert!(!cfg.has_rskip535(8_000_000));
        assert_eq!(cfg.active_upgrade(7_604_200), RskNetworkUpgrade::Vetiver900);
    }
}
