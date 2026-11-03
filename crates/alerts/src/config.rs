//! Configuration, read from a TOML file.
//!
//! Every threshold and address is configurable because the sensible value is an
//! operational judgement, not a property of the chain. Defaults are set so that
//! a file with only `enabled = true` behaves the way the feature was asked for:
//! alert above 100 BTC per peg-out and per output, and above 200 BTC in transit.

use serde::Deserialize;
use std::path::Path;

/// One BTC in satoshis. Thresholds are given in BTC in the file because that is
/// how people think about peg-outs; everything internal is satoshis.
pub const SATOSHIS_PER_BTC: u64 = 100_000_000;
/// RBTC is quoted in wei (18 decimals) and BTC in satoshis (8), so one
/// satoshi of RBTC is 10^10 wei. Used to carry a BTC-denominated threshold
/// into the wei-denominated world of the EVM.
pub const WEI_PER_SATOSHI: u64 = 10_000_000_000;

fn default_true() -> bool { true }
fn default_poll_secs() -> u64 { 5 }
fn default_pegout_btc() -> f64 { 100.0 }
fn default_output_btc() -> f64 { 100.0 }
fn default_in_transit_btc() -> f64 { 200.0 }
fn default_in_transit_report_secs() -> u64 { 600 }
fn default_confirmations() -> u64 { 4_000 }
fn default_smtp_port() -> u16 { 587 }
fn default_queue() -> usize { 256 }
fn default_contract_transfer_btc() -> f64 { 50.0 }
fn default_max_catchup_blocks() -> u64 { 128 }
fn default_replay_filter_btc() -> f64 { 0.1 }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub alerts: Alerts,
}

/// Everything this node alerts about, and the one transport it alerts through.
///
/// Shaped so a third kind of alert is a new section rather than a second file:
/// `[alerts.email]` is the shared delivery, and each `[alerts.<kind>]` decides
/// what to watch. One transport means one credential, which is one thing to
/// keep current instead of several that drift.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    /// How alerts are delivered. Shared by every kind below.
    #[serde(default)]
    pub email: EmailConfig,
    /// Peg-outs above a threshold, and the value in transit.
    #[serde(default)]
    pub pegout: PegoutAlerts,
    /// Stalled, behind the network, or ahead of every peer.
    #[serde(default)]
    pub node_health: NodeHealth,
    /// Large value transfers in or out of a smart contract.
    #[serde(default)]
    pub contract_value: ContractValueAlerts,
}

fn default_health_gap() -> u64 { 10 }
fn default_health_for_secs() -> u64 { 600 }
fn default_health_cooldown_secs() -> u64 { 86_400 }
fn default_health_poll_secs() -> u64 { 30 }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHealth {
    /// Off by default, like every other alerting surface here.
    #[serde(default)]
    pub enabled: bool,
    /// How often to take a reading. Well below `for_secs`, or a condition
    /// could come and go between polls unseen.
    #[serde(default = "default_health_poll_secs")]
    pub poll_interval_secs: u64,
    /// Blocks of difference before "behind" or "ahead" is true at all.
    #[serde(default = "default_health_gap")]
    pub block_gap: u64,
    /// How long a condition must hold continuously before it is reported.
    #[serde(default = "default_health_for_secs")]
    pub for_secs: u64,
    /// How long that alarm stays quiet after firing. Not reset by recovery.
    #[serde(default = "default_health_cooldown_secs")]
    pub cooldown_secs: u64,
}

impl Default for NodeHealth {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_secs: default_health_poll_secs(),
            block_gap: default_health_gap(),
            for_secs: default_health_for_secs(),
            cooldown_secs: default_health_cooldown_secs(),
        }
    }
}

impl Alerts {
    /// Reject a transport that cannot deliver, at startup rather than at the
    /// moment an alert needs to go out.
    pub fn validate_email(&self) -> anyhow::Result<()> {
        if !self.email.enabled {
            return Ok(());
        }
        if self.email.to.is_empty() {
            anyhow::bail!("alerts.email.enabled is true but `to` is empty");
        }
        if self.email.from.trim().is_empty() {
            anyhow::bail!("alerts.email.enabled is true but `from` is empty");
        }
        if self.email.smtp_host.trim().is_empty() {
            anyhow::bail!("alerts.email.enabled is true but `smtp_host` is empty");
        }
        Ok(())
    }

    /// Load the referenced env file and expand every `${NAME}` in the email
    /// section. Runs before validation, so a reference resolving to an empty
    /// string is caught as a missing setting rather than as a working one.
    pub fn resolve_secrets(&mut self) -> anyhow::Result<()> {
        let vars = match &self.email.env_file {
            Some(p) => read_env_file(Path::new(p))?,
            None => std::collections::HashMap::new(),
        };
        self.email.from = expand(&self.email.from, &vars)?;
        self.email.smtp_host = expand(&self.email.smtp_host, &vars)?;
        for t in self.email.to.iter_mut() {
            *t = expand(t, &vars)?;
        }
        if let Some(u) = &self.email.username {
            self.email.username = Some(expand(u, &vars)?);
        }
        if let Some(p) = &self.email.password {
            self.email.password = Some(expand(p, &vars)?);
        }
        Ok(())
    }
}

impl NodeHealth {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.poll_interval_secs == 0 {
            anyhow::bail!("node_health.poll_interval_secs must be greater than zero");
        }
        if self.for_secs == 0 {
            anyhow::bail!("node_health.for_secs must be greater than zero");
        }
        // A poll slower than the window means a condition can hold for its
        // full duration between two readings and never be seen.
        if self.poll_interval_secs > self.for_secs {
            anyhow::bail!(
                "node_health.poll_interval_secs ({}) exceeds for_secs ({}); a condition \
                 could hold for its whole window between two readings and go unseen",
                self.poll_interval_secs,
                self.for_secs
            );
        }
        Ok(())
    }

    pub fn thresholds(&self) -> crate::health::HealthThresholds {
        crate::health::HealthThresholds {
            block_gap: self.block_gap,
            for_secs: self.for_secs,
            cooldown_secs: self.cooldown_secs,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PegoutAlerts {
    /// Off unless asked for: a node that has not been configured for alerting
    /// should not start a watcher.
    #[serde(default)]
    pub enabled: bool,
    /// How often to look for newly executed blocks.
    #[serde(default = "default_poll_secs")]
    pub poll_interval_secs: u64,
    /// Where to begin. `None` starts at the node's current executed head, which
    /// is what you want when switching this on for the first time — otherwise
    /// it would replay and re-alert the entire chain.
    #[serde(default)]
    pub start_block: Option<u64>,
    /// Alert when a single peg-out request exceeds this.
    #[serde(default = "default_pegout_btc")]
    pub pegout_alert_btc: f64,
    /// Alert when any non-change output of a peg-out BTC transaction exceeds
    /// this.
    #[serde(default = "default_output_btc")]
    pub output_alert_btc: f64,
    /// Alert when the total value of peg-outs awaiting confirmation exceeds
    /// this.
    #[serde(default = "default_in_transit_btc")]
    pub in_transit_alert_btc: f64,
    /// How often to report the total value in transit, in seconds. `0`
    /// disables the report.
    ///
    /// This is a *report*, not an alert: it fires whatever the total is, as
    /// long as it is non-zero, so an operator can see money moving rather than
    /// only being told when it exceeds a threshold. Peg-outs take 4,000
    /// confirmations to clear, so ten minutes is frequent enough to watch one
    /// progress and rare enough not to fill the log.
    #[serde(default = "default_in_transit_report_secs")]
    pub in_transit_report_secs: u64,
    /// Confirmations a peg-out needs before it leaves "in transit". Mainnet
    /// uses 4,000; it is configurable because testnet and regtest do not.
    #[serde(default = "default_confirmations")]
    pub confirmations: u64,
    /// Bound on undelivered alerts. Alerts are dropped rather than queued
    /// without limit if a mail server is unreachable for a long time; the drop
    /// is counted and logged.
    #[serde(default = "default_queue")]
    pub max_queued_alerts: usize,
    /// scriptPubKeys (hex) that are federation change, not a transfer to an end
    /// user. Outputs paying these are excluded from the per-output check and
    /// from the in-transit total.
    ///
    /// Empty by default, which means **every** output is treated as a user
    /// output. That over-alerts on a large change output; it can never hide a
    /// real transfer. Fill this in to silence the change output precisely.
    #[serde(default)]
    pub federation_change_scripts: Vec<String>,
}

impl Default for PegoutAlerts {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_secs: default_poll_secs(),
            start_block: None,
            pegout_alert_btc: default_pegout_btc(),
            output_alert_btc: default_output_btc(),
            in_transit_alert_btc: default_in_transit_btc(),
            in_transit_report_secs: default_in_transit_report_secs(),
            confirmations: default_confirmations(),
            max_queued_alerts: default_queue(),
            federation_change_scripts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    /// Path to a `KEY=VALUE` file holding the secrets this section refers to.
    ///
    /// Credentials must never be written into the configuration file, because
    /// that file lives next to the code and gets copied, diffed and pasted.
    /// Put them in a file owned by the node user with mode 0600 and refer to
    /// them here as `${SMTP_PASSWORD}`; the watcher expands those at startup
    /// and the expanded values are never logged.
    #[serde(default)]
    pub env_file: Option<String>,
    /// When false (the default) alerts are logged and nothing is sent, which is
    /// how this runs until SMTP credentials are supplied.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// `none`, `starttls` or `implicit`.
    #[serde(default)]
    pub tls: TlsMode,
    #[serde(default = "default_true")]
    pub subject_prefix_enabled: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    None,
    #[default]
    Starttls,
    Implicit,
}

/// Large value transfers in or out of a smart contract.
///
/// Unlike every other watch in this crate, this one cannot be answered from
/// what the node stored: a value transfer emits no log and writes nothing to
/// the receipt, so the block is re-executed with the call tracer attached.
/// That costs real CPU — see [`crate::value`] — which is why it is off by
/// default and why `max_catchup_blocks` exists.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractValueAlerts {
    /// Off unless asked for.
    #[serde(default)]
    pub enabled: bool,
    /// Alert when a single transfer with a contract on either side exceeds
    /// this many RBTC.
    ///
    /// Deliberately its own setting rather than reusing the peg-out
    /// threshold: a peg-out is the federation moving bitcoin, and a contract
    /// payment is not the same event at the same scale.
    #[serde(default = "default_contract_transfer_btc")]
    pub transfer_alert_btc: f64,
    /// How far behind the executed head this watch will still re-execute.
    ///
    /// A node that was stopped for a day, or that is still syncing, comes
    /// back with thousands of blocks to sweep. Re-executing all of them would
    /// turn a backlog into an outage, so blocks further back than this are
    /// swept for peg-outs — which is cheap — and not traced. The skipped
    /// range is logged, so a gap in this watch is never silent.
    #[serde(default = "default_max_catchup_blocks")]
    pub max_catchup_blocks: u64,
    /// Do not re-execute a block unless some account's balance moved more
    /// than this many RBTC.
    ///
    /// The node already computes every account's balance delta for every
    /// block, as part of the supply check, so this filter is free and skips
    /// essentially every block: over 300 consecutive mainnet blocks in
    /// November 2026 the largest single transfer in a block was 2.0 RBTC and
    /// the median was zero.
    ///
    /// **Deliberately far below `transfer_alert_btc`, and it must stay
    /// below it.** A delta is a net figure, so a transfer hides from this
    /// filter only if the value came back inside the same block -- a closed
    /// cycle, most realistically a flash loan. At 0.1 RBTC such a cycle has
    /// to leave every account within 0.1 RBTC of where it started, which is
    /// to say nobody profited. Raising it towards the alert threshold widens
    /// that hole for no measurable saving, which is why a value at or above
    /// `transfer_alert_btc` is refused.
    ///
    /// Zero re-executes every block, which is the behaviour before this
    /// filter existed. Kept reachable as the control.
    #[serde(default = "default_replay_filter_btc")]
    pub replay_filter_btc: f64,
}

impl Default for ContractValueAlerts {
    fn default() -> Self {
        Self {
            enabled: false,
            transfer_alert_btc: default_contract_transfer_btc(),
            max_catchup_blocks: default_max_catchup_blocks(),
            replay_filter_btc: default_replay_filter_btc(),
        }
    }
}

impl ContractValueAlerts {
    /// The threshold in wei.
    ///
    /// Routed through satoshis rather than multiplying the float by 1e18
    /// directly: `f64` has 53 bits of mantissa and cannot represent most
    /// wei-scale integers, so `50.0 * 1e18` is not 50 RBTC. A threshold is
    /// wanted to satoshi precision at most, and this way the rounding is the
    /// same one `pegout_alert_btc` already gets.
    pub fn transfer_alert_wei(&self) -> alloy_primitives::U256 {
        alloy_primitives::U256::from(btc_to_sats(self.transfer_alert_btc))
            * alloy_primitives::U256::from(WEI_PER_SATOSHI)
    }

    /// The re-execution filter in wei, by the same route.
    pub fn replay_filter_wei(&self) -> alloy_primitives::U256 {
        alloy_primitives::U256::from(btc_to_sats(self.replay_filter_btc))
            * alloy_primitives::U256::from(WEI_PER_SATOSHI)
    }

    /// What a running watcher can adopt, and what needs a restart.
    pub fn describe_changes(&self, new: &ContractValueAlerts) -> (Vec<String>, Vec<String>) {
        let mut live = Vec::new();
        let mut restart = Vec::new();
        if self.transfer_alert_btc != new.transfer_alert_btc {
            live.push(format!(
                "contract_value.transfer_alert_btc: {} -> {}",
                self.transfer_alert_btc, new.transfer_alert_btc
            ));
        }
        if self.max_catchup_blocks != new.max_catchup_blocks {
            live.push(format!(
                "contract_value.max_catchup_blocks: {} -> {}",
                self.max_catchup_blocks, new.max_catchup_blocks
            ));
        }
        if self.replay_filter_btc != new.replay_filter_btc {
            live.push(format!(
                "contract_value.replay_filter_btc: {} -> {}",
                self.replay_filter_btc, new.replay_filter_btc
            ));
        }
        // Whether this watch runs at all decides whether the watcher built a
        // block processor, which happens once at startup.
        if self.enabled != new.enabled {
            restart.push(format!(
                "contract_value.enabled: {} -> {}",
                self.enabled, new.enabled
            ));
        }
        (live, restart)
    }

    pub fn adopt_live(&mut self, new: &ContractValueAlerts) {
        self.transfer_alert_btc = new.transfer_alert_btc;
        self.max_catchup_blocks = new.max_catchup_blocks;
        self.replay_filter_btc = new.replay_filter_btc;
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !(self.transfer_alert_btc.is_finite() && self.transfer_alert_btc >= 0.0) {
            anyhow::bail!(
                "alerts.contract_value.transfer_alert_btc must be a non-negative number, got {}",
                self.transfer_alert_btc
            );
        }
        // Zero would alert on every transfer a contract makes, which on a
        // busy block is thousands of mails. Refuse it rather than discover it
        // at three in the morning.
        if self.transfer_alert_wei().is_zero() {
            anyhow::bail!(
                "alerts.contract_value.transfer_alert_btc is {} RBTC, which rounds to zero and \
                 would alert on every transfer; set a real threshold",
                self.transfer_alert_btc
            );
        }
        if self.max_catchup_blocks == 0 {
            anyhow::bail!(
                "alerts.contract_value.max_catchup_blocks must be greater than zero, or this \
                 watch would never run"
            );
        }
        if !(self.replay_filter_btc.is_finite() && self.replay_filter_btc >= 0.0) {
            anyhow::bail!(
                "alerts.contract_value.replay_filter_btc must be a non-negative number, got {}",
                self.replay_filter_btc
            );
        }
        // A filter at or above the alert threshold can skip a block holding a
        // transfer that would have alerted and did not net out at all, which
        // makes the filter -- not `transfer_alert_btc` -- the real threshold.
        // Refuse rather than let the configuration mean something other than
        // what it says.
        if self.replay_filter_wei() >= self.transfer_alert_wei() {
            anyhow::bail!(
                "alerts.contract_value.replay_filter_btc ({}) must be below \
                 transfer_alert_btc ({}), or blocks holding a reportable transfer could be \
                 skipped before anything looks at them",
                self.replay_filter_btc,
                self.transfer_alert_btc
            );
        }
        Ok(())
    }
}

impl PegoutAlerts {
    pub fn pegout_alert_sats(&self) -> u64 { btc_to_sats(self.pegout_alert_btc) }
    pub fn output_alert_sats(&self) -> u64 { btc_to_sats(self.output_alert_btc) }
    pub fn in_transit_alert_sats(&self) -> u64 { btc_to_sats(self.in_transit_alert_btc) }


    /// Decode `federation_change_scripts` from hex.
    pub fn change_scripts(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        self.federation_change_scripts
            .iter()
            .map(|h| hex::decode(h.trim_start_matches("0x")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("federation_change_scripts must be hex: {e}"))
    }

    /// What differs between this configuration and `new`, split into what the
    /// running watcher can adopt and what it cannot.
    ///
    /// The live set is the tuning you actually want to change against a running
    /// node: thresholds, the confirmation depth, the change-script list and the
    /// poll interval. The restart set is everything whose effect was decided
    /// when the watcher was built — whether it runs at all, where it started,
    /// and how mail is delivered. Reporting the second set is the point: a
    /// silently ignored edit is worse than one that says it needs a restart.
    pub fn describe_changes(&self, new: &PegoutAlerts) -> (Vec<String>, Vec<String>) {
        let mut live = Vec::new();
        let mut restart = Vec::new();
        let mut f = |name: &str, a: String, b: String, live_field: bool| {
            if a != b {
                let line = format!("{name}: {a} -> {b}");
                if live_field { live.push(line) } else { restart.push(line) }
            }
        };
        f("pegout_alert_btc", self.pegout_alert_btc.to_string(), new.pegout_alert_btc.to_string(), true);
        f("output_alert_btc", self.output_alert_btc.to_string(), new.output_alert_btc.to_string(), true);
        f("in_transit_alert_btc", self.in_transit_alert_btc.to_string(), new.in_transit_alert_btc.to_string(), true);
        f("in_transit_report_secs", self.in_transit_report_secs.to_string(), new.in_transit_report_secs.to_string(), true);
        f("confirmations", self.confirmations.to_string(), new.confirmations.to_string(), true);
        f("poll_interval_secs", self.poll_interval_secs.to_string(), new.poll_interval_secs.to_string(), true);
        f(
            "federation_change_scripts",
            format!("{} entries", self.federation_change_scripts.len()),
            format!("{} entries", new.federation_change_scripts.len()),
            true,
        );
        f("enabled", self.enabled.to_string(), new.enabled.to_string(), false);
        f("start_block", format!("{:?}", self.start_block), format!("{:?}", new.start_block), false);
        f("max_queued_alerts", self.max_queued_alerts.to_string(), new.max_queued_alerts.to_string(), false);
        (live, restart)
    }

    /// Adopt the fields `describe_changes` reports as live, leaving everything
    /// else — notably the mail settings and the resolved secrets — untouched.
    pub fn adopt_live(&mut self, new: &PegoutAlerts) {
        self.pegout_alert_btc = new.pegout_alert_btc;
        self.output_alert_btc = new.output_alert_btc;
        self.in_transit_alert_btc = new.in_transit_alert_btc;
        self.confirmations = new.confirmations;
        self.poll_interval_secs = new.poll_interval_secs;
        self.federation_change_scripts = new.federation_change_scripts.clone();
    }

    /// Reject a configuration that cannot do what it claims, at startup rather
    /// than at the moment an alert needs to go out.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.poll_interval_secs == 0 {
            anyhow::bail!("alerts.pegout.poll_interval_secs must be greater than zero");
        }
        Ok(())
    }
}

/// BTC (as written in the config) to satoshis, rounded to the nearest satoshi.
pub fn btc_to_sats(btc: f64) -> u64 {
    (btc * SATOSHIS_PER_BTC as f64).round().max(0.0) as u64
}

/// Satoshis to a BTC string, for humans reading an alert.
pub fn sats_to_btc_string(sats: u64) -> String {
    format!("{}.{:08}", sats / SATOSHIS_PER_BTC, sats % SATOSHIS_PER_BTC)
}

/// Wei to an RBTC string, to satoshi precision, for humans reading an alert.
///
/// Eight decimals rather than eighteen on purpose: the extra ten digits are
/// noise in a subject line, and every alert that uses this also prints the
/// exact wei. The value is **truncated**, not rounded, so the printed figure
/// is never larger than what moved.
pub fn wei_to_rbtc_string(wei: alloy_primitives::U256) -> String {
    let per_sat = alloy_primitives::U256::from(WEI_PER_SATOSHI);
    let sats = wei / per_sat;
    // A transfer cannot exceed the 21M-RBTC supply, so this conversion cannot
    // hide a real value; it only avoids a panic on absurd input.
    let sats: u64 = sats.try_into().unwrap_or(u64::MAX);
    sats_to_btc_string(sats)
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        cfg.alerts.resolve_secrets()?;
        cfg.alerts.validate_email()?;
        cfg.alerts.pegout.validate()?;
        cfg.alerts.node_health.validate()?;
        cfg.alerts.contract_value.validate()?;
        Ok(cfg)
    }
}

/// Read a `KEY=VALUE` file. Blank lines and `#` comments are skipped, values
/// may be quoted, and a `export ` prefix is tolerated so the same file can be
/// sourced by a shell.
fn read_env_file(path: &Path) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            // Refuse rather than warn: a credential readable by other users on
            // the box is already disclosed, and continuing would imply it is
            // not.
            anyhow::bail!(
                "{} is readable by group or others (mode {:o}); chmod 600 it",
                path.display(),
                meta.permissions().mode() & 0o777
            );
        }
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"').and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    Ok(out)
}

/// Replace every `${NAME}` with a value from `vars`, falling back to the
/// process environment. An unresolved reference is an error: silently leaving
/// `${SMTP_PASSWORD}` as the literal password would authenticate as that string
/// and fail with a confusing message much later.
fn expand(value: &str, vars: &std::collections::HashMap<String, String>) -> anyhow::Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            anyhow::bail!("unterminated ${{ in configuration value");
        };
        let name = &after[..end];
        let resolved = vars
            .get(name)
            .cloned()
            .or_else(|| std::env::var(name).ok())
            .ok_or_else(|| anyhow::anyhow!("${{{name}}} is not set in the env file or environment"))?;
        out.push_str(&resolved);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_threshold_edit_is_live_but_a_mail_edit_needs_a_restart() {
        let old = PegoutAlerts::default();
        let mut new = old.clone();
        new.pegout_alert_btc = 0.01;
        new.confirmations = 10;
        new.enabled = !old.enabled;

        let (live, restart) = old.describe_changes(&new);
        assert!(live.iter().any(|c| c.starts_with("pegout_alert_btc")), "{live:?}");
        assert!(live.iter().any(|c| c.starts_with("confirmations")), "{live:?}");
        assert!(restart.iter().any(|c| c.starts_with("enabled")), "{restart:?}");
        // Mail cannot appear here at all: the transport is `[alerts.email]`,
        // which this type does not own, so a live reload structurally cannot
        // reach it. That used to be a rule enforced by a test; it is now a
        // property of the shape.
        assert!(!live.iter().any(|c| c.starts_with("email")), "{live:?}");
        assert!(!restart.iter().any(|c| c.starts_with("email")), "{restart:?}");
    }

    #[test]
    fn an_unchanged_file_reports_nothing() {
        let a = PegoutAlerts::default();
        let (live, restart) = a.describe_changes(&a.clone());
        assert!(live.is_empty() && restart.is_empty(), "{live:?} {restart:?}");
    }

    /// **A live reload cannot reach the resolved credentials**, because the
    /// transport is not part of what gets reloaded.
    ///
    /// The watcher re-reads `[alerts.pegout]` and adopts its threshold fields.
    /// `[alerts.email]` is a sibling, so a re-read carrying an unexpanded
    /// `${SMTP_PASSWORD}` has no path to the running transport at all.
    #[test]
    fn a_live_reload_carries_thresholds_and_nothing_else() {
        let mut running = PegoutAlerts::default();
        let from_disk = PegoutAlerts {
            pegout_alert_btc: 0.01,
            confirmations: 17,
            ..PegoutAlerts::default()
        };

        running.adopt_live(&from_disk);
        assert_eq!(running.pegout_alert_btc, 0.01);
        assert_eq!(running.confirmations, 17);
    }

    /// Secrets are expanded on the transport, once, at load.
    #[test]
    fn secrets_are_expanded_on_the_shared_transport() {
        let mut alerts = Alerts::default();
        alerts.email.enabled = true;
        alerts.email.to = vec!["ops@example.com".into()];
        alerts.email.from = "node@example.com".into();
        alerts.email.smtp_host = "smtp.example".into();
        // No env_file, so a plain value passes through untouched...
        alerts.resolve_secrets().expect("no placeholders to expand");
        assert_eq!(alerts.email.smtp_host, "smtp.example");
        alerts.validate_email().expect("a complete transport validates");

        // ...and an incomplete one is refused at load rather than at send.
        alerts.email.to.clear();
        assert!(alerts.validate_email().is_err(), "no recipient must be rejected");
    }

    use super::*;

    #[test]
    fn defaults_match_the_requested_thresholds() {
        let c = PegoutAlerts::default();
        assert_eq!(c.pegout_alert_sats(), 100 * SATOSHIS_PER_BTC);
        assert_eq!(c.output_alert_sats(), 100 * SATOSHIS_PER_BTC);
        assert_eq!(c.in_transit_alert_sats(), 200 * SATOSHIS_PER_BTC);
        assert_eq!(c.confirmations, 4_000);
        assert!(!c.enabled, "must be off unless asked for");
        assert!(!Alerts::default().email.enabled, "must not mail unless asked for");
    }

    #[test]
    fn a_minimal_file_parses() {
        let c: Config = toml::from_str("[alerts.pegout]\nenabled = true\n").unwrap();
        assert!(c.alerts.pegout.enabled);
        assert_eq!(c.alerts.pegout.pegout_alert_sats(), 100 * SATOSHIS_PER_BTC);
    }

    #[test]
    fn thresholds_are_overridable() {
        let c: Config = toml::from_str(
            "[alerts.pegout]\nenabled = true\npegout_alert_btc = 12.5\nin_transit_alert_btc = 0.5\n",
        ).unwrap();
        assert_eq!(c.alerts.pegout.pegout_alert_sats(), 1_250_000_000);
        assert_eq!(c.alerts.pegout.in_transit_alert_sats(), 50_000_000);
    }

    #[test]
    fn a_typo_is_rejected_rather_than_ignored() {
        // deny_unknown_fields: a misspelled threshold must not silently keep
        // the default and leave the operator believing it took effect.
        let r: Result<Config, _> =
            toml::from_str("[alerts.pegout]\nenabled = true\npegout_alert_bt = 5.0\n");
        assert!(r.is_err());
    }

    #[test]
    fn email_without_a_recipient_is_rejected() {
        let c: Config = toml::from_str(
            "[alerts.pegout]\nenabled = true\n[alerts.email]\nenabled = true\nfrom = \"a@b\"\nsmtp_host = \"h\"\n",
        ).unwrap();
        assert!(c.alerts.validate_email().is_err());
    }

    /// **A file in the old shape must fail loudly.** `[pegout_alerts]` was the
    /// section name until the health alarms arrived; a node silently ignoring
    /// such a file would run with alerting off while its operator believed
    /// otherwise, which is the worst outcome available here.
    #[test]
    fn a_file_in_the_old_shape_is_refused() {
        let r: Result<Config, _> = toml::from_str("[pegout_alerts]\nenabled = true\n");
        assert!(r.is_err(), "the old section name must not parse as nothing");
    }

    #[test]
    fn btc_formatting_is_exact() {
        assert_eq!(sats_to_btc_string(100 * SATOSHIS_PER_BTC), "100.00000000");
        assert_eq!(sats_to_btc_string(1), "0.00000001");
        assert_eq!(sats_to_btc_string(250_000_000), "2.50000000");
    }
}

#[cfg(test)]
mod example_file_tests {
    /// The shipped example must stay valid: an example that does not parse is
    /// worse than none.
    #[test]
    fn the_shipped_example_parses_and_validates() {
        let text = include_str!("../../../alerts.example.toml");
        let cfg: super::Config = toml::from_str(text).expect("example must parse");
        cfg.alerts.pegout.validate().expect("example must validate");
        cfg.alerts.node_health.validate().expect("health section must validate");
        cfg.alerts.validate_email().expect("transport must validate");
        assert!(cfg.alerts.pegout.enabled);
        assert!(!cfg.alerts.email.enabled, "example must not mail by default");
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    use std::io::Write;

    fn env_file(body: &str, mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        f
    }

    #[test]
    fn secrets_come_from_the_env_file_not_the_config() {
        let f = env_file("SMTP_USER=someuser\nSMTP_PASSWORD=s3cr3t\n", 0o600);
        let mut c = Alerts {
            email: EmailConfig {
                enabled: true,
                env_file: Some(f.path().display().to_string()),
                to: vec!["ops@example.com".into()],
                from: "node@example.com".into(),
                smtp_host: "smtp.example.com".into(),
                username: Some("${SMTP_USER}".into()),
                password: Some("${SMTP_PASSWORD}".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        c.resolve_secrets().unwrap();
        assert_eq!(c.email.username.as_deref(), Some("someuser"));
        assert_eq!(c.email.password.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn a_world_readable_env_file_is_refused() {
        let f = env_file("SMTP_PASSWORD=s3cr3t\n", 0o644);
        let mut c = Alerts {
            email: EmailConfig {
                enabled: true,
                env_file: Some(f.path().display().to_string()),
                password: Some("${SMTP_PASSWORD}".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = c.resolve_secrets().unwrap_err().to_string();
        assert!(err.contains("readable by group or others"), "{err}");
    }

    #[test]
    fn an_unresolved_reference_is_an_error_not_a_literal_password() {
        let f = env_file("SMTP_USER=someuser\n", 0o600);
        let mut c = Alerts {
            email: EmailConfig {
                enabled: true,
                env_file: Some(f.path().display().to_string()),
                password: Some("${SMTP_PASSWORD}".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = c.resolve_secrets().unwrap_err().to_string();
        assert!(err.contains("SMTP_PASSWORD"), "{err}");
    }

    #[test]
    fn quoted_and_exported_lines_parse() {
        let f = env_file("export SMTP_USER=\"quoted user\"\n# a comment\n\nSMTP_PASSWORD=plain\n", 0o600);
        let vars = read_env_file(f.path()).unwrap();
        assert_eq!(vars.get("SMTP_USER").unwrap(), "quoted user");
        assert_eq!(vars.get("SMTP_PASSWORD").unwrap(), "plain");
    }

    #[test]
    fn a_from_address_with_a_display_name_survives_expansion() {
        let f = env_file("SMTP_FROM=Alerts <alerts@example.com>\n", 0o600);
        let vars = read_env_file(f.path()).unwrap();
        assert_eq!(expand("${SMTP_FROM}", &vars).unwrap(), "Alerts <alerts@example.com>");
    }
}

#[cfg(test)]
mod contract_value_tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn the_threshold_reaches_wei_without_going_through_a_float() {
        let c = ContractValueAlerts { transfer_alert_btc: 50.0, ..Default::default() };
        // 50 RBTC exactly, to the wei. `50.0 * 1e18` as an f64 is not this
        // number, which is the whole reason the conversion goes via satoshis.
        assert_eq!(
            c.transfer_alert_wei(),
            U256::from(50u64) * U256::from(10u64).pow(U256::from(18u64))
        );
    }

    #[test]
    fn a_fractional_threshold_survives_to_satoshi_precision() {
        let c = ContractValueAlerts { transfer_alert_btc: 0.5, ..Default::default() };
        assert_eq!(
            c.transfer_alert_wei(),
            U256::from(5u64) * U256::from(10u64).pow(U256::from(17u64))
        );
    }

    /// Zero would mail on every transfer a contract makes. Catch it when the
    /// file is read, not at three in the morning.
    #[test]
    fn a_threshold_that_rounds_to_zero_is_refused() {
        let c = ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: 0.0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        // Below one satoshi rounds to zero too, and is just as wrong.
        let c = ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: 1e-12,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_disabled_section_is_not_validated() {
        let c = ContractValueAlerts { enabled: false, transfer_alert_btc: 0.0, ..Default::default() };
        assert!(c.validate().is_ok(), "a section that does nothing cannot be misconfigured");
    }

    #[test]
    fn a_zero_catchup_window_is_refused() {
        let c = ContractValueAlerts { enabled: true, max_catchup_blocks: 0, ..Default::default() };
        assert!(c.validate().is_err(), "this watch would never run");
    }

    #[test]
    fn the_threshold_is_live_but_enabling_it_needs_a_restart() {
        let old = ContractValueAlerts::default();
        let new = ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: 10.0,
            max_catchup_blocks: 256,
            replay_filter_btc: 0.5,
        };
        let (live, restart) = old.describe_changes(&new);
        assert_eq!(live.len(), 3, "threshold, window and filter are adoptable: {live:?}");
        assert_eq!(restart.len(), 1, "enabling builds a processor: {restart:?}");
        assert!(restart[0].contains("enabled"));
    }

    #[test]
    fn adopting_live_changes_leaves_enabled_alone() {
        let mut old = ContractValueAlerts::default();
        let new = ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: 10.0,
            max_catchup_blocks: 256,
            replay_filter_btc: 0.5,
        };
        old.adopt_live(&new);
        assert_eq!(old.transfer_alert_btc, 10.0);
        assert_eq!(old.max_catchup_blocks, 256);
        assert_eq!(old.replay_filter_btc, 0.5);
        assert!(!old.enabled, "a running watcher cannot grow a processor");
    }

    /// The section is new, so every deployed configuration file lacks it.
    /// Those files must keep loading, with the watch off.
    #[test]
    fn a_configuration_without_the_section_still_loads_with_it_off() {
        let cfg: Config = toml::from_str(
            r#"
            [alerts.pegout]
            enabled = true
            "#,
        )
        .expect("an older file must still parse");
        assert!(!cfg.alerts.contract_value.enabled);
        assert_eq!(cfg.alerts.contract_value.transfer_alert_btc, 50.0);
    }

    #[test]
    fn the_section_parses_from_toml() {
        let cfg: Config = toml::from_str(
            r#"
            [alerts.contract_value]
            enabled = true
            transfer_alert_btc = 25.5
            max_catchup_blocks = 64
            "#,
        )
        .unwrap();
        let c = cfg.alerts.contract_value;
        assert!(c.enabled);
        assert_eq!(c.transfer_alert_btc, 25.5);
        assert_eq!(c.max_catchup_blocks, 64);
    }

    /// A filter at or above the alert threshold makes the filter the real
    /// threshold, because a block can be skipped before anything looks at the
    /// transfer inside it.
    #[test]
    fn a_filter_at_or_above_the_alert_threshold_is_refused() {
        let at = ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: 50.0,
            replay_filter_btc: 50.0,
            ..Default::default()
        };
        assert!(at.validate().is_err(), "equal is already too high");
        let above = ContractValueAlerts { replay_filter_btc: 60.0, ..at.clone() };
        assert!(above.validate().is_err());
        let below = ContractValueAlerts { replay_filter_btc: 49.9, ..at };
        assert!(below.validate().is_ok());
    }

    /// Zero is the control an operator uses to measure what the filter saves,
    /// so it has to stay reachable.
    #[test]
    fn a_zero_filter_is_allowed() {
        let c = ContractValueAlerts {
            enabled: true,
            transfer_alert_btc: 50.0,
            replay_filter_btc: 0.0,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
        assert!(c.replay_filter_wei().is_zero());
    }

    #[test]
    fn the_filter_defaults_well_below_the_alert_threshold() {
        let c = ContractValueAlerts::default();
        assert!(
            c.replay_filter_wei() * alloy_primitives::U256::from(100u64)
                <= c.transfer_alert_wei(),
            "the default filter should be at least 100x below the default alert threshold"
        );
    }

    #[test]
    fn wei_renders_to_rbtc_truncated_not_rounded() {
        let one = U256::from(10u64).pow(U256::from(18u64));
        assert_eq!(wei_to_rbtc_string(one), "1.00000000");
        // A shade under one satoshi more: it must not round up to .00000001.
        assert_eq!(wei_to_rbtc_string(one + U256::from(9_999_999_999u64)), "1.00000000");
        assert_eq!(wei_to_rbtc_string(one + U256::from(10_000_000_000u64)), "1.00000001");
    }
}
