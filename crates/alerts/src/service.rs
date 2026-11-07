//! The watcher task.
//!
//! Polls the node's own database. It never touches execution, never holds a
//! lock the node needs, and its only inputs are blocks the node has already
//! committed — so no failure here can affect consensus or block rate.

use crate::alert::Alert;
use crate::config::PegoutAlerts;
use crate::config::ContractValueAlerts;
use crate::sink::AlertSink;
use crate::value;
use crate::watch;
use alloy_primitives::{Address, B256, U256};
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Peg-out events worth recording, whether or not they breach a threshold.
/// Requirement: *every* peg-out is logged.
fn pegout_event_names() -> Vec<(B256, &'static str)> {
    let t = |s: &str| B256::from(alloy_primitives::keccak256(s.as_bytes()).0);
    vec![
        (t("release_request_received(address,bytes,uint256)"), "release_request_received"),
        (t("release_request_received(address,bytes20,uint256)"), "release_request_received"),
        (t("release_requested(bytes32,bytes32,uint256)"), "release_requested"),
        (t("release_btc(bytes32,bytes)"), "release_btc"),
        (t("pegout_confirmed(bytes32,uint256)"), "pegout_confirmed"),
        (t("pegout_transaction_created(bytes32,bytes)"), "pegout_transaction_created"),
    ]
}

/// Modification time of `path`, or `None` if it cannot be read right now.
fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Heights re-examined on every sweep, in case the chain moved under them.
///
/// The sweep advances by height and never goes back. Without this, a block
/// that stopped being canonical *after* it was examined is never replaced by
/// the one that took its place, and whatever the replacement contains is
/// never reported.
///
/// That is not hypothetical. This node reorgs at nearly every height on
/// mainnet, and on 2026-11-07 two of seven Flyover peg-outs went unreported
/// for exactly this reason: the watcher looked at #9390291 and #9390496 while
/// a different block was canonical there, and never looked again.
///
/// 128 is far beyond any reorg depth seen here. It costs one canonical-hash
/// lookup per height per poll; the expensive part -- re-examining the block --
/// happens only for a height that actually changed.
const REORG_RECHECK_DEPTH: u64 = 128;

/// What the watcher saw at one height, so a reorg can be noticed afterwards.
#[derive(Debug, Clone)]
struct Examined {
    /// The block that was canonical when this height was examined.
    hash: B256,
    /// Dedup keys of every alert this height produced -- whether or not it
    /// was delivered, so a re-examination can tell which ones vanished with
    /// the block they came from.
    observed: Vec<String>,
}

pub struct Watcher {
    store: Arc<BlockStore>,
    trie: Arc<dyn TrieStore>,
    cfg: PegoutAlerts,
    sinks: Vec<Box<dyn AlertSink>>,
    change_scripts: Vec<Vec<u8>>,
    /// Alerts already delivered, so a condition that persists across polls is
    /// reported once rather than every few seconds.
    seen: HashSet<String>,
    next_block: u64,
    /// Configuration file to re-read when it changes on disk. `None` means the
    /// watcher keeps whatever it was built with.
    config_path: Option<PathBuf>,
    /// Out-of-band alerts pushed in from block processing (supply violations).
    ///
    /// The sender is called on the thread executing blocks, so it must never
    /// block: it drops into this queue and returns, and delivery happens here
    /// on the watcher's own task like any other alert.
    inbox: Option<std::sync::mpsc::Receiver<Alert>>,
    /// Modification time of that file as last seen — whether or not it parsed,
    /// so a broken edit is reported once rather than on every poll.
    config_seen_mtime: Option<SystemTime>,
    /// When the periodic in-transit report last fired.
    last_in_transit_report: std::time::Instant,
    /// Large transfers in or out of a contract. Disabled unless a processor
    /// was handed in: finding these means re-executing the block, and a
    /// watcher with no processor has nothing to re-execute with.
    contract: ContractValueAlerts,
    processor: Option<Arc<rustock_execution::BlockProcessor>>,
    chain_id: u64,
    /// What the node's own execution saw each block move. Consulted before
    /// re-executing anything; see [`crate::movement`].
    movements: Option<Arc<crate::movement::MovementLog>>,
    /// Counted per sweep, for the one line at the end of it.
    replays: u64,
    filtered: u64,
    unrecorded: Option<(u64, u64)>,
    /// Blocks this sweep declined to re-execute, and why. Summarised once per
    /// sweep rather than logged per block, so a long catch-up reports a range
    /// instead of thousands of lines -- but is never silent about the gap.
    skipped_too_far: Option<(u64, u64)>,
    skipped_no_state: Option<(u64, u64)>,
    /// Recently examined heights and what they held, for reorg detection.
    /// Bounded to [`REORG_RECHECK_DEPTH`] entries behind the head.
    examined: BTreeMap<u64, Examined>,
    /// Alert keys seen while examining the current block. Scratch, cleared
    /// per block and moved into `examined` when the block is done.
    observed: Vec<String>,
    rechecked: u64,
}

impl Watcher {
    pub fn new(
        store: Arc<BlockStore>,
        trie: Arc<dyn TrieStore>,
        cfg: PegoutAlerts,
        sinks: Vec<Box<dyn AlertSink>>,
        change_scripts: Vec<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        cfg.validate()?;
        // Default to the current head: switching alerting on should not replay
        // and re-alert the whole chain.
        let head = store
            .exec_head()?
            .and_then(|(h, _)| store.header(h).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);
        let next_block = cfg.start_block.unwrap_or(head.saturating_add(1));
        Ok(Self {
            store,
            trie,
            cfg,
            sinks,
            change_scripts,
            seen: HashSet::new(),
            next_block,
            config_path: None,
            config_seen_mtime: None,
            last_in_transit_report: std::time::Instant::now(),
            inbox: None,
            contract: ContractValueAlerts::default(),
            processor: None,
            chain_id: 0,
            movements: None,
            replays: 0,
            filtered: 0,
            unrecorded: None,
            skipped_too_far: None,
            skipped_no_state: None,
            examined: BTreeMap::new(),
            observed: Vec::new(),
            rechecked: 0,
        })
    }

    /// Watch for large value transfers involving a contract.
    ///
    /// The processor is what makes this possible and is the reason it is a
    /// separate builder method rather than a field of the configuration: this
    /// watch re-executes each block, so a caller that cannot supply a
    /// processor cannot have it, and that should be a compile-time shape
    /// rather than a runtime surprise.
    pub fn with_contract_value(
        mut self,
        cfg: ContractValueAlerts,
        processor: Arc<rustock_execution::BlockProcessor>,
        chain_id: u64,
        movements: Arc<crate::movement::MovementLog>,
    ) -> Self {
        self.contract = cfg;
        self.processor = Some(processor);
        self.chain_id = chain_id;
        self.movements = Some(movements);
        self
    }

    /// Accept alerts raised outside the watcher, such as a block that failed
    /// the supply check.
    pub fn with_inbox(mut self, rx: std::sync::mpsc::Receiver<Alert>) -> Self {
        self.inbox = Some(rx);
        self
    }

    /// Deliver anything pushed in from block processing.
    fn drain_inbox(&mut self) {
        let Some(rx) = &self.inbox else { return };
        let pending: Vec<Alert> = rx.try_iter().collect();
        for alert in pending {
            self.deliver(alert);
        }
    }

    /// Re-read `path` whenever its modification time changes, so thresholds can
    /// be retuned against a running node.
    ///
    /// Only the fields that can take effect immediately are adopted; a change
    /// to how mail is delivered, or to whether the watcher runs at all, is
    /// reported as needing a restart rather than half-applied.
    pub fn reloading_from(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.config_seen_mtime = file_mtime(&path);
        self.config_path = Some(path);
        self
    }

    fn reload_config_if_changed(&mut self) {
        let Some(path) = self.config_path.clone() else { return };
        // Unreadable right now (being rewritten, say): keep running on what we
        // have and look again next poll.
        let Some(mtime) = file_mtime(&path) else { return };
        if Some(mtime) == self.config_seen_mtime {
            return;
        }
        self.config_seen_mtime = Some(mtime);

        let (new, new_contract) = match crate::config::Config::load(&path) {
            Ok(c) => (c.alerts.pegout, c.alerts.contract_value),
            Err(e) => {
                tracing::error!(
                    target: "rustock::alerts::pegout",
                    "{} changed but does not load; keeping the running configuration: {e:#}",
                    path.display()
                );
                return;
            }
        };
        let scripts = match new.change_scripts() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    target: "rustock::alerts::pegout",
                    "{} changed but is unusable; keeping the running configuration: {e:#}",
                    path.display()
                );
                return;
            }
        };

        let (mut live, mut restart) = self.cfg.describe_changes(&new);
        let (contract_live, contract_restart) = self.contract.describe_changes(&new_contract);
        live.extend(contract_live);
        restart.extend(contract_restart);
        if live.is_empty() && restart.is_empty() {
            tracing::info!(
                target: "rustock::alerts::pegout",
                "{} changed but no setting differs", path.display()
            );
            return;
        }
        for change in &restart {
            tracing::warn!(
                target: "rustock::alerts::pegout",
                "{} changed {change}, which needs a node restart to take effect",
                path.display()
            );
        }
        if !live.is_empty() {
            self.cfg.adopt_live(&new);
            self.contract.adopt_live(&new_contract);
            self.change_scripts = scripts;
            tracing::info!(
                target: "rustock::alerts::pegout",
                "reloaded {}: {}", path.display(), live.join(", ")
            );
        }
    }

    /// Run until cancelled. Every error is logged and swallowed: a watcher that
    /// exits on a transient read failure is worse than one that retries.
    ///
    /// Each tick runs on a blocking thread rather than on a runtime worker.
    /// A sweep reads the trie and, with the contract-value watch on,
    /// re-executes blocks; both are CPU-bound work measured in tens of
    /// milliseconds, and doing that on an async worker stalls every other
    /// task sharing it -- the RPC server among them. The watcher is moved into
    /// the blocking task and handed back, which is what keeps `&mut self`
    /// usable without wrapping the whole thing in a lock.
    pub async fn run(mut self) {
        if self.cfg.enabled {
            tracing::info!(
                target: "rustock::alerts::pegout",
                "peg-out watcher started at #{}, thresholds: pegout {} BTC, output {} BTC, in transit {} BTC, {} confirmations",
                self.next_block, self.cfg.pegout_alert_btc, self.cfg.output_alert_btc,
                self.cfg.in_transit_alert_btc, self.cfg.confirmations
            );
        }
        if self.contract_value_active() {
            tracing::info!(
                target: "rustock::alerts::pegout",
                "contract value watcher started at #{}, threshold {} RBTC, re-executing a block \
                 only when some account moved more than {} RBTC, and only within {} blocks of \
                 the executed head",
                self.next_block,
                self.contract.transfer_alert_btc,
                self.contract.replay_filter_btc,
                self.contract.max_catchup_blocks
            );
        }
        loop {
            // Read inside the loop so poll_interval_secs is itself reloadable.
            tokio::time::sleep(Duration::from_secs(self.cfg.poll_interval_secs)).await;
            self = match tokio::task::spawn_blocking(move || {
                self.tick();
                self
            })
            .await
            {
                Ok(back) => back,
                // The only way this returns Err is the tick panicking, which
                // has already been reported by the panic hook. There is no
                // watcher left to carry on with.
                Err(e) => {
                    tracing::error!(
                        target: "rustock::alerts::pegout",
                        "watcher task died and will not restart: {e}"
                    );
                    return;
                }
            };
        }
    }

    /// One poll: re-read the configuration, deliver anything pushed in, sweep
    /// the new blocks, and emit the periodic report. Synchronous on purpose --
    /// see [`Watcher::run`].
    fn tick(&mut self) {
        self.reload_config_if_changed();
        self.drain_inbox();
        if let Err(e) = self.sweep() {
            tracing::warn!(target: "rustock::alerts::pegout", "sweep failed, will retry: {e:#}");
        }
        // Reads Bridge state out of the trie, so it is worth nothing to a
        // node running only the contract-value watch.
        if self.cfg.enabled {
            self.report_in_transit_if_due();
        }
    }

    /// Whether the contract-value watch can actually run.
    fn contract_value_active(&self) -> bool {
        self.contract.enabled && self.processor.is_some()
    }

    /// Emit the in-transit line.
    ///
    /// One function, used by both callers -- the periodic report and the
    /// moment a peg-out is requested -- so the two cannot drift into saying
    /// the same thing two different ways.
    fn log_in_transit(&self, number: u64, total_sats: u64, in_transit: &[(u64, u64)], waiting: usize, why: &str) {
        let counted = in_transit
            .iter()
            .filter(|(created, _)| number.saturating_sub(*created) < self.cfg.confirmations)
            .count();
        // Leading label, not a number: every other periodic line in the node
        // reads "Mempool in the last 5m:", "Chain in the last 5m:", "BTC block
        // cache:", and a line that starts with its own value cannot be grepped
        // for without knowing the value first.
        tracing::info!(
            target: "rustock::alerts::pegout",
            "Peg-out transit: {} BTC across {} transaction(s) at #{number} \
             ({} waiting, {} confirmations to clear) [{why}]",
            crate::config::sats_to_btc_string(total_sats),
            counted,
            waiting,
            self.cfg.confirmations,
        );
    }

    /// Report the total value of peg-outs in transit, periodically.
    ///
    /// A *report*, not an alert. The existing `InTransitAboveThreshold` alert
    /// fires only when the total crosses 200 BTC and only on the block that
    /// pushed it there; between those moments an operator has no way to see
    /// that money is moving at all. A peg-out needs 4,000 confirmations —
    /// roughly a day — to clear, so a ten-minute line is frequent enough to
    /// watch one progress and rare enough not to fill the log.
    ///
    /// Silent when nothing is in transit, which is the usual case: a line
    /// saying "0 BTC" every ten minutes teaches the reader to skip it, and
    /// then the line that matters gets skipped too.
    fn report_in_transit_if_due(&mut self) {
        let every = self.cfg.in_transit_report_secs;
        if every == 0 || self.last_in_transit_report.elapsed() < Duration::from_secs(every) {
            return;
        }
        // Reset the clock whatever the outcome, so a run of blocks the Bridge
        // never touched does not cost a trie read every poll.
        let since_last = self.last_in_transit_report.elapsed();
        self.last_in_transit_report = std::time::Instant::now();

        let (number, state_root) = match self.head_with_state_root() {
            Ok(Some(v)) => v,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(
                    target: "rustock::alerts::pegout",
                    "in-transit report: reading the head: {e:#}"
                );
                return;
            }
        };

        let (waiting_txs, in_transit) = match self.read_bridge_state(state_root) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "rustock::alerts::pegout",
                    "in-transit report: reading Bridge state at #{number}: {e:#}"
                );
                return;
            }
        };

        let (total, _) = watch::check_in_transit(number, &in_transit, &self.cfg);
        if !watch::in_transit_report_due(total, since_last, every) {
            return;
        }

        self.log_in_transit(number, total, &in_transit, waiting_txs.len(), "periodic");
    }

    /// The executed head's number and state root, for a read that is not
    /// driven by block processing.
    fn head_with_state_root(&self) -> anyhow::Result<Option<(u64, alloy_primitives::B256)>> {
        let Some((hash, _)) = self.store.exec_head()? else { return Ok(None) };
        let Some(header) = self.store.header(hash)? else { return Ok(None) };
        Ok(Some((header.number, header.state_root)))
    }

    fn head_number(&self) -> anyhow::Result<u64> {
        Ok(self
            .store
            .exec_head()?
            .and_then(|(h, _)| self.store.header(h).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0))
    }

    /// Process every block executed since the last sweep.
    pub fn sweep(&mut self) -> anyhow::Result<()> {
        let head = self.head_number()?;
        self.skipped_too_far = None;
        self.skipped_no_state = None;
        self.unrecorded = None;
        self.replays = 0;
        self.filtered = 0;
        self.rechecked = 0;
        // Before moving forward, make sure the ground has not shifted behind.
        self.recheck_reorged(head);
        while self.next_block <= head {
            let n = self.next_block;
            if let Err(e) = self.process_block(n, head) {
                // Do not advance past a block we failed to read: retry it.
                tracing::warn!(target: "rustock::alerts::pegout", "block #{n}: {e:#}");
                self.report_skipped();
                return Ok(());
            }
            self.next_block = n + 1;
        }
        let floor = head.saturating_sub(REORG_RECHECK_DEPTH);
        self.examined.retain(|&n, _| n >= floor);
        self.report_skipped();
        Ok(())
    }

    /// Alerts reported from a block that the block replacing it does not
    /// contain -- so they describe transfers that did not happen.
    #[allow(clippy::ptr_arg)]
    fn withdrawn<'a>(before: &'a [String], after: &[String]) -> Vec<&'a String> {
        before.iter().filter(|k| !after.contains(k)).collect()
    }

    /// Re-examine any recent height whose canonical block has changed.
    ///
    /// Deduplication does the rest: an alert whose transaction survived the
    /// reorg into the replacement block has the same key -- the key is the
    /// transaction hash and its position in the call tree, neither of which
    /// mentions a height -- so it is not mailed twice. Anything genuinely new
    /// in the replacement is reported, which is the whole point.
    fn recheck_reorged(&mut self, head: u64) {
        let floor = head.saturating_sub(REORG_RECHECK_DEPTH);
        let changed: Vec<(u64, B256, B256)> = self
            .examined
            .range(floor..)
            .filter_map(|(&number, seen)| match self.store.canonical_hash(number) {
                Ok(Some(now)) if now != seen.hash => Some((number, seen.hash, now)),
                _ => None,
            })
            .collect();

        for (number, was, now) in changed {
            tracing::info!(
                target: "rustock::alerts::pegout",
                "#{number} is now {now} (was {was}); re-examining it after a reorg"
            );
            let before =
                self.examined.get(&number).map(|e| e.observed.clone()).unwrap_or_default();
            if let Err(e) = self.process_block(number, head) {
                tracing::warn!(
                    target: "rustock::alerts::pegout",
                    "re-examining #{number} after a reorg: {e:#}"
                );
                continue;
            }
            self.rechecked += 1;
            let after =
                self.examined.get(&number).map(|e| e.observed.clone()).unwrap_or_default();
            // An alert that came from the block this reorg discarded, and is
            // not in its replacement, describes something that did not
            // happen. Mail cannot be unsent, so say so in the log rather than
            // leave a false report standing.
            for key in Self::withdrawn(&before, &after) {
                tracing::warn!(
                    target: "rustock::alerts::pegout",
                    "WITHDRAWN: an alert reported from #{number} is not in the block that \
                     replaced it, so it describes a transfer that did not happen: {key}"
                );
            }
        }
    }

    /// Say out loud which blocks the contract-value watch did not look at.
    ///
    /// A watch that quietly stops watching is worse than one that is off, so
    /// the gap is always named. Once per sweep as a range, because a node
    /// catching up from a day's downtime would otherwise emit thousands of
    /// identical lines.
    fn report_skipped(&mut self) {
        if self.replays > 0 || self.filtered > 0 || self.rechecked > 0 {
            tracing::debug!(
                target: "rustock::alerts::pegout",
                replayed = self.replays,
                filtered = self.filtered,
                rechecked_after_reorg = self.rechecked,
                "contract value sweep"
            );
        }
        if let Some((from, to)) = self.unrecorded.take() {
            // Not an error -- a block this node imported rather than executed
            // has no record and never will. Persistent, though, it means the
            // movement hook is not installed and every block is being
            // re-executed, which is the cost the filter exists to avoid.
            tracing::info!(
                target: "rustock::alerts::pegout",
                "contract value watch re-executed #{from}..=#{to} without a movement record; \
                 this node did not execute them, or the per-block supply check is off"
            );
        }
        if let Some((from, to)) = self.skipped_too_far.take() {
            tracing::warn!(
                target: "rustock::alerts::pegout",
                "contract value watch skipped #{from}..=#{to}: more than {} blocks behind the \
                 executed head, so they were not re-executed. Peg-out checks still ran on them.",
                self.contract.max_catchup_blocks
            );
        }
        if let Some((from, to)) = self.skipped_no_state.take() {
            tracing::warn!(
                target: "rustock::alerts::pegout",
                "contract value watch skipped #{from}..=#{to}: the parent state is no longer \
                 held, so they cannot be re-executed"
            );
        }
    }

    fn note_skip(slot: &mut Option<(u64, u64)>, number: u64) {
        match slot {
            Some((_, to)) => *to = number,
            None => *slot = Some((number, number)),
        }
    }

    fn process_block(&mut self, number: u64, head: u64) -> anyhow::Result<()> {
        let Some(hash) = self.store.canonical_hash(number)? else {
            anyhow::bail!("no canonical hash");
        };
        let Some(header) = self.store.header(hash)? else {
            anyhow::bail!("no header");
        };
        let receipts = self.store.receipts(hash)?.unwrap_or_default();
        self.observed.clear();

        if self.cfg.enabled {
            self.process_pegouts(number, &header, &receipts)?;
        }
        if self.contract_value_active() {
            // Never fatal to the sweep: a block that cannot be re-executed is
            // reported and the watcher moves on, because stopping here would
            // also stop the peg-out watch that shares this loop.
            if let Err(e) = self.process_contract_value(number, hash, &header, &receipts, head) {
                tracing::warn!(
                    target: "rustock::alerts::pegout",
                    "contract value watch, block #{number}: {e:#}"
                );
            }
        }
        // Remember the block this height held and what it produced, so a
        // later reorg at this height is noticed rather than silently missed.
        let observed = std::mem::take(&mut self.observed);
        self.examined.insert(number, Examined { hash, observed });
        Ok(())
    }

    /// Everything the peg-out watch does with one block.
    fn process_pegouts(
        &mut self,
        number: u64,
        header: &rustock_core::Header,
        receipts: &[rustock_core::Receipt],
    ) -> anyhow::Result<()> {
        let bridge = rustock_execution::precompiles::BRIDGE_ADDR;

        // 1. Log every peg-out event.
        let names = pegout_event_names();
        for r in receipts {
            for log in &r.logs {
                if log.address != bridge {
                    continue;
                }
                if let Some((_, name)) = log
                    .topics
                    .first()
                    .and_then(|t| names.iter().find(|(topic, _)| topic == t))
                {
                    tracing::info!(
                        target: "rustock::alerts::pegout",
                        block = number, event = name, topics = log.topics.len(),
                        data = %hex::encode(&log.data),
                        "peg-out event"
                    );
                }
            }
        }

        let mut alerts = Vec::new();

        // 2. Per-peg-out threshold, from release_requested.
        let pegouts = watch::pegouts_in_receipts(receipts, &bridge);
        for p in &pegouts {
            tracing::info!(
                target: "rustock::alerts::pegout",
                block = number,
                // Both: sats is what the event carries and what a script wants;
                // BTC is what a person reads. `release_requested`'s data field
                // is the amount in satoshis, so this is a rendering of the
                // event, not an interpretation of it.
                amount_btc = %crate::config::sats_to_btc_string(p.amount_sats),
                amount_sats = p.amount_sats,
                rsk_tx = %hex::encode(p.rsk_tx_hash),
                btc_tx = %hex::encode(p.btc_tx_hash),
                "peg-out requested"
            );
        }
        alerts.extend(watch::check_pegouts(number, &pegouts, &self.cfg));

        // 3 and 4 need Bridge state, and are only worth reading when something
        // peg-out related happened or periodically — reading the trie on every
        // block would be wasted work on a chain where most blocks have none.
        let bridge_touched = !pegouts.is_empty()
            || receipts.iter().any(|r| r.logs.iter().any(|l| l.address == bridge));
        if bridge_touched {
            match self.read_bridge_state(header.state_root) {
                Ok((waiting_txs, in_transit)) => {
                    alerts.extend(watch::check_outputs(
                        number, &waiting_txs, &self.cfg, &self.change_scripts,
                    ));
                    // In transit is a running total, so it would otherwise
                    // re-alert on every change -- including when the total
                    // FALLS as peg-outs reach their confirmations. Evaluate it
                    // only when this block requested a new peg-out: that is the
                    // moment the number goes up and is worth knowing about.
                    let (total, alert) = watch::check_in_transit(number, &in_transit, &self.cfg);
                    tracing::debug!(
                        target: "rustock::alerts::pegout",
                        block = number, in_transit_sats = total,
                        waiting_txs = waiting_txs.len(), "bridge peg-out state"
                    );
                    if !pegouts.is_empty() {
                        // A peg-out was requested in this block, which is the
                        // moment the total goes UP. Report it here rather than
                        // waiting up to ten minutes for the periodic line: the
                        // increase is the event worth seeing, and seeing it
                        // next to the request that caused it is the whole point.
                        if total > 0 {
                            self.log_in_transit(
                                number, total, &in_transit, waiting_txs.len(), "peg-out requested",
                            );
                            // The periodic report would otherwise repeat this
                            // within seconds.
                            self.last_in_transit_report = std::time::Instant::now();
                        }
                        alerts.extend(alert);
                    }
                }
                Err(e) => tracing::warn!(
                    target: "rustock::alerts::pegout",
                    "block #{number}: reading Bridge state: {e:#}"
                ),
            }
        }

        for alert in alerts {
            self.observed.push(alert.dedup_key());
            self.deliver(alert);
        }
        Ok(())
    }

    /// Large value transfers in or out of a contract, found by re-executing
    /// the block with the call tracer attached.
    ///
    /// This is the only watch here that is not a read. A value transfer emits
    /// no log and leaves nothing in the receipt, so the only way to see a
    /// contract paying out is to run the block again and read the call tree.
    /// The replay is still an observer -- it is handed a trie node, writes
    /// nothing and runs on the watcher's own thread -- but it costs a second
    /// execution of every block that has transactions in it.
    fn process_contract_value(
        &mut self,
        number: u64,
        hash: B256,
        header: &rustock_core::Header,
        receipts: &[rustock_core::Receipt],
        head: u64,
    ) -> anyhow::Result<()> {
        let Some(processor) = self.processor.clone() else { return Ok(()) };

        // A node catching up has thousands of blocks to sweep and would spend
        // hours re-executing them. The peg-out watch still covers those; this
        // one resumes once the backlog is inside the window.
        if head.saturating_sub(number) > self.contract.max_catchup_blocks {
            Self::note_skip(&mut self.skipped_too_far, number);
            return Ok(());
        }

        // Did anything here move at all? Execution already computed every
        // account's balance delta for this block as part of the supply
        // check, so this answer is free and skips almost every block. See
        // `crate::movement` for what a net figure gives up.
        let recorded = self.movements.as_ref().and_then(|m| m.largest_movement(&hash));
        match crate::movement::decide(recorded, self.contract.replay_filter_wei()) {
            crate::movement::Replay::Skip => {
                self.filtered += 1;
                return Ok(());
            }
            crate::movement::Replay::NotRecorded => {
                Self::note_skip(&mut self.unrecorded, number);
                self.replays += 1;
            }
            crate::movement::Replay::Moved => self.replays += 1,
        }

        let Some((transactions, ommers)) = self.store.body(hash)? else {
            anyhow::bail!("no body stored, so it cannot be re-executed");
        };
        // Free to dismiss, but rarer than it sounds: 300 consecutive mainnet
        // blocks sampled in November 2026 all had transactions in them.
        if transactions.is_empty() {
            return Ok(());
        }

        let Some(parent) = self.store.header(header.parent_hash)? else {
            anyhow::bail!("the parent header is missing, so there is no state to replay from");
        };
        let Some(parent_bytes) = self.trie.get(parent.state_root.as_slice()) else {
            // Expected on a pruning node once a block ages out, and on the
            // first blocks after a snapshot sync. Not an error.
            Self::note_skip(&mut self.skipped_no_state, number);
            return Ok(());
        };
        let parent_root = TrieNode::from_message(&parent_bytes, self.trie.as_ref());

        let started = std::time::Instant::now();
        let block = rustock_core::Block {
            header: header.clone(),
            transactions,
            ommers,
        };
        let traces = processor
            .trace_block_calls(&block, &parent_root, self.trie.clone())
            .map_err(|e| anyhow::anyhow!("re-executing the block: {e}"))?;

        // Whether an address is a contract is asked of the state **after**
        // this block, not before it. A transaction that creates a contract and
        // funds it in the same breath is exactly the case this watch is for,
        // and the created account only has code in the post-state. The cost of
        // that choice is a contract which self-destructs in the same block,
        // whose outgoing transfer is still caught -- a SELFDESTRUCT frame
        // names a contract by construction -- but whose incoming one is not.
        let post_root = self
            .trie
            .get(header.state_root.as_slice())
            .map(|b| TrieNode::from_message(&b, self.trie.as_ref()))
            .unwrap_or_else(|| {
                tracing::debug!(
                    target: "rustock::alerts::pegout",
                    "block #{number}: no post-state, classifying accounts against the parent"
                );
                parent_root.clone()
            });

        let threshold = self.contract.transfer_alert_wei();
        let threshold_rbtc = crate::config::wei_to_rbtc_string(threshold);
        let trie = self.trie.clone();
        let chain_id = self.chain_id;
        let mut code_memo: HashMap<Address, bool> = HashMap::new();
        let mut found: Vec<Alert> = Vec::new();

        for (index, tx) in block.transactions.iter().enumerate() {
            let Some(trace) = traces.get(index) else { continue };
            // A failed transaction moved nothing. `value::transfers_in_transaction`
            // enforces this too; checking here saves the work.
            if !receipts.get(index).map(|r| r.status).unwrap_or(false) {
                continue;
            }

            // Recovering the sender costs an ECDSA recovery, so it is done
            // only when the transaction's own transfer could breach. Passing
            // a zero value below suppresses the top-level entry, which is
            // correct: a transfer that cannot reach the threshold is not one
            // this watch reports. Internal transfers need no sender.
            let (sender, destination, top_value) = if tx.value > threshold {
                match tx.recover_sender(chain_id) {
                    Ok(s) => {
                        let to = if tx.to.len() == 20 {
                            Address::from_slice(tx.to.as_ref())
                        } else {
                            s.create(tx.nonce)
                        };
                        (s, to, tx.value)
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "rustock::alerts::pegout",
                            "block #{number} tx {index}: sender not recoverable, its own \
                             transfer cannot be checked: {e}"
                        );
                        (Address::ZERO, Address::ZERO, U256::ZERO)
                    }
                }
            } else {
                (Address::ZERO, Address::ZERO, U256::ZERO)
            };

            let transfers =
                value::transfers_in_transaction(sender, destination, top_value, true, trace);
            if transfers.is_empty() {
                continue;
            }

            let tx_hash = tx.tx_hash().0;
            let breaches = value::breaches(&transfers, threshold, |a| {
                *code_memo.entry(*a).or_insert_with(|| {
                    post_root
                        .get(
                            &rustock_trie::TrieKeySlice::from_key(&rustock_trie::code_key(a)),
                            trie.as_ref(),
                        )
                        .is_some_and(|code| !code.is_empty())
                })
            });

            for b in breaches {
                let alert = Alert::LargeContractTransfer {
                    block: number,
                    tx_hash,
                    from: format!("{}", b.transfer.from),
                    to: format!("{}", b.transfer.to),
                    direction: b.direction.as_str(),
                    kind: b.transfer.kind.as_str(),
                    path: b.transfer.path.clone(),
                    amount_wei: b.transfer.value.to_string(),
                    amount_rbtc: crate::config::wei_to_rbtc_string(b.transfer.value),
                    threshold_rbtc: threshold_rbtc.clone(),
                };
                // Log once per transfer, not once per sighting. The same
                // transaction is seen again whenever a reorg moves it, and a
                // log that counts those as separate events reads as a flurry
                // of alerts where there was one.
                if !self.seen.contains(&alert.dedup_key()) {
                    tracing::warn!(
                        target: "rustock::alerts::pegout",
                        block = number,
                        tx = %format!("0x{}", hex::encode(tx_hash)),
                        from = %b.transfer.from,
                        to = %b.transfer.to,
                        amount_rbtc = %crate::config::wei_to_rbtc_string(b.transfer.value),
                        amount_wei = %b.transfer.value,
                        kind = b.transfer.kind.as_str(),
                        "large transfer {}", b.direction.as_str()
                    );
                }
                found.push(alert);
            }
        }

        tracing::debug!(
            target: "rustock::alerts::pegout",
            block = number,
            transactions = block.transactions.len(),
            took_ms = started.elapsed().as_millis() as u64,
            alerts = found.len(),
            "contract value replay"
        );

        for alert in found {
            self.observed.push(alert.dedup_key());
            self.deliver(alert);
        }
        Ok(())
    }

    /// Alerts remembered for deduplication before the set is dropped and
    /// rebuilt. Peg-out alerts arrive a few a day and would never reach this;
    /// the contract-value watch can, if someone sets a threshold low enough
    /// to match ordinary traffic. Forgetting is better than growing without
    /// bound, and saying so is better than forgetting quietly.
    const MAX_REMEMBERED_ALERTS: usize = 50_000;

    /// Deduplicate and hand one alert to every sink.
    fn deliver(&mut self, alert: Alert) {
        if self.seen.len() >= Self::MAX_REMEMBERED_ALERTS {
            tracing::warn!(
                target: "rustock::alerts::pegout",
                "{} alerts remembered for deduplication; forgetting them. Repeats of older \
                 alerts may be delivered again. A threshold low enough to reach this is \
                 probably mis-set.",
                self.seen.len()
            );
            self.seen.clear();
        }
        if !self.seen.insert(alert.dedup_key()) {
            return;
        }
        for sink in &self.sinks {
            if let Err(e) = sink.deliver(&alert) {
                tracing::error!(
                    target: "rustock::alerts::pegout",
                    "sink {} failed to deliver {:?}: {e:#}", sink.name(), alert.subject()
                );
            }
        }
    }

    /// Read the two peg-out queues straight out of the unitrie at `state_root`.
    ///
    /// Returns the transactions awaiting signature (what the signers are handed)
    /// and, for the in-transit total, the creation height and non-change output
    /// value of each peg-out awaiting confirmation.
    fn read_bridge_state(
        &self,
        state_root: B256,
    ) -> anyhow::Result<(Vec<watch::WaitingTx>, Vec<(u64, u64)>)> {
        use rustock_execution::bridge::peg::{
            deserialize_pegouts_waiting_for_confirmations, deserialize_rsk_txs_waiting_for_signatures,
        };
        use rustock_execution::bridge::storage::{
            PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY, PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY,
            PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
        };

        let data = self
            .trie
            .get(state_root.as_slice())
            .ok_or_else(|| anyhow::anyhow!("state root {state_root:?} not in the trie store"))?;
        let root = TrieNode::from_message(&data, self.trie.as_ref());

        let wfs_raw = self.read_named(&root, PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
        let waiting = deserialize_rsk_txs_waiting_for_signatures(&wfs_raw);
        let waiting_txs = watch::parse_waiting_txs(waiting.into_values());

        let mut wfc = deserialize_pegouts_waiting_for_confirmations(
            &self.read_named(&root, PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY),
            false,
        );
        wfc.extend(deserialize_pegouts_waiting_for_confirmations(
            &self.read_named(&root, PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY),
            true,
        ));

        // Value in transit is what leaves the federation, so configured change
        // outputs are excluded — the same rule the per-output check uses.
        let in_transit = watch::parse_waiting_txs(wfc.iter().map(|e| e.btc_tx_raw.clone()))
            .into_iter()
            .zip(wfc.iter())
            .map(|(tx, entry)| {
                let leaving: u64 = tx
                    .outputs
                    .iter()
                    .filter(|(script, _)| !self.change_scripts.iter().any(|c| c == script))
                    .map(|(_, v)| *v)
                    .sum();
                (entry.rsk_block_height, leaving)
            })
            .collect();

        Ok((waiting_txs, in_transit))
    }

    fn read_named(&self, root: &TrieNode, name: &str) -> Vec<u8> {
        use rustock_execution::bridge::storage::bridge_storage_key;
        let slot = B256::from(bridge_storage_key(name));
        let key = rustock_trie::storage_key(&rustock_execution::precompiles::BRIDGE_ADDR, &slot);
        root.get(&rustock_trie::TrieKeySlice::from_key(&key), self.trie.as_ref())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod reorg_tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> { xs.iter().map(|s| s.to_string()).collect() }

    /// A transfer that survived the reorg into the replacement block is not
    /// withdrawn -- it still happened, just in a different block.
    #[test]
    fn an_alert_present_in_the_replacement_is_not_withdrawn() {
        let before = v(&["a", "b"]);
        let after = v(&["b", "a"]);
        assert!(Watcher::withdrawn(&before, &after).is_empty());
    }

    #[test]
    fn an_alert_absent_from_the_replacement_is_withdrawn() {
        let before = v(&["a", "b"]);
        let after = v(&["b"]);
        assert_eq!(Watcher::withdrawn(&before, &after), vec![&"a".to_string()]);
    }

    /// Something new in the replacement block is not a withdrawal; it is
    /// reported through the ordinary path.
    #[test]
    fn an_alert_new_in_the_replacement_is_not_a_withdrawal() {
        assert!(Watcher::withdrawn(&v(&["a"]), &v(&["a", "c"])).is_empty());
    }

    #[test]
    fn a_block_that_produced_nothing_withdraws_nothing() {
        assert!(Watcher::withdrawn(&[], &v(&["a"])).is_empty());
    }

    #[test]
    fn everything_is_withdrawn_when_the_replacement_is_empty() {
        assert_eq!(Watcher::withdrawn(&v(&["a", "b"]), &[]).len(), 2);
    }
}
