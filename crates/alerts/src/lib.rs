//! Alerting: peg-out monitoring and node health.
//!
//! An observer, not a participant. It reads blocks, receipts and Bridge state
//! that the node has already committed, so it cannot change what the node
//! computes and cannot slow block processing: there is no hook in the execution
//! or sync path at all. If this module stalls, crashes or blocks on an
//! unreachable mail server, the node does not notice.
//!
//! What it watches, all thresholds configurable:
//!
//! - every peg-out request, logged, and alerted above a per-peg-out threshold;
//! - every output of a peg-out Bitcoin transaction awaiting signature -- the
//!   transactions handed to the signers -- alerted above a per-output
//!   threshold, excluding configured federation change scripts;
//! - the total value in transit: peg-outs built but not yet confirmed.
//!
//! And the **node health alarms** -- stalled, behind the network, ahead of it
//! -- which share this crate's mail transport and configuration file, because
//! two mail configurations is how one of them goes stale. See [`health`] and
//! `docs/alerts-node-health.md`.
//!
//! # The one watch that is not a read
//!
//! [`value`] alerts on large transfers in or out of a smart contract, and it
//! is the exception to the paragraph above. A value transfer emits no log and
//! writes nothing to the receipt, so a contract paying out cannot be seen from
//! stored data at all; the block has to be **re-executed** with the call
//! tracer attached. That is still an observer -- the replay is handed a trie
//! node, writes nothing, and runs on the watcher's own thread, so it cannot
//! change what the node computes -- but it costs a second execution of the
//! block, which is why it is off by default and why [`movement`] filters
//! first: the supply check already records every account's balance delta for
//! every block, and a block in which nothing moved needs no second look. See
//! `docs/alerts-contract-value.md`.
//!
//! # A note on names
//!
//! The crate is `rustock-alerts`; it was `rustock-pegout-alerts` until the
//! health alarms arrived and outgrew the name. The **configuration** keeps its
//! old names on purpose -- the file is still `[pegout_alerts]` and the flag is
//! still `--alerts-config` -- because those are deployed. A rename that
//! stops a running node from reading its own configuration is not a tidying.
//! `--alerts-config` is accepted as an alias so a deployment can migrate when
//! it suits.

pub mod alert;
pub mod config;
pub mod health;
pub mod movement;
pub mod service;
pub mod sink;
pub mod value;
pub mod watch;

pub use alert::Alert;
pub use config::{Config, ContractValueAlerts, NodeHealth, PegoutAlerts};
pub use service::Watcher;
pub use sink::{AlertSink, LogSink};
#[cfg(feature = "smtp")]
pub use sink::SmtpSink;
