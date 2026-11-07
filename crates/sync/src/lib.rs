pub mod execution_commit;
pub mod sampler;
pub mod uncle_guard;
mod unlinked;
mod body_check;
mod events;
mod handler;
mod manager;
mod progress;
mod service;
mod state;
mod tracker;
pub mod chain_activity;
pub mod gas_price;
pub mod invariant;
pub mod quota;
pub mod rollback;
pub mod snap;
pub mod tx_relay;
pub mod txpool;
pub mod watchdog;

// Re-exports for external consumers
pub use events::SyncEvent;
pub use handler::SyncHandler;
pub use manager::SyncManager;
pub use service::{BestBlockListeners, ExternalBlockSource, SyncService};
pub use state::{InFlightBody, SyncState};
pub use invariant::{Scope, Violation};
pub use tracker::PeerChunkTracker;
pub use watchdog::{Escalation, Phi, ProgressWatchdog};
pub use snap::{client::StateDownload, server::servable_roots as snap_servable_roots, server::SnapServer, SnapConfig};
pub use tx_relay::TxRelay;
pub use txpool::TransactionPool;

#[cfg(test)]
pub use rustock_core::types::header::Header;
#[cfg(test)]
pub use rustock_core::validation::HeaderVerifier;
#[cfg(test)]
pub use rustock_networking::protocol::BlockIdentifier;
#[cfg(test)]
pub use rustock_storage::BlockStore;
#[cfg(test)]
pub use std::sync::Arc;
#[cfg(test)]
pub use std::time::{Duration, Instant};
#[cfg(test)]
pub use tokio::sync::mpsc;

#[cfg(test)]
mod tests;
