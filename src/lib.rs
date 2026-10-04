//! Apollo's edge gateway: admitted routing snapshots, durable control, and TLS proxying.
//!
//! Public feature facades retain the control and storage interfaces; process
//! startup and Pingora request handling remain private behind [`run`].
pub mod control;
pub mod material;
pub mod snapshot;
pub mod state;
pub mod transport;

mod proxy;
mod startup;

#[cfg(test)]
mod test_support;

pub use control::GatewayState;
pub use snapshot::{AdmissionError, Snapshot};
pub use startup::run;
