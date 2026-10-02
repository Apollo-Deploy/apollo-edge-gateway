//! Authenticated control transport and background gateway health probes.
//!
//! [`ControlConfig`] and [`ControlServer`] are the public entry points. Listener
//! lifecycle, mTLS authentication, bounded framing, command dispatch, and health
//! probing remain private implementation details of this feature.

mod dispatch;
mod framing;
mod health;
mod server;
mod tls;

pub use server::{ControlConfig, ControlServer};
