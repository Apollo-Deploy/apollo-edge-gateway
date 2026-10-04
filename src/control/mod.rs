//! Gateway configuration authority, durable commands, and the public control protocol.
//!
//! Feature implementations stay private; protocol types and routing results retain
//! their existing `crate::control` paths.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;

use crate::snapshot::AdmissionError;
use crate::state::StateStore;

use self::authority::AuthorityState;

mod active;
mod authority;
mod certificates;
mod commands;
mod inspection;
mod protocol;
mod recovery;
mod routing;

pub use active::ActiveConfigurations;
pub use protocol::*;
pub use routing::{RouteLookup, RuntimeLimits};

#[derive(Debug, Clone)]
pub enum CommandOutcome {
    Accepted,
    AlreadyApplied,
    Rejected(AdmissionError),
}

pub struct GatewayState {
    active: ArcSwap<ActiveConfigurations>,
    authority: Mutex<AuthorityState>,
    store: Option<StateStore>,
    certificate_material_directory: Option<PathBuf>,
    material_retirement_since: Mutex<BTreeMap<String, Instant>>,
    last_material_gc: Mutex<Option<Instant>>,
    draining: ArcSwap<BTreeMap<String, i64>>,
    local_health: ArcSwap<BTreeMap<String, bool>>,
}

impl GatewayState {
    pub fn empty() -> Self {
        Self {
            active: ArcSwap::from_pointee(ActiveConfigurations::default()),
            authority: Mutex::new(AuthorityState {
                epoch: 0,
                tombstones: BTreeMap::new(),
                drains: BTreeMap::new(),
            }),
            store: None,
            certificate_material_directory: None,
            material_retirement_since: Mutex::new(BTreeMap::new()),
            last_material_gc: Mutex::new(None),
            draining: ArcSwap::from_pointee(BTreeMap::new()),
            local_health: ArcSwap::from_pointee(BTreeMap::new()),
        }
    }

    pub fn active(&self) -> Arc<ActiveConfigurations> {
        self.active.load_full()
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod health_tests;
#[cfg(test)]
mod routing_tests;
#[cfg(test)]
mod tests;
