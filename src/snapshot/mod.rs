//! Admitted routing snapshots and their public model, with private admission and routing logic.

use std::net::SocketAddr;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::control::{EdgeConfiguration, EdgeRoute, ProductIdentity};

mod admission;
mod health;
mod routing;
mod selection;

use selection::StaticSelection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    MissingOperation,
    MissingConfiguration,
    InvalidIdentity,
    IdentityMismatch,
    ConfigurationHash,
    StaleEpoch,
    StaleGeneration,
    Conflict,
    InvalidValidity,
    AuthorityExpired,
    InvalidRoute,
    InvalidEndpoint,
    UnsupportedNetworkScope,
    CertificateMaterial,
    LimitExceeded,
    Persistence,
    Withdrawn,
    UnsupportedOperation,
}

#[derive(Clone)]
pub struct Snapshot {
    pub configuration: EdgeConfiguration,
    pub identity: ProductIdentity,
    pub controller_epoch: u64,
    pub generation: u64,
    pub configuration_hash: Vec<u8>,
    pub issued_at_unix_ms: i64,
    pub valid_until_unix_ms: i64,
    pub routes: Vec<EdgeRoute>,
    pub withdrawn: bool,
    backend_selectors: Vec<Option<StaticSelection>>,
    backend_addresses: Vec<Vec<SocketAddr>>,
    backend_health_keys: Vec<Vec<String>>,
    health_targets: Vec<HealthTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthTarget {
    pub key: String,
    pub address: SocketAddr,
}

impl Snapshot {
    pub fn is_live(&self) -> bool {
        !self.withdrawn && self.valid_until_unix_ms > unix_ms()
    }

    pub fn empty() -> Self {
        Self {
            configuration: EdgeConfiguration::default(),
            identity: ProductIdentity::default(),
            controller_epoch: 0,
            generation: 0,
            configuration_hash: vec![0; 32],
            issued_at_unix_ms: 0,
            valid_until_unix_ms: 0,
            routes: Vec::new(),
            withdrawn: false,
            backend_selectors: Vec::new(),
            backend_addresses: Vec::new(),
            backend_health_keys: Vec::new(),
            health_targets: Vec::new(),
        }
    }

    pub fn with_withdrawn(mut self) -> Self {
        self.withdrawn = true;
        self
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}
