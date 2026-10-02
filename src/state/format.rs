//! Persisted protobuf messages, envelope constants, errors, and retained-authority validation.

use std::collections::HashSet;
use std::fmt;

use prost::Message;

use crate::control::EdgeConfiguration;

pub(super) const MAGIC: &[u8] = b"APOLLO-EDGE-STATE\n";
pub(super) const DIGEST_BYTES: usize = 32;
pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TOMBSTONES: usize = 4_096;
pub const MAX_ACTIVE_CONFIGURATIONS: usize = 1_024;

#[derive(Clone, PartialEq, Message)]
pub struct PersistedState {
    #[prost(message, repeated, tag = "1")]
    pub active: Vec<EdgeConfiguration>,
    #[prost(message, repeated, tag = "3")]
    pub tombstones: Vec<PersistedTombstone>,
    #[prost(uint64, tag = "4")]
    pub authority_epoch: u64,
    #[prost(message, repeated, tag = "5")]
    pub drains: Vec<PersistedDrain>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PersistedTombstone {
    #[prost(string, tag = "1")]
    pub target_id: String,
    #[prost(uint64, tag = "2")]
    pub controller_epoch: u64,
    #[prost(uint64, tag = "3")]
    pub generation: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub configuration_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PersistedDrain {
    #[prost(string, tag = "1")]
    pub target_id: String,
    #[prost(uint64, tag = "2")]
    pub controller_epoch: u64,
    #[prost(uint64, tag = "3")]
    pub generation: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub configuration_hash: Vec<u8>,
    #[prost(int64, tag = "5")]
    pub drain_until_unix_ms: i64,
}

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    Invalid(&'static str),
    Decode(prost::DecodeError),
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "state I/O failed: {error}"),
            Self::Invalid(reason) => write!(formatter, "state is invalid: {reason}"),
            Self::Decode(error) => write!(formatter, "state protobuf is invalid: {error}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<std::io::Error> for StateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<prost::DecodeError> for StateError {
    fn from(error: prost::DecodeError) -> Self {
        Self::Decode(error)
    }
}

pub(super) fn validate_state(state: &PersistedState) -> Result<(), StateError> {
    if state.tombstones.len() > MAX_TOMBSTONES {
        return Err(StateError::Invalid("too many tombstones"));
    }
    if state.active.len() > MAX_ACTIVE_CONFIGURATIONS {
        return Err(StateError::Invalid("too many active configurations"));
    }
    let mut active_targets = HashSet::new();
    for active in &state.active {
        let target_id = active
            .identity
            .as_ref()
            .map(|identity| identity.traffic_target_id.as_str())
            .unwrap_or_default();
        if target_id.is_empty() || !active_targets.insert(target_id) {
            return Err(StateError::Invalid("active configuration identity"));
        }
    }
    for tombstone in &state.tombstones {
        if tombstone.target_id.is_empty()
            || tombstone.controller_epoch == 0
            || tombstone.generation == 0
            || tombstone.configuration_hash.len() != DIGEST_BYTES
            || tombstone.controller_epoch > state.authority_epoch
        {
            return Err(StateError::Invalid("tombstone identity"));
        }
    }
    if state.drains.len() > MAX_ACTIVE_CONFIGURATIONS {
        return Err(StateError::Invalid("too many drains"));
    }
    let mut drain_targets = HashSet::new();
    for drain in &state.drains {
        if drain.target_id.is_empty()
            || !drain_targets.insert(&drain.target_id)
            || drain.controller_epoch == 0
            || drain.generation == 0
            || drain.configuration_hash.len() != DIGEST_BYTES
            || drain.drain_until_unix_ms <= 0
            || drain.controller_epoch > state.authority_epoch
        {
            return Err(StateError::Invalid("drain identity"));
        }
    }
    for active in &state.active {
        if active.controller_epoch > state.authority_epoch {
            return Err(StateError::Invalid(
                "active authority exceeds retained authority",
            ));
        }
    }
    Ok(())
}
