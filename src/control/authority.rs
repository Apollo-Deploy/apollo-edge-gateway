//! Shared epoch/generation fencing, withdrawal tombstones, and drain authority.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::snapshot::Snapshot;

#[derive(Clone)]
pub(super) struct AuthorityState {
    pub(super) epoch: u64,
    pub(super) tombstones: BTreeMap<String, Tombstone>,
    pub(super) drains: BTreeMap<String, DrainState>,
}

#[derive(Clone)]
pub(super) struct Tombstone {
    pub(super) controller_epoch: u64,
    pub(super) generation: u64,
    pub(super) configuration_hash: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct DrainState {
    pub(super) controller_epoch: u64,
    pub(super) generation: u64,
    pub(super) configuration_hash: Vec<u8>,
    pub(super) drain_until_unix_ms: i64,
}

pub(super) fn prior_authority(
    active: Option<&Arc<Snapshot>>,
    tombstone: Option<&Tombstone>,
) -> (u64, u64, Vec<u8>) {
    match (active, tombstone) {
        (Some(snapshot), Some(tombstone))
            if (snapshot.controller_epoch, snapshot.generation)
                >= (tombstone.controller_epoch, tombstone.generation) =>
        {
            (
                snapshot.controller_epoch,
                snapshot.generation,
                snapshot.configuration_hash.clone(),
            )
        }
        (Some(snapshot), _) => (
            snapshot.controller_epoch,
            snapshot.generation,
            snapshot.configuration_hash.clone(),
        ),
        (None, Some(tombstone)) => (
            tombstone.controller_epoch,
            tombstone.generation,
            tombstone.configuration_hash.clone(),
        ),
        (None, None) => (0, 0, Vec::new()),
    }
}

pub(super) fn drain_map(authority: &AuthorityState) -> BTreeMap<String, i64> {
    authority
        .drains
        .iter()
        .map(|(target_id, drain)| (target_id.clone(), drain.drain_until_unix_ms))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AuthorityDecision {
    StaleEpoch,
    StaleGeneration,
    Conflict,
    Idempotent,
    New,
}

pub(super) fn authority_decision(
    active_epoch: u64,
    active_generation: u64,
    active_hash: &[u8],
    incoming_epoch: u64,
    incoming_generation: u64,
    incoming_hash: &[u8],
) -> AuthorityDecision {
    if incoming_epoch < active_epoch {
        return AuthorityDecision::StaleEpoch;
    }

    if incoming_epoch > active_epoch {
        return AuthorityDecision::New;
    }

    if incoming_generation < active_generation {
        return AuthorityDecision::StaleGeneration;
    }

    if incoming_generation == active_generation {
        return if active_hash == incoming_hash {
            AuthorityDecision::Idempotent
        } else {
            AuthorityDecision::Conflict
        };
    }

    AuthorityDecision::New
}
