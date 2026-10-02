//! Recovery of durable authority and persistence before runtime publication.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::snapshot::{AdmissionError, Snapshot};
use crate::state::{PersistedDrain, PersistedState, PersistedTombstone, StateError, StateStore};

use super::authority::{
    AuthorityDecision, AuthorityState, DrainState, Tombstone, authority_decision,
};
use super::{ActiveConfigurations, GatewayState};

impl GatewayState {
    pub fn from_store(store: StateStore) -> Result<Self, StateError> {
        let persisted = store.load()?;
        let (active, epoch, tombstones, drains) = match persisted {
            None => (
                ActiveConfigurations::default(),
                0,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            Some(state) => {
                let mut entries = BTreeMap::new();
                let mut expired_tombstones = BTreeMap::new();
                for configuration in state.active {
                    let snapshot = Snapshot::admit_persisted(configuration)
                        .map_err(|_| StateError::Invalid("active configuration admission"))?;
                    let target_id = snapshot.identity.traffic_target_id.clone();
                    if !snapshot.is_live() {
                        expired_tombstones.insert(
                            target_id,
                            Tombstone {
                                controller_epoch: snapshot.controller_epoch,
                                generation: snapshot.generation,
                                configuration_hash: snapshot.configuration_hash,
                            },
                        );
                        continue;
                    }
                    if entries.insert(target_id, Arc::new(snapshot)).is_some() {
                        return Err(StateError::Invalid("duplicate active target"));
                    }
                }
                let mut tombstones = state
                    .tombstones
                    .into_iter()
                    .map(|tombstone| {
                        (
                            tombstone.target_id,
                            Tombstone {
                                controller_epoch: tombstone.controller_epoch,
                                generation: tombstone.generation,
                                configuration_hash: tombstone.configuration_hash,
                            },
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                for (target_id, expired) in expired_tombstones {
                    match tombstones.get(&target_id) {
                        Some(current)
                            if (current.controller_epoch, current.generation)
                                > (expired.controller_epoch, expired.generation) => {}
                        Some(current)
                            if (current.controller_epoch, current.generation)
                                == (expired.controller_epoch, expired.generation)
                                && current.configuration_hash != expired.configuration_hash =>
                        {
                            return Err(StateError::Invalid("conflicting expired authority"));
                        }
                        _ => {
                            tombstones.insert(target_id, expired);
                        }
                    }
                }
                let drains = state
                    .drains
                    .into_iter()
                    .map(|drain| {
                        (
                            drain.target_id,
                            DrainState {
                                controller_epoch: drain.controller_epoch,
                                generation: drain.generation,
                                configuration_hash: drain.configuration_hash,
                                drain_until_unix_ms: drain.drain_until_unix_ms,
                            },
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                for (target_id, snapshot) in &entries {
                    if let Some(tombstone) = tombstones.get(target_id) {
                        if authority_decision(
                            tombstone.controller_epoch,
                            tombstone.generation,
                            &tombstone.configuration_hash,
                            snapshot.controller_epoch,
                            snapshot.generation,
                            &snapshot.configuration_hash,
                        ) != AuthorityDecision::New
                        {
                            return Err(StateError::Invalid(
                                "active configuration is fenced by tombstone",
                            ));
                        }
                    }
                }
                (
                    ActiveConfigurations::new(entries),
                    state.authority_epoch,
                    tombstones,
                    drains,
                )
            }
        };
        let draining = drains
            .iter()
            .map(|(target_id, drain)| (target_id.clone(), drain.drain_until_unix_ms))
            .collect();
        Ok(Self {
            active: ArcSwap::from_pointee(active),
            authority: Mutex::new(AuthorityState {
                epoch,
                tombstones,
                drains,
            }),
            store: Some(store),
            certificate_material_directory: None,
            material_retirement_since: Mutex::new(BTreeMap::new()),
            last_material_gc: Mutex::new(None),
            draining: ArcSwap::from_pointee(draining),
            local_health: ArcSwap::from_pointee(BTreeMap::new()),
        })
    }

    pub(super) fn persist(
        &self,
        active: &ActiveConfigurations,
        authority: &AuthorityState,
    ) -> Result<(), AdmissionError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let state = PersistedState {
            active: active
                .entries
                .values()
                .map(|snapshot| snapshot.configuration.clone())
                .collect(),
            tombstones: authority
                .tombstones
                .iter()
                .map(|(target_id, tombstone)| PersistedTombstone {
                    target_id: target_id.clone(),
                    controller_epoch: tombstone.controller_epoch,
                    generation: tombstone.generation,
                    configuration_hash: tombstone.configuration_hash.clone(),
                })
                .collect(),
            authority_epoch: authority.epoch,
            drains: authority
                .drains
                .iter()
                .map(|(target_id, drain)| PersistedDrain {
                    target_id: target_id.clone(),
                    controller_epoch: drain.controller_epoch,
                    generation: drain.generation,
                    configuration_hash: drain.configuration_hash.clone(),
                    drain_until_unix_ms: drain.drain_until_unix_ms,
                })
                .collect(),
        };
        store
            .replace(&state)
            .map_err(|_| AdmissionError::Persistence)
    }
}
