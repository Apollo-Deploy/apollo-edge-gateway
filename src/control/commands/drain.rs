//! Durable drain admission and expiry into withdrawal tombstones.

use std::sync::Arc;

use crate::control::authority::{DrainState, Tombstone, drain_map};
use crate::control::{
    ActiveConfigurations, CommandOutcome, DrainConfigurationRequest, GatewayState, unix_ms,
};
use crate::snapshot::AdmissionError;

const MAX_DRAIN_MILLIS: i64 = 10 * 60 * 1_000;

impl GatewayState {
    pub fn retire_expired_drains(&self) -> bool {
        let now = unix_ms();
        let mut authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => return false,
        };
        let expired = authority
            .drains
            .iter()
            .filter(|(_, drain)| drain.drain_until_unix_ms <= now)
            .map(|(target_id, drain)| (target_id.clone(), drain.clone()))
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return false;
        }
        let active = self.active.load_full();
        let mut entries = active.entries.clone();
        let mut next_authority = authority.clone();
        for (target_id, drain) in expired {
            next_authority.drains.remove(&target_id);
            let should_retire = entries.get(&target_id).is_some_and(|snapshot| {
                snapshot.controller_epoch == drain.controller_epoch
                    && snapshot.generation == drain.generation
                    && snapshot.configuration_hash == drain.configuration_hash
            });
            if should_retire {
                entries.remove(&target_id);
                next_authority.tombstones.insert(
                    target_id,
                    Tombstone {
                        controller_epoch: drain.controller_epoch,
                        generation: drain.generation,
                        configuration_hash: drain.configuration_hash,
                    },
                );
            }
        }
        let next = ActiveConfigurations::new(entries);
        if self.persist(&next, &next_authority).is_err() {
            return false;
        }
        *authority = next_authority.clone();
        self.active.store(Arc::new(next));
        self.draining.store(Arc::new(drain_map(&next_authority)));
        true
    }

    pub fn drain(&self, request: DrainConfigurationRequest) -> CommandOutcome {
        let Some(operation) = request.operation else {
            return CommandOutcome::Rejected(AdmissionError::MissingOperation);
        };
        let Some(identity) = request.identity else {
            return CommandOutcome::Rejected(AdmissionError::InvalidIdentity);
        };
        if operation.operation_id.is_empty()
            || operation.effect_id.is_empty()
            || operation.controller_epoch == 0
            || operation.generation == 0
            || operation.configuration_hash.len() != 32
            || identity.organization_id.is_empty()
            || identity.project_id.is_empty()
            || identity.traffic_target_id.is_empty()
            || request.drain_generation != operation.generation
            || request.drain_until_unix_ms <= unix_ms()
            || request.drain_until_unix_ms > unix_ms().saturating_add(MAX_DRAIN_MILLIS)
        {
            return CommandOutcome::Rejected(AdmissionError::InvalidValidity);
        }
        let mut authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => return CommandOutcome::Rejected(AdmissionError::Persistence),
        };
        if operation.controller_epoch < authority.epoch {
            return CommandOutcome::Rejected(AdmissionError::StaleEpoch);
        }
        let active = self.active.load_full();
        let Some(snapshot) = active.entries.get(&identity.traffic_target_id) else {
            return match authority.tombstones.get(&identity.traffic_target_id) {
                Some(tombstone)
                    if tombstone.controller_epoch == operation.controller_epoch
                        && tombstone.generation == operation.generation
                        && tombstone.configuration_hash == operation.configuration_hash =>
                {
                    CommandOutcome::AlreadyApplied
                }
                _ => CommandOutcome::Rejected(AdmissionError::StaleGeneration),
            };
        };
        if snapshot.identity != identity
            || snapshot.controller_epoch != operation.controller_epoch
            || snapshot.generation != operation.generation
            || snapshot.configuration_hash != operation.configuration_hash
        {
            return CommandOutcome::Rejected(AdmissionError::Conflict);
        }
        if let Some(existing) = authority.drains.get(&identity.traffic_target_id) {
            return if existing.controller_epoch == operation.controller_epoch
                && existing.generation == operation.generation
                && existing.configuration_hash == operation.configuration_hash
            {
                CommandOutcome::AlreadyApplied
            } else {
                CommandOutcome::Rejected(AdmissionError::Conflict)
            };
        }
        let mut next_authority = authority.clone();
        next_authority.drains.insert(
            identity.traffic_target_id.clone(),
            DrainState {
                controller_epoch: operation.controller_epoch,
                generation: operation.generation,
                configuration_hash: operation.configuration_hash,
                drain_until_unix_ms: request.drain_until_unix_ms,
            },
        );
        if let Err(error) = self.persist(&active, &next_authority) {
            return CommandOutcome::Rejected(error);
        }
        *authority = next_authority.clone();
        self.draining.store(Arc::new(drain_map(&next_authority)));
        CommandOutcome::Accepted
    }
}
