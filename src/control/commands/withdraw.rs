//! Durable withdrawal tombstones and retirement of fenced active configurations.
use std::sync::Arc;

use crate::control::authority::{
    AuthorityDecision, Tombstone, authority_decision, drain_map, prior_authority,
};
use crate::control::{
    ActiveConfigurations, CommandOutcome, GatewayState, WithdrawConfigurationRequest,
};
use crate::snapshot::AdmissionError;

impl GatewayState {
    pub fn withdraw(&self, request: WithdrawConfigurationRequest) -> CommandOutcome {
        let Some(operation) = request.operation else {
            return CommandOutcome::Rejected(AdmissionError::MissingOperation);
        };

        let Some(identity) = request.identity else {
            return CommandOutcome::Rejected(AdmissionError::InvalidIdentity);
        };

        if identity.traffic_target_id.is_empty()
            || operation.configuration_hash.len() != 32
            || operation.operation_id.is_empty()
            || operation.effect_id.is_empty()
            || operation.controller_epoch == 0
            || operation.generation == 0
            || request.withdrawn_generation != operation.generation
        {
            return CommandOutcome::Rejected(AdmissionError::InvalidIdentity);
        }

        let mut authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => return CommandOutcome::Rejected(AdmissionError::Persistence),
        };

        let active = self.active.load_full();

        if operation.controller_epoch < authority.epoch {
            return CommandOutcome::Rejected(AdmissionError::StaleEpoch);
        }

        let (prior_epoch, prior_generation, prior_hash) = prior_authority(
            active.entries.get(&identity.traffic_target_id),
            authority.tombstones.get(&identity.traffic_target_id),
        );

        let decision = if operation.controller_epoch > authority.epoch {
            AuthorityDecision::New
        } else {
            authority_decision(
                prior_epoch,
                prior_generation,
                &prior_hash,
                operation.controller_epoch,
                operation.generation,
                &operation.configuration_hash,
            )
        };

        match decision {
            AuthorityDecision::StaleEpoch => {
                return CommandOutcome::Rejected(AdmissionError::StaleEpoch);
            }
            AuthorityDecision::StaleGeneration => {
                return CommandOutcome::Rejected(AdmissionError::StaleGeneration);
            }
            AuthorityDecision::Idempotent => return CommandOutcome::AlreadyApplied,
            AuthorityDecision::Conflict => {
                return CommandOutcome::Rejected(AdmissionError::Conflict);
            }
            AuthorityDecision::New => {}
        }

        let tombstone = Tombstone {
            controller_epoch: operation.controller_epoch,
            generation: request.withdrawn_generation,
            configuration_hash: operation.configuration_hash,
        };

        let mut next_authority = authority.clone();

        next_authority.epoch = next_authority.epoch.max(tombstone.controller_epoch);

        next_authority
            .tombstones
            .insert(identity.traffic_target_id.clone(), tombstone);

        next_authority.drains.remove(&identity.traffic_target_id);

        let mut entries = active.entries.clone();

        if let Some(current) = entries.get(&identity.traffic_target_id) {
            if operation.controller_epoch > current.controller_epoch
                || current.generation <= request.withdrawn_generation
            {
                entries.remove(&identity.traffic_target_id);
            }
        }

        let next = ActiveConfigurations::new(entries);

        if let Err(error) = self.persist(&next, &next_authority) {
            return CommandOutcome::Rejected(error);
        }

        *authority = next_authority;

        self.active.store(Arc::new(next));

        self.draining.store(Arc::new(drain_map(&authority)));

        CommandOutcome::Accepted
    }
}
