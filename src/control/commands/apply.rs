//! Apply admission, operation validation, and authority-fenced publication.
use std::sync::Arc;

use crate::control::authority::{
    AuthorityDecision, authority_decision, drain_map, prior_authority,
};
use crate::control::{
    ActiveConfigurations, ApplyConfigurationRequest, CommandOutcome, EdgeConfiguration,
    GatewayState, OperationIdentity, ProductIdentity,
};
use crate::snapshot::{AdmissionError, Snapshot};

impl GatewayState {
    pub fn apply(&self, request: ApplyConfigurationRequest) -> CommandOutcome {
        let Some(operation) = request.operation else {
            return CommandOutcome::Rejected(AdmissionError::MissingOperation);
        };

        let Some(configuration) = request.configuration else {
            return CommandOutcome::Rejected(AdmissionError::MissingConfiguration);
        };

        let Some(identity) = request.identity else {
            return CommandOutcome::Rejected(AdmissionError::InvalidIdentity);
        };

        if let Err(error) = validate_operation(&operation, &identity, &configuration) {
            return CommandOutcome::Rejected(error);
        }

        let mut authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => return CommandOutcome::Rejected(AdmissionError::Persistence),
        };

        let active = self.active.load_full();

        let target_id = configuration
            .identity
            .as_ref()
            .map(|value| value.traffic_target_id.clone())
            .unwrap_or_default();

        let (prior_epoch, prior_generation, prior_hash) = prior_authority(
            active.entries.get(&target_id),
            authority.tombstones.get(&target_id),
        );

        let decision = if operation.controller_epoch < authority.epoch {
            AuthorityDecision::StaleEpoch
        } else if operation.controller_epoch > authority.epoch {
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
            AuthorityDecision::StaleEpoch => CommandOutcome::Rejected(AdmissionError::StaleEpoch),
            AuthorityDecision::StaleGeneration => {
                CommandOutcome::Rejected(AdmissionError::StaleGeneration)
            }
            AuthorityDecision::Conflict => CommandOutcome::Rejected(AdmissionError::Conflict),
            AuthorityDecision::Idempotent => CommandOutcome::AlreadyApplied,
            AuthorityDecision::New => {
                if !active.entries.contains_key(&target_id)
                    && active.entries.len() >= crate::state::MAX_ACTIVE_CONFIGURATIONS
                {
                    return CommandOutcome::Rejected(AdmissionError::LimitExceeded);
                }

                let mut snapshot = match Snapshot::admit(configuration) {
                    Ok(snapshot) => snapshot,
                    Err(error) => return CommandOutcome::Rejected(error),
                };

                if let Some(root) = &self.certificate_material_directory {
                    snapshot.certificates =
                        match crate::material::load_configuration(root, &snapshot.configuration) {
                            Ok(material) => material,
                            Err(_) => {
                                return CommandOutcome::Rejected(
                                    AdmissionError::CertificateMaterial,
                                );
                            }
                        };
                }

                let mut next_authority = authority.clone();

                next_authority.epoch = next_authority.epoch.max(snapshot.controller_epoch);

                next_authority.drains.remove(&target_id);

                let mut entries = active.entries.clone();

                entries.insert(target_id, Arc::new(snapshot));

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
    }
}

fn validate_operation(
    operation: &OperationIdentity,
    identity: &ProductIdentity,
    configuration: &EdgeConfiguration,
) -> Result<(), AdmissionError> {
    if operation.operation_id.is_empty() || operation.effect_id.is_empty() {
        return Err(AdmissionError::MissingOperation);
    }

    if operation.controller_epoch == 0
        || operation.generation == 0
        || identity.organization_id.is_empty()
        || identity.project_id.is_empty()
        || identity.traffic_target_id.is_empty()
    {
        return Err(AdmissionError::InvalidIdentity);
    }

    if operation.configuration_hash.len() != 32 {
        return Err(AdmissionError::ConfigurationHash);
    }

    if configuration.controller_epoch != operation.controller_epoch
        || configuration.generation != operation.generation
        || configuration.configuration_hash != operation.configuration_hash
    {
        return Err(AdmissionError::IdentityMismatch);
    }

    if configuration.identity.as_ref() != Some(identity) {
        return Err(AdmissionError::IdentityMismatch);
    }

    if configuration.max_header_bytes == 0
        || configuration.max_header_bytes > 256 * 1024
        || configuration.max_body_bytes == 0
        || configuration.max_body_bytes > 1024 * 1024 * 1024
        || configuration.max_connections == 0
        || configuration.max_connections > 1_000_000
        || configuration.max_concurrency == 0
        || configuration.max_concurrency > 1_000_000
        || configuration.drain_timeout_seconds == 0
        || configuration.drain_timeout_seconds > 600
        || configuration.retry_max_attempts == 0
        || configuration.retry_max_attempts > 2
        || configuration.retry_methods.len() > 8
        || configuration
            .retry_methods
            .iter()
            .any(|method| method.is_empty() || method.len() > 16 || !method.is_ascii())
    {
        return Err(AdmissionError::LimitExceeded);
    }

    Ok(())
}
