//! Binding, installing, retiring, and selecting admitted certificate material.
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::snapshot::AdmissionError;

use super::{CommandOutcome, GatewayState, InstallCertificateMaterialRequest};

impl GatewayState {
    /// Bind the production state to its private, versioned certificate store.
    /// Persisted routes must still have valid material after a restart.
    pub fn with_certificate_material_directory(mut self, path: PathBuf) -> anyhow::Result<Self> {
        let root = crate::material::canonical_root(&path)?;

        let mut entries = self.active.load().entries.clone();

        for snapshot in entries.values_mut() {
            if snapshot.is_live() {
                let snapshot = std::sync::Arc::make_mut(snapshot);

                snapshot.certificates =
                    crate::material::load_configuration(&root, &snapshot.configuration)?;
            }
        }

        self.active
            .store(std::sync::Arc::new(super::ActiveConfigurations::new(
                entries,
            )));

        self.certificate_material_directory = Some(root);

        Ok(self)
    }

    pub fn install_certificate_material(
        &self,
        request: &InstallCertificateMaterialRequest,
    ) -> CommandOutcome {
        let Some(root) = self.certificate_material_directory.as_deref() else {
            return CommandOutcome::Rejected(AdmissionError::CertificateMaterial);
        };

        let _authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => return CommandOutcome::Rejected(AdmissionError::Persistence),
        };

        let outcome = match crate::material::install_certificate_material(root, request) {
            Ok(true) => CommandOutcome::Accepted,
            Ok(false) => CommandOutcome::AlreadyApplied,
            Err(_) => CommandOutcome::Rejected(AdmissionError::CertificateMaterial),
        };

        if matches!(
            &outcome,
            CommandOutcome::Accepted | CommandOutcome::AlreadyApplied
        ) {
            let reference = format!(
                "{}/{}/{}/{}",
                request.organization_id,
                request.project_id,
                request.certificate_id,
                request.certificate_version
            );

            match self.material_retirement_since.lock() {
                Ok(mut retirements) => {
                    retirements.remove(&reference);
                }
                Err(_) => return CommandOutcome::Rejected(AdmissionError::Persistence),
            }
        }

        outcome
    }

    pub fn retire_unused_certificate_material(&self) {
        let now = Instant::now();

        let Ok(mut last_gc) = self.last_material_gc.lock() else {
            return;
        };

        if last_gc.is_some_and(|last| now.duration_since(last) < Duration::from_secs(15)) {
            return;
        }

        *last_gc = Some(now);

        drop(last_gc);

        let Some(root) = self.certificate_material_directory.as_deref() else {
            return;
        };

        let Ok(_authority) = self.authority.lock() else {
            return;
        };

        let active = self.active.load_full();

        let active_references: BTreeSet<String> = active
            .entries
            .values()
            .filter(|snapshot| snapshot.is_live())
            .flat_map(|snapshot| snapshot.routes.iter())
            .filter_map(|route| route.tls.as_ref())
            .map(|tls| tls.material_reference.clone())
            .collect();

        let Ok(disk_references) = crate::material::discover_material_references(root) else {
            return;
        };

        let Ok(mut retirement_since) = self.material_retirement_since.lock() else {
            return;
        };

        retirement_since.retain(|reference, _| {
            disk_references.contains(reference) && !active_references.contains(reference)
        });

        for reference in disk_references.difference(&active_references) {
            let first_seen = retirement_since.entry(reference.clone()).or_insert(now);

            if now.duration_since(*first_seen) >= Duration::from_secs(60)
                && crate::material::remove_certificate_material(root, reference).is_ok()
            {
                retirement_since.remove(reference);
            }
        }
    }

    /// Selects prevalidated material from the same immutable routing snapshot.
    pub fn certificate_for_host(
        &self,
        host: &str,
    ) -> Option<std::sync::Arc<crate::material::CachedCertificate>> {
        let active = self.active.load();

        active.candidates(host).iter().find_map(|snapshot| {
            if !snapshot.is_live() {
                return None;
            }

            snapshot
                .certificates
                .get(host)
                .filter(|material| material.is_valid_now())
                .cloned()
        })
    }

    /// Returns certificate metadata admitted for the exact hostname in the
    /// active snapshot. Requests never supply certificate references.
    pub fn certificate_binding_for_host(&self, host: &str) -> Option<(String, Vec<u8>, Vec<u8>)> {
        let active = self.active.load();

        active.candidates(host).iter().find_map(|snapshot| {
            if !snapshot.is_live() {
                return None;
            }

            snapshot.routes.iter().find_map(|route| {
                if route.hostname != host {
                    return None;
                }

                let tls = route.tls.as_ref()?;

                if tls.material_reference.is_empty()
                    || tls.public_certificate_hash.len() != 32
                    || tls.certificate_chain_hash.len() != 32
                {
                    return None;
                }

                Some((
                    tls.material_reference.clone(),
                    tls.public_certificate_hash.clone(),
                    tls.certificate_chain_hash.clone(),
                ))
            })
        })
    }
}
