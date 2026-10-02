//! Runtime route lookup, per-route limits, and local backend health publication.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::snapshot::{HealthTarget, Snapshot};

use super::GatewayState;

#[derive(Debug, PartialEq, Eq)]
pub enum RouteLookup {
    Backend(SocketAddr),
    NotFound,
    MethodNotAllowed,
    Unavailable,
    Ambiguous,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    pub max_header_bytes: usize,
    pub max_body_bytes: u64,
    pub max_concurrency: usize,
    pub retry_max_attempts: usize,
    pub retry_methods: Vec<String>,
}

impl GatewayState {
    pub fn limits_for(&self, host: &str, path: &str) -> Option<RuntimeLimits> {
        let active = self.active.load();
        active.candidates(host).iter().find_map(|snapshot| {
            if !snapshot.is_live() {
                return None;
            }
            snapshot
                .route_for_host_path(host, path)
                .map(|_| RuntimeLimits {
                    max_header_bytes: snapshot.configuration.max_header_bytes as usize,
                    max_body_bytes: snapshot.configuration.max_body_bytes,
                    max_concurrency: snapshot.configuration.max_concurrency as usize,
                    retry_max_attempts: snapshot.configuration.retry_max_attempts as usize,
                    retry_methods: snapshot.configuration.retry_methods.clone(),
                })
        })
    }

    pub fn resolve_backend(&self, host: &str, path: &str, method: &str) -> RouteLookup {
        let active = self.active.load();
        let draining = self.draining.load();
        let mut matched: Option<&Arc<Snapshot>> = None;
        let mut method_blocked = false;
        for snapshot in active.candidates(host) {
            if !snapshot.is_live() {
                continue;
            }
            if draining.contains_key(&snapshot.identity.traffic_target_id) {
                continue;
            }
            let Some(route) = snapshot.route_for_host_path(host, path) else {
                continue;
            };
            if !route.methods.is_empty() && !route.methods.iter().any(|allowed| allowed == method) {
                method_blocked = true;
                continue;
            }
            if matched.is_some() {
                return RouteLookup::Ambiguous;
            }
            matched = Some(snapshot);
        }
        let Some(snapshot) = matched else {
            return if method_blocked {
                RouteLookup::MethodNotAllowed
            } else {
                RouteLookup::NotFound
            };
        };
        let health = self.local_health.load();
        snapshot
            .select_backend(host, path, method, |key| {
                health.get(key).copied().unwrap_or(false)
            })
            .map(RouteLookup::Backend)
            .unwrap_or(RouteLookup::Unavailable)
    }

    pub fn health_targets(&self) -> Vec<HealthTarget> {
        let active = self.active.load_full();
        let mut targets = BTreeMap::new();
        for snapshot in active.entries.values() {
            if snapshot.withdrawn
                || self
                    .draining
                    .load()
                    .contains_key(&snapshot.identity.traffic_target_id)
            {
                continue;
            }
            for target in snapshot.health_targets() {
                targets.insert(target.key.clone(), target.clone());
            }
        }
        targets.into_values().collect()
    }

    pub fn publish_health(&self, updates: BTreeMap<String, bool>) {
        self.local_health.store(Arc::new(updates));
    }
}
