//! Observed gateway state for the fleet and individual traffic targets.
use crate::snapshot::Snapshot;

use super::{EdgeConfigurationState, GatewayState, ProductIdentity, unix_ms};

impl GatewayState {
    pub fn inspect(&self) -> EdgeConfigurationState {
        let active = self.active.load_full();

        let authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => {
                return EdgeConfigurationState {
                    withdrawn: true,
                    observed_at_unix_ms: unix_ms(),
                    ..Default::default()
                };
            }
        };

        if active.entries.len() == 1 {
            if let Some(snapshot) = active.entries.values().next() {
                let draining = authority
                    .drains
                    .contains_key(&snapshot.identity.traffic_target_id);

                return snapshot_state(snapshot, draining);
            }
        }

        let mut routes = Vec::new();

        for snapshot in active.entries.values() {
            if authority
                .drains
                .contains_key(&snapshot.identity.traffic_target_id)
            {
                continue;
            }

            routes.extend(snapshot.routes.iter().filter_map(|route| {
                route
                    .identity
                    .as_ref()
                    .map(|identity| identity.route_id.clone())
            }));
        }

        routes.retain(|route_id| !route_id.is_empty());

        routes.sort();

        routes.dedup();

        let latest = active
            .entries
            .values()
            .max_by_key(|snapshot| (snapshot.controller_epoch, snapshot.generation));

        EdgeConfigurationState {
            identity: None,
            controller_epoch: authority.epoch,
            generation: latest
                .map(|snapshot| snapshot.generation)
                .unwrap_or_default(),
            configuration_hash: if active.entries.len() == 1 {
                latest
                    .map(|snapshot| snapshot.configuration_hash.clone())
                    .unwrap_or_default()
            } else {
                Vec::new()
            },
            withdrawn: active.entries.is_empty(),
            valid_until_unix_ms: latest
                .map(|snapshot| snapshot.valid_until_unix_ms)
                .unwrap_or_default(),
            active_connections: 0,
            observed_at_unix_ms: unix_ms(),
            semantic_hash: Vec::new(),
            serving_route_ids: routes,
        }
    }

    pub fn inspect_for(&self, identity: Option<ProductIdentity>) -> EdgeConfigurationState {
        let Some(identity) = identity else {
            return self.inspect();
        };

        let active = self.active.load_full();

        if let Some(snapshot) = active.entries.get(&identity.traffic_target_id) {
            if snapshot.identity.organization_id == identity.organization_id
                && snapshot.identity.project_id == identity.project_id
            {
                let draining = self
                    .draining
                    .load()
                    .contains_key(&identity.traffic_target_id);

                return snapshot_state(snapshot, draining);
            }

            return EdgeConfigurationState {
                identity: Some(identity),
                withdrawn: true,
                observed_at_unix_ms: unix_ms(),
                ..Default::default()
            };
        }

        let authority = match self.authority.lock() {
            Ok(authority) => authority,
            Err(_) => {
                return EdgeConfigurationState {
                    identity: Some(identity),
                    withdrawn: true,
                    observed_at_unix_ms: unix_ms(),
                    ..Default::default()
                };
            }
        };

        if let Some(tombstone) = authority.tombstones.get(&identity.traffic_target_id) {
            EdgeConfigurationState {
                identity: Some(identity),
                controller_epoch: tombstone.controller_epoch,
                generation: tombstone.generation,
                configuration_hash: tombstone.configuration_hash.clone(),
                withdrawn: true,
                observed_at_unix_ms: unix_ms(),
                ..Default::default()
            }
        } else {
            EdgeConfigurationState {
                identity: Some(identity),
                withdrawn: true,
                observed_at_unix_ms: unix_ms(),
                ..Default::default()
            }
        }
    }
}

fn snapshot_state(snapshot: &Snapshot, draining: bool) -> EdgeConfigurationState {
    let now = unix_ms();

    EdgeConfigurationState {
        identity: Some(snapshot.identity.clone()),
        controller_epoch: snapshot.controller_epoch,
        generation: snapshot.generation,
        configuration_hash: snapshot.configuration_hash.clone(),
        withdrawn: snapshot.withdrawn,
        valid_until_unix_ms: snapshot.valid_until_unix_ms,
        active_connections: 0,
        observed_at_unix_ms: now,
        semantic_hash: snapshot.configuration.semantic_hash.clone(),
        serving_route_ids: if !snapshot.withdrawn && !draining && snapshot.valid_until_unix_ms > now
        {
            snapshot
                .routes
                .iter()
                .filter_map(|route| {
                    route
                        .identity
                        .as_ref()
                        .map(|identity| identity.route_id.clone())
                })
                .filter(|route_id| !route_id.is_empty())
                .collect()
        } else {
            Vec::new()
        },
    }
}
