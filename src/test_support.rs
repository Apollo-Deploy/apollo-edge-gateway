//! Independently signed input fixtures shared by snapshot and command tests.
use prost::Message;
use sha2::{Digest, Sha256};

use crate::control::{
    BackendHealthRequirement, EdgeBackend, EdgeConfiguration, EdgeProtocol, EdgeRoute,
    NetworkScope, ProductIdentity, WorkloadEndpoint,
};

pub(crate) fn configuration() -> EdgeConfiguration {
    let identity = ProductIdentity {
        organization_id: "org".into(),
        project_id: "project".into(),
        service_id: "service".into(),
        deployment_id: "deployment".into(),
        release_id: "release".into(),
        route_id: "route".into(),
        traffic_target_id: "target".into(),
    };

    let mut configuration = EdgeConfiguration {
        identity: Some(identity.clone()),
        controller_epoch: 1,
        generation: 1,
        issued_at_unix_ms: 1,
        valid_until_unix_ms: i64::MAX,
        max_header_bytes: 64 * 1024,
        max_body_bytes: 64 * 1024 * 1024,
        max_connections: 1_024,
        max_concurrency: 1_024,
        drain_timeout_seconds: 60,
        retry_max_attempts: 1,
        semantic_hash: vec![1; 32],
        routes: vec![EdgeRoute {
            identity: Some(identity),
            hostname: "api.example.com".into(),
            path_match: "/".into(),
            protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
            backends: vec![EdgeBackend {
                endpoint: Some(WorkloadEndpoint {
                    workload_id: "workload".into(),
                    workload_generation: 1,
                    node_id: "node".into(),
                    region_id: "region".into(),
                    cell_id: "cell".into(),
                    address: "10.0.0.5".into(),
                    port: 8080,
                    protocol: EdgeProtocol::Http1 as i32,
                    network_scope: NetworkScope::CellPrivate as i32,
                    observed_at_unix_ms: 1,
                    ready: true,
                    healthy: true,
                }),
                health_requirement: BackendHealthRequirement::ReadyAndHealthy as i32,
                weight: 1,
                draining: false,
            }],
            route_generation: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    sign_configuration(&mut configuration);

    configuration
}

pub(crate) fn sign_configuration(configuration: &mut EdgeConfiguration) {
    configuration.configuration_hash.clear();

    configuration.configuration_hash = Sha256::digest(configuration.encode_to_vec()).to_vec();
}
