use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::net::Ipv4Addr;

use apollo_edge_gateway::GatewayState;
use apollo_edge_gateway::control::WorkloadEndpoint;
use apollo_edge_gateway::control::{
    ApplyConfigurationRequest, BackendHealthRequirement, CommandOutcome, EdgeBackend,
    EdgeConfiguration, EdgeProtocol, EdgeRoute, EdgeTlsBinding, NetworkScope, OperationIdentity,
    ProductIdentity, RouteLookup,
};
use prost::Message;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub(crate) struct Shape {
    pub(crate) id: &'static str,
    pub(crate) targets: usize,
    pub(crate) routes: usize,
    pub(crate) backends: usize,
    pub(crate) healthy: bool,
}

pub(crate) const SHAPES: [Shape; 4] = [
    Shape {
        id: "small",
        targets: 1,
        routes: 1,
        backends: 1,
        healthy: true,
    },
    Shape {
        id: "fleet",
        targets: 128,
        routes: 8,
        backends: 4,
        healthy: true,
    },
    Shape {
        id: "wide-healthy",
        targets: 1,
        routes: 1,
        backends: 256,
        healthy: true,
    },
    Shape {
        id: "wide-unhealthy",
        targets: 1,
        routes: 1,
        backends: 256,
        healthy: false,
    },
];

#[derive(Clone, Copy)]
pub(crate) enum Op {
    Limits,
    ResolveGet,
    ResolveHead,
    Decision,
    Binding,
    HostMiss,
    PathMiss,
    Denied,
    LimitsMiss,
    BindingMiss,
}

impl Op {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Limits => "limits",
            Self::ResolveGet => "resolve-get",
            Self::ResolveHead => "resolve-head",
            Self::Decision => "decision",
            Self::Binding => "binding",
            Self::HostMiss => "host-miss",
            Self::PathMiss => "path-miss",
            Self::Denied => "method-denied",
            Self::LimitsMiss => "limits-miss",
            Self::BindingMiss => "binding-miss",
        }
    }
}

pub(crate) const OPS: [Op; 10] = [
    Op::Limits,
    Op::ResolveGet,
    Op::ResolveHead,
    Op::Decision,
    Op::Binding,
    Op::HostMiss,
    Op::PathMiss,
    Op::Denied,
    Op::LimitsMiss,
    Op::BindingMiss,
];

pub(crate) struct Fixture {
    pub(crate) state: GatewayState,
    pub(crate) host: String,
    pub(crate) path: String,
}

pub(crate) fn build_fixture(shape: Shape) -> Fixture {
    let state = GatewayState::empty();

    for target in 0..shape.targets {
        let identity = ProductIdentity {
            organization_id: "org".into(),
            project_id: "project".into(),
            service_id: format!("service-{target:03}"),
            deployment_id: format!("deployment-{target:03}"),
            release_id: format!("release-{target:03}"),
            route_id: format!("route-{target:03}"),
            traffic_target_id: format!("target-{target:03}"),
        };

        let routes = (0..shape.routes)
            .map(|route| {
                let hostname = format!("target-{target:03}.bench.example");

                let backends = (0..shape.backends)
                    .map(|backend| {
                        let index = (target * shape.routes + route) * shape.backends + backend;

                        EdgeBackend {
                            endpoint: Some(WorkloadEndpoint {
                                workload_id: format!("workload-{index:05}"),
                                workload_generation: index as u64 + 1,
                                node_id: "node".into(),
                                region_id: "region".into(),
                                cell_id: "cell".into(),
                                address: "10.23.0.1".into(),
                                port: 10_000 + index as u32,
                                protocol: EdgeProtocol::Http1 as i32,
                                network_scope: NetworkScope::CellPrivate as i32,
                                observed_at_unix_ms: 1,
                                ready: true,
                                healthy: true,
                            }),
                            health_requirement: BackendHealthRequirement::ReadyAndHealthy as i32,
                            weight: 1,
                            draining: false,
                        }
                    })
                    .collect();

                EdgeRoute {
                    identity: Some(ProductIdentity {
                        route_id: format!("route-{target:03}-{route:02}"),
                        ..identity.clone()
                    }),
                    hostname: hostname.clone(),
                    path_match: format!("/route-{route:02}/"),
                    methods: vec!["GET".into(), "HEAD".into()],
                    protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
                    backends,
                    tls: Some(EdgeTlsBinding {
                        certificate_id: "cert".into(),
                        certificate_version: 1,
                        hostname,
                        material_reference: "org/project/cert/1".into(),
                        public_certificate_hash: vec![0x31; 32],
                        certificate_chain_hash: vec![0x52; 32],
                    }),
                    route_generation: route as u64 + 1,
                }
            })
            .collect();

        let mut configuration = EdgeConfiguration {
            identity: Some(identity.clone()),
            controller_epoch: 1,
            generation: 1,
            configuration_hash: Vec::new(),
            issued_at_unix_ms: 1,
            valid_until_unix_ms: i64::MAX,
            routes,
            max_header_bytes: 64 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            max_connections: 1024,
            max_concurrency: 1024,
            drain_timeout_seconds: 60,
            retry_max_attempts: 2,
            retry_methods: vec!["GET".into(), "HEAD".into()],
            semantic_hash: vec![0x73; 32],
        };

        // Independent Prost encoding/SHA256 signing, not a production/test fixture helper.
        configuration.configuration_hash = Sha256::digest(configuration.encode_to_vec()).to_vec();

        let operation = OperationIdentity {
            operation_id: format!("operation-{target:03}"),
            effect_id: format!("effect-{target:03}"),
            controller_epoch: 1,
            generation: 1,
            configuration_hash: configuration.configuration_hash.clone(),
        };

        let outcome = state.apply(ApplyConfigurationRequest {
            operation: Some(operation),
            identity: Some(identity),
            configuration: Some(configuration),
        });

        assert!(
            matches!(outcome, CommandOutcome::Accepted),
            "{} target {target}: {outcome:?}",
            shape.id
        );
    }

    let health = state.health_targets();

    assert_eq!(health.len(), shape.targets * shape.routes * shape.backends);

    let keys: BTreeSet<_> = health.iter().map(|target| &target.key).collect();

    let addresses: BTreeSet<_> = health.iter().map(|target| target.address).collect();

    assert_eq!(
        keys.len(),
        health.len(),
        "distinct target/workload/generation health keys"
    );

    assert_eq!(
        addresses.len(),
        health.len(),
        "distinct private endpoint ports"
    );

    let updates: BTreeMap<_, _> = health
        .iter()
        .map(|target| (target.key.clone(), shape.healthy))
        .collect();

    state.publish_health(updates);

    let fixture = Fixture {
        state,
        host: format!("target-{:03}.bench.example", shape.targets - 1),
        path: format!("/route-{:02}/request", shape.routes - 1),
    };

    validate_fixture(&fixture, shape);

    fixture
}

pub(crate) fn validate_fixture(f: &Fixture, shape: Shape) {
    let limits = f
        .state
        .limits_for(&f.host, &f.path)
        .expect("exact target limits");

    assert_eq!(limits.max_header_bytes, 64 * 1024);

    assert_eq!(limits.max_body_bytes, 64 * 1024 * 1024);

    assert_eq!(limits.max_concurrency, 1024);

    assert_eq!(limits.retry_max_attempts, 2);

    assert_eq!(limits.retry_methods, ["GET", "HEAD"]);

    // The final target and final route make scans deterministic, rather than matching target zero.
    let first_index = (shape.targets * shape.routes - 1) * shape.backends;

    let mut observed = BTreeSet::new();

    for method in ["GET", "HEAD"] {
        for _ in 0..shape.backends {
            match f.state.resolve_backend(&f.host, &f.path, method) {
                RouteLookup::Backend(address) if shape.healthy => {
                    assert_eq!(address.ip(), Ipv4Addr::new(10, 23, 0, 1));

                    assert!(
                        (10_000 + first_index..10_000 + first_index + shape.backends)
                            .contains(&(address.port() as usize))
                    );

                    observed.insert(address);
                }
                RouteLookup::Unavailable if !shape.healthy => {}
                result => panic!("{} exact target {method}: {result:?}", shape.id),
            }
        }
    }

    if shape.healthy {
        assert_eq!(
            observed.len(),
            shape.backends,
            "all exact-route endpoints selectable"
        );
    }

    assert_eq!(
        f.state
            .resolve_backend("missing.bench.example", &f.path, "GET"),
        RouteLookup::NotFound
    );

    assert_eq!(
        f.state.resolve_backend(&f.host, "/missing", "GET"),
        RouteLookup::NotFound
    );

    assert_eq!(
        f.state.resolve_backend(&f.host, &f.path, "POST"),
        RouteLookup::MethodNotAllowed
    );

    assert!(
        f.state
            .limits_for("missing.bench.example", &f.path)
            .is_none()
    );

    assert!(
        f.state
            .certificate_binding_for_host("missing.bench.example")
            .is_none()
    );

    assert_eq!(
        f.state.certificate_binding_for_host(&f.host),
        Some(("org/project/cert/1".into(), vec![0x31; 32], vec![0x52; 32]))
    );
}

#[inline]
pub(crate) fn exercise(f: &Fixture, op: Op) {
    let state = black_box(&f.state);

    let host = black_box(f.host.as_str());

    let path = black_box(f.path.as_str());

    match op {
        Op::Limits => drop(black_box(state.limits_for(host, path))),
        Op::ResolveGet => {
            black_box(state.resolve_backend(host, path, black_box("GET")));
        }
        Op::ResolveHead => {
            black_box(state.resolve_backend(host, path, black_box("HEAD")));
        }
        Op::Decision => {
            // Owned retry-method strings are dropped INSIDE the measured operation.
            drop(black_box(state.limits_for(host, path)));

            black_box(state.resolve_backend(host, path, black_box("GET")));
        }
        Op::Binding => drop(black_box(state.certificate_binding_for_host(host))),
        Op::HostMiss => {
            black_box(state.resolve_backend(
                black_box("missing.bench.example"),
                path,
                black_box("GET"),
            ));
        }
        Op::PathMiss => {
            black_box(state.resolve_backend(host, black_box("/missing"), black_box("GET")));
        }
        Op::Denied => {
            black_box(state.resolve_backend(host, path, black_box("POST")));
        }
        Op::LimitsMiss => drop(black_box(
            state.limits_for(black_box("missing.bench.example"), path),
        )),
        Op::BindingMiss => drop(black_box(
            state.certificate_binding_for_host(black_box("missing.bench.example")),
        )),
    }
}
