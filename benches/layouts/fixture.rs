use std::net::{Ipv4Addr, SocketAddr};

use apollo_edge_gateway::GatewayState;
use apollo_edge_gateway::control::{
    ApplyConfigurationRequest, BackendHealthRequirement, CommandOutcome, EdgeBackend,
    EdgeConfiguration, EdgeProtocol, EdgeRoute, EdgeTlsBinding, NetworkScope, OperationIdentity,
    ProductIdentity, RouteLookup, WorkloadEndpoint,
};
use prost::Message;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) id: &'static str,
    pub(crate) targets: usize,
    pub(crate) routes: usize,
    pub(crate) distinct_hosts: bool,
    pub(crate) long_hosts: bool,
}

pub(crate) const LAYOUTS: [Layout; 4] = [
    Layout {
        id: "distinct-host-fleet128x8",
        targets: 128,
        routes: 8,
        distinct_hosts: true,
        long_hosts: false,
    },
    Layout {
        id: "shared-host-fleet128x8",
        targets: 128,
        routes: 8,
        distinct_hosts: false,
        long_hosts: false,
    },
    Layout {
        id: "one-target-routes1024",
        targets: 1,
        routes: 1024,
        distinct_hosts: false,
        long_hosts: false,
    },
    Layout {
        id: "long-host-fleet128x8",
        targets: 128,
        routes: 8,
        distinct_hosts: true,
        long_hosts: true,
    },
];

pub(crate) const SMALL: Layout = Layout {
    id: "lifecycle",
    targets: 1,
    routes: 1,
    distinct_hosts: true,
    long_hosts: false,
};

pub(crate) fn identity(target: usize) -> ProductIdentity {
    ProductIdentity {
        organization_id: "org".into(),
        project_id: "project".into(),
        service_id: format!("service-{target:03}"),
        deployment_id: format!("deployment-{target:03}"),
        release_id: format!("release-{target:03}"),
        route_id: format!("route-{target:03}"),
        traffic_target_id: format!("target-{target:03}"),
    }
}

pub(crate) fn hostname(layout: Layout, target: usize, route: usize) -> String {
    if layout.long_hosts {
        // Four valid DNS labels, exactly 253 bytes, still unique for every route.
        format!(
            "{}.{}.{}.t{target:03}-r{route:04}-{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(50)
        )
    } else if layout.distinct_hosts {
        format!("t{target:03}-r{route:04}.bench.example")
    } else {
        "shared.bench.example".into()
    }
}

pub(crate) fn path(target: usize, route: usize) -> String {
    // Trailing separators prevent /r0001 from also matching /r00010.
    format!("/t{target:03}/r{route:04}/")
}

pub(crate) fn address(layout: Layout, target: usize, route: usize, variant: usize) -> SocketAddr {
    SocketAddr::from((
        Ipv4Addr::new(10, 23, 0, 1),
        (10_000 + target * layout.routes + route + variant * 2_000) as u16,
    ))
}

pub(crate) fn sign(mut configuration: EdgeConfiguration) -> ApplyConfigurationRequest {
    configuration.configuration_hash.clear();

    configuration.configuration_hash = Sha256::digest(configuration.encode_to_vec()).to_vec();

    let operation = OperationIdentity {
        operation_id: format!(
            "apply-{}-{}",
            configuration
                .identity
                .as_ref()
                .expect("identity")
                .traffic_target_id,
            configuration.generation
        ),
        effect_id: format!("effect-{}", configuration.generation),
        controller_epoch: configuration.controller_epoch,
        generation: configuration.generation,
        configuration_hash: configuration.configuration_hash.clone(),
    };

    ApplyConfigurationRequest {
        operation: Some(operation),
        identity: configuration.identity.clone(),
        configuration: Some(configuration),
    }
}

pub(crate) fn request(
    layout: Layout,
    target: usize,
    generation: u64,
    variant: usize,
) -> ApplyConfigurationRequest {
    let owner = identity(target);

    let routes = (0..layout.routes)
        .map(|route| {
            let host = hostname(layout, target, route);

            EdgeRoute {
                identity: Some(ProductIdentity {
                    route_id: format!("route-{target:03}-{route:04}"),
                    ..owner.clone()
                }),
                hostname: host.clone(),
                path_match: path(target, route),
                methods: vec!["GET".into(), "HEAD".into()],
                protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
                backends: vec![EdgeBackend {
                    endpoint: Some(WorkloadEndpoint {
                        workload_id: format!("workload-{target:03}-{route:04}"),
                        workload_generation: 1,
                        node_id: "node".into(),
                        region_id: "region".into(),
                        cell_id: "cell".into(),
                        address: "10.23.0.1".into(),
                        port: u32::from(address(layout, target, route, variant).port()),
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
                tls: Some(EdgeTlsBinding {
                    certificate_id: "cert".into(),
                    certificate_version: 1,
                    hostname: host,
                    material_reference: "org/project/cert/1".into(),
                    public_certificate_hash: vec![0x31; 32],
                    certificate_chain_hash: vec![0x52; 32],
                }),
                route_generation: generation,
            }
        })
        .collect();

    sign(EdgeConfiguration {
        identity: Some(owner),
        controller_epoch: 1,
        generation,
        configuration_hash: Vec::new(),
        issued_at_unix_ms: 1,
        valid_until_unix_ms: i64::MAX,
        routes,
        max_header_bytes: (64 + variant as u32 * 32) * 1024,
        max_body_bytes: 64 * 1024 * 1024,
        max_connections: 1024,
        max_concurrency: 1024,
        drain_timeout_seconds: 60,
        retry_max_attempts: 2,
        retry_methods: vec!["GET".into(), "HEAD".into()],
        semantic_hash: vec![0x73; 32],
    })
}

pub(crate) fn accepted(outcome: CommandOutcome) {
    assert!(
        matches!(outcome, CommandOutcome::Accepted),
        "expected new admitted publication: {outcome:?}"
    );
}

pub(crate) fn publish_health(state: &GatewayState) {
    state.publish_health(
        state
            .health_targets()
            .into_iter()
            .map(|target| (target.key, true))
            .collect(),
    );
}

pub(crate) struct Fixture {
    pub(crate) state: GatewayState,
    pub(crate) host: String,
    pub(crate) path: String,
}

pub(crate) fn fixture(layout: Layout) -> Fixture {
    let state = GatewayState::empty();

    for target in 0..layout.targets {
        accepted(state.apply(request(layout, target, 1, 0)));
    }

    assert_eq!(state.health_targets().len(), layout.targets * layout.routes);

    publish_health(&state);

    // Validate every route, not just the timed late hit: catches shared-host ambiguity/cross-target leaks.
    for target in 0..layout.targets {
        for route in 0..layout.routes {
            let host = hostname(layout, target, route);

            let query = path(target, route) + "request";

            assert_eq!(
                state.resolve_backend(&host, &query, "GET"),
                RouteLookup::Backend(address(layout, target, route, 0))
            );
        }
    }

    let f = Fixture {
        state,
        host: hostname(layout, layout.targets - 1, layout.routes - 1),
        path: path(layout.targets - 1, layout.routes - 1) + "request",
    };

    validate(&f, layout, 0);

    f
}

pub(crate) fn validate(f: &Fixture, layout: Layout, variant: usize) {
    let limits = f.state.limits_for(&f.host, &f.path).expect("exact limits");

    assert_eq!(limits.max_header_bytes, (64 + variant * 32) * 1024);

    assert_eq!(limits.retry_max_attempts, 2);

    assert_eq!(limits.retry_methods, ["GET", "HEAD"]);

    for method in ["GET", "HEAD"] {
        assert_eq!(
            f.state.resolve_backend(&f.host, &f.path, method),
            RouteLookup::Backend(address(
                layout,
                layout.targets - 1,
                layout.routes - 1,
                variant
            ))
        );
    }

    assert_eq!(
        f.state.resolve_backend(&f.host, &f.path, "POST"),
        RouteLookup::MethodNotAllowed
    );

    assert_eq!(
        f.state.resolve_backend(&f.host, "/absent/", "GET"),
        RouteLookup::NotFound
    );

    assert_eq!(
        f.state
            .resolve_backend("absent.bench.example", &f.path, "GET"),
        RouteLookup::NotFound
    );

    assert!(f.state.limits_for(&f.host, "/absent/").is_none());

    assert!(
        f.state
            .certificate_binding_for_host("absent.bench.example")
            .is_none()
    );

    assert_eq!(
        f.state.certificate_binding_for_host(&f.host),
        Some(("org/project/cert/1".into(), vec![0x31; 32], vec![0x52; 32]))
    );

    if layout.long_hosts {
        assert_eq!(f.host.len(), 253);
    }
}

pub(crate) fn semantic_controls() {
    // Not a performance assertion: overlapping targets MUST fail closed, unlike disjoint shared-host paths.
    let shared = Layout {
        targets: 2,
        routes: 1,
        ..LAYOUTS[1]
    };

    let state = GatewayState::empty();

    accepted(state.apply(request(shared, 0, 1, 0)));

    let mut conflict = request(shared, 1, 1, 0)
        .configuration
        .expect("configuration");

    conflict.routes[0].path_match = path(0, 0);

    accepted(state.apply(sign(conflict)));

    publish_health(&state);

    assert_eq!(
        state.resolve_backend("shared.bench.example", &path(0, 0), "GET"),
        RouteLookup::Ambiguous
    );

    assert_eq!(
        state.resolve_backend("shared.bench.example", &path(0, 0), "POST"),
        RouteLookup::MethodNotAllowed
    );

    // Within one target, the longest admitted prefix wins; a denied method must not fall back.
    let nested = Layout {
        targets: 1,
        routes: 2,
        ..shared
    };

    let state = GatewayState::empty();

    let mut configuration = request(nested, 0, 1, 0)
        .configuration
        .expect("configuration");

    configuration.routes[0].path_match = "/".into();

    configuration.routes[0].methods.push("POST".into());

    configuration.routes[1].path_match = "/nested/".into();

    accepted(state.apply(sign(configuration)));

    assert_eq!(
        state.resolve_backend("shared.bench.example", "/nested/request", "GET"),
        RouteLookup::Unavailable
    );

    publish_health(&state);

    assert_eq!(
        state.resolve_backend("shared.bench.example", "/nested/request", "GET"),
        RouteLookup::Backend(address(nested, 0, 1, 0))
    );

    assert_eq!(
        state.resolve_backend("shared.bench.example", "/nested/request", "POST"),
        RouteLookup::MethodNotAllowed
    );

    eprintln!(
        "validated controls=overlapping-target-ambiguity,longest-prefix,method-no-fallback,unpublished-health-fail-closed"
    );
}
