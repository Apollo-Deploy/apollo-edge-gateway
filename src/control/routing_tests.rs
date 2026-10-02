//! Public routing contracts shared by the scan-based and indexed control implementations.

use std::fs;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::control::{
    ApplyConfigurationRequest, CommandOutcome, DrainConfigurationRequest, EdgeConfiguration,
    EdgeTlsBinding, GatewayState, OperationIdentity, RouteLookup, RuntimeLimits,
    WithdrawConfigurationRequest,
};
use crate::snapshot::AdmissionError;
use crate::state::StateStore;
use crate::test_support::{configuration, sign_configuration};

fn target_configuration(
    target_id: &str,
    generation: u64,
    routes: &[(&str, &str, u32)],
) -> EdgeConfiguration {
    let mut input = configuration();
    let identity = input.identity.as_mut().expect("fixture identity");
    identity.traffic_target_id = target_id.into();
    input.generation = generation;
    let template = input.routes.remove(0);
    input.routes = routes
        .iter()
        .enumerate()
        .map(|(index, (host, path, port))| {
            let mut route = template.clone();
            let mut identity = input.identity.clone().expect("fixture identity");
            identity.route_id = format!("{target_id}-route-{index}");
            route.identity = Some(identity);
            route.hostname = (*host).into();
            route.path_match = (*path).into();
            route.route_generation = generation;
            route.backends[0]
                .endpoint
                .as_mut()
                .expect("fixture endpoint")
                .port = *port;
            route
        })
        .collect();
    input
}

fn apply_request(mut input: EdgeConfiguration) -> ApplyConfigurationRequest {
    sign_configuration(&mut input);
    let identity = input.identity.clone().expect("fixture identity");
    ApplyConfigurationRequest {
        operation: Some(OperationIdentity {
            operation_id: format!("{}-op-{}", identity.traffic_target_id, input.generation),
            effect_id: format!("{}-effect-{}", identity.traffic_target_id, input.generation),
            controller_epoch: input.controller_epoch,
            generation: input.generation,
            configuration_hash: input.configuration_hash.clone(),
        }),
        identity: Some(identity),
        configuration: Some(input),
    }
}

fn apply(state: &GatewayState, input: EdgeConfiguration) -> ApplyConfigurationRequest {
    let request = apply_request(input);
    let outcome = state.apply(request.clone());
    assert!(matches!(outcome, CommandOutcome::Accepted), "{outcome:?}");
    request
}

fn publish_health(state: &GatewayState, healthy: impl Fn(SocketAddr) -> bool) {
    state.publish_health(
        state
            .health_targets()
            .into_iter()
            .map(|target| (target.key, healthy(target.address)))
            .collect(),
    );
}

fn backend(port: u16) -> RouteLookup {
    RouteLookup::Backend(SocketAddr::from(([10, 0, 0, 5], port)))
}

fn set_limits(input: &mut EdgeConfiguration, limits: &RuntimeLimits) {
    input.max_header_bytes = limits.max_header_bytes as u32;
    input.max_body_bytes = limits.max_body_bytes;
    input.max_concurrency = limits.max_concurrency as u32;
    input.retry_max_attempts = limits.retry_max_attempts as u32;
    input.retry_methods = limits.retry_methods.clone();
}

fn limits(marker: usize) -> RuntimeLimits {
    RuntimeLimits {
        max_header_bytes: marker * 4_096,
        max_body_bytes: marker as u64 * 8_192,
        max_concurrency: marker * 3,
        retry_max_attempts: marker,
        retry_methods: if marker == 1 {
            vec!["GET".into()]
        } else {
            vec!["GET".into(), "HEAD".into()]
        },
    }
}

fn bind_tls(input: &mut EdgeConfiguration, route_index: usize, certificate_id: &str, marker: u8) {
    let route = &mut input.routes[route_index];
    route.tls = Some(EdgeTlsBinding {
        certificate_id: certificate_id.into(),
        certificate_version: 1,
        hostname: route.hostname.clone(),
        public_certificate_hash: vec![marker; 32],
        material_reference: format!("org/project/{certificate_id}/1"),
        certificate_chain_hash: vec![marker + 1; 32],
    });
}

fn binding(certificate_id: &str, marker: u8) -> Option<(String, Vec<u8>, Vec<u8>)> {
    Some((
        format!("org/project/{certificate_id}/1"),
        vec![marker; 32],
        vec![marker + 1; 32],
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct Lookups {
    backend: RouteLookup,
    limits: Option<RuntimeLimits>,
    certificate: Option<(String, Vec<u8>, Vec<u8>)>,
}

fn lookups(state: &GatewayState, host: &str, path: &str) -> Lookups {
    Lookups {
        backend: state.resolve_backend(host, path, "GET"),
        limits: state.limits_for(host, path),
        certificate: state.certificate_binding_for_host(host),
    }
}

fn assert_absent(state: &GatewayState, host: &str, path: &str) {
    assert_eq!(
        lookups(state, host, path),
        Lookups {
            backend: RouteLookup::NotFound,
            limits: None,
            certificate: None,
        },
        "{host}{path}"
    );
}

fn now_unix_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock after Unix epoch")
            .as_millis(),
    )
    .expect("wall clock fits in milliseconds")
}

fn wait_until_expired(deadline: i64) {
    let timeout = Instant::now() + Duration::from_secs(2);
    while now_unix_ms() <= deadline {
        assert!(Instant::now() < timeout, "expiration deadline did not pass");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn same_target_routes_choose_longest_prefix_before_method_admission() {
    let state = GatewayState::empty();
    let mut input = target_configuration(
        "target-a",
        1,
        &[
            ("shared.example.com", "/api", 8_101),
            ("other.example.com", "/", 8_102),
            ("shared.example.com", "/", 8_103),
            ("shared.example.com", "/api/admin", 8_104),
        ],
    );
    for route in &mut input.routes {
        route.methods = vec!["GET".into(), "POST".into()];
    }
    input.routes[3].methods = vec!["POST".into()];
    apply(&state, input);
    assert_eq!(
        state.resolve_backend("shared.example.com", "/api/item", "GET"),
        RouteLookup::Unavailable
    );
    publish_health(&state, |_| true);

    for (host, path, method, expected) in [
        ("shared.example.com", "/", "GET", backend(8_103)),
        ("shared.example.com", "/api/item", "GET", backend(8_101)),
        (
            "shared.example.com",
            "/api/admin/item",
            "POST",
            backend(8_104),
        ),
        (
            "shared.example.com",
            "/api/admin/item",
            "GET",
            RouteLookup::MethodNotAllowed,
        ),
        ("other.example.com", "/", "GET", backend(8_102)),
        ("missing.example.com", "/", "GET", RouteLookup::NotFound),
    ] {
        assert_eq!(
            state.resolve_backend(host, path, method),
            expected,
            "{method} {host}{path}"
        );
    }
}

#[test]
fn cross_target_eligibility_precedes_health_and_metadata_keep_target_and_route_order() {
    let mut first = target_configuration(
        "target-a",
        1,
        &[
            ("shared.example.com", "/z", 8_101),
            ("other.example.com", "/", 8_102),
            ("shared.example.com", "/api", 8_103),
        ],
    );
    first.routes[0].methods = vec!["POST".into()];
    first.routes[2].methods = vec!["GET".into()];
    set_limits(&mut first, &limits(1));
    bind_tls(&mut first, 0, "first-route", 1);
    bind_tls(&mut first, 1, "other-host", 3);
    bind_tls(&mut first, 2, "longer-route", 5);

    let mut second = target_configuration(
        "target-b",
        1,
        &[
            ("shared.example.com", "/api/private", 8_201),
            ("shared.example.com", "/b-only", 8_202),
        ],
    );
    second.routes[0].methods = vec!["GET".into(), "POST".into()];
    set_limits(&mut second, &limits(2));
    bind_tls(&mut second, 0, "second-target", 7);

    for inputs in [
        [second.clone(), first.clone()],
        [first.clone(), second.clone()],
    ] {
        let state = GatewayState::empty();
        for input in inputs {
            apply(&state, input);
        }
        for healthy_ports in [&[][..], &[8_103][..], &[8_201][..], &[8_103, 8_201][..]] {
            publish_health(&state, |address| healthy_ports.contains(&address.port()));
            assert_eq!(
                lookups(&state, "shared.example.com", "/api/private/item"),
                Lookups {
                    backend: RouteLookup::Ambiguous,
                    limits: Some(limits(1)),
                    certificate: binding("first-route", 1),
                },
                "healthy ports: {healthy_ports:?}"
            );
        }
        publish_health(&state, |_| true);
        assert_eq!(
            state.resolve_backend("shared.example.com", "/api/private/item", "POST"),
            backend(8_201)
        );
        assert_eq!(
            state.resolve_backend("shared.example.com", "/api/private/item", "DELETE"),
            RouteLookup::MethodNotAllowed
        );
        assert_eq!(
            lookups(&state, "shared.example.com", "/b-only/item"),
            Lookups {
                backend: backend(8_202),
                limits: Some(limits(2)),
                certificate: binding("first-route", 1),
            }
        );
        assert_eq!(
            lookups(&state, "shared.example.com", "/outside"),
            Lookups {
                backend: RouteLookup::NotFound,
                limits: None,
                certificate: binding("first-route", 1),
            }
        );
        assert_eq!(
            state.certificate_binding_for_host("other.example.com"),
            binding("other-host", 3)
        );
    }
}

#[test]
fn replacement_recovery_and_withdrawal_remove_only_retired_route_ownership() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = StateStore::new(directory.path().join("gateway.state"));
    let state = GatewayState::from_store(store.clone()).expect("initial state");
    let mut old = target_configuration(
        "target-a",
        1,
        &[
            ("retired.example.com", "/old", 8_101),
            ("shared.example.com", "/old", 8_102),
        ],
    );
    set_limits(&mut old, &limits(1));
    bind_tls(&mut old, 0, "retired-host", 1);
    bind_tls(&mut old, 1, "retired-path", 3);
    apply(&state, old);

    let mut peer = target_configuration("target-b", 1, &[("shared.example.com", "/stable", 8_201)]);
    set_limits(&mut peer, &limits(1));
    bind_tls(&mut peer, 0, "peer", 5);
    apply(&state, peer);
    publish_health(&state, |_| true);
    assert_eq!(
        lookups(&state, "retired.example.com", "/old/item"),
        Lookups {
            backend: backend(8_101),
            limits: Some(limits(1)),
            certificate: binding("retired-host", 1),
        }
    );
    assert_eq!(
        state.resolve_backend("shared.example.com", "/old/item", "GET"),
        backend(8_102)
    );

    let mut next = target_configuration(
        "target-a",
        2,
        &[
            ("current.example.com", "/new", 8_103),
            ("shared.example.com", "/new", 8_104),
        ],
    );
    set_limits(&mut next, &limits(2));
    bind_tls(&mut next, 0, "current-host", 7);
    bind_tls(&mut next, 1, "current-path", 9);
    let applied = apply(&state, next);
    let recovered = GatewayState::from_store(store.clone()).expect("recovered replacement");
    for current in [&state, &recovered] {
        publish_health(current, |_| true);
        assert_absent(current, "retired.example.com", "/old/item");
        assert_eq!(
            lookups(current, "current.example.com", "/new/item"),
            Lookups {
                backend: backend(8_103),
                limits: Some(limits(2)),
                certificate: binding("current-host", 7),
            }
        );
        for (path, expected_backend, expected_limits) in [
            ("/old/item", RouteLookup::NotFound, None),
            ("/new/item", backend(8_104), Some(limits(2))),
            ("/stable/item", backend(8_201), Some(limits(1))),
        ] {
            assert_eq!(
                lookups(current, "shared.example.com", path),
                Lookups {
                    backend: expected_backend,
                    limits: expected_limits,
                    certificate: binding("current-path", 9),
                },
                "shared.example.com{path}"
            );
        }
    }

    let mut operation = applied.operation.expect("applied operation");
    operation.operation_id = "withdraw-op".into();
    operation.effect_id = "withdraw-effect".into();
    operation.generation = 3;
    operation.configuration_hash = vec![11; 32];
    assert!(matches!(
        recovered.withdraw(WithdrawConfigurationRequest {
            operation: Some(operation),
            identity: applied.identity,
            withdrawn_generation: 3,
        }),
        CommandOutcome::Accepted
    ));
    let withdrawn = GatewayState::from_store(store).expect("recovered withdrawal");
    for current in [&recovered, &withdrawn] {
        publish_health(current, |_| true);
        assert_absent(current, "retired.example.com", "/old/item");
        assert_absent(current, "current.example.com", "/new/item");
        for (path, expected_backend, expected_limits) in [
            ("/old/item", RouteLookup::NotFound, None),
            ("/new/item", RouteLookup::NotFound, None),
            ("/stable/item", backend(8_201), Some(limits(1))),
        ] {
            assert_eq!(
                lookups(current, "shared.example.com", path),
                Lookups {
                    backend: expected_backend,
                    limits: expected_limits,
                    certificate: binding("peer", 5),
                },
                "shared.example.com{path}"
            );
        }
    }
}

#[test]
fn passive_expiration_and_drain_retirement_release_route_ownership() {
    let state = GatewayState::empty();
    let mut expiring = target_configuration(
        "target-a",
        1,
        &[
            ("shared.example.com", "/api", 8_101),
            ("expiring.example.com", "/", 8_102),
        ],
    );
    apply(
        &state,
        target_configuration("target-b", 1, &[("shared.example.com", "/api", 8_201)]),
    );
    let mut draining = target_configuration(
        "target-c",
        1,
        &[
            ("shared.example.com", "/api", 8_301),
            ("draining.example.com", "/", 8_302),
        ],
    );
    set_limits(&mut draining, &limits(2));
    bind_tls(&mut draining, 1, "draining", 1);
    let applied = apply(&state, draining);

    let deadline = now_unix_ms() + 500;
    expiring.valid_until_unix_ms = deadline;
    apply(&state, expiring);
    publish_health(&state, |_| true);
    assert_eq!(
        state.resolve_backend("expiring.example.com", "/", "GET"),
        backend(8_102)
    );
    assert_eq!(
        state.resolve_backend("shared.example.com", "/api/item", "GET"),
        RouteLookup::Ambiguous
    );
    let draining_metadata = lookups(&state, "draining.example.com", "/");
    assert_eq!(draining_metadata.backend, backend(8_302));
    assert!(matches!(
        state.drain(DrainConfigurationRequest {
            operation: applied.operation,
            identity: applied.identity,
            drain_generation: 1,
            drain_until_unix_ms: deadline,
        }),
        CommandOutcome::Accepted
    ));
    let suppressed = Lookups {
        backend: RouteLookup::NotFound,
        limits: Some(limits(2)),
        certificate: binding("draining", 1),
    };
    assert_eq!(lookups(&state, "draining.example.com", "/"), suppressed);
    assert_eq!(
        state.resolve_backend("shared.example.com", "/api/item", "GET"),
        RouteLookup::Ambiguous
    );

    // No configuration or health publication occurs while authority expires.
    wait_until_expired(deadline);
    assert_eq!(
        state.resolve_backend("expiring.example.com", "/", "GET"),
        RouteLookup::NotFound
    );
    assert_eq!(
        state.resolve_backend("shared.example.com", "/api/item", "GET"),
        backend(8_201)
    );
    assert_eq!(lookups(&state, "draining.example.com", "/"), suppressed);
    assert!(state.retire_expired_drains());
    assert_absent(&state, "draining.example.com", "/");
    assert_eq!(
        state.resolve_backend("shared.example.com", "/api/item", "GET"),
        backend(8_201)
    );
}

#[test]
fn persistence_rejection_preserves_backend_limits_and_certificate_lookups() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("gateway.state");
    let store = StateStore::new(&path);
    let state = GatewayState::from_store(store.clone()).expect("initial state");
    let mut old = target_configuration(
        "target-a",
        1,
        &[
            ("old.example.com", "/", 8_101),
            ("shared.example.com", "/old", 8_102),
        ],
    );
    set_limits(&mut old, &limits(1));
    bind_tls(&mut old, 0, "old-host", 1);
    bind_tls(&mut old, 1, "old-path", 3);
    let applied = apply(&state, old);
    publish_health(&state, |_| true);
    assert_eq!(
        lookups(&state, "old.example.com", "/"),
        Lookups {
            backend: backend(8_101),
            limits: Some(limits(1)),
            certificate: binding("old-host", 1),
        }
    );
    assert_eq!(
        lookups(&state, "shared.example.com", "/old/item"),
        Lookups {
            backend: backend(8_102),
            limits: Some(limits(1)),
            certificate: binding("old-path", 3),
        }
    );
    assert_absent(&state, "new.example.com", "/new/item");

    let mut next = target_configuration(
        "target-a",
        2,
        &[
            ("new.example.com", "/new", 8_103),
            ("shared.example.com", "/new", 8_104),
        ],
    );
    set_limits(&mut next, &limits(2));
    bind_tls(&mut next, 0, "new-host", 5);
    bind_tls(&mut next, 1, "new-path", 7);
    let queries = [
        ("old.example.com", "/"),
        ("shared.example.com", "/old/item"),
        ("shared.example.com", "/new/item"),
        ("new.example.com", "/new/item"),
    ];
    let before: Vec<_> = queries
        .iter()
        .map(|(host, path)| lookups(&state, host, path))
        .collect();
    let durable_before = fs::read(&path).expect("initial durable state");
    // A directory at the staging-file path causes a real, permission-independent I/O failure.
    fs::create_dir(path.with_extension("tmp")).expect("block state replacement");
    let assert_rejected_without_publication = |outcome| {
        assert!(
            matches!(
                outcome,
                CommandOutcome::Rejected(AdmissionError::Persistence)
            ),
            "{outcome:?}"
        );
        let after: Vec<_> = queries
            .iter()
            .map(|(host, path)| lookups(&state, host, path))
            .collect();
        assert_eq!(after, before);
        assert_eq!(
            fs::read(&path).expect("retained durable state"),
            durable_before
        );
    };
    assert_rejected_without_publication(state.apply(apply_request(next)));
    let mut withdrawal = applied.operation.clone().expect("applied operation");
    withdrawal.operation_id = "withdraw-op".into();
    withdrawal.effect_id = "withdraw-effect".into();
    withdrawal.generation = 2;
    withdrawal.configuration_hash = vec![9; 32];
    assert_rejected_without_publication(state.withdraw(WithdrawConfigurationRequest {
        operation: Some(withdrawal),
        identity: applied.identity.clone(),
        withdrawn_generation: 2,
    }));
    assert_rejected_without_publication(state.drain(DrainConfigurationRequest {
        operation: applied.operation,
        identity: applied.identity,
        drain_generation: 1,
        drain_until_unix_ms: now_unix_ms() + 60_000,
    }));
    let recovered = GatewayState::from_store(store).expect("recovered rejected commands");
    publish_health(&recovered, |_| true);
    let after_recovery: Vec<_> = queries
        .iter()
        .map(|(host, path)| lookups(&recovered, host, path))
        .collect();
    assert_eq!(after_recovery, before);
}
