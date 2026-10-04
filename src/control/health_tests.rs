//! Health scope is enforced through signed commands, opaque producer keys, and public routing.
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;

use prost::Message;
use sha2::{Digest, Sha256};

use crate::control::{
    ApplyConfigurationRequest, CommandOutcome, EdgeConfiguration, GatewayState, OperationIdentity,
    RouteLookup,
};
use crate::state::{PersistedState, StateStore};
use crate::test_support::{configuration, sign_configuration};

fn target_configuration(target: &str, workload: &str, host: &str) -> EdgeConfiguration {
    let mut input = configuration();

    input
        .identity
        .as_mut()
        .expect("fixture identity")
        .traffic_target_id = target.into();

    input.routes[0].identity = input.identity.clone();

    input.routes[0].hostname = host.into();

    input.routes[0].backends[0]
        .endpoint
        .as_mut()
        .expect("fixture endpoint")
        .workload_id = workload.into();

    input
}

fn request(mut input: EdgeConfiguration) -> ApplyConfigurationRequest {
    sign_configuration(&mut input);

    ApplyConfigurationRequest {
        operation: Some(OperationIdentity {
            operation_id: format!("op-{}", input.generation),
            effect_id: format!("effect-{}", input.generation),
            controller_epoch: input.controller_epoch,
            generation: input.generation,
            configuration_hash: input.configuration_hash.clone(),
        }),
        identity: input.identity.clone(),
        configuration: Some(input),
    }
}

fn apply(state: &GatewayState, input: EdgeConfiguration) {
    let outcome = state.apply(request(input));

    assert!(matches!(outcome, CommandOutcome::Accepted), "{outcome:?}");
}

fn lookup(state: &GatewayState, host: &str) -> RouteLookup {
    state.resolve_backend(host, "/", "GET")
}

fn publish_all(state: &GatewayState) {
    state.publish_health(
        state
            .health_targets()
            .into_iter()
            .map(|target| (target.key, true))
            .collect(),
    );
}

fn assert_isolated_targets(a: (&str, &str), b: (&str, &str)) {
    let state = GatewayState::empty();

    apply(&state, target_configuration(a.0, a.1, "a.example.com"));

    assert_eq!(lookup(&state, "a.example.com"), RouteLookup::Unavailable);

    let a_targets = state.health_targets();

    assert_eq!(a_targets.len(), 1);

    publish_all(&state);

    let backend = RouteLookup::Backend("10.0.0.5:8080".parse().expect("literal endpoint"));

    assert_eq!(lookup(&state, "a.example.com"), backend);

    // B is applied after the producer has published only A's health.
    apply(&state, target_configuration(b.0, b.1, "b.example.com"));

    assert_eq!(
        lookup(&state, "b.example.com"),
        RouteLookup::Unavailable,
        "unprobed B must not inherit A's health: A={a:?}, B={b:?}"
    );

    assert_eq!(lookup(&state, "a.example.com"), backend);

    let both = state.health_targets();

    assert_eq!(both.len(), 2, "producer must retain both scoped targets");

    let b_target = both
        .iter()
        .find(|target| target.key != a_targets[0].key)
        .expect("distinct B key");

    state.publish_health(BTreeMap::from([(b_target.key.clone(), true)]));

    assert_eq!(lookup(&state, "a.example.com"), RouteLookup::Unavailable);

    assert_eq!(lookup(&state, "b.example.com"), backend);
}

#[test]
fn embedded_nul_two_target_collision_does_not_share_health() {
    assert_isolated_targets(("a", "b\0c"), ("a\0b", "c"));
}

#[test]
fn delimiter_looking_nul_soh_and_unicode_identities_keep_health_isolated() {
    for (a, b) in [
        (("a\0", "b"), ("a", "\0b")),
        (("a\0\0", "b"), ("a", "\0\0b")),
        (("a", "\x01\0c"), ("a\0\x01", "c")),
        (("東京", "é\0λ"), ("東京\0é", "λ")),
        (("a\0\x01b", "c"), ("a\x01\0b", "c")),
        (("a", "b\0\x01c"), ("a\0b", "\x01c")),
    ] {
        assert_isolated_targets(a, b);
    }
}

#[test]
fn ordinary_target_change_requires_its_own_health() {
    assert_isolated_targets(("target-a", "workload"), ("target-b", "workload"));
}

fn assert_replacement_needs_health(case: &str, mut next: EdgeConfiguration, expected: &str) {
    let state = GatewayState::empty();

    apply(&state, configuration());

    publish_all(&state);

    assert_eq!(
        lookup(&state, "api.example.com"),
        RouteLookup::Backend("10.0.0.5:8080".parse().expect("literal endpoint"))
    );

    let old_targets = state.health_targets();

    next.generation = 2;

    apply(&state, next);

    assert_eq!(
        lookup(&state, "api.example.com"),
        RouteLookup::Unavailable,
        "{case}: replacement must not inherit old health"
    );

    assert_ne!(state.health_targets()[0].key, old_targets[0].key, "{case}");

    publish_all(&state);

    assert_eq!(
        lookup(&state, "api.example.com"),
        RouteLookup::Backend(expected.parse().expect("literal endpoint")),
        "{case}: fresh health must enable the expected replacement"
    );
}

#[test]
fn endpoint_scope_replacements_require_fresh_health() {
    for (case, workload, generation, address, port, expected) in [
        (
            "workload ID",
            "next-workload",
            1,
            "10.0.0.5",
            8080,
            "10.0.0.5:8080",
        ),
        (
            "workload generation",
            "workload",
            2,
            "10.0.0.5",
            8080,
            "10.0.0.5:8080",
        ),
        (
            "IP address",
            "workload",
            1,
            "10.0.0.6",
            8080,
            "10.0.0.6:8080",
        ),
        ("port", "workload", 1, "10.0.0.5", 8081, "10.0.0.5:8081"),
    ] {
        let mut next = configuration();

        let endpoint = next.routes[0].backends[0]
            .endpoint
            .as_mut()
            .expect("fixture endpoint");

        endpoint.workload_id = workload.into();

        endpoint.workload_generation = generation;

        endpoint.address = address.into();

        endpoint.port = port;

        assert_replacement_needs_health(case, next, expected);
    }
}

#[test]
fn configuration_generation_and_ipv6_spelling_do_not_change_typed_health_scope() {
    let state = GatewayState::empty();

    let mut input = configuration();

    input.routes[0].backends[0]
        .endpoint
        .as_mut()
        .expect("fixture endpoint")
        .address = "fd00:0:0:0:0:0:0:5".into();

    apply(&state, input.clone());

    publish_all(&state);

    let targets = state.health_targets();

    input.generation = 2;

    input.routes[0].backends[0]
        .endpoint
        .as_mut()
        .expect("fixture endpoint")
        .address = "fd00::5".into();

    apply(&state, input);

    assert_eq!(state.health_targets(), targets);

    assert_eq!(
        lookup(&state, "api.example.com"),
        RouteLookup::Backend("[fd00::5]:8080".parse().expect("literal endpoint"))
    );
}

#[test]
fn producer_first_4096_sorted_keys_preserve_nul_free_identity_order() {
    let state = GatewayState::empty();

    let mut aa = target_configuration("aa", "workload", "aa.example.com");

    let template = aa.routes.remove(0);

    aa.routes = (0..16)
        .map(|route_index| {
            let mut route = template.clone();

            route.path_match = format!("/route-{route_index:02}/");

            route.identity.as_mut().expect("fixture identity").route_id =
                format!("route-{route_index}");

            route.backends = (0..256)
                .map(|backend_index| {
                    let mut backend = template.backends[0].clone();

                    let index = route_index * 256 + backend_index;

                    let endpoint = backend.endpoint.as_mut().expect("fixture endpoint");

                    endpoint.workload_id = format!("workload-{index:04}");

                    endpoint.port = 10_000 + index;

                    backend
                })
                .collect();

            route
        })
        .collect();

    // Reverse publication order: producer ordering, not command order, owns the cap.
    apply(
        &state,
        target_configuration("b", "workload", "b.example.com"),
    );

    apply(&state, aa);

    let targets = state.health_targets();

    assert_eq!(targets.len(), 4_097);

    assert!(targets.windows(2).all(|pair| pair[0].key < pair[1].key));

    let expected_prefix: Vec<_> = (10_000..14_096)
        .map(|port| SocketAddr::from(([10, 0, 0, 5], port)))
        .collect();

    assert_eq!(
        targets
            .iter()
            .take(4_096)
            .map(|target| target.address)
            .collect::<Vec<_>>(),
        expected_prefix
    );

    assert_eq!(
        targets[4_096].address,
        "10.0.0.5:8080".parse().expect("B endpoint")
    );

    state.publish_health(
        targets
            .into_iter()
            .take(4_096)
            .map(|target| (target.key, true))
            .collect(),
    );

    for route_index in 0..16 {
        assert!(
            matches!(
                state.resolve_backend(
                    "aa.example.com",
                    &format!("/route-{route_index:02}/item"),
                    "GET"
                ),
                RouteLookup::Backend(_)
            ),
            "aa route {route_index} must be probed"
        );
    }

    assert_eq!(lookup(&state, "b.example.com"), RouteLookup::Unavailable);

    publish_all(&state);

    assert!(matches!(
        lookup(&state, "b.example.com"),
        RouteLookup::Backend(_)
    ));
}

#[test]
fn recovery_rebuilds_health_with_unchanged_signed_configuration_and_state_format() {
    let directory = tempfile::tempdir().expect("temporary directory");

    let path = directory.path().join("gateway.state");

    let store = StateStore::new(&path);

    let inputs = [
        request(target_configuration("a", "b\0c", "a.example.com")),
        request(target_configuration("a\0b", "c", "b.example.com")),
    ];

    let persisted = PersistedState {
        authority_epoch: 1,
        active: inputs
            .iter()
            .map(|input| input.configuration.clone().expect("signed input"))
            .collect(),
        ..Default::default()
    };

    // Independent legacy envelope: no health keys or new persisted fields.
    let payload = persisted.encode_to_vec();

    let mut bytes = b"APOLLO-EDGE-STATE\n".to_vec();

    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("payload length")
            .to_be_bytes(),
    );

    bytes.extend_from_slice(&payload);

    bytes.extend_from_slice(&Sha256::digest(&payload));

    fs::write(&path, &bytes).expect("write independent persisted fixture");

    assert_eq!(store.load().expect("load fixture"), Some(persisted.clone()));

    let recovered = GatewayState::from_store(store.clone()).expect("recover legacy state");

    let targets = recovered.health_targets();

    assert_eq!(targets.len(), inputs.len());

    let fresh = GatewayState::empty();

    assert!(matches!(
        fresh.apply(inputs[0].clone()),
        CommandOutcome::Accepted
    ));

    let a_targets = fresh.health_targets();

    assert_eq!(a_targets.len(), 1);

    assert!(matches!(
        fresh.apply(inputs[1].clone()),
        CommandOutcome::Accepted
    ));

    assert_eq!(fresh.health_targets(), targets);

    for input in &inputs {
        let expected = input.configuration.as_ref().expect("signed input");

        let inspected = recovered.inspect_for(input.identity.clone());

        assert_eq!(inspected.identity, expected.identity);

        assert_eq!(inspected.configuration_hash, expected.configuration_hash);

        assert_eq!(inspected.semantic_hash, expected.semantic_hash);

        assert_eq!(inspected.controller_epoch, expected.controller_epoch);

        assert_eq!(inspected.generation, expected.generation);

        assert!(matches!(
            recovered.apply(input.clone()),
            CommandOutcome::AlreadyApplied
        ));
    }

    for host in ["a.example.com", "b.example.com"] {
        assert_eq!(lookup(&recovered, host), RouteLookup::Unavailable);
    }

    recovered.publish_health(BTreeMap::from([(a_targets[0].key.clone(), true)]));

    assert!(matches!(
        lookup(&recovered, "a.example.com"),
        RouteLookup::Backend(_)
    ));

    assert_eq!(
        lookup(&recovered, "b.example.com"),
        RouteLookup::Unavailable
    );

    publish_all(&recovered);

    assert!(matches!(
        lookup(&recovered, "b.example.com"),
        RouteLookup::Backend(_)
    ));

    let restarted =
        GatewayState::from_store(store.clone()).expect("restart after health publication");

    for current in [&restarted, &fresh] {
        assert_eq!(current.health_targets(), targets);

        for host in ["a.example.com", "b.example.com"] {
            assert_eq!(lookup(current, host), RouteLookup::Unavailable);
        }
    }

    assert_eq!(store.load().expect("retained state"), Some(persisted));

    assert_eq!(fs::read(&path).expect("retained envelope"), bytes);
}
