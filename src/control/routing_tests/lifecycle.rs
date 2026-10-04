use super::support::*;
use crate::control::{
    CommandOutcome, DrainConfigurationRequest, GatewayState, RouteLookup,
    WithdrawConfigurationRequest,
};
use crate::state::StateStore;

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
