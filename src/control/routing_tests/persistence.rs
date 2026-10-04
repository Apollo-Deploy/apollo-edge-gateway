use crate::control::{
    CommandOutcome, DrainConfigurationRequest, GatewayState, WithdrawConfigurationRequest,
};
use crate::snapshot::AdmissionError;
use crate::state::StateStore;
use std::fs;

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

use super::support::*;
