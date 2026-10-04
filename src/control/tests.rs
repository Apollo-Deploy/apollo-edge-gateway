//! Command fencing, independent targets, and durable withdrawal/drain behavior.
use crate::snapshot::AdmissionError;
use crate::state::StateStore;
use crate::test_support::{configuration, sign_configuration};

use super::{
    ApplyConfigurationRequest, CommandOutcome, DrainConfigurationRequest, GatewayState,
    OperationIdentity, RouteLookup, WithdrawConfigurationRequest, unix_ms,
};

fn request(target_id: &str, epoch: u64, generation: u64, marker: u8) -> ApplyConfigurationRequest {
    let mut configuration = configuration();

    let mut identity = configuration.identity.take().expect("fixture identity");

    identity.traffic_target_id = target_id.into();

    configuration.identity = Some(identity.clone());

    configuration.controller_epoch = epoch;

    configuration.generation = generation;

    configuration.semantic_hash = vec![marker; 32];

    for route in &mut configuration.routes {
        route.identity = Some(identity.clone());

        route.hostname = format!("{target_id}.example.com");

        route.route_generation = generation;
    }

    sign_configuration(&mut configuration);

    ApplyConfigurationRequest {
        operation: Some(OperationIdentity {
            operation_id: format!("op-{generation}"),
            effect_id: format!("effect-{generation}"),
            controller_epoch: epoch,
            generation,
            configuration_hash: configuration.configuration_hash.clone(),
        }),
        identity: Some(identity),
        configuration: Some(configuration),
    }
}

#[test]
fn generation_fencing_is_fail_closed() {
    use AdmissionError::{Conflict, InvalidIdentity, StaleEpoch, StaleGeneration};

    let cases = [
        (0, 6, Err(InvalidIdentity), Err(InvalidIdentity)),
        (1, 4, Err(StaleEpoch), Err(StaleEpoch)),
        (1, 5, Err(StaleEpoch), Err(StaleEpoch)),
        (1, 6, Err(StaleEpoch), Err(StaleEpoch)),
        (2, 0, Err(InvalidIdentity), Err(InvalidIdentity)),
        (2, 4, Err(StaleGeneration), Err(StaleGeneration)),
        (2, 5, Ok(false), Err(Conflict)),
        (2, 6, Ok(true), Ok(true)),
        (3, 4, Ok(true), Ok(true)),
        (3, 5, Ok(true), Ok(true)),
        (3, 6, Ok(true), Ok(true)),
    ];

    for (epoch, generation, same_semantics, changed_semantics) in cases {
        for (marker, expected_outcome) in [(1, same_semantics), (2, changed_semantics)] {
            let state = GatewayState::empty();

            let prior = request("target", 2, 5, 1);

            let prior_configuration = prior.configuration.clone().expect("prior configuration");

            assert!(matches!(state.apply(prior), CommandOutcome::Accepted));

            let next = request("target", epoch, generation, marker);

            let next_configuration = next.configuration.clone().expect("next configuration");

            let identity = next.identity.clone();

            let outcome = match state.apply(next) {
                CommandOutcome::Accepted => Ok(true),
                CommandOutcome::AlreadyApplied => Ok(false),
                CommandOutcome::Rejected(error) => Err(error),
            };

            assert_eq!(
                outcome, expected_outcome,
                "epoch={epoch}, generation={generation}, marker={marker}"
            );

            let expected = if outcome == Ok(true) {
                next_configuration
            } else {
                prior_configuration
            };

            let observed = state.inspect_for(identity);

            assert_eq!(observed.controller_epoch, expected.controller_epoch);

            assert_eq!(observed.generation, expected.generation);

            assert_eq!(observed.configuration_hash, expected.configuration_hash);

            assert_eq!(observed.semantic_hash, expected.semantic_hash);
        }
    }
}

#[test]
fn independent_targets_do_not_overwrite_each_other() {
    let state = GatewayState::empty();

    let requests = [request("target-a", 1, 1, 1), request("target-b", 1, 1, 2)];

    let submitted = requests
        .iter()
        .map(|request| {
            request
                .configuration
                .clone()
                .expect("submitted configuration")
        })
        .collect::<Vec<_>>();

    for request in requests {
        assert!(matches!(state.apply(request), CommandOutcome::Accepted));
    }

    for expected in submitted {
        let observed = state.inspect_for(expected.identity.clone());

        assert_eq!(observed.identity, expected.identity);

        assert_eq!(observed.controller_epoch, expected.controller_epoch);

        assert_eq!(observed.generation, expected.generation);

        assert_eq!(observed.configuration_hash, expected.configuration_hash);

        assert_eq!(observed.semantic_hash, expected.semantic_hash);

        assert!(!observed.withdrawn);
    }
}

#[test]
fn withdrawal_tombstone_survives_restart_and_rejects_resurrection() {
    let directory = tempfile::tempdir().expect("temporary directory");

    let store = StateStore::new(directory.path().join("gateway.state"));

    let state = GatewayState::from_store(store.clone()).expect("initial state");

    let applied = request("target", 1, 1, 1);

    let identity = applied.identity.clone().expect("submitted identity");

    assert!(matches!(state.apply(applied), CommandOutcome::Accepted));

    assert!(matches!(
        state.withdraw(WithdrawConfigurationRequest {
            operation: Some(OperationIdentity {
                operation_id: "withdraw-op".into(),
                effect_id: "withdraw-effect".into(),
                controller_epoch: 1,
                generation: 2,
                configuration_hash: vec![8; 32],
            }),
            identity: Some(identity.clone()),
            withdrawn_generation: 2,
        }),
        CommandOutcome::Accepted
    ));

    let recovered = GatewayState::from_store(store).expect("recovered state");

    let observed = recovered.inspect_for(Some(identity));

    assert!(observed.withdrawn);

    assert_eq!(observed.generation, 2);

    assert_eq!(observed.configuration_hash, vec![8; 32]);

    assert!(matches!(
        recovered.apply(request("target", 1, 1, 1)),
        CommandOutcome::Rejected(AdmissionError::StaleGeneration)
    ));
}

#[test]
fn drain_is_durable_and_expires_to_a_tombstone() {
    let directory = tempfile::tempdir().expect("temporary directory");

    let store = StateStore::new(directory.path().join("gateway.state"));

    let state = GatewayState::from_store(store.clone()).expect("initial state");

    let applied = request("target", 1, 1, 1);

    let identity = applied.identity.clone().expect("submitted identity");

    let operation = applied.operation.clone().expect("submitted operation");

    assert!(matches!(state.apply(applied), CommandOutcome::Accepted));

    state.publish_health(
        state
            .health_targets()
            .into_iter()
            .map(|target| (target.key, true))
            .collect(),
    );

    assert_eq!(
        state.resolve_backend("target.example.com", "/", "GET"),
        RouteLookup::Backend("10.0.0.5:8080".parse().expect("expected endpoint"))
    );

    assert_eq!(
        state.inspect_for(Some(identity.clone())).serving_route_ids,
        vec!["route"]
    );

    let until = unix_ms() + 50;

    assert!(matches!(
        state.drain(DrainConfigurationRequest {
            operation: Some(operation),
            identity: Some(identity.clone()),
            drain_generation: 1,
            drain_until_unix_ms: until,
        }),
        CommandOutcome::Accepted
    ));

    assert_eq!(
        state.resolve_backend("target.example.com", "/", "GET"),
        RouteLookup::NotFound
    );

    let recovered = GatewayState::from_store(store).expect("recovered state");

    assert_eq!(
        recovered.resolve_backend("target.example.com", "/", "GET"),
        RouteLookup::NotFound
    );

    assert!(
        recovered
            .inspect_for(Some(identity.clone()))
            .serving_route_ids
            .is_empty()
    );

    std::thread::sleep(std::time::Duration::from_millis(75));

    assert!(recovered.retire_expired_drains());

    assert!(recovered.inspect_for(Some(identity)).withdrawn);

    assert!(matches!(
        recovered.apply(request("target", 1, 1, 1)),
        CommandOutcome::AlreadyApplied
    ));
}
