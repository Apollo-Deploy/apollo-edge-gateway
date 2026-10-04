use super::fixture::*;
use super::measure::*;

use apollo_edge_gateway::control::{
    CommandOutcome, DrainConfigurationRequest, RouteLookup, WithdrawConfigurationRequest,
};
use apollo_edge_gateway::state::StateStore;
use apollo_edge_gateway::{AdmissionError, GatewayState};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as i64
}

pub(crate) fn run(o: &Options) {
    for cycle in 1..=o.cycles {
        let directory = tempfile::tempdir().expect("private bounded state directory");

        let store = StateStore::new(directory.path().join("gateway.state"));

        let state = GatewayState::from_store(store.clone()).expect("empty durable state");

        let initial = request(SMALL, 0, 1, 0);

        let stale = initial.clone();

        let (outcome, cold) = measure(|| state.apply(initial));

        accepted(outcome);

        publish_health(&state);

        let host = hostname(SMALL, 0, 0);

        let query = path(0, 0) + "request";

        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::Backend(address(SMALL, 0, 0, 0))
        );

        measurement_row("lifecycle", "cold-durable-apply", 1, cycle, cold);

        // A newer independently signed configuration supplies the authority hash for withdrawal.
        let fence = request(SMALL, 0, 2, 0);

        let withdraw = WithdrawConfigurationRequest {
            operation: fence.operation,
            identity: fence.identity,
            withdrawn_generation: 2,
        };

        let (outcome, withdrawal) = measure(|| state.withdraw(withdraw));

        accepted(outcome);

        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );

        assert!(state.inspect_for(Some(identity(0))).withdrawn);

        measurement_row("lifecycle", "durable-withdraw", 1, cycle, withdrawal);

        drop(state);

        let (recovered, recovery) = measure(|| GatewayState::from_store(store.clone()));

        let state = recovered.expect("withdrawal recovery");

        assert_eq!(state.inspect_for(Some(identity(0))).generation, 2);

        assert!(state.inspect_for(Some(identity(0))).withdrawn);

        assert!(matches!(
            state.apply(stale.clone()),
            CommandOutcome::Rejected(AdmissionError::StaleGeneration)
        ));

        measurement_row(
            "lifecycle",
            "recover-withdrawal-tombstone",
            1,
            cycle,
            recovery,
        );

        let next = request(SMALL, 0, 3, 0);

        let operation = next.operation.clone();

        accepted(state.apply(next));

        publish_health(&state);

        let until = unix_ms() + 100;

        let drain = DrainConfigurationRequest {
            operation,
            identity: Some(identity(0)),
            drain_generation: 3,
            drain_until_unix_ms: until,
        };

        let (outcome, draining) = measure(|| state.drain(drain));

        accepted(outcome);

        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );

        assert!(
            state
                .inspect_for(Some(identity(0)))
                .serving_route_ids
                .is_empty()
        );

        measurement_row("lifecycle", "durable-drain", 1, cycle, draining);

        drop(state);

        let (recovered, recovery) = measure(|| GatewayState::from_store(store.clone()));

        let state = recovered.expect("drain recovery");

        assert!(!state.inspect_for(Some(identity(0))).withdrawn);

        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );

        measurement_row("lifecycle", "recover-draining-active", 1, cycle, recovery);

        // Real clock/public expiry, not a fake clock or injected persisted drain. Sleep is never timed.
        let remaining = until.saturating_sub(unix_ms()).max(0) as u64;

        assert!(
            remaining <= 100,
            "clock moved backwards; refusing unbounded wait"
        );

        std::thread::sleep(Duration::from_millis(remaining + 2));

        let (retired, retirement) = measure(|| state.retire_expired_drains());

        assert!(retired, "expired admitted drain must actually retire");

        assert!(state.inspect_for(Some(identity(0))).withdrawn);

        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );

        assert!(
            !state.retire_expired_drains(),
            "second retirement is a no-op"
        );

        measurement_row(
            "lifecycle",
            "durable-expired-drain-retirement",
            1,
            cycle,
            retirement,
        );

        drop(state);

        let (recovered, recovery) = measure(|| GatewayState::from_store(store.clone()));

        let state = recovered.expect("retirement recovery");

        assert!(state.inspect_for(Some(identity(0))).withdrawn);

        assert_eq!(state.inspect_for(Some(identity(0))).generation, 3);

        assert!(matches!(
            state.apply(stale),
            CommandOutcome::Rejected(AdmissionError::StaleGeneration)
        ));

        measurement_row(
            "lifecycle",
            "recover-retirement-tombstone",
            1,
            cycle,
            recovery,
        );
    }
}
