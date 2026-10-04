use zeroize::Zeroize;

use crate::control::{
    CommandOutcome, ControlRequest, ControlResponse, EdgeCommandResponse, EdgeObservation,
    EdgeObservationKind, EdgeProtocol, GatewayCapabilities, GatewayState, GatewayStatus,
    control_request, control_response,
};

const PINGORA_RELEASE: &str = "0.9.0";

pub(super) fn dispatch(
    mut request: ControlRequest,
    state: &GatewayState,
    gateway_id: &str,
    session_id: &str,
    tls_termination: bool,
) -> ControlResponse {
    let (payload, observation) = match request.payload.take() {
        Some(control_request::Payload::ApplyConfiguration(request)) => {
            let identity = request.identity.clone();

            let operation = request.operation.clone();

            let outcome = state.apply(request);

            let observation = command_observation(
                gateway_id,
                session_id,
                identity.clone(),
                operation,
                &outcome,
                EdgeObservationKind::ConfigurationActive,
            );

            (
                control_response::Payload::Command(command_response(outcome, state, identity)),
                Some(observation),
            )
        }
        Some(control_request::Payload::WithdrawConfiguration(request)) => {
            let identity = request.identity.clone();

            let operation = request.operation.clone();

            let outcome = state.withdraw(request);

            let observation = command_observation(
                gateway_id,
                session_id,
                identity.clone(),
                operation,
                &outcome,
                EdgeObservationKind::ConfigurationWithdrawn,
            );

            (
                control_response::Payload::Command(command_response(outcome, state, identity)),
                Some(observation),
            )
        }
        Some(control_request::Payload::DrainConfiguration(request)) => {
            let identity = request.identity.clone();

            let operation = request.operation.clone();

            let outcome = state.drain(request);

            let observation = command_observation(
                gateway_id,
                session_id,
                identity.clone(),
                operation,
                &outcome,
                EdgeObservationKind::RouteDrained,
            );

            (
                control_response::Payload::Command(command_response(outcome, state, identity)),
                Some(observation),
            )
        }
        Some(control_request::Payload::InspectConfiguration(request)) => (
            control_response::Payload::Configuration(state.inspect_for(request.identity)),
            None,
        ),
        Some(control_request::Payload::GatewayCapabilities(_request)) => (
            control_response::Payload::Capabilities(GatewayCapabilities {
                gateway_id: gateway_id.into(),
                pingora_version: PINGORA_RELEASE.into(),
                protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
                tls_termination,
                http3: false,
                max_routes: 1_024,
                max_backends_per_route: 256,
            }),
            None,
        ),
        Some(control_request::Payload::GatewayStatus(_request)) => {
            let state = state.inspect();

            (
                control_response::Payload::Status(GatewayStatus {
                    gateway_id: gateway_id.into(),
                    session_id: session_id.into(),
                    controller_epoch: state.controller_epoch,
                    active_generation: state.generation,
                    active_configuration_hash: state.configuration_hash,
                    serving: !state.serving_route_ids.is_empty(),
                    authority_valid: !state.serving_route_ids.is_empty()
                        && state.valid_until_unix_ms > unix_ms(),
                    active_connections: state.active_connections,
                    observed_at_unix_ms: state.observed_at_unix_ms,
                }),
                None,
            )
        }
        Some(control_request::Payload::InstallCertificateMaterial(mut request)) => {
            let outcome = state.install_certificate_material(&request);

            request.private_key_pem.zeroize();

            (
                control_response::Payload::Command(command_response(outcome, state, None)),
                None,
            )
        }
        None => (
            control_response::Payload::Command(EdgeCommandResponse {
                result: crate::control::EdgeCommandResult::Rejected as i32,
                error_code: "missing_operation".into(),
                retryable: false,
                ..Default::default()
            }),
            None,
        ),
    };

    ControlResponse {
        payload: Some(payload),
        observations: observation.into_iter().collect(),
    }
}

fn command_observation(
    gateway_id: &str,
    session_id: &str,
    identity: Option<crate::control::ProductIdentity>,
    operation: Option<crate::control::OperationIdentity>,
    outcome: &CommandOutcome,
    accepted_kind: EdgeObservationKind,
) -> EdgeObservation {
    let rejected = matches!(outcome, CommandOutcome::Rejected(_));

    EdgeObservation {
        gateway_id: gateway_id.into(),
        session_id: session_id.into(),
        identity,
        operation,
        kind: if rejected {
            EdgeObservationKind::ConfigurationRejected as i32
        } else {
            accepted_kind as i32
        },
        subject_id: "configuration".into(),
        detail_code: if rejected {
            format!("{outcome:?}").to_ascii_lowercase()
        } else {
            "admitted".into()
        },
        observed_at_unix_ms: unix_ms(),
    }
}

fn command_response(
    outcome: CommandOutcome,
    state: &GatewayState,
    identity: Option<crate::control::ProductIdentity>,
) -> EdgeCommandResponse {
    let current = state.inspect_for(identity);

    let current_fields = EdgeCommandResponse {
        controller_epoch: current.controller_epoch,
        generation: current.generation,
        configuration_hash: current.configuration_hash,
        semantic_hash: current.semantic_hash,
        observed_at_unix_ms: current.observed_at_unix_ms,
        ..Default::default()
    };

    match outcome {
        CommandOutcome::Accepted => EdgeCommandResponse {
            result: crate::control::EdgeCommandResult::Accepted as i32,
            ..current_fields
        },
        CommandOutcome::AlreadyApplied => EdgeCommandResponse {
            result: crate::control::EdgeCommandResult::AlreadyApplied as i32,
            ..current_fields
        },
        CommandOutcome::Rejected(error) => EdgeCommandResponse {
            result: crate::control::EdgeCommandResult::Rejected as i32,
            error_code: format!("{error:?}").to_ascii_lowercase(),
            retryable: matches!(error, crate::snapshot::AdmissionError::Persistence),
            ..current_fields
        },
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::control::{EdgeCommandResult, GatewayCapabilitiesRequest};

    #[test]
    fn capabilities_response_metadata_preserves_protocols_limits_and_tls_flag() {
        let state = GatewayState::empty();

        for tls_termination in [false, true] {
            let request = ControlRequest {
                payload: Some(control_request::Payload::GatewayCapabilities(
                    GatewayCapabilitiesRequest {},
                )),
            };

            let response = dispatch(request, &state, "gateway-1", "session-1", tls_termination);

            assert_eq!(
                response,
                ControlResponse {
                    payload: Some(control_response::Payload::Capabilities(
                        GatewayCapabilities {
                            gateway_id: "gateway-1".into(),
                            pingora_version: "0.9.0".into(),
                            protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
                            tls_termination,
                            http3: false,
                            max_routes: 1_024,
                            max_backends_per_route: 256,
                        }
                    )),
                    observations: Vec::new(),
                }
            );
        }
    }

    #[test]
    fn missing_payload_is_rejected_without_retry_or_observations() {
        let state = GatewayState::empty();

        let response = dispatch(
            ControlRequest { payload: None },
            &state,
            "gateway-1",
            "session-1",
            true,
        );

        assert_eq!(
            response,
            ControlResponse {
                payload: Some(control_response::Payload::Command(EdgeCommandResponse {
                    result: EdgeCommandResult::Rejected as i32,
                    error_code: "missing_operation".into(),
                    retryable: false,
                    ..Default::default()
                })),
                observations: Vec::new(),
            }
        );
    }
}
