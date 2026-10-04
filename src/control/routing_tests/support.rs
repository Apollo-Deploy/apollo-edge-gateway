//! Public routing contracts shared by the scan-based and indexed control implementations.
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::control::{
    ApplyConfigurationRequest, CommandOutcome, EdgeConfiguration, EdgeTlsBinding, GatewayState,
    OperationIdentity, RouteLookup, RuntimeLimits,
};
use crate::test_support::{configuration, sign_configuration};

pub(crate) fn target_configuration(
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

pub(crate) fn apply_request(mut input: EdgeConfiguration) -> ApplyConfigurationRequest {
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

pub(crate) fn apply(state: &GatewayState, input: EdgeConfiguration) -> ApplyConfigurationRequest {
    let request = apply_request(input);

    let outcome = state.apply(request.clone());

    assert!(matches!(outcome, CommandOutcome::Accepted), "{outcome:?}");

    request
}

pub(crate) fn publish_health(state: &GatewayState, healthy: impl Fn(SocketAddr) -> bool) {
    state.publish_health(
        state
            .health_targets()
            .into_iter()
            .map(|target| (target.key, healthy(target.address)))
            .collect(),
    );
}

pub(crate) fn backend(port: u16) -> RouteLookup {
    RouteLookup::Backend(SocketAddr::from(([10, 0, 0, 5], port)))
}

pub(crate) fn set_limits(input: &mut EdgeConfiguration, limits: &RuntimeLimits) {
    input.max_header_bytes = limits.max_header_bytes as u32;

    input.max_body_bytes = limits.max_body_bytes;

    input.max_concurrency = limits.max_concurrency as u32;

    input.retry_max_attempts = limits.retry_max_attempts as u32;

    input.retry_methods = limits.retry_methods.clone();
}

pub(crate) fn limits(marker: usize) -> RuntimeLimits {
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

pub(crate) fn bind_tls(
    input: &mut EdgeConfiguration,
    route_index: usize,
    certificate_id: &str,
    marker: u8,
) {
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

pub(crate) fn binding(certificate_id: &str, marker: u8) -> Option<(String, Vec<u8>, Vec<u8>)> {
    Some((
        format!("org/project/{certificate_id}/1"),
        vec![marker; 32],
        vec![marker + 1; 32],
    ))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lookups {
    pub(crate) backend: RouteLookup,
    pub(crate) limits: Option<RuntimeLimits>,
    pub(crate) certificate: Option<(String, Vec<u8>, Vec<u8>)>,
}

pub(crate) fn lookups(state: &GatewayState, host: &str, path: &str) -> Lookups {
    Lookups {
        backend: state.resolve_backend(host, path, "GET"),
        limits: state.limits_for(host, path),
        certificate: state.certificate_binding_for_host(host),
    }
}

pub(crate) fn assert_absent(state: &GatewayState, host: &str, path: &str) {
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

pub(crate) fn now_unix_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock after Unix epoch")
            .as_millis(),
    )
    .expect("wall clock fits in milliseconds")
}

pub(crate) fn wait_until_expired(deadline: i64) {
    let timeout = Instant::now() + Duration::from_secs(2);

    while now_unix_ms() <= deadline {
        assert!(Instant::now() < timeout, "expiration deadline did not pass");

        std::thread::sleep(Duration::from_millis(5));
    }
}
