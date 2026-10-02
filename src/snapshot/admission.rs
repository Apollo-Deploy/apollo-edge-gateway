//! Configuration admission, route and endpoint validation, and unsigned configuration hashing.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};

use pingora::lb::Backend;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::control::{EdgeConfiguration, EdgeProtocol, EdgeRoute, NetworkScope};

use super::health::backend_health_key;
use super::{AdmissionError, HealthTarget, Snapshot, StaticSelection, unix_ms};

impl Snapshot {
    pub fn admit(configuration: EdgeConfiguration) -> Result<Self, AdmissionError> {
        Self::admit_with_expiry(configuration, false)
    }

    pub fn admit_persisted(configuration: EdgeConfiguration) -> Result<Self, AdmissionError> {
        Self::admit_with_expiry(configuration, true)
    }

    fn admit_with_expiry(
        configuration: EdgeConfiguration,
        allow_expired: bool,
    ) -> Result<Self, AdmissionError> {
        let identity = configuration
            .identity
            .clone()
            .ok_or(AdmissionError::InvalidIdentity)?;
        if identity.organization_id.is_empty()
            || identity.project_id.is_empty()
            || identity.traffic_target_id.is_empty()
        {
            return Err(AdmissionError::InvalidIdentity);
        }
        if configuration.configuration_hash.len() != 32 {
            return Err(AdmissionError::ConfigurationHash);
        }
        if configuration.semantic_hash.len() != 32 {
            return Err(AdmissionError::ConfigurationHash);
        }
        if configuration.controller_epoch == 0 || configuration.generation == 0 {
            return Err(AdmissionError::InvalidIdentity);
        }
        if configuration.valid_until_unix_ms <= configuration.issued_at_unix_ms {
            return Err(AdmissionError::InvalidValidity);
        }
        if !allow_expired && configuration.valid_until_unix_ms <= unix_ms() {
            return Err(AdmissionError::AuthorityExpired);
        }
        if configuration.routes.len() > 1_024 {
            return Err(AdmissionError::LimitExceeded);
        }
        let mut route_keys = HashSet::new();
        let mut backend_selectors = Vec::with_capacity(configuration.routes.len());
        let mut backend_addresses = Vec::with_capacity(configuration.routes.len());
        let mut backend_health_keys = Vec::with_capacity(configuration.routes.len());
        let mut health_targets = Vec::new();
        let target_id = identity.traffic_target_id.clone();
        for route in &configuration.routes {
            validate_route(route, &mut route_keys)?;
            let mut route_addresses = Vec::new();
            let mut route_health_keys = Vec::new();
            let backends = route
                .backends
                .iter()
                .filter(|backend| !backend.draining)
                .map(|backend| {
                    let endpoint = backend
                        .endpoint
                        .as_ref()
                        .ok_or(AdmissionError::InvalidEndpoint)?;
                    let socket_address = endpoint
                        .address
                        .parse::<IpAddr>()
                        .map(|address| SocketAddr::new(address, endpoint.port as u16))
                        .map_err(|_| AdmissionError::InvalidEndpoint)?;
                    let address = socket_address.to_string();

                    let health_key = backend_health_key(&target_id, endpoint, &socket_address);
                    route_addresses.push(socket_address);
                    route_health_keys.push(health_key.clone());
                    health_targets.push(HealthTarget {
                        key: health_key,
                        address: socket_address,
                    });
                    Backend::new(&address).map_err(|_| AdmissionError::InvalidEndpoint)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            let selector = if backends.is_empty() {
                None
            } else {
                Some(StaticSelection::new(backends))
            };

            backend_addresses.push(route_addresses);
            backend_health_keys.push(route_health_keys);
            backend_selectors.push(selector);
        }
        let expected_hash = digest_without_hash(&configuration);
        if expected_hash != configuration.configuration_hash {
            return Err(AdmissionError::ConfigurationHash);
        }
        Ok(Self {
            configuration: configuration.clone(),
            identity,
            controller_epoch: configuration.controller_epoch,
            generation: configuration.generation,
            configuration_hash: configuration.configuration_hash,
            issued_at_unix_ms: configuration.issued_at_unix_ms,
            valid_until_unix_ms: configuration.valid_until_unix_ms,
            routes: configuration.routes,
            withdrawn: false,
            backend_selectors,
            backend_addresses,
            backend_health_keys,
            health_targets,
        })
    }
}

fn validate_route(
    route: &EdgeRoute,
    route_keys: &mut HashSet<String>,
) -> Result<(), AdmissionError> {
    let key = format!("{}\0{}", route.hostname, route.path_match);
    if route.hostname.is_empty()
        || route.hostname.len() > 253
        || route.hostname != route.hostname.to_ascii_lowercase()
        || !valid_hostname(&route.hostname)
        || !route_keys.insert(key)
        || route.path_match.len() > 2_048
        || (!route.path_match.is_empty() && !route.path_match.starts_with('/'))
        || route.backends.is_empty()
        || route.backends.len() > 256
    {
        return Err(AdmissionError::InvalidRoute);
    }
    if route.protocols.iter().any(|protocol| {
        *protocol != EdgeProtocol::Http1 as i32 && *protocol != EdgeProtocol::Http2 as i32
    }) {
        return Err(AdmissionError::UnsupportedOperation);
    }
    for backend in &route.backends {
        let endpoint = backend
            .endpoint
            .as_ref()
            .ok_or(AdmissionError::InvalidEndpoint)?;
        if endpoint.workload_id.is_empty()
            || endpoint.workload_generation == 0
            || endpoint.node_id.is_empty()
            || endpoint.region_id.is_empty()
            || endpoint.cell_id.is_empty()
            || endpoint.port == 0
            || endpoint.port > u16::MAX as u32
            || !endpoint.ready
            || !endpoint.healthy
            || endpoint.protocol != EdgeProtocol::Http1 as i32
            || endpoint.network_scope != NetworkScope::CellPrivate as i32
        {
            return Err(AdmissionError::UnsupportedNetworkScope);
        }
        let address: IpAddr = endpoint
            .address
            .parse()
            .map_err(|_| AdmissionError::InvalidEndpoint)?;
        if address.is_loopback() || address.is_unspecified() || !is_private(address) {
            return Err(AdmissionError::InvalidEndpoint);
        }
        let _ = SocketAddr::new(address, endpoint.port as u16);
    }
    Ok(())
}

fn valid_hostname(value: &str) -> bool {
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_private() || value.is_link_local(),
        IpAddr::V6(value) => value.is_unique_local() || value.is_unicast_link_local(),
    }
}

fn digest_without_hash(configuration: &EdgeConfiguration) -> Vec<u8> {
    let mut unsigned = configuration.clone();
    unsigned.configuration_hash.clear();
    let bytes = unsigned.encode_to_vec();
    Sha256::digest(bytes).to_vec()
}

#[cfg(test)]
mod tests {
    //! Signed inputs must reach route/endpoint validation and publish selectable backends.

    use std::net::SocketAddr;

    use crate::snapshot::{AdmissionError, Snapshot};
    use crate::test_support::{configuration, sign_configuration};

    #[test]
    fn admission_accepts_private_address_families_and_rejects_invalid_endpoints() {
        for (address, expected_backend) in [
            ("10.0.0.5", "10.0.0.5:8080"),
            ("172.16.0.5", "172.16.0.5:8080"),
            ("192.168.0.5", "192.168.0.5:8080"),
            ("169.254.0.5", "169.254.0.5:8080"),
            ("fd00::5", "[fd00::5]:8080"),
            ("fe80::5", "[fe80::5]:8080"),
        ] {
            let mut input = configuration();
            input.routes[0].backends[0]
                .endpoint
                .as_mut()
                .expect("fixture endpoint")
                .address = address.into();
            sign_configuration(&mut input);
            let snapshot = Snapshot::admit(input).expect("private endpoint admitted");
            let expected: SocketAddr = expected_backend.parse().expect("literal backend address");
            assert_eq!(
                snapshot.select_backend("api.example.com", "/", "GET", |_| true),
                Some(expected),
                "{address}"
            );
        }

        for address in [
            "127.0.0.1",
            "8.8.8.8",
            "0.0.0.0",
            "::1",
            "::",
            "2001:4860:4860::8888",
            "224.0.0.1",
            "ff02::1",
            "::ffff:10.0.0.5",
            "not-an-ip",
            "10.0.0.5:8080",
        ] {
            let mut input = configuration();
            input.routes[0].backends[0]
                .endpoint
                .as_mut()
                .expect("fixture endpoint")
                .address = address.into();
            sign_configuration(&mut input);
            assert_eq!(
                Snapshot::admit(input).err(),
                Some(AdmissionError::InvalidEndpoint),
                "{address}"
            );
        }
    }

    #[test]
    fn admission_enforces_hostname_grammar_label_bounds_and_total_length() {
        let longest_hostname = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest_hostname.len(), 253);
        let expected: SocketAddr = "10.0.0.5:8080".parse().expect("literal backend address");
        for hostname in [
            "api.example.com".to_owned(),
            "api-1.example.com".to_owned(),
            format!("{}.example", "a".repeat(63)),
            longest_hostname,
        ] {
            let mut input = configuration();
            input.routes[0].hostname = hostname.clone();
            sign_configuration(&mut input);
            let snapshot = Snapshot::admit(input).expect("valid hostname admitted");
            assert_eq!(
                snapshot.select_backend(&hostname, "/", "GET", |_| true),
                Some(expected),
                "{hostname}"
            );
        }

        let oversized_hostname = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(oversized_hostname.len(), 254);
        for hostname in [
            "".to_owned(),
            ".example".to_owned(),
            "example.".to_owned(),
            "api..example".to_owned(),
            "-api.example".to_owned(),
            "api-.example".to_owned(),
            "api_example".to_owned(),
            "café.example".to_owned(),
            "API.example.com".to_owned(),
            format!("{}.example", "a".repeat(64)),
            oversized_hostname,
        ] {
            let mut input = configuration();
            input.routes[0].hostname = hostname.clone();
            sign_configuration(&mut input);
            assert_eq!(
                Snapshot::admit(input).err(),
                Some(AdmissionError::InvalidRoute),
                "{hostname:?}"
            );
        }
    }
}
