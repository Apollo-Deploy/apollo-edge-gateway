//! Host/path/method matching and health-aware backend selection without cloning routes.

use std::net::SocketAddr;

use crate::control::EdgeRoute;

use super::{HealthTarget, Snapshot};

impl Snapshot {
    pub fn route(&self, host: &str, path: &str, method: &str) -> Option<&EdgeRoute> {
        self.route_for_host_path(host, path)
            .filter(|route| method_allowed(&route.methods, method))
    }

    pub fn route_for_host_path(&self, host: &str, path: &str) -> Option<&EdgeRoute> {
        self.routes
            .iter()
            .filter(|route| route.hostname == host && path_matches(&route.path_match, path))
            .max_by_key(|route| route.path_match.len())
    }

    pub fn select_backend<F>(
        &self,
        host: &str,
        path: &str,
        method: &str,
        mut healthy: F,
    ) -> Option<SocketAddr>
    where
        F: FnMut(&str) -> bool,
    {
        if !self.is_live() {
            return None;
        }
        let route_index = self
            .routes
            .iter()
            .enumerate()
            .filter(|(_, route)| {
                route.hostname == host
                    && path_matches(&route.path_match, path)
                    && method_allowed(&route.methods, method)
            })
            .max_by_key(|(_, route)| route.path_match.len())
            .map(|(index, _)| index)?;
        let selector = self.backend_selectors.get(route_index)?.as_ref()?;
        let addresses = self.backend_addresses.get(route_index)?;
        let health_keys = self.backend_health_keys.get(route_index)?;
        for _ in 0..addresses.len().max(1) {
            let address = selector.select()?;
            let backend_index = addresses
                .iter()
                .position(|candidate| *candidate == address)?;
            if health_keys
                .get(backend_index)
                .is_some_and(|key| healthy(key))
            {
                return Some(address);
            }
        }
        None
    }

    pub fn health_targets(&self) -> &[HealthTarget] {
        &self.health_targets
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = if pattern.is_empty() { "/" } else { pattern };
    path.starts_with(pattern)
}

fn method_allowed(methods: &[String], method: &str) -> bool {
    methods.is_empty() || methods.iter().any(|allowed| allowed == method)
}

#[cfg(test)]
mod tests {
    //! Admitted routes must apply path, method, and external health inputs during selection.

    use std::net::SocketAddr;

    use crate::snapshot::Snapshot;
    use crate::test_support::{configuration, sign_configuration};

    #[test]
    fn backend_selection_uses_literal_path_prefixes_and_empty_patterns_match_root() {
        let expected: SocketAddr = "10.0.0.5:8080".parse().expect("literal backend address");
        for (pattern, path, matches) in [
            ("/", "/", true),
            ("", "/anything", true),
            ("", "anything", false),
            ("/api", "/api/v1", true),
            ("/api", "/apix", true),
            ("/api", "/API", false),
            ("/api", "/other", false),
        ] {
            let mut input = configuration();
            input.routes[0].path_match = pattern.into();
            sign_configuration(&mut input);
            let snapshot = Snapshot::admit(input).expect("path configuration admitted");
            assert_eq!(
                snapshot.select_backend("api.example.com", path, "GET", |_| true),
                matches.then_some(expected),
                "pattern {pattern:?}, path {path:?}"
            );
        }
    }

    #[test]
    fn backend_selection_allows_empty_method_lists_and_matches_explicit_methods_by_case() {
        let expected: SocketAddr = "10.0.0.5:8080".parse().expect("literal backend address");
        for (methods, requests) in [
            (vec![], vec![("PATCH", true), ("get", true)]),
            (
                vec!["GET", "POST"],
                vec![
                    ("GET", true),
                    ("POST", true),
                    ("get", false),
                    ("PATCH", false),
                ],
            ),
        ] {
            let mut input = configuration();
            input.routes[0].methods = methods.iter().map(|method| (*method).to_owned()).collect();
            sign_configuration(&mut input);
            let snapshot = Snapshot::admit(input).expect("method configuration admitted");
            for (method, allowed) in requests {
                assert_eq!(
                    snapshot.select_backend("api.example.com", "/", method, |_| true),
                    allowed.then_some(expected),
                    "allowed methods {methods:?}, request method {method:?}"
                );
            }
        }
    }

    #[test]
    fn failed_selection_preserves_recovery_sequence_and_clone_shared_cursor() {
        for count in [2, 4, 5, 256] {
            let mut input = configuration();
            let backend = input.routes[0].backends[0].clone();
            input.routes[0].backends = (0..count)
                .map(|index| {
                    let mut backend = backend.clone();
                    let endpoint = backend.endpoint.as_mut().expect("fixture endpoint");
                    endpoint.port = 8000 + index;
                    endpoint.workload_id = format!("workload-{index}");
                    backend
                })
                .collect();
            input.routes[0].backends.reverse();
            sign_configuration(&mut input);
            let snapshot = Snapshot::admit(input).expect("backend set admitted");
            assert_eq!(
                snapshot.select_backend("api.example.com", "/", "GET", |_| false),
                None
            );
            let clone = snapshot.clone();
            for index in 0..3 {
                let reader = if index == 1 { &clone } else { &snapshot };
                let expected: SocketAddr = format!("10.0.0.5:{}", 8000 + index % count)
                    .parse()
                    .expect("expected address");
                assert_eq!(
                    reader.select_backend("api.example.com", "/", "GET", |_| true),
                    Some(expected)
                );
            }
            let last_key = &snapshot
                .health_targets()
                .iter()
                .find(|target| u32::from(target.address.port()) == 8000 + count - 1)
                .expect("final-address health target")
                .key;
            let expected: SocketAddr = format!("10.0.0.5:{}", 8000 + count - 1)
                .parse()
                .expect("expected final address");
            assert_eq!(
                snapshot.select_backend("api.example.com", "/", "GET", |key| key == last_key),
                Some(expected)
            );
        }
    }

    #[test]
    fn duplicate_addresses_keep_first_scope_and_repeat_stateful_health_callbacks() {
        for count in [2, 5, 256] {
            let mut input = configuration();
            let template = input.routes[0].backends[0].clone();
            for index in 1..count {
                let mut duplicate = template.clone();
                duplicate
                    .endpoint
                    .as_mut()
                    .expect("fixture endpoint")
                    .workload_id = format!("another-workload-{index}");
                input.routes[0].backends.push(duplicate);
            }
            sign_configuration(&mut input);
            let snapshot = Snapshot::admit(input.clone()).expect("duplicate address admitted");
            let targets = snapshot.health_targets();
            assert_ne!(targets[0].key, targets[1].key);
            let mut callbacks = Vec::new();
            assert_eq!(
                snapshot.select_backend("api.example.com", "/", "GET", |key| {
                    callbacks.push(key.to_owned());
                    callbacks.len() == 2
                }),
                Some(targets[0].address)
            );
            assert_eq!(
                callbacks,
                vec![targets[0].key.clone(), targets[0].key.clone()]
            );
            assert_eq!(
                snapshot.select_backend("api.example.com", "/", "GET", |key| key == targets[1].key),
                None
            );

            for backend in &mut input.routes[0].backends {
                backend.draining = true;
            }
            sign_configuration(&mut input);
            let drained = Snapshot::admit(input).expect("draining backend set admitted");
            assert_eq!(
                drained.select_backend("api.example.com", "/", "GET", |_| true),
                None
            );
        }
    }

    #[test]
    fn selection_preserves_effective_uniform_weights_without_changing_signed_configuration() {
        let mut input = configuration();
        input.routes[0].backends[0].weight = 0;
        let mut second = input.routes[0].backends[0].clone();
        second.weight = 10_000;
        second.endpoint.as_mut().expect("fixture endpoint").port = 8081;
        input.routes[0].backends.push(second);
        sign_configuration(&mut input);
        let snapshot = Snapshot::admit(input.clone()).expect("weighted input admitted");
        assert_eq!(snapshot.configuration, input);
        let first: SocketAddr = "10.0.0.5:8080".parse().expect("first address");
        let second: SocketAddr = "10.0.0.5:8081".parse().expect("second address");
        for expected in [first, second, first, second] {
            assert_eq!(
                snapshot.select_backend("api.example.com", "/", "GET", |_| true),
                Some(expected)
            );
        }
    }

    #[test]
    fn backend_selection_obeys_external_health_without_changing_the_route() {
        let snapshot = Snapshot::admit(configuration()).expect("live configuration admitted");
        let expected: SocketAddr = "10.0.0.5:8080".parse().expect("literal backend address");
        assert_eq!(
            snapshot.select_backend("api.example.com", "/", "GET", |_| true),
            Some(expected)
        );
        assert_eq!(
            snapshot.select_backend("api.example.com", "/", "GET", |_| false),
            None
        );
        assert_eq!(
            snapshot.select_backend("api.example.com", "/", "GET", |_| true),
            Some(expected)
        );
    }
}
