use super::support::*;
use crate::control::{GatewayState, RouteLookup};

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
