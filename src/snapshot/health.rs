//! Process-local derived health identity; never part of signed or persisted configuration.
use std::net::SocketAddr;

use crate::control::WorkloadEndpoint;

pub(super) fn backend_health_key(
    target_id: &str,
    endpoint: &WorkloadEndpoint,
    address: &SocketAddr,
) -> String {
    let mut key = String::new();

    for field in [target_id, endpoint.workload_id.as_str()] {
        for character in field.chars() {
            key.push(character);

            if character == '\0' {
                key.push('\x01');
            }
        }

        // NUL+NUL terminates; NUL+SOH escapes. NUL-free field prefixes still
        // sort before longer identities, preserving the producer's capped prefix.
        key.push_str("\0\0");
    }

    key.push_str(&format!("{}\0{address}", endpoint.workload_generation));

    key
}

#[cfg(test)]
mod tests {

    use std::net::SocketAddr;

    use crate::control::WorkloadEndpoint;

    use super::backend_health_key;

    fn encode(target: &str, workload: &str, generation: u64, address: &str) -> String {
        let endpoint = WorkloadEndpoint {
            workload_id: workload.into(),
            workload_generation: generation,
            ..Default::default()
        };

        backend_health_key(
            target,
            &endpoint,
            &address.parse().expect("literal socket address"),
        )
    }

    #[test]
    fn nul_free_keys_keep_legacy_lexicographic_order_in_every_component() {
        let identities = [
            "", "\x01", "a", "aa", "aaa", "ab", "b", "e\u{301}", "é", "東京", "🙂",
        ];

        let address = "10.0.0.5:8080";

        let mut cases = Vec::new();

        for identity in identities {
            cases.push((identity, "workload", 1, address));

            cases.push(("target", identity, 1, address));
        }

        for generation in [1, 2, 10, 100, u64::MAX] {
            cases.push(("target", "workload", generation, address));
        }

        for address in [
            "10.0.0.5:80",
            "10.0.0.5:8080",
            "10.0.0.6:8080",
            "[fd00::5]:8080",
        ] {
            cases.push(("target", "workload", 1, address));
        }

        let pairs: Vec<_> = cases
            .into_iter()
            .map(|(target, workload, generation, address)| {
                let canonical: SocketAddr = address.parse().expect("literal socket address");

                (
                    format!("{target}\0{workload}\0{generation}\0{canonical}"),
                    encode(target, workload, generation, address),
                )
            })
            .collect();

        for (legacy_a, encoded_a) in &pairs {
            for (legacy_b, encoded_b) in &pairs {
                assert_eq!(
                    encoded_a.cmp(encoded_b),
                    legacy_a.cmp(legacy_b),
                    "legacy order changed for {legacy_a:?} and {legacy_b:?}"
                );
            }
        }
    }
}
