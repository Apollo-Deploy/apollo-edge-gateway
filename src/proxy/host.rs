//! Request hostname normalization and HTTP Host/authority/TLS SNI validation.

use pingora::proxy::Session;
use pingora::{Error, ErrorType, Result};

use super::tls::TlsMetadata;

pub(super) fn request_host(session: &Session) -> Result<String> {
    let request = session.req_header();
    let hosts = request.headers.get_all("host");
    let host = match hosts.iter().count() {
        0 if session.as_downstream().is_http2() => request
            .uri
            .authority()
            .and_then(|authority| normalize_host(authority.as_str()))
            .ok_or_else(|| Error::new(ErrorType::HTTPStatus(400)))?,
        1 => {
            let host_header = hosts
                .iter()
                .next()
                .ok_or_else(|| Error::new(ErrorType::HTTPStatus(400)))?;
            match normalize_host(host_header.to_str().unwrap_or_default()) {
                Some(host) => host,
                None => return Error::e_explain(ErrorType::HTTPStatus(400), "invalid Host"),
            }
        }
        _ => return Error::e_explain(ErrorType::HTTPStatus(400), "exactly one Host is required"),
    };
    if session.as_downstream().is_http2()
        && let Some(authority) = request.uri.authority()
        && normalize_host(authority.as_str()).as_deref() != Some(host.as_str())
    {
        return Error::e_explain(
            ErrorType::HTTPStatus(421),
            "Host and authority do not match",
        );
    }
    let sni = match session
        .as_downstream()
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .and_then(|digest| digest.extension.get::<TlsMetadata>())
        .and_then(|metadata| normalize_host(&metadata.sni))
    {
        Some(sni) => sni,
        None => return Error::e_explain(ErrorType::HTTPStatus(421), "missing TLS SNI"),
    };
    if sni != host {
        return Error::e_explain(ErrorType::HTTPStatus(421), "Host and SNI do not match");
    }
    Ok(host)
}

fn normalize_host(value: &str) -> Option<String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    let (host, port) = if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') || port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            return None;
        }
        (host, Some(port))
    } else {
        (value, None)
    };
    if host.is_empty()
        || host.contains(':')
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
    {
        return None;
    }
    let host = host.to_ascii_lowercase();
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    let _ = port;
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::normalize_host;

    #[test]
    fn normalizes_case_and_discards_valid_ports() {
        for (value, expected) in [
            ("Example.COM", "example.com"),
            ("Example.COM:443", "example.com"),
            ("Example.COM:00443", "example.com"),
            ("Example.COM:1", "example.com"),
            ("Example.COM:65535", "example.com"),
            ("LOCALHOST", "localhost"),
            ("127.0.0.1:443", "127.0.0.1"),
            ("My-App.example.com", "my-app.example.com"),
        ] {
            assert_eq!(normalize_host(value).as_deref(), Some(expected), "{value}");
        }
    }

    #[test]
    fn rejects_empty_hosts_whitespace_and_control_bytes() {
        for value in [
            "",
            " example.com",
            "example.com ",
            "exam ple.com",
            "example.com\t",
            "example.com\r\n",
            "example.com\0",
            "example.com\u{7f}",
        ] {
            assert_eq!(normalize_host(value), None, "{value:?}");
        }
    }

    #[test]
    fn rejects_invalid_ports_and_ipv6_hosts() {
        for value in [
            ":443",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:-1",
            "example.com:https",
            "example.com:443:443",
            "::1",
            "[::1]:443",
        ] {
            assert_eq!(normalize_host(value), None, "{value}");
        }
    }

    #[test]
    fn rejects_invalid_dns_labels_and_non_dns_characters() {
        for value in [
            ".example.com",
            "example.com.",
            "example..com",
            "-example.com",
            "example-.com",
            "example_com",
            "example.com/path",
            "example.com?query",
            "example.com#fragment",
            "user@example.com",
            "bücher.example",
        ] {
            assert_eq!(normalize_host(value), None, "{value}");
        }
    }

    #[test]
    fn enforces_label_and_hostname_length_bounds() {
        let label = "a".repeat(63);
        assert_eq!(normalize_host(&label).as_deref(), Some(label.as_str()));
        assert_eq!(normalize_host(&"a".repeat(64)), None);

        let host = format!("{label}.{label}.{label}.{}", "b".repeat(61));
        assert_eq!(host.len(), 253);
        assert_eq!(normalize_host(&host).as_deref(), Some(host.as_str()));
        assert_eq!(normalize_host(&format!("{host}b")), None);
    }
}
