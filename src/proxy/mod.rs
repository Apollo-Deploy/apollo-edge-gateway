//! Gateway HTTP proxy handling, with host validation, limits, and listener TLS.
//!
//! Startup constructs [`ApolloGateway`] and obtains listener settings through
//! [`tls_settings`]; the supporting modules remain private to this feature.

mod host;
mod limits;
mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::RequestHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};

use crate::GatewayState;
use crate::control::RouteLookup;

use self::host::request_host;
use self::limits::{RequestContext, acquire_in_flight, default_runtime_limits};

pub(crate) use self::tls::tls_settings;

const MAX_PATH_BYTES: usize = 2_048;

/// HTTP proxy handler backed by the gateway's admitted routing state.
pub(crate) struct ApolloGateway {
    state: Arc<GatewayState>,
    in_flight: Arc<AtomicUsize>,
}

impl ApolloGateway {
    /// Creates a handler with an empty in-flight request counter.
    pub(crate) fn new(state: Arc<GatewayState>) -> Self {
        Self {
            state,
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl ProxyHttp for ApolloGateway {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let host = request_host(session)?;
        let request = session.req_header();
        if !request.raw_path_is_utf8() {
            return Error::e_explain(
                ErrorType::HTTPStatus(400),
                "request target is not valid UTF-8",
            );
        }
        if request.uri.authority().is_some() && !session.as_downstream().is_http2() {
            return Error::e_explain(
                ErrorType::HTTPStatus(400),
                "absolute-form request targets are not accepted",
            );
        }
        let path = request.uri.path();
        if path.len() > MAX_PATH_BYTES {
            return Error::e_explain(ErrorType::HTTPStatus(414), "request path exceeds the bound");
        }
        let limits = self
            .state
            .limits_for(&host, path)
            .unwrap_or_else(default_runtime_limits);
        let header_bytes = request
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .sum::<usize>()
            .saturating_add(request.method.as_str().len())
            .saturating_add(request.raw_path().len());
        if header_bytes > limits.max_header_bytes {
            return Error::e_explain(
                ErrorType::HTTPStatus(431),
                "request headers exceed the bound",
            );
        }
        if request.headers.get_all("content-length").iter().count() > 1 {
            return Error::e_explain(
                ErrorType::HTTPStatus(400),
                "multiple Content-Length headers are not accepted",
            );
        }
        let transfer_encoding = request.headers.get_all("transfer-encoding");
        if transfer_encoding.iter().count() > 1
            || transfer_encoding
                .iter()
                .any(|value| value.as_bytes() != b"chunked")
        {
            return Error::e_explain(ErrorType::HTTPStatus(400), "invalid Transfer-Encoding");
        }
        if request.headers.get("content-length").is_some()
            && transfer_encoding.iter().next().is_some()
        {
            return Error::e_explain(
                ErrorType::HTTPStatus(400),
                "Content-Length with Transfer-Encoding is not accepted",
            );
        }
        if let Some(content_length) = request.headers.get("content-length") {
            let content_length = content_length
                .to_str()
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .ok_or_else(|| Error::new(ErrorType::HTTPStatus(400)))?;
            if content_length > limits.max_body_bytes {
                return Error::e_explain(
                    ErrorType::HTTPStatus(413),
                    "request body exceeds the bound",
                );
            }
        }
        if request.headers.get("upgrade").is_some() {
            return Error::e_explain(
                ErrorType::HTTPStatus(501),
                "protocol upgrade is unsupported",
            );
        }
        acquire_in_flight(&self.in_flight, limits.max_concurrency)?;
        ctx.max_body_bytes = limits.max_body_bytes;
        ctx.retry_max_attempts = limits.retry_max_attempts;
        ctx.retry_methods = limits.retry_methods;
        ctx.counted = true;
        if ctx.retry_max_attempts > 1
            && ctx
                .retry_methods
                .iter()
                .any(|method| method == request.method.as_str())
        {
            session.enable_retry_buffering();
        }
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.record_body(body.as_ref())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = request_host(session)?;
        let request = session.req_header();
        if request.uri.authority().is_some() && !session.as_downstream().is_http2() {
            return Error::e_explain(
                ErrorType::HTTPStatus(400),
                "absolute-form request targets are not accepted",
            );
        }
        let path = request.uri.path();
        let method = session.req_header().method.as_str();
        if path.len() > MAX_PATH_BYTES {
            return Error::e_explain(ErrorType::HTTPStatus(414), "request path exceeds the bound");
        }
        let address = match self.state.resolve_backend(&host, path, method) {
            RouteLookup::Backend(address) => address,
            RouteLookup::NotFound => {
                return Error::e_explain(ErrorType::HTTPStatus(404), "route not found");
            }
            RouteLookup::MethodNotAllowed => {
                return Error::e_explain(ErrorType::HTTPStatus(405), "method is not allowed");
            }
            RouteLookup::Unavailable => return Err(Error::new(ErrorType::HTTPStatus(503))),
            RouteLookup::Ambiguous => {
                return Error::e_explain(ErrorType::HTTPStatus(421), "ambiguous route ownership");
            }
        };
        let peer = HttpPeer::new(address, false, String::new());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        for header in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "transfer-encoding",
            "trailer",
            "te",
        ] {
            upstream_request.remove_header(header);
        }
        let host = request_host(session)?;
        upstream_request.insert_header("host", host)?;
        Ok(())
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        let mut error = e.more_context(format!("Peer: {peer}"));
        let method = session.req_header().method.as_str();
        let retry_allowed = ctx.retry_max_attempts > 1
            && ctx.retry_methods.iter().any(|allowed| allowed == method)
            && !session.as_ref().retry_buffer_truncated();
        if retry_allowed {
            error.retry.decide_reuse(client_reused);
        } else {
            error.set_retry(false);
        }
        error
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(error) = error {
            let status = session
                .response_written()
                .map_or(0, |response| response.status.as_u16());
            eprintln!(
                "apollo_edge_request_failed status={status} type={:?} source={:?}",
                error.etype, error.esource
            );
        }
        if ctx.counted {
            let _ = self
                .in_flight
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(1)
                });
            ctx.counted = false;
        }
    }
}
