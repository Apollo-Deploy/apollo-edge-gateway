//! Per-request body/retry state, fallback limits, and in-flight admission.

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use pingora::{Error, ErrorType, Result};

use crate::control::RuntimeLimits;

const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENCY: usize = 1_024;

/// Crate-visible because it is the associated context type of `ApolloGateway`.
pub(crate) struct RequestContext {
    pub(super) max_body_bytes: u64,
    pub(super) retry_max_attempts: usize,
    pub(super) retry_methods: Vec<String>,
    body_bytes: u64,
    pub(super) counted: bool,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            retry_max_attempts: 1,
            retry_methods: Vec::new(),
            body_bytes: 0,
            counted: false,
        }
    }
}

impl RequestContext {
    pub(super) fn record_body(&mut self, body: Option<&Bytes>) -> Result<()> {
        if let Some(body) = body {
            self.body_bytes = self
                .body_bytes
                .checked_add(body.len() as u64)
                .ok_or_else(|| Error::new(ErrorType::HTTPStatus(413)))?;
            if self.body_bytes > self.max_body_bytes {
                return Error::e_explain(
                    ErrorType::HTTPStatus(413),
                    "request body exceeds the bound",
                );
            }
        }
        Ok(())
    }
}

pub(super) fn default_runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
        max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        max_concurrency: DEFAULT_MAX_CONCURRENCY,
        retry_max_attempts: 1,
        retry_methods: Vec::new(),
    }
}

pub(super) fn acquire_in_flight(counter: &AtomicUsize, limit: usize) -> Result<()> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if current >= limit {
            return Error::e_explain(
                ErrorType::HTTPStatus(503),
                "request concurrency limit reached",
            );
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use bytes::Bytes;
    use pingora::ErrorType;
    use pingora::proxy::{ProxyHttp, Session};

    use crate::GatewayState;

    use super::super::ApolloGateway;
    use super::{RequestContext, acquire_in_flight, default_runtime_limits};

    fn body_filter_fixture(max_body_bytes: u64) -> (ApolloGateway, Session, RequestContext) {
        let gateway = ApolloGateway::new(Arc::new(GatewayState::empty()));
        let (stream, _) = tokio::io::duplex(64);
        let session = Session::new_h1(Box::new(stream));
        let mut ctx = gateway.new_ctx();
        ctx.max_body_bytes = max_body_bytes;
        (gateway, session, ctx)
    }

    #[test]
    fn request_context_and_fallback_limits_preserve_defaults() {
        let ctx = RequestContext::default();
        let limits = default_runtime_limits();
        assert_eq!(limits.max_header_bytes, 64 * 1024);
        assert_eq!(limits.max_body_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_concurrency, 1_024);
        assert_eq!(limits.retry_max_attempts, 1);
        assert!(limits.retry_methods.is_empty());
        assert_eq!(ctx.max_body_bytes, limits.max_body_bytes);
        assert_eq!(ctx.retry_max_attempts, limits.retry_max_attempts);
        assert!(ctx.retry_methods.is_empty());
        assert_eq!(ctx.body_bytes, 0);
        assert!(!ctx.counted);
    }

    #[test]
    fn acquires_up_to_the_limit_and_leaves_rejected_count_unchanged() {
        let counter = AtomicUsize::new(0);
        acquire_in_flight(&counter, 2).expect("first request admitted");
        acquire_in_flight(&counter, 2).expect("second request admitted");
        let error = acquire_in_flight(&counter, 2).expect_err("limit reached");
        assert_eq!(error.etype, ErrorType::HTTPStatus(503));
        assert_eq!(counter.load(Ordering::Acquire), 2);
    }

    #[test]
    fn rejects_zero_or_lowered_limits_without_incrementing() {
        for (current, limit) in [(0, 0), (2, 1)] {
            let counter = AtomicUsize::new(current);
            let error = acquire_in_flight(&counter, limit).expect_err("no capacity");
            assert_eq!(error.etype, ErrorType::HTTPStatus(503));
            assert_eq!(counter.load(Ordering::Acquire), current);
        }
    }

    #[test]
    fn rejects_at_the_maximum_counter_without_overflow() {
        let counter = AtomicUsize::new(usize::MAX - 1);
        acquire_in_flight(&counter, usize::MAX).expect("last slot admitted");
        let error = acquire_in_flight(&counter, usize::MAX).expect_err("counter full");
        assert_eq!(error.etype, ErrorType::HTTPStatus(503));
        assert_eq!(counter.load(Ordering::Acquire), usize::MAX);
    }

    #[test]
    fn concurrent_admission_does_not_exceed_the_limit() {
        let counter = AtomicUsize::new(0);
        let barrier = Barrier::new(16);
        let admitted = thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        acquire_in_flight(&counter, 8).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().expect("admission thread completed")))
                .sum::<usize>()
        });
        assert_eq!(admitted, 8);
        assert_eq!(counter.load(Ordering::Acquire), 8);
    }

    #[tokio::test]
    async fn body_chunks_are_counted_cumulatively_and_accept_the_exact_bound() {
        let (gateway, mut session, mut ctx) = body_filter_fixture(5);
        let mut body = Some(Bytes::from_static(b"abc"));
        gateway
            .request_body_filter(&mut session, &mut body, false, &mut ctx)
            .await
            .expect("first chunk accepted");
        body = Some(Bytes::from_static(b"de"));
        gateway
            .request_body_filter(&mut session, &mut body, false, &mut ctx)
            .await
            .expect("exact body bound accepted");

        body = Some(Bytes::from_static(b"f"));
        let error = gateway
            .request_body_filter(&mut session, &mut body, true, &mut ctx)
            .await
            .expect_err("cumulative body exceeds bound");
        assert_eq!(error.etype, ErrorType::HTTPStatus(413));
    }

    #[tokio::test]
    async fn absent_and_empty_body_chunks_do_not_consume_capacity() {
        for max_body_bytes in [0, 5] {
            let (gateway, mut session, mut ctx) = body_filter_fixture(max_body_bytes);
            let mut body = Some(Bytes::new());
            gateway
                .request_body_filter(&mut session, &mut body, false, &mut ctx)
                .await
                .expect("empty body accepted");
            body = Some(Bytes::from_static(if max_body_bytes == 0 {
                b""
            } else {
                b"abcde"
            }));
            gateway
                .request_body_filter(&mut session, &mut body, false, &mut ctx)
                .await
                .expect("remaining body capacity accepted");
            body = Some(Bytes::new());
            gateway
                .request_body_filter(&mut session, &mut body, false, &mut ctx)
                .await
                .expect("empty body at the bound accepted");
            body = None;
            gateway
                .request_body_filter(&mut session, &mut body, true, &mut ctx)
                .await
                .expect("terminal absent body accepted");
        }

        let (gateway, mut session, mut ctx) = body_filter_fixture(0);
        let mut body = Some(Bytes::from_static(b"a"));
        let error = gateway
            .request_body_filter(&mut session, &mut body, true, &mut ctx)
            .await
            .expect_err("nonempty body rejected at zero capacity");
        assert_eq!(error.etype, ErrorType::HTTPStatus(413));
    }

    #[test]
    fn body_counter_overflow_returns_413_without_wrapping() {
        let mut ctx = RequestContext {
            max_body_bytes: u64::MAX,
            body_bytes: u64::MAX,
            ..RequestContext::default()
        };
        let error = ctx
            .record_body(Some(&Bytes::from_static(b"a")))
            .expect_err("body counter overflow rejected");
        assert_eq!(error.etype, ErrorType::HTTPStatus(413));
        assert_eq!(ctx.body_bytes, u64::MAX);
    }
}
