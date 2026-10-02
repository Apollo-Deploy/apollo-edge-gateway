//! Static, uniformly weighted Pingora selection; Apollo owns external health.
//!
//! The former static discovery constructor discarded configured weights and its
//! internal readiness was never changed. Keep that membership and cursor behavior
//! without retaining an unused discovery/health service. Each attempt must use a
//! fresh iterator's first candidate: iterating further changes exhaustion/dedup
//! semantics. A future internal-health service must revisit this invariant.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use pingora::lb::Backend;
use pingora::lb::selection::{BackendIter, BackendSelection, RoundRobin};

#[derive(Clone)]
pub(super) struct StaticSelection(Arc<RoundRobin>);

impl StaticSelection {
    pub(super) fn new(backends: BTreeSet<Backend>) -> Self {
        Self(Arc::new(RoundRobin::build(&backends)))
    }

    pub(super) fn select(&self) -> Option<SocketAddr> {
        self.0.iter(b"").next()?.addr.as_inet().copied()
    }
}
