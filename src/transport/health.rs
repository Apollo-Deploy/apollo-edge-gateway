use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::control::GatewayState;

const HEALTH_INTERVAL: Duration = Duration::from_secs(2);
const HEALTH_TIMEOUT: Duration = Duration::from_millis(500);
const HEALTH_SUCCESS_THRESHOLD: u8 = 2;
const HEALTH_FAILURE_THRESHOLD: u8 = 3;
const MAX_HEALTH_TARGETS_PER_CYCLE: usize = 4_096;

#[derive(Clone, Copy)]
struct HealthWindow {
    healthy: bool,
    successes: u8,
    failures: u8,
}

pub(super) async fn health_loop(state: Arc<GatewayState>) {
    let mut interval = tokio::time::interval(HEALTH_INTERVAL);
    let mut windows: BTreeMap<String, HealthWindow> = BTreeMap::new();
    loop {
        interval.tick().await;
        let targets = state.health_targets();
        let target_keys = targets
            .iter()
            .take(MAX_HEALTH_TARGETS_PER_CYCLE)
            .map(|target| target.key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        windows.retain(|key, _| target_keys.contains(key));
        let mut published = BTreeMap::new();
        for target in targets.into_iter().take(MAX_HEALTH_TARGETS_PER_CYCLE) {
            let reachable = matches!(
                timeout(HEALTH_TIMEOUT, TcpStream::connect(target.address)).await,
                Ok(Ok(_)),
            );
            let window = windows.entry(target.key.clone()).or_insert(HealthWindow {
                healthy: false,
                successes: 0,
                failures: 0,
            });
            if reachable {
                window.successes = window.successes.saturating_add(1);
                window.failures = 0;
                if window.successes >= HEALTH_SUCCESS_THRESHOLD {
                    window.healthy = true;
                }
            } else {
                window.failures = window.failures.saturating_add(1);
                window.successes = 0;
                if window.failures >= HEALTH_FAILURE_THRESHOLD {
                    window.healthy = false;
                }
            }
            published.insert(target.key, window.healthy);
        }
        state.publish_health(published);
        state.retire_expired_drains();
        state.retire_unused_certificate_material();
    }
}
