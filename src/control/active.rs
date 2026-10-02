//! Authoritative entries and their derived exact-host candidates are published together.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::snapshot::Snapshot;

#[derive(Clone, Default)]
pub struct ActiveConfigurations {
    pub(super) entries: BTreeMap<String, Arc<Snapshot>>,
    by_host: BTreeMap<String, Vec<Arc<Snapshot>>>,
}

impl ActiveConfigurations {
    pub(super) fn new(entries: BTreeMap<String, Arc<Snapshot>>) -> Self {
        let mut by_host: BTreeMap<String, Vec<Arc<Snapshot>>> = BTreeMap::new();
        for snapshot in entries.values() {
            for route in &snapshot.routes {
                let candidates = by_host.entry(route.hostname.clone()).or_default();
                // A target's routes are contiguous in this traversal, even when its
                // repeated hostnames are not. Preserve target order without duplicates.
                if !candidates
                    .last()
                    .is_some_and(|last| Arc::ptr_eq(last, snapshot))
                {
                    candidates.push(Arc::clone(snapshot));
                }
            }
        }
        Self { entries, by_host }
    }

    pub(super) fn candidates(&self, host: &str) -> &[Arc<Snapshot>] {
        self.by_host.get(host).map_or(&[], Vec::as_slice)
    }
}
