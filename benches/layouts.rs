//! Bounded supplemental public-API benchmarks; hot_paths.rs remains the primary frozen harness.
#![forbid(unsafe_code)]
#[cfg(feature = "bench-allocations")]
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[path = "layouts/fixture.rs"]
mod fixture;
#[path = "layouts/lifecycle.rs"]
mod lifecycle;
#[path = "layouts/measure.rs"]
mod measure;
#[path = "layouts/scenarios.rs"]
mod scenarios;

fn main() {
    scenarios::run();
}
