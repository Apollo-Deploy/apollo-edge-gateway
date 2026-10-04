//! Public GatewayState microbenchmarks. See README.md beside this file.
#![forbid(unsafe_code)]
#[cfg(feature = "bench-allocations")]
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[path = "hot_paths/fixture.rs"]
mod fixture;
#[path = "hot_paths/runner.rs"]
mod runner;

fn main() {
    runner::run();
}
