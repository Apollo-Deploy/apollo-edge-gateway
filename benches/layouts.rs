//! Bounded supplemental public-API benchmarks; hot_paths.rs remains the primary frozen harness.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
#[cfg(not(feature = "bench-allocations"))]
use std::sync::{Barrier, atomic::AtomicBool};
#[cfg(not(feature = "bench-allocations"))]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apollo_edge_gateway::control::{
    ApplyConfigurationRequest, BackendHealthRequirement, CommandOutcome, DrainConfigurationRequest,
    EdgeBackend, EdgeConfiguration, EdgeProtocol, EdgeRoute, EdgeTlsBinding, NetworkScope,
    OperationIdentity, ProductIdentity, RouteLookup, WithdrawConfigurationRequest,
    WorkloadEndpoint,
};
use apollo_edge_gateway::state::StateStore;
use apollo_edge_gateway::{AdmissionError, GatewayState};
use prost::Message;
use sha2::{Digest, Sha256};

// No override in the timing executable. Counting never changes the production allocator.
#[cfg(feature = "bench-allocations")]
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[derive(Clone, Copy)]
struct Layout {
    id: &'static str,
    targets: usize,
    routes: usize,
    distinct_hosts: bool,
    long_hosts: bool,
}

const LAYOUTS: [Layout; 4] = [
    Layout {
        id: "distinct-host-fleet128x8",
        targets: 128,
        routes: 8,
        distinct_hosts: true,
        long_hosts: false,
    },
    Layout {
        id: "shared-host-fleet128x8",
        targets: 128,
        routes: 8,
        distinct_hosts: false,
        long_hosts: false,
    },
    Layout {
        id: "one-target-routes1024",
        targets: 1,
        routes: 1024,
        distinct_hosts: false,
        long_hosts: false,
    },
    Layout {
        id: "long-host-fleet128x8",
        targets: 128,
        routes: 8,
        distinct_hosts: true,
        long_hosts: true,
    },
];
const SMALL: Layout = Layout {
    id: "lifecycle",
    targets: 1,
    routes: 1,
    distinct_hosts: true,
    long_hosts: false,
};

fn identity(target: usize) -> ProductIdentity {
    ProductIdentity {
        organization_id: "org".into(),
        project_id: "project".into(),
        service_id: format!("service-{target:03}"),
        deployment_id: format!("deployment-{target:03}"),
        release_id: format!("release-{target:03}"),
        route_id: format!("route-{target:03}"),
        traffic_target_id: format!("target-{target:03}"),
    }
}

fn hostname(layout: Layout, target: usize, route: usize) -> String {
    if layout.long_hosts {
        // Four valid DNS labels, exactly 253 bytes, still unique for every route.
        format!(
            "{}.{}.{}.t{target:03}-r{route:04}-{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(50)
        )
    } else if layout.distinct_hosts {
        format!("t{target:03}-r{route:04}.bench.example")
    } else {
        "shared.bench.example".into()
    }
}

fn path(target: usize, route: usize) -> String {
    // Trailing separators prevent /r0001 from also matching /r00010.
    format!("/t{target:03}/r{route:04}/")
}

fn address(layout: Layout, target: usize, route: usize, variant: usize) -> SocketAddr {
    SocketAddr::from((
        Ipv4Addr::new(10, 23, 0, 1),
        (10_000 + target * layout.routes + route + variant * 2_000) as u16,
    ))
}

fn sign(mut configuration: EdgeConfiguration) -> ApplyConfigurationRequest {
    configuration.configuration_hash.clear();
    configuration.configuration_hash = Sha256::digest(configuration.encode_to_vec()).to_vec();
    let operation = OperationIdentity {
        operation_id: format!(
            "apply-{}-{}",
            configuration
                .identity
                .as_ref()
                .expect("identity")
                .traffic_target_id,
            configuration.generation
        ),
        effect_id: format!("effect-{}", configuration.generation),
        controller_epoch: configuration.controller_epoch,
        generation: configuration.generation,
        configuration_hash: configuration.configuration_hash.clone(),
    };
    ApplyConfigurationRequest {
        operation: Some(operation),
        identity: configuration.identity.clone(),
        configuration: Some(configuration),
    }
}

fn request(
    layout: Layout,
    target: usize,
    generation: u64,
    variant: usize,
) -> ApplyConfigurationRequest {
    let owner = identity(target);
    let routes = (0..layout.routes)
        .map(|route| {
            let host = hostname(layout, target, route);
            EdgeRoute {
                identity: Some(ProductIdentity {
                    route_id: format!("route-{target:03}-{route:04}"),
                    ..owner.clone()
                }),
                hostname: host.clone(),
                path_match: path(target, route),
                methods: vec!["GET".into(), "HEAD".into()],
                protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
                backends: vec![EdgeBackend {
                    endpoint: Some(WorkloadEndpoint {
                        workload_id: format!("workload-{target:03}-{route:04}"),
                        workload_generation: 1,
                        node_id: "node".into(),
                        region_id: "region".into(),
                        cell_id: "cell".into(),
                        address: "10.23.0.1".into(),
                        port: u32::from(address(layout, target, route, variant).port()),
                        protocol: EdgeProtocol::Http1 as i32,
                        network_scope: NetworkScope::CellPrivate as i32,
                        observed_at_unix_ms: 1,
                        ready: true,
                        healthy: true,
                    }),
                    health_requirement: BackendHealthRequirement::ReadyAndHealthy as i32,
                    weight: 1,
                    draining: false,
                }],
                tls: Some(EdgeTlsBinding {
                    certificate_id: "cert".into(),
                    certificate_version: 1,
                    hostname: host,
                    material_reference: "org/project/cert/1".into(),
                    public_certificate_hash: vec![0x31; 32],
                    certificate_chain_hash: vec![0x52; 32],
                }),
                route_generation: generation,
            }
        })
        .collect();
    sign(EdgeConfiguration {
        identity: Some(owner),
        controller_epoch: 1,
        generation,
        configuration_hash: Vec::new(),
        issued_at_unix_ms: 1,
        valid_until_unix_ms: i64::MAX,
        routes,
        max_header_bytes: (64 + variant as u32 * 32) * 1024,
        max_body_bytes: 64 * 1024 * 1024,
        max_connections: 1024,
        max_concurrency: 1024,
        drain_timeout_seconds: 60,
        retry_max_attempts: 2,
        retry_methods: vec!["GET".into(), "HEAD".into()],
        semantic_hash: vec![0x73; 32],
    })
}

fn accepted(outcome: CommandOutcome) {
    assert!(
        matches!(outcome, CommandOutcome::Accepted),
        "expected new admitted publication: {outcome:?}"
    );
}

fn publish_health(state: &GatewayState) {
    state.publish_health(
        state
            .health_targets()
            .into_iter()
            .map(|target| (target.key, true))
            .collect(),
    );
}

struct Fixture {
    state: GatewayState,
    host: String,
    path: String,
}

fn fixture(layout: Layout) -> Fixture {
    let state = GatewayState::empty();
    for target in 0..layout.targets {
        accepted(state.apply(request(layout, target, 1, 0)));
    }
    assert_eq!(state.health_targets().len(), layout.targets * layout.routes);
    publish_health(&state);
    // Validate every route, not just the timed late hit: catches shared-host ambiguity/cross-target leaks.
    for target in 0..layout.targets {
        for route in 0..layout.routes {
            let host = hostname(layout, target, route);
            let query = path(target, route) + "request";
            assert_eq!(
                state.resolve_backend(&host, &query, "GET"),
                RouteLookup::Backend(address(layout, target, route, 0))
            );
        }
    }
    let f = Fixture {
        state,
        host: hostname(layout, layout.targets - 1, layout.routes - 1),
        path: path(layout.targets - 1, layout.routes - 1) + "request",
    };
    validate(&f, layout, 0);
    f
}

fn validate(f: &Fixture, layout: Layout, variant: usize) {
    let limits = f.state.limits_for(&f.host, &f.path).expect("exact limits");
    assert_eq!(limits.max_header_bytes, (64 + variant * 32) * 1024);
    assert_eq!(limits.retry_max_attempts, 2);
    assert_eq!(limits.retry_methods, ["GET", "HEAD"]);
    for method in ["GET", "HEAD"] {
        assert_eq!(
            f.state.resolve_backend(&f.host, &f.path, method),
            RouteLookup::Backend(address(
                layout,
                layout.targets - 1,
                layout.routes - 1,
                variant
            ))
        );
    }
    assert_eq!(
        f.state.resolve_backend(&f.host, &f.path, "POST"),
        RouteLookup::MethodNotAllowed
    );
    assert_eq!(
        f.state.resolve_backend(&f.host, "/absent/", "GET"),
        RouteLookup::NotFound
    );
    assert_eq!(
        f.state
            .resolve_backend("absent.bench.example", &f.path, "GET"),
        RouteLookup::NotFound
    );
    assert!(f.state.limits_for(&f.host, "/absent/").is_none());
    assert!(
        f.state
            .certificate_binding_for_host("absent.bench.example")
            .is_none()
    );
    assert_eq!(
        f.state.certificate_binding_for_host(&f.host),
        Some(("org/project/cert/1".into(), vec![0x31; 32], vec![0x52; 32]))
    );
    if layout.long_hosts {
        assert_eq!(f.host.len(), 253);
    }
}

fn semantic_controls() {
    // Not a performance assertion: overlapping targets MUST fail closed, unlike disjoint shared-host paths.
    let shared = Layout {
        targets: 2,
        routes: 1,
        ..LAYOUTS[1]
    };
    let state = GatewayState::empty();
    accepted(state.apply(request(shared, 0, 1, 0)));
    let mut conflict = request(shared, 1, 1, 0)
        .configuration
        .expect("configuration");
    conflict.routes[0].path_match = path(0, 0);
    accepted(state.apply(sign(conflict)));
    publish_health(&state);
    assert_eq!(
        state.resolve_backend("shared.bench.example", &path(0, 0), "GET"),
        RouteLookup::Ambiguous
    );
    assert_eq!(
        state.resolve_backend("shared.bench.example", &path(0, 0), "POST"),
        RouteLookup::MethodNotAllowed
    );

    // Within one target, the longest admitted prefix wins; a denied method must not fall back.
    let nested = Layout {
        targets: 1,
        routes: 2,
        ..shared
    };
    let state = GatewayState::empty();
    let mut configuration = request(nested, 0, 1, 0)
        .configuration
        .expect("configuration");
    configuration.routes[0].path_match = "/".into();
    configuration.routes[0].methods.push("POST".into());
    configuration.routes[1].path_match = "/nested/".into();
    accepted(state.apply(sign(configuration)));
    assert_eq!(
        state.resolve_backend("shared.bench.example", "/nested/request", "GET"),
        RouteLookup::Unavailable
    );
    publish_health(&state);
    assert_eq!(
        state.resolve_backend("shared.bench.example", "/nested/request", "GET"),
        RouteLookup::Backend(address(nested, 0, 1, 0))
    );
    assert_eq!(
        state.resolve_backend("shared.bench.example", "/nested/request", "POST"),
        RouteLookup::MethodNotAllowed
    );
    eprintln!(
        "validated controls=overlapping-target-ambiguity,longest-prefix,method-no-fallback,unpublished-health-fail-closed"
    );
}

struct Options {
    case: String,
    iterations: usize,
    samples: usize,
    writes: usize,
    cycles: usize,
}

fn options() -> Options {
    let mut o = Options {
        case: "all".into(),
        iterations: 2_000,
        samples: 10_000,
        writes: 16,
        cycles: 4,
    };
    let mut args = std::env::args().skip(1);
    let mut mode = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--timing" => mode = Some(false),
            "--allocations" => mode = Some(true),
            "--case" => o.case = args.next().expect("--case value"),
            "--iterations" => {
                o.iterations = args.next().expect("iterations").parse().expect("integer")
            }
            "--samples" => o.samples = args.next().expect("samples").parse().expect("integer"),
            "--writes" => o.writes = args.next().expect("writes").parse().expect("integer"),
            "--cycles" => o.cycles = args.next().expect("cycles").parse().expect("integer"),
            "--list" => {
                for layout in LAYOUTS {
                    println!("{}", layout.id);
                }
                println!("lifecycle");
                std::process::exit(0);
            }
            _ => panic!("unknown argument {arg}; see benches/README.md"),
        }
    }
    assert_eq!(
        mode,
        Some(cfg!(feature = "bench-allocations")),
        "choose --timing for System, --allocations for the counting executable"
    );
    assert!((1..=20_000).contains(&o.iterations));
    assert!((1_000..=10_000).contains(&o.samples));
    assert!((2..=64).contains(&o.writes));
    assert!((1..=16).contains(&o.cycles));
    assert!(
        o.case == "all"
            || o.case == "lifecycle"
            || LAYOUTS.iter().any(|layout| layout.id == o.case),
        "unknown case"
    );
    o
}

struct Measurement {
    #[cfg(not(feature = "bench-allocations"))]
    ns: u64,
    #[cfg(feature = "bench-allocations")]
    stats: stats_alloc::Stats,
}

fn measure<T>(operation: impl FnOnce() -> T) -> (T, Measurement) {
    #[cfg(feature = "bench-allocations")]
    let region = stats_alloc::Region::new(ALLOCATOR);
    #[cfg(not(feature = "bench-allocations"))]
    let start = Instant::now();
    let result = operation();
    let measurement = Measurement {
        #[cfg(feature = "bench-allocations")]
        stats: region.change(),
        #[cfg(not(feature = "bench-allocations"))]
        ns: start.elapsed().as_nanos() as u64,
    };
    (result, measurement)
}

#[cfg(feature = "bench-allocations")]
fn allocation_row(id: &str, phase: &str, n: usize, cycle: usize, stats: stats_alloc::Stats) {
    let live = stats.bytes_allocated as i128 - stats.bytes_deallocated as i128;
    println!(
        "{id},{phase},{n},{cycle},{},{},{},{},{},{},{live}",
        stats.allocations,
        stats.deallocations,
        stats.reallocations,
        stats.bytes_allocated,
        stats.bytes_deallocated,
        stats.bytes_reallocated
    );
}

fn measurement_row(id: &str, phase: &str, n: usize, cycle: usize, measurement: Measurement) {
    #[cfg(feature = "bench-allocations")]
    allocation_row(id, phase, n, cycle, measurement.stats);
    #[cfg(not(feature = "bench-allocations"))]
    timing_row(TimingRow {
        context: RowContext {
            id,
            phase,
            operations: n,
            readers: 1,
        },
        cycle,
        elapsed: measurement.ns as u128,
        samples: &[],
        cohort: 0,
        writes: 0,
    });
}

#[cfg(not(feature = "bench-allocations"))]
struct RowContext<'a> {
    id: &'a str,
    phase: &'a str,
    operations: usize,
    readers: usize,
}

#[cfg(not(feature = "bench-allocations"))]
struct TimingRow<'a> {
    context: RowContext<'a>,
    cycle: usize,
    elapsed: u128,
    samples: &'a [u64],
    cohort: usize,
    writes: usize,
}

#[cfg(not(feature = "bench-allocations"))]
fn timing_row(row: TimingRow<'_>) {
    let TimingRow {
        context:
            RowContext {
                id,
                phase,
                operations: n,
                readers,
            },
        cycle,
        elapsed,
        samples,
        cohort: overlap,
        writes,
    } = row;
    let percentile = |percent: usize| -> String {
        if samples.is_empty() {
            String::new()
        } else {
            samples[(samples.len() * percent).div_ceil(100) - 1].to_string()
        }
    };
    let throughput = if samples.is_empty() || phase == "replacement-control-throughput" {
        format!("{:.3}", n as f64 * 1e9 / elapsed.max(1) as f64)
    } else {
        // Sums of individually timestamped (possibly concurrent) calls are not wall throughput.
        String::new()
    };
    println!(
        "{id},{phase},{n},{cycle},{readers},{elapsed},{:.3},{throughput},{},{},{},{overlap},{writes},,,,,,,,,,",
        elapsed as f64 / n as f64,
        percentile(50),
        percentile(95),
        percentile(99)
    );
}

#[cfg(not(feature = "bench-allocations"))]
struct ConcurrentRow<'a> {
    context: RowContext<'a>,
    samples: &'a [u64],
    cohort: usize,
    writes: usize,
    reader: Option<usize>,
    decisions: usize,
    stored: usize,
    truncated: usize,
    straddlers: usize,
    covered_writes: usize,
    full_worker_lifetime: bool,
    eligible: bool,
    capacity: usize,
    union_covered_writes: Option<usize>,
}

#[cfg(not(feature = "bench-allocations"))]
fn concurrent_row(row: ConcurrentRow<'_>) {
    let ConcurrentRow {
        context:
            RowContext {
                id,
                phase,
                operations: n,
                readers,
            },
        samples,
        cohort,
        writes,
        reader,
        decisions,
        stored,
        truncated,
        straddlers,
        covered_writes,
        full_worker_lifetime,
        eligible,
        capacity,
        union_covered_writes,
    } = row;
    let elapsed: u128 = samples.iter().map(|ns| u128::from(*ns)).sum();
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize| -> String {
        if !eligible || sorted.is_empty() {
            String::new()
        } else {
            sorted[(sorted.len() * percent).div_ceil(100) - 1].to_string()
        }
    };
    let average = if eligible && n > 0 {
        format!("{:.3}", elapsed as f64 / n as f64)
    } else {
        String::new()
    };
    let reader = reader.map(|id| id.to_string()).unwrap_or_default();
    let union = union_covered_writes
        .map(|count| count.to_string())
        .unwrap_or_default();
    println!(
        "{id},{phase},{n},0,{readers},{elapsed},{average},,{},{},{},{cohort},{writes},{reader},{decisions},{stored},{truncated},{straddlers},{covered_writes},{full_worker_lifetime},{eligible},{capacity},{union}",
        percentile(50),
        percentile(95),
        percentile(99)
    );
}

fn decision(f: &Fixture) {
    black_box(f.state.limits_for(black_box(&f.host), black_box(&f.path)));
    black_box(
        f.state
            .resolve_backend(black_box(&f.host), black_box(&f.path), black_box("GET")),
    );
}

fn steady(f: &Fixture, layout: Layout, o: &Options) {
    for phase in ["decision", "binding", "host-miss", "path-miss"] {
        let operation = || match phase {
            "decision" => decision(f),
            "binding" => {
                black_box(f.state.certificate_binding_for_host(black_box(&f.host)));
            }
            "host-miss" => {
                black_box(f.state.resolve_backend(
                    black_box("absent.bench.example"),
                    black_box(&f.path),
                    "GET",
                ));
            }
            _ => {
                black_box(f.state.resolve_backend(
                    black_box(&f.host),
                    black_box("/absent/"),
                    "GET",
                ));
            }
        };
        for _ in 0..128 {
            operation();
        }
        let (_, measurement) = measure(|| {
            for _ in 0..o.iterations {
                operation();
            }
        });
        measurement_row(layout.id, phase, o.iterations, 0, measurement);
        #[cfg(not(feature = "bench-allocations"))]
        {
            let mut samples = Vec::with_capacity(o.samples);
            for _ in 0..o.samples {
                let start = Instant::now();
                operation();
                samples.push(start.elapsed().as_nanos() as u64);
            }
            let elapsed = samples.iter().map(|ns| u128::from(*ns)).sum();
            samples.sort_unstable();
            timing_row(TimingRow {
                context: RowContext {
                    id: layout.id,
                    phase: &format!("{phase}-latency"),
                    operations: samples.len(),
                    readers: 1,
                },
                cycle: 0,
                elapsed,
                samples: &samples,
                cohort: 0,
                writes: 0,
            });
        }
    }
}

// Both old and replacement health keys are ready BEFORE the writer starts. Otherwise a
// changed address would measure unpublished-health failures instead of routing publication.
fn replacement_health(f: &Fixture, layout: Layout) -> BTreeMap<String, bool> {
    let replacement = GatewayState::empty();
    accepted(replacement.apply(request(layout, layout.targets - 1, 2, 1)));
    f.state
        .health_targets()
        .into_iter()
        .chain(replacement.health_targets())
        .map(|target| (target.key, true))
        .collect()
}

#[cfg(feature = "bench-allocations")]
fn allocation_layout(layout: Layout, o: &Options) {
    let total = stats_alloc::Region::new(ALLOCATOR);
    let f = fixture(layout);
    let setup = total.change();
    let old = f.state.active();
    let weak = Arc::downgrade(&old);
    let inputs = stats_alloc::Region::new(ALLOCATOR);
    let update = request(layout, layout.targets - 1, 2, 1);
    let health = replacement_health(&f, layout);
    let input_stats = inputs.change();
    let (_, health_publication) = measure(|| f.state.publish_health(health));
    let (outcome, publication) = measure(|| f.state.apply(update));
    accepted(outcome);
    let old_new_live = total.change();
    assert!(
        !Arc::ptr_eq(&old, &f.state.active()),
        "replacement must publish a new active Arc"
    );
    assert!(weak.upgrade().is_some(), "old active Arc remains retained");
    let (_, release) = measure(|| {
        drop(old);
        assert!(
            weak.upgrade().is_none(),
            "old active Arc must release after the last public owner drops"
        );
        drop(weak);
    });
    let new_live = total.change();
    validate(&f, layout, 1);
    // Capture all cumulative live checkpoints before CSV formatting can perturb the counters.
    allocation_row(layout.id, "setup-gross-and-live-old", 1, 0, setup);
    allocation_row(layout.id, "signed-replacement-inputs", 1, 0, input_stats);
    measurement_row(layout.id, "health-publication", 1, 0, health_publication);
    measurement_row(
        layout.id,
        "replacement-publication-old-retained",
        1,
        0,
        publication,
    );
    allocation_row(
        layout.id,
        "cumulative-live-old-plus-new",
        1,
        0,
        old_new_live,
    );
    measurement_row(layout.id, "release-retained-old", 1, 0, release);
    allocation_row(layout.id, "cumulative-live-new-only", 1, 0, new_live);
    steady(&f, layout, o);
}

#[cfg(not(feature = "bench-allocations"))]
#[path = "support/layout_policy.rs"]
mod layout_policy;

#[cfg(not(feature = "bench-allocations"))]
fn concurrent_replacement(f: &Fixture, layout: Layout, o: &Options) {
    let old = f.state.active();
    let weak = Arc::downgrade(&old);
    f.state.publish_health(replacement_health(f, layout));
    let updates: Vec<_> = (0..o.writes)
        .map(|index| {
            request(
                layout,
                layout.targets - 1,
                index as u64 + 2,
                (index + 1) % 2,
            )
        })
        .collect();
    let barrier = Barrier::new(5);
    let done = AtomicBool::new(false);
    let (windows, observations, workload) = std::thread::scope(|scope| {
        use layout_policy::{Interval, StopOnDrop, collect_until_done};
        let stop_on_error = StopOnDrop(&done);
        let mut handles = Vec::with_capacity(4);
        for _ in 0..4 {
            let barrier = &barrier;
            let done = &done;
            handles.push(scope.spawn(move || {
                let trace = layout_policy::Trace::with_capacity(o.samples * 8);
                for _ in 0..128 { decision(f); }
                let active_start = Instant::now();
                barrier.wait();
                barrier.wait();
                let trace = collect_until_done(done, trace, || {
                    let start = Instant::now();
                    let limits = black_box(f.state.limits_for(black_box(&f.host), black_box(&f.path)));
                    let backend = black_box(f.state.resolve_backend(black_box(&f.host), black_box(&f.path), black_box("GET")));
                    let end = Instant::now();
                    // Independent public reads can span different generations. Do NOT assert a
                    // transactional pair; each result must be a complete valid old or new result.
                    let limits = limits.expect("no limits gap during replacement");
                    assert!([64 * 1024, 96 * 1024].contains(&limits.max_header_bytes));
                    assert_eq!(limits.retry_methods, ["GET", "HEAD"]);
                    match backend {
                        RouteLookup::Backend(endpoint) => assert!(
                            [address(layout, layout.targets - 1, layout.routes - 1, 0), address(layout, layout.targets - 1, layout.routes - 1, 1)].contains(&endpoint)
                        ),
                        other => panic!("replacement reader must never lose/falsely deny/ambiguously route: {other:?}"),
                    }
                    Interval { start, end }
                });
                (trace, Interval { start: active_start, end: Instant::now() })
            }));
        }
        let mut windows = Vec::with_capacity(o.writes);
        barrier.wait();
        barrier.wait();
        let wall = Instant::now();
        for update in updates {
            let start = Instant::now();
            let outcome = f.state.apply(black_box(update));
            let end = Instant::now();
            accepted(outcome);
            windows.push(Interval { start, end });
        }
        let workload = Interval {
            start: wall,
            end: Instant::now(),
        };
        drop(stop_on_error);
        let observations: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("reader failed"))
            .collect();
        (windows, observations, workload)
    });
    assert!(!Arc::ptr_eq(&old, &f.state.active()));
    assert!(weak.upgrade().is_some());
    let observed = f.state.inspect_for(Some(identity(layout.targets - 1)));
    assert_eq!(observed.generation, o.writes as u64 + 1);
    validate(f, layout, o.writes % 2);
    if layout.targets > 1 {
        assert_eq!(
            f.state
                .resolve_backend(&hostname(layout, 0, 0), &(path(0, 0) + "request"), "GET"),
            RouteLookup::Backend(address(layout, 0, 0, 0)),
            "untouched neighbor must keep serving"
        );
    }
    let evidence: Vec<_> = observations
        .iter()
        .map(|(trace, worker)| layout_policy::summarize(trace, *worker, workload, &windows))
        .collect();
    let traces: Vec<_> = observations.iter().map(|(trace, _)| trace).collect();
    let union = layout_policy::union_covered_writes(&traces, &windows);
    let adequate = layout_policy::pooled_eligible(&evidence, union, o.writes);
    let mut cohort = Vec::new();
    let mut straddlers = 0;
    for (reader, ((trace, _), evidence)) in observations.iter().zip(&evidence).enumerate() {
        concurrent_row(ConcurrentRow {
            context: RowContext {
                id: layout.id,
                phase: "reader-workload-coverage",
                operations: evidence.latency.len(),
                readers: 1,
            },
            samples: &evidence.latency,
            cohort: evidence.latency.len(),
            writes: o.writes,
            reader: Some(reader),
            decisions: trace.decisions,
            stored: trace.samples.len(),
            truncated: trace.truncated,
            straddlers: evidence.straddlers,
            covered_writes: evidence.covered_writes,
            full_worker_lifetime: evidence.full_worker_lifetime,
            eligible: evidence.eligible,
            capacity: trace.capacity,
            union_covered_writes: None,
        });
        eprintln!(
            "layout={} reader={reader} decisions={} stored={} cohort={} truncated={} straddlers={} covered_writes={}/{} full_worker_lifetime={} p99_eligible={} sample_capacity={} capacity_reached={}",
            layout.id,
            trace.decisions,
            trace.samples.len(),
            evidence.latency.len(),
            trace.truncated,
            evidence.straddlers,
            evidence.covered_writes,
            o.writes,
            evidence.full_worker_lifetime,
            evidence.eligible,
            trace.capacity,
            trace.samples.len() == trace.capacity
        );
        straddlers += evidence.straddlers;
        cohort.extend(evidence.latency.iter().copied());
    }
    eprintln!(
        "layout={} union_covered_writes={union}/{} p99_eligible={adequate}",
        layout.id, o.writes
    );
    cohort.sort_unstable();
    concurrent_row(ConcurrentRow {
        context: RowContext {
            id: layout.id,
            phase: "decision-4readers-writer-workload-latency",
            operations: cohort.len(),
            readers: 4,
        },
        samples: &cohort,
        cohort: cohort.len(),
        writes: o.writes,
        reader: None,
        decisions: observations.iter().map(|(trace, _)| trace.decisions).sum(),
        stored: observations
            .iter()
            .map(|(trace, _)| trace.samples.len())
            .sum(),
        truncated: observations.iter().map(|(trace, _)| trace.truncated).sum(),
        straddlers,
        covered_writes: evidence.iter().map(|reader| reader.covered_writes).sum(),
        full_worker_lifetime: observations
            .iter()
            .all(|(_, worker)| worker.start <= workload.start && worker.end >= workload.end),
        eligible: adequate,
        capacity: observations.iter().map(|(trace, _)| trace.capacity).sum(),
        union_covered_writes: Some(union),
    });
    assert!(
        adequate,
        "inadequate concurrent evidence for {}: each reader needs >= {} full-cohort samples, >0 publication intersections, full worker lifetime, and storage capacity not reached (zero truncated decisions); the observed reader union must cover every apply interval; concurrent p99 withheld (see reader-workload-coverage rows)",
        layout.id,
        layout_policy::MIN_READER_SAMPLES
    );
    let mut writer_ns: Vec<_> = windows
        .iter()
        .map(|window| window.end.duration_since(window.start).as_nanos() as u64)
        .collect();
    writer_ns.sort_unstable();
    timing_row(TimingRow {
        context: RowContext {
            id: layout.id,
            phase: "replacement-control-throughput",
            operations: o.writes,
            readers: 4,
        },
        cycle: 0,
        elapsed: workload.end.duration_since(workload.start).as_nanos(),
        samples: &writer_ns,
        cohort: cohort.len(),
        writes: o.writes,
    });
    let (_, release) = measure(|| {
        drop(old);
        assert!(weak.upgrade().is_none());
        drop(weak);
    });
    measurement_row(layout.id, "release-retained-old", 1, 0, release);
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as i64
}

fn lifecycle(o: &Options) {
    for cycle in 1..=o.cycles {
        let directory = tempfile::tempdir().expect("private bounded state directory");
        let store = StateStore::new(directory.path().join("gateway.state"));
        let state = GatewayState::from_store(store.clone()).expect("empty durable state");
        let initial = request(SMALL, 0, 1, 0);
        let stale = initial.clone();
        let (outcome, cold) = measure(|| state.apply(initial));
        accepted(outcome);
        publish_health(&state);
        let host = hostname(SMALL, 0, 0);
        let query = path(0, 0) + "request";
        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::Backend(address(SMALL, 0, 0, 0))
        );
        measurement_row("lifecycle", "cold-durable-apply", 1, cycle, cold);

        // A newer independently signed configuration supplies the authority hash for withdrawal.
        let fence = request(SMALL, 0, 2, 0);
        let withdraw = WithdrawConfigurationRequest {
            operation: fence.operation,
            identity: fence.identity,
            withdrawn_generation: 2,
        };
        let (outcome, withdrawal) = measure(|| state.withdraw(withdraw));
        accepted(outcome);
        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );
        assert!(state.inspect_for(Some(identity(0))).withdrawn);
        measurement_row("lifecycle", "durable-withdraw", 1, cycle, withdrawal);
        drop(state);
        let (recovered, recovery) = measure(|| GatewayState::from_store(store.clone()));
        let state = recovered.expect("withdrawal recovery");
        assert_eq!(state.inspect_for(Some(identity(0))).generation, 2);
        assert!(state.inspect_for(Some(identity(0))).withdrawn);
        assert!(matches!(
            state.apply(stale.clone()),
            CommandOutcome::Rejected(AdmissionError::StaleGeneration)
        ));
        measurement_row(
            "lifecycle",
            "recover-withdrawal-tombstone",
            1,
            cycle,
            recovery,
        );

        let next = request(SMALL, 0, 3, 0);
        let operation = next.operation.clone();
        accepted(state.apply(next));
        publish_health(&state);
        let until = unix_ms() + 100;
        let drain = DrainConfigurationRequest {
            operation,
            identity: Some(identity(0)),
            drain_generation: 3,
            drain_until_unix_ms: until,
        };
        let (outcome, draining) = measure(|| state.drain(drain));
        accepted(outcome);
        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );
        assert!(
            state
                .inspect_for(Some(identity(0)))
                .serving_route_ids
                .is_empty()
        );
        measurement_row("lifecycle", "durable-drain", 1, cycle, draining);
        drop(state);
        let (recovered, recovery) = measure(|| GatewayState::from_store(store.clone()));
        let state = recovered.expect("drain recovery");
        assert!(!state.inspect_for(Some(identity(0))).withdrawn);
        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );
        measurement_row("lifecycle", "recover-draining-active", 1, cycle, recovery);
        // Real clock/public expiry, not a fake clock or injected persisted drain. Sleep is never timed.
        let remaining = until.saturating_sub(unix_ms()).max(0) as u64;
        assert!(
            remaining <= 100,
            "clock moved backwards; refusing unbounded wait"
        );
        std::thread::sleep(Duration::from_millis(remaining + 2));
        let (retired, retirement) = measure(|| state.retire_expired_drains());
        assert!(retired, "expired admitted drain must actually retire");
        assert!(state.inspect_for(Some(identity(0))).withdrawn);
        assert_eq!(
            state.resolve_backend(&host, &query, "GET"),
            RouteLookup::NotFound
        );
        assert!(
            !state.retire_expired_drains(),
            "second retirement is a no-op"
        );
        measurement_row(
            "lifecycle",
            "durable-expired-drain-retirement",
            1,
            cycle,
            retirement,
        );
        drop(state);
        let (recovered, recovery) = measure(|| GatewayState::from_store(store.clone()));
        let state = recovered.expect("retirement recovery");
        assert!(state.inspect_for(Some(identity(0))).withdrawn);
        assert_eq!(state.inspect_for(Some(identity(0))).generation, 3);
        assert!(matches!(
            state.apply(stale),
            CommandOutcome::Rejected(AdmissionError::StaleGeneration)
        ));
        measurement_row(
            "lifecycle",
            "recover-retirement-tombstone",
            1,
            cycle,
            recovery,
        );
    }
}

fn main() {
    let o = options();
    eprintln!(
        "layouts schema=3 allocator={} iterations={} samples={} writes={} cycles={} public-api=true signing=Prost/SHA256 network=none",
        if cfg!(feature = "bench-allocations") {
            "stats_alloc-0.1.10-counting-only"
        } else {
            "default-System-uninstrumented"
        },
        o.iterations,
        o.samples,
        o.writes,
        o.cycles
    );
    #[cfg(feature = "bench-allocations")]
    println!(
        "workload,phase,operations,cycle,allocations,deallocations,reallocations,bytes_allocated,bytes_deallocated,bytes_reallocated,live_requested_bytes"
    );
    #[cfg(not(feature = "bench-allocations"))]
    {
        println!(
            "workload,phase,operations,cycle,readers,elapsed_ns,ns_per_op,ops_per_second,p50_ns,p95_ns,p99_ns,cohort_samples,writer_operations,reader_id,reader_decisions,stored_samples,truncated_decisions,straddling_samples,covered_writer_ops,full_worker_lifetime,p99_eligible,sample_capacity,union_covered_writer_ops"
        );
        let mut samples = Vec::with_capacity(o.samples);
        for _ in 0..o.samples {
            let start = Instant::now();
            black_box(0u64);
            samples.push(start.elapsed().as_nanos() as u64);
        }
        let elapsed = samples.iter().map(|ns| u128::from(*ns)).sum();
        samples.sort_unstable();
        timing_row(TimingRow {
            context: RowContext {
                id: "timer-control",
                phase: "latency",
                operations: samples.len(),
                readers: 1,
            },
            cycle: 0,
            elapsed,
            samples: &samples,
            cohort: 0,
            writes: 0,
        });
    }
    semantic_controls();
    for layout in LAYOUTS {
        if o.case != "all" && o.case != layout.id {
            continue;
        }
        #[cfg(feature = "bench-allocations")]
        allocation_layout(layout, &o);
        #[cfg(not(feature = "bench-allocations"))]
        {
            let (f, setup) = measure(|| fixture(layout));
            measurement_row(layout.id, "setup-including-validation", 1, 0, setup);
            steady(&f, layout, &o);
            concurrent_replacement(&f, layout, &o);
        }
        eprintln!(
            "validated layout={} targets={} routes_per_target={} backends_per_route=1",
            layout.id, layout.targets, layout.routes
        );
    }
    if o.case == "all" || o.case == "lifecycle" {
        lifecycle(&o);
    }
    eprintln!(
        "completed; omissions=certificate-file-GC,TLS,network,production-capacity; allocation-concurrency=excluded"
    );
}
