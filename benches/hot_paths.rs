//! Public GatewayState microbenchmarks. See README.md beside this file.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Barrier;
use std::time::Instant;

use apollo_edge_gateway::GatewayState;
use apollo_edge_gateway::control::WorkloadEndpoint;
use apollo_edge_gateway::control::{
    ApplyConfigurationRequest, BackendHealthRequirement, CommandOutcome, EdgeBackend,
    EdgeConfiguration, EdgeProtocol, EdgeRoute, EdgeTlsBinding, NetworkScope, OperationIdentity,
    ProductIdentity, RouteLookup,
};
use prost::Message;
use sha2::{Digest, Sha256};

// This attribute exists ONLY in this benchmark executable, never in the library or gateway.
// Without the feature there is no allocator override: Rust uses its default System allocator.
#[cfg(feature = "bench-allocations")]
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[derive(Clone, Copy)]
struct Shape {
    id: &'static str,
    targets: usize,
    routes: usize,
    backends: usize,
    healthy: bool,
}

const SHAPES: [Shape; 4] = [
    Shape {
        id: "small",
        targets: 1,
        routes: 1,
        backends: 1,
        healthy: true,
    },
    Shape {
        id: "fleet",
        targets: 128,
        routes: 8,
        backends: 4,
        healthy: true,
    },
    Shape {
        id: "wide-healthy",
        targets: 1,
        routes: 1,
        backends: 256,
        healthy: true,
    },
    Shape {
        id: "wide-unhealthy",
        targets: 1,
        routes: 1,
        backends: 256,
        healthy: false,
    },
];

#[derive(Clone, Copy)]
enum Op {
    Limits,
    ResolveGet,
    ResolveHead,
    Decision,
    Binding,
    HostMiss,
    PathMiss,
    Denied,
    LimitsMiss,
    BindingMiss,
}

impl Op {
    fn id(self) -> &'static str {
        match self {
            Self::Limits => "limits",
            Self::ResolveGet => "resolve-get",
            Self::ResolveHead => "resolve-head",
            Self::Decision => "decision",
            Self::Binding => "binding",
            Self::HostMiss => "host-miss",
            Self::PathMiss => "path-miss",
            Self::Denied => "method-denied",
            Self::LimitsMiss => "limits-miss",
            Self::BindingMiss => "binding-miss",
        }
    }
}
const OPS: [Op; 10] = [
    Op::Limits,
    Op::ResolveGet,
    Op::ResolveHead,
    Op::Decision,
    Op::Binding,
    Op::HostMiss,
    Op::PathMiss,
    Op::Denied,
    Op::LimitsMiss,
    Op::BindingMiss,
];

struct Fixture {
    state: GatewayState,
    host: String,
    path: String,
}

fn build_fixture(shape: Shape) -> Fixture {
    let state = GatewayState::empty();
    for target in 0..shape.targets {
        let identity = ProductIdentity {
            organization_id: "org".into(),
            project_id: "project".into(),
            service_id: format!("service-{target:03}"),
            deployment_id: format!("deployment-{target:03}"),
            release_id: format!("release-{target:03}"),
            route_id: format!("route-{target:03}"),
            traffic_target_id: format!("target-{target:03}"),
        };
        let routes = (0..shape.routes)
            .map(|route| {
                let hostname = format!("target-{target:03}.bench.example");
                let backends = (0..shape.backends)
                    .map(|backend| {
                        let index = (target * shape.routes + route) * shape.backends + backend;
                        EdgeBackend {
                            endpoint: Some(WorkloadEndpoint {
                                workload_id: format!("workload-{index:05}"),
                                workload_generation: index as u64 + 1,
                                node_id: "node".into(),
                                region_id: "region".into(),
                                cell_id: "cell".into(),
                                address: "10.23.0.1".into(),
                                port: 10_000 + index as u32,
                                protocol: EdgeProtocol::Http1 as i32,
                                network_scope: NetworkScope::CellPrivate as i32,
                                observed_at_unix_ms: 1,
                                ready: true,
                                healthy: true,
                            }),
                            health_requirement: BackendHealthRequirement::ReadyAndHealthy as i32,
                            weight: 1,
                            draining: false,
                        }
                    })
                    .collect();
                EdgeRoute {
                    identity: Some(ProductIdentity {
                        route_id: format!("route-{target:03}-{route:02}"),
                        ..identity.clone()
                    }),
                    hostname: hostname.clone(),
                    path_match: format!("/route-{route:02}/"),
                    methods: vec!["GET".into(), "HEAD".into()],
                    protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
                    backends,
                    tls: Some(EdgeTlsBinding {
                        certificate_id: "cert".into(),
                        certificate_version: 1,
                        hostname,
                        material_reference: "org/project/cert/1".into(),
                        public_certificate_hash: vec![0x31; 32],
                        certificate_chain_hash: vec![0x52; 32],
                    }),
                    route_generation: route as u64 + 1,
                }
            })
            .collect();
        let mut configuration = EdgeConfiguration {
            identity: Some(identity.clone()),
            controller_epoch: 1,
            generation: 1,
            configuration_hash: Vec::new(),
            issued_at_unix_ms: 1,
            valid_until_unix_ms: i64::MAX,
            routes,
            max_header_bytes: 64 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            max_connections: 1024,
            max_concurrency: 1024,
            drain_timeout_seconds: 60,
            retry_max_attempts: 2,
            retry_methods: vec!["GET".into(), "HEAD".into()],
            semantic_hash: vec![0x73; 32],
        };
        // Independent Prost encoding/SHA256 signing, not a production/test fixture helper.
        configuration.configuration_hash = Sha256::digest(configuration.encode_to_vec()).to_vec();
        let operation = OperationIdentity {
            operation_id: format!("operation-{target:03}"),
            effect_id: format!("effect-{target:03}"),
            controller_epoch: 1,
            generation: 1,
            configuration_hash: configuration.configuration_hash.clone(),
        };
        let outcome = state.apply(ApplyConfigurationRequest {
            operation: Some(operation),
            identity: Some(identity),
            configuration: Some(configuration),
        });
        assert!(
            matches!(outcome, CommandOutcome::Accepted),
            "{} target {target}: {outcome:?}",
            shape.id
        );
    }
    let health = state.health_targets();
    assert_eq!(health.len(), shape.targets * shape.routes * shape.backends);
    let keys: BTreeSet<_> = health.iter().map(|target| &target.key).collect();
    let addresses: BTreeSet<_> = health.iter().map(|target| target.address).collect();
    assert_eq!(
        keys.len(),
        health.len(),
        "distinct target/workload/generation health keys"
    );
    assert_eq!(
        addresses.len(),
        health.len(),
        "distinct private endpoint ports"
    );
    let updates: BTreeMap<_, _> = health
        .iter()
        .map(|target| (target.key.clone(), shape.healthy))
        .collect();
    state.publish_health(updates);
    let fixture = Fixture {
        state,
        host: format!("target-{:03}.bench.example", shape.targets - 1),
        path: format!("/route-{:02}/request", shape.routes - 1),
    };
    validate_fixture(&fixture, shape);
    fixture
}

fn validate_fixture(f: &Fixture, shape: Shape) {
    let limits = f
        .state
        .limits_for(&f.host, &f.path)
        .expect("exact target limits");
    assert_eq!(limits.max_header_bytes, 64 * 1024);
    assert_eq!(limits.max_body_bytes, 64 * 1024 * 1024);
    assert_eq!(limits.max_concurrency, 1024);
    assert_eq!(limits.retry_max_attempts, 2);
    assert_eq!(limits.retry_methods, ["GET", "HEAD"]);
    // The final target and final route make scans deterministic, rather than matching target zero.
    let first_index = (shape.targets * shape.routes - 1) * shape.backends;
    let mut observed = BTreeSet::new();
    for method in ["GET", "HEAD"] {
        for _ in 0..shape.backends {
            match f.state.resolve_backend(&f.host, &f.path, method) {
                RouteLookup::Backend(address) if shape.healthy => {
                    assert_eq!(address.ip(), Ipv4Addr::new(10, 23, 0, 1));
                    assert!(
                        (10_000 + first_index..10_000 + first_index + shape.backends)
                            .contains(&(address.port() as usize))
                    );
                    observed.insert(address);
                }
                RouteLookup::Unavailable if !shape.healthy => {}
                result => panic!("{} exact target {method}: {result:?}", shape.id),
            }
        }
    }
    if shape.healthy {
        assert_eq!(
            observed.len(),
            shape.backends,
            "all exact-route endpoints selectable"
        );
    }
    assert_eq!(
        f.state
            .resolve_backend("missing.bench.example", &f.path, "GET"),
        RouteLookup::NotFound
    );
    assert_eq!(
        f.state.resolve_backend(&f.host, "/missing", "GET"),
        RouteLookup::NotFound
    );
    assert_eq!(
        f.state.resolve_backend(&f.host, &f.path, "POST"),
        RouteLookup::MethodNotAllowed
    );
    assert!(
        f.state
            .limits_for("missing.bench.example", &f.path)
            .is_none()
    );
    assert!(
        f.state
            .certificate_binding_for_host("missing.bench.example")
            .is_none()
    );
    assert_eq!(
        f.state.certificate_binding_for_host(&f.host),
        Some(("org/project/cert/1".into(), vec![0x31; 32], vec![0x52; 32]))
    );
}

#[inline]
fn exercise(f: &Fixture, op: Op) {
    let state = black_box(&f.state);
    let host = black_box(f.host.as_str());
    let path = black_box(f.path.as_str());
    match op {
        Op::Limits => drop(black_box(state.limits_for(host, path))),
        Op::ResolveGet => {
            black_box(state.resolve_backend(host, path, black_box("GET")));
        }
        Op::ResolveHead => {
            black_box(state.resolve_backend(host, path, black_box("HEAD")));
        }
        Op::Decision => {
            // Owned retry-method strings are dropped INSIDE the measured operation.
            drop(black_box(state.limits_for(host, path)));
            black_box(state.resolve_backend(host, path, black_box("GET")));
        }
        Op::Binding => drop(black_box(state.certificate_binding_for_host(host))),
        Op::HostMiss => {
            black_box(state.resolve_backend(
                black_box("missing.bench.example"),
                path,
                black_box("GET"),
            ));
        }
        Op::PathMiss => {
            black_box(state.resolve_backend(host, black_box("/missing"), black_box("GET")));
        }
        Op::Denied => {
            black_box(state.resolve_backend(host, path, black_box("POST")));
        }
        Op::LimitsMiss => drop(black_box(
            state.limits_for(black_box("missing.bench.example"), path),
        )),
        Op::BindingMiss => drop(black_box(
            state.certificate_binding_for_host(black_box("missing.bench.example")),
        )),
    }
}

struct Options {
    allocations: bool,
    case: String,
    iterations: usize,
    samples: usize,
    warmup: usize,
}

fn options() -> Options {
    let mut o = Options {
        allocations: false,
        case: "all".into(),
        iterations: 100_000,
        samples: 10_000,
        warmup: 2_000,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--latency" => o.allocations = false,
            "--allocations" => o.allocations = true,
            "--case" => o.case = args.next().expect("--case requires a workload ID or shape"),
            "--iterations" => {
                o.iterations = args
                    .next()
                    .expect("--iterations value")
                    .parse()
                    .expect("positive integer")
            }
            "--samples" => {
                o.samples = args
                    .next()
                    .expect("--samples value")
                    .parse()
                    .expect("integer >= 10000")
            }
            "--warmup" => {
                o.warmup = args
                    .next()
                    .expect("--warmup value")
                    .parse()
                    .expect("positive integer")
            }
            "--list" => {
                for shape in SHAPES {
                    for op in OPS {
                        println!("{}.{}", shape.id, op.id());
                    }
                    println!("{}.decision-4readers", shape.id);
                }
                std::process::exit(0);
            }
            "--help" => {
                println!(
                    "hot_paths [--latency|--allocations] [--case all|SHAPE|SHAPE.OP] [--iterations 100000] [--samples 10000] [--warmup 2000]\n--latency reports separate batched throughput and timestamp latency; samples must be >=10000.\n--allocations requires --features bench-allocations; only single-reader cases are counted."
                );
                std::process::exit(0);
            }
            // Cargo may append this to a harness=false benchmark invocation.
            "--bench" => {}
            _ => panic!("unknown argument {arg}; use --help"),
        }
    }
    assert!(
        o.iterations > 0 && o.warmup > 0 && o.samples >= 10_000,
        "positive iterations/warmup and at least 10000 samples required"
    );
    assert_eq!(
        o.allocations,
        cfg!(feature = "bench-allocations"),
        "separate executables required: uninstrumented --latency; bench-allocations --allocations ONLY"
    );
    o
}

fn selected(o: &Options, shape: Shape, operation: &str) -> bool {
    o.case == "all" || o.case == shape.id || o.case == format!("{}.{}", shape.id, operation)
}

fn warmup(f: &Fixture, op: Op, n: usize) {
    for _ in 0..n {
        exercise(f, op);
    }
}

fn throughput(id: &str, f: &Fixture, op: Op, n: usize) {
    let start = Instant::now();
    for _ in 0..n {
        exercise(f, op);
    }
    let ns = start.elapsed().as_nanos();
    throughput_row(id, n, 1, ns);
}
fn throughput_row(id: &str, n: usize, readers: usize, ns: u128) {
    println!(
        "{id},throughput,{n},{readers},{ns},{:.3},{:.3},,,,",
        ns as f64 / n as f64,
        n as f64 * 1e9 / ns as f64
    );
}
fn latency_row(id: &str, mut samples: Vec<u64>, readers: usize) {
    samples.sort_unstable();
    let n = samples.len();
    // Nearest-rank percentiles, not interpolated values.
    let percentile = |thousandths: usize| samples[(n * thousandths).div_ceil(1000) - 1];
    let sum: u128 = samples.iter().map(|v| *v as u128).sum();
    println!(
        "{id},latency,{n},{readers},{sum},{:.3},,{},{},{},{}",
        sum as f64 / n as f64,
        percentile(500),
        percentile(950),
        percentile(990),
        percentile(999)
    );
}
fn latency(id: &str, f: &Fixture, op: Op, n: usize) {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        exercise(f, op);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    latency_row(id, samples, 1);
}

fn contention(id: &str, f: &Fixture, o: &Options) {
    let per_reader = o.iterations.div_ceil(4);
    let barrier = Barrier::new(5);
    let ns = std::thread::scope(|scope| {
        for _ in 0..4 {
            let barrier = &barrier;
            scope.spawn(move || {
                warmup(f, Op::Decision, o.warmup);
                barrier.wait();
                barrier.wait();
                for _ in 0..per_reader {
                    exercise(f, Op::Decision);
                }
                barrier.wait();
            });
        }
        // Thread creation and per-reader ArcSwap registration/warmup are outside the batch.
        barrier.wait();
        let start = Instant::now();
        barrier.wait();
        barrier.wait();
        start.elapsed().as_nanos()
    });
    throughput_row(id, per_reader * 4, 4, ns);
    let all = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let barrier = &barrier;
        for _ in 0..4 {
            handles.push(scope.spawn(move || {
                let mut samples = Vec::with_capacity(o.samples);
                warmup(f, Op::Decision, o.warmup);
                barrier.wait();
                for _ in 0..o.samples {
                    let start = Instant::now();
                    exercise(f, Op::Decision);
                    samples.push(start.elapsed().as_nanos() as u64);
                }
                samples
            }));
        }
        barrier.wait();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("reader failed"))
            .collect()
    });
    latency_row(id, all, 4);
}

#[cfg(feature = "bench-allocations")]
fn allocation_row(id: &str, measurement: &str, n: usize, stats: stats_alloc::Stats) {
    // Reallocation deltas are ALREADY included in allocated/deallocated bytes in 0.1.10.
    let live = stats.bytes_allocated as i128 - stats.bytes_deallocated as i128;
    println!(
        "{id},{measurement},{n},{},{},{},{},{},{},{live},{:.6},{:.6}",
        stats.allocations,
        stats.deallocations,
        stats.reallocations,
        stats.bytes_allocated,
        stats.bytes_deallocated,
        stats.bytes_reallocated,
        stats.allocations as f64 / n as f64,
        stats.bytes_allocated as f64 / n as f64
    );
}
#[cfg(feature = "bench-allocations")]
fn allocations(id: &str, f: &Fixture, op: Op, n: usize) {
    let region = stats_alloc::Region::new(ALLOCATOR);
    for _ in 0..n {
        exercise(f, op);
    }
    let stats = region.change();
    allocation_row(id, "operation", n, stats);
}

fn main() {
    let o = options();
    eprintln!(
        "hot_paths schema=1 mode={} iterations={} samples={} warmup={} allocator={} fixture=independently-signed public-api-only network=none database=none certificate-files=none",
        if o.allocations {
            "allocations"
        } else {
            "latency"
        },
        o.iterations,
        o.samples,
        o.warmup,
        if cfg!(feature = "bench-allocations") {
            "stats_alloc-0.1.10-SeqCst"
        } else {
            "default-System"
        }
    );
    if o.allocations {
        println!(
            "workload,measurement,iterations,allocations,deallocations,reallocations,bytes_allocated,bytes_deallocated,bytes_reallocated,live_requested_bytes,allocations_per_op,bytes_allocated_per_op"
        );
    } else {
        println!(
            "workload,measurement,iterations,readers,elapsed_ns,ns_per_op,ops_per_second,p50_ns,p95_ns,p99_ns,p999_ns"
        );
        let mut control = Vec::with_capacity(o.samples);
        for _ in 0..o.samples {
            let start = Instant::now();
            black_box(0u64);
            control.push(start.elapsed().as_nanos() as u64);
        }
        latency_row("timer-control", control, 1);
    }
    let mut cases = 0;
    for shape in SHAPES {
        let run_ops = OPS.iter().any(|op| selected(&o, shape, op.id()));
        let run_contention = !o.allocations && selected(&o, shape, "decision-4readers");
        if !run_ops && !run_contention {
            continue;
        }
        #[cfg(feature = "bench-allocations")]
        let setup = stats_alloc::Region::new(ALLOCATOR);
        let fixture = build_fixture(shape);
        #[cfg(feature = "bench-allocations")]
        allocation_row(
            shape.id,
            "setup_including_validation_live_heap",
            1,
            setup.change(),
        );
        eprintln!(
            "validated shape={} targets={} routes_per_target={} backends_per_route={} health={} exact_target=last exact_route=last retry=GET/HEAD/2 tls=org/project/cert/1 hashes=32/32",
            shape.id,
            shape.targets,
            shape.routes,
            shape.backends,
            if shape.healthy {
                "all-healthy"
            } else {
                "all-unhealthy"
            }
        );
        for op in OPS {
            if !selected(&o, shape, op.id()) {
                continue;
            }
            cases += 1;
            let id = format!("{}.{}", shape.id, op.id());
            warmup(&fixture, op, o.warmup);
            if o.allocations {
                #[cfg(feature = "bench-allocations")]
                allocations(&id, &fixture, op, o.iterations);
            } else {
                throughput(&id, &fixture, op, o.iterations);
                latency(&id, &fixture, op, o.samples);
            }
        }
        if run_contention {
            cases += 1;
            contention(&format!("{}.decision-4readers", shape.id), &fixture, &o);
        }
    }
    assert!(
        cases > 0,
        "unknown/unavailable --case {}; use --list (contention is timing-only)",
        o.case
    );
    eprintln!("completed cases={cases}");
}
