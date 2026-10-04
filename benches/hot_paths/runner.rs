use super::fixture::*;
#[cfg(feature = "bench-allocations")]
use crate::ALLOCATOR;
use std::hint::black_box;
use std::sync::Barrier;
use std::time::Instant;

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

pub(crate) fn run() {
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
