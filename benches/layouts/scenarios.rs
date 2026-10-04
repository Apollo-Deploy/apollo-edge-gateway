use super::fixture::*;
use super::measure::*;
#[cfg(feature = "bench-allocations")]
use crate::ALLOCATOR;
use apollo_edge_gateway::GatewayState;
#[cfg(not(feature = "bench-allocations"))]
use apollo_edge_gateway::control::RouteLookup;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
#[cfg(not(feature = "bench-allocations"))]
use std::sync::{Barrier, atomic::AtomicBool};
#[cfg(not(feature = "bench-allocations"))]
use std::time::Instant;

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
#[path = "../support/layout_policy.rs"]
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

pub(crate) fn run() {
    semantic_controls();

    let options = options();

    if options.case == "lifecycle" || options.case == "all" {
        super::lifecycle::run(&options);
    }

    for layout in LAYOUTS {
        if options.case != "all" && options.case != layout.id {
            continue;
        }

        #[cfg(feature = "bench-allocations")]
        allocation_layout(layout, &options);

        #[cfg(not(feature = "bench-allocations"))]
        {
            let fixture = fixture(layout);

            validate(&fixture, layout, 0);

            steady(&fixture, layout, &options);

            concurrent_replacement(&fixture, layout, &options);
        }
    }
}
