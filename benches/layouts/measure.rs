use super::fixture::*;
#[cfg(feature = "bench-allocations")]
use crate::ALLOCATOR;
#[cfg(not(feature = "bench-allocations"))]
use std::time::Instant;

pub(crate) struct Options {
    pub(crate) case: String,
    pub(crate) iterations: usize,
    pub(crate) samples: usize,
    pub(crate) writes: usize,
    pub(crate) cycles: usize,
}

pub(crate) fn options() -> Options {
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

pub(crate) struct Measurement {
    #[cfg(not(feature = "bench-allocations"))]
    ns: u64,
    #[cfg(feature = "bench-allocations")]
    stats: stats_alloc::Stats,
}

pub(crate) fn measure<T>(operation: impl FnOnce() -> T) -> (T, Measurement) {
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
pub(crate) fn allocation_row(
    id: &str,
    phase: &str,
    n: usize,
    cycle: usize,
    stats: stats_alloc::Stats,
) {
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

pub(crate) fn measurement_row(
    id: &str,
    phase: &str,
    n: usize,
    cycle: usize,
    measurement: Measurement,
) {
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
pub(crate) struct RowContext<'a> {
    pub(crate) id: &'a str,
    pub(crate) phase: &'a str,
    pub(crate) operations: usize,
    pub(crate) readers: usize,
}

#[cfg(not(feature = "bench-allocations"))]
pub(crate) struct TimingRow<'a> {
    pub(crate) context: RowContext<'a>,
    pub(crate) cycle: usize,
    pub(crate) elapsed: u128,
    pub(crate) samples: &'a [u64],
    pub(crate) cohort: usize,
    pub(crate) writes: usize,
}

#[cfg(not(feature = "bench-allocations"))]
pub(crate) fn timing_row(row: TimingRow<'_>) {
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
pub(crate) struct ConcurrentRow<'a> {
    pub(crate) context: RowContext<'a>,
    pub(crate) samples: &'a [u64],
    pub(crate) cohort: usize,
    pub(crate) writes: usize,
    pub(crate) reader: Option<usize>,
    pub(crate) decisions: usize,
    pub(crate) stored: usize,
    pub(crate) truncated: usize,
    pub(crate) straddlers: usize,
    pub(crate) covered_writes: usize,
    pub(crate) full_worker_lifetime: bool,
    pub(crate) eligible: bool,
    pub(crate) capacity: usize,
    pub(crate) union_covered_writes: Option<usize>,
}

#[cfg(not(feature = "bench-allocations"))]
pub(crate) fn concurrent_row(row: ConcurrentRow<'_>) {
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
