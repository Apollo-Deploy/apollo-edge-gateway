#![forbid(unsafe_code)]

#[path = "../benches/support/layout_policy.rs"]
mod layout_policy;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use layout_policy::*;

fn interval(origin: Instant, start: u64, end: u64) -> Interval {
    Interval {
        start: origin + Duration::from_nanos(start),
        end: origin + Duration::from_nanos(end),
    }
}

#[test]
fn full_cohort_retains_left_right_and_whole_series_straddlers_unclipped() {
    let origin = Instant::now();
    let workload = interval(origin, 100, 200);
    let trace = Trace {
        samples: vec![
            interval(origin, 50, 100), // touches only, outside the half-open cohort
            interval(origin, 75, 125),
            interval(origin, 120, 130),
            interval(origin, 175, 225),
            interval(origin, 50, 250),
            interval(origin, 200, 250),
        ],
        decisions: 6,
        truncated: 0,
        capacity: 64,
    };
    let evidence = summarize(
        &trace,
        interval(origin, 0, 300),
        workload,
        &[interval(origin, 110, 115), interval(origin, 185, 190)],
    );
    assert_eq!(evidence.latency, [50, 10, 50, 200]);
    assert_eq!(evidence.straddlers, 3);
    assert_eq!(evidence.covered_writes, 2);
    assert!(
        !evidence.eligible,
        "four samples cannot certify concurrent p99"
    );
}

#[test]
fn an_early_storage_cap_does_not_stop_real_operations_and_cannot_certify_p99() {
    let done = AtomicBool::new(false);
    let origin = Instant::now();
    let mut calls = 0;
    let trace = collect_until_done(&done, Trace::with_capacity(2), || {
        calls += 1;
        if calls == 30 {
            done.store(true, Ordering::Release);
        }
        interval(origin, calls, calls + 1)
    });
    assert_eq!(
        calls, 30,
        "reader must continue until writer completion, not its sample cap"
    );
    assert_eq!(trace.decisions, 30);
    assert_eq!(trace.samples.len(), 2);
    assert_eq!(trace.truncated, 28);
    let evidence = summarize(
        &trace,
        interval(origin, 0, 40),
        interval(origin, 0, 35),
        &[interval(origin, 1, 31)],
    );
    assert!(!evidence.eligible);
}

#[test]
fn exactly_filling_the_capacity_also_withholds_p99() {
    let origin = Instant::now();
    let done = AtomicBool::new(false);
    let mut calls = 0;
    let trace = collect_until_done(&done, Trace::with_capacity(25), || {
        calls += 1;
        if calls == 25 {
            done.store(true, Ordering::Release);
        }
        interval(origin, calls, calls + 1)
    });
    assert_eq!(trace.truncated, 0);
    assert_eq!(trace.samples.len(), 25);
    assert!(
        !summarize(
            &trace,
            interval(origin, 0, 40),
            interval(origin, 0, 35),
            &[interval(origin, 1, 31)]
        )
        .eligible
    );
}

fn coverage_trace(origin: Instant, hits_second_write: bool) -> Trace {
    let starts: Vec<_> = if hits_second_write {
        (10..25).chain(70..85).collect()
    } else {
        (10..40).collect()
    };
    Trace {
        samples: starts
            .into_iter()
            .map(|n| interval(origin, n, n + 1))
            .collect(),
        decisions: 30,
        truncated: 0,
        capacity: 64,
    }
}

#[test]
fn one_reader_can_miss_a_write_when_the_observed_union_covers_the_series() {
    let origin = Instant::now();
    let workload = interval(origin, 10, 100);
    let writes = [interval(origin, 15, 20), interval(origin, 70, 80)];
    let traces: Vec<_> = (0..4)
        .map(|reader| coverage_trace(origin, reader != 0))
        .collect();
    let evidence: Vec<_> = traces
        .iter()
        .map(|trace| summarize(trace, interval(origin, 0, 110), workload, &writes))
        .collect();
    assert_eq!(evidence[0].covered_writes, 1);
    assert!(evidence[0].full_worker_lifetime);
    assert!(
        evidence[1..]
            .iter()
            .all(|reader| reader.covered_writes == 2)
    );
    let union = union_covered_writes(&traces.iter().collect::<Vec<_>>(), &writes);
    assert_eq!(union, 2);
    assert!(pooled_eligible(&evidence, union, writes.len()));
}

#[test]
fn all_readers_missing_the_same_write_rejects_even_with_a_large_coverage_sum() {
    let origin = Instant::now();
    let workload = interval(origin, 10, 100);
    let writes = [interval(origin, 15, 20), interval(origin, 70, 80)];
    let traces: Vec<_> = (0..4).map(|_| coverage_trace(origin, false)).collect();
    let evidence: Vec<_> = traces
        .iter()
        .map(|trace| summarize(trace, interval(origin, 0, 110), workload, &writes))
        .collect();
    assert!(evidence.iter().all(|reader| reader.eligible));
    assert_eq!(
        evidence
            .iter()
            .map(|reader| reader.covered_writes)
            .sum::<usize>(),
        4
    );
    let union = union_covered_writes(&traces.iter().collect::<Vec<_>>(), &writes);
    assert_eq!(union, 1);
    assert!(!pooled_eligible(&evidence, union, writes.len()));
}

#[test]
fn writer_unwind_releases_readers_instead_of_leaving_the_loop_running() {
    let done = AtomicBool::new(false);
    let result = std::panic::catch_unwind(|| {
        let _stop = StopOnDrop(&done);
        panic!("synthetic writer failure");
    });
    assert!(result.is_err());
    assert!(done.load(Ordering::Acquire));
}

#[test]
fn uncapped_counts_do_not_hide_zero_publication_intersections_or_early_exit() {
    let origin = Instant::now();
    let workload = interval(origin, 10, 100);
    let trace = Trace {
        samples: (10..40).map(|n| interval(origin, n, n + 1)).collect(),
        decisions: 30,
        truncated: 0,
        capacity: 64,
    };
    let writes = [interval(origin, 15, 20), interval(origin, 70, 80)];
    let partial = summarize(&trace, interval(origin, 0, 110), workload, &writes);
    assert!(partial.eligible);
    assert_eq!(partial.covered_writes, 1);
    assert!(!summarize(&trace, interval(origin, 0, 50), workload, &writes[..1]).eligible);
    assert!(!summarize(&trace, interval(origin, 0, 110), workload, &writes[1..]).eligible);
}
