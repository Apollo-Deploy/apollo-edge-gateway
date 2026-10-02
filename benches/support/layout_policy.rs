use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MIN_READER_SAMPLES: usize = 25;

#[derive(Clone, Copy)]
pub struct Interval {
    pub start: Instant,
    pub end: Instant,
}

impl Interval {
    pub fn intersects(self, other: Self) -> bool {
        self.start < other.end && self.end > other.start
    }
}

pub struct Trace {
    pub samples: Vec<Interval>,
    pub decisions: usize,
    pub truncated: usize,
    pub capacity: usize,
}

impl Trace {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
            decisions: 0,
            truncated: 0,
            capacity,
        }
    }
}

pub fn collect_until_done(
    done: &AtomicBool,
    mut trace: Trace,
    mut operation: impl FnMut() -> Interval,
) -> Trace {
    let capacity = trace.capacity;
    let deadline = Instant::now() + Duration::from_secs(30);
    // Storage exhaustion must NEVER shorten the competing reader workload.
    while !done.load(Ordering::Acquire) {
        assert!(
            Instant::now() < deadline,
            "reader deadline exceeded before writer completion"
        );
        let sample = operation();
        trace.decisions += 1;
        if trace.samples.len() < capacity {
            trace.samples.push(sample);
        } else {
            trace.truncated += 1;
        }
    }
    trace
}

pub struct Evidence {
    pub latency: Vec<u64>,
    pub straddlers: usize,
    pub covered_writes: usize,
    pub full_worker_lifetime: bool,
    pub eligible: bool,
}

pub fn summarize(
    trace: &Trace,
    worker: Interval,
    workload: Interval,
    writes: &[Interval],
) -> Evidence {
    let cohort: Vec<_> = trace
        .samples
        .iter()
        .copied()
        .filter(|sample| sample.intersects(workload))
        .collect();
    let full_worker_lifetime = worker.start <= workload.start && worker.end >= workload.end;
    let covered_writes = writes
        .iter()
        .filter(|write| {
            trace
                .samples
                .iter()
                .any(|sample| sample.intersects(**write))
        })
        .count();
    Evidence {
        latency: cohort
            .iter()
            .map(|sample| sample.end.duration_since(sample.start).as_nanos() as u64)
            .collect(),
        straddlers: cohort
            .iter()
            .filter(|sample| sample.start < workload.start || sample.end > workload.end)
            .count(),
        covered_writes,
        full_worker_lifetime,
        eligible: trace.truncated == 0
            && trace.samples.len() < trace.capacity
            && cohort.len() >= MIN_READER_SAMPLES
            && full_worker_lifetime
            && covered_writes > 0,
    }
}

pub fn union_covered_writes(traces: &[&Trace], writes: &[Interval]) -> usize {
    writes
        .iter()
        .filter(|write| {
            traces.iter().any(|trace| {
                trace
                    .samples
                    .iter()
                    .any(|sample| sample.intersects(**write))
            })
        })
        .count()
}

pub fn pooled_eligible(evidence: &[Evidence], union: usize, writes: usize) -> bool {
    evidence.len() == 4 && evidence.iter().all(|reader| reader.eligible) && union == writes
}

pub struct StopOnDrop<'a>(pub &'a AtomicBool);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
