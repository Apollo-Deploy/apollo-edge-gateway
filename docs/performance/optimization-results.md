# Retained optimization results

The retained implementation combines A (exact-host indexing and short ArcSwap
guards), B (borrowed Pingora RoundRobin and one local health view), and S (a local
health-key correctness fix). Binary and hybrid address-search variants C/D were
reverted. See [architecture.md](architecture.md) and
[optimization-plan.md](optimization-plan.md) for the design and decisions.

These are historical **in-process decision microbenchmarks**, not HTTP capacity.
The original source, binaries, and raw results are archived in the originating
deployment repository and are not shipped here. The standalone checkout can
measure its current source using [the benchmark guide](../../benches/README.md),
but cannot reproduce this historical delta by itself.

## Primary decision timing

Combined `limits_for` + GET `resolve_backend`; batch medians from three interleaved
original/retained repetitions on ARM64 Apple M1 Pro, 32 GiB RAM, macOS, Rust 1.88.
System allocator, thin LTO, and stripping were unchanged. Percentiles were measured
separately and summarized as medians of per-run percentiles. Method and workload
boundaries are in [baseline.md](baseline.md).

| Shape | Original µs/op | Retained µs/op | Speedup | p99 µs, original → retained | p99.9 µs, original → retained |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 target, 1 route, 1 healthy backend | 0.308509 | 0.171297 | 1.80× | 0.417 → 0.250 | 0.500 → 0.333 |
| 128 targets, 8 routes each, 4 healthy backends per route | 9.293974 | 0.419671 | 22.15× | 10.084 → 0.542 | 24.542 → 0.666 |
| 1 target, 1 route, 256 healthy backends | 0.446879 | 0.315216 | 1.42× | 0.625 → 0.458 | 0.708 → 0.542 |
| 1 target, 1 route, 256 unhealthy backends | 71.953737 | 37.632680 | 1.91× | 87.292 → 47.875 | 150.958 → 76.875 |

Fleet batch throughput increased from approximately **107.6k to 2.3828M
decisions/sec**. This is not requests/sec or an HTTP capacity prediction.
Four-reader aggregate speedups were 2.24× (small), 16.74× (fleet), 2.13×
(wide healthy), and 1.44× (wide unhealthy). They are throughput comparisons, not
per-reader latency guarantees; the primary reader cases have no concurrent writer.

## Separate allocation counting

Counts are per warmed operation, with owned results dropped inside the counting
region. Timing does not use this instrumented executable.

| Operation | Original allocations / requested bytes | Retained allocations / requested bytes |
| --- | ---: | ---: |
| Healthy GET/HEAD resolve | 1 / 44 | 0 / 0 |
| 256-unhealthy GET/HEAD resolve | 256 / 11,264 | 0 / 0 |
| Healthy combined decision | 4 / 99 | 3 / 55 |
| 256-unhealthy combined decision | 259 / 11,319 | 3 / 55 |
| Limits | 3 / 55 | 3 / 55 |
| TLS metadata binding | 3 / 82 | 3 / 82 |
| Misses and method denials | 0 / 0 | 0 / 0 |

The 40 primary operation regions balanced allocations/frees and requested bytes,
with zero retained operation heap and zero reallocations. This does not count
native TLS allocations or prove that complete request handling allocates nothing.
No body-copy reduction was measured. See [hot-path.md](hot-path.md) for the
remaining ownership costs.

## Setup heap and whole-process resources

| Metric and scope | Original | Retained | Reduction |
| --- | ---: | ---: | ---: |
| Fleet setup-live Rust requested heap | 11,425,642 B | 5,210,434 B | 54.40% |
| Whole primary timing-process CPU | 58.89 s | 32.20 s | 45.32% |
| Whole primary timing-process peak RSS | 20,234,240 B | 12,795,904 B | 36.76% |

Setup-live heap is net Rust requested memory while the fixture is alive, including
setup validation; it is not peak heap, RSS, or allocator overhead. Its original
value comes from historical original counting, separately from interleaved timing.
CPU and peak RSS are whole-benchmark process medians, including setup, warmup,
all cases, samples, and output. They are **not CPU/request or production RSS**.

## Supplemental layouts and adverse results

These distinct supplemental measurements use two repetitions and a separately
rebuilt original. Publication includes concurrent-reader scheduling. They are not
primary latency percentiles, and publication costs varied between runs.

| Layout | Decision µs, original → retained | Publication µs, original → retained |
| --- | ---: | ---: |
| Distinct hostname per route | 9.192 → 0.341 | 161.027 → 327.413 |
| Distinct 253-byte hostnames | 21.005 → 0.777 | 83.307 → 352.344 |
| One target, 1,024 routes | 14.110 → 14.411 | 8,331.784 → 3,766.440 |
| Shared hostname, disjoint paths | 14.411 → 13.583 | 95.810 → 374.167 |

Distinct-host publication was **2.03× slower**, long-host publication **4.23×
slower**, and shared-host publication **3.91× slower**. These costs are explicitly
accepted for read-mostly, multi-host routing, not write-heavy or universally
shared-host traffic. The shared-host decision gain is limited; the single-target
1,024-route decision is **2.13% slower**, despite faster publication. Additional
lifecycle, binding, and miss regressions were also observed; uniformly faster
control operations are not claimed. Long-host gross setup allocation churn also
increased substantially, despite lower net live memory.

C/D improved some wide single-reader cases but regressed small and concurrent
cases, so neither is included in the retained results. Original address order and
linear health-key lookup remain. S prevents embedded-NUL identity health sharing;
it is retained for correctness, not presented as a speed improvement.

## Validation status and limits

Earlier checks reported **51 unit tests and 7 integration tests**, Clippy, a
release build, and startup checks passing. A later offline check was blocked by
an unavailable cached dependency, `alloc-no-stdlib` 2.0.4. Those historical checks
do not establish validation of standalone packaging; no new validation was run
for this documentation.

Native Linux HTTPS/load, per-request syscalls, native allocator/heap behavior,
runtime qualification, and crash-soak remain unverified. Miri and sanitizers were
not run. No new unsafe code was introduced by the retained changes. Clock
quantization, limited tail samples, deterministic late hits, and host scheduling
limit generalization. These results are not production qualification or an SLA.
