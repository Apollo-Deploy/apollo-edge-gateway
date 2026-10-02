# Optimization decisions and next ceiling

The measured decision-path optimization is complete. This document records what
was retained, what was reverted, and what evidence would justify further work.
It is not a pending implementation or security-review plan. See
[optimization-results.md](optimization-results.md) for the measurements and
[architecture.md](architecture.md) for the resulting design.

## Completed decisions

| Change | Decision | Reason and cost |
| --- | --- | --- |
| A: exact-host index and short ArcSwap guards | Retained | Removes fleet-wide hostname scans; entries/index publish together. Rebuilding the index adds cold publication work. |
| B: borrowed Pingora RoundRobin and one local health view | Retained | Removes per-attempt selection allocations and unused wrapper state without changing the retry loop, cursor, or effective uniform membership. |
| S: collision-free scoped health keys | Retained | Prevents embedded-NUL identities from sharing health. A correctness correction, not a performance claim. |
| C/D: binary and hybrid address lookup | Reverted | Wide single-reader gains did not justify small-route and concurrent regressions. Original-order linear lookup remains. |

The retained primary fleet decision improved from 9.293974 to 0.419671 µs/op
(22.15×). Warm resolution became allocation-free in the measured fixtures. These
results justify a read-mostly design, not a universal improvement: supplemental
distinct-host, long-host, and shared-host publication became 2.03×, 4.23×, and
3.91× slower respectively. Shared-host routing gained little, and the 1,024-route
single-target decision regressed 2.13%. All adverse layout rows remain in
[the results](optimization-results.md).

## Non-negotiable behavior

- Preserve exact-host matching, literal longest-prefix paths, method policy,
  eligible-target ambiguity, and deterministic target/route precedence.
- Check expiry and drain status at lookup time; do not turn an index into an
  authority cache or publish it separately from its entries.
- Preserve raw attempt bounds, duplicate-address first-key precedence, stateful
  health callbacks, shared round-robin cursor behavior, and fail-closed health.
- Keep Host/SNI/authority checks, framing, bounds, retries, concurrency admission,
  certificate validation, and required audit/error reporting.
- Persist before publication and acknowledgment. Do not change signed
  configuration, durable formats, or epoch/generation fencing to save lookup work.
- Keep health keys local and collision-free; recovery needs fresh health. Do not
  reuse a mixed old/new key map.

## Practical next measurement ceiling

1. **Measure the real serving path on native Linux.** Use representative HTTPS
   traffic, connection reuse, TLS setup, payload sizes, route distributions,
   partial health, and update rates. Report throughput, sampled tails, errors,
   concurrency, and CPU with enough context to distinguish decision work from
   parsing, TLS, upstream I/O, and scheduling.
2. **Profile before redesigning ownership.** Determine whether repeated host
   normalization, limits-output cloning, certificate work, or framework allocation
   is material. A microbenchmark does not justify caching certificate material or
   authority across callbacks. See [hot-path.md](hot-path.md).
3. **Revisit remaining scans only with workload evidence.** Shared-host/path-heavy
   layouts and wide all-unhealthy backend sets expose the remaining ceiling.
   Any alternative must preserve ordering and selector semantics and improve small
   and concurrent cases as well as the favorable wide case.
4. **Measure update and memory overlap.** Include publication under readers,
   retained old snapshots, recovery, transient setup allocations, and update
   bursts. Lower net live heap does not prove lower transient or native peak heap.

Native syscall, allocator/heap, runtime, and crash-soak measurements remain open.
No current evidence justifies io_uring, SIMD, a custom executor, kernel bypass,
allocator replacement, assembly, or unsafe implementations. The existing System
allocator, thin LTO, and stripping remain unchanged.

## Future regression reporting

Use the [benchmark guide](../../benches/README.md) to establish comparable
current-source runs. Keep timing and counting separate and report all workloads,
including misses, denials, publication, and adverse layouts. Preserve environment,
repetition counts, sample counts, and workload shapes with each result.

The measured warm fixtures provide useful allocation envelopes: GET/HEAD resolve,
misses, and denials at 0 allocations / 0 bytes; limits and combined decisions at
no more than 3 / 55; TLS metadata binding at no more than 3 / 82. Report counts,
requested bytes, balanced frees, retained bytes, and reallocations together.
These are scoped measurement targets, not claims of new CI enforcement or
allocation-free HTTPS.

Timing checks should surface statistically meaningful, repeatable regressions
across shapes and reader counts, rather than enforce brittle nanosecond thresholds
on shared CI machines. A future comparison needs its own baseline; the historical
original source and raw archive are not part of this checkout. No new tests,
benchmarks, or production qualification are claimed by this documentation.
