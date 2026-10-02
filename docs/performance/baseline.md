# Performance baseline

These measurements cover synchronous gateway routing decisions, not complete HTTP
requests. They establish the historical reference for the retained optimizations
in [optimization-results.md](optimization-results.md).

## Measurement scope and provenance

The primary operation, `decision`, calls `limits_for` followed by GET
`resolve_backend`. Other cases measure GET/HEAD resolution, limits, TLS metadata
binding, misses, method denial, and four-reader decisions. Fixtures exercise real
signed-configuration admission and publish health using the gateway's health keys.
TLS binding means metadata lookup, not certificate loading or a handshake.

The original source, comparison binaries, and raw measurements are archived in the
originating deployment repository. They are **not included in the standalone
checkout**. The historical original-to-retained delta cannot be reproduced from
this checkout alone. Use the [benchmark guide](../../benches/README.md) for Cargo
commands that measure the current source and establish a new local baseline.

## Environment and method

- ARM64 Apple M1 Pro, 32 GiB RAM, macOS; Rust 1.88.
- System allocator, thin LTO, and stripping retained; no native-CPU tuning.
- Three interleaved original/retained primary repetitions; two supplemental
  repetitions. The table below uses the original side of the primary comparison,
  not a mixture of earlier exploratory runs.
- Primary timing: 2,000 warmup calls, 100,000 batched operations, and 10,000
  separately timestamped observations per single-reader case.
- Four-reader timing: 10,000 observations per reader. Aggregate throughput is not
  per-reader latency; primary cases have no concurrent writer or health update.
- Allocation counting uses a separate instrumented executable. Its timing is not
  used for performance comparisons. Owned outputs are dropped within each region.

Batched times are medians across the three repetitions. Reported primary latency
percentiles are medians of per-run percentiles, not pooled percentiles. Timestamp
cost and clock quantization matter at submicrosecond scale; 10,000 observations
leave only about ten above p99.9. Scheduling, power, and thermal state were not
controlled sufficiently to support universal latency guarantees.

## Historical original decision cost

Hits select the last target and last route, deliberately exposing late-hit scans.
All shapes use one target and one route unless otherwise specified.

| Shape | Targets | Routes per target | Backends per route | Batch µs/op | Allocations / requested bytes per decision |
| --- | ---: | ---: | ---: | ---: | ---: |
| Small, healthy | 1 | 1 | 1 | 0.308509 | 4 / 99 |
| Fleet, healthy | 128 | 8 | 4 | 9.293974 | 4 / 99 |
| Wide, healthy | 1 | 1 | 256 | 0.446879 | 4 / 99 |
| Wide, all unhealthy | 1 | 1 | 256 | 71.953737 | 259 / 11,319 |

The fleet's original p99 was 10.084 µs and p99.9 was 24.542 µs. Original healthy
GET/HEAD resolution allocated once for 44 requested bytes; all-unhealthy wide
resolution allocated 256 times for 11,264 bytes. Misses and method denials
allocated zero times. See the [hot-path analysis](hot-path.md) for the cost sources.

## Interpretation boundaries

There are no sockets, HTTP parsing, TLS handshakes, body forwarding, or database
requests in these decision measurements. The serving path already performs zero
database requests; there is no database round-trip reduction to claim.

Allocation counters measure Rust allocator requests, not native TLS allocations,
allocator metadata, fragmentation, or physical memory. Setup-live requested heap
and whole-process CPU/RSS have different scopes; their comparisons are labeled
separately in [the results](optimization-results.md).

Native Linux HTTPS/load, syscall, native allocator/heap, runtime, and crash-soak
qualification remain unverified. These measurements are not production capacity
or an SLA. Consult [architecture.md](architecture.md) for the implementation
boundaries and [optimization-plan.md](optimization-plan.md) for the completed
decisions and practical next measurement ceiling.
