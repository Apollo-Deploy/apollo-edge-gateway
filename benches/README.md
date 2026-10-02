# Gateway benchmarks

Run from the standalone gateway repository root after installing the [build prerequisites](../README.md#build). Neither benchmark requires a sibling repository, a live database, real certificate files, or a deployed workload.

The harnesses exercise public gateway state/admission/routing behavior. They are **not HTTP or TLS load tests**. Keep allocation counting and latency timing in separate executables: enabling `bench-allocations` changes only the benchmark's allocator instrumentation, not the production allocator.

## Hot-path timing

List workload IDs, then measure a selected case:

```sh
cargo bench --locked --bench hot_paths -- --list
cargo bench --locked --bench hot_paths -- \
  --latency --case fleet.decision --iterations 100000 --samples 10000 --warmup 2000
```

`--case` accepts `all`, a shape, or `SHAPE.OP`. Shapes are `small`, `fleet`, `wide-healthy`, and `wide-unhealthy`. The fleet fixture contains 128 targets, 8 routes per target, and 4 backends per route; hits select the last target/route. Operations include limits, GET/HEAD resolution, combined decisions, certificate metadata, misses, method denial, and four-reader decisions. `--list` is authoritative.

Batched throughput uses one clock pair around the operation loop. Latency is a separate timestamped sample loop. At least 10,000 samples are required. Percentiles use nearest-rank ordering; very short operations include clock quantization and instrumentation overhead. Certificate binding is metadata lookup, not TLS handshake or key validation.

## Allocation counting

```sh
cargo bench --locked --bench hot_paths --features bench-allocations -- \
  --allocations --case fleet.decision --iterations 100000 --warmup 2000
```

The counting build rejects latency mode; the uninstrumented build rejects allocation mode. Allocation counters report requested Rust allocations, not native OpenSSL heap, allocator fragmentation, or RSS. Owned outputs are dropped within operation regions.

## Layout, publication, and lifecycle cases

```sh
cargo bench --locked --bench layouts -- --list
cargo bench --locked --bench layouts -- \
  --timing --case all --iterations 2000 --samples 10000 --writes 16 --cycles 4
cargo bench --locked --bench layouts --features bench-allocations -- \
  --allocations --case all --iterations 2000 --samples 10000 --writes 16 --cycles 4
```

This suite includes distinct/long/shared hosts, many routes in one target, cold publication, durable lifecycle, and concurrent readers during publication. Case IDs come from `--list`; `lifecycle` is also selectable. Publication intervals can overlap reader decisions. Truncated/capped cohorts are not eligible latency evidence, and observing the union of publication coverage does not establish an each-reader/every-write SLA. The production benchmark reader policy is shared with `tests/layout_policy.rs`.

Use a bounded local run; increase repetitions before drawing conclusions. Concurrent timing, publication timing, and allocation regions measure different work and must not be combined into a fictitious request cost.

## Compare changes honestly

- Record CPU/OS, Rust/protoc versions, native libraries, dependency lockfile, build profile, source revision, workload, exact commands, and machine load/power conditions.
- Build both revisions with identical harness bytes and flags. Run timing repetitions interleaved; retain complete outputs, including adverse cases.
- Time **without** `bench-allocations`; count allocations in a separate pass.
- Keep setup, process-wide CPU/RSS, cold publication, and steady-state decision measurements labeled separately.
- Do not average reader percentiles to fabricate pooled percentiles. Retain raw samples or report only the statistics actually collected.
- No nanosecond/p99 CI threshold is imposed. Allocation budgets apply only to exact declared fixtures, not all real HTTPS requests.

The [baseline](../docs/performance/baseline.md), [results](../docs/performance/optimization-results.md), and [optimization plan](../docs/performance/optimization-plan.md) describe historical measurements and tradeoffs. Original source snapshots, paired executables, raw traces, and comparison runners from that campaign are not distributed in this checkout. The previous deployment-specific guide is preserved in the originating repository, not required for these current-source commands.

After caching every locked dependency, `--offline` can be added. A missing cached crate is an environment blocker, not permission to change pinned versions or infer a benchmark pass.
