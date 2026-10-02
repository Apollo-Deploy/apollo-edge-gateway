# Gateway hot path

The gateway serves requests from admitted, in-memory configuration and health
snapshots. It makes **no database requests on the serving path**. The
[baseline](baseline.md) and [results](optimization-results.md) measure only a
subset of the following flow.

## Request flow

```text
Pingora connection handling and HTTP parsing
  -> TLS SNI binding and certificate-material validation on new TLS connections
  -> request context and Host/SNI/authority validation
  -> framing, bounds, limits, and concurrency admission
  -> route resolution, backend selection, and upstream peer creation
  -> upstream header filtering and normalized Host
  -> pooled upstream forwarding and body callbacks
  -> response/error handling and concurrency release
```

`proxy` owns request callbacks; `control` and `snapshot` provide synchronous
lookups; `material` owns certificate loading and validation. Framework networking,
TLS, peer construction, and forwarding are outside the routing microbenchmark.
A peer object allocation does not imply a new TCP connection.

## Retained changes at the decision boundary

| Cost source | Retained behavior | Remaining constraint |
| --- | --- | --- |
| Scanning every target for a hostname | An immutable exact-host index narrows candidates | Routes within matching candidates still need path/method checks |
| Owned active-snapshot loads | Short synchronous ArcSwap guards | Guards do not cross awaits or separate callbacks |
| Selection allocation on each health rejection | Borrow the first candidate from a fresh Pingora RoundRobin iterator per attempt | Keep the original retry budget and shared cursor behavior |
| Repeated local-health loads | Pin one immutable local-health view per resolution | Later resolutions may observe a newer view |
| Address-to-health-key search | Keep original-order linear lookup | Wide all-unhealthy sets remain relatively expensive |
| Ambiguous identity delimiters in health keys | Collision-free local identity encoding | Correctness fix, not a speed claim |

The exact-host index and entries are published as one value, not as separately
updated state. Lookup-time expiry, draining, ambiguity, and admission rules still
apply. The [architecture](architecture.md) describes ordering and isolation details.

## Selection compatibility

The private selector stores an `Arc` to Pingora's existing RoundRobin. Each outer
attempt takes only the first borrowed candidate from a **fresh iterator**. This
preserves cursor advancement, duplicate-address callback behavior, stateful
`FnMut` calls, clone sharing, and first-address health-key precedence. It is not a
replacement scheduling algorithm or a uniqueness-filtered retry loop.

Gateway health is external to the selector; absent or false local health fails
closed. Internal Pingora discovery/readiness machinery was unused and removed.
The effective membership remains uniform: the previous static constructor reset
weights to one. Intended nonuniform weighted distribution was not validated or
enabled by this optimization.

## Allocation and ownership boundary

Separate counting measured warm GET/HEAD resolution falling from 1 allocation /
44 bytes for healthy resolution, or 256 / 11,264 for the all-unhealthy wide case,
to **0 / 0**. The combined decision still allocates 3 times / 55 bytes for owned
limits output. TLS metadata binding remains 3 / 82; misses and denials remain
0 / 0. These are fixture-specific Rust allocation counts, not a claim that full
HTTP handling allocates nothing. No body-copy reduction was measured.

Repeated host normalization across proxy callbacks, owned retry-policy output,
certificate-material work, and framework futures/peer objects are potential
profiling targets, not established dominant costs. Original-order address scans
remain intentional: binary and hybrid alternatives were reverted after small and
concurrent regressions.

## Concurrency and next evidence

Active configurations, drains, and local health are separate immutable snapshots,
not a single transaction. A resolution pins one local health view; it does not
cache request authority across callbacks. Control mutation uses a separate
serialized authority path, while public lookup remains synchronous. This does
not imply that Pingora, TLS libraries, or the kernel are lock-free or task-free.

The System allocator and release settings are unchanged. There is no measured
basis for io_uring, SIMD, custom executors, kernel bypass, allocator changes,
assembly, or new unsafe code. Follow the [completed decision plan and next
ceiling](optimization-plan.md) before broadening the optimization scope. Current
source benchmark commands and instrumentation modes are in
[the benchmark guide](../../benches/README.md).
