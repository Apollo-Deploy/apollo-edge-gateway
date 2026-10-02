# Performance architecture

The gateway separates synchronous serving decisions from configuration admission,
durability, certificate material, and control transport. The optimizations change
private lookup and selection state, not the wire protocol, durable format,
allocator, network framework, or executor. See [hot-path.md](hot-path.md) for the
request flow and [optimization-results.md](optimization-results.md) for measured
benefits and costs.

## Module boundaries

| Area | Responsibility |
| --- | --- |
| `src/main.rs`, `src/startup/` | Thin entry point, configuration, and startup wiring |
| `src/proxy/` | HTTP callbacks, Host/SNI/authority checks, limits, and TLS integration |
| `src/control/commands/`, `src/control/active.rs` | Serialized mutations and immutable active entries/index; other control modules own authority, recovery, routing, and certificates |
| `src/snapshot/` | Admission, route policy, backend selection, and scoped health keys |
| `src/transport/` | Control-channel mTLS, framing, command dispatch, and health probing |
| `src/state/` | Durable envelope and state-store operations |
| `src/material/` | Certificate install, load, validation, paths, and retirement |

The standalone build contract is Rust 1.88, edition 2024. The schema lives at
`proto/apollo/edge/edge_control.proto`, and `build.rs` uses that repository-local
schema rather than a parent checkout. System allocation, thin LTO, and stripping
are unchanged; packaging does not introduce a performance tuning claim.

## Publication and serving

```text
Control transport -> command admission -> construct next immutable state
  -> durable persistence -> active entries + host index publication -> acknowledgment

Health probes -> immutable local-health publication

Proxy callback -> short snapshot guards -> limits / route / backend decision
  -> owned result returned to the proxy
```

Serving lookups make no database requests and do not acquire the control authority
mutex. Entries and the host index form one atomically published ArcSwap value.
Active configurations, drains, and local health are separate snapshots: this is
not a global transaction across all three. Guards remain within synchronous
lookups and do not cross awaits or separate proxy callbacks. The public API can
still return an owned active-state reference where required.

## A: ordered exact-host candidates

Active entries retain target ordering. The derived exact-host index points to
ordered snapshot candidates, deduplicated per target/hostname even when several
routes share the host. Both entries and index are constructed together on active
configuration changes and recovery; there is no separately maintained mutable
index or expiry timer.

Index membership is only a search accelerator. Lookups still enforce expiry,
drain status, path and method rules. Backend routing chooses the longest matching
path before checking its method; direct snapshot selection filters methods before
choosing the longest path. These distinct policies are preserved. Ambiguity counts
eligible targets rather than routes or healthy backends. Limits/TLS preserve
first-hit target precedence, and TLS retains original route precedence. Draining
excludes backend lookup, not limits or TLS lookup.

## B: borrowed selector, pinned health

The private selector holds an `Arc` to Pingora RoundRobin with the same effective
uniform, deduplicated membership as the previous static wrapper. Every outer retry
uses the first borrowed candidate from a fresh iterator. The raw address count
still bounds attempts; cursor advancement, duplicate-address callbacks, stateful
`FnMut` behavior, and sharing across clones remain compatible.

A resolution pins one local health view. Original-order address/key vectors and
the first matching address lookup are retained. C/D binary and hybrid variants
were reverted after common-case and concurrent regressions. Missing or false
health fails closed. The gateway owns external health; the removed internal
readiness/discovery machinery was unused. Introducing internal selector health
later would require revisiting this invariant. Configured weights were already
reset to one by the previous static constructor; nonuniform weighting is not a
verified capability of this change.

## S: isolated local health identities

Delimiter concatenation could let embedded-NUL target/workload identities collide
and inherit another identity's healthy state. The local encoding escapes an
embedded NUL as NUL + SOH and terminates each identity field with NUL + NUL, with
an explicitly represented generation and canonical address suffix. Ordinary
NUL-free identity probe ordering is preserved.

This changes only locally derived health keys, not admitted identities, signed
configuration, or durable/wire data. Empty and recovered processes require fresh
health publication. Old and new encodings are not universally disjoint, so mixed
old/new map reuse and universal stale-key rejection must not be assumed.

## Tradeoffs and evidence boundary

The exact-host index is justified for read-mostly multi-host traffic. Its rebuild
cost makes some publications slower, and shared-host/high-route shapes show
limited decision gains. Retained old snapshots and transient setup allocations
must be included when assessing memory; lower fixture live heap is not a
production peak-memory guarantee.

The [baseline](baseline.md) explains historical measurement provenance. Current
source commands are in [the benchmark guide](../../benches/README.md); the
[decision plan](optimization-plan.md) describes the practical next ceiling.
Native Linux HTTPS/load, syscalls, native allocation/heap, runtime, and crash-soak
qualification remain unverified. No new unsafe code or custom low-level execution
mechanism is justified by the current evidence.
