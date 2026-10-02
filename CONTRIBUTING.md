# Contributing

Thank you for helping improve Apollo Edge Gateway.

## Before contributing

This is an experimental gateway, not a production-qualified deployment platform. The project is distributed under the [MIT license](LICENSE); contributions are intended to be distributed under that same license. No contributor license agreement or additional rights assignment is implied by this document. Use [SECURITY.md](SECURITY.md) for private disclosure rather than reporting vulnerabilities publicly.

Use the [README](README.md) to install the pinned toolchain and native dependencies. All commands run from the gateway repository root; no parent repository is required.

## Scope and module ownership

Keep changes focused on their owning feature. Startup composition belongs in `startup`, request handling in `proxy`, authenticated control operations in `control`/`transport`, snapshot admission and selection in `snapshot`, and filesystem/certificate mechanics in `state`/`material`.

Preserve safe Rust, tenant isolation, authority fencing, certificate checks, request limits, and fail-closed behavior. Avoid new production exports solely to reach private implementation details from tests. A change to the dependency graph or native runtime needs a concrete rationale, not a speculative performance claim.

## Compatibility

[`proto/apollo/edge/edge_control.proto`](proto/apollo/edge/edge_control.proto) is the checked-in control contract. Do not hand-edit generated Rust. Preserve existing protobuf field numbers, package identity, enum values, and persisted-state bytes. A protocol, environment, or storage change must document migration, mixed-version behavior, and rollback implications.

The schema was extracted byte-for-byte from the originating application. While that application retains its own contract copy, coordinate changes across both consumers; neither a network fetch nor a parent-directory fallback is part of this build.

## Validation

```sh
cargo fmt --check
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
```

The Linux [CI workflow](.github/workflows/ci.yml) runs these commands. Record checks actually executed, including environmental blockers. Compilation and unit tests do not establish native TLS delivery, firewall isolation, or production capacity.

For tests, protect observable behavior at its production owner. Name the credible regression, ensure stronger existing coverage does not already prove the same contract, and avoid source-text assertions, test-only APIs, or expected values computed by the function under test. For a bug regression, demonstrate the intended failure before the fix and a pass afterward.

## Performance changes

Follow [the benchmark guide](benches/README.md). Compare identical workloads, build flags, dependency locks, and machine conditions. Run multiple matched repetitions and report adverse cases as well as improvements. Keep allocation instrumentation separate from timing. Do not introduce brittle wall-clock CI thresholds or trade security for throughput.

## Pull requests

Describe the problem, owning module, compatibility impact, measured evidence where applicable, and validation actually run. Keep unrelated refactors separate. Never include production credentials, certificate material, runtime state, raw private deployment evidence, or private infrastructure details.

Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md), not a public issue or pull request.
