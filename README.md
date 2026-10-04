# Apollo Edge Gateway

A Rust HTTPS gateway built on [Pingora](https://github.com/cloudflare/pingora), with an authenticated protobuf control channel and immutable routing snapshots.

[Repository](https://github.com/Apollo-Deploy/apollo-edge-gateway) · [MIT license](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

The gateway separates serving traffic from authorizing configuration: a controller installs certificate material and publishes bounded, versioned route configurations; request handling reads local admitted state without querying a database or the controller.


## What it does

- Terminates frontend TLS with hostname-scoped certificate selection.
- Routes by exact hostname, path prefix, and admitted HTTP method to private IPv4 workload endpoints.
- Supports HTTP/1.1 and HTTP/2.
- Applies controller-epoch and generation fencing, conflict detection, withdrawal tombstones, and draining.
- Persists configuration with bounded protobuf decoding, an integrity digest, and atomic file replacement.
- Exposes apply, inspect, drain, withdraw, capabilities, status, and certificate installation over mutually authenticated TLS.
- Uses immutable snapshots for read-mostly routing and local TCP-connect health probes.

A compatible controller authorizes routes and installs frontend certificate
material. Certificate lifecycle operations belong to
[apollo-certd](https://github.com/Apollo-Deploy/apollo-certd), and provider DNS
operations belong to [apollo-dnsd](https://github.com/Apollo-Deploy/apollo-dnsd).
The gateway continues serving its admitted local state when those services or
the controller are unavailable, subject to certificate and snapshot validity.
The control protocol uses framed protobuf over TLS.

`src/bin/edge-control-client.rs` is a fixed-fixture development client, not a general production controller or automatic certificate provisioner. Inspect its test identities, hostname, backend address, and validity assumptions before use.

## Build

All commands below run from this repository's root. No sibling Apollo repository, parent workspace, database, or private deployment artifact is needed to compile it.

Requirements:

- Rust **1.88.0**, with Rustfmt and Clippy; `rust-toolchain.toml` pins the toolchain.
- A native C/C++ toolchain, CMake, OpenSSL development headers, and `pkg-config`.
- Protocol Buffers compiler (`protoc`) on `PATH`, or an explicit `PROTOC` path.

Ubuntu/Debian build prerequisites:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends build-essential clang cmake libssl-dev pkg-config protobuf-compiler
```

macOS build prerequisites, using Homebrew:

```sh
brew install cmake openssl@3 pkg-config protobuf
```

Apple command-line developer tools must also be installed. If OpenSSL is not discovered, configure `OPENSSL_DIR` using your installed OpenSSL prefix; do not change dependency versions to work around discovery.

```sh
cargo build --locked --release --bin apollo-edge-gateway
```

The workspace-owned [`crates/edge-gateway-protocol/proto/apollo/edge/edge_control.proto`](crates/edge-gateway-protocol/proto/apollo/edge/edge_control.proto) is compiled by that crate's `build.rs`; the gateway depends only on the versioned local `edge-gateway-protocol` crate. `Cargo.lock` is checked in. The first build may download locked crates; `--offline` works only after all dependencies are cached.

## Run

The binary reads environment variables; it **does not automatically load `.env`**.

1. Provision a control CA, server certificate chain, and server private key. Authorized controller client certificates must chain to that CA and have a subject common name matching `APOLLO_EDGE_GATEWAY_ID`.
2. Create private writable state/material directories and copy [`.env.example`](.env.example) to `.env`; set the paths and listener addresses for your environment.
3. Load the trusted local environment file and start the binary:

```sh
mkdir -p var/certificates secrets
chmod 700 var var/certificates secrets
cp .env.example .env
# Edit .env and provision the referenced control TLS files before continuing.
set -a
. ./.env
set +a
./target/release/apollo-edge-gateway
```

An empty gateway can start, but it has no serving routes or frontend certificates. A compatible controller must install certificate material and apply a valid configuration before HTTPS requests can succeed. State and certificate material recover before the public listener starts. If the authenticated control listener is missing or cannot initialize, the gateway logs the failure and continues serving already-admitted local state; a supervisor can restart it to restore management connectivity.

See [configuration](docs/configuration.md) and [control protocol](docs/control-protocol.md). Keep the control listener on a trusted management network. Run as a dedicated unprivileged user with private persistent storage; the example binds localhost and an unprivileged HTTPS port deliberately.

## Architecture

```text
Client HTTPS -> Pingora proxy -> admitted snapshot -> private workload endpoint
Controller  -> mTLS + framed protobuf -> admission/fencing -> durable state + publication
```

| Directory | Responsibility |
| --- | --- |
| `src/startup/` | Configuration, recovery, and listener composition |
| `src/proxy/` | HTTP handling, request limits, hostname/SNI checks, and frontend TLS |
| `src/control/` | Authority, commands, recovery, inspection, and indexed active state |
| `src/snapshot/` | Admission, routing, backend selection, and scoped health identity |
| `src/transport/` | Control mTLS, bounded framing, dispatch, and health probes |
| `src/state/` | Persisted protobuf envelope, validation, and atomic replacement |
| `src/material/` | Scoped certificate verification, installation, loading, and retirement |
| `crates/edge-gateway-protocol/` | Versioned source control protocol and generated Prost types |
| `benches/`, `tests/` | Routing/layout benchmarks and owner-boundary integration coverage |

`src/main.rs` composes the services; implementation helpers remain private.
Certificate parsing and validation happen during snapshot admission. Handshakes
select cached material, with no ACME, DNS, or controller RPC on the request path.

## Development

```sh
cargo fmt --check
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
```

The repository-local [CI workflow](.github/workflows/ci.yml) runs these checks on Linux. It uses read-only repository permissions and does not deploy or publish releases. See [contributing](CONTRIBUTING.md) for protocol compatibility and test expectations, and [security](SECURITY.md) for trust boundaries and disclosure guidance.
