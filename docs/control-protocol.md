# Control protocol

The source contract is [`crates/edge-gateway-protocol/proto/apollo/edge/edge_control.proto`](../crates/edge-gateway-protocol/proto/apollo/edge/edge_control.proto), in protobuf package `apollo.edge`. The protocol crate's `build.rs` generates Prost types locally; the gateway reexports the versioned contract through `apollo_edge_gateway::control`.

This transport is **not gRPC**. A compatible controller connects to the gateway's control listener using mutually authenticated TLS and exchanges length-prefixed protobuf messages.

## Authentication

The server requires a client certificate chaining to `APOLLO_EDGE_CONTROL_CA`. After the TLS handshake, the client's certificate subject common name must exactly equal `APOLLO_EDGE_GATEWAY_ID`. The controller must independently verify the gateway server certificate and its expected server identity; do not disable certificate verification in a client.

The accepted identity is a trusted gateway controller, not per-organization client authorization. Do not distribute accepted client keys to untrusted tenants. Keep the listener on a private management network.

## Framing

Each frame consists of:

```text
4-byte unsigned big-endian payload length | protobuf payload bytes
```

- Request payload: `ControlRequest`; response payload: `ControlResponse`.
- Payload lengths must be between **1 and 4,194,304 bytes**, inclusive.
- Request header and body reads each have a **5-second timeout**.
- Multiple sequential request/response exchanges may share a TLS connection.
- Invalid framing, decoding, or authorization terminates the connection; it does not create an HTTP error response.

These wire numbers are compatibility contracts. Protobuf schema fields alone do not implement the framing or TLS authentication.

## Operations

`ControlRequest.payload` selects one operation:

| Operation | Purpose |
| --- | --- |
| `apply_configuration` | Validate identity, integrity, validity, route/endpoints, material references, and controller authority; persist before publishing |
| `inspect_configuration` | Inspect current state for a target identity |
| `drain_configuration` | Fence and persist a bounded drain command |
| `withdraw_configuration` | Remove serving ownership and retain durable withdrawal authority |
| `gateway_capabilities` | Discover advertised protocols and bounds |
| `gateway_status` | Inspect gateway/session authority and serving state |
| `install_certificate_material` | Verify and install tenant-scoped certificate material over authenticated control |

Read the actual schema for complete field definitions and result variants. Command admission also lives in `src/control/commands/` and `src/snapshot/admission.rs`; the schema does not imply that every representable value is accepted.

## Configuration authority and integrity

Operations and configurations carry a nonzero controller epoch, generation, identity, and configuration hash. The gateway fences stale authority, detects same-generation conflicting hashes, and preserves withdrawal tombstones. An idempotent admission result is not permission to skip identity or transport checks.

The configuration digest is SHA-256 over Prost encoding of a configuration with `configuration_hash` cleared; see `digest_without_hash` in `src/snapshot/admission.rs`. It is an integrity check, **not a cryptographic signature**. Cross-language controllers must prove that their encoded bytes satisfy the same contract rather than hashing a JSON representation or relying on field-name equality. `semantic_hash` has separate controller-owned meaning; the gateway requires its configured length but does not derive it as a replacement for the configuration digest.

Install frontend material before applying a configuration that references it. A listening empty gateway cannot serve frontend TLS without admitted certificate bindings. Controller orchestration and credentials are not bundled in this repository.

## Compatibility ownership

The checked-in schema was copied byte-for-byte from the originating deployment contract. That application retains its copy for its own consumers. Coordinate any future changes across both repositories; there is no parent-directory fallback or build-time network fetch. Preserve protobuf field numbers, package names, enum identities, framing, and persisted representation. Document upgrade and rollback behavior for changes affecting authority or durable state.

See [configuration](configuration.md), [security](../SECURITY.md), and [contributing](../CONTRIBUTING.md).
