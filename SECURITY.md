# Security

## Release status

Version 0.1.0 is experimental. No supported production release line or production-security qualification is claimed. Local tests and microbenchmarks are not evidence of firewall isolation, native TLS lifecycle correctness, overload resilience, or crash-safe operation under every filesystem failure.

## Reporting a vulnerability

Do not disclose exploit details, tenant data, credentials, private keys, or persisted production state in a public issue or pull request.

GitHub private vulnerability reporting is enabled for [`Apollo-Deploy/apollo-edge-gateway`](https://github.com/Apollo-Deploy/apollo-edge-gateway). Use the repository's **Security → Report a vulnerability** entry to submit reports privately. Maintainers must verify notification receipt and monitoring; enabling the feature alone does not prove response readiness. No alternate private contact or response-time commitment is configured yet.

## Trust boundaries

- Control commands require a client certificate chaining to the configured control CA. The client certificate subject common name must equal `APOLLO_EDGE_GATEWAY_ID`.
- That certificate identity authorizes the controller for the gateway. It is not an organization-specific RBAC system: only trusted controllers should hold an accepted client key.
- Configuration hashes and persisted-state digests detect inconsistency; they are **not signatures** and do not authenticate maliciously rewritten local files. Authentication comes from mTLS and protected local storage.
- Frontend certificate material is scoped by organization, project, certificate, and version. Private material must not be committed or exposed through logs, configuration snapshots, or public artifacts.
- Private workload addressing is an admission condition, not a network firewall. Restrict upstream workload ingress to authorized gateways separately.

Run under a dedicated unprivileged account. Keep the control listener on a trusted management network, restrict CA/key access, and use private persistent state/material directories. Prevent multiple gateway processes from concurrently owning the same state path or certificate-material root. Backups require the same confidentiality and integrity controls.

## Known limits and dependency policy

HTTP/3 is unsupported; gRPC, WebSocket, and SSE are not qualified features. TCP-connect health is not application-level readiness. The native Linux load, certificate rotation/retirement, recovery, and network-isolation qualification work remains incomplete.

The locked Pingora graph historically included unmaintained `derivative` 2.2.0 (`RUSTSEC-2024-0388`). This is a maintenance advisory, not proof of an exploitable vulnerability. Recheck current advisories before release rather than treating an old audit as current evidence. [`deny.toml`](deny.toml) governs dependency source/license policy; it does not grant a license for this project's code.

## Public-release gate

Before making a public release, preserve the MIT license and copyright notice, verify private disclosure monitoring, review the exact source archive and any Git history for secrets and rights to redistribute, review current dependency advisories/licenses, and run native integration and operational qualification. The source-export command excludes obvious private file classes but is **not a general secret scanner or a security certification**.
