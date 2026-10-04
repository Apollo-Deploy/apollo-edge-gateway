# Security

## Reporting a vulnerability

Do not disclose exploit details, tenant data, credentials, private keys, or persisted production state in a public issue or pull request.

GitHub private vulnerability reporting is enabled for [`Apollo-Deploy/apollo-edge-gateway`](https://github.com/Apollo-Deploy/apollo-edge-gateway). Use the repository's **Security → Report a vulnerability** entry to submit reports privately.

## Trust boundaries

- Control commands require a client certificate chaining to the configured control CA. The client certificate subject common name must equal `APOLLO_EDGE_GATEWAY_ID`.
- That certificate identity authorizes the controller for the gateway. It is not an organization-specific RBAC system: only trusted controllers should hold an accepted client key.
- Configuration hashes and persisted-state digests detect inconsistency; they are **not signatures** and do not authenticate maliciously rewritten local files. Authentication comes from mTLS and protected local storage.
- Frontend certificate material is scoped by organization, project, certificate, and version. Private material must not be committed or exposed through logs, configuration snapshots, or public artifacts.
- Private workload addressing is an admission condition, not a network firewall. Restrict upstream workload ingress to authorized gateways separately.

Run under a dedicated unprivileged account. Keep the control listener on a trusted management network, restrict CA/key access, and use private persistent state/material directories. Prevent multiple gateway processes from concurrently owning the same state path or certificate-material root. Backups require the same confidentiality and integrity controls.

## Dependency policy

The checked-in lockfile pins dependencies. [`deny.toml`](deny.toml) defines
source and license policy. Review current dependency advisories when updating
the lockfile and before tagging a release.
