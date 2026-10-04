# Configuration

The executable reads environment variables directly. The public serving variables must be nonempty. The control variables are an all-or-nothing management configuration: when they are absent or invalid, the gateway logs the control failure and continues serving recovered local state. It does not read `.env`, a local route YAML file, or an unauthenticated administration API.

| Variable | Meaning |
| --- | --- |
| `APOLLO_EDGE_LISTEN` | Public HTTPS socket address, for example `127.0.0.1:8443` |
| `APOLLO_EDGE_CONTROL_LISTEN` | Optional with the other control variables; authenticated control socket address, for example `127.0.0.1:9443` |
| `APOLLO_EDGE_GATEWAY_ID` | Optional with the other control variables; gateway identity and required controller client certificate common name |
| `APOLLO_EDGE_STATE_PATH` | Persistent gateway-state file path |
| `APOLLO_EDGE_CERTIFICATE_MATERIAL_DIR` | Existing certificate-material directory, private and writable by the gateway user |
| `APOLLO_EDGE_CONTROL_CA` | Optional with the other control variables; PEM CA certificate file used to verify controller client certificates |
| `APOLLO_EDGE_CONTROL_CERTIFICATE` | Optional with the other control variables; PEM server certificate-chain file for the control listener |
| `APOLLO_EDGE_CONTROL_PRIVATE_KEY` | Optional with the other control variables; PEM server private-key file matching the control certificate |

Relative paths resolve from the process working directory. Prefer explicit absolute paths in service-manager configuration. The certificate-material root must already exist; it is canonicalized at startup. State replacement creates its parent directory when needed, but operators should provision private directories before running.

## Local development

The root [`.env.example`](../.env.example) deliberately uses loopback and unprivileged ports. It contains no usable credentials. Provision your own trusted development control CA/server material and protect the files; do not commit them. Export a trusted environment file explicitly as shown in the [README](../README.md).

Control mTLS credentials and frontend certificates are separate. The gateway loads control credentials at startup. Frontend certificates are installed through the authenticated `InstallCertificateMaterialRequest` operation and referenced by admitted routes. Do not put private-key bytes in `EdgeConfiguration`.

An empty startup does not create demo routes or install a default frontend certificate. Public TLS handshakes need an admitted hostname and its matching material. A controller must publish routes to private IPv4 workloads using the [control protocol](control-protocol.md).

## Startup and persistence

Startup recovers validated state and certificate material before starting the public Pingora listener. The authenticated control listener is attempted independently: missing or invalid control configuration, bind failure, TLS setup failure, and later control-server termination are logged while local serving continues. Restart the process under a supervisor to restore management connectivity. A gateway restart recovers the persisted route/certificate state before accepting public traffic.

Persisted configuration includes epoch/generation authority and withdrawal/drain state. It uses a bounded protobuf envelope with a SHA-256 integrity digest and atomic replacement. The digest is not protection against a malicious actor who can rewrite the file; restrict filesystem access. Do not run multiple processes against the same state/material paths. Recovered local health begins empty and is populated by probes.

Do not equate successful file replacement with verified behavior under every post-rename directory-sync failure. Native crash/recovery qualification remains incomplete. See [security](../SECURITY.md).

## What is not configured here

Route policies, validity, retries, resource limits, backend endpoints, and certificate references belong to admitted protobuf configurations, not additional environment variables. Database credentials, deployment authorization, ACME issuance, and workload firewall management are outside this executable.
