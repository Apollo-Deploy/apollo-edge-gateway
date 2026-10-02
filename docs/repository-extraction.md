# Preparing the independent GitHub repository

The gateway directory is self-contained: Cargo manifest/lockfile, Rust toolchain, local protobuf schema, native-build instructions, source, tests, benchmarks, public documentation, and Linux CI all live beneath this root. The independent repository destination is [`Apollo-Deploy/apollo-edge-gateway`](https://github.com/Apollo-Deploy/apollo-edge-gateway), licensed under [MIT](../LICENSE). The deployment application can keep its existing checkout during extraction.

## Do not split only committed history yet

The modular refactor includes new, uncommitted source files. A subtree split, `git archive HEAD`, or copying only tracked files would omit them. Do not publish the parent application's history: it contains unrelated code and private operational context.

Create a clean source snapshot from the current working tree instead:

```sh
python3 scripts/export_source.py
```

This command requires Python **3.11+** and creates:

```text
target/source-export/apollo-edge-gateway-source.tar.gz
```

It exports an explicit set of source directories and root files, includes approved `LICENSE*`/`NOTICE*` files when present, and captures uncommitted source. It excludes parent Git history, build output, private evidence/raw directories, runtime storage, and secrets directories. It rejects source symlinks and obvious private file extensions instead of following them. The archive normalizes owner/group/timestamp metadata and includes `SOURCE-MANIFEST.sha256` for the bytes actually exported.

The exporter refuses to overwrite an existing archive. For another snapshot, select a new `--output` path or intentionally remove your previous local export. Missing licensing produces a warning; creating an archive does **not** grant an open-source license or authorize publication.

## Validate the snapshot

List and inspect the archive before extracting it into a **new empty staging directory**, not over the deployment checkout:

```sh
tar -tzf target/source-export/apollo-edge-gateway-source.tar.gz
```

After extraction, use the `apollo-edge-gateway` directory as the new repository root. Verify `SOURCE-MANIFEST.sha256` there with `shasum -a 256 -c SOURCE-MANIFEST.sha256` on macOS or `sha256sum -c SOURCE-MANIFEST.sha256` on Linux. The manifest is a handoff artifact; remove it after verification before starting normal source maintenance.

Run the [README's build and validation commands](../README.md#development) from that extracted root. Verify the build never needs a sibling `schemas/` directory or a parent workspace. `protoc` remains a documented external build prerequisite, not a hidden repository dependency.

Review the exact exported files for credentials, private infrastructure details, and redistribution rights. The filename/directory filters are **not a general secret scanner**. The `.env.example` template contains only local addresses and paths, and the binary does not automatically load it.

## Before GitHub publication

1. Preserve the approved MIT [license text](../LICENSE) and Cargo's `license = "MIT"` metadata. Audit redistribution requirements for any bundled third-party material and dependencies; the project's license does not replace dependency licenses.
2. Use the approved destination `Apollo-Deploy/apollo-edge-gateway`, matching Cargo's `repository` URL. Verify repository access and visibility before publishing.
3. Initialize a **new** Git repository in the extracted root, inspect its staging area, and make the initial commit only when authorized. Do not copy a parent `.git` directory or attach another Git repository inside the current deployment checkout.
4. Private vulnerability reporting is enabled on the approved repository. Verify the maintainer notification path and monitoring. Update [SECURITY.md](../SECURITY.md) with a real alternate private contact if one is provided.
5. Review GitHub Actions permissions, configure branch protection/review requirements, and require the gateway CI job. CI does not publish artifacts, deploy, or grant release authority.
6. The approved public repository has been created. Push source only with explicit commit/push authorization. Keep `publish = false` until a separate crates.io release decision is made.
7. Coordinate the parent application's consumption model and protobuf contract ownership. Its schema copy remains unchanged; decide explicitly whether it consumes tagged source, release binaries, or another pinned integration. Do not delete or repoint the running integration merely to prepare the repository.

No repository creation, commit, remote change, public push, deployment, or parent-source removal is performed by the exporter.
