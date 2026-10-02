#!/usr/bin/env python3
"""Export the current gateway source without parent history or private artifacts."""

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = (
    "Cargo.toml", "Cargo.lock", "build.rs", "deny.toml", "rust-toolchain.toml",
    "README.md", "CONTRIBUTING.md", "SECURITY.md", ".gitignore", ".env.example",
)
SOURCE_DIRECTORIES = ("src", "proto", "benches", "tests", "docs", "scripts", ".github")
EXCLUDED_DIRECTORIES = {".git", "target", "__pycache__", "secrets", "var", "raw", "evidence"}
PRIVATE_SUFFIXES = {".pem", ".key", ".crt", ".p12", ".pfx", ".state", ".log"}


def source_files():
    candidates = [ROOT / name for name in ROOT_FILES]
    candidates.extend(ROOT.glob("LICENSE*"))
    candidates.extend(ROOT.glob("NOTICE*"))
    for name in SOURCE_DIRECTORIES:
        candidates.extend((ROOT / name).rglob("*"))
    files = []
    for path in sorted(set(candidates)):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if path.name == ".DS_Store" or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ValueError(f"refusing to export a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"missing or nonregular source file: {relative}")
        if path.suffix in PRIVATE_SUFFIXES or (path.name.startswith(".env") and relative.as_posix() != ".env.example"):
            raise ValueError(f"refusing to export a private artifact: {relative}")
        files.append(path)
    return files


def add_file(archive, name, data):
    # Do not publish developer usernames, group names, paths, or file timestamps.
    entry = tarfile.TarInfo(f"apollo-edge-gateway/{name}")
    entry.size = len(data)
    entry.mode = 0o644
    archive.addfile(entry, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/source-export/apollo-edge-gateway-source.tar.gz")
    options = parser.parse_args()
    files = source_files()
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    if not package.get("license") and not package.get("license-file"):
        print("WARNING: project license is pending; this archive is not an open-source release.", file=sys.stderr)
    output = options.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as destination:
        with gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                manifest = []
                for path in files:
                    name = path.relative_to(ROOT).as_posix()
                    data = path.read_bytes()
                    add_file(archive, name, data)
                    manifest.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
                add_file(archive, "SOURCE-MANIFEST.sha256", "".join(manifest).encode())
    print(f"Exported {len(files)} source files to {output}")
    print(f"SHA-256: {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"export failed: {error}", file=sys.stderr)
        sys.exit(1)
