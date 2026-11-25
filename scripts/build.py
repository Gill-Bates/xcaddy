#!/usr/bin/env python3
#
# scripts/build.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Build Caddy with the plugins of config/plugins.txt via xcaddy and verify the result."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import toolchain
from check_version import build_fingerprint, inputs_hash
from common import (
    ARCHS,
    VERSION_RE,
    ScriptError,
    elf_arch,
    host_arch,
    repo_root,
    require_tools,
    run,
    run_main,
    sha256_file,
)
from lock import load_lock, locked_plugins
from plugins import load_plugins


def locked_args(rows: list[dict[str, Any]]) -> list[str]:
    return [a for r in rows for a in ("--with", f"{r['module']}@{r['version']}")]


def replacement_args(replacements: tuple[str, ...]) -> list[str]:
    return [arg for replacement in replacements for arg in ("--replace", replacement)]


def verify_binary(binary: Path, arch: str, version: str, rows: list[dict[str, Any]]) -> None:
    if elf_arch(binary) != arch:
        raise ScriptError(f"architecture mismatch: binary is {elf_arch(binary)}, expected {arch}")
    if host_arch() != arch:
        raise ScriptError(f"host is {host_arch()}; the {arch} binary can only be verified natively")
    reported = run([binary, "version"]).stdout.strip()
    if not reported.startswith(f"v{version}"):
        raise ScriptError(f"caddy reports {reported!r}, expected v{version}")
    listed = set(run([binary, "list-modules"]).stdout.split())
    problems = missing_modules(rows, listed)
    if problems:
        raise ScriptError("module verification failed: " + "; ".join(problems))


def missing_modules(rows: list[dict[str, Any]], listed: set[str]) -> list[str]:
    """Every root-package module ID must be listed; without root IDs at least one ID must be."""
    problems = []
    for row in rows:
        required = row["module_ids"] or []
        if required:
            problems += [f"{row['module']}: {m} missing" for m in required if m not in listed]
        elif not listed & set(row["module_ids_any"]):
            problems.append(f"{row['module']}: none of {row['module_ids_any']} listed")
    return problems


def built_modules(binary: Path) -> dict[str, tuple[str, str]]:
    """Module path to (version, h1 sum) from the Go build info embedded in the binary."""
    return parse_build_info(run(["go", "version", "-m", binary]).stdout)


def parse_build_info(text: str) -> dict[str, tuple[str, str]]:
    modules: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "dep":
            modules[parts[1]] = (parts[2], parts[3] if len(parts) > 3 else "")
    return modules


def verify_lock(deps: dict[str, tuple[str, str]], rows: list[dict[str, Any]]) -> None:
    for row in rows:
        got = deps.get(row["module"])
        if got is None:
            raise ScriptError(f"plugin {row['module']} is not in the binary's build info")
        if got != (row["version"], row["sum"]):
            raise ScriptError(f"{row['module']} built as {got}, lock says {row['version']}")


def sbom(deps: dict[str, tuple[str, str]], version: str) -> dict[str, Any]:
    components = [
        {
            "type": "library",
            "name": path,
            "version": ver,
            "purl": f"pkg:golang/{path}@{ver}",
        }
        for path, (ver, _sum) in sorted(deps.items())
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "caddy", "version": version}},
        "components": components,
    }


def write_manifest(binary: Path, arch: str, version: str, rows: list[dict[str, Any]], out: Path):
    deps = built_modules(binary)
    verify_lock(deps, rows)
    ihash = inputs_hash(repo_root())
    manifest = {
        "caddy_version": version,
        "architecture": arch,
        "go_version": run(["go", "env", "GOVERSION"]).stdout.strip(),
        "xcaddy_version": toolchain.XCADDY_VERSION,
        "build_flags": toolchain.BUILD_FLAGS,
        "build_replacements": list(toolchain.BUILD_REPLACEMENTS),
        "inputs_hash": ihash,
        "build_fingerprint": build_fingerprint(version, ihash),
        "source_commit": os.environ.get("GITHUB_SHA", "unknown"),
        "binary_sha256": sha256_file(binary),
        "plugins": [{k: r[k] for k in ("module", "requested", "version", "sum")} for r in rows],
        "module_graph": [
            {"module": m, "version": v, "sum": s} for m, (v, s) in sorted(deps.items())
        ],
    }
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sbom_path = out.with_name("sbom.cdx.json")
    sbom_path.write_text(json.dumps(sbom(deps, version), indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy-version", required=True)
    parser.add_argument("--arch", required=True, choices=ARCHS)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--plugins-file", type=Path)
    parser.add_argument("--lock-file", type=Path)
    ns = parser.parse_args()
    if not VERSION_RE.fullmatch(ns.caddy_version):
        raise ScriptError(f"invalid --caddy-version {ns.caddy_version!r}")
    require_tools("xcaddy", "go")
    root = repo_root()
    entries = load_plugins(ns.plugins_file or root / "config/plugins.txt")
    rows = locked_plugins(entries, load_lock(ns.lock_file or root / "config/plugins.lock"))
    ns.out.mkdir(parents=True, exist_ok=True)
    binary = ns.out / "caddy"
    print(f"Building Caddy v{ns.caddy_version} for linux/{ns.arch}, {len(rows)} locked plugins")
    env = {**os.environ, "GOOS": "linux", "GOARCH": ns.arch, "CGO_ENABLED": "0"}
    run(
        [
            "xcaddy",
            "build",
            f"v{ns.caddy_version}",
            *locked_args(rows),
            *replacement_args(toolchain.BUILD_REPLACEMENTS),
            "--output",
            binary,
        ],
        env=env,
    )
    binary.chmod(0o755)
    verify_binary(binary, ns.arch, ns.caddy_version, rows)
    write_manifest(binary, ns.arch, ns.caddy_version, rows, ns.out / "build-manifest.json")
    sums = "".join(
        f"{sha256_file(ns.out / n)}  {n}\n"
        for n in ("caddy", "build-manifest.json", "sbom.cdx.json")
    )
    (ns.out / "SHA256SUMS").write_text(sums, encoding="utf-8")
    print(f"Build verified: {binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
