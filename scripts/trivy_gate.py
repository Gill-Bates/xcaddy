#!/usr/bin/env python3
#
# scripts/trivy_gate.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Run Trivy scans and decide the blocking gate from the JSON reports."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import publish
from common import (
    ScriptError,
    repo_root,
    require_tools,
    run,
    run_main,
    sha256_file,
    write_summary,
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
BLOCKING = ("CRITICAL", "HIGH")
CONFIG_DIRS = ("packaging", "config", "apt", ".github")
CANARY_DIR = Path("tests") / "fixtures" / "trivy-canary"


def load_report(path: Path) -> dict[str, Any]:
    """Return the parsed report or raise; a missing or malformed report blocks the gate."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScriptError(f"report {path} is missing or not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "SchemaVersion" not in data or "ArtifactName" not in data:
        raise ScriptError(f"report {path} is not a Trivy report")
    results = data.get("Results")
    if results is not None and not isinstance(results, list):
        raise ScriptError(f"report {path} has a malformed Results field")
    return data


def count_findings(report: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for result in report.get("Results") or []:
        for key in ("Vulnerabilities", "Secrets"):
            for item in result.get(key) or []:
                counts[str(item.get("Severity", "UNKNOWN")).upper()] += 1
        for item in result.get("Misconfigurations") or []:
            if item.get("Status", "FAIL") == "FAIL":
                counts[str(item.get("Severity", "UNKNOWN")).upper()] += 1
    return counts


def evaluate(paths: list[Path]) -> tuple[bool, str]:
    """Return (passed, markdown summary) for the given reports."""
    if not paths:
        raise ScriptError("no reports given")
    lines = ["| Report | " + " | ".join(SEVERITIES) + " |", "|---|" + "---|" * len(SEVERITIES)]
    blocked: list[str] = []
    for path in paths:
        counts = count_findings(load_report(path))
        lines.append(f"| {path.name} | " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |")
        if any(counts[s] for s in BLOCKING):
            blocked.append(path.name)
    verdict = (
        f"**Gate failed**: CRITICAL or HIGH findings in {', '.join(blocked)}"
        if blocked
        else "**Gate passed**: no CRITICAL or HIGH findings (MEDIUM and LOW are documented only)"
    )
    return not blocked, f"### Trivy gate\n\n{verdict}\n\n" + "\n".join(lines) + "\n"


def require_go_modules(report: Path) -> None:
    """A scan that saw no Go modules in the binary is an error, not a clean result."""
    for result in load_report(report).get("Results") or []:
        if result.get("Type") == "gobinary" and result.get("Packages"):
            return
    raise ScriptError(f"{report.name}: no Go modules detected in the binary; scan is not trusted")


def require_misconfigurations(report: Path) -> None:
    """The canary scan must flag the insecure fixture, else the misconfig scanner is blind."""
    for result in load_report(report).get("Results") or []:
        if result.get("Misconfigurations"):
            return
    raise ScriptError(f"{report.name}: canary produced no misconfiguration; scanner is not trusted")


def copy_config_inputs(root: Path, dest: Path) -> None:
    """Copy the scanned directories; a missing or empty one would make the scan vacuous."""
    for name in CONFIG_DIRS:
        src = root / name
        if not src.is_dir() or not any(p.is_file() for p in src.rglob("*")):
            raise ScriptError(f"scan input {name}/ is missing or empty; refusing a vacuous scan")
        run(["cp", "-r", src, dest / name])


def fetch_published(url: str, arch: str, dest: Path, fingerprint: str) -> Path:
    """Download the published package for arch; manifest signature and package bytes are checked."""
    with tempfile.TemporaryDirectory(prefix="published-state-") as state:
        if not publish.fetch_public_state(url, Path(state), fingerprint):
            raise ScriptError("no release is published yet; nothing to scan")
        manifest = json.loads((Path(state) / "release-manifest.json").read_text(encoding="utf-8"))
    names = [n for n in manifest.get("packages", {}) if n.endswith(f"_{arch}.deb")]
    if len(names) != 1:
        raise ScriptError(f"manifest lists {len(names)} packages for {arch}")
    if not re.fullmatch(r"[A-Za-z0-9._+~-]+\.deb", names[0]):
        raise ScriptError(f"unsafe package name in the release manifest: {names[0]!r}")
    deb = dest / names[0]
    publish._download(f"{url.rstrip('/')}/pool/main/x/xcaddy/{names[0]}", deb)
    if sha256_file(deb) != manifest["packages"][names[0]]:
        raise ScriptError(f"{names[0]} does not match the SHA-256 in the release manifest")
    return deb


def trivy_scan(kind: str, target: Path, report: Path) -> None:
    """Scan with all severities recorded; the gate decision is made by evaluate()."""
    require_tools("trivy")
    scanners = "vuln,secret" if kind == "rootfs" else "misconfig,secret"
    report.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "trivy",
            kind,
            "--scanners",
            scanners,
            "--format",
            "json",
            "--output",
            report,
            "--exit-code",
            "0",
            "--quiet",
            target,
        ]
    )
    load_report(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    deb = sub.add_parser("scan-deb", help="unpack a package and scan binary and files")
    deb.add_argument("deb", type=Path)
    deb.add_argument("--report", required=True, type=Path)
    pub = sub.add_parser("scan-published", help="verify and scan the public package bytes")
    pub.add_argument("--url", default="https://gill-bates.github.io/xcaddy")
    pub.add_argument("--fingerprint", required=True, help="pinned signer (APT_GPG_KEY_ID)")
    pub.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    pub.add_argument("--report", required=True, type=Path)
    cfg = sub.add_parser("scan-config", help="scan the build configuration of this repository")
    cfg.add_argument("--report", required=True, type=Path)
    ev = sub.add_parser("evaluate")
    ev.add_argument("reports", nargs="+", type=Path)
    ev.add_argument("--summary", type=Path)
    ns = parser.parse_args()

    if ns.command == "scan-deb":
        require_tools("dpkg-deb")
        with tempfile.TemporaryDirectory(prefix="trivy-rootfs-") as tmp:
            run(["dpkg-deb", "--extract", ns.deb, tmp])
            trivy_scan("rootfs", Path(tmp), ns.report)
        require_go_modules(ns.report)
    elif ns.command == "scan-published":
        with tempfile.TemporaryDirectory(prefix="published-") as tmp:
            deb = fetch_published(ns.url, ns.arch, Path(tmp), ns.fingerprint)
            with tempfile.TemporaryDirectory(prefix="trivy-rootfs-") as root:
                run(["dpkg-deb", "--extract", deb, root])
                trivy_scan("rootfs", Path(root), ns.report)
        require_go_modules(ns.report)
    elif ns.command == "scan-config":
        root = repo_root()
        with tempfile.TemporaryDirectory(prefix="trivy-config-") as tmp:
            copy_config_inputs(root, Path(tmp))
            trivy_scan("fs", Path(tmp), ns.report)
        canary = ns.report.with_name(f"{ns.report.stem}-canary{ns.report.suffix}")
        trivy_scan("fs", root / CANARY_DIR, canary)
        require_misconfigurations(canary)
    else:
        passed, text = evaluate(ns.reports)
        print(text)
        write_summary(text)
        if ns.summary:
            ns.summary.write_text(text, encoding="utf-8")
        if not passed:
            raise ScriptError("Trivy gate blocked the release")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
