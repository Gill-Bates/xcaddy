#!/usr/bin/env python3
#
# scripts/check_version.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Find the latest stable Caddy release and decide whether a build is due."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import toolchain
from common import (
    VERSION_RE,
    ScriptError,
    dpkg_compare,
    repo_root,
    require_tools,
    run_main,
    set_output,
    write_summary,
)
from plugins import load_plugins

API_URL = "https://api.github.com/repos/caddyserver/caddy/releases?per_page=50"
TAG_RE = r"v[0-9]+\.[0-9]+\.[0-9]+"


@dataclass(frozen=True)
class Decision:
    should_build: bool
    reason: str
    caddy_version: str
    revision: int
    recover: bool = False

    @property
    def package_version(self) -> str:
        return f"{self.caddy_version}+xcaddy.{self.revision}"


def fetch_releases(token: str | None = None) -> Any:
    request = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise ScriptError(f"GitHub releases API request failed: {last}")


def latest_stable(releases: Any) -> str:
    """Highest X.Y.Z among published, non-draft, non-prerelease releases."""
    if not isinstance(releases, list):
        raise ScriptError("releases response is not a JSON array")
    found: list[tuple[int, ...]] = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name")
        if isinstance(tag, str) and tag.startswith("v") and VERSION_RE.fullmatch(tag[1:]):
            found.append(tuple(int(p) for p in tag[1:].split(".")))
    if not found:
        raise ScriptError("no stable Caddy release found")
    return ".".join(str(p) for p in max(found))


def inputs_hash(root: Path) -> str:
    """Hash everything that changes the built package apart from the Caddy version."""
    files = [
        "scripts/build.py",
        "scripts/package.py",
        "scripts/common.py",
        "scripts/plugins.py",
        "scripts/lock.py",
        "config/plugins.lock",
        "apt/conf/distributions",
    ]
    files += sorted(
        p.relative_to(root).as_posix() for p in (root / "packaging").rglob("*") if p.is_file()
    )
    digest = hashlib.sha256()
    for name in files:
        try:
            content = (root / name).read_bytes()
        except OSError as exc:
            raise ScriptError(f"cannot read {name}: {exc}") from exc
        digest.update(f"{name}\0{hashlib.sha256(content).hexdigest()}\n".encode())
    digest.update("\n".join(load_plugins(root / "config/plugins.txt")).encode() + b"\0")
    toolchain_pins = (
        toolchain.XCADDY_VERSION,
        toolchain.GO_VERSION,
        toolchain.BUILD_FLAGS,
        *toolchain.BUILD_REPLACEMENTS,
    )
    digest.update("\0".join(toolchain_pins).encode())
    return digest.hexdigest()


def build_fingerprint(caddy_version: str, ihash: str) -> str:
    return hashlib.sha256(f"{caddy_version}\0{ihash}".encode()).hexdigest()


def _package_version(state: dict[str, Any]) -> str:
    try:
        version, revision = str(state["caddy_version"]), int(state["revision"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ScriptError("state file is invalid") from exc
    if not VERSION_RE.fullmatch(version):
        raise ScriptError(f"state file has malformed version {version!r}")
    return f"{version}+xcaddy.{revision}"


def _staged_ahead(public: dict[str, Any] | None, staged: dict[str, Any] | None) -> bool:
    """True when apt-repo holds a release the public repository has not (yet) served."""
    if staged is None:
        return False
    if public is None:
        return True
    if staged.get("release_id") == public.get("release_id"):
        return False
    return dpkg_compare(_package_version(staged), "gt", _package_version(public))


def decide(
    latest: str,
    state: dict[str, Any] | None,
    ihash: str,
    force: bool,
    status: dict[str, Any] | None = None,
    staged: dict[str, Any] | None = None,
) -> Decision:
    """Decide against the public state; a newer unconfirmed stage in apt-repo takes precedence."""
    if not VERSION_RE.fullmatch(latest):
        raise ScriptError(f"invalid latest version {latest!r}")
    if _staged_ahead(state, staged):
        state, status = staged, None
    if state is None:
        return Decision(True, "first-release", latest, 1)
    try:
        s_ver, s_rev = str(state["caddy_version"]), int(state["revision"])
        s_hash = state["inputs_hash"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ScriptError("state file is invalid") from exc
    if not VERSION_RE.fullmatch(s_ver):
        raise ScriptError(f"state file has malformed version {s_ver!r}")
    if dpkg_compare(latest, "lt", s_ver):
        raise ScriptError(f"latest {latest} is older than published {s_ver}; refusing a downgrade")
    if dpkg_compare(latest, "gt", s_ver):
        return Decision(True, "new-version", latest, 1)
    confirmed = (
        status is not None
        and status.get("status") == "PUBLISHED"
        and status.get("release_id") == state.get("release_id")
    )
    unconfirmed = not confirmed
    # force escapes a recovery whose packages are gone (build artifacts expire after 90 days).
    if s_hash == ihash and unconfirmed and not force:
        return Decision(False, "recover", latest, s_rev, recover=True)
    if s_hash != ihash:
        return Decision(True, "config-changed", latest, s_rev + 1)
    if force:
        return Decision(True, "forced", latest, s_rev + 1)
    return Decision(False, "unchanged", latest, s_rev)


def load_state(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file() or path.stat().st_size == 0:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScriptError(f"state file {path} is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise ScriptError(f"state file {path} is not a JSON object")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_latest = sub.add_parser("latest")
    p_latest.add_argument("--releases-file", type=Path)
    sub.add_parser("inputs-hash")
    p_dec = sub.add_parser("decide")
    p_dec.add_argument("--latest", required=True)
    p_dec.add_argument("--state", type=Path)
    p_dec.add_argument("--staged", type=Path, help="release-manifest.json staged in apt-repo")
    p_dec.add_argument("--status", type=Path, help="release-status.json of the published state")
    p_dec.add_argument("--inputs-hash", required=True)
    p_dec.add_argument("--force", choices=["true", "false"], default="false")
    p_dec.add_argument("--expect-package-version", help="fail when the decision differs")
    ns = parser.parse_args()

    if ns.command == "latest":
        if ns.releases_file:
            try:
                releases = json.loads(ns.releases_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ScriptError(f"cannot read releases file: {exc}") from exc
        else:
            releases = fetch_releases(os.environ.get("GITHUB_TOKEN"))
        print(latest_stable(releases))
    elif ns.command == "inputs-hash":
        print(inputs_hash(repo_root()))
    else:
        require_tools("dpkg")
        result = decide(
            ns.latest,
            load_state(ns.state),
            ns.inputs_hash,
            ns.force == "true",
            load_state(ns.status),
            load_state(ns.staged),
        )
        set_output("should_build", str(result.should_build).lower())
        set_output("reason", result.reason)
        set_output("caddy_version", result.caddy_version)
        set_output("revision", str(result.revision))
        set_output("package_version", result.package_version)
        set_output("recover", str(result.recover).lower())
        # A release already staged in apt-repo but unconfirmed is the expected one.
        reached = result.should_build or result.recover
        if ns.expect_package_version and (
            not reached or result.package_version != ns.expect_package_version
        ):
            raise ScriptError(
                f"state changed since the version check: decision is {result.package_version} "
                f"({result.reason}), expected {ns.expect_package_version}; re-run the workflow"
            )
        verdict = "build required" if result.should_build else "no new version, nothing to do"
        write_summary(f"### Version check\n\n{verdict} ({result.reason}): {result.package_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
