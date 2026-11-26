#!/usr/bin/env python3
#
# scripts/modules.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Parse and validate config/modules.txt; entries are matched, never executed."""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from common import ScriptError, repo_root, run_main

MODULE_RE = re.compile(
    r"github\.com/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*(/v[0-9]+)?"
    r"(@(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|[0-9a-f]{40}))?"
)


def parse_modules(text: str, name: str = "modules") -> list[str]:
    """Return the entries; report every invalid or duplicate line in one error."""
    entries: list[str] = []
    seen: dict[str, int] = {}
    errors: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        if not MODULE_RE.fullmatch(entry):
            errors.append(f"{name}:{lineno}: invalid module entry {entry!r}")
            continue
        module = entry.split("@", 1)[0]
        if module in seen:
            errors.append(f"{name}:{lineno}: duplicate module {module!r} (line {seen[module]})")
            continue
        seen[module] = lineno
        entries.append(entry)
    if errors:
        raise ScriptError("\n".join(errors))
    return entries


def load_modules(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScriptError(f"cannot read {path}: {exc}") from exc
    return parse_modules(text, str(path))


REGISTRY_URL = "https://caddyserver.com/api/packages"
MAX_REGISTRY = 64 * 1024 * 1024


def fetch_registry_paths(url: str = REGISTRY_URL, attempts: int = 4) -> set[str]:
    """Paths of the listed, available packages of Caddy's module registry; fails closed."""
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                raw = response.read(MAX_REGISTRY + 1)
            if len(raw) > MAX_REGISTRY:
                raise ScriptError(f"{url} is larger than {MAX_REGISTRY} bytes")
            return registry_paths(json.loads(raw))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(2 * (attempt + 1))
    raise ScriptError(f"cannot read the Caddy module registry {url}: {last}")


def registry_paths(payload: object) -> set[str]:
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, list) or not result:
        raise ScriptError("the Caddy module registry returned no package list")
    paths = {
        p["path"]
        for p in result
        if isinstance(p, dict)
        and isinstance(p.get("path"), str)
        and p.get("listed")
        and p.get("available")
    }
    if not paths:
        raise ScriptError("the Caddy module registry lists no available package")
    return paths


def check_registered(entries: list[str], paths: set[str]) -> None:
    """Fail unless every entry is a package of the official registry."""
    missing = sorted({e.split("@", 1)[0] for e in entries} - paths)
    if missing:
        raise ScriptError(
            "modules not registered in the official Caddy module registry "
            f"({REGISTRY_URL}): {', '.join(missing)}"
        )


def xcaddy_args(entries: list[str]) -> list[str]:
    return [arg for entry in entries for arg in ("--with", entry)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or print the module list.")
    parser.add_argument("command", choices=["validate", "check-registry", "list", "args"])
    parser.add_argument("file", nargs="?", type=Path, default=repo_root() / "config/modules.txt")
    ns = parser.parse_args()
    entries = load_modules(ns.file)
    if ns.command == "validate":
        print(f"modules ok: {len(entries)} entries")
    elif ns.command == "check-registry":
        check_registered(entries, fetch_registry_paths())
        print(f"registry ok: {len(entries)} entries are registered")
    elif ns.command == "list":
        print("\n".join(entries))
    else:
        print("\n".join(xcaddy_args(entries)))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
