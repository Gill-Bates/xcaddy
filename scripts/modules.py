#!/usr/bin/env python3
#
# scripts/plugins.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Parse and validate config/plugins.txt; entries are matched, never executed."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from common import ScriptError, repo_root, run_main

PLUGIN_RE = re.compile(
    r"github\.com/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*(/v[0-9]+)?"
    r"(@(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|[0-9a-f]{40}))?"
)


def parse_plugins(text: str, name: str = "plugins") -> list[str]:
    """Return the entries; report every invalid or duplicate line in one error."""
    entries: list[str] = []
    seen: dict[str, int] = {}
    errors: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        if not PLUGIN_RE.fullmatch(entry):
            errors.append(f"{name}:{lineno}: invalid plugin entry {entry!r}")
            continue
        module = entry.split("@", 1)[0]
        if module in seen:
            errors.append(f"{name}:{lineno}: duplicate plugin {module!r} (line {seen[module]})")
            continue
        seen[module] = lineno
        entries.append(entry)
    if errors:
        raise ScriptError("\n".join(errors))
    return entries


def load_plugins(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScriptError(f"cannot read {path}: {exc}") from exc
    return parse_plugins(text, str(path))


def xcaddy_args(entries: list[str]) -> list[str]:
    return [arg for entry in entries for arg in ("--with", entry)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or print the plugin list.")
    parser.add_argument("command", choices=["validate", "list", "args"])
    parser.add_argument("file", nargs="?", type=Path, default=repo_root() / "config/plugins.txt")
    ns = parser.parse_args()
    entries = load_plugins(ns.file)
    if ns.command == "validate":
        print(f"plugins ok: {len(entries)} entries")
    elif ns.command == "list":
        print("\n".join(entries))
    else:
        print("\n".join(xcaddy_args(entries)))
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
