#!/usr/bin/env python3
#
# scripts/lock.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Resolve config/plugins.txt to config/plugins.lock (versions, h1 checksums, Caddy module IDs)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from common import ScriptError, repo_root, run_main
from plugins import load_plugins

PROXY = "https://proxy.golang.org"
MAX_ZIP = 100 * 1024 * 1024
ID_RE = re.compile(
    r"CaddyModule\(\)\s+caddy\.ModuleInfo\s*\{\s*return\s+caddy\.ModuleInfo\{\s*ID:\s*\"([^\"]+)\""
)
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


def escape_path(path: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def dirhash(files: dict[str, bytes]) -> str:
    """Go's dirhash h1 checksum (the value in go.sum)."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n".encode())
    return "h1:" + base64.b64encode(digest.digest()).decode()


def _get(url: str, limit: int = MAX_ZIP) -> bytes:
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ScriptError(f"{url} is larger than {limit} bytes")
            return data
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise ScriptError(f"cannot download {url}: {last}")


def module_ids(files: dict[str, bytes], prefix: str) -> tuple[list[str], list[str]]:
    root: set[str] = set()
    anywhere: set[str] = set()
    for name, data in files.items():
        rel = name[len(prefix) :]
        if not rel.endswith(".go") or rel.endswith("_test.go"):
            continue
        found = set(ID_RE.findall(data.decode("utf-8", errors="replace")))
        anywhere |= found
        if "/" not in rel:
            root |= found
    return sorted(root), sorted(anywhere)


def resolve(entry: str) -> dict[str, Any]:
    module, _, requested = entry.partition("@")
    esc = escape_path(module)
    if requested:
        info = json.loads(_get(f"{PROXY}/{esc}/@v/{requested}.info", 1 << 20))
    else:
        info = json.loads(_get(f"{PROXY}/{esc}/@latest", 1 << 20))
    version = info["Version"]
    zip_bytes = _get(f"{PROXY}/{esc}/@v/{escape_path(version)}.zip")
    gomod = _get(f"{PROXY}/{esc}/@v/{escape_path(version)}.mod", 1 << 20)
    prefix = f"{module}@{version}/"
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            if not item.filename.startswith(prefix):
                raise ScriptError(f"{entry}: unexpected path {item.filename} in module zip")
            files[item.filename] = archive.read(item)
    root_ids, any_ids = module_ids(files, prefix)
    if not any_ids:
        raise ScriptError(f"{entry}: no Caddy module ID found in the module sources")
    return {
        "module": module,
        "requested": entry,
        "version": version,
        "sum": dirhash(files),
        "go_mod_sum": dirhash({"go.mod": gomod}),
        "module_ids": root_ids,
        "module_ids_any": any_ids,
    }


def load_lock(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScriptError(
            f"cannot read lock file {path}: {exc}; run scripts/lock.py update"
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
        raise ScriptError(f"{path} is not a valid lock file")
    return data


def locked_plugins(entries: list[str], lock: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the lock rows for entries; fail when the lock does not match plugins.txt."""
    by_module = {row["module"]: row for row in lock["plugins"]}
    wanted = {e.split("@", 1)[0]: e for e in entries}
    if set(by_module) != set(wanted):
        raise ScriptError("plugins.lock is stale (plugin set differs); run scripts/lock.py update")
    rows = []
    for module, entry in wanted.items():
        row = by_module[module]
        pinned = entry.partition("@")[2]
        if pinned and not COMMIT_RE.fullmatch(pinned) and row["version"] != pinned:
            raise ScriptError(f"plugins.lock pins {module} at {row['version']}, not {pinned}")
        if not str(row.get("sum", "")).startswith("h1:"):
            raise ScriptError(f"plugins.lock has no checksum for {module}")
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["update", "check"])
    parser.add_argument("--plugins-file", type=Path, default=repo_root() / "config/plugins.txt")
    parser.add_argument("--lock-file", type=Path, default=repo_root() / "config/plugins.lock")
    ns = parser.parse_args()
    entries = load_plugins(ns.plugins_file)
    if ns.command == "check":
        locked_plugins(entries, load_lock(ns.lock_file))
        print("plugins.lock matches plugins.txt")
        return 0
    rows = []
    for entry in entries:
        row = resolve(entry)
        print(f"locked {row['module']} {row['version']} {row['sum']} ids={row['module_ids_any']}")
        rows.append(row)
    ns.lock_file.write_text(json.dumps({"version": 1, "plugins": rows}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
