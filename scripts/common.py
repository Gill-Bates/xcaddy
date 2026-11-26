#!/usr/bin/env python3
#
# scripts/common.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared helpers for the xcaddy scripts."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PACKAGE_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\+custom\.[0-9]+")
__author__ = "xcaddy maintainers"
HELP_URL = "https://github.com/Gill-Bates/xcaddy#readme"
ARCHS = ("amd64", "arm64")
ELF_MACHINES = {"amd64": 0x3E, "arm64": 0xB7}


class ScriptError(Exception):
    """A failure that must stop the run with a readable message."""


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def run(
    cmd: Sequence[str | os.PathLike[str]],
    *,
    check: bool = True,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a program without a shell; secrets must go through input_text, never argv."""
    args = [str(c) for c in cmd]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, env=env, cwd=cwd, input=input_text, check=False
        )
    except FileNotFoundError as exc:
        raise ScriptError(f"tool not found: {args[0]}") from exc
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[-2000:]
        raise ScriptError(f"{' '.join(args[:3])} failed with exit {proc.returncode}: {detail}")
    return proc


def require_tools(*names: str) -> None:
    missing = [n for n in names if shutil.which(n) is None]
    if missing:
        raise ScriptError(f"missing tools: {', '.join(missing)}")


def dpkg_compare(left: str, op: str, right: str) -> bool:
    return run(["dpkg", "--compare-versions", left, op, right], check=False).returncode == 0


def elf_arch(path: Path) -> str:
    """Return amd64, arm64 or unknown from the ELF header; raise for non-ELF files."""
    header = path.read_bytes()[:20]
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ScriptError(f"{path} is not an ELF file")
    machine = int.from_bytes(header[18:20], "little")
    return next((a for a, m in ELF_MACHINES.items() if m == machine), "unknown")


def host_arch() -> str:
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine(), "unknown"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_summary(text: str) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text.rstrip("\n") + "\n")


def set_output(key: str, value: str) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"{key}={value}\n")
    print(f"{key}={value}")


def _neutralize(text: str) -> str:
    """Keep untrusted text on one line and break GitHub workflow-command tokens."""
    return re.sub(r"^(\s*)::", r"\1: :", " ".join(str(text).splitlines()))


def log(level: str, message: str) -> None:
    """Print one line carrying its level once: info, warning or error."""
    text = _neutralize(message)
    if level == "info":
        print(text, flush=True)
    elif os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{text}", flush=True)
    else:
        print(f"{level.upper()}: {text}", flush=True)


def _git(*args: str) -> str | None:
    cmd = ["git", "-C", str(Path(__file__).resolve().parent), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return (proc.stdout.strip() or None) if proc.returncode == 0 else None


def print_header(script: str, doc: str | None) -> None:
    summary = (doc or "").strip().splitlines()
    commit = _git("rev-parse", "HEAD") or os.environ.get("GITHUB_SHA") or "unknown"
    name = Path(script).name
    log("info", f"Script: {name}")
    log("info", f"Description: {summary[0] if summary else ''}")
    log("info", f"Version: {commit}")
    log("info", f"Source: {_git('ls-files', '--full-name', '--', name) or 'unknown'}")
    log("info", f"Author: {__author__}")
    log("info", f"Help: {HELP_URL}")


def run_main(func: Callable[[], int | None], script: str, doc: str | None) -> int:
    """Print the header, run func and turn a ScriptError into a logged failure."""
    print_header(script, doc)
    try:
        return func() or 0
    except ScriptError as exc:
        log("error", str(exc))
        return 1
