#!/usr/bin/env python3
#
# scripts/package.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Assemble and validate the xcaddy .deb with dpkg-deb."""

from __future__ import annotations

import argparse
import math
import os
import shutil
import tempfile
import time
from pathlib import Path

from common import (
    ARCHS,
    PACKAGE_VERSION_RE,
    ScriptError,
    elf_arch,
    repo_root,
    require_tools,
    run,
    run_main,
)

DOC_DIR = "usr/share/doc/xcaddy"
SCRIPTS = ("postinst", "prerm", "postrm")
ALLOWED_FILES = (
    "./usr/bin/caddy",
    "./usr/lib/systemd/system/caddy.service",
)
ALLOWED_PREFIXES = (
    "./etc/caddy/",
    f"./{DOC_DIR}/",
)
REQUIRED = (
    "./usr/bin/caddy",
    "./usr/lib/systemd/system/caddy.service",
    "./etc/caddy/Caddyfile",
    f"./{DOC_DIR}/build-manifest.json",
)
PARENT_DIRS = (
    "./",
    "./usr/",
    "./usr/bin/",
    "./usr/lib/",
    "./usr/lib/systemd/",
    "./usr/lib/systemd/system/",
    "./usr/share/",
    "./usr/share/doc/",
    "./etc/",
)


def build_package(version: str, arch: str, binary: Path, manifest: Path, out: Path) -> Path:
    if not PACKAGE_VERSION_RE.fullmatch(version):
        raise ScriptError(f"invalid --version {version!r}")
    if elf_arch(binary) != arch:
        raise ScriptError(f"binary is not a {arch} ELF")
    require_tools("dpkg-deb")
    root = repo_root()
    out.mkdir(parents=True, exist_ok=True)
    deb = out / f"xcaddy_{version}_{arch}.deb"
    with tempfile.TemporaryDirectory(prefix="xcaddy-pkg-") as tmp:
        stage = Path(tmp) / "pkg"
        for sub in ("DEBIAN", "usr/bin", "usr/lib/systemd/system", "etc/caddy", DOC_DIR):
            (stage / sub).mkdir(parents=True)
        files = {
            binary: ("usr/bin/caddy", 0o755),
            root / "packaging/caddy.service": (
                "usr/lib/systemd/system/caddy.service",
                0o644,
            ),
            root / "packaging/Caddyfile": ("etc/caddy/Caddyfile", 0o644),
            root / "packaging/copyright": (f"{DOC_DIR}/copyright", 0o644),
            manifest: (f"{DOC_DIR}/build-manifest.json", 0o644),
            **{root / f"packaging/{s}": (f"DEBIAN/{s}", 0o755) for s in SCRIPTS},
        }
        for src, (dest, mode) in files.items():
            shutil.copyfile(src, stage / dest)
            (stage / dest).chmod(mode)
        (stage / "DEBIAN/conffiles").write_text("/etc/caddy/Caddyfile\n", encoding="utf-8")
        size = sum(
            p.stat().st_size for p in stage.rglob("*") if p.is_file() and "DEBIAN" not in p.parts
        )
        control = (root / "packaging/control").read_text(encoding="utf-8")
        for key, value in (
            ("@VERSION@", version),
            ("@ARCH@", arch),
            ("@INSTALLED_SIZE@", str(math.ceil(size / 1024))),
        ):
            control = control.replace(key, value)
        (stage / "DEBIAN/control").write_text(control, encoding="utf-8")
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or _commit_epoch(root))
        for path in [stage, *stage.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        stage.chmod(0o755)
        run(
            ["dpkg-deb", "--root-owner-group", "-Zxz", "--build", stage, deb],
            env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch)},
        )
    validate_deb(deb, arch, version)
    return deb


def _commit_epoch(root: Path) -> int:
    proc = run(["git", "-C", root, "log", "-1", "--format=%ct"], check=False)
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return int(time.time())


def validate_deb(deb: Path, arch: str, version: str) -> None:
    """Check metadata, contents, permissions and maintainer scripts; raise on any problem."""
    require_tools("dpkg-deb", "sh")
    problems: list[str] = []
    print(run(["dpkg-deb", "--info", deb]).stdout)
    contents = run(["dpkg-deb", "--contents", deb]).stdout
    print(contents)
    for field, want in (
        ("Package", "xcaddy"),
        ("Version", version),
        ("Architecture", arch),
        ("Provides", "caddy"),
        ("Conflicts", "caddy"),
        ("Replaces", "caddy"),
    ):
        got = run(["dpkg-deb", "--field", deb, field]).stdout.strip()
        if got != want:
            problems.append(f"{field} is {got!r}, expected {want!r}")
    modes = {}
    for line in contents.splitlines():
        parts = line.split()
        modes[parts[-1]] = parts[0]
    for need in REQUIRED:
        if need not in modes:
            problems.append(f"missing {need}")
    for path in modes:
        if not (path in PARENT_DIRS or path in ALLOWED_FILES or path.startswith(ALLOWED_PREFIXES)):
            problems.append(f"unexpected path {path} (conflict risk with other packages)")
    if modes.get("./usr/bin/caddy") != "-rwxr-xr-x":
        problems.append("caddy binary must be -rwxr-xr-x")
    with tempfile.TemporaryDirectory(prefix="xcaddy-ctrl-") as tmp:
        ctrl = Path(tmp) / "ctrl"
        run(["dpkg-deb", "--control", deb, ctrl])
        for name in SCRIPTS:
            script = ctrl / name
            if not script.is_file() or not os.access(script, os.X_OK):
                problems.append(f"maintainer script {name} missing or not executable")
            elif run(["sh", "-n", script], check=False).returncode != 0:
                problems.append(f"maintainer script {name} has a syntax error")
        if (ctrl / "conffiles").read_text(encoding="utf-8").split() != [
            "/etc/caddy/Caddyfile"
        ]:
            problems.append("conffiles must list exactly /etc/caddy/Caddyfile")
    if problems:
        raise ScriptError("package validation failed:\n" + "\n".join(problems))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--version", required=True)
    build.add_argument("--arch", required=True, choices=ARCHS)
    build.add_argument("--binary", required=True, type=Path)
    build.add_argument("--manifest", required=True, type=Path)
    build.add_argument("--out", required=True, type=Path)
    check = sub.add_parser("validate")
    check.add_argument("deb", type=Path)
    check.add_argument("--version", required=True)
    check.add_argument("--arch", required=True, choices=ARCHS)
    ns = parser.parse_args()
    if ns.command == "build":
        print(build_package(ns.version, ns.arch, ns.binary, ns.manifest, ns.out))
    else:
        validate_deb(ns.deb, ns.arch, ns.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
