#!/usr/bin/env python3
#
# scripts/test.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Install, upgrade and no-op tests of caddy-custom against a locally signed APT repository."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import publish
from common import (
    ScriptError,
    host_arch,
    log,
    require_tools,
    run,
    run_main,
)
from package import validate_deb

NAME = "caddy-custom"


def installed_version() -> str:
    return run(["dpkg-query", "--showformat=${Version}", "--show", NAME]).stdout.strip()


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ScriptError(f"install test failed: {message}")
    log("info", f"ok: {message}")


def systemd_running() -> bool:
    return Path("/run/systemd/system").is_dir()


def check_installed(version: str, check_binary: bool) -> None:
    expect(installed_version() == version, f"installed version is {version}")
    expect(Path("/usr/bin/caddy-custom").is_file(), "binary installed")
    expect(Path("/etc/caddy-custom/Caddyfile").is_file(), "config installed")
    expect(run(["getent", "passwd", NAME], check=False).returncode == 0, "service user exists")
    if check_binary:
        run(["/usr/bin/caddy-custom", "validate", "--config", "/etc/caddy-custom/Caddyfile"])
        log("info", "ok: caddy-custom validates the default Caddyfile")
    if systemd_running():
        enabled = run(["systemctl", "is-enabled", NAME], check=False).stdout.strip()
        expect(enabled == "enabled", f"service is enabled (systemctl is-enabled: {enabled!r})")


def apt_flow(old_deb: Path, new_deb: Path, check_binary: bool) -> None:
    if os.geteuid() != 0:
        raise ScriptError("the install test needs root")
    require_tools("apt-get", "dpkg-query", "reprepro", "gpg")
    arch = host_arch()
    old_v, new_v = (publish.deb_field(d, "Version") for d in (old_deb, new_deb))
    for deb, version in ((old_deb, old_v), (new_deb, new_v)):
        validate_deb(deb, arch, version)
    with tempfile.TemporaryDirectory(prefix="apt-test-") as tmp_name:
        tmp = Path(tmp_name)
        os.environ["GNUPGHOME"] = str(tmp / "gnupg")
        try:
            fpr = publish.make_throwaway_key(tmp / "gnupg")
            repo, site = tmp / "repo", tmp / "site"
            repo.mkdir()
            publish.init_repo(repo, fpr)

            def publish_deb(deb: Path, version: str) -> bool:
                added = publish.add_packages(repo, [deb], (arch,))
                if added:
                    publish.finalize(repo, fpr, version.split("+")[0], 1, "test", [deb])
                    publish.export_site(repo, site)
                    publish.verify_site(site, (arch,), fingerprint=fpr)
                return added

            expect(publish_deb(old_deb, old_v), "first version published and signature verified")
            sources = tmp / "sources.list"
            key = publish.install_apt_key(site / "gpg.key", tmp / "keyrings")
            sources.write_text(f"deb [signed-by={key}] file:{site} stable main\n", encoding="utf-8")
            for sub in ("lists/partial", "cache/archives/partial"):
                (tmp / sub).mkdir(parents=True)
            opts = [
                "-o", f"Dir::Etc::sourcelist={sources}", "-o", "Dir::Etc::sourceparts=/dev/null",
                "-o", f"Dir::State::lists={tmp}/lists", "-o", f"Dir::Cache={tmp}/cache",
                "-o", "APT::Sandbox::User=root",
            ]  # fmt: skip
            env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}

            def apt(*args: str) -> None:
                run(["apt-get", "-y", *opts, *args], env=env)

            apt("update")
            apt("install", NAME)
            check_installed(old_v, check_binary)
            expect(publish_deb(new_deb, new_v), "newer version published")
            # stale lists and an empty archive cache: the old index must still resolve to a file
            apt("clean")
            apt("install", "--reinstall", NAME)
            check_installed(old_v, check_binary)
            apt("update")
            apt("install", "--only-upgrade", NAME)
            check_installed(new_v, check_binary)
            expect(not publish_deb(new_deb, new_v), "repeated run without change is a no-op")
            apt("remove", NAME)
            expect(Path("/etc/caddy-custom/Caddyfile").is_file(), "config kept on remove")
            expect(Path("/var/lib/caddy-custom").is_dir(), "data kept on remove")
            apt("purge", NAME)
            expect(not Path("/etc/caddy-custom").exists(), "config removed on purge")
            expect(not Path("/var/lib/caddy-custom").exists(), "data removed on purge")
            gone = run(["getent", "passwd", NAME], check=False).returncode != 0
            expect(gone, "service user removed on purge")
        finally:
            publish.cleanup_keyring()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    apt = sub.add_parser("apt", help="install, upgrade, remove and purge via a local signed repo")
    apt.add_argument("--old-deb", required=True, type=Path)
    apt.add_argument("--new-deb", required=True, type=Path)
    apt.add_argument("--allow-host-changes", action="store_true", required=True)
    apt.add_argument("--check-binary", action="store_true", help="run caddy-custom validate")
    ns = parser.parse_args()
    apt_flow(ns.old_deb, ns.new_deb, ns.check_binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
