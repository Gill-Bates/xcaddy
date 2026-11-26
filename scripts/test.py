#!/usr/bin/env python3
#
# scripts/test.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Install, upgrade and no-op tests of xcaddy against a locally signed APT repository."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import stat
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

NAME = "xcaddy"


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
    expect(Path("/usr/bin/caddy").is_file(), "binary installed")
    expect(Path("/etc/caddy/Caddyfile").is_file(), "config installed")
    expect(run(["getent", "passwd", "caddy"], check=False).returncode == 0, "caddy user exists")
    owner, group = pwd.getpwnam("caddy"), grp.getgrnam("caddy")
    data_stat = Path("/var/lib/caddy").stat()
    expect(
        (data_stat.st_uid, data_stat.st_gid, stat.S_IMODE(data_stat.st_mode))
        == (owner.pw_uid, group.gr_gid, 0o750),
        "Caddy data directory has standard ownership and permissions",
    )
    expect("www-data" in run(["id", "-Gn", "caddy"]).stdout.split(), "caddy belongs to www-data")
    if check_binary:
        run(["/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
        log("info", "ok: xcaddy validates the default Caddyfile")
        modules = set(run(["/usr/bin/caddy", "list-modules"]).stdout.splitlines())
        lock = json.loads(
            (Path(__file__).resolve().parent.parent / "config/plugins.lock").read_text(
                encoding="utf-8"
            )
        )
        for plugin in lock["plugins"]:
            required = set(plugin["module_ids"])
            alternatives = set(plugin["module_ids_any"])
            expect(required <= modules, f"required modules are present for {plugin['module']}")
            expect(
                not alternatives or bool(alternatives & modules),
                f"plugin module is present for {plugin['module']}",
            )
    if systemd_running():
        expect(
            run(["systemctl", "is-active", "--quiet", "caddy"], check=False).returncode == 0,
            "caddy.service is running",
        )
    if systemd_running():
        enabled = run(["systemctl", "is-enabled", "caddy"], check=False).stdout.strip()
        expect(enabled == "enabled", f"service is enabled (systemctl is-enabled: {enabled!r})")


def install_legacy_caddy(tmp: Path) -> None:
    """Install a file-compatible caddy package to exercise dpkg replacement semantics."""
    require_tools("dpkg", "dpkg-deb", "adduser")
    if (
        run(["dpkg-query", "-W", "-f=${Status}", "caddy"], check=False).stdout.strip()
        == "install ok installed"
    ):
        raise ScriptError("install test requires a host without an installed caddy package")
    stage = tmp / "legacy-caddy"
    for path in ("DEBIAN", "usr/bin", "usr/lib/systemd/system", "etc/caddy"):
        (stage / path).mkdir(parents=True, exist_ok=True)
    (stage / "DEBIAN/control").write_text(
        "Package: caddy\nVersion: 2.11.9-1\nArchitecture: all\n"
        "Maintainer: test <test@example.invalid>\nDepends: adduser\n"
        "Description: Caddy migration fixture\n",
        encoding="utf-8",
    )
    (stage / "DEBIAN/conffiles").write_text("/etc/caddy/Caddyfile\n", encoding="utf-8")
    (stage / "DEBIAN/postinst").write_text(
        "#!/bin/sh\nset -e\n"
        "if ! getent passwd caddy >/dev/null; then "
        "adduser --system --group --home /var/lib/caddy --shell /usr/sbin/nologin caddy; fi\n",
        encoding="utf-8",
    )
    (stage / "DEBIAN/postinst").chmod(0o755)
    (stage / "usr/bin/caddy").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (stage / "usr/bin/caddy").chmod(0o755)
    (stage / "etc/caddy/Caddyfile").write_text(
        ':18080 { respond "migration fixture" }\n', encoding="utf-8"
    )
    (stage / "usr/lib/systemd/system/caddy.service").write_text(
        "[Unit]\nDescription=Caddy\n[Service]\nType=notify\nUser=caddy\nGroup=caddy\n"
        "ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile\n"
        "[Install]\nWantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    deb = tmp / "caddy_2.11.9-1_all.deb"
    run(["dpkg-deb", "--root-owner-group", "--build", stage, deb])
    run(["dpkg", "-i", deb])
    Path("/var/lib/caddy/migration-marker").write_text("keep this data\n", encoding="utf-8")


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
                    caddy, _, revision = version.partition("+custom.")
                    publish.finalize(repo, fpr, caddy, int(revision), "test", [deb])
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
                run(
                    ["apt-get", "-y", *opts, "-o", "Dpkg::Options::=--force-confold", *args],
                    env=env,
                )

            apt("update")
            install_legacy_caddy(tmp)
            legacy_config = Path("/etc/caddy/Caddyfile").read_text(encoding="utf-8")
            apt("install", NAME)
            check_installed(old_v, check_binary)
            expect(
                Path("/etc/caddy/Caddyfile").read_text(encoding="utf-8") == legacy_config,
                "legacy Caddyfile is unchanged after replacement",
            )
            expect(
                Path("/var/lib/caddy/migration-marker").read_text(encoding="utf-8")
                == "keep this data\n",
                "legacy Caddy data is unchanged after replacement",
            )
            expect(
                run(["dpkg-query", "-W", "-f=${Status}", "caddy"], check=False).returncode != 0,
                "legacy caddy package is replaced",
            )
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
            expect(Path("/etc/caddy/Caddyfile").is_file(), "config kept on remove")
            expect(Path("/var/lib/caddy").is_dir(), "data kept on remove")
            apt("purge", NAME)
            expect(not Path("/etc/caddy").exists(), "config removed on purge")
            expect(not Path("/var/lib/caddy").exists(), "data removed on purge")
            gone = run(["getent", "passwd", "caddy"], check=False).returncode != 0
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
    apt.add_argument("--check-binary", action="store_true", help="run xcaddy validate")
    ns = parser.parse_args()
    apt_flow(ns.old_deb, ns.new_deb, ns.check_binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
