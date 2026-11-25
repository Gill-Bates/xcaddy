#!/usr/bin/env python3
#
# tests/test_postrm.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import os
import shutil
import stat
import subprocess

import pytest

from common import repo_root


def test_purge_stays_inside_package_directories(tmp_path):
    data, conf, outside = tmp_path / "lib", tmp_path / "etc", tmp_path / "outside"
    for d in (data, conf, outside):
        d.mkdir()
    (outside / "keep.txt").write_text("precious")
    (data / "link").symlink_to(outside)
    (data / "cert.pem").write_text("tls identity")
    (conf / "Caddyfile").write_text("x")
    script = (repo_root() / "packaging/postrm").read_text()
    script = script.replace("/var/lib/caddy-custom", str(data)).replace(
        "/etc/caddy-custom", str(conf)
    )
    patched = tmp_path / "postrm"
    patched.write_text(script)
    sh = shutil.which("sh")
    result = subprocess.run([sh, str(patched), "purge"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not data.exists()
    assert not conf.exists()
    assert (outside / "keep.txt").read_text() == "precious"


def _patched_postrm(tmp_path, data, conf):
    script = (repo_root() / "packaging/postrm").read_text()
    script = script.replace("/var/lib/caddy-custom", str(data)).replace(
        "/etc/caddy-custom", str(conf)
    )
    patched = tmp_path / "postrm"
    patched.write_text(script)
    return patched


def _stub_bin(tmp_path, **bodies):
    """Directory of stub commands that shadow the real ones, so a test never touches accounts."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in bodies.items():
        stub = stubs / name
        stub.write_text(f"#!/bin/sh\n{body}\n")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stubs


def test_purge_removes_a_symlinked_package_directory_without_following_it(tmp_path):
    outside, conf = tmp_path / "outside", tmp_path / "etc"
    outside.mkdir()
    conf.mkdir()
    (outside / "keep.txt").write_text("precious")
    data = tmp_path / "lib"
    data.symlink_to(outside)
    patched = _patched_postrm(tmp_path, data, conf)
    stubs = _stub_bin(tmp_path, getent="exit 1")
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}
    result = subprocess.run(
        [shutil.which("sh"), str(patched), "purge"], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    assert not data.is_symlink()
    assert (outside / "keep.txt").read_text() == "precious"


def test_a_failing_removal_keeps_the_service_account(tmp_path):
    data, conf = tmp_path / "lib", tmp_path / "etc"
    data.mkdir()
    conf.mkdir()
    patched = _patched_postrm(tmp_path, data, conf)
    # A failed removal must not orphan remaining files under a deleted service UID.
    calls = tmp_path / "calls.log"
    stubs = _stub_bin(
        tmp_path,
        rm="exit 1",
        getent="exit 0",
        deluser=f'echo "$@" >> "{calls}"',
        delgroup=f'echo "$@" >> "{calls}"',
    )
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}
    result = subprocess.run(
        [shutil.which("sh"), str(patched), "purge"], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    assert "could not remove" in result.stderr
    assert not calls.exists()


def test_purge_does_not_enter_a_mounted_package_directory(tmp_path):
    data, conf = tmp_path / "lib", tmp_path / "etc"
    data.mkdir()
    conf.mkdir()
    (data / "cert.pem").write_text("tls identity")
    patched = _patched_postrm(tmp_path, data, conf)
    calls = tmp_path / "calls.log"
    stubs = _stub_bin(
        tmp_path,
        mountpoint="exit 0",
        rm=f'echo rm >> "{calls}"',
        getent="exit 0",
        deluser=f'echo deluser >> "{calls}"',
        delgroup=f'echo delgroup >> "{calls}"',
    )
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}
    result = subprocess.run(
        [shutil.which("sh"), str(patched), "purge"], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    assert "is a mount point" in result.stderr
    assert (data / "cert.pem").read_text() == "tls identity"
    assert not calls.exists()


def test_purge_leaves_a_package_directory_with_a_nested_mount_untouched(tmp_path):
    data, conf = tmp_path / "lib", tmp_path / "etc"
    (data / "bind").mkdir(parents=True)
    conf.mkdir()
    (data / "bind" / "other.txt").write_text("not ours")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"1 0 8:1 / {data}/bind rw - ext4 /dev/sda1 rw\n")
    patched = _patched_postrm(tmp_path, data, conf)
    patched.write_text(patched.read_text().replace("/proc/self/mountinfo", str(mountinfo)))
    calls = tmp_path / "calls.log"
    stubs = _stub_bin(
        tmp_path,
        getent="exit 0",
        deluser=f'echo deluser >> "{calls}"',
        delgroup=f'echo delgroup >> "{calls}"',
    )
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}
    result = subprocess.run(
        [shutil.which("sh"), str(patched), "purge"], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stderr
    assert "cannot rule out mount points" in result.stderr
    assert (data / "bind" / "other.txt").read_text() == "not ours"
    assert not conf.exists()
    assert not calls.exists()


def test_remove_keeps_configuration_and_data(tmp_path):
    data = tmp_path / "lib"
    data.mkdir()
    script = (
        (repo_root() / "packaging/postrm").read_text().replace("/var/lib/caddy-custom", str(data))
    )
    patched = tmp_path / "postrm"
    patched.write_text(script)
    subprocess.run([shutil.which("sh"), str(patched), "remove"], check=True)
    assert data.exists()


UNIT = "caddy-custom.service"


@pytest.fixture
def postinst(tmp_path):
    """Run the real postinst against the real deb-systemd-helper inside a DPKG_ROOT sandbox."""
    helper = shutil.which("deb-systemd-helper")
    if helper is None:
        pytest.skip("deb-systemd-helper not installed")
    root, bin_dir, log = tmp_path / "root", tmp_path / "bin", tmp_path / "invoke.log"
    unit_dir = root / "usr/lib/systemd/system"
    unit_dir.mkdir(parents=True)
    (root / "etc/systemd/system").mkdir(parents=True)
    (root / "var/lib/systemd/deb-systemd-helper-enabled").mkdir(parents=True)
    shutil.copyfile(repo_root() / "packaging" / UNIT, unit_dir / UNIT)
    bin_dir.mkdir()
    shims = {
        "getent": "exit 0",
        "install": 'for last; do :; done; mkdir -p "$last"',
        "systemctl": "exit 0",
        "caddy-custom": "exit 0",
        "deb-systemd-invoke": f'echo "$@" >> "{log}"',
    }
    for name, body in shims.items():
        shim = bin_dir / name
        shim.write_text(f"#!/bin/sh\n{body}\n")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    systemd_run = tmp_path / "run-systemd"
    script = (
        (repo_root() / "packaging/postinst")
        .read_text()
        .replace("/run/systemd/system", str(systemd_run))
        .replace("/usr/bin/caddy-custom", str(bin_dir / "caddy-custom"))
        .replace("/var/lib/caddy-custom", str(tmp_path / "lib"))
    )
    patched = tmp_path / "postinst"
    patched.write_text(script)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DPKG_ROOT": str(root),
        "DPKG_MAINTSCRIPT_PACKAGE": "caddy-custom",
        "DPKG_MAINTSCRIPT_NAME": "postinst",
        "DPKG_MAINTSCRIPT_ARCH": "amd64",
    }
    link = root / "etc/systemd/system/multi-user.target.wants" / UNIT

    def run_postinst(*args, systemd_running=False):
        systemd_run.mkdir(exist_ok=True) if systemd_running else None
        result = subprocess.run(
            [shutil.which("sh"), str(patched), "configure", *args],
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    return run_postinst, link, log


@pytest.mark.parametrize("systemd_running", [False, True])
def test_first_install_enables_the_service(postinst, systemd_running):
    run, link, _ = postinst
    run(systemd_running=systemd_running)
    assert link.is_symlink()


def test_first_install_starts_the_service_when_systemd_runs(postinst):
    run, _, log = postinst
    run(systemd_running=True)
    assert "start caddy-custom.service" in log.read_text()


def test_upgrade_keeps_an_enabled_service_enabled(postinst):
    run, link, _ = postinst
    run()
    run("1.0", systemd_running=True)
    assert link.is_symlink()


def test_upgrade_does_not_enable_a_service_the_admin_disabled(postinst):
    run, link, _ = postinst
    run()
    link.unlink()
    run("1.0", systemd_running=True)
    assert not link.is_symlink()
