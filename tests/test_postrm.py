#!/usr/bin/env python3
#
# tests/test_postrm.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import shutil
import subprocess

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
