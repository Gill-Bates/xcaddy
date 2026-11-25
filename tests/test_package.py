#!/usr/bin/env python3
#
# tests/test_package.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import shutil

import pytest

from common import ScriptError, elf_arch, repo_root, run
from package import build_package, validate_deb

pytestmark = pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="dpkg-deb not installed")


def test_elf_arch_reads_header(fake_elf):
    assert elf_arch(fake_elf("amd64")) == "amd64"
    assert elf_arch(fake_elf("arm64", "other")) == "arm64"


def test_elf_arch_rejects_non_elf(tmp_path):
    path = tmp_path / "x"
    path.write_text("not elf")
    with pytest.raises(ScriptError):
        elf_arch(path)


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_package_is_valid_and_standalone(arch, fake_elf, tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text("{}")
    deb = build_package("2.11.9+custom.2", arch, fake_elf(arch), manifest, tmp_path / "out")
    assert deb.name == f"caddy-custom_2.11.9+custom.2_{arch}.deb"
    names = run(["dpkg-deb", "--contents", deb]).stdout
    assert "./usr/bin/caddy-custom" in names
    assert "/usr/bin/caddy\n" not in names


def test_wrong_architecture_is_rejected(fake_elf, tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text("{}")
    with pytest.raises(ScriptError, match="arm64"):
        build_package("2.11.9+custom.1", "arm64", fake_elf("amd64"), manifest, tmp_path / "o")


def test_validation_detects_wrong_version(fake_elf, tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text("{}")
    deb = build_package("2.11.9+custom.1", "amd64", fake_elf("amd64"), manifest, tmp_path / "o")
    with pytest.raises(ScriptError, match="Version"):
        validate_deb(deb, "amd64", "2.11.9+custom.2")


def test_maintainer_scripts_exist():
    for name in ("postinst", "prerm", "postrm"):
        assert (repo_root() / "packaging" / name).is_file()
