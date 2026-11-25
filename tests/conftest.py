#!/usr/bin/env python3
#
# tests/conftest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared fixtures."""

import pytest

ELF_MACHINE = {"amd64": 0x3E, "arm64": 0xB7}


@pytest.fixture
def fake_elf(tmp_path):
    """Create a file with a valid ELF header for the given architecture."""

    def make(arch: str, name: str = "caddy"):
        header = b"\x7fELF\x02\x01\x01" + bytes(11) + ELF_MACHINE[arch].to_bytes(2, "little")
        path = tmp_path / name
        path.write_bytes(header + bytes(100))
        path.chmod(0o755)
        return path

    return make
