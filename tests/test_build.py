#!/usr/bin/env python3
#
# tests/test_build.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import pytest

from build import locked_args, missing_modules, parse_build_info, sbom, verify_lock
from common import ScriptError
from lock import locked_plugins

ROWS = [
    {
        "module": "github.com/a/rate",
        "version": "v0.1.0",
        "sum": "h1:aaa",
        "module_ids": ["http.handlers.rate_limit"],
        "module_ids_any": ["http.handlers.rate_limit"],
    },
    {
        "module": "github.com/b/bouncer",
        "version": "v0.15.0",
        "sum": "h1:bbb",
        "module_ids": [],
        "module_ids_any": ["crowdsec", "http.handlers.crowdsec"],
    },
]
BUILD_INFO = """caddy: go1.27.4
\tpath\tgithub.com/caddyserver/caddy/v2/cmd/caddy
\tdep\tgithub.com/a/rate\tv0.1.0\th1:aaa
\tdep\tgithub.com/b/bouncer\tv0.15.0\th1:bbb
\tdep\tgolang.org/x/net\tv0.30.0\th1:ccc
"""


def test_build_info_is_parsed_into_versions_and_sums():
    deps = parse_build_info(BUILD_INFO)
    assert deps["golang.org/x/net"] == ("v0.30.0", "h1:ccc")
    verify_lock(deps, ROWS)


def test_checksum_or_version_drift_fails_the_build():
    deps = parse_build_info(BUILD_INFO.replace("h1:aaa", "h1:evil"))
    with pytest.raises(ScriptError, match="lock says"):
        verify_lock(deps, ROWS)
    with pytest.raises(ScriptError, match="not in the binary"):
        verify_lock({}, ROWS)


def test_module_ids_are_checked_against_list_modules():
    assert missing_modules(ROWS, {"http.handlers.rate_limit", "crowdsec"}) == []
    assert missing_modules(ROWS, {"crowdsec"}) == [
        "github.com/a/rate: http.handlers.rate_limit missing"
    ]
    assert len(missing_modules(ROWS, {"http.handlers.rate_limit"})) == 1


def test_build_uses_only_locked_versions():
    assert locked_args(ROWS)[:2] == ["--with", "github.com/a/rate@v0.1.0"]


def test_stale_lock_is_rejected():
    lock = {"plugins": ROWS}
    assert len(locked_plugins(["github.com/a/rate", "github.com/b/bouncer@v0.15.0"], lock)) == 2
    with pytest.raises(ScriptError, match="stale"):
        locked_plugins(["github.com/a/rate"], lock)
    with pytest.raises(ScriptError, match="pins"):
        locked_plugins(["github.com/a/rate@v0.2.0", "github.com/b/bouncer"], lock)


def test_sbom_lists_every_module():
    bom = sbom(parse_build_info(BUILD_INFO), "2.11.9")
    assert {c["name"] for c in bom["components"]} >= {"golang.org/x/net", "github.com/a/rate"}
    assert bom["bomFormat"] == "CycloneDX"
