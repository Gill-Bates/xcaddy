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
    lock = {
        "plugins": [
            {**ROWS[0], "requested": "github.com/a/rate"},
            {**ROWS[1], "requested": "github.com/b/bouncer@v0.15.0"},
        ]
    }
    assert len(locked_plugins(["github.com/a/rate", "github.com/b/bouncer@v0.15.0"], lock)) == 2
    with pytest.raises(ScriptError, match="stale"):
        locked_plugins(["github.com/a/rate"], lock)
    with pytest.raises(ScriptError, match="pins"):
        locked_plugins(["github.com/a/rate@v0.2.0", "github.com/b/bouncer"], lock)


def test_changed_commit_pin_rejects_a_lock_for_an_older_request():
    old_commit = "0123456789abcdef0123456789abcdef01234567"
    new_commit = "abcdef0123456789abcdef0123456789abcdef01"
    lock = {"plugins": [{**ROWS[0], "requested": f"github.com/a/rate@{old_commit}"}]}

    with pytest.raises(ScriptError, match="request.*stale"):
        locked_plugins([f"github.com/a/rate@{new_commit}"], lock)


def test_sbom_lists_every_module():
    bom = sbom(parse_build_info(BUILD_INFO), "2.11.9")
    assert {c["name"] for c in bom["components"]} >= {"golang.org/x/net", "github.com/a/rate"}
    assert bom["bomFormat"] == "CycloneDX"


def test_build_info_ignores_everything_but_dependency_lines():
    text = "go\tgo1.27.4\npath\tx/y\nmod\tx/y\t(devel)\t\ndep\ta/b\tv1.0.0\nbuild\t-ldflags=-s\n"
    assert parse_build_info(text) == {"a/b": ("v1.0.0", "")}
    assert parse_build_info("") == {}


def test_a_locked_module_without_a_recorded_checksum_fails_the_build():
    deps = parse_build_info("dep\tgithub.com/a/rate\tv0.1.0\n")
    with pytest.raises(ScriptError, match="lock says"):
        verify_lock(deps, ROWS[:1])


def test_a_version_change_with_the_same_checksum_fails_the_build():
    deps = parse_build_info(BUILD_INFO.replace("v0.15.0", "v0.16.0"))
    with pytest.raises(ScriptError, match="github.com/b/bouncer"):
        verify_lock(deps, ROWS)


def test_unlocked_transitive_modules_do_not_fail_the_lock_check():
    verify_lock(parse_build_info(BUILD_INFO + "\tdep\texample.org/extra\tv9.9.9\th1:zzz\n"), ROWS)


def test_every_missing_module_is_reported_at_once():
    problems = missing_modules(ROWS, set())
    assert [p.split(":")[0] for p in problems] == ["github.com/a/rate", "github.com/b/bouncer"]
    assert missing_modules(ROWS, {"http.handlers.crowdsec", "http.handlers.rate_limit"}) == []
