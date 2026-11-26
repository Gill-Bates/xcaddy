#!/usr/bin/env python3
#
# tests/test_modules.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import pytest

from common import ScriptError
from modules import (
    check_registered,
    load_modules,
    parse_modules,
    registry_paths,
    xcaddy_args,
)

GOOD = """
# comment

github.com/caddy-dns/cloudflare   # inline
github.com/mholt/caddy-ratelimit@v0.1.0
github.com/example/module/v2@0123456789abcdef0123456789abcdef01234567
"""


def test_shipped_modules_file_is_valid(tmp_path):
    from common import repo_root

    assert load_modules(repo_root() / "config/modules.txt")


def test_parse_normalizes_entries():
    assert parse_modules(GOOD) == [
        "github.com/caddy-dns/cloudflare",
        "github.com/mholt/caddy-ratelimit@v0.1.0",
        "github.com/example/module/v2@0123456789abcdef0123456789abcdef01234567",
    ]


def test_xcaddy_args_are_with_pairs():
    assert xcaddy_args(["github.com/a/b", "github.com/c/d@v1.0.0"]) == [
        "--with",
        "github.com/a/b",
        "--with",
        "github.com/c/d@v1.0.0",
    ]


@pytest.mark.parametrize(
    "bad",
    [
        "github.com/a/b;rm -rf /",
        "gitlab.com/a/b",
        "github.com/a",
        "github.com/a/b@main",
        "github.com/a/b@v1.2",
        "$(id)",
        "github.com/a/b c",
    ],
)
def test_invalid_entries_are_rejected(bad):
    with pytest.raises(ScriptError):
        parse_modules(bad)


def test_duplicates_are_rejected_regardless_of_version():
    with pytest.raises(ScriptError, match="duplicate"):
        parse_modules("github.com/a/b\ngithub.com/a/b@v1.0.0\n")


def test_all_errors_are_reported_together():
    with pytest.raises(ScriptError) as info:
        parse_modules("bad one\nbad two\n")
    assert str(info.value).count("invalid") == 2


def test_crlf_and_empty_input():
    assert parse_modules("github.com/a/b\r\n") == ["github.com/a/b"]
    assert parse_modules("") == []


def test_missing_file_fails(tmp_path):
    with pytest.raises(ScriptError):
        load_modules(tmp_path / "nope.txt")


def _registry(*rows):
    return {"status_code": 200, "result": list(rows)}


def test_registered_modules_pass_the_registry_check():
    paths = registry_paths(_registry({"path": "github.com/a/b", "listed": True, "available": True}))
    check_registered(["github.com/a/b@v1.0.0"], paths)


def test_unregistered_module_fails_with_its_name():
    paths = registry_paths(_registry({"path": "github.com/a/b", "listed": True, "available": True}))
    with pytest.raises(ScriptError, match="github.com/x/y"):
        check_registered(["github.com/a/b", "github.com/x/y"], paths)


def test_unlisted_or_unavailable_packages_do_not_count():
    rows = [
        {"path": "github.com/a/hidden", "listed": False, "available": True},
        {"path": "github.com/a/gone", "listed": True, "available": False},
        {"path": "github.com/a/ok", "listed": True, "available": True},
    ]
    assert registry_paths(_registry(*rows)) == {"github.com/a/ok"}


@pytest.mark.parametrize("payload", [{}, [], {"result": []}, {"result": "x"}])
def test_an_empty_or_malformed_registry_answer_fails_closed(payload):
    with pytest.raises(ScriptError):
        registry_paths(payload)
