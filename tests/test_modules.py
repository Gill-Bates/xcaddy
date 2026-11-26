#!/usr/bin/env python3
#
# tests/test_plugins.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import pytest

from common import ScriptError
from plugins import load_plugins, parse_plugins, xcaddy_args

GOOD = """
# comment

github.com/caddy-dns/cloudflare   # inline
github.com/mholt/caddy-ratelimit@v0.1.0
github.com/example/plugin/v2@0123456789abcdef0123456789abcdef01234567
"""


def test_shipped_plugins_file_is_valid(tmp_path):
    from common import repo_root

    assert load_plugins(repo_root() / "config/plugins.txt")


def test_parse_normalizes_entries():
    assert parse_plugins(GOOD) == [
        "github.com/caddy-dns/cloudflare",
        "github.com/mholt/caddy-ratelimit@v0.1.0",
        "github.com/example/plugin/v2@0123456789abcdef0123456789abcdef01234567",
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
        parse_plugins(bad)


def test_duplicates_are_rejected_regardless_of_version():
    with pytest.raises(ScriptError, match="duplicate"):
        parse_plugins("github.com/a/b\ngithub.com/a/b@v1.0.0\n")


def test_all_errors_are_reported_together():
    with pytest.raises(ScriptError) as info:
        parse_plugins("bad one\nbad two\n")
    assert str(info.value).count("invalid") == 2


def test_crlf_and_empty_input():
    assert parse_plugins("github.com/a/b\r\n") == ["github.com/a/b"]
    assert parse_plugins("") == []


def test_missing_file_fails(tmp_path):
    with pytest.raises(ScriptError):
        load_plugins(tmp_path / "nope.txt")
