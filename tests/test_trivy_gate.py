#!/usr/bin/env python3
#
# tests/test_trivy_gate.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import json

import pytest

from common import ScriptError
from trivy_gate import (
    CONFIG_DIRS,
    copy_config_inputs,
    evaluate,
    require_go_modules,
    require_misconfigurations,
)


def report(tmp_path, name, results=None, **extra):
    data = {"SchemaVersion": 2, "ArtifactName": "x", **extra}
    if results is not None:
        data["Results"] = results
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


def vuln(sev):
    return {"Vulnerabilities": [{"Severity": sev}]}


def test_clean_report_passes(tmp_path):
    passed, text = evaluate([report(tmp_path, "a.json")])
    assert passed
    assert "Gate passed" in text


@pytest.mark.parametrize("sev", ["CRITICAL", "HIGH"])
def test_critical_and_high_block(tmp_path, sev):
    passed, text = evaluate([report(tmp_path, "a.json", [vuln(sev)])])
    assert not passed
    assert "a.json" in text


@pytest.mark.parametrize("sev", ["MEDIUM", "LOW"])
def test_medium_and_low_do_not_block(tmp_path, sev):
    passed, text = evaluate([report(tmp_path, "a.json", [vuln(sev)])])
    assert passed
    assert sev in text


def test_secrets_and_failed_misconfigurations_block(tmp_path):
    assert not evaluate([report(tmp_path, "s.json", [{"Secrets": [{"Severity": "HIGH"}]}])])[0]
    fail = {"Misconfigurations": [{"Severity": "CRITICAL", "Status": "FAIL"}]}
    assert not evaluate([report(tmp_path, "m.json", [fail])])[0]
    ok = {"Misconfigurations": [{"Severity": "CRITICAL", "Status": "PASS"}]}
    assert evaluate([report(tmp_path, "p.json", [ok])])[0]


def test_one_bad_report_blocks_all(tmp_path):
    good = report(tmp_path, "good.json")
    bad = report(tmp_path, "bad.json", [vuln("HIGH")])
    assert not evaluate([good, bad])[0]


def test_invalid_reports_raise(tmp_path):
    missing = tmp_path / "missing.json"
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    wrong = tmp_path / "wrong.json"
    wrong.write_text("{}")
    for path in (missing, broken, wrong):
        with pytest.raises(ScriptError):
            evaluate([path])
    with pytest.raises(ScriptError):
        evaluate([report(tmp_path, "r.json", Results="x")])
    with pytest.raises(ScriptError):
        evaluate([])


def test_scan_without_go_modules_is_an_error(tmp_path):
    empty = report(tmp_path, "e.json", [{"Type": "debian"}])
    with pytest.raises(ScriptError, match="no Go modules"):
        require_go_modules(empty)
    seen = report(tmp_path, "g.json", [{"Type": "gobinary", "Packages": [{"Name": "x"}]}])
    require_go_modules(seen)


def test_canary_must_report_a_misconfiguration(tmp_path):
    with pytest.raises(ScriptError, match="canary"):
        require_misconfigurations(report(tmp_path, "c.json", [{"Type": "dockerfile"}]))
    require_misconfigurations(
        report(tmp_path, "d.json", [{"Misconfigurations": [{"Severity": "HIGH"}]}])
    )


def test_config_scan_refuses_missing_or_empty_inputs(tmp_path):
    root, dest = tmp_path / "root", tmp_path / "dest"
    dest.mkdir()
    for name in CONFIG_DIRS:
        (root / name).mkdir(parents=True)
        (root / name / "f").write_text("x")
    copy_config_inputs(root, dest)
    assert all((dest / name / "f").is_file() for name in CONFIG_DIRS)
    (root / "apt" / "f").unlink()
    dest2 = tmp_path / "dest2"
    dest2.mkdir()
    with pytest.raises(ScriptError, match="apt/"):
        copy_config_inputs(root, dest2)
