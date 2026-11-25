#!/usr/bin/env python3
#
# tests/test_check_version.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import re
import shutil

import pytest

from check_version import decide, inputs_hash, latest_stable
from common import ScriptError, dpkg_compare, repo_root

RELEASES = [
    {"tag_name": "v2.12.0-beta.1", "draft": False, "prerelease": True},
    {"tag_name": "v2.99.0", "draft": True, "prerelease": False},
    {"tag_name": "v2.11.10", "draft": False, "prerelease": False},
    {"tag_name": "v2.11.9", "draft": False, "prerelease": False},
    {"tag_name": "v2.11.0-rc.1", "draft": False, "prerelease": False},
]
STATE = {"caddy_version": "2.11.9", "revision": 3, "inputs_hash": "aaa", "release_id": "r1"}
PUBLISHED = {"release_id": "r1", "status": "PUBLISHED"}


def test_latest_ignores_drafts_prereleases_and_sorts_numerically():
    assert latest_stable(RELEASES) == "2.11.10"


@pytest.mark.parametrize(
    "payload",
    [{"message": "rate limited"}, [], [{"tag_name": "v3.0.0", "draft": False, "prerelease": True}]],
)
def test_latest_fails_without_stable_release(payload):
    with pytest.raises(ScriptError):
        latest_stable(payload)


def test_first_release_without_state():
    d = decide("2.11.9", None, "aaa", False)
    assert (d.should_build, d.reason, d.package_version) == (
        True,
        "first-release",
        "2.11.9+custom.1",
    )


def test_unchanged_is_a_noop_and_keeps_revision():
    d = decide("2.11.9", STATE, "aaa", False, PUBLISHED)
    assert (d.should_build, d.reason, d.package_version) == (False, "unchanged", "2.11.9+custom.3")


def test_new_version_restarts_revision():
    d = decide("2.11.10", STATE, "aaa", False)
    assert (d.should_build, d.reason, d.package_version) == (
        True,
        "new-version",
        "2.11.10+custom.1",
    )


def test_changed_inputs_and_force_bump_revision():
    changed = decide("2.11.9", STATE, "bbb", False)
    assert (changed.reason, changed.package_version) == ("config-changed", "2.11.9+custom.4")
    forced = decide("2.11.9", STATE, "aaa", True, PUBLISHED)
    assert (forced.reason, forced.package_version) == ("forced", "2.11.9+custom.4")


def test_downgrade_and_bad_input_fail():
    with pytest.raises(ScriptError, match="downgrade"):
        decide("2.11.8", STATE, "aaa", False)
    with pytest.raises(ScriptError):
        decide("2.11.9", {}, "aaa", False)
    with pytest.raises(ScriptError):
        decide("v2.11", STATE, "aaa", False)


def test_revision_scheme_sorts_in_dpkg_order():
    assert dpkg_compare("2.11.10+custom.1", "gt", "2.11.9+custom.9")
    assert dpkg_compare("2.11.9+custom.10", "gt", "2.11.9+custom.9")


def test_inputs_hash_is_stable_sha256():
    first = inputs_hash(repo_root())
    assert len(first) == 64
    assert inputs_hash(repo_root()) == first


def test_apt_configuration_changes_the_build_input_hash(tmp_path):
    for directory in ("scripts", "packaging", "config", "apt"):
        shutil.copytree(repo_root() / directory, tmp_path / directory)
    before = inputs_hash(tmp_path)
    distribution = tmp_path / "apt/conf/distributions"
    distribution.write_text(distribution.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert inputs_hash(tmp_path) != before


def test_dependency_replacements_change_the_build_input_hash(monkeypatch):
    import check_version

    before = inputs_hash(repo_root())
    monkeypatch.setattr(
        check_version.toolchain,
        "BUILD_REPLACEMENTS",
        (
            *check_version.toolchain.BUILD_REPLACEMENTS,
            "example.org/module@v1.0.0=example.org/module@v1.1.0",
        ),
    )
    assert inputs_hash(repo_root()) != before


@pytest.mark.parametrize(
    "status",
    [
        None,
        {"release_id": "r1", "status": "DEPLOYED"},
        {"release_id": "old", "status": "PUBLISHED"},
    ],
)
def test_unconfirmed_release_triggers_recovery_not_a_rebuild(status):
    d = decide("2.11.9", STATE, "aaa", False, status)
    assert (d.should_build, d.recover, d.reason, d.revision) == (False, True, "recover", 3)


def test_new_version_wins_over_recovery():
    d = decide("2.11.10", STATE, "aaa", False, None)
    assert (d.should_build, d.recover) == (True, False)


def test_decide_cli_accepts_an_already_staged_release(tmp_path, capsys, monkeypatch):
    import json
    import sys

    import check_version

    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({**STATE, "revision": 1, "release_id": "r2"}))
    argv = [
        "check_version.py",
        "decide",
        "--latest",
        "2.11.9",
        "--state",
        str(manifest),
        "--inputs-hash",
        "aaa",
        "--expect-package-version",
        "2.11.9+custom.1",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert check_version.main() == 0
    monkeypatch.setattr(sys, "argv", [*argv[:-1], "2.11.9+custom.2"])
    with pytest.raises(ScriptError, match="state changed"):
        check_version.main()


def run_decide(monkeypatch, tmp_path, state, *extra, status=None):
    import json
    import sys

    import check_version

    manifest = tmp_path / "state.json"
    manifest.write_text(json.dumps(state))
    argv = ["check_version.py", "decide", "--latest", "2.11.9", "--state", str(manifest)]
    argv += ["--inputs-hash", "aaa", *extra]
    if status is not None:
        (tmp_path / "status.json").write_text(json.dumps(status))
        argv += ["--status", str(tmp_path / "status.json")]
    monkeypatch.setattr(sys, "argv", argv)
    return check_version.main()


def test_forced_rebuild_survives_the_recheck_under_the_release_lock(tmp_path, monkeypatch):
    # The version check and the publish recheck must both see force=true, else the
    # recheck reports "unchanged" and the finished build is thrown away.
    expected = ("--expect-package-version", "2.11.9+custom.4")
    run_decide(monkeypatch, tmp_path, STATE, "--force", "true", status=PUBLISHED)
    run_decide(monkeypatch, tmp_path, STATE, "--force", "true", *expected, status=PUBLISHED)
    with pytest.raises(ScriptError, match="state changed"):
        run_decide(monkeypatch, tmp_path, STATE, "--force", "false", *expected, status=PUBLISHED)


def workflow_job(name):
    text = (repo_root() / ".github/workflows/build.yml").read_text(encoding="utf-8")
    block = text.split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z-]+:\n", block, maxsplit=1)[0]


def test_version_check_and_publish_recheck_read_the_same_sources():
    # Both decisions compare against the public state and see the same staged state; differing
    # sources could demand different revisions and block every later run.
    for job in ("check-version", "sign-and-publish"):
        block = workflow_job(job)
        assert "--state published/release-manifest.json" in block
        assert "--staged repo-state/release-manifest.json" in block
        assert 'fetch-public "$PUBLIC_URL"' in block


def test_publish_recheck_receives_the_force_flag_of_the_run():
    check = workflow_job("check-version")
    recheck = workflow_job("sign-and-publish")
    expression = "${{ inputs.force_build && 'true' || 'false' }}"
    assert expression in check
    assert f"FORCE_BUILD: {expression}" in recheck
    assert '--force "$FORCE_BUILD"' in recheck


STAGED = {**STATE, "revision": 4, "release_id": "r2"}
UNCONFIRMED = {"release_id": "r2", "status": "DEPLOYED"}


def test_an_unconfirmed_stage_is_recovered_not_rebuilt():
    # Deployment failed: apt-repo holds r2 (rev 4), the public repository still serves r1.
    d = decide("2.11.9", STATE, "aaa", False, PUBLISHED, staged=STAGED)
    assert (d.should_build, d.recover, d.package_version) == (False, True, "2.11.9+custom.4")


def test_an_unconfirmed_stage_with_new_inputs_gets_the_next_revision(tmp_path, monkeypatch):
    # Rebuilding at the staged revision would be a silent no-op in reprepro; the decision
    # must be reproducible by the publish recheck, which reads the same sources.
    d = decide("2.11.9", STATE, "bbb", False, PUBLISHED, staged=STAGED)
    assert (d.should_build, d.reason, d.package_version) == (
        True,
        "config-changed",
        "2.11.9+custom.5",
    )
    import json

    for name, body in (("public", STATE), ("status", PUBLISHED), ("staged", STAGED)):
        (tmp_path / f"{name}.json").write_text(json.dumps(body))
    for expected in ("2.11.9+custom.5",) * 2:
        run_decide_cli(
            monkeypatch,
            tmp_path,
            "--inputs-hash",
            "bbb",
            "--expect-package-version",
            expected,
        )


def run_decide_cli(monkeypatch, tmp_path, *extra):
    import sys

    import check_version

    argv = ["check_version.py", "decide", "--latest", "2.11.9"]
    argv += ["--state", str(tmp_path / "public.json"), "--status", str(tmp_path / "status.json")]
    argv += ["--staged", str(tmp_path / "staged.json"), *extra]
    monkeypatch.setattr(sys, "argv", argv)
    return check_version.main()


def test_a_stage_without_any_public_release_is_recovered():
    d = decide("2.11.9", None, "aaa", False, None, staged=STAGED)
    assert (d.should_build, d.recover) == (False, True)


def test_a_confirmed_or_older_stage_does_not_override_the_public_state():
    same = decide("2.11.9", STATE, "aaa", False, PUBLISHED, staged=STATE)
    assert (same.should_build, same.recover, same.reason) == (False, False, "unchanged")
    older = {**STATE, "revision": 2, "release_id": "r0"}
    assert decide("2.11.9", STATE, "aaa", False, PUBLISHED, staged=older).reason == "unchanged"


def test_publication_chain_runs_when_one_of_the_publishing_jobs_is_skipped():
    # sign-and-publish (normal) or recover-stage (recovery) is always skipped; without a
    # status function the implicit success() would skip every downstream job.
    for job in ("verify-publication", "confirm-published", "verify-status"):
        condition = next(
            line for line in workflow_job(job).splitlines() if line.startswith("    if:")
        )
        assert "!cancelled()" in condition, job


def test_summary_requires_the_published_status_when_a_release_was_needed():
    block = workflow_job("summary")
    assert "verify-status" in block
    assert "DEPLOY_STATUS: ${{ needs.deploy-status.result }}" in block
    assert '"$VERIFY_STATUS" != "success"' in block
