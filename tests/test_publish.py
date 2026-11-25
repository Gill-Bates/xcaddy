#!/usr/bin/env python3
#
# tests/test_publish.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import copy
import json
import re
import shutil
import time
from pathlib import Path

import pytest
import yaml

import publish
from common import ScriptError
from package import build_package

NEEDS_TOOLS = shutil.which("reprepro") is None or shutil.which("gpg") is None
ARCHS = ("amd64", "arm64")


@pytest.fixture
def env(tmp_path, monkeypatch, fake_elf):
    if NEEDS_TOOLS:
        pytest.skip("reprepro or gpg not installed")
    home = tmp_path / "gnupg"
    monkeypatch.setenv("GNUPGHOME", str(home))
    fpr = publish.make_throwaway_key(home)
    manifest = tmp_path / "m.json"
    manifest.write_text("{}")
    repo = tmp_path / "repo"
    repo.mkdir()
    publish.init_repo(repo, fpr)

    def debs(version):
        return [
            build_package(version, a, fake_elf(a, f"caddy-{a}"), manifest, tmp_path / version)
            for a in ARCHS
        ]

    yield repo, fpr, debs, tmp_path
    publish.cleanup_keyring()


def publish_version(repo, fpr, debs, version, revision):
    built = debs(version)
    assert publish.add_packages(repo, built)
    publish.finalize(repo, fpr, version.split("+")[0], revision, "hash", built)


def test_signed_site_verifies_and_noop_rerun(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    publish.verify_site(site, fingerprint=fpr)
    assert not publish.add_packages(repo, debs("2.11.9+custom.1"))


def test_tampered_metadata_fails_verification(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    release = site / "dists/stable/Release"
    release.write_text(release.read_text().replace("Suite: stable", "Suite: evil"))
    with pytest.raises(ScriptError):
        publish.verify_site(site, fingerprint=fpr)


def test_inrelease_must_match_the_signed_release(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    release = site / "dists/stable/Release"
    release.write_text(
        release.read_text(encoding="utf-8") + "X-Review: changed\n", encoding="utf-8"
    )
    publish._detached(release, release.with_name("Release.gpg"), fpr)
    with pytest.raises(ScriptError, match="different metadata"):
        publish.verify_site(site, fingerprint=fpr)


def test_init_updates_an_existing_repository_configuration(tmp_path, monkeypatch):
    source = tmp_path / "source"
    distribution = source / "apt/conf/distributions"
    distribution.parent.mkdir(parents=True)
    distribution.write_text("SignWith: @SIGN_WITH@\n", encoding="utf-8")
    monkeypatch.setattr(publish, "repo_root", lambda: source)
    repo = tmp_path / "repo"
    publish.init_repo(repo, "A" * 40)
    distribution.write_text("SignWith: @SIGN_WITH@\nDescription: updated\n", encoding="utf-8")
    publish.init_repo(repo, "A" * 40)
    assert "Description: updated" in (repo / "conf/distributions").read_text(encoding="utf-8")


def test_downgrade_and_missing_arch_are_refused(env):
    repo, fpr, debs, _ = env
    publish_version(repo, fpr, debs, "2.11.9+custom.2", 2)
    with pytest.raises(ScriptError, match="not newer"):
        publish.add_packages(repo, debs("2.11.9+custom.1"))
    with pytest.raises(ScriptError, match="expected packages"):
        publish.add_packages(repo, debs("2.11.9+custom.3")[:1])


def test_upgrade_replaces_old_version_and_files(env):
    repo, fpr, debs, _ = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    publish_version(repo, fpr, debs, "2.11.10+custom.1", 1)
    assert publish.list_versions(repo) == ["2.11.10+custom.1"]
    assert not list(repo.glob("pool/**/*2.11.9*"))


def test_signer_must_match_the_pinned_fingerprint(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    publish.export_site(repo, tmp / "site")
    publish.verify_site(tmp / "site", fingerprint=fpr)
    with pytest.raises(ScriptError, match="expected key"):
        publish.verify_site(tmp / "site", fingerprint="A" * 40)
    publish.verify_state(tmp / "site", fpr)
    with pytest.raises(ScriptError):
        publish.verify_state(tmp / "site", "B" * 40)
    with pytest.raises(ScriptError, match="40-hex"):
        publish.verify_state(tmp / "site", "")


def test_missing_secrets_abort(monkeypatch, tmp_path):
    monkeypatch.setenv("GNUPGHOME", str(tmp_path / "g"))
    monkeypatch.delenv("APT_GPG_PRIVATE_KEY", raising=False)
    with pytest.raises(ScriptError, match="unsigned"):
        publish.import_key()
    monkeypatch.setenv("APT_GPG_PRIVATE_KEY", "x")
    monkeypatch.delenv("APT_GPG_PASSPHRASE", raising=False)
    with pytest.raises(ScriptError, match="PASSPHRASE"):
        publish.import_key()


def test_default_gnupg_home_is_refused(monkeypatch):
    monkeypatch.delenv("GNUPGHOME", raising=False)
    with pytest.raises(ScriptError):
        publish.gnupg_home()


def test_gnupg_home_outside_a_temporary_root_is_refused_and_never_deleted(monkeypatch):
    victim = Path.home() / "gnupg-cleanup-victim"
    monkeypatch.setenv("GNUPGHOME", str(victim))
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    with pytest.raises(ScriptError, match="temporary root"):
        publish.gnupg_home()
    with pytest.raises(ScriptError, match="temporary root"):
        publish.cleanup_keyring()
    assert not victim.exists()


def test_manifest_is_signed_and_by_hash_survives_version_change(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    old_hashes = {p.name for p in site.glob("dists/**/by-hash/SHA256/*")}
    assert old_hashes
    assert "Acquire-By-Hash: yes" in (site / "dists/stable/Release").read_text()
    publish_version(repo, fpr, debs, "2.11.10+custom.1", 1)
    publish.export_site(repo, site)
    publish.verify_site(site, fingerprint=fpr)
    new_hashes = {p.name for p in site.glob("dists/**/by-hash/SHA256/*")}
    assert old_hashes < new_hashes
    manifest = (site / "release-manifest.json").read_text()
    assert "2.11.10+custom.1" in manifest
    (site / "release-manifest.json").write_text(manifest.replace("2.11.10", "2.99.99"))
    with pytest.raises(ScriptError):
        publish.verify_site(site, fingerprint=fpr)


def test_manifest_is_immutable_and_status_is_separate(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    manifest = (repo / "release-manifest.json").read_text()
    assert "status" not in manifest
    assert '"DEPLOYED"' in (repo / "release-status.json").read_text()
    publish.write_status(repo, fpr, "VERIFIED")
    publish.write_status(repo, fpr, "PUBLISHED")
    assert (repo / "release-manifest.json").read_text() == manifest
    publish.write_status(repo, fpr, "DEPLOYED")
    assert '"PUBLISHED"' in (repo / "release-status.json").read_text()
    site = tmp / "site"
    publish.export_site(repo, site)
    publish.verify_site(site, fingerprint=fpr)
    status = site / "release-status.json"
    status.write_text(status.read_text().replace("PUBLISHED", "DEPLOYED"))
    with pytest.raises(ScriptError):
        publish.verify_site(site, fingerprint=fpr)


def test_old_metadata_stays_fetchable_by_hash_until_grace_expires(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    cached = {p.relative_to(repo): p.read_bytes() for p in repo.glob("dists/**/by-hash/SHA256/*")}
    assert cached
    publish_version(repo, fpr, debs, "2.11.10+custom.1", 1)
    for rel, data in cached.items():
        assert (repo / rel).read_bytes() == data
    later = time.time() + (publish.BY_HASH_GRACE_DAYS + 1) * 86400
    publish.add_by_hash(repo, fpr, now=later)
    publish.add_by_hash(repo, fpr, now=later + 1)
    stale = [rel for rel in cached if (repo / rel).exists()]
    assert len(stale) < len(cached)
    publish.export_site(repo, tmp / "site")
    publish.verify_site(tmp / "site", fingerprint=fpr)


def test_publish_is_idempotent(env):
    repo, fpr, debs, _ = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    before = (repo / "release-manifest.json").read_text()
    assert not publish.add_packages(repo, debs("2.11.9+custom.1"))
    assert (repo / "release-manifest.json").read_text() == before


def test_public_key_is_armored_and_matches_signer(env):
    repo, fpr, debs, _ = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    key = (repo / "gpg.key").read_text()
    assert key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert "PRIVATE" not in key
    assert publish.fingerprint_of(publish.gnupg_home()) == fpr


@pytest.fixture
def served(env, monkeypatch):
    """A published site served to verify_url by a fake downloader."""
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    requested: list[str] = []

    def download(url, dest, attempts=6):
        name = url.removeprefix("https://example.invalid/")
        requested.append(name)
        if not (site / name).is_file():
            raise ScriptError(f"404 {name}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((site / name).read_bytes())

    monkeypatch.setattr(publish, "_download", download)
    release_id = json.loads((repo / "release-manifest.json").read_text())["release_id"]
    return site, requested, fpr, release_id


def test_verify_url_loads_everything_the_signed_release_lists(served):
    site, requested, fpr, release_id = served
    publish.verify_url("https://example.invalid", fingerprint=fpr, release_id=release_id)
    assert any("/by-hash/SHA256/" in name for name in requested)
    assert any(name.endswith(".deb") for name in requested)
    assert "release-manifest.json.asc" in requested


def test_verify_url_rejects_an_unexpected_release(served):
    _, _, fpr, _ = served
    with pytest.raises(ScriptError, match="expected"):
        publish.verify_url("https://example.invalid", fingerprint=fpr, release_id="0" * 16)


def test_verify_url_rejects_changed_package_bytes(served):
    site, _, fpr, release_id = served
    deb = next(site.glob("pool/**/*.deb"))
    deb.write_bytes(deb.read_bytes() + b"x")
    with pytest.raises(ScriptError, match="differs from the signed Packages"):
        publish.verify_url("https://example.invalid", fingerprint=fpr, release_id=release_id)


def test_verify_url_rejects_a_missing_by_hash_file(served):
    site, _, fpr, release_id = served
    next(site.glob("dists/stable/main/binary-amd64/by-hash/SHA256/*")).unlink()
    with pytest.raises(ScriptError, match="404"):
        publish.verify_url("https://example.invalid", fingerprint=fpr, release_id=release_id)


ARCH_RELEASE = "dists/stable/main/binary-amd64/Release"


def _by_hash_of(site, name):
    import hashlib

    file = site / name
    return file.parent / "by-hash" / "SHA256" / hashlib.sha256(file.read_bytes()).hexdigest()


def test_verify_site_rejects_a_tampered_arch_release(served):
    site, _, fpr, _ = served
    (site / ARCH_RELEASE).write_text("tampered")
    with pytest.raises(ScriptError, match="does not match the signed Release"):
        publish.verify_site(site, fingerprint=fpr)


def test_verify_site_rejects_a_missing_arch_release_by_hash_file(served):
    site, _, fpr, _ = served
    _by_hash_of(site, ARCH_RELEASE).unlink()
    with pytest.raises(ScriptError, match="by-hash file"):
        publish.verify_site(site, fingerprint=fpr)


def test_verify_url_rejects_a_tampered_arch_release(served):
    site, _, fpr, release_id = served
    (site / ARCH_RELEASE).write_text("tampered")
    with pytest.raises(ScriptError, match="does not match the signed Release"):
        publish.verify_url("https://example.invalid", fingerprint=fpr, release_id=release_id)


def test_verify_url_rejects_a_missing_arch_release_by_hash_file(served):
    site, _, fpr, release_id = served
    _by_hash_of(site, ARCH_RELEASE).unlink()
    with pytest.raises(ScriptError, match="404"):
        publish.verify_url("https://example.invalid", fingerprint=fpr, release_id=release_id)


def test_verify_site_pins_the_signer(served):
    site, _, _, _ = served
    with pytest.raises(ScriptError, match="expected key"):
        publish.verify_site(site, fingerprint="A" * 40)


def test_apt_key_is_installed_with_the_extension_apt_requires(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    key = publish.install_apt_key(repo / "gpg.key", tmp / "keyrings")
    assert key.suffix == ".asc"
    assert key.read_bytes() == (repo / "gpg.key").read_bytes()


def test_workflow_hands_apt_an_armored_key_with_the_asc_extension():
    # APT reads a signed-by file as binary unless it ends in .asc (armored) or .gpg (binary).
    from common import repo_root

    text = (repo_root() / ".github/workflows/build.yml").read_text(encoding="utf-8")
    keys = re.findall(r"signed-by=(\S+?)[\]\s]", text)
    assert keys
    assert all(key.endswith(".asc") for key in keys)


def test_fetch_public_state_reports_a_first_release_only_for_404(tmp_path, monkeypatch):
    import urllib.error

    def failing(code):
        def fake(url, timeout):
            raise urllib.error.HTTPError(url, code, "x", {}, None)

        return fake

    monkeypatch.setattr(publish.urllib.request, "urlopen", failing(404))
    assert publish.fetch_public_state("https://example.invalid", tmp_path, "A" * 40) is False
    monkeypatch.setattr(publish.urllib.request, "urlopen", failing(503))
    with pytest.raises(ScriptError, match="503"):
        publish.fetch_public_state("https://example.invalid", tmp_path, "A" * 40)


def _by_hash_package_entries(site):
    """(Filename, SHA256) of every package named by any Packages index kept under by-hash."""
    import gzip

    entries = set()
    for path in site.glob("dists/**/binary-*/by-hash/SHA256/*"):
        data = path.read_bytes()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        entries.update(publish._package_entries(data.decode("utf-8", errors="ignore")))
    return entries


def test_every_package_named_by_a_retained_index_stays_downloadable(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    publish_version(repo, fpr, debs, "2.11.10+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    entries = _by_hash_package_entries(site)
    assert {name for name, _ in entries if "2.11.9" in name}
    for filename, digest in entries:
        assert (site / filename).is_file(), filename
        assert publish.sha256_file(site / filename) == digest
    publish.verify_site(site, fingerprint=fpr)


def test_retained_packages_are_dropped_with_their_indexes_after_the_grace_period(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    publish_version(repo, fpr, debs, "2.11.10+custom.1", 1)
    later = time.time() + (publish.BY_HASH_GRACE_DAYS + 1) * 86400
    publish.add_by_hash(repo, fpr, now=later)
    publish.add_by_hash(repo, fpr, now=later + 1)
    publish.export_site(repo, tmp / "site")
    assert not list((tmp / "site").glob("pool/**/*2.11.9*"))
    assert list((tmp / "site").glob("pool/**/*2.11.10*"))


def test_same_version_with_different_package_bytes_is_refused(env, fake_elf):
    from package import build_package

    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    other = fake_elf("amd64", "other")
    other.write_bytes(other.read_bytes() + b"changed")
    changed = [
        build_package("2.11.9+custom.1", "amd64", other, tmp / "m.json", tmp / "changed"),
        debs("2.11.9+custom.1")[1],
    ]
    with pytest.raises(ScriptError, match="different package bytes"):
        publish.add_packages(repo, changed)


def test_an_architecture_missing_for_a_published_version_is_added(env):
    repo, fpr, debs, tmp = env
    built = debs("2.11.9+custom.1")
    # simulate an interrupted run: only amd64 made it into the repository
    publish.reprepro(repo, "includedeb", publish.CODENAME, built[0])
    assert publish.add_packages(repo, built)
    assert not publish.add_packages(repo, built)
    out = publish.reprepro(repo, "list", publish.CODENAME, publish.PACKAGE).stdout
    assert "amd64" in out
    assert "arm64" in out


def test_verification_without_a_pinned_fingerprint_is_refused(served, monkeypatch, tmp_path):
    import sys
    import urllib.error

    site, _, fpr, release_id = served
    with pytest.raises(ScriptError, match="40-hex"):
        publish.verify_site(site)
    with pytest.raises(ScriptError, match="40-hex"):
        publish.verify_url("https://example.invalid", release_id=release_id)
    # a first release (404) must not skip the pin either
    monkeypatch.setattr(
        publish.urllib.request,
        "urlopen",
        lambda url, timeout: (_ for _ in ()).throw(urllib.error.HTTPError(url, 404, "x", {}, None)),
    )
    with pytest.raises(ScriptError, match="40-hex"):
        publish.fetch_public_state("https://example.invalid", tmp_path, "")
    monkeypatch.setattr(sys, "argv", ["publish.py", "verify-site", str(site)])
    with pytest.raises(SystemExit):
        publish.main()


def test_workflows_pin_the_signer_for_every_verification():
    from common import repo_root

    for name in ("build.yml", "security.yml"):
        text = (repo_root() / ".github/workflows" / name).read_text(encoding="utf-8")
        for call in re.findall(
            r"(?:verify-site|verify-url|fetch-public|scan-published)\b[^\n]*", text
        ):
            assert "--fingerprint" in call, call


def test_each_architecture_ships_its_own_checksum_file():
    from common import repo_root

    text = (repo_root() / ".github/workflows/build.yml").read_text(encoding="utf-8")
    written = re.findall(r"sha256sum \./\*\.deb > \"?(\S+?)\"?\s*$", text, re.MULTILINE)
    assert written
    assert all("ARCH" in name for name in written), written
    checked = re.findall(r"sha256sum -c \"?(\S+?)\"?\)", text)
    assert checked
    assert all("arch" in name for name in checked), checked


def test_published_package_scan_verifies_the_signed_manifest(served, monkeypatch, tmp_path):
    import trivy_gate

    site, _, fpr, _ = served
    monkeypatch.setattr(
        publish, "_download_once", lambda url, dest: dest.write_bytes(_site_file(site, url))
    )
    deb = trivy_gate.fetch_published("https://example.invalid", "amd64", tmp_path, fpr)
    assert deb.name.endswith("_amd64.deb")
    manifest = site / "release-manifest.json"
    manifest.write_text(manifest.read_text().replace("amd64.deb", "amd64.dev"))
    with pytest.raises(ScriptError):
        trivy_gate.fetch_published("https://example.invalid", "amd64", tmp_path, fpr)
    manifest.write_text(manifest.read_text().replace("amd64.dev", "amd64.deb"))
    with pytest.raises(ScriptError, match="expected|unexpected|signed"):
        trivy_gate.fetch_published("https://example.invalid", "amd64", tmp_path, "A" * 40)


def _site_file(site, url):
    return (site / url.removeprefix("https://example.invalid/")).read_bytes()


DEFAULT_BRANCH_GATE = (
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
)
SUCCESS_TERM = re.compile(r"needs\.([\w-]+)\.result == 'success'")
PUBLISHING_PERMISSIONS = {"contents", "pages", "packages", "deployments", "actions"}


def _load_workflow(name):
    from common import repo_root

    return yaml.safe_load((repo_root() / ".github/workflows" / name).read_text(encoding="utf-8"))


def _needs(job):
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _publishes(job):
    """True for a job that can write to the repository or Pages, or that reads a secret."""
    permissions = job.get("permissions") or {}
    if permissions == "write-all" or any(
        permissions.get(scope) == "write" for scope in PUBLISHING_PERMISSIONS
    ):
        return True
    return "environment" in job or "secrets." in json.dumps(job)


def _directly_gated(condition):
    if not isinstance(condition, str) or "||" in condition:
        return False
    return DEFAULT_BRANCH_GATE in [" ".join(part.split()) for part in condition.split("&&")]


def _ungated_publishers(workflow):
    jobs = workflow["jobs"]
    verdict = {}

    def gated(name):
        if name not in verdict:
            verdict[name] = False  # a dependency cycle never counts as gated
            verdict[name] = _gated(name)
        return verdict[name]

    def _gated(name):
        job = jobs[name]
        condition = job.get("if")
        if isinstance(condition, str):
            condition = re.sub(r"^\$\{\{\s*(.*?)\s*\}\}$", r"\1", condition.strip())
        if _directly_gated(condition):
            return True
        needs = _needs(job)
        if condition is None:
            return bool(needs) and all(gated(n) for n in needs)
        residue = SUCCESS_TERM.sub("", condition)
        residue = re.sub(r"always\(\)|!cancelled\(\)|&&|\|\||[()\s]", "", residue)
        deps = SUCCESS_TERM.findall(condition)
        return not residue and bool(deps) and all(n in needs and gated(n) for n in deps)

    return sorted(name for name, job in jobs.items() if _publishes(job) and not gated(name))


def _mutate(workflow, mutation):
    mutated = copy.deepcopy(workflow)
    mutation(mutated["jobs"])
    return mutated


def test_nothing_is_published_from_a_branch_other_than_the_default_branch():
    workflow = _load_workflow("build.yml")
    publishers = {name for name, job in workflow["jobs"].items() if _publishes(job)}
    assert {"sign-and-publish", "deploy-pages", "confirm-published", "deploy-status"} <= publishers
    assert _ungated_publishers(workflow) == []
    # recover-stage stages the Pages artifact without a write scope, so it is gated explicitly.
    assert _directly_gated(workflow["jobs"]["recover-stage"]["if"])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda jobs: jobs["sign-and-publish"].pop("if"),
        lambda jobs: jobs["sign-and-publish"].update(
            {"if": DEFAULT_BRANCH_GATE.replace("==", "!=")}
        ),
        lambda jobs: jobs["sign-and-publish"].update(
            {"if": f"github.event_name == 'workflow_dispatch' || {DEFAULT_BRANCH_GATE}"}
        ),
        lambda jobs: jobs["sign-and-publish"].update(
            {"if": "contains(github.event.repository.default_branch, github.ref)"}
        ),
        lambda jobs: jobs["deploy-pages"].update({"if": "always()"}),
        lambda jobs: jobs["deploy-pages"].update({"needs": ["check-version"]}),
        lambda jobs: jobs["confirm-published"].update({"if": "always()"}),
        lambda jobs: jobs["confirm-published"].update(
            {"if": "needs.verify-publication.result != 'failure'"}
        ),
        lambda jobs: jobs.update({"extra": {"needs": ["build"], "environment": "apt-publish"}}),
        lambda jobs: jobs.update(
            {"extra": {"needs": ["build"], "permissions": {"contents": "write"}}}
        ),
        lambda jobs: jobs.update(
            {"extra": {"needs": ["build"], "steps": [{"env": {"K": "${{ secrets.APT_KEY }}"}}]}}
        ),
    ],
)
def test_the_branch_gate_check_detects_a_publish_path_from_any_branch(mutation):
    mutated = _mutate(_load_workflow("build.yml"), mutation)
    assert _ungated_publishers(mutated) != []


@pytest.mark.parametrize("name", ["ci.yml", "security.yml"])
def test_the_other_workflows_never_publish(name):
    assert [j for j, job in _load_workflow(name)["jobs"].items() if _publishes(job)] == []


def test_triggers_that_start_a_release_run_only_on_the_default_branch():
    triggers = _load_workflow("build.yml")[True]  # YAML 1.1 reads the key `on` as True
    assert set(triggers) == {"schedule", "workflow_dispatch", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert "tags" not in triggers["push"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda on: on.update({"pull_request": {}}),
        lambda on: on.update({"workflow_run": {"workflows": ["ci"]}}),
        lambda on: on["push"].update({"branches": ["main", "feature/dev"]}),
        lambda on: on["push"].pop("branches"),
        lambda on: on["push"].update({"tags": ["v*"]}),
    ],
)
def test_the_trigger_check_detects_a_run_that_can_start_elsewhere(mutation):
    triggers = copy.deepcopy(_load_workflow("build.yml")[True])
    mutation(triggers)
    safe = (
        set(triggers) == {"schedule", "workflow_dispatch", "push"}
        and triggers["push"].get("branches") == ["main"]
        and "tags" not in triggers["push"]
    )
    assert not safe


def test_verify_state_binds_the_state_to_the_expected_release(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    manifest = publish.verify_state(repo, fpr)
    publish.verify_state(repo, fpr, manifest["release_id"], manifest["package_version"])
    with pytest.raises(ScriptError, match="expected"):
        publish.verify_state(repo, fpr, release_id="0" * 16)
    with pytest.raises(ScriptError, match="expected 2.11.10"):
        publish.verify_state(repo, fpr, package_version="2.11.10+custom.1")


def test_a_state_rolled_back_to_an_older_signed_release_is_refused(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    older = tmp / "older"
    shutil.copytree(repo, older, ignore=shutil.ignore_patterns("db", "pool", "dists"))
    publish_version(repo, fpr, debs, "2.11.10+custom.1", 1)
    # the apt-repo branch was reset: it validly signs 2.11.9 while 2.11.10 is expected
    with pytest.raises(ScriptError, match="expected 2.11.10"):
        publish.verify_state(older, fpr, package_version="2.11.10+custom.1")


def test_a_status_of_another_release_is_refused(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    status = repo / "release-status.json"
    status.write_text(json.dumps({"release_id": "0" * 16, "status": "PUBLISHED"}))
    publish._detached(status, repo / "release-status.json.asc", fpr)
    with pytest.raises(ScriptError, match="different release"):
        publish.verify_state(repo, fpr)


def test_finalize_refuses_a_package_of_another_version(env):
    repo, fpr, debs, _ = env
    built = debs("2.11.9+custom.0")
    publish.add_packages(repo, built)
    with pytest.raises(ScriptError, match="not version 2.11.9\\+custom.1"):
        publish.finalize(repo, fpr, "2.11.9", 1, "hash", built)
    assert not (repo / "release-manifest.json").exists()


def test_verify_url_requires_the_expected_release_id(served):
    _, _, fpr, _ = served
    with pytest.raises(ScriptError, match="release id is required"):
        publish.verify_url("https://example.invalid", fingerprint=fpr, release_id="")


@pytest.mark.parametrize("marker", ["EXPKEYSIG", "REVKEYSIG", "EXPSIG", "BADSIG", "ERRSIG"])
def test_expired_revoked_or_bad_signatures_are_refused(marker):
    fpr = "A" * 40
    good = f"[GNUPG:] GOODSIG 1234 x\n[GNUPG:] VALIDSIG {fpr} 2026-01-01 1 0 4 0 22 8 00 {fpr}\n"
    publish._require_signer(good, fpr, "file")
    with pytest.raises(ScriptError, match="expired|bad"):
        publish._require_signer(f"[GNUPG:] {marker} 1234 x\n{good}", fpr, "file")
    with pytest.raises(ScriptError, match="no valid signature"):
        publish._require_signer(good.splitlines()[1], fpr, "file")
    with pytest.raises(ScriptError, match="unexpected key"):
        publish._require_signer(good, "B" * 40, "file")


def _git(path, *args):
    import subprocess

    return subprocess.run(
        ["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def commits(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "--quiet")
    _git(work, "commit", "--quiet", "--allow-empty", "-m", "one")
    first = _git(work, "rev-parse", "HEAD")
    _git(work, "commit", "--quiet", "--allow-empty", "-m", "two")
    second = _git(work, "rev-parse", "HEAD")
    return work, first, second


def _state_from(tmp_path, commit):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    (state / "release-manifest.json").write_text(json.dumps({"source_commit": commit}))
    return state


def test_ancestry_accepts_the_same_or_an_older_state_commit(commits, tmp_path, monkeypatch):
    work, first, second = commits
    monkeypatch.chdir(work)
    publish.check_ancestry(tmp_path / "none", second)
    publish.check_ancestry(_state_from(tmp_path, first), second)
    publish.check_ancestry(_state_from(tmp_path, second), second)
    publish.check_ancestry(_state_from(tmp_path, "unknown"), second)


def test_ancestry_refuses_a_state_from_a_newer_or_foreign_commit(commits, tmp_path, monkeypatch):
    work, first, second = commits
    monkeypatch.chdir(work)
    with pytest.raises(ScriptError, match="not an ancestor"):
        publish.check_ancestry(_state_from(tmp_path, second), first)
    with pytest.raises(ScriptError, match="not a full commit id"):
        publish.check_ancestry(_state_from(tmp_path, "abc"), second)


def test_a_manifest_with_an_unsafe_package_name_is_not_downloaded(monkeypatch, tmp_path):
    import trivy_gate

    def fetch(url, out, fingerprint):
        manifest = {"packages": {"../evil_amd64.deb": "0" * 64}}
        (out / "release-manifest.json").write_text(json.dumps(manifest))
        return True

    monkeypatch.setattr(publish, "fetch_public_state", fetch)
    with pytest.raises(ScriptError, match="unsafe package name"):
        trivy_gate.fetch_published("https://example.invalid", "amd64", tmp_path, "A" * 40)


def test_signing_secrets_are_not_inherited_by_child_processes(monkeypatch):
    monkeypatch.setenv("APT_GPG_PASSPHRASE", "secret")
    monkeypatch.setenv("APT_GPG_PRIVATE_KEY", "key")
    monkeypatch.setenv("GNUPGHOME", "/tmp/x")
    env = publish._clean_env()
    assert "APT_GPG_PASSPHRASE" not in env
    assert "APT_GPG_PRIVATE_KEY" not in env
    assert env["GNUPGHOME"] == "/tmp/x"


def _step_text(job):
    return "\n".join(
        str(step.get("run", "")) + json.dumps(step.get("env", {})) for step in job["steps"]
    )


def test_the_job_that_runs_the_built_binary_cannot_attest_or_sign():
    jobs = _load_workflow("build.yml")["jobs"]
    test_job, package_job = jobs["install-test"], jobs["package"]
    assert set(test_job["permissions"]) == {"contents"}
    assert "scripts/test.py" in _step_text(test_job)
    assert "attest-build-provenance" not in json.dumps(test_job)
    assert "scripts/test.py" not in _step_text(package_job)
    assert "attest-build-provenance" in json.dumps(package_job)
    assert {"package", "install-test"} <= set(_needs(jobs["prepare-apt-repository"]))


def test_recovery_and_confirmation_are_bound_to_the_expected_release():
    jobs = _load_workflow("build.yml")["jobs"]
    recover = _step_text(jobs["recover-stage"])
    assert "--expect-package-version" in recover
    assert "--expect-release-id" in recover
    confirm = jobs["confirm-published"]
    assert {"sign-and-publish", "recover-stage"} <= set(_needs(confirm))
    text = _step_text(confirm)
    assert "verify-state" in text
    assert text.count("--expect-release-id") >= 2
    verify = _step_text(jobs["verify-publication"])
    assert '[ -n "$RELEASE_ID" ]' in verify
