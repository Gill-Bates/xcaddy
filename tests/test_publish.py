#!/usr/bin/env python3
#
# tests/test_publish.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import json
import re
import shutil
import time

import pytest

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
    publish.verify_site(site)
    assert not publish.add_packages(repo, debs("2.11.9+custom.1"))


def test_tampered_metadata_fails_verification(env):
    repo, fpr, debs, tmp = env
    publish_version(repo, fpr, debs, "2.11.9+custom.1", 1)
    site = tmp / "site"
    publish.export_site(repo, site)
    release = site / "dists/stable/Release"
    release.write_text(release.read_text().replace("Suite: stable", "Suite: evil"))
    with pytest.raises(ScriptError):
        publish.verify_site(site)


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
    publish.verify_site(site)
    new_hashes = {p.name for p in site.glob("dists/**/by-hash/SHA256/*")}
    assert old_hashes < new_hashes
    manifest = (site / "release-manifest.json").read_text()
    assert "2.11.10+custom.1" in manifest
    (site / "release-manifest.json").write_text(manifest.replace("2.11.10", "2.99.99"))
    with pytest.raises(ScriptError):
        publish.verify_site(site)


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
    publish.verify_site(site)
    status = site / "release-status.json"
    status.write_text(status.read_text().replace("PUBLISHED", "DEPLOYED"))
    with pytest.raises(ScriptError):
        publish.verify_site(site)


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
    publish.verify_site(tmp / "site")


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
