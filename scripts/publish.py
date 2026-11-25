#!/usr/bin/env python3
#
# scripts/publish.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Sign, add to and verify the reprepro APT repository.

reprepro keeps only the newest version per architecture, which is the retention policy.
"""

from __future__ import annotations

import argparse
import functools
import gzip
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from common import (
    ARCHS,
    PACKAGE_VERSION_RE,
    ScriptError,
    dpkg_compare,
    log,
    repo_root,
    require_tools,
    run,
    run_main,
    set_output,
    sha256_file,
)

CODENAME = "stable"
PACKAGE = "caddy-custom"
PAGES_URL = "https://gill-bates.github.io/xcaddy"


SECRET_ENV = ("APT_GPG_PRIVATE_KEY", "APT_GPG_PASSPHRASE")


def _clean_env(**extra: str) -> dict[str, str]:
    """Environment for child processes that never need the signing secrets (they use stdin)."""
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
    env.update(extra)
    return env


def _checked_gnupg_path() -> Path:
    """Return GNUPGHOME if it lies strictly below a temporary root (RUNNER_TEMP or the temp dir)."""
    value = os.environ.get("GNUPGHOME")
    if not value:
        raise ScriptError("GNUPGHOME must point to a temporary directory")
    path = Path(value).resolve()
    roots = {Path(tempfile.gettempdir()).resolve()}
    if os.environ.get("RUNNER_TEMP"):
        roots.add(Path(os.environ["RUNNER_TEMP"]).resolve())
    if not any(path != root and path.is_relative_to(root) for root in roots):
        raise ScriptError(f"GNUPGHOME {value} is not a directory below a temporary root")
    return path


def gnupg_home() -> Path:
    """Return the temporary GNUPGHOME; refuse to touch a default keyring."""
    home = _checked_gnupg_path()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    return home


def fingerprint_of(home: Path, secret: bool = True) -> str:
    listing = run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys" if secret else "--list-keys"],
        env=_clean_env(GNUPGHOME=str(home)),
    ).stdout
    for line in listing.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise ScriptError("no key found in the keyring")


def import_key(require_passphrase: bool = True) -> str:
    """Import APT_GPG_PRIVATE_KEY into GNUPGHOME and unlock it; return the fingerprint."""
    require_tools("gpg", "gpgconf")
    key = os.environ.get("APT_GPG_PRIVATE_KEY", "")
    passphrase = os.environ.get("APT_GPG_PASSPHRASE", "")
    if not key.strip():
        raise ScriptError("APT_GPG_PRIVATE_KEY is not set; refusing to publish unsigned")
    if require_passphrase and not passphrase:
        raise ScriptError("APT_GPG_PASSPHRASE is not set; refusing to publish")
    home = gnupg_home()
    (home / "gpg-agent.conf").write_text(
        "allow-preset-passphrase\ndefault-cache-ttl 3600\nmax-cache-ttl 3600\n", encoding="utf-8"
    )
    env = _clean_env(GNUPGHOME=str(home))
    run(["gpg", "--batch", "--import"], env=env, input_text=key)
    fpr = fingerprint_of(home)
    expected = os.environ.get("APT_GPG_KEY_ID", "").replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", expected):
        raise ScriptError("APT_GPG_KEY_ID must be the full 40-hex primary key fingerprint")
    if fpr.upper() != expected:
        raise ScriptError("imported key does not match APT_GPG_KEY_ID")
    if passphrase:
        libexec = run(["gpgconf", "--list-dirs", "libexecdir"], env=env).stdout.strip()
        preset = Path(libexec) / "gpg-preset-passphrase"
        if not preset.is_file():
            raise ScriptError("gpg-preset-passphrase not found")
        grips = [
            ln.split(":")[9]
            for ln in run(
                ["gpg", "--batch", "--with-colons", "--with-keygrip", "--list-secret-keys"], env=env
            ).stdout.splitlines()
            if ln.startswith("grp:")
        ]
        for grip in grips:
            run([preset, "--preset", grip], env=env, input_text=passphrase)
    return fpr


def cleanup_keyring() -> None:
    if not os.environ.get("GNUPGHOME"):
        return
    home = _checked_gnupg_path()
    run(["gpgconf", "--kill", "gpg-agent"], check=False, env=_clean_env())
    shutil.rmtree(home, ignore_errors=True)


def make_throwaway_key(home: Path) -> str:
    """Create an unprotected test key in home; only for tests, never for publishing."""
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = _clean_env(GNUPGHOME=str(home))
    run(
        [
            "gpg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "xcaddy test <test@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ],
        env=env,
    )
    return fingerprint_of(home)


def reprepro(repo: Path, *args: str, check: bool = True):
    return run(["reprepro", "-b", repo, *args], check=check, env=_clean_env())


def init_repo(repo: Path, fingerprint: str) -> None:
    template = (repo_root() / "apt/conf/distributions").read_text(encoding="utf-8")
    (repo / "conf").mkdir(parents=True, exist_ok=True)
    (repo / "conf/distributions").write_text(
        template.replace("@SIGN_WITH@", fingerprint), encoding="utf-8"
    )


def list_versions(repo: Path) -> list[str]:
    """Distinct package versions in the repository, oldest first."""
    out = reprepro(repo, "list", CODENAME, PACKAGE).stdout
    versions = {line.split()[-1] for line in out.splitlines() if line.strip()}
    return sorted(versions, key=functools.cmp_to_key(_cmp))


def _cmp(left: str, right: str) -> int:
    if left == right:
        return 0
    return -1 if dpkg_compare(left, "lt", right) else 1


def deb_field(deb: Path, field: str) -> str:
    return run(["dpkg-deb", "--field", deb, field], env=_clean_env()).stdout.strip()


def add_packages(repo: Path, debs: list[Path], archs: tuple[str, ...] = ARCHS) -> bool:
    """Include one deb per architecture; return False when the version is already published."""
    require_tools("reprepro", "dpkg-deb")
    by_arch: dict[str, Path] = {}
    versions = set()
    for deb in debs:
        if deb_field(deb, "Package") != PACKAGE:
            raise ScriptError(f"{deb.name} is not a {PACKAGE} package")
        arch = deb_field(deb, "Architecture")
        if arch in by_arch:
            raise ScriptError(f"two packages for {arch}")
        by_arch[arch] = deb
        versions.add(deb_field(deb, "Version"))
    if set(by_arch) != set(archs):
        raise ScriptError(f"expected packages for {sorted(archs)}, got {sorted(by_arch)}")
    if len(versions) != 1:
        raise ScriptError(f"architectures disagree on the version: {sorted(versions)}")
    version = versions.pop()
    if not PACKAGE_VERSION_RE.fullmatch(version):
        raise ScriptError(f"unexpected package version {version!r}")
    existing = list_versions(repo) if (repo / "db").exists() else []
    if version in existing:
        missing = _verify_published_identity(repo, version, by_arch)
        if not missing:
            log("info", f"{version} is already published with identical packages; nothing to add")
            return False
        by_arch = {arch: by_arch[arch] for arch in missing}
    elif existing and not dpkg_compare(version, "gt", existing[-1]):
        raise ScriptError(f"{version} is not newer than published {existing[-1]}; refusing")
    retain_packages(repo)
    for deb in by_arch.values():
        reprepro(repo, "includedeb", CODENAME, deb)
    return True


def _published_packages(repo: Path, arch: str) -> dict[str, tuple[str, str]]:
    """Version -> (Filename, SHA256) of caddy-custom in the repository's Packages index."""
    path = repo / "dists" / CODENAME / "main" / f"binary-{arch}" / "Packages"
    if not path.is_file():
        return {}
    found: dict[str, tuple[str, str]] = {}
    for stanza in path.read_text(encoding="utf-8").split("\n\n"):
        fields = dict(
            line.split(": ", 1) for line in stanza.splitlines() if line[:1].strip() and ": " in line
        )
        if fields.get("Package") == PACKAGE and "Version" in fields:
            found[fields["Version"]] = (fields.get("Filename", ""), fields.get("SHA256", ""))
    return found


def _verify_published_identity(repo: Path, version: str, by_arch: dict[str, Path]) -> list[str]:
    """Return the architectures still missing for version; refuse differing package bytes."""
    missing = []
    for arch, deb in by_arch.items():
        entry = _published_packages(repo, arch).get(version)
        if entry is None:
            missing.append(arch)
        elif entry[1] != sha256_file(deb):
            raise ScriptError(
                f"{version} ({arch}) is published with different package bytes; "
                "a changed package needs a new revision"
            )
    return missing


def retain_packages(repo: Path) -> None:
    """Copy published .deb files aside; reprepro drops them, but cached old indexes name them."""
    for deb in (repo / "pool").glob(f"**/{PACKAGE}_*.deb"):
        target = repo / RETAINED_DIR / deb.relative_to(repo)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(deb, target)


RETAINED_DIR = "retained"
FILENAME_RE = re.compile(r"^Filename: (\S+)$", re.MULTILINE)


def prune_retained(repo: Path, dist: Path) -> None:
    """Keep a retained .deb only while a still-served by-hash Packages index names it."""
    referenced: set[str] = set()
    for path in dist.glob("main/binary-*/by-hash/SHA256/*"):
        data = path.read_bytes()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        referenced.update(FILENAME_RE.findall(data.decode("utf-8", errors="ignore")))
    root = repo / RETAINED_DIR
    for deb in root.glob("**/*.deb"):
        if deb.relative_to(root).as_posix() not in referenced:
            deb.unlink()


def _gpg_env() -> dict[str, str]:
    return _clean_env(GNUPGHOME=str(gnupg_home()))


def add_by_hash(repo: Path, fingerprint: str, now: float | None = None) -> None:
    """Add by-hash copies, announce Acquire-By-Hash and re-sign Release and InRelease.

    Hash files from earlier releases stay in place so clients holding old metadata keep working.
    """
    dist = repo / "dists" / CODENAME
    release = dist / "Release"
    text = release.read_text(encoding="utf-8")
    for name in _release_hashes(text):
        src = dist / name
        if src.is_file():
            target = (
                src.parent / "by-hash" / "SHA256" / hashlib.sha256(src.read_bytes()).hexdigest()
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
    if "Acquire-By-Hash: yes" not in text:
        marker = "\nSHA256:"
        head, sep, tail = text.partition(marker)
        text = (
            f"{head}\nAcquire-By-Hash: yes{sep}{tail}" if sep else text + "Acquire-By-Hash: yes\n"
        )
        release.write_text(text, encoding="utf-8")
    prune_by_hash(dist, text, now)
    prune_retained(repo, dist)
    _sign(release, dist / "InRelease", dist / "Release.gpg", fingerprint)


BY_HASH_GRACE_DAYS = 14


def prune_by_hash(dist: Path, release_text: str, now: float | None = None) -> None:
    """Delete by-hash files that no Release has referenced for BY_HASH_GRACE_DAYS."""
    now = time.time() if now is None else now
    keep = set(_release_hashes(release_text).values())
    track = dist / "by-hash-unreferenced.json"
    since: dict[str, float] = json.loads(track.read_text()) if track.is_file() else {}
    for path in dist.glob("**/by-hash/SHA256/*"):
        key = path.relative_to(dist).as_posix()
        if path.name in keep:
            since.pop(key, None)
        elif now - since.setdefault(key, now) >= BY_HASH_GRACE_DAYS * 86400:
            path.unlink()
            since.pop(key)
    track.write_text(json.dumps(since, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sign(source: Path, inline: Path, detached: Path, fingerprint: str) -> None:
    base = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--local-user", fingerprint]
    passphrase = os.environ.get("APT_GPG_PASSPHRASE", "")
    base += ["--passphrase-fd", "0"] if passphrase else ["--passphrase", ""]
    stdin = passphrase + "\n" if passphrase else None
    run([*base, "--clearsign", "--output", inline, source], env=_gpg_env(), input_text=stdin)
    run([*base, "--detach-sign", "--output", detached, source], env=_gpg_env(), input_text=stdin)


def finalize(
    repo: Path, fingerprint: str, caddy_version: str, revision: int, ihash: str, debs: list[Path]
) -> None:
    """Write the public key and the signed release manifest, then add by-hash metadata."""
    key = run(["gpg", "--batch", "--armor", "--export", fingerprint], env=_gpg_env()).stdout
    if "BEGIN PGP PUBLIC KEY BLOCK" not in key:
        raise ScriptError("public key export failed")
    (repo / "gpg.key").write_text(key, encoding="utf-8")
    package_version = f"{caddy_version}+custom.{revision}"
    for deb in debs:
        if deb_field(deb, "Version") != package_version:
            raise ScriptError(f"{deb.name} is not version {package_version}; refusing to sign")
    packages = {d.name: sha256_file(d) for d in sorted(debs)}
    release_id = hashlib.sha256(
        json.dumps([package_version, ihash, packages], sort_keys=True).encode()
    ).hexdigest()[:16]
    manifest = {
        "release_id": release_id,
        "caddy_version": caddy_version,
        "revision": revision,
        "package_version": package_version,
        "inputs_hash": ihash,
        "signing_fingerprint": fingerprint,
        "packages": packages,
        "source_commit": os.environ.get("GITHUB_SHA", "unknown"),
    }
    path = repo / "release-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    add_by_hash(repo, fingerprint)
    _detached(path, repo / "release-manifest.json.asc", fingerprint)
    write_status(repo, fingerprint, "DEPLOYED")


STATUS_ORDER = ("DEPLOYED", "VERIFIED", "PUBLISHED")


def write_status(repo: Path, fingerprint: str, status: str) -> None:
    """Record the release state in a separate signed file; the manifest stays untouched."""
    if status not in STATUS_ORDER:
        raise ScriptError(f"unknown status {status!r}")
    manifest = json.loads((repo / "release-manifest.json").read_text(encoding="utf-8"))
    path = repo / "release-status.json"
    if path.is_file():
        old = json.loads(path.read_text(encoding="utf-8"))
        same = old["release_id"] == manifest["release_id"]
        if same and STATUS_ORDER.index(status) <= STATUS_ORDER.index(old["status"]):
            log("info", f"status stays {old['status']}; {status} is not an advance")
            return
    body = {"release_id": manifest["release_id"], "status": status}
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    _detached(path, repo / "release-status.json.asc", fingerprint)


def _detached(source: Path, target: Path, fingerprint: str) -> None:
    base = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--local-user", fingerprint]
    passphrase = os.environ.get("APT_GPG_PASSPHRASE", "")
    base += ["--passphrase-fd", "0"] if passphrase else ["--passphrase", ""]
    run(
        [*base, "--armor", "--detach-sign", "--output", target, source],
        env=_gpg_env(),
        input_text=passphrase + "\n" if passphrase else None,
    )


def require_fingerprint(value: str) -> str:
    """Return the normalized pin; a public key never vouches for itself, so a pin is mandatory."""
    value = value.replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", value):
        raise ScriptError("a full 40-hex signer fingerprint (APT_GPG_KEY_ID) is required")
    return value


BAD_SIGNATURE_STATUS = re.compile(r"\[GNUPG:\] (BADSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|ERRSIG) ")


def _require_signer(status: str, fingerprint: str, what: str) -> None:
    """Accept only a good signature from the pinned primary key; expired or revoked keys fail."""
    lines = status.splitlines()
    if any(BAD_SIGNATURE_STATUS.match(ln) for ln in lines):
        raise ScriptError(f"{what}: signature is bad, expired or made by an expired or revoked key")
    signers = [ln.split()[-1] for ln in lines if " VALIDSIG " in ln]
    if not any(" GOODSIG " in ln for ln in lines) or not signers:
        raise ScriptError(f"{what}: no valid signature")
    if signers[0].upper() != fingerprint:
        raise ScriptError(f"{what} is signed by an unexpected key")


def verify_state(
    directory: Path, fingerprint: str, release_id: str = "", package_version: str = ""
) -> dict:
    """Verify manifest and status; return the manifest.

    The pinned primary fingerprint must be the signer. Given release_id or package_version, the
    manifest must describe exactly that release, so an older signed state cannot stand in for it.
    """
    require_tools("gpg")
    fingerprint = require_fingerprint(fingerprint)
    with tempfile.TemporaryDirectory(prefix="verify-state-") as tmp:
        os.chmod(tmp, 0o700)
        env = _clean_env(GNUPGHOME=tmp)
        run(["gpg", "--batch", "--import", directory / "gpg.key"], env=env)
        for name in ("release-manifest.json", "release-status.json"):
            out = run(
                [
                    "gpg",
                    "--batch",
                    "--status-fd",
                    "1",
                    "--verify",
                    directory / f"{name}.asc",
                    directory / name,
                ],
                env=env,
            ).stdout
            _require_signer(out, fingerprint, name)
    manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
    status = json.loads((directory / "release-status.json").read_text(encoding="utf-8"))
    if status.get("release_id") != manifest.get("release_id"):
        raise ScriptError("release status belongs to a different release than the manifest")
    if release_id and manifest.get("release_id") != release_id:
        raise ScriptError(f"served release is {manifest.get('release_id')}, expected {release_id}")
    if package_version and manifest.get("package_version") != package_version:
        raise ScriptError(
            f"state holds {manifest.get('package_version')}, expected {package_version}"
        )
    return manifest


def check_ancestry(repo: Path, commit: str) -> None:
    """An older commit must never overwrite the state a newer commit produced."""
    path = repo / "release-manifest.json"
    if not path.is_file():
        return
    old = json.loads(path.read_text(encoding="utf-8")).get("source_commit", "unknown")
    if old in ("unknown", commit):
        return
    if not re.fullmatch(r"[0-9a-f]{40}", old) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ScriptError("source_commit is not a full commit id")
    if (
        run(
            ["git", "merge-base", "--is-ancestor", old, commit], check=False, env=_clean_env()
        ).returncode
        != 0
    ):
        raise ScriptError(f"published state comes from {old}, which is not an ancestor of {commit}")


def export_site(repo: Path, out: Path) -> None:
    for name in (
        "dists",
        "pool",
        "gpg.key",
        "release-manifest.json",
        "release-manifest.json.asc",
        "release-status.json",
        "release-status.json.asc",
    ):
        src = repo / name
        if not src.exists():
            raise ScriptError(f"repository is incomplete: {name} missing")
        if src.is_dir():
            shutil.copytree(src, out / name, dirs_exist_ok=True)
        else:
            out.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, out / name)
    retained = repo / RETAINED_DIR
    if retained.is_dir():
        shutil.copytree(retained, out, dirs_exist_ok=True)
    (out / ".nojekyll").write_text("", encoding="utf-8")
    (out / "index.html").write_text(
        "<!doctype html><title>xcaddy APT repository</title>"
        "<p>Signed APT repository for caddy-custom. See the project README for setup.</p>\n",
        encoding="utf-8",
    )


def _release_hashes(release: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    in_sha = False
    for line in release.splitlines():
        if line.startswith("SHA256:"):
            in_sha = True
        elif not line.startswith(" "):
            in_sha = False
        elif in_sha:
            digest, _size, name = line.split()
            hashes[name] = digest
    return hashes


def _release_sizes(release: str) -> dict[str, int]:
    sizes: dict[str, int] = {}
    in_sha = False
    for line in release.splitlines():
        if line.startswith("SHA256:"):
            in_sha = True
        elif not line.startswith(" "):
            in_sha = False
        elif in_sha:
            _digest, size, name = line.split()
            sizes[name] = int(size)
    return sizes


STATE_FILES = (
    "release-manifest.json",
    "release-manifest.json.asc",
    "release-status.json",
    "release-status.json.asc",
)
SAFE_REL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:/-]*")


def _safe_rel(name: str) -> str:
    """Reject paths from untrusted index files that could leave the site directory."""
    if not SAFE_REL_RE.fullmatch(name) or ".." in name.split("/"):
        raise ScriptError(f"unsafe path in repository metadata: {name!r}")
    return name


def _package_entries(packages: str) -> list[tuple[str, str]]:
    """(Filename, SHA256) of every stanza in a Packages index."""
    entries: list[tuple[str, str]] = []
    fields: dict[str, str] = {}
    for line in [*packages.splitlines(), ""]:
        if line.strip():
            if not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
        else:
            if "Filename" in fields:
                entries.append((_safe_rel(fields["Filename"]), fields.get("SHA256", "")))
            fields = {}
    return entries


def verify_site(
    site: Path, archs: tuple[str, ...] = ARCHS, fingerprint: str = "", release_id: str = ""
) -> None:
    """Check signatures, every index and by-hash file against Release, and package bytes.

    The signer must be the pinned primary key; with a release_id the manifest and the status
    file must describe exactly that release.
    """
    require_tools("gpg")
    fingerprint = require_fingerprint(fingerprint)
    dist = site / "dists" / CODENAME
    with tempfile.TemporaryDirectory(prefix="verify-gnupg-") as tmp:
        os.chmod(tmp, 0o700)
        env = _clean_env(GNUPGHOME=tmp)
        run(["gpg", "--batch", "--import", site / "gpg.key"], env=env)
        out = run(["gpg", "--batch", "--status-fd", "2", "--decrypt", dist / "InRelease"], env=env)
        _require_signer(out.stderr, fingerprint, "InRelease")
        release = (dist / "Release").read_text(encoding="utf-8")
        if out.stdout != release:
            raise ScriptError("InRelease and Release contain different metadata")
        detached = run(
            [
                "gpg",
                "--batch",
                "--status-fd",
                "1",
                "--verify",
                dist / "Release.gpg",
                dist / "Release",
            ],
            env=env,
        )
        _require_signer(detached.stdout, fingerprint, "Release.gpg")
    manifest = _verify_state_files(site, fingerprint, release_id)
    by_hash_enabled = "Acquire-By-Hash: yes" in release
    hashes = _release_hashes(release)
    sizes = _release_sizes(release)
    for name, digest in hashes.items():
        file = dist / _safe_rel(name)
        if (
            not file.is_file()
            or file.stat().st_size != sizes[name]
            or hashlib.sha256(file.read_bytes()).hexdigest() != digest
        ):
            raise ScriptError(f"{name} is missing or does not match the signed Release file")
        by_hash = file.parent / "by-hash" / "SHA256" / digest
        if by_hash_enabled and (not by_hash.is_file() or sha256_file(by_hash) != digest):
            raise ScriptError(f"by-hash file for {name} is missing or damaged")
    published: dict[str, str] = {}
    for arch in archs:
        rel = f"main/binary-{arch}/Packages"
        path = dist / rel
        if f"Package: {PACKAGE}" not in path.read_text(encoding="utf-8"):
            raise ScriptError(f"{rel} lists no {PACKAGE}")
        gz = dist / f"{rel}.gz"
        if gz.is_file() and gzip.decompress(gz.read_bytes()) != path.read_bytes():
            raise ScriptError(f"{rel}.gz differs from {rel}")
        for filename, digest in _package_entries(path.read_text(encoding="utf-8")):
            deb = site / filename
            if not deb.is_file() or sha256_file(deb) != digest:
                raise ScriptError(f"{filename} is missing or differs from the signed Packages")
            published[Path(filename).name] = digest
    if manifest is not None and any(
        manifest["packages"].get(name) != digest for name, digest in published.items()
    ):
        raise ScriptError("published packages differ from the signed release manifest")


def _verify_state_files(site: Path, fingerprint: str, release_id: str) -> dict | None:
    """Verify manifest and status signatures; return the manifest if present."""
    present = [(site / name).is_file() for name in STATE_FILES]
    if release_id and not all(present):
        raise ScriptError("release manifest or status file is missing")
    if not any(present):
        return None
    if not all(present):
        raise ScriptError("release manifest and status files are incomplete")
    return verify_state(site, fingerprint, release_id)


def _download(url: str, dest: Path, attempts: int = 6) -> None:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(response.read())
            return
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
            time.sleep(10 * (attempt + 1))
    raise ScriptError(f"cannot download {url}: {last}")


def verify_url(
    base: str, archs: tuple[str, ...] = ARCHS, fingerprint: str = "", release_id: str = ""
) -> None:
    """Fetch everything the signed Release index lists and verify it like a local site."""
    fingerprint = require_fingerprint(fingerprint)
    if not release_id:
        raise ScriptError("the expected release id is required to verify a public repository")
    base = base.rstrip("/")
    dist = f"dists/{CODENAME}"
    with tempfile.TemporaryDirectory(prefix="verify-url-") as tmp:
        root = Path(tmp)

        def fetch(name: str) -> None:
            _download(f"{base}/{_safe_rel(name)}", root / name)

        for name in ("gpg.key", *STATE_FILES, f"{dist}/InRelease", f"{dist}/Release"):
            fetch(name)
        fetch(f"{dist}/Release.gpg")
        hashes = _release_hashes((root / dist / "Release").read_text(encoding="utf-8"))
        for name, digest in hashes.items():
            fetch(f"{dist}/{name}")
            fetch(f"{dist}/{Path(name).parent}/by-hash/SHA256/{digest}")
        for arch in archs:
            rel = f"main/binary-{arch}/Packages"
            if rel not in hashes or f"{rel}.gz" not in hashes:
                raise ScriptError(f"{rel} is not listed in the Release file")
            index = (root / dist / rel).read_text(encoding="utf-8")
            for filename, _digest in _package_entries(index):
                fetch(filename)
        verify_site(root, archs, fingerprint, release_id)
    log("info", f"{base} serves a correctly signed repository")


def fetch_public_state(base: str, out: Path, fingerprint: str) -> bool:
    """Download and verify the public manifest and status; False when none is published yet."""
    fingerprint = require_fingerprint(fingerprint)
    base = base.rstrip("/")
    try:
        _download_once(f"{base}/release-manifest.json", out / "release-manifest.json")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise ScriptError(f"unexpected HTTP {exc.code} from the public manifest URL") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ScriptError(f"cannot fetch the public manifest: {exc}") from exc
    for name in (*STATE_FILES[1:], "gpg.key"):
        _download(f"{base}/{name}", out / name)
    verify_state(out, fingerprint)
    return True


def _download_once(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url, timeout=30) as response:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(response.read())


def install_apt_key(public_key: Path, directory: Path) -> Path:
    """Copy the published key where APT reads it correctly: .asc if armored, else .gpg."""
    armored = public_key.read_bytes().startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    target = directory / ("xcaddy.asc" if armored else "xcaddy.gpg")
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(public_key, target)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import-key")
    imp.add_argument("--no-passphrase", action="store_true", help="tests only")
    sub.add_parser("cleanup")
    for name in ("init", "add", "finalize", "export-site"):
        p = sub.add_parser(name)
        p.add_argument("--repo-dir", required=True, type=Path)
        if name in ("init", "finalize"):
            p.add_argument("--fingerprint", required=True)
        if name == "add":
            p.add_argument("debs", nargs="+", type=Path)
        if name == "finalize":
            p.add_argument("--caddy-version", required=True)
            p.add_argument("--revision", required=True, type=int)
            p.add_argument("--inputs-hash", required=True)
            p.add_argument("--debs", nargs="+", required=True, type=Path)
        if name == "export-site":
            p.add_argument("--out", required=True, type=Path)
    st = sub.add_parser("set-status")
    st.add_argument("--repo-dir", required=True, type=Path)
    st.add_argument("--fingerprint", required=True)
    st.add_argument("--status", required=True, choices=STATUS_ORDER)
    vst = sub.add_parser("verify-state")
    vst.add_argument("directory", type=Path)
    vst.add_argument("--fingerprint", required=True)
    vst.add_argument("--expect-release-id", default="")
    vst.add_argument("--expect-package-version", default="")
    anc = sub.add_parser("check-ancestry")
    anc.add_argument("--repo-dir", required=True, type=Path)
    anc.add_argument("--commit", required=True)
    vs = sub.add_parser("verify-site")
    vs.add_argument("site", type=Path)
    vs.add_argument("--fingerprint", required=True)
    vs.add_argument("--expect-release-id", default="")
    rid = sub.add_parser("release-id")
    rid.add_argument("--repo-dir", required=True, type=Path)
    fp = sub.add_parser("fetch-public")
    fp.add_argument("url", nargs="?", default=PAGES_URL)
    fp.add_argument("--out", required=True, type=Path)
    fp.add_argument("--fingerprint", required=True)
    vu = sub.add_parser("verify-url")
    vu.add_argument("url", nargs="?", default=PAGES_URL)
    vu.add_argument("--fingerprint", required=True)
    vu.add_argument("--expect-release-id", required=True)
    ns = parser.parse_args()

    if ns.command == "import-key":
        set_output("fingerprint", import_key(not ns.no_passphrase))
    elif ns.command == "cleanup":
        cleanup_keyring()
    elif ns.command == "init":
        init_repo(ns.repo_dir, ns.fingerprint)
    elif ns.command == "add":
        set_output("added", str(add_packages(ns.repo_dir, ns.debs)).lower())
    elif ns.command == "finalize":
        finalize(
            ns.repo_dir, ns.fingerprint, ns.caddy_version, ns.revision, ns.inputs_hash, ns.debs
        )
    elif ns.command == "export-site":
        export_site(ns.repo_dir, ns.out)
    elif ns.command == "set-status":
        write_status(ns.repo_dir, ns.fingerprint, ns.status)
    elif ns.command == "verify-state":
        verify_state(ns.directory, ns.fingerprint, ns.expect_release_id, ns.expect_package_version)
    elif ns.command == "check-ancestry":
        check_ancestry(ns.repo_dir, ns.commit)
    elif ns.command == "verify-site":
        verify_site(ns.site, fingerprint=ns.fingerprint, release_id=ns.expect_release_id)
    elif ns.command == "release-id":
        manifest = json.loads((ns.repo_dir / "release-manifest.json").read_text(encoding="utf-8"))
        set_output("release_id", manifest["release_id"])
    elif ns.command == "fetch-public":
        found = fetch_public_state(ns.url, ns.out, ns.fingerprint)
        set_output("present", str(found).lower())
    else:
        verify_url(ns.url, fingerprint=ns.fingerprint, release_id=ns.expect_release_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, __file__, __doc__))
