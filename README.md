# xcaddy

Daily-checked, plugin-extended Caddy as the Debian package `xcaddy`, built with xcaddy on
GitHub-hosted runners and served from a GPG-signed APT repository on GitHub Pages:
`https://gill-bates.github.io/xcaddy/`.

## 1. How it works

`build.yml` runs daily at 04:15 UTC, on `workflow_dispatch` (input `force_build`) and on pushes to `main`
that touch `config/`, `scripts/`, `packaging/`, `apt/` or the workflow.
GitHub starts `schedule` only on the default branch (`main`). Publishing (`sign-and-publish`, `recover-stage` and the jobs that
depend on them) runs only on the default branch; a `workflow_dispatch` from any other branch builds and tests but publishes nothing.

```
check-version -> build (amd64, arm64) -> package -> install-test, trivy-scan
  -> prepare-apt-repository -> sign-and-publish -> deploy-pages -> verify-publication
```

- `check-version` compares the latest stable Caddy release and a hash of the build inputs (plugin list,
  build and packaging files, Go and xcaddy versions) with the public `release-manifest.json`.
  Nothing changed: the run ends successfully with "No new version".
- Publishing needs both architectures, passing tests, a passing Trivy gate and valid packages.
- Runs are serialized and never cancelled; GitHub keeps one waiting run, so a newer run replaces a waiting `workflow_dispatch` with `force_build`. Dispatch it again if it was replaced.
  A failed run never touches the published state; the state lives on the `apt-repo` branch (reprepro
  `conf`, `db`, pool) and is pushed fast-forward only.
- `stable` holds only the newest version per architecture; reprepro drops older ones, which is the retention.
- `ci.yml` validates pull requests without secrets (ruff, pytest, ShellCheck, actionlint, probe build,
  install and upgrade test with a throwaway key). `security.yml` rescans the published packages weekly.
- No separate `pages.yml`: the Pages deployment is one job that needs the signed artifact of the same run.

Runners: `ubuntu-26.04` and `ubuntu-26.04-arm` (labels listed in the runner-images README; `actionlint`
needs `.github/actionlint.yaml` for them).

## 2. Plugins

`config/plugins.txt`, one entry per line: `github.com/owner/repo[/vN][@version]`; `#` starts a comment.
`@version` is `vX.Y.Z` or a 40-character commit.

```text
github.com/caddy-dns/cloudflare
github.com/mholt/caddy-ratelimit@v0.1.0
```

Validate locally: `python3 scripts/plugins.py validate`. Entries are matched against a strict
pattern and passed to xcaddy as list arguments, never to a shell. `config/plugins.lock` pins the resolved versions and h1 checksums; builds use only the lock. After editing `plugins.txt` run `python3 scripts/lock.py update` (or the maintainers update the lock in a pull request). Any change of the lock or the build inputs triggers a build with the next revision (`2.x.y+custom.N`). The Caddy module IDs a plugin registers are read from its sources into the lock; the build fails if `caddy list-modules` lacks them.

## 3. Manual build

Needs Go and xcaddy (versions in `scripts/toolchain.py`) on a host of the target architecture.

```bash
python3 scripts/build.py --caddy-version 2.11.9 --arch amd64 --out build
python3 scripts/package.py build --version 2.11.9+custom.1 --arch amd64 \
  --binary build/caddy --manifest build/build-manifest.json --out dist
```

The package contains `/usr/share/doc/xcaddy/build-manifest.json` (Caddy, plugin, Go and xcaddy versions,
binary SHA-256).

## 4. Repository setup

1. Settings, Pages: Source "GitHub Actions".
2. Settings, Actions, General: workflow permissions "Read repository contents" (jobs raise it themselves).
3. Environments: create `apt-publish` (secrets below, restrict to `main`, optional required reviewers) and
   `github-pages` (restrict to `main`).
4. Branch protection on `main`: no force pushes. Do not protect `apt-repo` against the workflow token.
5. Secrets in `apt-publish`: `APT_GPG_PRIVATE_KEY`, `APT_GPG_PASSPHRASE`. Repository variable `APT_GPG_KEY_ID` (required: the full 40-hex primary fingerprint;
   the publish job and the version check reject any other signer).

### Signing key (once)

```bash
export GNUPGHOME="$(mktemp -d)"
gpg --quick-generate-key "xcaddy APT <apt@example.invalid>" ed25519 sign 5y   # asks for a passphrase
gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}'      # fingerprint
gpg --armor --export-secret-keys "<fingerprint>" | gh secret set APT_GPG_PRIVATE_KEY --env apt-publish
gh secret set APT_GPG_PASSPHRASE --env apt-publish
rm -rf "$GNUPGHOME"
```

Set the fingerprint as `APT_GPG_KEY_ID` **before the first release** (bootstrap: it is read from your own local key,
never from the published `gpg.key`); every workflow, including the weekly rescan, fails without it and trusts only
manifests and indexes signed by exactly that key.

Key rotation (manual, tooling deferred): generate the new key as above; ship a `gpg.key` containing old and new
public key (`cat old.asc new.asc`) and keep signing with the old key until clients have fetched it (at least
one release cycle, announce the date); switch `APT_GPG_PRIVATE_KEY`, `APT_GPG_PASSPHRASE` and `APT_GPG_KEY_ID`
to the new key, publish, and drop the old public key in a later release. Clients refresh
`/etc/apt/keyrings/xcaddy.asc` from the published `gpg.key`.

## 5. Installation (Debian, Ubuntu)

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://gill-bates.github.io/xcaddy/gpg.key -o /etc/apt/keyrings/xcaddy.asc
sudo tee /etc/apt/sources.list.d/xcaddy.sources >/dev/null <<'SRC'
Types: deb
URIs: https://gill-bates.github.io/xcaddy
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/xcaddy.asc
SRC
sudo apt update && sudo apt install xcaddy
```

Upgrade with `sudo apt update && sudo apt upgrade`.

## 6. Operation

The `xcaddy` package replaces the official `caddy` package and keeps its paths: binary
`/usr/bin/caddy`, unit `caddy.service`, service user and group `caddy`, configuration
`/etc/caddy/Caddyfile`, and data `/var/lib/caddy`. The Caddyfile is a conffile, so local
configuration is retained during upgrades. Caddy uses its standard admin API on `localhost:2019`.

| Action | Behavior |
| --- | --- |
| install | enabled; started only if the configuration validates and the ports are free |
| upgrade | restarted only if the service ran and the configuration validates |
| `apt remove` | service stopped, configuration and data kept |
| `apt purge` | configuration, data (`/var/lib/caddy`, **including TLS certificates and ACME account keys**) and service user removed; cleanup stays inside package directories and does not cross symlinks or mount points |

Back up the TLS identities before a purge or a host move:

```bash
sudo tar --numeric-owner -C / -czf xcaddy-backup-$(date +%F).tar.gz var/lib/caddy etc/caddy
```

```bash
sudo systemctl status caddy
sudo systemctl reload caddy
sudo apt remove xcaddy      # or: sudo apt purge xcaddy
```

Installing `xcaddy` replaces the official `caddy` package. The existing `/etc/caddy/Caddyfile`
and `/var/lib/caddy` data stay in place, so Caddy can reuse its configuration and TLS certificates.
Purging `xcaddy` removes those paths and the `caddy` service account.

## 7. Trivy policy

Per architecture, Trivy scans the unpacked package (binary with Go modules, files) and the build configuration
(misconfiguration, secrets). CRITICAL and HIGH block publishing; MEDIUM and LOW are listed in the summary.
Scanner or database errors, missing or invalid reports, and a scan that finds no Go modules in the
binary fail the job. Reports and `summary-*.md` are artifacts, also on failure. No ignore list exists.

## 8. Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pytest -q
```

`tests/test_publish.py` needs `reprepro` and `gpg` (skipped otherwise). `scripts/test.py apt` installs
packages on the host and therefore needs `--allow-host-changes`; run it only in disposable environments.

## 9. Troubleshooting

| Symptom | Cause and action |
| --- | --- |
| Publish job: "refusing to publish unsigned" | Secrets missing in the `apt-publish` environment |
| "is not newer than published" | Downgrade refused; the repository already holds an equal or newer revision |
| Pages deploy failed after the push to `apt-repo` | Re-run the failed `deploy-pages` job; the artifact is from the same run |
| `Hash Sum mismatch` on clients | Run `apt update` again; by-hash metadata keeps old index files reachable |
| Status stays DEPLOYED | `verify-publication` failed; the next run detects it (`recover`), re-stages the last signed snapshot and confirms |
| Scheduled run did nothing | No new stable Caddy and no input change (see the job summary) |

Recovery of an older package: take the `.deb` from the workflow artifacts or a release archive and
publish it through a new, higher revision; versions are never reused for different bytes.
