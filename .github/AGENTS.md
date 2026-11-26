# .github

## Purpose
CI/CD for `xcaddy`: `workflows/ci.yml` (PR gate, no secrets), `build.yml` (check, build, scan, sign, publish),
`security.yml` (weekly read-only rescan), Renovate policy and the actionlint runner-label list.

## Rules
- Every third-party action is pinned to a full commit SHA with a version comment; verify new SHAs with `gh api repos/<owner>/<repo>/commits/<sha>`.
- Publishing and secrets only in the signing jobs `sign-and-publish` and `confirm-published` (environment `apt-publish`, `main` only); never `pull_request_target`.
- No `continue-on-error`, no Trivy ignore file, no weakened gate to get green. Exceptions need the user's agreement.
- Script logic is Python (standard library) in `scripts/`; Bash only in `packaging/` maintainer scripts and one-line workflow calls.
- Versions of Go, xcaddy and Trivy live in `scripts/toolchain.py` (Renovate regex manager); plugin pins in `config/plugins.txt`.
- Agents do not push, tag or publish; the user does.

## Checks
`ruff check . && ruff format --check . && pytest -q`; `shellcheck -s sh packaging/postinst packaging/prerm packaging/postrm`; `actionlint -config-file .github/actionlint.yaml`.
