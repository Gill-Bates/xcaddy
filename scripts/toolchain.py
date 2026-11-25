#!/usr/bin/env python3
#
# scripts/toolchain.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Pinned toolchain versions; Renovate updates the constants, the workflows read them via main()."""

XCADDY_VERSION = "v0.4.7"  # renovate: datasource=github-releases depName=caddyserver/xcaddy
GO_VERSION = "1.27.4"  # renovate: datasource=golang-version depName=go
TRIVY_VERSION = "v0.76.2"  # renovate: datasource=github-releases depName=aquasecurity/trivy

BUILD_FLAGS = "GOOS=linux CGO_ENABLED=0"
# Mirrors Caddy PR #8368 until the dependency update reaches a stable Caddy release.
BUILD_REPLACEMENTS = (
    "github.com/smallstep/certificates@v0.30.2=github.com/smallstep/certificates@v0.30.3-0.20261105213751-6d5a251fbe01",
    "go.step.sm/crypto@v0.92.0=go.step.sm/crypto@v0.92.1",
    "golang.org/x/net@v0.61.0=golang.org/x/net@v0.62.0",
)


def main() -> int:
    for key in ("XCADDY_VERSION", "GO_VERSION", "TRIVY_VERSION"):
        print(f"{key}={globals()[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
