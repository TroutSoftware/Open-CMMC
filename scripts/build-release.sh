#!/usr/bin/env bash
# Build a CMMC-Filebrowser release tarball on a Linux build host.
#
# Output: cmmc-filebrowser-<version>-<os>-<arch>.tar.gz containing:
#   bin/cmmc-filebrowser          FIPS-compiled Go binary (-trimpath)
#   frontend/dist/                built SPA bundle (pnpm run build)
#   config/                       installer + systemd units + bootstrap
#   docs/                         operator + architecture docs
#   VERSION                       git tag or short SHA
#   SHA256SUMS                    checksums for every file under the tarball
#
# The tarball is consumed by `install.sh deploy --from-release <path>`
# on target appliances that don't have (or don't want) node + go +
# pnpm locally. This is the air-gap-friendly deploy path.
#
# Host requirements:
#   - Linux (RHEL 9, AlmaLinux 9, or compatible)
#   - go-toolset (1.24+ for GOFIPS140=v1.0.0)
#   - Node >= 18.12 (pnpm v10 requirement)
#   - pnpm (installed on demand via corepack or `npm install -g pnpm`)
#   - tar, sha256sum, git
#
# Usage:
#   bash scripts/build-release.sh                    # auto-version from git
#   VERSION=v0.1.0 bash scripts/build-release.sh     # explicit tag
#   OUTPUT_DIR=/tmp bash scripts/build-release.sh    # custom output location
#
# Exit codes: non-zero on any build step failure. The tarball is only
# produced if every step succeeded, so a successful run always yields
# a complete + checksummable artifact.

set -Eeuo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_DIR/dist}"

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
fail(){ printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# --- version -----------------------------------------------------------
# Prefer an explicit $VERSION (CI passes the release tag). Otherwise
# derive from git: tag if we're exactly on one, else short SHA with
# "-dirty" suffix when the tree has uncommitted changes.
if [ -z "${VERSION:-}" ]; then
  if git -C "$REPO_DIR" describe --tags --exact-match >/dev/null 2>&1; then
    VERSION=$(git -C "$REPO_DIR" describe --tags --exact-match)
  else
    sha=$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
    dirty=""
    if ! git -C "$REPO_DIR" diff --quiet 2>/dev/null || \
       ! git -C "$REPO_DIR" diff --cached --quiet 2>/dev/null; then
      dirty="-dirty"
    fi
    VERSION="dev-${sha}${dirty}"
  fi
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

ARTIFACT="cmmc-filebrowser-${VERSION}-${OS}-${ARCH}"
STAGE="$OUTPUT_DIR/$ARTIFACT"
TARBALL="$OUTPUT_DIR/${ARTIFACT}.tar.gz"

# --- preflight ---------------------------------------------------------

say "Preflight"
command -v go >/dev/null      || fail "go-toolset required"
command -v node >/dev/null    || fail "node >= 18.12 required"
command -v tar >/dev/null     || fail "tar required"
command -v sha256sum >/dev/null || fail "sha256sum required"

node_major=$(node --version | sed -E 's/^v([0-9]+).*/\1/')
[ "$node_major" -ge 18 ] || fail "node $node_major too old; need >= 18.12"

# pnpm via corepack (preferred) or global npm install (fallback).
if ! command -v pnpm >/dev/null 2>&1; then
  if command -v corepack >/dev/null 2>&1; then
    corepack enable >/dev/null
    corepack prepare pnpm@latest --activate >/dev/null
  else
    npm install -g pnpm >/dev/null || fail "pnpm install failed"
  fi
fi
echo "    go:    $(go version | awk '{print $3}')"
echo "    node:  $(node --version)"
echo "    pnpm:  $(pnpm --version)"
echo "    arch:  $OS/$ARCH"
echo "    build: $VERSION"

# --- build frontend ----------------------------------------------------

say "Build frontend (pnpm install + build)"
(cd "$REPO_DIR/frontend" && pnpm install --prefer-offline 2>&1 | tail -3)
(cd "$REPO_DIR/frontend" && pnpm run build 2>&1 | tail -3)
[ -s "$REPO_DIR/frontend/dist/index.html" ] || fail "frontend/dist/index.html missing after build"

# --- build binary ------------------------------------------------------

say "Build Go binary (FIPS + trimpath)"
(
  cd "$REPO_DIR"
  GOFIPS140=v1.0.0 CGO_ENABLED=0 go build \
    -tags noboringcrypto \
    -trimpath \
    -ldflags "-s -w -X main.Version=$VERSION" \
    -o "$STAGE/bin/cmmc-filebrowser" \
    .
)
chmod +x "$STAGE/bin/cmmc-filebrowser"
binsize=$(stat -c '%s' "$STAGE/bin/cmmc-filebrowser" 2>/dev/null || stat -f '%z' "$STAGE/bin/cmmc-filebrowser")
echo "    binary: $STAGE/bin/cmmc-filebrowser ($binsize bytes)"

# --- stage config / docs / frontend-dist ------------------------------

say "Stage release tree"
install -d "$STAGE/config/systemd" "$STAGE/config/rsyslog" \
           "$STAGE/config/keycloak" "$STAGE/config/wazuh/decoders" \
           "$STAGE/config/wazuh/rules" "$STAGE/docs" \
           "$STAGE/frontend"

cp "$REPO_DIR/config/install.sh"                              "$STAGE/config/install.sh"
cp "$REPO_DIR/config/systemd/cmmc-filebrowser.service"        "$STAGE/config/systemd/"
cp "$REPO_DIR/config/systemd/cmmc-keycloak.service"           "$STAGE/config/systemd/"
cp "$REPO_DIR/config/systemd/cmmc-wazuh.service"              "$STAGE/config/systemd/"
cp "$REPO_DIR/config/rsyslog/50-cmmc-filebrowser.conf"        "$STAGE/config/rsyslog/"
cp "$REPO_DIR/config/keycloak/bootstrap.sh"                   "$STAGE/config/keycloak/"
cp "$REPO_DIR/config/keycloak/bootstrap_test.sh"              "$STAGE/config/keycloak/"
cp "$REPO_DIR/config/wazuh/podman-compose.wazuh.yml"          "$STAGE/config/wazuh/"
cp "$REPO_DIR/config/wazuh/decoders/filebrowser-cmmc.xml"     "$STAGE/config/wazuh/decoders/"
cp "$REPO_DIR/config/wazuh/rules/filebrowser-cmmc.xml"        "$STAGE/config/wazuh/rules/"

# Docs — whole docs/ tree; these carry operator-facing guidance.
cp -r "$REPO_DIR/docs/." "$STAGE/docs/"

# Frontend dist — embedded in the binary, but shipped alongside for
# operators who want to inspect the built SPA (audit / security review).
cp -r "$REPO_DIR/frontend/dist" "$STAGE/frontend/"

# --- version + checksums ---------------------------------------------

say "Stamp version + checksums"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"
(cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 \
  | xargs -0 sha256sum) > "$STAGE/SHA256SUMS"

# --- tar ---------------------------------------------------------------

say "Pack tarball"
(cd "$OUTPUT_DIR" && tar -czf "$TARBALL" -C "$OUTPUT_DIR" "$ARTIFACT")
tarsize=$(stat -c '%s' "$TARBALL" 2>/dev/null || stat -f '%z' "$TARBALL")
tar_sha=$(sha256sum "$TARBALL" | awk '{print $1}')

cat <<EOF

──────────────────────────────────────────────────────────────────────
 Release artifact ready
──────────────────────────────────────────────────────────────────────
 File:   $TARBALL
 Size:   $tarsize bytes
 SHA256: $tar_sha
 Version: $VERSION

 Install on a target appliance:

   sudo install.sh deploy --from-release <path-or-url>

 (The installer extracts into /opt/cmmc-filebrowser-release-staging/,
  validates SHA256SUMS, and bypasses phase_frontend + phase_binary.)
──────────────────────────────────────────────────────────────────────
EOF
