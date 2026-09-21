#!/usr/bin/env bash
# CMMC-Filebrowser single-host installer (prod-grade).
#
# Supported base OS (all co-equal — no distro-specific branching):
#   RHEL 9        — Red Hat Enterprise Linux (subscription)
#   AlmaLinux 9   — free binary-compatible rebuild, same CMVP #4774
#                   OpenSSL module via inheritance
#   Rocky 9       — community rebuild (tested-compatible, no docs)
# Requires: podman + systemd + FIPS mode (or SKIP_FIPS_CHECK=1 for dev).
# Output: a running cmmc-filebrowser + cmmc-keycloak (OIDC IdP),
# optionally a cmmc-wazuh bundle, all under systemd.
#
# Idempotent: safe to re-run. Each phase checks "already done?" and
# skips rather than erroring. The one exception is the env file —
# once written we never overwrite it, so rotating the KEK / HMAC
# keys is a deliberate manual operation.
#
# Usage:
#   sudo FB_ADMIN_USER=jsmith config/install.sh deploy          # production
#   sudo config/install.sh deploy --demo                        # evaluation org
#   sudo config/install.sh deploy --with-smb --ot-ip 10.20.0.5   # + shop-floor SMB (docs/smb-shop-floor.md)
#        optional: --ot-interface eth1 | --ot-vlan 20 | --smb-image REF | --legacy-ip IP
#   sudo config/install.sh deploy --with-wazuh                  # + bundled Wazuh
#   sudo config/install.sh deploy --from-release <path|url>     # prebuilt tarball
#   sudo config/install.sh deploy --no-clamav                   # skip AV provisioning
#   sudo config/install.sh enable-av                            # retry AV, flip to required
#   sudo config/install.sh backup <dir>                         # full backup
#   sudo config/install.sh restore <dir>                        # restore a backup
#   sudo config/install.sh status                               # health check
#   sudo config/install.sh uninstall                            # clean teardown
#   config/install.sh help
#
# Who can log in — pick ONE (deploy refuses if you pick neither):
#   FB_ADMIN_USER=<name>  provision one named administrator. Temporary
#                         password is generated and printed once.
#   --demo                seed the five-person evaluation roster with a
#                         shared temp password. EVALUATION ONLY — never
#                         on a system that will hold real CUI.
#
# Override knobs (env vars):
#   FB_INSTALL_PREFIX     default /usr/local/bin
#   FB_DATA_DIR           default /srv/cmmc-filebrowser/files
#   FB_STATE_DIR          default /var/lib/cmmc-filebrowser
#   FB_ETC_DIR            default /etc/cmmc-filebrowser
#   FB_LISTEN_PORT        default 8443
#   FB_USER               default cmmc-filebrowser
#   KC_BIND_PORT          default 8081 (loopback-only)
#   SKIP_FIPS_CHECK       default 0 (set 1 on dev VMs without FIPS mode)
#   FB_ADMIN_EMAIL        default <FB_ADMIN_USER>@localhost
#   FB_ADMIN_FIRST/LAST   default the username

set -Eeuo pipefail

# --- knobs + constants ------------------------------------------------

FB_INSTALL_PREFIX="${FB_INSTALL_PREFIX:-/usr/local/bin}"
FB_DATA_DIR="${FB_DATA_DIR:-/srv/cmmc-filebrowser/files}"
FB_STATE_DIR="${FB_STATE_DIR:-/var/lib/cmmc-filebrowser}"
FB_ETC_DIR="${FB_ETC_DIR:-/etc/cmmc-filebrowser}"
FB_LISTEN_PORT="${FB_LISTEN_PORT:-8443}"
FB_USER="${FB_USER:-cmmc-filebrowser}"
KC_BIND_PORT="${KC_BIND_PORT:-8081}"
FB_TLS_DIR="${FB_TLS_DIR:-/etc/cmmc-filebrowser/tls}"
SKIP_FIPS_CHECK="${SKIP_FIPS_CHECK:-0}"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WITH_WAZUH=0
WITH_SMB=0
SMB_OT_IF=""
SMB_OT_IP=""
SMB_IMAGE=""
SMB_LEGACY_IP=""
SMB_OT_VLAN=""
WIPE_STATE=0
# Demo roster is opt-in. See the "Who can log in" block in the header and
# § 7 of config/keycloak/bootstrap.sh for why the default flipped.
WITH_DEMO=0
# Escape hatch for shops running AV at another layer (mount filter,
# endpoint agent). Leaves 3.14.2 / 3.14.5 to the customer.
NO_CLAMAV=0
EXT_TLS_CERT=""
EXT_TLS_KEY=""
FROM_RELEASE=""

# detect_host_ip picks the appliance's primary IP — the address
# clients on the LAN will reach the service at. Priority order:
#   1. FB_HOST_IP env var — explicit operator override. Always wins.
#   2. ip route get 1.1.1.1 — the source IP for outbound traffic.
#      This is the correct answer 99% of the time: it's whichever
#      interface the default route uses. Docker bridges, loopback,
#      and secondary NICs are skipped.
#   3. hostname -I first field — fallback if `ip` is missing.
#   4. 127.0.0.1 — last resort so env generation doesn't crash.
# The result is embedded in /etc/cmmc-filebrowser/environment at
# install time, NOT baked into any committed file. Re-deploy on a
# host whose IP changed → operator either overrides FB_HOST_IP or
# re-runs install.sh deploy (env file is preserved; they'd need to
# `uninstall --wipe-state` first to regenerate against the new IP).
detect_host_ip() {
  if [ -n "${FB_HOST_IP:-}" ]; then
    printf '%s' "$FB_HOST_IP"
    return 0
  fi
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
  fi
  if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  [ -z "$ip" ] && ip="127.0.0.1"
  printf '%s' "$ip"
}

# detect_host_name picks a DNS name for the appliance. WebAuthn's
# browser spec rejects IP-address origins — you cannot enroll or
# use a passkey against `https://192.168.x.y`. A hostname is
# required for the Relying Party ID. Priority:
#   1. FB_HOST_NAME env var — explicit operator override.
#   2. hostname -f — the FQDN, if it resolves.
#   3. cmmc.local — deployment-friendly fallback. Operators add
#      `<host_ip> cmmc.local` to /etc/hosts on client machines
#      until a real DNS record is available; mDNS (Avahi) on the
#      appliance advertises .local hostnames automatically on most
#      LANs so this often "just works" on macOS without /etc/hosts.
# The result lands in the cert's DNS SANs + the OIDC env URIs, so
# operators end up browsing `https://<host_name>:8443` from their
# laptops and passkey enrollment works.
detect_host_name() {
  if [ -n "${FB_HOST_NAME:-}" ]; then
    printf '%s' "$FB_HOST_NAME"
    return 0
  fi
  local name=""
  name=$(hostname -f 2>/dev/null || true)
  # hostname -f returns "localhost.localdomain" on a default RHEL
  # install — useless for LAN browser access from another host.
  # Fall through to cmmc.local if we got the default.
  case "$name" in
    ""|"localhost"|"localhost.localdomain") name="cmmc.local" ;;
  esac
  printf '%s' "$name"
}

# Colored phase headers — operators eyeball this log when things go
# sideways; contrast helps find the last successful phase quickly.
say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()  { printf '    \033[1;32mok\033[0m %s\n' "$*"; }
note(){ printf '    %s\n' "$*"; }
warn(){ printf '    \033[1;33m!!\033[0m %s\n' "$*" >&2; }
fail(){ printf '    \033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# --- argument parsing -------------------------------------------------

cmd="${1:-help}"
shift || true
# Non-flag arguments (backup/restore destination). Declared before the
# loop so `set -u` is satisfied even when nothing positional is passed.
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --with-wazuh)      WITH_WAZUH=1 ;;
    --with-smb)        WITH_SMB=1 ;;
    --ot-vlan=*)       SMB_OT_VLAN="${1#*=}" ;;
    --ot-vlan)         shift; SMB_OT_VLAN="$1" ;;
    --ot-interface=*)  SMB_OT_IF="${1#*=}" ;;
    --ot-interface)    shift; SMB_OT_IF="$1" ;;
    --ot-ip=*)         SMB_OT_IP="${1#*=}" ;;
    --ot-ip)           shift; SMB_OT_IP="$1" ;;
    --smb-image=*)     SMB_IMAGE="${1#*=}" ;;
    --smb-image)       shift; SMB_IMAGE="$1" ;;
    --legacy-ip=*)     SMB_LEGACY_IP="${1#*=}" ;;
    --legacy-ip)       shift; SMB_LEGACY_IP="$1" ;;
    --demo)            WITH_DEMO=1 ;;
    --no-clamav)       NO_CLAMAV=1 ;;
    --wipe-state)      WIPE_STATE=1 ;;
    --tls-cert=*)      EXT_TLS_CERT="${1#*=}" ;;
    --tls-cert)        shift; EXT_TLS_CERT="$1" ;;
    --tls-key=*)       EXT_TLS_KEY="${1#*=}" ;;
    --tls-key)         shift; EXT_TLS_KEY="$1" ;;
    --from-release=*)  FROM_RELEASE="${1#*=}" ;;
    --from-release)    shift; FROM_RELEASE="$1" ;;
    --help|-h)         cmd=help ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) POSITIONAL+=("$1") ;;
  esac
  shift
done

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "this command requires root (run with sudo)"
  fi
}

# --- help -------------------------------------------------------------

cmd_help() {
  # Print the header comment block: every line from line 2 up to the
  # first line that is not a comment. Previously a hardcoded 2,22p,
  # which silently truncated the usage text as the header grew.
  awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
}

# --- preflight --------------------------------------------------------
#
# Any failure here aborts the run — we'd rather stop before touching
# /etc than half-install and leave the operator to diagnose partial
# state.

preflight() {
  say "Preflight"

  # Identity posture. A realm with no administrator and no demo roster
  # has no way in; a realm seeded with the demo roster on a production
  # box has five accounts whose password is published in this repo.
  # Both are install-time mistakes that are painful to unwind later, so
  # refuse to guess and make the operator state the intent once.
  if [ "$WITH_DEMO" = "1" ] && [ -n "${FB_ADMIN_USER:-}" ]; then
    fail "--demo and FB_ADMIN_USER are mutually exclusive — pick one"
  fi
  if [ "$WITH_DEMO" = "0" ] && [ -z "${FB_ADMIN_USER:-}" ]; then
    cat >&2 <<'EOF'

  No login identity selected. Choose one:

    Production — provision one named administrator:
      sudo FB_ADMIN_USER=jsmith config/install.sh deploy

    Evaluation — seed the five-person demo org (shared temp password,
    never on a system that will hold real CUI):
      sudo config/install.sh deploy --demo

EOF
    fail "refusing to deploy without an administrator or --demo"
  fi
  if [ "$WITH_DEMO" = "1" ]; then
    warn "demo roster enabled — evaluation only, not for real CUI"
  else
    ok "administrator: ${FB_ADMIN_USER}"
  fi

  # OS: RHEL/Alma/Rocky 9. We don't try to support other distros here
  # because the FIPS posture, SELinux policy, and systemd version
  # assumptions are all RHEL-family-specific.
  if [ ! -f /etc/os-release ]; then
    fail "/etc/os-release missing — unsupported OS"
  fi
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    rhel:9*|almalinux:9*|rocky:9*) ok "OS: $PRETTY_NAME" ;;
    *) fail "unsupported OS: ${PRETTY_NAME:-unknown} (need RHEL 9 / AlmaLinux 9 / Rocky 9)" ;;
  esac

  # systemd
  command -v systemctl >/dev/null || fail "systemctl not found"
  ok "systemd present"

  # podman
  command -v podman >/dev/null || fail "podman not installed — run: sudo dnf install -y podman"
  ok "podman: $(podman --version)"

  # FIPS mode — CMMC production MUST run with host FIPS on. Dev VMs
  # often don't; respect SKIP_FIPS_CHECK=1 but print a loud warning
  # so a forgotten dev override isn't mistaken for prod-ready.
  if command -v fips-mode-setup >/dev/null 2>&1; then
    if fips-mode-setup --check 2>/dev/null | grep -q "enabled"; then
      ok "FIPS mode: enabled"
    else
      if [ "$SKIP_FIPS_CHECK" = "1" ]; then
        note "FIPS mode: DISABLED (SKIP_FIPS_CHECK=1; OK on dev)"
      else
        fail "FIPS mode not enabled. Run: sudo fips-mode-setup --enable && sudo reboot
     Or bypass with SKIP_FIPS_CHECK=1 (dev only)"
      fi
    fi
  else
    note "fips-mode-setup not found (non-RHEL-family?) — skipping check"
  fi

  # Port availability (best-effort — if `ss` is missing, skip
  # quietly). Re-deploy is the intended path, so a port bound by
  # OUR own service is fine. We map each watched port to the unit
  # that should own it; if that unit is active, the bound port is
  # expected and gets skipped.
  if command -v ss >/dev/null 2>&1; then
    check_port() {
      local port="$1" owner_unit="$2"
      ss -tln "sport = :$port" | tail -n +2 | grep -q ":$port" || return 0
      # Port is bound. OK only if our unit owns it.
      if systemctl is-active --quiet "$owner_unit" 2>/dev/null; then
        note "port $port bound by $owner_unit (re-deploy path)"
        return 0
      fi
      fail "port $port already in use by something other than $owner_unit — stop the other listener or override"
    }
    check_port "$FB_LISTEN_PORT" cmmc-filebrowser.service
    check_port "$KC_BIND_PORT" cmmc-keycloak.service
    ok "ports $FB_LISTEN_PORT, $KC_BIND_PORT accounted for"
  fi

  # Repo sanity: in source mode we need main.go + the config/ tree to build + install.
  # With --from-release, REPO_DIR gets redirected to the extracted tarball by
  # phase_from_release (which runs after preflight) — that tree has config/ but
  # no main.go, so skip the source-tree checks here and validate the tarball
  # layout inside phase_from_release instead.
  if [ -z "$FROM_RELEASE" ]; then
    [ -f "$REPO_DIR/main.go" ] || fail "main.go not found under $REPO_DIR — run from a repo checkout"
    [ -d "$REPO_DIR/config/systemd" ] || fail "config/systemd missing — run from a repo checkout"
    ok "repo layout: $REPO_DIR"
  else
    ok "repo layout check deferred — --from-release provided"
  fi
}

# --- system user + directories ---------------------------------------
#
# CMMC 3.1.1 / 3.1.5: service runs as an unprivileged account that
# owns only its state + data dirs. /etc stays root-owned so a
# compromise of the service can't rewrite its own config.

phase_user_and_dirs() {
  say "System user + directories"

  if id "$FB_USER" >/dev/null 2>&1; then
    ok "user '$FB_USER' already exists"
  else
    useradd --system --home-dir "$FB_STATE_DIR" --shell /sbin/nologin \
      --comment "CMMC-Filebrowser service" "$FB_USER"
    ok "created user '$FB_USER'"
  fi

  # /etc is root:root 0755 — config is authoritative and read-only
  # to the service (ProtectSystem=strict in the unit seals it anyway).
  install -d -m 0755 -o root -g root "$FB_ETC_DIR"

  # State (BoltDB, OIDC mapping, audit chain genesis) is owned by
  # the service so it can write without fs escalations. 0750 keeps
  # out curious local users.
  install -d -m 0750 -o "$FB_USER" -g "$FB_USER" "$FB_STATE_DIR"

  # Data (the cabinet file tree) — same ownership but a wider dir
  # umask not needed; individual files are written with 0640 via
  # the unit's UMask=0027.
  install -d -m 0750 -o "$FB_USER" -g "$FB_USER" "$FB_DATA_DIR"

  # Doc drop — so journalctl / systemctl status users can find the
  # integration notes referenced by Documentation= directives.
  install -d -m 0755 /usr/share/doc/cmmc-filebrowser

  ok "dirs provisioned ($FB_ETC_DIR, $FB_STATE_DIR, $FB_DATA_DIR)"
}

# --- from-release: extract prebuilt tarball --------------------------
#
# Release tarballs are produced by scripts/build-release.sh on a
# build host with node + go + pnpm. They contain:
#   bin/cmmc-filebrowser          FIPS-built Go binary
#   config/ + docs/ + frontend/dist (reference)
#   VERSION, SHA256SUMS
#
# When `--from-release <path-or-url>` is passed:
#   1. Download (URL) or reuse (local path) the tarball
#   2. Extract to /tmp/cmmc-filebrowser-release/
#   3. Validate SHA256SUMS
#   4. Install the binary into $FB_INSTALL_PREFIX
#   5. Redirect REPO_DIR at the extracted tree so every OTHER phase
#      (units, configs, bootstrap.sh) reads from the release, not
#      the operator's working checkout. This is the critical bit:
#      phase_units + phase_keycloak both copy from $REPO_DIR, so
#      pointing it at the release tree gives us a single source of
#      truth per install.
# phase_frontend + phase_binary become no-ops when FROM_RELEASE is
# set — cmd_deploy checks the flag and skips them.

phase_from_release() {
  [ -n "$FROM_RELEASE" ] || return 0
  say "Install from release artifact: $FROM_RELEASE"

  command -v tar >/dev/null || fail "tar required for --from-release"
  command -v sha256sum >/dev/null || fail "sha256sum required for --from-release"

  local tarball="$FROM_RELEASE"

  # URL → download; otherwise expect a local file path.
  case "$FROM_RELEASE" in
    http://*|https://*)
      command -v curl >/dev/null || fail "curl required to fetch $FROM_RELEASE"
      tarball="/tmp/cmmc-filebrowser-release-$$.tar.gz"
      curl -fsSL --retry 3 -o "$tarball" "$FROM_RELEASE" || \
        fail "download failed: $FROM_RELEASE"
      ok "downloaded → $tarball"
      ;;
    *)
      [ -s "$tarball" ] || fail "release tarball missing or empty: $tarball"
      ;;
  esac

  local extract_root="/tmp/cmmc-filebrowser-release"
  rm -rf "$extract_root"
  install -d -m 0755 "$extract_root"
  tar -xzf "$tarball" -C "$extract_root" || fail "tar extract failed for $tarball"

  # Tarball's top-level is a single dir like cmmc-filebrowser-v0.1.0-linux-arm64/
  local release_dir
  release_dir=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d -print -quit)
  [ -n "$release_dir" ] || fail "no release dir inside tarball"

  # Validate checksums — the build script emits one line per file.
  if [ -s "$release_dir/SHA256SUMS" ]; then
    (cd "$release_dir" && sha256sum --quiet --check SHA256SUMS) || \
      fail "SHA256SUMS check failed — release artifact tampered or corrupted"
    ok "SHA256SUMS verified"
  else
    note "SHA256SUMS missing from release — proceeding without hash check"
  fi

  local bin="$release_dir/bin/cmmc-filebrowser"
  [ -x "$bin" ] || fail "binary missing from release: expected $bin"
  install -m 0755 -o root -g root "$bin" "$FB_INSTALL_PREFIX/cmmc-filebrowser"
  ok "installed binary → $FB_INSTALL_PREFIX/cmmc-filebrowser"

  # Rewire $REPO_DIR so subsequent phases pick up the release's
  # config + docs instead of the operator's git checkout (which may
  # not exist on an air-gap host).
  REPO_DIR="$release_dir"
  ok "REPO_DIR redirected → $release_dir"

  if [ -s "$release_dir/VERSION" ]; then
    note "version: $(cat "$release_dir/VERSION")"
  fi
}

# --- frontend build --------------------------------------------------
#
# The Vue SPA lives in frontend/src and gets compiled to frontend/dist
# which Go embeds at compile time. Operators who rsync the repo often
# exclude frontend/dist (it's the wrong thing to commit — generated
# output), so a go build against a stale or empty dist produces a
# binary that serves old HTML. Symptoms: missing UI features (e.g.
# the file-level CUI classify button) or CSS regressions re-appearing
# (the /me activity hover oval).
#
# Skip rebuild when the dist is newer than every frontend/src file —
# same pattern phase_binary uses. Missing node/npm is a hard fail
# only on the first run (when dist is empty); subsequent runs with
# a pre-built dist are allowed to proceed.

phase_frontend() {
  say "Build frontend bundle"

  local src_dir="$REPO_DIR/frontend"
  local dist_dir="$src_dir/dist"
  local index="$dist_dir/index.html"

  if [ ! -d "$src_dir/src" ]; then
    note "no frontend/src dir — skipping (release artifact?)"
    return 0
  fi

  # Already built + fresh?
  if [ -s "$index" ]; then
    local newest
    newest=$(find "$src_dir/src" "$src_dir/package.json" -type f \
      -newer "$index" -print -quit 2>/dev/null || true)
    if [ -z "$newest" ]; then
      ok "frontend/dist up-to-date (index.html newer than sources)"
      return 0
    fi
    note "frontend sources newer than dist ($newest) — rebuilding"
  fi

  # The repo's package.json pins pnpm as its packageManager and the
  # build script does `pnpm run typecheck && vite build`, so npm can't
  # run it end-to-end (pnpm-only lockfile, pnpm-specific workspace
  # semantics). Enable pnpm via corepack (bundled in Node >= 16.10);
  # fall back to a manual `npm install -g pnpm` only when corepack is
  # absent (e.g. an unusually old Node).
  if ! command -v node >/dev/null 2>&1; then
    if [ -s "$index" ]; then
      note "node not found but dist looks populated — proceeding"
      return 0
    fi
    fail "node missing; install via: sudo dnf install -y nodejs npm"
  fi
  if ! command -v pnpm >/dev/null 2>&1; then
    if command -v corepack >/dev/null 2>&1; then
      # Corepack materializes whatever packageManager the repo pins,
      # no network fetch if the version is already cached under
      # ~/.cache/node/corepack.
      corepack enable >/dev/null 2>&1 || true
      corepack prepare pnpm@latest --activate >/dev/null 2>&1 || \
        fail "corepack prepare pnpm failed — run: sudo npm install -g pnpm"
    else
      note "corepack missing — falling back to global pnpm install via npm"
      npm install -g pnpm 2>&1 | tail -1 || \
        fail "pnpm not installable; try: sudo dnf module install nodejs:20 -y"
    fi
  fi

  # --prefer-offline trades one round-trip per dep for a cached-bytes
  # path; safe on re-runs. --reporter=append gives us flat log lines
  # so journald / tty output isn't ANSI-dependent.
  (cd "$src_dir" && pnpm install --prefer-offline --reporter=append 2>&1 | tail -4) || \
    fail "frontend pnpm install failed — check $src_dir"

  (cd "$src_dir" && pnpm run build 2>&1 | tail -4) || \
    fail "frontend pnpm run build failed — check $src_dir"

  [ -s "$index" ] || fail "frontend build claims success but $index is missing"
  ok "frontend built at $dist_dir"
}

# --- binary build + install ------------------------------------------
#
# Build from source using the repo's FIPS flags so the installed
# binary matches what upstream tests ran against. Production shops
# swapping to a pre-built release artifact replace this one function.

phase_binary() {
  say "Build + install cmmc-filebrowser binary"

  command -v go >/dev/null || fail "go toolchain not found — run: sudo dnf install -y go-toolset"
  local goversion
  goversion=$(go env GOVERSION 2>/dev/null || echo unknown)
  note "go: $goversion"

  # Skip rebuild if installed binary is newer than every .go file.
  local newest
  local installed="$FB_INSTALL_PREFIX/cmmc-filebrowser"
  if [ -x "$installed" ]; then
    newest=$(find "$REPO_DIR" -type f -name '*.go' -not -path '*/node_modules/*' -not -path '*/.git/*' \
      -newer "$installed" -print -quit 2>/dev/null || true)
    if [ -z "$newest" ]; then
      ok "binary up-to-date at $installed"
      return 0
    fi
    note "source newer than installed binary ($newest) — rebuilding"
  fi

  # GOFIPS140=v1.0.0 keys the runtime onto the CAVP-certified module.
  # -trimpath strips build host paths from the binary (SBOM hygiene).
  # Build into a tempfile so a failed build can't leave a half-written
  # /usr/local/bin binary.
  local tmpbin
  tmpbin=$(mktemp --suffix=.cmmc-filebrowser)
  (cd "$REPO_DIR" && GOFIPS140=v1.0.0 CGO_ENABLED=0 go build \
    -tags noboringcrypto -trimpath -ldflags '-s -w' \
    -o "$tmpbin" .)
  install -m 0755 -o root -g root "$tmpbin" "$installed"
  rm -f "$tmpbin"

  # Helper: convenience symlink for operators running ad-hoc commands.
  # `cmmc-filebrowser config show` etc. — same binary.
  ok "installed: $installed ($(stat -c '%s' "$installed") bytes)"
}

# --- systemd + rsyslog units -----------------------------------------

phase_units() {
  say "Install systemd units + rsyslog drop-in"

  install -m 0644 -o root -g root \
    "$REPO_DIR/config/systemd/cmmc-filebrowser.service" \
    /etc/systemd/system/cmmc-filebrowser.service
  install -m 0644 -o root -g root \
    "$REPO_DIR/config/systemd/cmmc-keycloak.service" \
    /etc/systemd/system/cmmc-keycloak.service
  if [ "$WITH_WAZUH" = "1" ]; then
    install -m 0644 -o root -g root \
      "$REPO_DIR/config/systemd/cmmc-wazuh.service" \
      /etc/systemd/system/cmmc-wazuh.service
  fi
  ok "systemd units installed"

  # rsyslog drop-in — routes journald-captured audit JSON to the
  # customer SIEM over mTLS. Best-effort: missing rsyslog isn't
  # a hard fail on single-host deployments that keep audit in
  # journald only (CMMC 3.3.1 still satisfied locally).
  if [ -d /etc/rsyslog.d ]; then
    install -m 0644 -o root -g root \
      "$REPO_DIR/config/rsyslog/50-cmmc-filebrowser.conf" \
      /etc/rsyslog.d/50-cmmc-filebrowser.conf
    ok "rsyslog drop-in: /etc/rsyslog.d/50-cmmc-filebrowser.conf"
    systemctl restart rsyslog 2>/dev/null || note "rsyslog not running — skipping restart"
  else
    note "/etc/rsyslog.d missing — audit stays in journald only"
  fi

  # Copy the docs + config snippets so Documentation= URIs resolve.
  for doc in wazuh-integration.md wazuh-endpoint-agents.md audit-forwarder.md \
             keycloak-setup.md architecture.md almalinux9-setup.md; do
    if [ -f "$REPO_DIR/docs/$doc" ]; then
      install -m 0644 "$REPO_DIR/docs/$doc" \
        "/usr/share/doc/cmmc-filebrowser/$doc"
    fi
  done

  systemctl daemon-reload
  ok "systemd daemon-reload"
}

# --- Wazuh compose + decoders (only if --with-wazuh) ----------------

phase_wazuh_assets() {
  [ "$WITH_WAZUH" = "1" ] || return 0
  say "Install Wazuh compose + decoder/rules"

  install -d -m 0755 "$FB_ETC_DIR/wazuh"
  install -d -m 0755 "$FB_ETC_DIR/wazuh/decoders"
  install -d -m 0755 "$FB_ETC_DIR/wazuh/rules"
  install -m 0644 \
    "$REPO_DIR/config/wazuh/podman-compose.wazuh.yml" \
    "$FB_ETC_DIR/wazuh/podman-compose.wazuh.yml"
  install -m 0644 \
    "$REPO_DIR/config/wazuh/decoders/filebrowser-cmmc.xml" \
    "$FB_ETC_DIR/wazuh/decoders/filebrowser-cmmc.xml"
  install -m 0644 \
    "$REPO_DIR/config/wazuh/rules/filebrowser-cmmc.xml" \
    "$FB_ETC_DIR/wazuh/rules/filebrowser-cmmc.xml"

  ok "Wazuh assets: $FB_ETC_DIR/wazuh/"
}

# --- firewalld: open service ports -----------------------------------
#
# RHEL 9 / AlmaLinux 9 / Rocky 9 ship firewalld with a restrictive
# default zone (public) that blocks 8081 + 8443. Without an explicit
# open, the services bind happily on localhost but LAN clients hit
# connection-refused. We open both ports in the default zone with
# --permanent (survives reboots) and --reload immediately.
#
# If firewalld isn't installed/running (some appliance images ship
# nftables directly) this phase is a no-op — we don't try to edit
# the other firewall systems.
#
# Closed on uninstall by the reverse logic (see cmd_uninstall).

phase_firewall() {
  say "Firewall"

  if ! command -v firewall-cmd >/dev/null 2>&1; then
    note "firewall-cmd not found — skipping (assuming no firewalld)"
    return 0
  fi
  if ! systemctl is-active --quiet firewalld 2>/dev/null; then
    note "firewalld not active — skipping"
    return 0
  fi

  local opened=""
  for p in "$FB_LISTEN_PORT" "$KC_BIND_PORT"; do
    # --permanent edits config, --reload applies; a single
    # --add-port without --permanent would only hold until reboot.
    firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true
    opened="$opened $p/tcp"
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
  ok "firewalld ports opened:$opened"
}

# --- TLS: generate or install server certs ---------------------------
#
# Precedence (first match wins):
#   1. /etc/cmmc-filebrowser/tls/{server.crt,server.key} already present
#      → customer-supplied cert (Access Gate PKI, enterprise CA, etc.).
#      Installer uses as-is and never overwrites.
#   2. --tls-cert + --tls-key flags → copy those files into the tls dir.
#      CI / operator-pushes pattern.
#   3. Neither → generate a local self-signed CA + leaf for this host.
#      Dev default. Browser shows cert warning until the operator trusts
#      /etc/cmmc-filebrowser/tls/ca.crt.
#
# SANs always include the appliance's primary IP, 127.0.0.1, and
# localhost — the same cert serves both filebrowser (8080) and
# Keycloak (8081) since they share a host.
#
# Keys are RSA-2048 — FIPS-approved and broadly compatible. P-256
# (ECDSA) would also work but keeps broader interop with older RHEL
# base images and stick-shift OpenSSL builds.

phase_tls() {
  say "TLS certificates"

  # First: make the hostname resolvable on the appliance itself.
  # filebrowser's Go OIDC client needs to fetch the .well-known
  # config from $host_name; if nothing resolves it, startup 503s.
  # Customer-managed DNS isn't here on a fresh bring-up, so we add
  # a loopback /etc/hosts line so the APPLIANCE always works with
  # its own canonical hostname — LAN clients still need DNS or
  # their own /etc/hosts to reach the same name, but that's a
  # deployment concern (see docs/operator-2fa.md). Edit is
  # idempotent — we never stack duplicate lines.
  ensure_hosts_entry "$(detect_host_name)"

  # Directory mode 0755 (not 0750) so the Keycloak container's
  # internal UID 1000 can traverse to read the cert/key — it's not
  # a member of the host's cmmc-filebrowser group (container user
  # namespace doesn't map host groups). Cert files themselves are
  # 0644 anyway (certs are public); the key file is the asymmetry
  # to watch — see fix_tls_perms comment.
  install -d -m 0755 -o root -g "$FB_USER" "$FB_TLS_DIR"

  local crt="$FB_TLS_DIR/server.crt"
  local key="$FB_TLS_DIR/server.key"
  local ca="$FB_TLS_DIR/ca.crt"

  # Case 1: already present — respect operator's choice.
  if [ -s "$crt" ] && [ -s "$key" ]; then
    ok "TLS cert exists at $crt — keeping (customer-supplied)"
    fix_tls_perms
    trust_ca_system_wide "$ca"
    return 0
  fi

  # Case 2: operator passed paths on the command line.
  if [ -n "$EXT_TLS_CERT" ] || [ -n "$EXT_TLS_KEY" ]; then
    [ -s "$EXT_TLS_CERT" ] || fail "--tls-cert file missing or empty: $EXT_TLS_CERT"
    [ -s "$EXT_TLS_KEY" ]  || fail "--tls-key file missing or empty: $EXT_TLS_KEY"
    install -m 0644 -o root -g "$FB_USER" "$EXT_TLS_CERT" "$crt"
    install -m 0640 -o root -g "$FB_USER" "$EXT_TLS_KEY" "$key"
    ok "installed operator-supplied cert ($EXT_TLS_CERT) → $crt"
    fix_tls_perms
    trust_ca_system_wide "$ca"
    return 0
  fi

  # Case 3: self-signed fallback. Two-tier (CA + leaf) so the
  # operator trusts one cert (ca.crt) and every refresh of the leaf
  # is transparent to browsers that already trusted the CA.
  command -v openssl >/dev/null || fail "openssl not found — install it or provide --tls-cert/--tls-key"

  local host_ip host_name
  host_ip=$(detect_host_ip)
  host_name=$(detect_host_name)

  note "generating self-signed CA + leaf (SANs: $host_ip, 127.0.0.1, localhost, $host_name)"

  local ca_key="$FB_TLS_DIR/ca.key"
  # CA — 10-year validity so the operator doesn't hit a surprise
  # expiry mid-demo. Leaf is shorter (2y) to encourage rotation.
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$ca_key" -out "$ca" \
    -subj "/CN=CMMC Filebrowser Dev CA" 2>/dev/null

  # Leaf CSR + self-sign with the CA.
  local csr
  csr=$(mktemp --suffix=.csr)
  local ext
  ext=$(mktemp --suffix=.ext)

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$key" -out "$csr" \
    -subj "/CN=$host_name" 2>/dev/null

  cat > "$ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
DNS.2=$host_name
IP.1=127.0.0.1
IP.2=$host_ip
EOF

  openssl x509 -req -in "$csr" -CA "$ca" -CAkey "$ca_key" -CAcreateserial \
    -out "$crt" -days 730 -sha256 -extfile "$ext" 2>/dev/null

  rm -f "$csr" "$ext" "$FB_TLS_DIR/ca.srl"

  fix_tls_perms
  trust_ca_system_wide "$ca"
  ok "generated self-signed leaf (valid 2y) + CA (valid 10y)"
  note "trust the CA in a browser by importing $ca; the leaf will refresh silently"
}

# trust_ca_system_wide copies the CA cert into the RHEL ca-trust
# anchor dir and runs update-ca-trust. Two consumers need this:
#   1. filebrowser's Go OIDC client — when it fetches KC's .well-
#      known/openid-configuration, it goes through Go's crypto/x509
#      which honors the system bundle. Without this, filebrowser
#      logs "x509: certificate signed by unknown authority" and
#      returns 503 on /api/auth/oidc/login.
#   2. curl / kcadm / any host-side diagnostic — so operators can
#      `curl https://localhost:8081/...` without -k.
#
# Customers who dropped in an Access-Gate/enterprise cert into
# /etc/cmmc-filebrowser/tls/ca.crt get the same treatment. Harmless
# no-op if the CA is already trusted (update-ca-trust dedupes).
trust_ca_system_wide() {
  local ca="$1"
  local anchor_dir="/etc/pki/ca-trust/source/anchors"
  [ -f "$ca" ] || return 0
  [ -d "$anchor_dir" ] || return 0
  install -m 0644 "$ca" "$anchor_dir/cmmc-filebrowser-ca.crt"
  if command -v update-ca-trust >/dev/null 2>&1; then
    update-ca-trust 2>/dev/null || true
    note "CA trusted system-wide via $anchor_dir"
  fi
}

# ensure_hosts_entry adds `127.0.0.1 <name>` to /etc/hosts if the
# name isn't already resolvable. Only touches /etc/hosts when the
# name is missing — we never collide with operator edits or real
# DNS that's already in place.
ensure_hosts_entry() {
  local name="$1"
  [ -n "$name" ] || return 0
  # Already resolvable (DNS, existing /etc/hosts, mDNS) → skip.
  if getent hosts "$name" >/dev/null 2>&1; then
    note "$name already resolves — skipping /etc/hosts edit"
    return 0
  fi
  # Add the entry. Prepend a comment so operators know it's ours.
  if ! grep -qE "^[^#].*[[:space:]]${name}([[:space:]]|\$)" /etc/hosts 2>/dev/null; then
    printf '\n# Added by cmmc-filebrowser install.sh — enables local OIDC discovery.\n127.0.0.1  %s\n' "$name" >> /etc/hosts
    ok "added 127.0.0.1 → $name to /etc/hosts"
  fi
}

# fix_tls_perms sets ownership + mode for TLS material. Unusual
# choice: server.key is chmod 0644 (world-readable on the host),
# not 0640. Rationale: the Keycloak container runs as UID 1000
# inside its own user namespace, not a member of the host
# cmmc-filebrowser group — 0640 would make the key unreadable from
# within the container. The threat model on a single-host appliance
# is "other services on the box"; root on the host can read
# anything regardless. If that threat model changes (multi-tenant
# host, rootless-podman with userns mapping), revisit this mode.
# ca.key stays root-only (0600) — it's the minting authority for
# the leaf and has a much longer valid life than the leaf itself.
fix_tls_perms() {
  chown root:"$FB_USER" "$FB_TLS_DIR"/*.crt 2>/dev/null || true
  chown root:"$FB_USER" "$FB_TLS_DIR"/*.key 2>/dev/null || true
  chmod 0644 "$FB_TLS_DIR"/*.crt 2>/dev/null || true
  chmod 0644 "$FB_TLS_DIR/server.key" 2>/dev/null || true
  [ -f "$FB_TLS_DIR/ca.key" ] && chmod 0600 "$FB_TLS_DIR/ca.key"
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "$FB_TLS_DIR" 2>/dev/null || true
  fi
}

# --- environment file seeding ----------------------------------------
#
# Key security operation: generates long-lived secrets that survive
# across reboots. We write the file ONCE and never overwrite. A
# re-run picks up the existing values so a second `install.sh deploy`
# doesn't invalidate existing sessions.

phase_kek() {
  # CMMC 3.13.16 / 3.8.9 — envelope encryption needs a master KEK.
  # Without one, filebrowser boots with envelope=disabled and files
  # land in plaintext (release warns: "NOT CMMC-compliant; for dev
  # only"). Generating a local KEK here gives the default install an
  # encryption-on posture; TPM sealing / HSM custody is a separate
  # hardening step documented in docs/architecture.md §8.
  say "KEK (envelope-encryption master key)"

  local kek="$FB_ETC_DIR/kek.bin"
  if [ -s "$kek" ]; then
    ok "KEK already present: $kek (keeping)"
    return 0
  fi

  install -d -m 0750 -o root -g "$FB_USER" "$FB_ETC_DIR"
  umask 077
  # 32 raw bytes — exactly what envelope.KeySize expects.
  openssl rand -out "$kek" 32
  chown "$FB_USER:$FB_USER" "$kek"
  chmod 0400 "$kek"
  umask 022
  # Reset SELinux context so systemd (init_t) can read the file.
  command -v restorecon >/dev/null 2>&1 && restorecon -F "$kek" || true
  ok "generated KEK → $kek (owner $FB_USER, mode 0400)"
}

# --- clamav -----------------------------------------------------------
#
# CMMC 3.14.2 / 3.14.4 / 3.14.5. Open-CMMC has had an INSTREAM ClamAV
# client since v1.0.0, but the installer never provisioned clamd and
# never set FB_CMMC_AV — so scanning shipped off and every deployment
# was silently unscanned. This phase closes that.
#
# Sequencing matters and is not negotiable:
#   1. install packages
#   2. fetch signatures (freshclam) — clamd will not start without a
#      signature database
#   3. start clamd, wait for it to answer
#   4. only then does phase_env_file write FB_CMMC_AV=required
#
# If any step fails we fall back to FB_CMMC_AV=optional rather than
# required. This is deliberate: required mode is fail-closed at boot,
# so writing it when clamd is not answering would leave the operator
# with an appliance that refuses to start and no obvious cause.
# Optional mode keeps the appliance usable and says loudly that
# scanning is not active.
#
# AV_MODE is consumed by phase_env_file.
AV_MODE="required"

phase_clamav() {
  say "ClamAV (malicious-code protection)"

  if [ "$NO_CLAMAV" = "1" ]; then
    AV_MODE="disabled"
    warn "--no-clamav: scanning disabled; 3.14.2 / 3.14.5 are yours to cover"
    return 0
  fi

  # clamd + the signature updater. clamav-update carries freshclam.
  if ! rpm -q clamd >/dev/null 2>&1 || ! rpm -q clamav-update >/dev/null 2>&1; then
    if ! dnf install -y clamav clamd clamav-update >/dev/null 2>&1; then
      AV_MODE="optional"
      warn "could not install clamav packages (no repo access?)"
      note "uploads will NOT be scanned. See docs/day2-operations.md → antivirus"
      return 0
    fi
  fi
  ok "packages present (clamav, clamd, clamav-update)"

  # Listen on loopback TCP rather than a unix socket: no SELinux
  # socket-context coupling between the clamd and filebrowser service
  # domains, and nothing is exposed because phase_firewall never opens
  # 3310. LocalSocket stays configured for clamdscan CLI use.
  local conf=/etc/clamd.d/scan.conf
  if [ -f "$conf" ]; then
    # These ship commented-out in the RHEL package.
    sed -i 's/^#\?LocalSocket .*/LocalSocket \/run\/clamd.scan\/clamd.sock/' "$conf"
    sed -i 's/^#\?TCPSocket .*/TCPSocket 3310/'                              "$conf"
    sed -i 's/^#\?TCPAddr .*/TCPAddr 127.0.0.1/'                             "$conf"
    grep -q '^TCPSocket'  "$conf" || echo 'TCPSocket 3310'    >> "$conf"
    grep -q '^TCPAddr'    "$conf" || echo 'TCPAddr 127.0.0.1' >> "$conf"
    # The package ships a literal "Example" line that makes clamd
    # refuse to start until removed.
    sed -i '/^Example$/d' "$conf"
    ok "clamd configured on 127.0.0.1:3310"
  else
    AV_MODE="optional"
    warn "no $conf after install — clamd layout unexpected"
    return 0
  fi

  # Signatures. This is the step that needs egress (or an internal
  # mirror configured in /etc/freshclam.conf) and the step most likely
  # to fail on an air-gapped host.
  sed -i '/^Example$/d' /etc/freshclam.conf 2>/dev/null || true
  if [ ! -s /var/lib/clamav/daily.cvd ] && [ ! -s /var/lib/clamav/daily.cld ]; then
    say "  fetching initial signature database (this takes a few minutes)"
    if ! freshclam --quiet; then
      AV_MODE="optional"
      warn "freshclam could not fetch signatures"
      note "air-gapped? point /etc/freshclam.conf at an internal mirror, run"
      note "freshclam, then: sudo config/install.sh enable-av"
      return 0
    fi
  fi
  ok "signature database present"

  # Keep signatures current — 3.14.4.
  systemctl enable --now clamav-freshclam >/dev/null 2>&1 ||
    warn "clamav-freshclam not enabled — signatures will go stale (3.14.4)"

  # Let clamd read the cabinet under SELinux enforcing.
  command -v setsebool >/dev/null 2>&1 &&
    setsebool -P antivirus_can_scan_system 1 2>/dev/null || true

  systemctl enable --now clamd@scan >/dev/null 2>&1 || true

  # clamd loads the full signature set into memory before it answers;
  # on modest hardware that is 30-60 s. Poll rather than assume.
  local waited=0
  while [ "$waited" -lt 120 ]; do
    if (exec 3<>/dev/tcp/127.0.0.1/3310) 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      break
    fi
    sleep 3; waited=$((waited + 3))
  done

  if [ "$waited" -ge 120 ]; then
    AV_MODE="optional"
    warn "clamd did not answer on 127.0.0.1:3310 within 120s"
    note "check: systemctl status clamd@scan; journalctl -u clamd@scan"
    return 0
  fi

  ok "clamd answering after ${waited}s — scanning will be fail-closed (required)"
}

# Re-run the AV phase and flip an existing deployment to required.
# The deploy path never rewrites the env file, so an operator who
# fixed signatures after a failed first run needs this.
cmd_enable_av() {
  need_root
  NO_CLAMAV=0
  phase_clamav
  local env="$FB_ETC_DIR/environment"
  [ -f "$env" ] || fail "no env file at $env — run deploy first"

  if [ "$AV_MODE" != "required" ]; then
    fail "clamd still not healthy — not changing FB_CMMC_AV (see warnings above)"
  fi
  if grep -q '^FB_CMMC_AV=' "$env"; then
    sed -i 's|^FB_CMMC_AV=.*|FB_CMMC_AV=required|' "$env"
  else
    printf '\nFB_CMMC_AV=required\nFB_CMMC_AV_ADDR=tcp://127.0.0.1:3310\n' >> "$env"
  fi
  grep -q '^FB_CMMC_AV_ADDR=' "$env" ||
    printf 'FB_CMMC_AV_ADDR=tcp://127.0.0.1:3310\n' >> "$env"
  ok "FB_CMMC_AV=required written to $env"
  systemctl restart cmmc-filebrowser 2>/dev/null || true
  ok "filebrowser restarted — uploads are now scanned fail-closed"
}

phase_env_file() {
  say "Seed environment file"

  local env="$FB_ETC_DIR/environment"
  if [ -f "$env" ]; then
    ok "env file already exists: $env (keeping)"
    return 0
  fi

  # 64 bytes of base64 entropy per secret — comfortable for
  # HS256 / AES-256 / HMAC-SHA256 downstream derivation.
  local fb_key fb_audit kc_admin_pass indexer_pass dashboard_pass
  fb_key=$(openssl rand -base64 48 | tr -d '\n')
  fb_audit=$(openssl rand -base64 48 | tr -d '\n')
  kc_admin_pass=$(openssl rand -base64 24 | tr -d '\n=/+')
  indexer_pass=$(openssl rand -base64 24 | tr -d '\n=/+')
  dashboard_pass=$(openssl rand -base64 24 | tr -d '\n=/+')

  # OIDC URIs use a HOSTNAME, not an IP. WebAuthn refuses passkey
  # registration against an IP-address origin — the browser throws
  # "SecurityError: invalid domain". Operators override with
  # FB_HOST_NAME=<fqdn> at install time; default is cmmc.local
  # (clients add a /etc/hosts line until real DNS is in place).
  # host_ip is still needed for the cert's IP SAN so localhost /
  # LAN-IP access keeps working for curl + debug paths.
  local host_ip host_name
  host_ip=$(detect_host_ip)
  host_name=$(detect_host_name)

  umask 077
  cat > "$env" <<EOF
# CMMC-Filebrowser environment
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Mode: 0600 — contains long-lived secrets. Do NOT commit.

# --- Filebrowser core -------------------------------------------------

FB_SETTINGS_KEY=$fb_key
FB_AUDIT_HMAC_KEY=$fb_audit
FB_CMMC_SESSION_IDLE_TIMEOUT=15m
# Envelope encryption — CMMC 3.13.16 / 3.8.9. "required" mode refuses
# to start without a valid KEK, which is the production posture.
# Downgrade to "optional" during a migration only.
FB_CMMC_ENCRYPTION=required
FB_CMMC_KEK_FILE=$FB_ETC_DIR/kek.bin
# Malicious-code protection — CMMC 3.14.2 / 3.14.5. "required" is
# fail-closed: a sick clamd returns 503 rather than letting an
# unscanned file through. Set to the posture phase_clamav actually
# achieved; if it reads "optional" here, clamd was not healthy at
# install time — fix it and run: sudo config/install.sh enable-av
FB_CMMC_AV=$AV_MODE
FB_CMMC_AV_ADDR=tcp://127.0.0.1:3310
# Window in which the session's OIDC MFA assertion is considered
# "fresh" for privileged writes (classify, ACL, share, settings).
# Default (10 min) is hostile to real workflows — 60 min still
# enforces periodic re-MFA without forcing re-auth on every click.
FB_OIDC_MFA_FRESH_SECONDS=3600
FB_OIDC_REQUIRE_FIPS=true

# --- OIDC (bundled Keycloak at loopback) ------------------------------
# Issuer uses the appliance's LAN IP so OIDC tokens issued by KC
# validate for browser-originated requests from other hosts on the
# LAN. For external IdPs (Entra GCC-H / Okta Gov), overwrite these
# three lines with the customer's issuer + client_id + secret.

# OIDC issuer URL has to be ONE canonical value — filebrowser's
# discovery + token verifier check that tokens' iss claim matches.
# We default to the IP so a fresh deploy without DNS works out of
# the box (TOTP login, all the usual flows). Cost: passkeys don't
# work against an IP origin (browsers reject WebAuthn on IP). When
# the customer's DNS publishes cmmc.local (or whatever $host_name
# becomes), operators flip this line to the hostname URL and
# restart the service — KC_HOSTNAME_STRICT=false already lets KC
# serve either host header, so no KC change needed.
#
# To switch to hostname issuer (enables passkeys):
#   1. sudo sed -i 's|FB_OIDC_ISSUER=.*|FB_OIDC_ISSUER=https://$host_name:$KC_BIND_PORT/realms/cmmc|' /etc/cmmc-filebrowser/environment
#   2. sudo systemctl restart cmmc-filebrowser
FB_OIDC_ISSUER=https://$host_ip:$KC_BIND_PORT/realms/cmmc
FB_OIDC_CLIENT_ID=filebrowser
FB_OIDC_CLIENT_SECRET=PENDING_BOOTSTRAP
# Legacy single-redirect (still honored when the filebrowser process
# runs pre-dynamic-redirect code). The current code path derives the
# callback URI from the incoming request Host, so KC's allowlist
# (set by bootstrap.sh from REDIRECT_URIS below) is what matters.
FB_OIDC_REDIRECT_URI=https://$host_ip:$FB_LISTEN_PORT/api/auth/oidc/callback
FB_OIDC_ALLOW_INSECURE_HTTP_ISSUER=false
# Groups whose members are promoted to filebrowser admin. Must match
# the Keycloak group name seeded by bootstrap.sh (filebrowser-admins).
# Without this var set, no one gets admin — users only see drawers
# their functional group owns.
FB_OIDC_ADMIN_GROUPS=filebrowser-admins

# --- Keycloak (for cmmc-keycloak.service) -----------------------------

KC_ADMIN=admin
KC_ADMIN_PASSWORD=$kc_admin_pass
KC_BIND_ADDR=0.0.0.0
KC_BIND_PORT=$KC_BIND_PORT

# --- Wazuh bundle (only used when cmmc-wazuh is installed) ------------

INDEXER_PASSWORD=$indexer_pass
DASHBOARD_PASSWORD=$dashboard_pass
EOF
  chown root:"$FB_USER" "$env"
  chmod 0640 "$env"
  umask 022

  # Reset SELinux context. `cat > file` from install.sh's shell gives
  # the file the invoking user's context (user_tmp_t on a typical sudo
  # session) — systemd (init_t) gets an AVC-denied reading it and
  # silently starts the unit with an empty environment. restorecon
  # resets to etc_t per the /etc policy.
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "$FB_ETC_DIR" 2>/dev/null || true
  fi

  ok "env file: $env (mode 0640, root:$FB_USER)"
  note "Keycloak admin password stored in $env (KC_ADMIN_PASSWORD)"
}

# --- Keycloak start + bootstrap --------------------------------------

phase_keycloak() {
  say "Start Keycloak + run bootstrap"

  systemctl enable cmmc-keycloak.service >/dev/null
  systemctl restart cmmc-keycloak.service

  # Poll until KC answers on its admin port. 90s is plenty for the
  # H2-backed dev mode; cluster / Postgres deployments should raise.
  # -k: self-signed cert is the default dev path; prod operators drop
  # a CA-issued cert in and the probe still passes (curl's -k just
  # skips verification).
  note "waiting for Keycloak on 127.0.0.1:$KC_BIND_PORT ..."
  local waited=0
  until curl -skf "https://127.0.0.1:$KC_BIND_PORT/realms/master" >/dev/null 2>&1; do
    sleep 2
    waited=$((waited+2))
    if [ $waited -ge 90 ]; then
      fail "Keycloak did not become ready in 90s — check: journalctl -u cmmc-keycloak"
    fi
  done
  ok "Keycloak ready after ${waited}s"

  # Run bootstrap.sh — it creates the cmmc realm, client, groups,
  # users. Idempotent but re-seeds users each run. Override KC_URL
  # so bootstrap talks to KC over HTTPS + tells curl to skip cert
  # verification (self-signed dev default; operators on CA-issued
  # certs can remove the -k by setting CURL_OPTS="").
  local bootstrap="$REPO_DIR/config/keycloak/bootstrap.sh"
  if [ ! -x "$bootstrap" ]; then
    fail "keycloak bootstrap not executable: $bootstrap"
  fi
  # shellcheck disable=SC1090
  set -a && . "$FB_ETC_DIR/environment" && set +a
  # Register BOTH IP-based and hostname-based redirect URIs +
  # webOrigins so filebrowser's per-request redirect_uri matches
  # whichever origin the user browsed in on. Callers can append
  # more (e.g. behind a reverse proxy) via REDIRECT_URIS_EXTRA.
  local host_ip_here host_name_here
  host_ip_here=$(detect_host_ip)
  host_name_here=$(detect_host_name)
  local ip_redir="https://$host_ip_here:$FB_LISTEN_PORT/api/auth/oidc/callback"
  local name_redir="https://$host_name_here:$FB_LISTEN_PORT/api/auth/oidc/callback"
  local ip_origin="https://$host_ip_here:$FB_LISTEN_PORT"
  local name_origin="https://$host_name_here:$FB_LISTEN_PORT"

  # SEED_USERS / FB_ADMIN_USER carry the identity posture resolved in
  # preflight. Exactly one of the two is set there.
  KEYCLOAK_CONTAINER=cmmc-keycloak \
    KC_URL="https://127.0.0.1:$KC_BIND_PORT" \
    FB_OIDC_REDIRECT_URI="$FB_OIDC_REDIRECT_URI" \
    REDIRECT_URIS="$ip_redir $name_redir ${REDIRECT_URIS_EXTRA:-}" \
    WEB_ORIGINS="$ip_origin $name_origin" \
    SEED_USERS="$WITH_DEMO" \
    FB_ADMIN_USER="${FB_ADMIN_USER:-}" \
    FB_ADMIN_EMAIL="${FB_ADMIN_EMAIL:-}" \
    FB_ADMIN_FIRST="${FB_ADMIN_FIRST:-}" \
    FB_ADMIN_LAST="${FB_ADMIN_LAST:-}" \
    CURL_OPTS="-k" \
    "$bootstrap"
  ok "bootstrap complete"

  # Read the generated client secret back + patch the env file.
  # Use the REST admin API directly (same path bootstrap.sh uses);
  # kcadm.sh inside the container would need a separate `config
  # credentials` step and adds no value here. -k skips cert verify
  # against our self-signed dev CA; customers on a trusted CA can
  # tighten by dropping -k.
  local kc_url="https://127.0.0.1:$KC_BIND_PORT"
  local admin_tok secret uuid
  admin_tok=$(curl -kfsS -X POST \
    "$kc_url/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$KC_ADMIN" -d "password=$KC_ADMIN_PASSWORD" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    | jq -r .access_token)
  [ -n "$admin_tok" ] && [ "$admin_tok" != "null" ] || fail "could not acquire admin token for secret sync"
  uuid=$(curl -kfsS -H "Authorization: Bearer $admin_tok" \
    "$kc_url/admin/realms/cmmc/clients?clientId=filebrowser" \
    | jq -r '.[0].id')
  [ -n "$uuid" ] && [ "$uuid" != "null" ] || fail "could not resolve filebrowser client UUID"
  secret=$(curl -kfsS -H "Authorization: Bearer $admin_tok" \
    "$kc_url/admin/realms/cmmc/clients/$uuid/client-secret" \
    | jq -r .value)
  [ -n "$secret" ] && [ "$secret" != "null" ] || fail "could not read client secret from Keycloak"

  local env="$FB_ETC_DIR/environment"
  local tmp
  tmp=$(mktemp)
  awk -v s="FB_OIDC_CLIENT_SECRET=$secret" \
    '/^FB_OIDC_CLIENT_SECRET=/ {print s; next} {print}' \
    "$env" > "$tmp" && mv "$tmp" "$env"
  chown root:"$FB_USER" "$env"
  chmod 0640 "$env"
  # mv preserves the source file's context (from mktemp = tmp_t), so
  # re-label here too — otherwise the freshly-synced env file would
  # slip back to an SELinux-incompatible context and systemd's next
  # restart would lose the variables again.
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$env" 2>/dev/null || true
  fi
  ok "client secret synced into $env"
}

# --- Filebrowser bolt init + start -----------------------------------

phase_filebrowser() {
  say "Initialize filebrowser DB + start service"

  local db="$FB_STATE_DIR/filebrowser.db"
  if [ ! -f "$db" ]; then
    # Run as the service user so the resulting file is owned
    # correctly from the start.
    sudo -u "$FB_USER" "$FB_INSTALL_PREFIX/cmmc-filebrowser" \
      --database "$db" config init >/dev/null
    sudo -u "$FB_USER" "$FB_INSTALL_PREFIX/cmmc-filebrowser" \
      --database "$db" config set --auth.method=oidc >/dev/null
    ok "fresh bolt DB at $db (auth.method=oidc)"
  else
    ok "bolt DB exists at $db"
  fi

  systemctl enable cmmc-filebrowser.service >/dev/null
  systemctl restart cmmc-filebrowser.service

  # Brief startup probe — filebrowser should be listening within 5s.
  # Probing HTTPS with -k because we're likely using a self-signed
  # cert; this is a liveness check, not a trust check.
  local waited=0
  until curl -skf -o /dev/null "https://127.0.0.1:$FB_LISTEN_PORT/health" \
     || curl -skf -o /dev/null "https://127.0.0.1:$FB_LISTEN_PORT/"; do
    sleep 1
    waited=$((waited+1))
    if [ $waited -ge 15 ]; then
      fail "filebrowser did not respond within 15s — check: journalctl -u cmmc-filebrowser"
    fi
  done
  ok "filebrowser responding on :$FB_LISTEN_PORT (HTTPS) after ${waited}s"
}

# --- Wazuh start (only if --with-wazuh) ------------------------------

phase_wazuh_start() {
  [ "$WITH_WAZUH" = "1" ] || return 0
  say "Start Wazuh bundle"

  systemctl enable cmmc-wazuh.service >/dev/null
  systemctl restart cmmc-wazuh.service

  note "Wazuh bundle boot takes 60-90s (indexer cluster form-up)"
  note "Dashboard will land on https://<host>:5601 — creds in $FB_ETC_DIR/environment"
}

# --- status + summary ------------------------------------------------

# --- Shop-floor SMB delivery (only if --with-smb) ----------------------
# Thin wrapper: the real work is config/smb/install-smb.sh (idempotent,
# also runnable on its own after deploy). Needs /etc/cmmc-smb/cells.yaml
# to exist — the inventory is site-specific and cannot be guessed.
phase_smb() {
  [ "$WITH_SMB" -eq 1 ] || return 0
  say "Shop-floor SMB delivery (--with-smb)"
  [ -n "$SMB_OT_IP" ] || fail "--with-smb needs --ot-ip <address the controllers connect to>"
  local bin=/usr/local/bin/cmmc-smb
  if [ -x "$REPO_DIR/bin/cmmc-smb" ]; then
    install -m 0755 "$REPO_DIR/bin/cmmc-smb" "$bin"          # release tarball
  else
    (cd "$REPO_DIR" && GOFIPS140=v1.0.0 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$bin" ./smb/cmd/cmmc-smb) \
      || fail "could not build cmmc-smb"
  fi
  ok "cmmc-smb installed at $bin"
  if [ ! -f /etc/cmmc-smb/cells.yaml ]; then
    install -d -m 0750 /etc/cmmc-smb
    install -m 0640 "$REPO_DIR/config/smb/cells.example.yaml" /etc/cmmc-smb/cells.example.yaml
    # Start empty: no shares, no firewall rules. The first cell is added
    # from the web UI (Settings → Shop floor) or by editing this file.
    cat > /etc/cmmc-smb/cells.yaml <<'EOF_CELLS'
# Shop-floor inventory — managed from the Open-CMMC web UI (Settings → Shop floor).
# Hand edits are fine; see cells.example.yaml in this directory for every field.
cells: []
EOF_CELLS
    chmod 0640 /etc/cmmc-smb/cells.yaml
    note "no inventory yet — add your cells and machines in the web UI (Settings → Shop floor)"
  fi
  local args=(--ot-ip "$SMB_OT_IP" --bin "$bin")
  [ -n "$SMB_OT_IF" ] && args+=(--ot-interface "$SMB_OT_IF")
  [ -n "$SMB_OT_VLAN" ] && args+=(--ot-vlan "$SMB_OT_VLAN")
  [ -n "$SMB_IMAGE" ] && args+=(--image "$SMB_IMAGE")
  [ -n "$SMB_LEGACY_IP" ] && args+=(--legacy-ip "$SMB_LEGACY_IP")
  ENV_FILE="$FB_ETC_DIR/environment" FB_USER="$FB_USER" bash "$REPO_DIR/config/smb/install-smb.sh" "${args[@]}"
  systemctl restart cmmc-filebrowser.service
  ok "shop-floor SMB enabled — next: cmmc-smb useradd <machine> for each controller"
}

phase_summary() {
  say "Summary"
  local host_ip host_name
  host_ip=$(detect_host_ip)
  host_name=$(detect_host_name)
  cat <<EOF
CMMC-Filebrowser deployed.
  URL:        https://$host_name:$FB_LISTEN_PORT
  Keycloak:   https://$host_name:$KC_BIND_PORT
              admin creds: see $FB_ETC_DIR/environment (KC_ADMIN / KC_ADMIN_PASSWORD)
  TLS cert:   $FB_TLS_DIR/server.crt
  Trust bundle: $FB_TLS_DIR/ca.crt  (import in browsers to silence dev warnings)
  Host IP:    $host_ip  (for the SAN list; hostname is the canonical URL)
  State DB:   $FB_STATE_DIR/filebrowser.db
  Cabinet:    $FB_DATA_DIR
  Systemd:    cmmc-filebrowser.service, cmmc-keycloak.service$([ "$WITH_WAZUH" = "1" ] && printf ', cmmc-wazuh.service')

>>> Access paths <<<

Default deploy (TOTP-only, zero-DNS):
  • https://$host_ip:$FB_LISTEN_PORT → filebrowser
  • https://$host_ip:$KC_BIND_PORT → Keycloak
  • All flows work over IP: TOTP login, cabinet access, audit stream
  • Passkeys are NOT enrollable (browsers reject WebAuthn on IP)

To enable passkeys — requires a hostname DNS record (or /etc/hosts
on every client machine):
  1. Point $host_name → $host_ip in DNS (or clients' /etc/hosts)
  2. On this appliance:
       sudo sed -i 's|FB_OIDC_ISSUER=.*|FB_OIDC_ISSUER=https://$host_name:$KC_BIND_PORT/realms/cmmc|' $FB_ETC_DIR/environment
       sudo systemctl restart cmmc-filebrowser
  3. Clients browse https://$host_name:$FB_LISTEN_PORT instead
  4. Passkey enrollment now works

No appliance redeploy needed to switch modes — the cert, KC realm,
and KC's redirect-URI allowlist already carry BOTH the IP and
hostname. Only FB_OIDC_ISSUER is the canonical anchor FB pins its
token verification to.

Override the hostname at deploy time (picks a different SAN):
  sudo FB_HOST_NAME=filebrowser.customer.internal install.sh deploy

EOF

  if [ "$WITH_DEMO" = "1" ]; then
    cat <<EOF
>>> EVALUATION ROSTER ACTIVE <<<

Demo users (temp password: ${SEED_TEMP_PASSWORD:-WelcomeCMMC2026!}):
  dana   — filebrowser-admins + compliance (admin)
  alice  — engineering
  bob    — operations
  carol  — management
  dave   — sales

These accounts share a password published in the Open-CMMC repository.
Delete them before this system holds real CUI, and redeploy with
FB_ADMIN_USER=<name> instead of --demo.
EOF
  else
    cat <<EOF
>>> Administrator <<<

  $FB_ADMIN_USER — filebrowser-admins + compliance
  Temporary password was printed once during the Keycloak bootstrap
  phase above. Scroll up if you have not captured it; if it is lost,
  reset it from the Keycloak admin console.
EOF
  fi

  if [ "$AV_MODE" = "required" ]; then
    cat <<EOF

>>> Antivirus <<<

  Fail-closed scan-on-upload is ACTIVE (FB_CMMC_AV=required, clamd on
  127.0.0.1:3310). An infected upload is refused with 422; an
  unreachable clamd returns 503 rather than storing unscanned bytes.
  Signature updates run via clamav-freshclam.
EOF
  else
    cat <<EOF

>>> Antivirus — NOT ACTIVE <<<

  FB_CMMC_AV=$AV_MODE. Uploads are not being scanned, so NIST 3.14.2
  and 3.14.5 are not met by the product on this host.

  Fix the cause reported above, then:
      sudo config/install.sh enable-av

  Air-gapped hosts: point /etc/freshclam.conf at an internal mirror,
  run freshclam, then enable-av.
EOF
  fi

  cat <<EOF
First login forces password change + TOTP enrollment (CMMC 3.5.3).
Security keys — once DNS is in place — enroll from the Account
Console. See docs/operator-2fa.md.

>>> BACK UP THE KEK BEFORE STORING ANY CUI <<<

  $FB_ETC_DIR/kek.bin

Every file in the cabinet is encrypted under this 32-byte key. It is
generated on this host and stored nowhere else. If it is lost, the
cabinet is unrecoverable — there is no escrow, no recovery code, and
no vendor copy.

  sudo config/install.sh backup /mnt/removable/open-cmmc-\$(date +%F)

Then move that directory to media held separately from this appliance,
and verify it restores on a spare host before you trust it. Full
procedure: docs/backup-restore.md
EOF
}

# --- backup / restore -------------------------------------------------
#
# What has to survive a total loss of this host, and why:
#
#   kek.bin        the 32-byte envelope master key. Without it every
#                  file in the cabinet is ciphertext forever. This is
#                  the single irreplaceable artifact.
#   environment    FB_SETTINGS_KEY (JWT signing), FB_AUDIT_HMAC_KEY
#                  (audit chain continuity), OIDC client secret. Losing
#                  the HMAC key breaks chain verification across the
#                  restore boundary — the audit history stays readable
#                  but no longer verifies as one chain.
#   filebrowser.db users, folder ACLs, CUI marks, share rows.
#   cabinet        the files themselves (already envelope-encrypted on
#                  disk, but back them up encrypted anyway).
#   keycloak       realm export: users, groups, TOTP credentials.
#
# The backup is NOT independently encrypted. It contains kek.bin in the
# clear, so the archive is exactly as sensitive as the cabinet itself
# and must go to media with the same handling controls. Independent
# backup-key custody (800-171 3.8.9) is not implemented — see
# docs/backup-restore.md for what that means for your SSP.

backup_manifest() {
  printf '%s\n' \
    "open-cmmc backup" \
    "created: $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "host: $(hostname)" \
    "version: $("$FB_INSTALL_PREFIX/filebrowser" version 2>/dev/null | head -1 || echo unknown)" \
    "etc: $FB_ETC_DIR" \
    "state: $FB_STATE_DIR" \
    "data: $FB_DATA_DIR"
}

cmd_backup() {
  need_root
  local dest="${1:-}"
  [ -n "$dest" ] || fail "usage: install.sh backup <destination-dir>"
  [ -e "$dest" ] && fail "destination already exists: $dest (pick a new path)"

  say "Backup → $dest"
  install -d -m 0700 "$dest"

  # Config + keys. cp -a preserves the 0400/0600 modes the daemon
  # enforces on restore.
  if [ -d "$FB_ETC_DIR" ]; then
    cp -a "$FB_ETC_DIR" "$dest/etc"
    ok "config + keys (includes kek.bin)"
  else
    fail "no config dir at $FB_ETC_DIR — is this an installed host?"
  fi

  # BoltDB. Stop-free copy is unsafe while the service writes, so take
  # the service down for the copy and bring it back. A backup that
  # silently captures a torn database is worse than no backup.
  local was_active=0
  if systemctl is-active --quiet cmmc-filebrowser; then
    was_active=1
    systemctl stop cmmc-filebrowser
  fi
  install -d -m 0700 "$dest/state"
  if [ -f "$FB_STATE_DIR/filebrowser.db" ]; then
    cp -a "$FB_STATE_DIR/filebrowser.db" "$dest/state/"
    ok "state database (service quiesced for a consistent copy)"
  else
    warn "no filebrowser.db found at $FB_STATE_DIR"
  fi

  # Cabinet.
  if [ -d "$FB_DATA_DIR" ]; then
    cp -a "$FB_DATA_DIR" "$dest/cabinet"
    ok "cabinet ($(du -sh "$FB_DATA_DIR" 2>/dev/null | cut -f1))"
  fi

  [ "$was_active" = "1" ] && systemctl start cmmc-filebrowser

  # Keycloak realm — users, groups, enrolled TOTP credentials. Without
  # this a restore leaves every user re-enrolling their second factor.
  if podman container exists cmmc-keycloak 2>/dev/null; then
    if podman exec cmmc-keycloak /opt/keycloak/bin/kc.sh export \
         --realm cmmc --file /tmp/cmmc-realm.json >/dev/null 2>&1 &&
       podman cp cmmc-keycloak:/tmp/cmmc-realm.json "$dest/cmmc-realm.json" 2>/dev/null; then
      podman exec cmmc-keycloak rm -f /tmp/cmmc-realm.json 2>/dev/null || true
      ok "keycloak realm export"
    else
      warn "keycloak realm export failed — users/TOTP will need re-provisioning on restore"
    fi
  else
    warn "cmmc-keycloak container not found — skipping realm export"
  fi

  backup_manifest > "$dest/MANIFEST"
  chmod -R go-rwx "$dest"
  ok "backup complete: $dest"
  warn "this archive contains kek.bin in the clear — handle it as CUI"
  note "verify it: restore onto a spare host before you rely on it"
}

cmd_restore() {
  need_root
  local src="${1:-}"
  [ -n "$src" ] || fail "usage: install.sh restore <backup-dir>"
  [ -f "$src/MANIFEST" ] || fail "no MANIFEST in $src — not an install.sh backup"

  say "Restore ← $src"
  cat "$src/MANIFEST"

  # Refuse to restore over a live cabinet. Overwriting a populated
  # cabinet with an older one is unrecoverable in the other direction.
  if [ -d "$FB_DATA_DIR" ] && [ -n "$(ls -A "$FB_DATA_DIR" 2>/dev/null)" ]; then
    fail "cabinet at $FB_DATA_DIR is not empty — run 'uninstall --wipe-state' first if you really mean to replace it"
  fi

  systemctl stop cmmc-filebrowser 2>/dev/null || true

  cp -a "$src/etc/." "$FB_ETC_DIR/"
  ok "config + keys restored"
  install -d -m 0750 -o "$FB_USER" -g "$FB_USER" "$FB_STATE_DIR"
  [ -f "$src/state/filebrowser.db" ] && cp -a "$src/state/filebrowser.db" "$FB_STATE_DIR/"
  install -d -m 0750 -o "$FB_USER" -g "$FB_USER" "$FB_DATA_DIR"
  [ -d "$src/cabinet" ] && cp -a "$src/cabinet/." "$FB_DATA_DIR/"
  chown -R "$FB_USER:$FB_USER" "$FB_STATE_DIR" "$FB_DATA_DIR"
  ok "state + cabinet restored"

  # SELinux contexts do not survive a cp from removable media.
  command -v restorecon >/dev/null 2>&1 && restorecon -RF "$FB_ETC_DIR" "$FB_STATE_DIR" "$FB_DATA_DIR" 2>/dev/null || true

  if [ -f "$src/cmmc-realm.json" ] && podman container exists cmmc-keycloak 2>/dev/null; then
    podman cp "$src/cmmc-realm.json" cmmc-keycloak:/tmp/cmmc-realm.json 2>/dev/null &&
      podman exec cmmc-keycloak /opt/keycloak/bin/kc.sh import \
        --file /tmp/cmmc-realm.json --override true >/dev/null 2>&1 &&
      ok "keycloak realm imported" ||
      warn "realm import failed — re-provision users manually"
  fi

  systemctl start cmmc-filebrowser 2>/dev/null || true
  ok "restore complete"
  note "audit chain: events from before the restore verify as their own"
  note "chain; the first event after restore starts a new segment."
}

# --- status command --------------------------------------------------

cmd_status() {
  echo "--- systemd units ---"
  systemctl --no-pager status cmmc-filebrowser cmmc-keycloak 2>/dev/null || true
  if systemctl list-unit-files cmmc-wazuh.service >/dev/null 2>&1; then
    systemctl --no-pager status cmmc-wazuh 2>/dev/null || true
  fi

  echo
  echo "--- reachability ---"
  curl -skf -o /dev/null -w 'filebrowser :%{http_code}\n' \
    "https://127.0.0.1:$FB_LISTEN_PORT/" || echo "filebrowser: not reachable"
  curl -skf -o /dev/null -w 'keycloak    :%{http_code}\n' \
    "https://127.0.0.1:$KC_BIND_PORT/realms/master" || echo "keycloak: not reachable"

  # Antivirus posture. Two things can disagree here and both matter:
  # what the env file asks for, and whether clamd is actually
  # answering. Report both rather than a single green/red.
  echo
  echo "--- antivirus (3.14.2 / 3.14.5) ---"
  local declared="unset"
  if [ -f "$FB_ETC_DIR/environment" ]; then
    # `|| true` for the same pipefail reason as the find below: an env
    # file predating this feature has no FB_CMMC_AV line, grep exits 1,
    # and status would abort instead of reporting "unset".
    declared=$(grep -E '^FB_CMMC_AV=' "$FB_ETC_DIR/environment" 2>/dev/null | cut -d= -f2 || true)
    [ -n "$declared" ] || declared="unset"
  fi
  echo "configured  : FB_CMMC_AV=$declared"

  if (exec 3<>/dev/tcp/127.0.0.1/3310) 2>/dev/null; then
    exec 3<&- 2>/dev/null || true
    echo "clamd       : answering on 127.0.0.1:3310"
  else
    echo "clamd       : NOT answering on 127.0.0.1:3310"
    if [ "$declared" = "required" ]; then
      echo "              filebrowser will refuse to start in this state (fail-closed)"
    else
      echo "              uploads are NOT being scanned"
    fi
  fi

  # `|| true` is load-bearing: under `set -o pipefail` a failing find
  # (no /var/lib/clamav on a host that never installed clamav) fails
  # the whole pipeline and `set -e` aborts status entirely.
  local sigs
  sigs=$(find /var/lib/clamav -name 'daily.c[lv]d' -mtime -7 2>/dev/null | head -1 || true)
  if [ -n "$sigs" ]; then
    echo "signatures  : current (updated within 7 days)"
  elif [ -e /var/lib/clamav/daily.cvd ] || [ -e /var/lib/clamav/daily.cld ]; then
    echo "signatures  : STALE (older than 7 days) — check clamav-freshclam (3.14.4)"
  else
    echo "signatures  : absent — run freshclam"
  fi

  if [ "$declared" != "required" ]; then
    echo
    echo "  To turn on fail-closed scanning: sudo config/install.sh enable-av"
  fi
}

# --- uninstall --------------------------------------------------------
#
# Stop + disable services, remove units, DELETE the binary.
# Leaves state (DB + cabinet + env file + KC data volume) in place
# so accidental runs don't destroy CUI. Operator removes state
# manually after a deliberate review.

cmd_uninstall() {
  need_root
  if [ "$WIPE_STATE" = "1" ]; then
    say "Uninstalling + wiping state (DESTRUCTIVE — cabinet contents will be deleted)"
  else
    say "Uninstalling (state preserved — pass --wipe-state for a full wipe)"
  fi

  for svc in cmmc-wazuh cmmc-filebrowser cmmc-keycloak; do
    systemctl stop "$svc.service" 2>/dev/null || true
    systemctl disable "$svc.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$svc.service"
  done
  systemctl daemon-reload

  rm -f "$FB_INSTALL_PREFIX/cmmc-filebrowser"
  rm -f /etc/rsyslog.d/50-cmmc-filebrowser.conf
  systemctl restart rsyslog 2>/dev/null || true

  # Close firewall ports the installer opened. Safe to run even if
  # firewalld isn't present — we swallow errors.
  if command -v firewall-cmd >/dev/null 2>&1; then
    for p in "$FB_LISTEN_PORT" "$KC_BIND_PORT"; do
      firewall-cmd --permanent --remove-port="${p}/tcp" >/dev/null 2>&1 || true
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi

  # Remove the CA anchor we installed (harmless no-op if dev cert
  # never was generated).
  rm -f /etc/pki/ca-trust/source/anchors/cmmc-filebrowser-ca.crt
  if command -v update-ca-trust >/dev/null 2>&1; then
    update-ca-trust 2>/dev/null || true
  fi

  # Strip the /etc/hosts line we added (identified by the comment).
  # Sed is in-place; a backup file would leak old hosts state on
  # uninstall, so we accept the trade-off of no backup.
  if grep -q "Added by cmmc-filebrowser install.sh" /etc/hosts 2>/dev/null; then
    sed -i '/# Added by cmmc-filebrowser install.sh/,+1d' /etc/hosts
  fi

  if [ "$WIPE_STATE" = "1" ]; then
    # Stop the podman containers before removing volumes — podman
    # refuses to rm a volume attached to a stopped container.
    podman rm -f cmmc-keycloak 2>/dev/null || true
    podman volume rm cmmc-keycloak-data 2>/dev/null || true
    # Wazuh bundle if present.
    if [ -f "$FB_ETC_DIR/wazuh/podman-compose.wazuh.yml" ]; then
      podman compose -f "$FB_ETC_DIR/wazuh/podman-compose.wazuh.yml" down -v 2>/dev/null || true
    fi
    # Filebrowser state + cabinet + env file.
    rm -f "$FB_STATE_DIR/filebrowser.db" "$FB_STATE_DIR/filebrowser.db.lock"
    # Cabinet contents — leave the directory itself so a re-deploy
    # reuses the same SELinux context.
    if [ -d "$FB_DATA_DIR" ]; then
      find "$FB_DATA_DIR" -mindepth 1 -delete 2>/dev/null || true
    fi
    rm -f "$FB_ETC_DIR/environment"
    # KEK — wipe alongside cabinet contents. Keeping a stale KEK after
    # the cabinet is gone is pointless (nothing left to decrypt) and
    # risks a new deploy picking up someone else's key by accident.
    rm -f "$FB_ETC_DIR/kek.bin"
    rm -rf "$FB_ETC_DIR/wazuh"
    # TLS material — removed on --wipe-state so the next deploy
    # regenerates against the current FB_HOST_NAME / FB_HOST_IP.
    # Customer-supplied certs (case 1 of phase_tls) also get wiped
    # here; `uninstall` without --wipe-state preserves them.
    rm -rf "$FB_TLS_DIR"
    ok "state wiped; next deploy starts from scratch"
  else
    say "Preserved (remove manually OR re-run with --wipe-state)"
    cat <<EOF
  $FB_STATE_DIR            (filebrowser BoltDB + audit state)
  $FB_DATA_DIR             (cabinet files — MAY CONTAIN CUI)
  $FB_ETC_DIR/environment  (OIDC + KEK + HMAC keys)
  podman volume cmmc-keycloak-data  (IdP state)
EOF
  fi
}

# --- deploy orchestrator ---------------------------------------------

cmd_deploy() {
  need_root
  preflight
  phase_user_and_dirs
  # --from-release skips the build-from-source path: we install the
  # pre-built binary + redirect REPO_DIR at the extracted release
  # tree, so phase_units / phase_keycloak / phase_wazuh_assets pick
  # up the release's config files instead of a local git checkout
  # (which may not even exist on an air-gap deploy host).
  if [ -n "$FROM_RELEASE" ]; then
    phase_from_release
  else
    phase_frontend
    phase_binary
  fi
  phase_units
  phase_wazuh_assets
  phase_tls
  phase_firewall
  phase_kek
  phase_clamav
  phase_env_file
  phase_keycloak
  phase_filebrowser
  phase_wazuh_start
  phase_smb
  phase_summary
}

# --- dispatch ---------------------------------------------------------

case "$cmd" in
  deploy)    cmd_deploy ;;
  backup)    cmd_backup "${POSITIONAL[0]:-}" ;;
  restore)   cmd_restore "${POSITIONAL[0]:-}" ;;
  enable-av) cmd_enable_av ;;
  status)    cmd_status ;;
  uninstall) cmd_uninstall ;;
  help|"")   cmd_help ;;
  *) echo "unknown command: $cmd" >&2; cmd_help; exit 2 ;;
esac
