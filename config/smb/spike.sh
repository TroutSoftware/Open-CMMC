#!/usr/bin/env bash
# spike.sh — Phase 0 go/no-go for shop-floor SMB on a FIPS host
#
# Proves, on a real RHEL 9 / AlmaLinux 9 host with fips=1, that a Samba
# container with a non-FIPS userspace can serve password (NTLMv2)
# clients with SMB2 signing and SMB3 encryption — the one assumption
# rev 3 of docs/cmmc/smb-connectivity-scope.md rests on (§ 2, § 8).
#
# Does NOT need the enclave binary. Needs: podman, samba-client
# (smbclient), go (or --bin), and a spare OT-side address to publish on.
#
# Usage:
#   sudo config/smb/spike.sh --ot-ip 10.20.0.5 [--image REF | --base REF]
#                            [--bin ./cmmc-smb] [--keep] [--gnutls-lever]
#
#   --image        use a prebuilt image instead of building the Containerfile
#   --base         alternative base for the build (e.g. a UBI image) —
#                  combine with --gnutls-lever to test GNUTLS_FORCE_FIPS_MODE=0
#   --ot-ip2       second address for the SMB2-only test machine (default:
#                  <ot-ip with last octet 250>, added as a temporary alias).
#                  Loopback cannot be used: podman masquerades 127.0.0.1
#                  connections as the bridge gateway, which hosts allow denies.
#   --keep         leave the container and work dir in place for inspection
#
# Exit 0 only if every check passes.
set -euo pipefail

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
pass(){ printf '    \033[1;32mPASS\033[0m %s\n' "$*"; PASSED=$((PASSED+1)); }
failc(){ printf '    \033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); }
die() { printf '\033[1;31mabort:\033[0m %s\n' "$*" >&2; exit 2; }

OT_IP=""; OT_IP2=""; IMAGE=""; BASE=""; BIN=""; KEEP=0; GNUTLS_LEVER=0
PASSED=0; FAILED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ot-ip) OT_IP="$2"; shift 2 ;;
    --ot-ip2) OT_IP2="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --base)  BASE="$2"; shift 2 ;;
    --bin)   BIN="$2"; shift 2 ;;
    --keep)  KEEP=1; shift ;;
    --gnutls-lever) GNUTLS_LEVER=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown flag $1" ;;
  esac
done
[ -n "$OT_IP" ] || die "--ot-ip is required (an address on this host that the test client can reach)"
[ "$(id -u)" -eq 0 ] || die "run as root (podman + firewalld)"
[ -n "$OT_IP2" ] || OT_IP2="${OT_IP%.*}.250"
OT_IF="$(ip -4 -o addr show | awk -v ip="$OT_IP" '$4 ~ "^"ip"/" {print $2; exit}')"
[ -n "$OT_IF" ] || die "$OT_IP is not configured on any interface"
ADDED_ALIAS=0
if ! ip -4 -o addr show dev "$OT_IF" | grep -q " $OT_IP2/"; then
  ip addr add "$OT_IP2/32" dev "$OT_IF" && ADDED_ALIAS=1
fi

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /tmp/cmmc-smb-spike.XXXXXX)"
NAME="cmmc-smb-spike"
cleanup() {
  if [ "$KEEP" -eq 1 ]; then echo "kept: container $NAME, workdir $WORK"; return; fi
  podman rm -f "$NAME" >/dev/null 2>&1 || true
  podman volume rm -f "${NAME}-state" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "${ADDED_ALIAS:-0}" -eq 1 ] && ip addr del "$OT_IP2/32" dev "$OT_IF" 2>/dev/null || true
}
trap cleanup EXIT

say "Preflight"
if command -v fips-mode-setup >/dev/null; then
  fips-mode-setup --check | grep -qi enabled || die "host is not in FIPS mode — the spike is meaningless off a fips=1 kernel"
else
  [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = "1" ] || die "fips_enabled != 1"
fi
command -v podman >/dev/null || die "podman missing"
# smbclient: use the host's if present, otherwise run it from a small
# client container on the host network (no subscription / dnf needed).
CLIENT_IMAGE="localhost/cmmc-smbclient:spike"
if command -v smbclient >/dev/null; then
  smbc() { smbclient "$@"; }
else
  if ! podman image exists "$CLIENT_IMAGE"; then
    printf 'FROM docker.io/library/debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends smbclient && rm -rf /var/lib/apt/lists/*\n' \
      | podman build -q -t "$CLIENT_IMAGE" -f - . >/dev/null
  fi
  smbc() { podman run --rm -i --network host "$CLIENT_IMAGE" smbclient "$@"; }
fi
if [ -z "$BIN" ]; then
  command -v go >/dev/null || die "go missing and no --bin given"
  ( cd "$REPO" && go build -o "$WORK/cmmc-smb" ./smb/cmd/cmmc-smb )
  BIN="$WORK/cmmc-smb"
fi
pass "fips=1 host, podman, smbclient ($(command -v smbclient >/dev/null && echo host || echo container)), cmmc-smb binary"

say "Image"
if [ -z "$IMAGE" ]; then
  IMAGE="localhost/cmmc-smb:spike"
  build_args=()
  [ -n "$BASE" ] && build_args+=(--build-arg "BASE=$BASE")
  podman build "${build_args[@]}" -t "$IMAGE" -f "$REPO/config/smb/Containerfile" "$REPO/config/smb" >/dev/null
fi
pass "image $IMAGE"

say "Render a two-machine inventory (smb3 + smb2), both from $OT_IP"
# Both "machines" are this host, so hosts allow must admit the address
# the test client egresses from. Two accounts let us test the encrypted
# share and the signed-only share separately.
cat > "$WORK/cells.yaml" <<EOF
cells:
  - name: spike
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/spike/return
    pds_attested: true
    machines:
      - { name: m3, ip: $OT_IP, dialect: smb3 }
      - { name: m2, ip: $OT_IP2, dialect: smb2 }
EOF
# cells.go refuses duplicate IPs, so m2 gets the alias address; a
# locally-originated connection to the alias carries the alias as its
# source, which is what hosts allow sees after the DNAT.
GID="$(getent group cmmc-filebrowser | cut -d: -f3 || true)"; GID="${GID:-$(id -g)}"
"$BIN" render --cells "$WORK/cells.yaml" --out "$WORK/etc" --image "$IMAGE" --ot-ip "$OT_IP" --gid "$GID" >/dev/null
mkdir -p "$WORK/ot/out/spike" "$WORK/ot/return/spike/m3" "$WORK/ot/return/spike/m2"
echo "O0001 (SPIKE) G0 X0 M30" > "$WORK/ot/out/spike/O0001.nc"
chown -R ":$GID" "$WORK/ot"; chmod -R g+rwX "$WORK/ot"
pass "rendered $(grep -c '^\[' "$WORK/etc/primary/smb.conf") sections"

say "Start container (same flags as the quadlet)"
podman rm -f "$NAME" >/dev/null 2>&1 || true
env_args=()
[ "$GNUTLS_LEVER" -eq 1 ] && env_args+=(-e GNUTLS_FORCE_FIPS_MODE=0)
podman run -d --name "$NAME" "${env_args[@]}" \
  -p "$OT_IP:445:445" -p "$OT_IP2:445:445" \
  --read-only --cap-drop=ALL --cap-add=NET_BIND_SERVICE,SETUID,SETGID,DAC_OVERRIDE,CHOWN \
  --security-opt=no-new-privileges --pids-limit=256 --memory=512m \
  --tmpfs /run --tmpfs /var/cache/samba --tmpfs /var/log/samba \
  -v "${NAME}-state:/var/lib/samba" \
  -v "$WORK/etc/primary:/etc/samba:ro,Z" \
  -v "$WORK/etc/primary/passwd:/etc/passwd:ro,Z" -v "$WORK/etc/primary/group:/etc/group:ro,Z" \
  -v "$WORK/ot/out:/export/out:ro,z" -v "$WORK/ot/return:/export/return:rw,z" \
  "$IMAGE" >/dev/null
sleep 2
podman ps --filter "name=$NAME" --format '{{.Status}}' | grep -q Up || { podman logs --tail 20 "$NAME" 2>&1 || true; die "container did not stay up"; }
pass "container up"

say "Accounts (NTLMv2 hash creation is the first MD4 test)"
# (finite read → no SIGPIPE under pipefail; `tr … </dev/urandom | head` aborts the script)
genpw() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }
PW3="$(genpw)"; PW2="$(genpw)"
# smbd creates passdb.tdb lazily; give it a few seconds before the
# first account is added rather than failing on a startup race.
addacct() { # name password
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if printf '%s\n%s\n' "$2" "$2" | podman exec -i "$NAME" smbpasswd -s -a "$1" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}
if addacct m3 "$PW3" && addacct m2 "$PW2"; then
  pass "smbpasswd -a succeeded (MD4 available in container userspace, fips_enabled=$(podman exec "$NAME" cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo '?') inside)"
else
  failc "smbpasswd -a failed — MD4 refused; try --base <ubi> --gnutls-lever"; podman logs --tail 20 "$NAME" 2>&1 || true
fi

sc() { smbc "$@" -c 'ls' 2>&1; }
say "Checks"
# (a) NTLMv2 login + list on the encrypted share
if sc "//$OT_IP/spike-out" -U "m3%$PW3" | grep -q O0001.nc; then pass "(a) NTLMv2 login, share listing"; else failc "(a) NTLMv2 login"; fi
# (b) encryption required by the client succeeds on the smb3 share
if sc "//$OT_IP/spike-out" -U "m3%$PW3" --client-protection=encrypt | grep -q O0001.nc; then pass "(b) SMB3 encryption negotiated"; else failc "(b) SMB3 encryption"; fi
# (c) SMB2-only client connects to the signed share; signing cannot be disabled
if sc "//$OT_IP2/spike-out-signed" -U "m2%$PW2" -m SMB2 | grep -q O0001.nc; then pass "(c1) SMB2 client, mandatory signing"; else failc "(c1) SMB2 client"; fi
# A client cannot refuse signing the server mandates, so "connect with
# signing disabled and expect failure" proves nothing. Instead hold a
# session open and read what smbd negotiated from its session table.
# Interactive smbclient reads commands from stdin; a silent stdin that
# closes after 8s holds the session open exactly that long.
( sleep 8 | smbc "//$OT_IP2/spike-out-signed" -U "m2%$PW2" -m SMB2 >/dev/null 2>&1 & )
( sleep 8 | smbc "//$OT_IP/spike-out" -U "m3%$PW3" >/dev/null 2>&1 & )
sleep 4
st="$(podman exec "$NAME" smbstatus 2>/dev/null || true)"
if printf '%s' "$st" | grep -E '^[0-9]+ +m2 ' | grep -qE 'HMAC-SHA256|AES-128-CMAC|AES-128-GMAC'; then pass "(c2) SMB2 session from m2 is signed ($(printf '%s' "$st" | grep -E '^[0-9]+ +m2 ' | grep -oE 'HMAC-SHA256|AES-128-CMAC|AES-128-GMAC' | head -1))"; else failc "(c2) m2 session not shown as signed in smbstatus"; printf '%s\n' "$st" | head -20; fi
if printf '%s' "$st" | grep -E '^[0-9]+ +m3 ' | grep -qE 'AES-128-GCM|AES-256-GCM|AES-128-CCM'; then pass "(b2) SMB3 session from m3 is encrypted ($(printf '%s' "$st" | grep -E '^[0-9]+ +m3 ' | grep -oE 'AES-[0-9]+-(GCM|CCM)' | head -1))"; else failc "(b2) m3 session not shown as encrypted in smbstatus"; fi
sleep 4
# (d) SMB1 refused by the primary instance
if sc "//$OT_IP/spike-out" -U "m3%$PW3" -m NT1 | grep -q O0001.nc; then failc "(d) SMB1 was accepted by the primary instance"; else pass "(d) SMB1 refused (server min protocol = SMB2_02)"; fi
# (e) wrong password fails and is visible in auth_audit
sc "//$OT_IP/spike-out" -U "m3%wrong-$PW3" >/dev/null || true
if podman logs "$NAME" 2>&1 | grep -qE 'Auth: .*\[m3\].*(NT_STATUS_WRONG_PASSWORD|NT_STATUS_LOGON_FAILURE|NT_STATUS_NO_SUCH_USER)'; then pass "(e) failed logon visible as an Auth record (client IP, account, NTLMv2, status)"; else failc "(e) failed logon not found in container log"; fi
# (f) return share is writable, out share is not
if echo "probe" | smbc "//$OT_IP/spike-return" -U "m3%$PW3" -c 'put /dev/stdin probe.txt' >/dev/null 2>&1 && [ -f "$WORK/ot/return/spike/m3/probe.txt" ]; then pass "(f1) return share writable, lands in return/spike/m3/"; else failc "(f1) return write"; fi
if echo "x" | smbc "//$OT_IP/spike-out" -U "m3%$PW3" -c 'put /dev/stdin x.nc' >/dev/null 2>&1; then failc "(f2) out share is WRITABLE"; else pass "(f2) out share read-only"; fi

say "Summary: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
