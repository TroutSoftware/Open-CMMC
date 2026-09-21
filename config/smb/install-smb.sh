#!/usr/bin/env bash
# install-smb.sh — enable shop-floor SMB delivery on an Open-CMMC host
#
# Standalone for now. FUTURE: called by `install.sh --with-smb` once the
# pending installer changes land; until then run it after install.sh.
#
# What it does (docs/cmmc/smb-connectivity-scope.md § 4, § 8):
#   1. verify podman + firewalld + a FIPS-mode host
#   2. create /srv/cmmc-filebrowser/ot/{out,return,state,quarantine}
#      owned by the service user, group-accessible to the container
#   3. create firewalld zone "ot" bound to the OT interface, target DROP
#   4. render smb.conf / passwd / group / firewalld.sh / quadlets from
#      cells.yaml with `cmmc-smb render`
#   5. apply the rich rules, install the quadlets, start cmmc-smb
#   6. write FB_CMMC_SMB=required (+root, +cells) into the env file
#
# Usage (simplest first):
#   sudo config/smb/install-smb.sh --ot-ip 10.20.0.5
#       OT interface auto-detected: the one NIC without a default route.
#       None?  --ot-ip becomes an alias on the LAN NIC (single-NIC shop;
#       firewall keyed on the OT address instead of a separate zone).
#   sudo config/smb/install-smb.sh --ot-ip 10.20.0.5 --ot-vlan 20
#       802.1Q sub-interface on the LAN NIC (managed switch, one cable).
#   sudo config/smb/install-smb.sh --ot-ip 10.20.0.5 --ot-interface eth1
#       explicit second NIC.
# Optional: --image REF (default: images/cmmc-smb.tar from the release, else
#           build config/smb/Containerfile), --legacy-ip IP (SMB1 cells),
#           --cells PATH, --bin PATH, --no-clamav (do not start the bundled
#           ClamAV container when nothing answers on FB_CMMC_AV_ADDR).
#
# Idempotent: re-running re-renders and restarts; nothing is duplicated.
set -euo pipefail

say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()  { printf '    \033[1;32mok\033[0m %s\n' "$*"; }
note(){ printf '    %s\n' "$*"; }
warn(){ printf '    \033[1;33m!!\033[0m %s\n' "$*" >&2; }
fail(){ printf '    \033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

OT_IF=""; OT_IP=""; OT_VLAN=""; LEGACY_IP=""; IMAGE=""; ALIAS=0; NO_CLAMAV=0
CELLS="/etc/cmmc-smb/cells.yaml"
BIN="${BIN:-/usr/local/bin/cmmc-smb}"
FB_USER="${FB_USER:-cmmc-filebrowser}"
ENV_FILE="${ENV_FILE:-/etc/cmmc-filebrowser/environment}"
OT_ROOT="/srv/cmmc-filebrowser/ot"
ETC="/etc/cmmc-smb"
ZONE="ot"

while [ $# -gt 0 ]; do
  case "$1" in
    --ot-interface) OT_IF="$2"; shift 2 ;;
    --ot-ip)        OT_IP="$2"; shift 2 ;;
    --ot-vlan)      OT_VLAN="$2"; shift 2 ;;
    --no-clamav)    NO_CLAMAV=1; shift ;;
    --legacy-ip)    LEGACY_IP="$2"; shift 2 ;;
    --image)        IMAGE="$2"; shift 2 ;;
    --cells)        CELLS="$2"; shift 2 ;;
    --bin)          BIN="$2"; shift 2 ;;
    -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
    *) fail "unknown flag: $1" ;;
  esac
done
[ -n "$OT_IP" ] || fail "--ot-ip <address> is required (the address controllers will connect to)"
[ "$(id -u)" -eq 0 ] || fail "run as root"
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGES_DIR="$HERE/../../images"

say "Network mode"
LAN_IF="$(ip -4 route show default | awk '{print $5; exit}')"
if [ -n "$OT_VLAN" ]; then
  [ -n "$LAN_IF" ] || fail "no default route — cannot pick the NIC for VLAN $OT_VLAN; pass --ot-interface"
  OT_IF="${OT_IF:-$LAN_IF.$OT_VLAN}"
  if ! nmcli -t -f NAME con show | grep -qx "ot-vlan"; then
    nmcli con add type vlan ifname "$OT_IF" con-name ot-vlan dev "$LAN_IF" id "$OT_VLAN" \
      ipv4.method manual ipv4.addresses "$OT_IP/24" ipv6.method disabled ipv4.never-default yes >/dev/null
  fi
  nmcli con up ot-vlan >/dev/null
  ok "VLAN $OT_VLAN on $LAN_IF → $OT_IF ($OT_IP)"
elif [ -z "$OT_IF" ]; then
  # Auto-detect: an interface that is up, carries no default route and is
  # not a container/loopback/dummy device. Exactly one → that's the OT NIC.
  cands="$(ip -o link show up | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -vE '^(lo|podman|veth|cni|docker|dummy|virbr|br-)' | grep -vx "$LAN_IF" || true)"
  n="$(printf '%s\n' "$cands" | grep -c . || true)"
  if [ "$n" -eq 1 ]; then
    OT_IF="$cands"; ok "OT interface auto-detected: $OT_IF"
  elif [ "$n" -gt 1 ]; then
    fail "several candidate OT interfaces ($(printf '%s' "$cands" | tr '\n' ' ')) — pass --ot-interface"
  else
    # Single NIC: the OT address becomes an alias on the LAN NIC. No
    # physical separation; deny-by-default via destination-keyed rules.
    ALIAS=1; OT_IF="$LAN_IF"
    ok "single NIC ($LAN_IF): $OT_IP will be an alias on it (alias mode)"
  fi
fi
if [ "$ALIAS" -eq 1 ] && ! ip -4 addr show dev "$OT_IF" | grep -q " $OT_IP/"; then
  con="$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$OT_IF" '$2==d{print $1; exit}')"
  [ -n "$con" ] || fail "no NetworkManager connection on $OT_IF to add the alias to"
  nmcli con mod "$con" +ipv4.addresses "$OT_IP/32" && nmcli con up "$con" >/dev/null
  ok "alias $OT_IP added to $con"
fi

say "Preflight"
command -v podman >/dev/null || fail "podman not installed (dnf install -y podman)"
command -v firewall-cmd >/dev/null || fail "firewalld not installed — the OT zone is the deny-by-default evidence (3.13.1/3.13.6)"
[ -x "$BIN" ] || fail "cmmc-smb binary not found at $BIN (build: go build -o $BIN ./smb/cmd/cmmc-smb)"
if command -v fips-mode-setup >/dev/null && ! fips-mode-setup --check 2>/dev/null | grep -qi enabled; then
  warn "host is not in FIPS mode — the enclave side requires it; continuing for lab use only"
fi
ip link show "$OT_IF" >/dev/null 2>&1 || fail "interface $OT_IF not found"
ip -4 addr show "$OT_IF" | grep -q "inet $OT_IP/" || warn "$OT_IP is not configured on $OT_IF — 445 will not be reachable until it is"
id "$FB_USER" >/dev/null 2>&1 || fail "service user $FB_USER missing — run install.sh first"
[ -f "$CELLS" ] || fail "$CELLS not found — copy config/smb/cells.example.yaml there and edit it"
"$BIN" validate --cells "$CELLS" || fail "cells.yaml does not validate"
GID="$(getent group "$FB_USER" | cut -d: -f3)"
[ -n "$GID" ] || fail "group $FB_USER not found"
ok "preflight passed (service gid $GID)"

say "Directories"
# out/ and return/ are the only paths the container ever sees. The
# machine accounts run as per-machine uids with the service gid as
# primary group (rendered passwd/group), so: out/ is group-readable,
# return/ is group-writable, and the intake poller (service user)
# collects what the machines drop. state/ and quarantine/ are private.
install -d -m 0750 -o "$FB_USER" -g "$FB_USER" "$OT_ROOT" "$OT_ROOT/out"
install -d -m 0770 -o "$FB_USER" -g "$FB_USER" "$OT_ROOT/return"
install -d -m 0700 -o "$FB_USER" -g "$FB_USER" "$OT_ROOT/state" "$OT_ROOT/quarantine"
install -d -m 0750 -g "$FB_USER" "$ETC"
install -d -m 0750 "$ETC/primary" "$ETC/legacy" "$ETC/quadlet"
# The enclave process loads cells.yaml at boot and rewrites it from the
# web UI (Settings → Shop floor), so the service user owns it; the apply
# path unit below re-renders Samba whenever it changes.
chown "$FB_USER:$FB_USER" "$CELLS" && chmod 0640 "$CELLS"
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -a -t container_file_t "$OT_ROOT/(out|return)(/.*)?" 2>/dev/null || true
  restorecon -R "$OT_ROOT/out" "$OT_ROOT/return" 2>/dev/null || true
fi
ok "$OT_ROOT tree ready"

if [ "$ALIAS" -eq 1 ]; then
  ZONE="$(firewall-cmd --get-zone-of-interface "$OT_IF" 2>/dev/null || firewall-cmd --get-default-zone)"
  say "firewalld: alias mode — destination-keyed rules for $OT_IP in zone $ZONE"
else
  say "firewalld zone $ZONE on $OT_IF"
  if ! firewall-cmd --permanent --get-zones | tr ' ' '\n' | grep -qx "$ZONE"; then
    firewall-cmd --permanent --new-zone="$ZONE" >/dev/null
  fi
  firewall-cmd --permanent --zone="$ZONE" --change-interface="$OT_IF" >/dev/null
  firewall-cmd --permanent --zone="$ZONE" --set-target=DROP >/dev/null
fi
# The enclave's HTTPS listener must not be reachable from the OT side:
# nothing but 445 (added per machine by firewalld.sh) is opened here.
sysctl -w net.ipv4.ip_forward=0 >/dev/null
grep -q '^net.ipv4.ip_forward' /etc/sysctl.d/99-cmmc-smb.conf 2>/dev/null || echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/99-cmmc-smb.conf
[ "$ALIAS" -eq 1 ] && ok "ip_forward=0" || ok "zone $ZONE: interface $OT_IF, target DROP, ip_forward=0"

say "Image"
if [ -z "$IMAGE" ]; then
  IMAGE="localhost/cmmc-smb:bundled"
  if [ -f "$IMAGES_DIR/cmmc-smb.tar" ]; then
    podman load -q -i "$IMAGES_DIR/cmmc-smb.tar" >/dev/null; ok "loaded $IMAGES_DIR/cmmc-smb.tar"
  elif ! podman image exists "$IMAGE"; then
    podman build -q -t "$IMAGE" -f "$HERE/Containerfile" "$HERE" >/dev/null; ok "built from $HERE/Containerfile"
  else
    note "image $IMAGE present"
  fi
fi

say "Render"
args=(render --cells "$CELLS" --out "$ETC" --image "$IMAGE" --ot-ip "$OT_IP" --ot-zone "$ZONE" --gid "$GID")
[ -n "$LEGACY_IP" ] && args+=(--legacy-ip "$LEGACY_IP")
[ "$ALIAS" -eq 1 ] && args+=(--alias)
"$BIN" "${args[@]}"
chmod 0640 "$ETC"/primary/* "$ETC"/legacy/* 2>/dev/null || true
# The web UI reads render.env (OT address, apply timestamp) as the service user.
chgrp "$FB_USER" "$ETC/render.env" && chmod 0640 "$ETC/render.env"
ok "rendered under $ETC"

say "Apply firewalld rules"
# Drop rules from a previous render before applying the current set so
# a removed machine loses access (idempotency).
while IFS= read -r r; do
  [ -n "$r" ] || continue
  # alias mode shares the LAN zone: touch only rules for the OT address.
  if [ "$ALIAS" -eq 1 ] && ! printf '%s' "$r" | grep -q "destination address=\"$OT_IP/32\""; then continue; fi
  firewall-cmd --permanent --zone="$ZONE" --remove-rich-rule="$r" >/dev/null || warn "could not remove old rule: $r"
done < <(firewall-cmd --permanent --zone="$ZONE" --list-rich-rules)
bash "$ETC/firewalld.sh"
ok "rich rules applied in zone $ZONE: $(firewall-cmd --zone="$ZONE" --list-rich-rules | grep -c 'port="445"')"

say "Container units"
install -m 0644 "$ETC"/quadlet/*.container /etc/containers/systemd/
if podman image exists "$IMAGE"; then note "image $IMAGE present locally"; else podman pull "$IMAGE" >/dev/null; fi
systemctl daemon-reload
systemctl restart cmmc-smb.service
[ -f /etc/containers/systemd/cmmc-smb-legacy.container ] && systemctl restart cmmc-smb-legacy.service
sleep 2
systemctl is-active --quiet cmmc-smb.service || fail "cmmc-smb.service did not start — journalctl -u cmmc-smb"
ok "cmmc-smb running ($(podman inspect -f '{{.ImageDigest}}' cmmc-smb 2>/dev/null || echo digest n/a))"
podman inspect -f '{{.ImageDigest}}' cmmc-smb > "$ETC/image.digest" 2>/dev/null || true

say "Antivirus"
# Intake scans before filing; the enclave refuses FB_CMMC_SMB=required
# without FB_CMMC_AV=required. If nothing answers on 3310, bring up the
# bundled container (unless --no-clamav).
AV_ADDR="$(grep -E '^FB_CMMC_AV_ADDR=' "$ENV_FILE" 2>/dev/null | cut -d= -f2)"; AV_ADDR="${AV_ADDR:-tcp://127.0.0.1:3310}"
hp="${AV_ADDR#tcp://}"; av_host="${hp%%:*}"; av_port="${hp##*:}"
if (exec 3<>"/dev/tcp/$av_host/$av_port") 2>/dev/null; then
  ok "scanner answers on $AV_ADDR"
elif [ "$NO_CLAMAV" -eq 1 ]; then
  warn "nothing answers on $AV_ADDR and --no-clamav given — the enclave will refuse to start until a scanner is reachable"
else
  bash "$HERE/../clamav/install-clamav-container.sh" --images-dir "$IMAGES_DIR"
fi
AV_KV=("FB_CMMC_AV=required" "FB_CMMC_AV_ADDR=$AV_ADDR")

say "Apply-on-change"
# The web UI edits cells.yaml as the unprivileged service user; this
# root-owned path unit re-runs the installer (render, rules, container)
# whenever the file changes, so the UI never needs podman or firewalld.
# The flags used for this run are recorded so the re-run needs none.
cat > "$ETC/apply.env" <<EOF
OT_IP=$OT_IP
OT_IF=$OT_IF
OT_VLAN=$OT_VLAN
LEGACY_IP=$LEGACY_IP
IMAGE=$IMAGE
NO_CLAMAV=$NO_CLAMAV
INSTALL_SMB=$(readlink -f "$0")
EOF
chmod 0640 "$ETC/apply.env"
cat > "$ETC/apply.sh" <<'SCRIPT'
#!/usr/bin/env bash
# Re-runs install-smb.sh with the flags recorded at install time.
# Invoked by cmmc-smb-apply.service whenever cells.yaml changes.
set -euo pipefail
. /etc/cmmc-smb/apply.env
args=(--ot-ip "$OT_IP")
[ -n "${OT_IF:-}" ] && args+=(--ot-interface "$OT_IF")
[ -n "${OT_VLAN:-}" ] && args+=(--ot-vlan "$OT_VLAN")
[ -n "${LEGACY_IP:-}" ] && args+=(--legacy-ip "$LEGACY_IP")
[ -n "${IMAGE:-}" ] && args+=(--image "$IMAGE")
[ "${NO_CLAMAV:-0}" = 1 ] && args+=(--no-clamav)
exec bash "$INSTALL_SMB" "${args[@]}"
SCRIPT
chmod 0750 "$ETC/apply.sh"
cat > /etc/systemd/system/cmmc-smb-apply.service <<'UNIT'
[Unit]
Description=Open-CMMC shop-floor: re-render Samba after an inventory change
After=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/cmmc-smb/apply.sh
UNIT
cat > /etc/systemd/system/cmmc-smb-apply.path <<'UNIT'
[Unit]
Description=Open-CMMC shop-floor: watch the inventory for changes
[Path]
PathChanged=/etc/cmmc-smb/cells.yaml
Unit=cmmc-smb-apply.service
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now cmmc-smb-apply.path >/dev/null 2>&1
ok "cmmc-smb-apply.path watches $CELLS"

say "Enclave unit drop-in"
# The service runs under ProtectSystem=strict (/etc read-only). The web
# UI rewrites the inventory, so grant write access to that one file.
install -d /etc/systemd/system/cmmc-filebrowser.service.d
cat > /etc/systemd/system/cmmc-filebrowser.service.d/50-shopfloor.conf <<UNIT
# Installed by config/smb/install-smb.sh — Settings → Shop floor edits the inventory.
[Service]
ReadWritePaths=$CELLS
UNIT
systemctl daemon-reload
ok "cmmc-filebrowser may write $CELLS"

say "Enclave env"
touch "$ENV_FILE"
for kv in "FB_CMMC_SMB=required" "FB_CMMC_SMB_ROOT=$OT_ROOT" "FB_CMMC_SMB_CELLS=$CELLS" "${AV_KV[@]}"; do
  k="${kv%%=*}"
  if grep -q "^$k=" "$ENV_FILE"; then
    sed -i "s|^$k=.*|$kv|" "$ENV_FILE"
  else
    echo "$kv" >> "$ENV_FILE"
  fi
done
ok "$ENV_FILE updated — restart cmmc-filebrowser.service to enable release/intake"
[ "$ALIAS" -eq 1 ] && note "alias mode: the OT address shares the LAN NIC — no physical separation; say so in the SSP (3.13.1/3.13.5)"

say "Next steps"
note "1. systemctl restart cmmc-filebrowser.service"
note "2. for each machine:  $BIN useradd <machine>   (prints the controller setup card; password shown once)"
note "3. $BIN ssp-table --cells $CELLS --image $IMAGE  >> your SSP evidence"
note "4. for every smb2/smb1 cell: file the PDS checklist photos (scope § 5.2)"
