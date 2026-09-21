#!/usr/bin/env bash
# install-clamav-container.sh — ClamAV as a podman container on loopback
#
# For hosts that cannot install the clamav OS package (expired
# subscription, air-gap, arm64). Same result for the enclave: clamd
# answering on tcp://127.0.0.1:3310, FB_CMMC_AV=required.
#
#   sudo config/clamav/install-clamav-container.sh [--image REF] [--images-dir DIR]
#
# Image resolution: --image if given; else images/cmmc-clamd.tar from the
# release (podman load); else build from config/clamav/Containerfile.
# Idempotent. Signatures live in the named volume cmmc-clamd-db and are
# refreshed by a systemd timer (cmmc-clamd-freshclam.timer, daily).
set -euo pipefail
say() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()  { printf '    \033[1;32mok\033[0m %s\n' "$*"; }
note(){ printf '    %s\n' "$*"; }
fail(){ printf '    \033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE=""; IMAGES_DIR="$HERE/../../images"
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --images-dir) IMAGES_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) fail "unknown flag: $1" ;;
  esac
done
[ "$(id -u)" -eq 0 ] || fail "run as root"
command -v podman >/dev/null || fail "podman required"
ETC=/etc/cmmc-clamav
install -d -m 0755 "$ETC"
install -m 0644 "$HERE/clamd.conf" "$HERE/freshclam.conf" "$ETC/"

say "ClamAV image"
if [ -z "$IMAGE" ]; then
  IMAGE="localhost/cmmc-clamd:bundled"
  if [ -f "$IMAGES_DIR/cmmc-clamd.tar" ]; then
    podman load -q -i "$IMAGES_DIR/cmmc-clamd.tar" >/dev/null; ok "loaded from $IMAGES_DIR/cmmc-clamd.tar"
  elif ! podman image exists "$IMAGE"; then
    podman build -q -t "$IMAGE" -f "$HERE/Containerfile" "$HERE" >/dev/null; ok "built from $HERE/Containerfile"
  else
    note "image $IMAGE present"
  fi
fi

say "Signatures"
if ! podman volume exists cmmc-clamd-db || ! podman run --rm -v cmmc-clamd-db:/var/lib/clamav "$IMAGE" test -f /var/lib/clamav/main.cvd; then
  podman run --rm -v cmmc-clamd-db:/var/lib/clamav -v "$ETC/freshclam.conf:/etc/clamav/freshclam.conf:ro,Z" "$IMAGE" freshclam \
    || fail "signature download failed (database.clamav.net rate-limits; retry in an hour or point DatabaseMirror at an internal mirror)"
fi
ok "signatures present in volume cmmc-clamd-db"

say "Unit"
cat > /etc/containers/systemd/cmmc-clamd.container <<UNIT
[Unit]
Description=Open-CMMC ClamAV daemon (container, loopback :3310)
[Container]
Image=$IMAGE
ContainerName=cmmc-clamd
PublishPort=127.0.0.1:3310:3310
Volume=cmmc-clamd-db:/var/lib/clamav
Volume=$ETC/clamd.conf:/etc/clamav/clamd.conf:ro,Z
Volume=$ETC/freshclam.conf:/etc/clamav/freshclam.conf:ro,Z
LogDriver=journald
NoNewPrivileges=true
[Service]
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/cmmc-clamd-freshclam.service <<UNIT
[Unit]
Description=Open-CMMC ClamAV signature refresh (3.14.4)
[Service]
Type=oneshot
ExecStart=/usr/bin/podman run --rm -v cmmc-clamd-db:/var/lib/clamav -v $ETC/freshclam.conf:/etc/clamav/freshclam.conf:ro,Z $IMAGE freshclam
UNIT
cat > /etc/systemd/system/cmmc-clamd-freshclam.timer <<UNIT
[Unit]
Description=Daily ClamAV signature refresh
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl restart cmmc-clamd.service
systemctl enable --now cmmc-clamd-freshclam.timer >/dev/null 2>&1
# clamd loads ~200 MB of signatures before it listens; allow two minutes.
for i in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/3310) 2>/dev/null && break; sleep 2; done
(exec 3<>/dev/tcp/127.0.0.1/3310) 2>/dev/null || fail "clamd did not answer on 127.0.0.1:3310 within 2 min — podman logs cmmc-clamd"
ok "clamd listening on 127.0.0.1:3310; timer cmmc-clamd-freshclam refreshes signatures daily"
note "enclave env: FB_CMMC_AV=required  FB_CMMC_AV_ADDR=tcp://127.0.0.1:3310"
