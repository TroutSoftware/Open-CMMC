# Day-2 operations

Everything after the install works. Written for a small IT team that
runs this appliance alongside everything else they do, not for a
dedicated operator.

Install and first-boot: [`almalinux9-setup.md`](./almalinux9-setup.md).
Backup and restore: [`backup-restore.md`](./backup-restore.md).

---

## The short version

| Task | Command | Cadence |
|---|---|---|
| Health check | `sudo config/install.sh status` | weekly |
| Backup | `sudo config/install.sh backup <dir>` | per your SSP; weekly is typical |
| Restore drill | see backup-restore.md | annually, and after any key change |
| Upgrade | see below | per release |
| Add a user | Keycloak admin console | as needed |
| Remove a user | Keycloak admin console, then verify | same day as departure |
| Audit review | Wazuh dashboard, or per-user activity view | per your SSP |

---

## Adding a user

Users live in Keycloak, not in Open-CMMC. Open-CMMC reads group
membership from the OIDC token on every request.

1. Keycloak admin console → Users → Add user. Set username and email,
   leave **Email verified** on.
2. Credentials → set a temporary password, **Temporary = On**.
3. Required user actions: `Update Password` and `Configure OTP`.
4. Groups → join one of: `engineering`, `operations`, `management`,
   `sales`, `compliance`, `filebrowser-admins`.

Group membership determines which cabinet drawers they see — the
mapping is in `cmmc/cabinet` (`DefaultLayout`) and is applied by
`cmmc/authz/folderacl`. A user in `engineering` sees `Engineering` and
`Engineering_CUI`; `filebrowser-admins` sees everything.

The user enrolls TOTP on first login. Security keys (FIDO2) are a peer
factor they can add from the Account Console once you have a DNS name —
see [`operator-2fa.md`](./operator-2fa.md).

## Removing a user

Departures are the access-control event most likely to be audited, so
do all three steps and record the date.

1. Keycloak → Users → **Disable** (do not delete — deleting loses the
   audit linkage from their past events to a named identity).
2. Sessions → sign out all sessions for that user.
3. Confirm: their next request fails authentication. Open-CMMC sessions
   are 15 min idle / 8 h absolute, so an already-issued session can
   survive up to 8 hours — step 2 is what closes that window, not
   step 1.

If the departure is not amicable, also rotate anything they held:
Keycloak admin credentials, and the appliance SSH keys.

---

## Upgrading

`install.sh deploy` is idempotent, so an upgrade is a redeploy against
the new release. It never overwrites `/etc/cmmc-filebrowser/environment`,
so your keys and OIDC secret survive.

```bash
# 1. Back up first. Always.
sudo config/install.sh backup /mnt/removable/pre-upgrade-$(date +%F)

# 2. Redeploy from the new release tarball. Pass the same identity flag
#    you used originally — preflight requires one, and on an upgrade the
#    accounts already exist, so this is a no-op either way.
sudo FB_ADMIN_USER=<your-admin> config/install.sh deploy \
  --from-release ./cmmc-filebrowser-<version>-linux-amd64.tar.gz

# 3. Verify.
sudo config/install.sh status
```

Check the release notes for any migration step. There is no automatic
schema migration between versions today — if a release needs one it
will say so explicitly.

**Roll back** by restoring the pre-upgrade backup. This is the reason
step 1 is not optional.

---

## Health and monitoring

`install.sh status` reports systemd unit state for `cmmc-filebrowser`,
`cmmc-keycloak`, and the Wazuh bundle if installed.

Worth watching beyond that:

- **Disk on the cabinet volume.** A full cabinet volume fails uploads.
- **Audit chain continuity.** Wazuh rule 200050 alerts on a chain break.
  Expected breaks: after a restore, and across an HKDF split boundary.
  Anything else is worth investigating —
  [`wazuh-integration.md`](./wazuh-integration.md) has the triage steps.
- **Certificate expiry.** The installer's self-signed CA and server cert
  are not auto-renewed. If you supplied your own certs with
  `--tls-cert` / `--tls-key`, renewal is on your normal PKI cadence.
- **ClamAV signature freshness.** Stale signatures mean uploads are
  scanned against an old definition set.

---

## Antivirus

`install.sh deploy` provisions ClamAV: it installs `clamd`, fetches the
signature database, starts `clamd@scan` on `127.0.0.1:3310`, enables
`clamav-freshclam` for updates, and writes `FB_CMMC_AV=required`.

`required` is **fail-closed**, which has two consequences worth knowing
before you meet them at 2am:

- An upload whose scan cannot complete gets a **503**, not a stored
  file. A sick clamd stops uploads rather than silently accepting
  unscanned bytes.
- **filebrowser refuses to start** if `FB_CMMC_AV=required` and no
  scanner can be attached. That is deliberate — booting into a state
  that logs "scanning enabled" while scanning nothing is the failure
  this design exists to prevent.

Check posture at any time:

```bash
sudo config/install.sh status
```

The antivirus block reports the configured mode, whether clamd is
answering, and signature age (flagged stale past 7 days).

### When scanning is not active

If the installer could not reach package repos or fetch signatures, it
falls back to `FB_CMMC_AV=optional` and says so loudly rather than
leaving you with an appliance that will not boot. Uploads work; they are
not scanned. Fix the cause, then:

```bash
sudo config/install.sh enable-av
```

That re-runs provisioning, flips the env file to `required`, and
restarts the service. It refuses to change anything if clamd still is
not healthy.

### Air-gapped sites

`freshclam` needs egress. Point `/etc/freshclam.conf` at an internal
mirror (`DatabaseMirror <your-host>`), run `freshclam` once by hand, then
`enable-av`. Keep the mirror current — stale signatures are a 3.14.4
finding, and `status` will flag them.

### Running AV at another layer

If you already scan at the filesystem or endpoint layer, deploy with
`--no-clamav`. That sets `FB_CMMC_AV=disabled` and leaves 3.14.2 and
3.14.5 for your SSP to cover with the compensating control.

### Periodic re-scan

Scan-on-upload is real-time only. Nothing re-scans files already at
rest, which matters when a signature update would newly detect
something stored earlier. Add a host-level scheduled scan:

```bash
# /etc/cron.weekly/cmmc-rescan
clamdscan --fdpass --quiet /srv/cmmc-filebrowser/files || \
  logger -t cmmc-rescan "clamdscan reported detections"
```

Note this scans ciphertext-at-rest only if envelope encryption is off;
with encryption on, the durable files are AES-GCM sealed and a host
scanner cannot read them. In that deployment the upload-time scan is
the control, and the re-scan gap is an SSP statement rather than a cron
job.

---

## Audit review

Two surfaces:

- **Per-user activity view** in the Open-CMMC UI — every CUI mark
  change, preview, download, and admin action, stamped with a
  correlation id. Good for answering "what did this person touch."
- **Wazuh dashboard** (if deployed with `--with-wazuh`) — aggregate
  review, alerting, and retention. Good for "what happened this month."

Shops on Splunk, Sentinel, or Elastic forward via rsyslog-ossl instead —
see [`audit-forwarder.md`](./audit-forwarder.md).

Your SSP names the review cadence and who performs it. The product does
not enforce one.

---

## Things that are not automated

Worth knowing before you plan around them:

- **KEK rotation.** No supported procedure on a populated cabinet.
- **Periodic re-scan of at-rest files.** Upload-time scanning only — see the antivirus section above.
- **Certificate renewal.** Manual.
- **Schema migration between versions.** Manual when required.
- **Realm backup outside `install.sh backup`.** If you manage Keycloak
  yourself, include `kc.sh export` in your own runbook.
- **Log retention/pruning on the appliance.** Retention is enforced
  wherever you forward audit events, not locally.
