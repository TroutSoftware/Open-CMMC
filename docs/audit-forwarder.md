# CMMC audit forwarder — rsyslog-ossl → SIEM

The canonical audit pipeline for a CMMC-Filebrowser deployment is:

```
filebrowser-fips  ──stdout──▶ systemd / journald ──imjournal──▶ rsyslog-ossl ──mTLS──▶ customer SIEM
     (JSON events)                (WORM spool)           (FIPS-validated OpenSSL)     (Splunk / Sentinel / Elastic)
```

This document covers the rsyslog leg — installing the drop-in,
configuring TLS, testing it, and integrating with each of the three
common SIEM targets. The choice of rsyslog-ossl (rather than Vector
or Fluent Bit) is documented in `architecture.md` §7; short version:
rsyslog linked to RHEL's OpenSSL is the only option in 2026 that
inherits a FIPS 140-3 validated module on RHEL 9 — the others either
have no FIPS story, a partial one, or ship a separate paid agent.

Controls satisfied by this pipeline:
- 3.3.1 create/retain audit records
- 3.3.2 traceability to user (`user_id` + `correlation_id` in payload)
- 3.3.4 alert on audit-logging failure (disk queue + SIEM-side
  heartbeat)
- 3.3.5 correlate across components (`correlation_id` preserved
  end-to-end via HTTP header + context + audit event + syslog MSG)
- 3.3.8 protect audit info in transit (mTLS + FIPS ciphers)
- 3.13.8 crypto for CUI-adjacent data in transit

---

## Files in this repository

| Path | Purpose |
|---|---|
| `config/systemd/cmmc-filebrowser.service` | Hardened systemd unit — runs filebrowser-fips with stdout → journald under SyslogIdentifier `cmmc-filebrowser` |
| `config/rsyslog/50-cmmc-filebrowser.conf` | rsyslog drop-in — picks up the journald stream, parses JSON, forwards over mTLS |
| `docs/audit-forwarder.md` | This document |

---

## Prerequisites

1. RHEL 9 (or Rocky / Alma 9) with FIPS mode enabled: `fips-mode-setup --check` returns `FIPS mode is enabled`.
2. Full `rsyslog` package set. Base + `mmjsonparse` are BOTH required — the latter is a separate sub-package on RHEL 9, commonly missed:
   ```bash
   sudo dnf install -y rsyslog rsyslog-openssl rsyslog-mmjsonparse
   ```
3. systemd-journald configured for persistence AND high-throughput audit. Defaults drop bursts via per-service rate-limiting; we need that off for the audit stream:
   ```bash
   sudo mkdir -p /var/log/journal
   sudo install -d -m 0755 /var/lib/rsyslog
   sudo tee /etc/systemd/journald.conf.d/10-cmmc.conf <<'EOF'
   [Journal]
   Storage=persistent
   SystemMaxUse=10G
   SystemKeepFree=5G
   MaxRetentionSec=14day
   RateLimitIntervalSec=0
   RateLimitBurst=0
   EOF
   sudo systemctl restart systemd-journald
   ```
4. mTLS materials. The SIEM vendor will tell you their CA for peer verification; you generate / request client cert from your CA.
   ```
   /etc/pki/cmmc/ca.pem       # CA that issued the SIEM server cert
   /etc/pki/cmmc/client.pem   # this host's client cert
   /etc/pki/cmmc/client.key   # this host's key (mode 0400, owned by root)
   ```
5. **Dedicated spool** (strongly recommended): `/var/spool/rsyslog` should be on its own mount / LVM volume so that a SIEM outage filling the queue does not take down `/var/log/journal` or filebrowser's `/var/lib/cmmc-filebrowser/filebrowser.db`.
6. SELinux (RHEL default `enforcing`): non-default paths may need `semanage fcontext -a` + `restorecon -Rv`. The three defaults above (`/var/spool/rsyslog`, `/var/log/journal`, `/etc/pki/cmmc`) already have correct contexts out of the box.
7. Firewall: open the outbound port chosen by your SIEM (default `6514/tcp` here) in `firewalld` or your perimeter NGFW.

---

## Install

```bash
# 1. systemd unit
sudo useradd --system --home-dir /var/lib/cmmc-filebrowser --shell /sbin/nologin cmmc-filebrowser
# /var/lib/cmmc-filebrowser is managed by systemd's StateDirectory
# (mode 0750 per the unit) — just pre-create /srv/cmmc-filebrowser/files
# which is the file-tree root.
sudo install -o cmmc-filebrowser -g cmmc-filebrowser -m 0750 -d \
  /srv/cmmc-filebrowser /srv/cmmc-filebrowser/files
sudo install -D -m 0755 filebrowser-fips /usr/local/bin/cmmc-filebrowser
sudo install -m 0644 config/systemd/cmmc-filebrowser.service /etc/systemd/system/
sudo install -m 0640 -o root -g cmmc-filebrowser -D \
  your-env-file /etc/cmmc-filebrowser/environment
sudo systemctl daemon-reload
sudo systemctl enable --now cmmc-filebrowser

# 2. rsyslog drop-in
sudo install -m 0644 config/rsyslog/50-cmmc-filebrowser.conf /etc/rsyslog.d/
sudo rsyslogd -N1                       # syntax-validate; must print OK
sudo systemctl restart rsyslog

# 3. Confirm the journald side is flowing
sudo journalctl -u cmmc-filebrowser -n 20 --output=cat
# Every line should be a JSON object {"ts":..., "event_id":..., ...}
```

---

## Customizing for your SIEM

The shipped drop-in uses literal `⟪ REPLACE ⟫` markers for deployment-specific values — rsyslog does NOT expand message-scoped `set $.var` references in action parameters (they resolve at config-load time, before any message exists). So operators replace the literals directly.

**Recommended**: template the file via Ansible / Terraform / Puppet. A minimal Ansible snippet:

```yaml
- name: CMMC audit forwarder
  template:
    src: 50-cmmc-filebrowser.conf.j2
    dest: /etc/rsyslog.d/50-cmmc-filebrowser.conf
    owner: root
    group: root
    mode: '0644'
  vars:
    siem_host: "{{ cmmc_siem_host }}"
    siem_port: "{{ cmmc_siem_port | default(6514) }}"
    siem_cn:   "{{ cmmc_siem_peer_cn }}"
  notify: restart rsyslog
```

The four values to substitute are the four `⟪ REPLACE ⟫` markers in the shipped conf — `target=`, `port=`, `StreamDriverPermittedPeers=`, and optionally the three `streamdriver.*File=` paths if you prefer non-default PKI locations.

### Splunk

- **Preferred**: Splunk Connect for Syslog (SC4S) or the Universal
  Forwarder with RELP. The omfwd config above uses plain TCP+TLS
  which Splunk HEC accepts if you have the syslog technical add-on
  enabled.
- Splunk itself must be running a FIPS 140-3 posture (validated by
  Sept 21 2026 — see `gap-analysis.md` note on `Splunk 140-2 sunset`).
- Source type: set to `cmmc_filebrowser_audit` at the inputs layer.
- A sample Splunk SPL query to stitch a session:
  ```
  index=cmmc sourcetype=cmmc_filebrowser_audit correlation_id="abc..."
    | sort 0 ts | table ts action outcome resource user_id
  ```

### Microsoft Sentinel

- Deploy the Azure Monitor Agent (AMA) on a separate log-collector
  host inside the enclave. AMA pulls from rsyslog via a local RFC5424
  listener, forwards to the Sentinel workspace.
- Data connector: **Syslog via AMA** → Data collection rule targets
  the `cmmc-filebrowser` facility.
- Sentinel KQL:
  ```kql
  Syslog
  | where ProcessName == "cmmc-filebrowser"
  | extend Event = parse_json(SyslogMessage)
  | where Event.outcome == "reject" or Event.action startswith "authz"
  ```

### Elastic (Elastic Agent / Beats)

- Deploy Elastic Agent with the **Custom Logs** integration pointing
  at `/var/log/cmmc-filebrowser-mirror.log` (an additional rsyslog
  action that writes a local mirror) OR the **Syslog** integration
  listening on a local port that rsyslog fans out to.
- In Kibana, create a dataview for `action`, `outcome`,
  `correlation_id`, `user_id`, `mac` so the SIEM-side chain-verify
  dashboard has the right fields.

---

## Verifying the HMAC chain on the SIEM side

Every audit event carries `mac` + `prev_mac`. The Go helper
`audit.VerifyChain(events, key, expectedFirstPrev)` is the reference
implementation. **The normative MAC framing lives in
`cmmc/audit/chain.go::macDigestInput`** — any reimplementation MUST
match it byte-for-byte, otherwise MACs will not verify.

Critical details the framing enforces:

- Events are walked in **emission order**, NOT `ts` order. Two events
  sharing a nanosecond timestamp (which does happen under load) must
  be kept in the order the chain emitter produced them; sorting by
  `ts` and then verifying will produce false breaks.
- The 13 fields covered by the MAC are: `prev_mac`, `ts` (RFC3339Nano
  UTC, format `"2006-01-02T15:04:05.000000000Z07:00"`), `event_id`,
  `correlation_id`, `user_id`, `username`, `client_ip`, `user_agent`,
  `action`, `resource`, `outcome`, `status` (integer), `latency_ms`
  (integer), `reason`.
- Each field is length-prefixed with its decimal byte length, followed
  by `0x1F` (ASCII Unit Separator), the field value, then another
  `0x1F`. The integer fields are first rendered as decimal strings,
  then length-prefixed the same way.
- `extra` is **not** covered by the MAC (Go's `map[string]interface{}`
  serializes non-deterministically; documented residual in the SSP).

Illustrative pseudocode (consult `chain.go` for the authoritative form):

```
prev = expected_first_prev   # "" for chain genesis, or the last
                             # known good tip on a subsequent run
for i, ev in enumerate(events_in_emission_order):
    if ev.prev_mac != prev:
        raise ChainBreak(index=i, reason="prev_mac mismatch")
    digest = canonical_frame(                 # see chain.go:macDigestInput
        prev, ev.ts, ev.event_id, ev.correlation_id,
        ev.user_id, ev.username, ev.client_ip, ev.user_agent,
        ev.action, ev.resource, ev.outcome,
        str(ev.status), str(ev.latency_ms), ev.reason,
    )
    want = b64url(hmac_sha256(key, digest))
    if ev.mac != want:
        raise ChainBreak(index=i, reason="mac mismatch")
    prev = ev.mac
```

Run this on the SIEM side daily (or continuously) and alert on any
break — this is how 3.3.8 tamper-detection is actually enforced,
beyond the filesystem-level `chattr +a` that a root actor could
bypass.

**Key rotation**: the HMAC key is the same `settings.Key` that signs
session JWTs (auto-generated 64-byte value at `filebrowser config init`).
Rotation breaks the chain across the rotation boundary — SIEM-side
verification logic should accept a list of valid keys and attempt each
in turn, so rotation produces a single expected break with a
operator-recorded annotation rather than an incident. A dedicated TPM-
sealed key + rotation procedure is tracked as a v1.1 deferral.

---

## Testing locally (without a real SIEM)

Option A — point the forwarder at a local netcat listener and
observe the raw wire format (dev-only, no TLS):

```bash
# Terminal 1: listen
sudo nc -lk 6515

# Terminal 2: deploy a no-TLS test drop-in
cat >/tmp/99-test-forward.conf <<'EOF'
module(load="imjournal" StateFile="imj-test.state")
module(load="mmjsonparse")
module(load="omfwd")
if ($programname == "cmmc-filebrowser") then {
    action(type="mmjsonparse" cookie="")
    action(type="omfwd" target="127.0.0.1" port="6515" protocol="tcp" template="RSYSLOG_ForwardFormat")
    stop
}
EOF
sudo install -m 0644 /tmp/99-test-forward.conf /etc/rsyslog.d/
sudo systemctl restart rsyslog

# Terminal 3: provoke an audit event
curl -s -o /dev/null -X POST http://localhost:8080/api/users  # 401 → authz.priv.reject

# Terminal 1 should now show the syslog line with embedded JSON.
# When done:
sudo rm /etc/rsyslog.d/99-test-forward.conf && sudo systemctl restart rsyslog
```

Option B — use an `omfile` action that writes to a local file so you
can diff the stdout JSON stream against what rsyslog forwarded:

```
action(type="omfile" file="/var/log/cmmc-filebrowser-mirror.jsonl" template="CMMCJSON")
```

---

## Scaling the queue

Audit event volume scales roughly linearly with active-user count
because every `file.read` (directory listing, file metadata) emits
an event. Rough capacity planning for a busy-hours steady state at
~1 KB/event on the wire:

| Users | Events/min (avg) | Recommended `queue.size` | `queue.maxDiskSpace` | Approx buffer @ SIEM outage |
|---|---|---|---|---|
| 10 | ~300 | 100000 (default) | 1g (default) | ~55 min |
| 100 | ~3,000 | 200000 | 4g | ~22 min |
| 1000 | ~30,000 | 1000000 | 20g | ~11 min |
| 5000 | ~150,000 | 5000000 | 100g | ~11 min |

Rough guidance: aim for enough buffer to survive a planned SIEM
maintenance window (typically 30–60 min) plus one half-hour of
unplanned outage. If a larger buffer is needed, favor a **dedicated
spool mount** (see Prerequisites §5) so queue growth cannot evict
the local journal or the filebrowser database.

## First-boot posture — avoid the empty-admin trap

Upstream filebrowser's "quick setup" path creates an admin user with
an empty password if no DB exists at startup. Under this fork's
`AuthMethod=oidc` deployment profile you MUST run `config init` +
`config set` BEFORE the systemd unit starts for the first time, or
run those steps as an `ExecStartPre` baked into a site-local drop-in:

```bash
sudo -u cmmc-filebrowser /usr/local/bin/cmmc-filebrowser config init \
    --database /var/lib/cmmc-filebrowser/filebrowser.db
sudo -u cmmc-filebrowser /usr/local/bin/cmmc-filebrowser config set \
    --auth.method=oidc \
    --database /var/lib/cmmc-filebrowser/filebrowser.db
```

Only then: `sudo systemctl enable --now cmmc-filebrowser`. This is a
CMMC 3.5.7 sharp edge — empty-password admin on first boot would be
an immediate finding.

## Verifying the running process is actually in FIPS mode

Build-time `GOFIPS140=v1.0.0` and env `GODEBUG=fips140=on` are
complementary. Assessors often ask for live evidence:

```bash
# 1. Process environment shows GODEBUG=fips140=on.
sudo tr '\0' '\n' < /proc/$(pgrep -f cmmc-filebrowser)/environ | grep fips

# 2. The binary was linked against the FIPS-validated OpenSSL module.
ldd /usr/local/bin/cmmc-filebrowser | grep -iE 'libcrypto|libssl'
# expect libcrypto.so.3 from /usr/lib64/

# 3. Host itself is in FIPS mode.
fips-mode-setup --check
```

## Failure modes + alerting

| Failure | Detection | Response |
|---|---|---|
| rsyslog down | journald accumulates; `systemctl status rsyslog` red | restart + page on-call |
| SIEM unreachable | rsyslog queue grows; disk spool fills; alert on queue-full | investigate SIEM / network; queue protects up to `queue.maxDiskSpace` |
| Chain break detected | SIEM-side verifier flags the break index + reason | incident response — suspect tamper or unexpected log gap |
| filebrowser not emitting | journald has no `cmmc-filebrowser` entries; SIEM silence | check `/var/log/messages` for systemd restart loops; verify `GODEBUG` env wasn't dropped |

---

## Known limitations (carried from `NOTES-for-documentation.md`)

- `extra` field is not covered by the HMAC chain — only the 13
  controlled fields. Document this explicitly in your SSP as a
  residual risk.
- This forwarder targets RHEL 9 + rsyslog-openssl specifically. On
  Ubuntu, Chainguard's `fluent-bit-fips` image is the sibling path;
  see `NOTES-for-documentation.md` for which platform gets which
  agent.
