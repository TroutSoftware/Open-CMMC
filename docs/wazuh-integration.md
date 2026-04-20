# Wazuh integration

Wazuh is the default recommended SIEM + endpoint-monitoring stack for
filebrowser-cmmc. It's open source, ships a FIPS-compatible agent for
Windows / Linux / macOS, and gives a CMMC-opinionated shop a single
pane of glass over:

- filebrowser-cmmc audit chain (CMMC 3.3.1 / 3.3.8)
- Keycloak authentication events (3.5.3)
- Endpoint agents on operator workstations (3.14.2 / 3.14.4 / 3.14.5)
- File integrity monitoring on the appliance host (3.4.1 / 3.4.3)
- Rootcheck / vulnerability scans

rsyslog-ossl is still supported as a peer for customers whose SIEM
is already Splunk / Sentinel / Elastic — see
[audit-forwarder.md](./audit-forwarder.md). Wazuh and rsyslog can
run side-by-side; the filebrowser agent-side wiring is independent
of the audit forwarder.

## Deployment shapes

### (a) Agent-only — customer runs their own Wazuh manager

The common case for shops that already operate a Wazuh deployment.

1. On the filebrowser host, install the Wazuh agent:

   ```bash
   # RHEL / AlmaLinux 9
   sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
   sudo dnf install https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm
   ```

2. Point the agent at the manager:

   ```bash
   sudo WAZUH_MANAGER="wazuh.customer.internal" \
     WAZUH_REGISTRATION_SERVER="wazuh.customer.internal" \
     /var/ossec/bin/agent-auth -m wazuh.customer.internal
   ```

3. Merge the filebrowser agent fragment into the agent config:

   ```bash
   sudo tee -a /var/ossec/etc/ossec.conf \
     < config/wazuh/ossec-agent.fragment.conf
   sudo systemctl enable --now wazuh-agent
   ```

4. On the manager, install the CMMC decoder + rules:

   ```bash
   sudo install -m 0644 config/wazuh/decoders/filebrowser-cmmc.xml \
     /var/ossec/etc/decoders/
   sudo install -m 0644 config/wazuh/rules/filebrowser-cmmc.xml \
     /var/ossec/etc/rules/
   sudo systemctl restart wazuh-manager
   ```

### (b) Bundled — appliance ships its own Wazuh stack

Opt-in turn-key install for shops without existing SIEM infrastructure.

```bash
# Compose the filebrowser appliance with the Wazuh bundle.
podman-compose \
  -f compose.yaml \
  -f config/wazuh/podman-compose.wazuh.yml \
  up -d

# First-boot: change the indexer admin password. The bundle ships
# with "CHANGE_ME_BEFORE_BOOT" so a forgotten deployment fails
# loud instead of exposing the default credential.
podman exec -it wazuh-indexer \
  /usr/share/wazuh-indexer/bin/opensearch-security/wazuh-passwords-tool.sh \
  -a -au admin -ac CHANGE_ME_BEFORE_BOOT -n cmmc-cluster
```

Dashboard lands on `https://<host>:5601`. First-login credentials
match the indexer admin. Front it with the Trout Access Gate / a
reverse proxy if you want TLS on 443 (same host as filebrowser
can't bind both).

### (c) Disabled

Customers who decline the Wazuh integration entirely (rsyslog-only)
set no Wazuh agent and skip this directory — nothing in the
filebrowser boot path depends on Wazuh being present.

## Event flow

```
filebrowser-cmmc ─stdout(json)─▶ journald ─▶ wazuh-agent ─TLS/1514─▶ wazuh-manager
                                                                         │
keycloak (conmon) ─stdout(json)─▶ journald ─▶ wazuh-agent ──┘            │
                                                                         │
endpoint (win/linux/mac) ───────── wazuh-agent ─TLS/1514 ────────────────┤
                                                                         │
                                                           wazuh-indexer │
                                                                         │
                                                          wazuh-dashboard
```

## Rule coverage

The shipped rule file covers 22 CMMC-relevant event types across 9
categories. Severity mapping + control anchors in the file's header
comment; summary:

| Category | Rule IDs | Peak severity | Controls |
|---|---|---|---|
| Authentication | 200010–200017 | 12 (brute-force) | 3.5.3 / 3.1.8 / 3.1.11 |
| CUI handling | 200030–200034 | 12 (mark orphan) | 3.8.3 / 3.8.4 / 3.1.3 |
| Malware scan | 200040–200041 | 12 (detection) | 3.14.2 / 3.14.5 |
| Audit integrity | 200050 | 14 (chain break) | 3.3.8 |
| Public share | 200060–200062 | 12 (token brute) | 3.1.22 / 3.13.4 |
| Administrative | 200070–200073 | 8 (settings edit) | 3.1.5 / 3.1.7 / 3.4.5 |

A chain-break at level 14 is the loudest event we emit. A Wazuh
dashboard alert on any level-12+ rule is the recommended pager wire.

## FIPS posture

The Wazuh agent's built-in TLS stack uses the host's OpenSSL. On a
`fips-mode-setup --enable` host, the agent inherits the FIPS-validated
OpenSSL cert (the same cert filebrowser-cmmc inherits — see
[architecture.md §4](./architecture.md)). No separate Wazuh-side
validation needed.

The bundled manager + indexer images are upstream Wazuh builds. If
FIPS validation of the manager itself is required (usually it is not —
the manager receives events from FIPS-compliant agents and stores
them, it is not part of the CUI confidentiality boundary), a customer
can rebuild against a RHEL / Alma base using the Dockerfile in the
upstream wazuh-docker repo.

## Endpoint agents

See [wazuh-endpoint-agents.md](./wazuh-endpoint-agents.md) for the
per-OS install + CMMC-opinionated config for operator workstations.
Agent streams to the same manager as the appliance; a single dashboard
covers server + endpoints.

## Troubleshooting

- **Agent not connecting to manager.** Check `systemctl status wazuh-agent` on the host and `tail /var/ossec/logs/ossec.log`. The most common failure is firewall: port 1514/tcp must be open from agent → manager.
- **No filebrowser events appearing in dashboard.** Confirm (1) filebrowser-cmmc is emitting JSON (tail `/tmp/fb-fips.log` or journald — one line per event), (2) the agent's journald reader is active (`/var/ossec/logs/ossec.log` shows `journald: reading`), (3) decoder loaded (`/var/ossec/bin/wazuh-logtest` → paste one of our JSON lines → expect `decoder: 'filebrowser-cmmc'`).
- **Rules fire but with wrong severity.** Your local rules file takes precedence over the one shipped here. Check `/var/ossec/etc/rules/local_rules.xml` for an overriding rule on the same ID range.
- **Chain break alert (200050) with no actual tamper.** Confirm you upgraded across the H2 HKDF split boundary — the first event after upgrade starts a new chain; the SIEM-saved tip from before the boundary won't match. This is a one-time expected break; recheck after a second event cycles in.
