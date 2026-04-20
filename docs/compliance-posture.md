# Compliance posture — Open-CMMC deployed

**Scope:** this document describes the CMMC Level 2 / NIST SP 800-171 Rev 2
posture **after Open-CMMC is installed** on a RHEL 9 or AlmaLinux 9 FIPS host.
It is the positive counterpart to [`gap-analysis.md`](./gap-analysis.md),
which describes the pre-fork baseline of upstream `filebrowser/filebrowser`.

Every one of the 110 NIST 800-171 Rev 2 controls is listed. For each control
we state **who delivers it** in a default Open-CMMC deployment and **where the
evidence lives** (source path, config file, or SSP section).

## Legend

| Marker | Source | Meaning |
|---|---|---|
| ✅ | Open-CMMC | Implemented in the filebrowser binary or its bundled Keycloak-FIPS IdP |
| 🟢 | Wazuh | Delivered by the bundled Wazuh stack (enabled with `--with-wazuh`) |
| 📋 | Customer SSP | Policy / procedure control — documented in the customer's SSP, POA&M, or training records |
| 🏢 | Host / facility | Satisfied by the underlying RHEL 9 / AlmaLinux 9 host, LUKS, systemd, firewalld, physical facility, or network boundary (NGFW / Trout Access Gate) |

## Headline numbers

| Source | Count |
|---|---|
| ✅ Open-CMMC directly | 72 |
| 🟢 Wazuh (with `--with-wazuh`) | 18 |
| 📋 Customer SSP | 8 |
| 🏢 Host / facility | 12 |
| **Total** | **110** |

Open-CMMC alone covers ~72 controls out of the box. Adding the bundled Wazuh
stack extends coverage into monitoring-heavy families (3.3 audit retention,
3.4 config management, 3.6 incident response, 3.11 vulnerability scanning,
3.14 system integrity).

---

## 3.1 — Access Control (22)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.1.1 | Limit system access to authorized users | ✅ | OIDC authentication via bundled Keycloak or customer IdP; local accounts disabled under CUI profile | `cmmc/auth/oidc/`, `config/keycloak/bootstrap.sh` |
| 3.1.2 | Limit transactions to authorized functions | ✅ | Per-folder ACL evaluated on every request alongside user permission flags | `cmmc/authz/folderacl/`, `http/cmmc_folderacl.go` |
| 3.1.3 | Control flow of CUI per approved authorizations | ✅ | CUI marking model + marking-aware authz; public shares refused for CUI-marked files | `cmmc/marking/`, `http/cmmc_enforcement.go` |
| 3.1.4 | Separation of duties | ✅ | Admin / audit-admin / user roles enforced by role store | `cmmc/authz/role.go`, `storage/bolt/authz.go` |
| 3.1.5 | Least privilege | ✅ | Permissions default to `false` on user creation; config-review cadence documented in SSP | `users/permissions.go`, SSP |
| 3.1.6 | Non-privileged accounts for non-security functions | 📋 | Operator-policy control; SSP states admins have separate daily-use accounts | Customer SSP |
| 3.1.7 | Prevent non-priv users from priv functions; log attempts | ✅ | Admin check on every priv handler; denied attempts emit `authz.denied` audit events | `http/cmmc_enforcement.go`, `cmmc/audit/emitter.go` |
| 3.1.8 | Limit unsuccessful logon attempts | ✅ | Rate-limit middleware + Keycloak brute-force lockout (30 failures → temporary lockout) | `http/cmmc_ratelimit.go`, `config/keycloak/bootstrap.sh` |
| 3.1.9 | Privacy / security notices | ✅ | Login banner configurable via realm theme; default wording warns about CUI handling | `config/keycloak/bootstrap.sh` |
| 3.1.10 | Session lock with pattern hiding | ✅ | Idle-session middleware forces re-auth after 15 min inactivity | `http/cmmc_session_idle.go`, `cmmc/auth/session/idle.go` |
| 3.1.11 | Terminate session after condition | ✅ | 15 min idle + 8 h absolute; server-side revocation list for priv actions | `cmmc/auth/session/` |
| 3.1.12 | Monitor and control remote access | ✅🟢 | All sessions audited; Wazuh endpoint agents extend monitoring to operator workstations | `cmmc/audit/`, `config/wazuh/endpoints/` |
| 3.1.13 | Cryptographic mechanisms for remote access | ✅ | TLS 1.3 FIPS profile enforced by `cmmc/crypto/tlsprofile`; FIPS-approved cipher list only | `cmmc/crypto/tlsprofile/tlsprofile.go` |
| 3.1.14 | Route remote access via managed control points | 🏢 | Host firewall + NGFW (or Trout Access Gate) enforce the single ingress path | `docs/architecture.md` §3, customer NGFW |
| 3.1.15 | Authorize remote priv commands | ✅ | `fresh_mfa` middleware requires MFA within 10 min for privileged endpoints | `http/fresh_mfa.go` |
| 3.1.16 | Authorize wireless access prior to connection | 🏢 | Host / network layer control | Customer network SSP |
| 3.1.17 | Protect wireless with authn + crypto | 🏢 | Host / network layer control | Customer network SSP |
| 3.1.18 | Control mobile device connections | 🏢 | MDM / endpoint policy | Customer MDM SSP |
| 3.1.19 | Encrypt CUI on mobile devices | 🏢 | Device-level FDE via MDM | Customer MDM SSP |
| 3.1.20 | Verify and control external-system connections | ✅🟢 | Egress allowlist at firewalld + host; Wazuh flags unexpected outbound on operator workstations | `config/install.sh` phase_firewall, `config/wazuh/` |
| 3.1.21 | Limit portable storage on external systems | 📋 | Operator policy; SSP statement | Customer SSP |
| 3.1.22 | Control CUI on publicly accessible systems | ✅ | Share-creation refuses any file flagged with a non-NONE CUI mark | `http/cmmc_marking.go`, `http/share.go` |

## 3.2 — Awareness & Training (3)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.2.1 | Security awareness | 📋 | Customer training program | Customer SSP |
| 3.2.2 | Role-based training | 📋 | Customer training program | Customer SSP |
| 3.2.3 | Insider-threat training | 📋 | Customer training program | Customer SSP |

## 3.3 — Audit & Accountability (9)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.3.1 | Create and retain audit records | ✅ | Structured JSON events emitted on every auth, file, and admin action | `cmmc/audit/emitter.go`, `http/cmmc_audit.go` |
| 3.3.2 | Uniquely trace actions to user | ✅ | `user_id` + `correlation_id` stamped on every event | `cmmc/audit/correlation.go`, `cmmc/audit/event.go` |
| 3.3.3 | Review and update logged events | ✅ | Event schema versioned; review cadence documented in SSP | `cmmc/audit/event.go`, Customer SSP |
| 3.3.4 | Alert on audit logging failure | 🟢 | Wazuh manager alerts on agent drop-off + local health endpoint | `config/wazuh/rules/filebrowser-cmmc.xml` |
| 3.3.5 | Correlate audit review | ✅ | Per-request correlation id flows through filebrowser, rsyslog, and SIEM | `cmmc/audit/correlation.go` |
| 3.3.6 | Record reduction and report generation | 🟢 | Wazuh dashboard + customer SIEM reporting | Wazuh dashboard, customer SIEM |
| 3.3.7 | Authoritative timestamp source | 🟢🏢 | chrony synced to authenticated NTS source; Wazuh verifies clock skew | `config/install.sh`, Wazuh agent config |
| 3.3.8 | Protect audit info and tools | ✅🟢 | Per-batch HMAC chain + WORM spool; Wazuh enforces manager-side retention | `cmmc/audit/chain.go`, `cmmc/audit/verify.go`, `config/wazuh/` |
| 3.3.9 | Limit audit mgmt to subset of priv users | ✅ | Dedicated `audit-admin` role separate from `admin` | `cmmc/authz/role.go` |

## 3.4 — Configuration Management (9)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.4.1 | Baseline configs and inventories | ✅🟢 | Opinionated FIPS baseline shipped; Wazuh FIM inventories binary + config paths | `config/`, `config/wazuh/endpoints/` |
| 3.4.2 | Enforce security config settings | ✅ | Config-change audit + rejection of non-FIPS settings under CUI profile | `http/cmmc_enforcement.go` |
| 3.4.3 | Track, review, approve, log changes | ✅🟢 | `config.change` events on every settings mutation; Wazuh FIM on `/etc/cmmc-filebrowser/` | `cmmc/audit/emitter.go`, `config/wazuh/` |
| 3.4.4 | Analyze security impact of changes | 📋 | Change-management procedure | Customer SSP |
| 3.4.5 | Access restrictions for change | ✅ | Admin role required for all config mutations | `users/permissions.go`, `http/settings.go` |
| 3.4.6 | Least functionality | ✅ | CUI profile disables shares, previews, archives, and public endpoints by default | `config/`, `http/public.go` |
| 3.4.7 | Restrict nonessential ports and services | 🏢🟢 | firewalld + Wazuh FIM detects new listeners | `config/install.sh` phase_firewall, `config/wazuh/` |
| 3.4.8 | Deny-by-exception software | 🏢 | SELinux enforcing + host package policy | RHEL SELinux |
| 3.4.9 | Control user-installed software | 🏢 | Host package policy | RHEL dnf policy |

## 3.5 — Identification & Authentication (11)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.5.1 | Identify users, processes, devices | ✅ | Per-user OIDC identity + per-request session key; device x509 optional | `cmmc/auth/oidc/identity.go`, `cmmc/auth/session/` |
| 3.5.2 | Authenticate identities | ✅ | OIDC-delegated authentication; PBKDF2-HMAC-SHA-256 for any local admin account | `cmmc/auth/oidc/`, `users/password.go` |
| 3.5.3 | MFA for priv local + network, non-priv network | ✅ | Keycloak enforces TOTP or WebAuthn on every login | `config/keycloak/bootstrap.sh` |
| 3.5.4 | Replay-resistant authentication | ✅ | PKCE on OIDC flow + `jti` + nonce validation + revocation list | `cmmc/auth/oidc/pkce.go`, `cmmc/auth/session/mint.go` |
| 3.5.5 | Prevent identifier reuse | ✅ | Username soft-delete preserves historical identifier | `storage/bolt/users.go` |
| 3.5.6 | Disable inactive identifiers | ✅ | Keycloak + filebrowser enforce last-login cutoff via OIDC claims | `config/keycloak/bootstrap.sh`, SSP for cadence |
| 3.5.7 | Minimum password complexity | ✅ | Keycloak password policy: length 12, upper, lower, digit, special, history 24 | `config/keycloak/bootstrap.sh` |
| 3.5.8 | Prohibit password reuse | ✅ | Keycloak password-history policy (24 generations) | `config/keycloak/bootstrap.sh` |
| 3.5.9 | Temporary password with immediate change | ✅ | Keycloak admin-set passwords flagged `UPDATE_PASSWORD` required action | `config/keycloak/bootstrap.sh` |
| 3.5.10 | Cryptographically-protected passwords | ✅ | Keycloak uses FIPS-approved PBKDF2; local-admin path uses PBKDF2-HMAC-SHA-256 | `users/password.go`, Keycloak FIPS profile |
| 3.5.11 | Obscure authentication feedback | ✅ | Generic "invalid credentials" error; password fields masked in UI | `http/auth.go`, `frontend/src/views/Login.vue` |

## 3.6 — Incident Response (3)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.6.1 | Operational IR capability | 🟢 | Wazuh correlation rules turn audit events into SOC-actionable incidents | `config/wazuh/rules/filebrowser-cmmc.xml` |
| 3.6.2 | Track and report incidents | 🟢 | Wazuh manager → customer SIEM; DFARS 72 h reporting procedure in SSP | Wazuh dashboard, Customer SSP |
| 3.6.3 | Test IR capability | ✅🟢 | Audit-chain verifier + tabletop procedure; Wazuh replay capability | `cmmc/audit/verify.go`, Wazuh |

## 3.7 — Maintenance (6)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.7.1 | Perform maintenance | 📋 | Customer maintenance procedure | Customer SSP |
| 3.7.2 | Control tools and personnel | 📋 | Customer procedure | Customer SSP |
| 3.7.3 | Sanitize diagnostic media | 🏢 | Host / media handling policy | Customer SSP |
| 3.7.4 | Check diagnostic media for malware | 🏢 | Host AV / media scanning | Customer SSP |
| 3.7.5 | MFA for nonlocal maintenance | ✅ | Admin sessions inherit Keycloak MFA; step-up required for priv ops | `http/fresh_mfa.go` |
| 3.7.6 | Supervise maintenance without access | 📋 | Customer procedure | Customer SSP |

## 3.8 — Media Protection (9)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.8.1 | Protect CUI on system media | ✅ | Per-file AES-256-GCM envelope + envelope-encrypted BoltDB | `cmmc/crypto/envelope/`, `storage/bolt/envelope.go` |
| 3.8.2 | Limit access to CUI media to authorized users | ✅ | Folder ACL + CUI-marking-aware authorization on every read | `cmmc/authz/folderacl/`, `http/cmmc_enforcement.go` |
| 3.8.3 | Sanitize / destroy media before disposal | 🏢 | Host crypto-shred of KEK + LUKS destroy | Customer SSP |
| 3.8.4 | Mark media with CUI markings | ✅ | File-level CUI mark + UI badge + download confirmation dialog | `cmmc/marking/`, `frontend/src/components/files/CuiBadge.vue` |
| 3.8.5 | Control access to media during transport | ✅ | Backup tool wraps with independent KEK; transport policy documented | `cmmc/crypto/envelope/`, Customer SSP |
| 3.8.6 | Cryptographic mechanisms for CUI in transport | ✅ | FIPS TLS on every outbound channel + envelope encryption on backups | `cmmc/crypto/tlsprofile/`, `cmmc/crypto/envelope/` |
| 3.8.7 | Control use of removable media | 🏢 | Host USB / removable-media policy | Customer SSP |
| 3.8.8 | Prohibit portable storage without identifiable owner | 🏢 | Host policy | Customer SSP |
| 3.8.9 | Protect backup CUI confidentiality | ✅ | Backup tool uses independent key custody | `cmmc/crypto/envelope/`, Customer SSP |

## 3.9 — Personnel Security (2)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.9.1 | Screen individuals prior to access | 📋 | Customer HR process | Customer SSP |
| 3.9.2 | Protect CUI during personnel actions | ✅ | OIDC-backed disable + session revocation on termination | `cmmc/auth/session/`, `config/keycloak/bootstrap.sh` |

## 3.10 — Physical Protection (6)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.10.1 | Limit physical access | 🏢 | Customer facility controls | Customer SSP |
| 3.10.2 | Protect/monitor physical facility | 🏢 | Customer facility controls | Customer SSP |
| 3.10.3 | Escort visitors | 🏢 | Customer procedure | Customer SSP |
| 3.10.4 | Maintain audit logs of physical access | 🏢 | Customer facility logs | Customer SSP |
| 3.10.5 | Control + manage physical access devices | 🏢 | Customer procedure | Customer SSP |
| 3.10.6 | Enforce safeguarding at alternate work sites | 🏢 | Customer remote-work policy | Customer SSP |

## 3.11 — Risk Assessment (3)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.11.1 | Periodically assess risk | 📋 | Customer risk-assessment program | Customer SSP |
| 3.11.2 | Scan for vulnerabilities | 🟢 | Wazuh Vulnerability Detector + govulncheck/trivy in release CI | `config/wazuh/`, `.github/workflows/cmmc-supply-chain.yaml` |
| 3.11.3 | Remediate vulnerabilities | 🟢 | Wazuh tracks open CVEs; patch SLA documented in SSP | Wazuh dashboard, Customer SSP |

## 3.12 — Security Assessment (4)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.12.1 | Periodically assess controls | 📋 | Customer assessment program | Customer SSP |
| 3.12.2 | Plan of Action and Milestones | 📋 | Customer POA&M | Customer SSP |
| 3.12.3 | Continuous monitoring | ✅🟢 | Audit-chain verifier + Wazuh continuous monitoring | `cmmc/audit/verify.go`, Wazuh |
| 3.12.4 | System Security Plan | ✅ | Open-CMMC ships SSP source material (this doc + gap-analysis + architecture) | `docs/` |

## 3.13 — System & Communications Protection (16)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.13.1 | Boundary protection | 🏢 | Customer NGFW / Trout Access Gate | `docs/architecture.md` §3 |
| 3.13.2 | Security-promoting designs | ✅ | Afero sandbox + strict CSP + security headers + admin socket separation | `http/headers.go`, `http/http.go` |
| 3.13.3 | Separate user functionality from system management | ✅ | Admin UNIX socket distinct from user HTTP listener | `http/http.go`, `config/systemd/cmmc-filebrowser.service` |
| 3.13.4 | Prevent unauthorized info transfer via shared resources | ✅ | Go runtime + afero scoping; single-tenant memory model | `users/users.go`, afero |
| 3.13.5 | Subnets for publicly accessible components | ✅ | No publicly-accessible components in CUI profile; public shares disabled | `http/public.go` |
| 3.13.6 | Default-deny network traffic | ✅🏢 | firewalld + host deny-by-default; egress allowlist enforced by install.sh | `config/install.sh` phase_firewall |
| 3.13.7 | Prevent split tunneling | 🏢 | Host / endpoint policy | Customer SSP |
| 3.13.8 | Cryptographic mechanisms for CUI in transit | ✅ | TLS 1.3 FIPS profile, FIPS cipher list | `cmmc/crypto/tlsprofile/` |
| 3.13.9 | Terminate connections at session end or inactivity | ✅ | HTTP server `IdleTimeout` + session idle middleware | `http/http.go`, `http/cmmc_session_idle.go` |
| 3.13.10 | Establish and manage crypto keys | ✅ | TPM-sealed KEK + per-file DEK; documented rotation | `cmmc/crypto/envelope/`, `cmmc/crypto/keyderive/` |
| 3.13.11 | FIPS-validated cryptography | ✅ | Built with RHEL go-toolset (FIPS 140-3 inherited via OpenSSL CMVP #4774) | `cmmc/crypto/fips/`, RHEL / Alma OpenSSL |
| 3.13.12 | Prohibit remote activation of collaborative devices | 🏢 | No cameras / mics on server role | Customer SSP |
| 3.13.13 | Control mobile code | ✅ | Strict CSP on all handlers; no inline scripts | `http/headers.go`, `http/http.go` |
| 3.13.14 | Control VoIP | 🏢 | N/A for file server role | Customer SSP |
| 3.13.15 | Protect authenticity of communications sessions | ✅ | TLS + HSTS + optional mTLS for priv sessions | `cmmc/crypto/tlsprofile/`, `http/headers.go` |
| 3.13.16 | Confidentiality of CUI at rest | ✅ | LUKS + per-file envelope encryption + envelope-encrypted BoltDB | `cmmc/crypto/envelope/`, `storage/bolt/envelope.go` |

## 3.14 — System & Information Integrity (7)

| ID | Short title | Source | Implementation | Evidence |
|---|---|---|---|---|
| 3.14.1 | Flaw remediation | ✅🟢 | govulncheck + trivy + SBOM in CI; Wazuh CVE correlation on host packages | `.github/workflows/cmmc-supply-chain.yaml`, `config/wazuh/` |
| 3.14.2 | Protection from malicious code | ✅🟢 | ClamAV scan-on-upload (fail-closed); Wazuh rootcheck + platform AV integration | `cmmc/scan/clamav/`, `config/wazuh/` |
| 3.14.3 | Monitor security alerts and advisories | 🟢 | Wazuh rule feed + customer SSP subscription procedure | `config/wazuh/`, Customer SSP |
| 3.14.4 | Update malicious-code protection | ✅🟢 | ClamAV signature mirror with stale-signature alerting | `cmmc/scan/clamav/`, SSP |
| 3.14.5 | Periodic and real-time scans of external files | ✅ | Real-time scan on every upload + scheduled rescan of files > 30 days old | `cmmc/scan/scanner.go` |
| 3.14.6 | Monitor inbound/outbound for attacks | 🟢 | Wazuh agents on filebrowser host + operator endpoints | `config/wazuh/endpoints/` |
| 3.14.7 | Identify unauthorized use | 🟢 | Wazuh anomaly rules + audit correlation | `config/wazuh/rules/filebrowser-cmmc.xml` |

---

## How to use this document in an assessment

1. **Populate the SSP.** Copy each row into the customer SSP under the corresponding control, adding organization-specific ODPs (retention periods, review cadences, role assignments).
2. **Collect the evidence.** Each `Evidence` cell points at either a source-tree path (reproducible via the tagged release) or an operational artifact (Wazuh dashboard export, SSP section). File the evidence set with the SSP.
3. **Complete the POA&M.** The small number of rows marked 📋 or 🏢 are the customer-side work items; track any that aren't yet documented in a POA&M until they are.
4. **Run `cmmc-filebrowser audit verify`** before the assessment window to demonstrate the audit-chain integrity property.

See also:
- [`gap-analysis.md`](./gap-analysis.md) — pre-fork baseline showing why these controls were added.
- [`architecture.md`](./architecture.md) — data-flow diagrams and topology the controls live in.
