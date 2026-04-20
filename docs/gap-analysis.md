# CMMC Level 2 / NIST SP 800-171 Rev 2 — Gap Analysis

**Target product:** hardened fork of [filebrowser/filebrowser](https://github.com/filebrowser/filebrowser) for on-prem CUI file storage.
**Baseline analysed:** upstream v2.63.2 (commit `dd53644`, 2026-04-17).
**Assessment framework:** CMMC 2.0 Level 2 → NIST SP 800-171 Rev 2 (Feb 2020), 110 controls.
**Rule context:** CMMC Program Final Rule effective 2025-11-10 (32 CFR 170); Phase 2 (mandatory C3PAO) begins 2026-11-10. Rev 3 not adopted by DoD.
**Authoritative control text:** [NIST.SP.800-171r2.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf).
**Regulatory companions:** DFARS 252.204-7012, FAR 52.204-21, DFARS 252.204-7021.
**Positive counterpart:** [`compliance-posture.md`](./compliance-posture.md) — per-control coverage once Open-CMMC is installed.

---

## How to read this document

| Column | Meaning |
|---|---|
| **ID** | 800-171 Rev 2 control id |
| **Short title** | Abbreviated control intent (see NIST r2 Appendix D for full text) |
| **Upstream state** | What filebrowser v2.63.2 does today, with `file:line` citation |
| **Gap** | What's missing vs control intent |
| **Severity** | `Blocker` (cannot ship), `Major` (must before assessment), `Minor` (policy/doc), `N/A-Infra` (satisfied by host/network layer), `N/A-Policy` (outside product scope), `Inherited-AG` (satisfied by Trout Access Gate when deployed in the AG profile) |
| **Remediation** | Shorthand for the fix: `replace-auth`, `add-module`, `config`, `host-control`, `siem`, `doc-only`, `inherit-idp`, `inherit-ag` |

Anchor for defined values (e.g., "defined period"): organizationally-defined parameters (ODPs) must be set in the SSP. This gap analysis assumes the standard FedRAMP Moderate baseline values where Rev 2 is silent.

---

## Executive summary — top 10 blockers

Rank-ordered by effort-adjusted risk to Phase 2 assessment readiness.

| # | Blocker | Controls touched | Remediation theme |
|---|---|---|---|
| 1 | **No FIPS-validated cryptography.** Go's stdlib `crypto/tls`, `crypto/bcrypt`, `crypto/hmac` used throughout without a FIPS module. | 3.13.11, 3.13.8, 3.5.10, 3.13.16 | Rebuild on RHEL go-toolset (FIPS 140-3 inherited) OR microsoft/go; pin all crypto to FIPS-approved algs. |
| 2 | **No MFA / OIDC / SAML.** Only JSON auth, shell-hook auth, reverse-proxy auth. `http/auth.go:123`. | 3.5.3, 3.5.4, 3.5.1, 3.5.2 | Add OIDC + SAML + x509 (CAC/PIV) auth backends; push MFA to IdP. |
| 3 | **No lockout / replay protection / session mgmt.** No failed-login counter. JWT 2h expiry but no server-side session revocation. | 3.1.8, 3.5.4, 3.1.10, 3.1.11 | Failed-attempt store + lockout; session revocation list; idle lock. |
| 4 | **No encryption at rest.** BoltDB plaintext. No envelope encryption for files. | 3.13.16, 3.8.9, 3.8.1 | LUKS for filesystem + per-file envelope (AES-256-GCM, DEK wrapped by KEK in TPM). |
| 5 | **Audit trail insufficient.** stdlib `log` → lumberjack rotation. No tamper protection, no clock-sync assertion, no failure alerts, no structured correlation ids, file-ops logged only if shell hooks configured. | 3.3.1, 3.3.2, 3.3.4, 3.3.5, 3.3.7, 3.3.8, 3.3.9 | Structured JSON events with correlation id; hash-chain or signed batch; rsyslog-ossl → SIEM. |
| 6 | **TLS not FIPS-profiled.** `MinVersion: TLS 1.2` is set (`cmd/root.go:219-221`) but cipher list is Go defaults — includes non-FIPS suites under non-FIPS builds. No HSTS/X-Frame-Options/X-Content-Type-Options. | 3.13.8, 3.13.11, 3.13.15 | Explicit FIPS-only cipher list; TLS 1.3 preferred; add security headers. |
| 7 | **No malware scanning on upload.** Hook system exists (`runner/runner.go:20-52`) but no bundled AV. | 3.14.2, 3.14.5, 3.14.6 | ClamAV integration via hook; fail-closed on scan error; internal mirror for signatures. |
| 8 | **No CUI marking model.** Files are plain paths; no mark, no banner, no distribution-limit metadata. | 3.8.4, 3.1.3, 3.1.22 | File-metadata table for CUI marks; UI banners; download warnings. |
| 9 | **Public share links bypass auth.** `http/public.go` serves via share hash only (bcrypt password optional). | 3.1.3, 3.1.22, 3.13.5 | Disable public shares for CUI-marked files; authenticated-only + time-bounded tokens; audit every share read. |
| 10 | **No SBOM, no reproducible builds, no vulnerability management story.** `.goreleaser.yml` lacks `-trimpath`, SBOM. | 3.14.1, 3.11.2, 3.14.3, 3.4.1 | SBOM in CI; sign releases; vulnerability scanner in pipeline; documented patch SLA. |

---

## Family 3.1 — Access Control (22)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.1.1 | Limit system access to authorized users | JSON/Proxy/Hook/None auth; bcrypt password (`users/password.go:27`); JWT (`http/auth.go:215`). Works only for locally-defined users. | No federation; admin check is boolean (`users/permissions.go:3-13`); no RBAC beyond 8 flags. | Major | replace-auth (inherit-idp) |
| 3.1.2 | Limit transactions/functions to authorized | `users/permissions.go`: Admin, Create, Rename, Modify, Delete, Share, Download, Execute flags | Coarse; no per-file or per-classification controls | Major | add-module (RBAC + CUI-marking-aware) |
| 3.1.3 | Control flow of CUI per approved authorizations | No CUI concept | Entire flow-control story missing | Blocker | add-module (marking + policy engine) |
| 3.1.4 | Separation of duties | Admin is a single flag; no split between system-admin / audit-admin / user-admin | Single-admin design | Major | add-module (roles) |
| 3.1.5 | Least privilege | Permission flags default to `false` for new users | Good default but no enforced review cycle | Minor | doc-only (policy) |
| 3.1.6 | Non-priv accounts for non-security functions | N/A in product — operator policy | Doc | N/A-Policy | doc-only |
| 3.1.7 | Prevent non-priv users from priv functions; log attempts | Admin check is a boolean gate; no audit on denied priv attempts | Deny events not logged | Major | config + add audit events |
| 3.1.8 | Limit unsuccessful logon attempts | **ABSENT** — no failed-attempt counter anywhere | No lockout | Blocker | add-module (attempt store + lockout) |
| 3.1.9 | Privacy/security notices | No login banner support | Missing banner surface | Major | add-module (config-driven banner) |
| 3.1.10 | Session lock with pattern hiding | **ABSENT** | No idle lock | Major | add-module (idle timer → re-auth) |
| 3.1.11 | Terminate session after condition | JWT expires 2h (`http/auth.go:22`) — no server-side invalidation, no idle termination | No revocation | Major | add-module (session store + revocation) |
| 3.1.12 | Monitor and control remote access | All access is remote here. No distinct "remote" concept | Need explicit monitoring and audit of all sessions | Major | config + siem |
| 3.1.13 | Cryptographic mechanisms for remote access confidentiality | TLS 1.2+ (`cmd/root.go:219`) but not FIPS-profiled | Cipher list not FIPS-constrained | Blocker | config (FIPS cipher list) |
| 3.1.14 | Route remote access via managed control points | Host-level — NGFW / Trout Access Gate | Assertion only | N/A-Infra | host-control + doc |
| 3.1.15 | Authorize remote priv commands / security-relevant info | Admin endpoints gated by `withAdmin` (`http/auth.go:111`) | No step-up auth for priv actions | Major | add-module (re-auth for admin) |
| 3.1.16 | Authorize wireless access prior to connection | Host/network layer | | N/A-Infra | doc |
| 3.1.17 | Protect wireless with authn+crypto | Host/network layer | | N/A-Infra | doc |
| 3.1.18 | Control mobile device connections | Host/MDM | | N/A-Infra | doc |
| 3.1.19 | Encrypt CUI on mobile devices | If mobile access enabled, device-level FDE required | Docs must forbid sync clients without device-FDE | Major | doc-only (profile) |
| 3.1.20 | Verify/control connections to external systems | Egress lockdown at NGFW; no outbound calls from filebrowser host (AV mirror, SIEM, IdP only — no SMTP client in-product, see [architecture § 10](./architecture.md)) | Must be asserted in SSP | Major | host-control + doc |
| 3.1.21 | Limit portable storage on external systems | Host/endpoint policy | | N/A-Policy | doc |
| 3.1.22 | Control CUI on publicly accessible systems | Public shares exist (`http/public.go`) — bypass auth | Public shares must be disabled for CUI-marked files | Blocker | config + add-module (marking-aware block) |

---

## Family 3.2 — Awareness & Training (3)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.2.1 | Security awareness | Outside product | | N/A-Policy | doc-only (customer program) |
| 3.2.2 | Role-based training | Outside product | | N/A-Policy | doc-only |
| 3.2.3 | Insider-threat training | Outside product | | N/A-Policy | doc-only |

---

## Family 3.3 — Audit & Accountability (9)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.3.1 | Create/retain audit records | stdlib `log`, rotated by lumberjack (`cmd/root.go:375-391`). Auth errors logged (`http/data.go:69-72`). File CRUD NOT logged unless shell hooks configured (`runner/runner.go:20-52`). | Incomplete event coverage; unstructured | Blocker | add-module (structured audit emitter) |
| 3.3.2 | Uniquely trace actions to user | JWT claims include user id (`http/auth.go:215-249`); partial on error paths | No correlation id; no subject-device binding | Major | add-module (correlation context) |
| 3.3.3 | Review and update logged events | No centralized event schema | Cannot review what isn't structured | Major | add-module (audit schema + admin tool) |
| 3.3.4 | Alert on audit logging failure | lumberjack writes silently fail | Fail-open risk | Major | add-module (health check + watchdog) |
| 3.3.5 | Correlate audit review | No correlation id | | Major | add-module (correlation context) |
| 3.3.6 | Record reduction and report generation | None | | Major | siem (Splunk/Sentinel/Elastic does this) |
| 3.3.7 | Authoritative timestamp source | `time.Now()` (`http/auth.go:232`) — wall clock | Must use chrony → stratum-1 per host policy | Major | host-control + doc |
| 3.3.8 | Protect audit info and tools | lumberjack files at default perms | No append-only FS; no hash chain | Blocker | add-module (signed batch or WORM spool) + rsyslog-ossl forwarder |
| 3.3.9 | Limit audit mgmt to subset of priv users | Admin flag covers everything | No dedicated audit-admin role | Major | add-module (roles) |

---

## Family 3.4 — Configuration Management (9)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.4.1 | Baseline configs / inventories | No baseline shipped; viper reads `/etc/filebrowser/.filebrowser.yaml` | Ship an opinionated FIPS-enabled baseline config | Major | config + doc |
| 3.4.2 | Enforce security config settings | settings in BoltDB (`settings/settings.go:23-41`); changeable via admin UI | Need config-lock mode | Major | add-module (signed config) |
| 3.4.3 | Track/review/approve/log changes | Admin changes logged only via hook | No approval workflow | Major | add-module (change log + optional 2-person) |
| 3.4.4 | Analyze security impact | Outside product | | N/A-Policy | doc |
| 3.4.5 | Access restrictions for change | Admin flag only | | Major | add-module (roles) |
| 3.4.6 | Least functionality | Full feature surface enabled by default | Add disable-by-default for shares, previews, archives | Major | config + add-module |
| 3.4.7 | Restrict nonessential ports/protocols/services | Host-level (systemd + firewall) | | N/A-Infra | doc |
| 3.4.8 | Deny-by-exception / permit-by-exception for software | Host/SELinux policy | | N/A-Infra | doc |
| 3.4.9 | Control user-installed software | Host-level | | N/A-Infra | doc |

---

## Family 3.5 — Identification & Authentication (11)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.5.1 | Identify users / processes / devices | Username only (`users/users.go:21-40`) | No device identification | Major | add-module (x509 device auth) |
| 3.5.2 | Authenticate identities | bcrypt (`users/password.go:27`); JWT HS256 | HS256 OK under FIPS; bcrypt not FIPS-approved — switch to PBKDF2-SHA256 or Argon2id-via-FIPS-HMAC | Blocker | replace-auth (hash algo) |
| 3.5.3 | MFA (priv local+network, non-priv network) | **ABSENT** | No TOTP / WebAuthn; must push to IdP | Blocker | inherit-idp (OIDC + MFA at IdP) |
| 3.5.4 | Replay-resistant authentication | JWT with NumericDate expiry (`http/auth.go:232-233`); no nonce or anti-replay for token reuse inside window | Need one-time-use artifact for priv step-up | Major | add-module (jti + revocation) |
| 3.5.5 | Prevent identifier reuse | Usernames stored in BoltDB; no historical record | Soft-delete with identifier-reuse guard | Minor | add-module |
| 3.5.6 | Disable inactive identifiers | **ABSENT** | No last-login tracking → auto-disable | Major | add-module |
| 3.5.7 | Minimum password complexity | `settings/settings.go:15` — DefaultMinimumPasswordLength=12 | Complexity rules missing (char classes), no history, no age | Major | config + add-module |
| 3.5.8 | Prohibit password reuse for N generations | **ABSENT** | No history table | Major | add-module |
| 3.5.9 | Temporary password with immediate change | **ABSENT** (admins set passwords that persist) | Add forced-rotation flag | Major | add-module |
| 3.5.10 | Store/transmit only cryptographically-protected passwords | bcrypt in DB (`users/password.go:27`); over TLS (if enabled) | bcrypt not FIPS-approved; DB unencrypted at rest | Blocker | replace-auth (PBKDF2) + at-rest-encrypt DB |
| 3.5.11 | Obscure feedback of authentication info | Frontend masks password field; login error generic ("forbidden to access this resource") | Acceptable | Minor | doc (verify in UI test) |

---

## Family 3.6 — Incident Response (3)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.6.1 | Operational IR capability | Outside product | | N/A-Policy | doc (runbook template) |
| 3.6.2 | Track/report incidents | SIEM dashboards + DFARS 72h reporting | | N/A-Policy | doc |
| 3.6.3 | Test IR capability | Outside product | | N/A-Policy | doc |

---

## Family 3.7 — Maintenance (6)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.7.1 | Perform maintenance | N/A | | N/A-Policy | doc |
| 3.7.2 | Control tools/personnel | N/A | | N/A-Policy | doc |
| 3.7.3 | Sanitize diagnostic media | N/A | | N/A-Policy | doc |
| 3.7.4 | Check diag media for malware | N/A | | N/A-Policy | doc |
| 3.7.5 | MFA for nonlocal maintenance | Admin session access = nonlocal maintenance; inherit IdP MFA | | Major | inherit-idp |
| 3.7.6 | Supervise maintenance w/o access | N/A | | N/A-Policy | doc |

---

## Family 3.8 — Media Protection (9)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.8.1 | Protect CUI on system media | No at-rest encryption; BoltDB plaintext | | Blocker | add-module (envelope encryption) + host (LUKS) |
| 3.8.2 | Limit access to CUI on media to authorized users | Scope + afero sandbox (`users/users.go:94-97`); Rules (`http/data.go:28-47`) | No marking-aware authz | Major | add-module |
| 3.8.3 | Sanitize/destroy media before disposal/reuse | Host policy | | N/A-Policy | doc |
| 3.8.4 | Mark media with CUI markings | **ABSENT** | | Blocker | add-module (marking model) |
| 3.8.5 | Control access to media during transport | Backups: encrypted with independent keys; transport controls | | Major | add-module (backup tool) + doc |
| 3.8.6 | Cryptographic mechanisms for CUI in transport | TLS for network; encrypted backups | | Major | config (FIPS) + backup pattern |
| 3.8.7 | Control use of removable media | Host policy (USB lockdown) | | N/A-Infra | doc |
| 3.8.8 | Prohibit portable storage w/o identifiable owner | Host policy | | N/A-Infra | doc |
| 3.8.9 | Protect confidentiality of backup CUI | Backup target encrypted; offsite controls | | Major | add-module (restic/BorgBackup + documented procedure) |

---

## Family 3.9 — Personnel Security (2)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.9.1 | Screen individuals prior to access | HR process | | N/A-Policy | doc |
| 3.9.2 | Protect CUI during personnel actions | Admin must disable accounts at IdP; revoke sessions | Tie to 3.5.6 (inactive identifier disable) | Major | inherit-idp + add-module |

---

## Family 3.10 — Physical Protection (6)

All six (3.10.1–3.10.6) are facility-level. **N/A-Infra**, satisfied by customer's datacenter controls; documented in SSP.

---

## Family 3.11 — Risk Assessment (3)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.11.1 | Periodically assess risk | Customer program | | N/A-Policy | doc |
| 3.11.2 | Scan for vulnerabilities | No scanner in CI | | Major | add trivy/govulncheck to CI |
| 3.11.3 | Remediate vulnerabilities | No patch SLA | | Major | doc (publish patch SLA) |

---

## Family 3.12 — Security Assessment (4)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.12.1 | Periodically assess controls | Outside product | | N/A-Policy | doc |
| 3.12.2 | POA&M | Outside product | | N/A-Policy | doc |
| 3.12.3 | Continuous monitoring | SIEM + health dashboard | | Major | add-module (health endpoint) + siem |
| 3.12.4 | SSP | Outside product (but we supply a SSP template) | | Minor | doc (ship SSP template) |

---

## Family 3.13 — System & Communications Protection (16)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.13.1 | Boundary protection | Trout Access Gate / NGFW | | N/A-Infra | host-control + doc |
| 3.13.2 | Security-promoting designs/techniques | Afero sandbox, CSP headers | Partial | Major | add-module (threat model in SSP) |
| 3.13.3 | Separate user functionality from system management | Single HTTP server serves UI + admin API | Co-mingled surface | Major | add-module (admin interface on separate listener) |
| 3.13.4 | Prevent unauthorized info transfer via shared resources | Go GC + afero; no multi-tenant memory | Probably OK for single-tenant | Minor | doc |
| 3.13.5 | Subnets for public components | No publicly accessible components in CUI build | Disable public shares | Major | config |
| 3.13.6 | Default-deny network traffic | Host firewall + Trout Access Gate | | N/A-Infra | host-control + doc |
| 3.13.7 | Prevent split tunneling | Host/endpoint policy | | N/A-Infra | doc |
| 3.13.8 | Crypto mechanisms for CUI in transit | TLS 1.2+ (`cmd/root.go:219`); ciphers not FIPS-pinned | Enforce FIPS cipher list | Blocker | config (FIPS TLS) |
| 3.13.9 | Terminate connections at session end / after inactivity | Go default idle timeout; no explicit config | Add server.IdleTimeout + force on auth session | Major | config + add-module |
| 3.13.10 | Establish and manage crypto keys | JWT key in settings (`settings/settings.go:24`); no rotation | Need KMS-like key mgmt: TPM-sealed KEK + key rotation | Blocker | add-module (KMS abstraction) |
| 3.13.11 | FIPS-validated cryptography | Go stdlib crypto — NOT FIPS-validated | Build on RHEL go-toolset (RHEL FIPS 140-3) | Blocker | replace-toolchain (FIPS Go) |
| 3.13.12 | Prohibit remote activation of collaborative computing devices | N/A (no cameras/mics) | | N/A-Infra | doc |
| 3.13.13 | Control mobile code | CSP `script-src 'none'` on raw handlers (`http/raw.go:220`); `default-src 'self'` otherwise | Audit frontend for eval / inline | Major | config (tighten CSP) |
| 3.13.14 | Control VoIP | N/A | | N/A-Infra | doc |
| 3.13.15 | Protect authenticity of communications sessions | TLS + JWT | mTLS for priv sessions; HSTS | Major | config (add mTLS + HSTS) |
| 3.13.16 | Confidentiality of CUI at rest | **ABSENT** — BoltDB plaintext; files plaintext | LUKS + envelope encryption | Blocker | host-control + add-module |

---

## Family 3.14 — System & Information Integrity (7)

| ID | Short title | Upstream state | Gap | Severity | Remediation |
|---|---|---|---|---|---|
| 3.14.1 | Flaw remediation | Upstream CI present (`.github/workflows/ci.yaml`); no SBOM, no govulncheck | | Major | add-module (govulncheck + trivy + SBOM) |
| 3.14.2 | Protection from malicious code | **ABSENT** (no bundled AV) | | Blocker | add-module (ClamAV hook on upload) |
| 3.14.3 | Monitor security alerts/advisories | Customer program | | N/A-Policy | doc (ship advisory channel) |
| 3.14.4 | Update malicious code protection | Tied to ClamAV mirror pattern; alert on stale signatures (Cisco/Cloudflare Nov 2025 outage) | | Major | add-module (stale-signature alert) |
| 3.14.5 | Periodic and real-time scans of files from external sources | **ABSENT** | | Blocker | add-module (scan-on-upload + periodic re-scan) |
| 3.14.6 | Monitor inbound/outbound for attacks | NIDS/NSM at network layer | Plus app-level anomaly events to SIEM | Major | host-control + add-module |
| 3.14.7 | Identify unauthorized use | Audit + SIEM correlation | | Major | siem |

---

## Deployment profiles

Two deployment profiles are supported. The profile chosen at install time changes which controls are implemented inside filebrowser-cmmc and which are inherited from the boundary:

### Profile A — BYO-IdP (default)

Filebrowser speaks OIDC/SAML/x509 directly to a customer IdP (Entra GCC-H, Keycloak-FIPS, Ping, Okta Gov). A generic NGFW provides boundary protection only. This is the row-by-row assessment above.

### Profile B — Trout Access Gate

The filebrowser-cmmc host is deployed behind a Trout Access Gate (AG), which provides four capabilities that filebrowser can inherit:

1. **Pre-auth + MFA at the boundary.** AG federates to the customer's real IdP (or holds local accounts), performs MFA, and hands filebrowser a short-lived signed identity assertion over an mTLS-pinned channel. Filebrowser's OIDC client is disabled in this profile.
2. **PAM session proxy for privileged access.** The admin UNIX socket is fronted by AG's recorded, MFA-gated PAM session. Privileged-command audit lives in AG's session recorder as well as filebrowser's audit stream.
3. **Authoritative DNS with egress allowlist.** AG is the only resolver the filebrowser host sees. Requests outside the allowlist (IdP, SIEM, ClamAV mirror, time source) return NXDOMAIN. DNS queries themselves are audited — catches beaconing before packets leave. No SMTP egress — outbound CUI sharing is out of scope (see [architecture § 10](./architecture.md)).
4. **Built-in Certificate Authority.** AG runs a CA by default, issuing all internal mTLS certificates — filebrowser service cert, rsyslog forwarder cert, ClamAV mirror cert, AG→filebrowser assertion signing key, and (optionally) user mTLS CAC/PIV-style client certs. Two deployment modes:
   - **AG as root CA**: self-signed root in AG's HSM; all enclave trust chains up to AG.
   - **AG as intermediary**: customer's existing root CA (DoD PKI or contractor root) issues AG an intermediate CA certificate; AG then issues enclave certs under that chain. Preserves customer chain of trust and makes AG's CA cert revocable from outside.

### AG-profile inheritance mapping

The following controls change severity under Profile B. Unlisted controls are unchanged between profiles.

| ID | Profile A severity | Profile B severity | What AG delivers |
|---|---|---|---|
| 3.1.1 | Major | Inherited-AG | Pre-auth before any request reaches filebrowser |
| 3.1.2 | Major | Inherited-AG (partial) | Group-based coarse authz at AG; filebrowser keeps per-resource |
| 3.1.8 | Blocker | Inherited-AG | AG does lockout/backoff |
| 3.1.9 | Major | Inherited-AG | AG shows login banner |
| 3.1.10 | Major | Inherited-AG | AG idle session lock |
| 3.1.11 | Major | Inherited-AG | AG session termination |
| 3.1.12 | Major | Inherited-AG | AG IS the managed remote access control point |
| 3.1.13 | Blocker | Inherited-AG | TLS via AG CA |
| 3.1.14 | N/A-Infra | Inherited-AG | AG is the managed access control point |
| 3.1.15 | Major | Inherited-AG | AG PAM records + MFA-gates priv commands |
| 3.1.20 | Major | Inherited-AG | Egress allowlist enforced at AG DNS and firewall |
| 3.3.1 | Blocker | Major | Filebrowser still emits; AG adds boundary events |
| 3.3.2 | Major | Inherited-AG (partial) | AG correlation id flows into filebrowser events |
| 3.3.5 | Major | Inherited-AG | Correlation across AG and filebrowser makes this real |
| 3.3.7 | Major | Inherited-AG | AG provides authenticated NTS time source |
| 3.5.1 | Major | Inherited-AG | AG identifies users/devices |
| 3.5.2 | Blocker | Inherited-AG | AG does authn |
| 3.5.3 | Blocker | Inherited-AG | AG does MFA |
| 3.5.4 | Major | Inherited-AG | AG replay-resistant protocol |
| 3.5.5 | Minor | Inherited-AG | AG manages identifier lifecycle |
| 3.5.6 | Major | Inherited-AG | AG disables inactive identifiers |
| 3.5.7 | Major | Inherited-AG | AG enforces password policy (if password) |
| 3.5.8 | Major | Inherited-AG | AG handles password history |
| 3.5.9 | Major | Inherited-AG | AG temporary-password mechanism |
| 3.5.10 | Blocker | Inherited-AG | AG custodies credentials; filebrowser has none for users |
| 3.5.11 | Minor | Inherited-AG | AG login UI masks feedback |
| 3.7.5 | Major | Inherited-AG | AG PAM for nonlocal maintenance w/ MFA + recording |
| 3.9.2 | Major | Inherited-AG (partial) | AG revokes on termination → filebrowser sessions invalid |
| 3.13.1 | N/A-Infra | Inherited-AG | AG is the boundary |
| 3.13.5 | Major | Inherited-AG | AG separates public from CUI subnet |
| 3.13.6 | N/A-Infra | Inherited-AG | AG enforces default-deny at DNS + firewall |
| 3.13.8 | Blocker | Inherited-AG | AG terminates and re-originates TLS with FIPS ciphers |
| 3.13.10 | Blocker | Inherited-AG | **AG is the CA** — all cert issuance, rotation, revocation, CRL/OCSP at AG |
| 3.13.11 | Blocker | Inherited-AG | FIPS-validated crypto inherited via AG |
| 3.13.14 | N/A-Infra | Inherited-AG | AG controls VoIP flows |
| 3.13.15 | Major | Inherited-AG | AG-CA-issued mTLS on all enclave channels |
| 3.14.6 | Major | Inherited-AG (partial) | AG monitors inbound/outbound at boundary |
| 3.14.7 | Major | Inherited-AG (partial) | AG detects unauthorized use at boundary |

**38 controls** change severity under Profile B. Of those, **11 Blockers** drop to Inherited-AG.

### AG-as-CA: specific impact on 3.13.10 and 3.13.11

The "AG runs a CA by default" capability is the biggest single inheritance lever in the profile because it addresses two historically painful controls at once:

- **3.13.10 (establish and manage cryptographic keys)** — under Profile A, we had to build a TPM-backed KEK management layer and design rotation protocols ourselves. Under Profile B, AG owns the full PKI/TLS identity key lifecycle: key ceremony, rotation cadence, revocation (CRL/OCSP), and audit trail. Filebrowser owns the file-encryption KEKs at the data-path layer (§8 of architecture.md) — the two custody layers are complementary and independent.
- **3.13.11 (FIPS-validated cryptography)** — the CA's crypto module becomes the inheritance anchor for every channel AG terminates or signs. Filebrowser's own crypto (envelope encryption) still needs RHEL go-toolset / FIPS-validated path.

**Customer-as-root + AG-as-intermediary is the preferred deployment** for larger DoD shops: it binds the enclave PKI into the customer's existing chain of trust (often DoD PKI or contractor root), makes AG's CA cert revocable from outside the enclave, and avoids the "island of trust" problem that pure AG-root deployments create.

---

## Severity rollup

| Severity | Profile A (BYO-IdP) | Profile B (Access Gate) |
|---|---|---|
| Blocker | 14 | **3** |
| Major | 43 | 18 |
| Minor | 5 | 3 |
| N/A-Infra | 18 | 14 |
| N/A-Policy | 30 | 30 |
| Inherited-AG | 0 | **42** |
| **Total** | **110** | **110** |

**Profile A:** 14 Blockers map into v1 scope.

**Profile B:** Only 3 Blockers remain in filebrowser itself — the data-path controls that live inside the application:
- **3.13.16** (CUI at rest) — filebrowser's envelope encryption on files and BoltDB.
- **3.14.2** (malicious code protection) — ClamAV + YARA at upload time.
- **3.14.5** (scan files from external sources) — same scan path as 3.14.2.

Profile B remains a real engineering project (18 Majors to close, principally around envelope encryption, audit schema, CUI marking, AEAD AAD binding, and admin listener separation) — but the auth/IdP/session/TLS/CA/key-mgmt clusters move from "we build it" to "we configure and document the AG inheritance."

---

## Remediation pattern legend

- `replace-auth` — swap auth code path for FIPS-friendly / IdP-delegated flow
- `replace-toolchain` — rebuild on FIPS-Go
- `add-module` — new Go package under `cmmc/` namespace
- `config` — settings + defaults change, no new code
- `host-control` — provided by RHEL / LUKS / systemd / NGFW
- `siem` — provided by customer SIEM (Splunk / Sentinel / Elastic)
- `inherit-idp` — delegated to IdP (Entra GCC-H / Keycloak-FIPS / Okta Gov / Ping)
- `doc-only` — SSP/policy text only, no code

---

## Open questions for the customer / assessor

1. **Rev 3 pivot** — want the marking model to pre-accommodate organizationally-defined parameters (ODPs) even though Rev 2 doesn't require them?
2. **IdP default** — Entra GCC-H, Keycloak-FIPS-on-RHEL, or customer choice with both supported as blessed configurations?
3. **Envelope encryption key custody** — TPM-sealed KEK on the filebrowser host, or HSM (YubiHSM 2 / Thales network HSM)?
4. **mTLS for user sessions** — required for all users, or only privileged?
5. **Backup target** — local encrypted NAS, GCC-H-tenant storage, or physical offsite media rotation?
6. **Share link semantics for CUI** — **decided (2026-04-18)**: disabled entirely for CUI-marked files, and no in-product outbound CUI sharing mechanism (SMTP, S/MIME, portal). Customers route outbound CUI through their existing specialized service (Virtru, PreVeil, Kiteworks, Exchange + S/MIME, etc.). See [architecture § 10](./architecture.md) for the scope rationale.

These are decided in `architecture.md` with placeholder defaults.
