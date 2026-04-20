# Security policy

## Reporting a vulnerability

This project handles Controlled Unclassified Information by design — security findings matter. Please report privately before disclosing publicly.

**Email:** <hello@trout.software>

Include, where possible:

- Affected version (tag, commit SHA, or build date)
- Reproduction steps (minimal)
- Impact assessment — what CUI boundary is at risk
- Proof-of-concept that stops at demonstrating the flaw, not at exercising it
- Your preferred disclosure timeline

We aim to acknowledge within **72 hours** and publish a fix or mitigation within **30 days** for high-severity issues. CVEs are assigned via GitHub's advisory database.

## In scope

- The CMMC additions under `cmmc/`, `http/cmmc_*.go`, `config/`, `scripts/`
- The installer + systemd unit configurations
- The Keycloak realm bootstrap + security policies in `config/keycloak/bootstrap.sh`
- FIPS-related code paths (`cmmc/crypto/`)
- Audit pipeline integrity (`cmmc/audit/`)

## Also in scope but please try upstream first

- Core filebrowser code (non-`cmmc/` Go packages, `frontend/src/` non-CMMC views) that predates the fork — please also open an issue at [filebrowser/filebrowser](https://github.com/filebrowser/filebrowser/security). We'll coordinate disclosure when a fix rebases.

## Out of scope

- Social-engineering attacks on Keycloak operators
- DoS on a single appliance via unthrottled upload (the product is single-tenant; rate limits apply to auth endpoints only)
- Issues requiring physical access to the host
- Vulnerabilities in third-party dependencies that have a published fix — `go.mod` + `pnpm-lock.yaml` are tracked and updated on a cadence

## Coordinated disclosure

We follow a 90-day disclosure window by default, extendable to 120 days for issues requiring customer-side deployment changes (e.g. KEK rotation, cert reissue). Earlier disclosure may be requested for issues under active exploitation.

## Bounty

There is no bounty program. Acknowledgment in the release notes is standard.

## Compliance note

Findings that affect a specific **NIST SP 800-171 Rev 2 control** should reference the control number (e.g., "3.5.3") in the report so we can map the fix into `docs/gap-analysis.md` on disclosure.
