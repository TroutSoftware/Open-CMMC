# Notes for the final operator / SSP documentation

Running log of things we've learned while building the fork that MUST
land in the shipped docs but aren't architectural decisions (which go
in `architecture.md`) or control-specific (`gap-analysis.md`). When it's
time to write the proper operator guide / runbook / SSP supplement,
this is where to pull material from.

Format: dated entries, topic-tagged. Each entry points at the commits
or code that demonstrate the finding so the doc author has concrete
anchors.

---

## 2026-04-17 · build → binary drift trap

**Tag:** ops · gotcha · verification

While validating the expanded audit coverage (commit `b82d425`) the
live ring buffer showed only 1 of 10 expected event types. First
instinct was that the route wiring was wrong. Actually: the VM's
`filebrowser-fips` binary was built at 19:42 but the source edits
that added the new action constants landed at 19:55. I rsync'd the
source without rebuilding. All of the audit emitter / route wrapping
code was correct — just not compiled in.

**In the operator docs**, flag this loud:

> Any change to `cmmc/*` source MUST be followed by `GOFIPS140=v1.0.0
> go build -o filebrowser-fips .` on the target host. If a feature
> appears to misbehave, first confirm the running binary post-dates
> the source change: `ls -la filebrowser-fips` then compare to
> `git log -1 --format=%ct` on the relevant file.

A confirmation command for the SSP / runbook:

```bash
# Sanity: binary embeds all expected audit action constants.
strings filebrowser-fips | grep -E '^(auth|user|share|settings|file|admin|authz)\.' | sort -u
```

The helper script `config/dev/vm-redeploy.sh` (commit `e97b8ca`) does
rsync + rebuild + restart atomically so developers stop tripping
this. Ops in a real deployment should do the same via their
deployment pipeline — never "patch a file and expect it to take."

---

## 2026-04-17 · Go FIPS toggle naming (validated on RHEL 9.7 aarch64)

**Tag:** fips · gotcha · validated-live

Earlier docs / Dockerfile used `GOFIPS=1` — that's the pre-Go-1.24
env var and is a silent no-op on current toolchains. Under Go 1.25.6
the correct toggles are:

- `GOFIPS140=v1.0.0` at **build** time → bakes the FIPS module in;
  `fips140.Enabled()` returns true regardless of runtime env.
- `GODEBUG=fips140=on` at **run** time → activates the FIPS module
  in a binary built without the above.
- Neither → `fips140.Enabled()` returns false; under CMMC L2 the
  boot-time `FB_OIDC_REQUIRE_FIPS=true` assertion refuses to start.

Fix landed in commit `d46dca1`; pinned by test
`TestFIPS_TogglesDocumented`. Operator doc must show the exact env
values — `GOFIPS=1` is a common retry when something breaks and it
silently does nothing.

---

## 2026-04-17 · Bash `GROUPS` variable is reserved

**Tag:** bootstrap · gotcha

Initial `config/keycloak/bootstrap.sh` had:

```bash
GROUPS=(filebrowser-admins management engineering operations quality sales compliance)
```

Bash reserves `GROUPS` as a readonly array holding the current user's
POSIX group IDs. The assignment is silently ignored; the loop then
iterates over `10 1000` (wheel + user gid on RHEL) and created two
garbage groups in the realm.

Fix: renamed to `CMMC_GROUPS`; commit `0-to-be-linked` +
`bootstrap_test.sh::GROUPS trap` regression guard. Operator doc
should call out this specific pitfall if we add more script-based
bootstrap utilities — bash reserves a small pile of variable names
(`GROUPS`, `EUID`, `UID`, `PPID`, ...) and silent-ignore is
surprising to anyone used to POSIX-sh semantics.

---

## 2026-04-17 · Keycloak default `amr` emission is absent

**Tag:** keycloak · mfa · gotcha

Keycloak 26's OIDC client does NOT emit an `amr` claim by default,
even when the user authenticated with password + TOTP. It emits
`acr: "1"` regardless of whether MFA occurred. So our `FB_OIDC_
MFA_CLAIM=amr` detection fails out of the box.

We worked around it by adding an `oidc-hardcoded-claim-mapper` that
injects `amr: ["pwd", "otp"]` on every token. Documented as a
"truthful only because the realm enforces CONFIGURE_TOTP + Browser
Conditional OTP" tradeoff in `docs/keycloak-setup.md`.

**For production-hardened docs**: recommend customers configure
Keycloak's Level-of-Assurance (LoA) step-up authentication instead.
It binds `acr` to actual authenticator use (e.g., `acr=silver` for
password-only, `acr=gold` when OTP required), and filebrowser's
`FB_OIDC_MFA_CLAIM=acr` with an `FB_OIDC_MFA_ACR_MIN=gold` check
would remove the hardcoded mapper entirely.

---

## 2026-04-18 · Outbound CUI sharing / email — out of MVP scope

**Tag:** scope · email · share · decided

Originally deferred ("email server not yet wired"); **removed from
scope 2026-04-18**. The wedge this product solves is whole-company
CMMC storage migration, not the outbound-CUI-email problem that
affects 5–20 people per customer and is already served by Virtru,
PreVeil, Kiteworks, Exchange+S/MIME, etc. Pulling an email stack
into the appliance would duplicate tooling every customer licenses
and drag FedRAMP-Moderate email-infra concerns into the assessment
boundary.

Consequences applied in this commit:
- Removed SMTP node from the deployment mermaid and component table.
- Dropped SMTP from the egress allowlist (D7).
- Flipped Keycloak realm `verifyEmail: true → false` in
  `config/keycloak/bootstrap.sh` so no admin workaround is needed.
- Rewrote `architecture.md` §10 to document the scope boundary +
  when we would revisit (multiple customers cite it as a *migration
  blocker*, not a preference).
- Answered open question #6 in `gap-analysis.md`.

See memory record `project_cmmc_filebrowser.md` D6 for the locked
decision.

---

## 2026-04-17 · rsyslog does not substitute properties in action params

**Tag:** rsyslog · gotcha · validated-live

First draft of `config/rsyslog/50-cmmc-filebrowser.conf` used
`set $.siem_host = ...` + \`echo $.siem_host\` inside action params
to let operators override destinations without editing the config.
`rsyslogd -N1` rejected it — `set $.foo` creates a message-scoped
property, which doesn't exist at config-load time when action
parameters are resolved. Actual error:

```
parameter 'streamdriverpermittedpeers' contains whitespace, which is not permitted
```

(because the backtick string with `$.siem_cn` contained a `$` that
rsyslog tried to parse, and the leftover space tripped the
permitted-peers validation).

Fix: hardcode the per-deployment values with `⟪ REPLACE ⟫` markers
and recommend operators template the file via Ansible / Terraform
/ CM, or maintain a sibling `/etc/rsyslog.d/49-cmmc-vars.conf` that
is managed out-of-band. Landed in commit `ec79b75`.

**For the shipped docs**: flag this loud when telling operators
about customization. It's the kind of "obvious" config pattern they
will try because most logging daemons support env substitution.

---

## Template for future entries

```
## YYYY-MM-DD · short title

**Tag:** topic · gotcha | validated-live | deferred | ops

Paragraph of what happened + why it matters.

**For the shipped docs**: the specific thing that needs to appear.

Link to commits / tests / code that anchor it.
```
