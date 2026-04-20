#!/usr/bin/env bash
#
# Smoke tests for config/keycloak/bootstrap.sh. Runs without a live
# Keycloak — validates the script's structural correctness so a
# future refactor can't silently break the realm-provisioning surface
# that the docs promise.
#
# Not a replacement for an integration test against a live Keycloak.
# That path was exercised manually on 2026-04-17 (RHEL 9.7 VM + Keycloak
# 26.0); this suite protects the shell-script parts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOOTSTRAP="$SCRIPT_DIR/bootstrap.sh"
PASS=0
FAIL=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

echo "==> bash syntax"
if bash -n "$BOOTSTRAP"; then
  ok "bootstrap.sh parses cleanly"
else
  fail "bootstrap.sh has shell syntax errors"
fi

echo "==> shebang"
if head -1 "$BOOTSTRAP" | grep -q '^#!/usr/bin/env bash'; then
  ok "uses env-bash shebang"
else
  fail "missing or wrong shebang"
fi

echo "==> strict mode"
if grep -q 'set -euo pipefail' "$BOOTSTRAP"; then
  ok "enables strict mode (set -euo pipefail)"
else
  fail "not in strict mode — operator errors would go undetected"
fi

echo "==> executable bit"
if [ -x "$BOOTSTRAP" ]; then
  ok "executable bit set"
else
  fail "not executable"
fi

echo "==> GROUPS trap"
# bash reserves the GROUPS variable; the script must use a distinct name.
if grep -qE '^GROUPS=\(' "$BOOTSTRAP"; then
  fail "bootstrap reassigns bash built-in GROUPS (silently ignored)"
else
  ok "does not reassign the bash built-in GROUPS"
fi

echo "==> CMMC groups documented"
# 'quality' was intentionally dropped when the starter cabinet was
# trimmed; don't assert it. If a future rebase reintroduces it, add
# it back here AND to the CMMC_GROUPS array in bootstrap.sh.
for g in filebrowser-admins management engineering operations sales compliance; do
  if grep -q "\b$g\b" "$BOOTSTRAP"; then
    ok "group '$g' present"
  else
    fail "group '$g' missing from bootstrap"
  fi
done

echo "==> password policy hits all CMMC complexity rules"
for rule in "length(12)" "digits(1)" "lowerCase(1)" "upperCase(1)" "specialChars(1)" "passwordHistory(5)" "forceExpiredPasswordChange(90)" "notUsername"; do
  if grep -q "$rule" "$BOOTSTRAP"; then
    ok "password policy contains '$rule'"
  else
    fail "password policy missing '$rule' (control 3.5.7/3.5.8 regression)"
  fi
done

echo "==> MFA defaults"
if grep -q '"bruteForceProtected": true' "$BOOTSTRAP"; then
  ok "brute-force protection enabled (3.1.8)"
else
  fail "brute-force protection not enabled"
fi
if grep -q '"failureFactor": 5' "$BOOTSTRAP"; then
  ok "failure factor = 5 (3.1.8)"
else
  fail "failure factor not set to 5"
fi
if grep -q 'CONFIGURE_TOTP' "$BOOTSTRAP"; then
  ok "TOTP required-action reference present (3.5.3)"
else
  fail "TOTP required-action not configured"
fi

echo "==> audit logging"
if grep -q '"eventsEnabled": true' "$BOOTSTRAP"; then
  ok "auth events enabled (3.3.1/3.3.2)"
else
  fail "auth events not enabled"
fi
if grep -q '"adminEventsEnabled": true' "$BOOTSTRAP"; then
  ok "admin events enabled (3.3.9)"
else
  fail "admin events not enabled"
fi

echo "==> PKCE S256 required on client"
if grep -q '"pkce.code.challenge.method": "S256"' "$BOOTSTRAP"; then
  ok "PKCE S256 pinned on the client (3.5.4)"
else
  fail "PKCE S256 not required on the client"
fi

echo "==> direct-access-grants disabled on client"
if grep -q '"directAccessGrantsEnabled": false' "$BOOTSTRAP"; then
  ok "direct-access-grants disabled (auth-code only)"
else
  fail "direct-access-grants not disabled"
fi

echo "==> amr mapper with pwd+otp"
if grep -q '"amr-hardcoded"' "$BOOTSTRAP" && grep -q '\[\\"pwd\\",\\"otp\\"\]' "$BOOTSTRAP"; then
  ok "amr hardcoded mapper emits pwd+otp"
else
  fail "amr mapper missing or wrong value"
fi

echo "==> groups claim mapper"
if grep -q 'oidc-group-membership-mapper' "$BOOTSTRAP"; then
  ok "groups membership mapper present"
else
  fail "groups claim mapper missing"
fi

echo "==> WebAuthn (FIDO2) peer-to-TOTP configuration"
# Sig algs restricted to FIPS-approved subset (ES256/RS256). Ed25519
# is explicitly NOT in the list because it isn't FIPS-approved.
if grep -q '"ES256"' "$BOOTSTRAP" && grep -q '"RS256"' "$BOOTSTRAP"; then
  ok "WebAuthn policy restricts signatures to ES256/RS256 (FIPS)"
else
  fail "WebAuthn policy missing ES256/RS256 sig-alg restriction"
fi
if grep -q 'webAuthnPolicySignatureAlgorithms.*Ed25519\|"EdDSA"' "$BOOTSTRAP"; then
  fail "WebAuthn policy contains Ed25519/EdDSA (NOT FIPS-approved)"
else
  ok "WebAuthn policy excludes EdDSA (CMMC FIPS posture intact)"
fi
if grep -q 'webAuthnPolicyUserVerificationRequirement' "$BOOTSTRAP"; then
  ok "WebAuthn user-verification policy set"
else
  fail "WebAuthn user-verification policy not configured"
fi
if grep -q 'webauthn-register' "$BOOTSTRAP"; then
  ok "webauthn-register required action referenced"
else
  fail "webauthn-register action not configured"
fi

echo "==> browser flow modified for WebAuthn as peer to TOTP"
# The clone POST uses escaped JSON inside a bash heredoc/string, so
# grep for the alias literal — robust against quote-escaping changes.
if grep -q 'browser-webauthn' "$BOOTSTRAP" && grep -q '/flows/browser/copy' "$BOOTSTRAP"; then
  ok "browser flow cloned as browser-webauthn"
else
  fail "browser flow not cloned (WebAuthn can't be added to built-in flows)"
fi
if grep -q '"provider":"webauthn-authenticator"' "$BOOTSTRAP"; then
  ok "webauthn-authenticator execution added to OTP subflow"
else
  fail "webauthn-authenticator not added to the browser flow"
fi
if grep -q 'auth-otp-form webauthn-authenticator\|"ALTERNATIVE"' "$BOOTSTRAP"; then
  ok "auth-otp-form + webauthn-authenticator flipped to ALTERNATIVE"
else
  fail "factors not set to ALTERNATIVE — one would still be REQUIRED"
fi
if grep -q 'browserFlow = \$f\|\.browserFlow = "browser-webauthn"' "$BOOTSTRAP"; then
  ok "realm browserFlow bound to browser-webauthn"
else
  fail "realm browserFlow not rebound; WebAuthn flow would be orphaned"
fi

echo "==> 2FA enrollment policy (TOTP forced + WebAuthn peer-at-login)"
# CMMC 3.5.3 requires MFA for privileged access. CONFIGURE_TOTP is
# kept as the baseline gate; a user cannot skip 2FA enrollment on
# first login. WebAuthn is an additive factor that users register
# from the Account Console AFTER onboarding; once registered, it's
# a peer choice at subsequent logins via the browser-webauthn flow.
if grep -q '"requiredActions": \["UPDATE_PASSWORD","CONFIGURE_TOTP"\]' "$BOOTSTRAP"; then
  ok "new users get UPDATE_PASSWORD + CONFIGURE_TOTP (3.5.3 baseline)"
else
  fail "user creation no longer forces CONFIGURE_TOTP — first-login 2FA bypass"
fi
if grep -q 'defaultAction = true' "$BOOTSTRAP"; then
  ok "CONFIGURE_TOTP is a realm default action (enforced on new users)"
else
  fail "CONFIGURE_TOTP defaultAction=false — users could skip 2FA"
fi

echo "==> idempotent re-run tolerance"
# The 409 from re-adding an existing webauthn execution must not
# abort bootstrap — a prior version's bug.
if grep -q '201|204|409\|409) :' "$BOOTSTRAP"; then
  ok "webauthn-authenticator re-add tolerates 409 (idempotent)"
else
  fail "409 on re-add not tolerated — second bootstrap run would fail"
fi

echo "==> Passwordless WebAuthn (third enrollment option)"
if grep -q 'webAuthnPolicyPasswordlessSignatureAlgorithms' "$BOOTSTRAP"; then
  ok "passwordless policy signature algorithms configured"
else
  fail "passwordless policy missing — sig algs unconstrained"
fi
if grep -q 'webAuthnPolicyPasswordlessUserVerificationRequirement.*"required"' "$BOOTSTRAP"; then
  ok "passwordless UV is required (PIN/biometric enforced)"
else
  fail "passwordless UV not required — would downgrade to single-factor"
fi
if grep -q 'webAuthnPolicyPasswordlessRequireResidentKey.*"Yes"' "$BOOTSTRAP"; then
  ok "passwordless requires resident key (username discoverable from key)"
else
  fail "resident key not required — passwordless UX reduced to type-username-then-tap"
fi
if grep -q 'webauthn-register-passwordless' "$BOOTSTRAP"; then
  ok "webauthn-register-passwordless required action referenced"
else
  fail "passwordless register action not configured"
fi
if grep -q 'webauthn-authenticator-passwordless' "$BOOTSTRAP"; then
  ok "webauthn-authenticator-passwordless added to browser flow"
else
  fail "passwordless login authenticator not in flow — key-alone login path absent"
fi

echo
echo "--- $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
