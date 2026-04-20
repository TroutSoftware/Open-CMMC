#!/usr/bin/env bash
#
# CMMC-Filebrowser — Keycloak realm bootstrap.
#
# Creates (or updates) a realm configured to NIST SP 800-171 Rev 2
# baseline: MFA-required default action, password complexity + history,
# brute-force lockout, session timeouts, audit event logging, PKCE-only
# client. Every setting is mapped to a control in the adjacent
# docs/keycloak-setup.md.
#
# Usage:
#   KC_URL=http://localhost:8081 \
#   KC_ADMIN=admin \
#   KC_ADMIN_PASSWORD=admin \
#   REALM=cmmc \
#   REDIRECT_URI=http://localhost:8080/api/auth/oidc/callback \
#   ./config/keycloak/bootstrap.sh
#
# On success, prints the generated filebrowser client secret on the last
# line of stdout (keep it out of shell history).

set -euo pipefail

KC_URL="${KC_URL:-https://localhost:8081}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-admin}"
REALM="${REALM:-cmmc}"
CLIENT_ID="${CLIENT_ID:-filebrowser}"
# Prefer FB_OIDC_REDIRECT_URI (the value filebrowser actually sends)
# when set, so a fresh-install on a non-localhost host (e.g. a VM at
# 192.168.x.y) matches the appliance's runtime config without a
# second-hop override. Explicit REDIRECT_URI still wins.
REDIRECT_URI="${REDIRECT_URI:-${FB_OIDC_REDIRECT_URI:-https://localhost:8080/api/auth/oidc/callback}}"
WEB_ORIGIN="${WEB_ORIGIN:-$(dirname "$REDIRECT_URI" | sed 's|/api/auth/oidc$||')}"

# REDIRECT_URIS / WEB_ORIGINS — space-separated lists used to register
# MULTIPLE redirect URIs on the filebrowser client. Filebrowser sends
# a per-request redirect_uri matching the origin the user browsed in
# on (IP vs hostname); KC must accept both. install.sh passes both
# the IP-based and hostname-based URIs here.
# Falls back to the single REDIRECT_URI / WEB_ORIGIN pair for legacy
# single-origin callers.
REDIRECT_URIS="${REDIRECT_URIS:-$REDIRECT_URI}"
WEB_ORIGINS="${WEB_ORIGINS:-$WEB_ORIGIN}"
# Extra curl flags for the admin API calls. Defaults to empty; set
# CURL_OPTS="-k" to skip TLS verification against a self-signed KC
# cert (install.sh sets this when the TLS phase generated a dev CA).
# Production deployments with a trusted CA leave CURL_OPTS empty so
# man-in-the-middle probes actually fail.
CURL_OPTS="${CURL_OPTS:-}"

# NOTE: bash reserves `GROUPS` as a readonly built-in array of the
# current user's system group IDs — assigning to it is silently ignored.
# Use a distinct name to avoid that trap.
CMMC_GROUPS=(filebrowser-admins management engineering operations sales compliance)

log() { printf '\n==> %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "$1 not found on PATH"; }
require curl
require jq

# --- 1. Acquire admin token ------------------------------------------------

log "Acquiring admin token from $KC_URL"
# shellcheck disable=SC2086  # $CURL_OPTS is intentionally word-split
TOKEN=$(curl $CURL_OPTS -fsS -X POST \
  "$KC_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$KC_ADMIN" \
  -d "password=$KC_ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r .access_token)

[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || die "admin token fetch failed"
AUTH="Authorization: Bearer $TOKEN"

# Wrap curl with auth header for brevity. $CURL_OPTS (e.g. -k for
# self-signed dev) propagates to every call.
kc() {
  local method="$1" path="$2"
  shift 2
  # shellcheck disable=SC2086
  curl $CURL_OPTS -fsS -X "$method" "$KC_URL$path" -H "$AUTH" "$@"
}
kc_status() {
  local method="$1" path="$2"
  shift 2
  # shellcheck disable=SC2086
  curl $CURL_OPTS -s -o /dev/null -w '%{http_code}' -X "$method" "$KC_URL$path" -H "$AUTH" "$@"
}

# --- 2. Create or update the realm ----------------------------------------

log "Ensuring realm '$REALM' exists with CMMC baseline"

# CMMC control mappings:
#   passwordPolicy     → 3.5.7 (complexity), 3.5.8 (history+expiry)
#   bruteForceProtected→ 3.1.8 (unsuccessful logon attempts)
#   ssoSessionIdleTimeout → 3.1.10 (session lock — enforced at app re-auth)
#   ssoSessionMaxLifespan → 3.1.11 (session termination after defined period)
#   accessTokenLifespan   → 3.1.11 (short-lived bearer for back-channel)
#   eventsEnabled/adminEventsEnabled → 3.3.1, 3.3.2, 3.3.9
#   sslRequired=external  → 3.13.8 (crypto on transmission; localhost excepted for dev)
#   registrationAllowed=false → 3.1.5 / 3.5.3 (admins provision)
#   editUsernameAllowed=false → 3.1.1 / 3.5.5 (identifier stability)
REALM_JSON=$(cat <<EOF
{
  "realm": "$REALM",
  "enabled": true,
  "displayName": "CMMC Filebrowser",
  "displayNameHtml": "<div style='text-align:center;text-transform:none;font-family:system-ui,sans-serif;'><div style='font-size:22px;font-weight:600;letter-spacing:.01em;text-transform:none;'>CMMC Filebrowser</div><div style='font-size:12px;font-weight:400;opacity:.8;margin-top:4px;text-transform:none;'>Controlled Unclassified Information — authorized use only</div><div style='margin:14px auto 0;max-width:30em;padding:8px 10px;background:#fff4e5;border:1px solid #d89a3e;border-left:3px solid #d89a3e;color:#4a2e00;font-size:11px;line-height:1.45;text-align:left;text-transform:none;border-radius:2px;'><strong style='color:#a8590e;text-transform:none;'>Notice:</strong> This system may process, store, or transmit CUI under NIST SP 800-171 / CMMC L2. All activity is logged and monitored. By continuing you consent to monitoring; unauthorized access may result in civil and criminal penalties under 18 U.S.C. § 1030.</div></div>",
  "sslRequired": "external",
  "registrationAllowed": false,
  "registrationEmailAsUsername": false,
  "rememberMe": false,
  "verifyEmail": false,
  "loginWithEmailAllowed": false,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "permanentLockout": false,
  "failureFactor": 5,
  "waitIncrementSeconds": 60,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 43200,
  "passwordPolicy": "length(12) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1) and passwordHistory(5) and forceExpiredPasswordChange(90) and notUsername(undefined)",
  "otpPolicyType": "totp",
  "otpPolicyAlgorithm": "HmacSHA256",
  "otpPolicyDigits": 6,
  "otpPolicyLookAheadWindow": 1,
  "otpPolicyPeriod": 30,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 28800,
  "accessTokenLifespan": 600,
  "accessCodeLifespan": 60,
  "accessCodeLifespanUserAction": 300,
  "offlineSessionIdleTimeout": 2592000,
  "eventsEnabled": true,
  "eventsExpiration": 15552000,
  "adminEventsEnabled": true,
  "adminEventsDetailsEnabled": true,
  "enabledEventTypes": [
    "LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR",
    "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
    "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR",
    "UPDATE_TOTP", "REMOVE_TOTP",
    "REGISTER", "REGISTER_ERROR",
    "REMOVE_FEDERATED_IDENTITY",
    "USER_INFO_REQUEST",
    "GRANT_CONSENT", "REVOKE_GRANT",
    "IDENTITY_PROVIDER_LINK_ACCOUNT",
    "IMPERSONATE",
    "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR"
  ]
}
EOF
)

# Check if realm exists.
EXISTS_CODE=$(kc_status GET "/admin/realms/$REALM")
if [ "$EXISTS_CODE" = "200" ]; then
  log "Realm exists; updating"
  kc PUT "/admin/realms/$REALM" -H "Content-Type: application/json" -d "$REALM_JSON" >/dev/null
elif [ "$EXISTS_CODE" = "404" ]; then
  log "Realm does not exist; creating"
  kc POST "/admin/realms" -H "Content-Type: application/json" -d "$REALM_JSON" >/dev/null
else
  die "unexpected status $EXISTS_CODE querying realm"
fi

# --- 3. TOTP as required action default ------------------------------------

log "Making CONFIGURE_TOTP a default required action (CMMC 3.5.3)"
# Mandatory TOTP enrollment on first login is the baseline 2FA
# guarantee. The "Conditional OTP" subflow in the KC browser flow
# uses "User Configured" as its gate — if the user has no OTP
# credential, the whole subflow SKIPS, meaning ALTERNATIVE factors
# inside it are never offered. Without a forced enrollment, a user
# could complete UPDATE_PASSWORD and land in the app with zero 2FA.
# CMMC 3.5.3 requires multi-factor for privileged/remote access, so
# we keep CONFIGURE_TOTP as the baseline gate. WebAuthn is offered
# at login as a peer alternative (see 3b below) and as an ADDITIONAL
# factor users can register from the Account Console.
ACTION_JSON=$(kc GET "/admin/realms/$REALM/authentication/required-actions/CONFIGURE_TOTP")
UPDATED=$(echo "$ACTION_JSON" | jq '.enabled = true | .defaultAction = true')
kc PUT "/admin/realms/$REALM/authentication/required-actions/CONFIGURE_TOTP" \
  -H "Content-Type: application/json" -d "$UPDATED" >/dev/null

# --- 3b. WebAuthn (FIDO2) as peer 2FA option -------------------------------
#
# FIDO2 physical keys (YubiKey, Nitrokey, Titan, plus DoD CAC/PIV via
# WebAuthn CTAP2) are a stronger factor than TOTP: phishing-resistant
# (NIST 800-63B AAL3), replay-resistant (CMMC 3.5.4), and no shared
# secret to leak. We offer them as a peer to the authenticator-app
# factor so users can pick whichever fits — the flow accepts either.
#
# Policy notes:
#   - Signature algorithms restricted to FIPS-approved subset:
#     ES256 (ECDSA P-256 + SHA-256; YubiKey 5 FIPS series + CAC/PIV)
#     RS256 (RSASSA-PKCS1-v1_5 + SHA-256; fallback).
#     Ed25519 is deliberately EXCLUDED — NOT FIPS-approved.
#   - User verification = "preferred" so authenticators that can
#     elevate (PIN / biometric) do so without locking out keys that
#     can't (U2F-only devices). "required" would break CAC enrollment
#     on older card stacks.

log "Configuring WebAuthn policy (FIPS-approved signatures only)"
CURRENT_REALM_JSON=$(kc GET "/admin/realms/$REALM")
WA_REALM_JSON=$(echo "$CURRENT_REALM_JSON" | jq '. + {
  webAuthnPolicySignatureAlgorithms: ["ES256","RS256"],
  webAuthnPolicyUserVerificationRequirement: "preferred",
  webAuthnPolicyAttestationConveyancePreference: "not specified",
  webAuthnPolicyAuthenticatorAttachment: "not specified",
  webAuthnPolicyRequireResidentKey: "not specified",
  webAuthnPolicyCreateTimeout: 60,
  webAuthnPolicyAvoidSameAuthenticatorRegister: true,
  webAuthnPolicyRpEntityName: "CMMC Filebrowser"
}')
kc PUT "/admin/realms/$REALM" \
  -H "Content-Type: application/json" -d "$WA_REALM_JSON" >/dev/null

log "Enabling 'webauthn-register' required action (optional, user-initiated)"
# enabled=true makes the action available; defaultAction=false means
# new users aren't forced to register a key on first login (TOTP is
# still the default). Users add a key via the Account Console when
# they want the stronger factor.
WA_ACTION=$(kc GET "/admin/realms/$REALM/authentication/required-actions/webauthn-register")
WA_UPDATED=$(echo "$WA_ACTION" | jq '.enabled = true | .defaultAction = false')
kc PUT "/admin/realms/$REALM/authentication/required-actions/webauthn-register" \
  -H "Content-Type: application/json" -d "$WA_UPDATED" >/dev/null

log "Adding WebAuthn as ALTERNATIVE to OTP in browser flow"
# KC's default "browser" flow ends in a "Browser - Conditional OTP"
# subflow that only prompts for TOTP. We clone the flow (built-ins
# aren't editable), then ADD webauthn-authenticator as an
# ALTERNATIVE execution alongside auth-otp-form. After that:
#   - user with TOTP enrolled → prompted for TOTP
#   - user with WebAuthn enrolled → prompted for WebAuthn
#   - user with both → KC shows chooser
FLOW_ALIAS="browser-webauthn"
# Copy is idempotent at the ALIAS level: KC may report GET=404 even
# when a prior failed run left partial state, so we ALWAYS attempt
# the copy and tolerate 409 (already-exists). 201 and 409 are both
# "flow is now ready"; anything else is a real error.
COPY_CODE=$(kc_status POST "/admin/realms/$REALM/authentication/flows/browser/copy" \
  -H "Content-Type: application/json" \
  -d "{\"newName\":\"$FLOW_ALIAS\"}")
case "$COPY_CODE" in
  201|204|409) : ;;  # created | no-content | already-exists
  *) die "cloning browser flow to $FLOW_ALIAS failed: HTTP $COPY_CODE" ;;
esac

# Get executions of the cloned flow; find the OTP subflow's child-
# flow alias (the alias KC assigned when copying the subflow).
EXECS=$(kc GET "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions")
OTP_SUBFLOW_FLOW_ID=$(echo "$EXECS" | jq -r '
  .[] | select(.displayName // "" | test("Conditional OTP"; "i")) | .flowId
' | head -1)

if [ -n "$OTP_SUBFLOW_FLOW_ID" ] && [ "$OTP_SUBFLOW_FLOW_ID" != "null" ]; then
  # Look up the subflow's alias from its id (list all flows).
  ALL_FLOWS=$(kc GET "/admin/realms/$REALM/authentication/flows")
  OTP_SUBFLOW_ALIAS=$(echo "$ALL_FLOWS" | jq -r --arg id "$OTP_SUBFLOW_FLOW_ID" \
    '.[] | select(.id == $id) | .alias')

  if [ -n "$OTP_SUBFLOW_ALIAS" ]; then
    # Add webauthn-authenticator to the OTP subflow. Two paths are
    # both valid outcomes:
    #   - first run on a fresh flow → POST returns 201
    #   - re-run on a flow that already has it → POST returns 409
    # We accept both; anything else is a real error. `kc POST` uses
    # curl -fsS which would fail on 409, so switch to a status probe
    # and only hard-fail on unexpected codes.
    ADD_CODE=$(kc_status POST \
      "/admin/realms/$REALM/authentication/flows/$OTP_SUBFLOW_ALIAS/executions/execution" \
      -H "Content-Type: application/json" \
      -d '{"provider":"webauthn-authenticator"}')
    case "$ADD_CODE" in
      201|204|409) : ;;  # created | no-content | already-exists — all fine
      *) die "adding webauthn-authenticator to $OTP_SUBFLOW_ALIAS failed: HTTP $ADD_CODE" ;;
    esac

    # Re-fetch executions now that webauthn-authenticator exists;
    # flip both auth-otp-form and webauthn-authenticator to
    # ALTERNATIVE so either satisfies the 2FA requirement.
    EXECS=$(kc GET "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions")
    for provider in auth-otp-form webauthn-authenticator; do
      EXEC_JSON=$(echo "$EXECS" | jq --arg p "$provider" \
        '.[] | select(.providerId == $p) | .requirement = "ALTERNATIVE"')
      if [ -n "$EXEC_JSON" ] && [ "$EXEC_JSON" != "null" ]; then
        kc PUT "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions" \
          -H "Content-Type: application/json" -d "$EXEC_JSON" >/dev/null
      fi
    done
  fi
fi

# --- 3c. Passwordless WebAuthn as TOP-LEVEL login alternative --------------
#
# Separate from the 2FA WebAuthn in 3b: passwordless = username + key only.
# The key PLUS its PIN/biometric UV is inherently two factors (possession +
# knowledge/inherence), satisfies NIST 800-63B AAL3, and is phishing-
# resistant. This is how DoD CAC/PIV cards authenticate.
#
# Key differences from the 2FA WebAuthn policy:
#   - UserVerification = "required" (not "preferred") — passwordless REQUIRES
#     PIN or biometric because there's no password to pair with.
#   - RequireResidentKey = "Yes" so the username can be discovered from the
#     key itself (tap-to-sign-in UX). YubiKey 5 supports ~25 resident keys.
#   - Stored as a DIFFERENT credential type in KC (webauthn-passwordless vs
#     webauthn), so a user can register the same physical key twice — once
#     as 2FA, once as passwordless — or just once as passwordless.
#
# FIPS sig alg subset matches 3b — ES256 + RS256, no Ed25519.

log "Configuring WebAuthn Passwordless policy (FIPS-approved, UV required)"
CURRENT_REALM_PL=$(kc GET "/admin/realms/$REALM")
PL_POLICY_JSON=$(echo "$CURRENT_REALM_PL" | jq '. + {
  webAuthnPolicyPasswordlessSignatureAlgorithms: ["ES256","RS256"],
  webAuthnPolicyPasswordlessUserVerificationRequirement: "required",
  webAuthnPolicyPasswordlessAttestationConveyancePreference: "not specified",
  webAuthnPolicyPasswordlessAuthenticatorAttachment: "not specified",
  webAuthnPolicyPasswordlessRequireResidentKey: "Yes",
  webAuthnPolicyPasswordlessCreateTimeout: 60,
  webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: true,
  webAuthnPolicyPasswordlessRpEntityName: "CMMC Filebrowser"
}')
kc PUT "/admin/realms/$REALM" \
  -H "Content-Type: application/json" -d "$PL_POLICY_JSON" >/dev/null

log "Enabling 'webauthn-register-passwordless' required action (opt-in)"
WAPL_ACTION=$(kc GET "/admin/realms/$REALM/authentication/required-actions/webauthn-register-passwordless")
WAPL_UPDATED=$(echo "$WAPL_ACTION" | jq '.enabled = true | .defaultAction = false')
kc PUT "/admin/realms/$REALM/authentication/required-actions/webauthn-register-passwordless" \
  -H "Content-Type: application/json" -d "$WAPL_UPDATED" >/dev/null

log "Adding passwordless WebAuthn to browser flow as top-level ALTERNATIVE"
# Added at the TOP level of browser-webauthn (not inside the OTP subflow
# like the 2FA WebAuthn) so the login page shows BOTH options side-by-
# side: the standard username/password form, AND a "Sign in with
# security key" button. Users with a passwordless credential registered
# can click the button, tap their key, and skip the password step
# entirely. Users without a passwordless credential can still use the
# password + 2FA path unchanged.
EXECS_PL=$(kc GET "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions")
HAS_WAPL=$(echo "$EXECS_PL" | jq -r 'any(.providerId == "webauthn-authenticator-passwordless")')
if [ "$HAS_WAPL" != "true" ]; then
  ADD_PL_CODE=$(kc_status POST \
    "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions/execution" \
    -H "Content-Type: application/json" \
    -d '{"provider":"webauthn-authenticator-passwordless"}')
  case "$ADD_PL_CODE" in
    201|204|409) : ;;
    *) die "adding webauthn-authenticator-passwordless to $FLOW_ALIAS failed: HTTP $ADD_PL_CODE" ;;
  esac
fi

# Flip the passwordless authenticator to ALTERNATIVE so it's offered
# as a login option alongside Browser Forms. Newly added executions
# default to DISABLED; without this step, the button never renders.
EXECS_PL=$(kc GET "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions")
WAPL_EXEC=$(echo "$EXECS_PL" | jq \
  '.[] | select(.providerId == "webauthn-authenticator-passwordless") | .requirement = "ALTERNATIVE"')
if [ -n "$WAPL_EXEC" ] && [ "$WAPL_EXEC" != "null" ]; then
  kc PUT "/admin/realms/$REALM/authentication/flows/$FLOW_ALIAS/executions" \
    -H "Content-Type: application/json" -d "$WAPL_EXEC" >/dev/null
fi

log "Binding browser-webauthn as realm browser flow"
BOUND_REALM=$(kc GET "/admin/realms/$REALM" | jq --arg f "$FLOW_ALIAS" '.browserFlow = $f')
kc PUT "/admin/realms/$REALM" \
  -H "Content-Type: application/json" -d "$BOUND_REALM" >/dev/null

# --- 4. Groups -------------------------------------------------------------

log "Ensuring groups: ${CMMC_GROUPS[*]}"
EXISTING=$(kc GET "/admin/realms/$REALM/groups" | jq -r '.[].name')
for g in "${CMMC_GROUPS[@]}"; do
  if echo "$EXISTING" | grep -qx "$g"; then
    printf '    = %s (exists)\n' "$g" >&2
  else
    kc POST "/admin/realms/$REALM/groups" \
      -H "Content-Type: application/json" \
      -d "{\"name\": \"$g\"}" >/dev/null
    printf '    + %s (created)\n' "$g" >&2
  fi
done

# --- 5. Filebrowser client -------------------------------------------------

log "Ensuring client '$CLIENT_ID' with PKCE + groups mapper"
# CMMC control mappings:
#   publicClient=false → client authentication required (3.13.15)
#   standardFlowEnabled + directAccessGrantsEnabled=false → authorization-code only
#   pkce.code.challenge.method=S256 → 3.5.4 replay resistance

# Convert space-separated REDIRECT_URIS + WEB_ORIGINS into JSON arrays.
# jq is already a hard dep of this script, so we use it to build the
# arrays safely (correct quoting for URLs with : and /).
REDIRECT_URIS_JSON=$(printf '%s\n' $REDIRECT_URIS | jq -R . | jq -sc .)
WEB_ORIGINS_JSON=$(printf '%s\n' $WEB_ORIGINS | jq -R . | jq -sc .)

CLIENT_JSON=$(cat <<EOF
{
  "clientId": "$CLIENT_ID",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "authorizationServicesEnabled": false,
  "rootUrl": "$WEB_ORIGIN",
  "baseUrl": "$WEB_ORIGIN",
  "redirectUris": $REDIRECT_URIS_JSON,
  "webOrigins": $WEB_ORIGINS_JSON,
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "access.token.lifespan": "600",
    "client.session.idle.timeout": "1800",
    "client.session.max.lifespan": "28800",
    "require.pushed.authorization.requests": "false",
    "post.logout.redirect.uris": "$WEB_ORIGIN/*",
    "frontchannel.logout.url": "",
    "backchannel.logout.session.required": "true"
  },
  "protocolMappers": [
    {
      "name": "groups",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-group-membership-mapper",
      "consentRequired": false,
      "config": {
        "full.path": "false",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "claim.name": "groups",
        "userinfo.token.claim": "true"
      }
    },
    {
      "name": "amr-hardcoded",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-hardcoded-claim-mapper",
      "consentRequired": false,
      "config": {
        "claim.name": "amr",
        "claim.value": "[\"pwd\",\"otp\"]",
        "jsonType.label": "JSON",
        "id.token.claim": "true",
        "access.token.claim": "false",
        "userinfo.token.claim": "false"
      }
    }
  ]
}
EOF
)

# Look up existing client by clientId.
EXISTING_UUID=$(kc GET "/admin/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id // empty')
if [ -n "$EXISTING_UUID" ]; then
  log "Client exists ($EXISTING_UUID); updating"
  kc PUT "/admin/realms/$REALM/clients/$EXISTING_UUID" \
    -H "Content-Type: application/json" -d "$CLIENT_JSON" >/dev/null
  CLIENT_UUID="$EXISTING_UUID"
else
  log "Creating client"
  kc POST "/admin/realms/$REALM/clients" \
    -H "Content-Type: application/json" -d "$CLIENT_JSON" >/dev/null
  CLIENT_UUID=$(kc GET "/admin/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
fi

# --- 6. Rotate client secret -----------------------------------------------

log "Regenerating client secret"
SECRET=$(kc POST "/admin/realms/$REALM/clients/$CLIENT_UUID/client-secret" | jq -r .value)
[ -n "$SECRET" ] && [ "$SECRET" != "null" ] || die "secret generation failed"

# --- 7. Seed users ---------------------------------------------------------
#
# A small opinionated roster modeled on a typical midsize DIB contractor
# so the product boots with a realistic, demoable org from the first
# install. Every user:
#   * has a temporary password the script prints at the end (CMMC 3.5.7
#     initial password, stronger than shipped-with-product secret),
#   * is marked UPDATE_PASSWORD + CONFIGURE_TOTP so first login
#     forces rotation + TOTP enrollment (3.5.3 / 3.5.7). WebAuthn
#     (FIDO2) is offered as a peer factor at LOGIN time — once the
#     user finishes onboarding, they can add a security key from
#     the Account Console and pick it on subsequent logins,
#   * is enabled and emailVerified (no admin-moderation step needed),
#   * belongs to one or more of the groups created in section 4.
#
# Disable this block with SEED_USERS=0 for production deployments that
# manage identity exclusively via IdP federation.
SEED_USERS="${SEED_USERS:-1}"

# user roster: username:email:firstname:lastname:groups(comma-separated)
# Groups must already exist in CMMC_GROUPS. filebrowser-admins promotes
# the user to perm.admin on the filebrowser side via the cmmc-admins
# role mapping; compliance is the ISSO function; sales intentionally
# has NO CUI-bearing group so the starter org shows clean separation.
CMMC_USERS=(
  "dana:dana@example.local:Dana:Reyes:filebrowser-admins,compliance"
  "alice:alice@example.local:Alice:Chen:engineering"
  "bob:bob@example.local:Bob:Ortega:operations"
  "carol:carol@example.local:Carol:Kim:management"
  "dave:dave@example.local:Dave:Nguyen:sales"
)

TEMP_PASSWORD="${SEED_TEMP_PASSWORD:-WelcomeCMMC2026!}"

seed_user() {
  local username="$1" email="$2" first="$3" last="$4" groups_csv="$5"

  # Create if missing; on re-runs, preserve the existing row so MFA
  # secrets and password changes survive — only top up group
  # membership so the roster stays consistent with the source of
  # truth (this file).
  local uid status
  uid=$(kc GET "/admin/realms/$REALM/users?username=$username&exact=true" | jq -r '.[0].id // empty')
  if [ -n "$uid" ]; then
    status="exists"
  else
    local payload
    payload=$(cat <<EOF
{
  "username": "$username",
  "email": "$email",
  "firstName": "$first",
  "lastName": "$last",
  "enabled": true,
  "emailVerified": true,
  "requiredActions": ["UPDATE_PASSWORD","CONFIGURE_TOTP"],
  "credentials": [{"type":"password","value":"$TEMP_PASSWORD","temporary":true}]
}
EOF
)
    kc POST "/admin/realms/$REALM/users" -H "Content-Type: application/json" -d "$payload" >/dev/null
    uid=$(kc GET "/admin/realms/$REALM/users?username=$username&exact=true" | jq -r '.[0].id')
    status="created"
  fi

  # Idempotent group join. PUT on a group-id the user already belongs
  # to is a no-op in KC; missing joins are added.
  IFS=',' read -r -a groups <<< "$groups_csv"
  for g in "${groups[@]}"; do
    local gid
    gid=$(kc GET "/admin/realms/$REALM/groups" | jq -r ".[] | select(.name==\"$g\") | .id")
    [ -n "$gid" ] || { printf '    ! %s: group %s not found\n' "$username" "$g" >&2; continue; }
    kc PUT "/admin/realms/$REALM/users/$uid/groups/$gid" >/dev/null
  done
  printf '    %s %s (groups=%s)\n' \
    "$([ "$status" = "created" ] && echo + || echo =)" \
    "$username" "$groups_csv" >&2
}

if [ "$SEED_USERS" = "1" ]; then
  log "Seeding starter users"
  for entry in "${CMMC_USERS[@]}"; do
    IFS=':' read -r u e f l g <<< "$entry"
    seed_user "$u" "$e" "$f" "$l" "$g"
  done
fi

# --- 8. Done ---------------------------------------------------------------

log "Realm '$REALM' configured. Client secret follows on stdout (single line)."
if [ "$SEED_USERS" = "1" ]; then
  log "Seeded users use temp password: $TEMP_PASSWORD (forced rotation + TOTP on first login)"
fi
echo "$SECRET"
