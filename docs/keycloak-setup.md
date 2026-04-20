# CMMC-opinionated Keycloak realm

`config/keycloak/bootstrap.sh` provisions a Keycloak realm configured to
the NIST SP 800-171 Rev 2 baseline in one command. Every setting it
applies is mapped below to the control it inherits.

## Running the bootstrap

```bash
KC_URL=http://localhost:8081 \
KC_ADMIN=admin \
KC_ADMIN_PASSWORD=<admin-password> \
REALM=cmmc \
REDIRECT_URI=https://filebrowser.your-domain.mil/api/auth/oidc/callback \
./config/keycloak/bootstrap.sh
```

The last line of stdout is the client secret — capture it out of shell
history and feed it to filebrowser as `FB_OIDC_CLIENT_SECRET`. Rerunning
the script rotates the secret, so do it once at install time.

Requires `curl` and `jq` on the machine running the script.

## Controls inherited from this realm configuration

| Setting | Value | Control |
|---|---|---|
| `passwordPolicy` | length(12), digits, lower/upper, special, history(5), 90-day expiry, notUsername | 3.5.7, 3.5.8 |
| `bruteForceProtected` | true, failureFactor=5, waitIncrement=60s, max=900s | 3.1.8 |
| `ssoSessionIdleTimeout` | 1800s (30 min) | 3.1.10 |
| `ssoSessionMaxLifespan` | 28800s (8 hours) | 3.1.11 |
| `accessTokenLifespan` | 600s (10 min) | 3.1.11 |
| CONFIGURE_TOTP default action | enabled, defaultAction=true | 3.5.3 |
| `otpPolicyAlgorithm` | HmacSHA256 (FIPS-approved) | 3.13.11 |
| `eventsEnabled` + `adminEventsEnabled` | true, 180-day retention | 3.3.1, 3.3.2, 3.3.9 |
| `sslRequired` | external (allows localhost dev) | 3.13.8 |
| `registrationAllowed` | false (admins provision) | 3.1.5 |
| `editUsernameAllowed` | false (identifier stability) | 3.1.1, 3.5.5 |
| `rememberMe` | false | 3.5.4 |
| `duplicateEmailsAllowed` | false | 3.5.1 |
| Client `pkce.code.challenge.method` | S256 (required) | 3.5.4 |
| Client `directAccessGrantsEnabled` | false (auth-code only) | 3.13.15 |
| `clientAuthenticatorType` | client-secret, confidential | 3.13.15 |

## Default groups

Created empty and ready to populate with users:

- `filebrowser-admins` → maps to `Perm.Admin=true` via `FB_OIDC_ADMIN_GROUPS`
- `management`
- `engineering`
- `operations`
- `quality`
- `sales`
- `compliance` — reserved for the audit-admin role (separation-of-duties per 3.3.9 / 3.1.4)

The group membership is surfaced to filebrowser via the `oidc-group-
membership-mapper` on the filebrowser client, emitted as the `groups`
claim in the id_token.

## The amr-hardcoded protocol mapper — known tradeoff

Keycloak 26 does not emit an `amr` claim by default; it emits
`acr: "1"` for all logins regardless of whether MFA was used. The
bootstrap adds a `oidc-hardcoded-claim-mapper` that injects
`amr: ["pwd", "otp"]` into every id_token emitted for the filebrowser
client.

**This is only truthful because** the realm enforces:

1. `CONFIGURE_TOTP` as a `defaultAction` — every new user is forced
   through TOTP setup on first login.
2. The default `browser` authentication flow's `Browser - Conditional
   OTP` subflow — any user who has TOTP configured is prompted for
   their code on subsequent logins.

**Breaks if an admin removes a user's OTP credential without also
revoking group membership.** Mitigations:

- Use the Keycloak admin event log (enabled by this script, 180-day
  retention) to alert on `REMOVE_TOTP` events to `compliance`.
- For a stronger guarantee, replace the Conditional OTP step in the
  auth flow with a hard-required OTP step. Tracked in the project
  memory as a follow-up to the v1 MFA work.

A production-hardened alternative is Keycloak's Level-of-Assurance
(LoA) mechanism: configure the auth flow to emit `acr=mfa` when
OTP was used, set the client's "Default ACR Values" to require
`acr=mfa`, and point filebrowser at `FB_OIDC_MFA_CLAIM=acr`. This
binds the claim to what Keycloak actually enforced rather than a
hardcoded value.

## Adding users

The bootstrap only creates empty groups. Users are provisioned
separately. Example for adding an engineer via the admin REST API:

```bash
TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$KC_ADMIN&password=$KC_ADMIN_PASSWORD&grant_type=password&client_id=admin-cli" \
  | jq -r .access_token)

# Create user with the CONFIGURE_TOTP required action
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$KC_URL/admin/realms/cmmc/users" \
  -d '{"username":"alice","enabled":true,"emailVerified":true,
       "email":"alice@cmmc.local","firstName":"Alice","lastName":"Engineer",
       "requiredActions":["CONFIGURE_TOTP"]}'

ALICE_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/cmmc/users?username=alice" | jq -r '.[0].id')

# Set initial password (must satisfy policy: 12+ chars, complexity)
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$KC_URL/admin/realms/cmmc/users/$ALICE_ID/reset-password" \
  -d '{"type":"password","value":"<initial-password>","temporary":true}'

# Add to engineering group
ENG_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/cmmc/groups" | jq -r '.[] | select(.name=="engineering") | .id')
curl -s -X PUT -H "Authorization: Bearer $TOKEN" \
  "$KC_URL/admin/realms/cmmc/users/$ALICE_ID/groups/$ENG_ID"
```

On first login, alice will be forced through TOTP setup, then prompted
for the TOTP code on every subsequent session.

## Non-CMMC requirements this script deliberately does NOT set

- **Kerberos / LDAP federation** — up to the deployment; the realm
  is configured to work with local Keycloak users only.
- **Email SMTP** — intentionally unconfigured. Outbound email (including
  password reset and CUI sharing) is out of MVP scope — see
  [architecture § 10](./architecture.md). The realm ships with
  `verifyEmail: false` so no operator intervention is needed on
  first login. If an operator wants password-reset-by-email they
  wire their own SMTP into Keycloak; it's pure Keycloak config,
  not an appliance concern.
- **Identity providers / social logins** — disabled by default;
  enable only with customer approval.
- **WebAuthn / FIDO2** — not configured; recommended as an upgrade
  from TOTP once assessor accepts the WebAuthn attestation path.
- **Themes / branding** — left at Keycloak defaults.
