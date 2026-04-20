# OIDC Providers — v1 Supported Identity Providers

> **Scope.** This document describes the three OIDC identity providers that
> CMMC-Filebrowser **must** support at v1 general availability. These are the
> only providers a CMMC L2 assessor will see referenced in our System Security
> Plan (SSP) for AC-2 (Account Management), IA-2 (Identification and
> Authentication), and IA-5 (Authenticator Management).
>
> Operators are expected to configure **one** of these three providers. The
> fallback `access-gate` profile (username/password + TOTP, fully local,
> FIPS-validated PBKDF2) is **future work** — it is not wired in v1 and is
> tracked separately under the `access-gate` epic. If you need a local auth
> path before it ships, deploy Keycloak on the same host and treat it as the
> "local" IdP.

---

## Table of contents

1. [Provider matrix](#provider-matrix)
2. [Common configuration](#common-configuration)
3. [FIPS algorithm constraint](#fips-algorithm-constraint)
4. [Microsoft Entra ID in GCC High](#microsoft-entra-id-in-gcc-high)
5. [Keycloak (self-hosted, incl. FIPS-on-RHEL)](#keycloak-self-hosted-incl-fips-on-rhel)
6. [Okta for Government High](#okta-for-government-high)
7. [SSP cross-references](#ssp-cross-references)
8. [Troubleshooting checklist](#troubleshooting-checklist)

---

## Provider matrix

| Provider                  | Tenant boundary                | FedRAMP authorization           | Typical CMMC L2 fit                                  | MFA claim convention         |
| ------------------------- | ------------------------------ | ------------------------------- | ---------------------------------------------------- | ---------------------------- |
| Microsoft Entra ID (GCC High) | US sovereign cloud, `.us` TLD | FedRAMP High (via Azure Gov)    | Primary — most DoD primes and subs                    | `amr` array contains `"mfa"` |
| Keycloak (self-hosted)    | Customer-operated              | Inherits host environment       | Airgap / on-prem; FIPS-on-RHEL variant ships with us | `acr` = `"1"` or `"2"`       |
| Okta for Government High  | US Gov tenant, `.okta.gov`     | FedRAMP High                    | ~15-20% of contractors                               | `amr` array contains `"mfa"` |

---

## Common configuration

All three providers share the same redirect URI pattern and the same minimum
scope set. The operator-facing environment file lives at
`/etc/cmmc-filebrowser/environment` and is read by the systemd unit on start.

### Redirect URI

```
https://{filebrowser_host}/api/auth/oidc/callback
```

There is exactly **one** redirect URI per deployment. Register that exact
string (case-sensitive, no trailing slash) in the provider. Wildcard hosts are
rejected by all three providers for confidential clients; use per-environment
app registrations instead (dev, staging, prod).

### Minimum scopes

Every provider requires:

```
openid profile email
```

Additional scopes are provider-specific and noted in each section below.

### Common environment variables

| Variable                   | Required | Notes                                                                 |
| -------------------------- | -------- | --------------------------------------------------------------------- |
| `FB_OIDC_ISSUER`           | yes      | The `iss` claim value. Discovery document must live at `{iss}/.well-known/openid-configuration`. |
| `FB_OIDC_CLIENT_ID`        | yes      | Confidential client ID issued by the provider.                        |
| `FB_OIDC_CLIENT_SECRET`    | yes      | Stored with mode `0600`, owned by `cmmc-filebrowser:cmmc-filebrowser`.|
| `FB_OIDC_REDIRECT_URI`     | yes      | Must match the string registered in the provider, exactly.            |
| `FB_OIDC_SCOPES`           | yes      | Space-separated list; always starts with `openid profile email`.      |
| `FB_OIDC_USERNAME_CLAIM`   | yes      | Claim used as the canonical username. Default: `preferred_username`.  |
| `FB_OIDC_GROUPS_CLAIM`     | no       | Claim holding the user's group list. Default: `groups`.               |
| `FB_OIDC_ADMIN_GROUPS`     | no       | Comma-separated list of groups granted admin role.                    |
| `FB_OIDC_MFA_CLAIM`        | yes      | Claim that proves MFA occurred. Provider-specific, see sections below.|
| `FB_OIDC_REQUIRE_MFA`      | yes      | `true` in all CMMC deployments. `false` is for dev only.              |

---

## FIPS algorithm constraint

> **The server rejects id_tokens signed with EdDSA, HS256/384/512, or any
> non-approved algorithm.** It will only accept the following `alg` values in
> the id_token header:
>
> - `RS256`, `RS384`, `RS512`
> - `PS256`, `PS384`, `PS512`
> - `ES256`, `ES384`, `ES512`
>
> This is enforced by `auth/oidc/verifier.go` at `VerifyIDToken` time; the
> `alg` is compared against a hard-coded allowlist **before** the signature is
> checked. HMAC families are rejected because the client secret is not a
> FIPS-approved MAC key. EdDSA is rejected because Ed25519 is not yet in the
> FIPS 140-3 module validation list that Red Hat and Microsoft publish.

If the provider signs id_tokens with an algorithm outside that list, the
operator must reconfigure the provider — we will not relax the allowlist to
work around a misconfigured IdP. All three supported providers default to
`RS256` and are compliant out of the box.

### Why this matters for CMMC

Under CMMC L2, authenticator handling is scoped to SC-13 (Cryptographic
Protection) and IA-7 (Cryptographic Module Authentication). A FedRAMP
assessor will ask to see the id_token `alg` on a representative sample of
logins. Our audit log records the `alg` on every successful authentication
(`auth.oidc.login_success` event, `alg` field) so the assessor can sample
from the last 90 days of retained logs.

---

## Microsoft Entra ID in GCC High

Entra ID in GCC High is the **primary target** for v1 because the majority of
DoD CMMC L2 environments are already licensed on GCC High for M365. The
tenant is completely separate from the commercial Entra cloud — you cannot
reuse a commercial tenant for a CMMC deployment.

### Issuer pattern

Entra GCC High uses the `.us` endpoint:

```
https://login.microsoftonline.us/<TENANT_ID>/v2.0
```

That is the exact string that will appear as the `iss` claim in id_tokens
issued by your tenant. The discovery document is at:

```
https://login.microsoftonline.us/<TENANT_ID>/v2.0/.well-known/openid-configuration
```

> **Gotcha.** The commercial endpoint is `login.microsoftonline.com`. The DoD
> endpoint is `login.microsoftonline.us`. If you copy a snippet from
> `learn.microsoft.com` it will almost always show the commercial host; you
> must change it to `.us` for GCC High. The server will refuse to start if
> the issuer's discovery document hostname does not match the configured
> issuer.

### Creating the app registration

This is a high-level sequence; the exact portal UI shifts every few months.

1. Sign in to the **Entra admin center** at `https://entra.microsoft.us` with
   an account that has the **Application Administrator** or **Global
   Administrator** role in the GCC High tenant.
2. Navigate to **Applications → App registrations → New registration**.
3. Name the app something like `cmmc-filebrowser-prod`. Set supported account
   types to **Accounts in this organizational directory only (single tenant)**.
4. Under **Redirect URI**, select **Web** and enter
   `https://filebrowser.contoso.mil/api/auth/oidc/callback`.
5. After creation, go to **Certificates & secrets → Client secrets → New
   client secret**. Give it a name and a 12- or 24-month expiry. **Copy the
   secret value immediately**; Entra only displays it once.
6. Go to **Token configuration → Add optional claim** and add the `groups`
   claim to the **ID** token. Select **sAMAccountName** or **Group ID** per
   your preference — be consistent with what you put in `FB_OIDC_ADMIN_GROUPS`.
7. Go to **API permissions**. The registration comes with `User.Read`
   pre-added on Microsoft Graph — leave it. If your tenant requires admin
   consent, click **Grant admin consent for {tenant}**.
8. Copy the **Application (client) ID** and the **Directory (tenant) ID**
   from the **Overview** blade.

Official docs:
- GCC High identity overview: <https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-welcome>
- Register an app: <https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app>
- GCC High endpoints: <https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure>

### Required scopes

```
openid profile email User.Read
```

`User.Read` is a Microsoft Graph scope that lets the app read the signed-in
user's basic profile. Without it, `email` and `preferred_username` may be
null for certain guest-invited accounts.

### MFA claim convention

Entra signals MFA via the `amr` (Authentication Methods References) claim in
the id_token. When MFA has been performed, `amr` is a JSON array containing
one of the OIDC-registered values — for Entra this is `"mfa"`:

```json
"amr": ["pwd", "mfa"]
```

Configure the server with:

```
FB_OIDC_MFA_CLAIM=amr
FB_OIDC_REQUIRE_MFA=true
```

The server's MFA enforcement logic checks for any of `{"mfa", "otp", "fido",
"hwk", "pop"}` in the `amr` array. For CMMC L2, you should enforce MFA via a
Conditional Access policy on the tenant **as well** — server-side enforcement
is defense in depth, not the primary control.

### Example environment block

```
FB_OIDC_ISSUER=https://login.microsoftonline.us/<TENANT_ID>/v2.0
FB_OIDC_CLIENT_ID=<CLIENT_ID>
FB_OIDC_CLIENT_SECRET=<CLIENT_SECRET>
FB_OIDC_REDIRECT_URI=https://filebrowser.contoso.mil/api/auth/oidc/callback
FB_OIDC_SCOPES=openid profile email User.Read
FB_OIDC_USERNAME_CLAIM=preferred_username
FB_OIDC_GROUPS_CLAIM=groups
FB_OIDC_ADMIN_GROUPS=filebrowser-admins
FB_OIDC_MFA_CLAIM=amr
FB_OIDC_REQUIRE_MFA=true
```

### Tenant / assessor notes

- **GCC High is a separate tenant.** A commercial Entra tenant **cannot** be
  reused for CMMC. The Microsoft contract vehicle is different, the data
  residency boundary is different, and the assessor will reject a design that
  authenticates CUI users against a commercial tenant.
- **Conditional Access is mandatory.** An assessor will expect to see a CA
  policy that requires MFA for the filebrowser app registration, blocks
  legacy auth, and scopes sign-in to known (managed) devices if the
  customer's SSP claims device-based access control.
- **Group claim size limits.** Entra emits the `groups` claim inline up to
  ~200 groups, then switches to a `_claim_sources` overage link. v1 does
  **not** follow the overage link; if your admins belong to more than 200
  groups, put them in a dedicated group that is the only one mapped to
  `FB_OIDC_ADMIN_GROUPS`, or use **Group filtering** in the token
  configuration blade to emit only the groups assigned to the app.
- **Tenant ID is considered sensitive in GCC High.** Treat it like a
  customer account number; do not paste it into commercial support tickets.

---

## Keycloak (self-hosted, incl. FIPS-on-RHEL)

Keycloak is the fallback for operators who cannot use Entra or Okta — most
often airgap / disconnected sites. We ship a **FIPS-on-RHEL** variant of
Keycloak in the `cmmc-filebrowser-offline` bundle; it runs on a
FIPS-validated JDK (Red Hat build of OpenJDK 17 with the FIPS provider
enabled via `fips-mode-setup --enable` on the host).

### Issuer pattern

Keycloak uses a per-realm issuer:

```
https://<KEYCLOAK_HOST>/realms/<REALM_NAME>
```

Discovery is at:

```
https://<KEYCLOAK_HOST>/realms/<REALM_NAME>/.well-known/openid-configuration
```

> **Older Keycloak (pre-17).** If your bundle is still on a WildFly-based
> Keycloak (pre-Quarkus, pre-17.0), the issuer path is
> `/auth/realms/<REALM_NAME>` — note the extra `/auth` prefix. The bundled
> FIPS-on-RHEL variant is **always** Keycloak 24 or later, which uses the
> `/realms/` form. If you see `/auth/realms/` in a config, the operator is
> running an unsupported upstream build.

### Creating the client

1. Sign in to the Keycloak admin console at
   `https://<KEYCLOAK_HOST>/admin/` as a user with the `manage-realm` role
   in the target realm (or the master realm admin).
2. Select the realm (create one if this is a fresh install; do **not** use
   the `master` realm for application clients).
3. **Clients → Create client**.
   - Client type: **OpenID Connect**.
   - Client ID: `cmmc-filebrowser`.
   - Click **Next**.
4. Capability config:
   - **Client authentication: ON** (this makes it a confidential client).
   - **Standard flow: ON** (authorization code).
   - **Direct access grants: OFF** (we do not support ROPC).
   - **Implicit flow: OFF**.
   - **Service accounts roles: OFF** unless you separately need client-credentials.
5. Login settings:
   - **Valid redirect URIs:**
     `https://filebrowser.contoso.mil/api/auth/oidc/callback`.
   - **Web origins:** `+` (copies from redirect URIs) or the scheme+host.
6. Save, then open the **Credentials** tab and copy the generated **client
   secret**.
7. **Client scopes → Assigned default client scopes** should include
   `openid`, `profile`, `email`. Add a `groups` mapper if your realm does
   not emit groups by default: **Client scopes → create a `groups` scope
   → Mappers → Add mapper → "Group Membership"**, set **Token Claim Name**
   to `groups`, uncheck **Full group path** (unless you want
   `/engineering/admins` style), and mark **Add to ID token: ON**.
8. Assign admin users to a Keycloak group named `filebrowser-admins` (or
   whatever you put in `FB_OIDC_ADMIN_GROUPS`).

Official docs:
- Keycloak server admin guide: <https://www.keycloak.org/docs/latest/server_admin/>
- Keycloak FIPS 140-2 mode: <https://www.keycloak.org/server/fips>

### Required scopes

```
openid profile email
```

Add `groups` if you configured a groups client scope. Keycloak does not
require a provider-specific scope equivalent to Entra's `User.Read`.

### MFA claim convention

Keycloak is flexible here. Unlike Entra and Okta (which emit `amr`), Keycloak
signals step-up via the **`acr`** (Authentication Context Class Reference)
claim. By convention:

- `acr = "0"` — no authentication (should never reach the server).
- `acr = "1"` — single-factor (password only).
- `acr = "2"` — multi-factor (password + OTP / WebAuthn / etc.).

The exact value depends on how the realm's **Authentication → Flows** and
**Authentication → Policies → Authenticator Reference (ACR) to Level of
Assurance (LoA) Mapping** are configured. The bundled FIPS-on-RHEL realm
template ships with `2` mapped to the "browser-with-otp" flow.

Because the claim is `acr`, not `amr`, configure:

```
FB_OIDC_MFA_CLAIM=acr
FB_OIDC_REQUIRE_MFA=true
```

When `FB_OIDC_MFA_CLAIM=acr`, the server treats any value `>= "2"` (string
compare, not numeric) as "MFA satisfied". If your realm uses custom ACR
values (e.g., `"gold"` for MFA), you must instead set
`FB_OIDC_MFA_CLAIM=amr` and emit an `amr` claim via a hardcoded claim
mapper — contact CMMC support for the template.

### Example environment block

```
FB_OIDC_ISSUER=https://keycloak.contoso.mil/realms/cmmc
FB_OIDC_CLIENT_ID=cmmc-filebrowser
FB_OIDC_CLIENT_SECRET=<CLIENT_SECRET>
FB_OIDC_REDIRECT_URI=https://filebrowser.contoso.mil/api/auth/oidc/callback
FB_OIDC_SCOPES=openid profile email
FB_OIDC_USERNAME_CLAIM=preferred_username
FB_OIDC_GROUPS_CLAIM=groups
FB_OIDC_ADMIN_GROUPS=filebrowser-admins
FB_OIDC_MFA_CLAIM=acr
FB_OIDC_REQUIRE_MFA=true
```

### FIPS-on-RHEL bundle notes

- The bundle ships `keycloak-24.x` built against the **Red Hat build of
  OpenJDK 17** with the SunPKCS11-NSS-FIPS provider first in
  `java.security`. This makes the JVM FIPS 140-3 Module-in-Process on RHEL 9
  when the host is in FIPS mode (`fips-mode-setup --check` returns
  `FIPS mode is enabled.`).
- `standalone.conf` sets `-Dcom.redhat.fips=true` — do not remove it.
- The realm template disables all HMAC-based id_token signers and pre-seeds
  an RS256 realm key. Operators must not add an `HS256` key via the admin
  console; the CMMC-Filebrowser server will reject the resulting id_token
  regardless.
- The realm ships with **Password policy → PBKDF2-SHA256, 27,500 iterations
  minimum** to stay above the NIST SP 800-63B 2024 baseline. This is only
  relevant if Keycloak itself is the authoritative user store (as opposed to
  federating LDAP / AD).

### Tenant / assessor notes

- **Environment inheritance.** Keycloak has no independent FedRAMP
  authorization. The assessor will inherit the authorization boundary from
  the host — typically a FedRAMP-authorized IaaS (Azure Gov, AWS GovCloud,
  on-prem datacenter in-scope for the customer's CMMC boundary).
- **Airgap considerations.** The bundle ships with `hostname-strict=false`
  only during first-boot; the operator **must** set a real hostname before
  exposing the admin console. The ship-default hostname is
  `keycloak.local` — using that on a real deployment will break discovery.
- **Admin console exposure.** Per IA-2(1), the Keycloak admin console must
  be on a separate VLAN / network path from end-user traffic. The SSP must
  describe this separation; the bundle's default `firewalld` profile
  enforces it by opening `8443/tcp` only on the management interface.
- **Backup and export.** The realm export (`kc.sh export --realm cmmc`)
  must be included in the customer's backup runbook; Keycloak's encrypted
  client secret will not round-trip through a JSON export unless the
  operator also copies the realm's master key.

---

## Okta for Government High

Okta for Government High is a FedRAMP High-authorized tenant of Okta,
physically and logically separated from the commercial `*.okta.com`
deployment. Approximately 15-20% of CMMC L2 contractors use it, typically
ones that standardized on Okta before moving into the DoD supply chain.

### Issuer pattern

Okta emits the `iss` claim as the authorization server URL. For Government
High, the tenant hostname ends in `.okta.gov`:

```
https://<TENANT>.okta.gov/oauth2/default
```

Or, if you create a dedicated custom authorization server (recommended for
CMMC, because it lets you scope claims and lifetimes per-application):

```
https://<TENANT>.okta.gov/oauth2/<AUTH_SERVER_ID>
```

Discovery is at `{iss}/.well-known/openid-configuration`.

> **Commercial vs Gov High.** Commercial Okta uses `.okta.com` and lives
> outside the FedRAMP boundary. `okta.gov` is FedRAMP High. Some
> customer-specific Gov High tenants use a vanity domain (e.g.,
> `sso.contoso.mil`) that CNAMEs to a `.okta.gov` host; in that case, the
> `iss` claim is the **vanity domain**, not the underlying `.okta.gov`
> address. Configure `FB_OIDC_ISSUER` with whatever the discovery document
> reports as `issuer`.

### Creating the app integration

1. Sign in to the Okta admin console at `https://<TENANT>-admin.okta.gov/`
   as a Super Admin or an Application Administrator.
2. **Applications → Applications → Create App Integration**.
3. Sign-in method: **OIDC - OpenID Connect**. Application type: **Web
   Application**. Click **Next**.
4. App integration name: `cmmc-filebrowser`. Logo optional.
5. **Grant type:** check **Authorization Code**. Uncheck everything else
   (no implicit, no refresh-token-without-code, no client credentials unless
   explicitly required).
6. **Sign-in redirect URIs:**
   `https://filebrowser.contoso.mil/api/auth/oidc/callback`.
7. **Sign-out redirect URIs:** your front-channel logout URL if used;
   optional for v1.
8. **Assignments:** limit to specific groups (e.g., `filebrowser-users`,
   `filebrowser-admins`). Do not assign to **Everyone**.
9. Save. Copy the **Client ID** and **Client secret** from the **General**
   tab.
10. **Security → API → Authorization Servers.** Either use `default` or
    create a CMMC-specific authorization server. If creating a new one:
    - Name: `cmmc`. Audience: `api://cmmc-filebrowser`. Save.
    - Open the new server → **Claims → Add Claim**. Name: `groups`.
      Include in token type: **ID Token, Always**. Value type: **Groups**.
      Filter: **Matches regex** `.*` (or scope to `filebrowser-.*`).
    - **Access Policies → Add Policy**, assign it to the
      `cmmc-filebrowser` app, add a rule that requires MFA.
11. Copy the **Issuer URI** from the authorization server detail page. That
    is the value for `FB_OIDC_ISSUER`.

Official docs:
- Okta for US Government overview: <https://www.okta.com/products/government/>
- Create an OIDC web app: <https://developer.okta.com/docs/guides/sign-into-web-app-redirect/>
- Custom authorization servers: <https://developer.okta.com/docs/concepts/auth-servers/>

### Required scopes

```
openid profile email
```

Add `groups` only if you configured a `groups` scope on the authorization
server (by default, the `groups` claim is emitted based on the claim
configuration, not a separate scope).

### MFA claim convention

Okta emits `amr` in the id_token when the session satisfies the
authorization server's MFA requirement. The values follow RFC 8176; `"mfa"`
appears in the array when a second factor was used:

```json
"amr": ["pwd", "mfa", "kba"]
```

Configure:

```
FB_OIDC_MFA_CLAIM=amr
FB_OIDC_REQUIRE_MFA=true
```

Okta also emits `acr` values like `urn:okta:loa:2fa:any`. The server does
not parse those in v1 — rely on `amr` for MFA gating and let the Okta
authorization server policy enforce the actual factor requirement.

### Example environment block

```
FB_OIDC_ISSUER=https://contoso.okta.gov/oauth2/<AUTH_SERVER_ID>
FB_OIDC_CLIENT_ID=<CLIENT_ID>
FB_OIDC_CLIENT_SECRET=<CLIENT_SECRET>
FB_OIDC_REDIRECT_URI=https://filebrowser.contoso.mil/api/auth/oidc/callback
FB_OIDC_SCOPES=openid profile email
FB_OIDC_USERNAME_CLAIM=preferred_username
FB_OIDC_GROUPS_CLAIM=groups
FB_OIDC_ADMIN_GROUPS=filebrowser-admins
FB_OIDC_MFA_CLAIM=amr
FB_OIDC_REQUIRE_MFA=true
```

### Tenant / assessor notes

- **FedRAMP High authorization.** Okta for Government High carries a
  FedRAMP High ATO; the assessor can find it on the FedRAMP Marketplace at
  <https://marketplace.fedramp.gov/>. Cite the ATO package ID in the SSP.
- **Gov High is a separate tenant.** Do not federate from a commercial Okta
  org into Gov High for CUI users — it breaks the FedRAMP boundary. If the
  customer has a commercial Okta for non-CUI apps, the CMMC deployment must
  point at a Gov High tenant independently.
- **IdP-discovery routing.** Okta supports IdP discovery (route the user to
  a different IdP based on email domain). We support this transparently;
  the `iss` is still Okta's authorization server, and `amr` still reflects
  the downstream factor.
- **Session binding.** Okta Gov High can emit `sid` (session ID) in the
  id_token. v1 does not use it for anything, but the SSP should note that
  session revocation at the IdP is not automatically propagated to the
  filebrowser — we rely on short access-token lifetimes (default 1 hour)
  plus the backchannel-logout endpoint (which **is** wired in v1).

---

## SSP cross-references

The SSP must name the identity provider in the control narratives below, and
it must cite the provider's FIPS / FedRAMP attestation. Use the following
section references when updating the SSP from this template:

| SSP section | Control family | What to reference                                                                                               |
| ----------- | -------------- | --------------------------------------------------------------------------------------------------------------- |
| 3.5.1       | IA-2           | Which of the three providers is deployed and why (tenant ID / realm not required — generic name is sufficient). |
| 3.5.2       | IA-2(1), IA-2(2) | How MFA is enforced (CA policy for Entra, flow-level for Keycloak, Auth Server policy for Okta).              |
| 3.5.3       | IA-5           | Authenticator management: where the authenticator lifecycle lives (tenant admin, not filebrowser).              |
| 3.13.11     | SC-13          | **FIPS attestation of the signing algorithm.** This is where the id_token `alg` matters.                        |
| 3.13.8      | SC-8           | Transport protection — TLS to the IdP, `iss` validation, JWKS TLS chain pinning to the tenant CA.               |
| 3.14.2      | SI-2           | Patching cadence for the IdP (Microsoft / Okta handle it; Keycloak the operator patches monthly).               |

### Provider-specific FIPS attestation links

- **Entra ID (GCC High)** runs on Azure Government, which carries a
  FedRAMP High authorization and a DoD IL5 authorization. The Microsoft FIPS
  140 validation index is at
  <https://learn.microsoft.com/en-us/compliance/assurance/assurance-fips-140-2>.
  Cite the current Windows Server / Azure module certificate number in
  SSP §3.13.11.
- **Keycloak FIPS-on-RHEL** inherits the Red Hat Enterprise Linux 9 FIPS
  140-3 module validation. The certificates are at
  <https://access.redhat.com/articles/2918071>. Cite the RHEL 9
  cryptographic module certificate **and** the Red Hat build of OpenJDK
  FIPS provider certificate; both must be listed.
- **Okta for Government High** carries a FedRAMP High ATO (package ID
  available on the FedRAMP Marketplace). Okta does not publish an
  independent FIPS 140 module certificate because the signing happens in
  the cloud under the FedRAMP boundary; cite the FedRAMP ATO instead and
  note that SC-13 is inherited.

---

## Troubleshooting checklist

When the operator reports "OIDC login fails" — walk this list in order.

1. **Does discovery resolve?** From the filebrowser host:
   `curl -v {FB_OIDC_ISSUER}/.well-known/openid-configuration`. If this
   fails, the `iss` is wrong, DNS is wrong, or egress is blocked.
2. **Does the discovered `issuer` match `FB_OIDC_ISSUER` byte-for-byte?**
   Trailing slashes matter. Entra in particular will happily serve
   discovery from both `/v2.0` and `/v2.0/` but only one will match the
   id_token's `iss`.
3. **Is the redirect URI registered exactly?** Copy it out of the browser's
   URL bar on a failed login and paste it into the provider — matching
   subtle differences (http vs https, `:443`, trailing `/`) is the most
   common cause.
4. **What is the id_token `alg`?** If the login succeeds at the provider
   but the filebrowser logs
   `oidc: id_token signed with unsupported alg "HS256"`, the provider is
   misconfigured. For Keycloak, rotate the realm key to RS256. For Entra /
   Okta this should not happen with stock config.
5. **Is MFA actually occurring?** Check the provider's sign-in logs.
   Filebrowser logging an `amr missing mfa` error means the user bypassed
   MFA at the IdP — fix the policy at the IdP, not the filebrowser.
6. **Clock skew.** id_tokens have `iat`, `nbf`, `exp`. The server allows 60
   seconds of skew. On a VM without an NTP source this is the silent
   killer.
7. **JWKS TLS.** If the provider rotates keys and the filebrowser's HTTP
   client cannot fetch the new JWKS (proxy, firewall, internal CA not in
   trust store), logins will start failing 24 hours after rotation. The
   server logs `oidc: jwks fetch: x509: certificate signed by unknown
   authority` in that case.

---

*Document owner: CMMC-Filebrowser platform team. Updated alongside any
change to `auth/oidc/verifier.go` or the `FB_OIDC_*` environment contract.*
