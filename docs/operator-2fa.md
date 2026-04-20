# Operator guide — 2FA enrollment, including passkeys

This guide is for **operations teams** onboarding users onto
CMMC-Filebrowser. Two scenarios are covered in order of decreasing
frequency:

1. **Add a security key (passkey) to an existing user** — the
   recommended factor for CMMC L2; a few clicks.
2. **Switch a user from authenticator-app (TOTP) to key-only
   passwordless login** — tap the key, no password typed.

> Physical keys matter: CMMC 3.5.3 (multi-factor) and 3.5.4
> (replay-resistant) both prefer hardware tokens over TOTP. The
> DoD CAC / PIV stack is functionally a FIDO2 device. YubiKey 5
> FIPS series and CAC cards both satisfy this in under 60
> seconds of operator time per user.

## The DNS / hostname prerequisite — READ FIRST

**Passkeys (WebAuthn / FIDO2) require a hostname URL, not an IP.**
Every browser vendor implements the WebAuthn spec's restriction:
the Relying Party Identifier must be a domain name, and
`https://10.20.30.40:8443` is rejected as "SecurityError: invalid
domain" during enrollment. There is no browser flag or policy
knob that unlocks it.

**What this means for deployment sequencing:**

| Deployment stage | 2FA available | What's missing |
|------------------|---------------|----------------|
| Appliance booted, only IP access (`https://10.20.30.40:8443`) | **TOTP only** — authenticator app, no keys | Hostname DNS |
| Hostname resolves on operator laptop only (one-off `/etc/hosts` edit) | TOTP + keys for that operator | LAN-wide DNS |
| Hostname resolves LAN-wide (customer's internal DNS, or mDNS + Bonjour) | TOTP + keys for everyone | — |

Practically: an appliance rolled out without a DNS plan can start
accepting users on TOTP from day one. Passkeys come online the
moment the customer's network team publishes a DNS record like
`cmmc.customer.internal → 10.20.30.40`. No filebrowser redeploy
needed — the hostname is already in the cert SAN and the KC
realm's redirect URI (both set at install time).

**Installer defaults** use `cmmc.local` as the hostname. Override
at install with `FB_HOST_NAME=<fqdn>` to match your DNS plan:

```bash
sudo FB_HOST_NAME=filebrowser.customer.internal \
     ~/cmmc-filebrowser/config/install.sh deploy
```

**mDNS / `.local` hostnames** work on LANs where the appliance runs
Avahi (stock RHEL 9 does, if `avahi-daemon` is enabled). macOS and
most desktop Linux distros resolve `.local` automatically via
Bonjour; Windows requires the Apple Bonjour Print Services install
OR a real DNS A record. Assume `.local` is a demo / small-team
hack, not a production plan.

**Access Gate / customer PKI:** the Gate typically fronts the
appliance with its own TLS cert bound to a real hostname the
customer already manages in DNS. In that deployment shape,
passkeys work out of the box — the Gate's cert + DNS entry is the
hostname infrastructure the WebAuthn spec wants.

## Other prerequisites (secondary)

- TLS must be active on the appliance — WebAuthn refuses to run
  over plain HTTP. `install.sh deploy` turns this on by default;
  verify with `install.sh status` (both services should report HTTPS).
- Browser must be Chromium, Edge, Firefox, or Safari within the
  last two releases. IE and old Edge do not implement WebAuthn.
- Self-signed dev CA: import `/etc/cmmc-filebrowser/tls/ca.crt` into
  the user's browser trust store once. Customer PKI / Access Gate:
  no import needed; the CA is already trusted.

---

## Scenario 1 — Add a security key to an existing user

### Three clicks and a tap

1. User logs into filebrowser as they normally do (password +
   authenticator-app code). They land in the file tree.
2. User opens the Keycloak **Account Console** in a new tab:
   `https://<appliance>:8081/realms/cmmc/account/`
   (link also in the filebrowser profile menu → "Security
   settings" when that menu lands).
3. Left rail → **Signing In**.
4. Under **Security Key**, click **"Set up security key"**.
   - The browser shows a prompt: "CMMC Filebrowser wants to set up
     a security key" → tap the key → enter PIN if the key has one.
   - Browser confirms "Your key is registered."
5. (Optional, recommended) Give the credential a friendly label
   like "Yubikey-operations-2026" so the audit stream records
   something human-meaningful.

The security key is now a peer to the authenticator-app code at
every subsequent login. On the 2FA page after password, KC shows
a chooser: **[Authenticator app]** or **[Security key]**.

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "WebAuthn is not supported by this browser" | HTTP, not HTTPS | Access via `https://…` — `install.sh deploy` should have enabled this. |
| Prompt never appears | Extension blocking `navigator.credentials.create` | Temporarily disable ad blockers / security extensions. |
| Prompt appears, key taps, registration fails with Passkey Error | Wrong algorithm (key offering Ed25519) | We restrict to ES256/RS256 (FIPS). Use a FIDO2 key that supports ES256 — every YubiKey 5 series and every FIDO2-certified device does. |
| Multiple keys, can't tell them apart on login chooser | No friendly name was set | Set a name from Signing In → rename the credential row. |

---

## Scenario 2 — Enable key-only passwordless login

Instead of password + key, the user types nothing and taps the
key — the key authenticates both who they are (possession) and
something they know/are (PIN or biometric). This is AAL3 per
NIST 800-63B and exceeds the CMMC L2 baseline.

### One-time user setup (from Account Console)

1. Same path as above: Account Console → **Signing In**.
2. This time click **"Set up passwordless key"** (separate row
   from the 2FA Security Key — they're different credential
   types in Keycloak, and the same physical key can hold both).
3. On the key prompt, either:
   - Set a PIN for the key if not already set (YubiKey: do this
     once with the Yubico Authenticator app).
   - Or use biometric verification (fingerprint keys / Windows Hello).
4. Browser confirms "Your passwordless key is registered."

### Login from now on

On the filebrowser login page the user now sees **two buttons**:
- **Sign in with password** (legacy path — password + 2FA)
- **Sign in with security key** (new path — key only)

Clicking the key button:
1. Browser prompts "Touch your security key."
2. User taps key → browser asks for PIN or biometric.
3. KC verifies the signature → user lands in filebrowser.

No password typed at any point.

### When passwordless beats TOTP for operations

- **Phishing-resistant.** Operator can't be tricked into typing a
  code into a fake page — the key signs a challenge bound to the
  real origin.
- **Recoverable failure modes.** Lost phone = TOTP locked out until
  admin resets. Lost key = user's other keys (you should issue two)
  or admin re-enrolls a new key.
- **Audit clarity.** Event `auth.login.ok` records the credential
  used (webauthn-passwordless vs otp), so the SIEM can tell which
  operators are on the stronger factor.

### Enrollment decision matrix

| User profile | Recommended setup |
|--------------|--------------------|
| Admin (dana, `filebrowser-admins`) | Password + TOTP + passwordless key (redundancy) |
| CUI handler (alice, bob, carol) | Password + TOTP **or** password + 2FA key |
| Shop-floor user (dave, sales) | Password + TOTP (lowest-cost baseline) |
| Contractor with CAC/PIV | Passwordless key only (CAC acts as the key) |

## Batch onboarding

For bulk enrollment (10+ users, new team spin-up), skip the
per-user walk-through and script it via:

```bash
# On the appliance, get an admin token for the cmmc realm
TOK=$(curl -sk -X POST \
  "https://localhost:8081/realms/master/protocol/openid-connect/token" \
  -d "username=admin" -d "password=$KC_ADMIN_PASSWORD" \
  -d "grant_type=password" -d "client_id=admin-cli" | jq -r .access_token)

# For each user, add webauthn-register-passwordless to their required
# actions. On next login they'll be forced through key enrollment.
for u in alice bob carol; do
  uid=$(curl -sk -H "Authorization: Bearer $TOK" \
    "https://localhost:8081/admin/realms/cmmc/users?username=$u&exact=true" \
    | jq -r '.[0].id')
  curl -sk -X PUT -H "Authorization: Bearer $TOK" \
    -H "Content-Type: application/json" \
    "https://localhost:8081/admin/realms/cmmc/users/$uid" \
    -d "{\"requiredActions\": [\"webauthn-register-passwordless\"]}"
done
```

After that script, each of those users is prompted to register a
passwordless key on their next login.

## FIPS compliance note

The realm policy pins WebAuthn signatures to `ES256` and `RS256`.
`Ed25519` is explicitly excluded because it isn't in the FIPS 140
approved set. YubiKey 5 FIPS and CAC/PIV both use ES256 (ECDSA
P-256); standard YubiKey 5 also supports ES256. No action needed
from operators — the key will pick an acceptable algorithm
automatically.
