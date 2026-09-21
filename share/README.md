# Open-CMMC share daemon

Lightweight, DMZ-facing daemon for one-off **external** CUI shares:
a recipient outside the enclave clicks a link, enters a passphrase
delivered out-of-band, and downloads the file. Every other component
of Open-CMMC is inside-only; this is the single boundary hop.

See `docs/architecture.md` §10 for the scope rationale and the
spec-level design. This README is the implementer's map.

## Package layout

| Path | Role |
|---|---|
| `share/daemon/` | The `cmmc-share` DMZ binary library: storage, audit, public HTTP, back-channel. |
| `share/daemon/recipient_templates/` | Embedded HTML templates served to recipients (landing, passphrase, acknowledgment). |
| `share/enclave/` | Enclave-side: rewrap a file under a passphrase-derived key, periodically push to the daemon. |
| `share/cmd/cmmc-share/` | `package main` — the binary entry point that wires `daemon.Run`. |
| `share/systemd/` | `cmmc-share.service` + SELinux module. Deploy these on the DMZ host. |

## Threat model recap

- **Public listener (tcp:8444)** sees unauthenticated internet traffic. It holds no plaintext, no KEK, no recipient identity. Wrong passphrase = Argon2 miss; N misses auto-burn the share.
- **Backchannel listener (tcp:8445)** is enclave-only, pinned via mTLS (client cert chains to the enclave CA) **and** gated by a bearer token that both sides hold. Push accepts metadata+ciphertext; GET drains audit; POST /revoke burns a share.
- **Enclave initiates all internal flow.** The daemon has no outbound path and no DNS. A full DMZ compromise yields ciphertext the attacker cannot decrypt and email-hashes the attacker cannot reverse.

## Crypto choices

- **KDF:** Argon2id over `passphrase || server-pepper`. Per-share random salt. Default params `t=3, m=64MiB, p=4` — tune via `enclave.DefaultArgon2Params`.
- **DEK wrap:** AES-256-GCM on the 32-byte DEK, key = Argon2id output, nonce = fresh per share.
- **Blob:** AES-256-GCM whole-blob (v1). Files > ~1 GiB should be chunked — the back-channel caps individual pushes at 1 GiB.
- **Audit chain:** per-event HMAC-SHA256 chained from a genesis MAC; enclave verifies on drain and folds into the main audit chain.

## CMMC mapping

| Control | What the daemon does |
|---|---|
| 3.1.3 / 3.1.22 | Recipient name, mark, and expiry travel with every share; public-without-passphrase is impossible by construction. |
| 3.1.9 | The landing + passphrase pages each restate the CUI acknowledgment. |
| 3.1.20 | Each share is a logged external connection. |
| 3.3.1 / 3.3.2 | HMAC-chained audit, correlation id carried from enclave. |
| 3.8.4 | CUI mark on every metadata row; ITAR / NOFORN refused at rewrap time. |
| 3.13.1 / 3.13.2 / 3.13.5 | DMZ-pattern boundary; daemon is the only public component. |
| 3.13.8 | TLS 1.3 FIPS on the public side, mTLS on the backchannel. |
| 3.13.16 | Rewrapped blob + passphrase-wrapped DEK; DMZ holds no plaintext. |

## Operator install (RHEL 9 / AlmaLinux 9)

```bash
# 1. User + dirs
sudo useradd --system --home-dir /var/lib/cmmc-share --shell /sbin/nologin cmmc-share
sudo install -d -m 0700 -o cmmc-share -g cmmc-share /var/lib/cmmc-share/store
sudo install -d -m 0750 -o root       -g cmmc-share /etc/cmmc-share

# 2. Secrets (match the file permissions the daemon enforces)
sudo openssl rand -out /etc/cmmc-share/pepper.bin   32
sudo openssl rand -out /etc/cmmc-share/audit.key    32
sudo openssl rand -out /etc/cmmc-share/bearer.token 32
sudo chmod 0400 /etc/cmmc-share/{pepper.bin,audit.key,bearer.token}
sudo chown cmmc-share:cmmc-share /etc/cmmc-share/{pepper.bin,audit.key,bearer.token}

# 3. TLS material (public server cert + enclave CA trust anchor)
sudo install -d -m 0750 -o root -g cmmc-share /etc/cmmc-share/tls
# put server.crt / server.key / enclave-ca.pem there, all 0400 cmmc-share

# 4. Binary + systemd unit
sudo install -m 0755 -o root -g root cmmc-share /usr/local/bin/cmmc-share
sudo install -m 0644 share/systemd/cmmc-share.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cmmc-share

# 5. SELinux
cd share/systemd
checkmodule -M -m -o cmmc-share.mod cmmc-share.selinux
semodule_package -o cmmc-share.pp -m cmmc-share.mod
sudo semodule -i cmmc-share.pp
sudo restorecon -RFv /usr/local/bin/cmmc-share /etc/cmmc-share /var/lib/cmmc-share
```

The daemon refuses to boot if any secret file is group- or
world-readable, or if the store dir is wider than 0700 — the
permission checks in `daemon.readSecret` and `daemon.NewStore` are
deliberately strict.

## Enclave wiring

From the main filebrowser process, invoke:

```go
pusher := &enclave.Pusher{
    DaemonURL:   "https://share.internal:8445",
    BearerToken: base64.StdEncoding.EncodeToString(rawBearerBytes),
    Client:      enclave.NewMutualTLSClient(clientCert, caCfg),
    OnAuditEvents: func(evs []daemon.Event) error {
        // fold events into the main cmmc/audit chain
        return nil
    },
}
go pusher.Run(ctx)

// On "Share externally" click:
art, err := enclave.Rewrap(enclave.RewrapParams{
    Plaintext:      plaintext,
    Filename:       "report.pdf",
    ContentType:    "application/pdf",
    CUIMark:        "BASIC",
    SenderUserID:   user.ID,
    RecipientEmail: "dana@example.com",
    TTL:            72 * time.Hour,
    MaxDownloads:   1,
    MaxFailures:    5,
    Passphrase:     passphrase,
    CorrelationID:  cor,
}, pepper, "p1", enclave.DefaultArgon2Params)
if err != nil { return err }
pusher.Enqueue(art)
```

The enclave never sees the DMZ disk; the DMZ never sees the KEK.
