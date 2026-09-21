# Backup and restore

Open-CMMC encrypts every file in the cabinet under a 32-byte master key
(the KEK) that is generated on your appliance during install and stored
nowhere else. **There is no escrow, no recovery code, and no vendor
copy.** If you lose that key, the cabinet is ciphertext forever.

This page is the procedure for making sure that does not happen.

---

## What must survive

| Artifact | Path | Why it matters |
|---|---|---|
| **KEK** | `/etc/cmmc-filebrowser/kek.bin` | Decrypts every file. Irreplaceable. |
| Environment | `/etc/cmmc-filebrowser/environment` | `FB_SETTINGS_KEY` (session JWT signing), `FB_AUDIT_HMAC_KEY` (audit chain), OIDC client secret. |
| State DB | `/var/lib/cmmc-filebrowser/filebrowser.db` | Users, folder ACLs, CUI marks, share rows. |
| Cabinet | `/srv/cmmc-filebrowser/files` | The files. Envelope-encrypted on disk. |
| Keycloak realm | container volume | Users, groups, enrolled TOTP secrets. |

Losing only the KEK loses everything. Losing only `filebrowser.db`
loses your marks and ACLs but the files remain decryptable. Losing only
the realm means every user re-enrolls their second factor.

---

## Taking a backup

```bash
sudo config/install.sh backup /mnt/removable/open-cmmc-$(date +%F)
```

The command stops `cmmc-filebrowser` for the duration of the database
copy and restarts it afterwards. A BoltDB file copied while the service
is writing can be torn in ways that only surface at restore time, so
the outage is deliberate — expect a few seconds plus the time to copy
the cabinet.

It captures config and keys, the state database, the cabinet, and a
Keycloak realm export, then writes a `MANIFEST` recording the host,
version, and timestamp.

### The archive is as sensitive as the cabinet

The backup **contains `kek.bin` in the clear**. It is not independently
encrypted. Anyone holding the archive holds the plaintext of every file
in it.

Practically, that means the backup media inherits the same handling
controls as the appliance itself: physical custody, marked media, and
the same access restrictions your SSP places on CUI at rest.

> **SSP note (800-171 3.8.9).** The control asks you to protect the
> confidentiality of backup CUI. Open-CMMC's backup satisfies that only
> to the extent that your *media handling* does — the product does not
> yet implement independent backup-key custody, where the backup is
> wrapped under a separate key held apart from the appliance. Document
> your compensating control (encrypted removable media, offline safe,
> two-person access) rather than citing a product feature.

---

## Restoring

```bash
sudo config/install.sh restore /mnt/removable/open-cmmc-2026-08-25
```

The command refuses to run if `/srv/cmmc-filebrowser/files` is
non-empty. Restoring over a populated cabinet would destroy the newer
copy with no way back, so replacing a live cabinet is a deliberate
two-step:

```bash
sudo config/install.sh uninstall --wipe-state
sudo config/install.sh restore /mnt/removable/open-cmmc-2026-08-25
```

Restore replaces config and keys, the state DB, and the cabinet;
re-applies SELinux contexts (these do not survive a copy from removable
media); and imports the Keycloak realm.

### What changes after a restore

**The audit chain gets a seam.** Events recorded before the backup
verify as one chain, and the first event after the restore begins a new
segment. This is expected and is the same behaviour Wazuh documents for
the HKDF split boundary — see
[`wazuh-integration.md`](./wazuh-integration.md). Note the restore
timestamp in your incident record so the seam is explained rather than
investigated as tampering.

**Sessions are invalidated.** Users re-authenticate.

---

## Verify the backup before you need it

A backup you have never restored is a hypothesis.

1. Build a spare host with the same OS and FIPS posture.
2. `install.sh deploy` with `FB_ADMIN_USER` set, then
   `uninstall --wipe-state` to leave a clean installed shell.
3. `install.sh restore` from your archive.
4. Log in, open a CUI-marked file, and confirm the contents decrypt.
5. Run `install.sh status`.

Step 4 is the one that matters. It is the only step that proves the KEK
in the archive matches the cabinet in the archive.

Do this when you first deploy, and again whenever you rotate keys or
change the storage layout. An annual recovery drill with the result
recorded is straightforward evidence for your SSP.

---

## What is not covered

- **Key rotation.** There is no supported procedure for rotating the
  KEK on a populated cabinet today. `install.sh` never overwrites the
  environment file precisely because rotation is not automated.
- **Independent backup-key custody.** See the SSP note above.
- **Off-site replication.** Copy the archive off-site yourself.
- **Hardware key custody.** The KEK is a file on disk, protected by
  filesystem permissions (`0400`, owned by the service account) and
  SELinux. It is not sealed to a TPM or held in an HSM.
