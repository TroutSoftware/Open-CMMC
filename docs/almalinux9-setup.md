# AlmaLinux 9 deployment

AlmaLinux 9 and RHEL 9 are **co-equal first-class supported targets**
for CMMC-Filebrowser. Pick either; the FIPS posture is identical
across the two:

- Same Go toolchain (`go-toolset`, currently 1.25.x on both)
- Same cgo link path to the OpenSSL FIPS 140-3 validated module
  (CMVP cert #4774, inherited by AlmaLinux via RHEL binary compat)
- Same systemd unit behavior, SELinux policy, and podman runtime
- Same installer (`config/install.sh` accepts `rhel` and `almalinux`
  in `/etc/os-release` without any distro-specific branching)

Picking between them is a procurement / support / update-cadence
decision, not a compliance one:

- **Choose RHEL 9** if you already have a Red Hat subscription, need
  official Red Hat enterprise support contracts, or your SSP is
  already written against the RHEL audit trail.
- **Choose AlmaLinux 9** if you want a free rebuild with the same
  CMVP-validated OpenSSL module, air-gap-friendly package mirrors,
  or standardization across build infrastructure and on-prem hosts.
- **UBI 9** (Red Hat Universal Base Images) is a subset of RHEL 9
  that's free to redistribute as a container image — useful when
  you want the RHEL userspace but aren't deploying on a RHEL host.

Customers audit-ready on one can switch to the other without
re-validating the crypto path — same OpenSSL cert, same module
boundary.

## Enable FIPS mode on the host

```bash
# As root on the appliance host before installing filebrowser.
sudo fips-mode-setup --enable
sudo reboot

# Verify after reboot.
fips-mode-setup --check     # "FIPS mode is enabled."
cat /proc/sys/crypto/fips_enabled   # "1"
```

The container's `GODEBUG=fips140=on` is a belt-and-suspenders check — it
fails closed if the runtime cannot resolve FIPS-approved algorithms. On
a non-FIPS host, filebrowser-cmmc boot will refuse with a loud error
if `FB_OIDC_REQUIRE_FIPS=true` (the CMMC-default).

## Build the container

```bash
podman build \
  -f Dockerfile.alma9 \
  -t cmmc-filebrowser:cmmc-v2.63.2-001-alma9 \
  .
```

Produces a ~40 MB runtime image on `almalinux:9-minimal`. Build stage
uses the full `almalinux:9` for `go-toolset` + `openssl-devel`.

Image provenance:

- Base: `quay.io/almalinuxorg/almalinux:9` + `:9-minimal` (signed by the
  AlmaLinux OS Foundation, GPG key published at almalinux.org).
- go-toolset: AlmaLinux 9 appstream package (mirror of the RHEL one).
- OpenSSL: the distribution's `openssl-libs` package inherits the RHEL
  FIPS 140-3 validation via binary compatibility.

## Run on an AlmaLinux 9 host

```bash
podman run --rm --name cmmc-filebrowser \
  -p 8080:8080 \
  -v /srv/cmmc-filebrowser:/srv \
  --env-file /etc/cmmc-filebrowser/environment \
  cmmc-filebrowser:cmmc-v2.63.2-001-alma9
```

SELinux: the container runs as UID 10001; the mounted `/srv` directory
must be labeled `container_file_t` (or mount with `:Z`). See the
matching note in `docs/architecture.md` §12.

## Package deploy (no container)

For operators who prefer a system-service deployment, the binary from
the build stage can be extracted and installed alongside the systemd
unit in `config/systemd/cmmc-filebrowser.service`:

```bash
podman create --name _extract cmmc-filebrowser:cmmc-v2.63.2-001-alma9
podman cp _extract:/usr/local/bin/filebrowser /usr/local/bin/
podman rm _extract

install -m 0644 config/systemd/cmmc-filebrowser.service \
    /etc/systemd/system/cmmc-filebrowser.service
systemctl daemon-reload
systemctl enable --now cmmc-filebrowser
```

## Drift vs RHEL UBI 9

Known deltas between the two build paths:

| Aspect | RHEL UBI 9 | AlmaLinux 9 |
|---|---|---|
| go-toolset version | Tied to RHEL release cycle | Mirrored from RHEL, typically same week |
| OpenSSL FIPS cert | CMVP #4774 (direct Red Hat listing) | CMVP #4774 (inherited via binary compat) |
| Base image size | UBI minimal ~80 MB | AlmaLinux minimal ~65 MB |
| Subscription required | No for UBI, yes for full RHEL | No |
| Update cadence | Red Hat security advisories (RHSA) | AlmaLinux Security Advisories (ALSA), usually same day |

The SSP supplement template supports both as blessed configurations.
Document the one you chose in §3.13 crypto inheritance.

## Testing checklist

Before assessing either build:

- [ ] `fips-mode-setup --check` on the host → enabled
- [ ] `podman inspect <image>` → image built from AlmaLinux 9 tags (or UBI 9)
- [ ] `filebrowser version` at runtime → reports the cmmc release tag
- [ ] Boot log shows `FIPS 140 posture: enabled`
- [ ] Boot log shows `envelope: encryption required`
- [ ] `/api/cmmc/audit/verify` returns `{"intact": true, "key_missing": false}`
- [ ] `fips-mode-setup --check` on host is re-verified post-install

## Known deltas between AlmaLinux 9 and RHEL 9

Verified via a containerized audit of install.sh's portable phases
(preflight, TLS cert generation, tooling availability) against
AlmaLinux 9.7 on 2026-04-19. Phases that require systemd / firewalld
/ rootful podman (unit installs, KC bring-up, passkey flow) are
transitively expected to work because the underlying system
semantics match, but need a real Alma9 VM run to be claimed as
tested end-to-end.

### Verified identical to RHEL 9.7

| Surface | RHEL 9.7 | AlmaLinux 9.7 | Notes |
|---|---|---|---|
| `/etc/os-release` ID | `rhel` | `almalinux` | install.sh preflight accepts both (case line 164) |
| go-toolset version | `go1.25.8 (Red Hat 1.25.8-1.el9_7)` | identical | `GOFIPS140=v1.0.0` build produces byte-compatible binaries |
| podman package | available in baseos | available in baseos | same version family |
| SELinux policy | targeted | targeted | `restorecon`, `policycoreutils-python-utils` identical |
| `update-ca-trust` | installed by default | installed by default | CA anchor drop-in path `/etc/pki/ca-trust/source/anchors/` matches |
| firewalld default zone | public | public | `install.sh phase_firewall` works identically |
| `ip route get` output shape | `...src <addr>...` | `...src <addr>...` | `detect_host_ip` logic matches |
| FIPS in containers | inherited from host `/proc/sys/crypto/fips_enabled` | inherited from host | start-time check passes if host FIPS is on |

### Minor drift (non-blocking)

| Aspect | RHEL 9 | AlmaLinux 9 | Impact |
|---|---|---|---|
| OpenSSL minor version | `3.0.x` (RHSA stream) | `3.5.x` (ALSA stream as of 9.7) | Newer TLS / cert parsing paths on Alma; CAVP #4774 validation path matches at the FIPS-module layer |
| Security advisory stream | RHSA | ALSA (usually same-day with RHSA) | SBOM scanners treat them as separate sources; both satisfy CMMC 3.11.3 scan cadence |

### Not yet tested on real VM

The following rely on systemd + rootful podman + firewalld being
active, which a container probe can't exercise cleanly. On RHEL 9.7
they've been validated end-to-end; on AlmaLinux 9 they're expected
to match but unverified:

- [ ] `cmmc-filebrowser.service` starts with correct sandbox directives
- [ ] `cmmc-keycloak.service` mounts `/etc/cmmc-filebrowser/tls` with `:ro,z` and KC trusts the cert
- [ ] `firewall-cmd --permanent --add-port ... --reload` opens 8443 + 8081
- [ ] `update-ca-trust` makes the dev CA trusted by the filebrowser Go OIDC client
- [ ] First-login TOTP flow completes against the KC realm
- [ ] Passkey enrollment (once DNS is in place) via Account Console
- [ ] Audit chain HMAC verification over a multi-hour run

The commit that claims AlmaLinux 9 as a first-class supported target
should include either a VM-test artifact OR an explicit "container-
audited, VM-run pending" disclaimer in the SSP supplement.
