# Contributing

Thanks for looking at CMMC-Filebrowser. This is a focused fork of [filebrowser/filebrowser](https://github.com/filebrowser/filebrowser) aimed at CMMC Level 2 / NIST 800-171 Rev 2 deployment. Contributions are welcome; please read the ground rules first.

## Where issues go

- **CMMC / compliance / fork-specific bugs + features** → [this repo's issues](https://github.com/TroutSoftware/Open-CMMC/issues)
- **Upstream filebrowser bugs** (file rendering, SPA glitches, core upload/download logic unrelated to our hardening) → [filebrowser/filebrowser issues](https://github.com/filebrowser/filebrowser/issues) first. We'll pick up fixes on rebase.

## Scope

This fork stays narrowly focused on CMMC L2 posture. Good fits:

- New or tighter **NIST 800-171 Rev 2** control coverage
- **OIDC / IdP** integrations (Entra GCC-H, Okta Gov, Ping, CAC/PIV)
- **FIPS** toolchain and algorithm lockdowns
- **Audit pipeline** (structured events, SIEM decoders, HMAC chain)
- **CUI marking + flow control** (3.1.3, 3.8.4, 3.1.22)
- **Installer + operator docs** (RHEL / Alma / Rocky 9)

Out of scope (and will be closed with a link here):

- Generic file-browser features that don't touch the CMMC posture — upstream those.
- UI themes, cosmetic changes.
- Rebasing to a newer upstream filebrowser — we do that on a cadence; PRs that bump upstream alone are noise.

## Development loop

```bash
# Build + test on a RHEL/Alma 9 dev VM with go-toolset
GOFIPS140=v1.0.0 go build ./...
go test ./...

# Frontend (Vue 3 + Vite)
cd frontend && pnpm install && pnpm run build

# End-to-end install smoke test on a VM
sudo config/install.sh uninstall --wipe-state
sudo config/install.sh deploy
sudo config/install.sh status
```

For air-gap deployments, package via `scripts/build-release.sh` and install with `--from-release`.

## Before opening a PR

- [ ] Run `go test ./...` — every package passes
- [ ] `bash config/keycloak/bootstrap_test.sh` green (if you touched Keycloak bootstrap)
- [ ] New / modified behavior has a test (unit or integration — we're not shy about shell tests)
- [ ] Commit messages explain **why**, not just **what** — the audit trail matters here
- [ ] If you changed a control's implementation, update the corresponding row in `docs/gap-analysis.md`
- [ ] If you changed a deployment step, update the corresponding row in `docs/architecture.md` and re-check `docs/almalinux9-setup.md`

## Commit attribution

The project uses `git config user.name` + `user.email` for author attribution. Please commit under your own name + email; we do not add Co-Authored-By trailers for AI assistants.

## Release cadence

Major versions follow semver. The GitHub Actions workflow in `.github/workflows/release.yml` fires only on `vMAJOR.0.0` tags (e.g. `v1.0.0`, `v2.0.0`) — minor and patch releases are built locally via `scripts/build-release.sh` and distributed via whatever channel the customer uses (direct download, internal artifact server, air-gap sneakernet).

## Code style

- Go: `gofmt` + `go vet` clean; one concern per commit
- Vue: the project uses Vue 3 + TypeScript + Vite + pnpm. `pnpm run typecheck` must pass.
- Shell: `bash -n` clean; `set -euo pipefail` in new scripts; prefer POSIX-ish portability but RHEL 9 is the baseline.

## Security

If you find a vulnerability, please read [SECURITY.md](./SECURITY.md) before opening a public issue.

## License

By contributing, you agree to license your work under [Apache-2.0](./LICENSE) — same as the rest of the project and upstream filebrowser.
