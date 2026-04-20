// Package fips reports whether the Go runtime is executing in FIPS
// 140-3 mode.
//
// On Go 1.24+ this delegates to `crypto/fips140.Enabled()`, which
// reports whether the Go Cryptographic Module v1.0.0 (CAVP A6650, CMVP
// In Process / Validated depending on the toolchain's vintage) is
// active. On RHEL go-toolset builds, this also reflects the status of
// the underlying RHEL OpenSSL FIPS 140-3 module — the two layers
// co-operate via the GOFIPS environment and the system crypto policy.
//
// The package is split by build tag so the codebase compiles cleanly
// on pre-1.24 toolchains (fips_stub.go returns false, Mode "unknown").
// On Go 1.24+ fips_go124.go does the real query.
//
// CMMC note: 800-171 3.13.11 wants FIPS-validated cryptography. This
// runtime check lets cmd/root.go refuse to start an OIDC deployment
// that was built with a non-FIPS toolchain — the SSP can point at the
// boot-time log line as evidence the attestation is live, not just
// asserted at build.
package fips

// Mode returns a short human string describing the detected FIPS
// posture: "enabled", "disabled", or "unknown" (pre-1.24 toolchain).
func Mode() string {
	if Enabled() {
		return "enabled"
	}
	return "disabled"
}
