//go:build go1.24

package fips

import "crypto/fips140"

// Enabled returns true when the Go runtime's FIPS 140 mode is active.
// This is the Go-layer flag; it does not by itself prove that the
// underlying OpenSSL / platform crypto module is validated — that part
// is the toolchain's responsibility (RHEL go-toolset inherits RHEL's
// 140-3 cert; microsoft/go inherits platform crypto; vanilla Go 1.24+
// honors GOFIPS=1 via the native Cryptographic Module).
func Enabled() bool {
	return fips140.Enabled()
}
