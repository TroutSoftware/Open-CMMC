// Package tlsprofile provides a *tls.Config tuned to the FIPS-approved
// subset of TLS 1.2 / 1.3 for the CMMC L2 posture.
//
// Mapped controls:
//   - 3.13.8  cryptographic mechanisms to protect CUI in transit
//   - 3.13.11 FIPS-validated cryptography
//   - 3.13.15 protect authenticity of communications sessions
//   - 3.1.13  cryptographic mechanisms for remote access
//
// Under GODEBUG=fips140=on the Go runtime already refuses non-approved
// ciphers, so this explicit list is belt-and-suspenders; it also serves
// as the SSP evidence pointer for which ciphers the listener presents.
package tlsprofile

import "crypto/tls"

// FIPSCipherSuites are the FIPS-approved TLS 1.2 cipher suites. TLS 1.3
// cipher suites are hardcoded by Go's runtime and cannot be configured
// via CipherSuites — under FIPS the runtime narrows to
// TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384.
func FIPSCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
}

// FIPSCurves returns the FIPS-approved elliptic curves. X25519 is
// intentionally excluded — not in the FIPS allowlist.
func FIPSCurves() []tls.CurveID {
	return []tls.CurveID{tls.CurveP256, tls.CurveP384}
}

// Server returns a *tls.Config tuned for a FIPS-capable server listener.
// Certificates are left to the caller. MinVersion TLS 1.2 (for legacy
// IdP clients); prefer TLS 1.3 via the runtime default.
func Server() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     FIPSCipherSuites(),
		CurvePreferences: FIPSCurves(),
	}
}
