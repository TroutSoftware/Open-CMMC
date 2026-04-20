package tlsprofile

import (
	"crypto/tls"
	"strings"
	"testing"
)

// nonFIPSCiphers are the Go TLS 1.2 cipher suites we explicitly do NOT
// want in the FIPS profile. If any of these leaks back in, this test
// breaks loudly — these are the common regressions.
var nonFIPSCiphers = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, //nolint:staticcheck // explicit regression guard
}

func TestFIPSCipherSuites_OnlyApprovedAEAD(t *testing.T) {
	got := FIPSCipherSuites()
	if len(got) == 0 {
		t.Fatal("no cipher suites returned — FIPS listener would fail")
	}
	approved := map[uint16]struct{}{}
	for _, c := range got {
		approved[c] = struct{}{}
	}
	for _, bad := range nonFIPSCiphers {
		if _, ok := approved[bad]; ok {
			t.Errorf("non-FIPS cipher %#x leaked into FIPSCipherSuites", bad)
		}
	}
}

func TestFIPSCipherSuites_AllAEAD_GCM(t *testing.T) {
	// Every approved suite must be an AEAD AES-GCM variant. CBC-based
	// suites are out regardless of CA — they're not in the CMMC
	// allowlist per 800-171 3.13.8/11.
	got := FIPSCipherSuites()
	all := tls.CipherSuites()
	byID := map[uint16]*tls.CipherSuite{}
	for _, s := range all {
		byID[s.ID] = s
	}
	for _, id := range got {
		info, ok := byID[id]
		if !ok {
			t.Errorf("cipher %#x unknown to Go stdlib", id)
			continue
		}
		// Go's CipherSuite doesn't expose AEAD explicitly; pin via the
		// stable name prefix instead.
		if !strings.Contains(info.Name, "GCM") {
			t.Errorf("cipher %q is not AES-GCM AEAD", info.Name)
		}
	}
}

func TestFIPSCurves(t *testing.T) {
	got := FIPSCurves()
	want := map[tls.CurveID]string{
		tls.CurveP256: "P-256",
		tls.CurveP384: "P-384",
	}
	if len(got) != len(want) {
		t.Errorf("curve count = %d, want %d", len(got), len(want))
	}
	for _, c := range got {
		if _, ok := want[c]; !ok {
			t.Errorf("unexpected curve %v (X25519 must not be present)", c)
		}
	}
	// X25519 explicitly not allowed.
	for _, c := range got {
		if c == tls.X25519 {
			t.Fatalf("X25519 is not in the FIPS curve allowlist")
		}
	}
}

func TestServer_ConfigShape(t *testing.T) {
	cfg := Server()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS1.2", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Error("Server config has no CipherSuites — FIPS listener would not pin ciphers")
	}
	if len(cfg.CurvePreferences) == 0 {
		t.Error("Server config has no CurvePreferences")
	}
}

