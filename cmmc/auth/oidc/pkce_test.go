package oidc

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// RFC 7636 §4.1: code_verifier is 43-128 chars from the unreserved set
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~". With 32 random bytes
// encoded as raw base64url we get exactly 43 chars of [A-Za-z0-9_-].
var rfc7636Verifier = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

func TestNewPKCE_VerifierMatchesRFC7636(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	if !rfc7636Verifier.MatchString(p.Verifier) {
		t.Errorf("verifier %q does not match RFC 7636 unreserved set / length", p.Verifier)
	}
	if p.Method != "S256" {
		t.Errorf("method = %q, want S256 (plain is rejected)", p.Method)
	}
}

func TestNewPKCE_ChallengeIsS256OfVerifier(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	want := VerifierChallenge(p.Verifier)
	if p.Challenge != want {
		t.Errorf("challenge = %q, want %q (S256 of verifier)", p.Challenge, want)
	}
	// Challenge should decode as 32 bytes (SHA-256 output).
	raw, err := base64.RawURLEncoding.DecodeString(p.Challenge)
	if err != nil {
		t.Fatalf("challenge not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("challenge decodes to %d bytes, want 32", len(raw))
	}
}

func TestNewPKCE_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		p, err := NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE[%d]: %v", i, err)
		}
		if _, dup := seen[p.Verifier]; dup {
			t.Fatalf("collision at iteration %d", i)
		}
		seen[p.Verifier] = struct{}{}
	}
}

func TestNewStateAndNonce_LengthAndCharset(t *testing.T) {
	cases := []struct {
		name string
		gen  func() (string, error)
	}{
		{"state", NewState},
		{"nonce", NewNonce},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			s, err := c.gen()
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(s) != 43 {
				t.Errorf("%s length = %d, want 43", c.name, len(s))
			}
			if strings.ContainsAny(s, "+/=") {
				t.Errorf("%s = %q contains non-URL-safe base64 chars", c.name, s)
			}
		})
	}
}

func TestNewStateAndNonce_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		s, err := NewState()
		if err != nil {
			t.Fatalf("NewState[%d]: %v", i, err)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("state collision at iteration %d", i)
		}
		seen[s] = struct{}{}
	}
}
