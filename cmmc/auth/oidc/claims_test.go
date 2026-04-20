package oidc

import (
	"testing"
)

// These tests cover the claim-extraction helpers in callback.go. The
// integration-level ExchangeAndVerify test lives in callback_test.go and
// exercises the full path including go-oidc verification.

func TestNormalizeStringSlice(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want int
	}{
		{"nil", nil, 0},
		{"empty string", "", 0},
		{"single string", "alpha", 1},
		{"slice of string", []string{"a", "b"}, 2},
		{"slice of interface", []interface{}{"x", "y", "z"}, 3},
		{"slice of interface with non-strings", []interface{}{"a", 42, "b"}, 2},
		{"unsupported type", 42, 0},
		{"map", map[string]string{"a": "b"}, 0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := normalizeStringSlice(c.in)
			if len(got) != c.want {
				t.Errorf("normalizeStringSlice(%v) = %v (len %d), want len %d", c.in, got, len(got), c.want)
			}
		})
	}
}

func TestPickStringClaim(t *testing.T) {
	rc := rawClaims{
		Sub:               "stable-sub",
		Email:             "user@example.mil",
		PreferredUsername: "pref",
		UPN:               "user@tenant",
		Name:              "Real Name",
		Username:          "from-generic-username",
	}
	cases := map[string]string{
		"preferred_username": "pref",
		"PREFERRED_USERNAME": "pref", // lowercased in impl
		"upn":                "user@tenant",
		"email":              "user@example.mil",
		"name":               "Real Name",
		"sub":                "stable-sub",
		"username":           "from-generic-username",
		"unknown":            "",
	}
	for claim, want := range cases {
		claim := claim
		want := want
		t.Run(claim, func(t *testing.T) {
			got := pickStringClaim(rc, claim)
			if got != want {
				t.Errorf("pickStringClaim(%q) = %q, want %q", claim, got, want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "c"); got != "c" {
		t.Errorf("firstNonEmpty skipped empties: got %q", got)
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("firstNonEmpty not left-to-right: got %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("firstNonEmpty() = %q, want empty", got)
	}
}

func TestAuthTime_FallbackToNowWhenMissing(t *testing.T) {
	got := authTime(0)
	if got.IsZero() {
		t.Errorf("authTime(0) must not be zero — should fall back to now")
	}
}

func TestAuthTime_UsesClaimWhenPresent(t *testing.T) {
	got := authTime(1700000000)
	if got.Unix() != 1700000000 {
		t.Errorf("authTime(1700000000) = %v, want unix 1700000000", got)
	}
}

func TestGenericClaim(t *testing.T) {
	rc := rawClaims{Groups: []string{"g1", "g2"}, AMR: []interface{}{"pwd", "mfa"}}
	if g := genericClaim(rc, "groups"); g == nil {
		t.Errorf("genericClaim(groups) returned nil")
	}
	if g := genericClaim(rc, "amr"); g == nil {
		t.Errorf("genericClaim(amr) returned nil")
	}
	if g := genericClaim(rc, "unknown"); g != nil {
		t.Errorf("genericClaim(unknown) = %v, want nil", g)
	}
}
