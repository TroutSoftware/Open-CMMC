package keyderive

import (
	"bytes"
	"errors"
	"testing"
)

var master = bytes.Repeat([]byte("m"), 32)

func TestSubKey_Deterministic(t *testing.T) {
	a, err := SubKey(master, "label-a", 32)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := SubKey(master, "label-a", 32)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("same inputs must produce same subkey")
	}
}

func TestSubKey_DomainSeparation(t *testing.T) {
	a, _ := SubKey(master, "label-a", 32)
	b, _ := SubKey(master, "label-b", 32)
	if bytes.Equal(a, b) {
		t.Error("different labels must produce different subkeys")
	}
}

func TestSessionAndAudit_AreDistinct(t *testing.T) {
	s, err := SessionSigningKey(master)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	a, err := AuditChainKey(master)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if bytes.Equal(s, a) {
		t.Error("session and audit subkeys MUST differ (domain separation)")
	}
	if len(s) != 32 || len(a) != 32 {
		t.Errorf("subkey lengths s=%d a=%d, want 32", len(s), len(a))
	}
}

func TestSubKey_RejectsShortMaster(t *testing.T) {
	_, err := SubKey([]byte("short"), "x", 32)
	if !errors.Is(err, ErrMasterTooShort) {
		t.Errorf("want ErrMasterTooShort, got %v", err)
	}
}

func TestSubKey_RejectsZeroSize(t *testing.T) {
	if _, err := SubKey(master, "x", 0); err == nil {
		t.Error("size=0 must error")
	}
	if _, err := SubKey(master, "x", -1); err == nil {
		t.Error("negative size must error")
	}
}

func TestSubKey_RejectsEmptyLabel(t *testing.T) {
	if _, err := SubKey(master, "", 32); err == nil {
		t.Error("empty label must error")
	}
}

func TestSubKey_DifferentMastersYieldDifferentSubkeys(t *testing.T) {
	m1 := bytes.Repeat([]byte("a"), 32)
	m2 := bytes.Repeat([]byte("b"), 32)
	k1, _ := SessionSigningKey(m1)
	k2, _ := SessionSigningKey(m2)
	if bytes.Equal(k1, k2) {
		t.Error("different masters must yield different subkeys")
	}
}

func TestLabelsAreVersioned(t *testing.T) {
	// Pin the label strings — if someone bumps -v1 → -v2 it's a
	// breaking change and should be a deliberate test-break.
	if LabelSessionSign != "cmmc-session-jwt-v1" {
		t.Errorf("LabelSessionSign = %q, labels are API", LabelSessionSign)
	}
	if LabelAuditChain != "cmmc-audit-chain-v1" {
		t.Errorf("LabelAuditChain = %q, labels are API", LabelAuditChain)
	}
}
