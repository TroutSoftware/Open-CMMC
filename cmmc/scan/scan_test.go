package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMockScanner_Clean(t *testing.T) {
	s := &MockScanner{Clean: true}
	r, err := s.Scan(context.Background(), strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !r.Clean {
		t.Errorf("clean = false")
	}
	if s.Calls != 1 {
		t.Errorf("calls = %d", s.Calls)
	}
}

func TestMockScanner_Infected(t *testing.T) {
	s := &MockScanner{Clean: false, Signature: "Eicar-Test-Signature"}
	r, err := s.Scan(context.Background(), strings.NewReader("<eicar bytes>"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Clean {
		t.Error("infected verdict must set Clean=false")
	}
	if r.Signature != "Eicar-Test-Signature" {
		t.Errorf("signature = %q", r.Signature)
	}
}

func TestMockScanner_HonorsContextCancel(t *testing.T) {
	s := &MockScanner{Clean: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Scan(ctx, strings.NewReader("data"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want Canceled", err)
	}
}

func TestRejectedError_Format(t *testing.T) {
	e := &RejectedError{Signature: "Win.Trojan.Example", Path: "/srv/x.exe"}
	if !strings.Contains(e.Error(), "Win.Trojan.Example") {
		t.Errorf("Error() = %q; must include signature", e.Error())
	}
	// Unwrapping via errors.As.
	var target *RejectedError
	if !errors.As(e, &target) {
		t.Error("errors.As(*RejectedError) failed")
	}
	if target.Path != "/srv/x.exe" {
		t.Errorf("Path lost through errors.As: %q", target.Path)
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":          ModeDisabled,
		"disabled":  ModeDisabled,
		"optional":  ModeOptional,
		"required":  ModeRequired,
		"REQUIRED":  ModeRequired,
		"garbage":   ModeDisabled, // with stderr warning, but no crash
	}
	for in, want := range cases {
		t.Setenv("FB_CMMC_AV", in)
		if got := ParseMode(); got != want {
			t.Errorf("FB_CMMC_AV=%q → %q, want %q", in, got, want)
		}
	}
}

func TestLoadScannerFromEnv_DisabledReturnsNilNilNil(t *testing.T) {
	s, err := LoadScannerFromEnv(ModeDisabled)
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if s != nil {
		t.Errorf("scanner should be nil when disabled")
	}
}

func TestLoadScannerFromEnv_UnknownBackend_RequiredFails(t *testing.T) {
	t.Setenv("FB_CMMC_AV_BACKEND", "nope-does-not-exist")
	_, err := LoadScannerFromEnv(ModeRequired)
	if err == nil {
		t.Error("expected error for unknown backend in required mode")
	}
}

func TestLoadScannerFromEnv_UnknownBackend_OptionalNils(t *testing.T) {
	t.Setenv("FB_CMMC_AV_BACKEND", "nope-does-not-exist")
	s, err := LoadScannerFromEnv(ModeOptional)
	if err != nil {
		t.Errorf("optional mode should not error on unknown backend; got %v", err)
	}
	if s != nil {
		t.Errorf("scanner should be nil when backend unknown + optional")
	}
}

func TestRegisterBackend_WinsLastRegistration(t *testing.T) {
	// Save+restore the map so this test doesn't pollute other tests.
	saved := backends
	t.Cleanup(func() { backends = saved })
	backends = map[string]func() (Scanner, error){}

	calls := 0
	RegisterBackend("test", func() (Scanner, error) {
		calls++
		return &MockScanner{Clean: true}, nil
	})
	RegisterBackend("test", func() (Scanner, error) {
		calls += 100
		return &MockScanner{Clean: true}, nil
	})
	t.Setenv("FB_CMMC_AV_BACKEND", "test")
	if _, err := LoadScannerFromEnv(ModeOptional); err != nil {
		t.Fatalf("load: %v", err)
	}
	// Second Register should have overwritten first; factory called
	// exactly once with calls += 100.
	if calls != 100 {
		t.Errorf("factory call count = %d, want 100 (re-register should overwrite)", calls)
	}
}

// TestMockScanner_DrainsReader — real scanners always consume the
// full stream; the mock must match so tests can assert io.EOF on
// the source after a Scan.
func TestMockScanner_DrainsReader(t *testing.T) {
	input := strings.NewReader("abcdef")
	s := &MockScanner{Clean: true}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Scan(ctx, input); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Input should be fully consumed.
	buf := make([]byte, 4)
	n, _ := input.Read(buf)
	if n != 0 {
		t.Errorf("mock did not drain reader; %d bytes remained", n)
	}
}
