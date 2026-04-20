package fbhttp

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestRateLimitKey_IgnoresSpoofedXFF_WhenNoTrustedProxies — reviewer-
// flagged bypass: without FB_CMMC_TRUSTED_PROXY_CIDRS configured,
// X-Forwarded-For must be ignored. Attacker rotating XFF values
// does not get per-value buckets.
func TestRateLimitKey_IgnoresSpoofedXFF_WhenNoTrustedProxies(t *testing.T) {
	t.Setenv("FB_CMMC_TRUSTED_PROXY_CIDRS", "")
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	k1 := rateLimitKey(r)
	r.Header.Set("X-Forwarded-For", "5.6.7.8")
	k2 := rateLimitKey(r)
	if k1 != "10.0.0.1" || k2 != "10.0.0.1" {
		t.Errorf("XFF spoofing bypass: k1=%q k2=%q (want 10.0.0.1)", k1, k2)
	}
}

// TestRateLimitKey_HonorsXFF_WhenProxyTrusted — correct path: the
// operator configured the CIDR of the real trusted proxy (e.g.
// Trout Access Gate), XFF from that peer is honored.
func TestRateLimitKey_HonorsXFF_WhenProxyTrusted(t *testing.T) {
	t.Setenv("FB_CMMC_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.5.5.5:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.42, 10.5.5.5")
	if got := rateLimitKey(r); got != "203.0.113.42" {
		t.Errorf("trusted-proxy XFF not honored: got %q, want 203.0.113.42", got)
	}
}

// TestRateLimitKey_UntrustedPeerCannotSpoof — a request from an
// IP outside the trusted CIDR cannot trick the limiter even if
// it sets XFF.
func TestRateLimitKey_UntrustedPeerCannotSpoof(t *testing.T) {
	t.Setenv("FB_CMMC_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "198.51.100.7:9999" // not in 10.0.0.0/8
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := rateLimitKey(r); got != "198.51.100.7" {
		t.Errorf("untrusted peer XFF accepted: got %q", got)
	}
}

// TestRateLimitKey_MalformedCIDRs_Ignored — bad env values must
// not panic; they're silently skipped.
func TestRateLimitKey_MalformedCIDRs_Ignored(t *testing.T) {
	t.Setenv("FB_CMMC_TRUSTED_PROXY_CIDRS", "not-a-cidr, also-bad, 10.0.0.0/8")
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.1.1.1:1000"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := rateLimitKey(r); got != "1.1.1.1" {
		t.Errorf("valid CIDR after malformed ones should still work: got %q", got)
	}
}

func TestTokenBucket_NilDisabled(t *testing.T) {
	var b *TokenBucket
	ok, wait := b.Allow("1.2.3.4")
	if !ok || wait != 0 {
		t.Errorf("nil bucket must allow everything")
	}
	b.Sweep(time.Hour) // must not panic
	if b.Size() != 0 {
		t.Error("nil Size must return 0")
	}
}

func TestTokenBucket_ZeroOrNegativeBurstReturnsNil(t *testing.T) {
	if NewTokenBucket(0, time.Second) != nil {
		t.Error("burst=0 must return nil (feature off)")
	}
	if NewTokenBucket(-1, time.Second) != nil {
		t.Error("negative burst must return nil")
	}
	if NewTokenBucket(5, 0) != nil {
		t.Error("refill=0 must return nil")
	}
}

func TestTokenBucket_BurstThenBlock(t *testing.T) {
	b := NewTokenBucket(3, time.Hour) // long refill so we stay in burst phase
	for i := 0; i < 3; i++ {
		if ok, _ := b.Allow("1.2.3.4"); !ok {
			t.Fatalf("burst attempt %d rejected", i)
		}
	}
	ok, wait := b.Allow("1.2.3.4")
	if ok {
		t.Error("4th request must be rejected (burst exhausted)")
	}
	if wait <= 0 {
		t.Errorf("expected positive wait hint, got %v", wait)
	}
}

func TestTokenBucket_PerIPIsolation(t *testing.T) {
	b := NewTokenBucket(1, time.Hour)
	if ok, _ := b.Allow("1.1.1.1"); !ok {
		t.Fatal("first IP first request rejected")
	}
	if ok, _ := b.Allow("2.2.2.2"); !ok {
		t.Fatal("different IP must get its own bucket")
	}
	if ok, _ := b.Allow("1.1.1.1"); ok {
		t.Fatal("first IP second request should be blocked")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	b := NewTokenBucket(1, 50*time.Millisecond)
	if ok, _ := b.Allow("x"); !ok {
		t.Fatal("first request rejected")
	}
	if ok, _ := b.Allow("x"); ok {
		t.Fatal("second immediate request must block")
	}
	time.Sleep(80 * time.Millisecond)
	if ok, _ := b.Allow("x"); !ok {
		t.Error("post-refill request must succeed")
	}
}

func TestTokenBucket_Sweep_DropsIdle(t *testing.T) {
	b := NewTokenBucket(1, time.Millisecond)
	b.Allow("idle-ip")
	// Advance past refill so tokens are back to burst, but row
	// remains.
	time.Sleep(5 * time.Millisecond)
	b.Allow("idle-ip") // refills
	b.Sweep(time.Microsecond)
	if sz := b.Size(); sz != 0 {
		t.Errorf("sweep should have dropped idle row, Size=%d", sz)
	}
}

func TestTokenBucket_Concurrent(t *testing.T) {
	b := NewTokenBucket(100, time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				b.Allow("shared")
			}
		}()
	}
	wg.Wait()
	// No assertion on state — race detector is the check.
}

func TestLoadTokenBucketFromEnv_Defaults(t *testing.T) {
	t.Setenv("FB_CMMC_RATELIMIT_FOO_BURST", "")
	t.Setenv("FB_CMMC_RATELIMIT_FOO_REFILL", "")
	b := loadTokenBucketFromEnv("FOO", 7, 2*time.Second)
	if b == nil {
		t.Fatal("defaults must produce a non-nil bucket")
	}
}

func TestLoadTokenBucketFromEnv_Overrides(t *testing.T) {
	t.Setenv("FB_CMMC_RATELIMIT_BAR_BURST", "50")
	t.Setenv("FB_CMMC_RATELIMIT_BAR_REFILL", "1s")
	b := loadTokenBucketFromEnv("BAR", 1, time.Second)
	// Fill burst to cap → should allow 50 before blocking.
	allowed := 0
	for i := 0; i < 60; i++ {
		if ok, _ := b.Allow("ip"); ok {
			allowed++
		}
	}
	if allowed != 50 {
		t.Errorf("burst override: allowed=%d, want 50", allowed)
	}
}

func TestLoadTokenBucketFromEnv_MalformedIgnored(t *testing.T) {
	t.Setenv("FB_CMMC_RATELIMIT_BAZ_BURST", "not-a-number")
	t.Setenv("FB_CMMC_RATELIMIT_BAZ_REFILL", "not-a-duration")
	b := loadTokenBucketFromEnv("BAZ", 3, time.Second)
	if b == nil {
		t.Error("malformed values must fall back to defaults, not disable")
	}
}
