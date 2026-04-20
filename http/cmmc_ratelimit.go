package fbhttp

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
)

// TokenBucket is an IP-keyed token bucket for rate limiting
// unauthenticated or weakly-authenticated endpoints (login, public
// share access). Burst tokens replenish at refillEvery; map keys
// age out via Sweep so memory is bounded across long uptimes.
//
// This is a first line of defense — not a replacement for IdP-side
// brute-force protection (Keycloak has its own). Keeps a rogue
// client from hammering the filebrowser front door hard enough to
// amplify attempts into the IdP backend.
//
// Satisfies:
//   - CMMC 3.1.8 (limit unsuccessful logon attempts) — auth gate
//   - CMMC 3.13.4 (prevent unauthorized info transfer) — share
//     share-token brute force defense
type TokenBucket struct {
	mu          sync.Mutex
	buckets     map[string]*bucketState
	burst       int
	refillEvery time.Duration
}

type bucketState struct {
	tokens   int
	updated  time.Time
}

// NewTokenBucket returns a bucket with the given burst capacity and
// refill interval (one token per refillEvery). A burst <= 0 or a
// non-positive interval returns nil — the operator explicitly
// disabled this rate limiter.
func NewTokenBucket(burst int, refillEvery time.Duration) *TokenBucket {
	if burst <= 0 || refillEvery <= 0 {
		return nil
	}
	return &TokenBucket{
		buckets:     make(map[string]*bucketState),
		burst:       burst,
		refillEvery: refillEvery,
	}
}

// Allow decrements the caller's bucket if tokens are available and
// returns true. Returns false when the bucket is empty along with
// the time to wait until the next refill. A nil receiver returns
// (true, 0) — feature off.
func (b *TokenBucket) Allow(key string) (bool, time.Duration) {
	if b == nil {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	st, ok := b.buckets[key]
	if !ok {
		st = &bucketState{tokens: b.burst, updated: now}
		b.buckets[key] = st
	}
	// Refill: one token per refillEvery elapsed since last update,
	// capped at burst.
	elapsed := now.Sub(st.updated)
	if elapsed > 0 && b.refillEvery > 0 {
		gained := int(elapsed / b.refillEvery)
		if gained > 0 {
			st.tokens += gained
			if st.tokens > b.burst {
				st.tokens = b.burst
			}
			st.updated = st.updated.Add(time.Duration(gained) * b.refillEvery)
		}
	}
	if st.tokens <= 0 {
		return false, b.refillEvery - now.Sub(st.updated)
	}
	st.tokens--
	return true, 0
}

// Sweep drops bucket rows that haven't been touched for age. A row
// that's fully refilled but has activity within the window stays
// so back-to-back bursts from the same IP see the same bucket.
// Intended to run from a goroutine ticker so long-lived processes
// don't accumulate a bucket per ephemeral NAT client.
func (b *TokenBucket) Sweep(age time.Duration) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := time.Now().Add(-age)
	for k, st := range b.buckets {
		if st.updated.Before(cutoff) {
			delete(b.buckets, k)
		}
	}
}

// Size returns the current count of tracked IPs. Exposed for
// metrics / tests.
func (b *TokenBucket) Size() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}

// loadTokenBucketFromEnv reads FB_CMMC_RATELIMIT_<NAME>_BURST and
// FB_CMMC_RATELIMIT_<NAME>_REFILL (duration, e.g. "12s"). Returns
// nil when either is unset/zero — feature off for that surface.
// Never panics on malformed — defaults to nil so operators get a
// predictable "no limiter" on misconfig.
func loadTokenBucketFromEnv(name string, defaultBurst int, defaultRefill time.Duration) *TokenBucket {
	burst := defaultBurst
	refill := defaultRefill
	if raw := strings.TrimSpace(os.Getenv("FB_CMMC_RATELIMIT_" + name + "_BURST")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			burst = v
		}
	}
	if raw := strings.TrimSpace(os.Getenv("FB_CMMC_RATELIMIT_" + name + "_REFILL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			refill = d
		}
	}
	return NewTokenBucket(burst, refill)
}

// Rate limiters. Boot-time wiring (cmd/root.go) calls
// SetRateLimiters with the desired instances or disables by
// leaving them nil.
var (
	loginRateLimiter  *TokenBucket
	publicRateLimiter *TokenBucket
)

// SetRateLimiters installs the two rate limiter singletons. Called
// once at boot. Nil values disable enforcement for that surface.
func SetRateLimiters(login, public *TokenBucket) {
	loginRateLimiter = login
	publicRateLimiter = public
}

// LoadRateLimitersFromEnv returns the two limiters configured from
// the FB_CMMC_RATELIMIT_* env family with CMMC-sensible defaults.
// Login: 5 attempts, refill one every 12s (5 per minute). Public
// share: 20 requests, refill one every 3s (20 per minute).
func LoadRateLimitersFromEnv() (login, public *TokenBucket) {
	login = loadTokenBucketFromEnv("LOGIN", 5, 12*time.Second)
	public = loadTokenBucketFromEnv("PUBLIC", 20, 3*time.Second)
	return login, public
}

// rateLimitKey returns the effective source IP for rate-limiting
// decisions. Uses r.RemoteAddr (the socket peer) only — we
// deliberately do NOT consult X-Forwarded-For / X-Real-IP because
// those headers are set by the caller and spoofable by anyone
// hitting the listener directly. A deployment behind a trusted
// proxy that rewrites the socket peer (nginx with proxy_protocol,
// Trout Access Gate, HAProxy) gets the true client IP for free;
// a deployment that exposes filebrowser direct-to-internet gets
// bucket-per-connection-peer which is still correct.
//
// If FB_CMMC_TRUSTED_PROXY_CIDRS is set (comma-separated CIDRs),
// the first X-Forwarded-For hop is honored ONLY when the socket
// peer matches one of the trusted proxy ranges.
func rateLimitKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && isTrustedProxy(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First hop in the chain is the real client.
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	return host
}

// isTrustedProxy checks whether the socket peer is allowed to
// supply X-Forwarded-For. Empty/unset env means "no proxy is
// trusted" — the safest default.
func isTrustedProxy(ip net.IP) bool {
	raw := strings.TrimSpace(os.Getenv("FB_CMMC_TRUSTED_PROXY_CIDRS"))
	if raw == "" {
		return false
	}
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// withRateLimit wraps a handler with a token-bucket check keyed on
// the client IP. emitAction is the audit action stamped on a block
// ("auth.ratelimit.block" or "share.ratelimit.block"). A nil bucket
// is a no-op — enforcement off.
func withRateLimit(bucket *TokenBucket, emitAction string, fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if bucket == nil {
			return fn(w, r, d)
		}
		ip := rateLimitKey(r)
		if ok, wait := bucket.Allow(ip); !ok {
			secs := int(wait.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			emitRateLimitBlock(r, emitAction, ip, wait)
			return http.StatusTooManyRequests, nil
		}
		return fn(w, r, d)
	}
}

// emitRateLimitBlock records the 429 in the audit chain so SIEM can
// alert on sustained bucket exhaustion. IP is stamped as client_ip
// (always available); Reason includes the wait hint for operator
// triage.
func emitRateLimitBlock(r *http.Request, action, ip string, wait time.Duration) {
	ev := audit.New(action, audit.OutcomeReject)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = ip
	ev.UserAgent = r.UserAgent()
	ev.Resource = r.URL.Path
	ev.Status = http.StatusTooManyRequests
	ev.Reason = "rate limit exceeded; retry in ~" + wait.Truncate(time.Second).String()
	audit.Emit(r.Context(), ev)
}
