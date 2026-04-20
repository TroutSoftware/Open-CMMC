package session

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
)

// DefaultFreshMFAThreshold is the interval beyond which a session's
// cmmc_mfa_at claim is considered stale for privileged operations. 10
// minutes matches architecture.md §4 and the common IdP step-up window.
const DefaultFreshMFAThreshold = 10 * time.Minute

// IsFreshMFA reports whether a Claims record carries MFA proof within
// the given threshold. Fail-closed: nil or zero-valued MFAAt returns
// false. Exported so the fbhttp http-handler wrapper can share the
// predicate with the net/http middleware in this package.
func IsFreshMFA(c *Claims, threshold time.Duration) bool {
	if c == nil || c.MFAAt == 0 {
		return false
	}
	return time.Since(time.Unix(c.MFAAt, 0)) <= threshold
}

// ErrStaleMFA is surfaced via the 401 response body for observability;
// the middleware does not include raw error text in logs that might
// reach untrusted log consumers.
var ErrStaleMFA = errors.New("mfa not fresh")

// KeyLookup returns the HS256 signing key the middleware should use to
// validate tokens. Typically a closure over settings.Key from the
// enclosing handler chain.
type KeyLookup func(r *http.Request) ([]byte, error)

// freshMFAParser is allocated once at package init so the middleware
// does not build a new parser on every request hot-path.
var freshMFAParser = jwt.NewParser(
	jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	jwt.WithExpirationRequired(),
)

// RequiresFreshMFA wraps the next handler with an authz gate that
// accepts the request only if the bearer session JWT carries a
// cmmc_mfa_at claim newer than threshold. Missing claim, invalid
// token, or stale MFA all fail-closed with a generic 401.
//
// Response body is intentionally uniform ("401 Unauthorized") across
// every reject branch so it does not disclose to a caller whether the
// failure was "no token", "bad signature", "missing MFA claim", or
// "stale MFA". The specific reason is still useful for operators; if
// you need visibility, wrap this in your own logging middleware.
func RequiresFreshMFA(threshold time.Duration, keyLookup KeyLookup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := keyLookup(r)
		if err != nil || len(key) == 0 {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		keyFunc := func(_ *jwt.Token) (interface{}, error) { return key, nil }
		var c Claims
		tok, err := request.ParseFromRequest(r, tokenExtractor{}, keyFunc, request.WithClaims(&c), request.WithParser(freshMFAParser))
		if err != nil || !tok.Valid {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		if !IsFreshMFA(&c, threshold) {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenExtractor mirrors the upstream fbhttp extractor: X-Auth header
// first, then the `auth` cookie on GET requests. Duplicated here
// because the upstream version is unexported. If upstream exports a
// shared extractor we should reuse it.
type tokenExtractor struct{}

func (tokenExtractor) ExtractToken(r *http.Request) (string, error) {
	if v := r.Header.Get("X-Auth"); v != "" && strings.Count(v, ".") == 2 {
		return v, nil
	}
	if r.Method == http.MethodGet {
		if ck, err := r.Cookie("auth"); err == nil && ck != nil && strings.Count(ck.Value, ".") == 2 {
			return ck.Value, nil
		}
	}
	return "", request.ErrNoTokenInRequest
}
