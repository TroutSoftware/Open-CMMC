package daemon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

//go:embed recipient_templates/*.html
var recipientTemplates embed.FS

var tmpls = template.Must(template.ParseFS(recipientTemplates, "recipient_templates/*.html"))

// PublicServer is the internet-facing HTTP surface. It exposes only
// three routes — landing, acknowledgment, download — and nothing
// else. No admin endpoints, no metrics endpoints, no listing: the
// daemon is a single-purpose hop for a single-purpose recipient.
type PublicServer struct {
	Store  *Store
	Audit  *AuditLog
	Pepper []byte // server-side secret added to every Argon2 derive

	// RateLimit is a simple in-memory per-IP token bucket; sufficient
	// for the DMZ's realistic traffic profile. A production deploy
	// behind a reverse proxy should also set rate-limits there.
	RateLimit *IPRateLimiter
}

// NewPublicServer wires the default route set.
func NewPublicServer(store *Store, audit *AuditLog, pepper []byte) *PublicServer {
	return &PublicServer{
		Store:     store,
		Audit:     audit,
		Pepper:    append([]byte(nil), pepper...),
		RateLimit: NewIPRateLimiter(30, time.Minute),
	}
}

// Routes returns a ready http.Handler. Using net/http rather than a
// router dep keeps the daemon's dependency set minimal — every
// extra package is an extra supply-chain concern in a DMZ binary.
func (s *PublicServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	// Share paths: /s/{id}, /s/{id}/acknowledge, /s/{id}/download.
	// net/http doesn't do path params so we dispatch by suffix.
	mux.HandleFunc("/s/", s.handleShare)
	mux.HandleFunc("/", s.handle404)
	return withSecurityHeaders(mux)
}

func (s *PublicServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// Deliberately no details — an internet-reachable health probe
	// that leaks version or config is a reconnaissance gift.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

func (s *PublicServer) handle404(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

// handleShare dispatches /s/{id}[/sub] to the right page/handler.
func (s *PublicServer) handleShare(w http.ResponseWriter, r *http.Request) {
	remote := clientIP(r)
	if !s.RateLimit.Allow(remote) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/s/")
	id, sub := splitFirst(rest, "/")

	if !validID(id) {
		s.notFound(w, r)
		return
	}

	meta, err := s.Store.Load(id)
	if err != nil {
		// No distinction between "never existed", "expired and
		// swept", or "auto-burned". Same 404 page.
		s.notFound(w, r)
		return
	}
	if meta.Expired(time.Now()) {
		_ = s.Store.Burn(id)
		s.notFound(w, r)
		return
	}

	switch {
	case sub == "" && r.Method == http.MethodGet:
		s.renderLanding(w, r, meta)
	case sub == "acknowledge" && r.Method == http.MethodPost:
		s.renderPassphrase(w, r, meta, "")
	case sub == "download" && r.Method == http.MethodPost:
		s.handleDownload(w, r, meta)
	default:
		s.notFound(w, r)
	}
}

func (s *PublicServer) notFound(w http.ResponseWriter, r *http.Request) {
	_, _ = s.Audit.Append(Event{
		Action:   ActionDownloadDenied,
		RemoteIP: clientIP(r),
		Outcome:  "not_found",
		Reason:   path.Clean(r.URL.Path),
	})
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *PublicServer) renderLanding(w http.ResponseWriter, r *http.Request, meta *Metadata) {
	_, _ = s.Audit.Append(Event{
		Action:        ActionLandingView,
		ShareID:       meta.ID,
		CorrelationID: meta.CorrelationID,
		RemoteIP:      clientIP(r),
		Outcome:       "success",
	})

	data := map[string]any{
		"ID":           meta.ID,
		"CUIMark":      humanMark(meta.CUIMark),
		"Filename":     meta.Filename,
		"SenderUserID": meta.SenderUserID,
		"ExpiresAt":    meta.ExpiresAt.Format(time.RFC1123),
		"DownloadsLeft": meta.DownloadsRemaining,
	}
	renderTemplate(w, "landing.html", data)
}

func (s *PublicServer) renderPassphrase(w http.ResponseWriter, r *http.Request, meta *Metadata, errMsg string) {
	data := map[string]any{
		"ID":       meta.ID,
		"CUIMark":  humanMark(meta.CUIMark),
		"Filename": meta.Filename,
		"Error":    errMsg,
	}
	renderTemplate(w, "passphrase.html", data)
}

// handleDownload verifies passphrase, decrements the counter, and
// streams the decrypted plaintext. A failed passphrase attempt is
// rate-limited and contributes to the per-share failure counter —
// enough failures and the share auto-burns.
func (s *PublicServer) handleDownload(w http.ResponseWriter, r *http.Request, meta *Metadata) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pass := r.FormValue("passphrase")
	if pass == "" {
		s.renderPassphrase(w, r, meta, "Passphrase required.")
		return
	}
	if _, ok := r.Form["acknowledge"]; !ok {
		s.renderPassphrase(w, r, meta, "You must acknowledge the CUI handling notice to continue.")
		return
	}

	dek, err := deriveAndUnwrap(meta.Wrap, pass, s.Pepper)
	if err != nil {
		after, _ := s.Store.RecordFailure(meta.ID)
		_, _ = s.Audit.Append(Event{
			Action:        ActionPassphraseFail,
			ShareID:       meta.ID,
			CorrelationID: meta.CorrelationID,
			RemoteIP:      clientIP(r),
			Outcome:       "fail",
			Reason:        "unwrap",
		})
		// If we just burned the share, fall through to 404 so the
		// attacker can't distinguish "wrong passphrase once" from
		// "share just burned after N tries" — they both look the
		// same from the outside.
		if after != nil && after.MaxFailures > 0 && after.FailureCount >= after.MaxFailures {
			_, _ = s.Audit.Append(Event{
				Action:        ActionBurned,
				ShareID:       meta.ID,
				CorrelationID: meta.CorrelationID,
				RemoteIP:      clientIP(r),
				Outcome:       "brute_force",
			})
			s.notFound(w, r)
			return
		}
		s.renderPassphrase(w, r, meta, "Incorrect passphrase.")
		return
	}

	_, _ = s.Audit.Append(Event{
		Action:        ActionPassphraseOK,
		ShareID:       meta.ID,
		CorrelationID: meta.CorrelationID,
		RemoteIP:      clientIP(r),
		Outcome:       "success",
	})

	// Read the ciphertext off disk BEFORE the counter decrement. If
	// this is the last-remaining download, RecordDownload will burn
	// the share (unlink the .blob) the moment it returns — doing the
	// read after that point races the unlink. Concurrent requests
	// are still safe: only one of them wins RecordDownload's mutex,
	// the rest get ErrNotFound.
	rc, err := s.Store.OpenBlob(meta.ID)
	if err != nil {
		s.notFound(w, r)
		return
	}
	ct, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		_, _ = s.Audit.Append(Event{
			Action:        ActionDownloadDenied,
			ShareID:       meta.ID,
			CorrelationID: meta.CorrelationID,
			RemoteIP:      clientIP(r),
			Outcome:       "blob_read_error",
			Reason:        err.Error(),
		})
		http.Error(w, "blob read error", http.StatusInternalServerError)
		return
	}

	if _, err := s.Store.RecordDownload(meta.ID); err != nil {
		s.notFound(w, r)
		return
	}

	pt, err := blobDecrypt(dek, meta.Wrap, ct)
	if err != nil {
		_, _ = s.Audit.Append(Event{
			Action:        ActionDownloadDenied,
			ShareID:       meta.ID,
			CorrelationID: meta.CorrelationID,
			RemoteIP:      clientIP(r),
			Outcome:       "decrypt_error",
			Reason:        err.Error(),
		})
		http.Error(w, "decrypt error", http.StatusInternalServerError)
		return
	}

	s.writeDownload(w, meta, pt)
	_, _ = s.Audit.Append(Event{
		Action:        ActionDownloadOK,
		ShareID:       meta.ID,
		CorrelationID: meta.CorrelationID,
		RemoteIP:      clientIP(r),
		Outcome:       "success",
	})
}

// writeDownload sets the response headers and writes the plaintext
// body. Separated out so the caller can log before/after without
// the response header logic cluttering the flow.
func (s *PublicServer) writeDownload(w http.ResponseWriter, meta *Metadata, pt []byte) {
	cd := meta.ContentType
	if cd == "" {
		cd = "application/octet-stream"
	}
	fn := safeFilename(meta.Filename)
	w.Header().Set("Content-Type", cd)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fn))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pt)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pt)
}

// deriveAndUnwrap derives the key-wrapping-key from passphrase + salt
// + server pepper via Argon2id, then unwraps the DEK with AES-256-GCM.
// Wrong passphrase produces a GCM auth failure — treated as an
// incorrect-passphrase signal by the caller. Errors are intentionally
// opaque to the recipient.
func deriveAndUnwrap(wp WrapParams, passphrase string, pepper []byte) ([]byte, error) {
	if wp.KDF != "argon2id" {
		return nil, fmt.Errorf("unknown kdf %q", wp.KDF)
	}
	salt, err := base64.StdEncoding.DecodeString(wp.SaltB64)
	if err != nil {
		return nil, fmt.Errorf("salt decode: %w", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(wp.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("wrapped dek decode: %w", err)
	}
	// Peppered passphrase: the server-side pepper means an attacker
	// who steals the DMZ disk still needs server secrets to even
	// attempt a single Argon2 derive.
	material := make([]byte, 0, len(passphrase)+len(pepper))
	material = append(material, []byte(passphrase)...)
	material = append(material, pepper...)

	kwk := argon2.IDKey(material, salt, wp.Argon2Time, wp.Argon2Mem, wp.Argon2Par, 32)
	block, err := aes.NewCipher(kwk)
	if err != nil {
		return nil, fmt.Errorf("kwk cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kwk gcm: %w", err)
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, errors.New("wrapped dek too short")
	}
	nonce, body := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	dek, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		// Wrong passphrase is the overwhelmingly common case here
		// — the caller maps this to "incorrect passphrase" without
		// distinguishing it from corrupted-wrap (both 401 the same).
		return nil, errors.New("unwrap failed")
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("unwrapped dek wrong size: %d", len(dek))
	}
	return dek, nil
}

// blobDecrypt performs the outer AES-GCM pass over the ciphertext
// blob using the DEK recovered from deriveAndUnwrap and the nonce
// the enclave recorded in the wrap params.
func blobDecrypt(dek []byte, wp WrapParams, ciphertext []byte) ([]byte, error) {
	if wp.BlobAEAD != "aes-256-gcm" {
		return nil, fmt.Errorf("unknown blob aead %q", wp.BlobAEAD)
	}
	nonce, err := base64.StdEncoding.DecodeString(wp.BlobNonce)
	if err != nil {
		return nil, fmt.Errorf("blob nonce decode: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("blob cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("blob gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("blob nonce size %d, want %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// renderTemplate executes a template into a ResponseWriter with
// the security headers the caller's middleware will also set.
func renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpls.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// withSecurityHeaders wraps every response with strict security
// headers. The daemon has no framing, no scripts, no cross-origin
// needs — we lock everything down.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
		h.Set("Permissions-Policy", "interest-cohort=()")
		next.ServeHTTP(w, r)
	})
}

// splitFirst splits s at the first sep. Returns (before, after). If
// sep is absent, after is empty.
func splitFirst(s, sep string) (string, string) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+len(sep):]
}

// clientIP extracts the client IP from X-Forwarded-For when behind
// a reverse proxy, else r.RemoteAddr. The DMZ pattern assumes a
// reverse proxy is always present (nginx / caddy / Access Gate) so
// XFF is the primary source.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Leftmost entry is the original client per RFC 7239.
		if comma := strings.Index(xff, ","); comma > 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// safeFilename sanitizes a filename for Content-Disposition. Strips
// any path components and control characters; caps length.
func safeFilename(name string) string {
	name = path.Base(name)
	if name == "" || name == "." || name == "/" {
		name = "file"
	}
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == '"' || r == '\\' || r == '/' {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 128 {
			break
		}
	}
	if b.Len() == 0 {
		return "file"
	}
	return b.String()
}

// humanMark maps internal CUI codes to the display format used in
// the UI. Empty mark renders as an explicit "UNMARKED" rather than
// blank so a misconfigured share is immediately obvious.
func humanMark(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	switch m {
	case "", "NONE":
		return "UNMARKED"
	case "BASIC":
		return "CUI//BASIC"
	case "SPECIFIED":
		return "CUI//SPECIFIED"
	case "SP-PROPIN":
		return "CUI//SP-PROPIN"
	case "SP-PRVCY":
		return "CUI//SP-PRVCY"
	case "SP-ITAR":
		return "CUI//SP-ITAR"
	}
	return "CUI//" + m
}

// IPRateLimiter is a small fixed-window rate limiter. Not a token
// bucket — simpler, good enough for the DMZ's traffic profile (a
// handful of downloads per minute).
type IPRateLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count     int
	resetAt   time.Time
}

// NewIPRateLimiter allows up to limit requests per window per IP.
func NewIPRateLimiter(limit int, window time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
	}
}

// Allow returns whether the given IP is under its quota.
// Side effect: increments the IP's counter on allow.
func (r *IPRateLimiter) Allow(ip string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[ip]
	if b == nil || now.After(b.resetAt) {
		r.buckets[ip] = &bucket{count: 1, resetAt: now.Add(r.window)}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}

// constantTimeEqual is a typed wrapper for subtle.ConstantTimeCompare.
// Used by test helpers; retained in-package so future callers don't
// reach for bytes.Equal in a passphrase comparison.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
