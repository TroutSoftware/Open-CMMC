package daemon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// makeShare rewraps "payload" under the given passphrase + pepper
// and stores the blob + metadata in a fresh store. Returns the
// share id and metadata for test assertions.
func makeShare(t *testing.T, s *Store, passphrase string, pepper []byte, payload []byte, maxDownloads, maxFailures int) (*Metadata, string) {
	t.Helper()

	// DEK for the blob.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand dek: %v", err)
	}
	blobNonce := make([]byte, 12)
	if _, err := rand.Read(blobNonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	blobBlock, _ := aes.NewCipher(dek)
	blobGCM, _ := cipher.NewGCM(blobBlock)
	blob := blobGCM.Seal(nil, blobNonce, payload, nil)

	// Wrap DEK under argon2id(passphrase || pepper, salt).
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand salt: %v", err)
	}
	material := append([]byte{}, []byte(passphrase)...)
	material = append(material, pepper...)
	kwk := argon2.IDKey(material, salt, 1, 16*1024, 1, 32) // fast params for tests
	wrapBlock, _ := aes.NewCipher(kwk)
	wrapGCM, _ := cipher.NewGCM(wrapBlock)
	wrapNonce := make([]byte, 12)
	_, _ = rand.Read(wrapNonce)
	wrappedDEK := wrapGCM.Seal(nil, wrapNonce, dek, nil)
	wrappedCombined := append(wrapNonce, wrappedDEK...)

	id, _ := NewID()
	m := &Metadata{
		ID:                 id,
		CreatedAt:          time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		MaxDownloads:       maxDownloads,
		DownloadsRemaining: maxDownloads,
		MaxFailures:        maxFailures,
		CUIMark:            "BASIC",
		SenderUserID:       "flo",
		CorrelationID:      "cor-test",
		Filename:           "report.pdf",
		ContentType:        "application/pdf",
		Wrap: WrapParams{
			KDF:        "argon2id",
			Argon2Time: 1,
			Argon2Mem:  16 * 1024,
			Argon2Par:  1,
			SaltB64:    base64.StdEncoding.EncodeToString(salt),
			PepperID:   "p1",
			WrappedDEK: base64.StdEncoding.EncodeToString(wrappedCombined),
			BlobNonce:  base64.StdEncoding.EncodeToString(blobNonce),
			BlobAEAD:   "aes-256-gcm",
		},
	}
	if err := s.Create(m, bytes.NewReader(blob)); err != nil {
		t.Fatalf("Create share: %v", err)
	}
	return m, id
}

func newTestServer(t *testing.T) (*PublicServer, *Store, *AuditLog, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	audit, _ := NewAuditLog(mkKey(t), 128)
	pepper := make([]byte, 32)
	_, _ = rand.Read(pepper)
	return NewPublicServer(store, audit, pepper), store, audit, pepper
}

func TestServer_LandingReturnsHTML(t *testing.T) {
	ps, store, _, pepper := newTestServer(t)
	_, id := makeShare(t, store, "correct horse battery staple", pepper, []byte("payload"), 2, 5)

	req := httptest.NewRequest(http.MethodGet, "/s/"+id, nil)
	rr := httptest.NewRecorder()
	ps.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "A file has been shared with you") {
		t.Fatalf("landing html missing expected copy")
	}
	// CSP header set.
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatalf("CSP header missing")
	}
}

func TestServer_UnknownShare404(t *testing.T) {
	ps, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/s/0000000000000000000000000A", nil)
	rr := httptest.NewRecorder()
	ps.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestServer_DownloadHappyPath(t *testing.T) {
	ps, store, audit, pepper := newTestServer(t)
	payload := []byte("secret report contents")
	_, id := makeShare(t, store, "sesame-open", pepper, payload, 1, 5)

	form := url.Values{"passphrase": {"sesame-open"}, "acknowledge": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/s/"+id+"/download", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	ps.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	got, _ := io.ReadAll(rr.Body)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch; got %q", got)
	}
	// Share should have been auto-burned (1 download used).
	if _, err := store.Load(id); err == nil {
		t.Fatalf("expected share burned after last download")
	}
	// Audit trail has landing skip + passphrase OK + download OK.
	events := audit.Drain(0)
	seen := map[Action]int{}
	for _, e := range events {
		seen[e.Action]++
	}
	if seen[ActionPassphraseOK] == 0 || seen[ActionDownloadOK] == 0 {
		t.Fatalf("expected OK audit events, got %+v", seen)
	}
}

func TestServer_WrongPassphraseShowsError(t *testing.T) {
	ps, store, audit, pepper := newTestServer(t)
	_, id := makeShare(t, store, "right-password", pepper, []byte("x"), 1, 5)

	form := url.Values{"passphrase": {"wrong"}, "acknowledge": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/s/"+id+"/download", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	ps.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (re-render), got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Incorrect passphrase") {
		t.Fatalf("error not rendered in page body: %s", rr.Body.String())
	}
	// Failure counter bumped.
	m, err := store.Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.FailureCount != 1 {
		t.Fatalf("expected FailureCount=1, got %d", m.FailureCount)
	}
	// Audit has one passphrase-fail.
	events := audit.Drain(0)
	seen := 0
	for _, e := range events {
		if e.Action == ActionPassphraseFail {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("expected 1 passphrase.fail event, got %d", seen)
	}
}

func TestServer_BruteForceBurnsShare(t *testing.T) {
	ps, store, audit, pepper := newTestServer(t)
	_, id := makeShare(t, store, "right-password", pepper, []byte("x"), 1, 3)

	for i := 0; i < 3; i++ {
		form := url.Values{"passphrase": {"wrong"}, "acknowledge": {"1"}}
		req := httptest.NewRequest(http.MethodPost, "/s/"+id+"/download", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		ps.Routes().ServeHTTP(rr, req)
	}
	// Share gone.
	if _, err := store.Load(id); err == nil {
		t.Fatalf("expected share burned by brute force")
	}
	// Audit shows a burn event.
	burned := false
	for _, e := range audit.Drain(0) {
		if e.Action == ActionBurned {
			burned = true
			break
		}
	}
	if !burned {
		t.Fatalf("expected ActionBurned event")
	}
}

func TestServer_MissingAcknowledgeBlocks(t *testing.T) {
	ps, store, _, pepper := newTestServer(t)
	_, id := makeShare(t, store, "pw", pepper, []byte("x"), 1, 5)
	form := url.Values{"passphrase": {"pw"}} // no acknowledge checkbox
	req := httptest.NewRequest(http.MethodPost, "/s/"+id+"/download", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	ps.Routes().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "acknowledge") {
		t.Fatalf("expected acknowledgment-required prompt, got %s", rr.Body.String())
	}
	// Share must still exist — no download was served.
	if _, err := store.Load(id); err != nil {
		t.Fatalf("share should still exist: %v", err)
	}
}

func TestServer_RateLimit(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	store, _ := NewStore(dir)
	audit, _ := NewAuditLog(mkKey(t), 128)
	pepper := []byte("peppers peppers peppers peppers 00")
	ps := &PublicServer{
		Store:     store,
		Audit:     audit,
		Pepper:    pepper,
		RateLimit: NewIPRateLimiter(2, time.Minute),
	}

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/s/00000000000000000000000000", nil)
		rr := httptest.NewRecorder()
		ps.Routes().ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("unexpected 429 at request %d", i)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/s/00000000000000000000000000", nil)
	rr := httptest.NewRecorder()
	ps.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd req, got %d", rr.Code)
	}
}

func TestSafeFilename(t *testing.T) {
	// path.Base runs first so any directory prefix is stripped
	// (defense against Content-Disposition path injection); then
	// a whitelist filter removes control chars and quotes from
	// what remains.
	cases := map[string]string{
		"report.pdf":            "report.pdf",
		"/etc/passwd":           "passwd",
		"../../etc/passwd":      "passwd",
		"":                      "file",
		"bad\"name\\with/chars": "chars",
		"control\x00chars":      "controlchars",
	}
	for in, want := range cases {
		if got := safeFilename(in); got != want {
			t.Errorf("safeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
