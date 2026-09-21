package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newBC(t *testing.T) (*BackChannel, *Store, *AuditLog, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	audit, _ := NewAuditLog(mkKey(t), 128)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	bc, err := NewBackChannel(store, audit, raw)
	if err != nil {
		t.Fatalf("NewBackChannel: %v", err)
	}
	return bc, store, audit, bc.BearerToken
}

func TestBackChannel_Push_HappyPath(t *testing.T) {
	bc, store, audit, token := newBC(t)
	id, _ := NewID()
	meta := Metadata{
		ID:                 id,
		CreatedAt:          time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		MaxDownloads:       1,
		DownloadsRemaining: 1,
		MaxFailures:        5,
		CUIMark:            "BASIC",
		SenderUserID:       "flo",
		CorrelationID:      "cor-1",
		Filename:           "x.pdf",
		ContentType:        "application/pdf",
	}
	metaJSON, _ := json.Marshal(meta)
	body := []byte("ciphertext-goes-here")

	req := httptest.NewRequest(http.MethodPost, "/push", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Share-Meta", string(metaJSON))
	req.Header.Set("X-Blob-Length", "20")
	rr := httptest.NewRecorder()
	bc.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := store.Load(id); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if audit.Len() != 1 {
		t.Fatalf("expected 1 audit event, got %d", audit.Len())
	}
}

func TestBackChannel_Push_RejectsWrongToken(t *testing.T) {
	bc, _, _, _ := newBC(t)
	req := httptest.NewRequest(http.MethodPost, "/push", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 32))
	req.Header.Set("X-Share-Meta", `{}`)
	req.Header.Set("X-Blob-Length", "0")
	rr := httptest.NewRecorder()
	bc.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestBackChannel_Push_RejectsOversizedBlob(t *testing.T) {
	bc, _, _, token := newBC(t)
	bc.MaxBlobBytes = 100
	req := httptest.NewRequest(http.MethodPost, "/push", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Share-Meta", `{}`)
	req.Header.Set("X-Blob-Length", "999")
	rr := httptest.NewRecorder()
	bc.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestBackChannel_AuditDrainAndAck(t *testing.T) {
	bc, _, audit, token := newBC(t)
	_, _ = audit.Append(Event{Action: ActionLandingView, ShareID: "a"})
	_, _ = audit.Append(Event{Action: ActionDownloadOK, ShareID: "a"})

	// Drain
	req := httptest.NewRequest(http.MethodGet, "/audit?max=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	bc.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("drain expected 200, got %d", rr.Code)
	}
	var drained struct {
		Events  []Event `json:"events"`
		Pending int     `json:"pending"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &drained); err != nil {
		t.Fatalf("decode drain: %v", err)
	}
	if len(drained.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(drained.Events))
	}

	// Ack through seq 1 (remove both).
	ackBody, _ := json.Marshal(map[string]uint64{"through": 1})
	req = httptest.NewRequest(http.MethodPost, "/audit/ack", bytes.NewReader(ackBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	bc.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("ack expected 204, got %d", rr.Code)
	}
	if audit.Len() != 0 {
		t.Fatalf("expected 0 remaining, got %d", audit.Len())
	}
}

func TestBackChannel_RevokeBurnsShare(t *testing.T) {
	bc, store, audit, token := newBC(t)
	id, _ := NewID()
	m := &Metadata{
		ID: id, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		MaxDownloads: 1, DownloadsRemaining: 1, MaxFailures: 5, BlobSize: 3,
	}
	_ = store.Create(m, bytes.NewReader([]byte("xyz")))

	body, _ := json.Marshal(map[string]string{"share_id": id, "reason": "sender recalled"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	bc.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := store.Load(id); err == nil {
		t.Fatalf("expected share removed after revoke")
	}
	burned := false
	for _, e := range audit.Drain(0) {
		if e.Action == ActionBurned && e.Reason == "sender recalled" {
			burned = true
		}
	}
	if !burned {
		t.Fatalf("expected revoke audit event")
	}
}

func TestNewBackChannel_RejectsShortToken(t *testing.T) {
	store, _ := NewStore(mkDir700(t))
	audit, _ := NewAuditLog(mkKey(t), 16)
	if _, err := NewBackChannel(store, audit, []byte("short")); err == nil {
		t.Fatalf("expected short-token rejection")
	}
}

func mkDir700(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	_ = os.Chmod(d, 0o700)
	return d
}
