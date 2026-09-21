package enclave

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/filebrowser/filebrowser/v2/share/daemon"
)

// plaintextServer spins up the daemon's backchannel over HTTP (no
// TLS) so we can exercise the push contract end-to-end without
// wrangling test certs. Production always runs mTLS.
func plaintextServer(t *testing.T) (*httptest.Server, *daemon.Store, *daemon.AuditLog, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	store, err := daemon.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	auditKey := make([]byte, 32)
	_, _ = rand.Read(auditKey)
	audit, err := daemon.NewAuditLog(auditKey, 128)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	bc, err := daemon.NewBackChannel(store, audit, raw)
	if err != nil {
		t.Fatalf("NewBackChannel: %v", err)
	}
	ts := httptest.NewServer(bc.Routes())
	t.Cleanup(ts.Close)
	return ts, store, audit, bc.BearerToken
}

func TestPusher_EndToEnd(t *testing.T) {
	ts, store, audit, token := plaintextServer(t)

	pepper := make([]byte, 32)
	_, _ = rand.Read(pepper)

	p := goodParams(t)
	art, err := Rewrap(p, pepper, "p1", testParams)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	var pulled []daemon.Event
	pusher := &Pusher{
		DaemonURL:   ts.URL,
		BearerToken: token,
		Client:      &http.Client{Timeout: 5 * time.Second},
		Interval:    10 * time.Millisecond,
		OnAuditEvents: func(evs []daemon.Event) error {
			pulled = append(pulled, evs...)
			return nil
		},
	}
	pusher.Enqueue(art)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Run drainOnce directly — simpler than spinning Run + waiting.
	if err := pusher.drainOnce(ctx); err != nil {
		t.Fatalf("drainOnce: %v", err)
	}
	if pusher.Pending() != 0 {
		t.Fatalf("expected queue drained, got %d", pusher.Pending())
	}

	// Share landed in the daemon's store.
	got, err := store.Load(art.Meta.ID)
	if err != nil {
		t.Fatalf("Load on daemon side: %v", err)
	}
	if got.Filename != "report.pdf" {
		t.Errorf("metadata didn't round-trip")
	}
	// drainOnce also runs pullAudit, which returned the
	// push.accepted event to our callback and then acked it on the
	// daemon — so we assert on the pulled slice, not on the
	// daemon-side buffer which is intentionally empty now.
	seen := false
	for _, e := range pulled {
		if e.Action == daemon.ActionPushAccepted && e.ShareID == art.Meta.ID {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("expected push.accepted audit event in pulled slice; got %d events", len(pulled))
	}
	if audit.Len() != 0 {
		t.Fatalf("expected daemon audit buffer drained + acked; got %d remaining", audit.Len())
	}
}

func TestPusher_DrainAndAckAudit(t *testing.T) {
	ts, _, audit, token := plaintextServer(t)
	// Seed some events on the daemon side.
	_, _ = audit.Append(daemon.Event{Action: daemon.ActionLandingView, ShareID: "a"})
	_, _ = audit.Append(daemon.Event{Action: daemon.ActionDownloadOK, ShareID: "a"})
	if audit.Len() != 2 {
		t.Fatalf("seed failed: len %d", audit.Len())
	}

	got := 0
	pusher := &Pusher{
		DaemonURL:   ts.URL,
		BearerToken: token,
		Client:      &http.Client{Timeout: 5 * time.Second},
		OnAuditEvents: func(evs []daemon.Event) error {
			got += len(evs)
			return nil
		},
	}
	if err := pusher.drainOnce(context.Background()); err != nil {
		t.Fatalf("drainOnce: %v", err)
	}
	if got != 2 {
		t.Fatalf("expected 2 events handled, got %d", got)
	}
	if audit.Len() != 0 {
		t.Fatalf("expected daemon audit drained, got %d", audit.Len())
	}
}

func TestPusher_RetainsQueueOnPushError(t *testing.T) {
	// Point at a URL that will immediately 401 (bad token).
	ts, _, _, _ := plaintextServer(t)
	pusher := &Pusher{
		DaemonURL:   ts.URL,
		BearerToken: "wrong-token-which-is-also-too-short-for-server",
		Client:      &http.Client{Timeout: 5 * time.Second},
	}
	pepper := make([]byte, 32)
	_, _ = rand.Read(pepper)
	art, _ := Rewrap(goodParams(t), pepper, "p1", testParams)
	pusher.Enqueue(art)

	err := pusher.drainOnce(context.Background())
	if err == nil {
		t.Fatalf("expected error on bad token")
	}
	if pusher.Pending() == 0 {
		t.Fatalf("queue should be retained after failure")
	}
}
