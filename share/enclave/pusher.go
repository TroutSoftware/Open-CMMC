package enclave

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/filebrowser/filebrowser/v2/share/daemon"
)

// Pusher is the enclave-side sender that shuttles new shares to the
// DMZ daemon and drains the daemon's audit buffer on every round
// trip. The pusher is the ONLY component that dials out of the
// enclave toward the DMZ — every other flow is inbound.
//
// Concurrency: Enqueue is safe to call from the filebrowser HTTP
// handler that services the "Share externally" action; the actual
// network I/O happens on a dedicated goroutine so the user-facing
// request returns as soon as the artifact is persisted.
type Pusher struct {
	// DaemonURL is the root of the share daemon's back-channel,
	// e.g. "https://share.internal:8445".
	DaemonURL string

	// BearerToken is the shared secret that both sides hold. It
	// travels as the Authorization header alongside the mTLS
	// client cert.
	BearerToken string

	// Client is an *http.Client preconfigured with mTLS: client
	// cert chaining to the enclave CA, root CAs including the
	// DMZ's server cert issuer. Callers build this via
	// NewMutualTLSClient below.
	Client *http.Client

	// Interval is how often the pusher drains its queue + pulls
	// the audit buffer from the daemon when it has nothing new to
	// push. 2–5s in production; tunable for tests.
	Interval time.Duration

	// OnAuditEvents is called with each drained batch of events
	// from the daemon. The enclave's main audit emitter folds
	// them into the HMAC chain here.
	OnAuditEvents func([]daemon.Event) error

	mu    sync.Mutex
	queue []*Artifact
}

// NewMutualTLSClient returns an *http.Client whose transport
// presents clientCert/clientKey to the DMZ daemon and trusts only
// the caCerts pool. A bare Client{} would happily talk to anything
// — requiring the caller to supply both sides of the pin means a
// misconfigured deployment fails loudly rather than silently
// downgrading.
func NewMutualTLSClient(clientCert tls.Certificate, caPool *tls.Config) *http.Client {
	cfg := caPool.Clone()
	cfg.Certificates = []tls.Certificate{clientCert}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: cfg,
			// No keep-alives means each push handshakes fresh;
			// for low-volume share traffic the cost is
			// negligible and the security story is clearer.
			DisableKeepAlives: true,
		},
	}
}

// Enqueue accepts an Artifact for eventual push. Returns immediately
// — the caller's request doesn't have to wait for network I/O to the
// DMZ. Shares survive a pusher restart because they're persisted
// to the enclave's BoltDB by the filebrowser before calling Enqueue
// (wiring left to the caller — this package is transport-only).
func (p *Pusher) Enqueue(a *Artifact) {
	if a == nil {
		return
	}
	p.mu.Lock()
	p.queue = append(p.queue, a)
	p.mu.Unlock()
}

// Pending returns the current queue depth. Used by metrics + tests.
func (p *Pusher) Pending() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue)
}

// Run blocks until ctx is cancelled, pushing queued shares and
// pulling audit events on each tick.
func (p *Pusher) Run(ctx context.Context) error {
	if p.Client == nil {
		return errors.New("pusher: nil Client")
	}
	if p.Interval <= 0 {
		p.Interval = 5 * time.Second
	}
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	for {
		if err := p.drainOnce(ctx); err != nil {
			// Transient errors are expected (DMZ reboot, network
			// blip). Log and continue — the queue persists across
			// ticks.
			if !errors.Is(err, context.Canceled) {
				fmt.Printf("share pusher: drain error: %v\n", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// drainOnce pushes every pending share, then pulls audit events.
// Returns the first error encountered; partial progress is kept.
func (p *Pusher) drainOnce(ctx context.Context) error {
	p.mu.Lock()
	batch := p.queue
	p.queue = nil
	p.mu.Unlock()

	for i, a := range batch {
		if err := p.pushOne(ctx, a); err != nil {
			// Put the un-pushed tail back in the queue so the next
			// tick retries. Preserves original ordering.
			p.mu.Lock()
			p.queue = append(batch[i:], p.queue...)
			p.mu.Unlock()
			return err
		}
	}
	return p.pullAudit(ctx)
}

// pushOne sends a single artifact. Uses header-framed metadata +
// raw body blob to match the daemon's /push contract.
func (p *Pusher) pushOne(ctx context.Context, a *Artifact) error {
	metaJSON, err := json.Marshal(a.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.DaemonURL+"/push", bytes.NewReader(a.Blob))
	if err != nil {
		return fmt.Errorf("new push req: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.BearerToken)
	req.Header.Set("X-Share-Meta", string(metaJSON))
	req.Header.Set("X-Blob-Length", strconv.Itoa(len(a.Blob)))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("push: daemon rejected %d: %s", resp.StatusCode, body)
	}
	return nil
}

// pullAudit drains the daemon's audit buffer and hands the events
// to OnAuditEvents. On success, acks the highest seq back to the
// daemon so it can free the buffer.
func (p *Pusher) pullAudit(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.DaemonURL+"/audit?max=1024", nil)
	if err != nil {
		return fmt.Errorf("new audit req: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.BearerToken)
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("audit pull: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("audit pull: %d: %s", resp.StatusCode, body)
	}
	var drained struct {
		Events  []daemon.Event `json:"events"`
		Pending int            `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&drained); err != nil {
		return fmt.Errorf("audit decode: %w", err)
	}
	if len(drained.Events) == 0 {
		return nil
	}
	if p.OnAuditEvents != nil {
		if err := p.OnAuditEvents(drained.Events); err != nil {
			// Don't ack; the daemon will re-serve the same events on
			// next pull. The enclave's audit emitter is expected to
			// dedupe by seq.
			return fmt.Errorf("audit handler: %w", err)
		}
	}
	highest := drained.Events[len(drained.Events)-1].Seq
	return p.ackAudit(ctx, highest)
}

func (p *Pusher) ackAudit(ctx context.Context, through uint64) error {
	body, _ := json.Marshal(map[string]uint64{"through": through})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.DaemonURL+"/audit/ack", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new ack req: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.BearerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("ack: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("ack: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Revoke asks the daemon to burn a share id. Typically called from
// the enclave's admin UI when a sender hits "recall share".
func (p *Pusher) Revoke(ctx context.Context, shareID, reason string) error {
	body, _ := json.Marshal(map[string]string{"share_id": shareID, "reason": reason})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.DaemonURL+"/revoke", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new revoke req: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.BearerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("revoke: %d: %s", resp.StatusCode, body)
	}
	return nil
}
