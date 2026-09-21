package daemon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Action is the closed set of share-daemon-visible audit actions.
// Keep the set small and stable — the enclave verifier rejects
// unknown actions on drain to stop a compromised daemon from
// injecting forged event shapes into the main audit log.
type Action string

const (
	ActionPushAccepted    Action = "share.push.accepted"
	ActionPushRejected    Action = "share.push.rejected"
	ActionLandingView     Action = "share.landing.view"
	ActionPassphraseOK    Action = "share.passphrase.ok"
	ActionPassphraseFail  Action = "share.passphrase.fail"
	ActionDownloadOK      Action = "share.download.ok"
	ActionDownloadDenied  Action = "share.download.denied"
	ActionBurned          Action = "share.burned"
	ActionSweeperExpired  Action = "share.sweeper.expired"
)

// Event is what the daemon buffers locally and the enclave drains
// on each back-channel pull. The fields are a deliberate subset of
// the main audit event schema so the drain path maps 1:1 into the
// enclave's HMAC chain without surprise.
type Event struct {
	Seq           uint64    `json:"seq"`
	Timestamp     time.Time `json:"ts"`
	Action        Action    `json:"action"`
	ShareID       string    `json:"share_id,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	RemoteIP      string    `json:"remote_ip,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	Reason        string    `json:"reason,omitempty"`

	// PrevMAC and MAC form a local HMAC chain that the enclave
	// verifies before folding events into its main chain. Any
	// tampering on the DMZ disk breaks the chain and is detected.
	PrevMAC string `json:"prev_mac"`
	MAC     string `json:"mac"`
}

// AuditLog is a capped, HMAC-chained ring. The daemon buffers events
// locally and the enclave drains them on each pull — Reserve() /
// AckThrough() give the enclave a simple two-phase drain so a failed
// network trip doesn't lose events.
//
// Why a ring and not persistent storage: if the daemon dies the
// buffer is lost, yes, but the alternative is a growing on-disk
// queue on the DMZ host which is itself an attractive target. An
// alert fires when the buffer crosses 50% full (HighWaterMark) and
// the enclave's pull interval is short. In practice events land in
// the main chain within seconds.
type AuditLog struct {
	key            []byte
	mu             sync.Mutex
	buf            []Event
	cap            int
	nextSeq        uint64
	highWaterMark  int
	highWaterFired bool
	lastMAC        string
}

// NewAuditLog seeds an empty chain rooted at hmac(key, "genesis").
// Key is the same HMAC key the enclave holds — the enclave verifies
// the chain with it on drain.
func NewAuditLog(key []byte, capacity int) (*AuditLog, error) {
	if len(key) < 32 {
		return nil, errors.New("audit: hmac key must be at least 32 bytes")
	}
	if capacity <= 0 {
		return nil, errors.New("audit: capacity must be positive")
	}
	genesis := hmac.New(sha256.New, key)
	genesis.Write([]byte("cmmc-share:genesis"))
	return &AuditLog{
		key:           append([]byte(nil), key...),
		cap:           capacity,
		highWaterMark: capacity / 2,
		lastMAC:       hex.EncodeToString(genesis.Sum(nil)),
	}, nil
}

// Append records an event. Sets Seq, PrevMAC, MAC, and Timestamp.
// Returns the sequence number so the caller can correlate.
func (a *AuditLog) Append(e Event) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	e.Seq = a.nextSeq
	a.nextSeq++
	e.PrevMAC = a.lastMAC

	macIn, err := json.Marshal(auditMACInput(e))
	if err != nil {
		return 0, fmt.Errorf("audit: marshal for mac: %w", err)
	}
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(a.lastMAC))
	mac.Write(macIn)
	e.MAC = hex.EncodeToString(mac.Sum(nil))

	a.lastMAC = e.MAC
	a.buf = append(a.buf, e)

	// Cap overflow: drop the oldest — we'd rather lose the earliest
	// event than back-pressure the request path. Drops are themselves
	// detectable by the enclave (sequence gap) and cause an alert.
	if len(a.buf) > a.cap {
		a.buf = a.buf[len(a.buf)-a.cap:]
	}

	if !a.highWaterFired && len(a.buf) >= a.highWaterMark {
		a.highWaterFired = true
		// In production this would fire a local health endpoint
		// alert. Keeping the side-effect to a stderr log here keeps
		// the package test-isolated.
		fmt.Printf("WARN: share audit buffer at %d / %d — is the enclave pull healthy?\n", len(a.buf), a.cap)
	}
	return e.Seq, nil
}

// auditMACInput shapes the fields that participate in the MAC. We
// deliberately exclude the MAC / PrevMAC fields themselves to avoid
// circularity, and we exclude runtime-only fields that have no
// durable meaning downstream.
func auditMACInput(e Event) Event {
	cp := e
	cp.MAC = ""
	cp.PrevMAC = ""
	return cp
}

// Len returns how many events are currently buffered.
func (a *AuditLog) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.buf)
}

// Drain returns up to max events starting from the oldest, WITHOUT
// removing them. The enclave calls AckThrough(seq) after it has
// persisted the events into its main chain.
func (a *AuditLog) Drain(max int) []Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	if max <= 0 || max > len(a.buf) {
		max = len(a.buf)
	}
	out := make([]Event, max)
	copy(out, a.buf[:max])
	return out
}

// AckThrough removes every event with Seq <= seq. Safe to call with
// a seq the enclave never sent us (no-op) — the worst case is the
// next drain returns an overlapping window that the enclave's
// dedupe-by-seq handles correctly.
func (a *AuditLog) AckThrough(seq uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keep := a.buf[:0]
	for _, e := range a.buf {
		if e.Seq > seq {
			keep = append(keep, e)
		}
	}
	a.buf = keep
	if len(a.buf) < a.highWaterMark {
		a.highWaterFired = false
	}
}

// Verify walks the buffer's HMAC chain and reports the first break
// (if any). Called by the enclave at drain time and by tests.
func Verify(key []byte, events []Event, seed string) (bool, int) {
	prev := seed
	for i, e := range events {
		macIn, err := json.Marshal(auditMACInput(e))
		if err != nil {
			return false, i
		}
		h := hmac.New(sha256.New, key)
		h.Write([]byte(prev))
		h.Write(macIn)
		want := hex.EncodeToString(h.Sum(nil))
		if want != e.MAC || e.PrevMAC != prev {
			return false, i
		}
		prev = e.MAC
	}
	return true, 0
}

// Seed exposes the initial MAC (genesis) so callers that verify
// the very first event can start their chain walk from the same
// root the daemon used.
func Seed(key []byte) string {
	g := hmac.New(sha256.New, key)
	g.Write([]byte("cmmc-share:genesis"))
	return hex.EncodeToString(g.Sum(nil))
}
