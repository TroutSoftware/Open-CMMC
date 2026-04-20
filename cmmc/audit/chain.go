package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"sync"
)

// HMACChainEmitter wraps another Emitter and stamps each outgoing
// event with `prev_mac` (the previous event's MAC) and `mac` (this
// event's MAC). The chain forms a tamper-evident log:
//
//   - insertion of a fake event between two real ones breaks the
//     receiving event's prev_mac,
//   - deletion of an event breaks the NEXT event's prev_mac,
//   - modification of any macInput field of any event breaks its own
//     mac AND the prev_mac of the next event.
//
// SIEM-side verification walks the sequence (via VerifyChain) and
// alerts on the first break.
//
// Satisfies CMMC 3.3.8 (protect audit information from unauthorized
// access/modification/deletion) beyond the filesystem-level `chattr
// +a` defense, which is root-bypassable.
//
// Known limitation: the `extra` field is NOT included in the MAC
// because Go's default json.Marshal of map[string]interface{} has
// non-deterministic key order. Controlled fields (ts, event_id,
// correlation_id, user_id, username, action, resource, outcome,
// status, reason, prev_mac) all cover the SSP-critical event
// semantics; `extra` carries best-effort context only. Documented in
// the SSP as a residual risk.
type HMACChainEmitter struct {
	mu      sync.Mutex
	inner   Emitter
	key     []byte
	prevMAC string
}

// NewHMACChainEmitter returns a chain emitter backed by the given
// inner emitter. The key must be at least 32 bytes (will be padded
// with a domain-separation tag via HKDF if you want multiple chains
// from one master key — out of scope for this commit).
//
// prevMAC starts empty — the first event's prev_mac field is empty,
// which the verifier treats as the chain genesis.
func NewHMACChainEmitter(inner Emitter, key []byte) *HMACChainEmitter {
	return &HMACChainEmitter{
		inner: inner,
		key:   append([]byte(nil), key...),
	}
}

// Emit computes the MAC, stamps prev_mac+mac on the event, updates
// the chain state, and forwards to the inner emitter.
func (e *HMACChainEmitter) Emit(ctx context.Context, ev *Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev.PrevMAC = e.prevMAC
	mac := computeMAC(e.key, e.prevMAC, ev)
	ev.MAC = mac
	e.prevMAC = mac
	e.inner.Emit(ctx, ev)
}

// Tip returns the current chain tip (the last MAC emitted), or ""
// if no events have flowed yet. An out-of-band verifier can compare
// this against the SIEM-side chain head to confirm no drop happened
// at the forwarder (3.3.4 audit-failure detection).
func (e *HMACChainEmitter) Tip() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prevMAC
}

// macDigestInput builds the deterministic byte sequence that the
// chain MAC covers. Field order is fixed; each field is prefixed with
// its length and a separator so concatenated values cannot collide
// (e.g., action="x" resource="y" vs action="xy" resource="").
func macDigestInput(prevMAC string, ev *Event) []byte {
	// 0x1f is ASCII Unit Separator — not valid in any of the string
	// fields we hash, safe as a delimiter.
	var buf []byte
	add := func(s string) {
		buf = append(buf, strconv.Itoa(len(s))...)
		buf = append(buf, 0x1f)
		buf = append(buf, s...)
		buf = append(buf, 0x1f)
	}
	addInt := func(n int64) {
		add(strconv.FormatInt(n, 10))
	}
	add(prevMAC)
	// RFC3339Nano of UTC; stable across Go releases.
	add(ev.Ts.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"))
	add(ev.EventID)
	add(ev.CorrelationID)
	add(ev.UserID)
	add(ev.Username)
	add(ev.ClientIP)
	add(ev.UserAgent)
	add(ev.Action)
	add(ev.Resource)
	add(ev.Outcome)
	addInt(int64(ev.Status))
	addInt(ev.LatencyMS)
	add(ev.Reason)
	return buf
}

func computeMAC(key []byte, prevMAC string, ev *Event) string {
	h := hmac.New(sha256.New, key)
	h.Write(macDigestInput(prevMAC, ev))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// VerifyChain walks an event sequence in chronological order and
// returns the zero-based index of the first break, or -1 if the
// chain is intact. `expectedFirstPrev` is the prev_mac that the
// verifier expects on the first event — "" for a genesis chain, or
// a saved tip when verifying a delta since the last checkpoint.
//
// key is the same key passed to NewHMACChainEmitter.
func VerifyChain(events []Event, key []byte, expectedFirstPrev string) int {
	prev := expectedFirstPrev
	for i := range events {
		ev := events[i]
		if ev.PrevMAC != prev {
			return i
		}
		wantMAC := computeMAC(key, prev, &ev)
		if !hmac.Equal([]byte(ev.MAC), []byte(wantMAC)) {
			return i
		}
		prev = ev.MAC
	}
	return -1
}

// ErrChainTampered is returned by verification helpers that want a
// typed error rather than an index.
var ErrChainTampered = errors.New("audit: chain MAC mismatch")

// --- JSON schema additions ------------------------------------------------

// Event gains two optional fields; included as JSON only when the
// chain emitter populates them. The fields live on Event (not a
// wrapper) so downstream Emitters (including the ring buffer and the
// JSON writer) see the same structure and consumers can verify on
// the data as-read.

