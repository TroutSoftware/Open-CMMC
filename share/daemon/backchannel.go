package daemon

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// BackChannel is the mTLS listener that accepts enclave-initiated
// pushes of new shares and serves audit drain pulls. It runs on its
// own listener (typically bound to a VPN or private link) so the
// public internet surface never touches this code path.
//
// Authentication model:
//   - TLS layer: client certificate MUST chain to the pinned
//     enclave CA, and the CN / SAN MUST be one the daemon's
//     config expects. Enforced in main.go at tls.Config setup.
//   - Application layer: a per-deployment shared bearer token
//     (also set via config) guards every endpoint as belt-and-
//     suspenders against a misconfigured TLS stack.
//
// Endpoints:
//
//   POST /push      — new share (multipart: meta JSON + blob bytes)
//   GET  /audit     — drain pending events (query: max=N)
//   POST /audit/ack — AckThrough(seq)
//   POST /revoke    — admin force-burn a share id
type BackChannel struct {
	Store *Store
	Audit *AuditLog

	// BearerToken is the on-wire shared secret as it appears in the
	// Authorization header: printable ASCII (typically base64 of a
	// 32-byte random value). Arbitrary binary is rejected at
	// NewBackChannel time so it can't leak into a header and cause
	// silent downgrades.
	BearerToken string

	// MaxBlobBytes caps the per-push ciphertext size. A misconfigured
	// enclave or a compromised sender shouldn't be able to fill the
	// DMZ disk with one giant push.
	MaxBlobBytes int64
}

// NewBackChannel returns a BackChannel with reasonable defaults. The
// bearer token must be derived from at least 32 bytes (256 bits) of
// entropy; callers that pass weaker secrets get an error so config
// drift doesn't silently downgrade the mutual-trust posture.
//
// token is the raw entropy (file bytes). The on-wire form is
// base64(raw) — returned via .BearerToken so the enclave side can
// mirror the same encoding without guessing.
func NewBackChannel(store *Store, audit *AuditLog, token []byte) (*BackChannel, error) {
	if len(token) < 32 {
		return nil, errors.New("backchannel: bearer token must be at least 32 bytes of entropy")
	}
	return &BackChannel{
		Store:        store,
		Audit:        audit,
		BearerToken:  base64.StdEncoding.EncodeToString(token),
		MaxBlobBytes: 1 << 30, // 1 GiB per-share ceiling
	}, nil
}

// Routes returns the backchannel mux. Typically mounted on a
// separate listener from the public server.
func (b *BackChannel) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/push", b.withAuth(b.handlePush))
	mux.HandleFunc("/audit", b.withAuth(b.handleAuditDrain))
	mux.HandleFunc("/audit/ack", b.withAuth(b.handleAuditAck))
	mux.HandleFunc("/revoke", b.withAuth(b.handleRevoke))
	return mux
}

// withAuth checks the Authorization header in constant time. Timing
// attacks on a single HMAC compare are not useful in practice but
// the cost of using subtle.ConstantTimeCompare is zero so there's
// no reason not to.
func (b *BackChannel) withAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(got) <= len(prefix) || got[:len(prefix)] != prefix {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(b.BearerToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fn(w, r)
	}
}

// pushEnvelope is the wire format the enclave sends. Meta first, blob
// second, both lengths known up front so we can reject at header-
// parse time rather than buffering the whole blob.
type pushEnvelope struct {
	Meta Metadata `json:"meta"`
	// Blob follows in the request body AFTER the JSON header — we
	// use an X-Blob-Length and read exactly that many bytes. Using
	// multipart would add a parser dep; hand-rolled framing keeps
	// the attack surface tiny.
}

func (b *BackChannel) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metaJSON := r.Header.Get("X-Share-Meta")
	blobLenStr := r.Header.Get("X-Blob-Length")
	if metaJSON == "" || blobLenStr == "" {
		http.Error(w, "missing X-Share-Meta or X-Blob-Length", http.StatusBadRequest)
		return
	}
	blobLen, err := strconv.ParseInt(blobLenStr, 10, 64)
	if err != nil || blobLen < 0 {
		http.Error(w, "bad X-Blob-Length", http.StatusBadRequest)
		return
	}
	if blobLen > b.MaxBlobBytes {
		http.Error(w, "blob exceeds per-share ceiling", http.StatusRequestEntityTooLarge)
		return
	}
	var meta Metadata
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		http.Error(w, "bad meta json", http.StatusBadRequest)
		return
	}
	if !validID(meta.ID) {
		http.Error(w, "bad share id", http.StatusBadRequest)
		return
	}
	if meta.BlobSize != 0 && meta.BlobSize != blobLen {
		http.Error(w, "meta.blob_size disagrees with X-Blob-Length", http.StatusBadRequest)
		return
	}
	meta.BlobSize = blobLen

	// Cap the read so a lying header doesn't pin memory.
	body := io.LimitReader(r.Body, blobLen)
	if err := b.Store.Create(&meta, body); err != nil {
		if errors.Is(err, ErrIDConflict) {
			http.Error(w, "id conflict", http.StatusConflict)
			return
		}
		_, _ = b.Audit.Append(Event{
			Action:        ActionPushRejected,
			ShareID:       meta.ID,
			CorrelationID: meta.CorrelationID,
			Outcome:       "fail",
			Reason:        err.Error(),
		})
		http.Error(w, fmt.Sprintf("create: %v", err), http.StatusInternalServerError)
		return
	}
	_, _ = b.Audit.Append(Event{
		Action:        ActionPushAccepted,
		ShareID:       meta.ID,
		CorrelationID: meta.CorrelationID,
		Outcome:       "success",
	})
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         meta.ID,
		"expires_at": meta.ExpiresAt,
	})
}

func (b *BackChannel) handleAuditDrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	max := 0
	if s := r.URL.Query().Get("max"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			max = n
		}
	}
	events := b.Audit.Drain(max)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events":  events,
		"pending": b.Audit.Len(),
	})
}

func (b *BackChannel) handleAuditAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Through uint64 `json:"through"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	b.Audit.AckThrough(body.Through)
	w.WriteHeader(http.StatusNoContent)
}

func (b *BackChannel) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ShareID string `json:"share_id"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if !validID(body.ShareID) {
		http.Error(w, "bad share id", http.StatusBadRequest)
		return
	}
	// Burn before logging so a partially-successful revoke still
	// removes the ciphertext even if the audit append errors.
	if err := b.Store.Burn(body.ShareID); err != nil && !errors.Is(err, ErrNotFound) {
		http.Error(w, fmt.Sprintf("burn: %v", err), http.StatusInternalServerError)
		return
	}
	_, _ = b.Audit.Append(Event{
		Action:  ActionBurned,
		ShareID: body.ShareID,
		Outcome: "revoked",
		Reason:  body.Reason,
	})
	w.WriteHeader(http.StatusNoContent)
}
