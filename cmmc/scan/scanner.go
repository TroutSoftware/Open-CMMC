// Package scan is the on-upload malicious-code scanner that closes
// CMMC control 3.14.2 (malicious code protection). Uploads pass
// their plaintext through the configured Scanner before the
// envelope layer seals them to disk. An infected file never reaches
// storage and never gets an envelope — it 422s at the HTTP boundary
// with a cui.scan.reject audit event.
//
// The canonical backend is ClamAV via the INSTREAM protocol; see
// subpackage clamav. Other backends (a cloud AV API, a reference
// hash check) can implement Scanner without touching envelope.
package scan

import (
	"context"
	"errors"
	"io"
)

// Scanner inspects a plaintext payload and reports whether it's safe
// to store. Implementations must be safe for concurrent use — a busy
// cabinet has many uploads in flight.
//
// The Context lets the caller propagate a per-request deadline so a
// hung clamd doesn't wedge the whole upload handler. Scanner
// implementations should honor Context cancellation promptly.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader) (Result, error)
}

// Result is a scan verdict. When Clean is false, Signature carries
// the specific detection name ("Eicar-Test-Signature", "Win.Trojan.
// Emotet-...") so the audit record and operator log preserve forensic
// detail. Empty Signature with Clean=false is tolerated but should
// be rare (typically on backend errors that default to "unsafe").
type Result struct {
	Clean     bool
	Signature string
}

// ErrRejected is the sentinel error sealAndWrite returns when a
// scan flags the payload. It wraps the detection signature so the
// HTTP layer can emit a structured audit event and return a
// consistent 422 status.
//
// Callers that need the signature should use errors.As with
// *RejectedError.
type RejectedError struct {
	Signature string
	Path      string // logical path reported to audit; set by the caller that has request context
}

func (e *RejectedError) Error() string {
	if e.Signature == "" {
		return "scan: rejected"
	}
	return "scan: rejected — " + e.Signature
}

// ErrUnavailable wraps a backend failure (connect, read, protocol)
// so callers can distinguish "scanner sick" from "file infected."
// In Required mode the handler 503s; in Optional mode it logs and
// proceeds.
var ErrUnavailable = errors.New("scan: backend unavailable")

// MockScanner is a deterministic Scanner for tests. If Verdict is
// nil it always returns Clean. Callers can set Verdict to inject
// specific returns per call (e.g., pass clean on odd calls, infected
// on even).
type MockScanner struct {
	Clean     bool
	Signature string
	Err       error
	Calls     int
}

// Scan honors Context cancellation immediately. Stubs the verdict
// from the struct fields.
func (m *MockScanner) Scan(ctx context.Context, r io.Reader) (Result, error) {
	m.Calls++
	// Drain the reader so the caller's bytes are consumed — real
	// scanners always do. Without this, a test that asserts
	// io.EOF on the source after scan would behave differently
	// between MockScanner and a real one.
	_, _ = io.Copy(io.Discard, r)
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}
	if m.Err != nil {
		return Result{}, m.Err
	}
	return Result{Clean: m.Clean, Signature: m.Signature}, nil
}
