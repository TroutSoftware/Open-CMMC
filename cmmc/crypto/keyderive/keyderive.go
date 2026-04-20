// Package keyderive provides domain-separated HKDF-SHA256 subkeys
// from the filebrowser settings master key. CMMC 3.13.11 /
// defense-in-depth: compromise of one primitive (e.g. a session
// JWT leaked to a log) must not compromise another (the audit
// HMAC chain). One master → many narrow keys with fixed labels.
//
// HKDF is a FIPS-approved construction (SP 800-56C / SP 800-108 rev 1),
// so all derived keys inherit the master's FIPS posture when the
// Go runtime is built with GOFIPS140=v1.0.0.
package keyderive

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// Labels are versioned (-v1) so a future rotation of one domain
// doesn't require recomputing the others. Changing a label is a
// breaking change — any persisted artifact signed/MACed with the
// old subkey stops verifying on boot.
const (
	LabelSessionSign = "cmmc-session-jwt-v1"
	LabelAuditChain  = "cmmc-audit-chain-v1"
)

// ErrMasterTooShort is returned when the input key is below the
// HMAC-SHA256 security floor (32 bytes). Shorter keys would expand
// through HKDF without error but wouldn't carry 256 bits of
// entropy into the subkey — fail-closed so operators see it.
var ErrMasterTooShort = errors.New("keyderive: master key must be ≥ 32 bytes")

// SubKey returns a size-byte subkey derived from master under the
// given label. Uses HKDF-SHA256 with an empty salt (the label
// provides domain separation; an operator-specific salt would add
// nothing because the master itself is already deployment-unique).
func SubKey(master []byte, label string, size int) ([]byte, error) {
	if len(master) < 32 {
		return nil, ErrMasterTooShort
	}
	if size <= 0 {
		return nil, errors.New("keyderive: size must be positive")
	}
	if label == "" {
		return nil, errors.New("keyderive: label is required")
	}
	return hkdf.Key(sha256.New, master, nil, label, size)
}

// SessionSigningKey returns the 32-byte subkey used by the HS256
// session-JWT signer. Caller must NOT log or persist the returned
// value.
func SessionSigningKey(master []byte) ([]byte, error) {
	return SubKey(master, LabelSessionSign, 32)
}

// AuditChainKey returns the 32-byte subkey used by the audit HMAC
// chain emitter. Distinct from SessionSigningKey so a JWT leak
// cannot be used to forge audit events and vice versa.
func AuditChainKey(master []byte) ([]byte, error) {
	return SubKey(master, LabelAuditChain, 32)
}
