// Package envelope implements per-file envelope encryption for the
// CMMC cabinet. Every file written to storage is encrypted with its
// own Data Encryption Key (DEK), and the DEK itself is wrapped by a
// process-wide Key Encryption Key (KEK) loaded from config at boot.
//
// CMMC controls addressed:
//   * 3.13.16 — protect the confidentiality of CUI at rest
//   * 3.8.9   — protect the confidentiality of CUI backups
//   * 3.13.11 — employ FIPS-validated cryptography
//
// Threat model:
//   * Root/ops on the host sees only ciphertext on disk. Reading raw
//     file bytes without the KEK yields no CUI plaintext.
//   * A stolen disk is useless without the KEK (which lives in a
//     separate storage domain — env, file, HSM).
//   * A compromised filebrowser process has the KEK in memory and
//     can decrypt any file. This is the same bar as "compromised
//     application process" in any envelope scheme; envelope is not
//     a defense against code execution inside the trust boundary.
//
// Primitives — FIPS-approved only:
//   * AES-256-GCM for both the file (DEK) and DEK-wrap (KEK).
//   * crypto/rand for DEK + nonce generation (routes through the
//     FIPS module when GODEBUG=fips140=on).
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is AES-256. Use a constant rather than sprinkling 32 in
// the code so grepping for key-size assumptions is trivial.
const KeySize = 32

// NonceSize is GCM's canonical 12 bytes. Don't change without a
// rationale — shorter nonces narrow the safe message limit per key.
const NonceSize = 12

// TagSize is GCM's 16-byte authentication tag, appended to ciphertext.
// Exposed as a constant so callers that pre-allocate buffers don't
// have to reach into crypto/cipher for it.
const TagSize = 16

// MaxPlaintextSize caps the single-shot AEAD path at 256 MiB. Larger
// files will need a chunked encoding (16 KiB blocks with per-block
// nonces, sequential) — tracked as a follow-up. Until then, uploads
// beyond this size are refused with a clear 413 rather than silently
// OOMing the process.
const MaxPlaintextSize int64 = 256 * 1024 * 1024

// ErrTooLarge is returned by Seal when the plaintext exceeds
// MaxPlaintextSize. The HTTP handler maps it to 413.
var ErrTooLarge = errors.New("envelope: plaintext exceeds max single-shot size")

// ErrAuth is returned by Open when authentication fails — invalid
// tag, truncated ciphertext, or wrong KEK. Treat every occurrence
// as a security-relevant audit event (cui.envelope.fail), not a
// run-of-the-mill IO error.
var ErrAuth = errors.New("envelope: authentication failed")

// KEK is a Key Encryption Key. Constructed from 32 raw bytes; the
// caller is responsible for sourcing those bytes (env var, KMS,
// HSM, Vault). Stored only in memory — never log, never serialize.
type KEK struct {
	aead cipher.AEAD
}

// NewKEK wraps a 32-byte master key. The returned value is safe
// for concurrent use by multiple goroutines; the underlying GCM
// object is stateless across Seal/Open calls.
func NewKEK(key []byte) (*KEK, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("envelope: KEK must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: cipher.NewGCM: %w", err)
	}
	return &KEK{aead: aead}, nil
}

// Envelope is the per-file key+nonce material persisted alongside
// the ciphertext on disk. Every field is required; callers must not
// construct this by hand — use Seal.
//
// Layout on the wire (bolt blob / JSON):
//
//	+------------------+------------------+
//	| EncDEKNonce (12) | EncDEK (32+16)   |
//	+------------------+------------------+
//	| FileNonce   (12) |                  |
//	+------------------+------------------+
//
// FileNonce is the nonce used for the FILE ciphertext (AEAD over
// plaintext). EncDEK is the DEK wrapped with KEK; EncDEKNonce is
// the nonce used to wrap the DEK. Two nonces because two different
// GCM instances are used (one per file, one for wrapping).
type Envelope struct {
	EncDEKNonce []byte // 12 bytes — nonce for the wrap of DEK
	EncDEK      []byte // 48 bytes — GCM-encrypted DEK (32 + 16 tag)
	FileNonce   []byte // 12 bytes — nonce for the file ciphertext
	PlaintextSize int64 // bytes of plaintext; used to return correct Stat().Size()
}

// Seal generates a random DEK, encrypts the plaintext with it
// (AES-256-GCM), wraps the DEK with the KEK (AES-256-GCM), and
// returns the ciphertext + the envelope to persist alongside.
//
// `aad` is authenticated-but-not-encrypted extra data bound to both
// the file encryption and the DEK wrap. Typical use: pass the
// absolute server path so a ciphertext relocated to a different path
// fails to decrypt (defense against swap-the-file attacks by host
// root). Empty aad is accepted for tests.
func (k *KEK) Seal(plaintext []byte, aad []byte) (ciphertext []byte, env *Envelope, err error) {
	if int64(len(plaintext)) > MaxPlaintextSize {
		return nil, nil, ErrTooLarge
	}

	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("envelope: rand DEK: %w", err)
	}
	// Wipe the DEK from the stack-ish byte slice once we're done —
	// Go can't guarantee no copies, but zeroing the explicit buffer
	// closes one obvious readback window.
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	fileAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, nil, err
	}
	fileNonce := make([]byte, NonceSize)
	if _, err := rand.Read(fileNonce); err != nil {
		return nil, nil, fmt.Errorf("envelope: rand fileNonce: %w", err)
	}
	ciphertext = fileAEAD.Seal(nil, fileNonce, plaintext, aad)

	// Wrap DEK with KEK. Fresh nonce per wrap.
	encDEKNonce := make([]byte, NonceSize)
	if _, err := rand.Read(encDEKNonce); err != nil {
		return nil, nil, fmt.Errorf("envelope: rand encDEKNonce: %w", err)
	}
	encDEK := k.aead.Seal(nil, encDEKNonce, dek, aad)

	return ciphertext, &Envelope{
		EncDEKNonce:   encDEKNonce,
		EncDEK:        encDEK,
		FileNonce:     fileNonce,
		PlaintextSize: int64(len(plaintext)),
	}, nil
}

// Open unwraps the DEK with the KEK, then decrypts the ciphertext.
// Returns ErrAuth on any authentication failure — callers should
// audit those as cui.envelope.fail (security-relevant), distinct
// from garden-variety IO errors.
func (k *KEK) Open(ciphertext []byte, env *Envelope, aad []byte) ([]byte, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	if len(env.EncDEKNonce) != NonceSize || len(env.FileNonce) != NonceSize {
		return nil, errors.New("envelope: malformed nonces")
	}
	dek, err := k.aead.Open(nil, env.EncDEKNonce, env.EncDEK, aad)
	if err != nil {
		return nil, ErrAuth
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	fileAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := fileAEAD.Open(nil, env.FileNonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: aes.NewCipher(DEK): %w", err)
	}
	return cipher.NewGCM(block)
}

// ReadAll is a small convenience for callers that have a ReadSeeker
// and want to Seal its contents; it returns ErrTooLarge early if
// the source is larger than MaxPlaintextSize, avoiding a full
// allocation before the size check.
func ReadAll(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, MaxPlaintextSize+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > MaxPlaintextSize {
		return nil, ErrTooLarge
	}
	return buf, nil
}
