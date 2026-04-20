package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func mustKEK(t *testing.T) *KEK {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k, err := NewKEK(key)
	if err != nil {
		t.Fatalf("NewKEK: %v", err)
	}
	return k
}

// TestSealOpen_RoundTrip pins the core AEAD contract. A regression
// here is a CUI leak — every file on disk stops decrypting.
func TestSealOpen_RoundTrip(t *testing.T) {
	k := mustKEK(t)
	plaintext := []byte("THIS IS CUI — drawing rev C, part 904-A12")
	aad := []byte("/srv/cmmc/users/alice/drawing.pdf")

	ct, env, err := k.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(env.EncDEKNonce) != NonceSize {
		t.Errorf("EncDEKNonce len=%d", len(env.EncDEKNonce))
	}
	if len(env.EncDEK) != KeySize+TagSize {
		t.Errorf("EncDEK len=%d, want %d", len(env.EncDEK), KeySize+TagSize)
	}
	if len(env.FileNonce) != NonceSize {
		t.Errorf("FileNonce len=%d", len(env.FileNonce))
	}
	if env.PlaintextSize != int64(len(plaintext)) {
		t.Errorf("PlaintextSize=%d", env.PlaintextSize)
	}
	// Ciphertext should not contain the plaintext.
	if bytes.Contains(ct, plaintext) {
		t.Errorf("ciphertext contains plaintext — encryption no-op?")
	}

	got, err := k.Open(ct, env, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch:\n got: %q\nwant: %q", got, plaintext)
	}
}

// TestSealOpen_AADBinding — changing the AAD between Seal and Open
// must fail authentication. This is the defense against a swap-
// the-file attack where host root moves ciphertext between paths.
func TestSealOpen_AADBinding(t *testing.T) {
	k := mustKEK(t)
	ct, env, err := k.Seal([]byte("hello"), []byte("/path/one"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := k.Open(ct, env, []byte("/path/two")); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong-AAD open returned %v, want ErrAuth", err)
	}
}

// TestOpen_WrongKEK_Fails pins the cross-deployment safety: a
// ciphertext + envelope from one cabinet can't be decrypted by
// another cabinet even if it's seemingly valid.
func TestOpen_WrongKEK_Fails(t *testing.T) {
	k1, k2 := mustKEK(t), mustKEK(t)
	ct, env, err := k1.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := k2.Open(ct, env, nil); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong-KEK open returned %v, want ErrAuth", err)
	}
}

// TestOpen_TamperedCiphertext_Fails — one flipped byte must break
// the tag check. Pin the GCM auth property.
func TestOpen_TamperedCiphertext_Fails(t *testing.T) {
	k := mustKEK(t)
	ct, env, err := k.Seal([]byte("0123456789"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ct[0] ^= 0x01
	if _, err := k.Open(ct, env, nil); !errors.Is(err, ErrAuth) {
		t.Errorf("tampered ciphertext open returned %v, want ErrAuth", err)
	}
}

// TestOpen_TamperedEnvelope_Fails — ditto for the envelope (DEK wrap).
func TestOpen_TamperedEnvelope_Fails(t *testing.T) {
	k := mustKEK(t)
	ct, env, err := k.Seal([]byte("0123456789"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env.EncDEK[0] ^= 0x01
	if _, err := k.Open(ct, env, nil); !errors.Is(err, ErrAuth) {
		t.Errorf("tampered envelope open returned %v, want ErrAuth", err)
	}
}

// TestNewKEK_RejectsWrongSize — must refuse <32 bytes to prevent
// someone passing a password directly and trivially weakening key
// entropy.
func TestNewKEK_RejectsWrongSize(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33, 64} {
		_, err := NewKEK(make([]byte, n))
		if err == nil {
			t.Errorf("NewKEK accepted %d-byte key", n)
		}
	}
}

// TestSeal_TooLarge — single-shot cap must fire before allocation.
func TestSeal_TooLarge(t *testing.T) {
	k := mustKEK(t)
	// Construct the smallest slice that trips the cap. We can't
	// actually allocate MaxPlaintextSize+1 in a unit test cheaply —
	// lower the constant via a local compare instead.
	if _, _, err := k.Seal(make([]byte, MaxPlaintextSize+1), nil); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize Seal returned %v, want ErrTooLarge", err)
	}
}

// TestReadAll_EnforcesCap covers the streaming ingress path.
func TestReadAll_EnforcesCap(t *testing.T) {
	// Short happy path.
	buf, err := ReadAll(strings.NewReader("hello"))
	if err != nil {
		t.Errorf("err: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q", buf)
	}
	// Over cap — simulate by limiting; the function uses
	// MaxPlaintextSize so we need an artificially-large reader.
	// Using a LimitReader keeps the test fast: feed MaxPlaintextSize+1
	// zero bytes from an infinite reader.
	big := io_LimitInfinite{}
	if _, err := ReadAll(big); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize ReadAll returned %v, want ErrTooLarge", err)
	}
}

type io_LimitInfinite struct{}

func (io_LimitInfinite) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
