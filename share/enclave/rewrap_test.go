package enclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// testParams: fast Argon2 for unit tests. Production uses
// DefaultArgon2Params.
var testParams = Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}

func mkPepper(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, 32)
	if _, err := rand.Read(p); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return p
}

func goodParams(t *testing.T) RewrapParams {
	t.Helper()
	return RewrapParams{
		Plaintext:      []byte("this is the document contents"),
		Filename:       "report.pdf",
		ContentType:    "application/pdf",
		CUIMark:        "BASIC",
		SenderUserID:   "flo",
		RecipientEmail: "dana@example.com",
		TTL:            72 * time.Hour,
		MaxDownloads:   1,
		MaxFailures:    5,
		Passphrase:     "correct horse battery staple",
		CorrelationID:  "cor-1",
	}
}

// Simulate the daemon-side unwrap to prove round-trip works.
func simUnwrapAndDecrypt(t *testing.T, art *Artifact, passphrase string, pepper []byte) []byte {
	t.Helper()
	material := append([]byte{}, []byte(passphrase)...)
	material = append(material, pepper...)
	salt, _ := base64.StdEncoding.DecodeString(art.Meta.Wrap.SaltB64)
	kwk := argon2.IDKey(material, salt, art.Meta.Wrap.Argon2Time, art.Meta.Wrap.Argon2Mem, art.Meta.Wrap.Argon2Par, 32)

	block, _ := aes.NewCipher(kwk)
	gcm, _ := cipher.NewGCM(block)
	wrapped, _ := base64.StdEncoding.DecodeString(art.Meta.Wrap.WrappedDEK)
	nonce, ct := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	dek, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("daemon unwrap: %v", err)
	}

	blobBlock, _ := aes.NewCipher(dek)
	blobGCM, _ := cipher.NewGCM(blobBlock)
	blobNonce, _ := base64.StdEncoding.DecodeString(art.Meta.Wrap.BlobNonce)
	pt, err := blobGCM.Open(nil, blobNonce, art.Blob, nil)
	if err != nil {
		t.Fatalf("daemon decrypt blob: %v", err)
	}
	return pt
}

func TestRewrap_RoundTrip(t *testing.T) {
	pepper := mkPepper(t)
	p := goodParams(t)
	art, err := Rewrap(p, pepper, "p1", testParams)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	got := simUnwrapAndDecrypt(t, art, p.Passphrase, pepper)
	if !bytes.Equal(got, p.Plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, p.Plaintext)
	}
	// Share metadata carries the expected bits.
	if art.Meta.Filename != "report.pdf" {
		t.Errorf("Filename lost")
	}
	if art.Meta.Wrap.PepperID != "p1" {
		t.Errorf("PepperID lost: %q", art.Meta.Wrap.PepperID)
	}
	if art.Meta.DownloadsRemaining != 1 {
		t.Errorf("DownloadsRemaining not initialized")
	}
}

func TestRewrap_WrongPassphraseFailsUnwrap(t *testing.T) {
	pepper := mkPepper(t)
	p := goodParams(t)
	art, err := Rewrap(p, pepper, "p1", testParams)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	// Same daemon-side derive but with the wrong passphrase: the
	// GCM.Open MUST fail.
	material := append([]byte{}, []byte("wrong")...)
	material = append(material, pepper...)
	salt, _ := base64.StdEncoding.DecodeString(art.Meta.Wrap.SaltB64)
	kwk := argon2.IDKey(material, salt, art.Meta.Wrap.Argon2Time, art.Meta.Wrap.Argon2Mem, art.Meta.Wrap.Argon2Par, 32)
	block, _ := aes.NewCipher(kwk)
	gcm, _ := cipher.NewGCM(block)
	wrapped, _ := base64.StdEncoding.DecodeString(art.Meta.Wrap.WrappedDEK)
	nonce, ct := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	if _, err := gcm.Open(nil, nonce, ct, nil); err == nil {
		t.Fatalf("wrong passphrase should fail unwrap")
	}
}

func TestRewrap_RefusesITAR(t *testing.T) {
	pepper := mkPepper(t)
	p := goodParams(t)
	p.CUIMark = "SP-ITAR"
	if _, err := Rewrap(p, pepper, "p1", testParams); err == nil {
		t.Fatalf("expected ITAR refusal")
	}
	p.CUIMark = "CUI//SP-NOFORN"
	if _, err := Rewrap(p, pepper, "p1", testParams); err == nil {
		t.Fatalf("expected NOFORN refusal")
	}
}

func TestRewrap_RejectsInvalidParams(t *testing.T) {
	pepper := mkPepper(t)
	p := goodParams(t)
	p.Plaintext = nil
	if _, err := Rewrap(p, pepper, "p1", testParams); err == nil {
		t.Fatalf("empty plaintext should fail")
	}
	p = goodParams(t)
	p.Passphrase = ""
	if _, err := Rewrap(p, pepper, "p1", testParams); err == nil {
		t.Fatalf("empty passphrase should fail")
	}
	p = goodParams(t)
	p.TTL = 0
	if _, err := Rewrap(p, pepper, "p1", testParams); err == nil {
		t.Fatalf("zero TTL should fail")
	}
}

func TestRewrap_DifferentArtifactsEachCall(t *testing.T) {
	pepper := mkPepper(t)
	p := goodParams(t)
	a1, err := Rewrap(p, pepper, "p1", testParams)
	if err != nil {
		t.Fatalf("Rewrap 1: %v", err)
	}
	a2, err := Rewrap(p, pepper, "p1", testParams)
	if err != nil {
		t.Fatalf("Rewrap 2: %v", err)
	}
	if a1.Meta.ID == a2.Meta.ID {
		t.Fatalf("IDs should differ across calls")
	}
	if a1.Meta.Wrap.SaltB64 == a2.Meta.Wrap.SaltB64 {
		t.Fatalf("salts should differ across calls")
	}
	if bytes.Equal(a1.Blob, a2.Blob) {
		t.Fatalf("blobs should differ across calls (fresh nonce + fresh DEK)")
	}
}

func TestHashEmail_StableAndLowercased(t *testing.T) {
	pepper := mkPepper(t)
	a := HashEmail("Dana@Example.COM", pepper)
	b := HashEmail("dana@example.com", pepper)
	c := HashEmail("  dana@example.com  ", pepper)
	if a != b || b != c {
		t.Fatalf("case/whitespace should not affect hash: %q %q %q", a, b, c)
	}
	d := HashEmail("other@example.com", pepper)
	if d == a {
		t.Fatalf("different emails must hash differently")
	}
}

func TestGeneratePassphrase_ShapesAndDistinct(t *testing.T) {
	p1, err := GeneratePassphrase()
	if err != nil {
		t.Fatalf("GeneratePassphrase: %v", err)
	}
	if parts := strings.Split(p1, "-"); len(parts) != 6 {
		t.Fatalf("expected 6 words, got %d: %q", len(parts), p1)
	}
	p2, _ := GeneratePassphrase()
	if p1 == p2 {
		// Astronomically unlikely with ~77 bits of entropy; if this
		// ever fires something is badly wrong.
		t.Fatalf("two generates produced identical passphrases: %q", p1)
	}
}
