package envelope

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Mode is the deployment posture for envelope encryption.
//
//   ModeDisabled — encryption off. Reads/writes pass through
//                  untransformed. Appropriate for dev or for a
//                  deployment that places CUI confidentiality
//                  controls at a lower layer (LUKS, LUKS+TPM).
//   ModeOptional — encrypt if KEK present; fall through to
//                  plaintext if not. Migration window.
//   ModeRequired — refuse to start if KEK is missing or
//                  invalid. Production CMMC L2 posture.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModeOptional Mode = "optional"
	ModeRequired Mode = "required"
)

// LoadKEKFromEnv reads the process KEK from configuration, matching
// these sources in order:
//
//   1. FB_CMMC_KEK_HEX — hex-encoded 32 bytes (64 chars). Dev only.
//   2. FB_CMMC_KEK_FILE — path to a file containing either 32 raw
//      bytes or 64 hex chars on one line. The file MUST be mode
//      0400 or 0600 (owner-read) — checked before use. Refusing
//      wide-readable files on disk prevents a trivial escalation.
//
// Returns (nil, nil) when no source is configured and mode is
// Disabled or Optional. Returns an error when mode is Required and
// the KEK can't be loaded — caller should exit rather than boot.
func LoadKEKFromEnv(mode Mode) (*KEK, error) {
	if mode == ModeDisabled {
		return nil, nil
	}
	if hx := strings.TrimSpace(os.Getenv("FB_CMMC_KEK_HEX")); hx != "" {
		return loadHex(hx)
	}
	if path := strings.TrimSpace(os.Getenv("FB_CMMC_KEK_FILE")); path != "" {
		return loadFile(path)
	}
	if mode == ModeRequired {
		return nil, fmt.Errorf("envelope: mode=required but no FB_CMMC_KEK_HEX or FB_CMMC_KEK_FILE set")
	}
	return nil, nil
}

func loadHex(hx string) (*KEK, error) {
	raw, err := hex.DecodeString(hx)
	if err != nil {
		return nil, fmt.Errorf("envelope: FB_CMMC_KEK_HEX not valid hex: %w", err)
	}
	return NewKEK(raw)
}

func loadFile(path string) (*KEK, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("envelope: KEK file stat %q: %w", path, err)
	}
	// 0o077 = anything-readable-by-group-or-other → refuse. The
	// KEK is the master key; leaving it world-readable is a CMMC
	// finding in itself. Matches ssh's strict host-key-file check.
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("envelope: KEK file %q too permissive (must be 0400 or 0600)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("envelope: read KEK file %q: %w", path, err)
	}
	// Accept either 32 binary bytes or 64 hex chars on one line.
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 2*KeySize {
		return loadHex(trimmed)
	}
	if len(raw) == KeySize {
		return NewKEK(raw)
	}
	return nil, fmt.Errorf("envelope: KEK file %q must contain %d raw bytes or %d hex chars, got %d bytes", path, KeySize, 2*KeySize, len(raw))
}

// ParseMode reads FB_CMMC_ENCRYPTION and returns a Mode. Invalid
// values are treated as Disabled with a warning to stderr — fail-
// open for dev, but the boot-time call to LoadKEKFromEnv with
// mode=Required still fails the process if production is
// misconfigured.
func ParseMode() Mode {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("FB_CMMC_ENCRYPTION")))
	switch v {
	case "required":
		return ModeRequired
	case "optional":
		return ModeOptional
	case "disabled", "":
		return ModeDisabled
	}
	fmt.Fprintf(os.Stderr, "WARNING: FB_CMMC_ENCRYPTION=%q unrecognized; defaulting to disabled\n", v)
	return ModeDisabled
}
