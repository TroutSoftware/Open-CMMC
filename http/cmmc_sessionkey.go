package fbhttp

import (
	"errors"
	"fmt"
	"log"

	"github.com/filebrowser/filebrowser/v2/cmmc/crypto/keyderive"
	"github.com/filebrowser/filebrowser/v2/settings"
)

// derivedSessionKey caches the HKDF-derived session JWT subkey so
// mint/verify sites don't recompute on every request. Populated at
// boot by SetDerivedSessionKeyFromSettings; lazy-populated with
// pass-through to settings.Key if boot didn't wire it (dev safety
// net — new deployments always wire).
var derivedSessionKey []byte

// SetDerivedSessionKey installs the cached session subkey. Pass
// nil to revert to the master-key-as-signing-key fallback (not
// recommended outside tests).
func SetDerivedSessionKey(subkey []byte) {
	derivedSessionKey = subkey
}

// SetDerivedSessionKeyFromSettings derives + installs the session
// subkey from the given settings. Called once at boot from
// cmd/root.go. Returns error on any condition that would
// compromise CMMC 3.13.11 domain separation (nil settings, short
// master, HKDF failure) so the boot sequence fails loud instead
// of silently falling back to the shared master.
func SetDerivedSessionKeyFromSettings(s *settings.Settings) error {
	if s == nil {
		return errors.New("session key: settings unavailable at boot")
	}
	subkey, err := keyderive.SessionSigningKey(s.Key)
	if err != nil {
		return fmt.Errorf("session key: HKDF derive failed: %w", err)
	}
	derivedSessionKey = subkey
	log.Printf("session JWT key derived (HKDF subkey)")
	return nil
}

// sessionSigningKey returns the key to sign/verify session JWTs
// with. Reads the cached derived subkey if present, otherwise
// falls through to the settings master. Kept as a function (not a
// var) so request-time behavior tracks hot reconfig if we ever
// add one.
func sessionSigningKey(s *settings.Settings) []byte {
	if len(derivedSessionKey) > 0 {
		return derivedSessionKey
	}
	if s != nil {
		return s.Key
	}
	return nil
}
