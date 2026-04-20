package scan

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Mode is the operator's AV posture for the deployment.
//
//   ModeDisabled — no scanner wired; uploads proceed unchecked.
//                  Acceptable only for environments where AV runs at
//                  a different layer (e.g., on the underlying
//                  filesystem via an antivirus mount filter).
//   ModeOptional — scanner configured but backend failures don't
//                  block uploads. Logs + audit reject on actual
//                  infection; logs + audit warn on backend error.
//                  Appropriate during rollout or when clamd is on a
//                  best-effort sidecar.
//   ModeRequired — CMMC L2 production posture. A backend failure is
//                  itself a 503 so a sick clamd can't silently let
//                  malware through. An infection rejects the upload
//                  with 422.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModeOptional Mode = "optional"
	ModeRequired Mode = "required"
)

// ParseMode reads FB_CMMC_AV. Unknown values fall back to disabled
// with a warning — mirrors envelope.ParseMode so operators don't
// have to remember two different failure-mode conventions.
func ParseMode() Mode {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("FB_CMMC_AV")))
	switch v {
	case "required":
		return ModeRequired
	case "optional":
		return ModeOptional
	case "disabled", "":
		return ModeDisabled
	}
	fmt.Fprintf(os.Stderr, "WARNING: FB_CMMC_AV=%q unrecognized; defaulting to disabled\n", v)
	return ModeDisabled
}

// LoadScannerFromEnv is the boot-time glue. Returns a Scanner ready
// to use, the active Mode, and any config error. Concrete backend
// wiring is left to each backend's factory — this file stays
// dependency-free so `cmd/root.go` can call it without pulling in a
// specific client library.
//
// Today the only backend recognized is ClamAV (FB_CMMC_AV_BACKEND
// is "clamav" or empty). Wiring is delegated to a registered
// factory map so a deployment can plug in a different backend by
// calling RegisterBackend at init time.
func LoadScannerFromEnv(mode Mode) (Scanner, error) {
	if mode == ModeDisabled {
		return nil, nil
	}
	name := strings.ToLower(strings.TrimSpace(os.Getenv("FB_CMMC_AV_BACKEND")))
	if name == "" {
		name = "clamav"
	}
	factory, ok := backends[name]
	if !ok {
		if mode == ModeRequired {
			return nil, fmt.Errorf("scan: mode=required but no backend registered for %q (import its package to register)", name)
		}
		return nil, nil
	}
	s, err := factory()
	if err != nil {
		if mode == ModeRequired {
			return nil, fmt.Errorf("scan: %s backend init: %w", name, err)
		}
		return nil, nil
	}
	return s, nil
}

// backends is populated by init() in each backend package.
// Kept package-private so callers can only register through
// RegisterBackend; prevents accidental double-registration.
var backends = map[string]func() (Scanner, error){}

// RegisterBackend is called from a backend package's init() to make
// itself discoverable by LoadScannerFromEnv. Safe to call multiple
// times with the same name (last registration wins) for test
// scenarios that swap a mock in.
func RegisterBackend(name string, factory func() (Scanner, error)) {
	backends[name] = factory
}

// DefaultTimeout caps an individual Scan call. Clamd's TCP INSTREAM
// can hang on a broken socket; 30 s is generous for a 256 MiB
// payload over loopback (clamd scans ~500 MiB/s on modest hardware)
// and bounded enough that a stuck upload doesn't burn a worker
// forever.
const DefaultTimeout = 30 * time.Second
