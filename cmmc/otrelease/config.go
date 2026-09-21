package otrelease

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mode is the deployment posture for shop-floor SMB delivery.
//
//	ModeDisabled — feature off; no directories, no routes, no pollers.
//	ModeRequired — cells file must load, the out/return tree must be
//	               writable, and AV must be in required mode (the
//	               return path scans before filing; an unscanned
//	               intake is not a posture we ship). Boot refuses
//	               otherwise. There is deliberately no "optional":
//	               a half-configured share is worse than none.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModeRequired Mode = "required"
)

// Config is read from the environment by cmd/root.go.
type Config struct {
	Mode Mode
	// Root is the tree the Samba container bind-mounts (out/, return/)
	// plus the quarantine/ the container never sees.
	Root string
	// CellsPath is the cells.yaml the cmmc-smb renderer also reads.
	CellsPath string
	// PollInterval is how often return folders are drained.
	PollInterval time.Duration
	// ExpiryInterval is how often TTL expiry runs.
	ExpiryInterval time.Duration
}

// Environment variable names.
const (
	EnvMode   = "FB_CMMC_SMB"
	EnvRoot   = "FB_CMMC_SMB_ROOT"
	EnvCells  = "FB_CMMC_SMB_CELLS"
	EnvPoll   = "FB_CMMC_SMB_POLL_SECONDS"
	EnvExpiry = "FB_CMMC_SMB_EXPIRY_SECONDS"

	DefaultRoot  = "/srv/cmmc-filebrowser/ot"
	DefaultCells = "/etc/cmmc-smb/cells.yaml"
)

// LoadConfigFromEnv parses the FB_CMMC_SMB_* variables. Returns a
// disabled config when FB_CMMC_SMB is unset or "disabled".
func LoadConfigFromEnv() (Config, error) {
	c := Config{
		Mode:           ModeDisabled,
		Root:           DefaultRoot,
		CellsPath:      DefaultCells,
		PollInterval:   60 * time.Second,
		ExpiryInterval: 10 * time.Minute,
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvMode))) {
	case "", string(ModeDisabled):
		return c, nil
	case string(ModeRequired):
		c.Mode = ModeRequired
	default:
		return c, fmt.Errorf("otrelease: %s must be %q or %q", EnvMode, ModeDisabled, ModeRequired)
	}
	if v := strings.TrimSpace(os.Getenv(EnvRoot)); v != "" {
		c.Root = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvCells)); v != "" {
		c.CellsPath = v
	}
	var err error
	if c.PollInterval, err = secondsEnv(EnvPoll, c.PollInterval); err != nil {
		return c, err
	}
	if c.ExpiryInterval, err = secondsEnv(EnvExpiry, c.ExpiryInterval); err != nil {
		return c, err
	}
	if _, err := os.Stat(c.CellsPath); err != nil {
		return c, fmt.Errorf("otrelease: %s=required but cells file %s: %w", EnvMode, c.CellsPath, err)
	}
	return c, nil
}

func secondsEnv(name string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 5 {
		return def, fmt.Errorf("otrelease: %s must be an integer ≥ 5", name)
	}
	return time.Duration(n) * time.Second, nil
}
