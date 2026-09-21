// Package otrelease implements shop-floor delivery of CUI files over SMB:
// an explicit, audited *release* of a cabinet file into a per-cell
// read-only share, and an *intake* path that pulls machine-written files
// back through quarantine, a content gate and the AV scanner before they
// touch the cabinet.
//
// The cabinet is never exported. The Samba container (see config/smb/)
// only ever sees two directories:
//
//	<root>/out/<cell>/            released plaintext + manifests (ro)
//	<root>/return/<cell>/<machine> machine drop folders (rw)
//
// Design and compliance rationale: docs/cmmc/smb-connectivity-scope.md
// (rev 3). Controls anchored here: 3.1.3 (flow control at release),
// 3.3.1/3.3.2 (every release/intake audited), 3.8.4 (mark travels in the
// manifest and is inherited on intake), 3.14.2 (gate + scan before filing).
package otrelease

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
)

// Dialect is the SMB dialect floor a machine needs. It drives which
// Samba instance serves the machine (smb1 → the legacy container) and
// whether encryption can be required on its shares.
type Dialect string

const (
	DialectSMB3 Dialect = "smb3" // SMB 3.x — encryption available
	DialectSMB2 Dialect = "smb2" // SMB 2.x — signing only
	DialectSMB1 Dialect = "smb1" // NT1 — legacy container, PDS required
)

func (d Dialect) valid() bool {
	return d == DialectSMB3 || d == DialectSMB2 || d == DialectSMB1
}

// Auth is how a machine identifies itself to the share.
//
//	AuthNone     — no password (default). The machine is identified by
//	               its source address and the physical path; the session
//	               is a guest session, so SMB signing/encryption are not
//	               available for it. Allowed only in a pds_attested cell.
//	AuthPassword — per-machine account with an NTLMv2 password (set with
//	               `cmmc-smb useradd`); signing and, for SMB3, encryption
//	               apply. Required when the cell is not PDS-attested.
type Auth string

const (
	AuthNone     Auth = "none"
	AuthPassword Auth = "password"
)

// Machine is one controller. Name doubles as the Samba account / forced
// Unix identity, so it must be a safe identifier. IP is the single
// source address the machine may connect from (hosts allow + firewalld
// rich rule).
type Machine struct {
	Name    string  `yaml:"name" json:"name"`
	IP      string  `yaml:"ip" json:"ip"`
	Dialect Dialect `yaml:"dialect" json:"dialect"`
	// Auth defaults to "none" (see Auth).
	Auth Auth `yaml:"auth,omitempty" json:"auth,omitempty"`
	// Model is free text for the asset inventory ("Haas VF-2 NGC").
	Model string `yaml:"model,omitempty" json:"model,omitempty"`
}

// HasPassword reports whether the machine authenticates with a password.
func (m *Machine) HasPassword() bool { return m.Auth == AuthPassword }

// Cell is a group of machines that share one out-share and one return
// root. Mark is the cell's designation: files released into it must
// carry a mark the cell is allowed to hold (an ITAR cell may receive
// anything; a non-ITAR cell may not receive ITAR).
type Cell struct {
	Name string `yaml:"name" json:"name"`
	// Mark is the designation, in cmmc/marking form ("CUI//BASIC",
	// "CUI//SP-ITAR", "" for uncontrolled). Files taken back from the
	// cell inherit this mark.
	Mark cmmcmark.Mark `yaml:"mark" json:"mark"`
	// ReturnPath is the user-visible cabinet folder where intake files
	// land, e.g. "/Operations_CUI/NC/cell-a/return". Absolute within the
	// server root.
	ReturnPath string `yaml:"return_path" json:"return_path"`
	// PDSAttested records the operator's attestation that the physical
	// path to this cell is a Protected Distribution System. Required for
	// smb1 and smb2 machines (plaintext wire); see scope § 5.2.
	PDSAttested bool `yaml:"pds_attested" json:"pds_attested"`
	// TTLDays is the default release lifetime; 0 means package default.
	TTLDays int `yaml:"ttl_days,omitempty" json:"ttl_days,omitempty"`
	// AllowedExtensions gates intake; lowercase with leading dot. Empty
	// means the package default list.
	AllowedExtensions []string `yaml:"allowed_extensions,omitempty" json:"allowed_extensions,omitempty"`
	// MaxReturnBytes caps a single returned file; 0 = default 16 MiB.
	MaxReturnBytes int64 `yaml:"max_return_bytes,omitempty" json:"max_return_bytes,omitempty"`
	// DailyQuotaPerMachine caps files accepted per machine per UTC day;
	// 0 = default 500.
	DailyQuotaPerMachine int `yaml:"daily_quota_per_machine,omitempty" json:"daily_quota_per_machine,omitempty"`
	// Encrypt selects the SMB3 encryption posture for smb3 machines:
	// "defense-in-depth" (default, smb encrypt = required on the share)
	// or "off" (strictest 3.13.11 reading — no non-validated crypto
	// touches CUI on this hop). Ignored for smb2/smb1 machines.
	Encrypt string `yaml:"encrypt,omitempty" json:"encrypt,omitempty"`

	Machines []Machine `yaml:"machines" json:"machines"`
}

// Cells is the loaded, validated configuration.
type Cells struct {
	Cells []Cell `yaml:"cells" json:"cells"`

	byName map[string]*Cell
}

// Defaults applied when a cell leaves a field zero.
const (
	DefaultTTLDays         = 30
	DefaultMaxReturnBytes  = 16 << 20
	DefaultDailyQuota      = 500
	EncryptDefenseInDepth  = "defense-in-depth"
	EncryptOff             = "off"
	defaultAllowedExtsList = ".nc .mpf .spf .eia .txt .csv .tap .ptp .cnc .gcode .h .prg .min .mcd .log .json"
)

// DefaultAllowedExtensions is the package default intake allow-list.
var DefaultAllowedExtensions = strings.Fields(defaultAllowedExtsList)

// identRe bounds cell and machine names: they become share names, Samba
// account names and directory names, so keep them boring.
var identRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

var reservedNames = map[string]bool{"root": true, "nobody": true, "nogroup": true, "daemon": true, "bin": true, "sys": true, "guest": true, "admin": true, "administrator": true}

// ErrInvalidCells wraps every validation failure so callers can
// distinguish "bad config" from I/O errors.
var ErrInvalidCells = errors.New("otrelease: invalid cells config")

// LoadCells reads and validates a cells.yaml file.
func LoadCells(p string) (*Cells, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("otrelease: read cells: %w", err)
	}
	return ParseCells(raw)
}

// ParseCells validates YAML bytes. Kept separate from LoadCells so
// tests and the renderer can validate without touching disk.
func ParseCells(raw []byte) (*Cells, error) {
	var c Cells
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCells, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Cells) validate() error {
	// An empty inventory is valid: the installer starts the feature with
	// no cells so the first one can be added from Settings → Shop floor.
	// Samba then renders with no shares and the firewall with no rules.
	c.byName = make(map[string]*Cell, len(c.Cells))
	seenMachine := map[string]string{}
	seenIP := map[string]string{}
	catalog := cmmcmark.DefaultCatalog()
	for i := range c.Cells {
		cell := &c.Cells[i]
		if !identRe.MatchString(cell.Name) {
			return fmt.Errorf("%w: cell %q: name must match %s", ErrInvalidCells, cell.Name, identRe)
		}
		if _, dup := c.byName[cell.Name]; dup {
			return fmt.Errorf("%w: duplicate cell %q", ErrInvalidCells, cell.Name)
		}
		if !catalog.Contains(cell.Mark) {
			return fmt.Errorf("%w: cell %q: unknown mark %q", ErrInvalidCells, cell.Name, cell.Mark)
		}
		if cell.ReturnPath == "" || !strings.HasPrefix(cell.ReturnPath, "/") || path.Clean(cell.ReturnPath) != cell.ReturnPath {
			return fmt.Errorf("%w: cell %q: return_path must be a clean absolute path", ErrInvalidCells, cell.Name)
		}
		switch cell.Encrypt {
		case "", EncryptDefenseInDepth, EncryptOff:
		default:
			return fmt.Errorf("%w: cell %q: encrypt must be %q or %q", ErrInvalidCells, cell.Name, EncryptDefenseInDepth, EncryptOff)
		}
		for _, ext := range cell.AllowedExtensions {
			if !strings.HasPrefix(ext, ".") || ext != strings.ToLower(ext) {
				return fmt.Errorf("%w: cell %q: allowed extension %q must be lowercase with a leading dot", ErrInvalidCells, cell.Name, ext)
			}
		}
		if len(cell.Machines) == 0 {
			return fmt.Errorf("%w: cell %q: no machines", ErrInvalidCells, cell.Name)
		}
		for j := range cell.Machines {
			m := &cell.Machines[j]
			if m.Auth == "" {
				m.Auth = AuthNone
			}
			if m.Auth != AuthNone && m.Auth != AuthPassword {
				return fmt.Errorf("%w: machine %q: auth must be %q or %q", ErrInvalidCells, m.Name, AuthNone, AuthPassword)
			}
			// No password means a guest session: no signing, no encryption.
			// That is only a certifiable posture where the cable is the
			// control — the same PDS attestation plaintext dialects need.
			if m.Auth == AuthNone && !cell.PDSAttested {
				return fmt.Errorf("%w: machine %q in cell %q has no password (auth: none) — set pds_attested: true on the cell, or give the machine auth: password", ErrInvalidCells, m.Name, cell.Name)
			}
			if !identRe.MatchString(m.Name) {
				return fmt.Errorf("%w: machine %q: name must match %s", ErrInvalidCells, m.Name, identRe)
			}
			// Names become Unix accounts inside the container (force user /
			// tdbsam); a machine called root would be a root session.
			if reservedNames[m.Name] {
				return fmt.Errorf("%w: machine %q: reserved name", ErrInvalidCells, m.Name)
			}
			if prev, dup := seenMachine[m.Name]; dup {
				return fmt.Errorf("%w: machine %q defined in cells %q and %q", ErrInvalidCells, m.Name, prev, cell.Name)
			}
			seenMachine[m.Name] = cell.Name
			ip := net.ParseIP(m.IP)
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("%w: machine %q: ip %q is not an IPv4 address", ErrInvalidCells, m.Name, m.IP)
			}
			if prev, dup := seenIP[m.IP]; dup {
				return fmt.Errorf("%w: machine %q: ip %s already used by %q", ErrInvalidCells, m.Name, m.IP, prev)
			}
			seenIP[m.IP] = m.Name
			if !m.Dialect.valid() {
				return fmt.Errorf("%w: machine %q: dialect must be smb3, smb2 or smb1", ErrInvalidCells, m.Name)
			}
			// Plaintext wire (smb1, smb2) is only certifiable over a
			// Protected Distribution System — scope § 5. Refuse to load
			// rather than let an operator configure an unassessable cell.
			if m.Dialect != DialectSMB3 && !cell.PDSAttested {
				return fmt.Errorf("%w: machine %q (%s) in cell %q requires pds_attested: true (plaintext SMB wire)", ErrInvalidCells, m.Name, m.Dialect, cell.Name)
			}
			// Without a PDS the wire must be encrypted, which needs SMB3
			// *and* a password (encryption keys derive from the session).
			if !cell.PDSAttested && cell.Encrypt == EncryptOff {
				return fmt.Errorf("%w: cell %q: encrypt: off needs pds_attested: true", ErrInvalidCells, cell.Name)
			}
		}
		c.byName[cell.Name] = cell
	}
	return nil
}

// Get returns the cell by name.
func (c *Cells) Get(name string) (*Cell, bool) {
	cell, ok := c.byName[name]
	return cell, ok
}

// Names returns cell names sorted.
func (c *Cells) Names() []string {
	out := make([]string, 0, len(c.Cells))
	for _, cell := range c.Cells {
		out = append(out, cell.Name)
	}
	sort.Strings(out)
	return out
}

// MachineByName finds a machine and its cell.
func (c *Cells) MachineByName(name string) (*Cell, *Machine, bool) {
	for i := range c.Cells {
		for j := range c.Cells[i].Machines {
			if c.Cells[i].Machines[j].Name == name {
				return &c.Cells[i], &c.Cells[i].Machines[j], true
			}
		}
	}
	return nil, nil, false
}

// TTL returns the cell's release lifetime.
func (cell *Cell) TTL() time.Duration {
	d := cell.TTLDays
	if d <= 0 {
		d = DefaultTTLDays
	}
	return time.Duration(d) * 24 * time.Hour
}

// Extensions returns the effective intake allow-list.
func (cell *Cell) Extensions() []string {
	if len(cell.AllowedExtensions) > 0 {
		return cell.AllowedExtensions
	}
	return DefaultAllowedExtensions
}

// MaxBytes returns the effective per-file intake cap.
func (cell *Cell) MaxBytes() int64 {
	if cell.MaxReturnBytes > 0 {
		return cell.MaxReturnBytes
	}
	return DefaultMaxReturnBytes
}

// Quota returns the effective per-machine daily intake quota.
func (cell *Cell) Quota() int {
	if cell.DailyQuotaPerMachine > 0 {
		return cell.DailyQuotaPerMachine
	}
	return DefaultDailyQuota
}

// EncryptShares reports whether smb3 shares in this cell should require
// SMB encryption.
func (cell *Cell) EncryptShares() bool {
	return cell.Encrypt != EncryptOff
}

// AcceptsMark reports whether a file carrying mark m may be released
// into this cell. Rule (scope § 4, mirrors the share daemon's 403):
// ITAR-marked files only go to ITAR-designated cells; everything else
// may go anywhere. Uncontrolled files may go to any cell.
func (cell *Cell) AcceptsMark(m cmmcmark.Mark) bool {
	if m == cmmcmark.MarkITAR {
		return cell.Mark == cmmcmark.MarkITAR
	}
	return true
}
