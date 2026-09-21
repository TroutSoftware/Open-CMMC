// cmmc-smb renders the shop-floor Samba configuration from cells.yaml
// and manages machine accounts in the running container.
//
//	cmmc-smb validate  [--cells F]
//	cmmc-smb render    [--cells F] [--out D] --image REF --ot-ip IP [--legacy-ip IP] [--ot-zone Z] [--gid N]
//	cmmc-smb useradd   [--cells F] MACHINE [--dry-run]     (prints the controller setup card once)
//	cmmc-smb card      [--cells F] MACHINE                 (re-prints the card, without the password)
//	cmmc-smb ssp-table [--cells F] --image REF
//
// The inventory (cells.yaml) is the single source of truth: shares,
// hosts allow, firewalld rich rules, Unix accounts and the SSP asset
// rows are all derived from it, so they cannot drift apart (3.4.1).
// Design: docs/cmmc/smb-connectivity-scope.md rev 3.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/filebrowser/filebrowser/v2/cmmc/otrelease"
	"github.com/filebrowser/filebrowser/v2/smb/render"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "cmmc-smb:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: cmmc-smb <command> [flags]

commands:
  validate    parse and validate cells.yaml
  render      write smb.conf(s), passwd/group, firewalld.sh and quadlets under --out
  useradd     create a machine account in the running container (prints the setup card once)
  card        print a machine's controller setup card (no password)
  ssp-table   print the SSP asset / crypto-module / exception rows as markdown

run "cmmc-smb <command> -h" for flags.
`)
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return flag.ErrHelp
	}
	switch args[0] {
	case "validate":
		return cmdValidate(args[1:], stdout, stderr)
	case "render":
		return cmdRender(args[1:], stdout, stderr)
	case "useradd":
		return cmdUseradd(args[1:], stdout, stderr)
	case "card":
		return cmdCard(args[1:], stdout, stderr)
	case "ssp-table":
		return cmdSSPTable(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cellsFlag(fs *flag.FlagSet) *string {
	return fs.String("cells", otrelease.DefaultCells, "path to cells.yaml")
}

func cmdValidate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cellsPath := cellsFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := otrelease.LoadCells(*cellsPath)
	if err != nil {
		return err
	}
	n := 0
	for _, cell := range c.Cells {
		n += len(cell.Machines)
	}
	fmt.Fprintf(stdout, "ok: %d cell(s), %d machine(s)\n", len(c.Cells), n)
	return nil
}

// renderOpts are the inputs to a render; kept as a struct so tests can
// call renderTo without a FlagSet.
type renderOpts struct {
	cellsPath, out, image, otIP, legacyIP, otZone string
	gid                                           int
	// alias: the OT address is an alias on the LAN NIC (single-NIC
	// shops); firewall rules are keyed on destination address instead
	// of a dedicated zone. See render.RenderFirewalldRules.
	alias bool
}

func cmdRender(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := renderOpts{}
	cellsPath := cellsFlag(fs)
	fs.StringVar(&o.out, "out", render.HostEtc, "output directory")
	fs.StringVar(&o.image, "image", "", "container image reference (digest-pinned)")
	fs.StringVar(&o.otIP, "ot-ip", "", "host address on the OT side to publish 445 on")
	fs.StringVar(&o.legacyIP, "legacy-ip", "", "second OT-side address for the SMB1 instance (required if any smb1 machine)")
	fs.StringVar(&o.otZone, "ot-zone", "ot", "firewalld zone bound to the OT interface")
	fs.IntVar(&o.gid, "gid", 0, "gid of the cmmc-filebrowser service group (owner of out/ and return/)")
	fs.BoolVar(&o.alias, "alias", false, "OT address is an alias on the LAN interface (single-NIC): destination-keyed rules in --ot-zone instead of a DROP zone")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.cellsPath = *cellsPath
	if o.image == "" || o.otIP == "" {
		return errors.New("render: --image and --ot-ip are required")
	}
	if o.gid <= 0 {
		return errors.New("render: --gid is required (getent group cmmc-filebrowser)")
	}
	written, err := renderTo(o)
	if err != nil {
		return err
	}
	for _, w := range written {
		fmt.Fprintln(stdout, "wrote", w)
	}
	return nil
}

// renderTo writes every artifact under o.out and returns the paths.
// Nothing outside o.out is touched.
func renderTo(o renderOpts) ([]string, error) {
	c, err := otrelease.LoadCells(o.cellsPath)
	if err != nil {
		return nil, err
	}
	primary, err := render.RenderPrimary(c)
	if err != nil {
		return nil, err
	}
	legacy, hasLegacy, err := render.RenderLegacy(c)
	if err != nil {
		return nil, err
	}
	if hasLegacy && o.legacyIP == "" {
		return nil, errors.New("render: cells.yaml has smb1 machines — --legacy-ip is required")
	}
	if !filepath.IsAbs(o.out) {
		abs, err := filepath.Abs(o.out)
		if err != nil {
			return nil, err
		}
		o.out = abs
	}
	var written []string
	put := func(rel, content string, mode os.FileMode) error {
		p := filepath.Join(o.out, rel)
		if !strings.HasPrefix(p, o.out+string(os.PathSeparator)) {
			return fmt.Errorf("render: refusing to write outside %s: %s", o.out, p)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			return err
		}
		written = append(written, p)
		return nil
	}
	passwd, group := render.RenderPasswd(c, false, o.gid)
	for rel, content := range map[string]string{
		"primary/smb.conf": primary,
		"primary/passwd":   passwd,
		"primary/group":    group,
	} {
		if err := put(rel, content, 0o640); err != nil {
			return written, err
		}
	}
	if hasLegacy {
		lp, lg := render.RenderPasswd(c, true, o.gid)
		for rel, content := range map[string]string{
			"legacy/smb.conf": legacy,
			"legacy/passwd":   lp,
			"legacy/group":    lg,
		} {
			if err := put(rel, content, 0o640); err != nil {
				return written, err
			}
		}
	}
	aliasIP := ""
	if o.alias {
		aliasIP = o.otIP
	}
	fw := "#!/bin/bash\n# GENERATED by cmmc-smb render — firewalld rich rules for the OT address (3.13.1 / 3.13.6).\nset -euo pipefail\n" +
		strings.Join(render.RenderFirewalldRules(c, o.otZone, aliasIP), "\n") + "\nfirewall-cmd --reload\n"
	if err := put("firewalld.sh", fw, 0o750); err != nil {
		return written, err
	}
	// render.env records what the shares were rendered for, so `card`
	// and the installer's re-runs do not need the flags again.
	envf := fmt.Sprintf("OT_IP=%s\nLEGACY_IP=%s\nIMAGE=%s\nOT_ZONE=%s\nALIAS=%t\n", o.otIP, o.legacyIP, o.image, o.otZone, o.alias)
	if err := put("render.env", envf, 0o640); err != nil {
		return written, err
	}
	pq, lq := render.RenderQuadlet(o.image, o.otIP, o.legacyIP, hasLegacy)
	if err := put("quadlet/"+render.PrimaryContainer+".container", pq, 0o644); err != nil {
		return written, err
	}
	if hasLegacy {
		if err := put("quadlet/"+render.LegacyContainer+".container", lq, 0o644); err != nil {
			return written, err
		}
	}
	return written, nil
}

// passwordAlphabet avoids characters operators mistype on a controller
// keypad (0/O, 1/l/I) and shell-hostile punctuation.
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// PasswordLength satisfies the 3.5.7 policy with margin for a
// machine credential that is never typed by a human after setup.
const PasswordLength = 24

func generatePassword() (string, error) {
	b := make([]byte, PasswordLength)
	max := byte(len(passwordAlphabet))
	for i := range b {
		for {
			var r [1]byte
			if _, err := rand.Read(r[:]); err != nil {
				return "", err
			}
			// Rejection sampling keeps the distribution uniform.
			if r[0] < 255-(255%max) {
				b[i] = passwordAlphabet[r[0]%max]
				break
			}
		}
	}
	return string(b), nil
}

// useraddCommand is the podman invocation that sets the account
// password inside the right container. smbpasswd -s reads the password
// twice from stdin; -a adds the account if missing.
func useraddCommand(container, machine string) []string {
	return []string{"podman", "exec", "-i", container, "smbpasswd", "-s", "-a", machine}
}

// readRenderEnv returns the values `render` recorded, if any.
func readRenderEnv(dir string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(filepath.Join(dir, "render.env"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

// setupCard is what goes to the machine: everything the person at the
// controller needs, in the order the vendor screens ask for it. password
// is empty on re-prints.
func setupCard(c *otrelease.Cells, cell *otrelease.Cell, m *otrelease.Machine, env map[string]string, password string) string {
	server := env["OT_IP"]
	if m.Dialect == otrelease.DialectSMB1 && env["LEGACY_IP"] != "" {
		server = env["LEGACY_IP"]
	}
	if server == "" {
		server = "<OT address — run cmmc-smb render first>"
	}
	suffix := ""
	// No-password machines get their own share pair, named after them.
	if !m.HasPassword() {
		suffix = "-" + m.Name
	}
	// A cell with both SMB3 and SMB2 password machines has a second,
	// signed-only share pair for the SMB2 ones (render.go).
	if m.HasPassword() && m.Dialect == otrelease.DialectSMB2 && cell.EncryptShares() {
		for _, other := range cell.Machines {
			if other.Dialect == otrelease.DialectSMB3 {
				suffix = "-signed"
				break
			}
		}
	}
	pw := password
	if !m.HasPassword() {
		pw = "none — no password (leave blank); identified by address + physical path"
	} else if pw == "" {
		pw = "(set with: cmmc-smb useradd " + m.Name + ")"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "┌─ Shop-floor share — %s ─────────────────────────\n", m.Name)
	if m.Model != "" {
		fmt.Fprintf(&b, "│ Machine     : %s\n", m.Model)
	}
	fmt.Fprintf(&b, "│ Cell        : %s   (marking %s)\n", cell.Name, orNone(string(cell.Mark)))
	fmt.Fprintf(&b, "│ Server      : %s\n", server)
	fmt.Fprintf(&b, "│ Programs    : \\\\%s\\%s-out%s      (read-only)\n", server, cell.Name, suffix)
	fmt.Fprintf(&b, "│ Send back   : \\\\%s\\%s-return%s   (write)\n", server, cell.Name, suffix)
	fmt.Fprintf(&b, "│ User name   : %s\n", m.Name)
	fmt.Fprintf(&b, "│ Password    : %s\n", pw)
	fmt.Fprintf(&b, "│ Workgroup   : WORKGROUP (any)\n")
	wire := " — signed"
	switch {
	case !m.HasPassword():
		wire = " — no signing/encryption (guest session; PDS cell)"
	case m.Dialect == otrelease.DialectSMB3 && cell.EncryptShares():
		wire = " — encrypted"
	}
	fmt.Fprintf(&b, "│ Dialect     : %s%s\n", strings.ToUpper(string(m.Dialect)), wire)
	fmt.Fprintf(&b, "│ Allowed from: %s only\n", m.IP)
	b.WriteString("└──────────────────────────────────────────────────────\n")
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func cmdCard(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("card", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cellsPath := cellsFlag(fs)
	etc := fs.String("etc", render.HostEtc, "rendered config directory (for render.env)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("card: exactly one MACHINE name is required")
	}
	c, err := otrelease.LoadCells(*cellsPath)
	if err != nil {
		return err
	}
	cell, m, ok := c.MachineByName(fs.Arg(0))
	if !ok {
		return fmt.Errorf("card: machine %q is not in %s", fs.Arg(0), *cellsPath)
	}
	_, err = io.WriteString(stdout, setupCard(c, cell, m, readRenderEnv(*etc), ""))
	return err
}

func cmdUseradd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("useradd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cellsPath := cellsFlag(fs)
	etc := fs.String("etc", render.HostEtc, "rendered config directory (for render.env)")
	dry := fs.Bool("dry-run", false, "print the podman command instead of running it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("useradd: exactly one MACHINE name is required")
	}
	machine := fs.Arg(0)
	c, err := otrelease.LoadCells(*cellsPath)
	if err != nil {
		return err
	}
	cell, m, ok := c.MachineByName(machine)
	if !ok {
		return fmt.Errorf("useradd: machine %q is not in %s", machine, *cellsPath)
	}
	if !m.HasPassword() {
		// Nothing to set: the machine connects without a password (guest
		// session mapped to its own Unix identity). Print the card so the
		// operator still gets the share paths to type in.
		fmt.Fprintf(stderr, "%s has auth: none — no password to set. To require one, set auth: password in cells.yaml, re-run install-smb.sh, then useradd again.\n", machine)
		_, err := io.WriteString(stdout, setupCard(c, cell, m, readRenderEnv(*etc), ""))
		return err
	}
	container := render.PrimaryContainer
	if m.Dialect == otrelease.DialectSMB1 {
		container = render.LegacyContainer
	}
	pw, err := generatePassword()
	if err != nil {
		return err
	}
	argv := useraddCommand(container, machine)
	if *dry {
		fmt.Fprintln(stdout, strings.Join(argv, " "))
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(pw + "\n" + pw + "\n")
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("useradd: %s: %w", strings.Join(argv, " "), err)
	}
	fmt.Fprintln(stderr, "Password shown ONCE below. Enter it on the controller now; it is stored nowhere else. Re-run useradd to rotate.")
	_, err = io.WriteString(stdout, setupCard(c, cell, m, readRenderEnv(*etc), pw))
	return err
}

func cmdSSPTable(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ssp-table", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cellsPath := cellsFlag(fs)
	image := fs.String("image", "", "container image reference, as deployed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := otrelease.LoadCells(*cellsPath)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, render.RenderSSPTable(c, *image))
	return err
}
