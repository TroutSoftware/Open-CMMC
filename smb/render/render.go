// Package render turns the cells.yaml inventory (cmmc/otrelease.Cells)
// into every artefact the shop-floor SMB hop needs: the two Samba
// configurations, the container's passwd/group, the firewalld rich
// rules, the podman quadlet units and the SSP evidence rows.
//
// One input, many outputs, deterministically. That is the whole point:
// `hosts allow`, the firewalld allow-list and the SSP asset inventory are
// rendered from the same machine list, so they cannot drift from each
// other (scope § 5.1). Output ordering is sorted everywhere so a re-render
// of an unchanged inventory is byte-identical and a config diff is a real
// posture change.
//
// Design: docs/cmmc/smb-connectivity-scope.md rev 3, §§ 4, 5, 5.1, 5.3.
// Controls anchored here: 3.1.3 (flow control — per-cell shares),
// 3.5.1/3.5.2 (one account per machine, NTLMv2 only), 3.13.1/3.13.5/
// 3.13.6 (deny-by-default at the host firewall), 3.13.8/3.13.15 (signing
// mandatory, encryption where the controller can), 3.3.1/3.3.2
// (full_audit with %I|%m|%u|%S so every record names the machine).
package render

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/filebrowser/filebrowser/v2/cmmc/otrelease"
)

// Container names and host paths. The installer, the quadlets and the
// useradd subcommand all agree through these constants.
const (
	PrimaryContainer = "cmmc-smb"
	LegacyContainer  = "cmmc-smb-legacy"

	// HostOTRoot is FB_CMMC_SMB_ROOT — the only tree the containers see.
	HostOTRoot = "/srv/cmmc-filebrowser/ot"
	// HostEtc holds the rendered configs; cells.yaml lives beside them.
	HostEtc = "/etc/cmmc-smb"

	// ServiceGroup is the enclave service account. Machine accounts inside
	// the container share its gid so the intake poller can read what a
	// controller wrote (0660 files under 0770 dirs) and the container can
	// read what the releaser published (0640 under 0750). See RenderPasswd.
	ServiceGroup = "cmmc-filebrowser"

	// uidBase is where machine uids start inside the container. There is
	// no user namespace (smbd needs the real uid for file ownership), so
	// these uids appear as-is on host files under ot/return. They are
	// deliberately far from any host system account.
	uidBase = 20000
)

// ErrUnattested is returned when an smb1 machine sits in a cell without
// the PDS attestation. ParseCells already refuses such a file; this is
// belt-and-braces for callers that build Cells by hand.
var ErrUnattested = errors.New("render: smb1 machine in a cell without pds_attested")

// ---------------------------------------------------------------------
// smb.conf
// ---------------------------------------------------------------------

// shareGroup is one (cell, encryption posture) pair — the unit that gets
// an [<cell>-out]/[<cell>-return] share pair. A cell with both smb3
// machines (encrypted) and smb2 machines (signed only) yields two groups
// because `smb encrypt = required` is per share and would lock the smb2
// controllers out.
type shareGroup struct {
	cell    string
	suffix  string // "" or "-signed"
	encrypt bool
	users   []string
	hosts   []string
	// guest groups are one machine each (see groupsFor): no password, the
	// share maps the guest session to that machine's Unix identity.
	guest   bool
	machine string
}

// groupsFor splits a cell's machines into share groups for one Samba
// instance. legacy=true selects smb1 machines only; legacy=false selects
// smb2 and smb3 and applies the encryption posture.
func groupsFor(cell *otrelease.Cell, legacy bool) []shareGroup {
	var enc, plain []otrelease.Machine
	var guests []otrelease.Machine
	for _, m := range cell.Machines {
		if (m.Dialect == otrelease.DialectSMB1) != legacy {
			continue
		}
		if !m.HasPassword() {
			// Guest sessions carry no session key, so neither signing
			// nor encryption can apply: one plain share pair per machine,
			// named after the machine, guest-mapped to its Unix identity.
			guests = append(guests, m)
			continue
		}
		if !legacy && m.Dialect == otrelease.DialectSMB3 && cell.EncryptShares() {
			enc = append(enc, m)
		} else {
			plain = append(plain, m)
		}
	}
	var out []shareGroup
	sort.Slice(guests, func(i, j int) bool { return guests[i].Name < guests[j].Name })
	for _, m := range guests {
		out = append(out, shareGroup{cell: cell.Name, suffix: "-" + m.Name, guest: true, machine: m.Name, users: []string{m.Name}, hosts: []string{m.IP}})
	}
	switch {
	case len(enc) > 0 && len(plain) > 0:
		// Mixed cell: the encrypted pair keeps the plain [<cell>-out] name
		// (it is the posture the cell was scoped for); the smb2 stragglers
		// get an explicit -signed suffix so the SSP can name them.
		out = append(out, newGroup(cell.Name, "", true, enc), newGroup(cell.Name, "-signed", false, plain))
	case len(enc) > 0:
		out = append(out, newGroup(cell.Name, "", true, enc))
	case len(plain) > 0:
		out = append(out, newGroup(cell.Name, "", false, plain))
	}
	return out
}

func newGroup(cell, suffix string, encrypt bool, ms []otrelease.Machine) shareGroup {
	g := shareGroup{cell: cell, suffix: suffix, encrypt: encrypt}
	for _, m := range ms {
		g.users = append(g.users, m.Name)
		g.hosts = append(g.hosts, m.IP)
	}
	sort.Strings(g.users)
	sortIPs(g.hosts)
	return g
}

// sortIPs orders dotted quads numerically, not lexically, so 10.20.1.9
// precedes 10.20.1.10 in hosts allow and in the firewall script.
func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a, b := net.ParseIP(ips[i]).To4(), net.ParseIP(ips[j]).To4()
		if a == nil || b == nil {
			return ips[i] < ips[j]
		}
		for k := 0; k < 4; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
}

// sortedCells returns the cells by name; the Cells type keeps file order.
func sortedCells(c *otrelease.Cells) []*otrelease.Cell {
	out := make([]*otrelease.Cell, 0, len(c.Cells))
	for i := range c.Cells {
		out = append(out, &c.Cells[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// auditBlock is shared by both instances verbatim: the enclave tails the
// journal for `%I|%m|%u|%S` prefixed records and folds them into the HMAC
// chain (smb.connect / smb.read / smb.write with machine + client_ip +
// share) — 3.3.1, 3.3.2. Both containers must speak the same dialect.
const auditBlock = `   ; --- audit (3.3.1 / 3.3.2) -------------------------------------------
   ; Every record carries client IP | client name | account | share so the
   ; enclave can attribute it to a machine without a lookup. auth_audit:3
   ; makes failed NTLMv2 logins visible (3.5.x evidence). Records leave via
   ; syslog(3); the quadlet bind-mounts the host's /dev/log so they land in
   ; the host journal under facility local5, not in a container-local void.
   log level = 1 auth_audit:3
   vfs objects = full_audit
   full_audit:prefix = %I|%m|%u|%S
   full_audit:success = connect disconnect openat pwrite unlinkat renameat
   full_audit:failure = connect openat
   full_audit:facility = local5
   logging = syslog@1
`

// RenderPrimary produces smb.conf for the cmmc-smb container: SMB2/3
// only, NTLMv2 only, signing mandatory, encryption required on shares
// whose machines can all do SMB3 (scope § 5.1). smb1 machines are
// absent from this file entirely — `server min protocol` is global, so
// they must be served by the legacy instance (§ 5.3).
func RenderPrimary(c *otrelease.Cells) (string, error) {
	var b strings.Builder
	b.WriteString(`; cmmc-smb — primary Samba instance (mode N: per-machine NTLMv2 accounts)
; GENERATED by cmmc-smb render from cells.yaml. Do not edit; edit the
; inventory and re-render. Design: docs/cmmc/smb-connectivity-scope.md § 5.1.
[global]
   server role = standalone server
   security = user
   passdb backend = tdbsam
   ; --- authentication (3.5.1 / 3.5.2) ---------------------------------
   ; NTLMv2 gives every session a key, which is what makes SMB2 signing
   ; and SMB3 encryption possible. NTLMv1 / LM never, even for a legacy
   ; controller: those go to the legacy instance, never here.
   ntlm auth = ntlmv2-only
   lanman auth = no
   ; Guest access exists only on shares rendered for auth: none machines
   ; (guest ok + guest only + force user); every other share keeps a
   ; valid users list. "Bad User" maps a login with an unknown name to
   ; guest on those shares and nowhere else.
   map to guest = Bad User
   restrict anonymous = 0
   ; --- transport (3.13.8 / 3.13.15) -----------------------------------
   ; SMB1 is off at the protocol floor. Signing is "desired", not
   ; "mandatory": a mandatory setting rejects guest sessions outright
   ; (they have no session key), and no-password machines are the
   ; default. Authenticated SMB2 sessions therefore sign only when the
   ; client asks — acceptable because every SMB2 machine sits on a PDS
   ; cell where signing is defense-in-depth. Non-PDS cells are SMB3 +
   ; password only (cells.go), and there "smb encrypt = required" on the
   ; share provides both confidentiality and integrity. The global
   ; encryption setting stays "off" for the same reason as signing: any
   ; global "desired"/"required" makes smbd refuse guest sessions
   ; (NT_STATUS_INVALID_PARAMETER_MIX); the per-share "required" on
   ; password SMB3 shares is what enforces encryption where it exists.
   server min protocol = SMB2_02
   server signing = desired
   smb encrypt = off
   ; Only 445 is published from the bridge; NetBIOS has no business here.
   smb ports = 445
   disable netbios = yes
   ; No symlink tricks from either side: clients cannot create them and
   ; smbd does not follow them. The enclave poller also refuses anything
   ; that is not a regular file (cmmc/otrelease/intake.go).
   unix extensions = no
   follow symlinks = no
   wide links = no
   ; Idle controllers hold sessions for days; reap after 10 min so the
   ; audit trail shows connect/disconnect per job rather than per week.
   deadtime = 10
` + auditBlock)

	for _, cell := range sortedCells(c) {
		for _, g := range groupsFor(cell, false) {
			writeSharePair(&b, g)
		}
	}
	return b.String(), nil
}

// RenderLegacy produces smb.conf for cmmc-smb-legacy: an NT1-only
// listener for controllers that implement nothing newer (Fanuc Data
// Server, Win CE). SMB1 signing is MD5 and is disabled; the wire is
// plaintext, so the cell must be PDS-attested (§ 5.2, § 5.3). Returns
// ok=false (and no config) when no machine needs it.
func RenderLegacy(c *otrelease.Cells) (string, bool, error) {
	var groups []shareGroup
	for _, cell := range sortedCells(c) {
		gs := groupsFor(cell, true)
		if len(gs) > 0 && !cell.PDSAttested {
			return "", false, fmt.Errorf("%w: cell %q", ErrUnattested, cell.Name)
		}
		groups = append(groups, gs...)
	}
	if len(groups) == 0 {
		return "", false, nil
	}
	var b strings.Builder
	b.WriteString(`; cmmc-smb-legacy — SMB1 (NT1) listener for controllers that speak nothing newer
; GENERATED by cmmc-smb render from cells.yaml. Do not edit; edit the
; inventory and re-render. Design: docs/cmmc/smb-connectivity-scope.md § 5.3.
;
; This instance exists because "server min protocol" is global: one NT1
; share would downgrade every controller on the primary instance. It is
; an ENDURING EXCEPTION in the SSP (32 CFR 170.4) whose subject is the
; controllers, served over a Protected Distribution System, on its own
; OT-side IP, isolated to the source addresses below.
[global]
   server role = standalone server
   security = user
   passdb backend = tdbsam
   ; --- authentication -------------------------------------------------
   ; NTLMv2 stays the default even here. Some SMB1-era firmware (early
   ; Data Server, Win CE) is NTLMv1-only; that is a SECOND, separate
   ; relaxation — "ntlm auth = ntlmv1-permitted" — enabled per deployment
   ; only after the Phase 0 spike has validated the controller model and
   ; the SSP exception names it. Never in the primary instance.
   ntlm auth = ntlmv2-only
   lanman auth = no
   map to guest = Never
   restrict anonymous = 2
   ; --- transport ------------------------------------------------------
   ; NT1 both ends of the range so nothing negotiates upward by accident
   ; and lands on an instance that was not scoped for it. SMB1 signing is
   ; MD5-based and gives no assurance; disabled rather than pretended.
   unix extensions = no
   follow symlinks = no
   wide links = no
   server min protocol = NT1
   server max protocol = NT1
   server signing = disabled
   smb ports = 445
   disable netbios = yes
   deadtime = 10
   ; Per-client debug log; the audit stream below is the record.
   log file = /var/log/samba/legacy-%m.log
` + auditBlock)
	for _, g := range groups {
		writeSharePair(&b, g)
	}
	return b.String(), true, nil
}

// writeSharePair emits [<cell><suffix>-out] and [<cell><suffix>-return]
// for one share group. The return path uses %U so each machine lands in
// its own directory (scope § 4: no controller reads another's results).
func writeSharePair(b *strings.Builder, g shareGroup) {
	users := strings.Join(g.users, " ")
	hosts := strings.Join(g.hosts, " ")
	posture := "N-signed (SMB2 signing, plaintext wire — PDS)"
	if g.encrypt {
		posture = "N-enc (SMB3 encryption required)"
	}
	if g.guest {
		posture = "no password (guest session: no signing/encryption — PDS; identity = source address + forced user " + g.machine + ")"
	}
	fmt.Fprintf(b, "\n; cell %s — %s\n", g.cell, posture)
	fmt.Fprintf(b, "[%s-out%s]\n", g.cell, g.suffix)
	fmt.Fprintf(b, "   path = /export/out/%s\n", g.cell)
	b.WriteString("   read only = yes\n")
	if g.guest {
		b.WriteString("   guest ok = yes\n")
		b.WriteString("   guest only = yes\n")
		fmt.Fprintf(b, "   force user = %s\n", g.machine)
	} else {
		fmt.Fprintf(b, "   valid users = %s\n", users)
	}
	fmt.Fprintf(b, "   hosts allow = %s\n", hosts)
	b.WriteString("   hosts deny = ALL\n")
	if g.encrypt {
		b.WriteString("   smb encrypt = required\n")
	}
	fmt.Fprintf(b, "\n[%s-return%s]\n", g.cell, g.suffix)
	if g.guest {
		// %U would be "nobody" on a guest session; the path is fixed to
		// the machine's own folder and the forced user owns what lands.
		fmt.Fprintf(b, "   path = /export/return/%s/%s\n", g.cell, g.machine)
	} else {
		fmt.Fprintf(b, "   path = /export/return/%s/%%U\n", g.cell)
	}
	b.WriteString("   read only = no\n")
	if g.guest {
		b.WriteString("   guest ok = yes\n")
		b.WriteString("   guest only = yes\n")
		fmt.Fprintf(b, "   force user = %s\n", g.machine)
	} else {
		fmt.Fprintf(b, "   valid users = %s\n", users)
	}
	fmt.Fprintf(b, "   hosts allow = %s\n", hosts)
	b.WriteString("   hosts deny = ALL\n")
	// Group-writable so the intake poller (same gid, see RenderPasswd)
	// can move the file into quarantine and delete the original.
	b.WriteString("   create mask = 0660\n")
	b.WriteString("   directory mask = 0770\n")
	if g.encrypt {
		b.WriteString("   smb encrypt = required\n")
	}
}

// ---------------------------------------------------------------------
// passwd / group
// ---------------------------------------------------------------------

// RenderPasswd renders the /etc/passwd and /etc/group that are bind-
// mounted into the container. Samba's tdbsam still needs a Unix account
// behind every SMB account (smbpasswd -a fails without one, and smbd
// needs a uid to own what the controller writes), and the container's
// rootfs is read-only, so the accounts are rendered here rather than
// created at runtime.
//
// Every machine gets its own uid (uidBase + position in the sorted
// machine list) and the enclave service gid as primary group. Ownership
// on the host therefore reads <uid>:cmmc-filebrowser, and the 0660/0770
// masks in the return shares are what let the intake poller collect the
// files. uids may shift when the inventory changes; nothing depends on
// them — every permission on the data path is group-based.
//
// legacy selects which instance the file is for: only the machines that
// instance serves are present, so a stray account cannot log in to the
// wrong listener even if a password were set for it.
func RenderPasswd(c *otrelease.Cells, legacy bool, gid int) (passwd, group string) {
	var names []string
	for _, cell := range c.Cells {
		for _, m := range cell.Machines {
			if (m.Dialect == otrelease.DialectSMB1) == legacy {
				names = append(names, m.Name)
			}
		}
	}
	sort.Strings(names)

	var p, g strings.Builder
	p.WriteString("root:x:0:0:root:/root:/usr/sbin/nologin\n")
	p.WriteString("nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
	for i, n := range names {
		fmt.Fprintf(&p, "%s:x:%d:%d:shop-floor machine account:/nonexistent:/usr/sbin/nologin\n", n, uidBase+i, gid)
	}
	g.WriteString("root:x:0:\n")
	g.WriteString("nogroup:x:65534:\n")
	fmt.Fprintf(&g, "%s:x:%d:%s\n", ServiceGroup, gid, strings.Join(names, ","))
	return p.String(), g.String()
}

// ---------------------------------------------------------------------
// firewalld
// ---------------------------------------------------------------------

// RenderFirewalld returns the firewall-cmd invocations that make the OT
// zone deny-by-default with a /32 allow per machine on 445/tcp
// (3.13.1, 3.13.5, 3.13.6). Because the container sits on a podman
// bridge with 445 published on the OT address, every SMB packet crosses
// host netfilter and these rules are the enforcement point; Samba's own
// `hosts allow` is the second layer, rendered from the same list.
//
// The zone itself (interface binding) is created by install-smb.sh; this
// only fills it. Rules are sorted by IP so the script is stable, and the
// caller runs `firewall-cmd --reload` afterwards.
func RenderFirewalld(c *otrelease.Cells, otZone string) []string {
	return RenderFirewalldRules(c, otZone, "")
}

// RenderFirewalldRules is RenderFirewalld with an optional alias mode.
// When otIP is empty the OT side is its own interface bound to otZone
// (target DROP, accept 445 per machine). When otIP is set, the OT address
// is an alias on the LAN interface — single-NIC shops — so the zone
// cannot be bound by interface; instead every rule is keyed on the
// destination address: accept 445 to otIP from each machine, then drop
// 445 to otIP from anyone else. otZone is then the LAN zone (usually
// "public"). Deny-by-default for the OT address holds either way
// (3.13.1 / 3.13.6); the alias form gives up the physical separation
// and the posture table says so.
func RenderFirewalldRules(c *otrelease.Cells, otZone, otIP string) []string {
	var ips []string
	for _, cell := range c.Cells {
		for _, m := range cell.Machines {
			ips = append(ips, m.IP)
		}
	}
	sortIPs(ips)
	lines := make([]string, 0, len(ips)+1)
	dest := ""
	if otIP != "" {
		dest = fmt.Sprintf(` destination address="%s/32"`, otIP)
	}
	for _, ip := range ips {
		lines = append(lines, fmt.Sprintf(
			`firewall-cmd --permanent --zone=%s --add-rich-rule='rule family="ipv4" source address="%s/32"%s port port="445" protocol="tcp" accept'`,
			otZone, ip, dest))
	}
	if otIP != "" {
		lines = append(lines, fmt.Sprintf(
			`firewall-cmd --permanent --zone=%s --add-rich-rule='rule family="ipv4"%s port port="445" protocol="tcp" drop'`,
			otZone, dest))
	} else {
		lines = append(lines, fmt.Sprintf("firewall-cmd --permanent --zone=%s --set-target=DROP", otZone))
	}
	return lines
}

// ---------------------------------------------------------------------
// quadlet
// ---------------------------------------------------------------------

// RenderQuadlet produces the podman quadlet .container units for the
// primary and (optionally) legacy instance. Hardening per scope § 4:
// read-only rootfs, all capabilities dropped bar the five smbd needs,
// no-new-privileges, pids/memory caps, journald logging. The two units
// differ only in name, published IP, config directory and state volume.
//
// Volume labels: out/ and return/ use the shared label (z) because the
// enclave process and, when present, both containers touch them; a
// private label (Z) on a directory shared by two containers would let
// whichever started last lock the other out. The per-instance config
// directory is private (Z).
func RenderQuadlet(image, otIP, legacyIP string, legacy bool) (primary, legacyUnit string) {
	primary = quadlet(PrimaryContainer, image, otIP, HostEtc+"/primary", "cmmc-smb-state",
		"Open-CMMC shop-floor SMB (primary: SMB2/3, NTLMv2, signing mandatory)")
	if legacy {
		legacyUnit = quadlet(LegacyContainer, image, legacyIP, HostEtc+"/legacy", "cmmc-smb-legacy-state",
			"Open-CMMC shop-floor SMB (legacy: SMB1/NT1 listener, PDS cells only)")
	}
	return primary, legacyUnit
}

func quadlet(name, image, ip, etcDir, stateVolume, description string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# %s.container — podman quadlet, GENERATED by cmmc-smb render.
# Install to /etc/containers/systemd/ and run systemctl daemon-reload; the
# generated unit is %s.service. Do not edit; re-render.
# Design: docs/cmmc/smb-connectivity-scope.md § 4 (hardening) and § 5.
[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Container]
ContainerName=%s
Image=%s
# The OT-side address only. Bridge + published port (not macvlan) so every
# packet crosses host firewalld — that is the 3.13.1/3.13.5 evidence.
PublishPort=%s:445:445
# --- hardening (scope § 4) ---------------------------------------------
ReadOnly=true
DropCapability=ALL
# NET_BIND_SERVICE: port 445. SETUID/SETGID: smbd drops to the machine's
# uid per session. DAC_OVERRIDE/CHOWN: create files as that uid under the
# group-owned return tree. Nothing else.
AddCapability=NET_BIND_SERVICE SETUID SETGID DAC_OVERRIDE CHOWN
NoNewPrivileges=true
PidsLimit=256
PodmanArgs=--memory=512m
# --- logging (3.3.1) ---------------------------------------------------
# Container stdout goes to the host journal; Samba's audit stream goes via
# syslog(3) to the host's /dev/log (below), so both end up in journald and
# under the same 3.3.x retention as every other host log.
LogDriver=journald
Volume=/dev/log:/dev/log
# --- mounts ------------------------------------------------------------
# Released files: read-only. Returned files: read-write, per-machine
# subdirectories. Nothing else from the host — no cabinet, no BoltDB, no
# KEK, no enclave socket.
Volume=%s/out:/export/out:ro,z
Volume=%s/return:/export/return:rw,z
# Rendered smb.conf + the machine accounts (passwd/group), read-only.
Volume=%s:/etc/samba:ro,Z
Volume=%s/passwd:/etc/passwd:ro,Z
Volume=%s/group:/etc/group:ro,Z
# tdbsam (the NTLMv2 password hashes set by "cmmc-smb useradd") must
# persist across restarts and image updates; a named volume is the only
# writable state this container has.
Volume=%s:/var/lib/samba
# smbd needs scratch space for lock/pid files, its cache and per-client
# logs; tmpfs keeps the rootfs read-only.
Tmpfs=/run
Tmpfs=/var/cache/samba
Tmpfs=/var/log/samba

[Service]
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, name, name, description, name, image, ip, HostOTRoot, HostOTRoot, etcDir, etcDir, etcDir, stateVolume)
	return b.String()
}

// ---------------------------------------------------------------------
// SSP evidence
// ---------------------------------------------------------------------

// RenderSSPTable prints the markdown rows an assessor asks for: the asset
// inventory (one row per controller, from the same file that drives
// hosts allow), the cryptographic-module row that says plainly the SMB
// hop uses a NON-VALIDATED module (3.13.11), and — only when SMB1 cells
// exist — the enduring-exception row worded per scope § 5.3 with the
// controllers as its subject.
func RenderSSPTable(c *otrelease.Cells, image string) string {
	var b strings.Builder
	b.WriteString("## Shop-floor SMB — asset inventory\n\n")
	b.WriteString("Rendered from `/etc/cmmc-smb/cells.yaml`; the same file produces `hosts allow` and the firewalld allow-list.\n\n")
	b.WriteString("| Machine | Model | IP | Dialect | Auth | Cell | Mark | PDS attested |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	var legacyCells []string
	for _, cell := range sortedCells(c) {
		ms := append([]otrelease.Machine(nil), cell.Machines...)
		sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
		hasSMB1 := false
		for _, m := range ms {
			if m.Dialect == otrelease.DialectSMB1 {
				hasSMB1 = true
			}
			auth := "none (address + physical path)"
			if m.HasPassword() {
				auth = "password (NTLMv2)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				m.Name, orDash(m.Model), m.IP, m.Dialect, auth, cell.Name, orDash(string(cell.Mark)), yesNo(cell.PDSAttested))
		}
		if hasSMB1 {
			legacyCells = append(legacyCells, cell.Name)
		}
	}

	b.WriteString("\n## Cryptographic modules (3.13.11)\n\n")
	b.WriteString("| Module | Relied-upon control |\n")
	b.WriteString("|---|---|\n")
	// Say it plainly and pre-empt the 3-of-5 reading: name which control
	// the confidentiality claim rests on (scope § 5, "default posture").
	fmt.Fprintf(&b, "| cmmc-smb container — Samba/GnuTLS in %s, non-validated — NTLMv2 device authentication, SMB2 signing, SMB3 encryption on the OT hop | Confidentiality of CUI on this hop rests on the Protected Distribution System where one is attested; SMB3 encryption is defense-in-depth. The FIPS kernel, the enclave binary, TLS, JWT, envelope encryption and LUKS are unaffected — this is explicitly a non-FIPS service. |\n", image)

	if len(legacyCells) > 0 {
		b.WriteString("\n## Enduring exception (32 CFR 170.4) — SMB1 controllers\n\n")
		b.WriteString("| Subject | Statement |\n")
		b.WriteString("|---|---|\n")
		fmt.Fprintf(&b, "| Cells %s | Cells %s contain controllers that implement no dialect later than SMB1 / no authentication later than NTLMv1. To serve them, the appliance operates a dedicated SMB1 listener (%s) on its own OT-side address, isolated to those source addresses, over a PDS. The listener is a CUI asset and remains fully assessed (3.4.6, 3.4.7, 3.14.1); the exception endures for the life of those controllers. |\n",
			strings.Join(legacyCells, ", "), strings.Join(legacyCells, ", "), LegacyContainer)
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
