package render

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/filebrowser/filebrowser/v2/cmmc/otrelease"
)

// go test ./smb/render -update  regenerates testdata/*.golden. Review the
// diff before committing: the goldens ARE the smb.conf contract the SSP
// cites, so a golden change is a posture change.
var update = flag.Bool("update", false, "rewrite golden files")

func loadFixture(t *testing.T) *otrelease.Cells {
	t.Helper()
	c, err := otrelease.LoadCells(filepath.Join("testdata", "cells.yaml"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return c
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatalf("update %s: %v", p, err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update to create)", p, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// parseCells is a helper for inline fixtures in the edge-case tests.
func parseCells(t *testing.T, yaml string) *otrelease.Cells {
	t.Helper()
	c, err := otrelease.ParseCells([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// section returns the body of one [name] block in an smb.conf, or ""
// when the share is absent.
func section(conf, name string) string {
	marker := "[" + name + "]\n"
	i := strings.Index(conf, marker)
	if i < 0 {
		return ""
	}
	rest := conf[i+len(marker):]
	if j := strings.Index(rest, "\n["); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// --- goldens ---------------------------------------------------------

func TestGoldenPrimary(t *testing.T) {
	got, err := RenderPrimary(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "primary.golden", got)
}

func TestGoldenLegacy(t *testing.T) {
	got, ok, err := RenderLegacy(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("fixture has an smb1 machine; legacy config expected")
	}
	checkGolden(t, "legacy.golden", got)
}

// --- primary ---------------------------------------------------------

func TestPrimaryGlobalPosture(t *testing.T) {
	conf, err := RenderPrimary(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	global := section(conf, "global")
	for _, want := range []string{
		"server role = standalone server",
		"security = user",
		"passdb backend = tdbsam",
		"ntlm auth = ntlmv2-only",
		"lanman auth = no",
		"server min protocol = SMB2_02",
		"server signing = desired",
		"smb encrypt = off",
		"map to guest = Bad User",
		"restrict anonymous = 0",
		"deadtime = 10",
		"log level = 1 auth_audit:3",
		"vfs objects = full_audit",
		"full_audit:prefix = %I|%m|%u|%S",
		"full_audit:success = connect disconnect openat pwrite unlinkat renameat",
		"full_audit:failure = connect openat",
		"full_audit:facility = local5",
		"logging = syslog@1",
	} {
		if !strings.Contains(global, want+"\n") {
			t.Errorf("[global] missing %q", want)
		}
	}
}

func TestPrimaryExcludesSMB1(t *testing.T) {
	conf, err := RenderPrimary(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"fanuc-l1", "10.20.9.5", "[cell-legacy-out]", "[cell-legacy-return]"} {
		if strings.Contains(conf, s) {
			t.Errorf("primary config must not mention smb1 machine/cell: found %q", s)
		}
	}
}

func TestPrimaryShareShape(t *testing.T) {
	conf, err := RenderPrimary(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	out := section(conf, "cell-a-out")
	if out == "" {
		t.Fatal("[cell-a-out] missing")
	}
	for _, want := range []string{
		"path = /export/out/cell-a",
		"read only = yes",
		"valid users = cnc-a1 cnc-a2", // sorted, even though the fixture lists a2 first
		"hosts allow = 10.20.1.11 10.20.1.12",
		"hosts deny = ALL",
		"smb encrypt = required",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("[cell-a-out] missing %q\n%s", want, out)
		}
	}
	ret := section(conf, "cell-a-return")
	for _, want := range []string{
		"path = /export/return/cell-a/%U",
		"read only = no",
		"create mask = 0660",
		"directory mask = 0770",
		"valid users = cnc-a1 cnc-a2",
		"hosts allow = 10.20.1.11 10.20.1.12",
		"smb encrypt = required",
	} {
		if !strings.Contains(ret, want+"\n") {
			t.Errorf("[cell-a-return] missing %q\n%s", want, ret)
		}
	}
	// cell-b is smb2-only: signed, never encrypted.
	if b := section(conf, "cell-b-out"); strings.Contains(b, "smb encrypt") {
		t.Errorf("[cell-b-out] must not carry an encrypt line:\n%s", b)
	}
	if strings.Contains(conf, "[cell-b-out-signed]") {
		t.Error("single-posture cell must not get a -signed share")
	}
}

func TestEncryptOffDropsEncryptLine(t *testing.T) {
	c := parseCells(t, `
cells:
  - name: cell-a
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/cell-a/return
    pds_attested: true
    encrypt: "off"
    machines:
      - { name: cnc-a1, ip: 10.20.1.11, dialect: smb3, auth: password }
`)
	conf, err := RenderPrimary(c)
	if err != nil {
		t.Fatal(err)
	}
	if out := section(conf, "cell-a-out"); strings.Contains(out, "smb encrypt = required") {
		t.Errorf("encrypt: off must not require encryption:\n%s", out)
	}
	if !strings.Contains(conf, "[cell-a-out]\n") || !strings.Contains(conf, "[cell-a-return]\n") {
		t.Error("shares missing")
	}
}

func TestMixedCellSplitsSharesByPosture(t *testing.T) {
	c := parseCells(t, `
cells:
  - name: mix
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/mix/return
    pds_attested: true
    machines:
      - { name: new-1, ip: 10.30.0.1, dialect: smb3, auth: password }
      - { name: old-1, ip: 10.30.0.2, dialect: smb2, auth: password }
      - { name: old-2, ip: 10.30.0.3, dialect: smb2, auth: password }
`)
	conf, err := RenderPrimary(c)
	if err != nil {
		t.Fatal(err)
	}
	enc := section(conf, "mix-out")
	if !strings.Contains(enc, "valid users = new-1\n") || !strings.Contains(enc, "smb encrypt = required\n") {
		t.Errorf("[mix-out] should be the encrypted smb3 share:\n%s", enc)
	}
	signed := section(conf, "mix-out-signed")
	if signed == "" {
		t.Fatal("[mix-out-signed] missing")
	}
	if !strings.Contains(signed, "valid users = old-1 old-2\n") || strings.Contains(signed, "smb encrypt") {
		t.Errorf("[mix-out-signed] should hold the smb2 machines without encrypt:\n%s", signed)
	}
	if section(conf, "mix-return-signed") == "" {
		t.Error("[mix-return-signed] missing")
	}
	if !strings.Contains(section(conf, "mix-return"), "valid users = new-1\n") {
		t.Error("[mix-return] should list only the smb3 machine")
	}
}

func TestMixedCellEncryptOffCollapses(t *testing.T) {
	// encrypt: off — every machine is signed-only, so one share pair.
	c := parseCells(t, `
cells:
  - name: mix
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/mix/return
    pds_attested: true
    encrypt: "off"
    machines:
      - { name: new-1, ip: 10.30.0.1, dialect: smb3, auth: password }
      - { name: old-1, ip: 10.30.0.2, dialect: smb2, auth: password }
`)
	conf, err := RenderPrimary(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, "-signed]") {
		t.Errorf("encrypt off must not split shares:\n%s", conf)
	}
	if !strings.Contains(section(conf, "mix-out"), "valid users = new-1 old-1\n") {
		t.Errorf("both machines expected in [mix-out]:\n%s", conf)
	}
}

// --- legacy ----------------------------------------------------------

func TestLegacyEmptyWithoutSMB1(t *testing.T) {
	c := parseCells(t, `
cells:
  - name: cell-a
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/cell-a/return
    machines:
      - { name: cnc-a1, ip: 10.20.1.11, dialect: smb3, auth: password }
`)
	conf, ok, err := RenderLegacy(c)
	if err != nil {
		t.Fatal(err)
	}
	if ok || conf != "" {
		t.Errorf("no smb1 machines: want (\"\", false), got (%q, %v)", conf, ok)
	}
}

func TestLegacyPosture(t *testing.T) {
	conf, ok, err := RenderLegacy(loadFixture(t))
	if err != nil || !ok {
		t.Fatalf("legacy: %v %v", err, ok)
	}
	global := section(conf, "global")
	for _, want := range []string{
		"server min protocol = NT1",
		"server max protocol = NT1",
		"server signing = disabled",
		"ntlm auth = ntlmv2-only",
		"log file = /var/log/samba/legacy-%m.log",
		"vfs objects = full_audit",
		"full_audit:facility = local5",
	} {
		if !strings.Contains(global, want+"\n") {
			t.Errorf("[global] missing %q", want)
		}
	}
	if !strings.Contains(conf, "ntlmv1-permitted") {
		t.Error("legacy config should carry the ntlmv1-permitted relaxation as a comment")
	}
	for _, s := range []string{"cnc-a1", "cnc-b1", "[cell-a-out]", "[cell-b-out]", "smb encrypt"} {
		if strings.Contains(conf, s) {
			t.Errorf("legacy config must only serve smb1 machines: found %q", s)
		}
	}
	out := section(conf, "cell-legacy-out")
	for _, want := range []string{
		"path = /export/out/cell-legacy",
		"valid users = fanuc-l1",
		"hosts allow = 10.20.9.5",
		"hosts deny = ALL",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("[cell-legacy-out] missing %q", want)
		}
	}
	if !strings.Contains(section(conf, "cell-legacy-return"), "path = /export/return/cell-legacy/%U\n") {
		t.Error("[cell-legacy-return] missing")
	}
}

func TestLegacyRefusesUnattestedCell(t *testing.T) {
	// ParseCells already refuses this; the renderer is defensive against
	// a Cells value built by hand (tests, future callers).
	c := &otrelease.Cells{Cells: []otrelease.Cell{{
		Name:       "bad",
		ReturnPath: "/x",
		Machines:   []otrelease.Machine{{Name: "m1", IP: "10.0.0.1", Dialect: otrelease.DialectSMB1}},
	}}}
	if _, _, err := RenderLegacy(c); err == nil {
		t.Fatal("expected error for smb1 machine in a cell without pds_attested")
	}
}

// --- firewalld -------------------------------------------------------

func TestFirewalldLineCount(t *testing.T) {
	c := loadFixture(t)
	lines := RenderFirewalld(c, "ot")
	machines := 0
	for _, cell := range c.Cells {
		machines += len(cell.Machines)
	}
	if len(lines) != machines+1 {
		t.Fatalf("want %d lines (machines + target), got %d:\n%s", machines+1, len(lines), strings.Join(lines, "\n"))
	}
	// Sorted by IP, every machine present, DROP target last.
	wantOrder := []string{"10.20.1.11", "10.20.1.12", "10.20.2.11", "10.20.2.12", "10.20.9.5"}
	for i, ip := range wantOrder {
		if !strings.Contains(lines[i], `source address="`+ip+`/32"`) {
			t.Errorf("line %d: want %s, got %s", i, ip, lines[i])
		}
		if !strings.Contains(lines[i], "--zone=ot") || !strings.Contains(lines[i], `port port="445"`) {
			t.Errorf("line %d malformed: %s", i, lines[i])
		}
	}
	if last := lines[len(lines)-1]; last != "firewall-cmd --permanent --zone=ot --set-target=DROP" {
		t.Errorf("last line: %s", last)
	}
}

// --- quadlet ---------------------------------------------------------

func TestQuadlet(t *testing.T) {
	primary, legacy := RenderQuadlet("registry.example/cmmc-smb@sha256:abc", "10.20.0.1", "10.20.0.2", true)
	for _, want := range []string{
		"[Container]\n",
		"ContainerName=cmmc-smb\n",
		"Image=registry.example/cmmc-smb@sha256:abc\n",
		"PublishPort=10.20.0.1:445:445\n",
		"ReadOnly=true\n",
		"DropCapability=ALL\n",
		"AddCapability=NET_BIND_SERVICE SETUID SETGID DAC_OVERRIDE CHOWN\n",
		"NoNewPrivileges=true\n",
		"LogDriver=journald\n",
		"Volume=/srv/cmmc-filebrowser/ot/out:/export/out:ro,z\n",
		"Volume=/srv/cmmc-filebrowser/ot/return:/export/return:rw,z\n",
		"Volume=/etc/cmmc-smb/primary:/etc/samba:ro,Z\n",
		"Volume=/etc/cmmc-smb/primary/passwd:/etc/passwd:ro,Z\n",
		"Volume=/etc/cmmc-smb/primary/group:/etc/group:ro,Z\n",
		"Volume=cmmc-smb-state:/var/lib/samba\n",
		"Tmpfs=/run\n",
		"PidsLimit=256\n",
		"PodmanArgs=--memory=512m\n",
		"[Service]\nRestart=always\n",
		"[Install]\nWantedBy=multi-user.target\n",
	} {
		if !strings.Contains(primary, want) {
			t.Errorf("primary quadlet missing %q", want)
		}
	}
	for _, want := range []string{
		"ContainerName=cmmc-smb-legacy\n",
		"PublishPort=10.20.0.2:445:445\n",
		"Volume=/etc/cmmc-smb/legacy:/etc/samba:ro,Z\n",
		"Volume=cmmc-smb-legacy-state:/var/lib/samba\n",
	} {
		if !strings.Contains(legacy, want) {
			t.Errorf("legacy quadlet missing %q", want)
		}
	}
	if strings.Contains(legacy, "cmmc-smb-state:") {
		t.Error("legacy container must not share the primary tdbsam volume")
	}
	if _, none := RenderQuadlet("img", "10.20.0.1", "", false); none != "" {
		t.Error("legacy=false must yield an empty legacy unit")
	}
}

// --- passwd / group --------------------------------------------------

func TestPasswdGroup(t *testing.T) {
	c := loadFixture(t)
	passwd, group := RenderPasswd(c, false, 987)
	for _, want := range []string{"root:x:0:0:", "cnc-a1:x:", "cnc-a2:x:", "cnc-b1:x:"} {
		if !strings.Contains(passwd, want) {
			t.Errorf("primary passwd missing %q:\n%s", want, passwd)
		}
	}
	if strings.Contains(passwd, "fanuc-l1") {
		t.Error("primary passwd must not contain the smb1 machine")
	}
	if !strings.Contains(group, "cmmc-filebrowser:x:987:cnc-a1,cnc-a2,cnc-b1,cnc-b2\n") {
		t.Errorf("group must map machines into the service gid:\n%s", group)
	}
	// Deterministic: same input, same output; uid stable across renders.
	p2, _ := RenderPasswd(c, false, 987)
	if p2 != passwd {
		t.Error("passwd rendering is not deterministic")
	}
	lp, _ := RenderPasswd(c, true, 987)
	if !strings.Contains(lp, "fanuc-l1:x:") || strings.Contains(lp, "cnc-a1") {
		t.Errorf("legacy passwd should hold only smb1 machines:\n%s", lp)
	}
	// Every machine line uses the service gid and a uid in the reserved range.
	for _, line := range strings.Split(strings.TrimSpace(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) != 7 {
			t.Fatalf("malformed passwd line %q", line)
		}
		if strings.HasPrefix(f[0], "cnc-") && f[3] != "987" {
			t.Errorf("machine %s gid = %s, want 987", f[0], f[3])
		}
	}
}

// --- SSP table -------------------------------------------------------

func TestSSPTable(t *testing.T) {
	c := loadFixture(t)
	md := RenderSSPTable(c, "registry.example/cmmc-smb@sha256:abc")
	for _, want := range []string{
		"| cnc-a1 | Haas VF-2 NGC | 10.20.1.11 | smb3 | password (NTLMv2) | cell-a | CUI//BASIC | no |",
		"| cnc-b2 | Haas TL-1 (no password — PDS cell) | 10.20.2.12 | smb2 | none (address + physical path) | cell-b | CUI//BASIC | yes |",
		"| fanuc-l1 | Fanuc 31i Data Server | 10.20.9.5 | smb1 | password (NTLMv2) | cell-legacy | CUI//SP-ITAR | yes |",
		"Samba/GnuTLS in registry.example/cmmc-smb@sha256:abc, non-validated",
		"Enduring exception",
		"Cells cell-legacy contain controllers",
		"dedicated SMB1 listener",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("SSP table missing %q\n%s", want, md)
		}
	}
	noLegacy := parseCells(t, `
cells:
  - name: cell-a
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/cell-a/return
    machines:
      - { name: cnc-a1, ip: 10.20.1.11, dialect: smb3, auth: password }
`)
	if md := RenderSSPTable(noLegacy, "img"); strings.Contains(md, "Enduring exception") {
		t.Error("exception row must only appear when smb1 machines exist")
	}
}

func TestNoPasswordMachinesGetGuestShares(t *testing.T) {
	c := parseCells(t, `
cells:
  - name: g
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/g/return
    pds_attested: true
    machines:
      - { name: m-pw, ip: 10.40.0.1, dialect: smb3, auth: password }
      - { name: m-guest, ip: 10.40.0.2, dialect: smb2 }
`)
	conf, err := RenderPrimary(c)
	if err != nil {
		t.Fatal(err)
	}
	g := section(conf, "g-out-m-guest")
	for _, want := range []string{"guest ok = yes", "guest only = yes", "force user = m-guest", "hosts allow = 10.40.0.2"} {
		if !strings.Contains(g, want+"\n") {
			t.Errorf("[g-out-m-guest] missing %q:\n%s", want, g)
		}
	}
	if strings.Contains(g, "valid users") || strings.Contains(g, "smb encrypt") {
		t.Errorf("guest share must have neither valid users nor encryption:\n%s", g)
	}
	r := section(conf, "g-return-m-guest")
	if !strings.Contains(r, "path = /export/return/g/m-guest\n") {
		t.Errorf("guest return path must be fixed to the machine folder:\n%s", r)
	}
	pw := section(conf, "g-out")
	if !strings.Contains(pw, "valid users = m-pw\n") || strings.Contains(pw, "guest ok") {
		t.Errorf("password share unchanged:\n%s", pw)
	}
}
