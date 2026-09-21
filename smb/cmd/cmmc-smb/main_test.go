package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := generatePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != PasswordLength {
			t.Fatalf("len = %d", len(pw))
		}
		for _, r := range pw {
			if !strings.ContainsRune(passwordAlphabet, r) {
				t.Fatalf("char %q outside alphabet", r)
			}
		}
		if seen[pw] {
			t.Fatal("duplicate password")
		}
		seen[pw] = true
	}
}

func TestUseraddDryRunPicksContainerByDialect(t *testing.T) {
	cells := filepath.Join("..", "..", "render", "testdata", "cells.yaml")
	var out, errb bytes.Buffer
	if err := run([]string{"useradd", "--cells", cells, "--dry-run", "cnc-a1"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if got := strings.TrimSpace(out.String()); got != "podman exec -i cmmc-smb smbpasswd -s -a cnc-a1" {
		t.Fatalf("primary: %q", got)
	}
	out.Reset()
	if err := run([]string{"useradd", "--cells", cells, "--dry-run", "fanuc-l1"}, &out, &errb); err != nil {
		t.Fatal(err, errb.String())
	}
	if !strings.Contains(out.String(), "cmmc-smb-legacy") {
		t.Fatalf("legacy: %q", out.String())
	}
	if err := run([]string{"useradd", "--cells", cells, "--dry-run", "nope"}, &out, &errb); err == nil {
		t.Fatal("unknown machine accepted")
	}
}

func TestRenderWritesOnlyUnderOut(t *testing.T) {
	cells := filepath.Join("..", "..", "render", "testdata", "cells.yaml")
	out := t.TempDir()
	written, err := renderTo(renderOpts{cellsPath: cells, out: out, image: "img@sha256:abc", otIP: "10.20.0.5", legacyIP: "10.20.0.6", otZone: "ot", gid: 990})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"primary/smb.conf", "primary/passwd", "primary/group", "legacy/smb.conf", "firewalld.sh", "quadlet/cmmc-smb.container", "quadlet/cmmc-smb-legacy.container"}
	for _, w := range want {
		if _, err := os.Stat(filepath.Join(out, w)); err != nil {
			t.Errorf("missing %s", w)
		}
	}
	for _, p := range written {
		if !strings.HasPrefix(p, out) {
			t.Fatalf("wrote outside out: %s", p)
		}
	}
	fw, _ := os.ReadFile(filepath.Join(out, "firewalld.sh"))
	if !strings.Contains(string(fw), "set -euo pipefail") || !strings.Contains(string(fw), "--set-target=DROP") {
		t.Fatalf("firewalld.sh: %s", fw)
	}
	// Legacy IP required when smb1 machines exist.
	if _, err := renderTo(renderOpts{cellsPath: cells, out: t.TempDir(), image: "img", otIP: "10.20.0.5", otZone: "ot", gid: 990}); err == nil {
		t.Fatal("missing --legacy-ip accepted")
	}
}

func TestValidateAndSSPTable(t *testing.T) {
	cells := filepath.Join("..", "..", "render", "testdata", "cells.yaml")
	var out, errb bytes.Buffer
	if err := run([]string{"validate", "--cells", cells}, &out, &errb); err != nil || !strings.HasPrefix(out.String(), "ok:") {
		t.Fatalf("validate: %v %s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"ssp-table", "--cells", cells, "--image", "img@sha256:abc"}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "non-validated") || !strings.Contains(out.String(), "cnc-a1") {
		t.Fatalf("ssp-table: %s", out.String())
	}
}

func TestCardAndAliasRules(t *testing.T) {
	cells := filepath.Join("..", "..", "render", "testdata", "cells.yaml")
	out := t.TempDir()
	if _, err := renderTo(renderOpts{cellsPath: cells, out: out, image: "img", otIP: "192.168.1.9", legacyIP: "192.168.1.10", otZone: "public", gid: 990, alias: true}); err != nil {
		t.Fatal(err)
	}
	fw, _ := os.ReadFile(filepath.Join(out, "firewalld.sh"))
	if !strings.Contains(string(fw), `destination address="192.168.1.9/32"`) || !strings.Contains(string(fw), `protocol="tcp" drop'`) || strings.Contains(string(fw), "set-target") {
		t.Fatalf("alias rules:\n%s", fw)
	}
	env := readRenderEnv(out)
	if env["OT_IP"] != "192.168.1.9" || env["ALIAS"] != "true" {
		t.Fatalf("render.env: %v", env)
	}
	var o, e bytes.Buffer
	if err := run([]string{"card", "--cells", cells, "--etc", out, "cnc-b1"}, &o, &e); err != nil {
		t.Fatal(err, e.String())
	}
	card := o.String()
	for _, want := range []string{"Server      : 192.168.1.9", `\\192.168.1.9\cell-b-out`, "User name   : cnc-b1", "SMB2 — signed", "Allowed from: 10.20.2.11"} {
		if !strings.Contains(card, want) {
			t.Fatalf("card missing %q:\n%s", want, card)
		}
	}
	o.Reset()
	if err := run([]string{"card", "--cells", cells, "--etc", out, "fanuc-l1"}, &o, &e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.String(), "Server      : 192.168.1.10") {
		t.Fatalf("legacy machine must point at the legacy address:\n%s", o.String())
	}
}
