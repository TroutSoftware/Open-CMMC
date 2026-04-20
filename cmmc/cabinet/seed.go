// Package cabinet bootstraps the CMMC-cabinet folder layout: a set
// of pre-classified top-level directories mapped to Keycloak groups,
// plus an ITAR drawer restricted to compliance. Runs idempotently on
// every boot — missing dirs are created, missing classifications are
// seeded, existing state is left alone.
package cabinet

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
)

// Folder describes one seeded top-level directory.
//
// Name is the directory name (no leading slash). Mark is the
// classification applied as a folder-level row in the marking store;
// empty means uncontrolled. Owner is a human-readable annotation
// for the bootstrap log — which group is the primary owner — and
// does not affect authorization directly (that comes from
// cmmc/authz group rules).
type Folder struct {
	Name  string
	Mark  cmmcmark.Mark
	Owner string // audit annotation only
}

// DefaultLayout is the opinionated starter roster. Matches the
// Keycloak group seed so dana (compliance) lands in ITAR, alice
// (engineering) lands in Engineering_*, etc. Deployments can replace
// this at build time by importing the package and calling Seed with
// a custom []Folder.
var DefaultLayout = []Folder{
	{Name: "Sales", Mark: cmmcmark.MarkNone, Owner: "sales"},
	{Name: "Sales_CUI", Mark: cmmcmark.MarkBasic, Owner: "sales"},
	{Name: "Engineering", Mark: cmmcmark.MarkNone, Owner: "engineering"},
	{Name: "Engineering_CUI", Mark: cmmcmark.MarkBasic, Owner: "engineering"},
	{Name: "Operations", Mark: cmmcmark.MarkNone, Owner: "operations"},
	{Name: "Operations_CUI", Mark: cmmcmark.MarkBasic, Owner: "operations"},
	{Name: "Management", Mark: cmmcmark.MarkNone, Owner: "management"},
	{Name: "ITAR", Mark: cmmcmark.MarkITAR, Owner: "compliance"},
}

// seedMarkerPath is a synthetic path used as a one-row marker in the
// marking store. Its presence means Seed has completed at least once
// on this database. Subsequent boots skip mark writes entirely so an
// admin who explicitly declassified a drawer (Delete'd its row) does
// not see their action reverted on restart. Without this, Seed can't
// distinguish "never classified" from "operator chose to uncontrol."
//
// The path is outside the normal filesystem namespace (`__cabinet_...__`)
// so it cannot collide with a real file.
const seedMarkerPath = "__cabinet_seed_marker_v1__"

// Seed lays down every folder in layout under rootPath and writes a
// folder-level marking row for each that has a Mark.
//
// First boot: creates dirs + writes marks + writes seed marker.
// Subsequent boots: ensures dirs exist (in case someone rm-rf'd
// the cabinet root) but does NOT rewrite marking rows, so operator
// declassify actions survive a restart.
//
// Returns the count of newly-created dirs and newly-written marking
// rows so the operator log can report what changed on this boot.
//
// rootPath is the server.Root — the filebrowser-serving directory.
// store is the marking backend.
func Seed(rootPath string, store cmmcmark.Store, layout []Folder) (dirsCreated, marksWritten int, err error) {
	if rootPath == "" {
		return 0, 0, fmt.Errorf("cabinet: empty rootPath")
	}
	if err := os.MkdirAll(rootPath, 0o750); err != nil {
		return 0, 0, fmt.Errorf("cabinet: mkdir root %q: %w", rootPath, err)
	}

	// Did we seed this database before? The marker is the
	// authority; it's written exactly once, at the end of the
	// first successful Seed. Operator edits to real folder rows
	// (upgrade from BASIC to ITAR, Delete to declassify, etc.)
	// stay intact across subsequent boots because we skip the
	// mark-write phase entirely.
	firstBoot := true
	if store != nil {
		if _, err := store.Get(seedMarkerPath); err == nil {
			firstBoot = false
		}
	}

	now := time.Now().UTC()
	for _, f := range layout {
		dirPath := filepath.Join(rootPath, f.Name)
		if _, statErr := os.Stat(dirPath); os.IsNotExist(statErr) {
			if mkErr := os.MkdirAll(dirPath, 0o750); mkErr != nil {
				return dirsCreated, marksWritten, fmt.Errorf("cabinet: mkdir %q: %w", dirPath, mkErr)
			}
			dirsCreated++
		} else if statErr != nil {
			return dirsCreated, marksWritten, fmt.Errorf("cabinet: stat %q: %w", dirPath, statErr)
		}
		// Post-first-boot: never touch the mark store here.
		if !firstBoot || store == nil || !f.Mark.IsCUI() {
			continue
		}
		// Belt-and-braces: if someone managed to write a row
		// before the first Seed completed (very unlikely — would
		// require pre-booting filebrowser, using the admin API,
		// shutting down, and re-running bootstrap), preserve it.
		if existing, gerr := store.Get(dirPath); gerr == nil && existing != nil {
			continue
		}
		if pErr := store.Put(&cmmcmark.FileMetadata{
			Path:       dirPath,
			Mark:       f.Mark,
			Source:     "cabinet:bootstrap",
			CreatedAt:  now,
			ModifiedAt: now,
		}); pErr != nil {
			return dirsCreated, marksWritten, fmt.Errorf("cabinet: seed mark %q: %w", dirPath, pErr)
		}
		marksWritten++
	}

	// Plant the marker only on a successful first-boot run so a
	// crash partway through leaves the system able to retry.
	if firstBoot && store != nil {
		if pErr := store.Put(&cmmcmark.FileMetadata{
			Path:       seedMarkerPath,
			Source:     "cabinet:seed-marker",
			CreatedAt:  now,
			ModifiedAt: now,
		}); pErr != nil {
			return dirsCreated, marksWritten, fmt.Errorf("cabinet: write seed marker: %w", pErr)
		}
	}
	return dirsCreated, marksWritten, nil
}
