// Package marking models the CUI (Controlled Unclassified Information)
// marking applied to files handled by the CMMC-Filebrowser fork.
//
// Mark values are sourced from the DoD CUI Registry
// (https://www.dodcui.mil/CUI-Registry/). The package ships a small
// starter set covering the categories most commonly relevant to an
// on-prem CUI file store; operators can extend the set via a
// config-loaded list (see the Catalog type below) so DoD Registry
// updates do not require a code change.
//
// Mapped CMMC controls:
//   3.8.4   Mark media with CUI markings and distribution limits
//   3.1.3   Control flow of CUI per approved authorizations
//   3.1.22  Control CUI posted on publicly accessible systems
package marking

// Mark is the wire value of a CUI designation. Empty string means
// "not CUI" — the default state for freshly uploaded content until
// an admin or policy engine applies a mark.
//
// The wire format follows the DoD Registry convention: a leading
// `CUI` token, optionally followed by `//<CATEGORY>` and
// `//<SUBCATEGORY>`. Empty string sorts out as "not CUI" in
// comparisons and is the zero value for JSON omission.
type Mark string

const (
	// MarkNone is the absence-of-CUI sentinel. Files with this mark
	// are treated as non-CUI for every enforcement check.
	MarkNone Mark = ""

	// MarkBasic is the baseline CUI designation for files whose
	// category is Basic (no specified category per the Registry).
	MarkBasic Mark = "CUI//BASIC"

	// MarkSpecified is a generic "CUI//SPECIFIED" for cases where
	// the user knows the file is in a Specified category but has
	// not yet picked one of the concrete subcategories below.
	MarkSpecified Mark = "CUI//SPECIFIED"

	// MarkPropIn — Proprietary Business Information (DoD Registry
	// category SP-PROPIN).
	MarkPropIn Mark = "CUI//SP-PROPIN"

	// MarkPrivacy — Privacy (DoD Registry category SP-PRVCY).
	MarkPrivacy Mark = "CUI//SP-PRVCY"

	// MarkITAR — Export-controlled under ITAR (Registry category
	// SP-ITAR). Stricter distribution rules; note the enforcement
	// layer should add a dedicated NOFORN-style check before
	// permitting foreign-person access.
	MarkITAR Mark = "CUI//SP-ITAR"
)

// IsCUI reports whether the mark indicates the file holds CUI and
// should be subject to all downstream enforcement (public-share
// block, fresh-MFA requirement on download, envelope-encryption AAD
// binding, etc.). Empty mark → false.
func (m Mark) IsCUI() bool { return m != MarkNone && m != "" }

// RequiresStepUpMFA reports whether a download of this mark's
// content must fail-closed when the session's cmmc_mfa_at is older
// than the freshness threshold. Today every CUI-marked file
// requires step-up; kept as a separate predicate so a future marking
// scheme could exempt a subset (for example, a low-sensitivity
// MarkTech label) without touching the handler wiring.
func (m Mark) RequiresStepUpMFA() bool { return m.IsCUI() }

// AllowsPublicShare reports whether unauthenticated share links may
// serve this file. CUI marks forbid it unconditionally (3.1.22);
// non-CUI files fall through to the user's own Perm.Share check.
func (m Mark) AllowsPublicShare() bool { return !m.IsCUI() }

// Catalog is the set of marks a deployment recognizes. The starter
// constants above populate the default catalog; an operator override
// file (docs/marking.md describes the format) can extend it
// when the DoD Registry adds a category we haven't pre-baked.
type Catalog struct {
	marks map[Mark]struct{}
}

// DefaultCatalog returns a Catalog pre-populated with the starter set.
func DefaultCatalog() *Catalog {
	c := &Catalog{marks: make(map[Mark]struct{}, 6)}
	for _, m := range []Mark{
		MarkNone, MarkBasic, MarkSpecified, MarkPropIn, MarkPrivacy, MarkITAR,
	} {
		c.marks[m] = struct{}{}
	}
	return c
}

// Extend adds additional marks (e.g., loaded from operator config).
// Duplicate marks are silently ignored.
func (c *Catalog) Extend(marks ...Mark) {
	for _, m := range marks {
		c.marks[m] = struct{}{}
	}
}

// Contains reports whether the mark is a member of this catalog.
// Used at PUT time to reject malformed marks before they land in
// storage.
func (c *Catalog) Contains(m Mark) bool {
	_, ok := c.marks[m]
	return ok
}

// Marks returns the catalog as a slice (for the /api/cmmc/marking
// admin UI to render a dropdown, or for SSP evidence).
func (c *Catalog) Marks() []Mark {
	out := make([]Mark, 0, len(c.marks))
	for m := range c.marks {
		out = append(out, m)
	}
	return out
}
