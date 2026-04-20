package marking

import "testing"

func TestMark_IsCUI(t *testing.T) {
	cases := map[Mark]bool{
		MarkNone:      false,
		MarkBasic:     true,
		MarkSpecified: true,
		MarkPropIn:    true,
		MarkPrivacy:   true,
		MarkITAR:      true,
	}
	for m, want := range cases {
		if got := m.IsCUI(); got != want {
			t.Errorf("%q.IsCUI() = %v, want %v", m, got, want)
		}
	}
}

func TestMark_RequiresStepUpAndPublicShare(t *testing.T) {
	// Every CUI mark requires step-up and blocks public share.
	for _, m := range []Mark{MarkBasic, MarkSpecified, MarkPropIn, MarkPrivacy, MarkITAR} {
		if !m.RequiresStepUpMFA() {
			t.Errorf("%q.RequiresStepUpMFA() = false, want true", m)
		}
		if m.AllowsPublicShare() {
			t.Errorf("%q.AllowsPublicShare() = true, want false", m)
		}
	}
	if MarkNone.RequiresStepUpMFA() {
		t.Errorf("MarkNone.RequiresStepUpMFA() = true, want false")
	}
	if !MarkNone.AllowsPublicShare() {
		t.Errorf("MarkNone.AllowsPublicShare() = false, want true")
	}
}

func TestCatalog_DefaultContainsStarterSet(t *testing.T) {
	c := DefaultCatalog()
	for _, m := range []Mark{MarkNone, MarkBasic, MarkSpecified, MarkPropIn, MarkPrivacy, MarkITAR} {
		if !c.Contains(m) {
			t.Errorf("default catalog missing %q", m)
		}
	}
	// Unknown mark rejected.
	if c.Contains("CUI//SP-MADEUP") {
		t.Error("default catalog accepted unknown mark")
	}
}

func TestCatalog_Extend(t *testing.T) {
	c := DefaultCatalog()
	custom := Mark("CUI//SP-HPTI")
	if c.Contains(custom) {
		t.Fatal("precondition: custom mark must not be in default")
	}
	c.Extend(custom)
	if !c.Contains(custom) {
		t.Error("Extend did not add the mark")
	}
	// Extend is idempotent.
	c.Extend(custom)
	marks := c.Marks()
	count := 0
	for _, m := range marks {
		if m == custom {
			count++
		}
	}
	if count != 1 {
		t.Errorf("custom mark appears %d times after re-Extend, want 1", count)
	}
}

func TestCatalog_Marks(t *testing.T) {
	c := DefaultCatalog()
	got := c.Marks()
	if len(got) < 6 {
		t.Errorf("expected at least 6 marks in starter set, got %d", len(got))
	}
}
