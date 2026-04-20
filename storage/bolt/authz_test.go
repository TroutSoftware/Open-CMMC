package bolt

import (
	"errors"
	"testing"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

func TestGroupPerm_PutGetRoundTrip(t *testing.T) {
	store := NewGroupPermBackend(openTestBolt(t))
	err := store.Put(&authz.GroupPermission{
		GroupName: "engineering",
		Role:      authz.RoleContributor,
		Source:    "admin:1",
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get("engineering")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Role != authz.RoleContributor {
		t.Errorf("role = %q", got.Role)
	}
	if got.CreatedAt.IsZero() || got.ModifiedAt.IsZero() {
		t.Errorf("timestamps not populated: %+v", got)
	}
}

func TestGroupPerm_GetMissing_ReturnsErrNotExist(t *testing.T) {
	store := NewGroupPermBackend(openTestBolt(t))
	_, err := store.Get("nope")
	if !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestGroupPerm_Put_Upserts_PreservesCreatedAt(t *testing.T) {
	store := NewGroupPermBackend(openTestBolt(t))
	_ = store.Put(&authz.GroupPermission{GroupName: "engineering", Role: authz.RoleViewer})
	first, _ := store.Get("engineering")
	firstCreated := first.CreatedAt

	_ = store.Put(&authz.GroupPermission{GroupName: "engineering", Role: authz.RoleAdmin})
	second, _ := store.Get("engineering")
	if second.Role != authz.RoleAdmin {
		t.Errorf("role not updated: %q", second.Role)
	}
	if !second.CreatedAt.Equal(firstCreated) {
		t.Errorf("CreatedAt changed on upsert: %v -> %v", firstCreated, second.CreatedAt)
	}
	if !second.ModifiedAt.After(firstCreated) && !second.ModifiedAt.Equal(firstCreated) {
		// Modified should be >= Created. Use >= via After||Equal to allow same-instant.
		t.Errorf("ModifiedAt not updated: %v", second.ModifiedAt)
	}
}

func TestGroupPerm_Delete_Idempotent(t *testing.T) {
	store := NewGroupPermBackend(openTestBolt(t))
	_ = store.Put(&authz.GroupPermission{GroupName: "engineering", Role: authz.RoleViewer})
	if err := store.Delete("engineering"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := store.Delete("engineering"); err != nil {
		t.Fatalf("second delete should be idempotent: %v", err)
	}
	if _, err := store.Get("engineering"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("row still present after delete")
	}
	if err := store.Delete("never-existed"); err != nil {
		t.Fatalf("delete of missing should be noop: %v", err)
	}
}

func TestGroupPerm_List_Ordered(t *testing.T) {
	store := NewGroupPermBackend(openTestBolt(t))
	_ = store.Put(&authz.GroupPermission{GroupName: "quality", Role: authz.RoleContributor})
	_ = store.Put(&authz.GroupPermission{GroupName: "engineering", Role: authz.RoleAdmin})
	_ = store.Put(&authz.GroupPermission{GroupName: "sales", Role: authz.RoleViewer})

	rows, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	// Alphabetical — deterministic UI rendering.
	if rows[0].GroupName != "engineering" || rows[1].GroupName != "quality" || rows[2].GroupName != "sales" {
		t.Errorf("not alphabetical: %v, %v, %v", rows[0].GroupName, rows[1].GroupName, rows[2].GroupName)
	}
}

func TestGroupPerm_List_EmptyIsNotError(t *testing.T) {
	store := NewGroupPermBackend(openTestBolt(t))
	rows, err := store.List()
	if err != nil {
		t.Fatalf("empty list should not error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(rows))
	}
}
