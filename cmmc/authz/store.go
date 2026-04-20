package authz

// Store persists GroupPermission records keyed on the Keycloak group
// name. Implementations live in storage backends (storage/bolt).
//
// The interface is intentionally small: admins only need to list,
// set, and clear. There is no "get per-user effective perms" method
// because that computation (list user groups → lookup each → union)
// happens at OIDC provisioning time and the result is written to the
// user row — the file-request hot path never touches this store.
type Store interface {
	// Get returns the role assignment for a single group. Missing
	// rows return (nil, ErrNotExist) so callers can default to
	// RoleNone without a type assertion.
	Get(groupName string) (*GroupPermission, error)

	// Put upserts the row. ModifiedAt is updated by the backend.
	// CreatedAt is preserved across upserts.
	Put(gp *GroupPermission) error

	// Delete removes the row. Missing is a no-op (idempotent).
	// A deleted group reverts users' perms to whatever their other
	// groups grant — possibly nothing, which by design denies all
	// file actions until an admin re-assigns.
	Delete(groupName string) error

	// List returns every row, ordered by GroupName. Admins use this
	// to render the "Groups & Permissions" UI; the HTTP layer
	// should not paginate — deployments have O(dozens) of groups,
	// never enough to need scrolling.
	List() ([]*GroupPermission, error)
}
