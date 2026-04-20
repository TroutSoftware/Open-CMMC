package oidc

import (
	"errors"
	"fmt"
	"sync"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
	cabinet "github.com/filebrowser/filebrowser/v2/cmmc/cabinet"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/rules"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// ComputeEffectivePerms turns a user's Keycloak group membership into
// a filebrowser users.Permissions struct by looking up each group's
// role in authz.Store and unioning the resulting permission sets.
//
// If permStore is nil (deployment hasn't wired group-based authz yet)
// the legacy isAdmin flag from the session drives a binary
// Admin-or-nothing behavior — this keeps existing deployments working
// during the Phase 1 rollout.
//
// Admin wins: membership in any adminGroup (FB_OIDC_ADMIN_GROUPS)
// promotes the user to the Admin role regardless of other matches.
// This preserves the existing convention and keeps the "admin switch"
// operators already rely on during break-glass scenarios.
func ComputeEffectivePerms(userGroups []string, permStore authz.Store, adminGroups []string, isAdminFallback bool) users.Permissions {
	// Admin override — matches existing behavior in callback.go
	// where `sess.IsAdmin` was already computed from adminGroups.
	adminSet := make(map[string]struct{}, len(adminGroups))
	for _, g := range adminGroups {
		adminSet[g] = struct{}{}
	}
	for _, g := range userGroups {
		if _, ok := adminSet[g]; ok {
			return authz.ApplyRole(authz.RoleAdmin)
		}
	}
	// No role store configured → Phase 0 compatibility: just
	// reflect the session's admin flag (preserves prior behavior
	// for any deployment that hasn't run the Phase 1 migration).
	if permStore == nil {
		if isAdminFallback {
			return authz.ApplyRole(authz.RoleAdmin)
		}
		return users.Permissions{Download: true, Create: true, Modify: true}
	}
	// Phase 1: union of matched group roles.
	var perms users.Permissions
	for _, g := range userGroups {
		gp, err := permStore.Get(g)
		if err != nil || gp == nil {
			continue
		}
		perms = authz.MergePerms(perms, authz.ApplyRole(gp.Role))
	}
	return perms
}

// provisionLocks serializes provisioning per (iss, sub) so two concurrent
// callbacks for the same new identity don't both race into createOIDCUser
// (which would double-MakeUserDir and fight on Save).
var (
	provisionLocksMu sync.Mutex
	provisionLocks   = make(map[string]*sync.Mutex)
)

func lockForIdentity(key string) *sync.Mutex {
	provisionLocksMu.Lock()
	defer provisionLocksMu.Unlock()
	m, ok := provisionLocks[key]
	if !ok {
		m = &sync.Mutex{}
		provisionLocks[key] = m
	}
	return m
}

// ErrUsernameCollision is returned when the claim-derived username
// matches an existing local user whose (iss, sub) mapping points to a
// different identity — the exact signature of a username-rewrite attack.
var ErrUsernameCollision = errors.New("oidc: username collides with a different OIDC identity")

// ProvisionOrFetchBySubject is the subject-keyed (iss+sub) provisioning
// entry point. It supersedes the earlier username-keyed ProvisionOrFetch:
//
//  1. Look up the (iss, sub) mapping.
//  2. Hit → load user by ID, sync admin flag, return.
//  3. Miss → check if a local user with the claim's username exists:
//     a. No user found → create user + write (iss, sub) mapping.
//     b. User exists and has NO mapping → backfill the mapping (migration
//        path for users provisioned before the mapping layer).
//     c. User exists and is mapped to a DIFFERENT (iss, sub) → refuse.
//        This is the attack signal where a user has renamed themselves
//        onto another user's username via mutable preferred_username.
//
// issuer is the config.Issuer — the token's `iss` is checked upstream in
// the go-oidc Verifier and thus guaranteed to equal the configured issuer
// by the time we get here.
func ProvisionOrFetchBySubject(
	idStore IdentityStore,
	userStore users.Store,
	permStore authz.Store,
	sess *VerifiedSession,
	issuer string,
	adminGroups []string,
	set *settings.Settings,
	srv *settings.Server,
) (*users.User, error) {
	if sess.Username == "" {
		return nil, errors.New("oidc: session has no username")
	}
	if sess.Subject == "" {
		return nil, errors.New("oidc: session has no subject")
	}
	key := IssSubKey(issuer, sess.Subject)
	mu := lockForIdentity(key)
	mu.Lock()
	defer mu.Unlock()

	// Path 1: existing (iss, sub) mapping.
	id, err := idStore.Get(key)
	if err == nil {
		u, gerr := userStore.Get(srv.Root, id.UserID)
		if gerr != nil {
			return nil, fmt.Errorf("oidc: mapped user id=%d not found: %w", id.UserID, gerr)
		}
		// Recompute the full Perm set from current group membership
		// on every login. This is the Phase 1 contract: Keycloak is
		// the source of truth for group membership, group→role is
		// the source of truth for permissions, and the local User
		// row is a cache refreshed at login. Admins who edit Perm
		// directly in the DB will see their changes overwritten —
		// that's the point.
		newPerms := ComputeEffectivePerms(sess.Groups, permStore, adminGroups, sess.IsAdmin)
		newRules := cabinet.GroupRules(sess.Groups, adminGroups, cabinet.DefaultLayout)
		changed := false
		if u.Perm != newPerms {
			u.Perm = newPerms
			changed = true
		}
		if u.Scope != "/" {
			// Migration: legacy users provisioned before C.5 have
			// scopes like /users/alice. Move them onto the shared
			// cabinet root so they see the seeded folder tree.
			u.Scope = "/"
			changed = true
		}
		if !rulesEqual(u.Rules, newRules) {
			u.Rules = newRules
			changed = true
		}
		// Profile fields re-sourced from the IdP on every login so
		// the "my page" view never shows stale name/email/groups.
		if u.Email != sess.Email {
			u.Email = sess.Email
			changed = true
		}
		if u.FullName != sess.FullName {
			u.FullName = sess.FullName
			changed = true
		}
		if !stringSlicesEqual(u.Groups, sess.Groups) {
			u.Groups = sess.Groups
			changed = true
		}
		if changed {
			if uerr := userStore.Update(u, "Perm", "Scope", "Rules", "Email", "FullName", "Groups"); uerr != nil {
				return nil, fmt.Errorf("oidc: sync profile: %w", uerr)
			}
		}
		return u, nil
	}
	if !errors.Is(err, fberrors.ErrNotExist) {
		return nil, fmt.Errorf("oidc: identity lookup: %w", err)
	}

	// Path 2: no mapping — check if local user exists by username.
	existing, ugerr := userStore.Get(srv.Root, sess.Username)
	if ugerr != nil && !errors.Is(ugerr, fberrors.ErrNotExist) {
		return nil, fmt.Errorf("oidc: username lookup: %w", ugerr)
	}

	if existing != nil {
		// Path 2b/2c: username match. Check if that user already has a
		// mapping to a DIFFERENT subject — if so, reject.
		if collision, err := anyIdentityForUser(idStore, existing.ID); err != nil {
			return nil, fmt.Errorf("oidc: collision check: %w", err)
		} else if collision {
			return nil, ErrUsernameCollision
		}
		// Backfill path: the legacy user gets a mapping written now.
		// Recompute perms same as Path 1 so a pre-Phase-1 user's
		// stale Perm struct doesn't outlive the migration.
		if perr := idStore.Put(&Identity{IssSubKey: key, UserID: existing.ID}); perr != nil {
			return nil, fmt.Errorf("oidc: backfill mapping: %w", perr)
		}
		newPerms := ComputeEffectivePerms(sess.Groups, permStore, adminGroups, sess.IsAdmin)
		existing.Perm = newPerms
		existing.Scope = "/"
		existing.Rules = cabinet.GroupRules(sess.Groups, adminGroups, cabinet.DefaultLayout)
		existing.Email = sess.Email
		existing.FullName = sess.FullName
		existing.Groups = sess.Groups
		if uerr := userStore.Update(existing, "Perm", "Scope", "Rules", "Email", "FullName", "Groups"); uerr != nil {
			return nil, fmt.Errorf("oidc: sync profile after backfill: %w", uerr)
		}
		return existing, nil
	}

	// Path 2a: create new user and write mapping.
	newPerms := ComputeEffectivePerms(sess.Groups, permStore, adminGroups, sess.IsAdmin)
	u, err := createOIDCUserWithPerms(userStore, sess, set, srv, newPerms)
	if err != nil {
		return nil, err
	}
	// First-login: seed this user's visibility rules. Admins get nil
	// rules (full cabinet); everyone else gets the deny-list for
	// folders they don't own.
	u.Rules = cabinet.GroupRules(sess.Groups, adminGroups, cabinet.DefaultLayout)
	if uerr := userStore.Update(u, "Rules"); uerr != nil {
		return nil, fmt.Errorf("oidc: seed rules for new user: %w", uerr)
	}
	if perr := idStore.Put(&Identity{IssSubKey: key, UserID: u.ID}); perr != nil {
		// The user row is created but the mapping write failed; next login
		// will hit the backfill path and succeed. Log-and-continue would
		// be worse because the mapping is load-bearing for identity —
		// return the error so the caller decides.
		return nil, fmt.Errorf("oidc: write mapping for new user: %w", perr)
	}
	return u, nil
}

// anyIdentityForUser reports whether any OIDC identity is already mapped
// to the given local user id. Uses DeleteByUserID's query path in reverse:
// Get-by-user is not in the interface to keep the surface small, so we
// add a lightweight check via a probe.
//
// This is a best-effort defense; the underlying store's uniqueness on
// IssSubKey is the ultimate guarantee. The check is wrapped around
// existing user provisioning to surface collisions with a clean error.
func anyIdentityForUser(idStore IdentityStore, userID uint) (bool, error) {
	// IdentityStore doesn't expose a lookup-by-UserID to keep the
	// interface minimal. For the collision check we rely on a sentinel
	// approach: attempt to DeleteByUserID a sentinel (no-op for records
	// with no matches). But that has side effects. Instead we introduce
	// an optional extension interface UserLookup and type-assert.
	if l, ok := idStore.(userLookup); ok {
		return l.HasUserID(userID)
	}
	// Fallback: backend does not expose the reverse lookup. In that case
	// we can't detect collisions at this layer — rely on the unique
	// constraint at Put time to surface them.
	return false, nil
}

// userLookup is an optional extension interface. The bolt implementation
// provides it. Alternative implementations (e.g., a mock in tests) can
// opt in by implementing HasUserID.
type userLookup interface {
	HasUserID(userID uint) (bool, error)
}

// createOIDCUserWithPerms is the Phase 1 entry point. Caller passes a
// pre-computed permission set (typically from ComputeEffectivePerms
// over the session's group list) so the creator doesn't need to know
// about the authz store.
//
// OIDC-specific defaults: LockPassword=true (the user will never log
// in with a local password — auth always re-verifies against the
// IdP), a random placeholder password the user can never use, and
// Execute always off regardless of role — shell-exec is incompatible
// with a CMMC cabinet.
func createOIDCUserWithPerms(store users.Store, sess *VerifiedSession, set *settings.Settings, srv *settings.Server, perms users.Permissions) (*users.User, error) {
	const placeholderLen = settings.DefaultMinimumPasswordLength + 10
	pwd, err := users.RandomPwd(placeholderLen)
	if err != nil {
		return nil, fmt.Errorf("oidc: random placeholder password: %w", err)
	}
	hashed, err := users.ValidateAndHashPwd(pwd, set.MinimumPasswordLength)
	if err != nil {
		return nil, fmt.Errorf("oidc: hash placeholder: %w", err)
	}
	user := &users.User{
		Username:     sess.Username,
		Password:     hashed,
		LockPassword: true,
		Email:        sess.Email,
		FullName:     sess.FullName,
		Groups:       sess.Groups,
	}
	set.Defaults.Apply(user)
	perms.Execute = false // hard deny — see doc above
	user.Perm = perms
	user.Commands = []string{}

	// CMMC cabinet (C.5): users share the server root rather than
	// living in a per-user scope. Visibility across the cabinet is
	// controlled by group-based rules applied at provision time
	// (see the ProvisionOrFetchBySubject caller); CUI containment
	// is enforced orthogonally by the marking layer. No more
	// MakeUserDir — the seeded cabinet folders are the workspace.
	user.Scope = "/"

	if err := store.Save(user); err != nil {
		return nil, fmt.Errorf("oidc: save user: %w", err)
	}
	return user, nil
}

// stringSlicesEqual compares two string slices element-wise. Used to
// avoid a user-row write on every login when the Groups claim hasn't
// actually changed — storm's Update is not free, and the modified
// timestamp on the users bucket drives cache invalidation.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// rulesEqual compares two rule slices by the three fields that
// GroupRules sets (Allow, Path, Regex). Used to skip a user-row
// write on logins where group membership didn't change the derived
// visibility rules.
func rulesEqual(a, b []rules.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Allow != b[i].Allow || a[i].Path != b[i].Path || a[i].Regex != b[i].Regex {
			return false
		}
	}
	return true
}
