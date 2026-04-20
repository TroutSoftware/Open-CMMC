// Package session provides the CMMC-fork's session-JWT claim shape,
// token minting, and the RequiresFreshMFA middleware that enforces
// recency of the user's MFA event for privileged handlers.
//
// The session token remains HS256-signed with the settings.Key so the
// upstream http.withUser middleware continues to parse it unchanged —
// upstream ignores extra claims. Our extended Claims embed the same
// UserInfo shape plus JTI (per-session unique id) and MFAAt (time of
// the IdP-asserted MFA). The RequiresFreshMFA middleware reads these
// extended claims and gates privileged handlers on MFA recency.
//
// Maps to CMMC controls:
//   - 3.5.3 (MFA for privileged/network access) — enforced at step-up
//   - 3.5.4 (replay-resistant authentication) — JTI is per-session unique
//   - 3.1.15 (authorize remote priv commands) — middleware gate
package session

import (
	"github.com/golang-jwt/jwt/v5"

	"github.com/filebrowser/filebrowser/v2/users"
)

// UserInfo mirrors the upstream http.userInfo claim shape so the
// upstream withUser parser reads the identity portion unchanged. When
// upstream adds a field here we MUST mirror it to avoid silently
// dropping the new permission in OIDC-issued sessions (tracked as a
// RedTeam deferral; monthly rebase check).
type UserInfo struct {
	ID                    uint              `json:"id"`
	Locale                string            `json:"locale"`
	ViewMode              users.ViewMode    `json:"viewMode"`
	SingleClick           bool              `json:"singleClick"`
	RedirectAfterCopyMove bool              `json:"redirectAfterCopyMove"`
	Perm                  users.Permissions `json:"perm"`
	Commands              []string          `json:"commands"`
	LockPassword          bool              `json:"lockPassword"`
	HideDotfiles          bool              `json:"hideDotfiles"`
	DateFormat            bool              `json:"dateFormat"`
	Username              string            `json:"username"`
	AceEditorTheme        string            `json:"aceEditorTheme"`
}

// Claims is the CMMC-extended session JWT payload. "user" matches the
// upstream authToken.User field name byte-for-byte so upstream parsing
// works; the cmmc fields are additive and invisible to upstream.
type Claims struct {
	User  UserInfo `json:"user"`
	JTI   string   `json:"cmmc_jti,omitempty"`
	MFAAt int64    `json:"cmmc_mfa_at,omitempty"` // unix seconds
	jwt.RegisteredClaims
}

// ToUser returns a minimal users.User built from the session UserInfo.
// Used by the RequiresFreshMFA middleware when the handler wants the
// authenticated user without re-reading the store.
func (c Claims) ToUser() *users.User {
	return &users.User{
		ID:                    c.User.ID,
		Username:              c.User.Username,
		Locale:                c.User.Locale,
		ViewMode:              c.User.ViewMode,
		SingleClick:           c.User.SingleClick,
		RedirectAfterCopyMove: c.User.RedirectAfterCopyMove,
		Perm:                  c.User.Perm,
		Commands:              c.User.Commands,
		LockPassword:          c.User.LockPassword,
		HideDotfiles:          c.User.HideDotfiles,
		DateFormat:            c.User.DateFormat,
		AceEditorTheme:        c.User.AceEditorTheme,
	}
}

// UserInfoFromUser converts a *users.User into the claim-ready UserInfo
// shape. Used at mint time.
func UserInfoFromUser(u *users.User) UserInfo {
	return UserInfo{
		ID:                    u.ID,
		Locale:                u.Locale,
		ViewMode:              u.ViewMode,
		SingleClick:           u.SingleClick,
		RedirectAfterCopyMove: u.RedirectAfterCopyMove,
		Perm:                  u.Perm,
		Commands:              u.Commands,
		LockPassword:          u.LockPassword,
		HideDotfiles:          u.HideDotfiles,
		DateFormat:            u.DateFormat,
		Username:              u.Username,
		AceEditorTheme:        u.AceEditorTheme,
	}
}
