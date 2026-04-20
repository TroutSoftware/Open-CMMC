package storage

import (
	"github.com/filebrowser/filebrowser/v2/auth"
	cmmcoidc "github.com/filebrowser/filebrowser/v2/cmmc/auth/oidc"
	cmmcauthz "github.com/filebrowser/filebrowser/v2/cmmc/authz"
	cmmcfolderacl "github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	envpkg "github.com/filebrowser/filebrowser/v2/cmmc/crypto/envelope"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/share"
	"github.com/filebrowser/filebrowser/v2/users"
)

// Storage is a storage powered by a Backend which makes the necessary
// verifications when fetching and saving data to ensure consistency.
type Storage struct {
	Users          users.Store
	Share          *share.Storage
	Auth           *auth.Storage
	Settings       *settings.Storage
	OIDCIdentities cmmcoidc.IdentityStore
	FileMetadata   cmmcmark.Store
	GroupPerms     cmmcauthz.Store
	FolderACLs     cmmcfolderacl.Store
	Envelopes      envpkg.Store
}
