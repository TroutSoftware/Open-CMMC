package fbhttp

import (
	"log"
	"net/http"
	"strconv"

	"github.com/tomasen/realip"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	"github.com/filebrowser/filebrowser/v2/rules"
	"github.com/filebrowser/filebrowser/v2/runner"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

type handleFunc func(w http.ResponseWriter, r *http.Request, d *data) (int, error)

type data struct {
	*runner.Runner
	settings *settings.Settings
	server   *settings.Server
	store    *storage.Storage
	user     *users.User
	raw      interface{}
}

// Check implements rules.Checker.
//
// Order of evaluation (first matching rule wins at each tier):
//  1. HideDotfiles on dotfile paths
//  2. Global rules (settings.Rules — starter cabinet defaults)
//  3. Per-user rules (users.Rules — OIDC-provisioned group denies)
//  4. Per-folder ACL (cmmc/authz/folderacl) — admin-authored grants
//     and denies that override the starter defaults
//
// The ACL tier runs LAST so an admin's explicit grant/deny at step
// 4 overrides whatever the starter defaults at steps 2–3 would
// have said. NoMatch at step 4 leaves the decision from steps 2–3
// untouched — the starter behavior is the fallback, not overridden.
func (d *data) Check(path string) bool {
	if d.user.HideDotfiles && rules.MatchHidden(path) {
		return false
	}

	allow := true
	for _, rule := range d.settings.Rules {
		if rule.Matches(path) {
			allow = rule.Allow
		}
	}
	for _, rule := range d.user.Rules {
		if rule.Matches(path) {
			allow = rule.Allow
		}
	}

	// Tier 4: folder ACL. rules.Checker doesn't know the action;
	// Check() is a READ gate (listings, preview, raw download,
	// marking reads). Write-path handlers call CheckAction with
	// ActionWrite; share-creation handlers with ActionShare.
	if !d.evalFolderACL(path, folderacl.ActionRead, allow) {
		return false
	}

	return allow
}

// CheckAction is the action-aware companion to Check. Handlers on
// the write path (resource POST/PUT/DELETE/PATCH, TUS uploads)
// call this with ActionWrite so an ACL that granted Read but not
// Write correctly denies the write. Handlers that create share
// links call it with ActionShare. The function runs the same
// four-tier evaluation as Check and returns the tier-4-aware
// decision.
func (d *data) CheckAction(path string, action folderacl.Action) bool {
	if !d.Check(path) {
		return false
	}
	return d.evalFolderACL(path, action, true)
}

// evalFolderACL runs the ACL evaluator and emits cui.acl.reject
// when the ACL denies. Returns the effective allow after ACL
// evaluation. `priorAllow` is whatever the tiers 1-3 decided;
// when there's no ACL match, priorAllow stands. Centralized so
// Check and CheckAction don't drift.
func (d *data) evalFolderACL(path string, action folderacl.Action, priorAllow bool) bool {
	if d.store == nil || d.store.FolderACLs == nil || d.user == nil {
		return priorAllow
	}
	dec, err := folderacl.Evaluate(
		d.store.FolderACLs,
		folderaclPrincipalFromUser(d.user),
		path,
		action,
	)
	if err != nil || dec.NoMatch {
		return priorAllow
	}
	if !dec.Allowed && priorAllow {
		// Tier 4 flipped a would-be allow into a deny. Emit a
		// chain-stamped audit row so SIEM can alert on ACL-denied
		// access attempts (3.3.1 traceability for the ACL
		// surface; matching rule id 200030 family in Wazuh).
		emitACLReject(d, path, string(action), dec.MatchedPath)
	}
	return dec.Allowed
}

// folderaclPrincipalFromUser builds the evaluator's Principal
// shape from a users.User. Admin bypass uses Perm.Admin (set by
// the OIDC provisioning path when a user's Keycloak groups
// include filebrowser-admins). Groups come from users.Groups
// which provisioning fills from the session's groups claim.
func folderaclPrincipalFromUser(u *users.User) folderacl.Principal {
	if u == nil {
		return folderacl.Principal{}
	}
	return folderacl.Principal{
		Username: u.Username,
		Groups:   u.Groups,
		IsAdmin:  u.Perm.Admin,
	}
}

func handle(fn handleFunc, prefix string, store *storage.Storage, server *settings.Server) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range globalHeaders {
			w.Header().Set(k, v)
		}

		settings, err := store.Settings.Get()
		if err != nil {
			log.Fatalf("ERROR: couldn't get settings: %v\n", err)
			return
		}

		status, err := fn(w, r, &data{
			Runner:   &runner.Runner{Enabled: server.EnableExec, Settings: settings},
			store:    store,
			settings: settings,
			server:   server,
		})

		if status >= 400 || err != nil {
			clientIP := realip.FromRequest(r)
			log.Printf("%s: %v %s %v", r.URL.Path, status, clientIP, err)
		}

		if status != 0 {
			txt := http.StatusText(status)
			if status == http.StatusBadRequest && err != nil {
				txt += " (" + err.Error() + ")"
			}
			http.Error(w, strconv.Itoa(status)+" "+txt, status)
			return
		}
	})

	return stripPrefix(prefix, handler)
}
