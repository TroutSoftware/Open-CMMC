package fbhttp

import (
	"io/fs"
	"net/http"

	"github.com/gorilla/mux"

	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
)

type modifyRequest struct {
	What            string   `json:"what"`             // Answer to: what data type?
	Which           []string `json:"which"`            // Answer to: which fields?
	CurrentPassword string   `json:"current_password"` // Answer to: user logged password
}

func NewHandler(
	imgSvc ImgService,
	fileCache FileCache,
	uploadCache UploadCache,
	store *storage.Storage,
	server *settings.Server,
	assetsFs fs.FS,
) (http.Handler, error) {
	server.Clean()

	r := mux.NewRouter()
	// CMMC 3.3.5: stamp every request with a correlation id so all
	// events the request emits (auth, authz, handler) can be stitched
	// in the SIEM. Runs before the security-headers middleware so the
	// correlation header also lands in the response.
	r.Use(audit.CorrelationMiddleware)
	// CMMC security headers (3.13.8 / 3.13.13 / 3.13.15 / 3.14.x):
	//   Content-Security-Policy — control mobile code (3.13.13)
	//   Strict-Transport-Security — force TLS on subsequent requests (3.13.8)
	//   X-Content-Type-Options — block MIME sniffing
	//   X-Frame-Options — clickjacking defense
	//   Referrer-Policy — avoid leaking CUI-adjacent URLs to external sites
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", `default-src 'self'; style-src 'unsafe-inline';`)
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			next.ServeHTTP(w, r)
		})
	})
	index, static := getStaticHandlers(store, server, assetsFs)

	monkey := func(fn handleFunc, prefix string) http.Handler {
		return handle(fn, prefix, store, server)
	}

	r.HandleFunc("/health", healthHandler)
	r.PathPrefix("/static").Handler(static)
	r.NotFoundHandler = index

	api := r.PathPrefix("/api").Subrouter()

	tokenExpirationTime := server.GetTokenExpirationTime(DefaultTokenExpirationTime)
	// CMMC 3.1.8 — bucket-limit login attempts per source IP.
	// Auth routes: login / signup emit their own audit events inline
	// (so the attempted username can be stamped on failure paths);
	// wrapping them with withAuditEmit at the route would emit a
	// duplicate with an empty Username since d.user is unset until
	// after auth succeeds. Renew runs inside withUser so d.user is
	// populated — a plain withAuditEmit wrapper gets full fields.
	api.Handle("/login", monkey(withRateLimit(loginRateLimiter, audit.ActionRateLimitAuth, loginHandler(tokenExpirationTime)), ""))
	api.Handle("/signup", monkey(signupHandler, ""))
	api.Handle("/renew", monkey(withAuditEmit(audit.ActionSessionRenew, renewHandler(tokenExpirationTime)), ""))
	// CMMC 3.1.11 — native-auth logout. Expires the HttpOnly `auth`
	// cookie server-side (the SPA cannot clear an HttpOnly cookie
	// from JS). OIDC flows use /api/auth/oidc/logout instead.
	api.Handle("/logout", monkey(withAuditEmit(audit.ActionAuthLogout, logoutHandler), "")).Methods("POST")

	// CMMC: OIDC redirect endpoints. The Auther contract is single-shot and
	// does not fit a redirect-based flow, so these live outside /api/login.
	authSub := api.PathPrefix("/auth").Subrouter()
	authSub.Handle("/oidc/login", monkey(oidcLoginHandler, "")).Methods("GET")
	authSub.Handle("/oidc/callback", monkey(oidcCallbackHandler(tokenExpirationTime), "")).Methods("GET")
	// CMMC 3.1.11: front-channel logout terminates the IdP SSO session
	// and the filebrowser cookies in one shot.
	authSub.Handle("/oidc/logout", monkey(withAuditEmit(audit.ActionAuthLogout, oidcLogoutHandler), "")).Methods("POST")

	// CMMC 3.3.x admin visibility: recent audit events. Admin-only
	// (wrapped via withAdmin at handler definition). Feeds a tiny
	// in-memory ring buffer populated by the audit MultiEmitter; does
	// not replace the durable SIEM ingest path.
	cmmc := api.PathPrefix("/cmmc").Subrouter()
	cmmc.Handle("/audit/recent", monkey(auditRecentHandler, "")).Methods("GET")
	// CMMC 3.3.8 — read-time audit chain verification. Operators
	// (and SIEM) confirm the HMAC chain is intact before trusting
	// audit data for an investigation.
	cmmc.Handle("/audit/verify", monkey(auditVerifyHandler, "")).Methods("GET")
	// CMMC 3.8.4 — CUI marking admin API. GET reads the current mark
	// for a path (any authenticated user); PUT sets/clears it (admin
	// + fresh MFA). /catalog returns the recognized mark set for the
	// SPA's dropdown. Audit every call.
	// CMMC 3.3.1 / 3.1.7 — every user can see their own profile +
	// their own audit tail. Admin panels for other users' activity
	// live under /api/cmmc/audit/recent.
	cmmc.Handle("/me", monkey(meHandler, "")).Methods("GET")
	cmmc.Handle("/marking", monkey(withAuditEmit(audit.ActionCUIMarkGet, markingGetHandler), "")).Methods("GET")
	cmmc.Handle("/marking", monkey(withFreshMFA(withAuditEmit(audit.ActionCUIMarkSet, markingPutHandler)), "")).Methods("PUT")
	cmmc.Handle("/marking/catalog", monkey(withAuditEmit(audit.ActionCUICatalogRead, markingCatalogHandler), "")).Methods("GET")
	// CMMC 3.1.5 / 3.1.7 — group→role authorization. GET lists the
	// current mapping (any user can see the table — transparency
	// beats secret authority). PUT/DELETE are admin + fresh MFA.
	cmmc.Handle("/groups", monkey(withAuditEmit(audit.ActionAuthzGroupRead, groupsListHandler), "")).Methods("GET")
	cmmc.Handle("/groups", monkey(withFreshMFA(withAuditEmit(audit.ActionAuthzGroupSet, groupsPutHandler)), "")).Methods("PUT")
	cmmc.PathPrefix("/groups/").Handler(monkey(withFreshMFA(withAuditEmit(audit.ActionAuthzGroupDelete, groupsDeleteHandler)), "/api/cmmc/groups/")).Methods("DELETE")
	// CMMC 3.1.1 / 3.1.5 / 3.1.7 — per-folder ACL. GET is open to
	// any authed user (the reveals are already visible in the
	// folder listing); PUT/DELETE require admin + fresh MFA.
	cmmc.Handle("/acl", monkey(withAuditEmit(audit.ActionCUIACLRead, aclReadHandler), "")).Methods("GET")
	cmmc.Handle("/acl", monkey(withFreshMFA(withAuditEmit(audit.ActionCUIACLSet, aclPutHandler)), "")).Methods("PUT")
	cmmc.Handle("/acl", monkey(withFreshMFA(withAuditEmit(audit.ActionCUIACLDelete, aclDeleteHandler)), "")).Methods("DELETE")
	cmmc.Handle("/acls", monkey(withAuditEmit(audit.ActionCUIACLRead, aclListHandler), "")).Methods("GET")

	// CMMC 3.1.15 / 3.5.3: privileged-action handlers require a fresh MFA
	// assertion in the OIDC session (no-op on other AuthMethods). Read
	// paths (GET) stay free; writes require a recent MFA step.
	users := api.PathPrefix("/users").Subrouter()
	users.Handle("", monkey(withAuditEmit(audit.ActionUserList, usersGetHandler), "")).Methods("GET")
	users.Handle("", monkey(withFreshMFA(withAuditEmit(audit.ActionUserCreate, userPostHandler)), "")).Methods("POST")
	// PUT /api/users/:id — fresh-MFA gate intentionally moved INSIDE
	// userPutHandler so preference fields (viewMode / locale /
	// singleClick / hideDotfiles / dateFormat / aceEditorTheme)
	// don't force a re-auth. The handler checks req.Which and applies
	// the MFA gate only when a sensitive field is present (perm /
	// password / scope / username / lockPassword / commands / rules,
	// or an "all" bulk replace). See users.go.
	users.Handle("/{id:[0-9]+}", monkey(withAuditEmit(audit.ActionUserUpdate, userPutHandler), "")).Methods("PUT")
	users.Handle("/{id:[0-9]+}", monkey(withAuditEmit(audit.ActionUserRead, userGetHandler), "")).Methods("GET")
	users.Handle("/{id:[0-9]+}", monkey(withFreshMFA(withAuditEmit(audit.ActionUserDelete, userDeleteHandler)), "")).Methods("DELETE")

	// CMMC 3.3.1 / 3.1.3: full file-CRUD audit. GET on /api/resources
	// (metadata + directory listings) emits file.read — this can be
	// noisy on an active browse session; the event stream rotates into
	// the ring buffer fast but the durable stdout→rsyslog→SIEM stream
	// keeps everything. If a deployment is truly noisy the ring
	// capacity can be raised (1000 today).
	api.PathPrefix("/resources").Handler(monkey(withAuditEmit(audit.ActionFileRead, resourceGetHandler), "/api/resources")).Methods("GET")
	api.PathPrefix("/resources").Handler(monkey(withAuditEmit(audit.ActionFileDelete, resourceDeleteHandler(fileCache)), "/api/resources")).Methods("DELETE")
	api.PathPrefix("/resources").Handler(monkey(withAuditEmit(audit.ActionFileUpload, resourcePostHandler(fileCache)), "/api/resources")).Methods("POST")
	api.PathPrefix("/resources").Handler(monkey(withAuditEmit(audit.ActionFileRename, resourcePutHandler), "/api/resources")).Methods("PUT")
	api.PathPrefix("/resources").Handler(monkey(withAuditEmit(audit.ActionFileModify, resourcePatchHandler(fileCache)), "/api/resources")).Methods("PATCH")

	api.PathPrefix("/tus").Handler(monkey(tusPostHandler(uploadCache), "/api/tus")).Methods("POST")
	api.PathPrefix("/tus").Handler(monkey(tusHeadHandler(uploadCache), "/api/tus")).Methods("HEAD", "GET")
	api.PathPrefix("/tus").Handler(monkey(tusPatchHandler(uploadCache), "/api/tus")).Methods("PATCH")
	api.PathPrefix("/tus").Handler(monkey(tusDeleteHandler(uploadCache), "/api/tus")).Methods("DELETE")

	api.PathPrefix("/usage").Handler(monkey(withAuditEmit(audit.ActionAdminUsageRead, diskUsage), "/api/usage")).Methods("GET")

	api.Handle("/shares", monkey(withAuditEmit(audit.ActionShareList, shareListHandler), "")).Methods("GET")
	api.PathPrefix("/share").Handler(monkey(withAuditEmit(audit.ActionShareRead, shareGetsHandler), "/api/share")).Methods("GET")
	// CMMC 3.1.15 / 3.3.1: share create/delete require fresh MFA + audit.
	api.PathPrefix("/share").Handler(monkey(withFreshMFA(withAuditEmit(audit.ActionShareCreate, sharePostHandler)), "/api/share")).Methods("POST")
	api.PathPrefix("/share").Handler(monkey(withFreshMFA(withAuditEmit(audit.ActionShareDelete, shareDeleteHandler)), "/api/share")).Methods("DELETE")

	api.Handle("/settings", monkey(withAuditEmit(audit.ActionSettingsRead, settingsGetHandler), "")).Methods("GET")
	// CMMC 3.4.3: settings changes require fresh MFA + audit.
	api.Handle("/settings", monkey(withFreshMFA(withAuditEmit(audit.ActionSettingsUpdate, settingsPutHandler)), "")).Methods("PUT")

	// CMMC 3.3.1: /api/raw serves the actual bytes of a file or archive
	// (individual download or zip/tar of a tree). Every hit represents
	// CUI leaving the enclave — audit unconditionally.
	api.PathPrefix("/raw").Handler(monkey(withAuditEmit(audit.ActionFileDownload, rawHandler), "/api/raw")).Methods("GET")
	api.PathPrefix("/preview/{size}/{path:.*}").
		Handler(monkey(withAuditEmit(audit.ActionFilePreview, previewHandler(imgSvc, fileCache, server.EnableThumbnails, server.ResizePreview)), "/api/preview")).Methods("GET")
	api.PathPrefix("/command").Handler(monkey(withAuditEmit(audit.ActionAdminCommandsRead, commandsHandler), "/api/command")).Methods("GET")
	api.PathPrefix("/search").Handler(monkey(withAuditEmit(audit.ActionFileSearch, searchHandler), "/api/search")).Methods("GET")
	api.PathPrefix("/subtitle").Handler(monkey(withAuditEmit(audit.ActionFileSubtitle, subtitleHandler), "/api/subtitle")).Methods("GET")

	public := api.PathPrefix("/public").Subrouter()
	// CMMC 3.1.22 / 3.3.1: public (unauthenticated) share access MUST be
	// audited — these paths bypass OIDC and represent CUI potentially
	// leaving the enclave without an identity. Identity fields will be
	// empty in the emitted event (withUser never ran); the IP + UA are
	// the only caller-trace we have.
	// CMMC 3.13.4 — rate-limit public-share access to slow
	// share-token brute force.
	public.PathPrefix("/dl").Handler(monkey(withRateLimit(publicRateLimiter, audit.ActionRateLimitShare, withAuditEmit(audit.ActionFilePublicDL, publicDlHandler)), "/api/public/dl/")).Methods("GET")
	public.PathPrefix("/share").Handler(monkey(withRateLimit(publicRateLimiter, audit.ActionRateLimitShare, withAuditEmit(audit.ActionFilePublicRead, publicShareHandler)), "/api/public/share/")).Methods("GET")

	return stripPrefix(server.BaseURL, r), nil
}
