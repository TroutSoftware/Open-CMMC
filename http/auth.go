package fbhttp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	DefaultTokenExpirationTime = time.Hour * 2
)

type userInfo struct {
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

type authToken struct {
	User userInfo `json:"user"`
	// CMMC extensions carried in the same struct so the single
	// upstream parser call in withUser reads them without a second
	// ParseWithClaims. printToken writes them back on /api/renew so
	// privileged handlers (withFreshMFA) still see evidence of the
	// original authentication.
	CmmcMFAAt int64 `json:"cmmc_mfa_at,omitempty"`
	jwt.RegisteredClaims
}

type extractor []string

func (e extractor) ExtractToken(r *http.Request) (string, error) {
	token, _ := request.HeaderExtractor{"X-Auth"}.ExtractToken(r)

	// Checks if the token isn't empty and if it contains two dots.
	// The former prevents incompatibility with URLs that previously
	// used basic auth.
	if token != "" && strings.Count(token, ".") == 2 {
		return token, nil
	}

	// Cookie is accepted on every method, not just GET. The CMMC
	// fork flips the session cookie to HttpOnly (see http/oidc.go
	// callback), so an SPA cannot supply X-Auth on a cold reload
	// and must rely on the cookie for POST /api/renew to bootstrap
	// its in-memory token. SameSite=Lax on the cookie still guards
	// against cross-site POST CSRF; same-origin POSTs (the SPA's
	// normal calls) continue to work.
	cookie, _ := r.Cookie("auth")
	if cookie != nil && strings.Count(cookie.Value, ".") == 2 {
		return cookie.Value, nil
	}

	return "", request.ErrNoTokenInRequest
}

func renewableErr(err error, d *data) bool {
	if d.settings.AuthMethod != fbAuth.MethodProxyAuth || err == nil {
		return false
	}

	if d.settings.LogoutPage == settings.DefaultLogoutPage {
		return false
	}

	if !errors.Is(err, jwt.ErrTokenExpired) {
		return false
	}

	return true
}

func withUser(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		keyFunc := func(_ *jwt.Token) (interface{}, error) {
			return sessionSigningKey(d.settings), nil
		}

		var tk authToken
		p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
		token, err := request.ParseFromRequest(r, &extractor{}, keyFunc, request.WithClaims(&tk), request.WithParser(p))
		if (err != nil || !token.Valid) && !renewableErr(err, d) {
			return http.StatusUnauthorized, nil
		}

		// CMMC 3.13.11 — defense-in-depth CSRF gate. When a state-
		// changing request authenticates via the cookie only (no
		// X-Auth), require its Origin/Referer to name this host.
		// The SPA's own fetch always sets Origin. SameSite=Lax is
		// the primary defense; this backstops proxies/extensions
		// that strip SameSite or browsers that don't honor it.
		if isCookieAuthedStateChange(r) && !csrfOriginCheck(r) {
			return http.StatusForbidden, nil
		}

		expiresSoon := tk.ExpiresAt != nil && time.Until(tk.ExpiresAt.Time) < time.Hour
		updated := tk.IssuedAt != nil && tk.IssuedAt.Unix() < d.store.Users.LastUpdate(tk.User.ID)

		if expiresSoon || updated {
			w.Header().Add("X-Renew-Token", "true")
		}

		// CMMC 3.10.2 / 3.1.11 — enforce idle timeout. Tracker is
		// nil when operator leaves FB_CMMC_SESSION_IDLE_TIMEOUT
		// unset; IsIdle returns false in that case so dev
		// deployments behave unchanged. Boot-time gate ensures the
		// tracker is only configured on OIDC deployments — no empty-
		// jti lockout risk here in the shipped config.
		if sessionIdleTracker != nil {
			if sessionIdleTracker.IsIdle(tk.ID) {
				emitSessionIdleLock(r, tk.User.Username, tk.ID)
				return http.StatusUnauthorized, nil
			}
			sessionIdleTracker.Bump(tk.ID)
		}
		// Stash jti + cmmc_mfa_at on context so downstream handlers
		// (logout Revoke, renew mint) don't re-parse the JWT.
		ctx := withJTI(r.Context(), tk.ID)
		ctx = withMFAAt(ctx, tk.CmmcMFAAt)
		r = r.WithContext(ctx)

		d.user, err = d.store.Users.Get(d.server.Root, tk.User.ID)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		return fn(w, r, d)
	}
}

func withAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

func loginHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		auther, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeFailure, "", "", http.StatusInternalServerError, "auther lookup: "+err.Error())
			return http.StatusInternalServerError, err
		}

		user, err := auther.Auth(r, d.store.Users, d.settings, d.server)
		switch {
		case errors.Is(err, os.ErrPermission):
			// Attempted username not logged — native auther parses
			// the body and we don't re-parse; IP + status are the
			// durable signal for brute-force forensics.
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeReject, "", "", http.StatusForbidden, "credential mismatch")
			return http.StatusForbidden, nil
		case err != nil:
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeFailure, "", "", http.StatusInternalServerError, err.Error())
			return http.StatusInternalServerError, err
		}

		emitAuthEvent(r, audit.ActionAuthLoginOK, audit.OutcomeSuccess, userIDString(user.ID), user.Username, http.StatusOK, "")
		return printToken(w, r, d, user, tokenExpireTime)
	}
}

type signupBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var signupHandler = func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.settings.Signup {
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeReject, "", "", http.StatusMethodNotAllowed, "signup disabled")
		return http.StatusMethodNotAllowed, nil
	}

	if r.Body == nil {
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeReject, "", "", http.StatusBadRequest, "empty body")
		return http.StatusBadRequest, nil
	}

	// CWE-400: cap the body so a multi-GB JSON bomb can't pin the
	// process on signup (unauthenticated endpoint).
	r.Body = http.MaxBytesReader(nil, r.Body, 8*1024)
	info := &signupBody{}
	err := json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeReject, "", "", http.StatusBadRequest, "invalid body: "+err.Error())
		return http.StatusBadRequest, err
	}

	if info.Password == "" || info.Username == "" {
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeReject, "", info.Username, http.StatusBadRequest, "missing username or password")
		return http.StatusBadRequest, nil
	}

	user := &users.User{
		Username: info.Username,
	}

	d.settings.Defaults.Apply(user)

	// Users signed up via the signup handler should never become admins, even
	// if that is the default permission.
	user.Perm.Admin = false

	// Self-registered users should not inherit execution capabilities from
	// default settings, regardless of what the administrator has configured
	// as the default. Execution rights must be explicitly granted by an admin.
	user.Perm.Execute = false
	user.Commands = []string{}

	pwd, err := users.ValidateAndHashPwd(info.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	user.Password = pwd
	if d.settings.CreateUserDir {
		user.Scope = ""
	}

	userHome, err := d.settings.MakeUserDir(user.Username, user.Scope, d.server.Root)
	if err != nil {
		log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeFailure, "", user.Username, http.StatusInternalServerError, "mkdir user home: "+err.Error())
		return http.StatusInternalServerError, err
	}
	user.Scope = userHome
	log.Printf("new user: %s, home dir: [%s].", logSafe(user.Username), userHome)

	err = d.store.Users.Save(user)
	if errors.Is(err, fberrors.ErrExist) {
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeReject, "", user.Username, http.StatusConflict, "username exists")
		return http.StatusConflict, err
	} else if err != nil {
		emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeFailure, "", user.Username, http.StatusInternalServerError, "save user: "+err.Error())
		return http.StatusInternalServerError, err
	}

	emitAuthEvent(r, audit.ActionAuthSignup, audit.OutcomeSuccess, userIDString(user.ID), user.Username, http.StatusOK, "")
	return http.StatusOK, nil
}

func renewHandler(tokenExpireTime time.Duration) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		w.Header().Set("X-Renew-Token", "false")
		return printToken(w, r, d, d.user, tokenExpireTime)
	})
}

// logoutHandler expires the HttpOnly `auth` cookie server-side and
// revokes the session's jti in the idle tracker. The SPA cannot
// clear HttpOnly cookies from JS, so without this the cookie
// would ride along with subsequent requests and silently re-
// authenticate a "logged out" user until the cookie TTL. CMMC
// 3.1.11.
//
// Wrapped in withUser so (a) an unauthenticated caller cannot
// force-logout another user via a forged POST, (b) the CSRF
// Origin gate in withUser fires for cookie-auth POSTs, (c) the
// jti is available on the request context for Revoke.
var logoutHandler = withUser(func(w http.ResponseWriter, r *http.Request, _ *data) (int, error) {
	if sessionIdleTracker != nil {
		sessionIdleTracker.Revoke(jtiFromContext(r.Context()))
	}
	// Clear both the session cookie and any id_token cookie a
	// prior OIDC session may have left behind. HttpOnly=true on
	// both for symmetry with the set path.
	secure := cookieSecure(r)
	for _, name := range []string{"auth", idTokenCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	return http.StatusNoContent, nil
})

// cookieSecure centralizes the "is this request over HTTPS?" check
// for every place we set or clear the session cookie. Three
// readers of the same predicate drift over time — keep one.
func cookieSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// setSessionCookie writes the HttpOnly session cookie. Shared by the
// native-login printToken path and the OIDC callback so the
// security attributes (HttpOnly + Secure + SameSite) are stamped
// identically and a future tweak lands in one place.
func setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func printToken(w http.ResponseWriter, r *http.Request, d *data, user *users.User, tokenExpirationTime time.Duration) (int, error) {
	// Carry forward the existing session's jti across a renew so the
	// idle tracker's record (keyed on jti) stays continuous. Without
	// this, /api/renew mints a JWT with empty jti; the very next
	// request's withUser-extractor reads tk.ID="" which IsIdle
	// treats as unknown (fail-closed) and 401s. Every SPA mount
	// did OIDC callback → renew → 401 → logout → re-login forever.
	//
	// On native login (first /api/login hit), no prior jti exists —
	// generate a fresh one so the tracker has something to Bump.
	jti := jtiFromContext(r.Context())
	if jti == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return http.StatusInternalServerError, err
		}
		jti = base64.RawURLEncoding.EncodeToString(b)
	}
	claims := &authToken{
		User: userInfo{
			ID:                    user.ID,
			Locale:                user.Locale,
			ViewMode:              user.ViewMode,
			SingleClick:           user.SingleClick,
			RedirectAfterCopyMove: user.RedirectAfterCopyMove,
			Perm:                  user.Perm,
			LockPassword:          user.LockPassword,
			Commands:              user.Commands,
			HideDotfiles:          user.HideDotfiles,
			DateFormat:            user.DateFormat,
			Username:              user.Username,
			AceEditorTheme:        user.AceEditorTheme,
		},
		// Carry forward MFA evidence across a renew so privileged
		// handlers (withFreshMFA, e.g. PUT /api/cmmc/marking) still
		// see the original MFA timestamp. Without this, the first
		// renew erased cmmc_mfa_at and every subsequent classify /
		// user-create / settings-edit hit returned 401.
		CmmcMFAAt: mfaAtFromContext(r.Context()),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpirationTime)),
			Issuer:    "File Browser",
			ID:        jti,
		},
	}
	// Keep the tracker record alive across the renew.
	if sessionIdleTracker != nil {
		sessionIdleTracker.Bump(jti)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sessionSigningKey(d.settings))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// CMMC 3.13.11 — symmetric with OIDC callback: mint the
	// HttpOnly cookie server-side so raw-subresource URLs (img,
	// a href=/api/raw/…) continue to authenticate after we stop
	// the SPA from writing document.cookie.
	setSessionCookie(w, r, "auth", signed, time.Now().Add(tokenExpirationTime))

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(signed)); err != nil {
		return http.StatusInternalServerError, err
	}
	return 0, nil
}
