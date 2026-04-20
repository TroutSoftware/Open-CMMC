package fbhttp

import (
	"net/http"

	"github.com/filebrowser/filebrowser/v2/rules"
	"github.com/filebrowser/filebrowser/v2/settings"
)

type settingsData struct {
	Signup                bool                  `json:"signup"`
	HideLoginButton       bool                  `json:"hideLoginButton"`
	CreateUserDir         bool                  `json:"createUserDir"`
	MinimumPasswordLength uint                  `json:"minimumPasswordLength"`
	UserHomeBasePath      string                `json:"userHomeBasePath"`
	Defaults              settings.UserDefaults `json:"defaults"`
	AuthMethod            settings.AuthMethod   `json:"authMethod"`
	Rules                 []rules.Rule          `json:"rules"`
	Branding              settings.Branding     `json:"branding"`
	Tus                   settings.Tus          `json:"tus"`
	Shell                 []string              `json:"shell"`
	Commands              map[string][]string   `json:"commands"`
}

var settingsGetHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	data := &settingsData{
		Signup:                d.settings.Signup,
		HideLoginButton:       d.settings.HideLoginButton,
		CreateUserDir:         d.settings.CreateUserDir,
		MinimumPasswordLength: d.settings.MinimumPasswordLength,
		UserHomeBasePath:      d.settings.UserHomeBasePath,
		Defaults:              d.settings.Defaults,
		AuthMethod:            d.settings.AuthMethod,
		Rules:                 d.settings.Rules,
		Branding:              d.settings.Branding,
		Tus:                   d.settings.Tus,
		Shell:                 d.settings.Shell,
		Commands:              d.settings.Commands,
	}

	return renderJSON(w, r, data)
})

// settingsPutHandler is DISABLED in the CMMC fork. Settings are
// SSP-level decisions baked into env + bootstrap at deploy time
// (FIPS posture, encryption requirement, MFA threshold, idle
// timeout, rate-limit knobs). Allowing runtime edits would turn
// admin compromise into a silent policy-degradation channel.
//
// The GET handler stays wired so assessors + operators can still
// read the current posture; the PUT endpoint refuses writes with
// 405 Method Not Allowed + an explanatory body.
var settingsPutHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-CMMC-Block", "settings-readonly")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte("settings-readonly: runtime edits are disabled in the CMMC build. Adjust env + bootstrap config and redeploy."))
	return 0, nil
})
