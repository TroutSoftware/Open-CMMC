package cmd

import (
	"testing"

	"github.com/spf13/pflag"

	"github.com/filebrowser/filebrowser/v2/auth"
)

// Compliance regression: `./filebrowser config set --auth.method=oidc`
// must succeed. Before this test existed the CLI's auth-method switch
// did not know about OIDC and returned "invalid auth method", which
// blocked any operator from configuring the OIDC backend.

func TestCLI_getAuthentication_AcceptsOIDCMethod(t *testing.T) {
	flags := &pflag.FlagSet{}
	flags.String("auth.method", "oidc", "")

	method, auther, err := getAuthentication(flags, true) // `true` → hasAuth=true short-circuits reading defaults
	if err != nil {
		t.Fatalf("CLI rejected --auth.method=oidc: %v", err)
	}
	if method != auth.MethodOIDCAuth {
		t.Errorf("method = %q, want %q", method, auth.MethodOIDCAuth)
	}
	if _, ok := auther.(*auth.OIDCAuth); !ok {
		t.Errorf("auther type = %T, want *auth.OIDCAuth", auther)
	}
}

func TestCLI_getAuthentication_StillAcceptsJSONMethod(t *testing.T) {
	// Non-regression: the OIDC addition must not break the default JSON path.
	flags := &pflag.FlagSet{}
	flags.String("auth.method", "json", "")
	flags.Bool("recaptcha", false, "")
	flags.String("recaptcha.host", "", "")
	flags.String("recaptcha.key", "", "")
	flags.String("recaptcha.secret", "", "")

	method, _, err := getAuthentication(flags, true)
	if err != nil {
		t.Fatalf("JSON method rejected: %v", err)
	}
	if method != auth.MethodJSONAuth {
		t.Errorf("method = %q, want %q", method, auth.MethodJSONAuth)
	}
}

func TestCLI_getAuthentication_RejectsUnknownMethod(t *testing.T) {
	flags := &pflag.FlagSet{}
	flags.String("auth.method", "nonsense", "")

	_, _, err := getAuthentication(flags, true)
	if err == nil {
		t.Fatalf("unknown auth method should be rejected")
	}
}
