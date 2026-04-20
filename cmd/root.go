package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/filebrowser/filebrowser/v2/auth"
	cmmcaudit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	cmmcoidc "github.com/filebrowser/filebrowser/v2/cmmc/auth/oidc"
	cmmcsession "github.com/filebrowser/filebrowser/v2/cmmc/auth/session"
	cmmcauthz "github.com/filebrowser/filebrowser/v2/cmmc/authz"
	keyderive "github.com/filebrowser/filebrowser/v2/cmmc/crypto/keyderive"
	cmmccabinet "github.com/filebrowser/filebrowser/v2/cmmc/cabinet"
	envelope "github.com/filebrowser/filebrowser/v2/cmmc/crypto/envelope"
	cmmcscan "github.com/filebrowser/filebrowser/v2/cmmc/scan"
	_ "github.com/filebrowser/filebrowser/v2/cmmc/scan/clamav" // registers scan backend
	cmmcfips "github.com/filebrowser/filebrowser/v2/cmmc/crypto/fips"
	cmmctls "github.com/filebrowser/filebrowser/v2/cmmc/crypto/tlsprofile"
	"github.com/filebrowser/filebrowser/v2/diskcache"
	"github.com/filebrowser/filebrowser/v2/frontend"
	fbhttp "github.com/filebrowser/filebrowser/v2/http"
	"github.com/filebrowser/filebrowser/v2/img"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

var (
	flagNamesMigrations = map[string]string{
		"file-mode":                        "fileMode",
		"dir-mode":                         "dirMode",
		"hide-login-button":                "hideLoginButton",
		"create-user-dir":                  "createUserDir",
		"minimum-password-length":          "minimumPasswordLength",
		"socket-perm":                      "socketPerm",
		"disable-thumbnails":               "disableThumbnails",
		"disable-preview-resize":           "disablePreviewResize",
		"disable-exec":                     "disableExec",
		"disable-type-detection-by-header": "disableTypeDetectionByHeader",
		"img-processors":                   "imageProcessors",
		"cache-dir":                        "cacheDir",
		"redis-cache-url":                  "redisCacheUrl",
		"token-expiration-time":            "tokenExpirationTime",
		"baseurl":                          "baseURL",
	}

	warnedFlags = map[string]bool{}
)

// TODO(remove): remove after July 2026.
func migrateFlagNames(_ *pflag.FlagSet, name string) pflag.NormalizedName {
	if newName, ok := flagNamesMigrations[name]; ok {

		if !warnedFlags[name] {
			warnedFlags[name] = true
			log.Printf("DEPRECATION NOTICE: Flag --%s has been deprecated, use --%s instead\n", name, newName)
		}

		name = newName
	}

	return pflag.NormalizedName(name)
}

func init() {
	rootCmd.SilenceUsage = true
	rootCmd.SetGlobalNormalizationFunc(migrateFlagNames)

	cobra.MousetrapHelpText = ""

	rootCmd.SetVersionTemplate("File Browser version {{printf \"%s\" .Version}}\n")

	// Flags available across the whole program
	persistent := rootCmd.PersistentFlags()
	persistent.StringP("config", "c", "", "config file path")
	persistent.StringP("database", "d", "./filebrowser.db", "database path")

	// Runtime flags for the root command
	flags := rootCmd.Flags()
	flags.Bool("noauth", false, "use the noauth auther when using quick setup")
	flags.String("username", "admin", "username for the first user when using quick setup")
	flags.String("password", "", "hashed password for the first user when using quick setup")
	flags.Uint32("socketPerm", 0666, "unix socket file permissions")
	flags.String("cacheDir", "", "file cache directory (disabled if empty)")
	flags.String("redisCacheUrl", "", "redis cache URL (for multi-instance deployments), e.g. redis://user:pass@host:port")
	flags.Int("imageProcessors", 4, "image processors count")
	addServerFlags(flags)
}

// addServerFlags adds server related flags to the given FlagSet. These flags are available
// in both the root command, config set and config init commands.
func addServerFlags(flags *pflag.FlagSet) {
	flags.StringP("address", "a", "127.0.0.1", "address to listen on")
	flags.StringP("log", "l", "stdout", "log output")
	flags.StringP("port", "p", "8080", "port to listen on")
	flags.StringP("cert", "t", "", "tls certificate")
	flags.StringP("key", "k", "", "tls key")
	flags.StringP("root", "r", ".", "root to prepend to relative paths")
	flags.String("socket", "", "socket to listen to (cannot be used with address, port, cert nor key flags)")
	flags.StringP("baseURL", "b", "", "base url")
	flags.String("tokenExpirationTime", "2h", "user session timeout")
	flags.Bool("disableThumbnails", false, "disable image thumbnails")
	flags.Bool("disablePreviewResize", false, "disable resize of image previews")
	flags.Bool("disableExec", true, "disables Command Runner feature")
	flags.Bool("disableTypeDetectionByHeader", false, "disables type detection by reading file headers")
	flags.Bool("disableImageResolutionCalc", false, "disables image resolution calculation by reading image files")
}

var rootCmd = &cobra.Command{
	Use:   "filebrowser",
	Short: "A stylish web-based file browser",
	Long: `File Browser CLI lets you create the database to use with File Browser,
manage your users and all the configurations without accessing the
web interface.

If you've never run File Browser, you'll need to have a database for
it. Don't worry: you don't need to setup a separate database server.
We're using Bolt DB which is a single file database and all managed
by ourselves.

For this command, all flags are available as environmental variables,
except for "--config", which specifies the configuration file to use.
The environment variables are prefixed by "FB_" followed by the flag name in
UPPER_SNAKE_CASE. For example, the flag "--disablePreviewResize" is available
as FB_DISABLE_PREVIEW_RESIZE.

If "--config" is not specified, File Browser will look for a configuration
file named .filebrowser.{json, toml, yaml, yml} in the following directories:

- ./
- $HOME/
- /etc/filebrowser/

**Note:** Only the options listed below can be set via the config file or
environment variables. Other configuration options live exclusively in the
database and so they must be set by the "config set" or "config
import" commands.

The precedence of the configuration values are as follows:

- Flags
- Environment variables
- Configuration file
- Database values
- Defaults

Also, if the database path doesn't exist, File Browser will enter into
the quick setup mode and a new database will be bootstrapped and a new
user created with the credentials from options "username" and "password".`,
	RunE: withViperAndStore(func(_ *cobra.Command, _ []string, v *viper.Viper, st *store) error {
		if !st.databaseExisted {
			err := quickSetup(v, st.Storage)
			if err != nil {
				return err
			}
		}

		// build img service
		imgWorkersCount := v.GetInt("imageProcessors")
		if imgWorkersCount < 1 {
			return errors.New("image resize workers count could not be < 1")
		}
		imageService := img.New(imgWorkersCount)

		var fileCache diskcache.Interface = diskcache.NewNoOp()
		cacheDir := v.GetString("cacheDir")
		if cacheDir != "" {
			if err := os.MkdirAll(cacheDir, 0700); err != nil {
				return fmt.Errorf("can't make directory %s: %w", cacheDir, err)
			}
			fileCache = diskcache.New(afero.NewOsFs(), cacheDir)
		}

		redisCacheURL := v.GetString("redisCacheUrl")
		uploadCache, err := fbhttp.NewUploadCache(redisCacheURL)
		if err != nil {
			return fmt.Errorf("failed to initialize upload cache: %w", err)
		}

		server, err := getServerSettings(v, st.Storage)
		if err != nil {
			return err
		}
		setupLog(server.Log)

		// CMMC Phase 1 group→role seed. First boot after Phase 1
		// ships writes sensible defaults matching the Keycloak group
		// bootstrap; subsequent runs are no-ops once the admin has
		// touched the table.
		if written, err := cmmcauthz.SeedDefaultGroupPerms(st.Storage.GroupPerms); err != nil {
			log.Printf("WARNING: authz seed failed: %v", err)
		} else if written > 0 {
			log.Printf("authz: seeded %d default group→role mappings", written)
		}

		// CMMC cabinet layout — opinionated folder roster with per-
		// folder CUI classifications matching the Keycloak group
		// seed. On first boot, creates the directories on disk and
		// writes folder-level marking rows. Rerun-safe: existing
		// dirs and marks are preserved.
		if dirs, marks, err := cmmccabinet.Seed(server.Root, st.Storage.FileMetadata, cmmccabinet.DefaultLayout); err != nil {
			log.Printf("WARNING: cabinet seed failed: %v", err)
		} else if dirs > 0 || marks > 0 {
			log.Printf("cabinet: seeded %d folder(s) on disk, %d classification(s) in store", dirs, marks)
		}

		// CMMC 3.13.16 / 3.8.9 — envelope encryption. Load the KEK
		// and interpose an EncryptingFS beneath each user's
		// BasePathFs so every read/write goes through AES-256-GCM
		// transparently. In mode=required we REFUSE TO START if
		// the KEK is missing — better a clean crash than quietly
		// writing CUI plaintext to disk.
		encMode := envelope.ParseMode()
		kek, err := envelope.LoadKEKFromEnv(encMode)
		if err != nil {
			return fmt.Errorf("envelope: %w", err)
		}
		// CMMC 3.14.2 — malicious-code protection. Load the AV
		// scanner alongside the KEK so EncryptingFS can run
		// plaintext through it before Seal. Required mode refuses
		// to start without a reachable backend; Optional mode
		// logs and continues.
		scanMode := cmmcscan.ParseMode()
		scanner, err := cmmcscan.LoadScannerFromEnv(scanMode)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		backendName := os.Getenv("FB_CMMC_AV_BACKEND")
		if backendName == "" {
			backendName = "clamav"
		}
		if scanner != nil {
			log.Printf("scan: malware scanner %s (backend=%s)", scanMode, backendName)
		} else if scanMode != cmmcscan.ModeDisabled {
			log.Printf("scan: %s mode, no backend configured — uploads are NOT being scanned (NOT CMMC-compliant)", scanMode)
		}

		if kek != nil {
			users.UserFsBuilder = func(scope string) afero.Fs {
				fs := envelope.NewWithMode(afero.NewOsFs(), kek, st.Storage.Envelopes, encMode)
				if scanner != nil {
					fs = fs.WithScanner(scanner, scanMode)
				}
				return afero.NewBasePathFs(fs, scope)
			}
			log.Printf("envelope: encryption %s (AES-256-GCM per-file, AES-256-GCM KEK-wrap)", encMode)
		} else if encMode == envelope.ModeOptional {
			log.Printf("envelope: optional mode, no KEK configured — files stored in plaintext (NOT CMMC-compliant)")
		} else {
			log.Printf("envelope: disabled — files stored in plaintext (NOT CMMC-compliant; for dev only)")
		}

		root, err := filepath.Abs(server.Root)
		if err != nil {
			return err
		}
		server.Root = root

		adr := server.Address + ":" + server.Port

		var listener net.Listener

		switch {
		case server.Socket != "":
			listener, err = net.Listen("unix", server.Socket)
			if err != nil {
				return err
			}
			socketPerm := v.GetUint32("socketPerm")
			err = os.Chmod(server.Socket, os.FileMode(socketPerm))
			if err != nil {
				return err
			}
		case server.TLSKey != "" && server.TLSCert != "":
			cer, err := tls.LoadX509KeyPair(server.TLSCert, server.TLSKey)
			if err != nil {
				return err
			}
			// CMMC 3.13.8 / 3.13.11: pin cipher suites + curves to the
			// FIPS-approved subset regardless of Go's default list.
			tlsCfg := cmmctls.Server()
			tlsCfg.Certificates = []tls.Certificate{cer}
			listener, err = tls.Listen("tcp", adr, tlsCfg)
			if err != nil {
				return err
			}
		default:
			listener, err = net.Listen("tcp", adr)
			if err != nil {
				return err
			}
		}

		assetsFs, err := fs.Sub(frontend.Assets(), "dist")
		if err != nil {
			panic(err)
		}

		// CMMC: wire the audit pipeline once, regardless of auth method.
		// JSONEmitter → stdout → journald → rsyslog-ossl → customer SIEM
		// is the canonical path (architecture.md §7). RingBufferEmitter
		// keeps the last 1000 events for the admin UI / API to render.
		// HMACChainEmitter wraps the JSON sink so the SIEM can detect
		// tamper via the MAC chain (3.3.8); chain key derived from the
		// same settings.Key already used for session JWT signing (we
		// would use a TPM-sealed dedicated key in a production deploy).
		auditRing := cmmcaudit.NewRingBufferEmitter(1000)
		auditSettings, _ := st.Settings.Get()
		var auditSink cmmcaudit.Emitter = cmmcaudit.NewJSONEmitter(os.Stdout)
		if auditSettings != nil {
			// CMMC 3.13.11 / H2 — derive a dedicated HMAC key for
			// the audit chain so a session-JWT leak cannot forge
			// audit events and vice versa. Old deployments that
			// relied on settings.Key directly are migrated at
			// boot; the chain tip persisted in SIEM will be
			// regenerated across the label boundary (one-time
			// break documented in operator notes).
			if subkey, err := keyderive.AuditChainKey(auditSettings.Key); err == nil {
				auditSink = cmmcaudit.NewHMACChainEmitter(auditSink, subkey)
				log.Printf("Audit HMAC chain enabled (HKDF subkey)")
			} else {
				log.Printf("Audit HMAC chain DISABLED: %v", err)
			}
		} else {
			log.Printf("Audit HMAC chain DISABLED: settings unavailable")
		}
		cmmcaudit.SetDefault(cmmcaudit.Multi(
			auditSink,
			auditRing,
		))
		fbhttp.SetAuditRing(auditRing)

		// CMMC 3.13.11 / H2 — derive the session-JWT signing subkey
		// from the master so an audit-chain leak can't forge JWTs
		// and vice versa. Must run after st.Settings.Get() above.
		// Fail boot on derivation failure rather than silently
		// falling back to the shared master.
		if err := fbhttp.SetDerivedSessionKeyFromSettings(auditSettings); err != nil {
			return err
		}

		// CMMC 3.1.8 / 3.13.4 — rate-limit the two
		// unauthenticated-or-weakly-authenticated surfaces:
		// /api/login (brute force) and /api/public/* (share-token
		// guessing). Defaults: 5 login/min, 20 public/min per IP.
		// Override via FB_CMMC_RATELIMIT_{LOGIN,PUBLIC}_{BURST,REFILL}.
		loginRL, publicRL := fbhttp.LoadRateLimitersFromEnv()
		fbhttp.SetRateLimiters(loginRL, publicRL)
		if loginRL != nil || publicRL != nil {
			log.Printf("rate limiting: login=%v public=%v", loginRL != nil, publicRL != nil)
			// Single sweeper for both, runs every minute.
			go func() {
				t := time.NewTicker(time.Minute)
				defer t.Stop()
				for range t.C {
					loginRL.Sweep(10 * time.Minute)
					publicRL.Sweep(10 * time.Minute)
				}
			}()
		}

		// CMMC 3.10.2 / 3.1.11 — idle session lock. Opt-in via
		// FB_CMMC_SESSION_IDLE_TIMEOUT (e.g., "15m"). Requires the
		// OIDC auth path: native-login tokens don't carry a jti, so
		// enforcement on that path would 401 every request. Empty
		// env leaves the feature off. A goroutine sweeps stale rows
		// so the in-memory map doesn't grow unbounded.
		idleTracker, idleErr := cmmcsession.LoadIdleConfigFromEnv()
		if idleErr != nil {
			return idleErr
		}
		if idleTracker != nil {
			authMethodSettings, _ := st.Settings.Get()
			if authMethodSettings == nil || authMethodSettings.AuthMethod != auth.MethodOIDCAuth {
				return fmt.Errorf("%s is set but AuthMethod is not OIDC — idle lock requires OIDC sessions (jti claim)", cmmcsession.EnvIdleTimeout)
			}
			fbhttp.SetSessionIdleTracker(idleTracker)
			go func(tr *cmmcsession.IdleTracker, every, maxAge time.Duration) {
				t := time.NewTicker(every)
				defer t.Stop()
				for range t.C {
					tr.Sweep(maxAge)
				}
			}(idleTracker, idleTracker.Threshold(), 2*idleTracker.Threshold())
			log.Printf("session idle lock enabled: threshold=%s", idleTracker.Threshold())
		} else {
			log.Printf("session idle lock DISABLED: set %s (e.g. 15m) to enable", cmmcsession.EnvIdleTimeout)
		}

		// CMMC: if the deployment uses OIDC, try to construct the provider
		// singleton at boot. Failure here is non-fatal — the /auth/oidc/login
		// handler checks Initialized() and will drive a lazy retry on demand
		// if the IdP was unreachable at startup. Keeps filebrowser bootable
		// during transient IdP outages (common during GCC-H rollouts).
		if settingsForServer, sErr := st.Settings.Get(); sErr == nil && settingsForServer.AuthMethod == auth.MethodOIDCAuth {
			cfg, cErr := cmmcoidc.LoadFromEnv()
			if cErr != nil {
				return fmt.Errorf("oidc config: %w", cErr)
			}
			// CMMC 3.13.11: runtime FIPS assertion. The built binary's
			// FIPS posture is determined by the Go toolchain + GOFIPS=1;
			// this check makes the attestation live at startup so the
			// SSP evidence trail points at an enforceable control, not
			// a build-time claim.
			log.Printf("FIPS 140 posture: %s", cmmcfips.Mode())
			if cfg.AllowInsecureHTTPIssuer {
				log.Printf("WARNING: FB_OIDC_ALLOW_INSECURE_HTTP_ISSUER=true — http:// issuer/redirect accepted. CMMC L2 production must leave this false (3.13.8/3.13.15).")
			}
			if cfg.RequireFIPS && !cmmcfips.Enabled() {
				return fmt.Errorf("oidc: FB_OIDC_REQUIRE_FIPS=true but Go FIPS 140 mode is %s. Enable it by (a) running with GODEBUG=fips140=on, (b) building with GOFIPS140=v1.0.0 to bake in the module, or (c) using RHEL go-toolset on a host in FIPS mode. Set FB_OIDC_REQUIRE_FIPS=false only for dev environments", cmmcfips.Mode())
			}
			cmmcoidc.SetConfigForLazyInit(cfg)
			initCtx, initCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer initCancel()
			if iErr := cmmcoidc.InitProvider(initCtx, cfg); iErr != nil {
				log.Printf("OIDC provider not initialized at boot (%v); will lazy-init on first login", iErr)
			} else {
				log.Printf("OIDC provider initialized: issuer=%s client_id=%s require_mfa=%v", cfg.Issuer, cfg.ClientID, cfg.RequireMFA)
			}
		}

		handler, err := fbhttp.NewHandler(imageService, fileCache, uploadCache, st.Storage, server, assetsFs)
		if err != nil {
			return err
		}

		defer listener.Close()

		log.Println("Listening on", listener.Addr().String())
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 60 * time.Second,
		}

		go func() {
			if err := srv.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP server error: %v", err)
			}

			log.Println("Stopped serving new connections.")
		}()

		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc,
			os.Interrupt,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT,
		)
		sig := <-sigc
		log.Println("Got signal:", sig)

		shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownRelease()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatalf("HTTP shutdown error: %v", err)
		}
		log.Println("Graceful shutdown complete.")

		return nil
	}, storeOptions{allowsNoDatabase: true}),
}

func getServerSettings(v *viper.Viper, st *storage.Storage) (*settings.Server, error) {
	server, err := st.Settings.GetServer()
	if err != nil {
		return nil, err
	}

	isSocketSet := false
	isAddrSet := false

	if v.IsSet("address") {
		server.Address = v.GetString("address")
		isAddrSet = true
	}

	if v.IsSet("log") {
		server.Log = v.GetString("log")
	}

	if v.IsSet("port") {
		server.Port = v.GetString("port")
		isAddrSet = true
	}

	if v.IsSet("cert") {
		server.TLSCert = v.GetString("cert")
		isAddrSet = true
	}

	if v.IsSet("key") {
		server.TLSKey = v.GetString("key")
		isAddrSet = true
	}

	if v.IsSet("root") {
		server.Root = v.GetString("root")
	}

	if v.IsSet("socket") {
		server.Socket = v.GetString("socket")
		isSocketSet = true
	}

	if v.IsSet("baseURL") {
		server.BaseURL = v.GetString("baseURL")
		// TODO(remove): remove after July 2026.
	} else if v := os.Getenv("FB_BASEURL"); v != "" {
		log.Println("DEPRECATION NOTICE: Environment variable FB_BASEURL has been deprecated, use FB_BASE_URL instead")
		server.BaseURL = v
	}

	if v.IsSet("tokenExpirationTime") {
		server.TokenExpirationTime = v.GetString("tokenExpirationTime")
	}

	if v.IsSet("disableThumbnails") {
		server.EnableThumbnails = !v.GetBool("disableThumbnails")
	}

	if v.IsSet("disablePreviewResize") {
		server.ResizePreview = !v.GetBool("disablePreviewResize")
	}

	if v.IsSet("disableTypeDetectionByHeader") {
		server.TypeDetectionByHeader = !v.GetBool("disableTypeDetectionByHeader")
	}

	if v.IsSet("disableImageResolutionCalc") {
		server.ImageResolutionCal = !v.GetBool("disableImageResolutionCalc")
	}

	if v.IsSet("disableExec") {
		server.EnableExec = !v.GetBool("disableExec")
	}

	if isAddrSet && isSocketSet {
		return nil, errors.New("--socket flag cannot be used with --address, --port, --key nor --cert")
	}

	// Do not use saved Socket if address was manually set.
	if isAddrSet && server.Socket != "" {
		server.Socket = ""
	}

	if server.EnableExec {
		log.Println("WARNING: Command Runner feature enabled!")
		log.Println("WARNING: This feature has known security vulnerabilities and should not")
		log.Println("WARNING: you fully understand the risks involved. For more information")
		log.Println("WARNING: read https://github.com/filebrowser/filebrowser/issues/5199")
	}

	return server, nil
}

func setupLog(logMethod string) {
	switch logMethod {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	case "":
		log.SetOutput(io.Discard)
	default:
		log.SetOutput(&lumberjack.Logger{
			Filename:   logMethod,
			MaxSize:    100,
			MaxAge:     14,
			MaxBackups: 10,
		})
	}
}

func quickSetup(v *viper.Viper, s *storage.Storage) error {
	log.Println("Performing quick setup")

	set := &settings.Settings{
		Key:                   generateKey(),
		Signup:                false,
		HideLoginButton:       true,
		CreateUserDir:         false,
		MinimumPasswordLength: settings.DefaultMinimumPasswordLength,
		UserHomeBasePath:      settings.DefaultUsersHomeBasePath,
		Defaults: settings.UserDefaults{
			Scope:                 ".",
			Locale:                "en",
			SingleClick:           false,
			RedirectAfterCopyMove: true,
			AceEditorTheme:        v.GetString("defaults.aceEditorTheme"),
			Perm: users.Permissions{
				Admin:    false,
				Execute:  true,
				Create:   true,
				Rename:   true,
				Modify:   true,
				Delete:   true,
				Share:    true,
				Download: true,
			},
		},
		AuthMethod: "",
		Branding:   settings.Branding{},
		Tus: settings.Tus{
			ChunkSize:  settings.DefaultTusChunkSize,
			RetryCount: settings.DefaultTusRetryCount,
		},
		Commands: nil,
		Shell:    nil,
		Rules:    nil,
	}

	var err error
	if v.GetBool("noauth") {
		set.AuthMethod = auth.MethodNoAuth
		err = s.Auth.Save(&auth.NoAuth{})
	} else {
		set.AuthMethod = auth.MethodJSONAuth
		err = s.Auth.Save(&auth.JSONAuth{})
	}
	if err != nil {
		return err
	}

	err = s.Settings.Save(set)
	if err != nil {
		return err
	}

	ser := &settings.Server{
		BaseURL:               v.GetString("baseURL"),
		Port:                  v.GetString("port"),
		Log:                   v.GetString("log"),
		TLSKey:                v.GetString("key"),
		TLSCert:               v.GetString("cert"),
		Address:               v.GetString("address"),
		Root:                  v.GetString("root"),
		TokenExpirationTime:   v.GetString("tokenExpirationTime"),
		EnableThumbnails:      !v.GetBool("disableThumbnails"),
		ResizePreview:         !v.GetBool("disablePreviewResize"),
		EnableExec:            !v.GetBool("disableExec"),
		TypeDetectionByHeader: !v.GetBool("disableTypeDetectionByHeader"),
		ImageResolutionCal:    !v.GetBool("disableImageResolutionCalc"),
	}

	err = s.Settings.SaveServer(ser)
	if err != nil {
		return err
	}

	username := v.GetString("username")
	password := v.GetString("password")

	if password == "" {
		var pwd string
		pwd, err = users.RandomPwd(set.MinimumPasswordLength)
		if err != nil {
			return err
		}

		log.Printf("User '%s' initialized with randomly generated password: %s\n", username, pwd)
		password, err = users.ValidateAndHashPwd(pwd, set.MinimumPasswordLength)
		if err != nil {
			return err
		}
	} else {
		log.Printf("User '%s' initialize wth user-provided password\n", username)
	}

	if username == "" || password == "" {
		log.Fatal("username and password cannot be empty during quick setup")
	}

	user := &users.User{
		Username:     username,
		Password:     password,
		LockPassword: false,
	}

	set.Defaults.Apply(user)
	user.Perm.Admin = true

	return s.Users.Save(user)
}
