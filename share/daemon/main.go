// Binary cmmc-share is the DMZ-facing daemon that serves one-off
// CUI share links to external recipients.
//
// Usage:
//
//	cmmc-share \
//	    --store-dir /var/lib/cmmc-share/store \
//	    --public-addr 0.0.0.0:8444 \
//	    --backchannel-addr 127.0.0.1:8445 \
//	    --tls-cert /etc/cmmc-share/tls/server.crt \
//	    --tls-key  /etc/cmmc-share/tls/server.key \
//	    --enclave-ca /etc/cmmc-share/tls/enclave-ca.pem \
//	    --bearer-token-file /etc/cmmc-share/bearer.token \
//	    --audit-key-file   /etc/cmmc-share/audit.key \
//	    --pepper-file      /etc/cmmc-share/pepper.bin
//
// Files:
//
//	store-dir         0700 root:cmmc-share  ciphertext + metadata
//	bearer-token-file 0400 cmmc-share       shared secret with enclave
//	audit-key-file    0400 cmmc-share       HMAC key, matches enclave
//	pepper-file       0400 cmmc-share       server-side passphrase pepper
//
// The binary is sized for a one-command install: open two listeners,
// start a sweeper, handle SIGTERM gracefully. Nothing else.
package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Config carries runtime configuration. Exported so it can be built
// by main() in a cmd/ wrapper or by tests.
type Config struct {
	StoreDir         string
	PublicAddr       string
	BackchannelAddr  string
	TLSCertFile      string
	TLSKeyFile       string
	EnclaveCAFile    string
	BearerTokenFile  string
	AuditKeyFile     string
	PepperFile       string
	SweepInterval    time.Duration
	AuditBufferCap   int
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	ShutdownTimeout  time.Duration
	// DisablePublicTLS is for tests + behind-a-terminating-proxy
	// deployments. In production, TLS is mandatory on the public
	// listener.
	DisablePublicTLS bool
}

// DefaultConfig returns a config with safe defaults filled in.
// Paths are left empty — callers set them from flags.
func DefaultConfig() Config {
	return Config{
		PublicAddr:      "0.0.0.0:8444",
		BackchannelAddr: "127.0.0.1:8445",
		SweepInterval:   5 * time.Minute,
		AuditBufferCap:  4096,
		ReadTimeout:     15 * time.Second,
		WriteTimeout:    2 * time.Minute,
		ShutdownTimeout: 10 * time.Second,
	}
}

// ParseFlags populates c from the standard flag set. Returns the
// parsed Config and a bool indicating whether --version was asked.
func ParseFlags(args []string) (Config, bool, error) {
	fs := flag.NewFlagSet("cmmc-share", flag.ContinueOnError)
	c := DefaultConfig()
	fs.StringVar(&c.StoreDir, "store-dir", "/var/lib/cmmc-share/store", "directory for per-share ciphertext + metadata")
	fs.StringVar(&c.PublicAddr, "public-addr", c.PublicAddr, "listen address for the public (internet) surface")
	fs.StringVar(&c.BackchannelAddr, "backchannel-addr", c.BackchannelAddr, "listen address for the mTLS enclave back-channel")
	fs.StringVar(&c.TLSCertFile, "tls-cert", "", "server certificate PEM for both listeners")
	fs.StringVar(&c.TLSKeyFile, "tls-key", "", "server private key PEM for both listeners")
	fs.StringVar(&c.EnclaveCAFile, "enclave-ca", "", "CA PEM that signs the enclave's mTLS client cert (backchannel)")
	fs.StringVar(&c.BearerTokenFile, "bearer-token-file", "", "file containing the backchannel bearer token (min 32 bytes)")
	fs.StringVar(&c.AuditKeyFile, "audit-key-file", "", "file containing the HMAC key for the audit chain (min 32 bytes)")
	fs.StringVar(&c.PepperFile, "pepper-file", "", "file containing the server-side Argon2 passphrase pepper (min 32 bytes)")
	fs.DurationVar(&c.SweepInterval, "sweep-interval", c.SweepInterval, "how often to scan for expired shares")
	fs.BoolVar(&c.DisablePublicTLS, "disable-public-tls", false, "INSECURE: terminate TLS at an upstream proxy instead of the daemon")
	version := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return c, false, err
	}
	return c, *version, nil
}

// Run starts the daemon. Blocks until SIGINT/SIGTERM. Returns the
// first error encountered by either listener or the shutdown path.
func Run(ctx context.Context, c Config) error {
	if err := validateConfig(c); err != nil {
		return err
	}

	pepper, err := readSecret(c.PepperFile, 32)
	if err != nil {
		return fmt.Errorf("pepper: %w", err)
	}
	auditKey, err := readSecret(c.AuditKeyFile, 32)
	if err != nil {
		return fmt.Errorf("audit key: %w", err)
	}
	bearer, err := readSecret(c.BearerTokenFile, 32)
	if err != nil {
		return fmt.Errorf("bearer token: %w", err)
	}

	store, err := NewStore(c.StoreDir)
	if err != nil {
		return err
	}
	audit, err := NewAuditLog(auditKey, c.AuditBufferCap)
	if err != nil {
		return err
	}

	public := NewPublicServer(store, audit, pepper)
	back, err := NewBackChannel(store, audit, bearer)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	// Public listener.
	publicSrv := &http.Server{
		Addr:         c.PublicAddr,
		Handler:      public.Routes(),
		ReadTimeout:  c.ReadTimeout,
		WriteTimeout: c.WriteTimeout,
	}
	if !c.DisablePublicTLS {
		publicSrv.TLSConfig = publicTLSConfig()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		if c.DisablePublicTLS {
			log.Printf("cmmc-share: public listener on %s (PLAINTEXT — terminate TLS upstream)", c.PublicAddr)
			err = publicSrv.ListenAndServe()
		} else {
			log.Printf("cmmc-share: public listener on %s (TLS)", c.PublicAddr)
			err = publicSrv.ListenAndServeTLS(c.TLSCertFile, c.TLSKeyFile)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public: %w", err)
		}
	}()

	// Backchannel listener — mTLS, pinned to the enclave CA.
	backTLS, err := enclaveTLSConfig(c.EnclaveCAFile)
	if err != nil {
		return fmt.Errorf("backchannel tls: %w", err)
	}
	backSrv := &http.Server{
		Addr:         c.BackchannelAddr,
		Handler:      back.Routes(),
		TLSConfig:    backTLS,
		ReadTimeout:  c.ReadTimeout,
		WriteTimeout: c.WriteTimeout,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("cmmc-share: backchannel listener on %s (mTLS, pinned to enclave CA)", c.BackchannelAddr)
		err := backSrv.ListenAndServeTLS(c.TLSCertFile, c.TLSKeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("backchannel: %w", err)
		}
	}()

	// Sweeper — periodic TTL / counter cleanup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(c.SweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := store.Sweep(time.Now())
				if err != nil {
					log.Printf("cmmc-share: sweep error: %v", err)
					continue
				}
				if n > 0 {
					for i := 0; i < n; i++ {
						_, _ = audit.Append(Event{
							Action:  ActionSweeperExpired,
							Outcome: "success",
						})
					}
					log.Printf("cmmc-share: sweep removed %d expired share(s)", n)
				}
			}
		}
	}()

	// Wait for shutdown signal or fatal error.
	select {
	case <-ctx.Done():
		log.Printf("cmmc-share: shutdown requested")
	case err := <-errCh:
		log.Printf("cmmc-share: fatal: %v", err)
		cancel()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), c.ShutdownTimeout)
	defer shutdownCancel()
	_ = publicSrv.Shutdown(shutdownCtx)
	_ = backSrv.Shutdown(shutdownCtx)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func validateConfig(c Config) error {
	if c.StoreDir == "" {
		return errors.New("config: --store-dir required")
	}
	if c.PepperFile == "" || c.AuditKeyFile == "" || c.BearerTokenFile == "" {
		return errors.New("config: --pepper-file, --audit-key-file, --bearer-token-file all required")
	}
	if !c.DisablePublicTLS && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return errors.New("config: --tls-cert and --tls-key required unless --disable-public-tls is set")
	}
	if c.EnclaveCAFile == "" {
		return errors.New("config: --enclave-ca required")
	}
	return nil
}

// readSecret opens a file expected to hold a binary secret of at
// least minLen bytes and refuses if the file is wider than 0600.
// The permission check mirrors ssh's KEK-file handling pattern —
// loose perms on a secrets file are a CMMC finding on their own.
func readSecret(path string, minLen int) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%q too permissive (%o); must be 0400 or 0600", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	// Accept either raw bytes or a single-line hex/base64 encoding —
	// for v1 we require raw bytes so the operator gets exactly what
	// `openssl rand -out <file> 32` produces.
	if len(data) < minLen {
		return nil, fmt.Errorf("%q too short: %d bytes, need >= %d", path, len(data), minLen)
	}
	return data, nil
}

// publicTLSConfig is the FIPS-friendly TLS config for the public
// listener. TLS 1.3 preferred, TLS 1.2 with FIPS ciphers only.
// Mirrors cmmc/crypto/tlsprofile intent without the import cycle
// the daemon would otherwise incur.
func publicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}
}

// enclaveTLSConfig returns the TLS config for the backchannel
// listener: mutual TLS with client certs required and chained to
// the enclave's CA. Nobody without a cert signed by that CA can
// even complete the handshake — a defence-in-depth before the
// bearer-token check.
func enclaveTLSConfig(caFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read enclave CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("enclave CA file: no PEM-encoded certificates found")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}, nil
}
