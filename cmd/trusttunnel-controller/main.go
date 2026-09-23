package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-pkgz/lgr"
	flags "github.com/jessevdk/go-flags"

	"github.com/reansnow/trusttunnel-controller/internal/app"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/migration"
)

var (
	version = "dev"
	commit  = "unknown"
)

type options struct {
	DataDir         string        `long:"data-dir" env:"TT_DATA_DIR" default:"/var/lib/trusttunnel" description:"Persistent data directory"`
	EndpointBinary  string        `long:"endpoint-binary" env:"TT_ENDPOINT_BINARY" default:"/usr/local/bin/trusttunnel_endpoint" description:"Official endpoint binary"`
	EndpointVersion string        `long:"endpoint-version" env:"TT_ENDPOINT_VERSION" default:"1.1.0" description:"Official endpoint version"`
	UIListen        string        `long:"ui-listen" env:"TT_UI_LISTEN" default:"127.0.0.1:8080" description:"Admin UI listener"`
	MetricsURL      string        `long:"metrics-url" env:"TT_METRICS_URL" default:"http://127.0.0.1:9090/metrics" description:"Internal endpoint metrics URL"`
	ProbeListen     string        `long:"probe-listen" env:"TT_PROBE_LISTEN" default:"127.0.0.1:8081" description:"Health/readiness listener"`
	HTTP01Listen    string        `long:"http01-listen" env:"TT_HTTP01_LISTEN" default:"0.0.0.0:80" description:"Temporary ACME HTTP-01 listener"`
	TrustedProxies  []string      `long:"trusted-proxy" env:"TT_TRUSTED_PROXY" description:"Trusted reverse proxy CIDR (repeatable)"`
	ExternalTLS     bool          `long:"external-tls" env:"TT_EXTERNAL_TLS" description:"Enable HSTS for externally terminated TLS"`
	StartTimeout    time.Duration `long:"start-timeout" env:"TT_START_TIMEOUT" default:"15s" description:"Endpoint start timeout"`
	StopTimeout     time.Duration `long:"stop-timeout" env:"TT_STOP_TIMEOUT" default:"10s" description:"Endpoint graceful stop timeout"`
	SessionLifetime time.Duration `long:"session-lifetime" env:"TT_SESSION_LIFETIME" default:"12h" description:"Administrator session lifetime"`
	RenewalLead     time.Duration `long:"renewal-lead" env:"TT_RENEWAL_LEAD" default:"720h" description:"Certificate renewal lead time"`
	LogFormat       string        `long:"log-format" env:"TT_LOG_FORMAT" choice:"json" choice:"text" default:"json" description:"Log encoding"`
	LogLevel        string        `long:"log-level" env:"TT_LOG_LEVEL" default:"info" description:"Log severity"`
	ShowVersion     bool          `long:"version" description:"Print version and exit"`
	MigrateLegacy   string        `long:"migrate-legacy" env:"TT_MIGRATE_LEGACY" description:"Import an absolute legacy volume path and exit"`
	Healthcheck     bool          `long:"healthcheck" description:"Check the local health endpoint and exit"`
	ACMEDefaultMode string        `long:"acme-default-mode" env:"TT_ACME_DEFAULT_MODE" choice:"production" choice:"staging" default:"production" description:"Default ACME mode before first configuration"`
}

func run(args []string) error {
	var opts options
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.ParseArgs(args); err != nil {
		var flagErr *flags.Error
		if errors.As(err, &flagErr) && flagErr.Type == flags.ErrHelp {
			return nil
		}
		return err
	}
	if opts.ShowVersion {
		fmt.Printf("trusttunnel-controller %s (%s)\n", version, commit)
		return nil
	}
	if opts.MigrateLegacy != "" {
		result, err := migration.Run(context.Background(), opts.MigrateLegacy, opts.DataDir)
		if err != nil {
			return fmt.Errorf("legacy migration: %w", err)
		}
		fmt.Printf("migration complete users=%d rules=%d certificate=%t already_complete=%t\n", result.Users, result.Rules, result.CertificateImported, result.AlreadyComplete)
		return nil
	}
	if opts.Healthcheck {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://" + opts.ProbeListen + "/healthz")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("health status %d", resp.StatusCode)
		}
		return nil
	}

	logOpts := []lgr.Option{lgr.LevelBraces}
	if opts.LogFormat == "json" {
		logOpts = append(logOpts, lgr.Format(`{"time":"{{.DT.Format "2006-01-02T15:04:05.000Z07:00"}}","level":"{{.Level}}","message":{{printf "%q" .Message}}}`))
	}
	log := lgr.New(logOpts...)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	cfg := app.Config{
		DataDir: opts.DataDir, EndpointBinary: opts.EndpointBinary, EndpointVersion: opts.EndpointVersion,
		UIListen: opts.UIListen, MetricsURL: opts.MetricsURL,
		ProbeListen: opts.ProbeListen, HTTP01Listen: opts.HTTP01Listen, StartTimeout: opts.StartTimeout,
		StopTimeout: opts.StopTimeout, Version: version, Commit: commit,
		SessionLifetime: opts.SessionLifetime, RenewalLead: opts.RenewalLead,
		TrustedProxies: opts.TrustedProxies, ExternalTLS: opts.ExternalTLS,
		ACMEDefaultMode: certificate.Mode(opts.ACMEDefaultMode),
	}
	return app.Run(ctx, cfg, log)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "controller:", err)
		os.Exit(1)
	}
}
