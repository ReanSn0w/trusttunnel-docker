package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/auth"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/datalock"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/endpointcli"
	"github.com/reansnow/trusttunnel-controller/internal/logbuffer"
	"github.com/reansnow/trusttunnel-controller/internal/metrics"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
	"github.com/reansnow/trusttunnel-controller/internal/probe"
	"github.com/reansnow/trusttunnel-controller/internal/service"
	"github.com/reansnow/trusttunnel-controller/internal/supervisor"
	"github.com/reansnow/trusttunnel-controller/internal/webui"
)

type Logger interface {
	Logf(format string, args ...interface{})
}

type Config struct {
	TLSHostname, ACMEEmail, TLSCertificateFile, TLSKeyFile                                    string
	TLSSource                                                                                 certificate.Source
	DataDir, EndpointBinary, EndpointVersion, UIListen, MetricsURL, ProbeListen, HTTP01Listen string
	StartTimeout, StopTimeout, SessionLifetime, RenewalLead                                   time.Duration
	Version, Commit                                                                           string
	ACMEDefaultMode                                                                           certificate.Mode
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.DataDir) || !filepath.IsAbs(c.EndpointBinary) {
		return fmt.Errorf("data-dir and endpoint-binary must be absolute")
	}
	for label, addr := range map[string]string{"ui-listen": c.UIListen, "probe-listen": c.ProbeListen, "http01-listen": c.HTTP01Listen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	u, err := url.Parse(c.MetricsURL)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return fmt.Errorf("metrics-url must be an http URL")
	}
	if c.StartTimeout <= 0 || c.StopTimeout <= 0 {
		return fmt.Errorf("timeouts must be positive")
	}
	return nil
}

func Run(ctx context.Context, cfg Config, log Logger) (runErr error) {
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	dataLock, err := datalock.Acquire(cfg.DataDir)
	if err != nil {
		return err
	}
	defer dataLock.Close()
	store, err := persistence.Open(ctx, filepath.Join(cfg.DataDir, "controller.db"))
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	defer store.Close()
	controllerLogs := logbuffer.New(256 << 10)
	runtimeLog := teeLogger{primary: log, buffer: controllerLogs}
	materializer, err := config.NewMaterializer(filepath.Join(cfg.DataDir, "config"), validateStaged)
	if err != nil {
		return fmt.Errorf("config materializer: %w", err)
	}
	proc, err := supervisor.New(supervisor.Config{
		Binary: cfg.EndpointBinary, WorkingDir: filepath.Join(cfg.DataDir, "config", "current"), StopTimeout: cfg.StopTimeout, Version: cfg.EndpointVersion,
		Args: func(revision string) []string {
			dir := filepath.Join(cfg.DataDir, "config", "revisions", revision)
			return []string{filepath.Join(dir, "vpn.toml"), filepath.Join(dir, "hosts.toml")}
		},
	})
	if err != nil {
		return err
	}
	readyProc := &readinessProcess{process: proc, store: store, timeout: cfg.StartTimeout}
	applyManager := service.NewApplyManager(store, materializer, readyProc)
	applyLock := &sync.Mutex{}
	applyManager.SetApplyLock(applyLock)
	userManager := service.NewUserManager(store, applyManager)
	userManager.SetApplyLock(applyLock)
	exporter, err := endpointcli.New(cfg.EndpointBinary, filepath.Join(cfg.DataDir, "config", "current", "vpn.toml"), filepath.Join(cfg.DataDir, "config", "current", "hosts.toml"), 10*time.Second, 1<<20, 2)
	if err != nil {
		return err
	}
	clientConfigs := service.NewClientConfigService(store, exporter, proc)
	tlsStore, err := certificate.NewTLSStore(filepath.Join(cfg.DataDir, "tls"))
	if err != nil {
		return err
	}
	tlsCoordinator := service.NewTLSCoordinator(store, tlsStore, materializer, readyProc, nil)
	http01 := certificate.NewHTTP01Provider(cfg.HTTP01Listen, 4)
	certificateManager := certificate.NewManager(store, tlsCoordinator, http01, cfg.DataDir, 2*time.Minute, nil)
	certificateManager.SetApplyLock(applyLock)
	tlsSettings := service.NewTLSSettingsServiceWithMode(store, certificateManager, cfg.ACMEDefaultMode)
	if err = seedTLS(ctx, tlsSettings, cfg, runtimeLog); err != nil {
		return err
	}
	renewal := certificate.NewAutomaticScheduler(store, func(ctx context.Context) (certificate.Metadata, error) {
		return certificateManager.Ensure(ctx, cfg.RenewalLead)
	}, runtimeLog.Logf)

	bootstrapService := auth.NewBootstrapService(store)
	sessionService := auth.NewSessionService(store, cfg.SessionLifetime)
	authHandler, err := webui.NewAuthHandler(sessionService, nil, nil, true)
	if err != nil {
		return fmt.Errorf("trusted proxies: %w", err)
	}
	router := webui.NewRouter(webui.RouterDependencies{
		Bootstrap: bootstrapService, Auth: authHandler,
		Dashboard: webui.NewDashboardHandler(proc, metrics.New(cfg.MetricsURL, 2*time.Second, 256<<10), store),
		Users:     webui.NewUsersHandler(userManager), Clients: webui.NewClientConfigHandler(clientConfigs),
		Connection: webui.NewConnectionHandler(store),
		TLS:        webui.NewTLSHandler(tlsSettings), Events: webui.NewEventsHandler(store, proc, controllerLogs),
		CSRF: webui.NewCSRF(true), Logger: runtimeLog, ExternalTLS: true,
	})
	probeServer := &http.Server{Addr: cfg.ProbeListen, Handler: probe.New(store, proc, materializer, cfg.Version), ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second}
	uiServer := &http.Server{Addr: cfg.UIListen, Handler: router, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	uiServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		active, err := tlsStore.Active()
		if err != nil {
			return nil, fmt.Errorf("no active AdminUI TLS certificate: %w", err)
		}
		pair, err := tls.LoadX509KeyPair(active.CertificatePath, active.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load active AdminUI TLS certificate: %w", err)
		}
		return &pair, nil
	}}
	probeListener, err := net.Listen("tcp", cfg.ProbeListen)
	if err != nil {
		return fmt.Errorf("probe listener: %w", err)
	}
	uiListener, err := net.Listen("tcp", cfg.UIListen)
	if err != nil {
		_ = probeListener.Close()
		return fmt.Errorf("UI listener: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.StopTimeout)
		defer cancel()
		_ = uiServer.Shutdown(shutdownCtx)
		_ = probeServer.Shutdown(shutdownCtx)
		runErr = errors.Join(runErr, proc.Stop(shutdownCtx))
	}()
	serverErr := make(chan error, 2)
	go func() {
		if serveErr := probeServer.Serve(probeListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
	}()
	go func() {
		if serveErr := uiServer.Serve(tls.NewListener(uiListener, uiServer.TLSConfig)); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
	}()

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Hostname != "" && len(snapshot.Users) > 0 {
		files, renderErr := config.Render(snapshot)
		if renderErr != nil {
			return renderErr
		}
		revision, applyErr := materializer.Apply(files)
		if applyErr != nil {
			return applyErr
		}
		if err = store.SetActiveRevision(ctx, revision); err != nil {
			return err
		}
		if err = readyProc.Restart(ctx, revision); err != nil {
			runtimeLog.Logf("endpoint startup degraded: %v", err)
		}
	}
	runtimeLog.Logf("controller started version=%s commit=%s", cfg.Version, cfg.Commit)
	// Start after listeners and endpoint recovery, avoiding a publish/startup race.
	if err = renewal.Start(ctx); err != nil {
		return err
	}
	defer func() {
		cancelRun()
		stopCtx, cancel := context.WithTimeout(context.Background(), cfg.StopTimeout)
		defer cancel()
		_ = renewal.Stop(stopCtx)
		_ = http01.Shutdown(stopCtx)
	}()
	select {
	case <-ctx.Done():
	case err = <-serverErr:
		runErr = err
	}
	runtimeLog.Logf("controller stopping")
	return runErr
}

type teeLogger struct {
	primary Logger
	buffer  *logbuffer.Ring
}

func (l teeLogger) Logf(format string, args ...interface{}) {
	if l.primary != nil {
		l.primary.Logf(format, args...)
	}
	l.buffer.Logf(format, args...)
}

type snapshotStore interface {
	Snapshot(context.Context) (domain.Snapshot, error)
	ActiveRevision(context.Context) (string, error)
}
type readinessProcess struct {
	process *supervisor.Supervisor
	store   snapshotStore
	timeout time.Duration
}

func (p *readinessProcess) Restart(ctx context.Context, revision string) error {
	if err := p.process.Restart(ctx, revision); err != nil {
		return err
	}
	return p.ready(ctx)
}
func (p *readinessProcess) Reload(ctx context.Context) error {
	if p.process.Status().PID == 0 {
		revision, err := p.store.ActiveRevision(ctx)
		if err != nil {
			return err
		}
		return p.Restart(ctx, revision)
	}
	if err := p.process.Reload(ctx); err != nil {
		return err
	}
	return p.ready(ctx)
}
func (p *readinessProcess) ready(ctx context.Context) error {
	snapshot, err := p.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err = waitTCP(ctx, snapshot.ListenAddress, p.timeout); err != nil {
		p.process.MarkDegraded(err)
		return err
	}
	p.process.MarkReady()
	return nil
}

func validateStaged(dir string) error {
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml", "rules.toml"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not regular", name)
		}
	}
	return nil
}

func waitTCP(ctx context.Context, address string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
