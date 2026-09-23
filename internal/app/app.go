package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
	"github.com/reansnow/trusttunnel-controller/internal/probe"
	"github.com/reansnow/trusttunnel-controller/internal/supervisor"
)

type Logger interface {
	Logf(format string, args ...interface{})
}

type Config struct {
	DataDir, EndpointBinary, UIListen, MetricsURL, ProbeListen string
	StartTimeout, StopTimeout                                  time.Duration
	Version, Commit                                            string
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.DataDir) || !filepath.IsAbs(c.EndpointBinary) {
		return fmt.Errorf("data-dir and endpoint-binary must be absolute")
	}
	for label, addr := range map[string]string{"ui-listen": c.UIListen, "probe-listen": c.ProbeListen} {
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

func Run(ctx context.Context, cfg Config, log Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	store, err := persistence.Open(ctx, filepath.Join(cfg.DataDir, "controller.db"))
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	defer store.Close()
	materializer, err := config.NewMaterializer(filepath.Join(cfg.DataDir, "config"), validateStaged)
	if err != nil {
		return fmt.Errorf("config materializer: %w", err)
	}
	proc, err := supervisor.New(supervisor.Config{
		Binary: cfg.EndpointBinary, WorkingDir: filepath.Join(cfg.DataDir, "config", "current"), StopTimeout: cfg.StopTimeout,
		Args: func(revision string) []string {
			dir := filepath.Join(cfg.DataDir, "config", "revisions", revision)
			return []string{filepath.Join(dir, "vpn.toml"), filepath.Join(dir, "hosts.toml")}
		},
	})
	if err != nil {
		return err
	}
	probeServer := &http.Server{Addr: cfg.ProbeListen, Handler: probe.New(store, proc, materializer, cfg.Version), ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second}
	listener, err := net.Listen("tcp", cfg.ProbeListen)
	if err != nil {
		return fmt.Errorf("probe listener: %w", err)
	}
	serverErr := make(chan error, 1)
	go func() {
		if serveErr := probeServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
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
		if err = proc.Start(ctx, revision); err != nil {
			return fmt.Errorf("start endpoint: %w", err)
		}
		if err = waitTCP(ctx, snapshot.ListenAddress, cfg.StartTimeout); err != nil {
			_ = proc.Stop(context.Background())
			return fmt.Errorf("endpoint readiness: %w", err)
		}
		proc.MarkReady()
	}
	log.Logf("controller started version=%s commit=%s", cfg.Version, cfg.Commit)
	select {
	case <-ctx.Done():
	case err = <-serverErr:
		return err
	}
	log.Logf("controller stopping")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.StopTimeout)
	defer cancel()
	_ = probeServer.Shutdown(shutdownCtx)
	return proc.Stop(shutdownCtx)
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
