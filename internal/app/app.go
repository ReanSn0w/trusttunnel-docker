package app

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
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
	log.Logf("controller started version=%s commit=%s", cfg.Version, cfg.Commit)
	<-ctx.Done()
	log.Logf("controller stopping")
	return nil
}
