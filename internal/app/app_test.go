package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type signalLogger struct {
	started chan struct{}
	once    sync.Once
}

func (l *signalLogger) Logf(format string, _ ...interface{}) {
	if strings.Contains(format, "controller started") {
		l.once.Do(func() { close(l.started) })
	}
}

func TestRunStartsAndStopsUIAndProbeListeners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := &signalLogger{started: make(chan struct{})}
	cfg := Config{DataDir: t.TempDir(), EndpointBinary: "/bin/true", EndpointVersion: "test", UIListen: "127.0.0.1:0", MetricsURL: "http://127.0.0.1:1/metrics", ProbeListen: "127.0.0.1:0", HTTP01Listen: "127.0.0.1:0", StartTimeout: time.Second, StopTimeout: 5 * time.Second, SessionLifetime: time.Hour, RenewalLead: 24 * time.Hour, Version: "test", Commit: "test"}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, logger) }()
	select {
	case <-logger.started:
		cancel()
	case err := <-done:
		t.Fatalf("controller exited before start: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("controller did not start")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("controller did not stop")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "controller.db")); err != nil {
		t.Fatal(err)
	}
}
