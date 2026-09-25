package app

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
	"github.com/reansnow/trusttunnel-controller/internal/service"
	"github.com/reansnow/trusttunnel-controller/internal/supervisor"
)

type messageLogger struct{ messages []string }

func (l *messageLogger) Logf(format string, args ...interface{}) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func TestSeedTLSKeepsPersistedSourceAndHostname(t *testing.T) {
	ctx := context.Background()
	store, err := persistence.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	settings := service.NewTLSSettingsService(store, nil)
	log := &messageLogger{}
	if err = seedTLS(ctx, settings, Config{TLSSource: certificate.SelfSigned, TLSHostname: "vpn.example.test"}, log); err != nil {
		t.Fatal(err)
	}
	if err = seedTLS(ctx, settings, Config{TLSSource: certificate.LetsEncrypt, TLSHostname: "other.example.com", ACMEEmail: "admin@example.com"}, log); err != nil {
		t.Fatal(err)
	}
	got, err := settings.View(ctx)
	if err != nil || got.Source != certificate.SelfSigned || got.Hostname != "vpn.example.test" {
		t.Fatalf("saved=%+v err=%v", got, err)
	}
	if len(log.messages) != 2 || !strings.Contains(log.messages[0], "differs") || !strings.Contains(log.messages[1], "differs") {
		t.Fatalf("missing mismatch diagnostics: %v", log.messages)
	}
}

type restartSnapshot struct{ address, revision string }

func (s restartSnapshot) Snapshot(context.Context) (domain.Snapshot, error) {
	return domain.Snapshot{ListenAddress: s.address}, nil
}
func (s restartSnapshot) ActiveRevision(context.Context) (string, error) { return s.revision, nil }

func TestTLSReloadStartsStoppedEndpoint(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep executable unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	proc, err := supervisor.New(supervisor.Config{
		Binary: sleep, WorkingDir: t.TempDir(), StopTimeout: time.Second,
		Args: func(string) []string { return []string{"30"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Stop(context.Background())
	p := &readinessProcess{process: proc, store: restartSnapshot{address: listener.Addr().String(), revision: "tls-revision"}, timeout: time.Second}
	if err = p.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := proc.Status()
	if status.PID == 0 || status.Revision != "tls-revision" || status.State != "ready" {
		t.Fatalf("stopped endpoint not started with TLS revision: %+v", status)
	}
}
