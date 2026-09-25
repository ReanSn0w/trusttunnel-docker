package app

import (
	"context"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/supervisor"
)

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
