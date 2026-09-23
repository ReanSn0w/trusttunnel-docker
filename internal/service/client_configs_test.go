package service

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"strings"
	"testing"
)

type clientRepoStub struct {
	user domain.VPNUser
	snap domain.Snapshot
}

func (r clientRepoStub) UserByID(context.Context, int64) (domain.VPNUser, error) { return r.user, nil }
func (r clientRepoStub) Snapshot(context.Context) (domain.Snapshot, error)       { return r.snap, nil }

type exporterStub struct{ called bool }

func (e *exporterStub) Export(_ context.Context, u domain.VPNUser, address string) (domain.ClientConfig, error) {
	e.called = true
	return domain.ClientConfig{DeepLink: "tt://?user=" + u.Username + "&address=" + address, TOML: "username = \"" + u.Username + "\""}, nil
}

type processStatusStub struct{ state string }

func (p processStatusStub) Status() domain.EndpointStatus {
	return domain.EndpointStatus{State: p.state}
}
func TestClientConfigUsesOfficialExporterAndQR(t *testing.T) {
	exporter := &exporterStub{}
	svc := NewClientConfigService(clientRepoStub{domain.VPNUser{ID: 1, Username: "alice", Status: domain.UserActive}, domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}, exporter, processStatusStub{"ready"})
	cfg, err := svc.Export(context.Background(), 1)
	if err != nil || !strings.HasPrefix(cfg.DeepLink, "tt://") || !exporter.called {
		t.Fatalf("cfg=%#v called=%v err=%v", cfg, exporter.called, err)
	}
	png, err := svc.QR(context.Background(), 1, 256)
	if err != nil || len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("png=%d err=%v", len(png), err)
	}
}
func TestClientConfigRejectsInactiveOrUnready(t *testing.T) {
	for _, tc := range []struct {
		state  string
		status domain.UserStatus
	}{{"starting", domain.UserActive}, {"ready", domain.UserDisabled}} {
		svc := NewClientConfigService(clientRepoStub{domain.VPNUser{Status: tc.status}, domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}, &exporterStub{}, processStatusStub{tc.state})
		if _, err := svc.Export(context.Background(), 1); err == nil {
			t.Fatalf("accepted state=%s status=%s", tc.state, tc.status)
		}
	}
}
