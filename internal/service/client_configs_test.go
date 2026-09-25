package service

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
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
func (r clientRepoStub) LoadClientProfile(context.Context) (clientprofile.Settings, error) {
	return clientprofile.Default(), nil
}

type exporterStub struct {
	called  bool
	address string
}

func (e *exporterStub) Export(_ context.Context, u domain.VPNUser, address string) (domain.ClientConfig, error) {
	e.called = true
	e.address = address
	return domain.ClientConfig{DeepLink: "tt://?AAEB", TOML: "username = \"" + u.Username + "\""}, nil
}

type processStatusStub struct{ state string }

type customProfileRepo struct {
	clientRepoStub
	profile clientprofile.Settings
}

func (r customProfileRepo) LoadClientProfile(context.Context) (clientprofile.Settings, error) {
	return r.profile, nil
}

func TestClientConfigUsesSavedProfile(t *testing.T) {
	p := clientprofile.Default()
	p.PublicAddress = "89.124.66.69:1443"
	p.AntiDPI = true
	p.PostQuantum = false
	r := customProfileRepo{clientRepoStub{domain.VPNUser{ID: 1, Username: "alice", Status: domain.UserActive}, domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}, p}
	e := &exporterStub{}
	cfg, err := NewClientConfigService(r, e, processStatusStub{"ready"}).Export(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if e.address != p.PublicAddress || !strings.Contains(cfg.CLI, "post_quantum_group_enabled = false") || !strings.Contains(cfg.TOML, "anti_dpi = true") {
		t.Fatalf("saved settings not applied: address=%s", e.address)
	}
}

func (p processStatusStub) Status() domain.EndpointStatus {
	return domain.EndpointStatus{State: p.state}
}
func TestClientConfigUsesOfficialExporterAndQR(t *testing.T) {
	exporter := &exporterStub{}
	svc := NewClientConfigService(clientRepoStub{domain.VPNUser{ID: 1, Username: "alice", Status: domain.UserActive}, domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}, exporter, processStatusStub{"ready"})
	cfg, err := svc.Export(context.Background(), 1)
	if exporter.address != "vpn.example.net:443" {
		t.Fatalf("exported internal port: %s", exporter.address)
	}
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
