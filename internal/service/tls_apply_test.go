package service

import (
	"context"
	"errors"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type tlsRepoStub struct {
	revision string
	events   []domain.ApplyEvent
	snapshot domain.Snapshot
}

func (r *tlsRepoStub) Snapshot(context.Context) (domain.Snapshot, error) { return r.snapshot, nil }
func (r *tlsRepoStub) ActiveRevision(context.Context) (string, error)    { return r.revision, nil }
func (r *tlsRepoStub) SetActiveRevision(_ context.Context, v string) error {
	r.revision = v
	return nil
}
func (r *tlsRepoStub) RecordEvent(_ context.Context, e domain.ApplyEvent) error {
	r.events = append(r.events, e)
	return nil
}

type tlsStoreStub struct{ rolled bool }

func (s *tlsStoreStub) Publish(context.Context, certificate.Bundle) (certificate.Published, error) {
	return certificate.Published{Revision: "tls-new", CertificatePath: "/tls/new/cert.pem", PrivateKeyPath: "/tls/new/key.pem"}, nil
}
func (s *tlsStoreStub) Rollback(context.Context) error { s.rolled = true; return nil }

type configStoreStub struct {
	rolled bool
	files  config.Files
}

func (s *configStoreStub) Apply(f config.Files) (string, error) {
	s.files = f
	return "config-new", nil
}
func (s *configStoreStub) Rollback() error { s.rolled = true; return nil }

type reloadStub struct {
	calls    int
	firstErr error
}

func (s *reloadStub) Reload(context.Context) error {
	s.calls++
	if s.calls == 1 {
		return s.firstErr
	}
	return nil
}

func TestTLSCoordinatorAppliesVerifiedPaths(t *testing.T) {
	repo := &tlsRepoStub{revision: "config-old", snapshot: domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}
	tlsStore := &tlsStoreStub{}
	configs := &configStoreStub{}
	proc := &reloadStub{}
	c := NewTLSCoordinator(repo, tlsStore, configs, proc, nil)
	got, err := c.Publish(context.Background(), certificate.Bundle{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != "tls-new" || repo.revision != "config-new" || proc.calls != 1 || tlsStore.rolled {
		t.Fatalf("got=%#v repo=%s calls=%d rolled=%v", got, repo.revision, proc.calls, tlsStore.rolled)
	}
	if string(configs.files["hosts.toml"]) == "" {
		t.Fatal("hosts.toml not rendered")
	}
}
func TestTLSCoordinatorRollsBackAndReloadsPrevious(t *testing.T) {
	repo := &tlsRepoStub{revision: "config-old", snapshot: domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}
	tlsStore := &tlsStoreStub{}
	configs := &configStoreStub{}
	proc := &reloadStub{firstErr: errors.New("sighup failed")}
	c := NewTLSCoordinator(repo, tlsStore, configs, proc, nil)
	if _, err := c.Publish(context.Background(), certificate.Bundle{}); err == nil {
		t.Fatal("expected reload failure")
	}
	if !tlsStore.rolled || !configs.rolled || repo.revision != "config-old" || proc.calls != 2 {
		t.Fatalf("tls=%v config=%v revision=%s calls=%d", tlsStore.rolled, configs.rolled, repo.revision, proc.calls)
	}
}
