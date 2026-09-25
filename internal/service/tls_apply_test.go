package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
)

func TestTLSCoordinatorCanRevertFirstPublication(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo, err := persistence.Open(ctx, filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.SetHostname(ctx, "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	tlsStore, err := certificate.NewTLSStore(filepath.Join(root, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := config.NewMaterializer(filepath.Join(root, "config"), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := certificate.GenerateSelfSigned("vpn.example.net", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordinator := NewTLSCoordinator(repo, tlsStore, files, &reloadStub{}, nil)
	admin := &certificate.AdminCertificate{}
	coordinator.SetAdminCertificate(admin)
	if _, err = coordinator.Publish(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.GetCertificate(nil); err == nil {
		t.Fatal("AdminUI exposed TLS before metadata was confirmed")
	}
	if err = coordinator.RevertLast(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.GetCertificate(nil); err == nil {
		t.Fatal("AdminUI exposed rolled-back TLS")
	}
	events, err := repo.ListApplyEvents(ctx, 0, 10)
	if err != nil || len(events) != 1 || events[0].Result != "rollback" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	for _, path := range []string{filepath.Join(root, "tls", "current"), filepath.Join(root, "config", "current")} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("first publication remained active at %s: %v", path, err)
		}
	}
	revision, err := repo.ActiveRevision(ctx)
	if err != nil || revision != "" {
		t.Fatalf("active revision=%q err=%v", revision, err)
	}
}

type tlsRepoStub struct {
	revision string
	events   []domain.ApplyEvent
	snapshot domain.Snapshot
}

type firstIssueACME struct{ bundle certificate.Bundle }

func (c firstIssueACME) EnsureAccount(context.Context) (string, error) { return "registration", nil }
func (c firstIssueACME) Obtain(context.Context, string) (certificate.Bundle, error) {
	return c.bundle, nil
}

func TestFirstBackgroundIssueWithoutVPNUsers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo, err := persistence.Open(ctx, filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.SetHostname(ctx, "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	if err = repo.SaveTLSMetadata(ctx, certificate.Metadata{State: certificate.Unconfigured, Source: certificate.LetsEncrypt, Mode: certificate.Staging, Hostname: "vpn.example.net", Email: "admin@example.net"}); err != nil {
		t.Fatal(err)
	}
	tlsStore, err := certificate.NewTLSStore(filepath.Join(root, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := config.NewMaterializer(filepath.Join(root, "config"), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	process := &reloadStub{firstErr: errors.New("endpoint must not be reloaded before first user")}
	coordinator := NewTLSCoordinator(repo, tlsStore, files, process, nil)
	admin := &certificate.AdminCertificate{}
	coordinator.SetAdminCertificate(admin)
	bundle, err := certificate.GenerateSelfSigned("vpn.example.net", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager := certificate.NewManager(repo, coordinator, nil, root, time.Second, func(certificate.ACMEConfig) (certificate.ACMEClient, error) {
		return firstIssueACME{bundle: bundle}, nil
	})
	got, err := manager.Ensure(ctx, time.Hour)
	if err != nil || got.State != certificate.Active || got.ActiveRevision == "" || process.calls != 0 {
		t.Fatalf("first issue=%+v reloads=%d err=%v", got, process.calls, err)
	}
	if _, err = admin.GetCertificate(nil); err != nil {
		t.Fatalf("AdminUI did not activate confirmed certificate: %v", err)
	}
	revision, err := repo.ActiveRevision(ctx)
	if err != nil || revision == "" {
		t.Fatalf("config revision=%q err=%v", revision, err)
	}
}

func TestAdminUIAndVPNShareConfirmedCertificateAcrossRenewal(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo, err := persistence.Open(ctx, filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.SetHostname(ctx, "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	if err = repo.SaveTLSMetadata(ctx, certificate.Metadata{State: certificate.Unconfigured, Source: certificate.LetsEncrypt, Mode: certificate.Staging, Hostname: "vpn.example.net", Email: "admin@example.net"}); err != nil {
		t.Fatal(err)
	}
	tlsStore, err := certificate.NewTLSStore(filepath.Join(root, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	configs, err := config.NewMaterializer(filepath.Join(root, "config"), nil)
	if err != nil {
		t.Fatal(err)
	}
	admin := &certificate.AdminCertificate{}
	coordinator := NewTLSCoordinator(repo, tlsStore, configs, &reloadStub{}, nil)
	coordinator.SetAdminCertificate(admin)
	first, err := certificate.GenerateSelfSigned("vpn.example.net", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := certificate.GenerateSelfSigned("vpn.example.net", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundles := []certificate.Bundle{first, second, {Certificate: []byte("invalid")}}
	manager := certificate.NewManager(repo, coordinator, nil, root, time.Second, func(certificate.ACMEConfig) (certificate.ACMEClient, error) {
		if len(bundles) == 0 {
			return nil, errors.New("unexpected ACME order")
		}
		bundle := bundles[0]
		bundles = bundles[1:]
		return firstIssueACME{bundle: bundle}, nil
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: admin.GetCertificate}
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "vpn.example.net"}}}
	defer client.CloseIdleConnections()
	handshake := func() []byte {
		t.Helper()
		client.CloseIdleConnections()
		resp, err := client.Get("https://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			t.Fatalf("HTTPS response=%+v", resp)
		}
		return resp.TLS.PeerCertificates[0].Raw
	}
	assertShared := func() []byte {
		t.Helper()
		meta, err := repo.LoadTLSMetadata(ctx)
		if err != nil {
			t.Fatal(err)
		}
		configDir, err := configs.ActiveDir()
		if err != nil {
			t.Fatal(err)
		}
		hosts, err := os.ReadFile(filepath.Join(configDir, "hosts.toml"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(hosts, []byte("cert_chain_path = "+strconv.Quote(meta.CertificatePath))) || !bytes.Contains(hosts, []byte("private_key_path = "+strconv.Quote(meta.PrivateKeyPath))) {
			t.Fatalf("VPN paths do not match confirmed revision: %s", hosts)
		}
		chain, err := os.ReadFile(meta.CertificatePath)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(chain)
		got := handshake()
		if block == nil || !bytes.Equal(got, block.Bytes) {
			t.Fatal("AdminUI handshake and VPN certificate differ")
		}
		return got
	}
	if _, err = manager.Ensure(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	old := assertShared()
	if _, err = manager.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	newCert := assertShared()
	if bytes.Equal(old, newCert) {
		t.Fatal("AdminUI did not load renewed certificate")
	}
	if _, err = manager.Renew(ctx); err == nil {
		t.Fatal("invalid renewal was accepted")
	}
	if got := assertShared(); !bytes.Equal(got, newCert) {
		t.Fatal("failed renewal replaced the last confirmed certificate")
	}
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

type tlsStoreStub struct {
	rolled      bool
	rollbackErr error
}

func (s *tlsStoreStub) Publish(context.Context, certificate.Bundle) (certificate.Published, error) {
	return certificate.Published{Revision: "tls-new", CertificatePath: "/tls/new/cert.pem", PrivateKeyPath: "/tls/new/key.pem"}, nil
}
func (s *tlsStoreStub) Rollback(context.Context) error { s.rolled = true; return s.rollbackErr }

type configStoreStub struct {
	rolled      bool
	rollbackErr error
	files       config.Files
}

func (s *configStoreStub) Apply(f config.Files) (string, error) {
	s.files = f
	return "config-new", nil
}
func (s *configStoreStub) Rollback() error { s.rolled = true; return s.rollbackErr }

type reloadStub struct {
	calls     int
	firstErr  error
	revisions []string
}

func (s *reloadStub) Restart(_ context.Context, revision string) error {
	s.calls++
	s.revisions = append(s.revisions, revision)
	if s.calls == 1 {
		return s.firstErr
	}
	return nil
}

func TestTLSCoordinatorAppliesVerifiedPaths(t *testing.T) {
	repo := &tlsRepoStub{revision: "config-old", snapshot: domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443", Users: []domain.VPNUser{{Username: "alice", Credential: "long-enough-credential", Status: domain.UserActive}}}}
	tlsStore := &tlsStoreStub{}
	configs := &configStoreStub{}
	proc := &reloadStub{}
	c := NewTLSCoordinator(repo, tlsStore, configs, proc, nil)
	got, err := c.Publish(context.Background(), certificate.Bundle{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != "tls-new" || repo.revision != "config-new" || proc.calls != 1 || proc.revisions[0] != "config-new" || tlsStore.rolled {
		t.Fatalf("got=%#v repo=%s calls=%d rolled=%v", got, repo.revision, proc.calls, tlsStore.rolled)
	}
	if string(configs.files["hosts.toml"]) == "" {
		t.Fatal("hosts.toml not rendered")
	}
}

func TestTLSCoordinatorDefersReloadBeforeFirstUser(t *testing.T) {
	repo := &tlsRepoStub{revision: "config-old", snapshot: domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}}
	tlsStore := &tlsStoreStub{}
	configs := &configStoreStub{}
	proc := &reloadStub{firstErr: errors.New("endpoint is not running")}
	c := NewTLSCoordinator(repo, tlsStore, configs, proc, nil)
	got, err := c.Publish(context.Background(), certificate.Bundle{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != "tls-new" || repo.revision != "config-new" || proc.calls != 0 || tlsStore.rolled || configs.rolled {
		t.Fatalf("got=%#v repo=%s calls=%d tls-rolled=%v config-rolled=%v", got, repo.revision, proc.calls, tlsStore.rolled, configs.rolled)
	}
	c.CompletePublished()
	if len(repo.events) != 1 || repo.events[0].Action != "none" || repo.events[0].Result != "success" {
		t.Fatalf("events=%#v", repo.events)
	}
}

func TestTLSCoordinatorRollsBackAndReloadsPrevious(t *testing.T) {
	repo := &tlsRepoStub{revision: "config-old", snapshot: domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443", Users: []domain.VPNUser{{Username: "alice", Credential: "long-enough-credential", Status: domain.UserActive}}}}
	tlsStore := &tlsStoreStub{}
	configs := &configStoreStub{}
	proc := &reloadStub{firstErr: errors.New("restart failed")}
	c := NewTLSCoordinator(repo, tlsStore, configs, proc, nil)
	if _, err := c.Publish(context.Background(), certificate.Bundle{}); err == nil {
		t.Fatal("expected reload failure")
	}
	if !tlsStore.rolled || !configs.rolled || repo.revision != "config-old" || proc.calls != 2 {
		t.Fatalf("tls=%v config=%v revision=%s calls=%d", tlsStore.rolled, configs.rolled, repo.revision, proc.calls)
	}
	if proc.revisions[0] != "config-new" || proc.revisions[1] != "config-old" {
		t.Fatalf("restart revisions=%v", proc.revisions)
	}
}

func TestTLSCoordinatorReportsRollbackFailure(t *testing.T) {
	repo := &tlsRepoStub{revision: "config-old", snapshot: domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443", Users: []domain.VPNUser{{Username: "alice", Credential: "long-enough-credential", Status: domain.UserActive}}}}
	tlsStore := &tlsStoreStub{rollbackErr: errors.New("tls rollback failed")}
	configs := &configStoreStub{rollbackErr: errors.New("config rollback failed")}
	proc := &reloadStub{firstErr: errors.New("restart failed")}
	c := NewTLSCoordinator(repo, tlsStore, configs, proc, nil)
	_, err := c.Publish(context.Background(), certificate.Bundle{})
	if err == nil || !tlsStore.rolled || !configs.rolled {
		t.Fatalf("err=%v tls=%v config=%v", err, tlsStore.rolled, configs.rolled)
	}
	for _, want := range []string{"tls rollback failed", "config rollback failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %q in %v", want, err)
		}
	}
}
