package service

import (
	"context"
	"database/sql"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"testing"
)

type tlsSettingsRepo struct {
	m     certificate.Metadata
	empty bool
}

func (r *tlsSettingsRepo) SetHostname(_ context.Context, hostname string) error {
	r.m.Hostname = hostname
	return nil
}

func (r *tlsSettingsRepo) LoadTLSMetadata(context.Context) (certificate.Metadata, error) {
	if r.empty {
		return certificate.Metadata{}, sql.ErrNoRows
	}
	return r.m, nil
}
func (r *tlsSettingsRepo) SaveTLSMetadata(_ context.Context, m certificate.Metadata) error {
	r.m = m
	r.empty = false
	return nil
}

type certOpsStub struct{ issued certificate.Metadata }

func (c *certOpsStub) Issue(_ context.Context, mode certificate.Mode, email, hostname string) (certificate.Metadata, error) {
	c.issued = certificate.Metadata{Mode: mode, Email: email, Hostname: hostname, State: certificate.Active}
	return c.issued, nil
}
func (c *certOpsStub) Renew(context.Context) (certificate.Metadata, error) { return c.issued, nil }
func TestTLSSettingsSaveSeparateFromIssue(t *testing.T) {
	repo := &tlsSettingsRepo{empty: true}
	ops := &certOpsStub{}
	svc := NewTLSSettingsService(repo, ops)
	if _, err := svc.Save(context.Background(), "vpn.example.net", "admin@example.net", certificate.Staging); err != nil {
		t.Fatal(err)
	}
	if ops.issued.State != "" {
		t.Fatal("save unexpectedly issued")
	}
	got, err := svc.Issue(context.Background())
	if err != nil || got.State != certificate.Active || got.Mode != certificate.Staging {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if _, err = svc.Save(context.Background(), "127.0.0.1", "bad", certificate.Production); err == nil {
		t.Fatal("invalid identity accepted")
	}
}

func TestTLSSettingsSourceIsExplicitAndPersistent(t *testing.T) {
	ctx := context.Background()
	repo := &tlsSettingsRepo{empty: true}
	svc := NewTLSSettingsService(repo, &certOpsStub{})
	got, err := svc.ConfigureInitial(ctx, certificate.Provided, "vpn.example.net", "", "/run/tls/cert.pem", "/run/tls/key.pem")
	if err != nil || got.Source != certificate.Provided || got.Mode != certificate.ManualMode {
		t.Fatalf("configured=%+v err=%v", got, err)
	}
	if _, err = svc.Save(ctx, "vpn.example.net", "admin@example.net", certificate.Production); err == nil {
		t.Fatal("ACME form silently changed the selected source")
	}
	if repo.m.Source != certificate.Provided || repo.m.ProvidedKeyPath != "/run/tls/key.pem" {
		t.Fatalf("persisted=%+v", repo.m)
	}
	got, err = svc.SaveConfiguration(ctx, certificate.LetsEncrypt, "vpn.example.net", "admin@example.net", certificate.Staging, "", "")
	if err != nil || got.Source != certificate.LetsEncrypt || got.Mode != certificate.Staging || got.State != certificate.Unconfigured {
		t.Fatalf("explicit switch=%+v err=%v", got, err)
	}
}
