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
