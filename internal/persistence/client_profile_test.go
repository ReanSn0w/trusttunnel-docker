package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"path/filepath"
	"testing"
)

func TestClientProfileMigrationFromV3(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations[:3] {
		if _, err = db.ExecContext(ctx, m); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", i+1, "2026-09-24T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO vpn_users(username,credential,status,created_at,updated_at) VALUES('existing','preserve','active','','')`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO tls_certificate(id,state,mode,hostname,active_revision,certificate_path,private_key_path,updated_at) VALUES(1,'manual','manual','vpn.example.com','tls-v3','/data/cert.pem','/data/key.pem','2026-09-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.LoadClientProfile(ctx)
	if err != nil || p != clientprofile.Default() {
		t.Fatal(fmt.Sprintf("profile=%+v err=%v", p, err))
	}
	u, err := s.UserByID(ctx, 1)
	if err != nil || u.Credential != "preserve" {
		t.Fatal("migration lost user")
	}
	m, err := s.LoadTLSMetadata(ctx)
	if err != nil || m.Source != certificate.Provided || m.State != certificate.Active || m.ActiveRevision != "tls-v3" || m.CertificatePath != "/data/cert.pem" || m.PrivateKeyPath != "/data/key.pem" {
		t.Fatalf("migration lost TLS metadata: %+v err=%v", m, err)
	}
}

func TestClientProfilePersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.LoadClientProfile(ctx)
	if err != nil || p != clientprofile.Default() {
		t.Fatalf("defaults=%+v err=%v", p, err)
	}
	p.PublicAddress = "127.0.0.1:18443"
	p.AntiDPI = true
	p.IPv6 = false
	p.TLSProfile = "safari"
	p.PostQuantum = false
	if err = s.SaveClientProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.LoadClientProfile(ctx)
	if err != nil || got != p {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if address, err := got.Address("vpn.example.com"); err != nil || address != "127.0.0.1:18443" {
		t.Fatalf("manual smoke address=%q err=%v", address, err)
	}
	invalid := p
	invalid.Protocol = "http3"
	if s.SaveClientProfile(ctx, invalid) == nil {
		t.Fatal("invalid settings saved")
	}
	got, err = s.LoadClientProfile(ctx)
	if err != nil || got != p {
		t.Fatal("invalid save changed settings")
	}
}
