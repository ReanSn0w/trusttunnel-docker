package persistence

import (
	"context"
	"database/sql"
	"fmt"
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
	p.PublicAddress = "vpn.example.com:1443"
	p.AntiDPI = true
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
