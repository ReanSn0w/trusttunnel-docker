package persistence

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func TestMigrationsBootstrapAndRepository(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	version, err := store.SchemaVersion(ctx)
	if err != nil || version != schemaVersion {
		t.Fatalf("version=%d err=%v", version, err)
	}
	if err = store.UpsertUser(ctx, domain.VPNUser{Username: "alice", Credential: "secret", Status: domain.UserActive}); err != nil {
		t.Fatal(err)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ListenAddress != "0.0.0.0:8443" || len(snap.Users) != 1 || snap.Users[0].Username != "alice" {
		t.Fatalf("unexpected snapshot: %#v", snap)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("idempotent reopen: %v", err)
	}
	defer store.Close()
	if version, err = store.SchemaVersion(ctx); err != nil || version != schemaVersion {
		t.Fatalf("version after reopen=%d err=%v", version, err)
	}
}

func TestTLSPersistenceStoresMetadataNotKeyMaterial(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	want := certificate.Metadata{State: certificate.Active, Mode: certificate.Staging, Hostname: "vpn.example.com", Email: "admin@example.com", Serial: "123", Issuer: "Test CA", SANs: []string{"vpn.example.com"}, NotBefore: time.Now().UTC().Truncate(time.Second), NotAfter: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second), Fingerprint: "abc", ActiveRevision: "r1"}
	if err = store.SaveACMEAccount(ctx, "https://acme.invalid/directory", want.Email, "registration", "active", ""); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveTLSMetadata(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadTLSMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != want.Hostname || got.ActiveRevision != "r1" || len(got.SANs) != 1 {
		t.Fatalf("got=%#v", got)
	}
}

func TestRejectsInvalidStatus(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.UpsertUser(context.Background(), domain.VPNUser{Username: "alice", Status: "wrong"}); err == nil {
		t.Fatal("expected status error")
	}
}
