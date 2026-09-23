package persistence

import (
	"context"
	"path/filepath"
	"testing"

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
