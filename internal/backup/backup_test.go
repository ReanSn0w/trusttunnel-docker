package backup

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateVerifyAndRestore(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := persistence.Open(context.Background(), filepath.Join(source, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetHostname(context.Background(), "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	if err = store.UpsertUser(context.Background(), domain.VPNUser{Username: "alice", Credential: "secret-password", Status: domain.UserActive}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if err = os.MkdirAll(filepath.Join(source, "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "acme", "account.key"), []byte("private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.tar.gz")
	versions := Versions{Controller: "v1.0.0", Commit: "abc", Endpoint: "1.1.0"}
	if err = Create(context.Background(), source, archive, versions); err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(archive)
	if err != nil || manifest.Versions != versions {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	target := filepath.Join(root, "restore")
	manifest, err = Restore(archive, target)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := persistence.Open(context.Background(), filepath.Join(target, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := restored.Snapshot(context.Background())
	restored.Close()
	if err != nil || len(snapshot.Users) != 1 || snapshot.Users[0].Credential != "secret-password" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	info, err := os.Stat(filepath.Join(target, "acme", "account.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
}
