package certificate

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSStorePermissionsAndRollback(t *testing.T) {
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Publish(context.Background(), makeBundle(t, "vpn.example.net", "Production CA"))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]fs.FileMode{first.CertificatePath: 0o644, first.PrivateKeyPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o want=%o", path, info.Mode().Perm(), want)
		}
	}
	if info, err := os.Stat(filepath.Dir(first.CertificatePath)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("revision dir mode=%v err=%v", info.Mode().Perm(), err)
	}
	second, err := store.Publish(context.Background(), makeBundle(t, "vpn.example.net", "Production CA 2"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision == second.Revision {
		t.Fatal("expected distinct revisions")
	}
	if err = store.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, err := store.Active()
	if err != nil || active.Revision != first.Revision {
		t.Fatalf("active=%#v err=%v", active, err)
	}
}

func TestTLSStoreFaultsNeverActivatePartialRevision(t *testing.T) {
	for name, inject := range map[string]func(*TLSStore){
		"disk-full": func(s *TLSStore) {
			s.writeFile = func(string, []byte, fs.FileMode) error { return errors.New("no space left on device") }
		},
		"crash-before-rename": func(s *TLSStore) { s.beforeRename = func() error { return errors.New("injected crash") } },
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewTLSStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			inject(store)
			if _, err = store.Publish(context.Background(), makeBundle(t, "vpn.example.net", "Production CA")); err == nil {
				t.Fatal("expected injected failure")
			}
			if _, err = store.Active(); err == nil {
				t.Fatal("partial revision activated")
			}
		})
	}
}

func TestTLSStoreRejectsMismatchedKey(t *testing.T) {
	store, _ := NewTLSStore(t.TempDir())
	bundle := makeBundle(t, "vpn.example.net", "Production CA")
	bundle.PrivateKey = makeBundle(t, "vpn.example.net", "Other CA").PrivateKey
	if _, err := store.Publish(context.Background(), bundle); err == nil {
		t.Fatal("accepted mismatched key")
	}
}
