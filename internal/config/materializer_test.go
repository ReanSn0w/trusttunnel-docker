package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializerApplyIdempotentAndRollback(t *testing.T) {
	root := t.TempDir()
	m, err := NewMaterializer(root, func(dir string) error {
		if _, err := os.Stat(filepath.Join(dir, "vpn.toml")); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.Apply(Files{"vpn.toml": []byte("one"), "credentials.toml": []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	again, err := m.Apply(Files{"credentials.toml": []byte("secret"), "vpn.toml": []byte("one")})
	if err != nil || first != again {
		t.Fatalf("idempotence: %s %s %v", first, again, err)
	}
	active, _ := m.ActiveDir()
	info, err := os.Stat(filepath.Join(active, "credentials.toml"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential permissions=%v err=%v", info.Mode().Perm(), err)
	}
	second, err := m.Apply(Files{"vpn.toml": []byte("two"), "credentials.toml": []byte("secret")})
	if err != nil || second == first {
		t.Fatalf("second revision=%s err=%v", second, err)
	}
	if err = m.Rollback(); err != nil {
		t.Fatal(err)
	}
	active, _ = m.ActiveDir()
	if filepath.Base(active) != first {
		t.Fatalf("rollback active=%s want=%s", filepath.Base(active), first)
	}
}

func TestMaterializerDoesNotPublishInvalidStage(t *testing.T) {
	m, err := NewMaterializer(t.TempDir(), func(string) error { return errors.New("invalid") })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Apply(Files{"vpn.toml": []byte("bad")}); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err = m.ActiveDir(); err == nil {
		t.Fatal("invalid revision became active")
	}
}

func TestMaterializerDiskFullAndCrashBeforeRename(t *testing.T) {
	for name, inject := range map[string]func(*Materializer){
		"disk-full": func(m *Materializer) {
			m.writeFile = func(string, []byte, os.FileMode) error { return errors.New("no space left on device") }
		},
		"crash-before-rename": func(m *Materializer) { m.beforeRename = func() error { return errors.New("injected crash") } },
	} {
		t.Run(name, func(t *testing.T) {
			m, err := NewMaterializer(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			inject(m)
			if _, err = m.Apply(Files{"vpn.toml": []byte("safe")}); err == nil {
				t.Fatal("expected injected error")
			}
			if _, err = m.ActiveDir(); err == nil {
				t.Fatal("partial revision became active")
			}
		})
	}
}
