package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
)

func TestUserChangeWaitsForTLSPublicationLock(t *testing.T) {
	ctx := context.Background()
	store, err := persistence.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.SetHostname(ctx, "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	lock := &sync.Mutex{}
	apply := NewApplyManager(store, &fakeFiles{}, &integrationProcess{})
	apply.SetApplyLock(lock)
	users := NewUserManager(store, apply)
	users.SetApplyLock(lock)
	lock.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := users.Create(ctx, "alice")
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("user change bypassed TLS lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	listed, err := store.ListUsers(ctx)
	if err != nil || len(listed) != 0 {
		t.Fatalf("user row changed during TLS publication: %+v err=%v", listed, err)
	}
	lock.Unlock()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("user change remained blocked")
	}
}

type integrationProcess struct {
	failures int
	restarts int
}

func (p *integrationProcess) Restart(context.Context, string) error {
	p.restarts++
	if p.failures > 0 {
		p.failures--
		return errors.New("injected restart failure")
	}
	return nil
}
func (p *integrationProcess) Reload(context.Context) error { return nil }
func TestUserCRUDRendersCredentialsAndRollsBack(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := persistence.Open(ctx, filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.SetHostname(ctx, "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	files, err := config.NewMaterializer(filepath.Join(root, "config"), nil)
	if err != nil {
		t.Fatal(err)
	}
	process := &integrationProcess{}
	users := NewUserManager(store, NewApplyManager(store, files, process))
	created, err := users.Create(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	active, err := files.ActiveDir()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(active, "credentials.toml"))
	if err != nil || !strings.Contains(string(data), created.Password) {
		t.Fatalf("credentials=%q err=%v", data, err)
	}
	process.failures = 1
	if err = users.Disable(ctx, created.User.ID); err == nil {
		t.Fatal("expected restart failure")
	}
	got, err := store.UserByID(ctx, created.User.ID)
	if err != nil || got.Status != domain.UserActive {
		t.Fatalf("user=%#v err=%v", got, err)
	}
	active, _ = files.ActiveDir()
	data, _ = os.ReadFile(filepath.Join(active, "credentials.toml"))
	if !strings.Contains(string(data), created.Password) {
		t.Fatal("active credentials were not rolled back")
	}
}
