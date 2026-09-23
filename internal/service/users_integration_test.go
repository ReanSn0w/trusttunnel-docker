package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
)

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
