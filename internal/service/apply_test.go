package service

import (
	"context"
	"errors"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type fakeRepo struct {
	revision string
	events   []domain.ApplyEvent
}

func (f *fakeRepo) ActiveRevision(context.Context) (string, error)      { return f.revision, nil }
func (f *fakeRepo) SetActiveRevision(_ context.Context, r string) error { f.revision = r; return nil }
func (f *fakeRepo) RecordEvent(_ context.Context, e domain.ApplyEvent) error {
	f.events = append(f.events, e)
	return nil
}

type fakeFiles struct{ rollback bool }

func (f *fakeFiles) Apply(config.Files) (string, error) { return "new", nil }
func (f *fakeFiles) Rollback() error                    { f.rollback = true; return nil }

type fakeProcess struct{ err error }

func (f fakeProcess) Restart(context.Context, string) error { return f.err }
func (f fakeProcess) Reload(context.Context) error          { return f.err }

func TestApplyRollsBackFilesAndDatabase(t *testing.T) {
	repo, files := &fakeRepo{revision: "old"}, &fakeFiles{}
	m := NewApplyManager(repo, files, fakeProcess{err: errors.New("failed to start")})
	s := domain.Snapshot{Hostname: "vpn.example.com", ListenAddress: "0.0.0.0:8443"}
	if _, err := m.Apply(context.Background(), s, "restart"); err == nil {
		t.Fatal("expected error")
	}
	if repo.revision != "old" || !files.rollback {
		t.Fatalf("rollback failed: repo=%s files=%v", repo.revision, files.rollback)
	}
	if len(repo.events) != 1 || repo.events[0].Result != "rollback" {
		t.Fatalf("missing rollback event: %#v", repo.events)
	}
}
