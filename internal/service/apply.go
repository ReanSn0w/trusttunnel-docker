package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type RevisionStore interface {
	ActiveRevision(context.Context) (string, error)
	SetActiveRevision(context.Context, string) error
	RecordEvent(context.Context, domain.ApplyEvent) error
}

type Materializer interface {
	Apply(config.Files) (string, error)
	Rollback() error
}

type Process interface {
	Restart(context.Context, string) error
	Reload(context.Context) error
}

type ApplyManager struct {
	mu      sync.Mutex
	repo    RevisionStore
	files   Materializer
	process Process
}

func NewApplyManager(repo RevisionStore, files Materializer, process Process) *ApplyManager {
	return &ApplyManager{repo: repo, files: files, process: process}
}

func (m *ApplyManager) Apply(ctx context.Context, snapshot domain.Snapshot, action string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, err := m.repo.ActiveRevision(ctx)
	if err != nil {
		return "", err
	}
	rendered, err := config.Render(snapshot)
	if err != nil {
		return "", err
	}
	revision, err := m.files.Apply(rendered)
	if err != nil {
		return "", err
	}
	if err = m.repo.SetActiveRevision(ctx, revision); err != nil {
		_ = m.files.Rollback()
		return "", err
	}
	switch action {
	case "restart":
		err = m.process.Restart(ctx, revision)
	case "sighup":
		err = m.process.Reload(ctx)
	case "none":
	default:
		err = fmt.Errorf("unknown apply action %q", action)
	}
	if err != nil {
		fileErr := m.files.Rollback()
		dbErr := m.repo.SetActiveRevision(ctx, old)
		_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: revision, Kind: "config", Action: action, Result: "rollback", Error: sanitizeError(err)})
		if fileErr != nil || dbErr != nil {
			return "", fmt.Errorf("apply: %w; rollback files=%v db=%v", err, fileErr, dbErr)
		}
		return "", err
	}
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: revision, Kind: "config", Action: action, Result: "success"})
	return revision, nil
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
