package service

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func ClassifyChange(before, after domain.Snapshot) string {
	if reflect.DeepEqual(before, after) {
		return "none"
	}
	baseBefore, baseAfter := before, after
	baseBefore.TLSCertificatePath, baseBefore.TLSPrivateKeyPath = "", ""
	baseAfter.TLSCertificatePath, baseAfter.TLSPrivateKeyPath = "", ""
	if reflect.DeepEqual(baseBefore, baseAfter) {
		return "sighup"
	}
	return "restart"
}

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
	mu      *sync.Mutex
	repo    RevisionStore
	files   Materializer
	process Process
}

func NewApplyManager(repo RevisionStore, files Materializer, process Process) *ApplyManager {
	return &ApplyManager{mu: &sync.Mutex{}, repo: repo, files: files, process: process}
}

func (m *ApplyManager) SetApplyLock(lock *sync.Mutex) { m.mu = lock }

// ApplyCurrent reads the snapshot while holding the publication lock.
func (m *ApplyManager) ApplyCurrent(ctx context.Context, action string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ApplyCurrentLocked(ctx, action)
}

func (m *ApplyManager) ApplyCurrentLocked(ctx context.Context, action string) (string, error) {
	repo, ok := m.repo.(interface {
		Snapshot(context.Context) (domain.Snapshot, error)
	})
	if !ok {
		return "", fmt.Errorf("current snapshot is unavailable")
	}
	snapshot, err := repo.Snapshot(ctx)
	if err != nil {
		return "", err
	}
	return m.apply(ctx, snapshot, action)
}

func (m *ApplyManager) Apply(ctx context.Context, snapshot domain.Snapshot, action string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apply(ctx, snapshot, action)
}

func (m *ApplyManager) apply(ctx context.Context, snapshot domain.Snapshot, action string) (string, error) {
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
		var processErr error
		if action == "restart" {
			processErr = m.process.Restart(ctx, old)
		} else if action == "sighup" {
			processErr = m.process.Reload(ctx)
		}
		_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: revision, Kind: "config", Action: action, Result: "rollback", Error: sanitizeError(err)})
		if fileErr != nil || dbErr != nil || processErr != nil {
			return "", fmt.Errorf("apply: %w; rollback files=%v db=%v process=%v", err, fileErr, dbErr, processErr)
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
	for _, marker := range []string{"-----BEGIN", "tt://", "/.well-known/acme-challenge/"} {
		if i := strings.Index(s, marker); i >= 0 {
			s = s[:i] + "[REDACTED]"
		}
	}
	secretAssignment := regexp.MustCompile(`(?i)(password|token|credential|cookie|csrf|keyauth)(\s*[:=]\s*)\S+`)
	s = secretAssignment.ReplaceAllString(s, `$1$2[REDACTED]`)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
