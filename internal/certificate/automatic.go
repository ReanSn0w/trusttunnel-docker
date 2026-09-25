package certificate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"
)

// Ensure serializes background work with manual issue/renew/import operations.
// It re-reads metadata under the manager lock, so a concurrent successful issue
// is never followed by an unnecessary order from a stale scheduler snapshot.
func (m *Manager) Ensure(ctx context.Context, lead time.Duration) (Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.repo.LoadTLSMetadata(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, nil
	}
	if err != nil {
		return current, err
	}
	if current.Mode == ManualMode || current.Hostname == "" || current.Email == "" {
		return current, nil
	}
	if err = ValidateIdentity(current.Email, current.Hostname); err != nil {
		return current, err
	}
	// No operation can still be running after we acquired the lock. These states
	// therefore represent an interrupted operation from a previous process.
	if current.State == Issuing || current.State == Renewing {
		current.State = Degraded
		if err = m.repo.SaveTLSMetadata(ctx, current); err != nil {
			return current, err
		}
	}
	chain, certErr := os.ReadFile(current.CertificatePath)
	key, keyErr := os.ReadFile(current.PrivateKeyPath)
	if certErr == nil && keyErr == nil && current.ActiveRevision != "" {
		leaf, validationErr := ValidateBundle(Bundle{Certificate: chain, PrivateKey: key}, current.Hostname, current.Mode, m.now())
		if validationErr == nil {
			if lead <= 0 {
				lead = 30 * 24 * time.Hour
			}
			// Avoid continuously renewing certificates whose lifetime is shorter
			// than the configured lead (for example short-lived ACME certificates).
			if third := leaf.NotAfter.Sub(leaf.NotBefore) / 3; lead > third {
				lead = third
			}
			if m.now().Before(leaf.NotAfter.Add(-lead)) {
				if current.State != Active {
					current.State = Active
					current.LastError = ""
					if err = m.repo.SaveTLSMetadata(ctx, current); err != nil {
						return current, err
					}
				}
				return current, nil
			}
		}
	}
	if current.State == Unconfigured || current.ActiveRevision == "" {
		if current.State != Unconfigured && current.State != Degraded {
			current.State = Degraded
			if err = m.repo.SaveTLSMetadata(ctx, current); err != nil {
				return current, err
			}
		}
		return m.issue(ctx, current.Mode, current.Email, current.Hostname)
	}
	return m.renew(ctx)
}

// NewAutomaticScheduler handles initial issuance and renewal in the same worker.
// Polling also picks up settings saved in the UI without restarting the app.
func NewAutomaticScheduler(repo MetadataRepository, ensure RenewFunc, logf func(string, ...interface{})) *Scheduler {
	s := NewScheduler(repo, ensure, 0)
	s.automatic = true
	s.logf = logf
	return s
}

func (s *Scheduler) runAutomatic(ctx context.Context) {
	attempt := 0
	for ctx.Err() == nil {
		_, err := s.renew(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := 30 * time.Second
		if err != nil {
			delay = Backoff(attempt, s.baseBackoff, s.maxBackoff)
			attempt++
			if s.logf != nil {
				s.logf("automatic TLS failed; retry in %s: %s", delay, sanitizeCertificateError(err))
			}
		} else {
			attempt = 0
		}
		if !waitScheduler(ctx, delay) {
			return
		}
	}
}
