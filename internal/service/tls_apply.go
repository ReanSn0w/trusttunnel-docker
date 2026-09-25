package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type TLSRepository interface {
	Snapshot(context.Context) (domain.Snapshot, error)
	ActiveRevision(context.Context) (string, error)
	SetActiveRevision(context.Context, string) error
	RecordEvent(context.Context, domain.ApplyEvent) error
}
type TLSRevisionStore interface {
	Publish(context.Context, certificate.Bundle) (certificate.Published, error)
	Rollback(context.Context) error
}
type ConfigRevisionStore interface {
	Apply(config.Files) (string, error)
	Rollback() error
}
type TLSProcess interface{ Reload(context.Context) error }
type ReadinessCheck func(context.Context) error
type AdminCertificate interface {
	Prepare(certificate.Published) (*tls.Certificate, error)
	Activate(*tls.Certificate)
}

type TLSCoordinator struct {
	mu      sync.Mutex
	repo    TLSRepository
	tls     TLSRevisionStore
	configs ConfigRevisionStore
	process TLSProcess
	ready   ReadinessCheck
	admin   AdminCertificate
	pending *tlsPublication
}

type tlsPublication struct {
	oldConfig, oldTLS, newConfig, action string
	activeUser                           bool
	adminPair                            *tls.Certificate
}

// SetAdminCertificate attaches the HTTPS listener before certificate work starts.
func (c *TLSCoordinator) SetAdminCertificate(admin AdminCertificate) { c.admin = admin }

func NewTLSCoordinator(repo TLSRepository, tls TLSRevisionStore, configs ConfigRevisionStore, process TLSProcess, ready ReadinessCheck) *TLSCoordinator {
	if ready == nil {
		ready = func(context.Context) error { return nil }
	}
	return &TLSCoordinator{repo: repo, tls: tls, configs: configs, process: process, ready: ready}
}

func (c *TLSCoordinator) Publish(ctx context.Context, bundle certificate.Bundle) (certificate.Published, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	oldConfig, err := c.repo.ActiveRevision(ctx)
	if err != nil {
		return certificate.Published{}, err
	}
	snapshot, err := c.repo.Snapshot(ctx)
	if err != nil {
		return certificate.Published{}, err
	}
	oldTLS := ""
	if snapshot.TLSCertificatePath != "" {
		oldTLS = filepath.Base(filepath.Dir(snapshot.TLSCertificatePath))
	}
	published, err := c.tls.Publish(ctx, bundle)
	if err != nil {
		return certificate.Published{}, err
	}
	rollbackTLS := true
	defer func() {
		if rollbackTLS {
			_ = c.restoreTLS(context.Background(), oldTLS)
		}
	}()
	var adminPair *tls.Certificate
	if c.admin != nil {
		adminPair, err = c.admin.Prepare(published)
		if err != nil {
			return certificate.Published{}, err
		}
	}
	snapshot.TLSCertificatePath, snapshot.TLSPrivateKeyPath = published.CertificatePath, published.PrivateKeyPath
	files, err := config.Render(snapshot)
	if err != nil {
		return certificate.Published{}, err
	}
	configRevision, err := c.configs.Apply(files)
	if err != nil {
		_ = c.restoreConfig(oldConfig)
		return certificate.Published{}, err
	}
	if err = c.repo.SetActiveRevision(ctx, configRevision); err != nil {
		_ = c.restoreConfig(oldConfig)
		return certificate.Published{}, err
	}
	// Before the first VPN user exists there is intentionally no endpoint
	// process to reload. Keep the verified certificate and rendered config; the
	// user creation path will start the endpoint with this revision later.
	activeUser := false
	for _, user := range snapshot.Users {
		if user.Status == domain.UserActive {
			activeUser = true
			break
		}
	}
	if !activeUser {
		rollbackTLS = false
		c.pending = &tlsPublication{oldConfig: oldConfig, oldTLS: oldTLS, newConfig: configRevision, action: "none", adminPair: adminPair}
		return published, nil
	}
	if err = c.process.Reload(ctx); err == nil {
		err = c.ready(ctx)
	}
	if err == nil {
		rollbackTLS = false
		c.pending = &tlsPublication{oldConfig: oldConfig, oldTLS: oldTLS, newConfig: configRevision, action: "sighup", activeUser: true, adminPair: adminPair}
		return published, nil
	}
	primaryErr := err
	configErr := c.restoreConfig(oldConfig)
	tlsErr := c.restoreTLS(ctx, oldTLS)
	rollbackTLS = false
	dbErr := c.repo.SetActiveRevision(ctx, oldConfig)
	reloadErr := c.process.Reload(ctx)
	var readyErr error
	if reloadErr == nil {
		readyErr = c.ready(ctx)
	}
	_ = c.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: configRevision, Kind: "tls", Action: "sighup", Result: "rollback", Error: sanitizeError(primaryErr)})
	if errors.Join(configErr, tlsErr, dbErr, reloadErr, readyErr) != nil {
		return certificate.Published{}, fmt.Errorf("TLS reload failed: %w; rollback config=%v tls=%v db=%v reload=%v ready=%v", primaryErr, configErr, tlsErr, dbErr, reloadErr, readyErr)
	}
	return certificate.Published{}, fmt.Errorf("TLS reload failed and was rolled back: %w", primaryErr)
}

// RevertLast restores both published revisions when metadata persistence fails.
// The caller holds the shared apply lock until this returns.
func (c *TLSCoordinator) RevertLast(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		return errors.New("no pending TLS publication")
	}
	old := *c.pending
	c.pending = nil
	configErr := c.restoreConfig(old.oldConfig)
	tlsErr := c.restoreTLS(ctx, old.oldTLS)
	dbErr := c.repo.SetActiveRevision(ctx, old.oldConfig)
	var processErr error
	if old.activeUser && configErr == nil && tlsErr == nil && dbErr == nil {
		processErr = c.process.Reload(ctx)
		if processErr == nil {
			processErr = c.ready(ctx)
		}
	}
	_ = c.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: old.newConfig, Kind: "tls", Action: old.action, Result: "rollback", Error: "TLS metadata publication failed"})
	return errors.Join(configErr, tlsErr, dbErr, processErr)
}

func (c *TLSCoordinator) restoreConfig(revision string) error {
	if store, ok := c.configs.(interface{ Restore(string) error }); ok {
		return store.Restore(revision)
	}
	return c.configs.Rollback()
}

func (c *TLSCoordinator) restoreTLS(ctx context.Context, revision string) error {
	if store, ok := c.tls.(interface{ Restore(string) error }); ok {
		return store.Restore(revision)
	}
	return c.tls.Rollback(ctx)
}

func (c *TLSCoordinator) CompletePublished() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		if c.admin != nil {
			c.admin.Activate(c.pending.adminPair)
		}
		_ = c.repo.RecordEvent(context.Background(), domain.ApplyEvent{Revision: c.pending.newConfig, Kind: "tls", Action: c.pending.action, Result: "success"})
	}
	c.pending = nil
}
