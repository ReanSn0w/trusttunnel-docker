package service

import (
	"context"
	"errors"
	"fmt"
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

type TLSCoordinator struct {
	mu      sync.Mutex
	repo    TLSRepository
	tls     TLSRevisionStore
	configs ConfigRevisionStore
	process TLSProcess
	ready   ReadinessCheck
}

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
	published, err := c.tls.Publish(ctx, bundle)
	if err != nil {
		return certificate.Published{}, err
	}
	rollbackTLS := true
	defer func() {
		if rollbackTLS {
			_ = c.tls.Rollback(context.Background())
		}
	}()
	snapshot.TLSCertificatePath, snapshot.TLSPrivateKeyPath = published.CertificatePath, published.PrivateKeyPath
	files, err := config.Render(snapshot)
	if err != nil {
		return certificate.Published{}, err
	}
	configRevision, err := c.configs.Apply(files)
	if err != nil {
		return certificate.Published{}, err
	}
	if err = c.repo.SetActiveRevision(ctx, configRevision); err != nil {
		_ = c.configs.Rollback()
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
		_ = c.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: configRevision, Kind: "tls", Action: "deferred", Result: "success"})
		return published, nil
	}
	if err = c.process.Reload(ctx); err == nil {
		err = c.ready(ctx)
	}
	if err == nil {
		rollbackTLS = false
		_ = c.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: configRevision, Kind: "tls", Action: "sighup", Result: "success"})
		return published, nil
	}
	primaryErr := err
	configErr := c.configs.Rollback()
	tlsErr := c.tls.Rollback(ctx)
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
