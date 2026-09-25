package app

import (
	"context"
	"fmt"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/service"
)

// Startup environment seeds an empty installation; persisted UI settings win.
func seedTLS(ctx context.Context, settings *service.TLSSettingsService, cfg Config) error {
	if cfg.TLSHostname == "" && cfg.ACMEEmail == "" {
		return nil
	}
	if err := certificate.ValidateIdentity(cfg.ACMEEmail, cfg.TLSHostname); err != nil {
		return fmt.Errorf("startup TLS identity: %w", err)
	}
	m, err := settings.View(ctx)
	if err != nil {
		return err
	}
	if m.Hostname != "" || m.Email != "" {
		return nil
	}
	_, err = settings.Save(ctx, cfg.TLSHostname, cfg.ACMEEmail, m.Mode)
	return err
}
