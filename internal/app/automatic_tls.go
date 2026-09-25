package app

import (
	"context"
	"fmt"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/service"
)

// Startup environment seeds an empty installation; persisted UI settings win.
func seedTLS(ctx context.Context, settings *service.TLSSettingsService, cfg Config, log Logger) error {
	if cfg.TLSSource == "" && cfg.TLSHostname == "" && cfg.ACMEEmail == "" && cfg.TLSCertificateFile == "" && cfg.TLSKeyFile == "" {
		return nil
	}
	m, err := settings.View(ctx)
	if err != nil {
		return err
	}
	if m.Hostname != "" || m.ActiveRevision != "" {
		if cfg.TLSHostname != "" && cfg.TLSHostname != m.Hostname && log != nil {
			log.Logf("startup TLS hostname %q differs from persisted hostname %q; keeping persisted settings", cfg.TLSHostname, m.Hostname)
		}
		if cfg.TLSSource != "" && cfg.TLSSource != m.EffectiveSource() && log != nil {
			log.Logf("startup TLS source %q differs from persisted source %q; keeping persisted settings", cfg.TLSSource, m.EffectiveSource())
		}
		return nil
	}
	source := cfg.TLSSource
	if source == "" {
		source = certificate.LetsEncrypt // Legacy TT_TLS_HOSTNAME + TT_ACME_EMAIL setup.
	}
	if _, err = settings.ConfigureInitial(ctx, source, cfg.TLSHostname, cfg.ACMEEmail, cfg.TLSCertificateFile, cfg.TLSKeyFile); err != nil {
		return fmt.Errorf("startup TLS settings: %w", err)
	}
	return nil
}
