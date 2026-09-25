package service

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
)

type TLSSettingsRepository interface {
	LoadTLSMetadata(context.Context) (certificate.Metadata, error)
	SaveTLSMetadata(context.Context, certificate.Metadata) error
	SetHostname(context.Context, string) error
}
type CertificateOperations interface {
	Issue(context.Context, certificate.Mode, string, string) (certificate.Metadata, error)
	Renew(context.Context) (certificate.Metadata, error)
}
type TLSSettingsService struct {
	repo        TLSSettingsRepository
	cert        CertificateOperations
	defaultMode certificate.Mode
}

func NewTLSSettingsService(repo TLSSettingsRepository, cert CertificateOperations) *TLSSettingsService {
	return &TLSSettingsService{repo: repo, cert: cert, defaultMode: certificate.Production}
}
func NewTLSSettingsServiceWithMode(repo TLSSettingsRepository, cert CertificateOperations, mode certificate.Mode) *TLSSettingsService {
	s := NewTLSSettingsService(repo, cert)
	if mode == certificate.Staging {
		s.defaultMode = mode
	}
	return s
}
func (s *TLSSettingsService) View(ctx context.Context) (certificate.Metadata, error) {
	m, err := s.repo.LoadTLSMetadata(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return certificate.Metadata{State: certificate.Unconfigured, Source: certificate.LetsEncrypt, Mode: s.defaultMode}, nil
	}
	return m, err
}
func (s *TLSSettingsService) Save(ctx context.Context, hostname, email string, mode certificate.Mode) (certificate.Metadata, error) {
	current, err := s.View(ctx)
	if err != nil {
		return current, err
	}
	if current.EffectiveSource() != certificate.LetsEncrypt {
		return current, errors.New("changing TLS source requires an explicit selection")
	}
	return s.SaveConfiguration(ctx, certificate.LetsEncrypt, hostname, email, mode, "", "")
}

func (s *TLSSettingsService) SaveConfiguration(ctx context.Context, source certificate.Source, hostname, email string, mode certificate.Mode, certificatePath, keyPath string) (certificate.Metadata, error) {
	if err := certificate.ValidateSourceSettings(source, hostname, email, certificatePath, keyPath); err != nil {
		return certificate.Metadata{}, err
	}
	if source == certificate.LetsEncrypt && mode != certificate.Production && mode != certificate.Staging {
		return certificate.Metadata{}, errors.New("invalid ACME mode")
	}
	var current certificate.Metadata
	var err error
	if serializer, ok := s.cert.(interface{ Serialize(func() error) error }); ok {
		err = serializer.Serialize(func() error {
			current, err = s.save(ctx, source, hostname, email, mode, certificatePath, keyPath)
			return err
		})
		return current, err
	}
	return s.save(ctx, source, hostname, email, mode, certificatePath, keyPath)
}

func (s *TLSSettingsService) save(ctx context.Context, source certificate.Source, hostname, email string, mode certificate.Mode, certificatePath, keyPath string) (certificate.Metadata, error) {
	current, err := s.View(ctx)
	if err != nil {
		return current, err
	}
	if current.State == certificate.Issuing || current.State == certificate.Renewing {
		return current, errors.New("certificate operation is in progress")
	}
	if current.EffectiveSource() != source || current.Hostname != hostname || current.ProvidedCertificatePath != certificatePath || current.ProvidedKeyPath != keyPath {
		current.State = certificate.Unconfigured
	}
	current.Hostname, current.Email, current.Source = hostname, email, source
	current.ProvidedCertificatePath, current.ProvidedKeyPath = certificatePath, keyPath
	if source == certificate.LetsEncrypt {
		current.Mode = mode
	} else {
		current.Mode = certificate.ManualMode
	}
	if current.State == "" {
		current.State = certificate.Unconfigured
	}
	if err = s.repo.SaveTLSMetadata(ctx, current); err != nil {
		return current, err
	}
	if err = s.repo.SetHostname(ctx, hostname); err != nil {
		return current, err
	}
	return current, nil
}

// ConfigureInitial records the source only for a fresh installation.
func (s *TLSSettingsService) ConfigureInitial(ctx context.Context, source certificate.Source, hostname, email, certificatePath, keyPath string) (certificate.Metadata, error) {
	if err := certificate.ValidateSourceSettings(source, hostname, email, certificatePath, keyPath); err != nil {
		return certificate.Metadata{}, err
	}
	configure := func() (certificate.Metadata, error) {
		current, err := s.View(ctx)
		if err != nil {
			return current, err
		}
		if current.Hostname != "" || current.ActiveRevision != "" {
			return current, errors.New("TLS source is already configured")
		}
		current.Source = source
		current.Hostname = hostname
		current.Email = email
		current.ProvidedCertificatePath = certificatePath
		current.ProvidedKeyPath = keyPath
		if source == certificate.Provided || source == certificate.SelfSigned {
			current.Mode = certificate.ManualMode
		}
		if err = s.repo.SaveTLSMetadata(ctx, current); err != nil {
			return current, err
		}
		if err = s.repo.SetHostname(ctx, hostname); err != nil {
			return current, err
		}
		return current, nil
	}
	if serializer, ok := s.cert.(interface{ Serialize(func() error) error }); ok {
		var current certificate.Metadata
		err := serializer.Serialize(func() error {
			var inner error
			current, inner = configure()
			return inner
		})
		return current, err
	}
	return configure()
}
func (s *TLSSettingsService) Issue(ctx context.Context) (certificate.Metadata, error) {
	current, err := s.View(ctx)
	if err != nil {
		return current, err
	}
	if current.Hostname == "" || current.Email == "" {
		return current, errors.New("save hostname and email before issue")
	}
	return s.cert.Issue(ctx, current.Mode, current.Email, current.Hostname)
}
func (s *TLSSettingsService) Renew(ctx context.Context) (certificate.Metadata, error) {
	return s.cert.Renew(ctx)
}

func (s *TLSSettingsService) PublicSelfSignedCertificate(ctx context.Context) ([]byte, error) {
	m, err := s.View(ctx)
	if err != nil {
		return nil, err
	}
	if m.EffectiveSource() != certificate.SelfSigned || m.State != certificate.Active || m.ActiveRevision == "" || m.CertificatePath == "" {
		return nil, errors.New("self-signed certificate is not available")
	}
	data, err := os.ReadFile(m.CertificatePath)
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("certificate is too large")
	}
	return data, nil
}
