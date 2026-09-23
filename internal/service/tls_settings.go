package service

import (
	"context"
	"database/sql"
	"errors"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
)

type TLSSettingsRepository interface {
	LoadTLSMetadata(context.Context) (certificate.Metadata, error)
	SaveTLSMetadata(context.Context, certificate.Metadata) error
}
type CertificateOperations interface {
	Issue(context.Context, certificate.Mode, string, string) (certificate.Metadata, error)
	Renew(context.Context) (certificate.Metadata, error)
}
type TLSSettingsService struct {
	repo TLSSettingsRepository
	cert CertificateOperations
}

func NewTLSSettingsService(repo TLSSettingsRepository, cert CertificateOperations) *TLSSettingsService {
	return &TLSSettingsService{repo: repo, cert: cert}
}
func (s *TLSSettingsService) View(ctx context.Context) (certificate.Metadata, error) {
	m, err := s.repo.LoadTLSMetadata(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return certificate.Metadata{State: certificate.Unconfigured, Mode: certificate.Production}, nil
	}
	return m, err
}
func (s *TLSSettingsService) Save(ctx context.Context, hostname, email string, mode certificate.Mode) (certificate.Metadata, error) {
	if mode != certificate.Production && mode != certificate.Staging {
		return certificate.Metadata{}, errors.New("invalid ACME mode")
	}
	if err := certificate.ValidateIdentity(email, hostname); err != nil {
		return certificate.Metadata{}, err
	}
	current, err := s.View(ctx)
	if err != nil {
		return current, err
	}
	if current.State == certificate.Issuing || current.State == certificate.Renewing {
		return current, errors.New("certificate operation is in progress")
	}
	current.Hostname, current.Email, current.Mode = hostname, email, mode
	if current.State == "" {
		current.State = certificate.Unconfigured
	}
	if err = s.repo.SaveTLSMetadata(ctx, current); err != nil {
		return current, err
	}
	return current, nil
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
