package service

import (
	"context"
	"errors"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
)

type Actor struct {
	AdminID     int64
	SessionHash string
}
type CertificateAuthorizer interface {
	AuthorizeCertificateManagement(context.Context, Actor) error
}
type ManualCertificateImporter interface {
	ImportManual(context.Context, string, []byte, []byte) (certificate.Metadata, error)
}

type CertificateService struct {
	authorizer CertificateAuthorizer
	manager    ManualCertificateImporter
}

func NewCertificateService(authorizer CertificateAuthorizer, manager ManualCertificateImporter) *CertificateService {
	return &CertificateService{authorizer: authorizer, manager: manager}
}
func (s *CertificateService) ImportManual(ctx context.Context, actor Actor, hostname string, chain, privateKey []byte) (certificate.Metadata, error) {
	if s.authorizer == nil || s.manager == nil {
		return certificate.Metadata{}, errors.New("certificate service is not configured")
	}
	if err := s.authorizer.AuthorizeCertificateManagement(ctx, actor); err != nil {
		return certificate.Metadata{}, err
	}
	return s.manager.ImportManual(ctx, hostname, chain, privateKey)
}
