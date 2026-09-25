package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	qrcode "github.com/skip2/go-qrcode"
)

type ClientUserRepository interface {
	UserByID(context.Context, int64) (domain.VPNUser, error)
	Snapshot(context.Context) (domain.Snapshot, error)
	LoadClientProfile(context.Context) (clientprofile.Settings, error)
}
type ClientExporter interface {
	Export(context.Context, domain.VPNUser, string) (domain.ClientConfig, error)
}
type EndpointStatusProvider interface{ Status() domain.EndpointStatus }
type ClientConfigService struct {
	repo       ClientUserRepository
	exporter   ClientExporter
	process    EndpointStatusProvider
	qrTimeout  time.Duration
	maxPayload int
}

func NewClientConfigService(repo ClientUserRepository, exporter ClientExporter, process EndpointStatusProvider) *ClientConfigService {
	return &ClientConfigService{repo: repo, exporter: exporter, process: process, qrTimeout: 2 * time.Second, maxPayload: 2048}
}
func (s *ClientConfigService) Export(ctx context.Context, id int64) (domain.ClientConfig, error) {
	if s.process.Status().State != "ready" {
		return domain.ClientConfig{}, errors.New("endpoint is not ready")
	}
	user, err := s.repo.UserByID(ctx, id)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	if user.Status != domain.UserActive {
		return domain.ClientConfig{}, errors.New("client config is available only for active users")
	}
	snap, err := s.repo.Snapshot(ctx)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	profile, err := s.repo.LoadClientProfile(ctx)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	if snap.Hostname == "" {
		return domain.ClientConfig{}, errors.New("public hostname is not configured")
	}
	address, err := profile.Address(snap.Hostname)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	cfg, err := s.exporter.Export(ctx, user, address)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	return clientprofile.Apply(cfg, profile)
}
func (s *ClientConfigService) QR(ctx context.Context, id int64, size int) ([]byte, error) {
	if size < 128 || size > 512 {
		return nil, errors.New("QR size must be between 128 and 512")
	}
	cfg, err := s.Export(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(cfg.DeepLink) > s.maxPayload {
		return nil, errors.New("QR payload exceeds limit")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.qrTimeout)
	defer cancel()
	result := make(chan struct {
		png []byte
		err error
	}, 1)
	go func() {
		png, e := qrcode.Encode(cfg.DeepLink, qrcode.Medium, size)
		result <- struct {
			png []byte
			err error
		}{png, e}
	}()
	select {
	case <-opCtx.Done():
		return nil, fmt.Errorf("QR generation timeout: %w", opCtx.Err())
	case out := <-result:
		return out.png, out.err
	}
}
