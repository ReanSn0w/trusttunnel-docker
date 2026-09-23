package auth

import (
	"context"
	"errors"
	"strings"
)

var ErrAlreadyBootstrapped = errors.New("administrator already exists")

type BootstrapRepository interface {
	HasAdmin(context.Context) (bool, error)
	CreateFirstAdmin(context.Context, string, string) error
}
type BootstrapService struct{ repo BootstrapRepository }

func NewBootstrapService(repo BootstrapRepository) *BootstrapService {
	return &BootstrapService{repo: repo}
}
func (s *BootstrapService) Required(ctx context.Context) (bool, error) {
	has, err := s.repo.HasAdmin(ctx)
	return !has, err
}
func (s *BootstrapService) Bootstrap(ctx context.Context, username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 {
		return errors.New("administrator username must contain 3 to 64 characters")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.repo.CreateFirstAdmin(ctx, username, hash)
}
