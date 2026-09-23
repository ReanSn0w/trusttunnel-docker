package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

var userNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var ErrRevokedUser = errors.New("revoked user cannot be changed")

type UserRepository interface {
	Snapshot(context.Context) (domain.Snapshot, error)
	ListUsers(context.Context) ([]domain.VPNUser, error)
	UserByID(context.Context, int64) (domain.VPNUser, error)
	InsertUser(context.Context, domain.VPNUser) (int64, error)
	UpdateUser(context.Context, domain.VPNUser) error
	DeleteUser(context.Context, int64) error
}
type SnapshotApplier interface {
	Apply(context.Context, domain.Snapshot, string) (string, error)
}
type UserManager struct {
	mu    sync.Mutex
	repo  UserRepository
	apply SnapshotApplier
}
type CreatedUser struct {
	User     domain.VPNUser
	Password string
}

func NewUserManager(repo UserRepository, apply SnapshotApplier) *UserManager {
	return &UserManager{repo: repo, apply: apply}
}
func (m *UserManager) List(ctx context.Context) ([]domain.VPNUser, error) {
	users, err := m.repo.ListUsers(ctx)
	for i := range users {
		users[i].Credential = ""
	}
	return users, err
}
func (m *UserManager) Create(ctx context.Context, username string) (CreatedUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !userNameRE.MatchString(username) {
		return CreatedUser{}, errors.New("invalid username")
	}
	password, err := randomCredential()
	if err != nil {
		return CreatedUser{}, err
	}
	user := domain.VPNUser{Username: username, Credential: password, Status: domain.UserActive}
	id, err := m.repo.InsertUser(ctx, user)
	if err != nil {
		return CreatedUser{}, err
	}
	user.ID = id
	if err = m.applyCurrent(ctx); err != nil {
		_ = m.repo.DeleteUser(context.Background(), id)
		return CreatedUser{}, err
	}
	safe := user
	safe.Credential = ""
	return CreatedUser{User: safe, Password: password}, nil
}
func (m *UserManager) Enable(ctx context.Context, id int64) error {
	return m.mutate(ctx, id, func(u *domain.VPNUser) error {
		if u.Status == domain.UserRevoked {
			return ErrRevokedUser
		}
		u.Status = domain.UserActive
		return nil
	})
}
func (m *UserManager) Disable(ctx context.Context, id int64) error {
	return m.mutate(ctx, id, func(u *domain.VPNUser) error {
		if u.Status == domain.UserRevoked {
			return ErrRevokedUser
		}
		u.Status = domain.UserDisabled
		return nil
	})
}
func (m *UserManager) Revoke(ctx context.Context, id int64) error {
	return m.mutate(ctx, id, func(u *domain.VPNUser) error {
		if u.Status == domain.UserRevoked {
			return ErrRevokedUser
		}
		u.Status = domain.UserRevoked
		u.Credential = "revoked-credential-not-exported"
		return nil
	})
}
func (m *UserManager) Rotate(ctx context.Context, id int64) (string, error) {
	var password string
	err := m.mutate(ctx, id, func(u *domain.VPNUser) error {
		if u.Status != domain.UserActive {
			return errors.New("only active users can rotate credentials")
		}
		var e error
		password, e = randomCredential()
		if e == nil {
			u.Credential = password
		}
		return e
	})
	return password, err
}
func (m *UserManager) mutate(ctx context.Context, id int64, change func(*domain.VPNUser) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	before, err := m.repo.UserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("user not found")
	}
	if err != nil {
		return err
	}
	after := before
	if err = change(&after); err != nil {
		return err
	}
	if err = m.repo.UpdateUser(ctx, after); err != nil {
		return err
	}
	if err = m.applyCurrent(ctx); err != nil {
		_ = m.repo.UpdateUser(context.Background(), before)
		return err
	}
	return nil
}
func (m *UserManager) applyCurrent(ctx context.Context) error {
	snap, err := m.repo.Snapshot(ctx)
	if err != nil {
		return err
	}
	_, err = m.apply.Apply(ctx, snap, "restart")
	return err
}
func randomCredential() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
