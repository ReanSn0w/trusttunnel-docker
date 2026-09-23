package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

var ErrInvalidCredentials = errors.New("invalid username or password")
var ErrInvalidSession = errors.New("invalid or expired session")

type Admin struct {
	ID                     int64
	Username, PasswordHash string
}
type Session struct {
	Token     string
	Admin     Admin
	ExpiresAt time.Time
}
type SessionRepository interface {
	AdminByUsername(context.Context, string) (Admin, error)
	AdminByID(context.Context, int64) (Admin, error)
	CreateSession(context.Context, []byte, int64, time.Time) error
	SessionAdmin(context.Context, []byte, time.Time) (Admin, error)
	DeleteSession(context.Context, []byte) error
	UpdateAdminPassword(context.Context, int64, string) error
	DeleteAdmin(context.Context, int64) error
}
type SessionService struct {
	repo      SessionRepository
	lifetime  time.Duration
	now       func() time.Time
	dummyHash string
}

func NewSessionService(repo SessionRepository, lifetime time.Duration) *SessionService {
	if lifetime <= 0 {
		lifetime = 12 * time.Hour
	}
	dummy, err := HashPassword("Timing-Equalizer-9!")
	if err != nil {
		panic(err)
	}
	return &SessionService{repo: repo, lifetime: lifetime, now: time.Now, dummyHash: dummy}
}
func tokenHash(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }
func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func (s *SessionService) Login(ctx context.Context, username, password string) (Session, error) {
	admin, err := s.repo.AdminByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		_ = VerifyPassword(s.dummyHash, password)
		return Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, err
	}
	if !VerifyPassword(admin.PasswordHash, password) {
		return Session{}, ErrInvalidCredentials
	}
	return s.create(ctx, admin)
}
func (s *SessionService) create(ctx context.Context, admin Admin) (Session, error) {
	token, err := newToken()
	if err != nil {
		return Session{}, err
	}
	expires := s.now().UTC().Add(s.lifetime)
	if err = s.repo.CreateSession(ctx, tokenHash(token), admin.ID, expires); err != nil {
		return Session{}, err
	}
	return Session{Token: token, Admin: admin, ExpiresAt: expires}, nil
}
func (s *SessionService) Authenticate(ctx context.Context, token string) (Admin, error) {
	if token == "" {
		return Admin{}, ErrInvalidSession
	}
	admin, err := s.repo.SessionAdmin(ctx, tokenHash(token), s.now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, ErrInvalidSession
	}
	return admin, err
}
func (s *SessionService) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.repo.DeleteSession(ctx, tokenHash(token))
}
func (s *SessionService) ChangePassword(ctx context.Context, token, current, next string) (Session, error) {
	admin, err := s.Authenticate(ctx, token)
	if err != nil {
		return Session{}, err
	}
	if !VerifyPassword(admin.PasswordHash, current) {
		return Session{}, ErrInvalidCredentials
	}
	hash, err := HashPassword(next)
	if err != nil {
		return Session{}, err
	}
	if err = s.repo.UpdateAdminPassword(ctx, admin.ID, hash); err != nil {
		return Session{}, err
	}
	admin.PasswordHash = hash
	return s.create(ctx, admin)
}
func (s *SessionService) DeleteAdmin(ctx context.Context, token, password string) error {
	admin, err := s.Authenticate(ctx, token)
	if err != nil {
		return err
	}
	if !VerifyPassword(admin.PasswordHash, password) {
		return ErrInvalidCredentials
	}
	return s.repo.DeleteAdmin(ctx, admin.ID)
}
