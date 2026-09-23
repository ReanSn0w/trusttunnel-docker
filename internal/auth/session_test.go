package auth

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"
)

type sessionRepo struct {
	admin    Admin
	sessions map[string]time.Time
}

func (r *sessionRepo) AdminByUsername(_ context.Context, username string) (Admin, error) {
	if username != r.admin.Username {
		return Admin{}, sql.ErrNoRows
	}
	return r.admin, nil
}
func (r *sessionRepo) AdminByID(context.Context, int64) (Admin, error) { return r.admin, nil }
func (r *sessionRepo) CreateSession(_ context.Context, h []byte, _ int64, e time.Time) error {
	if r.sessions == nil {
		r.sessions = map[string]time.Time{}
	}
	r.sessions[string(h)] = e
	return nil
}
func (r *sessionRepo) SessionAdmin(_ context.Context, h []byte, now time.Time) (Admin, error) {
	e, ok := r.sessions[string(h)]
	if !ok || !now.Before(e) {
		return Admin{}, sql.ErrNoRows
	}
	return r.admin, nil
}
func (r *sessionRepo) DeleteSession(_ context.Context, h []byte) error {
	delete(r.sessions, string(h))
	return nil
}
func (r *sessionRepo) UpdateAdminPassword(_ context.Context, _ int64, hash string) error {
	r.admin.PasswordHash = hash
	r.sessions = map[string]time.Time{}
	return nil
}
func (r *sessionRepo) DeleteAdmin(context.Context, int64) error {
	r.admin = Admin{}
	r.sessions = map[string]time.Time{}
	return nil
}
func TestSessionLifecycleAndRotation(t *testing.T) {
	hash, _ := HashPassword("Correct-Horse-9!")
	repo := &sessionRepo{admin: Admin{ID: 1, Username: "admin", PasswordHash: hash}}
	svc := NewSessionService(repo, time.Hour)
	now := time.Unix(1000, 0)
	svc.now = func() time.Time { return now }
	if _, err := svc.Login(context.Background(), "missing", "Correct-Horse-9!"); err != ErrInvalidCredentials {
		t.Fatalf("missing err=%v", err)
	}
	sess, err := svc.Login(context.Background(), "admin", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(keySet(repo.sessions)[0]), []byte(sess.Token)) {
		t.Fatal("raw token stored")
	}
	if _, err = svc.Authenticate(context.Background(), sess.Token); err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.ChangePassword(context.Background(), sess.Token, "Correct-Horse-9!", "New-Correct-Horse-8!")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Token == sess.Token {
		t.Fatal("session was not rotated")
	}
	if _, err = svc.Authenticate(context.Background(), sess.Token); err != ErrInvalidSession {
		t.Fatalf("old session err=%v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err = svc.Authenticate(context.Background(), rotated.Token); err != ErrInvalidSession {
		t.Fatalf("expired err=%v", err)
	}
}

func TestDeleteAdminInvalidatesAllSessions(t *testing.T) {
	hash, _ := HashPassword("Correct-Horse-9!")
	repo := &sessionRepo{admin: Admin{ID: 1, Username: "admin", PasswordHash: hash}}
	svc := NewSessionService(repo, time.Hour)
	sess, err := svc.Login(context.Background(), "admin", "Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.DeleteAdmin(context.Background(), sess.Token, "Correct-Horse-9!"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Authenticate(context.Background(), sess.Token); err != ErrInvalidSession {
		t.Fatalf("session survived admin deletion: %v", err)
	}
}
func keySet(m map[string]time.Time) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
func TestLoginLimiterBoundsAndBackoff(t *testing.T) {
	l := NewLoginLimiter(time.Minute, 2)
	now := time.Unix(1, 0)
	l.now = func() time.Time { return now }
	l.Failure("1.2.3.4", "Admin")
	if ok, wait := l.Allow("1.2.3.4", "admin"); ok || wait <= 0 {
		t.Fatalf("ok=%v wait=%v", ok, wait)
	}
	now = now.Add(time.Second)
	if ok, _ := l.Allow("1.2.3.4", "admin"); !ok {
		t.Fatal("backoff did not expire")
	}
	l.Failure("2", "a")
	l.Failure("3", "b")
	if len(l.entries) > 2 {
		t.Fatalf("entries=%d", len(l.entries))
	}
}
