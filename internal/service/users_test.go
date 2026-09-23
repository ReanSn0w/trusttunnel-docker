package service

import (
	"context"
	"database/sql"
	"errors"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"testing"
)

type userRepoStub struct {
	users map[int64]domain.VPNUser
	next  int64
}

func (r *userRepoStub) Snapshot(context.Context) (domain.Snapshot, error) {
	s := domain.Snapshot{Hostname: "vpn.example.net", ListenAddress: "0.0.0.0:8443"}
	for _, u := range r.users {
		s.Users = append(s.Users, u)
	}
	return s, nil
}
func (r *userRepoStub) ListUsers(context.Context) ([]domain.VPNUser, error) {
	s, _ := r.Snapshot(context.Background())
	return s.Users, nil
}
func (r *userRepoStub) UserByID(_ context.Context, id int64) (domain.VPNUser, error) {
	u, ok := r.users[id]
	if !ok {
		return u, sql.ErrNoRows
	}
	return u, nil
}
func (r *userRepoStub) InsertUser(_ context.Context, u domain.VPNUser) (int64, error) {
	r.next++
	u.ID = r.next
	r.users[u.ID] = u
	return u.ID, nil
}
func (r *userRepoStub) UpdateUser(_ context.Context, u domain.VPNUser) error {
	r.users[u.ID] = u
	return nil
}
func (r *userRepoStub) DeleteUser(_ context.Context, id int64) error { delete(r.users, id); return nil }

type applyStub struct {
	err   error
	calls int
}

func (a *applyStub) Apply(context.Context, domain.Snapshot, string) (string, error) {
	a.calls++
	return "r", a.err
}
func TestUserManagerLifecycleAndRollback(t *testing.T) {
	repo := &userRepoStub{users: map[int64]domain.VPNUser{}}
	apply := &applyStub{}
	m := NewUserManager(repo, apply)
	created, err := m.Create(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if created.Password == "" || repo.users[created.User.ID].Credential != created.Password {
		t.Fatal("credential not returned once")
	}
	if err = m.Disable(context.Background(), created.User.ID); err != nil {
		t.Fatal(err)
	}
	if repo.users[created.User.ID].Status != domain.UserDisabled {
		t.Fatal("not disabled")
	}
	apply.err = errors.New("restart failed")
	if err = m.Enable(context.Background(), created.User.ID); err == nil {
		t.Fatal("expected apply failure")
	}
	if repo.users[created.User.ID].Status != domain.UserDisabled {
		t.Fatal("database was not rolled back")
	}
	apply.err = nil
	if err = m.Revoke(context.Background(), created.User.ID); err != nil {
		t.Fatal(err)
	}
	if err = m.Enable(context.Background(), created.User.ID); !errors.Is(err, ErrRevokedUser) {
		t.Fatalf("err=%v", err)
	}
}
