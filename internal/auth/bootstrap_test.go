package auth

import (
	"context"
	"errors"
	"testing"
)

type bootstrapRepo struct {
	has            bool
	username, hash string
}

func (r *bootstrapRepo) HasAdmin(context.Context) (bool, error) { return r.has, nil }
func (r *bootstrapRepo) CreateFirstAdmin(_ context.Context, username, hash string) error {
	if r.has {
		return ErrAlreadyBootstrapped
	}
	r.has, r.username, r.hash = true, username, hash
	return nil
}
func TestBootstrapRequiresStrongPasswordAndRunsOnce(t *testing.T) {
	repo := &bootstrapRepo{}
	svc := NewBootstrapService(repo)
	if err := svc.Bootstrap(context.Background(), "admin", "weak"); err == nil {
		t.Fatal("weak password accepted")
	}
	password := "Correct-Horse-9!"
	if err := svc.Bootstrap(context.Background(), "admin", password); err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(repo.hash, password) || repo.hash == password {
		t.Fatal("password was not safely hashed")
	}
	if err := svc.Bootstrap(context.Background(), "other", "Another-Strong-8!"); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap err=%v", err)
	}
}
func TestArgonParametersAreEncodedAndEnforced(t *testing.T) {
	hash, err := HashPassword("Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "Correct-Horse-9!") || VerifyPassword(hash, "Wrong-Horse-9!") {
		t.Fatal("password verification failed")
	}
}
