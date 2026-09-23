package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/service"
	"net/http/httptest"
	"strings"
	"testing"
)

type userWebStub struct{ users []domain.VPNUser }

func (s userWebStub) List(context.Context) ([]domain.VPNUser, error) { return s.users, nil }
func (s userWebStub) Create(context.Context, string) (service.CreatedUser, error) {
	return service.CreatedUser{}, nil
}
func (s userWebStub) Enable(context.Context, int64) error           { return nil }
func (s userWebStub) Disable(context.Context, int64) error          { return nil }
func (s userWebStub) Revoke(context.Context, int64) error           { return nil }
func (s userWebStub) Rotate(context.Context, int64) (string, error) { return "", nil }
func TestUsersTemplateEscapesAndNeverListsCredentials(t *testing.T) {
	h := NewUsersHandler(userWebStub{[]domain.VPNUser{{ID: 1, Username: "<script>alert(1)</script>", Credential: "never-show-this", Status: domain.UserActive}}})
	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest("GET", "/users", nil))
	body := w.Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "never-show-this") {
		t.Fatalf("unsafe body: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("username not escaped")
	}
}
