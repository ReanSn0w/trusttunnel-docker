package webui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type bootstrapServiceStub struct{ required bool }

func (s *bootstrapServiceStub) Required(context.Context) (bool, error) { return s.required, nil }
func (s *bootstrapServiceStub) Bootstrap(_ context.Context, _, password string) error {
	if password == "bad" {
		return errors.New("weak password")
	}
	s.required = false
	return nil
}
func TestBootstrapGateAndDeactivation(t *testing.T) {
	svc := &bootstrapServiceStub{required: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := BootstrapGate(svc, next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/bootstrap" {
		t.Fatalf("gate code=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/bootstrap", strings.NewReader("username=admin&password=Correct-Horse-9%21"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || svc.required {
		t.Fatalf("bootstrap code=%d required=%v", w.Code, svc.required)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bootstrap", nil))
	if w.Header().Get("Location") != "/login" {
		t.Fatalf("bootstrap stayed active: %q", w.Header().Get("Location"))
	}
}
