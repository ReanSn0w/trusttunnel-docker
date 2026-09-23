package webui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/auth"
)

type webSessionStub struct {
	loggedOut bool
}

func (s *webSessionStub) Login(_ context.Context, user, password string) (auth.Session, error) {
	if user != "admin" || password != "Correct-Horse-9!" {
		return auth.Session{}, auth.ErrInvalidCredentials
	}
	return auth.Session{Token: "random-session", ExpiresAt: time.Now().Add(time.Hour), Admin: auth.Admin{ID: 1, Username: "admin"}}, nil
}
func (s *webSessionStub) Authenticate(context.Context, string) (auth.Admin, error) {
	return auth.Admin{}, errors.New("not used")
}
func (s *webSessionStub) Logout(context.Context, string) error { s.loggedOut = true; return nil }
func TestLoginCookieUniformErrorAndNoOpenRedirect(t *testing.T) {
	svc := &webSessionStub{}
	h, err := NewAuthHandler(svc, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"missing", "admin"} {
		body := "username=" + user + "&password=wrong"
		r := httptest.NewRequest(http.MethodPost, "/login?next=https://evil.example", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.Login(w, r)
		if !strings.Contains(w.Body.String(), "Invalid username or password") {
			t.Fatalf("enumerating response for %s", user)
		}
	}
	h, err = NewAuthHandler(svc, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/login?next=https://evil.example", strings.NewReader("username=admin&password=Correct-Horse-9%21"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Header().Get("Location") != "/" {
		t.Fatalf("open redirect: %q", w.Header().Get("Location"))
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("cookie=%#v", cookie)
	}
}
func TestForgedProxyHeaderIgnored(t *testing.T) {
	h, _ := NewAuthHandler(&webSessionStub{}, nil, []string{"10.0.0.0/8"}, true)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.4:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := h.clientIP(r); got != "203.0.113.4" {
		t.Fatalf("trusted forged header: %s", got)
	}
	r.RemoteAddr = "10.0.0.2:1234"
	if got := h.clientIP(r); got != "1.2.3.4" {
		t.Fatalf("ignored trusted proxy: %s", got)
	}
}

func TestLogoutRevokesSessionAndClearsCookie(t *testing.T) {
	svc := &webSessionStub{}
	h, _ := NewAuthHandler(svc, nil, nil, true)
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "session"})
	w := httptest.NewRecorder()
	h.Logout(w, r)
	if !svc.loggedOut || w.Header().Get("Location") != "/login" {
		t.Fatalf("logout=%v location=%q", svc.loggedOut, w.Header().Get("Location"))
	}
	cookie := w.Result().Cookies()[0]
	if cookie.MaxAge != -1 || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("cookie=%#v", cookie)
	}
}
