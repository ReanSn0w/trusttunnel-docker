package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFBindsMutationToCookie(t *testing.T) {
	csrf := NewCSRF(true)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(CSRFToken(r.Context()))) })
	h := csrf.Wrap(next)
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/", nil))
	seed := get.Result().Cookies()[0]
	token := get.Body.String()
	bad := httptest.NewRecorder()
	h.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/mutate", nil))
	if bad.Code != http.StatusForbidden {
		t.Fatalf("bad code=%d", bad.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/mutate", nil)
	r.AddCookie(seed)
	r.Header.Set("X-CSRF-Token", token)
	good := httptest.NewRecorder()
	h.ServeHTTP(good, r)
	if good.Code != http.StatusOK {
		t.Fatalf("good code=%d", good.Code)
	}
}

func TestSecurityHeadersRequestIDAndBodyLimit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		}
	})
	h := SecurityMiddleware(nil, 4, next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://vpn.example.net/", strings.NewReader("oversized")))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code=%d", w.Code)
	}
	for _, name := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Request-ID"} {
		if w.Header().Get(name) == "" {
			t.Fatalf("missing %s", name)
		}
	}
}

func TestDirectLoopbackOmitsHSTS(t *testing.T) {
	w := httptest.NewRecorder()
	SecurityMiddleware(nil, 1024, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil))
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS set for direct HTTP")
	}
}

func TestMalformedFormDoesNotReachMutation(t *testing.T) {
	called := false
	h := NewCSRF(true).Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("code=%d called=%v", w.Code, called)
	}
}
