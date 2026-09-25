package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/auth"
)

type profileWebStub struct {
	settings clientprofile.Settings
	saves    int
}

func (s *profileWebStub) LoadClientProfile(context.Context) (clientprofile.Settings, error) {
	return s.settings, nil
}
func (s *profileWebStub) SaveClientProfile(_ context.Context, p clientprofile.Settings) error {
	s.settings = p
	s.saves++
	return nil
}

func TestConnectionForm(t *testing.T) {
	repo := &profileWebStub{settings: clientprofile.Default()}
	h := NewConnectionHandler(repo)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/connection", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "connection.js") || !strings.Contains(w.Body.String(), "drops Anti-DPI") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	form := url.Values{"public_address": {"vpn.example.com:1443"}, "protocol": {"http2"}, "anti_dpi": {"on"}, "tls_profile": {"safari"}}
	post := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/connection", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w = post()
	if w.Code != 303 || repo.saves != 1 || !repo.settings.AntiDPI || repo.settings.PostQuantum || repo.settings.PublicAddress != "vpn.example.com:1443" {
		t.Fatalf("POST: %d %+v", w.Code, repo)
	}
	form.Set("protocol", "http3")
	w = post()
	if w.Code != 400 || repo.saves != 1 || !strings.Contains(w.Body.String(), "requires HTTP/2") {
		t.Fatalf("invalid POST: %d %s", w.Code, w.Body.String())
	}
}

type profileExportStub struct{ link string }

func (s profileExportStub) Export(context.Context, int64) (domain.ClientConfig, error) {
	return domain.ClientConfig{DeepLink: s.link, CLI: "post_quantum_group_enabled = false\n"}, nil
}
func (s profileExportStub) QR(context.Context, int64, int) ([]byte, error) { return nil, nil }

func TestProfileDownloads(t *testing.T) {
	for _, tc := range []struct {
		link   string
		status int
	}{{"tt://?AAEB", 200}, {"javascript:alert(1)", 500}, {"tt://?\"onclick=alert(1)", 500}} {
		r := httptest.NewRequest("POST", "/users/1/client/link", nil)
		r.SetPathValue("id", "1")
		w := httptest.NewRecorder()
		NewClientConfigHandler(profileExportStub{tc.link}).DeepLink(w, r)
		if w.Code != tc.status {
			t.Fatalf("link status=%d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("sensitive response cached")
		}
		if tc.status == 200 && !strings.Contains(w.Body.String(), `href="tt://?AAEB"`) {
			t.Fatal("deeplink launch missing")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/users/1/client/cli", nil)
	r.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	NewClientConfigHandler(profileExportStub{}).CLI(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "post_quantum_group_enabled") || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download: %+v", w.Result())
	}
	for _, handler := range []func(http.ResponseWriter, *http.Request){NewClientConfigHandler(profileExportStub{}).TOML, NewClientConfigHandler(profileExportStub{}).QR} {
		r := httptest.NewRequest(http.MethodPost, "/users/1/client/export", nil)
		r.SetPathValue("id", "1")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("export cache control: status=%d headers=%v", w.Code, w.Header())
		}
	}
}

type connectionSessionStub struct{ webSessionStub }

func (*connectionSessionStub) Authenticate(_ context.Context, token string) (auth.Admin, error) {
	if token == "random-session" {
		return auth.Admin{ID: 1, Username: "admin"}, nil
	}
	return auth.Admin{}, auth.ErrInvalidCredentials
}

func TestConnectionRouteRequiresSessionAndCSRF(t *testing.T) {
	repo := &profileWebStub{settings: clientprofile.Default()}
	router := NewRouter(RouterDependencies{Bootstrap: &bootstrapServiceStub{}, Auth: NewAuthHandler(&connectionSessionStub{}, nil), Connection: NewConnectionHandler(repo), CSRF: NewCSRF(true)})
	withoutSession := httptest.NewRecorder()
	router.ServeHTTP(withoutSession, httptest.NewRequest(http.MethodGet, "/connection", nil))
	if withoutSession.Code != http.StatusSeeOther || withoutSession.Header().Get("Location") != "/login" {
		t.Fatalf("unprotected connection page: %d", withoutSession.Code)
	}
	request := func(method, body string) *http.Request {
		r := httptest.NewRequest(method, "/connection", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "random-session"})
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	page := httptest.NewRecorder()
	router.ServeHTTP(page, request(http.MethodGet, ""))
	if page.Code != http.StatusOK {
		t.Fatalf("authorized page: %d", page.Code)
	}
	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, request(http.MethodPost, "protocol=http2&tls_profile=chrome"))
	if bad.Code != http.StatusForbidden || repo.saves != 0 {
		t.Fatalf("POST without CSRF: status=%d saves=%d", bad.Code, repo.saves)
	}
	token := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(token) != 2 {
		t.Fatal("connection form has no CSRF token")
	}
	good := httptest.NewRecorder()
	router.ServeHTTP(good, request(http.MethodPost, url.Values{"protocol": {"http2"}, "tls_profile": {"chrome"}, "_csrf": {token[1]}}.Encode()))
	if good.Code != http.StatusSeeOther || repo.saves != 1 {
		t.Fatalf("authorized POST: status=%d saves=%d", good.Code, repo.saves)
	}
}
