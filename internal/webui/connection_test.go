package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
}
