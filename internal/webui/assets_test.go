package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedAssets(t *testing.T) {
	for _, tc := range []struct {
		path, contentType string
	}{
		{"vendor/bootstrap.min.css", "text/css"},
		{"vendor/bootstrap.bundle.min.js", "javascript"},
		{"vendor/htmx.min.js", "javascript"},
		{"icons/shield.svg", "image/svg+xml"},
	} {
		r := httptest.NewRequest("GET", "/"+tc.path, nil)
		w := httptest.NewRecorder()
		AssetHandler().ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), tc.contentType) {
			t.Fatalf("%s: code=%d type=%q", tc.path, w.Code, w.Header().Get("Content-Type"))
		}
		if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
			t.Fatalf("%s cache=%q", tc.path, got)
		}
	}
}

func TestAssetLicensesAreNotServed(t *testing.T) {
	r := httptest.NewRequest("GET", "/vendor/LICENSE.bootstrap", nil)
	w := httptest.NewRecorder()
	AssetHandler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("code=%d", w.Code)
	}
}
