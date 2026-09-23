package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type dbStub struct{ err error }

func (d dbStub) SchemaVersion(context.Context) (int, error) { return 1, d.err }

type procStub struct{ state string }

func (p procStub) Status() domain.EndpointStatus {
	return domain.EndpointStatus{State: p.state, Revision: "abc"}
}

type filesStub struct {
	dir string
	err error
}

func (f filesStub) ActiveDir() (string, error) { return f.dir, f.err }

func TestHealthIndependentFromReadiness(t *testing.T) {
	h := New(dbStub{errors.New("down")}, procStub{"stopped"}, filesStub{err: errors.New("missing")}, "test")
	for path, want := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusServiceUnavailable} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
}

func TestReady(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/vpn.toml", []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(dbStub{}, procStub{"ready"}, filesStub{dir: dir}, "test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
