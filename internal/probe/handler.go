package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type Database interface {
	SchemaVersion(context.Context) (int, error)
}
type Process interface{ Status() domain.EndpointStatus }
type ActiveFiles interface{ ActiveDir() (string, error) }

type Handler struct {
	db      Database
	process Process
	files   ActiveFiles
	version string
}

func New(db Database, process Process, files ActiveFiles, version string) http.Handler {
	h := &Handler{db: db, process: process, files: files, version: version}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /readyz", h.ready)
	return mux
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusOK, map[string]any{"status": "alive", "version": h.version})
}
func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	checks := map[string]string{"database": "ready", "config": "ready", "endpoint": "ready"}
	code, status := http.StatusOK, "ready"
	if _, err := h.db.SchemaVersion(ctx); err != nil {
		checks["database"] = "unavailable"
		code, status = http.StatusServiceUnavailable, "not_ready"
	}
	if dir, err := h.files.ActiveDir(); err != nil {
		checks["config"] = "unavailable"
		code, status = http.StatusServiceUnavailable, "not_ready"
	} else if _, err = os.Stat(dir); err != nil {
		checks["config"] = "unavailable"
		code, status = http.StatusServiceUnavailable, "not_ready"
	}
	ep := h.process.Status()
	if ep.State != "ready" && ep.State != "degraded" {
		checks["endpoint"] = ep.State
		code, status = http.StatusServiceUnavailable, "not_ready"
	}
	write(w, code, map[string]any{"status": status, "checks": checks, "revision": ep.Revision})
}
func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
