package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"html/template"
	"net/http"
	"strconv"
)

type ClientConfigService interface {
	Export(context.Context, int64) (domain.ClientConfig, error)
	QR(context.Context, int64, int) ([]byte, error)
}
type ClientConfigHandler struct {
	service ClientConfigService
	tmpl    *template.Template
}

func NewClientConfigHandler(service ClientConfigService) *ClientConfigHandler {
	return &ClientConfigHandler{service: service, tmpl: template.Must(template.ParseFS(Files, "templates/client_config.html"))}
}
func (h *ClientConfigHandler) DeepLink(w http.ResponseWriter, r *http.Request) {
	id, ok := clientUserID(w, r)
	if !ok {
		return
	}
	cfg, err := h.service.Export(r.Context(), id)
	if err != nil {
		http.Error(w, "client config unavailable", http.StatusConflict)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, struct{ DeepLink string }{cfg.DeepLink})
}
func (h *ClientConfigHandler) TOML(w http.ResponseWriter, r *http.Request) {
	id, ok := clientUserID(w, r)
	if !ok {
		return
	}
	cfg, err := h.service.Export(r.Context(), id)
	if err != nil {
		http.Error(w, "client config unavailable", http.StatusConflict)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/toml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=trusttunnel-client.toml")
	_, _ = w.Write([]byte(cfg.TOML))
}
func (h *ClientConfigHandler) QR(w http.ResponseWriter, r *http.Request) {
	id, ok := clientUserID(w, r)
	if !ok {
		return
	}
	png, err := h.service.QR(r.Context(), id, 256)
	if err != nil {
		http.Error(w, "QR unavailable", http.StatusConflict)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}
func clientUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid user", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
