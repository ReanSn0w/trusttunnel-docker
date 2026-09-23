package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"html/template"
	"net/http"
)

type TLSService interface {
	View(context.Context) (certificate.Metadata, error)
	Save(context.Context, string, string, certificate.Mode) (certificate.Metadata, error)
	Issue(context.Context) (certificate.Metadata, error)
	Renew(context.Context) (certificate.Metadata, error)
}
type TLSHandler struct {
	service TLSService
	tmpl    *template.Template
}
type TLSData struct {
	CSRFToken, Error, Notice string
	Metadata                 certificate.Metadata
}

func NewTLSHandler(service TLSService) *TLSHandler {
	return &TLSHandler{service: service, tmpl: template.Must(template.ParseFS(Files, "templates/tls.html"))}
}
func (h *TLSHandler) View(w http.ResponseWriter, r *http.Request) { h.render(w, r, "", "") }
func (h *TLSHandler) Save(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "invalid form", "")
		return
	}
	mode := certificate.Mode(r.FormValue("mode"))
	if _, err := h.service.Save(r.Context(), r.FormValue("hostname"), r.FormValue("email"), mode); err != nil {
		h.render(w, r, err.Error(), "")
		return
	}
	h.render(w, r, "", "Settings saved. Certificate was not issued.")
}
func (h *TLSHandler) Issue(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	if _, err := h.service.Issue(r.Context()); err != nil {
		h.render(w, r, err.Error(), "")
		return
	}
	h.render(w, r, "", "Certificate issued and applied.")
}
func (h *TLSHandler) Renew(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	if _, err := h.service.Renew(r.Context()); err != nil {
		h.render(w, r, err.Error(), "")
		return
	}
	h.render(w, r, "", "Certificate renewed and applied.")
}
func (h *TLSHandler) render(w http.ResponseWriter, r *http.Request, message, notice string) {
	m, err := h.service.View(r.Context())
	if err != nil && message == "" {
		message = err.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, TLSData{CSRFToken: CSRFToken(r.Context()), Error: message, Notice: notice, Metadata: m})
}
func postOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}
