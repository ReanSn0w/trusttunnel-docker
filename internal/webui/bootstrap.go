package webui

import (
	"context"
	"html/template"
	"net/http"
	"strings"
)

type BootstrapService interface {
	Required(context.Context) (bool, error)
	Bootstrap(context.Context, string, string) error
}
type BootstrapHandler struct {
	service BootstrapService
	tmpl    *template.Template
}

func NewBootstrapHandler(service BootstrapService) *BootstrapHandler {
	return &BootstrapHandler{service: service, tmpl: template.Must(template.ParseFS(Files, "templates/bootstrap.html"))}
}
func (h *BootstrapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	required, err := h.service.Required(r.Context())
	if err != nil {
		http.Error(w, "bootstrap state unavailable", http.StatusInternalServerError)
		return
	}
	if !required {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	data := struct{ Error string }{}
	if r.Method == http.MethodPost {
		if err = r.ParseForm(); err == nil {
			err = h.service.Bootstrap(r.Context(), r.FormValue("username"), r.FormValue("password"))
		}
		if err == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		data.Error = err.Error()
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
func BootstrapGate(service BootstrapService, next http.Handler) http.Handler {
	bootstrap := NewBootstrapHandler(service)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			bootstrap.ServeHTTP(w, r)
			return
		}
		required, err := service.Required(r.Context())
		if err != nil {
			http.Error(w, "bootstrap state unavailable", http.StatusInternalServerError)
			return
		}
		if required && !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.Redirect(w, r, "/bootstrap", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
