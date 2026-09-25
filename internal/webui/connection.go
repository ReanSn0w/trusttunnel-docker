package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"html/template"
	"net/http"
	"strings"
)

type ClientProfileRepository interface {
	LoadClientProfile(context.Context) (clientprofile.Settings, error)
	SaveClientProfile(context.Context, clientprofile.Settings) error
}
type ConnectionHandler struct {
	repo ClientProfileRepository
	tmpl *template.Template
}

func NewConnectionHandler(repo ClientProfileRepository) *ConnectionHandler {
	return &ConnectionHandler{repo, template.Must(template.New("connection.html").Funcs(template.FuncMap{
		"profiles": func() []string { return []string{"chrome", "safari", "firefox", "okhttp", "openssl", "default"} },
	}).ParseFS(Files, "templates/connection.html"))}
}

func (h *ConnectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	p, err := h.repo.LoadClientProfile(r.Context())
	if err != nil {
		http.Error(w, "could not load connection settings", 500)
		return
	}
	message := ""
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		p = clientprofile.Settings{PublicAddress: strings.TrimSpace(r.FormValue("public_address")),
			Protocol: r.FormValue("protocol"), AntiDPI: r.FormValue("anti_dpi") == "on",
			IPv6: r.FormValue("ipv6") == "on", TLSProfile: r.FormValue("tls_profile"), PostQuantum: r.FormValue("post_quantum") == "on"}
		if err = p.Validate(); err != nil {
			message = err.Error()
		} else if err = h.repo.SaveClientProfile(r.Context(), p); err != nil {
			http.Error(w, "could not save connection settings", 500)
			return
		} else {
			http.Redirect(w, r, "/connection?saved=1", http.StatusSeeOther)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if message != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = h.tmpl.Execute(w, struct {
		Profile          clientprofile.Settings
		CSRFToken, Error string
		Saved            bool
	}{p, CSRFToken(r.Context()), message, r.URL.Query().Get("saved") == "1"})
}
