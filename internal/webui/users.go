package webui

import (
	"context"
	"html/template"
	"net/http"
	"strconv"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/service"
)

type UserService interface {
	List(context.Context) ([]domain.VPNUser, error)
	Create(context.Context, string) (service.CreatedUser, error)
	Enable(context.Context, int64) error
	Disable(context.Context, int64) error
	Revoke(context.Context, int64) error
	Rotate(context.Context, int64) (string, error)
}
type UsersHandler struct {
	service UserService
	tmpl    *template.Template
}
type UsersData struct {
	CSRFToken, Error, NewPassword, NewUsername string
	Users                                      []domain.VPNUser
}

func NewUsersHandler(service UserService) *UsersHandler {
	return &UsersHandler{service: service, tmpl: template.Must(template.ParseFS(Files, "templates/users.html"))}
}
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) { h.render(w, r, "", "", "") }
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "invalid form", "", "")
		return
	}
	created, err := h.service.Create(r.Context(), r.FormValue("username"))
	if err != nil {
		h.render(w, r, err.Error(), "", "")
		return
	}
	h.render(w, r, "", created.User.Username, created.Password)
}
func (h *UsersHandler) Enable(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, h.service.Enable)
}
func (h *UsersHandler) Disable(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, h.service.Disable)
}
func (h *UsersHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, h.service.Revoke)
}
func (h *UsersHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	password, err := h.service.Rotate(r.Context(), id)
	if err != nil {
		h.render(w, r, err.Error(), "", "")
		return
	}
	users, _ := h.service.List(r.Context())
	name := ""
	for _, u := range users {
		if u.ID == id {
			name = u.Username
		}
	}
	h.render(w, r, "", name, password)
}
func (h *UsersHandler) mutate(w http.ResponseWriter, r *http.Request, fn func(context.Context, int64) error) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	if err := fn(r.Context(), id); err != nil {
		h.render(w, r, err.Error(), "", "")
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
func userID(w http.ResponseWriter, r *http.Request) (int64, bool) {
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
func (h *UsersHandler) render(w http.ResponseWriter, r *http.Request, message, username, password string) {
	users, err := h.service.List(r.Context())
	if err != nil && message == "" {
		message = err.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, UsersData{CSRFToken: CSRFToken(r.Context()), Error: message, NewUsername: username, NewPassword: password, Users: users})
}
