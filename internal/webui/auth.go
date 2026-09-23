package webui

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/auth"
)

const SessionCookie = "__Host-tt_session"

type SessionService interface {
	Login(context.Context, string, string) (auth.Session, error)
	Authenticate(context.Context, string) (auth.Admin, error)
	Logout(context.Context, string) error
}
type AuthHandler struct {
	service SessionService
	limiter *auth.LoginLimiter
	trusted []*net.IPNet
	login   *template.Template
	secure  bool
}

func NewAuthHandler(service SessionService, limiter *auth.LoginLimiter, trustedProxyCIDRs []string, secure bool) (*AuthHandler, error) {
	if limiter == nil {
		limiter = auth.NewLoginLimiter(15*time.Minute, 4096)
	}
	h := &AuthHandler{service: service, limiter: limiter, login: template.Must(template.ParseFS(Files, "templates/login.html")), secure: secure}
	for _, raw := range trustedProxyCIDRs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		h.trusted = append(h.trusted, n)
	}
	return h, nil
}
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.renderLogin(w, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderLogin(w, "Invalid username or password")
		return
	}
	username := r.FormValue("username")
	ip := h.clientIP(r)
	if ok, wait := h.limiter.Allow(ip, username); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(wait.Seconds()))))
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	sess, err := h.service.Login(r.Context(), username, r.FormValue("password"))
	if err != nil {
		h.limiter.Failure(ip, username)
		h.renderLogin(w, "Invalid username or password")
		return
	}
	h.limiter.Success(ip, username)
	h.setCookie(w, sess)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		_ = h.service.Logout(r.Context(), c.Value)
	}
	h.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (h *AuthHandler) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		admin, err := h.service.Authenticate(r.Context(), c.Value)
		if err != nil {
			h.clearCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminContextKey{}, admin)))
	})
}
func (h *AuthHandler) renderLogin(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.login.Execute(w, struct{ Error string }{message})
}
func (h *AuthHandler) setCookie(w http.ResponseWriter, s auth.Session) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: s.Token, Path: "/", Expires: s.ExpiresAt, MaxAge: max(1, int(time.Until(s.ExpiresAt).Seconds())), Secure: h.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
func (h *AuthHandler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Path: "/", MaxAge: -1, Secure: h.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
func (h *AuthHandler) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	for _, n := range h.trusted {
		if peer != nil && n.Contains(peer) {
			if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
				return forwarded
			}
		}
	}
	return host
}

type adminContextKey struct{}

func AdminFromContext(ctx context.Context) (auth.Admin, bool) {
	a, ok := ctx.Value(adminContextKey{}).(auth.Admin)
	return a, ok
}
