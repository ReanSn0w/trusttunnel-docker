package webui

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

const csrfSeedCookie = "__Host-tt_csrf_seed"

type csrfContextKey struct{}
type requestIDContextKey struct{}

type CSRF struct {
	secret []byte
	secure bool
}

func NewCSRF(secure bool) *CSRF {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	return &CSRF{secret: secret, secure: secure}
}
func (c *CSRF) token(seed string) string {
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (c *CSRF) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seed := ""
		if session, err := r.Cookie(SessionCookie); err == nil {
			seed = session.Value
		} else if cookie, err := r.Cookie(csrfSeedCookie); err == nil {
			seed = cookie.Value
		}
		if seed == "" {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				http.Error(w, "entropy unavailable", http.StatusInternalServerError)
				return
			}
			seed = base64.RawURLEncoding.EncodeToString(raw)
			http.SetCookie(w, &http.Cookie{Name: csrfSeedCookie, Value: seed, Path: "/", Secure: c.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
		}
		token := c.token(seed)
		ctx := context.WithValue(r.Context(), csrfContextKey{}, token)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			provided := r.Header.Get("X-CSRF-Token")
			if provided == "" {
				provided = r.FormValue("_csrf")
			}
			if !hmac.Equal([]byte(token), []byte(provided)) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func CSRFToken(ctx context.Context) string {
	token, _ := ctx.Value(csrfContextKey{}).(string)
	return token
}

type RequestLogger interface{ Logf(string, ...interface{}) }
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func SecurityMiddleware(logger RequestLogger, externalTLS bool, maxBody int64, next http.Handler) http.Handler {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if externalTLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, id)))
		if logger != nil {
			logger.Logf("http request_id=%s method=%s status=%d duration_ms=%d", id, r.Method, sw.status, time.Since(start).Milliseconds())
		}
	})
}
func requestID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "unavailable"
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey{}).(string)
	return id
}
func IsMutation(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
