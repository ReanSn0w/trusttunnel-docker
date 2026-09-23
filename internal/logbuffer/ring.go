package logbuffer

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type Ring struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func New(max int) *Ring {
	if max <= 0 {
		max = 256 << 10
	}
	return &Ring{max: max}
}
func (r *Ring) Logf(format string, args ...interface{}) {
	r.Write([]byte(fmt.Sprintf(format, args...) + "\n"))
}
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clean := []byte(redact(string(p)))
	r.buf = append(r.buf, clean...)
	if len(r.buf) > r.max {
		r.buf = append([]byte(nil), r.buf[len(r.buf)-r.max:]...)
	}
	return len(p), nil
}
func (r *Ring) String() string { r.mu.Lock(); defer r.mu.Unlock(); return string(bytes.Clone(r.buf)) }
func redact(v string) string {
	for _, marker := range []string{"-----BEGIN", "tt://", "/.well-known/acme-challenge/"} {
		if i := strings.Index(v, marker); i >= 0 {
			v = v[:i] + "[REDACTED]"
		}
	}
	secret := regexp.MustCompile(`(?i)(password|token|credential|cookie|csrf|keyauth|account_key)(\s*[:=]\s*)\S+`)
	return secret.ReplaceAllString(v, `$1$2[REDACTED]`)
}
