package auth

import (
	"strings"
	"sync"
	"time"
)

type attempt struct {
	failures                int
	windowStart, next, seen time.Time
}
type LoginLimiter struct {
	mu         sync.Mutex
	entries    map[string]attempt
	window     time.Duration
	maxEntries int
	now        func() time.Time
}

func NewLoginLimiter(window time.Duration, maxEntries int) *LoginLimiter {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &LoginLimiter{entries: make(map[string]attempt), window: window, maxEntries: maxEntries, now: time.Now}
}
func loginKey(ip, username string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "\x00" + ip
}
func (l *LoginLimiter) Allow(ip, username string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := loginKey(ip, username)
	a, ok := l.entries[key]
	if !ok || now.Sub(a.windowStart) >= l.window {
		return true, 0
	}
	if now.Before(a.next) {
		return false, a.next.Sub(now)
	}
	return true, 0
}
func (l *LoginLimiter) Failure(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := loginKey(ip, username)
	a := l.entries[key]
	if a.windowStart.IsZero() || now.Sub(a.windowStart) >= l.window {
		a = attempt{windowStart: now}
	}
	a.failures++
	a.seen = now
	shift := a.failures - 1
	if shift > 5 {
		shift = 5
	}
	a.next = now.Add(250 * time.Millisecond * time.Duration(1<<shift))
	l.entries[key] = a
	if len(l.entries) > l.maxEntries {
		l.evictOldest()
	}
}
func (l *LoginLimiter) Success(ip, username string) {
	l.mu.Lock()
	delete(l.entries, loginKey(ip, username))
	l.mu.Unlock()
}
func (l *LoginLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for k, a := range l.entries {
		if oldestKey == "" || a.seen.Before(oldest) {
			oldestKey, oldest = k, a.seen
		}
	}
	delete(l.entries, oldestKey)
}
