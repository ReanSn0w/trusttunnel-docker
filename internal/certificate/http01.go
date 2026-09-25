package certificate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HTTP01Provider struct {
	address  string
	mu       sync.RWMutex
	tokens   map[string]string
	server   *http.Server
	listener net.Listener
	sem      chan struct{}
}

func NewHTTP01Provider(address string, maxParallel int) *HTTP01Provider {
	if maxParallel <= 0 {
		maxParallel = 32
	}
	return &HTTP01Provider{address: address, tokens: map[string]string{}, sem: make(chan struct{}, maxParallel)}
}

func (p *HTTP01Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	if strings.ContainsAny(token, "/\\") || token == "" || keyAuth == "" {
		return errors.New("invalid HTTP-01 challenge")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = keyAuth
	if p.server != nil {
		return nil
	}
	listener, err := net.Listen("tcp", p.address)
	if err != nil {
		delete(p.tokens, token)
		return fmt.Errorf("listen HTTP-01: %w", err)
	}
	p.listener = listener
	p.server = &http.Server{Handler: http.HandlerFunc(p.serveHTTP), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	server := p.server
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (p *HTTP01Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	delete(p.tokens, token)
	if len(p.tokens) > 0 || p.server == nil {
		p.mu.Unlock()
		return nil
	}
	server := p.server
	listener := p.listener
	p.server = nil
	p.listener = nil
	p.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func (p *HTTP01Provider) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.tokens = map[string]string{}
	server := p.server
	listener := p.listener
	p.server = nil
	p.listener = nil
	p.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if server == nil {
		return nil
	}
	return server.Shutdown(ctx)
}

func (p *HTTP01Provider) Addr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

func (p *HTTP01Provider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) || strings.TrimPrefix(r.URL.Path, prefix) == "" {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	p.mu.RLock()
	keyAuth, ok := p.tokens[token]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(keyAuth))
}
