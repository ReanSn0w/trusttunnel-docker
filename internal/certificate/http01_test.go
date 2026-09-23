package certificate

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHTTP01ExactTokenAndCleanup(t *testing.T) {
	p := NewHTTP01Provider("127.0.0.1:0", 2)
	if err := p.Present(context.Background(), "vpn.example.net", "token-one", "key-auth-secret"); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + p.Addr() + "/.well-known/acme-challenge/token-one")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "key-auth-secret" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	resp, err = client.Get("http://" + p.Addr() + "/.well-known/acme-challenge/token-one/extra")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected prefix match status=%d", resp.StatusCode)
	}
	if err = p.CleanUp(context.Background(), "vpn.example.net", "token-one", "key-auth-secret"); err != nil {
		t.Fatal(err)
	}
	if p.Addr() != "" {
		t.Fatal("listener remained open after cleanup")
	}
}

func TestHTTP01RejectsInvalidToken(t *testing.T) {
	p := NewHTTP01Provider("127.0.0.1:0", 1)
	if err := p.Present(context.Background(), "vpn.example.net", "../token", "secret"); err == nil {
		t.Fatal("expected invalid token")
	}
}
