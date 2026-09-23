package config

import (
	"bytes"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func validSnapshot() domain.Snapshot {
	return domain.Snapshot{Hostname: "vpn.example.com", ListenAddress: "0.0.0.0:8443", Users: []domain.VPNUser{
		{Username: "z-user", Credential: "long-safe-secret", Status: domain.UserActive},
		{Username: "a-user", Credential: "another-secret", Status: domain.UserDisabled},
	}}
}

func TestRenderDeterministicAndEscaped(t *testing.T) {
	s := validSnapshot()
	a, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a["credentials.toml"], b["credentials.toml"]) {
		t.Fatal("render is not deterministic")
	}
	if bytes.Index(a["credentials.toml"], []byte("a-user")) > bytes.Index(a["credentials.toml"], []byte("z-user")) {
		t.Fatal("users not sorted")
	}
	s.Users[0].Credential = "bad\"\n[[hosts]]\nowned=true"
	c, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c["credentials.toml"], []byte("\n[[hosts]]")) {
		t.Fatal("TOML injection was not escaped")
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	tests := []domain.Snapshot{
		{Hostname: "localhost", ListenAddress: "0.0.0.0:8443"},
		{Hostname: "vpn.example.com", ListenAddress: "0.0.0.0:70000"},
		{Hostname: "vpn.example.com", ListenAddress: "0.0.0.0:8443", Users: []domain.VPNUser{{Username: "bad name", Credential: "long-safe-secret", Status: domain.UserActive}}},
	}
	for _, tc := range tests {
		if err := Validate(tc); err == nil {
			t.Fatalf("expected rejection for %#v", tc)
		}
	}
}
