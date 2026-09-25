package clientprofile

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func TestApplyPreservesTrustAndCredentials(t *testing.T) {
	// Unknown tag, multi-byte length and DER-like certificate must survive byte-for-byte.
	keep := []byte{0, 1, 1, 5, 3, 'b', 'o', 'b', 6, 3, 'p', 'w', 'd', 8, 0x40, 70}
	keep = append(keep, bytes.Repeat([]byte{0xab}, 70)...)
	keep = append(keep, 0x40, 99, 2, 7, 8)
	raw := append(append([]byte{}, keep...), 4, 1, 1, 9, 1, 1, 10, 1, 0)
	s := Default()
	s.Protocol = "http3"
	s.IPv6 = false
	s.TLSProfile = "safari"
	s.PostQuantum = false
	cfg, err := Apply(domain.ClientConfig{DeepLink: "tt://?" + base64.RawURLEncoding.EncodeToString(raw), TOML: `hostname="vpn.example.com"
addresses=["vpn.example.com:443"]
username="bob"
password="pwd"
certificate="CERTIFICATE"
skip_verification=false
custom_sni="vpn.example.com"
future_setting="keep"
`}, s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cfg.DeepLink, "tt://?"))
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, keep...), 4, 1, 0, 9, 1, 2, 10, 1, 0)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("TLV fields changed: %x", decoded)
	}
	var cli map[string]any
	if _, err = toml.Decode(cfg.CLI, &cli); err != nil {
		t.Fatal(err)
	}
	ep := cli["endpoint"].(map[string]any)
	for k, v := range map[string]any{"username": "bob", "password": "pwd", "certificate": "CERTIFICATE", "skip_verification": false, "future_setting": "keep", "tls_profile": "safari", "anti_dpi": false, "upstream_protocol": "http3", "has_ipv6": false} {
		if ep[k] != v {
			t.Fatalf("%s=%v, want %v", k, ep[k], v)
		}
	}
	if cli["post_quantum_group_enabled"] != false || ep["post_quantum_group_enabled"] != nil {
		t.Fatal("PQ must be top-level")
	}
	if cli["listener"].(map[string]any)["tun"] == nil {
		t.Fatal("missing TUN listener")
	}
	var endpoint map[string]any
	if _, err = toml.Decode(cfg.TOML, &endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint["hostname"] != "vpn.example.com" || endpoint["endpoint"] != nil {
		t.Fatal("endpoint-only export changed shape")
	}
}

func TestAntiDPIAndMalformedLinks(t *testing.T) {
	s := Default()
	s.AntiDPI = true
	link, err := tuneLink("tt://?AAEB", s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "tt://?"))
	if !bytes.HasSuffix(raw, []byte{10, 1, 1}) {
		t.Fatal("Anti-DPI not encoded")
	}
	for _, raw := range [][]byte{{0x40}, {1}, {1, 9, 0}, {1, 0xff}, {0xc0, 1}} {
		if _, err := tuneLink("tt://?"+base64.RawURLEncoding.EncodeToString(raw), s); err == nil {
			t.Fatalf("accepted malformed %x", raw)
		}
	}
	for _, link := range []string{"https://example.com", "tt://?%%%", "tt://?", "tt://?" + strings.Repeat("A", (1<<20)+1)} {
		if _, err := tuneLink(link, s); err == nil {
			t.Fatal("accepted invalid link")
		}
	}
}

func TestSettingsValidation(t *testing.T) {
	s := Default()
	if address, err := s.Address("vpn.example.com"); err != nil || address != "vpn.example.com:443" {
		t.Fatalf("address=%s err=%v", address, err)
	}
	for _, address := range []string{"89.124.66.69:443", "vpn.example.com:18443", "[2001:db8::1]:443", "127.0.0.1:18443"} {
		s.PublicAddress = address
		if got, err := s.Address("vpn.example.com"); err != nil || got != address {
			t.Fatalf("%s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:443", "[::]:443", "224.0.0.1:443", "https://vpn.example.com:443", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com", "bad host:443"} {
		s.PublicAddress = address
		if s.Validate() == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	s = Default()
	s.Protocol = "http3"
	s.AntiDPI = true
	if s.Validate() == nil {
		t.Fatal("accepted TCP Anti-DPI with QUIC")
	}
	s = Default()
	s.TLSProfile = "unknown"
	if s.Validate() == nil {
		t.Fatal("accepted unknown fingerprint")
	}
}
