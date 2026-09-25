package clientprofile

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

// Apply preserves credentials, trust material and unknown fields from the official
// exporter. Only documented client transport fields are changed.
func Apply(cfg domain.ClientConfig, s Settings) (domain.ClientConfig, error) {
	if err := s.Validate(); err != nil {
		return domain.ClientConfig{}, err
	}
	var endpoint map[string]any
	if _, err := toml.Decode(cfg.TOML, &endpoint); err != nil {
		return domain.ClientConfig{}, errors.New("invalid official endpoint TOML")
	}
	endpoint["upstream_protocol"], endpoint["anti_dpi"], endpoint["has_ipv6"] = s.Protocol, s.AntiDPI, s.IPv6
	endpoint["tls_profile"] = s.TLSProfile
	var b bytes.Buffer
	if err := toml.NewEncoder(&b).Encode(endpoint); err != nil {
		return domain.ClientConfig{}, err
	}
	cfg.TOML = b.String()
	link, err := tuneLink(cfg.DeepLink, s)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	cfg.DeepLink = link
	b.Reset()
	// Full CLI configuration: PQ is a top-level option, never an endpoint option.
	cli := map[string]any{
		"loglevel": "info", "vpn_mode": "general", "killswitch_enabled": true,
		"post_quantum_group_enabled": s.PostQuantum, "endpoint": endpoint,
		"listener": map[string]any{"tun": map[string]any{
			"mtu_size": 1350, "change_system_dns": true,
			"included_routes": []string{"0.0.0.0/0", "2000::/3"},
			"excluded_routes": []string{"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"},
		}},
	}
	if err := toml.NewEncoder(&b).Encode(cli); err != nil {
		return domain.ClientConfig{}, err
	}
	cfg.CLI = b.String()
	return cfg, nil
}

func tuneLink(link string, s Settings) (string, error) {
	payload := strings.TrimPrefix(link, "tt://?")
	if payload == link || payload == "" || len(payload) > 1<<20 {
		return "", errors.New("invalid official deeplink")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", errors.New("invalid official deeplink encoding")
	}
	out := make([]byte, 0, len(raw)+9)
	for len(raw) > 0 {
		entry := raw
		tag, n, ok := varint(raw)
		if !ok {
			return "", errors.New("truncated deeplink tag")
		}
		raw = raw[n:]
		size, n, ok := varint(raw)
		if !ok {
			return "", errors.New("truncated deeplink length")
		}
		raw = raw[n:]
		if size > uint64(len(raw)) {
			return "", errors.New("truncated deeplink value")
		}
		raw = raw[int(size):]
		if tag != 4 && tag != 9 && tag != 10 {
			out = append(out, entry[:len(entry)-len(raw)]...)
		}
	}
	boolByte := func(v bool) byte {
		if v {
			return 1
		}
		return 0
	}
	protocol := byte(1)
	if s.Protocol == "http3" {
		protocol = 2
	}
	out = append(out, 4, 1, boolByte(s.IPv6), 9, 1, protocol, 10, 1, boolByte(s.AntiDPI))
	return "tt://?" + base64.RawURLEncoding.EncodeToString(out), nil
}

func varint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 63)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n, true
}
