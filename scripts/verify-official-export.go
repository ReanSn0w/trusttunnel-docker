//go:build ignore

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func main() {
	if len(os.Args) != 4 {
		fail("usage: verify-official-export.go <link-output> <toml-output> <certificate>")
	}
	linkOutput, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("read link output")
	}
	tomlOutput, err := os.ReadFile(os.Args[2])
	if err != nil {
		fail("read TOML output")
	}
	certificate, err := os.ReadFile(os.Args[3])
	if err != nil {
		fail("read certificate")
	}
	link := strings.TrimSpace(strings.SplitN(string(linkOutput), "\n", 2)[0])
	if !strings.HasPrefix(link, "tt://?") {
		fail("official exporter did not return a deeplink")
	}
	var original map[string]any
	if _, err = toml.Decode(string(tomlOutput), &original); err != nil {
		fail("official exporter did not return valid TOML")
	}
	checkEndpoint(original, certificate)
	fields, err := decodeFields(link)
	if err != nil {
		fail("official deeplink is malformed")
	}
	checkFields(fields, certificate)
	settings := clientprofile.Default()
	settings.AntiDPI = true
	settings.PostQuantum = false
	settings.TLSProfile = "safari"
	result, err := clientprofile.Apply(domain.ClientConfig{DeepLink: link, TOML: string(tomlOutput)}, settings)
	if err != nil {
		fail("controller rejected official export")
	}
	var endpoint, cli map[string]any
	if _, err = toml.Decode(result.TOML, &endpoint); err != nil {
		fail("controller endpoint TOML is invalid")
	}
	if _, err = toml.Decode(result.CLI, &cli); err != nil {
		fail("controller CLI TOML is invalid")
	}
	checkEndpoint(endpoint, certificate)
	checkEndpoint(cli["endpoint"].(map[string]any), certificate)
	if cli["post_quantum_group_enabled"] != false || endpoint["post_quantum_group_enabled"] != nil || cli["endpoint"].(map[string]any)["post_quantum_group_enabled"] != nil {
		fail("post-quantum option is not top-level")
	}
	if endpoint["upstream_protocol"] != "http2" || endpoint["anti_dpi"] != true || endpoint["tls_profile"] != "safari" {
		fail("selected transport or TLS settings missing from TOML")
	}
	updated, err := decodeFields(result.DeepLink)
	if err != nil {
		fail("updated deeplink is malformed")
	}
	checkFields(updated, certificate)
	if !bytes.Equal(updated[10], []byte{1}) || !bytes.Equal(updated[9], []byte{1}) {
		fail("selected transport or Anti-DPI missing from deeplink")
	}
}

func checkEndpoint(endpoint map[string]any, certificate []byte) {
	if endpoint["hostname"] != "vpn.example.com" || endpoint["username"] != "alice" || endpoint["password"] != "integration-test-password" || endpoint["skip_verification"] == true {
		fail("hostname, credentials or certificate verification changed")
	}
	addresses, ok := endpoint["addresses"].([]any)
	if !ok || len(addresses) != 1 || addresses[0] != "vpn.example.com:443" {
		fail("external address does not use host port 443")
	}
	want, _ := pem.Decode(certificate)
	got, _ := pem.Decode([]byte(fmt.Sprint(endpoint["certificate"])))
	if want == nil || got == nil || !bytes.Equal(want.Bytes, got.Bytes) {
		fail("certificate trust material was lost")
	}
}

func checkFields(fields map[uint64][]byte, certificate []byte) {
	want, _ := pem.Decode(certificate)
	if want == nil || !bytes.Contains(fields[8], want.Bytes) || !bytes.Equal(fields[5], []byte("alice")) || !bytes.Equal(fields[6], []byte("integration-test-password")) || !bytes.Equal(fields[2], []byte("vpn.example.com:443")) {
		fail("deeplink lost trust material, credentials or address")
	}
	if v, exists := fields[7]; exists && !bytes.Equal(v, []byte{0}) {
		fail("deeplink enabled skip_verification")
	}
}

func decodeFields(link string) (map[uint64][]byte, error) {
	if !strings.HasPrefix(link, "tt://?") || len(link) > 1<<20 {
		return nil, errors.New("invalid deeplink")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "tt://?"))
	if err != nil {
		return nil, err
	}
	fields := make(map[uint64][]byte)
	for len(raw) > 0 {
		tag, n, ok := varint(raw)
		if !ok {
			return nil, errors.New("invalid tag")
		}
		raw = raw[n:]
		size, n, ok := varint(raw)
		if !ok || size > uint64(len(raw)-n) {
			return nil, errors.New("invalid length")
		}
		raw = raw[n:]
		fields[tag] = bytes.Clone(raw[:int(size)])
		raw = raw[int(size):]
	}
	return fields, nil
}

func varint(raw []byte) (uint64, int, bool) {
	if len(raw) == 0 {
		return 0, 0, false
	}
	n := 1 << (raw[0] >> 6)
	if len(raw) < n {
		return 0, 0, false
	}
	v := uint64(raw[0] & 63)
	for _, b := range raw[1:n] {
		v = v<<8 | uint64(b)
	}
	return v, n, true
}

func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
