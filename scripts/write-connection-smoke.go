//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

// Creates a SOCKS-only variant of an exported profile for an isolated client.
// The released CLI v1.1.7 lacks tls_profile, so this local runtime probe omits
// that field while retaining the controller's transport and PQ settings.
func main() {
	if len(os.Args) != 5 {
		panic("usage: write-connection-smoke.go <deeplink> <endpoint-toml> <variant> <output>")
	}
	linkOutput, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	endpointTOML, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	settings := clientprofile.Default()
	switch os.Args[3] {
	case "baseline":
	case "anti-dpi":
		settings.AntiDPI = true
	case "pq-off":
		settings.PostQuantum = false
	case "quic":
		settings.Protocol = "http3"
	default:
		panic("unknown variant")
	}
	link := strings.TrimSpace(strings.SplitN(string(linkOutput), "\n", 2)[0])
	cfg, err := clientprofile.Apply(domain.ClientConfig{DeepLink: link, TOML: string(endpointTOML)}, settings)
	if err != nil {
		panic(err)
	}
	var full map[string]any
	if _, err = toml.Decode(cfg.CLI, &full); err != nil {
		panic(err)
	}
	endpoint, ok := full["endpoint"].(map[string]any)
	if !ok {
		panic("export missing endpoint")
	}
	delete(endpoint, "tls_profile")
	full["listener"] = map[string]any{"socks": map[string]any{"address": "127.0.0.1:1080"}}
	full["killswitch_enabled"] = false
	var output bytes.Buffer
	if err = toml.NewEncoder(&output).Encode(full); err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[4], output.Bytes(), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("wrote", os.Args[3], "isolated client profile")
}
