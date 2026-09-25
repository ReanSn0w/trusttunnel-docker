package main

import (
	"strings"
	"testing"
)

func TestLegacyReverseProxySettingsExplainMigration(t *testing.T) {
	for _, name := range []string{"TT_EXTERNAL_TLS", "TT_TRUSTED_PROXY"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "true")
			err := run([]string{"--version"})
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "docs/reverse-proxy.md") {
				t.Fatalf("migration error=%v", err)
			}
		})
	}
	for _, arg := range []string{"--external-tls", "--external-tls=false", "--trusted-proxy=127.0.0.1/8"} {
		t.Run(arg, func(t *testing.T) {
			err := run([]string{arg})
			if err == nil || !strings.Contains(err.Error(), "obsolete") || !strings.Contains(err.Error(), "docs/reverse-proxy.md") {
				t.Fatalf("migration error=%v", err)
			}
		})
	}
}
