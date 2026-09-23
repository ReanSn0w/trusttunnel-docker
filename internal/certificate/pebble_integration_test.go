//go:build integration

package certificate

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestPebbleIssueAndRenew(t *testing.T) {
	directory := os.Getenv("PEBBLE_DIRECTORY")
	if directory == "" {
		t.Skip("PEBBLE_DIRECTORY is not set")
	}

	provider := NewHTTP01Provider("127.0.0.1:0", 2)
	client, err := NewLegoClient(ACMEConfig{
		Mode:              Staging,
		Email:             "admin@example.net",
		DataDir:           t.TempDir(),
		DirectoryOverride: directory,
		Provider:          provider,
		Timeout:           20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = provider.Shutdown(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err = client.EnsureAccount(ctx); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"issue", "renew"} {
		bundle, obtainErr := client.Obtain(ctx, "vpn.example.net")
		if obtainErr != nil {
			t.Fatalf("%s: %v", operation, obtainErr)
		}
		if _, validateErr := ValidateBundle(bundle, "vpn.example.net", Staging, time.Now()); validateErr != nil {
			t.Fatalf("%s validation: %v", operation, validateErr)
		}
	}
}
