package certificate

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSelfSignedLifecycleKeepsFingerprintUntilRotation(t *testing.T) {
	ctx := context.Background()
	repo := &certRepo{m: Metadata{State: Unconfigured, Source: SelfSigned, Mode: ManualMode, Hostname: "vpn.example.test"}}
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(repo, store, nil, t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		t.Fatal("self-signed source contacted ACME")
		return nil, nil
	})
	first, err := m.Ensure(ctx, 30*24*time.Hour)
	if err != nil || first.State != Active || first.Source != SelfSigned || first.Fingerprint == "" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	info, err := os.Stat(first.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%v", info.Mode())
	}
	restarted := NewManager(repo, store, nil, t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		t.Fatal("restarted self-signed source contacted ACME")
		return nil, nil
	})
	again, err := restarted.Ensure(ctx, 30*24*time.Hour)
	if err != nil || again.Fingerprint != first.Fingerprint || again.ActiveRevision != first.ActiveRevision {
		t.Fatalf("unexpected regeneration: %+v err=%v", again, err)
	}
	m.now = func() time.Time { return time.Now().Add(350 * 24 * time.Hour) }
	rotated, err := m.Ensure(ctx, 30*24*time.Hour)
	if err != nil || rotated.Fingerprint == first.Fingerprint || rotated.PreviousRevision != first.ActiveRevision {
		t.Fatalf("rotation=%+v err=%v", rotated, err)
	}
}
