package certificate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProvidedPairReplacesOnlyWhenCompleteAndValid(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "mounted-cert.pem"), filepath.Join(root, "mounted-key.pem")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	firstBundle := makeBundle(t, "vpn.example.net", "Test CA")
	write(certPath, firstBundle.Certificate)
	write(keyPath, firstBundle.PrivateKey)
	repo := &certRepo{m: Metadata{State: Unconfigured, Source: Provided, Mode: ManualMode, Hostname: "vpn.example.net", ProvidedCertificatePath: certPath, ProvidedKeyPath: keyPath}}
	store, err := NewTLSStore(filepath.Join(root, "internal"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(repo, store, nil, root, time.Second, func(ACMEConfig) (ACMEClient, error) {
		t.Fatal("provided source contacted ACME")
		return nil, nil
	})
	first, err := m.Ensure(ctx, time.Hour)
	if err != nil || first.State != Active || first.ActiveRevision == "" || first.CertificatePath == certPath {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	again, err := m.Ensure(ctx, time.Hour)
	if err != nil || again.ActiveRevision != first.ActiveRevision {
		t.Fatalf("same pair republished: %+v err=%v", again, err)
	}
	secondBundle := makeBundle(t, "vpn.example.net", "Test CA")
	write(certPath, secondBundle.Certificate)
	failed, err := m.Ensure(ctx, time.Hour)
	if err == nil || failed.ActiveRevision != first.ActiveRevision {
		t.Fatalf("partial replacement=%+v err=%v", failed, err)
	}
	active, err := store.Active()
	if err != nil || active.Revision != first.ActiveRevision {
		t.Fatalf("active after partial replacement=%+v err=%v", active, err)
	}
	write(keyPath, secondBundle.PrivateKey)
	second, err := m.Ensure(ctx, time.Hour)
	if err != nil || second.ActiveRevision == first.ActiveRevision || second.PreviousRevision != first.ActiveRevision {
		t.Fatalf("complete replacement=%+v err=%v", second, err)
	}
	wrongSAN := makeBundle(t, "other.example.net", "Test CA")
	write(certPath, wrongSAN.Certificate)
	write(keyPath, wrongSAN.PrivateKey)
	failed, err = m.Ensure(ctx, time.Hour)
	if err == nil || failed.ActiveRevision != second.ActiveRevision {
		t.Fatalf("wrong SAN replacement=%+v err=%v", failed, err)
	}
}
