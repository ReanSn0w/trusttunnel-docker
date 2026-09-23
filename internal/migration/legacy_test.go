package migration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/persistence"
)

func TestLegacyMigrationIsIdempotentAndKeepsSource(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	cert, key := legacyCertificate(t, "vpn.example.net")
	mustWrite(t, filepath.Join(source, "certs", "cert.pem"), cert)
	mustWrite(t, filepath.Join(source, "certs", "key.pem"), key)
	mustWrite(t, filepath.Join(source, "vpn.toml"), []byte("listen_address = \"0.0.0.0:8443\"\n"))
	mustWrite(t, filepath.Join(source, "hosts.toml"), []byte("[[main_hosts]]\nhostname = \"vpn.example.net\"\ncert_chain_path = \"certs/cert.pem\"\nprivate_key_path = \"certs/key.pem\"\n"))
	mustWrite(t, filepath.Join(source, "credentials.toml"), []byte("[[client]]\nusername = \"alice\"\npassword = \"SuperSecret-9!\"\n"))
	mustWrite(t, filepath.Join(source, "rules.toml"), []byte("[[rule]]\nname = \"private\"\naction = \"allow\"\ncidr = \"10.0.0.0/8\"\n"))
	result, err := Run(context.Background(), source, target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Users != 1 || result.Rules != 1 || !result.CertificateImported {
		t.Fatalf("result=%#v", result)
	}
	store, err := persistence.Open(context.Background(), filepath.Join(target, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	store.Close()
	if err != nil || snapshot.Hostname != "vpn.example.net" || len(snapshot.Users) != 1 || len(snapshot.Rules) != 1 || snapshot.TLSCertificatePath == "" {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	again, err := Run(context.Background(), source, target)
	if err != nil || !again.AlreadyComplete {
		t.Fatalf("again=%#v err=%v", again, err)
	}
	if _, err = os.Stat(filepath.Join(source, "credentials.toml")); err != nil {
		t.Fatal("source was removed")
	}
	markerData, _ := os.ReadFile(filepath.Join(target, "migration", "legacy-v1.json"))
	if strings.Contains(string(markerData), "SuperSecret") {
		t.Fatal("credential leaked into marker")
	}
}
func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func legacyCertificate(t *testing.T, hostname string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
