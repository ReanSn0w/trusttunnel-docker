package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func makeBundle(t *testing.T, hostname, issuer string) Bundle {
	t.Helper()
	now := time.Now().UTC()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: issuer}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), IssuerCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func TestValidateBundle(t *testing.T) {
	b := makeBundle(t, "vpn.example.net", "Production CA")
	if _, err := ValidateBundle(b, "vpn.example.net", Production, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBundle(b, "other.example.net", Production, time.Now()); err == nil {
		t.Fatal("accepted wrong SAN")
	}
	other := makeBundle(t, "vpn.example.net", "Production CA")
	b.PrivateKey = other.PrivateKey
	if _, err := ValidateBundle(b, "vpn.example.net", Production, time.Now()); err == nil {
		t.Fatal("accepted mismatched key")
	}
}
func TestRejectStagingCertificateInProduction(t *testing.T) {
	b := makeBundle(t, "vpn.example.net", "Fake LE Intermediate X1")
	if _, err := ValidateBundle(b, "vpn.example.net", Production, time.Now()); err == nil {
		t.Fatal("accepted staging certificate")
	}
	if _, err := ValidateBundle(b, "vpn.example.net", Staging, time.Now()); err != nil {
		t.Fatal(err)
	}
}

type certRepo struct {
	mu     sync.Mutex
	m      Metadata
	events []domain.ApplyEvent
}

func (r *certRepo) SaveACMEAccount(context.Context, string, string, string, string, string) error {
	return nil
}
func (r *certRepo) SaveTLSMetadata(_ context.Context, m Metadata) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m = m
	return nil
}
func (r *certRepo) LoadTLSMetadata(context.Context) (Metadata, error) {
	return Metadata{State: Unconfigured}, nil
}
func (r *certRepo) RecordEvent(_ context.Context, e domain.ApplyEvent) error {
	r.events = append(r.events, e)
	return nil
}

type fakeACME struct{ bundle Bundle }

func (f fakeACME) EnsureAccount(context.Context) (string, error)  { return "account-uri", nil }
func (f fakeACME) Obtain(context.Context, string) (Bundle, error) { return f.bundle, nil }

type fakePublisher struct{}

func (fakePublisher) Publish(context.Context, Bundle) (Published, error) {
	return Published{Revision: "tls-r1", CertificatePath: "cert.pem", PrivateKeyPath: "key.pem"}, nil
}

func TestManagerIssue(t *testing.T) {
	repo := &certRepo{}
	bundle := makeBundle(t, "vpn.example.net", "Production CA")
	m := NewManager(repo, fakePublisher{}, NewHTTP01Provider("127.0.0.1:0", 1), t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) { return fakeACME{bundle}, nil })
	got, err := m.Issue(context.Background(), Production, "admin@example.net", "vpn.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Active || got.ActiveRevision != "tls-r1" || got.Fingerprint == "" {
		t.Fatalf("metadata=%#v", got)
	}
}
