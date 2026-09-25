package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

const selfSignedLifetime = 365 * 24 * time.Hour

func GenerateSelfSigned(hostname string, now time.Time) (Bundle, error) {
	if err := ValidateSourceSettings(SelfSigned, hostname, "", "", ""); err != nil {
		return Bundle{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return Bundle{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(selfSignedLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return Bundle{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})}, nil
}

func (m *Manager) ensureSelfSigned(ctx context.Context, current Metadata, lead time.Duration) (Metadata, error) {
	if err := ValidateSourceSettings(SelfSigned, current.Hostname, "", "", ""); err != nil {
		return current, err
	}
	if current.State == Issuing || current.State == Renewing {
		current.State = Degraded
		if err := m.repo.SaveTLSMetadata(ctx, current); err != nil {
			return current, err
		}
	}
	if current.ActiveRevision != "" && current.State != Unconfigured {
		chain, certErr := os.ReadFile(current.CertificatePath)
		key, keyErr := os.ReadFile(current.PrivateKeyPath)
		if certErr == nil && keyErr == nil {
			leaf, err := ValidateBundle(Bundle{Certificate: chain, PrivateKey: key}, current.Hostname, ManualMode, m.now())
			if err == nil {
				if lead <= 0 || lead > selfSignedLifetime/3 {
					lead = 30 * 24 * time.Hour
				}
				if m.now().Before(leaf.NotAfter.Add(-lead)) {
					if current.State != Active {
						current.State, current.LastError = Active, ""
						if err = m.repo.SaveTLSMetadata(ctx, current); err != nil {
							return current, err
						}
					}
					return current, nil
				}
			}
		}
	}
	next := current
	if current.ActiveRevision == "" || current.State == Unconfigured {
		next.State = Issuing
	} else {
		next.State = Renewing
	}
	if err := m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return current, err
	}
	bundle, err := GenerateSelfSigned(current.Hostname, m.now())
	if err != nil {
		return m.failUnmanaged(ctx, next, "self-signed-generate", err)
	}
	return m.publishUnmanaged(ctx, current, next, bundle, "tls-self-signed")
}

func (m *Manager) publishUnmanaged(ctx context.Context, previous, next Metadata, bundle Bundle, kind string) (Metadata, error) {
	leaf, err := ValidateBundle(bundle, next.Hostname, ManualMode, m.now())
	if err != nil {
		return m.failUnmanaged(ctx, next, kind+"-validate", err)
	}
	m.lockApply()
	defer m.unlockApply()
	published, err := m.publisher.Publish(ctx, bundle)
	if err != nil {
		return m.failUnmanaged(ctx, next, kind+"-publish", err)
	}
	next.State = Active
	next.Serial = leaf.SerialNumber.String()
	next.Issuer = leaf.Issuer.String()
	next.SANs = append([]string(nil), leaf.DNSNames...)
	next.NotBefore, next.NotAfter = leaf.NotBefore, leaf.NotAfter
	next.Fingerprint = fingerprint(leaf)
	next.PreviousRevision = previous.ActiveRevision
	next.ActiveRevision = published.Revision
	next.CertificatePath, next.PrivateKeyPath = published.CertificatePath, published.PrivateKeyPath
	next.LastError = ""
	next.UpdatedAt = m.now().UTC()
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		rollbackErr := m.revertPublication()
		return m.failUnmanaged(ctx, previous, kind+"-metadata", errors.Join(err, rollbackErr))
	}
	m.completePublication()
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: published.Revision, Kind: kind, Action: "none", Result: "success"})
	return next, nil
}

func (m *Manager) failUnmanaged(ctx context.Context, previous Metadata, stage string, cause error) (Metadata, error) {
	previous.State = Degraded
	previous.LastError = sanitizeCertificateError(cause)
	previous.UpdatedAt = m.now().UTC()
	_ = m.repo.SaveTLSMetadata(ctx, previous)
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: previous.ActiveRevision, Kind: stage, Action: "none", Result: "failure", Error: previous.LastError})
	return previous, fmt.Errorf("certificate %s: %w", stage, cause)
}
