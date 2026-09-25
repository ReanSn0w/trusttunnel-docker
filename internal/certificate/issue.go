package certificate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type Repository interface {
	SaveACMEAccount(context.Context, string, string, string, string, string) error
	SaveTLSMetadata(context.Context, Metadata) error
	LoadTLSMetadata(context.Context) (Metadata, error)
	RecordEvent(context.Context, domain.ApplyEvent) error
}
type Published struct{ Revision, CertificatePath, PrivateKeyPath string }
type Publisher interface {
	Publish(context.Context, Bundle) (Published, error)
}
type ClientFactory func(ACMEConfig) (ACMEClient, error)

type Manager struct {
	mu        sync.Mutex
	repo      Repository
	publisher Publisher
	factory   ClientFactory
	provider  *HTTP01Provider
	dataDir   string
	timeout   time.Duration
	now       func() time.Time
}

func NewManager(repo Repository, publisher Publisher, provider *HTTP01Provider, dataDir string, timeout time.Duration, factory ClientFactory) *Manager {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if factory == nil {
		factory = func(c ACMEConfig) (ACMEClient, error) { return NewLegoClient(c) }
	}
	return &Manager{repo: repo, publisher: publisher, provider: provider, dataDir: dataDir, timeout: timeout, factory: factory, now: time.Now}
}

// Serialize keeps TLS settings changes out of an in-flight issue or renewal.
func (m *Manager) Serialize(fn func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn()
}

func (m *Manager) Issue(ctx context.Context, mode Mode, email, hostname string) (Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issue(ctx, mode, email, hostname)
}

func (m *Manager) issue(ctx context.Context, mode Mode, email, hostname string) (Metadata, error) {
	if err := ValidateIdentity(email, hostname); err != nil {
		return Metadata{}, err
	}
	current, err := m.repo.LoadTLSMetadata(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		current = Metadata{State: Unconfigured}
	} else if err != nil {
		return Metadata{}, err
	}
	next, err := current.Transition(Issuing)
	if err != nil {
		return current, err
	}
	directory, err := DirectoryURL(mode)
	if err != nil {
		return current, err
	}
	next.Mode, next.Email, next.Hostname, next.DirectoryURL = mode, email, hostname, directory
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return current, err
	}
	opCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	client, err := m.factory(ACMEConfig{Mode: mode, Email: email, DataDir: m.dataDir, RegistrationURI: current.RegistrationURI, Provider: m.provider, Timeout: m.timeout})
	if err != nil {
		return m.fail(ctx, next, "create-client", err)
	}
	registrationURI, err := client.EnsureAccount(opCtx)
	if err != nil {
		return m.fail(ctx, next, "account", err)
	}
	next.RegistrationURI = registrationURI
	_ = m.repo.SaveACMEAccount(ctx, directory, email, registrationURI, "active", "")
	bundle, err := client.Obtain(opCtx, hostname)
	if err != nil {
		return m.fail(ctx, next, "issue", err)
	}
	validated, err := ValidateBundle(bundle, hostname, mode, m.now())
	if err != nil {
		return m.fail(ctx, next, "validate", err)
	}
	published, err := m.publisher.Publish(opCtx, bundle)
	if err != nil {
		return m.fail(ctx, next, "publish", err)
	}
	next.State = Active
	next.Serial = validated.SerialNumber.String()
	next.Issuer = validated.Issuer.String()
	next.SANs = append([]string(nil), validated.DNSNames...)
	next.NotBefore = validated.NotBefore
	next.NotAfter = validated.NotAfter
	next.Fingerprint = fingerprint(validated)
	next.PreviousRevision = current.ActiveRevision
	next.ActiveRevision = published.Revision
	next.CertificatePath, next.PrivateKeyPath = published.CertificatePath, published.PrivateKeyPath
	next.LastError = ""
	next.UpdatedAt = m.now().UTC()
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return m.fail(ctx, next, "metadata", err)
	}
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: published.Revision, Kind: "tls-issue", Action: "sighup", Result: "pending"})
	return next, nil
}

func (m *Manager) Renew(ctx context.Context) (Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.renew(ctx)
}

func (m *Manager) renew(ctx context.Context) (Metadata, error) {
	current, err := m.repo.LoadTLSMetadata(ctx)
	if err != nil {
		return Metadata{}, err
	}
	if current.Mode == ManualMode {
		return current, errors.New("ACME renewal is disabled in manual mode")
	}
	if err = ValidateIdentity(current.Email, current.Hostname); err != nil {
		return current, err
	}
	next, err := current.Transition(Renewing)
	if err != nil {
		return current, err
	}
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return current, err
	}
	opCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	client, err := m.factory(ACMEConfig{Mode: current.Mode, Email: current.Email, DataDir: m.dataDir, RegistrationURI: current.RegistrationURI, Provider: m.provider, Timeout: m.timeout})
	if err != nil {
		return m.fail(ctx, next, "renew-client", err)
	}
	registrationURI, err := client.EnsureAccount(opCtx)
	if err != nil {
		return m.fail(ctx, next, "renew-account", err)
	}
	next.RegistrationURI = registrationURI
	bundle, err := client.Obtain(opCtx, current.Hostname)
	if err != nil {
		return m.fail(ctx, next, "renew", err)
	}
	validated, err := ValidateBundle(bundle, current.Hostname, current.Mode, m.now())
	if err != nil {
		return m.fail(ctx, next, "renew-validate", err)
	}
	published, err := m.publisher.Publish(opCtx, bundle)
	if err != nil {
		return m.fail(ctx, next, "renew-publish", err)
	}
	next.State = Active
	next.Serial = validated.SerialNumber.String()
	next.Issuer = validated.Issuer.String()
	next.SANs = append([]string(nil), validated.DNSNames...)
	next.NotBefore = validated.NotBefore
	next.NotAfter = validated.NotAfter
	next.Fingerprint = fingerprint(validated)
	next.PreviousRevision = current.ActiveRevision
	next.ActiveRevision = published.Revision
	next.CertificatePath, next.PrivateKeyPath = published.CertificatePath, published.PrivateKeyPath
	next.LastError = ""
	next.UpdatedAt = m.now().UTC()
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return m.fail(ctx, next, "renew-metadata", err)
	}
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: published.Revision, Kind: "tls-renew", Action: "sighup", Result: "pending"})
	return next, nil
}

func (m *Manager) ImportManual(ctx context.Context, hostname string, chain, privateKey []byte) (Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.repo.LoadTLSMetadata(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		current = Metadata{State: Unconfigured}
	} else if err != nil {
		return Metadata{}, err
	}
	bundle := Bundle{Certificate: bytes.Clone(chain), PrivateKey: bytes.Clone(privateKey)}
	validated, err := ValidateBundle(bundle, hostname, ManualMode, m.now())
	if err != nil {
		return current, err
	}
	published, err := m.publisher.Publish(ctx, bundle)
	if err != nil {
		return current, err
	}
	next := current
	next.State = Manual
	next.Mode = ManualMode
	next.Hostname = hostname
	next.Serial = validated.SerialNumber.String()
	next.Issuer = validated.Issuer.String()
	next.SANs = append([]string(nil), validated.DNSNames...)
	next.NotBefore = validated.NotBefore
	next.NotAfter = validated.NotAfter
	next.Fingerprint = fingerprint(validated)
	next.PreviousRevision = current.ActiveRevision
	next.ActiveRevision = published.Revision
	next.CertificatePath, next.PrivateKeyPath = published.CertificatePath, published.PrivateKeyPath
	next.LastError = ""
	next.UpdatedAt = m.now().UTC()
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return current, err
	}
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: published.Revision, Kind: "tls-manual", Action: "sighup", Result: "success"})
	return next, nil
}

func (m *Manager) fail(ctx context.Context, state Metadata, stage string, cause error) (Metadata, error) {
	state.State = Degraded
	state.LastError = sanitizeCertificateError(cause)
	state.UpdatedAt = m.now().UTC()
	_ = m.repo.SaveTLSMetadata(ctx, state)
	_ = m.repo.SaveACMEAccount(ctx, state.DirectoryURL, state.Email, state.RegistrationURI, "error", state.LastError)
	_ = m.repo.RecordEvent(ctx, domain.ApplyEvent{Revision: state.ActiveRevision, Kind: "tls-" + stage, Action: "none", Result: "failure", Error: state.LastError})
	return state, fmt.Errorf("certificate %s: %w", stage, cause)
}

func ValidateBundle(bundle Bundle, hostname string, mode Mode, now time.Time) (*x509.Certificate, error) {
	certs, err := parseCertificates(append(bytes.Clone(bundle.Certificate), bundle.IssuerCertificate...))
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf := certs[0]
	if err = leaf.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("certificate SAN: %w", err)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is outside its validity window")
	}
	for i := 0; i+1 < len(certs); i++ {
		if err = certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("certificate chain: %w", err)
		}
	}
	keyBlock, rest := pem.Decode(bundle.PrivateKey)
	if keyBlock == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	certPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return nil, errors.New("certificate and private key do not match")
	}
	issuer := strings.ToLower(leaf.Issuer.String())
	if mode == Production && (strings.Contains(issuer, "staging") || strings.Contains(issuer, "fake le")) {
		return nil, errors.New("staging certificate rejected in production mode")
	}
	return leaf, nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	seen := map[[32]byte]struct{}{}
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(cert.Raw)
		if _, ok := seen[sum]; !ok {
			seen[sum] = struct{}{}
			certs = append(certs, cert)
		}
		data = rest
	}
	return certs, nil
}

type publicKeyer interface{ Public() crypto.PublicKey }

func parsePrivateKey(der []byte) (publicKeyer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if k, ok := key.(publicKeyer); ok {
			return k, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key")
}
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
func sanitizeCertificateError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	for _, marker := range []string{"-----BEGIN", "tt://", "/.well-known/acme-challenge/"} {
		if i := strings.Index(s, marker); i >= 0 {
			s = s[:i] + "[REDACTED]"
		}
	}
	secretAssignment := regexp.MustCompile(`(?i)(password|token|credential|cookie|csrf|keyauth)(\s*[:=]\s*)\S+`)
	s = secretAssignment.ReplaceAllString(s, `$1$2[REDACTED]`)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
