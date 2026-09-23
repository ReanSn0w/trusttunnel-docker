package certificate

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	legocert "github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

type Bundle struct{ Certificate, IssuerCertificate, PrivateKey []byte }
type ACMEClient interface {
	EnsureAccount(context.Context) (string, error)
	Obtain(context.Context, string) (Bundle, error)
}

type ACMEConfig struct {
	Mode                            Mode
	Email, DataDir, RegistrationURI string
	DirectoryOverride               string
	Provider                        challenge.Provider
	Timeout                         time.Duration
}

type legoUser struct {
	email        string
	key          crypto.Signer
	registration *acme.ExtendedAccount
}

func (u *legoUser) GetEmail() string                       { return u.email }
func (u *legoUser) GetRegistration() *acme.ExtendedAccount { return u.registration }
func (u *legoUser) GetPrivateKey() crypto.Signer           { return u.key }

type LegoClient struct {
	client *lego.Client
	user   *legoUser
}

func DirectoryURL(mode Mode) (string, error) {
	switch mode {
	case Production:
		return lego.DirectoryURLLetsEncrypt, nil
	case Staging:
		return lego.DirectoryURLLetsEncryptStaging, nil
	default:
		return "", fmt.Errorf("ACME unavailable in mode %q", mode)
	}
}

func NewLegoClient(cfg ACMEConfig) (*LegoClient, error) {
	if err := ValidateIdentity(cfg.Email, "placeholder.example.org"); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.DataDir) {
		return nil, errors.New("data directory must be absolute")
	}
	key, err := loadOrCreateAccountKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	user := &legoUser{email: cfg.Email, key: key}
	if cfg.RegistrationURI != "" {
		user.registration = &acme.ExtendedAccount{Location: cfg.RegistrationURI}
	}
	directory, err := DirectoryURL(cfg.Mode)
	if err != nil {
		return nil, err
	}
	if cfg.DirectoryOverride != "" {
		directory = cfg.DirectoryOverride
	}
	lcfg := lego.NewConfig(user)
	lcfg.CADirURL = directory
	if cfg.Timeout > 0 {
		lcfg.HTTPClient.Timeout = cfg.Timeout
		lcfg.Certificate.Timeout = cfg.Timeout
	}
	client, err := lego.NewClient(lcfg)
	if err != nil {
		return nil, err
	}
	if cfg.Provider == nil {
		return nil, errors.New("HTTP-01 provider is required")
	}
	if err = client.Challenge.SetHTTP01Provider(cfg.Provider); err != nil {
		return nil, err
	}
	return &LegoClient{client: client, user: user}, nil
}

func (c *LegoClient) EnsureAccount(ctx context.Context) (string, error) {
	if c.user.registration != nil {
		reg, err := c.client.Registration.QueryRegistration(ctx)
		if err == nil {
			c.user.registration = reg
			return reg.Location, nil
		}
	}
	if reg, err := c.client.Registration.ResolveAccountByKey(ctx); err == nil {
		c.user.registration = reg
		return reg.Location, nil
	}
	reg, err := c.client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return "", err
	}
	c.user.registration = reg
	return reg.Location, nil
}

func (c *LegoClient) Obtain(ctx context.Context, hostname string) (Bundle, error) {
	if err := ValidateIdentity(c.user.email, hostname); err != nil {
		return Bundle{}, err
	}
	res, err := c.client.Certificate.Obtain(ctx, legocert.ObtainRequest{Domains: []string{hostname}, Bundle: true, KeyType: certcrypto.EC256, AlwaysDeactivateAuthorizations: true})
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Certificate: res.Certificate, IssuerCertificate: res.IssuerCertificate, PrivateKey: res.PrivateKey}, nil
}

func ValidateIdentity(email, hostname string) error {
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || !strings.Contains(email, "@") {
		return errors.New("invalid ACME email")
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return errors.New("ACME hostname must be a public DNS name")
	}
	for _, suffix := range []string{".local", ".localhost", ".internal", ".invalid", ".test", ".example"} {
		if strings.HasSuffix(name, suffix) {
			return errors.New("ACME hostname uses a reserved suffix")
		}
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("invalid ACME hostname")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("invalid ACME hostname")
			}
		}
	}
	return nil
}

func loadOrCreateAccountKey(dataDir string) (crypto.Signer, error) {
	path := filepath.Join(dataDir, "acme", "account.key")
	data, err := os.ReadFile(path)
	if err == nil {
		return parseAccountKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if _, err = StoreAccountKey(dataDir, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}
func parseAccountKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid account key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("account key is not a signer")
	}
	return signer, nil
}
