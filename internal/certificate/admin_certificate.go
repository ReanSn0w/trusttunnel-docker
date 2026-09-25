package certificate

import (
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
)

// AdminCertificate exposes one confirmed TLS pair to all new handshakes.
// Preparing a revision never makes it visible until Activate is called.
type AdminCertificate struct {
	active atomic.Pointer[tls.Certificate]
}

func (a *AdminCertificate) Prepare(p Published) (*tls.Certificate, error) {
	if p.Revision == "" || filepath.Base(filepath.Dir(p.CertificatePath)) != p.Revision || filepath.Dir(p.CertificatePath) != filepath.Dir(p.PrivateKeyPath) {
		return nil, errors.New("AdminUI TLS paths do not belong to one revision")
	}
	pair, err := tls.LoadX509KeyPair(p.CertificatePath, p.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load AdminUI TLS revision: %w", err)
	}
	return &pair, nil
}

func (a *AdminCertificate) Activate(pair *tls.Certificate) { a.active.Store(pair) }

func (a *AdminCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if pair := a.active.Load(); pair != nil {
		return pair, nil
	}
	return nil, errors.New("AdminUI TLS certificate is not ready")
}
