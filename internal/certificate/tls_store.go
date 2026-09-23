package certificate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type TLSStore struct {
	root         string
	mu           sync.Mutex
	writeFile    func(string, []byte, fs.FileMode) error
	beforeRename func() error
}

func NewTLSStore(root string) (*TLSStore, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("TLS root must be absolute")
	}
	if err := os.MkdirAll(filepath.Join(root, "revisions"), 0o700); err != nil {
		return nil, err
	}
	return &TLSStore{root: root, writeFile: writeTLSSynced, beforeRename: func() error { return nil }}, nil
}

func (s *TLSStore) Publish(ctx context.Context, bundle Bundle) (Published, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-ctx.Done():
		return Published{}, ctx.Err()
	default:
	}
	if _, err := validateKeyPair(bundle); err != nil {
		return Published{}, err
	}
	h := sha256.New()
	h.Write(bundle.Certificate)
	h.Write(bundle.IssuerCertificate)
	h.Write(bundle.PrivateKey)
	revision := hex.EncodeToString(h.Sum(nil))[:16]
	revisions := filepath.Join(s.root, "revisions")
	destination := filepath.Join(revisions, revision)
	if _, err := os.Stat(destination); errors.Is(err, fs.ErrNotExist) {
		stage, err := os.MkdirTemp(revisions, ".stage-")
		if err != nil {
			return Published{}, err
		}
		published := false
		defer func() {
			if !published {
				_ = os.RemoveAll(stage)
			}
		}()
		if err = os.Chmod(stage, 0o700); err != nil {
			return Published{}, err
		}
		chain := append(bytes.Clone(bundle.Certificate), bundle.IssuerCertificate...)
		if err = s.writeFile(filepath.Join(stage, "cert.pem"), chain, 0o644); err != nil {
			return Published{}, err
		}
		if err = s.writeFile(filepath.Join(stage, "key.pem"), bundle.PrivateKey, 0o600); err != nil {
			return Published{}, err
		}
		if err = syncTLSDir(stage); err != nil {
			return Published{}, err
		}
		if err = s.beforeRename(); err != nil {
			return Published{}, fmt.Errorf("before TLS publish: %w", err)
		}
		if err = os.Rename(stage, destination); err != nil {
			return Published{}, err
		}
		published = true
		if err = syncTLSDir(revisions); err != nil {
			return Published{}, err
		}
	} else if err != nil {
		return Published{}, err
	}
	old, _ := os.Readlink(filepath.Join(s.root, "current"))
	target := filepath.Join("revisions", revision)
	if old != target && old != "" {
		if err := atomicTLSSymlink(filepath.Join(s.root, "previous"), old); err != nil {
			return Published{}, err
		}
	}
	if old != target {
		if err := atomicTLSSymlink(filepath.Join(s.root, "current"), target); err != nil {
			return Published{}, err
		}
		if err := syncTLSDir(s.root); err != nil {
			return Published{}, err
		}
	}
	return Published{Revision: revision, CertificatePath: filepath.Join(destination, "cert.pem"), PrivateKeyPath: filepath.Join(destination, "key.pem")}, nil
}

func (s *TLSStore) Rollback(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	previous, err := os.Readlink(filepath.Join(s.root, "previous"))
	if err != nil {
		return fmt.Errorf("no previous TLS revision: %w", err)
	}
	current, err := os.Readlink(filepath.Join(s.root, "current"))
	if err != nil {
		return err
	}
	if err = atomicTLSSymlink(filepath.Join(s.root, "current"), previous); err != nil {
		return err
	}
	if err = atomicTLSSymlink(filepath.Join(s.root, "previous"), current); err != nil {
		return err
	}
	return syncTLSDir(s.root)
}
func (s *TLSStore) Active() (Published, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, err := os.Readlink(filepath.Join(s.root, "current"))
	if err != nil {
		return Published{}, err
	}
	dir := filepath.Join(s.root, target)
	return Published{Revision: filepath.Base(target), CertificatePath: filepath.Join(dir, "cert.pem"), PrivateKeyPath: filepath.Join(dir, "key.pem")}, nil
}

func validateKeyPair(bundle Bundle) (*x509.Certificate, error) {
	certs, err := parseCertificates(append(bytes.Clone(bundle.Certificate), bundle.IssuerCertificate...))
	if err != nil || len(certs) == 0 {
		if err == nil {
			err = errors.New("certificate chain is empty")
		}
		return nil, err
	}
	block, rest := pem.Decode(bundle.PrivateKey)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	certPublic, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
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
	return certs[0], nil
}
func writeTLSSynced(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func syncTLSDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func atomicTLSSymlink(path, target string) error {
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
