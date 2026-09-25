package certificate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxProvidedPEMBytes = 1 << 20

func (m *Manager) ensureProvided(ctx context.Context, current Metadata) (Metadata, error) {
	if current.ProvidedCertificatePath == "" && current.ProvidedKeyPath == "" && current.ActiveRevision != "" {
		// A migrated manual import has no mounted source. Keep its internal pair.
		bundle, err := readPublishedBundle(current)
		if err != nil {
			return m.failUnmanaged(ctx, current, "provided-read", err)
		}
		if _, err = ValidateBundle(bundle, current.Hostname, ManualMode, m.now()); err != nil {
			return m.failUnmanaged(ctx, current, "provided-validate", err)
		}
		if current.State != Active || current.LastError != "" {
			current.State, current.LastError = Active, ""
			if err = m.repo.SaveTLSMetadata(ctx, current); err != nil {
				return current, err
			}
		}
		return current, nil
	}
	if err := ValidateSourceSettings(Provided, current.Hostname, "", current.ProvidedCertificatePath, current.ProvidedKeyPath); err != nil {
		return m.failUnmanaged(ctx, current, "provided-settings", err)
	}
	chain, err := readPEMLimited(current.ProvidedCertificatePath)
	if err != nil {
		return m.failUnmanaged(ctx, current, "provided-read", err)
	}
	key, err := readPEMLimited(current.ProvidedKeyPath)
	if err != nil {
		return m.failUnmanaged(ctx, current, "provided-read", err)
	}
	bundle := Bundle{Certificate: chain, PrivateKey: key}
	if _, err = ValidateBundle(bundle, current.Hostname, ManualMode, m.now()); err != nil {
		return m.failUnmanaged(ctx, current, "provided-validate", err)
	}
	if current.ActiveRevision != "" && current.State != Unconfigured {
		old, readErr := readPublishedBundle(current)
		if readErr == nil && bytes.Equal(old.Certificate, bundle.Certificate) && bytes.Equal(old.PrivateKey, bundle.PrivateKey) {
			if current.State != Active || current.LastError != "" {
				current.State, current.LastError = Active, ""
				if err = m.repo.SaveTLSMetadata(ctx, current); err != nil {
					return current, err
				}
			}
			return current, nil
		}
	}
	next := current
	if current.ActiveRevision == "" || current.State == Unconfigured {
		next.State = Issuing
	} else {
		next.State = Renewing
	}
	if err = m.repo.SaveTLSMetadata(ctx, next); err != nil {
		return current, err
	}
	return m.publishUnmanaged(ctx, current, next, bundle, "tls-provided")
}

func readPEMLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("provided PEM source must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxProvidedPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProvidedPEMBytes {
		return nil, fmt.Errorf("provided PEM exceeds %d bytes", maxProvidedPEMBytes)
	}
	return data, nil
}

func readPublishedBundle(m Metadata) (Bundle, error) {
	chain, err := readPEMLimited(m.CertificatePath)
	if err != nil {
		return Bundle{}, err
	}
	key, err := readPEMLimited(m.PrivateKeyPath)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Certificate: chain, PrivateKey: key}, nil
}
