package certificate

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// ValidateSourceSettings validates the initial source selection before it is persisted.
func ValidateSourceSettings(source Source, hostname, email, certificatePath, keyPath string) error {
	if err := validateCertificateHostname(hostname); err != nil {
		return err
	}
	switch source {
	case LetsEncrypt:
		if certificatePath != "" || keyPath != "" {
			return errors.New("provided PEM paths conflict with letsencrypt source")
		}
		return ValidateIdentity(email, hostname)
	case SelfSigned:
		if email != "" || certificatePath != "" || keyPath != "" {
			return errors.New("ACME email and provided PEM paths conflict with self-signed source")
		}
	case Provided:
		if email != "" {
			return errors.New("ACME email conflicts with provided source")
		}
		if certificatePath == "" || keyPath == "" {
			return errors.New("provided source requires both PEM paths")
		}
		for _, path := range []string{certificatePath, keyPath} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return errors.New("provided PEM paths must be absolute and clean")
			}
		}
	default:
		return fmt.Errorf("unknown TLS source %q", source)
	}
	return nil
}

func validateCertificateHostname(hostname string) error {
	name := strings.ToLower(strings.TrimSpace(hostname))
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return errors.New("TLS hostname must be a DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid TLS hostname label")
		}
		for _, char := range label {
			if char < 'a' || char > 'z' {
				if char < '0' || char > '9' {
					if char != '-' {
						return errors.New("invalid TLS hostname label")
					}
				}
			}
		}
	}
	return nil
}
