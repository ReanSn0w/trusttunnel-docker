package certificate

import (
	"errors"
	"os"
	"path/filepath"
)

func StoreAccountKey(dataDir string, key []byte) (string, error) {
	if !filepath.IsAbs(dataDir) {
		return "", errors.New("data directory must be absolute")
	}
	if len(key) == 0 {
		return "", errors.New("account key is empty")
	}
	dir := filepath.Join(dataDir, "acme")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "account.key")
	tmp, err := os.CreateTemp(dir, ".account-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(key)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return "", err
	}
	d, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return "", err
	}
	return path, nil
}
