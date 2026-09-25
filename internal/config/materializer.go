package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Materializer struct {
	root         string
	mu           sync.Mutex
	validate     func(string) error
	writeFile    func(string, []byte, fs.FileMode) error
	beforeRename func() error
}

func NewMaterializer(root string, validate func(string) error) (*Materializer, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("materializer root must be absolute")
	}
	if validate == nil {
		validate = func(string) error { return nil }
	}
	if err := os.MkdirAll(filepath.Join(root, "revisions"), 0o700); err != nil {
		return nil, err
	}
	return &Materializer{root: root, validate: validate, writeFile: writeSynced, beforeRename: func() error { return nil }}, nil
}

func revisionID(files Files) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(files[n])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (m *Materializer) Apply(files Files) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(files) == 0 {
		return "", errors.New("empty configuration set")
	}
	id := revisionID(files)
	revisions := filepath.Join(m.root, "revisions")
	destination := filepath.Join(revisions, id)
	if _, err := os.Stat(destination); errors.Is(err, fs.ErrNotExist) {
		stage, err := os.MkdirTemp(revisions, ".stage-")
		if err != nil {
			return "", err
		}
		published := false
		defer func() {
			if !published {
				_ = os.RemoveAll(stage)
			}
		}()
		if err = os.Chmod(stage, 0o700); err != nil {
			return "", err
		}
		for name, data := range files {
			if filepath.Base(name) != name {
				return "", fmt.Errorf("invalid config filename %q", name)
			}
			mode := fs.FileMode(0o640)
			if name == "credentials.toml" {
				mode = 0o600
			}
			if err = m.writeFile(filepath.Join(stage, name), data, mode); err != nil {
				return "", err
			}
		}
		if err = syncDir(stage); err != nil {
			return "", err
		}
		if err = m.validate(stage); err != nil {
			return "", fmt.Errorf("validate staged revision: %w", err)
		}
		if err = m.beforeRename(); err != nil {
			return "", fmt.Errorf("before publish: %w", err)
		}
		if err = os.Rename(stage, destination); err != nil {
			return "", err
		}
		published = true
		if err = syncDir(revisions); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	old, _ := os.Readlink(filepath.Join(m.root, "current"))
	if old == filepath.Join("revisions", id) {
		return id, nil
	}
	if old != "" {
		if err := atomicSymlink(filepath.Join(m.root, "previous"), old); err != nil {
			return "", err
		}
	}
	if err := atomicSymlink(filepath.Join(m.root, "current"), filepath.Join("revisions", id)); err != nil {
		return "", err
	}
	if err := syncDir(m.root); err != nil {
		return "", err
	}
	return id, nil
}

func (m *Materializer) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, err := os.Readlink(filepath.Join(m.root, "previous"))
	if err != nil {
		return fmt.Errorf("no previous revision: %w", err)
	}
	current, err := os.Readlink(filepath.Join(m.root, "current"))
	if err != nil {
		return err
	}
	if err = atomicSymlink(filepath.Join(m.root, "current"), previous); err != nil {
		return err
	}
	if err = atomicSymlink(filepath.Join(m.root, "previous"), current); err != nil {
		return err
	}
	return syncDir(m.root)
}

// Restore selects a known revision, or clears current on a failed first publish.
func (m *Materializer) Restore(revision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := filepath.Join(m.root, "current")
	if revision == "" {
		if err := os.Remove(current); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		_ = os.Remove(filepath.Join(m.root, "previous"))
		return syncDir(m.root)
	}
	if filepath.Base(revision) != revision || revision == "." || revision == ".." {
		return errors.New("invalid config revision")
	}
	if _, err := os.Stat(filepath.Join(m.root, "revisions", revision)); err != nil {
		return err
	}
	if err := atomicSymlink(current, filepath.Join("revisions", revision)); err != nil {
		return err
	}
	return syncDir(m.root)
}

func (m *Materializer) ActiveDir() (string, error) {
	target, err := os.Readlink(filepath.Join(m.root, "current"))
	if err != nil {
		return "", err
	}
	return filepath.Join(m.root, target), nil
}

func writeSynced(path string, data []byte, mode fs.FileMode) error {
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

func atomicSymlink(path, target string) error {
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

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
