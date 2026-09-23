package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/datalock"
	_ "modernc.org/sqlite"
)

type Versions struct{ Controller, Commit, Endpoint string }
type Manifest struct {
	Format    int               `json:"format"`
	CreatedAt time.Time         `json:"created_at"`
	Versions  Versions          `json:"versions"`
	Files     map[string]string `json:"files"`
}

var included = []string{"config", "tls", "acme", "migration"}

func Create(ctx context.Context, dataDir, output string, versions Versions) error {
	if !filepath.IsAbs(dataDir) || !filepath.IsAbs(output) {
		return errors.New("data directory and output must be absolute")
	}
	rel, _ := filepath.Rel(dataDir, output)
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("backup output must be outside data directory")
	}
	work, err := os.MkdirTemp("", "trusttunnel-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "controller.db"))
	if err != nil {
		return err
	}
	backupDB := filepath.Join(work, "controller.db")
	_, err = db.ExecContext(ctx, "VACUUM INTO ?", backupDB)
	closeErr := db.Close()
	if err != nil {
		return fmt.Errorf("sqlite online backup: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Chmod(backupDB, 0o600); err != nil {
		return err
	}
	for _, name := range included {
		source := filepath.Join(dataDir, name)
		if _, e := os.Lstat(source); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil {
			return e
		}
		if err = copyTree(source, filepath.Join(work, name)); err != nil {
			return err
		}
	}
	manifest := Manifest{Format: 1, CreatedAt: time.Now().UTC(), Versions: versions, Files: map[string]string{}}
	if err = filepath.WalkDir(work, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		name, _ := filepath.Rel(work, path)
		digest, e := digestPath(path)
		if e != nil {
			return e
		}
		manifest.Files[filepath.ToSlash(name)] = digest
		return nil
	}); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(work, "backup-manifest.json"), append(data, '\n'), 0o600); err != nil {
		return err
	}
	return archive(work, output)
}
func Verify(archivePath string) (Manifest, error) {
	work, err := os.MkdirTemp("", "trusttunnel-verify-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(work)
	if err = extract(archivePath, work); err != nil {
		return Manifest{}, err
	}
	return verifyDir(work)
}
func Restore(archivePath, target string) (Manifest, error) {
	if !filepath.IsAbs(target) {
		return Manifest{}, errors.New("target must be absolute")
	}
	lock, err := datalock.Acquire(target)
	if err != nil {
		return Manifest{}, err
	}
	defer lock.Close()
	entries, err := os.ReadDir(target)
	if err != nil {
		return Manifest{}, err
	}
	for _, entry := range entries {
		if entry.Name() != ".controller.lock" {
			return Manifest{}, errors.New("restore target must be empty")
		}
	}
	stage := filepath.Join(target, ".restore-stage")
	if err = os.Mkdir(stage, 0o700); err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(stage)
	if err = extract(archivePath, stage); err != nil {
		return Manifest{}, err
	}
	manifest, err := verifyDir(stage)
	if err != nil {
		return Manifest{}, err
	}
	stageEntries, err := os.ReadDir(stage)
	if err != nil {
		return Manifest{}, err
	}
	for _, entry := range stageEntries {
		if err = os.Rename(filepath.Join(stage, entry.Name()), filepath.Join(target, entry.Name())); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}
func verifyDir(root string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(root, "backup-manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Format != 1 {
		return manifest, errors.New("unsupported backup format")
	}
	for name, want := range manifest.Files {
		path, err := safePath(root, name)
		if err != nil {
			return manifest, err
		}
		got, err := digestPath(path)
		if err != nil {
			return manifest, err
		}
		if got != want {
			return manifest, fmt.Errorf("backup checksum mismatch for %s", name)
		}
	}
	return manifest, nil
}
func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, path)
		dst := filepath.Join(target, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err = os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			return os.Symlink(link, dst)
		}
		if d.IsDir() {
			return os.MkdirAll(dst, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if err = os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
}
func digestPath(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		_, _ = hash.Write([]byte("symlink:" + target))
	} else {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(hash, file)
		closeErr := file.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func archive(root, output string) error {
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	tmp := output + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	err = filepath.Walk(root, func(path string, info fs.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if path == root {
			return nil
		}
		name, _ := filepath.Rel(root, path)
		header, e := tar.FileInfoHeader(info, "")
		if e != nil {
			return e
		}
		header.Name = filepath.ToSlash(name)
		if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			if e != nil {
				return e
			}
			header.Linkname = target
		}
		if e = tw.WriteHeader(header); e != nil {
			return e
		}
		if info.Mode().IsRegular() {
			in, e := os.Open(path)
			if e != nil {
				return e
			}
			_, e = io.Copy(tw, in)
			_ = in.Close()
			return e
		}
		return nil
	})
	if closeErr := tw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := gz.Close(); err == nil {
		err = closeErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, output); err != nil {
		return err
	}
	ok = true
	return nil
}
func extract(archivePath, target string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		path, err := safePath(target, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(path, fs.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(header.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink:
			cleanLink := filepath.Clean(header.Linkname)
			if filepath.IsAbs(header.Linkname) || cleanLink == ".." || strings.HasPrefix(cleanLink, ".."+string(filepath.Separator)) {
				return errors.New("unsafe backup symlink")
			}
			if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err = os.Symlink(header.Linkname, path); err != nil {
				return err
			}
		default:
			return errors.New("unsupported backup entry")
		}
	}
}
func safePath(root, name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("unsafe backup path")
	}
	return filepath.Join(root, clean), nil
}
