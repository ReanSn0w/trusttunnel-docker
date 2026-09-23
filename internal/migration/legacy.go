package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/config"
	"github.com/reansnow/trusttunnel-controller/internal/datalock"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"github.com/reansnow/trusttunnel-controller/internal/persistence"
)

type Result struct {
	Users, Rules                         int
	Hostname                             string
	CertificateImported, AlreadyComplete bool
}
type legacyVPN struct {
	ListenAddress string `toml:"listen_address"`
}
type legacyHost struct {
	Hostname       string `toml:"hostname"`
	CertChainPath  string `toml:"cert_chain_path"`
	PrivateKeyPath string `toml:"private_key_path"`
}
type legacyHosts struct {
	MainHosts []legacyHost `toml:"main_hosts"`
}
type legacyUser struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}
type legacyCredentials struct {
	Client []legacyUser `toml:"client"`
}
type legacyRule struct {
	Name    string `toml:"name"`
	Action  string `toml:"action"`
	CIDR    string `toml:"cidr"`
	Network string `toml:"network"`
}
type legacyRules struct {
	Rule  []legacyRule `toml:"rule"`
	Rules []legacyRule `toml:"rules"`
}
type marker struct {
	Version     int               `json:"version"`
	Source      string            `json:"source"`
	Files       map[string]string `json:"files"`
	CompletedAt time.Time         `json:"completed_at"`
}

func Run(ctx context.Context, source, target string) (Result, error) {
	if !filepath.IsAbs(source) || !filepath.IsAbs(target) {
		return Result{}, errors.New("source and target must be absolute")
	}
	source = filepath.Clean(source)
	target = filepath.Clean(target)
	if source == target {
		return Result{}, errors.New("source and target must differ")
	}
	lock, err := datalock.Acquire(target)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()
	markerPath := filepath.Join(target, "migration", "legacy-v1.json")
	if _, err = os.Stat(markerPath); err == nil {
		return Result{AlreadyComplete: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	required := []string{"vpn.toml", "hosts.toml", "credentials.toml"}
	for _, name := range required {
		if info, e := os.Stat(filepath.Join(source, name)); e != nil || !info.Mode().IsRegular() {
			return Result{}, fmt.Errorf("legacy %s is unavailable", name)
		}
	}
	var vpn legacyVPN
	var hosts legacyHosts
	var credentials legacyCredentials
	var rules legacyRules
	if _, err = toml.DecodeFile(filepath.Join(source, "vpn.toml"), &vpn); err != nil {
		return Result{}, fmt.Errorf("vpn.toml: %w", err)
	}
	if _, err = toml.DecodeFile(filepath.Join(source, "hosts.toml"), &hosts); err != nil {
		return Result{}, fmt.Errorf("hosts.toml: %w", err)
	}
	if _, err = toml.DecodeFile(filepath.Join(source, "credentials.toml"), &credentials); err != nil {
		return Result{}, fmt.Errorf("credentials.toml: %w", err)
	}
	rulePath := filepath.Join(source, "rules.toml")
	if _, e := os.Stat(rulePath); e == nil {
		if _, err = toml.DecodeFile(rulePath, &rules); err != nil {
			return Result{}, fmt.Errorf("rules.toml: %w", err)
		}
	}
	if len(hosts.MainHosts) == 0 || strings.TrimSpace(hosts.MainHosts[0].Hostname) == "" {
		return Result{}, errors.New("legacy hostname is missing")
	}
	if len(credentials.Client) == 0 {
		return Result{}, errors.New("legacy credentials contain no users")
	}
	store, err := persistence.Open(ctx, filepath.Join(target, "controller.db"))
	if err != nil {
		return Result{}, err
	}
	defer store.Close()
	host := hosts.MainHosts[0]
	if err = store.SetHostname(ctx, host.Hostname); err != nil {
		return Result{}, err
	}
	if vpn.ListenAddress != "" {
		if err = store.SetListenAddress(ctx, vpn.ListenAddress); err != nil {
			return Result{}, err
		}
	}
	result := Result{Hostname: host.Hostname}
	for _, u := range credentials.Client {
		if u.Username == "" || u.Password == "" {
			return Result{}, errors.New("legacy credential is incomplete")
		}
		if err = store.UpsertUser(ctx, domain.VPNUser{Username: u.Username, Credential: u.Password, Status: domain.UserActive}); err != nil {
			return Result{}, err
		}
		result.Users++
	}
	allRules := append(rules.Rule, rules.Rules...)
	for i, r := range allRules {
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("legacy-%d", i+1)
		}
		network := r.Network
		if network == "" {
			network = r.CIDR
		}
		if err = store.UpsertRule(ctx, domain.Rule{Name: name, Action: r.Action, Network: network}); err != nil {
			return Result{}, err
		}
		result.Rules++
	}
	if host.CertChainPath != "" || host.PrivateKeyPath != "" {
		certPath, e := legacyPath(source, host.CertChainPath)
		if e != nil {
			return Result{}, e
		}
		keyPath, e := legacyPath(source, host.PrivateKeyPath)
		if e != nil {
			return Result{}, e
		}
		chain, e := os.ReadFile(certPath)
		if e != nil {
			return Result{}, e
		}
		key, e := os.ReadFile(keyPath)
		if e != nil {
			return Result{}, e
		}
		tlsStore, e := certificate.NewTLSStore(filepath.Join(target, "tls"))
		if e != nil {
			return Result{}, e
		}
		manager := certificate.NewManager(store, tlsStore, nil, target, time.Minute, nil)
		if _, e = manager.ImportManual(ctx, host.Hostname, chain, key); e != nil {
			return Result{}, fmt.Errorf("legacy certificate: %w", e)
		}
		result.CertificateImported = true
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return Result{}, err
	}
	files, err := config.Render(snapshot)
	if err != nil {
		return Result{}, err
	}
	materializer, err := config.NewMaterializer(filepath.Join(target, "config"), nil)
	if err != nil {
		return Result{}, err
	}
	revision, err := materializer.Apply(files)
	if err != nil {
		return Result{}, err
	}
	if err = store.SetActiveRevision(ctx, revision); err != nil {
		return Result{}, err
	}
	hashes, err := manifest(source, append(required, "rules.toml"))
	if err != nil {
		return Result{}, err
	}
	if err = writeMarker(markerPath, marker{Version: 1, Source: source, Files: hashes, CompletedAt: time.Now().UTC()}); err != nil {
		return Result{}, err
	}
	return result, nil
}
func legacyPath(source, raw string) (string, error) {
	if raw == "" {
		return "", errors.New("legacy TLS path is missing")
	}
	candidate := raw
	if filepath.IsAbs(raw) {
		trimmed := strings.TrimPrefix(filepath.Clean(raw), string(filepath.Separator))
		trimmed = strings.TrimPrefix(trimmed, "trusttunnel_endpoint/")
		candidate = filepath.Join(source, trimmed)
	} else {
		candidate = filepath.Join(source, raw)
	}
	candidate = filepath.Clean(candidate)
	rel, err := filepath.Rel(source, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("legacy TLS path escapes source")
	}
	return candidate, nil
}
func manifest(source string, names []string) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(source, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		out[name] = hex.EncodeToString(sum[:])
	}
	return out, nil
}
func writeMarker(path string, value marker) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
