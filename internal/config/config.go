package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type Files map[string][]byte

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var hostnameRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)

func Validate(s domain.Snapshot) error {
	host, port, err := net.SplitHostPort(s.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if host == "" {
		return errors.New("listen host is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("listen port is out of range")
	}
	if s.Hostname != "" && (!hostnameRE.MatchString(s.Hostname) || len(s.Hostname) > 253) {
		return errors.New("invalid hostname")
	}
	if (s.TLSCertificatePath == "") != (s.TLSPrivateKeyPath == "") {
		return errors.New("certificate and private key paths must be set together")
	}
	for _, p := range []string{s.TLSCertificatePath, s.TLSPrivateKeyPath} {
		if p != "" && (!filepath.IsAbs(p) || strings.Contains(filepath.Clean(p), ".."+string(filepath.Separator))) {
			return errors.New("TLS paths must be absolute and clean")
		}
	}
	seen := map[string]struct{}{}
	for _, u := range s.Users {
		if !usernameRE.MatchString(u.Username) {
			return fmt.Errorf("invalid username %q", u.Username)
		}
		if len(u.Credential) < 12 || len(u.Credential) > 512 {
			return fmt.Errorf("credential length for %q", u.Username)
		}
		if _, ok := seen[u.Username]; ok {
			return fmt.Errorf("duplicate username %q", u.Username)
		}
		seen[u.Username] = struct{}{}
		if u.Status != domain.UserActive && u.Status != domain.UserDisabled && u.Status != domain.UserRevoked {
			return fmt.Errorf("invalid status for %q", u.Username)
		}
	}
	for _, r := range s.Rules {
		if !usernameRE.MatchString(r.Name) || (r.Action != "allow" && r.Action != "deny") {
			return fmt.Errorf("invalid rule %q", r.Name)
		}
		if _, _, err := net.ParseCIDR(r.Network); err != nil {
			return fmt.Errorf("rule %q network: %w", r.Name, err)
		}
	}
	return nil
}

func Render(s domain.Snapshot) (Files, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	users := append([]domain.VPNUser(nil), s.Users...)
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	rules := append([]domain.Rule(nil), s.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	q := func(v string) string { return strconv.Quote(v) }
	var vpn, hosts, credentials, ruleFile bytes.Buffer
	fmt.Fprintf(&vpn, "listen_address = %s\ncredentials_file = %s\nrules_file = %s\n\n[listen_protocols]\nhttp1 = {}\nhttp2 = {}\nquic = {}\n\n[forward_protocol]\ndirect = {}\n\n[metrics]\naddress = %s\nper_client_metrics = false\n", q(s.ListenAddress), q("credentials.toml"), q("rules.toml"), q("127.0.0.1:9090"))
	fmt.Fprintf(&hosts, "[[main_hosts]]\nhostname = %s\n", q(s.Hostname))
	if s.TLSCertificatePath != "" {
		fmt.Fprintf(&hosts, "cert_chain_path = %s\nprivate_key_path = %s\n", q(s.TLSCertificatePath), q(s.TLSPrivateKeyPath))
	}
	for _, u := range users {
		if u.Status != domain.UserActive {
			continue
		}
		fmt.Fprintf(&credentials, "[[client]]\nusername = %s\npassword = %s\n", q(u.Username), q(u.Credential))
	}
	for _, r := range rules {
		fmt.Fprintf(&ruleFile, "# %s\n[[rule]]\ncidr = %s\naction = %s\n", r.Name, q(r.Network), q(r.Action))
	}
	return Files{"vpn.toml": vpn.Bytes(), "hosts.toml": hosts.Bytes(), "credentials.toml": credentials.Bytes(), "rules.toml": ruleFile.Bytes()}, nil
}
