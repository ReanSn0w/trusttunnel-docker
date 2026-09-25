// Package clientprofile applies client-side transport settings to official exports.
package clientprofile

import (
	"errors"
	"net"
	"regexp"
	"strconv"
)

type Settings struct {
	PublicAddress string
	Protocol      string
	AntiDPI       bool
	IPv6          bool
	TLSProfile    string
	PostQuantum   bool
}

func Default() Settings {
	return Settings{Protocol: "http2", IPv6: true, TLSProfile: "chrome", PostQuantum: true}
}

var dnsName = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$`)

func (s Settings) Validate() error {
	if s.PublicAddress != "" {
		host, port, err := net.SplitHostPort(s.PublicAddress)
		if err != nil {
			return errors.New("public address must be host:port (IPv6: [address]:port)")
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return errors.New("public port must be between 1 and 65535")
		}
		ip := net.ParseIP(host)
		if ip != nil {
			if ip.IsUnspecified() || ip.IsMulticast() {
				return errors.New("public address must identify a reachable server")
			}
		} else if len(host) > 253 || !dnsName.MatchString(host) {
			return errors.New("invalid public hostname")
		}
	}
	if s.Protocol != "http2" && s.Protocol != "http3" {
		return errors.New("choose HTTP/2 or QUIC/HTTP/3")
	}
	if s.AntiDPI && s.Protocol != "http2" {
		return errors.New("Anti-DPI preset requires HTTP/2; test QUIC separately")
	}
	switch s.TLSProfile {
	case "chrome", "safari", "firefox", "okhttp", "openssl", "default":
	default:
		return errors.New("unknown TLS fingerprint")
	}
	return nil
}

func (s Settings) Address(hostname string) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	if s.PublicAddress != "" {
		return s.PublicAddress, nil
	}
	if !dnsName.MatchString(hostname) || len(hostname) > 253 || net.ParseIP(hostname) != nil {
		return "", errors.New("configure a VPN TLS hostname first")
	}
	return net.JoinHostPort(hostname, "443"), nil
}
