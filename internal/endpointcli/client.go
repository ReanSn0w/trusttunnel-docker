package endpointcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type Client struct {
	binary, vpnConfig, hostsConfig string
	timeout                        time.Duration
	maxOutput                      int
	sem                            chan struct{}
}

func New(binary, vpnConfig, hostsConfig string, timeout time.Duration, maxOutput, concurrency int) (*Client, error) {
	if binary == "" || vpnConfig == "" || hostsConfig == "" {
		return nil, errors.New("binary and config paths are required")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if maxOutput <= 0 {
		maxOutput = 1 << 20
	}
	if concurrency <= 0 {
		concurrency = 2
	}
	return &Client{binary: binary, vpnConfig: vpnConfig, hostsConfig: hostsConfig, timeout: timeout, maxOutput: maxOutput, sem: make(chan struct{}, concurrency)}, nil
}

func (c *Client) Export(ctx context.Context, user domain.VPNUser, address string) (domain.ClientConfig, error) {
	if user.Status != domain.UserActive {
		return domain.ClientConfig{}, fmt.Errorf("user %q is not active", user.Username)
	}
	if strings.TrimSpace(address) == "" {
		return domain.ClientConfig{}, errors.New("public address is required")
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return domain.ClientConfig{}, ctx.Err()
	}
	deepLink, err := c.run(ctx, user.Username, address, "deeplink")
	if err != nil {
		return domain.ClientConfig{}, err
	}
	if !strings.HasPrefix(deepLink, "tt://?") && !strings.HasPrefix(deepLink, "tt://") {
		return domain.ClientConfig{}, errors.New("official endpoint returned an invalid deeplink")
	}
	toml, err := c.run(ctx, user.Username, address, "toml")
	if err != nil {
		return domain.ClientConfig{}, err
	}
	return domain.ClientConfig{DeepLink: deepLink, TOML: toml}, nil
}

func (c *Client) run(parent context.Context, username, address, format string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.binary, c.vpnConfig, c.hostsConfig, "-c", username, "-a", address, "--format", format)
	cmd.Dir = filepath.Dir(c.vpnConfig)
	out, stderr := &limitBuffer{max: c.maxOutput}, &limitBuffer{max: 4096}
	cmd.Stdout, cmd.Stderr = out, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("endpoint export timeout: %w", ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("endpoint export failed: %w: %s", err, sanitize(stderr.String()))
	}
	if out.tooLarge {
		return "", errors.New("endpoint export exceeded output limit")
	}
	return strings.TrimSpace(out.String()), nil
}

type limitBuffer struct {
	buf      bytes.Buffer
	max      int
	tooLarge bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if remaining > n {
			remaining = n
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if n > remaining {
		b.tooLarge = true
	}
	return n, nil
}
func (b *limitBuffer) String() string { return b.buf.String() }

func sanitize(s string) string {
	if i := strings.Index(s, "tt://"); i >= 0 {
		s = s[:i] + "[REDACTED]"
	}
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
