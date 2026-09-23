package metrics

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type Reader struct {
	url      string
	client   *http.Client
	maxBytes int64
}

func New(url string, timeout time.Duration, maxBytes int64) *Reader {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	return &Reader{url: url, client: &http.Client{Timeout: timeout}, maxBytes: maxBytes}
}

func (r *Reader) Read(ctx context.Context) (domain.EndpointMetrics, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return domain.EndpointMetrics{}, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return domain.EndpointMetrics{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return domain.EndpointMetrics{}, fmt.Errorf("metrics status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, r.maxBytes+1)
	scanner := bufio.NewScanner(limited)
	var result domain.EndpointMetrics
	var read int64
	for scanner.Scan() {
		read += int64(len(scanner.Bytes()) + 1)
		if read > r.maxBytes {
			return result, errors.New("metrics response exceeds limit")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "{") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "trusttunnel_active_connections":
			result.ActiveConnections = value
		case "trusttunnel_connections_total":
			result.TotalConnections = value
		}
	}
	return result, scanner.Err()
}
