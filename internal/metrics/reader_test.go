package metrics

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func readerWithBody(body string, max int64) *Reader {
	r := New("http://metrics.local", time.Second, max)
	r.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	return r
}

func TestReadAllowListedMetrics(t *testing.T) {
	got, err := readerWithBody("trusttunnel_active_connections 3\ntrusttunnel_connections_total 8\nsecret_metric{username=\"alice\"} 42\n", 1024).Read(context.Background())
	if err != nil || got.ActiveConnections != 3 || got.TotalConnections != 8 {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestRejectOversizedMetrics(t *testing.T) {
	if _, err := readerWithBody(strings.Repeat("x", 128), 16).Read(context.Background()); err == nil {
		t.Fatal("expected size error")
	}
}
