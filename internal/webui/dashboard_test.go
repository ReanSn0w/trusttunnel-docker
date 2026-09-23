package webui

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type statusStub struct{ status domain.EndpointStatus }

func (s statusStub) Status() domain.EndpointStatus { return s.status }

type metricsStub struct{ err error }

func (m metricsStub) Read(context.Context) (domain.EndpointMetrics, error) {
	return domain.EndpointMetrics{ActiveConnections: 2, TotalConnections: 8}, m.err
}

type tlsStub struct{}

func (tlsStub) LoadTLSMetadata(context.Context) (certificate.Metadata, error) {
	return certificate.Metadata{NotAfter: time.Now().Add(time.Hour)}, nil
}
func TestDashboardStatesAndBoundedMetrics(t *testing.T) {
	for _, state := range []string{"stopped", "starting", "ready", "degraded", "crash-loop"} {
		h := NewDashboardHandler(statusStub{domain.EndpointStatus{State: state, Version: "1.1.0"}}, metricsStub{}, tlsStub{})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if !strings.Contains(w.Body.String(), state) || !strings.Contains(w.Body.String(), "1.1.0") {
			t.Fatalf("state %s missing", state)
		}
	}
	h := NewDashboardHandler(statusStub{domain.EndpointStatus{State: "ready"}}, metricsStub{err: errors.New("down")}, tlsStub{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/fragments/status", nil))
	if !strings.Contains(w.Body.String(), "Metrics unavailable") {
		t.Fatal("missing unavailable state")
	}
}
