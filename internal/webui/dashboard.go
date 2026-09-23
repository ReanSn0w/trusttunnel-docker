package webui

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type StatusProvider interface{ Status() domain.EndpointStatus }
type MetricsProvider interface {
	Read(context.Context) (domain.EndpointMetrics, error)
}
type TLSMetadataProvider interface {
	LoadTLSMetadata(context.Context) (certificate.Metadata, error)
}
type DashboardHandler struct {
	process StatusProvider
	metrics MetricsProvider
	tls     TLSMetadataProvider
	tmpl    *template.Template
	now     func() time.Time
}
type DashboardData struct {
	Title, CSRFToken string
	Endpoint         domain.EndpointStatus
	Metrics          domain.EndpointMetrics
	MetricsAvailable bool
	TLS              certificate.Metadata
	Uptime           time.Duration
}

func NewDashboardHandler(process StatusProvider, metrics MetricsProvider, tls TLSMetadataProvider) *DashboardHandler {
	return &DashboardHandler{process: process, metrics: metrics, tls: tls, tmpl: template.Must(template.ParseFS(Files, "templates/dashboard.html")), now: time.Now}
}
func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := h.data(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path == "/fragments/status" {
		_ = h.tmpl.ExecuteTemplate(w, "status", data)
		return
	}
	_ = h.tmpl.ExecuteTemplate(w, "page", data)
}
func (h *DashboardHandler) data(ctx context.Context) DashboardData {
	status := h.process.Status()
	data := DashboardData{Title: "Dashboard", CSRFToken: CSRFToken(ctx), Endpoint: status}
	if !status.StartedAt.IsZero() {
		data.Uptime = h.now().Sub(status.StartedAt).Round(time.Second)
	}
	if h.metrics != nil {
		if m, err := h.metrics.Read(ctx); err == nil {
			data.Metrics = m
			data.MetricsAvailable = true
		}
	}
	if h.tls != nil {
		data.TLS, _ = h.tls.LoadTLSMetadata(ctx)
	}
	return data
}
