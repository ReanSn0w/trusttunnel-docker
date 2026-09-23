package webui

import (
	"context"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
	"html/template"
	"net/http"
	"strconv"
)

type ApplyEventRepository interface {
	ListApplyEvents(context.Context, int64, int) ([]domain.ApplyEvent, error)
}
type LogSource interface{ Logs() string }
type ControllerLogSource interface{ String() string }
type EventsHandler struct {
	repo       ApplyEventRepository
	endpoint   LogSource
	controller ControllerLogSource
	tmpl       *template.Template
}
type EventsData struct {
	CSRFToken, Error, EndpointLogs, ControllerLogs string
	Events                                         []domain.ApplyEvent
	Next                                           int64
}

func NewEventsHandler(repo ApplyEventRepository, endpoint LogSource, controller ControllerLogSource) *EventsHandler {
	return &EventsHandler{repo: repo, endpoint: endpoint, controller: controller, tmpl: template.Must(template.ParseFS(Files, "templates/events.html"))}
}
func (h *EventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		http.Error(w, "invalid pagination", http.StatusBadRequest)
		return
	}
	events, err := h.repo.ListApplyEvents(r.Context(), before, limit)
	data := EventsData{CSRFToken: CSRFToken(r.Context()), Events: events}
	if err != nil {
		data.Error = err.Error()
	}
	if len(events) == limit {
		data.Next = events[len(events)-1].ID
	}
	if h.endpoint != nil {
		data.EndpointLogs = h.endpoint.Logs()
	}
	if h.controller != nil {
		data.ControllerLogs = h.controller.String()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
