package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

type Config struct {
	Binary        string
	Args          func(string) []string
	WorkingDir    string
	StopTimeout   time.Duration
	MaxRestarts   int
	RestartWindow time.Duration
	MaxLogBytes   int
	Version       string
}

type Supervisor struct {
	cfg      Config
	mu       sync.Mutex
	cmd      *exec.Cmd
	done     chan struct{}
	desired  bool
	stopping bool
	status   domain.EndpointStatus
	restarts []time.Time
	logs     *ringWriter
}

func New(cfg Config) (*Supervisor, error) {
	if cfg.Binary == "" || cfg.Args == nil {
		return nil, errors.New("binary and args are required")
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = 10 * time.Second
	}
	if cfg.MaxRestarts <= 0 {
		cfg.MaxRestarts = 5
	}
	if cfg.RestartWindow <= 0 {
		cfg.RestartWindow = time.Minute
	}
	if cfg.MaxLogBytes <= 0 {
		cfg.MaxLogBytes = 256 << 10
	}
	return &Supervisor{cfg: cfg, logs: newRingWriter(cfg.MaxLogBytes), status: domain.EndpointStatus{State: "stopped", Version: cfg.Version}}, nil
}

func (s *Supervisor) Start(ctx context.Context, revision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return errors.New("endpoint is already running")
	}
	s.desired = true
	s.stopping = false
	return s.startLocked(ctx, revision)
}

func (s *Supervisor) startLocked(ctx context.Context, revision string) error {
	cmd := exec.Command(s.cfg.Binary, s.cfg.Args(revision)...)
	cmd.Dir = s.cfg.WorkingDir
	cmd.Stdout = s.logs
	cmd.Stderr = s.logs
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		s.status.State = "stopped"
		s.status.LastError = sanitize(err.Error())
		return err
	}
	s.cmd = cmd
	s.done = make(chan struct{})
	s.status = domain.EndpointStatus{State: "starting", Revision: revision, Version: s.cfg.Version, PID: cmd.Process.Pid, StartedAt: time.Now().UTC()}
	done := s.done
	go s.watch(ctx, cmd, revision, done)
	return nil
}

func (s *Supervisor) watch(ctx context.Context, cmd *exec.Cmd, revision string, done chan struct{}) {
	err := cmd.Wait()
	close(done)
	s.mu.Lock()
	if s.cmd != cmd {
		s.mu.Unlock()
		return
	}
	s.cmd = nil
	s.status.PID = 0
	if err != nil {
		s.status.LastError = sanitize(err.Error())
	}
	if !s.desired || s.stopping || ctx.Err() != nil {
		s.status.State = "stopped"
		s.mu.Unlock()
		return
	}
	now := time.Now()
	cutoff := now.Add(-s.cfg.RestartWindow)
	kept := s.restarts[:0]
	for _, t := range s.restarts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.restarts = append(kept, now)
	if len(s.restarts) > s.cfg.MaxRestarts {
		s.status.State = "crash-loop"
		s.desired = false
		s.mu.Unlock()
		return
	}
	s.status.State = "starting"
	delay := time.Duration(1<<min(len(s.restarts)-1, 5)) * 100 * time.Millisecond
	s.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.desired && s.cmd == nil && !s.stopping {
		_ = s.startLocked(ctx, revision)
	}
}

func (s *Supervisor) MarkReady() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		s.status.State = "ready"
	}
}

func (s *Supervisor) Reload(ctx context.Context) error {
	s.mu.Lock()
	if s.cmd == nil {
		s.mu.Unlock()
		return errors.New("endpoint is not running")
	}
	p := s.cmd.Process
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return p.Signal(syscall.SIGHUP)
	}
}

func (s *Supervisor) Restart(ctx context.Context, revision string) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}
	return s.Start(ctx, revision)
}

func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.cmd == nil {
		s.desired = false
		s.status.State = "stopped"
		s.mu.Unlock()
		return nil
	}
	s.desired = false
	s.stopping = true
	p, done := s.cmd.Process, s.done
	s.mu.Unlock()
	if err := p.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	timer := time.NewTimer(s.cfg.StopTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
		_ = p.Kill()
		<-done
		return ctx.Err()
	case <-timer.C:
		_ = p.Kill()
		<-done
	}
	s.mu.Lock()
	s.stopping = false
	s.status.State = "stopped"
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) Status() domain.EndpointStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
func (s *Supervisor) Logs() string { return s.logs.String() }

func sanitize(v string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|token|credential|cookie|csrf)[=: ]+[^\s]+`),
		regexp.MustCompile(`tt://[^\s]+`), regexp.MustCompile(`-----BEGIN [^-]*PRIVATE KEY-----`),
	}
	for _, p := range patterns {
		v = p.ReplaceAllString(v, "[REDACTED]")
	}
	if len(v) > 1024 {
		v = v[:1024]
	}
	return v
}

type ringWriter struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newRingWriter(max int) *ringWriter { return &ringWriter{max: max} }
func (w *ringWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	clean := []byte(sanitize(string(p)))
	w.buf = append(w.buf, clean...)
	if len(w.buf) > w.max {
		w.buf = append([]byte(nil), w.buf[len(w.buf)-w.max:]...)
	}
	return len(p), nil
}
func (w *ringWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(bytes.Clone(w.buf))
}

var _ io.Writer = (*ringWriter)(nil)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Supervisor) String() string {
	st := s.Status()
	return fmt.Sprintf("%s pid=%d revision=%s", st.State, st.PID, st.Revision)
}
