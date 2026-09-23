package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("TT_HELPER") != "1" {
		return
	}
	switch os.Getenv("TT_HELPER_MODE") {
	case "exit":
		os.Exit(2)
	default:
		ch := make(chan os.Signal, 4)
		signal.Notify(ch, syscall.SIGHUP, syscall.SIGTERM)
		for sig := range ch {
			if sig == syscall.SIGTERM {
				return
			}
		}
	}
}

func helperConfig(mode string) Config {
	return Config{
		Binary: os.Args[0], WorkingDir: "/", StopTimeout: time.Second,
		MaxRestarts: 2, RestartWindow: time.Minute, MaxLogBytes: 1024,
		Args: func(string) []string { return []string{"-test.run=TestHelperProcess"} },
	}
}

func TestStartReloadStopAndWait(t *testing.T) {
	t.Setenv("TT_HELPER", "1")
	s, err := New(helperConfig("wait"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	if s.Status().PID == 0 {
		t.Fatal("missing pid")
	}
	if err = s.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Status().State != "stopped" || s.Status().PID != 0 {
		t.Fatalf("status=%#v", s.Status())
	}
}

func TestCrashLoopCircuitBreaker(t *testing.T) {
	t.Setenv("TT_HELPER", "1")
	t.Setenv("TT_HELPER_MODE", "exit")
	s, err := New(helperConfig("exit"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = s.Start(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil && s.Status().State != "crash-loop" {
		time.Sleep(25 * time.Millisecond)
	}
	if got := s.Status().State; got != "crash-loop" {
		t.Fatalf("state=%s (%s)", got, fmt.Sprint(ctx.Err()))
	}
}

func TestRingRedactsAndBounds(t *testing.T) {
	w := newRingWriter(32)
	_, _ = w.Write([]byte("password=secret tt://private-payload and trailing-data"))
	if len(w.String()) > 32 {
		t.Fatal("ring exceeded bound")
	}
	if w.String() == "secret" {
		t.Fatal("secret leaked")
	}
}
