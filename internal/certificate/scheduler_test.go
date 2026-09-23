package certificate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRenewalWindowJitterAndBackoff(t *testing.T) {
	expiry := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	lead := 30 * 24 * time.Hour
	early := RenewalAt(expiry, lead, .1, 0)
	late := RenewalAt(expiry, lead, .1, 1)
	if !early.Before(late) || !late.Before(expiry) {
		t.Fatalf("early=%v late=%v", early, late)
	}
	if got := Backoff(0, time.Minute, time.Hour); got != time.Minute {
		t.Fatalf("backoff0=%v", got)
	}
	if got := Backoff(10, time.Minute, time.Hour); got != time.Hour {
		t.Fatalf("capped=%v", got)
	}
}

type schedulerRepo struct {
	mu sync.Mutex
	m  Metadata
}

func (r *schedulerRepo) LoadTLSMetadata(context.Context) (Metadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m, nil
}
func (r *schedulerRepo) SaveTLSMetadata(_ context.Context, m Metadata) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m = m
	return nil
}
func TestSchedulerStopsAndWaitsForRenewal(t *testing.T) {
	repo := &schedulerRepo{m: Metadata{State: Active, Mode: Staging, NotAfter: time.Now().Add(5 * time.Millisecond)}}
	started := make(chan struct{})
	finished := make(chan struct{})
	s := NewScheduler(repo, func(ctx context.Context) (Metadata, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return Metadata{}, ctx.Err()
	}, time.Millisecond)
	s.jitter = 0
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("renew did not start")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("stop returned before renewal exited")
	}
}
func TestSchedulerMarksDegradedNearExpiry(t *testing.T) {
	repo := &schedulerRepo{m: Metadata{State: Active, Mode: Staging, NotAfter: time.Now().Add(-time.Second)}}
	called := make(chan struct{}, 1)
	s := NewScheduler(repo, func(context.Context) (Metadata, error) {
		called <- struct{}{}
		return Metadata{}, errors.New("network timeout")
	}, time.Hour)
	s.baseBackoff = time.Hour
	s.jitter = 0
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("renew not attempted")
	}
	deadline := time.Now().Add(time.Second)
	for {
		repo.mu.Lock()
		state := repo.m.State
		repo.mu.Unlock()
		if state == Degraded || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.Stop(ctx)
	repo.mu.Lock()
	state := repo.m.State
	repo.mu.Unlock()
	if state != Degraded {
		t.Fatalf("state=%s", state)
	}
}
