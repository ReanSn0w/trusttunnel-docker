package certificate

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

type MetadataRepository interface {
	LoadTLSMetadata(context.Context) (Metadata, error)
	SaveTLSMetadata(context.Context, Metadata) error
}
type RenewFunc func(context.Context) (Metadata, error)
type Random interface{ Float64() float64 }
type globalRandom struct{}

func (globalRandom) Float64() float64 { return rand.Float64() }

type Scheduler struct {
	automatic                     bool
	logf                          func(string, ...interface{})
	repo                          MetadataRepository
	renew                         RenewFunc
	lead, baseBackoff, maxBackoff time.Duration
	jitter                        float64
	random                        Random
	mu                            sync.Mutex
	cancel                        context.CancelFunc
	done                          chan struct{}
	now                           func() time.Time
}

func NewScheduler(repo MetadataRepository, renew RenewFunc, lead time.Duration) *Scheduler {
	if lead <= 0 {
		lead = 30 * 24 * time.Hour
	}
	return &Scheduler{repo: repo, renew: renew, lead: lead, baseBackoff: time.Minute, maxBackoff: 6 * time.Hour, jitter: .1, random: globalRandom{}, now: time.Now}
}

func RenewalAt(notAfter time.Time, lead time.Duration, jitterFraction, random float64) time.Time {
	if lead < 0 {
		lead = 0
	}
	if jitterFraction < 0 {
		jitterFraction = 0
	}
	if jitterFraction > 1 {
		jitterFraction = 1
	}
	if random < 0 {
		random = 0
	}
	if random > 1 {
		random = 1
	}
	offset := (random*2 - 1) * jitterFraction * float64(lead)
	when := notAfter.Add(-lead).Add(time.Duration(offset))
	if !when.Before(notAfter) {
		return notAfter.Add(-time.Second)
	}
	return when
}
func Backoff(attempt int, base, maximum time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if base <= 0 {
		base = time.Second
	}
	if maximum < base {
		maximum = base
	}
	delay := base
	for i := 0; i < attempt && delay < maximum; i++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func jitterBackoff(delay, maximum time.Duration, fraction, random float64) time.Duration {
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	if random < 0 {
		random = 0
	}
	if random > 1 {
		random = 1
	}
	result := time.Duration(float64(delay) * (1 - fraction + 2*fraction*random))
	if result > maximum {
		return maximum
	}
	return result
}

func (s *Scheduler) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("renewal scheduler already running")
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.run(ctx, s.done)
	return nil
}
func (s *Scheduler) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		s.mu.Lock()
		s.cancel = nil
		s.done = nil
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Scheduler) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	if s.automatic {
		s.runAutomatic(ctx)
		return
	}
	attempt := 0
	for {
		meta, err := s.repo.LoadTLSMetadata(ctx)
		if err != nil {
			if !waitScheduler(ctx, Backoff(attempt, s.baseBackoff, s.maxBackoff)) {
				return
			}
			attempt++
			continue
		}
		if meta.Mode == ManualMode || meta.State == Unconfigured {
			if !waitScheduler(ctx, time.Hour) {
				return
			}
			attempt = 0
			continue
		}
		when := RenewalAt(meta.NotAfter, s.lead, s.jitter, s.random.Float64())
		delay := when.Sub(s.now())
		if delay > 0 {
			if !waitScheduler(ctx, delay) {
				return
			}
		}
		updated, err := s.renew(ctx)
		if err == nil {
			attempt = 0
			if updated.Mode == ManualMode {
				continue
			}
			continue
		}
		attempt++
		meta.LastError = sanitizeCertificateError(err)
		if s.now().After(meta.NotAfter.Add(-s.lead / 4)) {
			meta.State = Degraded
			_ = s.repo.SaveTLSMetadata(context.Background(), meta)
		}
		if !waitScheduler(ctx, Backoff(attempt-1, s.baseBackoff, s.maxBackoff)) {
			return
		}
	}
}
func waitScheduler(ctx context.Context, d time.Duration) bool {
	if d < 0 {
		d = 0
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
