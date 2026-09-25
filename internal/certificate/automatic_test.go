package certificate

import (
	"context"
	"testing"
	"time"
)

func TestEnsureIssuesOnceAndRenewsWhenDue(t *testing.T) {
	ctx := context.Background()
	repo := &certRepo{m: Metadata{State: Unconfigured, Mode: Staging, Hostname: "vpn.example.net", Email: "admin@example.net"}}
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle := makeBundle(t, "vpn.example.net", "Test CA")
	orders := 0
	m := NewManager(repo, store, NewHTTP01Provider("127.0.0.1:0", 1), t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		orders++
		return fakeACME{bundle}, nil
	})
	first, err := m.Ensure(ctx, 8*time.Hour)
	if err != nil || first.State != Active || orders != 1 {
		t.Fatalf("first=%+v orders=%d err=%v", first, orders, err)
	}
	again, err := m.Ensure(ctx, 8*time.Hour)
	if err != nil || again.ActiveRevision != first.ActiveRevision || orders != 1 {
		t.Fatalf("second=%+v orders=%d err=%v", again, orders, err)
	}
	m.now = func() time.Time { return time.Now().Add(20 * time.Hour) }
	_, err = m.Ensure(ctx, 8*time.Hour)
	if err != nil || orders != 2 {
		t.Fatalf("renew orders=%d err=%v", orders, err)
	}
}

func TestEnsureRecoversInterruptedIssue(t *testing.T) {
	repo := &certRepo{m: Metadata{State: Issuing, Mode: Staging, Hostname: "vpn.example.net", Email: "admin@example.net"}}
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(repo, store, NewHTTP01Provider("127.0.0.1:0", 1), t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		return fakeACME{makeBundle(t, "vpn.example.net", "Test CA")}, nil
	})
	got, err := m.Ensure(context.Background(), time.Hour)
	if err != nil || got.State != Active {
		t.Fatalf("recovery=%+v err=%v", got, err)
	}
}

func TestEnsureLeavesManualCertificateAlone(t *testing.T) {
	repo := &certRepo{m: Metadata{State: Manual, Mode: ManualMode, Hostname: "vpn.example.net"}}
	m := NewManager(repo, nil, nil, t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		t.Fatal("manual mode called ACME")
		return nil, nil
	})
	got, err := m.Ensure(context.Background(), time.Hour)
	if err != nil || got.State != Manual {
		t.Fatalf("manual=%+v err=%v", got, err)
	}
}

func TestAutomaticSchedulerStartsImmediately(t *testing.T) {
	repo := &schedulerRepo{}
	called := make(chan struct{})
	s := NewAutomaticScheduler(repo, func(ctx context.Context) (Metadata, error) {
		close(called)
		<-ctx.Done()
		return Metadata{}, ctx.Err()
	}, nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("initial check did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
