package certificate

import (
	"context"
	"testing"
	"time"
)

type controlledACME struct {
	started chan struct{}
	release chan struct{}
	bundle  Bundle
}

func (c controlledACME) EnsureAccount(context.Context) (string, error) { return "account-uri", nil }
func (c controlledACME) Obtain(ctx context.Context, _ string) (Bundle, error) {
	close(c.started)
	select {
	case <-c.release:
		return c.bundle, nil
	case <-ctx.Done():
		return Bundle{}, ctx.Err()
	}
}

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
	ctx := context.Background()
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.Publish(ctx, makeBundle(t, "vpn.example.net", "Test CA"))
	if err != nil {
		t.Fatal(err)
	}
	repo := &certRepo{m: Metadata{State: Manual, Mode: ManualMode, Hostname: "vpn.example.net", ActiveRevision: pair.Revision, CertificatePath: pair.CertificatePath, PrivateKeyPath: pair.PrivateKeyPath}}
	m := NewManager(repo, store, nil, t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		t.Fatal("manual mode called ACME")
		return nil, nil
	})
	got, err := m.Ensure(ctx, time.Hour)
	if err != nil || got.State != Active || got.ActiveRevision != pair.Revision {
		t.Fatalf("manual=%+v err=%v", got, err)
	}
}

func TestEnsureNeverCallsACMEForOtherSources(t *testing.T) {
	for _, source := range []Source{SelfSigned, Provided} {
		t.Run(string(source), func(t *testing.T) {
			repo := &certRepo{m: Metadata{State: Unconfigured, Source: source, Mode: ManualMode, Hostname: "vpn.example.net"}}
			m := NewManager(repo, fakePublisher{}, nil, t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
				t.Fatal("non-ACME source called ACME")
				return nil, nil
			})
			_, err := m.Ensure(context.Background(), time.Hour)
			if source == SelfSigned && err != nil {
				t.Fatal(err)
			}
			if source == Provided && err == nil {
				t.Fatal("missing provided pair was accepted")
			}
		})
	}
}

func TestEnsureRecoversInterruptedRenewalWithoutOrder(t *testing.T) {
	ctx := context.Background()
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle := makeBundle(t, "vpn.example.net", "Test CA")
	published, err := store.Publish(ctx, bundle)
	if err != nil {
		t.Fatal(err)
	}
	repo := &certRepo{m: Metadata{State: Renewing, Mode: Staging, Hostname: "vpn.example.net", Email: "admin@example.net", ActiveRevision: published.Revision, CertificatePath: published.CertificatePath, PrivateKeyPath: published.PrivateKeyPath}}
	m := NewManager(repo, store, NewHTTP01Provider("127.0.0.1:0", 1), t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		t.Fatal("valid pair triggered a second order")
		return nil, nil
	})
	got, err := m.Ensure(ctx, time.Hour)
	if err != nil || got.State != Active {
		t.Fatalf("recovered=%+v err=%v", got, err)
	}
}

func TestEnsureDoesNotReusePreviousSourceAfterExplicitSwitch(t *testing.T) {
	ctx := context.Background()
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle := makeBundle(t, "vpn.example.net", "Test CA")
	old, err := store.Publish(ctx, bundle)
	if err != nil {
		t.Fatal(err)
	}
	repo := &certRepo{m: Metadata{State: Unconfigured, Source: LetsEncrypt, Mode: Staging, Hostname: "vpn.example.net", Email: "admin@example.net", ActiveRevision: old.Revision, CertificatePath: old.CertificatePath, PrivateKeyPath: old.PrivateKeyPath}}
	orders := 0
	m := NewManager(repo, store, NewHTTP01Provider("127.0.0.1:0", 1), t.TempDir(), time.Second, func(ACMEConfig) (ACMEClient, error) {
		orders++
		return fakeACME{bundle}, nil
	})
	if _, err = m.Ensure(ctx, time.Hour); err != nil || orders != 1 {
		t.Fatalf("orders=%d err=%v", orders, err)
	}
}

func TestEnsureSerializesSettingsChange(t *testing.T) {
	repo := &certRepo{m: Metadata{State: Unconfigured, Mode: Staging, Hostname: "vpn.example.net", Email: "admin@example.net"}}
	client := controlledACME{started: make(chan struct{}), release: make(chan struct{}), bundle: makeBundle(t, "vpn.example.net", "Test CA")}
	m := NewManager(repo, fakePublisher{}, NewHTTP01Provider("127.0.0.1:0", 1), t.TempDir(), 5*time.Second, func(ACMEConfig) (ACMEClient, error) { return client, nil })
	issueDone := make(chan error, 1)
	go func() { _, err := m.Ensure(context.Background(), time.Hour); issueDone <- err }()
	select {
	case <-client.started:
	case <-time.After(time.Second):
		t.Fatal("issue did not start")
	}
	saveDone := make(chan struct{})
	go func() { _ = m.Serialize(func() error { close(saveDone); return nil }) }()
	select {
	case <-saveDone:
		t.Fatal("settings change ran during certificate issue")
	case <-time.After(30 * time.Millisecond):
	}
	close(client.release)
	if err := <-issueDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-saveDone:
	case <-time.After(time.Second):
		t.Fatal("settings change remained blocked")
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
