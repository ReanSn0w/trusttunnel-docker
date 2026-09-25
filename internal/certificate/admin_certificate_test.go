package certificate

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"
)

func TestAdminCertificateSwitchesOnlyOnActivation(t *testing.T) {
	store, err := NewTLSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	admin := &AdminCertificate{}
	if _, err := admin.GetCertificate(nil); err == nil {
		t.Fatal("certificate was available before activation")
	}
	var previous [32]byte
	for i := 0; i < 2; i++ {
		bundle, err := GenerateSelfSigned("vpn.example.net", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		published, err := store.Publish(context.Background(), bundle)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := admin.Prepare(published)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			active, err := admin.GetCertificate(nil)
			if err != nil || sha256.Sum256(active.Certificate[0]) != previous {
				t.Fatal("unconfirmed revision became visible")
			}
		}
		admin.Activate(pair)
		active, err := admin.GetCertificate(nil)
		if err != nil || sha256.Sum256(active.Certificate[0]) != sha256.Sum256(pair.Certificate[0]) {
			t.Fatal("confirmed revision was not activated")
		}
		previous = sha256.Sum256(pair.Certificate[0])
	}
}
