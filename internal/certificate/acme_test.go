package certificate

import (
	"crypto/ecdsa"
	"testing"
)

func TestDirectoryModes(t *testing.T) {
	prod, _ := DirectoryURL(Production)
	stage, _ := DirectoryURL(Staging)
	if prod == stage || prod == "" || stage == "" {
		t.Fatalf("prod=%q stage=%q", prod, stage)
	}
	if _, err := DirectoryURL(ManualMode); err == nil {
		t.Fatal("manual mode must not have ACME URL")
	}
}
func TestValidateIdentity(t *testing.T) {
	if err := ValidateIdentity("admin@example.net", "vpn.example.net"); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "localhost", "vpn.local", "-bad.example.net", "bad_name.example.net"} {
		if err := ValidateIdentity("admin@example.net", host); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	if err := ValidateIdentity("not-an-email", "vpn.example.net"); err == nil {
		t.Fatal("accepted invalid email")
	}
}
func TestAccountKeyIsRestored(t *testing.T) {
	dir := t.TempDir()
	first, err := loadOrCreateAccountKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateAccountKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Public().(*ecdsa.PublicKey).Equal(second.Public()) {
		t.Fatal("account key changed")
	}
}
