package certificate

import (
	"os"
	"testing"
)

func TestStoreAccountKeyPermissions(t *testing.T) {
	path, err := StoreAccountKey(t.TempDir(), []byte("private-account-key"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "private-account-key" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
