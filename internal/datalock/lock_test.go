package datalock

import (
	"path/filepath"
	"testing"
)

func TestExclusiveDataLock(t *testing.T) {
	dir, _ := filepath.Abs(t.TempDir())
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err = Acquire(dir); err == nil {
		t.Fatal("second lock succeeded")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
}
