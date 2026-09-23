package logbuffer

import (
	"strings"
	"testing"
)

func TestRingBoundsAndRedacts(t *testing.T) {
	r := New(64)
	r.Logf("token=secret tt://credential")
	r.Logf("safe line")
	got := r.String()
	if strings.Contains(got, "secret") || strings.Contains(got, "credential") {
		t.Fatalf("leak: %q", got)
	}
	r.Write([]byte(strings.Repeat("x", 128)))
	if len(r.String()) > 64 {
		t.Fatalf("size=%d", len(r.String()))
	}
}
