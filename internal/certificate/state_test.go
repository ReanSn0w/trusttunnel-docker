package certificate

import "testing"

func TestStateTransitions(t *testing.T) {
	valid := [][2]State{{Unconfigured, Issuing}, {Issuing, Active}, {Active, Renewing}, {Renewing, Degraded}, {Degraded, Renewing}, {Active, Manual}, {Manual, Issuing}}
	for _, p := range valid {
		if !CanTransition(p[0], p[1]) {
			t.Fatalf("expected %s -> %s", p[0], p[1])
		}
	}
	invalid := [][2]State{{Unconfigured, Active}, {Issuing, Manual}, {Manual, Renewing}}
	for _, p := range invalid {
		if CanTransition(p[0], p[1]) {
			t.Fatalf("unexpected %s -> %s", p[0], p[1])
		}
	}
}
