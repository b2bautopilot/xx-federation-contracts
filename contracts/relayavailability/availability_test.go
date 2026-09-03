package relayavailability

import (
	"reflect"
	"testing"
)

func TestReadinessLevelsOrdered(t *testing.T) {
	levels := []string{ReadinessL4Reachable, ReadinessRelayReady, ReadinessReservationReady, ReadinessCircuitProven}
	for _, level := range levels {
		if !ValidReadinessLevel(level) {
			t.Fatalf("declared level %q must validate", level)
		}
	}
	if !ValidReadinessLevel("") {
		// empty must be invalid: covered below; keep explicit for readability
	} else {
		t.Fatal("empty readiness level must be invalid")
	}
	for _, bad := range []string{"", "tcp_ok", "reachable", "L4_REACHABLE", "circuit-proven"} {
		if ValidReadinessLevel(bad) {
			t.Fatalf("unknown level %q must not validate", bad)
		}
	}
	for i := 1; i < len(levels); i++ {
		if ReadinessRank(levels[i]) <= ReadinessRank(levels[i-1]) {
			t.Fatalf("levels must rank strictly increasing: %q vs %q", levels[i-1], levels[i])
		}
	}
	if got := DefaultReadinessLevel("bogus"); got != ReadinessL4Reachable {
		t.Fatalf("default must fall to weakest level, got %q", got)
	}
	if got := DefaultReadinessLevel(ReadinessCircuitProven); got != ReadinessCircuitProven {
		t.Fatalf("default must keep declared levels, got %q", got)
	}
}

func TestTCPConnectNeverSatisfiesCircuitReadiness(t *testing.T) {
	// Fail-closed core: bare TCP/L4 reachability — and every level short of a
	// proven end-to-end circuit — must never count as circuit-relay-v2 success.
	for _, level := range []string{ReadinessL4Reachable, ReadinessRelayReady, ReadinessReservationReady} {
		if CircuitRelayV2Ready(level) {
			t.Fatalf("level %q must not satisfy circuit readiness", level)
		}
	}
	if !CircuitRelayV2Ready(ReadinessCircuitProven) {
		t.Fatal("proven end-to-end circuit must satisfy circuit readiness")
	}
	for _, bad := range []string{"", "tcp_ok", "reachable"} {
		if CircuitRelayV2Ready(bad) {
			t.Fatalf("unknown level %q must not satisfy circuit readiness", bad)
		}
		if ReadinessAtLeast(bad, ReadinessL4Reachable) {
			t.Fatalf("unknown level %q must not meet any threshold", bad)
		}
	}
	if ReadinessAtLeast(ReadinessRelayReady, ReadinessReservationReady) {
		t.Fatal("local relay readiness must not meet the reservation threshold")
	}
	if !ReadinessAtLeast(ReadinessCircuitProven, ReadinessReservationReady) {
		t.Fatal("proven circuit must meet every weaker threshold")
	}
}

func TestNMinusOneAvailability(t *testing.T) {
	if StandingCellCount != 3 || MinHealthyCells != 2 || MaxRelayCandidates != 3 {
		t.Fatalf("fabric shape must be 3 standing / 2 minimum / 3 candidates, got %d/%d/%d",
			StandingCellCount, MinHealthyCells, MaxRelayCandidates)
	}
	cases := []struct {
		name       string
		authorized bool
		healthy    []bool
		want       bool
	}{
		{"all healthy authorized", true, []bool{true, true, true}, true},
		{"lose aws authorized", true, []bool{false, true, true}, true},
		{"lose gcp authorized", true, []bool{true, false, true}, true},
		{"lose azure authorized", true, []bool{true, true, false}, true},
		{"lose two cells authorized", true, []bool{false, false, true}, false},
		{"lose all cells authorized", true, []bool{false, false, false}, false},
		{"all healthy unauthorized", false, []bool{true, true, true}, false},
		{"n-1 healthy unauthorized", false, []bool{false, true, true}, false},
	}
	for _, tc := range cases {
		if got := NMinusOneAvailable(tc.authorized, tc.healthy); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
	if !ExchangeAvailable(true, MinHealthyCells) {
		t.Fatal("minimum healthy count with authorization must be available")
	}
	if ExchangeAvailable(true, MinHealthyCells-1) {
		t.Fatal("below-minimum healthy count must be unavailable")
	}
	if ExchangeAvailable(false, StandingCellCount) {
		t.Fatal("unauthorized exchange must be unavailable even when all cells are healthy")
	}
}

func TestOrderedCandidateFailover(t *testing.T) {
	ordered := OrderCandidates([]string{" cell-b ", "", "cell-a", "cell-b", "cell-c", "cell-d"})
	if want := []string{"cell-b", "cell-a", "cell-c"}; !reflect.DeepEqual(ordered, want) {
		t.Fatalf("ordered candidates = %v want %v (trim, dedupe, keep order, cap at 3)", ordered, want)
	}
	if got := OrderCandidates(nil); len(got) != 0 {
		t.Fatalf("empty input must stay empty (fail closed), got %v", got)
	}
	if CandidateSetWellFormed(nil) || CandidateSetWellFormed([]string{}) {
		t.Fatal("empty candidate set must not be well formed")
	}
	if !CandidateSetWellFormed([]string{"cell-a", "cell-b"}) {
		t.Fatal("distinct in-cap entries must be well formed")
	}
	for _, bad := range [][]string{
		{"cell-a", "cell-a"},
		{"cell-a", "  "},
		{"a", "b", "c", "d"},
	} {
		if CandidateSetWellFormed(bad) {
			t.Fatalf("candidate set %v must fail closed", bad)
		}
	}

	health := map[string]bool{"cell-a": false, "cell-b": true, "cell-c": true}
	next, ok := SelectNextHealthy([]string{"cell-a", "cell-b", "cell-c"}, func(c string) bool { return health[c] })
	if !ok || next != "cell-b" {
		t.Fatalf("failover must walk authority order to first healthy, got %q,%v", next, ok)
	}
	if _, ok := SelectNextHealthy([]string{"cell-a"}, func(c string) bool { return health[c] }); ok {
		t.Fatal("no healthy candidate must report failure")
	}
	if _, ok := SelectNextHealthy([]string{"cell-a"}, nil); ok {
		t.Fatal("nil health function must fail closed")
	}
	if _, ok := SelectNextHealthy([]string{"", "  "}, func(c string) bool { return true }); ok {
		t.Fatal("blank-only candidates must fail closed")
	}
	// One failed relay dial must not disturb unrelated healthy selections: the
	// selector is a pure function of the ordered list and current health view.
	first, _ := SelectNextHealthy([]string{"cell-a", "cell-b"}, func(c string) bool { return c == "cell-b" })
	second, _ := SelectNextHealthy([]string{"cell-b", "cell-c"}, func(c string) bool { return c == "cell-b" })
	if first != "cell-b" || second != "cell-b" {
		t.Fatalf("healthy selections must be stable across independent calls, got %q,%q", first, second)
	}
}
