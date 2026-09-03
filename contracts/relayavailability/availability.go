// Package relayavailability is the machine-readable N-1 relay-cell
// availability and readiness contract for the standing multi-cloud relay
// fabric (issue #15).
//
// It codifies semantics already implemented downstream (notably xx-mesh-net:
// up to three signed relay candidates, bounded replacement of unhealthy
// reservations, ordered iteration over relay circuit multiaddrs, preservation
// of unrelated healthy streams when one relay dial fails) and the evidence
// rule observed live (bare TCP reachability of legacy TLS forwarders is not
// circuit-relay-v2 success). It invents no new failover algorithm and no
// retry budgets: callers iterate the ordered candidate list inside their own
// pre-existing bounds.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/relayavailability
// Spec evidence: rel.gateway-dials-relay (n-minus-one-availability,
// ordered-candidate-failover, readiness-levels, circuit-evidence-rule,
// downstream-consumers).
package relayavailability

import "strings"

// Standing fabric shape. Three provider cells stand (GCP, AWS, Azure); an
// otherwise authorized exchange must survive the loss of any one of them, so
// at least two healthy cells must remain reachable.
const (
	// StandingCellCount is the declared number of provider relay cells.
	StandingCellCount = 3
	// MinHealthyCells is the minimum reachable healthy cells that keeps an
	// otherwise authorized exchange unblocked.
	MinHealthyCells = 2
	// MaxRelayCandidates caps the ordered relay candidate set a gateway or
	// x-mesh dialer holds for one exchange (matches the downstream reservation
	// width of up to three signed candidates).
	MaxRelayCandidates = 3
)

// Relay readiness levels, weakest to strongest. Each level is necessary but
// insufficient for the next: a cell can answer TCP while its relay process is
// down, be locally ready while holding no authenticated reservation for the
// caller, and hold a reservation that still fails an end-to-end circuit.
const (
	// ReadinessL4Reachable: a TCP connect to the cell listener succeeded.
	// This is reachability evidence only and never circuit readiness.
	ReadinessL4Reachable = "l4_reachable"
	// ReadinessRelayReady: the relay process itself reports local readiness
	// (its own health/readiness gate passes).
	ReadinessRelayReady = "relay_ready"
	// ReadinessReservationReady: the caller holds an authenticated,
	// unexpired reservation (or parked rendezvous registration) on the cell.
	ReadinessReservationReady = "reservation_ready"
	// ReadinessCircuitProven: a full end-to-end circuit-relay-v2 circuit
	// completed through the cell with the inner identity pin verified. This
	// is the only level that satisfies circuit readiness.
	ReadinessCircuitProven = "circuit_proven"
)

// ValidReadinessLevel reports whether value names a declared readiness level.
func ValidReadinessLevel(value string) bool {
	switch value {
	case ReadinessL4Reachable, ReadinessRelayReady, ReadinessReservationReady, ReadinessCircuitProven:
		return true
	default:
		return false
	}
}

// DefaultReadinessLevel returns value when it names a declared level and the
// weakest level otherwise (fail toward least privilege, never upward).
func DefaultReadinessLevel(value string) string {
	if ValidReadinessLevel(value) {
		return value
	}
	return ReadinessL4Reachable
}

// ReadinessRank orders levels weakest (0) to strongest (3); unknown values
// rank below every declared level so they can never satisfy a threshold.
func ReadinessRank(level string) int {
	switch level {
	case ReadinessL4Reachable:
		return 0
	case ReadinessRelayReady:
		return 1
	case ReadinessReservationReady:
		return 2
	case ReadinessCircuitProven:
		return 3
	default:
		return -1
	}
}

// ReadinessAtLeast reports whether level meets or exceeds threshold. Unknown
// levels and unknown thresholds fail closed.
func ReadinessAtLeast(level, threshold string) bool {
	if !ValidReadinessLevel(level) || !ValidReadinessLevel(threshold) {
		return false
	}
	return ReadinessRank(level) >= ReadinessRank(threshold)
}

// CircuitRelayV2Ready reports whether level counts as circuit-relay-v2
// readiness. Only proven end-to-end circuit evidence qualifies: L4/TCP
// reachability, local relay readiness, and reservation readiness alone all
// return false.
func CircuitRelayV2Ready(level string) bool {
	return level == ReadinessCircuitProven
}

// ExchangeAvailable reports whether an exchange may proceed: the caller must
// be authorized AND at least MinHealthyCells cells must be reachable. A
// single lost cell (healthyCells == StandingCellCount-1) stays available;
// authorization failure or fewer than MinHealthyCells never is.
func ExchangeAvailable(authorized bool, healthyCells int) bool {
	return authorized && healthyCells >= MinHealthyCells
}

// NMinusOneAvailable evaluates the cell health vector fail-closed: exactly
// the loss-of-any-one-cell rule. healthy has one entry per standing cell;
// the exchange survives when the caller is authorized and at least
// MinHealthyCells entries are healthy, regardless of which cell failed.
func NMinusOneAvailable(authorized bool, healthy []bool) bool {
	count := 0
	for _, h := range healthy {
		if h {
			count++
		}
	}
	return ExchangeAvailable(authorized, count)
}

// OrderCandidates normalizes an ordered relay candidate list without
// reordering it: trims whitespace, drops blanks, removes duplicates keeping
// first occurrence, and caps at MaxRelayCandidates preserving authority
// order. A nil or empty result is fail-closed input: the caller must deny
// the exchange (there is nothing authorized left to dial).
func OrderCandidates(candidates []string) []string {
	ordered := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		ordered = append(ordered, candidate)
		if len(ordered) >= MaxRelayCandidates {
			break
		}
	}
	return ordered
}

// CandidateSetWellFormed reports whether candidates is a dialable ordered set:
// at least one entry, at most MaxRelayCandidates, every entry non-blank and
// unique after trimming. Anything else fails closed.
func CandidateSetWellFormed(candidates []string) bool {
	if len(candidates) == 0 || len(candidates) > MaxRelayCandidates {
		return false
	}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			return false
		}
		seen[candidate] = true
	}
	return true
}

// SelectNextHealthy returns the first candidate in authority order for which
// healthy reports true, so failover walks the ordered list and never skips
// ahead. It reports false when no candidate is healthy; the caller then
// applies its own pre-existing bounded retry/replacement semantics. Unknown
// candidates are skipped, never trusted.
func SelectNextHealthy(candidates []string, healthy func(string) bool) (string, bool) {
	if healthy == nil {
		return "", false
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if healthy(candidate) {
			return candidate, true
		}
	}
	return "", false
}
