package gatewaypool

import "testing"

func TestDefaultLeaseKind(t *testing.T) {
	if got := DefaultLeaseKind(""); got != LeaseKindCoordinator {
		t.Errorf("empty kind defaults to %q, want coordinator", got)
	}
	if got := DefaultLeaseKind("coordinator"); got != LeaseKindCoordinator {
		t.Errorf("coordinator kind normalized to %q", got)
	}
	// Non-empty kinds pass through trimmed (no fail-open, but no forced default).
	if got := DefaultLeaseKind(" worker "); got != "worker" {
		t.Errorf("non-empty kind normalized to %q, want worker", got)
	}
}

func TestValidLeaseKind(t *testing.T) {
	if !ValidLeaseKind("coordinator") {
		t.Error("coordinator must be a valid lease kind")
	}
	// Empty kind defaults to coordinator, so it is valid (matches source).
	if !ValidLeaseKind("") {
		t.Error("empty kind must default to coordinator and be valid")
	}
	if ValidLeaseKind("worker") {
		t.Error("unknown kind must be invalid")
	}
}

func TestActive(t *testing.T) {
	if !Active("gw-a", 2000, 1000) {
		t.Error("active holder within lease window must report active")
	}
	if Active("", 2000, 1000) {
		t.Error("empty holder must not report active")
	}
	if Active("gw-a", 1000, 2000) {
		t.Error("expired lease must not report active")
	}
	if Active("gw-a", 1000, 1000) {
		t.Error("lease at exact expiry must not report active")
	}
}
