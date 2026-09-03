package orgregistry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadPresenceFixture(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "parity", "orgregistry.json"))
	if err != nil {
		t.Fatalf("read orgregistry parity fixture: %v", err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode orgregistry parity fixture: %v", err)
	}
	return m
}

// TestGoldenPresenceRefReplays replays the presence-ref vectors for the blind
// presence contract (canonical source xx-builders-net/federation/orgregistry at
// origin/dev c1ad78a). Both ends of a pairing MUST derive the identical key, so this guards
// the blind presence contract against silent drift.
func TestGoldenPresenceRefReplays(t *testing.T) {
	fixture := loadPresenceFixture(t)
	secret := []byte("epoch-secret")
	for _, domain := range []string{"acme.com", "example.org"} {
		got := PresenceRef(secret, domain)
		if got != fixture[domain] {
			t.Errorf("PresenceRef(%q) = %q, want golden %q", domain, got, fixture[domain])
		}
	}
}

// TestPresenceRef_FailsClosedOnNonCanonicalInput verifies the contracts form fails
// closed (returns "") on input that is not already trimmed, lowercase, ASCII-only.
// This is the documented intentional exception vs the source CanonicalDomain path:
// callers canonicalise first (gateway-internal orgdomain) and pass the canonical
// form here.
func TestPresenceRef_FailsClosedOnNonCanonicalInput(t *testing.T) {
	secret := []byte("epoch-secret")
	bad := []string{
		"Acme.Com",       // mixed case
		" acme.com",      // leading whitespace
		"acme.com ",      // trailing whitespace
		"münich.example", // non-ASCII
		"",               // empty
	}
	for _, in := range bad {
		if got := PresenceRef(secret, in); got != "" {
			t.Errorf("PresenceRef(%q) = %q, want fail-closed empty", in, got)
		}
	}
	// empty secret always fails closed regardless of domain
	if got := PresenceRef(nil, "acme.com"); got != "" {
		t.Errorf("PresenceRef with empty secret = %q, want fail-closed empty", got)
	}
}

func TestReceiverRendezvousID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"acme.com", "fed-acme.com-receiver"},
		{"ACME.COM", "fed-acme.com-receiver"},
		{" acme.com ", "fed-acme.com-receiver"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := ReceiverRendezvousID(c.in); got != c.want {
			t.Errorf("ReceiverRendezvousID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsReceiverRendezvousID(t *testing.T) {
	yes := []string{"fed-acme.com-receiver", "fed-x-receiver", "fed-.example.com.-receiver"}
	no := []string{"", "fed-", "-receiver", "partner-uuid", "fed--receiver"}
	for _, id := range yes {
		if !IsReceiverRendezvousID(id) {
			t.Errorf("IsReceiverRendezvousID(%q) = false, want true", id)
		}
	}
	for _, id := range no {
		if IsReceiverRendezvousID(id) {
			t.Errorf("IsReceiverRendezvousID(%q) = true, want false", id)
		}
	}
}

func TestOrgHandleFromReceiverRendezvousID(t *testing.T) {
	if got := OrgHandleFromReceiverRendezvousID("fed-acme.com-receiver"); got != "acme.com" {
		t.Errorf("OrgHandleFromReceiverRendezvousID = %q, want acme.com", got)
	}
	if got := OrgHandleFromReceiverRendezvousID("fed-x-receiver"); got != "x" {
		t.Errorf("OrgHandleFromReceiverRendezvousID = %q, want x", got)
	}
	if got := OrgHandleFromReceiverRendezvousID("nope"); got != "" {
		t.Errorf("OrgHandleFromReceiverRendezvousID(nope) = %q, want empty", got)
	}
	if got := OrgHandleFromReceiverRendezvousID("fed--receiver"); got != "" {
		t.Errorf("OrgHandleFromReceiverRendezvousID(fed--receiver) = %q, want empty", got)
	}
}

func TestCanonicalInputGuard(t *testing.T) {
	// The isCanonicalDomain guard underpins PresenceRef fail-closed behaviour.
	for _, d := range []string{"acme.com", "a-b.example.co"} {
		if !isCanonicalDomain(d) {
			t.Errorf("isCanonicalDomain(%q) = false, want true", d)
		}
	}
	for _, d := range []string{"Acme.com", " acme.com", "", "ünï.com"} {
		if isCanonicalDomain(d) {
			t.Errorf("isCanonicalDomain(%q) = true, want false", d)
		}
	}
}
