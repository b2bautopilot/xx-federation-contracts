package gatewaycert_test

import (
	"errors"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
)

// The relay-client SPIFFE org segment becomes the control-plane TenantID, which the
// RLS-scoped credential resolver requires to be a uuid. A domain or handle is rejected.
func TestValidateRelayClientTenantID(t *testing.T) {
	valid := []string{
		"11111111-1111-4111-8111-111111111111",
		"018f4c2f-0000-4000-8000-0000000000c0",
	}
	for _, id := range valid {
		if err := gatewaycert.ValidateRelayClientTenantID(id); err != nil {
			t.Errorf("ValidateRelayClientTenantID(%q) = %v, want nil", id, err)
		}
	}
	invalid := []string{
		"",                       // empty
		"   ",                    // whitespace
		"oldco.example",          // a domain (the homograph/by-domain addressing label)
		"org-newco",              // a handle
		"not-a-uuid",             // junk
		"11111111-1111-4111-811", // truncated uuid
	}
	for _, id := range invalid {
		err := gatewaycert.ValidateRelayClientTenantID(id)
		if err == nil {
			t.Errorf("ValidateRelayClientTenantID(%q) = nil, want error", id)
			continue
		}
		if !errors.Is(err, gatewaycert.ErrPlaneIdentityMismatch) {
			t.Errorf("ValidateRelayClientTenantID(%q) error = %v, want ErrPlaneIdentityMismatch", id, err)
		}
	}
}
