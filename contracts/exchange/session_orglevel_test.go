package exchange

import "testing"

// A frictionless by-domain sender (Capstone C1b) addresses the recipient's ORG (its
// verified domain) and cannot know the receiver's gateway id, so the envelope's
// destination gateway is empty. sessionMatchesEnvelope must accept that once the
// org/tenant matches, while a NON-empty (bilateral) destination gateway still has to
// match exactly, and a wrong destination tenant always fails.
func TestSessionMatchesEnvelopeOrgLevelDestination(t *testing.T) {
	session := AuthenticatedSession{
		RemoteTenantID:  "gcpco.baylifeventures.com",
		RemoteGatewayID: "ba000000-0000-4000-8000-0000000000c0",
		LocalTenantID:   "oldco.baylifeventures.com",
		LocalGatewayID:  "ba000000-0000-4000-8000-0000000000c1",
		PartnerLinkID:   "fed-oldco.baylifeventures.com-receiver",
	}
	base := Envelope{
		PartnerLinkID: "fed-oldco.baylifeventures.com-receiver",
		Source:        GatewayRef{TenantID: "gcpco.baylifeventures.com", GatewayID: "ba000000-0000-4000-8000-0000000000c0"},
		Destination:   GatewayRef{TenantID: "oldco.baylifeventures.com"}, // org-level: gateway empty
	}
	if !sessionMatchesEnvelope(session, base) {
		t.Fatalf("org-level destination (empty gateway) must match when the org/tenant matches")
	}

	wrongGW := base
	wrongGW.Destination.GatewayID = "ba000000-0000-4000-8000-00000000WRON"
	if sessionMatchesEnvelope(session, wrongGW) {
		t.Fatalf("a NON-empty destination gateway must match the session's local gateway exactly")
	}

	wrongTenant := base
	wrongTenant.Destination.TenantID = "evil.example"
	if sessionMatchesEnvelope(session, wrongTenant) {
		t.Fatalf("a wrong destination tenant must always fail")
	}

	// Source still anti-impersonation: a source tenant that is not the verified remote fails.
	wrongSrc := base
	wrongSrc.Source.TenantID = "ee0001-control-uuid"
	if sessionMatchesEnvelope(session, wrongSrc) {
		t.Fatalf("source tenant must equal the verified remote tenant (anti-impersonation)")
	}
}
