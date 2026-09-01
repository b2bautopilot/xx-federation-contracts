package exchange

import (
	"context"
	"testing"
)

// A frictionless by-domain catalog-view read carries an EMPTY contract; the receiver's
// manifest-independent preflight must allow it (dispatching to GetServiceCatalogView,
// which validates against the receiver's own catalog) WITHOUT a seeded manifest — yet
// still enforce the session/identity gates (a spoofed source is denied).
func TestPreflightCatalogViewDiscovery(t *testing.T) {
	h := &Handler{}
	session := AuthenticatedSession{
		RemoteTenantID:   "gcpco.baylifeventures.com",
		RemoteGatewayID:  "ba000000-0000-4000-8000-0000000000c0",
		LocalTenantID:    "oldco.baylifeventures.com",
		LocalGatewayID:   "ba000000-0000-4000-8000-0000000000c1",
		PartnerLinkID:    "fed-oldco.baylifeventures.com-receiver",
		PartnerLinkState: PartnerLinkActive,
	}
	env := Envelope{
		SchemaVersion: SchemaGatewayExchangeV1,
		Action:        ActionGetServiceCatalogView,
		Contract:      ContractRef{}, // empty -> discovery bypass
		PartnerLinkID: "fed-oldco.baylifeventures.com-receiver",
		Source:        GatewayRef{TenantID: "gcpco.baylifeventures.com", GatewayID: "ba000000-0000-4000-8000-0000000000c0"},
		Destination:   GatewayRef{TenantID: "oldco.baylifeventures.com"}, // org-level: empty gateway
		ExpiresAtMS:   9_000_000_000_000,                                 // far future
	}
	if d, _, action := h.preflightManifestIndependent(context.Background(), session, env, ActionContract{Action: ActionGetServiceCatalogView, FacadeMethod: FacadeGetServiceCatalogView}); d.Decision != DecisionAllow || action.FacadeMethod != FacadeGetServiceCatalogView {
		t.Fatalf("empty-contract catalog-view read must ALLOW + dispatch GetServiceCatalogView; got %q/%q facade=%q", d.Decision, d.DenialCode, action.FacadeMethod)
	}

	// The session/identity gate is NOT bypassed: a spoofed source tenant is still denied.
	bad := env
	bad.Source.TenantID = "evil.example"
	if d, _, _ := h.preflightManifestIndependent(context.Background(), session, bad, ActionContract{Action: ActionGetServiceCatalogView, FacadeMethod: FacadeGetServiceCatalogView}); d.Decision == DecisionAllow {
		t.Fatalf("a spoofed source must be denied even on the discovery path")
	}
}
