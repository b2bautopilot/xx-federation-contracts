package exchange

import (
	"context"
	"testing"
)

// establish_data_channel (S4) carries an EMPTY contract; the receiver's
// manifest-independent preflight must ALLOW it (dispatching to the data-channel facade)
// without a seeded manifest, while still enforcing the session/identity gates.
func TestPreflightEstablishDataChannel(t *testing.T) {
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
		Action:        ActionEstablishDataChannel,
		Contract:      ContractRef{}, // empty -> manifest-independent path
		PartnerLinkID: "fed-oldco.baylifeventures.com-receiver",
		Source:        GatewayRef{TenantID: "gcpco.baylifeventures.com", GatewayID: "ba000000-0000-4000-8000-0000000000c0"},
		Destination:   GatewayRef{TenantID: "oldco.baylifeventures.com"},
		ExpiresAtMS:   9_000_000_000_000,
	}
	dcAction := ActionContract{Action: ActionEstablishDataChannel, FacadeMethod: FacadeEstablishDataChannel}
	if d, _, action := h.preflightManifestIndependent(context.Background(), session, env, dcAction); d.Decision != DecisionAllow || action.FacadeMethod != FacadeEstablishDataChannel {
		t.Fatalf("empty-contract establish_data_channel must ALLOW + dispatch EstablishDataChannel; got %q/%q facade=%q", d.Decision, d.DenialCode, action.FacadeMethod)
	}
	// the session/identity gate is NOT bypassed on the data-channel path.
	bad := env
	bad.Source.TenantID = "evil.example"
	if d, _, _ := h.preflightManifestIndependent(context.Background(), session, bad, dcAction); d.Decision == DecisionAllow {
		t.Fatal("a spoofed source must be denied even on the data-channel preflight path")
	}
}

// dataChannelFakeFacade is a fakeFacade that ALSO implements the optional DataChannelFacade.
type dataChannelFakeFacade struct {
	fakeFacade
	called bool
}

func (f *dataChannelFakeFacade) EstablishDataChannel(context.Context, AcceptedEnvelope) (DispatchResult, error) {
	f.called = true
	return DispatchResult{Status: "granted", PayloadJSON: `{"granted":false}`}, nil
}

// The optional-capability dispatch: a Facade without DataChannelFacade fails CLOSED
// (not supported) — no ripple to the core interface; a Facade that implements it is routed to.
func TestDispatchDataChannelFacadeOptional(t *testing.T) {
	accepted := AcceptedEnvelope{Action: ActionContract{Action: ActionEstablishDataChannel, FacadeMethod: FacadeEstablishDataChannel}}

	if _, err := (&Handler{Facade: &fakeFacade{}}).dispatch(context.Background(), accepted); err == nil {
		t.Fatal("dispatch establish_data_channel on a non-data-channel facade must fail closed (not supported)")
	}

	dc := &dataChannelFakeFacade{}
	if _, err := (&Handler{Facade: dc}).dispatch(context.Background(), accepted); err != nil {
		t.Fatalf("dispatch to a DataChannelFacade errored: %v", err)
	}
	if !dc.called {
		t.Fatal("EstablishDataChannel was not routed to the DataChannelFacade")
	}
}

// End-to-end through Handle: today (no facade implements DataChannelFacade) an
// establish_data_channel request is preflight-ALLOWED on the empty-contract path but
// then dispatch fails closed → the response is a DENY. This locks in the inert,
// default-off behavior and documents the allow-then-not-supported sequence.
func TestHandleEstablishDataChannelInertDeny(t *testing.T) {
	handler := newHandler(&fakeFacade{}) // does NOT implement DataChannelFacade
	env := validEnvelope()
	env.Action = ActionEstablishDataChannel
	env.Contract = ContractRef{} // empty -> manifest-independent preflight
	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision == DecisionAllow {
		t.Fatalf("establish_data_channel must be denied today (no data-channel facade wired); got %#v", resp.Decision)
	}
	if resp.Error == nil {
		t.Fatal("expected a not-supported error on the response")
	}
}
