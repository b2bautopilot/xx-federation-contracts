package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// NE-7.3: manifest discovery exchange — manifest-independent preflight.

type fakeManifestDiscovery struct {
	documents []SignedManifestDocument
	err       error
	calls     int
	session   AuthenticatedSession
}

func (f *fakeManifestDiscovery) DiscoverSignedManifests(_ context.Context, session AuthenticatedSession) ([]SignedManifestDocument, error) {
	f.calls++
	f.session = session
	return f.documents, f.err
}

func discoveryEnvelope() Envelope {
	env := validEnvelope()
	env.Action = ActionDiscoverContractManifests
	env.Contract = ContractRef{}
	env.Payload = nil
	env.PayloadHashSHA256 = ""
	env.PayloadEncoding = ""
	env.IdempotencyKey = ""
	return env
}

func TestHandleManifestDiscovery_AllowsWithoutAnyManifestState(t *testing.T) {
	discovery := &fakeManifestDiscovery{documents: []SignedManifestDocument{
		{ManifestID: "m-1", CatalogVersion: "v1", SigningKeyID: "k1", ManifestHashSHA256: "h1", Document: json.RawMessage(`{"manifest_id":"m-1"}`)},
		{ManifestID: "m-2", CatalogVersion: "v2", SigningKeyID: "k1", ManifestHashSHA256: "h2", Document: json.RawMessage(`{"manifest_id":"m-2"}`)},
	}}
	harness := newHandler(&fakeFacade{})
	// Adversarial pin: discovery must not depend on manifest resolution,
	// policy, payload validation, or approval state — the requesting
	// partner has none of it yet. With these nil the NORMAL preflight
	// fails closed, so an allow here proves manifest independence.
	harness.Handler.Manifests = nil
	harness.Handler.Policy = nil
	harness.Handler.Payloads = nil
	harness.Handler.Approvals = nil
	harness.Handler.Discovery = discovery

	resp, err := harness.Handle(context.Background(), validSession(), discoveryEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision != DecisionAllow {
		t.Fatalf("Decision = %s (%s), want allow", resp.Decision.Decision, resp.Decision.DenialCode)
	}
	if resp.Decision.Action != ActionDiscoverContractManifests || resp.Decision.FacadeMethod != FacadeDiscoverContractManifests {
		t.Fatalf("decision action/facade = %s/%s", resp.Decision.Action, resp.Decision.FacadeMethod)
	}
	if discovery.calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", discovery.calls)
	}
	if discovery.session.PartnerLinkID != testPartnerLink {
		t.Fatalf("discovery session partner link = %q", discovery.session.PartnerLinkID)
	}
	var result ManifestDiscoveryResult
	if err := json.Unmarshal([]byte(resp.Result.PayloadJSON), &result); err != nil {
		t.Fatalf("unmarshal result payload: %v", err)
	}
	if result.SchemaVersion != SchemaManifestDiscoveryV1 {
		t.Fatalf("result schema = %q", result.SchemaVersion)
	}
	if len(result.Manifests) != 2 || result.Manifests[0].ManifestID != "m-1" || result.Manifests[1].ManifestID != "m-2" {
		t.Fatalf("result manifests = %+v", result.Manifests)
	}
	last := harness.audit.events[len(harness.audit.events)-1]
	if last.Decision != DecisionAllow || last.Action != ActionDiscoverContractManifests {
		t.Fatalf("audit event = %+v", last)
	}
}

func TestHandleManifestDiscovery_DenialGates(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*Envelope, *AuthenticatedSession, *testHarness)
		wantCode string
	}{
		{
			name: "session mismatch",
			mutate: func(env *Envelope, _ *AuthenticatedSession, _ *testHarness) {
				env.PartnerLinkID = "link-other"
			},
			wantCode: ErrorUnauthenticated,
		},
		{
			name: "kill switch",
			mutate: func(_ *Envelope, session *AuthenticatedSession, _ *testHarness) {
				session.KillSwitchEnabled = true
			},
			wantCode: ErrorKillSwitch,
		},
		{
			name: "inactive partner link",
			mutate: func(_ *Envelope, session *AuthenticatedSession, _ *testHarness) {
				session.PartnerLinkState = PartnerLinkRevoked
			},
			wantCode: ErrorPartnerLinkDenied,
		},
		{
			name: "expired envelope",
			mutate: func(env *Envelope, _ *AuthenticatedSession, _ *testHarness) {
				env.ExpiresAtMS = 0
			},
			wantCode: ErrorExpired,
		},
		{
			name: "non-empty payload",
			mutate: func(env *Envelope, _ *AuthenticatedSession, _ *testHarness) {
				env.Payload = []byte(`{"probe":true}`)
			},
			wantCode: ErrorPayloadInvalid,
		},
		{
			name: "wrong schema version",
			mutate: func(env *Envelope, _ *AuthenticatedSession, _ *testHarness) {
				env.SchemaVersion = "builders.federation.gateway_exchange.v0"
			},
			wantCode: ErrorPayloadInvalid,
		},
		{
			name:     "nil discovery",
			mutate:   func(_ *Envelope, _ *AuthenticatedSession, h *testHarness) { h.Handler.Discovery = nil },
			wantCode: ErrorGatewayUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			harness := newHandler(&fakeFacade{})
			harness.Handler.Discovery = &fakeManifestDiscovery{}
			env := discoveryEnvelope()
			session := validSession()
			tc.mutate(&env, &session, harness)

			resp, err := harness.Handle(context.Background(), session, env)
			if err != nil {
				t.Fatalf("Handle error = %v", err)
			}
			if resp.Decision.Decision != DecisionDeny || resp.Decision.DenialCode != tc.wantCode {
				t.Fatalf("decision = %s/%s, want deny/%s", resp.Decision.Decision, resp.Decision.DenialCode, tc.wantCode)
			}
			last := harness.audit.events[len(harness.audit.events)-1]
			if last.Decision != DecisionDeny || last.DenialCode != tc.wantCode {
				t.Fatalf("audit event = %+v", last)
			}
		})
	}
}

func TestHandleManifestDiscovery_ReplayedEnvelopeDenied(t *testing.T) {
	harness := newHandler(&fakeFacade{})
	harness.Handler.Discovery = &fakeManifestDiscovery{}
	env := discoveryEnvelope()

	first, err := harness.Handle(context.Background(), validSession(), env)
	if err != nil || first.Decision.Decision != DecisionAllow {
		t.Fatalf("first Handle = %+v, %v", first.Decision, err)
	}
	second, err := harness.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("second Handle error = %v", err)
	}
	if second.Decision.Decision != DecisionDeny || second.Decision.DenialCode != ErrorReplayDetected {
		t.Fatalf("second decision = %s/%s, want deny/%s", second.Decision.Decision, second.Decision.DenialCode, ErrorReplayDetected)
	}
}

func TestHandleManifestDiscovery_DiscoveryErrorSurfacesDenial(t *testing.T) {
	harness := newHandler(&fakeFacade{})
	harness.Handler.Discovery = &fakeManifestDiscovery{err: errors.New("store offline")}

	resp, err := harness.Handle(context.Background(), validSession(), discoveryEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision != DecisionDeny || resp.Decision.DenialCode != ErrorGatewayUnavailable {
		t.Fatalf("decision = %s/%s", resp.Decision.Decision, resp.Decision.DenialCode)
	}
	if resp.Error == nil || resp.Error.Code != ErrorGatewayUnavailable {
		t.Fatalf("error info = %+v", resp.Error)
	}
}

func TestHandleManifestDiscovery_EmptyResultIsAllowedAndExplicit(t *testing.T) {
	harness := newHandler(&fakeFacade{})
	harness.Handler.Discovery = &fakeManifestDiscovery{}

	resp, err := harness.Handle(context.Background(), validSession(), discoveryEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision != DecisionAllow {
		t.Fatalf("decision = %+v", resp.Decision)
	}
	var result ManifestDiscoveryResult
	if err := json.Unmarshal([]byte(resp.Result.PayloadJSON), &result); err != nil {
		t.Fatalf("unmarshal result payload: %v", err)
	}
	if result.Manifests == nil || len(result.Manifests) != 0 {
		t.Fatalf("manifests = %#v, want explicit empty list", result.Manifests)
	}
}
