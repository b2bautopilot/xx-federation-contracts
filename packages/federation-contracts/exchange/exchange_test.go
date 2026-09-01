package exchange

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	testNowMS           int64 = 1000
	testExpiresMS       int64 = 2000
	testTenantA               = "tenant-a"
	testTenantB               = "tenant-b"
	testGatewayA              = "gw-a"
	testGatewayB              = "gw-b"
	testPartnerLink           = "link-ab"
	testContract              = "order_to_cash.purchase_order.request.v1"
	testContractVersion       = "1.0.0"
	testManifestHash          = "manifest-sha"
	testSchemaHash            = "schema-sha"
)

func TestAcceptedEnvelopeCallsOnlyNarrowedFacade(t *testing.T) {
	facade := &fakeFacade{}
	handler := newHandler(facade)

	resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision != DecisionAllow {
		t.Fatalf("decision = %#v, want allow", resp.Decision)
	}
	if !facade.openCalled || facade.catalogCalled {
		t.Fatalf("facade calls catalog=%v open=%v, want only open transaction", facade.catalogCalled, facade.openCalled)
	}
	if facade.accepted.Session.RemoteGatewayID != testGatewayA || facade.accepted.Envelope.Action != ActionOpenFederationTransaction {
		t.Fatalf("accepted envelope = %#v", facade.accepted)
	}
	assertAudit(t, handler.audit, DecisionAllow, "")
}

func TestAcceptedEnvelopeDispatchesOnlyDeclaredGatewayWorkAction(t *testing.T) {
	cases := []struct {
		name       string
		action     string
		wantMethod string
	}{
		{"catalog view", ActionGetServiceCatalogView, FacadeGetServiceCatalogView},
		{"open transaction", ActionOpenFederationTransaction, FacadeOpenFederationTransaction},
		{"create room", ActionCreateFederationRoom, FacadeCreateFederationRoom},
		{"submit message", ActionSubmitFederationMessage, FacadeSubmitFederationMessage},
		{"request builder work", ActionRequestBuilderWork, FacadeRequestBuilderWork},
		{"submit federation result", ActionSubmitFederationResult, FacadeSubmitFederationResult},
		{"deliver builder work result", ActionDeliverBuilderWorkResult, FacadeDeliverBuilderWorkResult},
		{"submit purchase order (O2C)", ActionSubmitPurchaseOrder, FacadeSubmitCommercialEvent},
		{"issue invoice (O2C)", ActionIssueInvoice, FacadeSubmitCommercialEvent},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facade := &fakeFacade{}
			handler := newHandler(facade)
			env := validEnvelope()
			env.EnvelopeID = "env-" + tc.action
			env.CorrelationID = "corr-" + tc.action
			env.IdempotencyKey = "idem-" + tc.action
			env.Action = tc.action

			resp, err := handler.Handle(context.Background(), validSession(), env)
			if err != nil {
				t.Fatalf("Handle error = %v", err)
			}
			if resp.Decision.Decision != DecisionAllow {
				t.Fatalf("decision = %#v, want allow", resp.Decision)
			}
			if got := facade.calledMethods(); len(got) != 1 || got[0] != tc.wantMethod {
				t.Fatalf("facade methods = %#v, want only %s", got, tc.wantMethod)
			}
		})
	}
}

func TestSpoofedBodyIdentityRejectedBeforeFacade(t *testing.T) {
	facade := &fakeFacade{}
	handler := newHandler(facade)
	env := validEnvelope()
	env.Source.GatewayID = "spoofed-gateway"

	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorUnauthenticated)
	if facade.anyCalled() {
		t.Fatal("facade was called for spoofed body identity")
	}
	assertAudit(t, handler.audit, DecisionDeny, ErrorUnauthenticated)
}

func TestUnknownContractRejectedBeforeReplayClaim(t *testing.T) {
	facade := &fakeFacade{}
	handler := newHandler(facade)
	env := validEnvelope()
	env.Contract.ContractID = "unknown"

	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorContractUnknown)
	if handler.replay.claims != 0 {
		t.Fatalf("replay claims = %d, want 0 for unknown contract", handler.replay.claims)
	}
}

func TestStaleManifestHashRejected(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	env := validEnvelope()
	env.Contract.ManifestHashSHA256 = "old-manifest"

	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorContractMismatch)
}

func TestExpiredEnvelopeRejected(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	env := validEnvelope()
	env.ExpiresAtMS = 800

	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorExpired)
}

func TestPayloadHashMismatchRejected(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	env := validEnvelope()
	env.PayloadHashSHA256 = hashBytes([]byte("other-payload"))

	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorPayloadInvalid)
}

func TestPayloadValidatorRequiredAndCanRejectShape(t *testing.T) {
	t.Run("missing validator", func(t *testing.T) {
		handler := newHandler(&fakeFacade{})
		handler.Payloads = nil

		resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
		if err != nil {
			t.Fatalf("Handle error = %v", err)
		}
		assertDeny(t, resp, ErrorPayloadInvalid)
	})

	t.Run("identity-like body rejected", func(t *testing.T) {
		handler := newHandler(&fakeFacade{})
		handler.payloads.err = errors.New("body identity is not contract payload")

		resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
		if err != nil {
			t.Fatalf("Handle error = %v", err)
		}
		assertDeny(t, resp, ErrorPayloadInvalid)
	})
}

func TestPolicyAuthorizerRequiredAndCanDeny(t *testing.T) {
	t.Run("missing policy", func(t *testing.T) {
		handler := newHandler(&fakeFacade{})
		handler.Policy = nil

		resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
		if err != nil {
			t.Fatalf("Handle error = %v", err)
		}
		assertDeny(t, resp, ErrorPolicyDenied)
	})

	t.Run("policy denied", func(t *testing.T) {
		handler := newHandler(&fakeFacade{})
		handler.policy.err = errors.New("no active policy grant")

		resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
		if err != nil {
			t.Fatalf("Handle error = %v", err)
		}
		assertDeny(t, resp, ErrorPolicyDenied)
		if handler.replay.claims != 0 {
			t.Fatalf("replay claims = %d, want 0 before policy allow", handler.replay.claims)
		}
	})
}

func TestMutatingEnvelopeRequiresReplayCache(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	handler.Replay = nil

	resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorReplayUnavailable)
}

func TestReplayEnvelopeRejected(t *testing.T) {
	handler := newHandler(&fakeFacade{})

	first, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil || first.Decision.Decision != DecisionAllow {
		t.Fatalf("first Handle resp=%#v err=%v, want allow", first, err)
	}
	second, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil {
		t.Fatalf("second Handle error = %v", err)
	}
	assertDeny(t, second, ErrorReplayDetected)
}

func TestRevokedPartnerLinkAndKillSwitchReject(t *testing.T) {
	t.Run("revoked link", func(t *testing.T) {
		handler := newHandler(&fakeFacade{})
		session := validSession()
		session.PartnerLinkState = PartnerLinkRevoked

		resp, err := handler.Handle(context.Background(), session, validEnvelope())
		if err != nil {
			t.Fatalf("Handle error = %v", err)
		}
		assertDeny(t, resp, ErrorPartnerLinkDenied)
	})

	t.Run("kill switch", func(t *testing.T) {
		handler := newHandler(&fakeFacade{})
		session := validSession()
		session.KillSwitchEnabled = true

		resp, err := handler.Handle(context.Background(), session, validEnvelope())
		if err != nil {
			t.Fatalf("Handle error = %v", err)
		}
		assertDeny(t, resp, ErrorKillSwitch)
	})
}

func TestRawFacadeMethodRejectedEvenWithKnownAction(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	manifest := validManifest()
	manifest.Actions[ActionOpenFederationTransaction] = ActionContract{
		Action:                 ActionOpenFederationTransaction,
		FacadeMethod:           "ProjectService.DeleteProject",
		Mutating:               true,
		IdempotencyRequired:    true,
		PayloadEncoding:        PayloadEncodingJSON,
		MaxPayloadBytes:        1024,
		PrivateTopologyAllowed: false,
		AllowedPartnerLinkIDs:  []string{testPartnerLink},
	}
	handler.manifests.manifest = manifest

	resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorContractMismatch)
}

func TestManifestWithoutExplicitPartnerLinkRejected(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	manifest := validManifest()
	action := manifest.Actions[ActionOpenFederationTransaction]
	action.AllowedPartnerLinkIDs = nil
	manifest.Actions[ActionOpenFederationTransaction] = action
	handler.manifests.manifest = manifest

	resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorContractMismatch)
}

func TestPrivateTopologyPayloadRejectedWhenContractDisallowsIt(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	env := validEnvelope()
	env.Payload = []byte(`{"mesh_ip":"fd00:b17e::1","task":"quote"}`)
	env.PayloadHashSHA256 = hashBytes(env.Payload)

	resp, err := handler.Handle(context.Background(), validSession(), env)
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorPayloadInvalid)
}

func TestPrivateTopologyResponseRejected(t *testing.T) {
	facade := &fakeFacade{openResult: DispatchResult{Status: "ok", PayloadJSON: `{"endpoint":"fd00:b17e::1"}`}}
	handler := newHandler(facade)

	resp, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	assertDeny(t, resp, ErrorPayloadInvalid)
	assertAudit(t, handler.audit, DecisionDeny, ErrorPayloadInvalid)
}

func TestAuditFailureIsReturned(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	handler.audit.err = errors.New("audit sink down")

	_, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err == nil {
		t.Fatal("Handle returned nil error, want audit failure")
	}
}

func TestAuditSinkRequired(t *testing.T) {
	handler := newHandler(&fakeFacade{})
	handler.Audit = nil

	_, err := handler.Handle(context.Background(), validSession(), validEnvelope())
	if err == nil {
		t.Fatal("Handle returned nil error, want missing audit sink failure")
	}
}

func newHandler(facade *fakeFacade) *testHarness {
	manifests := &fakeManifestCache{manifest: validManifest()}
	replay := &fakeReplayCache{inner: NewMemoryReplayCache()}
	policy := &fakePolicyAuthorizer{}
	payloads := &fakePayloadValidator{}
	audit := &fakeAuditSink{}
	return &testHarness{
		Handler: &Handler{
			Manifests:   manifests,
			Replay:      replay,
			Policy:      policy,
			Payloads:    payloads,
			Facade:      facade,
			Audit:       audit,
			NowMS:       func() int64 { return testNowMS },
			ClockSkewMS: 100,
		},
		manifests: manifests,
		replay:    replay,
		policy:    policy,
		payloads:  payloads,
		audit:     audit,
	}
}

type testHarness struct {
	*Handler
	manifests *fakeManifestCache
	replay    *fakeReplayCache
	policy    *fakePolicyAuthorizer
	payloads  *fakePayloadValidator
	audit     *fakeAuditSink
}

func validSession() AuthenticatedSession {
	return AuthenticatedSession{
		LocalTenantID:            testTenantB,
		LocalGatewayID:           testGatewayB,
		RemoteTenantID:           testTenantA,
		RemoteGatewayID:          testGatewayA,
		RemoteServicePrincipalID: "spn-gw-a",
		PartnerLinkID:            testPartnerLink,
		PartnerLinkState:         PartnerLinkActive,
	}
}

func validEnvelope() Envelope {
	payload := []byte(`{"kind":"purchase_order","subject":"PO-100"}`)
	return Envelope{
		SchemaVersion:  SchemaGatewayExchangeV1,
		EnvelopeID:     "env-1",
		CorrelationID:  "corr-1",
		IdempotencyKey: "idem-1",
		SentAtMS:       testNowMS,
		ExpiresAtMS:    testExpiresMS,
		PartnerLinkID:  testPartnerLink,
		Source: GatewayRef{
			TenantID:      testTenantA,
			GatewayID:     testGatewayA,
			GatewayPoolID: "pool-a",
		},
		Destination: GatewayRef{
			TenantID:      testTenantB,
			GatewayID:     testGatewayB,
			GatewayPoolID: "pool-b",
		},
		Contract: ContractRef{
			ContractID:              testContract,
			ContractVersion:         testContractVersion,
			ManifestHashSHA256:      testManifestHash,
			PayloadSchemaHashSHA256: testSchemaHash,
		},
		Action:            ActionOpenFederationTransaction,
		PayloadEncoding:   PayloadEncodingJSON,
		PayloadHashSHA256: hashBytes(payload),
		Payload:           payload,
	}
}

func validManifest() Manifest {
	return Manifest{
		ContractID:              testContract,
		ContractVersion:         testContractVersion,
		ManifestHashSHA256:      testManifestHash,
		PayloadSchemaHashSHA256: testSchemaHash,
		ExpiresAtMS:             testExpiresMS,
		Actions: map[string]ActionContract{
			ActionGetServiceCatalogView: {
				Action:                ActionGetServiceCatalogView,
				FacadeMethod:          FacadeGetServiceCatalogView,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				IdempotencyRequired:   false,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionOpenFederationTransaction: {
				Action:                ActionOpenFederationTransaction,
				FacadeMethod:          FacadeOpenFederationTransaction,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				Mutating:              true,
				IdempotencyRequired:   true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionCreateFederationRoom: {
				Action:                ActionCreateFederationRoom,
				FacadeMethod:          FacadeCreateFederationRoom,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				Mutating:              true,
				IdempotencyRequired:   true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionSubmitFederationMessage: {
				Action:                ActionSubmitFederationMessage,
				FacadeMethod:          FacadeSubmitFederationMessage,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				Mutating:              true,
				IdempotencyRequired:   true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionRequestBuilderWork: {
				Action:                ActionRequestBuilderWork,
				FacadeMethod:          FacadeRequestBuilderWork,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				Mutating:              true,
				IdempotencyRequired:   true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionSubmitFederationResult: {
				Action:                ActionSubmitFederationResult,
				FacadeMethod:          FacadeSubmitFederationResult,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				Mutating:              true,
				IdempotencyRequired:   true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionDeliverBuilderWorkResult: {
				Action:                ActionDeliverBuilderWorkResult,
				FacadeMethod:          FacadeDeliverBuilderWorkResult,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				Mutating:              true,
				IdempotencyRequired:   true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionSubmitPurchaseOrder: {
				Action:                ActionSubmitPurchaseOrder,
				FacadeMethod:          FacadeSubmitCommercialEvent,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				IdempotencyRequired:   true,
				Mutating:              true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
			ActionIssueInvoice: {
				Action:                ActionIssueInvoice,
				FacadeMethod:          FacadeSubmitCommercialEvent,
				PayloadEncoding:       PayloadEncodingJSON,
				MaxPayloadBytes:       1024,
				IdempotencyRequired:   true,
				Mutating:              true,
				AllowedPartnerLinkIDs: []string{testPartnerLink},
			},
		},
	}
}

func hashBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func assertDeny(t *testing.T, resp Response, code string) {
	t.Helper()
	if resp.Decision.Decision != DecisionDeny || resp.Decision.DenialCode != code {
		t.Fatalf("decision = %#v, want deny %s", resp.Decision, code)
	}
}

func assertAudit(t *testing.T, sink *fakeAuditSink, decision, code string) {
	t.Helper()
	if len(sink.events) == 0 {
		t.Fatal("missing audit event")
	}
	event := sink.events[len(sink.events)-1]
	if event.Decision != decision || event.DenialCode != code {
		t.Fatalf("audit event = %#v, want decision=%s code=%s", event, decision, code)
	}
}

type fakeManifestCache struct {
	manifest Manifest
}

func (f *fakeManifestCache) ResolveManifest(_ context.Context, ref ContractRef) (Manifest, error) {
	if ref.ContractID != f.manifest.ContractID || ref.ContractVersion != f.manifest.ContractVersion {
		return Manifest{}, ErrManifestNotFound
	}
	return f.manifest, nil
}

type fakeReplayCache struct {
	inner  *MemoryReplayCache
	claims int
}

func (f *fakeReplayCache) Claim(ctx context.Context, claim ReplayClaim) error {
	f.claims++
	return f.inner.Claim(ctx, claim)
}

type fakePolicyAuthorizer struct {
	err error
}

func (f *fakePolicyAuthorizer) AuthorizeGatewayExchange(_ context.Context, _ PolicyCheck) error {
	return f.err
}

type fakePayloadValidator struct {
	err error
}

func (f *fakePayloadValidator) ValidateGatewayExchangePayload(_ context.Context, _ PayloadValidationInput) error {
	return f.err
}

type fakeFacade struct {
	catalogCalled         bool
	openCalled            bool
	createRoomCalled      bool
	submitMessageCalled   bool
	requestBuilderCalled  bool
	submitResultCalled    bool
	deliverResultCalled   bool
	accepted              AcceptedEnvelope
	catalogResult         DispatchResult
	openResult            DispatchResult
	err                   error
	commercialEventCalled bool
}

func (f *fakeFacade) GetServiceCatalogView(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.catalogCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	if f.catalogResult.Status != "" || f.catalogResult.PayloadJSON != "" {
		return f.catalogResult, nil
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"entries":[]}`}, nil
}

func (f *fakeFacade) OpenFederationTransaction(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.openCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	if f.openResult.Status != "" || f.openResult.PayloadJSON != "" {
		return f.openResult, nil
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"transaction_id":"tx-1"}`}, nil
}

func (f *fakeFacade) CreateFederationRoom(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.createRoomCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"room_id":"room-1"}`}, nil
}

func (f *fakeFacade) SubmitFederationMessage(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.submitMessageCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"message_id":"msg-1"}`}, nil
}

func (f *fakeFacade) RequestBuilderWork(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.requestBuilderCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"work_request_id":"work-1"}`}, nil
}

func (f *fakeFacade) SubmitFederationResult(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.submitResultCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"work_request_id":"work-1"}`}, nil
}

func (f *fakeFacade) DeliverBuilderWorkResult(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.deliverResultCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"work_request_id":"work-1"}`}, nil
}

func (f *fakeFacade) SubmitCommercialEvent(_ context.Context, accepted AcceptedEnvelope) (DispatchResult, error) {
	f.commercialEventCalled = true
	f.accepted = accepted
	if f.err != nil {
		return DispatchResult{}, f.err
	}
	return DispatchResult{Status: "ok", PayloadJSON: `{"event_id":"event-1"}`}, nil
}

func (f *fakeFacade) anyCalled() bool {
	return f.catalogCalled || f.openCalled || f.createRoomCalled || f.submitMessageCalled || f.requestBuilderCalled || f.submitResultCalled || f.deliverResultCalled
}

func (f *fakeFacade) calledMethods() []string {
	var methods []string
	if f.catalogCalled {
		methods = append(methods, FacadeGetServiceCatalogView)
	}
	if f.openCalled {
		methods = append(methods, FacadeOpenFederationTransaction)
	}
	if f.createRoomCalled {
		methods = append(methods, FacadeCreateFederationRoom)
	}
	if f.submitMessageCalled {
		methods = append(methods, FacadeSubmitFederationMessage)
	}
	if f.requestBuilderCalled {
		methods = append(methods, FacadeRequestBuilderWork)
	}
	if f.submitResultCalled {
		methods = append(methods, FacadeSubmitFederationResult)
	}
	if f.deliverResultCalled {
		methods = append(methods, FacadeDeliverBuilderWorkResult)
	}
	if f.commercialEventCalled {
		methods = append(methods, FacadeSubmitCommercialEvent)
	}
	return methods
}

type fakeAuditSink struct {
	events []AuditEvent
	err    error
}

func (f *fakeAuditSink) RecordExchangeAudit(_ context.Context, event AuditEvent) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}
