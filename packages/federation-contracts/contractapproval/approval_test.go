package contractapproval

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/b2bautopilot/xyz-b2b/packages/app-errors"
	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/contractmanifest"
	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/exchange"
)

const (
	testTenantA     = "tenant-a"
	testTenantB     = "tenant-b"
	testGatewayA    = "gateway-a"
	testGatewayB    = "gateway-b"
	testPartnerLink = "plnk-a-b"
	testOtherLink   = "plnk-a-c"
	testCatalog     = "order_to_cash.v1"
	testContractID  = "order_to_cash.purchase_order.request.v1"
	testKeyID       = "contract-approval-key"
	testNowMS       = int64(1_000)
	testExpiresMS   = int64(9_000)
)

func TestExchangeRequiresApprovedPinnedContractPackVersion(t *testing.T) {
	cache, v1, v2 := signedManifestCache(t)
	registry := NewRegistry()
	handler := newHandler(cache, registry)

	if got := handleDecision(t, handler, v1, "unsigned"); got.Decision != exchange.DecisionDeny || got.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("unapproved decision = %#v, want contract mismatch deny", got)
	}

	putApproved(t, registry, v1, "1.0.0", []string{testPartnerLink}, testNowMS+10)
	if got := handleDecision(t, handler, v1, "approved-not-pinned"); got.Decision != exchange.DecisionDeny || got.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("approved but unpinned decision = %#v, want contract mismatch deny", got)
	}

	pin := pinApproved(t, registry, v1, "1.0.0", testNowMS+20, "initial approval")
	if len(pin.AuditBindingHashSHA256) != 64 {
		t.Fatalf("pin audit binding hash = %q, want sha256", pin.AuditBindingHashSHA256)
	}
	if got := handleDecision(t, handler, v1, "v1-pinned"); got.Decision != exchange.DecisionAllow {
		t.Fatalf("v1 pinned decision = %#v, want allow", got)
	}

	putApproved(t, registry, v2, "2.0.0", []string{testPartnerLink}, testNowMS+30)
	if got := handleDecision(t, handler, v2, "v2-approved-not-pinned"); got.Decision != exchange.DecisionDeny || got.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("v2 unpinned decision = %#v, want contract mismatch deny", got)
	}

	v2Pin := pinApproved(t, registry, v2, "2.0.0", testNowMS+40, "upgrade")
	if v2Pin.PreviousPackVersion != "1.0.0" || v2Pin.PreviousManifestHashSHA256 != v1.ManifestHashSHA256 {
		t.Fatalf("upgrade pin previous = %#v, want v1 rollback evidence", v2Pin)
	}
	if got := handleDecision(t, handler, v2, "v2-pinned"); got.Decision != exchange.DecisionAllow {
		t.Fatalf("v2 pinned decision = %#v, want allow", got)
	}
	if got := handleDecision(t, handler, v1, "v1-after-upgrade"); got.Decision != exchange.DecisionDeny || got.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("old v1 after upgrade decision = %#v, want contract mismatch deny", got)
	}

	rollbackPin := pinApproved(t, registry, v1, "1.0.0", testNowMS+50, "rollback to prior approved version")
	if rollbackPin.PreviousPackVersion != "2.0.0" || rollbackPin.PreviousManifestHashSHA256 != v2.ManifestHashSHA256 {
		t.Fatalf("rollback pin previous = %#v, want v2 evidence", rollbackPin)
	}
	if got := handleDecision(t, handler, v1, "v1-after-rollback"); got.Decision != exchange.DecisionAllow {
		t.Fatalf("v1 after rollback decision = %#v, want allow", got)
	}
	if got := handleDecision(t, handler, v2, "v2-after-rollback"); got.Decision != exchange.DecisionDeny || got.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("v2 after rollback decision = %#v, want contract mismatch deny", got)
	}
}

func TestApprovalPartnerLinkAllowlistFailsClosed(t *testing.T) {
	cache, v1, _ := signedManifestCache(t)
	registry := NewRegistry()
	handler := newHandler(cache, registry)
	record := putApproved(t, registry, v1, "1.0.0", []string{testPartnerLink}, testNowMS+10)
	if !containsString(record.AllowedPartnerLinkIDs, testPartnerLink) || containsString(record.AllowedPartnerLinkIDs, testOtherLink) {
		t.Fatalf("record partner allowlist = %#v", record.AllowedPartnerLinkIDs)
	}

	if _, err := registry.Pin(PinInput{
		TenantID:           testTenantB,
		PartnerLinkID:      testOtherLink,
		CatalogVersion:     testCatalog,
		PackVersion:        "1.0.0",
		ManifestHashSHA256: v1.ManifestHashSHA256,
		PinnedBy:           "operator-b",
		PinnedAtMS:         testNowMS + 20,
	}); err == nil || apperrors.From(err).Code != apperrors.CodePolicyDenied {
		t.Fatalf("Pin(other partner link) error = %v, want policy denied", err)
	}

	pinApproved(t, registry, v1, "1.0.0", testNowMS+30, "initial approval")
	if got := handleDecisionForPartner(t, handler, v1, testOtherLink, "other-link"); got.Decision != exchange.DecisionDeny || got.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("other partner-link decision = %#v, want contract mismatch deny", got)
	}
}

func TestApprovalRecordsRequireApprovalEvidenceAndStableAuditBinding(t *testing.T) {
	_, v1, _ := signedManifestCache(t)
	pending, err := NewApprovalRecord(ApprovalInput{
		Manifest:                     v1,
		PackVersion:                  "1.0.0",
		State:                        StatePendingApproval,
		AllowedPartnerLinkIDs:        []string{testPartnerLink},
		ServiceCatalogIDByContractID: map[string]string{testContractID: "catalog-v1"},
		CreatedBy:                    "operator-b",
		CreatedAtMS:                  testNowMS,
	})
	if err != nil {
		t.Fatalf("NewApprovalRecord pending error = %v", err)
	}
	if len(pending.AuditBindingHashSHA256) != 64 {
		t.Fatalf("pending audit binding hash = %q, want sha256", pending.AuditBindingHashSHA256)
	}
	registry := NewRegistry()
	if err := registry.PutApproval(pending); err != nil {
		t.Fatalf("PutApproval pending error = %v", err)
	}
	if _, err := registry.Pin(PinInput{
		TenantID:           testTenantB,
		PartnerLinkID:      testPartnerLink,
		CatalogVersion:     testCatalog,
		PackVersion:        "1.0.0",
		ManifestHashSHA256: v1.ManifestHashSHA256,
		PinnedBy:           "operator-b",
		PinnedAtMS:         testNowMS + 10,
	}); err == nil || apperrors.From(err).Code != apperrors.CodePolicyDenied {
		t.Fatalf("Pin pending record error = %v, want policy denied", err)
	}

	_, err = NewApprovalRecord(ApprovalInput{
		Manifest:                     v1,
		PackVersion:                  "1.0.0",
		State:                        StateApproved,
		ServiceCatalogIDByContractID: map[string]string{testContractID: "catalog-v1"},
		ApprovedBy:                   "operator-b",
		ApprovedAtMS:                 testNowMS + 20,
		CreatedBy:                    "operator-b",
		CreatedAtMS:                  testNowMS,
	})
	if err == nil || apperrors.From(err).Code != apperrors.CodePolicyDenied {
		t.Fatalf("approved record without partner links error = %v, want policy denied", err)
	}

	approved := putApproved(t, registry, v1, "1.0.0", []string{testPartnerLink}, testNowMS+30)
	approved.AuditBindingHashSHA256 = strings.Repeat("0", 64)
	if err := registry.PutApproval(approved); err == nil || apperrors.From(err).Code != apperrors.CodePolicyDenied {
		t.Fatalf("tampered audit binding error = %v, want policy denied", err)
	}
}

func TestApprovalRecordBindsServiceCatalogAction(t *testing.T) {
	_, v1, _ := signedManifestCache(t)
	record, err := NewApprovalRecord(ApprovalInput{
		Manifest:                         v1,
		PackVersion:                      "1.0.0",
		State:                            StateApproved,
		AllowedPartnerLinkIDs:            []string{testPartnerLink},
		ServiceCatalogIDByContractID:     map[string]string{testContractID: "catalog-v1"},
		ServiceCatalogActionByContractID: map[string]string{testContractID: "submit_purchase_order"},
		ApprovedBy:                       "operator-b",
		ApprovedAtMS:                     testNowMS + 20,
		CreatedBy:                        "operator-b",
		CreatedAtMS:                      testNowMS,
	})
	if err != nil {
		t.Fatalf("NewApprovalRecord error = %v", err)
	}
	if len(record.Contracts) != 1 || record.Contracts[0].Action != exchange.ActionOpenFederationTransaction ||
		record.Contracts[0].ServiceCatalogAction != "submit_purchase_order" {
		t.Fatalf("contract pin = %#v, want gateway action plus service catalog action", record.Contracts)
	}
	tampered := record
	tampered.Contracts[0].ServiceCatalogAction = "issue_invoice"
	if err := ValidateApprovalRecord(tampered); err == nil || apperrors.From(err).Code != apperrors.CodePolicyDenied {
		t.Fatalf("tampered service catalog action error = %v, want policy denied", err)
	}
}

func signedManifestCache(t *testing.T) (*contractmanifest.MemoryCache, contractmanifest.Manifest, contractmanifest.Manifest) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	v1 := signManifest(t, privateKey, "manifest-v1", "1.0.0", schemaHash("schema-v1"))
	v2 := signManifest(t, privateKey, "manifest-v2", "2.0.0", schemaHash("schema-v2"))
	cache := contractmanifest.NewMemoryCache(contractmanifest.Keyring{testKeyID: publicKey}, func() int64 { return testNowMS })
	for _, manifest := range []contractmanifest.Manifest{v1, v2} {
		if err := cache.PutVerified(context.Background(), manifest); err != nil {
			t.Fatalf("PutVerified(%s) error = %v", manifest.ManifestID, err)
		}
	}
	return cache, v1, v2
}

func signManifest(t *testing.T, privateKey ed25519.PrivateKey, manifestID, contractVersion, schemaHash string) contractmanifest.Manifest {
	t.Helper()
	manifest, err := contractmanifest.Sign(contractmanifest.Manifest{
		SchemaVersion:  contractmanifest.SchemaVersion,
		TenantID:       testTenantB,
		ManifestID:     manifestID,
		IssuedAtMS:     testNowMS,
		ExpiresAtMS:    testExpiresMS,
		CatalogVersion: testCatalog,
		SigningKeyID:   testKeyID,
		Contracts: []contractmanifest.Contract{
			{
				ContractID:                 testContractID,
				ContractVersion:            contractVersion,
				DisplayName:                "Purchase order",
				Action:                     exchange.ActionOpenFederationTransaction,
				PayloadSchemaRef:           "schemas/order_to_cash/purchase_order.json",
				PayloadSchemaHashSHA256:    schemaHash,
				MaxPayloadBytes:            1024,
				RequiresIdempotency:        true,
				ReplayWindowSeconds:        3600,
				AllowedPartnerLinkIDs:      []string{testPartnerLink, testOtherLink},
				AllowedGatewayMethodScopes: []string{"federation.open_federation_transaction"},
				PrivateTopologyAllowed:     false,
				EgressPolicyRef:            "egress.order_to_cash.submit_purchase_order",
				AuditClass:                 "commercial_transaction",
				RetentionClass:             "order_to_cash",
			},
		},
	}, privateKey)
	if err != nil {
		t.Fatalf("Sign(%s) error = %v", manifestID, err)
	}
	return manifest
}

func putApproved(t *testing.T, registry *Registry, manifest contractmanifest.Manifest, packVersion string, partnerLinks []string, approvedAtMS int64) ApprovalRecord {
	t.Helper()
	record, err := NewApprovalRecord(ApprovalInput{
		Manifest:                     manifest,
		PackVersion:                  packVersion,
		State:                        StateApproved,
		AllowedPartnerLinkIDs:        partnerLinks,
		ServiceCatalogIDByContractID: map[string]string{testContractID: "catalog-" + packVersion},
		ApprovedBy:                   "operator-b",
		ApprovedAtMS:                 approvedAtMS,
		CreatedBy:                    "operator-b",
		CreatedAtMS:                  testNowMS,
	})
	if err != nil {
		t.Fatalf("NewApprovalRecord(%s) error = %v", packVersion, err)
	}
	if err := registry.PutApproval(record); err != nil {
		t.Fatalf("PutApproval(%s) error = %v", packVersion, err)
	}
	return record
}

func pinApproved(t *testing.T, registry *Registry, manifest contractmanifest.Manifest, packVersion string, pinnedAtMS int64, reason string) PartnerPin {
	t.Helper()
	pin, err := registry.Pin(PinInput{
		TenantID:           testTenantB,
		PartnerLinkID:      testPartnerLink,
		CatalogVersion:     testCatalog,
		PackVersion:        packVersion,
		ManifestHashSHA256: manifest.ManifestHashSHA256,
		PinnedBy:           "operator-b",
		PinnedAtMS:         pinnedAtMS,
		Reason:             reason,
	})
	if err != nil {
		t.Fatalf("Pin(%s) error = %v", packVersion, err)
	}
	return pin
}

func newHandler(cache *contractmanifest.MemoryCache, approvals *Registry) *exchange.Handler {
	return &exchange.Handler{
		Manifests: cache,
		Replay:    exchange.NewMemoryReplayCache(),
		Policy:    allowPolicy{},
		Payloads:  allowPayloads{},
		Approvals: approvals,
		Facade:    fakeFacade{},
		Audit:     auditSink{},
		NowMS:     func() int64 { return testNowMS + 100 },
	}
}

func handleDecision(t *testing.T, handler *exchange.Handler, manifest contractmanifest.Manifest, suffix string) exchange.PreflightDecision {
	t.Helper()
	return handleDecisionForPartner(t, handler, manifest, testPartnerLink, suffix)
}

func handleDecisionForPartner(t *testing.T, handler *exchange.Handler, manifest contractmanifest.Manifest, partnerLinkID, suffix string) exchange.PreflightDecision {
	t.Helper()
	payload := []byte(`{}`)
	contract := manifest.Contracts[0]
	resp, err := handler.Handle(context.Background(), exchange.AuthenticatedSession{
		LocalTenantID:    testTenantB,
		LocalGatewayID:   testGatewayB,
		RemoteTenantID:   testTenantA,
		RemoteGatewayID:  testGatewayA,
		PartnerLinkID:    partnerLinkID,
		PartnerLinkState: exchange.PartnerLinkActive,
	}, exchange.Envelope{
		SchemaVersion:  exchange.SchemaGatewayExchangeV1,
		EnvelopeID:     "env-" + suffix,
		CorrelationID:  "corr-" + suffix,
		IdempotencyKey: "idem-" + suffix,
		SentAtMS:       testNowMS,
		ExpiresAtMS:    testExpiresMS,
		PartnerLinkID:  partnerLinkID,
		Source:         exchange.GatewayRef{TenantID: testTenantA, GatewayID: testGatewayA},
		Destination:    exchange.GatewayRef{TenantID: testTenantB, GatewayID: testGatewayB},
		Contract: exchange.ContractRef{
			ContractID:              contract.ContractID,
			ContractVersion:         contract.ContractVersion,
			ManifestHashSHA256:      manifest.ManifestHashSHA256,
			PayloadSchemaHashSHA256: contract.PayloadSchemaHashSHA256,
		},
		Action:            contract.Action,
		PayloadEncoding:   exchange.PayloadEncodingJSON,
		PayloadHashSHA256: hashBytes(payload),
		Payload:           payload,
	})
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	return resp.Decision
}

func schemaHash(value string) string {
	return hashBytes([]byte(value))
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

type allowPolicy struct{}

func (allowPolicy) AuthorizeGatewayExchange(context.Context, exchange.PolicyCheck) error {
	return nil
}

type allowPayloads struct{}

func (allowPayloads) ValidateGatewayExchangePayload(context.Context, exchange.PayloadValidationInput) error {
	return nil
}

type fakeFacade struct{}

func (fakeFacade) GetServiceCatalogView(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (fakeFacade) OpenFederationTransaction(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "ok", PayloadJSON: `{"transaction_id":"tx-approval"}`}, nil
}

func (fakeFacade) CreateFederationRoom(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (fakeFacade) SubmitFederationMessage(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (fakeFacade) RequestBuilderWork(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (fakeFacade) SubmitFederationResult(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (fakeFacade) DeliverBuilderWorkResult(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (fakeFacade) SubmitCommercialEvent(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

type auditSink struct{}

func (auditSink) RecordExchangeAudit(context.Context, exchange.AuditEvent) error {
	return nil
}
