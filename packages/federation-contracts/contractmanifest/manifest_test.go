package contractmanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/exchange"
)

const (
	testNowMS       int64 = 1000
	testExpiresMS   int64 = 2000
	testTenant            = "tenant-b"
	testManifestID        = "manifest-b-1"
	testSigningKey        = "sigkey-b"
	testContractID        = "order_to_cash.purchase_order.request.v1"
	testContractVer       = "1.0.0"
)

func TestSignedManifestVerifiesCachesAndAdaptsToExchange(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest, err := Sign(validManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	if err := Verify(manifest, Keyring{testSigningKey: publicKey}, testNowMS); err != nil {
		t.Fatalf("Verify error = %v", err)
	}

	cache := NewMemoryCache(Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), manifest); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}
	resolved, err := cache.ResolveManifest(context.Background(), exchange.ContractRef{
		ContractID:              testContractID,
		ContractVersion:         testContractVer,
		ManifestHashSHA256:      manifest.ManifestHashSHA256,
		PayloadSchemaHashSHA256: payloadSchemaHash(),
	})
	if err != nil {
		t.Fatalf("ResolveManifest error = %v", err)
	}
	action := resolved.Actions[exchange.ActionOpenFederationTransaction]
	if resolved.ManifestHashSHA256 != manifest.ManifestHashSHA256 ||
		action.FacadeMethod != exchange.FacadeOpenFederationTransaction ||
		action.MaxPayloadBytes != 32768 ||
		!action.IdempotencyRequired ||
		action.PrivateTopologyAllowed {
		t.Fatalf("resolved manifest/action = %#v %#v", resolved, action)
	}
}

func TestUnsignedManifestRejected(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest := validManifest()
	manifest.ManifestHashSHA256 = ComputeManifestHash(manifest)

	if err := Verify(manifest, Keyring{testSigningKey: publicKey}, testNowMS); err == nil {
		t.Fatal("Verify returned nil, want unsigned manifest rejection")
	}
}

func TestExpiredManifestRejected(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest, err := Sign(validManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}

	if err := Verify(manifest, Keyring{testSigningKey: publicKey}, testExpiresMS+1); err == nil {
		t.Fatal("Verify returned nil, want expired manifest rejection")
	}
}

func TestManifestHashDriftRejected(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest, err := Sign(validManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	manifest.Contracts[0].MaxPayloadBytes = 1

	if err := Verify(manifest, Keyring{testSigningKey: publicKey}, testNowMS); err == nil {
		t.Fatal("Verify returned nil, want hash drift rejection")
	}
}

func TestStaleSchemaHashRejectedByCache(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest, err := Sign(validManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	cache := NewMemoryCache(Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), manifest); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}

	_, err = cache.ResolveManifest(context.Background(), exchange.ContractRef{
		ContractID:              testContractID,
		ContractVersion:         testContractVer,
		ManifestHashSHA256:      manifest.ManifestHashSHA256,
		PayloadSchemaHashSHA256: "old-schema",
	})
	if err == nil {
		t.Fatal("ResolveManifest returned nil error, want schema drift rejection")
	}
}

func TestManifestMethodScopeRequired(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest := validManifest()
	manifest.Contracts[0].AllowedGatewayMethodScopes = []string{"federation.delete_project"}

	if _, err := Sign(manifest, privateKey); err == nil {
		t.Fatal("Sign returned nil error, want missing method scope rejection")
	}
}

func TestManifestRejectsExtraMethodScope(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest := validManifest()
	manifest.Contracts[0].AllowedGatewayMethodScopes = []string{
		"federation.open_federation_transaction",
		"federation.delete_project",
	}

	if _, err := Sign(manifest, privateKey); err == nil {
		t.Fatal("Sign returned nil error, want extra method scope rejection")
	}
}

func TestSupportedActionsMapToNarrowGatewayFacadeScopes(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	cases := []struct {
		action       string
		methodScope  string
		facadeMethod string
		mutating     bool
	}{
		{exchange.ActionGetServiceCatalogView, "federation.get_service_catalog_view", exchange.FacadeGetServiceCatalogView, false},
		{exchange.ActionOpenFederationTransaction, "federation.open_federation_transaction", exchange.FacadeOpenFederationTransaction, true},
		{exchange.ActionCreateFederationRoom, "federation.create_federation_room", exchange.FacadeCreateFederationRoom, true},
		{exchange.ActionSubmitFederationMessage, "federation.submit_federation_message", exchange.FacadeSubmitFederationMessage, true},
		{exchange.ActionRequestBuilderWork, "federation.request_builder_work", exchange.FacadeRequestBuilderWork, true},
		{exchange.ActionSubmitFederationResult, "federation.submit_federation_result", exchange.FacadeSubmitFederationResult, true},
	}

	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			manifest := validManifest()
			manifest.Contracts[0].Action = tc.action
			manifest.Contracts[0].AllowedGatewayMethodScopes = []string{tc.methodScope}
			manifest.Contracts[0].RequiresIdempotency = tc.mutating
			signed, err := Sign(manifest, privateKey)
			if err != nil {
				t.Fatalf("Sign error = %v", err)
			}
			cache := NewMemoryCache(Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
			if err := cache.PutVerified(context.Background(), signed); err != nil {
				t.Fatalf("PutVerified error = %v", err)
			}
			resolved, err := cache.ResolveManifest(context.Background(), exchange.ContractRef{
				ContractID:              testContractID,
				ContractVersion:         testContractVer,
				ManifestHashSHA256:      signed.ManifestHashSHA256,
				PayloadSchemaHashSHA256: payloadSchemaHash(),
			})
			if err != nil {
				t.Fatalf("ResolveManifest error = %v", err)
			}
			action := resolved.Actions[tc.action]
			if action.FacadeMethod != tc.facadeMethod || action.Mutating != tc.mutating {
				t.Fatalf("action = %#v, want method=%s mutating=%v", action, tc.facadeMethod, tc.mutating)
			}
		})
	}
}

func TestUnknownActionRejected(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest := validManifest()
	manifest.Contracts[0].Action = "delete_project"
	manifest.Contracts[0].AllowedGatewayMethodScopes = []string{"federation.delete_project"}

	if _, err := Sign(manifest, privateKey); err == nil {
		t.Fatal("Sign returned nil error, want unknown action rejection")
	}
}

func TestManifestPartnerLinkMismatchRejectedBeforePolicy(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest, err := Sign(validManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	cache := NewMemoryCache(Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), manifest); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}
	handler := &exchange.Handler{
		Manifests:   cache,
		Replay:      exchange.NewMemoryReplayCache(),
		Policy:      allowPolicy{},
		Payloads:    allowPayloadValidator{},
		Audit:       auditSink{},
		NowMS:       func() int64 { return testNowMS },
		ClockSkewMS: 0,
	}

	resp, err := handler.Handle(context.Background(), exchange.AuthenticatedSession{
		LocalTenantID:     testTenant,
		LocalGatewayID:    "gw-b",
		RemoteTenantID:    "tenant-a",
		RemoteGatewayID:   "gw-a",
		PartnerLinkID:     "plnk-other",
		PartnerLinkState:  exchange.PartnerLinkActive,
		KillSwitchEnabled: false,
	}, validEnvelopeForManifest(manifest, "plnk-other"))
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision != exchange.DecisionDeny || resp.Decision.DenialCode != exchange.ErrorContractMismatch {
		t.Fatalf("decision = %#v, want contract mismatch", resp.Decision)
	}
}

func TestValidManifestStillRequiresExchangePolicy(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest, err := Sign(validManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	cache := NewMemoryCache(Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), manifest); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}
	handler := &exchange.Handler{
		Manifests:   cache,
		Replay:      exchange.NewMemoryReplayCache(),
		Payloads:    allowPayloadValidator{},
		Audit:       auditSink{},
		NowMS:       func() int64 { return testNowMS },
		ClockSkewMS: 0,
	}

	resp, err := handler.Handle(context.Background(), exchange.AuthenticatedSession{
		LocalTenantID:     testTenant,
		LocalGatewayID:    "gw-b",
		RemoteTenantID:    "tenant-a",
		RemoteGatewayID:   "gw-a",
		PartnerLinkID:     "plnk-a-b",
		PartnerLinkState:  exchange.PartnerLinkActive,
		KillSwitchEnabled: false,
	}, validEnvelopeForManifest(manifest, "plnk-a-b"))
	if err != nil {
		t.Fatalf("Handle error = %v", err)
	}
	if resp.Decision.Decision != exchange.DecisionDeny || resp.Decision.DenialCode != exchange.ErrorPolicyDenied {
		t.Fatalf("decision = %#v, want policy denied", resp.Decision)
	}
}

func validEnvelopeForManifest(manifest Manifest, partnerLinkID string) exchange.Envelope {
	return exchange.Envelope{
		SchemaVersion:  exchange.SchemaGatewayExchangeV1,
		EnvelopeID:     "env-1",
		CorrelationID:  "corr-1",
		IdempotencyKey: "idem-1",
		SentAtMS:       testNowMS,
		ExpiresAtMS:    testExpiresMS,
		PartnerLinkID:  partnerLinkID,
		Source:         exchange.GatewayRef{TenantID: "tenant-a", GatewayID: "gw-a"},
		Destination:    exchange.GatewayRef{TenantID: testTenant, GatewayID: "gw-b"},
		Contract: exchange.ContractRef{
			ContractID:              testContractID,
			ContractVersion:         testContractVer,
			ManifestHashSHA256:      manifest.ManifestHashSHA256,
			PayloadSchemaHashSHA256: payloadSchemaHash(),
		},
		Action:            exchange.ActionOpenFederationTransaction,
		PayloadEncoding:   exchange.PayloadEncodingJSON,
		PayloadHashSHA256: hashPayload([]byte(`{"kind":"purchase_order"}`)),
		Payload:           []byte(`{"kind":"purchase_order"}`),
	}
}

func validManifest() Manifest {
	return Manifest{
		SchemaVersion:  SchemaVersion,
		TenantID:       testTenant,
		ManifestID:     testManifestID,
		IssuedAtMS:     testNowMS,
		ExpiresAtMS:    testExpiresMS,
		CatalogVersion: "2026-06-06.1",
		SigningKeyID:   testSigningKey,
		Contracts: []Contract{
			{
				ContractID:                 testContractID,
				ContractVersion:            testContractVer,
				DisplayName:                "Purchase order request",
				Action:                     exchange.ActionOpenFederationTransaction,
				PayloadSchemaRef:           "schemas/order_to_cash/purchase_order_request.v1.json",
				PayloadSchemaHashSHA256:    payloadSchemaHash(),
				MaxPayloadBytes:            32768,
				RequiresIdempotency:        true,
				ReplayWindowSeconds:        86400,
				AllowedPartnerLinkIDs:      []string{"plnk-a-b"},
				AllowedGatewayMethodScopes: []string{"federation.open_federation_transaction"},
				PrivateTopologyAllowed:     false,
				EgressPolicyRef:            "egress.order_to_cash.po_request",
				AuditClass:                 "commercial_transaction",
				RetentionClass:             "order_to_cash",
			},
		},
	}
}

func payloadSchemaHash() string {
	return hashPayload([]byte(`{"type":"object","required":["kind"]}`))
}

func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type allowPayloadValidator struct{}

func (allowPayloadValidator) ValidateGatewayExchangePayload(context.Context, exchange.PayloadValidationInput) error {
	return nil
}

type auditSink struct{}

func (auditSink) RecordExchangeAudit(context.Context, exchange.AuditEvent) error {
	return nil
}

type allowPolicy struct{}

func (allowPolicy) AuthorizeGatewayExchange(context.Context, exchange.PolicyCheck) error {
	return nil
}

// TestO2CActionsValidateInManifests pins the NE-4.4 live finding: every
// O2C typed action must be carriable by a valid signed manifest (the
// method-scope map gap made that impossible until fixed).
func TestO2CActionsValidateInManifests(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	actions := []string{
		exchange.ActionRequestForQuote,
		exchange.ActionSubmitQuote,
		exchange.ActionSubmitPurchaseOrder,
		exchange.ActionConfirmOrder,
		exchange.ActionUpdateShipmentStatus,
		exchange.ActionIssueInvoice,
		exchange.ActionUpdatePaymentStatus,
	}
	contracts := make([]Contract, 0, len(actions))
	for _, action := range actions {
		contracts = append(contracts, Contract{
			ContractID:                 "order_to_cash." + action + ".v1",
			ContractVersion:            "1.0.0",
			DisplayName:                action,
			Action:                     action,
			PayloadSchemaRef:           "schemas/order_to_cash/" + action + ".json",
			PayloadSchemaHashSHA256:    payloadSchemaHash(),
			MaxPayloadBytes:            32768,
			RequiresIdempotency:        true,
			ReplayWindowSeconds:        86400,
			AllowedPartnerLinkIDs:      []string{"plnk-a-b"},
			AllowedGatewayMethodScopes: []string{"federation." + action},
			EgressPolicyRef:            "egress.order_to_cash." + action,
			AuditClass:                 "commercial_transaction",
			RetentionClass:             "order_to_cash",
		})
	}
	manifest, err := Sign(Manifest{
		SchemaVersion:  SchemaVersion,
		TenantID:       testTenant,
		ManifestID:     testManifestID,
		IssuedAtMS:     testNowMS,
		ExpiresAtMS:    testExpiresMS,
		CatalogVersion: "2026-06-11.o2c",
		SigningKeyID:   testSigningKey,
		Contracts:      contracts,
	}, priv)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	keyring := Keyring{testSigningKey: pub}
	if err := Verify(manifest, keyring, testNowMS); err != nil {
		t.Fatalf("Verify rejected a manifest carrying the O2C actions: %v", err)
	}
}
