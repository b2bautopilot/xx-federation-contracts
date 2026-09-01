package ordertocash

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/contractmanifest"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/exchange"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/servicecatalog"
	"github.com/google/uuid"
)

const (
	testNowMS       int64 = 1_000
	testExpiresMS   int64 = 2_000
	testTenantA           = "tenant-a"
	testTenantB           = "tenant-b"
	testGatewayA          = "gateway-a"
	testGatewayB          = "gateway-b"
	testPartnerLink       = "plnk-a-b"
	testSigningKey        = "sigkey-order-to-cash"
	testManifestID        = "manifest-order-to-cash-v1"
)

func TestPackBuildsCatalogEntriesAndManifestContracts(t *testing.T) {
	entries := ServiceCatalogEntries(testTenantB, CatalogOptions{})
	if len(entries) != 7 {
		t.Fatalf("entries = %d, want seven order-to-cash interactions", len(entries))
	}
	for _, entry := range entries {
		if err := servicecatalog.ValidateEntry(entry); err != nil {
			t.Fatalf("ValidateEntry(%s) error = %v", entry.ServiceCatalogID, err)
		}
		if _, err := uuid.Parse(entry.ServiceCatalogID); err != nil {
			t.Fatalf("service catalog id for %s is not store-compatible UUID: %v", entry.DisplayName, err)
		}
		actions, err := servicecatalog.AllowedActions(entry.AllowedActionsJSON)
		if err != nil {
			t.Fatalf("AllowedActions(%s) error = %v", entry.ServiceCatalogID, err)
		}
		if len(actions) != 1 || actions[0] == exchange.ActionOpenFederationTransaction {
			t.Fatalf("allowed actions for %s = %#v, want one partner-facing business action", entry.ServiceCatalogID, actions)
		}
		if entry.SchemaVersion != SchemaVersion {
			t.Fatalf("schema version for %s = %q", entry.ServiceCatalogID, entry.SchemaVersion)
		}
	}

	contracts := Contracts(ManifestInput{PartnerLinkIDs: []string{testPartnerLink, testPartnerLink}})
	if len(contracts) != len(entries) {
		t.Fatalf("contracts = %d, want %d", len(contracts), len(entries))
	}
	contractIDs := map[string]struct{}{}
	interactionsByContractID := map[string]Interaction{}
	for _, interaction := range Interactions() {
		interactionsByContractID[interaction.ContractID] = interaction
	}
	for _, contract := range contracts {
		contractIDs[contract.ContractID] = struct{}{}
		if contract.Action != exchange.ActionOpenFederationTransaction {
			t.Fatalf("%s action = %q", contract.ContractID, contract.Action)
		}
		if interaction := interactionsByContractID[contract.ContractID]; contract.ServiceCatalogAction != interaction.BusinessAction {
			t.Fatalf("%s service catalog action = %q, want signed business action %q", contract.ContractID, contract.ServiceCatalogAction, interaction.BusinessAction)
		}
		if contract.ContractVersion != ContractVersion ||
			contract.MaxPayloadBytes != DefaultMaxPayload ||
			!contract.RequiresIdempotency ||
			contract.ReplayWindowSeconds != DefaultReplaySeconds ||
			contract.PrivateTopologyAllowed ||
			contract.AllowedGatewayMethodScopes[0] != "federation.open_federation_transaction" ||
			contract.AuditClass != "commercial_transaction" ||
			contract.RetentionClass != "order_to_cash" {
			t.Fatalf("contract %s has unsafe shape: %#v", contract.ContractID, contract)
		}
		if len(contract.AllowedPartnerLinkIDs) != 1 || contract.AllowedPartnerLinkIDs[0] != testPartnerLink {
			t.Fatalf("partner links for %s = %#v", contract.ContractID, contract.AllowedPartnerLinkIDs)
		}
		if got, want := contract.PayloadSchemaHashSHA256, PayloadSchemaHash(contract.ContractID); got != want || len(got) != 64 {
			t.Fatalf("schema hash for %s = %q, want %q", contract.ContractID, got, want)
		}
		if schema, ok := PayloadSchema(contract.ContractID); !ok || hashBytes([]byte(schema)) != contract.PayloadSchemaHashSHA256 {
			t.Fatalf("schema for %s is not bound to manifest hash", contract.ContractID)
		}
	}
	for _, contract := range contracts {
		for _, resultID := range contract.ResultContractIDs {
			if _, ok := contractIDs[resultID]; !ok {
				t.Fatalf("contract %s points at unknown result contract %s", contract.ContractID, resultID)
			}
		}
	}
}

func TestSignedPackManifestVerifiesCachesAndResolvesEveryContract(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	signed, err := contractmanifest.Sign(validPackManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	if err := contractmanifest.Verify(signed, contractmanifest.Keyring{testSigningKey: publicKey}, testNowMS); err != nil {
		t.Fatalf("Verify error = %v", err)
	}
	cache := contractmanifest.NewMemoryCache(contractmanifest.Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), signed); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}

	for _, interaction := range Interactions() {
		resolved, err := cache.ResolveManifest(context.Background(), exchange.ContractRef{
			ContractID:              interaction.ContractID,
			ContractVersion:         ContractVersion,
			ManifestHashSHA256:      signed.ManifestHashSHA256,
			PayloadSchemaHashSHA256: PayloadSchemaHash(interaction.ContractID),
		})
		if err != nil {
			t.Fatalf("ResolveManifest(%s) error = %v", interaction.ContractID, err)
		}
		action := resolved.Actions[exchange.ActionOpenFederationTransaction]
		if action.FacadeMethod != exchange.FacadeOpenFederationTransaction ||
			!action.Mutating ||
			!action.IdempotencyRequired ||
			action.PrivateTopologyAllowed ||
			len(action.AllowedPartnerLinkIDs) != 1 ||
			action.AllowedPartnerLinkIDs[0] != testPartnerLink {
			t.Fatalf("resolved action for %s = %#v", interaction.ContractID, action)
		}
	}
}

func TestPayloadValidatorRejectsSchemaMismatchAndInvalidShapes(t *testing.T) {
	for _, interaction := range Interactions() {
		t.Run("valid "+interaction.ContractID, func(t *testing.T) {
			action := exchange.ActionContract{
				Action:                 exchange.ActionOpenFederationTransaction,
				FacadeMethod:           exchange.FacadeOpenFederationTransaction,
				Mutating:               true,
				IdempotencyRequired:    true,
				PayloadEncoding:        exchange.PayloadEncodingJSON,
				MaxPayloadBytes:        DefaultMaxPayload,
				PrivateTopologyAllowed: false,
				AllowedPartnerLinkIDs:  []string{testPartnerLink},
			}
			input := exchange.PayloadValidationInput{
				Contract: exchange.ContractRef{
					ContractID:              interaction.ContractID,
					ContractVersion:         ContractVersion,
					PayloadSchemaHashSHA256: PayloadSchemaHash(interaction.ContractID),
				},
				Action:  action,
				Payload: samplePayload(t, interaction.ContractID),
			}
			if err := (PayloadValidator{}).ValidateGatewayExchangePayload(context.Background(), input); err != nil {
				t.Fatalf("valid %s payload error = %v", interaction.ContractID, err)
			}
		})
	}

	interaction := interactionByBusinessAction(t, "submit_purchase_order")
	action := exchange.ActionContract{
		Action:                 exchange.ActionOpenFederationTransaction,
		FacadeMethod:           exchange.FacadeOpenFederationTransaction,
		Mutating:               true,
		IdempotencyRequired:    true,
		PayloadEncoding:        exchange.PayloadEncodingJSON,
		MaxPayloadBytes:        DefaultMaxPayload,
		PrivateTopologyAllowed: false,
		AllowedPartnerLinkIDs:  []string{testPartnerLink},
	}
	validInput := exchange.PayloadValidationInput{
		Contract: exchange.ContractRef{
			ContractID:              interaction.ContractID,
			ContractVersion:         ContractVersion,
			PayloadSchemaHashSHA256: PayloadSchemaHash(interaction.ContractID),
		},
		Action:  action,
		Payload: samplePayload(t, interaction.ContractID),
	}
	if err := (PayloadValidator{}).ValidateGatewayExchangePayload(context.Background(), validInput); err != nil {
		t.Fatalf("valid payload error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(exchange.PayloadValidationInput) exchange.PayloadValidationInput
	}{
		{
			name: "schema hash mismatch",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Contract.PayloadSchemaHashSHA256 = strings.Repeat("0", 64)
				return input
			},
		},
		{
			name: "wrong contract version",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Contract.ContractVersion = "2.0.0"
				return input
			},
		},
		{
			name: "wrong facade action",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Action.Action = exchange.ActionRequestBuilderWork
				input.Action.FacadeMethod = exchange.FacadeRequestBuilderWork
				return input
			},
		},
		{
			name: "missing required field",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Payload = []byte(`{"document_id":"po-1"}`)
				return input
			},
		},
		{
			name: "wrong root type",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Payload = []byte(`{"transaction_kind":"order_to_cash.purchase_order","subject":"PO-1","document_id":"po-1","quote_document_id":"q-1","buyer_ref":"buyer-1","seller_ref":"seller-1","ordered_at":"2026-06-07T00:00:00Z","currency":"USD","total_amount":"123.45","line_items":[]}`)
				return input
			},
		},
		{
			name: "unsupported extra field",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Payload = []byte(`{"transaction_kind":"order_to_cash.purchase_order","subject":"PO-1","document_id":"po-1","quote_document_id":"q-1","buyer_ref":"buyer-1","seller_ref":"seller-1","ordered_at":"2026-06-07T00:00:00Z","currency":"USD","total_amount":123.45,"line_items":[],"extra":"not-allowed"}`)
				return input
			},
		},
		{
			name: "private topology value",
			mutate: func(input exchange.PayloadValidationInput) exchange.PayloadValidationInput {
				input.Payload = []byte(`{"transaction_kind":"order_to_cash.purchase_order","subject":"PO-1","document_id":"po-1","quote_document_id":"q-1","buyer_ref":"buyer-1","seller_ref":"seller-1","ordered_at":"2026-06-07T00:00:00Z","currency":"USD","total_amount":123.45,"line_items":[],"buyer_reference":"10.42.0.1"}`)
				return input
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.mutate(validInput)
			if err := (PayloadValidator{}).ValidateGatewayExchangePayload(context.Background(), input); err == nil {
				t.Fatal("ValidateGatewayExchangePayload returned nil error, want rejection")
			}
		})
	}
}

func TestGatewayExchangeDeniesUnsafeOrderToCashEnvelopes(t *testing.T) {
	interaction := interactionByBusinessAction(t, "submit_purchase_order")
	signed, publicKey := signedPackManifest(t)

	cases := []struct {
		name     string
		mutate   func(exchange.Envelope) exchange.Envelope
		wantCode string
	}{
		{
			name: "valid envelope allowed",
			mutate: func(env exchange.Envelope) exchange.Envelope {
				return env
			},
			wantCode: "",
		},
		{
			name: "unauthorized action",
			mutate: func(env exchange.Envelope) exchange.Envelope {
				env.Action = exchange.ActionRequestBuilderWork
				return env
			},
			wantCode: exchange.ErrorContractMismatch,
		},
		{
			name: "payload too large",
			mutate: func(env exchange.Envelope) exchange.Envelope {
				env.Payload = []byte(`{"document_id":"` + strings.Repeat("x", DefaultMaxPayload+1) + `"}`)
				env.PayloadHashSHA256 = hashBytes(env.Payload)
				return env
			},
			wantCode: exchange.ErrorPayloadInvalid,
		},
		{
			name: "missing idempotency",
			mutate: func(env exchange.Envelope) exchange.Envelope {
				env.IdempotencyKey = ""
				return env
			},
			wantCode: exchange.ErrorReplayDetected,
		},
		{
			name: "private topology leak",
			mutate: func(env exchange.Envelope) exchange.Envelope {
				env.Payload = []byte(`{"transaction_kind":"order_to_cash.purchase_order","subject":"PO-1","document_id":"po-1","quote_document_id":"q-1","buyer_ref":"buyer-1","seller_ref":"seller-1","ordered_at":"2026-06-07T00:00:00Z","currency":"USD","total_amount":123.45,"line_items":[],"buyer_reference":"fd00:b17e::1"}`)
				env.PayloadHashSHA256 = hashBytes(env.Payload)
				return env
			},
			wantCode: exchange.ErrorPayloadInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, facade := newOrderToCashHandler(t, publicKey, signed)
			env := tc.mutate(validEnvelopeForContract(signed, interaction.ContractID, samplePayload(t, interaction.ContractID)))
			resp, err := handler.Handle(context.Background(), validSession(), env)
			if err != nil {
				t.Fatalf("Handle error = %v", err)
			}
			if tc.wantCode == "" {
				if resp.Decision.Decision != exchange.DecisionAllow || !facade.openCalled {
					t.Fatalf("response = %#v openCalled=%v, want allow and open transaction", resp, facade.openCalled)
				}
				return
			}
			if resp.Decision.Decision != exchange.DecisionDeny || resp.Decision.DenialCode != tc.wantCode {
				t.Fatalf("decision = %#v, want deny %s", resp.Decision, tc.wantCode)
			}
			if facade.anyCalled() {
				t.Fatal("facade was called for unsafe envelope")
			}
		})
	}
}

func TestServiceCatalogDeprecatedAndRetiredBehavior(t *testing.T) {
	deprecated := "order_to_cash.quote.response.v1"
	retired := "order_to_cash.shipment_status.update.v1"
	replacement := "order_to_cash.payment_status.update.v1"
	entries := ServiceCatalogEntries(testTenantB, CatalogOptions{
		StateByContractID: map[string]string{
			deprecated: servicecatalog.StateDeprecated,
			retired:    servicecatalog.StateRetired,
		},
		ReplacementByContractID: map[string]string{
			deprecated: replacement,
		},
	})
	states := map[string]string{}
	for _, entry := range entries {
		if err := servicecatalog.ValidateEntry(entry); err != nil {
			t.Fatalf("ValidateEntry(%s) error = %v", entry.ServiceCatalogID, err)
		}
		states[entry.ServiceCatalogID] = servicecatalog.DefaultState(entry.State)
	}
	if !servicecatalog.VisibleState(states[ServiceCatalogID(deprecated)]) {
		t.Fatal("deprecated order-to-cash entry should remain visible")
	}
	if servicecatalog.VisibleState(states[ServiceCatalogID(retired)]) {
		t.Fatal("retired order-to-cash entry should be hidden from partner views")
	}
	for _, entry := range entries {
		if entry.ServiceCatalogID == ServiceCatalogID(deprecated) && entry.ReplacementCatalogEntryID != ServiceCatalogID(replacement) {
			t.Fatalf("deprecated replacement = %q, want %q", entry.ReplacementCatalogEntryID, ServiceCatalogID(replacement))
		}
	}
}

func TestManifestRejectsUnsupportedGatewayAction(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	manifest := validPackManifest()
	manifest.Contracts[0].Action = "delete_project"
	manifest.Contracts[0].AllowedGatewayMethodScopes = []string{"federation.delete_project"}
	if _, err := contractmanifest.Sign(manifest, privateKey); err == nil {
		t.Fatal("Sign returned nil error, want unsupported gateway action rejection")
	}
}

func validPackManifest() contractmanifest.Manifest {
	return Manifest(ManifestInput{
		TenantID:           testTenantB,
		ManifestID:         testManifestID,
		IssuedAtMS:         testNowMS,
		ExpiresAtMS:        testExpiresMS,
		SigningKeyID:       testSigningKey,
		PartnerLinkIDs:     []string{testPartnerLink},
		EgressPolicyPrefix: "egress.order_to_cash",
	})
}

func signedPackManifest(t *testing.T) (contractmanifest.Manifest, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error = %v", err)
	}
	signed, err := contractmanifest.Sign(validPackManifest(), privateKey)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	return signed, publicKey
}

func newOrderToCashHandler(t *testing.T, publicKey ed25519.PublicKey, signed contractmanifest.Manifest) (*exchange.Handler, *fakeFacade) {
	t.Helper()
	cache := contractmanifest.NewMemoryCache(contractmanifest.Keyring{testSigningKey: publicKey}, func() int64 { return testNowMS })
	if err := cache.PutVerified(context.Background(), signed); err != nil {
		t.Fatalf("PutVerified error = %v", err)
	}
	facade := &fakeFacade{}
	return &exchange.Handler{
		Manifests:   cache,
		Replay:      exchange.NewMemoryReplayCache(),
		Policy:      allowPolicy{},
		Payloads:    PayloadValidator{},
		Facade:      facade,
		Audit:       auditSink{},
		NowMS:       func() int64 { return testNowMS },
		ClockSkewMS: 0,
	}, facade
}

func validSession() exchange.AuthenticatedSession {
	return exchange.AuthenticatedSession{
		LocalTenantID:            testTenantB,
		LocalGatewayID:           testGatewayB,
		RemoteTenantID:           testTenantA,
		RemoteGatewayID:          testGatewayA,
		RemoteServicePrincipalID: "spn-gateway-a",
		PartnerLinkID:            testPartnerLink,
		PartnerLinkState:         exchange.PartnerLinkActive,
	}
}

func validEnvelopeForContract(manifest contractmanifest.Manifest, contractID string, payload []byte) exchange.Envelope {
	return exchange.Envelope{
		SchemaVersion:  exchange.SchemaGatewayExchangeV1,
		EnvelopeID:     "env-" + contractID,
		CorrelationID:  "corr-" + contractID,
		IdempotencyKey: "idem-" + contractID,
		SentAtMS:       testNowMS,
		ExpiresAtMS:    testExpiresMS,
		PartnerLinkID:  testPartnerLink,
		Source:         exchange.GatewayRef{TenantID: testTenantA, GatewayID: testGatewayA, GatewayPoolID: "pool-a"},
		Destination:    exchange.GatewayRef{TenantID: testTenantB, GatewayID: testGatewayB, GatewayPoolID: "pool-b"},
		Contract: exchange.ContractRef{
			ContractID:              contractID,
			ContractVersion:         ContractVersion,
			ManifestHashSHA256:      manifest.ManifestHashSHA256,
			PayloadSchemaHashSHA256: PayloadSchemaHash(contractID),
		},
		Action:            exchange.ActionOpenFederationTransaction,
		PayloadEncoding:   exchange.PayloadEncodingJSON,
		PayloadHashSHA256: hashBytes(payload),
		Payload:           payload,
	}
}

func interactionByBusinessAction(t *testing.T, businessAction string) Interaction {
	t.Helper()
	for _, interaction := range Interactions() {
		if interaction.BusinessAction == businessAction {
			return interaction
		}
	}
	t.Fatalf("missing interaction for business action %s", businessAction)
	return Interaction{}
}

func samplePayload(t *testing.T, contractID string) []byte {
	t.Helper()
	switch contractID {
	case "order_to_cash.request_for_quote.request.v1":
		return []byte(`{"transaction_kind":"order_to_cash.request_for_quote","subject":"RFQ-1","document_id":"rfq-1","buyer_ref":"buyer-1","seller_ref":"seller-1","requested_at":"2026-06-07T00:00:00Z","currency":"USD","line_items":[]}`)
	case "order_to_cash.quote.response.v1":
		return []byte(`{"transaction_kind":"order_to_cash.quote","subject":"QUOTE-1","document_id":"quote-1","rfq_document_id":"rfq-1","seller_ref":"seller-1","buyer_ref":"buyer-1","quoted_at":"2026-06-07T01:00:00Z","currency":"USD","total_amount":123.45,"line_items":[]}`)
	case "order_to_cash.purchase_order.request.v1":
		return []byte(`{"transaction_kind":"order_to_cash.purchase_order","subject":"PO-1","document_id":"po-1","quote_document_id":"quote-1","buyer_ref":"buyer-1","seller_ref":"seller-1","ordered_at":"2026-06-07T02:00:00Z","currency":"USD","total_amount":123.45,"line_items":[]}`)
	case "order_to_cash.order_confirmation.response.v1":
		return []byte(`{"transaction_kind":"order_to_cash.order_confirmation","subject":"CONFIRM-1","document_id":"confirm-1","purchase_order_document_id":"po-1","seller_ref":"seller-1","buyer_ref":"buyer-1","confirmed_at":"2026-06-07T03:00:00Z","status":"accepted"}`)
	case "order_to_cash.shipment_status.update.v1":
		return []byte(`{"transaction_kind":"order_to_cash.shipment_status","subject":"SHIP-1","document_id":"ship-1","purchase_order_document_id":"po-1","seller_ref":"seller-1","buyer_ref":"buyer-1","status":"in_transit","updated_at":"2026-06-07T04:00:00Z"}`)
	case "order_to_cash.invoice.issue.v1":
		return []byte(`{"transaction_kind":"order_to_cash.invoice","subject":"INV-1","document_id":"invoice-1","purchase_order_document_id":"po-1","seller_ref":"seller-1","buyer_ref":"buyer-1","issued_at":"2026-06-07T05:00:00Z","currency":"USD","invoice_amount":123.45,"due_at":"2026-07-07T00:00:00Z"}`)
	case "order_to_cash.payment_status.update.v1":
		return []byte(`{"transaction_kind":"order_to_cash.payment_status","subject":"PAYMENT-1","document_id":"payment-1","invoice_document_id":"invoice-1","buyer_ref":"buyer-1","seller_ref":"seller-1","status":"scheduled","updated_at":"2026-06-07T06:00:00Z"}`)
	default:
		t.Fatalf("no sample payload for contract %s", contractID)
		return nil
	}
}

func hashBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type fakeFacade struct {
	openCalled bool
}

func (f *fakeFacade) GetServiceCatalogView(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) OpenFederationTransaction(_ context.Context, _ exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	f.openCalled = true
	return exchange.DispatchResult{Status: "ok", PayloadJSON: `{"transaction_id":"tx-order-to-cash"}`}, nil
}

func (f *fakeFacade) CreateFederationRoom(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) SubmitFederationMessage(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) RequestBuilderWork(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) SubmitFederationResult(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) DeliverBuilderWorkResult(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) SubmitCommercialEvent(context.Context, exchange.AcceptedEnvelope) (exchange.DispatchResult, error) {
	return exchange.DispatchResult{Status: "unexpected"}, nil
}

func (f *fakeFacade) anyCalled() bool {
	return f.openCalled
}

type allowPolicy struct{}

func (allowPolicy) AuthorizeGatewayExchange(context.Context, exchange.PolicyCheck) error {
	return nil
}

type auditSink struct{}

func (auditSink) RecordExchangeAudit(context.Context, exchange.AuditEvent) error {
	return nil
}
