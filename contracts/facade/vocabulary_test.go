package facade

import "testing"

// TestBindingFieldMatchers pins the single source of truth for cert->binding field
// matching (FED-P16-001b FIX G), carried verbatim from memory_federation.go.
func TestRequiredBindingFieldMatches(t *testing.T) {
	if !RequiredBindingFieldMatches("org-a", "org-a") {
		t.Error("equal non-empty fields must match")
	}
	if !RequiredBindingFieldMatches(" org-a ", "org-a") {
		t.Error("trimmed equal fields must match")
	}
	if RequiredBindingFieldMatches("", "org-a") {
		t.Error("empty expected must not match")
	}
	if RequiredBindingFieldMatches("org-a", "") {
		t.Error("empty actual must not match")
	}
	if RequiredBindingFieldMatches("org-a", "org-b") {
		t.Error("unequal fields must not match")
	}
}

func TestOptionalBindingFieldMatches(t *testing.T) {
	// empty bound field is a wildcard
	if !OptionalBindingFieldMatches("", "anything") {
		t.Error("empty expected must be a wildcard")
	}
	if !OptionalBindingFieldMatches("spiffe://x", "spiffe://x") {
		t.Error("equal non-empty must match")
	}
	if OptionalBindingFieldMatches("spiffe://x", "") {
		t.Error("non-empty expected with empty actual must not match")
	}
	if OptionalBindingFieldMatches("spiffe://x", "spiffe://y") {
		t.Error("unequal fields must not match")
	}
}

// TestStateAndFailureStringValues pins the facade-carried vocabularies exactly.
func TestStateAndFailureStringValues(t *testing.T) {
	states := map[string]string{
		"pending": OutboundExchangeStatePending, "in_flight": OutboundExchangeStateInFlight,
		"responded": OutboundExchangeStateResponded, "needs_reconcile": OutboundExchangeStateNeedsReconcile,
		"failed": OutboundExchangeStateFailed,
	}
	for want, got := range states {
		if got != want {
			t.Errorf("state value %q != %q", got, want)
		}
	}
	failures := map[string]string{
		"identity_pin": OutboundExchangeFailureIdentityPin, "config": OutboundExchangeFailureConfig,
		"config_no_target": OutboundExchangeFailureConfigNoTarget, "exchange_contract_mismatch": OutboundExchangeFailureExchangeContract,
		"exchange_denied": OutboundExchangeFailureExchangeDenied, "transport": OutboundExchangeFailureTransport,
		"lost_ack_indeterminate": OutboundExchangeFailureLostAckReconcile,
	}
	for want, got := range failures {
		if got != want {
			t.Errorf("failure value %q != %q", got, want)
		}
	}
	headers := map[string]string{
		"x-builders-dev-gateway-tenant-id":            DevGatewayTenantIDHeader,
		"x-builders-dev-gateway-id":                   DevGatewayIDHeader,
		"x-builders-dev-gateway-service-principal-id": DevGatewayServicePrincipalHeader,
		"x-builders-dev-gateway-credential-kind":      DevGatewayCredentialKindHeader,
		"x-builders-dev-gateway-subject":              DevGatewaySubjectHeader,
		"x-builders-dev-gateway-fingerprint-sha256":   DevGatewayFingerprintSHA256Header,
		"x-builders-dev-gateway-spiffe-id":            DevGatewaySPIFFEIDHeader,
	}
	for want, got := range headers {
		if got != want {
			t.Errorf("dev header %q != %q", got, want)
		}
	}
}
