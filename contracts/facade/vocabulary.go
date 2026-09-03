// Package facade hosts the shared vocabulary and binding matchers that both the
// gateway and the control-plane facade must agree on for the federation wire
// protocol. These strings and matchers are the SINGLE source of truth carried
// verbatim over the facade boundary; they are assembled here (with unchanged
// bodies) from the canonical control-plane sources so the gateway and the relay
// can consume them without importing the control module.
//
// Sources (all bodies unchanged, package clause normalised):
//   - OutboundExchangeState*/OutboundExchangeFailure*: services/builders-net/store/store.go
//   - RequiredBindingFieldMatches/OptionalBindingFieldMatches: services/builders-net/store/memory_federation.go
//   - DevGateway*Header: services/builders-net/federationauth/auth.go
package facade

import "strings"

// Outbound exchange request lifecycle states (FED-P16-008). The control store
// records an operator-initiated outbound federation exchange; the store-less
// gateway worker claims pending/expired rows, sends them over the merged direct
// dialer, and records the outcome back.
const (
	OutboundExchangeStatePending        = "pending"
	OutboundExchangeStateInFlight       = "in_flight"
	OutboundExchangeStateResponded      = "responded"
	OutboundExchangeStateNeedsReconcile = "needs_reconcile"
	OutboundExchangeStateFailed         = "failed"
)

// Outbound exchange failure classifications recorded on terminal/transient
// outcomes. The classifier keys on EXPORTED gateway error sentinels, never on
// transport state.
const (
	OutboundExchangeFailureIdentityPin      = "identity_pin"
	OutboundExchangeFailureConfig           = "config"
	OutboundExchangeFailureConfigNoTarget   = "config_no_target"
	OutboundExchangeFailureExchangeContract = "exchange_contract_mismatch"
	OutboundExchangeFailureExchangeDenied   = "exchange_denied"
	OutboundExchangeFailureTransport        = "transport"
	OutboundExchangeFailureLostAckReconcile = "lost_ack_indeterminate"
)

// RequiredBindingFieldMatches reports whether a REQUIRED partner-binding field
// matches the cert evidence: both must be non-empty AND equal (after trimming).
// It is exported as the SINGLE source of truth for cert->binding field matching:
// the store-less gateway resolver (internal/federation/gateway) calls it directly
// so the two paths cannot drift (FED-P16-001b FIX G).
func RequiredBindingFieldMatches(expected, actual string) bool {
	return strings.TrimSpace(expected) != "" && strings.TrimSpace(actual) != "" && strings.TrimSpace(expected) == strings.TrimSpace(actual)
}

// OptionalBindingFieldMatches reports whether an OPTIONAL partner-binding field
// matches: an empty bound field is a wildcard; otherwise it must equal a
// non-empty cert field (after trimming). Exported alongside
// RequiredBindingFieldMatches as the single source of truth (FED-P16-001b FIX G).
func OptionalBindingFieldMatches(expected, actual string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	return actual != "" && expected == strings.TrimSpace(actual)
}

// Dev gateway authentication headers. These seven x-builders-dev-gateway-* metadata
// keys are set by the gateway runner and read by the control plane's dev-auth
// interceptor; they are part of the facade contract in dev auth mode.
const (
	DevGatewayTenantIDHeader          = "x-builders-dev-gateway-tenant-id"
	DevGatewayIDHeader                = "x-builders-dev-gateway-id"
	DevGatewayServicePrincipalHeader  = "x-builders-dev-gateway-service-principal-id"
	DevGatewayCredentialKindHeader    = "x-builders-dev-gateway-credential-kind"
	DevGatewaySubjectHeader           = "x-builders-dev-gateway-subject"
	DevGatewayFingerprintSHA256Header = "x-builders-dev-gateway-fingerprint-sha256"
	DevGatewaySPIFFEIDHeader          = "x-builders-dev-gateway-spiffe-id"
)
