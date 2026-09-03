package gatewayregistration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	CommandEnvelopeSchemaVersion        = "relay-mesh-registration.v0"
	LocalControlAuthorizationVersion    = "local-control-authorization.v0"
	GatewayBootstrapIntentVersion       = "gateway-bootstrap-intent.v0"
	PublicKeyBindingAlgorithmSHA256SPKI = "sha256-spki"
	SignatureAlgorithmEd25519JCSV1      = "ed25519-jcs-v1"
	DefaultMaxBootstrapTTLSeconds       = 900
	DefaultPollAfterSeconds             = 30
)

type ErrorCode string

const (
	CodeSchemaInvalid                     ErrorCode = "schema_invalid"
	CodeActorUnauthenticated              ErrorCode = "actor_unauthenticated"
	CodeActorUnauthorized                 ErrorCode = "actor_unauthorized"
	CodeOrgStatusInvalid                  ErrorCode = "org_status_invalid"
	CodeLocalControlAuthorizationRequired ErrorCode = "local_control_authorization_required"
	CodeLocalControlAuthorizationInvalid  ErrorCode = "local_control_authorization_invalid"
	CodeLocalControlAuthorizationMismatch ErrorCode = "local_control_authorization_mismatch"
	CodeBootstrapExpired                  ErrorCode = "bootstrap_expired"
	CodeBootstrapConsumed                 ErrorCode = "bootstrap_consumed"
	CodeBootstrapRevoked                  ErrorCode = "bootstrap_revoked"
	CodeBootstrapSignatureInvalid         ErrorCode = "bootstrap_signature_invalid"
	CodeBootstrapIntentMismatch           ErrorCode = "bootstrap_intent_mismatch"
	CodeCSRParseFailed                    ErrorCode = "csr_parse_failed"
	CodeCSRSignatureInvalid               ErrorCode = "csr_signature_invalid"
	CodeCSRIdentityAssertionMismatch      ErrorCode = "csr_identity_assertion_mismatch"
	CodeCSRPublicKeyConflict              ErrorCode = "csr_public_key_conflict"
	CodeIssuerUnavailable                 ErrorCode = "issuer_unavailable"
	CodeInternal                          ErrorCode = "internal_error"
	CodeIdempotencyConflict               ErrorCode = "idempotency_conflict"
	CodeConcurrencyFenceLost              ErrorCode = "concurrency_fence_lost"
	CodeLegacyIdentityRejected            ErrorCode = "legacy_identity_rejected"
	CodeIdentityProvenanceRejected        ErrorCode = "identity_provenance_rejected"
	CodePlaneIdentityMismatch             ErrorCode = "plane_identity_mismatch"
	CodePilotCompatInProductionRejected   ErrorCode = "pilot_compat_in_production_rejected"
	// CodePinFailure — the registration authority's TLS certificate did not verify against the operator's
	// PINNED CA (a possible impostor/MITM of the transport). Exit 5 is the install-family's pin-failure code
	// (matching b2bfabric join). Only reachable when a client opts into a pinned TLS dial (--tls-ca-file).
	CodePinFailure ErrorCode = "pin_failure"
)

type Disposition string

const (
	DispositionTerminalOK       Disposition = "terminal_ok"
	DispositionTerminalError    Disposition = "terminal_error"
	DispositionRetryNow         Disposition = "retry_now"
	DispositionAwaitingExternal Disposition = "awaiting_external"
	DispositionAwaitingHuman    Disposition = "awaiting_human"
)

type ErrorSpec struct {
	Code             ErrorCode
	ExitCode         int
	Disposition      Disposition
	Retryable        bool
	PollAfterSeconds int
	Message          string
}

var errorCatalog = map[ErrorCode]ErrorSpec{
	CodeSchemaInvalid:                     {CodeSchemaInvalid, 10, DispositionTerminalError, false, 0, "JSON schema, unknown field, enum, or type validation failed."},
	CodeActorUnauthenticated:              {CodeActorUnauthenticated, 20, DispositionTerminalError, false, 0, "Authenticated caller context is absent or invalid."},
	CodeActorUnauthorized:                 {CodeActorUnauthorized, 21, DispositionTerminalError, false, 0, "Caller lacks the required registration scope."},
	CodeOrgStatusInvalid:                  {CodeOrgStatusInvalid, 30, DispositionTerminalError, false, 0, "Org status does not permit the requested operation."},
	CodeLocalControlAuthorizationRequired: {CodeLocalControlAuthorizationRequired, 31, DispositionAwaitingExternal, true, DefaultPollAfterSeconds, "Gateway has not proved local control authorization."},
	CodeLocalControlAuthorizationInvalid:  {CodeLocalControlAuthorizationInvalid, 32, DispositionTerminalError, false, 0, "Local control assertion is unsigned, expired, unverifiable, or issued by the wrong authority."},
	CodeLocalControlAuthorizationMismatch: {CodeLocalControlAuthorizationMismatch, 33, DispositionTerminalError, false, 0, "Local control authorization does not match bootstrap scope."},
	CodeBootstrapExpired:                  {CodeBootstrapExpired, 34, DispositionTerminalError, false, 0, "Bootstrap expired before redemption."},
	CodeBootstrapConsumed:                 {CodeBootstrapConsumed, 35, DispositionTerminalError, false, 0, "Bootstrap was already redeemed or terminally rejected."},
	CodeBootstrapRevoked:                  {CodeBootstrapRevoked, 36, DispositionTerminalError, false, 0, "Bootstrap was revoked before redemption."},
	CodeBootstrapSignatureInvalid:         {CodeBootstrapSignatureInvalid, 37, DispositionTerminalError, false, 0, "Signed bootstrap cannot be verified."},
	CodeBootstrapIntentMismatch:           {CodeBootstrapIntentMismatch, 38, DispositionTerminalError, false, 0, "Bootstrap scope, local-control assertion, CSR, or SPKI binding do not match."},
	CodeCSRParseFailed:                    {CodeCSRParseFailed, 39, DispositionTerminalError, false, 0, "CSR is malformed or unsupported."},
	CodeCSRSignatureInvalid:               {CodeCSRSignatureInvalid, 40, DispositionTerminalError, false, 0, "CSR proof-of-possession failed."},
	CodeCSRIdentityAssertionMismatch:      {CodeCSRIdentityAssertionMismatch, 41, DispositionTerminalError, false, 0, "Advisory identity conflicts with derived identity."},
	CodeCSRPublicKeyConflict:              {CodeCSRPublicKeyConflict, 42, DispositionTerminalError, false, 0, "CSR public key is already bound to another active gateway."},
	CodeIssuerUnavailable:                 {CodeIssuerUnavailable, 43, DispositionRetryNow, true, DefaultPollAfterSeconds, "CA/issuer dependency is temporarily unavailable."},
	CodeInternal:                          {CodeInternal, 60, DispositionRetryNow, true, DefaultPollAfterSeconds, "An unexpected internal control-plane error occurred (not a client-request fault); retry, and if it persists inspect the control-plane logs."},
	CodeIdempotencyConflict:               {CodeIdempotencyConflict, 50, DispositionTerminalError, false, 0, "Same idempotency key was replayed with a different payload."},
	CodeConcurrencyFenceLost:              {CodeConcurrencyFenceLost, 51, DispositionRetryNow, true, DefaultPollAfterSeconds, "Another writer changed the bootstrap or binding state first."},
	CodeLegacyIdentityRejected:            {CodeLegacyIdentityRejected, 52, DispositionTerminalError, false, 0, "Legacy RPC attempted caller-supplied identity in enforced mode."},
	CodeIdentityProvenanceRejected:        {CodeIdentityProvenanceRejected, 53, DispositionTerminalError, false, 0, "Runtime authorization rejected non-CSR-derived identity provenance."},
	CodePlaneIdentityMismatch:             {CodePlaneIdentityMismatch, 54, DispositionTerminalError, false, 0, "Certificate trust root or SPIFFE namespace does not match the verifier plane."},
	CodePilotCompatInProductionRejected:   {CodePilotCompatInProductionRejected, 55, DispositionTerminalError, false, 0, "Production fabric attempted to start or serve with pilot_compat enabled."},
	CodePinFailure:                        {CodePinFailure, 5, DispositionTerminalError, false, 0, "The registration authority's TLS certificate did not verify against the pinned CA — possible impostor/MITM of the transport. Do NOT retry. (Transport-only: the app-layer identity is authenticated separately.)"},
}

var exactSchemaJSONFields = map[string]struct{}{
	"action":                      {},
	"actor":                       {},
	"advisory":                    {},
	"alg":                         {},
	"allowed_relay_fabric":        {},
	"allowed_relay_regions":       {},
	"auth_context":                {},
	"authorization_id":            {},
	"bootstrap":                   {},
	"bootstrap_id":                {},
	"binding_id":                  {},
	"code":                        {},
	"command":                     {},
	"correlation_id":              {},
	"csr_pem":                     {},
	"csr_public_key_binding":      {},
	"credential_id":               {},
	"display_name":                {},
	"disposition":                 {},
	"exit_code":                   {},
	"expires_at_ms":               {},
	"fabric_id":                   {},
	"facade_scope":                {},
	"gateway_id":                  {},
	"gateway_pool_id":             {},
	"idempotency_key":             {},
	"issued_at_ms":                {},
	"issuer_control_id":           {},
	"issuer_key_id":               {},
	"jti":                         {},
	"local_control_authorization": {},
	"local_control_authorization_digest_sha256": {},
	"local_control_authorization_ref":           {},
	"message":                                   {},
	"next_actions":                              {},
	"not_before_ms":                             {},
	"ok":                                        {},
	"operator_supplied_fingerprint_sha256":      {},
	"operator_supplied_spiffe_id":               {},
	"operator_supplied_subject":                 {},
	"org_id":                                    {},
	"payload":                                   {},
	"poll_after_seconds":                        {},
	"poll_handle":                               {},
	"previous_binding_id":                       {},
	"previous_credential_id":                    {},
	"principal_id":                              {},
	"reason":                                    {},
	"retryable":                                 {},
	"schema_version":                            {},
	"scopes":                                    {},
	"signature":                                 {},
	"signature_alg":                             {},
	"tenant_id":                                 {},
	"ttl_seconds":                               {},
	"type":                                      {},
	"value":                                     {},
}

type ValidationError struct {
	Code    ErrorCode
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Field == "" {
		return string(e.Code) + ": " + e.Message
	}
	return string(e.Code) + ": " + e.Field + ": " + e.Message
}

func IsCode(err error, code ErrorCode) bool {
	var validation *ValidationError
	return errors.As(err, &validation) && validation.Code == code
}

func validationErr(code ErrorCode, field, message string) error {
	return &ValidationError{Code: code, Field: field, Message: message}
}

func ErrorCatalog() map[ErrorCode]ErrorSpec {
	out := make(map[ErrorCode]ErrorSpec, len(errorCatalog))
	for code, spec := range errorCatalog {
		out[code] = spec
	}
	return out
}

func LookupError(code ErrorCode) (ErrorSpec, bool) {
	spec, ok := errorCatalog[code]
	return spec, ok
}

type NextAction struct {
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type ResponseEnvelope struct {
	OK               bool         `json:"ok"`
	Code             ErrorCode    `json:"code,omitempty"`
	ExitCode         int          `json:"exit_code"`
	Disposition      Disposition  `json:"disposition"`
	Message          string       `json:"message"`
	Retryable        bool         `json:"retryable"`
	PollAfterSeconds int          `json:"poll_after_seconds"`
	PollHandle       string       `json:"poll_handle"`
	NextActions      []NextAction `json:"next_actions,omitempty"`
	CorrelationID    string       `json:"correlation_id"`
}

func ErrorResponse(code ErrorCode, correlationID, pollHandle string) ResponseEnvelope {
	spec, ok := LookupError(code)
	if !ok {
		spec = errorCatalog[CodeSchemaInvalid]
	}
	// Org status failures are status-mapped by OrgStatusInvalidResponse. The
	// generic path is only a statusless fallback.
	if spec.PollAfterSeconds == 0 || !spec.Retryable {
		pollHandle = ""
	}
	return ResponseEnvelope{
		OK:               false,
		Code:             spec.Code,
		ExitCode:         spec.ExitCode,
		Disposition:      spec.Disposition,
		Message:          spec.Message,
		Retryable:        spec.Retryable,
		PollAfterSeconds: spec.PollAfterSeconds,
		PollHandle:       pollHandle,
		CorrelationID:    strings.TrimSpace(correlationID),
	}
}

func SuccessResponse(message, correlationID string) ResponseEnvelope {
	return ResponseEnvelope{
		OK:               true,
		ExitCode:         0,
		Disposition:      DispositionTerminalOK,
		Message:          strings.TrimSpace(message),
		Retryable:        false,
		PollAfterSeconds: 0,
		PollHandle:       "",
		CorrelationID:    strings.TrimSpace(correlationID),
	}
}

type OrgStatus string

const (
	OrgStatusActive                       OrgStatus = "active"
	OrgStatusVerifiedBusiness             OrgStatus = "verified_business"
	OrgStatusDomainVerified               OrgStatus = "domain_verified"
	OrgStatusDraft                        OrgStatus = "org_draft"
	OrgStatusDomainPending                OrgStatus = "domain_pending"
	OrgStatusKYGPending                   OrgStatus = "kyg_pending"
	OrgStatusDomainReverificationRequired OrgStatus = "domain_reverification_required"
	OrgStatusReviewHold                   OrgStatus = "review_hold"
	OrgStatusSuspendedPendingAppeal       OrgStatus = "suspended_pending_appeal"
	OrgStatusSuspended                    OrgStatus = "suspended"
	OrgStatusRevoked                      OrgStatus = "revoked"
	OrgStatusDeleted                      OrgStatus = "deleted"
	OrgStatusPermanentlyBarred            OrgStatus = "permanently_barred"
	OrgStatusUnknownOrg                   OrgStatus = "unknown_org"
)

type OrgRegistrationEligibility struct {
	Status                OrgStatus
	ProductionAllowed     bool
	SandboxOnly           bool
	Code                  ErrorCode
	Disposition           Disposition
	Retryable             bool
	PollAfterSeconds      int
	RequiresHumanAction   bool
	RequiresExternalProof bool
}

func RegistrationEligibilityForOrgStatus(status OrgStatus) OrgRegistrationEligibility {
	switch status {
	case OrgStatusActive:
		return OrgRegistrationEligibility{Status: status, ProductionAllowed: true, Disposition: DispositionTerminalOK}
	case OrgStatusVerifiedBusiness, OrgStatusDraft, OrgStatusReviewHold, OrgStatusSuspendedPendingAppeal:
		return orgAwaitingHuman(status)
	case OrgStatusDomainVerified:
		eligibility := orgAwaitingHuman(status)
		eligibility.SandboxOnly = true
		return eligibility
	case OrgStatusDomainPending, OrgStatusKYGPending, OrgStatusDomainReverificationRequired:
		return orgAwaitingExternal(status)
	case OrgStatusSuspended, OrgStatusRevoked, OrgStatusDeleted, OrgStatusPermanentlyBarred, OrgStatusUnknownOrg:
		return orgTerminal(status)
	default:
		return orgTerminal(OrgStatusUnknownOrg)
	}
}

// IsKnownOrgStatus reports whether status is one of the defined OrgStatus values.
// It is the single source of truth for org-status membership: config loaders use
// it to fail closed on a typo'd status at load time rather than letting an
// unknown value silently resolve to terminal unknown_org only at enrollment.
func IsKnownOrgStatus(status OrgStatus) bool {
	switch status {
	case OrgStatusActive, OrgStatusVerifiedBusiness, OrgStatusDomainVerified,
		OrgStatusDraft, OrgStatusDomainPending, OrgStatusKYGPending,
		OrgStatusDomainReverificationRequired, OrgStatusReviewHold,
		OrgStatusSuspendedPendingAppeal, OrgStatusSuspended, OrgStatusRevoked,
		OrgStatusDeleted, OrgStatusPermanentlyBarred, OrgStatusUnknownOrg:
		return true
	default:
		return false
	}
}

func orgAwaitingHuman(status OrgStatus) OrgRegistrationEligibility {
	return OrgRegistrationEligibility{
		Status:              status,
		Code:                CodeOrgStatusInvalid,
		Disposition:         DispositionAwaitingHuman,
		Retryable:           true,
		PollAfterSeconds:    DefaultPollAfterSeconds,
		RequiresHumanAction: true,
	}
}

func orgAwaitingExternal(status OrgStatus) OrgRegistrationEligibility {
	return OrgRegistrationEligibility{
		Status:                status,
		Code:                  CodeOrgStatusInvalid,
		Disposition:           DispositionAwaitingExternal,
		Retryable:             true,
		PollAfterSeconds:      DefaultPollAfterSeconds,
		RequiresExternalProof: true,
	}
}

func orgTerminal(status OrgStatus) OrgRegistrationEligibility {
	return OrgRegistrationEligibility{
		Status:                status,
		Code:                  CodeOrgStatusInvalid,
		Disposition:           DispositionTerminalError,
		Retryable:             false,
		PollAfterSeconds:      0,
		RequiresHumanAction:   false,
		RequiresExternalProof: false,
	}
}

func OrgStatusInvalidResponse(status OrgStatus, correlationID, bootstrapID string) ResponseEnvelope {
	eligibility := RegistrationEligibilityForOrgStatus(status)
	if eligibility.ProductionAllowed {
		return SuccessResponse("Org status permits production gateway registration.", correlationID)
	}
	pollHandle := ""
	if eligibility.PollAfterSeconds > 0 {
		pollHandle = strings.TrimSpace(bootstrapID)
	}
	return ResponseEnvelope{
		OK:               false,
		Code:             CodeOrgStatusInvalid,
		ExitCode:         errorCatalog[CodeOrgStatusInvalid].ExitCode,
		Disposition:      eligibility.Disposition,
		Message:          errorCatalog[CodeOrgStatusInvalid].Message,
		Retryable:        eligibility.Retryable,
		PollAfterSeconds: eligibility.PollAfterSeconds,
		PollHandle:       pollHandle,
		CorrelationID:    strings.TrimSpace(correlationID),
	}
}

type ActorType string

const (
	ActorTypeUser           ActorType = "user"
	ActorTypeServiceAccount ActorType = "service_account"
	ActorTypeAgent          ActorType = "agent"
)

type Actor struct {
	Type        ActorType `json:"type"`
	PrincipalID string    `json:"principal_id"`
	AuthContext string    `json:"auth_context"`
	Scopes      []string  `json:"scopes,omitempty"`
}

type CommandEnvelope struct {
	SchemaVersion  string          `json:"schema_version"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	CorrelationID  string          `json:"correlation_id"`
	Actor          Actor           `json:"actor"`
	Payload        json.RawMessage `json:"payload"`
}

func DecodeCommandEnvelope(data []byte, payload any, mutating bool) (CommandEnvelope, error) {
	var envelope CommandEnvelope
	if err := strictDecode(data, &envelope); err != nil {
		return CommandEnvelope{}, validationErr(CodeSchemaInvalid, "envelope", err.Error())
	}
	if err := envelope.Validate(mutating); err != nil {
		return CommandEnvelope{}, err
	}
	if payload != nil {
		if len(envelope.Payload) == 0 {
			return CommandEnvelope{}, validationErr(CodeSchemaInvalid, "payload", "is required")
		}
		if err := strictDecode(envelope.Payload, payload); err != nil {
			return CommandEnvelope{}, validationErr(CodeSchemaInvalid, "payload", err.Error())
		}
	}
	return envelope, nil
}

func (e CommandEnvelope) Validate(mutating bool) error {
	if strings.TrimSpace(e.SchemaVersion) != CommandEnvelopeSchemaVersion {
		return validationErr(CodeSchemaInvalid, "schema_version", fmt.Sprintf("must be %q", CommandEnvelopeSchemaVersion))
	}
	if mutating && strings.TrimSpace(e.IdempotencyKey) == "" {
		return validationErr(CodeSchemaInvalid, "idempotency_key", "is required for mutating commands")
	}
	if strings.TrimSpace(e.CorrelationID) == "" {
		return validationErr(CodeSchemaInvalid, "correlation_id", "is required")
	}
	if err := e.Actor.Validate(); err != nil {
		return err
	}
	if len(e.Payload) == 0 || bytes.Equal(bytes.TrimSpace(e.Payload), []byte("null")) {
		return validationErr(CodeSchemaInvalid, "payload", "is required")
	}
	return nil
}

func (a Actor) Validate() error {
	switch a.Type {
	case ActorTypeUser, ActorTypeServiceAccount, ActorTypeAgent:
	default:
		return validationErr(CodeActorUnauthenticated, "actor.type", "must be user, service_account, or agent")
	}
	if strings.TrimSpace(a.PrincipalID) == "" {
		return validationErr(CodeActorUnauthenticated, "actor.principal_id", "is required")
	}
	if strings.TrimSpace(a.AuthContext) == "" {
		return validationErr(CodeActorUnauthenticated, "actor.auth_context", "is required")
	}
	return nil
}

type PublicKeyBinding struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

func (b PublicKeyBinding) Validate(field string) error {
	if strings.TrimSpace(b.Alg) != PublicKeyBindingAlgorithmSHA256SPKI {
		return validationErr(CodeSchemaInvalid, field+".alg", fmt.Sprintf("must be %q", PublicKeyBindingAlgorithmSHA256SPKI))
	}
	if strings.TrimSpace(b.Value) == "" {
		return validationErr(CodeSchemaInvalid, field+".value", "is required")
	}
	return nil
}

type LocalControlAuthorization struct {
	SchemaVersion       string           `json:"schema_version"`
	AuthorizationID     string           `json:"authorization_id"`
	IssuerControlID     string           `json:"issuer_control_id"`
	IssuerKeyID         string           `json:"issuer_key_id"`
	FabricID            string           `json:"fabric_id"`
	OrgID               string           `json:"org_id"`
	TenantID            string           `json:"tenant_id"`
	GatewayPoolID       string           `json:"gateway_pool_id"`
	GatewayID           string           `json:"gateway_id"`
	AllowedRelayFabric  string           `json:"allowed_relay_fabric"`
	AllowedRelayRegions []string         `json:"allowed_relay_regions"`
	FacadeScope         []string         `json:"facade_scope"`
	CSRPublicKeyBinding PublicKeyBinding `json:"csr_public_key_binding"`
	NotBeforeMS         int64            `json:"not_before_ms"`
	ExpiresAtMS         int64            `json:"expires_at_ms"`
	SignatureAlg        string           `json:"signature_alg"`
	Signature           string           `json:"signature"`
}

type localControlAuthorizationSigningMaterial struct {
	SchemaVersion       string           `json:"schema_version"`
	AuthorizationID     string           `json:"authorization_id"`
	IssuerControlID     string           `json:"issuer_control_id"`
	IssuerKeyID         string           `json:"issuer_key_id"`
	FabricID            string           `json:"fabric_id"`
	OrgID               string           `json:"org_id"`
	TenantID            string           `json:"tenant_id"`
	GatewayPoolID       string           `json:"gateway_pool_id"`
	GatewayID           string           `json:"gateway_id"`
	AllowedRelayFabric  string           `json:"allowed_relay_fabric"`
	AllowedRelayRegions []string         `json:"allowed_relay_regions"`
	FacadeScope         []string         `json:"facade_scope"`
	CSRPublicKeyBinding PublicKeyBinding `json:"csr_public_key_binding"`
	NotBeforeMS         int64            `json:"not_before_ms"`
	ExpiresAtMS         int64            `json:"expires_at_ms"`
	SignatureAlg        string           `json:"signature_alg"`
}

func (a LocalControlAuthorization) ValidateShape() error {
	required := map[string]string{
		"schema_version":       a.SchemaVersion,
		"authorization_id":     a.AuthorizationID,
		"issuer_control_id":    a.IssuerControlID,
		"issuer_key_id":        a.IssuerKeyID,
		"fabric_id":            a.FabricID,
		"org_id":               a.OrgID,
		"tenant_id":            a.TenantID,
		"gateway_pool_id":      a.GatewayPoolID,
		"gateway_id":           a.GatewayID,
		"allowed_relay_fabric": a.AllowedRelayFabric,
		"signature_alg":        a.SignatureAlg,
		"signature":            a.Signature,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization."+field, "is required")
		}
	}
	if strings.TrimSpace(a.SchemaVersion) != LocalControlAuthorizationVersion {
		return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization.schema_version", fmt.Sprintf("must be %q", LocalControlAuthorizationVersion))
	}
	if strings.TrimSpace(a.SignatureAlg) != SignatureAlgorithmEd25519JCSV1 {
		return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization.signature_alg", fmt.Sprintf("must be %q", SignatureAlgorithmEd25519JCSV1))
	}
	if len(a.AllowedRelayRegions) == 0 {
		return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization.allowed_relay_regions", "requires at least one region")
	}
	if len(a.FacadeScope) == 0 {
		return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization.facade_scope", "requires at least one scope")
	}
	if a.NotBeforeMS <= 0 {
		return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization.not_before_ms", "must be positive")
	}
	if a.ExpiresAtMS <= a.NotBeforeMS {
		return validationErr(CodeLocalControlAuthorizationInvalid, "local_control_authorization.expires_at_ms", "must be after not_before_ms")
	}
	if err := a.CSRPublicKeyBinding.Validate("local_control_authorization.csr_public_key_binding"); err != nil {
		return err
	}
	return nil
}

func LocalControlAuthorizationCanonicalBytes(a LocalControlAuthorization) ([]byte, error) {
	material := localControlAuthorizationSigningMaterial{
		SchemaVersion:       a.SchemaVersion,
		AuthorizationID:     a.AuthorizationID,
		IssuerControlID:     a.IssuerControlID,
		IssuerKeyID:         a.IssuerKeyID,
		FabricID:            a.FabricID,
		OrgID:               a.OrgID,
		TenantID:            a.TenantID,
		GatewayPoolID:       a.GatewayPoolID,
		GatewayID:           a.GatewayID,
		AllowedRelayFabric:  a.AllowedRelayFabric,
		AllowedRelayRegions: append([]string(nil), a.AllowedRelayRegions...),
		FacadeScope:         append([]string(nil), a.FacadeScope...),
		CSRPublicKeyBinding: a.CSRPublicKeyBinding,
		NotBeforeMS:         a.NotBeforeMS,
		ExpiresAtMS:         a.ExpiresAtMS,
		SignatureAlg:        a.SignatureAlg,
	}
	if err := validateProgrammaticJSONValue(material); err != nil {
		return nil, err
	}
	body, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	return canonicalRawJSON(body)
}

func LocalControlAuthorizationDigestSHA256(a LocalControlAuthorization) (string, error) {
	body, err := LocalControlAuthorizationCanonicalBytes(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

type CreateGatewayBootstrapPayload struct {
	OrgID                     string                    `json:"org_id"`
	GatewayPoolID             string                    `json:"gateway_pool_id"`
	GatewayID                 string                    `json:"gateway_id"`
	DisplayName               string                    `json:"display_name"`
	AllowedRelayFabric        string                    `json:"allowed_relay_fabric"`
	AllowedRelayRegions       []string                  `json:"allowed_relay_regions"`
	FacadeScope               []string                  `json:"facade_scope"`
	CSRPublicKeyBinding       PublicKeyBinding          `json:"csr_public_key_binding"`
	LocalControlAuthorization LocalControlAuthorization `json:"local_control_authorization"`
	TTLSeconds                int                       `json:"ttl_seconds"`
}

func DecodeCreateGatewayBootstrapEnvelope(data []byte) (CommandEnvelope, CreateGatewayBootstrapPayload, error) {
	var payload CreateGatewayBootstrapPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, true)
	if err != nil {
		return CommandEnvelope{}, CreateGatewayBootstrapPayload{}, err
	}
	if err := payload.Validate(DefaultMaxBootstrapTTLSeconds); err != nil {
		return CommandEnvelope{}, CreateGatewayBootstrapPayload{}, err
	}
	return envelope, payload, nil
}

func (p CreateGatewayBootstrapPayload) Validate(maxTTLSeconds int) error {
	required := map[string]string{
		"org_id":               p.OrgID,
		"gateway_pool_id":      p.GatewayPoolID,
		"gateway_id":           p.GatewayID,
		"allowed_relay_fabric": p.AllowedRelayFabric,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeSchemaInvalid, "payload."+field, "is required")
		}
	}
	if len(p.AllowedRelayRegions) == 0 {
		return validationErr(CodeSchemaInvalid, "payload.allowed_relay_regions", "requires at least one region")
	}
	if len(p.FacadeScope) == 0 {
		return validationErr(CodeSchemaInvalid, "payload.facade_scope", "requires at least one scope")
	}
	if err := p.CSRPublicKeyBinding.Validate("payload.csr_public_key_binding"); err != nil {
		return err
	}
	if maxTTLSeconds <= 0 {
		maxTTLSeconds = DefaultMaxBootstrapTTLSeconds
	}
	if p.TTLSeconds <= 0 || p.TTLSeconds > maxTTLSeconds {
		return validationErr(CodeSchemaInvalid, "payload.ttl_seconds", fmt.Sprintf("must be between 1 and %d", maxTTLSeconds))
	}
	if err := p.LocalControlAuthorization.ValidateShape(); err != nil {
		return err
	}
	if err := p.validateLocalControlCoversBootstrap(); err != nil {
		return err
	}
	return nil
}

func (p CreateGatewayBootstrapPayload) validateLocalControlCoversBootstrap() error {
	auth := p.LocalControlAuthorization
	if auth.OrgID != p.OrgID ||
		auth.GatewayPoolID != p.GatewayPoolID ||
		auth.GatewayID != p.GatewayID ||
		auth.AllowedRelayFabric != p.AllowedRelayFabric ||
		auth.CSRPublicKeyBinding != p.CSRPublicKeyBinding {
		return validationErr(CodeLocalControlAuthorizationMismatch, "local_control_authorization", "does not match bootstrap request scope")
	}
	if !containsAll(auth.AllowedRelayRegions, p.AllowedRelayRegions) {
		return validationErr(CodeLocalControlAuthorizationMismatch, "local_control_authorization.allowed_relay_regions", "does not cover bootstrap request")
	}
	if !containsAll(auth.FacadeScope, p.FacadeScope) {
		return validationErr(CodeLocalControlAuthorizationMismatch, "local_control_authorization.facade_scope", "does not cover bootstrap request")
	}
	return nil
}

type GatewayBootstrapIntent struct {
	SchemaVersion                         string           `json:"schema_version"`
	BootstrapID                           string           `json:"bootstrap_id"`
	FabricID                              string           `json:"fabric_id"`
	OrgID                                 string           `json:"org_id"`
	GatewayPoolID                         string           `json:"gateway_pool_id"`
	GatewayID                             string           `json:"gateway_id"`
	AllowedRelayFabric                    string           `json:"allowed_relay_fabric"`
	AllowedRelayRegions                   []string         `json:"allowed_relay_regions"`
	FacadeScope                           []string         `json:"facade_scope"`
	LocalControlAuthorizationRef          string           `json:"local_control_authorization_ref"`
	LocalControlAuthorizationDigestSHA256 string           `json:"local_control_authorization_digest_sha256"`
	CSRPublicKeyBinding                   PublicKeyBinding `json:"csr_public_key_binding"`
	JTI                                   string           `json:"jti"`
	IssuedAtMS                            int64            `json:"issued_at_ms"`
	ExpiresAtMS                           int64            `json:"expires_at_ms"`
	SignatureAlg                          string           `json:"signature_alg"`
	Signature                             string           `json:"signature"`
}

type gatewayBootstrapIntentSigningMaterial struct {
	SchemaVersion                         string           `json:"schema_version"`
	BootstrapID                           string           `json:"bootstrap_id"`
	FabricID                              string           `json:"fabric_id"`
	OrgID                                 string           `json:"org_id"`
	GatewayPoolID                         string           `json:"gateway_pool_id"`
	GatewayID                             string           `json:"gateway_id"`
	AllowedRelayFabric                    string           `json:"allowed_relay_fabric"`
	AllowedRelayRegions                   []string         `json:"allowed_relay_regions"`
	FacadeScope                           []string         `json:"facade_scope"`
	LocalControlAuthorizationRef          string           `json:"local_control_authorization_ref"`
	LocalControlAuthorizationDigestSHA256 string           `json:"local_control_authorization_digest_sha256"`
	CSRPublicKeyBinding                   PublicKeyBinding `json:"csr_public_key_binding"`
	JTI                                   string           `json:"jti"`
	IssuedAtMS                            int64            `json:"issued_at_ms"`
	ExpiresAtMS                           int64            `json:"expires_at_ms"`
	SignatureAlg                          string           `json:"signature_alg"`
}

func GatewayBootstrapIntentCanonicalBytes(b GatewayBootstrapIntent) ([]byte, error) {
	material := gatewayBootstrapIntentSigningMaterial{
		SchemaVersion:                         b.SchemaVersion,
		BootstrapID:                           b.BootstrapID,
		FabricID:                              b.FabricID,
		OrgID:                                 b.OrgID,
		GatewayPoolID:                         b.GatewayPoolID,
		GatewayID:                             b.GatewayID,
		AllowedRelayFabric:                    b.AllowedRelayFabric,
		AllowedRelayRegions:                   append([]string(nil), b.AllowedRelayRegions...),
		FacadeScope:                           append([]string(nil), b.FacadeScope...),
		LocalControlAuthorizationRef:          b.LocalControlAuthorizationRef,
		LocalControlAuthorizationDigestSHA256: b.LocalControlAuthorizationDigestSHA256,
		CSRPublicKeyBinding:                   b.CSRPublicKeyBinding,
		JTI:                                   b.JTI,
		IssuedAtMS:                            b.IssuedAtMS,
		ExpiresAtMS:                           b.ExpiresAtMS,
		SignatureAlg:                          b.SignatureAlg,
	}
	if err := validateProgrammaticJSONValue(material); err != nil {
		return nil, err
	}
	body, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	return canonicalRawJSON(body)
}

func (b GatewayBootstrapIntent) ValidateShape() error {
	required := map[string]string{
		"schema_version":                  b.SchemaVersion,
		"bootstrap_id":                    b.BootstrapID,
		"fabric_id":                       b.FabricID,
		"org_id":                          b.OrgID,
		"gateway_pool_id":                 b.GatewayPoolID,
		"gateway_id":                      b.GatewayID,
		"allowed_relay_fabric":            b.AllowedRelayFabric,
		"local_control_authorization_ref": b.LocalControlAuthorizationRef,
		"local_control_authorization_digest_sha256": b.LocalControlAuthorizationDigestSHA256,
		"jti":           b.JTI,
		"signature_alg": b.SignatureAlg,
		"signature":     b.Signature,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeSchemaInvalid, "bootstrap."+field, "is required")
		}
	}
	if b.SchemaVersion != GatewayBootstrapIntentVersion {
		return validationErr(CodeSchemaInvalid, "bootstrap.schema_version", fmt.Sprintf("must be %q", GatewayBootstrapIntentVersion))
	}
	if b.SignatureAlg != SignatureAlgorithmEd25519JCSV1 {
		return validationErr(CodeBootstrapSignatureInvalid, "bootstrap.signature_alg", fmt.Sprintf("must be %q", SignatureAlgorithmEd25519JCSV1))
	}
	if len(b.AllowedRelayRegions) == 0 {
		return validationErr(CodeSchemaInvalid, "bootstrap.allowed_relay_regions", "requires at least one region")
	}
	if len(b.FacadeScope) == 0 {
		return validationErr(CodeSchemaInvalid, "bootstrap.facade_scope", "requires at least one scope")
	}
	if b.IssuedAtMS <= 0 || b.ExpiresAtMS <= b.IssuedAtMS {
		return validationErr(CodeSchemaInvalid, "bootstrap.expires_at_ms", "must be after issued_at_ms")
	}
	if !isSHA256Hex(b.LocalControlAuthorizationDigestSHA256) {
		return validationErr(CodeSchemaInvalid, "bootstrap.local_control_authorization_digest_sha256", "must be sha256 hex")
	}
	if err := b.CSRPublicKeyBinding.Validate("bootstrap.csr_public_key_binding"); err != nil {
		return err
	}
	return nil
}

type AdvisoryIdentity struct {
	DisplayName                       string `json:"display_name"`
	OperatorSuppliedSubject           string `json:"operator_supplied_subject"`
	OperatorSuppliedSPIFFEID          string `json:"operator_supplied_spiffe_id"`
	OperatorSuppliedFingerprintSHA256 string `json:"operator_supplied_fingerprint_sha256"`
}

func (a AdvisoryIdentity) HasOperatorIdentityAssertions() bool {
	return strings.TrimSpace(a.OperatorSuppliedSubject) != "" ||
		strings.TrimSpace(a.OperatorSuppliedSPIFFEID) != "" ||
		strings.TrimSpace(a.OperatorSuppliedFingerprintSHA256) != ""
}

type RedeemGatewayBootstrapPayload struct {
	Bootstrap                 GatewayBootstrapIntent    `json:"bootstrap"`
	CSRPem                    string                    `json:"csr_pem"`
	LocalControlAuthorization LocalControlAuthorization `json:"local_control_authorization"`
	Advisory                  AdvisoryIdentity          `json:"advisory"`
}

func DecodeRedeemGatewayBootstrapEnvelope(data []byte) (CommandEnvelope, RedeemGatewayBootstrapPayload, error) {
	var payload RedeemGatewayBootstrapPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, true)
	if err != nil {
		return CommandEnvelope{}, RedeemGatewayBootstrapPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, RedeemGatewayBootstrapPayload{}, err
	}
	if err := ValidateRedeemLocalControlDigest(payload); err != nil {
		return CommandEnvelope{}, RedeemGatewayBootstrapPayload{}, err
	}
	return envelope, payload, nil
}

func (p RedeemGatewayBootstrapPayload) ValidateShape() error {
	if err := p.Bootstrap.ValidateShape(); err != nil {
		return err
	}
	if strings.TrimSpace(p.CSRPem) == "" {
		return validationErr(CodeCSRParseFailed, "payload.csr_pem", "is required")
	}
	if err := p.LocalControlAuthorization.ValidateShape(); err != nil {
		return err
	}
	if p.LocalControlAuthorization.AuthorizationID != p.Bootstrap.LocalControlAuthorizationRef {
		return validationErr(CodeLocalControlAuthorizationMismatch, "payload.local_control_authorization.authorization_id", "does not match bootstrap ref")
	}
	if p.LocalControlAuthorization.CSRPublicKeyBinding != p.Bootstrap.CSRPublicKeyBinding ||
		p.LocalControlAuthorization.OrgID != p.Bootstrap.OrgID ||
		p.LocalControlAuthorization.GatewayPoolID != p.Bootstrap.GatewayPoolID ||
		p.LocalControlAuthorization.GatewayID != p.Bootstrap.GatewayID {
		return validationErr(CodeBootstrapIntentMismatch, "payload.local_control_authorization", "does not match bootstrap scope")
	}
	return nil
}

func ValidateRedeemLocalControlDigest(p RedeemGatewayBootstrapPayload) error {
	got, err := LocalControlAuthorizationDigestSHA256(p.LocalControlAuthorization)
	if err != nil {
		return validationErr(CodeLocalControlAuthorizationInvalid, "payload.local_control_authorization", err.Error())
	}
	if !strings.EqualFold(got, p.Bootstrap.LocalControlAuthorizationDigestSHA256) {
		return validationErr(CodeLocalControlAuthorizationMismatch, "payload.local_control_authorization", "digest does not match bootstrap commitment")
	}
	return nil
}

type RevokeGatewayRelayIdentityPayload struct {
	GatewayID    string `json:"gateway_id"`
	CredentialID string `json:"credential_id"`
	BindingID    string `json:"binding_id"`
	Reason       string `json:"reason"`
}

func DecodeRevokeGatewayRelayIdentityEnvelope(data []byte) (CommandEnvelope, RevokeGatewayRelayIdentityPayload, error) {
	var payload RevokeGatewayRelayIdentityPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, true)
	if err != nil {
		return CommandEnvelope{}, RevokeGatewayRelayIdentityPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, RevokeGatewayRelayIdentityPayload{}, err
	}
	return envelope, payload, nil
}

func (p RevokeGatewayRelayIdentityPayload) ValidateShape() error {
	required := map[string]string{
		"gateway_id":    p.GatewayID,
		"credential_id": p.CredentialID,
		"binding_id":    p.BindingID,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeSchemaInvalid, "payload."+field, "is required")
		}
	}
	return nil
}

type RotateGatewayRelayIdentityPayload struct {
	OrgID                string           `json:"org_id"`
	GatewayID            string           `json:"gateway_id"`
	PreviousCredentialID string           `json:"previous_credential_id"`
	PreviousBindingID    string           `json:"previous_binding_id"`
	AllowedRelayFabric   string           `json:"allowed_relay_fabric"`
	CSRPublicKeyBinding  PublicKeyBinding `json:"csr_public_key_binding"`
	CSRPem               string           `json:"csr_pem"`
	Advisory             AdvisoryIdentity `json:"advisory"`
	Reason               string           `json:"reason"`
}

func DecodeRotateGatewayRelayIdentityEnvelope(data []byte) (CommandEnvelope, RotateGatewayRelayIdentityPayload, error) {
	var payload RotateGatewayRelayIdentityPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, true)
	if err != nil {
		return CommandEnvelope{}, RotateGatewayRelayIdentityPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, RotateGatewayRelayIdentityPayload{}, err
	}
	return envelope, payload, nil
}

func (p RotateGatewayRelayIdentityPayload) ValidateShape() error {
	required := map[string]string{
		"org_id":                 p.OrgID,
		"gateway_id":             p.GatewayID,
		"previous_credential_id": p.PreviousCredentialID,
		"previous_binding_id":    p.PreviousBindingID,
		"allowed_relay_fabric":   p.AllowedRelayFabric,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeSchemaInvalid, "payload."+field, "is required")
		}
	}
	if strings.TrimSpace(p.CSRPem) == "" {
		return validationErr(CodeCSRParseFailed, "payload.csr_pem", "is required")
	}
	if err := p.CSRPublicKeyBinding.Validate("payload.csr_public_key_binding"); err != nil {
		return err
	}
	return nil
}

// IssueMembershipCapabilityPayload requests a short-TTL libp2p-fabric membership
// capability (libp2p-fabric-migration P1.3) for an already-enrolled gateway. It
// names the ACTIVE relay-gateway-client binding to bind to (gateway_id/binding_id/
// credential_id, matched exactly like the revoke/rotate lifecycle commands) plus
// the gateway's SEPARATE libp2p host public key and a proof-of-possession over a
// request-bound challenge (see MembershipCapabilityPoPChallenge). No cleartext org
// or domain crosses the wire — the signed capability carries only an opaque handle.
type IssueMembershipCapabilityPayload struct {
	GatewayID       string `json:"gateway_id"`
	BindingID       string `json:"binding_id"`
	CredentialID    string `json:"credential_id"`
	FabricID        string `json:"fabric_id"`
	LibP2PPublicKey string `json:"libp2p_public_key"` // base64 raw-url, 32-byte ed25519 host pubkey
	PoPSignature    string `json:"pop_signature"`     // base64 raw-url ed25519 sig over the request-bound challenge
}

func DecodeIssueMembershipCapabilityEnvelope(data []byte) (CommandEnvelope, IssueMembershipCapabilityPayload, error) {
	var payload IssueMembershipCapabilityPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, true)
	if err != nil {
		return CommandEnvelope{}, IssueMembershipCapabilityPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, IssueMembershipCapabilityPayload{}, err
	}
	return envelope, payload, nil
}

func (p IssueMembershipCapabilityPayload) ValidateShape() error {
	required := map[string]string{
		"gateway_id":        p.GatewayID,
		"binding_id":        p.BindingID,
		"credential_id":     p.CredentialID,
		"fabric_id":         p.FabricID,
		"libp2p_public_key": p.LibP2PPublicKey,
		"pop_signature":     p.PoPSignature,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeSchemaInvalid, "payload."+field, "is required")
		}
	}
	return nil
}

// RegisterMeshIdentityPayload is the RM command that records a relay daemon's MESH
// ed25519 identity + WireGuard-path material for an already-enrolled binding
// (control-plane peer-feed bridge G1). The Registration blob is the full
// membershipcap.MeshRegistrationClaim JSON (mesh pubkey + PubKeyWG + MeshIP + FQName +
// Role + libp2p PeerID + endpoints + bootstrap addrs + issued_at + proof_of_possession);
// the control plane verifies the daemon's mesh-key PoP against the named identity before
// persisting. The JSON schema stays the authority for canonical bytes (like the sibling
// membership command); the claim's own fields are not expanded here.
type RegisterMeshIdentityPayload struct {
	GatewayID    string          `json:"gateway_id"`
	BindingID    string          `json:"binding_id"`
	CredentialID string          `json:"credential_id"`
	FabricID     string          `json:"fabric_id"`
	Registration json.RawMessage `json:"registration"`
}

func DecodeRegisterMeshIdentityEnvelope(data []byte) (CommandEnvelope, RegisterMeshIdentityPayload, error) {
	var payload RegisterMeshIdentityPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, true)
	if err != nil {
		return CommandEnvelope{}, RegisterMeshIdentityPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, RegisterMeshIdentityPayload{}, err
	}
	return envelope, payload, nil
}

func (p RegisterMeshIdentityPayload) ValidateShape() error {
	required := map[string]string{
		"gateway_id":    p.GatewayID,
		"binding_id":    p.BindingID,
		"credential_id": p.CredentialID,
		"fabric_id":     p.FabricID,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return validationErr(CodeSchemaInvalid, "payload."+field, "is required")
		}
	}
	if len(p.Registration) == 0 {
		return validationErr(CodeSchemaInvalid, "payload.registration", "is required")
	}
	return nil
}

// MembershipCapabilityPoPChallenge derives the deterministic proof-of-possession
// challenge that the gateway signs with its libp2p private key and the control
// plane recomputes at issuance. Binding it to the specific issuance (fabric +
// named binding + idempotency key + the exact pubkey) keeps a captured PoP from
// being lifted onto a different binding, key, or issuance — the request-bound
// replay defense (libp2p-fabric-migration open-question #2, resolution "b").
func MembershipCapabilityPoPChallenge(fabricID, gatewayID, bindingID, idempotencyKey, libp2pPublicKeyB64 string) []byte {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"membership-pop-challenge",
		strings.TrimSpace(fabricID),
		strings.TrimSpace(gatewayID),
		strings.TrimSpace(bindingID),
		strings.TrimSpace(idempotencyKey),
		strings.TrimSpace(libp2pPublicKeyB64),
	}, "|")))
	return sum[:]
}

// PullMembershipRevocationListPayload requests the caller's OWN-ORG signed libp2p-
// fabric revocation list (libp2p-fabric-migration P1.4 transport). The org is the
// AUTHENTICATED tenant, never a payload field — own-org-only, so a caller can only
// pull its own tenant's list. This is a READ (no idempotency key).
type PullMembershipRevocationListPayload struct {
	FabricID string `json:"fabric_id"`
	// IncludeFabricPSK asks the control plane to also return the federation
	// private-network PSK in the (mTLS-confidential) response, for the caller to
	// seed its x-mesh-fed daemon (libp2p-fabric-migration P2.3, D4/D10). The
	// reconciler sets it on the first pull; it is not needed on refresh polls.
	IncludeFabricPSK bool `json:"include_fabric_psk,omitempty"`
}

func DecodePullMembershipRevocationListEnvelope(data []byte) (CommandEnvelope, PullMembershipRevocationListPayload, error) {
	var payload PullMembershipRevocationListPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, false)
	if err != nil {
		return CommandEnvelope{}, PullMembershipRevocationListPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, PullMembershipRevocationListPayload{}, err
	}
	return envelope, payload, nil
}

func (p PullMembershipRevocationListPayload) ValidateShape() error {
	if strings.TrimSpace(p.FabricID) == "" {
		return validationErr(CodeSchemaInvalid, "payload.fabric_id", "is required")
	}
	return nil
}

// PullFabricPeerRosterPayload requests the caller's OWN-ORG signed FabricPeerRoster — the
// control plane assembles it from that org's registered relay mesh identities
// (control-plane peer-feed bridge G2). A READ, like the revocation-list pull.
type PullFabricPeerRosterPayload struct {
	FabricID string `json:"fabric_id"`
}

func DecodePullFabricPeerRosterEnvelope(data []byte) (CommandEnvelope, PullFabricPeerRosterPayload, error) {
	var payload PullFabricPeerRosterPayload
	envelope, err := DecodeCommandEnvelope(data, &payload, false)
	if err != nil {
		return CommandEnvelope{}, PullFabricPeerRosterPayload{}, err
	}
	if err := payload.ValidateShape(); err != nil {
		return CommandEnvelope{}, PullFabricPeerRosterPayload{}, err
	}
	return envelope, payload, nil
}

func (p PullFabricPeerRosterPayload) ValidateShape() error {
	if strings.TrimSpace(p.FabricID) == "" {
		return validationErr(CodeSchemaInvalid, "payload.fabric_id", "is required")
	}
	return nil
}

type IdempotencyScope struct {
	FabricID       string
	ActorOrgID     string
	RPCMethod      string
	IdempotencyKey string
}

func (s IdempotencyScope) Validate() error {
	if strings.TrimSpace(s.FabricID) == "" {
		return validationErr(CodeSchemaInvalid, "idempotency_scope.fabric_id", "is required")
	}
	if strings.TrimSpace(s.ActorOrgID) == "" {
		return validationErr(CodeSchemaInvalid, "idempotency_scope.actor_org_id", "is required")
	}
	if strings.TrimSpace(s.RPCMethod) == "" {
		return validationErr(CodeSchemaInvalid, "idempotency_scope.rpc_method", "is required")
	}
	if strings.TrimSpace(s.IdempotencyKey) == "" {
		return validationErr(CodeSchemaInvalid, "idempotency_scope.idempotency_key", "is required")
	}
	return nil
}

func (s IdempotencyScope) Key() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return strings.Join([]string{
		strings.TrimSpace(s.FabricID),
		strings.TrimSpace(s.ActorOrgID),
		strings.TrimSpace(s.RPCMethod),
		strings.TrimSpace(s.IdempotencyKey),
	}, "\x1f"), nil
}

func EnvelopePayloadDigestSHA256(data []byte) (string, error) {
	var envelope CommandEnvelope
	if err := strictDecode(data, &envelope); err != nil {
		return "", validationErr(CodeSchemaInvalid, "envelope", err.Error())
	}
	return PayloadDigestSHA256(envelope.Payload)
}

func PayloadDigestSHA256(payload any) (string, error) {
	body, err := CanonicalPayloadBytes(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// JCSCanonicalBytes returns the RFC 8785 JSON Canonicalization Scheme byte
// form used by RM-2 ed25519-jcs-v1 signatures and digest comparisons.
func JCSCanonicalBytes(data []byte) ([]byte, error) {
	return canonicalRawJSON(data)
}

func CanonicalPayloadBytes(payload any) ([]byte, error) {
	switch value := payload.(type) {
	case nil:
		return nil, validationErr(CodeSchemaInvalid, "payload", "is required")
	case json.RawMessage:
		return canonicalRawJSON(value)
	case []byte:
		return canonicalRawJSON(value)
	case string:
		return canonicalRawJSON([]byte(value))
	default:
		if err := validateProgrammaticJSONValue(value); err != nil {
			return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
		}
		body, err := json.Marshal(value)
		if err != nil {
			return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
		}
		return canonicalRawJSON(body)
	}
}

func strictDecode(data []byte, v any) error {
	if err := rejectDuplicateObjectNames(data, true); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON")
		}
		return err
	}
	return nil
}

func canonicalRawJSON(data []byte) ([]byte, error) {
	if err := rejectDuplicateObjectNames(data, false); err != nil {
		return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, validationErr(CodeSchemaInvalid, "payload", "unexpected trailing JSON")
		}
		return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
	}
	normalized, err := normalizeCanonicalJSONValue(value)
	if err != nil {
		return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
	}
	body, err := marshalCanonicalJSON(normalized)
	if err != nil {
		return nil, validationErr(CodeSchemaInvalid, "payload", err.Error())
	}
	return body, nil
}

func rejectDuplicateObjectNames(data []byte, rejectSchemaCaseVariants bool) error {
	if err := rejectInvalidJSONStringEncoding(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := rejectDuplicateObjectNamesValue(decoder, rejectSchemaCaseVariants); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON")
		}
		return err
	}
	return nil
}

func rejectDuplicateObjectNamesValue(decoder *json.Decoder, rejectSchemaCaseVariants bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if rejectSchemaCaseVariants && schemaFieldCaseVariant(key) {
				return fmt.Errorf("JSON field %q must use exact schema casing", key)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateObjectNamesValue(decoder, rejectSchemaCaseVariants); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := rejectDuplicateObjectNamesValue(decoder, rejectSchemaCaseVariants); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func rejectInvalidJSONStringEncoding(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON input must be valid UTF-8")
	}
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		switch {
		case !inString:
			if data[i] == '"' {
				inString = true
			}
		case escaped:
			if data[i] == 'u' {
				codePoint, ok := readJSONUnicodeEscape(data, i+1)
				if !ok {
					return errors.New("invalid JSON unicode escape")
				}
				switch {
				case isHighSurrogate(codePoint):
					next := i + 5
					if next+5 >= len(data) || data[next] != '\\' || data[next+1] != 'u' {
						return errors.New("high surrogate must be followed by low surrogate")
					}
					low, ok := readJSONUnicodeEscape(data, next+2)
					if !ok || !isLowSurrogate(low) {
						return errors.New("high surrogate must be followed by low surrogate")
					}
					i = next + 5
				case isLowSurrogate(codePoint):
					return errors.New("low surrogate without preceding high surrogate")
				default:
					i += 4
				}
			}
			escaped = false
		case data[i] == '\\':
			escaped = true
		case data[i] == '"':
			inString = false
		}
	}
	return nil
}

func validateProgrammaticJSONValue(value any) error {
	return validateProgrammaticJSONReflect(reflect.ValueOf(value))
}

func validateProgrammaticJSONReflect(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		return validateProgrammaticJSONReflect(value.Elem())
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return errors.New("JSON string must be valid UTF-8")
		}
	case reflect.Map:
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			if key.Kind() == reflect.String && !utf8.ValidString(key.String()) {
				return errors.New("JSON object key must be valid UTF-8")
			}
			if err := validateProgrammaticJSONReflect(iter.Value()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if err := validateProgrammaticJSONReflect(value.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			if err := validateProgrammaticJSONReflect(value.Field(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func readJSONUnicodeEscape(data []byte, offset int) (rune, bool) {
	if offset+4 > len(data) {
		return 0, false
	}
	var value rune
	for _, b := range data[offset : offset+4] {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value += rune(b - '0')
		case b >= 'a' && b <= 'f':
			value += rune(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value += rune(b-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func isHighSurrogate(value rune) bool {
	return value >= 0xd800 && value <= 0xdbff
}

func isLowSurrogate(value rune) bool {
	return value >= 0xdc00 && value <= 0xdfff
}

func schemaFieldCaseVariant(key string) bool {
	if _, ok := exactSchemaJSONFields[key]; ok {
		return false
	}
	for exact := range exactSchemaJSONFields {
		if strings.EqualFold(key, exact) {
			return true
		}
	}
	return false
}

func normalizeCanonicalJSONValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			normalized, err := normalizeCanonicalJSONValue(nested)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(typed))
		for _, nested := range typed {
			normalized, err := normalizeCanonicalJSONValue(nested)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
		return out, nil
	case json.Number:
		return canonicalJSONNumber(typed)
	default:
		return typed, nil
	}
}

func canonicalJSONNumber(number json.Number) (json.Number, error) {
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "", fmt.Errorf("invalid JSON number %q", number.String())
	}
	return json.Number(formatJCSNumber(value)), nil
}

func formatJCSNumber(value float64) string {
	if value == 0 {
		return "0"
	}
	absolute := math.Abs(value)
	if absolute >= 1e-6 && absolute < 1e21 {
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	return normalizeJCSExponent(strconv.FormatFloat(value, 'e', -1, 64))
}

func normalizeJCSExponent(value string) string {
	i := strings.IndexAny(value, "eE")
	if i < 0 {
		return value
	}
	mantissa := value[:i]
	exponent := value[i+1:]
	sign := "+"
	if strings.HasPrefix(exponent, "-") {
		sign = "-"
		exponent = strings.TrimPrefix(exponent, "-")
	} else {
		exponent = strings.TrimPrefix(exponent, "+")
	}
	exponent = strings.TrimLeft(exponent, "0")
	if exponent == "" {
		exponent = "0"
	}
	return mantissa + "e" + sign + exponent
}

func marshalCanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16CodeUnits(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSONString(buf, key); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, nested := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, nested); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case json.Number:
		buf.WriteString(typed.String())
		return nil
	case string:
		return writeCanonicalJSONString(buf, typed)
	case bool, nil:
		body, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		buf.Write(body)
		return nil
	default:
		body, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		buf.Write(body)
		return nil
	}
}

func compareUTF16CodeUnits(a, b string) int {
	left := utf16.Encode([]rune(a))
	right := utf16.Encode([]rune(b))
	for i := 0; i < len(left) && i < len(right); i++ {
		switch {
		case left[i] < right[i]:
			return -1
		case left[i] > right[i]:
			return 1
		}
	}
	switch {
	case len(left) < len(right):
		return -1
	case len(left) > len(right):
		return 1
	default:
		return 0
	}
}

func writeCanonicalJSONString(buf *bytes.Buffer, value string) error {
	buf.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				writeCanonicalJSONControlEscape(buf, r)
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return nil
}

func writeCanonicalJSONControlEscape(buf *bytes.Buffer, value rune) {
	const hexDigits = "0123456789abcdef"
	buf.WriteString(`\u00`)
	buf.WriteByte(hexDigits[value>>4])
	buf.WriteByte(hexDigits[value&0xf])
}

func containsAll(haystack, needles []string) bool {
	seen := make(map[string]struct{}, len(haystack))
	for _, item := range haystack {
		item = strings.TrimSpace(item)
		if item != "" {
			seen[item] = struct{}{}
		}
	}
	for _, item := range needles {
		item = strings.TrimSpace(item)
		if item == "" {
			return false
		}
		if _, ok := seen[item]; !ok {
			return false
		}
	}
	return true
}

func isSHA256Hex(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
