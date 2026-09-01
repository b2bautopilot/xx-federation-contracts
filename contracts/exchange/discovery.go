package exchange

import (
	"context"
	"encoding/json"
)

// Manifest discovery exchange (NE-7.3, V3 §6.2) — kills the circular
// out-of-band manifest copy. A partner that is already authenticated at
// the transport layer (mTLS through the relay or direct) asks the
// receiver for its *signed* service-contract manifest documents; the
// ed25519 signature — verified by the consumer against its pinned
// keyring — is the authority, not the transport. The action is
// deliberately manifest-independent: it cannot go through the normal
// preflight, which resolves a manifest the consumer does not have yet.
const (
	ActionDiscoverContractManifests = "discover_contract_manifests"
	// FacadeDiscoverContractManifests labels decisions/audits only; the
	// action dispatches to Handler.Discovery, NOT the control-plane Facade.
	FacadeDiscoverContractManifests = "DiscoverContractManifests"
	SchemaManifestDiscoveryV1       = "builders.federation.manifest_discovery.v1"
)

// SignedManifestDocument carries one signed manifest verbatim. Document
// is the raw signed JSON — re-marshalling a parsed manifest could break
// byte-level expectations of foreign verifiers, so the receiver serves
// the exact bytes it verified at load.
type SignedManifestDocument struct {
	ManifestID         string          `json:"manifest_id"`
	CatalogVersion     string          `json:"catalog_version"`
	SigningKeyID       string          `json:"signing_key_id"`
	ManifestHashSHA256 string          `json:"manifest_hash_sha256"`
	Document           json.RawMessage `json:"document"`
}

// ManifestDiscovery serves the local tenant's signed manifest documents
// visible to the authenticated partner link.
type ManifestDiscovery interface {
	DiscoverSignedManifests(context.Context, AuthenticatedSession) ([]SignedManifestDocument, error)
}

// ManifestDiscoveryResult is the allow-path dispatch payload.
type ManifestDiscoveryResult struct {
	SchemaVersion string                   `json:"schema_version"`
	Manifests     []SignedManifestDocument `json:"manifests"`
}

// handleManifestDiscovery is the manifest-independent preflight + dispatch
// for ActionDiscoverContractManifests. It enforces the same session,
// expiry, and replay gates as the normal preflight, minus everything that
// presumes an installed manifest (contract resolution, approval pins,
// payload schemas). The request payload must be empty.
func (h *Handler) handleManifestDiscovery(ctx context.Context, session AuthenticatedSession, env Envelope) (Response, error) {
	action := ActionContract{
		Action:       ActionDiscoverContractManifests,
		FacadeMethod: FacadeDiscoverContractManifests,
	}
	refuse := func(code string) (Response, error) {
		decision := deny(session, env, code, Manifest{}, action)
		if err := h.audit(ctx, decision); err != nil {
			return Response{}, err
		}
		return Response{Decision: decision}, nil
	}
	if env.SchemaVersion != SchemaGatewayExchangeV1 {
		return refuse(ErrorPayloadInvalid)
	}
	if !sessionMatchesEnvelope(session, env) {
		return refuse(ErrorUnauthenticated)
	}
	if session.KillSwitchEnabled {
		return refuse(ErrorKillSwitch)
	}
	if session.PartnerLinkState != PartnerLinkActive {
		return refuse(ErrorPartnerLinkDenied)
	}
	if now := h.now(); env.ExpiresAtMS <= 0 || now > env.ExpiresAtMS+h.ClockSkewMS {
		return refuse(ErrorExpired)
	}
	if len(env.Payload) != 0 {
		return refuse(ErrorPayloadInvalid)
	}
	if h.Replay != nil {
		if err := h.Replay.Claim(ctx, ReplayClaim{
			EnvelopeID:     env.EnvelopeID,
			IdempotencyKey: env.IdempotencyKey,
			ExpiresAtMS:    env.ExpiresAtMS,
		}); err != nil {
			return refuse(ErrorReplayDetected)
		}
	}
	if h.Discovery == nil {
		return refuse(ErrorGatewayUnavailable)
	}
	documents, err := h.Discovery.DiscoverSignedManifests(ctx, session)
	if err != nil {
		code := facadeDenialCode(err)
		decision := deny(session, env, code, Manifest{}, action)
		if auditErr := h.audit(ctx, decision); auditErr != nil {
			return Response{}, auditErr
		}
		return Response{Decision: decision, Error: &ErrorInfo{Code: code, Message: err.Error()}}, nil
	}
	if documents == nil {
		documents = []SignedManifestDocument{}
	}
	payload, err := json.Marshal(ManifestDiscoveryResult{
		SchemaVersion: SchemaManifestDiscoveryV1,
		Manifests:     documents,
	})
	if err != nil {
		return refuse(ErrorGatewayUnavailable)
	}
	result := DispatchResult{Status: "ok", PayloadJSON: string(payload)}
	if err := validateDispatchResult(result); err != nil {
		return refuse(ErrorPayloadInvalid)
	}
	decision := allow(session, env, Manifest{}, action)
	if err := h.audit(ctx, decision); err != nil {
		return Response{}, err
	}
	return Response{Decision: decision, Result: result}, nil
}
