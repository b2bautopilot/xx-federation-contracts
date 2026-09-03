package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	PathDirect = "direct"
	PathRelay  = "relay"

	DirectModePreferred = "direct_preferred"
	DirectModeDisabled  = "direct_disabled"
	DirectModeRequired  = "direct_required"

	StateUnknown              = "unknown"
	StateDirectReady          = "direct_ready"
	StateRelayReady           = "relay_ready"
	StateDirectUnavailable    = "direct_unavailable"
	StateBootstrapUnavailable = "bootstrap_unavailable"
	StateRelayUnavailable     = "relay_unavailable"
	StateIdentityMismatch     = "identity_mismatch"

	ErrorIdentityRequired      = "identity_required"
	ErrorIdentityMismatch      = "identity_mismatch"
	ErrorDirectUnavailable     = "direct_unavailable"
	ErrorBootstrapUnavailable  = "bootstrap_unavailable"
	ErrorRelayUnavailable      = "relay_unavailable"
	ErrorRelayPayloadKey       = "relay_payload_key_required"
	ErrorRelayPayloadEncrypted = "relay_payload_encryption_failed"
)

var (
	ErrIdentityRequired     = errors.New(ErrorIdentityRequired)
	ErrDirectUnavailable    = errors.New(ErrorDirectUnavailable)
	ErrBootstrapUnavailable = errors.New(ErrorBootstrapUnavailable)
	ErrRelayUnavailable     = errors.New(ErrorRelayUnavailable)
	ErrRelayPayloadKey      = errors.New(ErrorRelayPayloadKey)
)

type Identity struct {
	TenantID              string
	GatewayID             string
	ServicePrincipalID    string
	SPIFFEID              string
	Subject               string
	FingerprintSHA256     string
	TrustRootID           string
	TrustRootBundleSHA256 string
}

type BootstrapServer struct {
	Endpoint            string
	TrustRootRef        string
	RendezvousNamespace string
}

type Policy struct {
	DirectMode           string
	RelayFallbackAllowed bool
}

type Request struct {
	PartnerLinkID          string
	LocalIdentity          Identity
	ExpectedRemoteIdentity Identity
	Policy                 Policy
	BootstrapServers       []BootstrapServer
	BusinessPayload        []byte
	RelayPayloadKeyID      string
	RelayPayloadKey        []byte
}

type Result struct {
	PartnerLinkID               string
	Path                        string
	State                       string
	ErrorCode                   string
	ErrorMessage                string
	AuthenticatedRemoteIdentity Identity
	BootstrapServer             BootstrapServer
	RelayFrame                  RelayFrame
}

type DirectRequest struct {
	PartnerLinkID          string
	LocalIdentity          Identity
	ExpectedRemoteIdentity Identity
}

type DirectSession struct {
	RemoteIdentity Identity
}

type DirectConnector interface {
	OpenDirect(context.Context, DirectRequest) (DirectSession, error)
}

type RelayRequest struct {
	PartnerLinkID          string
	LocalIdentity          Identity
	ExpectedRemoteIdentity Identity
	BootstrapServer        BootstrapServer
	Frame                  RelayFrame
}

type RelaySession struct {
	RemoteIdentity Identity
}

type RelayConnector interface {
	OpenRelay(context.Context, RelayRequest) (RelaySession, error)
}

type RelayFrame struct {
	KeyID          string
	Nonce          []byte
	Ciphertext     []byte
	AssociatedData []byte
}

// MetricsRecorder is the single-method observability hook used by the Negotiator
// to record relay-fallback transitions. It replaces the previously-imported
// builders-net metrics registry so this contracts package has zero builders-net
// dependency (contracts invariant 5).
type MetricsRecorder interface {
	RecordFederationGatewayRelayFallback(outcome string)
}

type Negotiator struct {
	Direct  DirectConnector
	Relay   RelayConnector
	Random  io.Reader
	Metrics MetricsRecorder
}

func NewNegotiator(direct DirectConnector, relay RelayConnector) Negotiator {
	return Negotiator{Direct: direct, Relay: relay, Random: rand.Reader}
}

func (n Negotiator) WithMetrics(recorder MetricsRecorder) Negotiator {
	n.Metrics = recorder
	return n
}

func (n Negotiator) Negotiate(ctx context.Context, req Request) (Result, error) {
	req = normalizeRequest(req)
	out := Result{PartnerLinkID: req.PartnerLinkID, State: StateUnknown}
	if !req.LocalIdentity.HasServiceIdentity() || !req.ExpectedRemoteIdentity.HasServiceIdentity() {
		return out, ErrIdentityRequired
	}

	if req.Policy.DirectMode != DirectModeDisabled {
		directResult, directErr := n.tryDirect(ctx, req)
		switch directResult.State {
		case StateDirectReady, StateIdentityMismatch:
			return directResult, nil
		case StateDirectUnavailable:
			if req.Policy.DirectMode == DirectModeRequired || !req.Policy.RelayFallbackAllowed {
				return directResult, directErr
			}
			n.recordRelayFallback("attempt")
		}
	}

	if !req.Policy.RelayFallbackAllowed {
		return Result{
			PartnerLinkID: req.PartnerLinkID,
			State:         StateDirectUnavailable,
			ErrorCode:     ErrorDirectUnavailable,
			ErrorMessage:  "direct transport unavailable and relay fallback is disabled",
		}, nil
	}
	if len(req.BootstrapServers) == 0 {
		if req.Policy.DirectMode != DirectModeDisabled {
			n.recordRelayFallback("failure")
		}
		return Result{
			PartnerLinkID: req.PartnerLinkID,
			State:         StateBootstrapUnavailable,
			ErrorCode:     ErrorBootstrapUnavailable,
			ErrorMessage:  "no bootstrap servers configured for relay fallback",
		}, nil
	}
	result, err := n.tryRelay(ctx, req)
	if req.Policy.DirectMode != DirectModeDisabled {
		if result.State == StateRelayReady {
			n.recordRelayFallback("success")
		} else {
			n.recordRelayFallback("failure")
		}
	}
	return result, err
}

// tryDirect opens the direct path. The public Result carries only fixed,
// sanitized messages (connector errors may embed endpoints, private
// addresses, or SPIFFE internals and must never surface there); the raw
// connector cause is returned as the Go error — the local-diagnostics-only
// channel — and is never persisted or forwarded.
func (n Negotiator) tryDirect(ctx context.Context, req Request) (Result, error) {
	out := Result{PartnerLinkID: req.PartnerLinkID, Path: PathDirect}
	if n.Direct == nil {
		out.State = StateDirectUnavailable
		out.ErrorCode = ErrorDirectUnavailable
		out.ErrorMessage = "direct connector is not configured"
		return out, nil
	}
	session, err := n.Direct.OpenDirect(ctx, DirectRequest{
		PartnerLinkID:          req.PartnerLinkID,
		LocalIdentity:          req.LocalIdentity,
		ExpectedRemoteIdentity: req.ExpectedRemoteIdentity,
	})
	if err != nil {
		out.State = StateDirectUnavailable
		out.ErrorCode = ErrorDirectUnavailable
		out.ErrorMessage = "direct transport unavailable"
		return out, err
	}
	if !MatchesExpectedIdentity(session.RemoteIdentity, req.ExpectedRemoteIdentity) {
		out.State = StateIdentityMismatch
		out.ErrorCode = ErrorIdentityMismatch
		out.ErrorMessage = "direct remote identity does not match expected gateway identity"
		return out, nil
	}
	out.State = StateDirectReady
	out.AuthenticatedRemoteIdentity = session.RemoteIdentity.Normalized()
	return out, nil
}

func (n Negotiator) recordRelayFallback(outcome string) {
	if n.Metrics != nil {
		n.Metrics.RecordFederationGatewayRelayFallback(outcome)
	}
}

func (n Negotiator) tryRelay(ctx context.Context, req Request) (Result, error) {
	out := Result{
		PartnerLinkID: req.PartnerLinkID,
		Path:          PathRelay,
	}
	if n.Relay == nil {
		out.State = StateRelayUnavailable
		out.ErrorCode = ErrorRelayUnavailable
		out.ErrorMessage = "relay connector is not configured"
		return out, nil
	}
	frame, err := n.relayFrame(req)
	if err != nil {
		out.State = StateRelayUnavailable
		out.ErrorCode = ErrorRelayPayloadEncrypted
		out.ErrorMessage = "relay payload encryption failed"
		return out, err
	}
	var last Result
	for _, server := range req.BootstrapServers {
		attempt := Result{
			PartnerLinkID:   req.PartnerLinkID,
			Path:            PathRelay,
			BootstrapServer: server,
			RelayFrame:      frame,
		}
		session, err := n.Relay.OpenRelay(ctx, RelayRequest{
			PartnerLinkID:          req.PartnerLinkID,
			LocalIdentity:          req.LocalIdentity,
			ExpectedRemoteIdentity: req.ExpectedRemoteIdentity,
			BootstrapServer:        server,
			Frame:                  frame,
		})
		if err != nil {
			if errors.Is(err, ErrBootstrapUnavailable) {
				attempt.State = StateBootstrapUnavailable
				attempt.ErrorCode = ErrorBootstrapUnavailable
				attempt.ErrorMessage = "bootstrap relay unavailable"
				attempt.BootstrapServer = BootstrapServer{}
				last = attempt
				continue
			} else {
				attempt.State = StateRelayUnavailable
				attempt.ErrorCode = ErrorRelayUnavailable
				attempt.ErrorMessage = "relay unavailable"
			}
			return attempt, nil
		}
		if !MatchesExpectedIdentity(session.RemoteIdentity, req.ExpectedRemoteIdentity) {
			attempt.State = StateIdentityMismatch
			attempt.ErrorCode = ErrorIdentityMismatch
			attempt.ErrorMessage = "relay remote identity does not match expected gateway identity"
			return attempt, nil
		}
		attempt.State = StateRelayReady
		attempt.AuthenticatedRemoteIdentity = session.RemoteIdentity.Normalized()
		return attempt, nil
	}
	if last.State != "" {
		return last, nil
	}
	out.State = StateBootstrapUnavailable
	out.ErrorCode = ErrorBootstrapUnavailable
	out.ErrorMessage = "no bootstrap servers configured for relay fallback"
	return out, nil
}

func (n Negotiator) relayFrame(req Request) (RelayFrame, error) {
	if len(req.BusinessPayload) == 0 {
		return RelayFrame{}, nil
	}
	aad := relayPayloadAssociatedData(req.PartnerLinkID, req.LocalIdentity, req.ExpectedRemoteIdentity)
	reader := n.Random
	if reader == nil {
		reader = rand.Reader
	}
	return SealRelayPayload(req.BusinessPayload, req.RelayPayloadKeyID, req.RelayPayloadKey, aad, reader)
}

func SealRelayPayload(plaintext []byte, keyID string, key []byte, associatedData []byte, random io.Reader) (RelayFrame, error) {
	if len(key) == 0 || strings.TrimSpace(keyID) == "" {
		return RelayFrame{}, ErrRelayPayloadKey
	}
	if random == nil {
		random = rand.Reader
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return RelayFrame{}, fmt.Errorf("%w: %v", ErrRelayPayloadKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return RelayFrame{}, fmt.Errorf("%w: %v", ErrRelayPayloadKey, err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return RelayFrame{}, fmt.Errorf("generate relay nonce: %w", err)
	}
	aad := append([]byte(nil), associatedData...)
	return RelayFrame{
		KeyID:          strings.TrimSpace(keyID),
		Nonce:          nonce,
		Ciphertext:     aead.Seal(nil, nonce, plaintext, aad),
		AssociatedData: aad,
	}, nil
}

func OpenRelayPayload(frame RelayFrame, key []byte, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRelayPayloadKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRelayPayloadKey, err)
	}
	return aead.Open(nil, frame.Nonce, frame.Ciphertext, associatedData)
}

// relayPayloadAssociatedData builds the AES-GCM associated data binding a
// sealed relay payload to its partner link and both transport identities.
// The encoding is unambiguous and deterministic: a big-endian field count
// followed by big-endian length-delimited fields, so no two distinct field
// tuples can produce identical bytes at a field boundary (a bare separator
// join would collide, e.g. ("a|b","c") vs ("a","b|c")).
func relayPayloadAssociatedData(partnerLinkID string, local, expectedRemote Identity) []byte {
	local = local.Normalized()
	expectedRemote = expectedRemote.Normalized()
	fields := []string{
		strings.TrimSpace(partnerLinkID),
		local.TenantID,
		local.GatewayID,
		local.ServicePrincipalID,
		local.SPIFFEID,
		local.Subject,
		local.FingerprintSHA256,
		local.TrustRootID,
		local.TrustRootBundleSHA256,
		expectedRemote.TenantID,
		expectedRemote.GatewayID,
		expectedRemote.ServicePrincipalID,
		expectedRemote.SPIFFEID,
		expectedRemote.Subject,
		expectedRemote.FingerprintSHA256,
		expectedRemote.TrustRootID,
		expectedRemote.TrustRootBundleSHA256,
	}
	out := make([]byte, 0, 8+len(fields)*4)
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(fields)))
	out = append(out, count[:]...)
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		out = append(out, length[:]...)
		out = append(out, field...)
	}
	return out
}

// MatchesExpectedIdentity reports whether the authenticated actual identity
// satisfies the expected gateway binding, fail-closed. Tenant and gateway must
// always match exactly. Beyond that, production matching requires an explicit
// cryptographic binding: the expected identity must pin the SPIFFE ID or the
// key fingerprint, and the actual identity must carry the same value. An
// expected identity with only tenant/gateway (plus display-level service
// fields) never matches — unpopulated binding fields are not wildcards.
func MatchesExpectedIdentity(actual, expected Identity) bool {
	actual = actual.Normalized()
	expected = expected.Normalized()
	if actual.TenantID == "" || actual.GatewayID == "" ||
		actual.TenantID != expected.TenantID || actual.GatewayID != expected.GatewayID {
		return false
	}
	if expected.SPIFFEID == "" && expected.FingerprintSHA256 == "" {
		return false
	}
	if expected.SPIFFEID != "" && actual.SPIFFEID != expected.SPIFFEID {
		return false
	}
	if expected.FingerprintSHA256 != "" && actual.FingerprintSHA256 != expected.FingerprintSHA256 {
		return false
	}
	if expected.Subject != "" && actual.Subject != expected.Subject {
		return false
	}
	if expected.TrustRootID != "" && actual.TrustRootID != expected.TrustRootID {
		return false
	}
	if expected.TrustRootBundleSHA256 != "" && actual.TrustRootBundleSHA256 != expected.TrustRootBundleSHA256 {
		return false
	}
	if expected.ServicePrincipalID != "" && actual.ServicePrincipalID != expected.ServicePrincipalID {
		return false
	}
	return expected.HasServiceIdentity() && actual.HasServiceIdentity()
}

func (i Identity) HasServiceIdentity() bool {
	i = i.Normalized()
	return i.TenantID != "" && i.GatewayID != "" &&
		(i.SPIFFEID != "" || i.FingerprintSHA256 != "" || i.Subject != "" || i.ServicePrincipalID != "")
}

func (i Identity) Normalized() Identity {
	return Identity{
		TenantID:              strings.TrimSpace(i.TenantID),
		GatewayID:             strings.TrimSpace(i.GatewayID),
		ServicePrincipalID:    strings.TrimSpace(i.ServicePrincipalID),
		SPIFFEID:              strings.TrimSpace(i.SPIFFEID),
		Subject:               strings.TrimSpace(i.Subject),
		FingerprintSHA256:     strings.ToLower(strings.TrimSpace(i.FingerprintSHA256)),
		TrustRootID:           strings.TrimSpace(i.TrustRootID),
		TrustRootBundleSHA256: strings.ToLower(strings.TrimSpace(i.TrustRootBundleSHA256)),
	}
}

func normalizeRequest(req Request) Request {
	req.PartnerLinkID = strings.TrimSpace(req.PartnerLinkID)
	req.LocalIdentity = req.LocalIdentity.Normalized()
	req.ExpectedRemoteIdentity = req.ExpectedRemoteIdentity.Normalized()
	req.Policy = req.Policy.Normalized()
	req.BootstrapServers = compactBootstrapServers(req.BootstrapServers)
	req.RelayPayloadKeyID = strings.TrimSpace(req.RelayPayloadKeyID)
	return req
}

func (p Policy) Normalized() Policy {
	p.DirectMode = strings.TrimSpace(p.DirectMode)
	if p.DirectMode == "" {
		p.DirectMode = DirectModePreferred
	}
	switch p.DirectMode {
	case DirectModePreferred, DirectModeDisabled, DirectModeRequired:
	default:
		p.DirectMode = DirectModePreferred
	}
	return p
}

func compactBootstrapServers(servers []BootstrapServer) []BootstrapServer {
	compacted := make([]BootstrapServer, 0, len(servers))
	seen := map[string]struct{}{}
	for _, server := range servers {
		endpoint := strings.TrimSpace(server.Endpoint)
		if endpoint == "" {
			continue
		}
		trustRootRef := strings.TrimSpace(server.TrustRootRef)
		rendezvousNamespace := strings.TrimSpace(server.RendezvousNamespace)
		key := strings.Join([]string{endpoint, trustRootRef, rendezvousNamespace}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		compacted = append(compacted, BootstrapServer{
			Endpoint:            endpoint,
			TrustRootRef:        trustRootRef,
			RendezvousNamespace: rendezvousNamespace,
		})
	}
	return compacted
}
