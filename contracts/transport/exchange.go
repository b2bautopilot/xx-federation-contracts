package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/exchange"
)

var ErrExchangeHandlerRequired = errors.New("gateway exchange handler is required")
var ErrExchangeSessionResolverRequired = errors.New("gateway exchange session resolver is required")
var ErrExchangeSessionMismatch = errors.New("gateway exchange session does not match authenticated transport identity")

type ExchangeSessionResolver interface {
	ResolveGatewayExchangeSession(context.Context, ExchangeSessionInput) (exchange.AuthenticatedSession, error)
}

type ExchangeSessionInput struct {
	PartnerLinkID               string
	LocalIdentity               Identity
	AuthenticatedRemoteIdentity Identity
	Transport                   Result
}

type ExchangeRequest struct {
	PartnerLinkID          string
	LocalIdentity          Identity
	ExpectedRemoteIdentity Identity
	Policy                 Policy
	BootstrapServers       []BootstrapServer
	Envelope               exchange.Envelope
	RelayPayloadKeyID      string
	RelayPayloadKey        []byte
}

type ExchangeResult struct {
	Transport Result
	Response  exchange.Response
}

type ExchangeHarness struct {
	Negotiator      Negotiator
	Handler         *exchange.Handler
	SessionResolver ExchangeSessionResolver
}

func (h ExchangeHarness) Send(ctx context.Context, req ExchangeRequest) (ExchangeResult, error) {
	req = normalizeExchangeRequest(req)
	if h.Handler == nil {
		return ExchangeResult{}, ErrExchangeHandlerRequired
	}
	if h.SessionResolver == nil {
		return ExchangeResult{}, ErrExchangeSessionResolverRequired
	}
	payload, err := json.Marshal(req.Envelope)
	if err != nil {
		return ExchangeResult{}, fmt.Errorf("marshal gateway exchange envelope: %w", err)
	}
	result, err := h.Negotiator.Negotiate(ctx, Request{
		PartnerLinkID:          req.PartnerLinkID,
		LocalIdentity:          req.LocalIdentity,
		ExpectedRemoteIdentity: req.ExpectedRemoteIdentity,
		Policy:                 req.Policy,
		BootstrapServers:       req.BootstrapServers,
		BusinessPayload:        payload,
		RelayPayloadKeyID:      req.RelayPayloadKeyID,
		RelayPayloadKey:        req.RelayPayloadKey,
	})
	out := ExchangeResult{Transport: result}
	if err != nil {
		return out, err
	}
	var received exchange.Envelope
	switch result.State {
	case StateDirectReady:
		received = req.Envelope
	case StateRelayReady:
		received, err = openRelayExchangeEnvelope(req, result.RelayFrame)
		if err != nil {
			out.Transport.State = StateRelayUnavailable
			out.Transport.ErrorCode = ErrorRelayPayloadEncrypted
			out.Transport.ErrorMessage = err.Error()
			return out, err
		}
	default:
		return out, nil
	}
	session, err := h.SessionResolver.ResolveGatewayExchangeSession(ctx, ExchangeSessionInput{
		PartnerLinkID:               req.PartnerLinkID,
		LocalIdentity:               req.LocalIdentity,
		AuthenticatedRemoteIdentity: result.AuthenticatedRemoteIdentity,
		Transport:                   result,
	})
	if err != nil {
		return out, err
	}
	if !exchangeSessionMatchesTransport(session, req, result) {
		return out, ErrExchangeSessionMismatch
	}
	response, err := h.Handler.Handle(ctx, session, received)
	out.Response = response
	return out, err
}

func openRelayExchangeEnvelope(req ExchangeRequest, frame RelayFrame) (exchange.Envelope, error) {
	plaintext, err := OpenRelayPayload(frame, req.RelayPayloadKey, relayPayloadAssociatedData(req.PartnerLinkID, req.LocalIdentity, req.ExpectedRemoteIdentity))
	if err != nil {
		return exchange.Envelope{}, err
	}
	var env exchange.Envelope
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return exchange.Envelope{}, fmt.Errorf("open relay gateway exchange envelope: %w", err)
	}
	return env, nil
}

func normalizeExchangeRequest(req ExchangeRequest) ExchangeRequest {
	req.PartnerLinkID = strings.TrimSpace(req.PartnerLinkID)
	req.LocalIdentity = req.LocalIdentity.Normalized()
	req.ExpectedRemoteIdentity = req.ExpectedRemoteIdentity.Normalized()
	req.Policy = req.Policy.Normalized()
	req.BootstrapServers = compactBootstrapServers(req.BootstrapServers)
	req.RelayPayloadKeyID = strings.TrimSpace(req.RelayPayloadKeyID)
	return req
}

func exchangeSessionMatchesTransport(session exchange.AuthenticatedSession, req ExchangeRequest, result Result) bool {
	req = normalizeExchangeRequest(req)
	sessionLocal := Identity{
		TenantID:  session.LocalTenantID,
		GatewayID: session.LocalGatewayID,
	}.Normalized()
	authenticatedRemote := result.AuthenticatedRemoteIdentity.Normalized()
	if sessionLocal.TenantID != authenticatedRemote.TenantID ||
		sessionLocal.GatewayID != authenticatedRemote.GatewayID {
		return false
	}
	sessionRemote := Identity{
		TenantID:           session.RemoteTenantID,
		GatewayID:          session.RemoteGatewayID,
		ServicePrincipalID: session.RemoteServicePrincipalID,
	}.Normalized()
	if sessionRemote.TenantID != req.LocalIdentity.TenantID ||
		sessionRemote.GatewayID != req.LocalIdentity.GatewayID {
		return false
	}
	if req.LocalIdentity.ServicePrincipalID != "" &&
		sessionRemote.ServicePrincipalID != req.LocalIdentity.ServicePrincipalID {
		return false
	}
	return strings.TrimSpace(session.PartnerLinkID) == req.PartnerLinkID
}
