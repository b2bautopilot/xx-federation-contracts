package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/b2bautopilot/xx-federation-contracts/apperrors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const trustDomain = "builders-net"

type RuntimeIdentity struct {
	TenantID   string
	ProjectID  string
	SessionID  string
	WorkloadID string
}

type AgentIdentity struct {
	TenantID  string
	ProjectID string
	NodeID    string
}

type GatewayIdentity struct {
	TenantID           string
	GatewayID          string
	ServicePrincipalID string
	SPIFFEID           string
	Subject            string
	FingerprintSHA256  string
}

func RuntimeIdentityFromContext(ctx context.Context) (RuntimeIdentity, error) {
	cert, err := peerCertificate(ctx)
	if err != nil {
		return RuntimeIdentity{}, err
	}
	for _, uri := range cert.URIs {
		identity, ok := parseRuntimeURI(uri)
		if ok {
			return identity, nil
		}
	}
	return RuntimeIdentity{}, apperrors.New(apperrors.CodeAuthUnauthorized, "runtime", "runtime certificate is missing builders-net workload identity")
}

func AgentIdentityFromContext(ctx context.Context) (AgentIdentity, error) {
	cert, err := peerCertificate(ctx)
	if err != nil {
		return AgentIdentity{}, err
	}
	for _, uri := range cert.URIs {
		identity, ok := parseAgentURI(uri)
		if ok {
			return identity, nil
		}
	}
	return AgentIdentity{}, apperrors.New(apperrors.CodeAuthUnauthorized, "agent", "agent certificate is missing builders-net node identity")
}

func GatewayIdentityFromContext(ctx context.Context) (GatewayIdentity, error) {
	identity, ok, err := GatewayIdentityFromContextIfPresent(ctx)
	if err != nil {
		return GatewayIdentity{}, err
	}
	if !ok {
		return GatewayIdentity{}, apperrors.New(apperrors.CodeAuthUnauthorized, "federation", "gateway certificate is missing builders-net gateway identity")
	}
	return identity, nil
}

func GatewayIdentityFromContextIfPresent(ctx context.Context) (GatewayIdentity, bool, error) {
	cert, err := peerCertificate(ctx)
	if err != nil {
		return GatewayIdentity{}, false, nil
	}
	return GatewayIdentityFromCertificateIfPresent(cert)
}

func GatewayIdentityFromCertificate(cert *x509.Certificate) (GatewayIdentity, error) {
	identity, ok, err := GatewayIdentityFromCertificateIfPresent(cert)
	if err != nil {
		return GatewayIdentity{}, err
	}
	if !ok {
		return GatewayIdentity{}, apperrors.New(apperrors.CodeAuthUnauthorized, "federation", "gateway certificate is missing builders-net gateway identity")
	}
	return identity, nil
}

func GatewayIdentityFromCertificateIfPresent(cert *x509.Certificate) (GatewayIdentity, bool, error) {
	if cert == nil {
		return GatewayIdentity{}, false, nil
	}
	for _, uri := range cert.URIs {
		identity, ok := parseGatewayURI(uri)
		if ok {
			identity.SPIFFEID = uri.String()
			identity.Subject = cert.Subject.String()
			identity.FingerprintSHA256 = CertificateFingerprintSHA256(cert)
			return identity, true, nil
		}
	}
	return GatewayIdentity{}, false, nil
}

func CertificateFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func peerCertificate(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, apperrors.New(apperrors.CodeAuthUnauthorized, "mtls", "mTLS peer information is required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, apperrors.New(apperrors.CodeAuthUnauthorized, "mtls", "mTLS transport is required")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, apperrors.New(apperrors.CodeAuthUnauthorized, "mtls", "mTLS peer certificate is required")
	}
	return tlsInfo.State.PeerCertificates[0], nil
}

// PeerCertificateFromContext returns the verified mTLS leaf certificate the peer
// presented, if any. ok=false (with a nil error) when there is no mTLS peer or no
// client certificate, so an authenticator can fall back to another evidence scheme
// instead of failing closed. The certificate chain is owned by the server's
// RequireAndVerifyClientCert; this only surfaces the already-verified leaf for callers
// that must read an identity under a non-federation-gateway SPIFFE scheme (e.g. the
// relay-client plane), which GatewayIdentityFromContextIfPresent does not parse.
func PeerCertificateFromContext(ctx context.Context) (*x509.Certificate, bool, error) {
	cert, err := peerCertificate(ctx)
	if err != nil {
		return nil, false, nil
	}
	return cert, true, nil
}

func parseRuntimeURI(uri *url.URL) (RuntimeIdentity, bool) {
	parts, ok := identityParts(uri, "runtime", 9)
	if !ok {
		return RuntimeIdentity{}, false
	}
	if parts[1] != "tenant" || parts[3] != "project" || parts[5] != "session" || parts[7] != "workload" {
		return RuntimeIdentity{}, false
	}
	identity := RuntimeIdentity{
		TenantID:   parts[2],
		ProjectID:  parts[4],
		SessionID:  parts[6],
		WorkloadID: parts[8],
	}
	if identity.TenantID == "" || identity.ProjectID == "" || identity.SessionID == "" || identity.WorkloadID == "" {
		return RuntimeIdentity{}, false
	}
	return identity, true
}

func parseAgentURI(uri *url.URL) (AgentIdentity, bool) {
	parts, ok := identityParts(uri, "agent", 7)
	if !ok {
		return AgentIdentity{}, false
	}
	if parts[1] != "tenant" || parts[3] != "project" || parts[5] != "node" {
		return AgentIdentity{}, false
	}
	identity := AgentIdentity{
		TenantID:  parts[2],
		ProjectID: parts[4],
		NodeID:    parts[6],
	}
	if identity.TenantID == "" || identity.ProjectID == "" || identity.NodeID == "" {
		return AgentIdentity{}, false
	}
	return identity, true
}

func parseGatewayURI(uri *url.URL) (GatewayIdentity, bool) {
	if uri == nil || uri.Scheme != "spiffe" {
		return GatewayIdentity{}, false
	}
	if uri.Host == "relay.b2bautopilot.com" {
		parts := strings.Split(strings.Trim(uri.EscapedPath(), "/"), "/")
		if len(parts) == 8 && parts[0] == "fabric" && parts[1] == "b2bautopilot-fed" && parts[2] == "org" && parts[4] == "gateway" && parts[6] == "role" {
			identity := GatewayIdentity{
				TenantID:           unescapeIdentityPart(parts[3]),
				GatewayID:          unescapeIdentityPart(parts[5]),
				ServicePrincipalID: "spn-" + unescapeIdentityPart(parts[3]) + "-gateway",
			}
			return identity, true
		}
	}
	if uri.Host != trustDomain {
		return GatewayIdentity{}, false
	}
	parts := strings.Split(strings.Trim(uri.EscapedPath(), "/"), "/")
	if len(parts) != 5 && len(parts) != 7 {
		return GatewayIdentity{}, false
	}
	if parts[0] != "federation-gateway" {
		return GatewayIdentity{}, false
	}
	for _, part := range parts {
		if strings.TrimSpace(part) != part {
			return GatewayIdentity{}, false
		}
	}
	if parts[1] != "tenant" || parts[3] != "gateway" {
		return GatewayIdentity{}, false
	}
	identity := GatewayIdentity{
		TenantID:  unescapeIdentityPart(parts[2]),
		GatewayID: unescapeIdentityPart(parts[4]),
	}
	if len(parts) == 7 {
		if parts[5] != "service-principal" {
			return GatewayIdentity{}, false
		}
		identity.ServicePrincipalID = unescapeIdentityPart(parts[6])
	}
	if identity.TenantID == "" || identity.GatewayID == "" {
		return GatewayIdentity{}, false
	}
	if strings.TrimSpace(identity.TenantID) != identity.TenantID ||
		strings.TrimSpace(identity.GatewayID) != identity.GatewayID ||
		strings.TrimSpace(identity.ServicePrincipalID) != identity.ServicePrincipalID {
		return GatewayIdentity{}, false
	}
	if len(parts) == 7 && identity.ServicePrincipalID == "" {
		return GatewayIdentity{}, false
	}
	return identity, true
}

func identityParts(uri *url.URL, component string, wantParts int) ([]string, bool) {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != trustDomain {
		return nil, false
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if len(parts) != wantParts || parts[0] != component {
		return nil, false
	}
	for _, part := range parts {
		if strings.TrimSpace(part) != part {
			return nil, false
		}
	}
	return parts, true
}

func RuntimeURI(identity RuntimeIdentity) string {
	return fmt.Sprintf("spiffe://%s/runtime/tenant/%s/project/%s/session/%s/workload/%s", trustDomain, identity.TenantID, identity.ProjectID, identity.SessionID, identity.WorkloadID)
}

func AgentURI(identity AgentIdentity) string {
	return fmt.Sprintf("spiffe://%s/agent/tenant/%s/project/%s/node/%s", trustDomain, identity.TenantID, identity.ProjectID, identity.NodeID)
}

func GatewayURI(identity GatewayIdentity) string {
	if strings.TrimSpace(identity.ServicePrincipalID) != "" {
		return fmt.Sprintf("spiffe://%s/federation-gateway/tenant/%s/gateway/%s/service-principal/%s",
			trustDomain,
			url.PathEscape(identity.TenantID),
			url.PathEscape(identity.GatewayID),
			url.PathEscape(identity.ServicePrincipalID),
		)
	}
	return fmt.Sprintf("spiffe://%s/federation-gateway/tenant/%s/gateway/%s", trustDomain, url.PathEscape(identity.TenantID), url.PathEscape(identity.GatewayID))
}

func unescapeIdentityPart(part string) string {
	out, err := url.PathUnescape(part)
	if err != nil {
		return part
	}
	return out
}
