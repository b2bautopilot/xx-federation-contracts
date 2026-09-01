package identity_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/identity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestRuntimeIdentityFromCertificateURI(t *testing.T) {
	ctx := peerContextWithURI(t, identity.RuntimeURI(identity.RuntimeIdentity{
		TenantID:   "tenant-1",
		ProjectID:  "project-1",
		SessionID:  "session-1",
		WorkloadID: "workload-1",
	}))

	identity, err := identity.RuntimeIdentityFromContext(ctx)

	if err != nil {
		t.Fatalf("RuntimeIdentityFromContext returned error: %v", err)
	}
	if identity.TenantID != "tenant-1" || identity.ProjectID != "project-1" ||
		identity.SessionID != "session-1" || identity.WorkloadID != "workload-1" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestAgentIdentityFromCertificateURI(t *testing.T) {
	ctx := peerContextWithURI(t, identity.AgentURI(identity.AgentIdentity{
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		NodeID:    "node-1",
	}))

	identity, err := identity.AgentIdentityFromContext(ctx)

	if err != nil {
		t.Fatalf("AgentIdentityFromContext returned error: %v", err)
	}
	if identity.TenantID != "tenant-1" || identity.ProjectID != "project-1" || identity.NodeID != "node-1" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestGatewayIdentityFromCertificateURI(t *testing.T) {
	ctx := peerContextWithCertificate(t, identity.GatewayURI(identity.GatewayIdentity{
		TenantID:  "tenant-1",
		GatewayID: "gateway-1",
	}), []byte("gateway-cert-der"))

	identity, err := identity.GatewayIdentityFromContext(ctx)

	if err != nil {
		t.Fatalf("GatewayIdentityFromContext returned error: %v", err)
	}
	if identity.TenantID != "tenant-1" || identity.GatewayID != "gateway-1" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if identity.SPIFFEID != "spiffe://builders-net/federation-gateway/tenant/tenant-1/gateway/gateway-1" {
		t.Fatalf("unexpected spiffe id %q", identity.SPIFFEID)
	}
	if _, err := hex.DecodeString(identity.FingerprintSHA256); identity.FingerprintSHA256 == "" || err != nil {
		t.Fatalf("fingerprint was not hex encoded: %q", identity.FingerprintSHA256)
	}
}

func TestGatewayIdentityFromCertificateURIWithServicePrincipal(t *testing.T) {
	ctx := peerContextWithCertificate(t, identity.GatewayURI(identity.GatewayIdentity{
		TenantID:           "tenant-1",
		GatewayID:          "gateway-1",
		ServicePrincipalID: "spn://company-a/gateway-primary",
	}), []byte("gateway-cert-der"))

	identity, err := identity.GatewayIdentityFromContext(ctx)

	if err != nil {
		t.Fatalf("GatewayIdentityFromContext returned error: %v", err)
	}
	if identity.TenantID != "tenant-1" || identity.GatewayID != "gateway-1" ||
		identity.ServicePrincipalID != "spn://company-a/gateway-primary" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if identity.SPIFFEID != "spiffe://builders-net/federation-gateway/tenant/tenant-1/gateway/gateway-1/service-principal/spn:%2F%2Fcompany-a%2Fgateway-primary" {
		t.Fatalf("unexpected spiffe id %q", identity.SPIFFEID)
	}
}

func TestRuntimeIdentityRejectsMissingCertificateIdentity(t *testing.T) {
	ctx := peerContextWithURI(t, "spiffe://other/runtime/tenant/tenant/project/project/session/session/workload/workload")

	_, err := identity.RuntimeIdentityFromContext(ctx)

	if err == nil {
		t.Fatal("expected missing builders-net identity to be rejected")
	}
}

func peerContextWithURI(t *testing.T, rawURI string) context.Context {
	t.Helper()
	return peerContextWithCertificate(t, rawURI, nil)
}

func peerContextWithCertificate(t *testing.T, rawURI string, raw []byte) context.Context {
	t.Helper()
	parsed, err := url.Parse(rawURI)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{parsed}, Raw: raw}}},
		},
	})
}
