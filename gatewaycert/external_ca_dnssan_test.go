package gatewaycert_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert/testonly"
)

func parseIssuedLeafCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestIssueAddsRequestedDNSSANForTransportServerOnly proves the transport-server
// plane gets the request's DNS SAN (needed for the inner-mTLS ServerName check)
// while the relay-client plane stays SAN-free (unchanged behavior). The SAN comes
// only from the request field, never from the CSR.
func TestIssueAddsRequestedDNSSANForTransportServerOnly(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	provider, err := testonly.NewTestOnlyGatewayCertificateProvider(testonly.TestOnlyGatewayCertificateProviderOptions{
		NotBefore: now.Add(-time.Hour),
		TTL:       24 * time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewTestOnlyGatewayCertificateProvider error = %v", err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://csr.local/ignored")
	baseRequest := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:   "fabric-prod",
		OrgID:      "org-newco",
		GatewayID:  "gateway-newco-01",
		CommonName: "gateway-newco-01",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now.Add(-time.Minute),
		TTL:       time.Hour,
	}

	transportReq := baseRequest
	transportReq.DNSNames = []string{"newco-gateway.b2bautopilot.local"}
	transport, err := provider.IssueGatewayTransportServer(context.Background(), transportReq)
	if err != nil {
		t.Fatalf("IssueGatewayTransportServer error = %v", err)
	}
	transportCert := parseIssuedLeafCert(t, transport.CertificatePEM)
	if len(transportCert.DNSNames) != 1 || transportCert.DNSNames[0] != "newco-gateway.b2bautopilot.local" {
		t.Fatalf("transport-server DNSNames = %v, want [newco-gateway.b2bautopilot.local]", transportCert.DNSNames)
	}

	// relay-client with no requested DNS names → none on the issued cert
	relay, err := provider.IssueRelayClient(context.Background(), baseRequest)
	if err != nil {
		t.Fatalf("IssueRelayClient error = %v", err)
	}
	relayCert := parseIssuedLeafCert(t, relay.CertificatePEM)
	if len(relayCert.DNSNames) != 0 {
		t.Fatalf("relay-client DNSNames = %v, want none", relayCert.DNSNames)
	}
}
