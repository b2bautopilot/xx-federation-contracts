package gatewaycert_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert/testonly"
	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

// Server-auth planes (gateway_transport, relay_cell_server) must bind the
// expected DNS hostname at verification time; client-auth planes keep their
// SPIFFE binding and never consult DNS.
func TestServerPlaneDNSBinding(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	provider, err := testonly.NewTestOnlyGatewayCertificateProvider(testonly.TestOnlyGatewayCertificateProviderOptions{
		NotBefore: now.Add(-time.Hour),
		TTL:       24 * time.Hour,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewTestOnlyGatewayCertificateProvider error = %v", err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	base := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now.Add(-time.Minute),
		TTL:       time.Hour,
	}
	const dnsName = "gateway-newco-01.b2bautopilot.local"

	withSANReq := base
	withSANReq.DNSNames = []string{dnsName}
	withSAN, err := provider.IssueGatewayTransportServer(context.Background(), withSANReq)
	if err != nil {
		t.Fatalf("IssueGatewayTransportServer error = %v", err)
	}
	verify := func(pem []byte, name string) error {
		_, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
			CertificatePEM:          pem,
			TrustRoots:              provider.TrustRoots(),
			ExpectedPlane:           gatewaycert.PlaneGatewayTransport,
			ExpectedSPIFFENamespace: gatewaycert.GatewayTransportNamespace,
			ExpectedServerDNSName:   name,
			Now:                     now,
		})
		return err
	}

	// Correct name verifies.
	if err := verify(withSAN.CertificatePEM, dnsName); err != nil {
		t.Errorf("correct DNS SAN rejected: %v", err)
	}
	// Wrong name fails closed.
	if err := verify(withSAN.CertificatePEM, "other-gateway.b2bautopilot.local"); !errorsIsPlaneMismatch(err) {
		t.Errorf("wrong DNS name error = %v, want plane mismatch", err)
	}
	// Missing expectation fails closed even for a well-formed server leaf.
	if err := verify(withSAN.CertificatePEM, ""); !errorsIsPlaneMismatch(err) {
		t.Errorf("missing DNS expectation error = %v, want plane mismatch", err)
	}
	// Missing SAN fails closed.
	noSAN, err := provider.IssueGatewayTransportServer(context.Background(), base)
	if err != nil {
		t.Fatalf("IssueGatewayTransportServer without DNS error = %v", err)
	}
	if err := verify(noSAN.CertificatePEM, dnsName); !errorsIsPlaneMismatch(err) {
		t.Errorf("missing DNS SAN error = %v, want plane mismatch", err)
	}
}

// A wildcard DNS SAN must be rejected even when x509 itself would accept the
// presented name — ServerName + RootCAs trust must never rest on an
// over-broad SAN.
func TestServerPlaneRejectsWildcardDNSAN(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	ca := backplaneTestCA(t, "transport test CA", now)
	spiffe := gatewaycert.GatewayTransportSPIFFE("fabric-prod", "11111111-1111-4111-8111-111111111111", "gateway-newco-01")
	issued, err := componentidentity.IssueCertificate(componentidentity.CertificateIssueOptions{
		Profile:    componentidentity.CertificateProfileServer,
		CommonName: "gateway-newco-01",
		DNSNames:   []string{"*.b2bautopilot.com"},
		URIs:       []string{spiffe},
		NotBefore:  now.Add(-time.Minute),
		TTL:        time.Hour,
		CA:         ca,
	})
	if err != nil {
		t.Fatalf("IssueCertificate wildcard error = %v", err)
	}
	root, err := gatewaycert.TrustRootFromPEMWithDescriptor(gatewaycert.TrustRootDescriptor{
		ID:               "transport-test-root",
		Plane:            gatewaycert.PlaneGatewayTransport,
		SPIFFENamespace:  gatewaycert.GatewayTransportNamespace,
		VerifierAudience: "test-audience",
	}, ca.CertPEM)
	if err != nil {
		t.Fatalf("TrustRootFromPEMWithDescriptor error = %v", err)
	}
	// Sanity: x509 alone accepts the wildcard for a matching name, proving the
	// rejection below comes from the plane's wildcard scan, not the chain.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	leaf := parseGatewayCertificateLeaf(t, issued.CertPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "a.b2bautopilot.com",
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("sanity: x509 should accept the wildcard fixture: %v", err)
	}
	// The plane verifier must reject it anyway.
	_, err = gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          issued.CertPEM,
		TrustRoots:              []gatewaycert.TrustRoot{root},
		ExpectedPlane:           gatewaycert.PlaneGatewayTransport,
		ExpectedSPIFFENamespace: gatewaycert.GatewayTransportNamespace,
		ExpectedServerDNSName:   "a.b2bautopilot.com",
		Now:                     now,
	})
	if !errorsIsPlaneMismatch(err) {
		t.Fatalf("wildcard DNS SAN error = %v, want plane mismatch", err)
	}
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("wildcard rejection should name the cause, got %v", err)
	}
}
