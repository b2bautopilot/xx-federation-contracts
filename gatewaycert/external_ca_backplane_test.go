package gatewaycert_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

// backplaneTestCA generates a distinct CA for the relay-cell backplane plane.
func backplaneTestCA(t *testing.T, cn string, now time.Time) componentidentity.CertificateAuthority {
	t.Helper()
	ca, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: cn,
		NotBefore:  now.Add(-time.Hour),
		TTL:        48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority %q error = %v", cn, err)
	}
	return ca
}

// Happy path: a provider configured with distinct relay + backplane CAs mints a
// relay-cell backplane leaf that (a) carries the backplane SPIFFE, (b) is ClientAuth
// EKU only (the mutual-EKU/listener decision is deferred to S2b), (c) chains under the
// backplane trust root, and (d) is REJECTED by the relay-client plane verifier.
func TestExternalCAProviderIssuesRelayCellBackplane(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "staging relay-client CA", now)
	backplaneCA := backplaneTestCA(t, "staging relay-cell backplane CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	backplaneCertFile, backplaneKeyFile := writeGatewayCertificateProviderFiles(t, backplaneCA.CertPEM, backplaneCA.KeyPEM)

	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.BackplaneCACertFile = backplaneCertFile
	cfg.BackplaneCAKeyFile = backplaneKeyFile
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: cfg,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v", err)
	}

	desc, err := provider.DescribeGatewayCertificatePlane(context.Background(), gatewaycert.GatewayCertificatePlaneDescriptorRequest{
		Plane:    gatewaycert.PlaneRelayCellBackplane,
		FabricID: "fabric-prod",
	})
	if err != nil {
		t.Fatalf("DescribeGatewayCertificatePlane backplane error = %v", err)
	}
	if desc.Plane != gatewaycert.PlaneRelayCellBackplane || desc.SPIFFENamespace != gatewaycert.RelayCellBackplaneNamespace {
		t.Fatalf("backplane descriptor = %#v, want backplane plane/namespace", desc)
	}

	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	request := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:    "fabric-prod",
		RelayCellID: "gcp-us-east1-a",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now,
		TTL:       time.Hour,
	}
	result, err := provider.IssueRelayCellBackplane(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueRelayCellBackplane error = %v", err)
	}

	wantSPIFFE := gatewaycert.RelayCellBackplaneSPIFFE("fabric-prod", "gcp-us-east1-a")
	if result.Evidence.SPIFFEID != wantSPIFFE {
		t.Fatalf("backplane SPIFFE = %q, want %q", result.Evidence.SPIFFEID, wantSPIFFE)
	}
	leaf := parseGatewayCertificateLeaf(t, result.CertificatePEM)
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) || hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("backplane EKUs = %#v, want clientAuth only (S1.5)", leaf.ExtKeyUsage)
	}

	roots := provider.TrustRoots()
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          result.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayCellBackplane,
		ExpectedSPIFFENamespace: gatewaycert.RelayCellBackplaneNamespace,
		Now:                     now,
	}); err != nil {
		t.Fatalf("backplane certificate rejected by its own plane verifier: %v", err)
	}
	// Cross-plane: the backplane leaf must NOT verify as a relay-client cert.
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          result.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayGatewayClient,
		ExpectedSPIFFENamespace: gatewaycert.RelayGatewayClientNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("backplane cert relay-plane error = %v, want plane mismatch", err)
	}
	// And a relay-client leaf must NOT verify as backplane.
	relayResult, err := provider.IssueRelayClient(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
		CSR:       gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
		NotBefore: now,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueRelayClient error = %v", err)
	}
	if relayResult.Evidence.TrustRootID == result.Evidence.TrustRootID {
		t.Fatalf("relay-client and backplane reused trust root %q", result.Evidence.TrustRootID)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          relayResult.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayCellBackplane,
		ExpectedSPIFFENamespace: gatewaycert.RelayCellBackplaneNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("relay-client cert backplane-plane error = %v, want plane mismatch", err)
	}
}

// PR-0 (S2b): the LISTENER-side backplane leaf. IssueRelayCellBackplaneServer mints a
// role/backplane-server leaf that (a) carries the backplane-server SPIFFE, (b) is
// ServerAuth EKU ONLY (so it can be the mutual-mTLS listener leaf — NEVER both EKUs,
// the keystone trap), (c) carries the backplane host as a DNS SAN (for the dialer's
// ServerName), (d) verifies under the backplane plane, and (e) is NOT a valid backplane
// CLIENT identity — so a server leaf can never be accepted as a dialer peer. The dialer
// (role/backplane) leaf stays ClientAuth-only. Two single-EKU roles under one CA.
func TestExternalCAProviderIssuesRelayCellBackplaneServer(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "staging relay-client CA", now)
	backplaneCA := backplaneTestCA(t, "staging relay-cell backplane CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	backplaneCertFile, backplaneKeyFile := writeGatewayCertificateProviderFiles(t, backplaneCA.CertPEM, backplaneCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.BackplaneCACertFile = backplaneCertFile
	cfg.BackplaneCAKeyFile = backplaneKeyFile
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: cfg,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v", err)
	}

	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	req := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:    "fabric-prod",
		RelayCellID: "gcp-us-east1-a",
		CSR:         gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
		NotBefore:   now,
		TTL:         time.Hour,
	}

	// --- the listener (server) leaf ---
	serverRes, err := provider.IssueRelayCellBackplaneServer(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueRelayCellBackplaneServer error = %v", err)
	}
	if want := gatewaycert.RelayCellBackplaneServerSPIFFE("fabric-prod", "gcp-us-east1-a"); serverRes.Evidence.SPIFFEID != want {
		t.Fatalf("server SPIFFE = %q, want %q", serverRes.Evidence.SPIFFEID, want)
	}
	serverLeaf := parseGatewayCertificateLeaf(t, serverRes.CertificatePEM)
	if !hasExtKeyUsage(serverLeaf, x509.ExtKeyUsageServerAuth) || hasExtKeyUsage(serverLeaf, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("server-leaf EKUs = %#v, want serverAuth only (never both = keystone trap)", serverLeaf.ExtKeyUsage)
	}
	// The dialer verifies the listener by STANDARD TLS — chain to the backplane CA +
	// ServerAuth + ServerName=relay-cell host — NOT the ClientAuth plane verifier (which
	// is for dialer/client leaves). Mirror that here; the DNSName match also proves the
	// DNS SAN is present.
	backplanePool := x509.NewCertPool()
	if !backplanePool.AppendCertsFromPEM(backplaneCA.CertPEM) {
		t.Fatal("append backplane CA to pool")
	}
	if _, err := serverLeaf.Verify(x509.VerifyOptions{
		Roots:       backplanePool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:     "relay-cell.b2bautopilot.com",
		CurrentTime: now,
	}); err != nil {
		t.Fatalf("server leaf must verify as a ServerAuth cert under the backplane CA with ServerName=relay-cell host: %v", err)
	}
	// SECURITY: a server leaf is NOT a valid backplane CLIENT identity (role/backplane),
	// so VerifyBackplanePeer (which uses RelayCellBackplaneIdentityFromCertificate) can
	// never accept a server leaf presented as a dialer.
	if _, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(serverLeaf); err == nil {
		t.Fatal("server leaf must NOT parse as a backplane CLIENT identity (role/backplane)")
	}

	// --- the dialer (client) leaf: still ClientAuth only, and a valid client identity ---
	clientRes, err := provider.IssueRelayCellBackplane(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueRelayCellBackplane error = %v", err)
	}
	clientLeaf := parseGatewayCertificateLeaf(t, clientRes.CertificatePEM)
	if !hasExtKeyUsage(clientLeaf, x509.ExtKeyUsageClientAuth) || hasExtKeyUsage(clientLeaf, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("client-leaf EKUs = %#v, want clientAuth only", clientLeaf.ExtKeyUsage)
	}
	if _, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(clientLeaf); err != nil {
		t.Fatalf("client leaf must parse as a backplane client identity: %v", err)
	}
}

// The distinct-CA guard fails closed when the backplane CA collides (cert OR key)
// with another configured plane CA — and preserves the legacy relay/transport
// message for that pair.
func TestExternalCAProviderBackplaneGuardFailsClosed(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "staging relay-client CA", now)
	transportCA := backplaneTestCA(t, "staging transport-server CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	transportCertFile, transportKeyFile := writeGatewayCertificateProviderFiles(t, transportCA.CertPEM, transportCA.KeyPEM)

	t.Run("rejects same CA for relay client and backplane", func(t *testing.T) {
		cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
		cfg.BackplaneCACertFile = relayCertFile
		cfg.BackplaneCAKeyFile = relayKeyFile
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg})
		if err == nil || !strings.Contains(err.Error(), "distinct relay-client and relay-cell-backplane CA certificates") {
			t.Fatalf("error = %v, want relay/backplane same-cert rejection", err)
		}
	})
	t.Run("rejects same signing key for relay client and backplane", func(t *testing.T) {
		reissuedCertFile, _ := writeGatewayCertificateProviderFiles(t, reissuedCACertificateWithSameKeyPEM(t, relayCA, now), relayCA.KeyPEM)
		cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
		cfg.BackplaneCACertFile = reissuedCertFile
		cfg.BackplaneCAKeyFile = relayKeyFile
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg})
		if err == nil || !strings.Contains(err.Error(), "distinct relay-client and relay-cell-backplane CA signing keys") {
			t.Fatalf("error = %v, want relay/backplane same-key rejection", err)
		}
	})
	t.Run("rejects same CA for transport server and backplane", func(t *testing.T) {
		cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
		cfg.ServerCACertFile = transportCertFile
		cfg.ServerCAKeyFile = transportKeyFile
		cfg.BackplaneCACertFile = transportCertFile
		cfg.BackplaneCAKeyFile = transportKeyFile
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg})
		if err == nil || !strings.Contains(err.Error(), "distinct transport-server and relay-cell-backplane CA certificates") {
			t.Fatalf("error = %v, want transport/backplane same-cert rejection", err)
		}
	})
	t.Run("preserves legacy relay/transport message", func(t *testing.T) {
		cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
		cfg.ServerCACertFile = relayCertFile
		cfg.ServerCAKeyFile = relayKeyFile
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg})
		if err == nil || !strings.Contains(err.Error(), "distinct relay-client and transport-server CA certificates") {
			t.Fatalf("error = %v, want preserved legacy relay/transport message", err)
		}
	})
}

// Without a backplane CA, the provider constructs fine (additive/dormant) but
// IssueRelayCellBackplane fails closed; and a half-configured backplane CA is
// rejected at construction.
func TestExternalCAProviderBackplaneDormantAndPartialConfig(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "staging relay-client CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)

	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewExternalCAGatewayCertificateProvider (no backplane) error = %v", err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	if _, err := provider.IssueRelayCellBackplane(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID:    "fabric-prod",
		RelayCellID: "gcp-us-east1-a",
		CSR:         gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("IssueRelayCellBackplane without backplane CA error = %v, want plane mismatch", err)
	}
	if _, err := provider.DescribeGatewayCertificatePlane(context.Background(), gatewaycert.GatewayCertificatePlaneDescriptorRequest{
		Plane:    gatewaycert.PlaneRelayCellBackplane,
		FabricID: "fabric-prod",
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("DescribeGatewayCertificatePlane backplane (unconfigured) error = %v, want plane mismatch", err)
	}

	t.Run("half-configured backplane CA rejected at construction", func(t *testing.T) {
		cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
		cfg.BackplaneCACertFile = relayCertFile // key intentionally omitted
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg})
		if err == nil || !strings.Contains(err.Error(), "backplane CA requires certificate and key files") {
			t.Fatalf("error = %v, want half-config rejection", err)
		}
	})
}

// The issue-request validator accepts the backplane plane (fabric + relay-cell id,
// no org/gateway), rejects a missing relay-cell id / fabric, and leaves the other
// planes' org/gateway requirements intact.
func TestValidateGatewayCertificateIssueRequestBackplane(t *testing.T) {
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	validCSR := gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki}

	if err := gatewaycert.ValidateGatewayCertificateIssueRequest(gatewaycert.PlaneRelayCellBackplane, gatewaycert.GatewayCertificateIssueRequest{
		FabricID:    "fabric-prod",
		RelayCellID: "gcp-us-east1-a",
		CSR:         validCSR,
	}); err != nil {
		t.Fatalf("backplane validate (fabric+cell) error = %v, want nil", err)
	}
	if err := gatewaycert.ValidateGatewayCertificateIssueRequest(gatewaycert.PlaneRelayCellBackplane, gatewaycert.GatewayCertificateIssueRequest{
		FabricID: "fabric-prod",
		CSR:      validCSR,
	}); err == nil || !strings.Contains(err.Error(), "relay cell id") {
		t.Fatalf("backplane validate (missing cell id) error = %v, want relay-cell-id rejection", err)
	}
	if err := gatewaycert.ValidateGatewayCertificateIssueRequest(gatewaycert.PlaneRelayCellBackplane, gatewaycert.GatewayCertificateIssueRequest{
		RelayCellID: "gcp-us-east1-a",
		CSR:         validCSR,
	}); err == nil || !strings.Contains(err.Error(), "fabric id") {
		t.Fatalf("backplane validate (missing fabric) error = %v, want fabric rejection", err)
	}
	// Other planes still require org + gateway (backplane's bypass must not leak).
	if err := gatewaycert.ValidateGatewayCertificateIssueRequest(gatewaycert.PlaneRelayGatewayClient, gatewaycert.GatewayCertificateIssueRequest{
		FabricID:    "fabric-prod",
		RelayCellID: "gcp-us-east1-a", // irrelevant for relay-client
		CSR:         validCSR,
	}); err == nil || !strings.Contains(err.Error(), "org id") {
		t.Fatalf("relay-client validate (missing org) error = %v, want org rejection", err)
	}
}
