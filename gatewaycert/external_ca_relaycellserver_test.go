package gatewaycert_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
)

// A2b: IssueRelayCellServer mints a relay cell's OUTER :443 server leaf — role/server, ServerAuth
// EKU ONLY, cell-scoped SPIFFE, with the canonical hostname as a SERVER-CONTROLLED DNS SAN, under
// a distinct relay-cell-server CA. It verifies under its own plane and is rejected by the others,
// and a spoofed CSR SAN is dropped.
func TestExternalCAProviderIssuesRelayCellServer(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "staging relay-client CA", now)
	serverCellCA := backplaneTestCA(t, "staging relay-cell server CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	serverCellCertFile, serverCellKeyFile := writeGatewayCertificateProviderFiles(t, serverCellCA.CertPEM, serverCellCA.KeyPEM)

	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.RelayCellServerCACertFile = serverCellCertFile
	cfg.RelayCellServerCAKeyFile = serverCellKeyFile
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: cfg,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewExternalCAGatewayCertificateProvider: %v", err)
	}

	const hostname = "gcprelay.b2bautopilot.com"
	// The CSR carries a SPOOFED SPIFFE URI to prove caller SANs are dropped (server-controlled).
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	result, err := provider.IssueRelayCellServer(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID:    "fabric-prod",
		RelayCellID: "gcp-us-east1-a",
		DNSNames:    []string{hostname}, // the AUTHORITY supplies the canonical hostname
		CSR:         gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
		NotBefore:   now,
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueRelayCellServer: %v", err)
	}

	// (a) SPIFFE = the cell server-role identity.
	wantSPIFFE := gatewaycert.RelayCellServerSPIFFE("fabric-prod", "gcp-us-east1-a")
	if result.Evidence.SPIFFEID != wantSPIFFE {
		t.Fatalf("server SPIFFE = %q, want %q", result.Evidence.SPIFFEID, wantSPIFFE)
	}
	leaf := parseGatewayCertificateLeaf(t, result.CertificatePEM)
	// (b) ServerAuth EKU ONLY (never ClientAuth — a :443 listener leaf, single-EKU).
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) || hasExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("EKUs = %#v, want serverAuth only", leaf.ExtKeyUsage)
	}
	// (c) exactly the canonical hostname DNS SAN.
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname {
		t.Fatalf("DNS SANs = %v, want exactly [%s] (server-controlled)", leaf.DNSNames, hostname)
	}
	// (f) the spoofed CSR URI was dropped — the only URI is the server-derived SPIFFE.
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantSPIFFE {
		t.Fatalf("URIs = %v, want exactly [%s] (no attacker CSR URI)", leaf.URIs, wantSPIFFE)
	}

	// (d) verifies under its own plane with the canonical hostname bound.
	roots := provider.TrustRoots()
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          result.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayCellServer,
		ExpectedSPIFFENamespace: gatewaycert.RelayCellServerNamespace,
		ExpectedServerDNSName:   hostname,
		Now:                     now,
	}); err != nil {
		t.Fatalf("server leaf rejected by its own plane verifier: %v", err)
	}
	// (e) NOT valid as a backplane or relay-client cert (cross-plane isolation).
	for _, bad := range []struct {
		plane gatewaycert.CertificatePlane
		ns    string
	}{
		{gatewaycert.PlaneRelayCellBackplane, gatewaycert.RelayCellBackplaneNamespace},
		{gatewaycert.PlaneRelayGatewayClient, gatewaycert.RelayGatewayClientNamespace},
	} {
		if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
			CertificatePEM:          result.CertificatePEM,
			TrustRoots:              roots,
			ExpectedPlane:           bad.plane,
			ExpectedSPIFFENamespace: bad.ns,
			Now:                     now,
		}); !errorsIsPlaneMismatch(err) {
			t.Errorf("server cert as %q = %v, want plane mismatch", bad.plane, err)
		}
	}
}

// Fail-closed: no relay-cell-server CA configured, and (with a CA) no DNS SAN supplied.
func TestExternalCAProviderRelayCellServerFailsClosed(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "staging relay-client CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://node/csr")

	// (1) provider WITHOUT a relay-cell-server CA -> IssueRelayCellServer fails closed.
	noCell, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noCell.IssueRelayCellServer(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID: "fabric-prod", RelayCellID: "c", DNSNames: []string{"h.example"},
		CSR: gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
	}); !errorsIsPlaneMismatch(err) {
		t.Errorf("no-CA IssueRelayCellServer = %v, want plane mismatch (fail-closed)", err)
	}

	// (2) provider WITH a relay-cell-server CA but a request with NO DNS SAN -> validation error.
	serverCellCA := backplaneTestCA(t, "staging relay-cell server CA", now)
	serverCellCertFile, serverCellKeyFile := writeGatewayCertificateProviderFiles(t, serverCellCA.CertPEM, serverCellCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.RelayCellServerCACertFile = serverCellCertFile
	cfg.RelayCellServerCAKeyFile = serverCellKeyFile
	withCell, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withCell.IssueRelayCellServer(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID: "fabric-prod", RelayCellID: "c", // no DNSNames
		CSR: gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
	}); err == nil {
		t.Error("IssueRelayCellServer with no DNS SAN should error (a :443 leaf needs a canonical hostname)")
	}
}

// Distinct-CA isolation: the relay-cell-server CA must differ from every other plane CA.
func TestExternalCAProviderRelayCellServerDistinctCA(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "shared CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	// Reuse the relay CA as the relay-cell-server CA -> must be rejected at construction.
	cfg.RelayCellServerCACertFile = relayCertFile
	cfg.RelayCellServerCAKeyFile = relayKeyFile
	if _, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg, Now: func() time.Time { return now }}); err == nil {
		t.Error("reusing the relay CA as the relay-cell-server CA should be rejected (distinct-CA)")
	}
}

// Distinct-CA vs the BACKPLANE CA — the sharp edge, since both live in the same relay-cell trust domain.
func TestExternalCAProviderRelayCellServerDistinctFromBackplaneCA(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "relay CA", now)
	sharedCA := backplaneTestCA(t, "shared relay-cell CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	sharedCertFile, sharedKeyFile := writeGatewayCertificateProviderFiles(t, sharedCA.CertPEM, sharedCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.BackplaneCACertFile, cfg.BackplaneCAKeyFile = sharedCertFile, sharedKeyFile
	cfg.RelayCellServerCACertFile, cfg.RelayCellServerCAKeyFile = sharedCertFile, sharedKeyFile // SAME as backplane
	if _, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg, Now: func() time.Time { return now }}); err == nil {
		t.Error("relay-cell-server CA == backplane CA should be rejected (distinct-CA)")
	}
}

// The sharpest confusion: backplane-server (role/backplane-server) and cell server (role/server) are
// BOTH ServerAuth leaves in the SAME relay-cell trust domain. Neither may verify as the other —
// isolation is by the DISTINCT CA + role, NOT the shared namespace string.
func TestRelayCellServerVsBackplaneServerIsolation(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "relay CA", now)
	backplaneCA := backplaneTestCA(t, "backplane CA", now)
	serverCellCA := backplaneTestCA(t, "server-cell CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	bpCertFile, bpKeyFile := writeGatewayCertificateProviderFiles(t, backplaneCA.CertPEM, backplaneCA.KeyPEM)
	scCertFile, scKeyFile := writeGatewayCertificateProviderFiles(t, serverCellCA.CertPEM, serverCellCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.BackplaneCACertFile, cfg.BackplaneCAKeyFile = bpCertFile, bpKeyFile
	cfg.RelayCellServerCACertFile, cfg.RelayCellServerCAKeyFile = scCertFile, scKeyFile
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://node/csr")
	req := func() gatewaycert.GatewayCertificateIssueRequest {
		return gatewaycert.GatewayCertificateIssueRequest{
			FabricID:    "fabric-prod",
			RelayCellID: "gcp-a",
			CSR:         gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki},
			NotBefore:   now,
			TTL:         time.Hour,
		}
	}
	serverReq := req()
	serverReq.DNSNames = []string{"gcprelay.b2bautopilot.com"}
	serverLeaf, err := provider.IssueRelayCellServer(context.Background(), serverReq)
	if err != nil {
		t.Fatalf("IssueRelayCellServer: %v", err)
	}
	bpServerLeaf, err := provider.IssueRelayCellBackplaneServer(context.Background(), req())
	if err != nil {
		t.Fatalf("IssueRelayCellBackplaneServer: %v", err)
	}
	roots := provider.TrustRoots()
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM: serverLeaf.CertificatePEM, TrustRoots: roots,
		ExpectedPlane: gatewaycert.PlaneRelayCellBackplane, ExpectedSPIFFENamespace: gatewaycert.RelayCellBackplaneNamespace, Now: now,
	}); !errorsIsPlaneMismatch(err) {
		t.Errorf("cell-server leaf verified as backplane = %v, want mismatch", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM: bpServerLeaf.CertificatePEM, TrustRoots: roots,
		ExpectedPlane: gatewaycert.PlaneRelayCellServer, ExpectedSPIFFENamespace: gatewaycert.RelayCellServerNamespace,
		ExpectedServerDNSName: "relay-cell.b2bautopilot.com", Now: now,
	}); !errorsIsPlaneMismatch(err) {
		t.Errorf("backplane-server leaf verified as cell-server = %v, want mismatch", err)
	}
	// A cell-server (role/server) leaf must NOT be accepted as a backplane CLIENT peer identity.
	if _, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(parseGatewayCertificateLeaf(t, serverLeaf.CertificatePEM)); err == nil {
		t.Error("cell-server leaf accepted as a backplane identity (role confusion)")
	}
}

// Fabric scope: a provider pinned to fabric X must not mint a fabric-Y cell server leaf.
func TestExternalCAProviderRelayCellServerFabricMismatch(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "relay CA", now)
	serverCellCA := backplaneTestCA(t, "server-cell CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	scCertFile, scKeyFile := writeGatewayCertificateProviderFiles(t, serverCellCA.CertPEM, serverCellCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.RelayCellServerCACertFile, cfg.RelayCellServerCAKeyFile = scCertFile, scKeyFile
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://node/csr")
	if _, err := provider.IssueRelayCellServer(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID: "fabric-OTHER", RelayCellID: "gcp-a", DNSNames: []string{"gcprelay.b2bautopilot.com"},
		CSR: gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki}, NotBefore: now, TTL: time.Hour,
	}); !errorsIsPlaneMismatch(err) {
		t.Errorf("fabric-mismatch issuance = %v, want plane mismatch", err)
	}
}

// Over-broad / malformed DNS SANs are rejected (wildcard, blank-among-valid, bad label, single-label).
func TestExternalCAProviderRelayCellServerRejectsBadDNS(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA := backplaneTestCA(t, "relay CA", now)
	serverCellCA := backplaneTestCA(t, "server-cell CA", now)
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	scCertFile, scKeyFile := writeGatewayCertificateProviderFiles(t, serverCellCA.CertPEM, serverCellCA.KeyPEM)
	cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
	cfg.RelayCellServerCACertFile, cfg.RelayCellServerCAKeyFile = scCertFile, scKeyFile
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{Config: cfg, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://node/csr")
	for _, bad := range [][]string{
		{"*.b2bautopilot.com"},              // wildcard
		{"*"},                               // bare wildcard
		{"gcprelay.b2bautopilot.com", "  "}, // blank among valid
		{"gcprelay.b2bautopilot.com", ""},   // empty among valid
		{" gcprelay.b2bautopilot.com"},      // leading whitespace
		{"singlelabel"},                     // not fully qualified
		{"bad_label.b2bautopilot.com"},      // underscore not a valid DNS char
	} {
		if _, err := provider.IssueRelayCellServer(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
			FabricID: "fabric-prod", RelayCellID: "gcp-a", DNSNames: bad,
			CSR: gatewaycert.GatewayCertificateCSR{PEM: csr.CSRPEM, ExpectedSPKISHA256: spki}, NotBefore: now, TTL: time.Hour,
		}); err == nil {
			t.Errorf("IssueRelayCellServer with DNS %v should be rejected", bad)
		}
	}
}
