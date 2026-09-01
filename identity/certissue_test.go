package identity_test

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/identity"
)

func TestGenerateSelfSignedServerCertificate(t *testing.T) {
	issued, err := identity.GenerateSelfSignedServerCertificate(identity.SelfSignedServerCertificateOptions{
		CommonName:  "builders-control",
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		TTL:         90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := tls.X509KeyPair(issued.CertPEM, issued.KeyPEM); err != nil {
		t.Fatalf("the generated cert/key must be a valid pair: %v", err)
	}
	c := issued.Certificate
	// ServerAuth EKU is load-bearing (the client REJECTS a wrong EKU — proven in design review); NOT a CA.
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", c.ExtKeyUsage)
	}
	if c.IsCA {
		t.Error("a self-signed server LEAF must not be a CA")
	}
	if c.Issuer.CommonName != c.Subject.CommonName {
		t.Errorf("self-signed cert must have Issuer==Subject, got issuer=%q subject=%q", c.Issuer.CommonName, c.Subject.CommonName)
	}
	// both SANs present (DNS localhost + IP 127.0.0.1) — the default that lets a client verify by name OR by IP.
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "localhost" {
		t.Errorf("DNSNames = %v, want [localhost]", c.DNSNames)
	}
	if len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", c.IPAddresses)
	}
}

func TestGenerateSelfSignedServerCertificate_RequiresSAN(t *testing.T) {
	if _, err := identity.GenerateSelfSignedServerCertificate(identity.SelfSignedServerCertificateOptions{
		CommonName: "builders-control",
	}); err == nil {
		t.Fatal("a self-signed server cert with NO SAN must be refused")
	}
	// whitespace-only DNS + a nil IP still count as ZERO SANs (the cleanStrings/cleanIPs hygiene).
	if _, err := identity.GenerateSelfSignedServerCertificate(identity.SelfSignedServerCertificateOptions{
		CommonName:  "builders-control",
		DNSNames:    []string{"  ", ""},
		IPAddresses: []net.IP{nil},
	}); err == nil {
		t.Fatal("whitespace/empty SANs must not satisfy the >=1-SAN requirement")
	}
}

var (
	testOIDExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	testOIDExtKeyUsageClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func TestIssueAgentCertificateCarriesBuildersNetIdentityURI(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "builders-net-test-ca",
		NotBefore:  now,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority returned error: %v", err)
	}
	identityURI := identity.AgentURI(identity.AgentIdentity{
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		NodeID:    "node-1",
	})

	issued, err := identity.IssueCertificate(identity.CertificateIssueOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "builders-agent node-1",
		URIs:       []string{identityURI},
		NotBefore:  now,
		TTL:        time.Hour,
		CA:         ca,
	})

	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if len(issued.Certificate.URIs) != 1 || issued.Certificate.URIs[0].String() != identityURI {
		t.Fatalf("unexpected URI SANs: %#v", issued.Certificate.URIs)
	}
	if got := issued.Certificate.ExtKeyUsage; len(got) != 1 || got[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected EKU: %#v", got)
	}
}

func TestIssueServerCertificateValidatesWithDeepCheck(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "builders-net-test-ca",
		NotBefore:  now,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority returned error: %v", err)
	}
	issued, err := identity.IssueCertificate(identity.CertificateIssueOptions{
		Profile:    identity.CertificateProfileServer,
		CommonName: "builders-control",
		DNSNames:   []string{"x-builders-net.internal"},
		NotBefore:  now,
		TTL:        time.Hour,
		CA:         ca,
	})
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certFile, issued.CertPEM, 0600); err != nil {
		t.Fatalf("WriteFile cert returned error: %v", err)
	}
	if err := os.WriteFile(keyFile, issued.KeyPEM, 0600); err != nil {
		t.Fatalf("WriteFile key returned error: %v", err)
	}
	if err := os.WriteFile(caFile, ca.CertPEM, 0600); err != nil {
		t.Fatalf("WriteFile ca returned error: %v", err)
	}

	report, err := identity.CheckCertificateMaterial(identity.CertificateCheckOptions{
		Profile:       identity.CertificateProfileServer,
		CertFile:      certFile,
		KeyFile:       keyFile,
		CAFile:        caFile,
		ExpectedDNS:   "x-builders-net.internal",
		MinValidFor:   30 * time.Minute,
		Now:           now,
		ComponentName: "control-server",
	})

	if err != nil {
		t.Fatalf("CheckCertificateMaterial returned error: %v", err)
	}
	if report.CACount != 1 {
		t.Fatalf("CACount = %d, want 1", report.CACount)
	}
}

func TestGenerateAgentCertificateSigningRequestCarriesIdentityProfile(t *testing.T) {
	identityURI := identity.AgentURI(identity.AgentIdentity{
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		NodeID:    "node-1",
	})

	request, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "builders-agent node-1",
		URIs:       []string{identityURI},
	})

	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest returned error: %v", err)
	}
	if len(request.CSRPEM) == 0 || len(request.KeyPEM) == 0 {
		t.Fatal("expected CSR and key PEM")
	}
	if err := request.Request.CheckSignature(); err != nil {
		t.Fatalf("CSR signature check returned error: %v", err)
	}
	if len(request.Request.URIs) != 1 || request.Request.URIs[0].String() != identityURI {
		t.Fatalf("unexpected URI SANs: %#v", request.Request.URIs)
	}
	if !csrRequestsEKU(request.Request, testOIDExtKeyUsageClientAuth) {
		t.Fatalf("CSR did not request client auth EKU: %#v", request.Request.Extensions)
	}
}

func TestGenerateServerCertificateSigningRequestRequiresDNSSAN(t *testing.T) {
	_, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileServer,
		CommonName: "builders-control",
	})
	if err == nil {
		t.Fatal("expected server CSR without DNS SAN to fail")
	}
}

func newSignTestCA(t *testing.T, now time.Time) identity.CertificateAuthority {
	t.Helper()
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "builders-net-test-ca",
		NotBefore:  now,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority returned error: %v", err)
	}
	return ca
}

// SignCertificateRequest signs an external CSR (key never leaves the requester) into a
// client leaf that passes the real control-side verifier.
func TestSignCertificateRequestRoundTripsThroughVerifier(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	ca := newSignTestCA(t, now)
	uri := identity.AgentURI(identity.AgentIdentity{TenantID: "tenant-1", ProjectID: "project-1", NodeID: "node-1"})
	req, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "csr-agent node-1",
		URIs:       []string{uri},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest: %v", err)
	}
	issued, err := identity.SignCertificateRequest(req.Request, identity.CertificateSignOptions{
		Profile:   identity.CertificateProfileClient,
		URIs:      []string{uri},
		NotBefore: now,
		TTL:       time.Hour,
		CA:        ca,
	})
	if err != nil {
		t.Fatalf("SignCertificateRequest: %v", err)
	}
	if len(issued.KeyPEM) != 0 {
		t.Fatal("signing an external CSR must NOT produce a private key")
	}
	if len(issued.Certificate.URIs) != 1 || issued.Certificate.URIs[0].String() != uri {
		t.Fatalf("URI SAN = %#v, want [%s]", issued.Certificate.URIs, uri)
	}
	if got := issued.Certificate.ExtKeyUsage; len(got) != 1 || got[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU = %#v, want [ClientAuth]", got)
	}
	if issued.Certificate.Subject.CommonName != "csr-agent node-1" {
		t.Fatalf("CN = %q, want the CSR's CN (fallback)", issued.Certificate.Subject.CommonName)
	}
	certFile := writeTestFile(t, dir, "agent-client.crt", issued.CertPEM)
	csrFile := writeTestFile(t, dir, "agent-client.csr", req.CSRPEM)
	caFile := writeTestFile(t, dir, "agent-client-ca.crt", ca.CertPEM)
	if _, err := identity.VerifyIssuedCertificateForCSR(identity.IssuedCSRVerificationOptions{
		Profile:       identity.CertificateProfileClient,
		CertFile:      certFile,
		CSRFile:       csrFile,
		CAFile:        caFile,
		MinValidFor:   30 * time.Minute,
		Now:           now,
		ComponentName: "agent-client",
	}); err != nil {
		t.Fatalf("verify-issued round-trip failed: %v", err)
	}
}

// SECURITY: the leaf SAN is stamped from the signer's options, never the CSR — a
// requester cannot obtain a cert for an identity it was not authorized for.
func TestSignCertificateRequestStampsServerSideSANIgnoringCSR(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ca := newSignTestCA(t, now)
	evil := identity.AgentURI(identity.AgentIdentity{TenantID: "tenant-EVIL", ProjectID: "p", NodeID: "n"})
	good := identity.AgentURI(identity.AgentIdentity{TenantID: "tenant-GOOD", ProjectID: "p", NodeID: "n"})
	req, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "csr-agent n",
		URIs:       []string{evil}, // the CSR asks for a DIFFERENT identity
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest: %v", err)
	}
	issued, err := identity.SignCertificateRequest(req.Request, identity.CertificateSignOptions{
		Profile:   identity.CertificateProfileClient,
		URIs:      []string{good}, // the operator authorizes only this one
		NotBefore: now,
		TTL:       time.Hour,
		CA:        ca,
	})
	if err != nil {
		t.Fatalf("SignCertificateRequest: %v", err)
	}
	if len(issued.Certificate.URIs) != 1 || issued.Certificate.URIs[0].String() != good {
		t.Fatalf("leaf SAN = %#v, want ONLY the authorized %q", issued.Certificate.URIs, good)
	}
	for _, u := range issued.Certificate.URIs {
		if u.String() == evil {
			t.Fatal("the CSR's unauthorized SAN leaked into the signed leaf")
		}
	}
}

// SECURITY: a CSR whose signature does not verify (no proof of possession) is rejected.
func TestSignCertificateRequestRejectsTamperedCSR(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ca := newSignTestCA(t, now)
	uri := identity.AgentURI(identity.AgentIdentity{TenantID: "t", ProjectID: "p", NodeID: "n"})
	req, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "csr-agent n",
		URIs:       []string{uri},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest: %v", err)
	}
	der := append([]byte(nil), req.Request.Raw...)
	der[len(der)-1] ^= 0xff // corrupt a signature byte; structure stays parseable
	tampered, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Skipf("tampered CSR no longer parses (%v) — cannot exercise the CheckSignature path", err)
	}
	if _, err := identity.SignCertificateRequest(tampered, identity.CertificateSignOptions{
		Profile:   identity.CertificateProfileClient,
		URIs:      []string{uri},
		NotBefore: now,
		TTL:       time.Hour,
		CA:        ca,
	}); err == nil {
		t.Fatal("SignCertificateRequest must reject a CSR whose signature does not verify")
	}
}

func TestSignCertificateRequestGuards(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ca := newSignTestCA(t, now)
	uri := identity.AgentURI(identity.AgentIdentity{TenantID: "t", ProjectID: "p", NodeID: "n"})
	req, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "csr-agent n",
		URIs:       []string{uri},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest: %v", err)
	}
	if _, err := identity.SignCertificateRequest(nil, identity.CertificateSignOptions{Profile: identity.CertificateProfileClient, URIs: []string{uri}, CA: ca}); err == nil {
		t.Fatal("nil CSR must error")
	}
	if _, err := identity.SignCertificateRequest(req.Request, identity.CertificateSignOptions{Profile: identity.CertificateProfileClient, URIs: []string{uri}}); err == nil {
		t.Fatal("missing CA must error")
	}
	if _, err := identity.SignCertificateRequest(req.Request, identity.CertificateSignOptions{Profile: identity.CertificateProfileClient, CA: ca}); err == nil {
		t.Fatal("client profile with no URI SAN must error")
	}
}

func TestVerifyIssuedCertificateForCSRAcceptsProductionReturnedAgentCertificate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "builders-net-test-ca",
		NotBefore:  now,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority returned error: %v", err)
	}
	identityURI := identity.AgentURI(identity.AgentIdentity{
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		NodeID:    "node-1",
	})
	request, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileClient,
		CommonName: "builders-agent node-1",
		URIs:       []string{identityURI},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest returned error: %v", err)
	}
	issuedPEM := issueCertificateFromCSR(t, ca, request.Request, identity.CertificateProfileClient, now, time.Hour, nil)
	certFile := writeTestFile(t, dir, "agent-client.crt", issuedPEM)
	csrFile := writeTestFile(t, dir, "agent-client.csr", request.CSRPEM)
	caFile := writeTestFile(t, dir, "agent-client-ca.crt", ca.CertPEM)

	report, err := identity.VerifyIssuedCertificateForCSR(identity.IssuedCSRVerificationOptions{
		Profile:       identity.CertificateProfileClient,
		CertFile:      certFile,
		CSRFile:       csrFile,
		CAFile:        caFile,
		MinValidFor:   30 * time.Minute,
		Now:           now,
		ComponentName: "agent-client",
	})

	if err != nil {
		t.Fatalf("VerifyIssuedCertificateForCSR returned error: %v", err)
	}
	if report.CACount != 1 {
		t.Fatalf("CACount = %d, want 1", report.CACount)
	}
	if len(report.URIs) != 1 || report.URIs[0] != identityURI {
		t.Fatalf("unexpected URI SANs: %#v", report.URIs)
	}
}

func TestVerifyIssuedCertificateForCSRRejectsChangedPublicKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "builders-net-test-ca",
		NotBefore:  now,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority returned error: %v", err)
	}
	request, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileServer,
		CommonName: "builders-control",
		DNSNames:   []string{"x-builders-net.internal"},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest returned error: %v", err)
	}
	other, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileServer,
		CommonName: "builders-control",
		DNSNames:   []string{"x-builders-net.internal"},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest other returned error: %v", err)
	}
	issuedPEM := issueCertificateFromCSR(t, ca, other.Request, identity.CertificateProfileServer, now, time.Hour, nil)
	certFile := writeTestFile(t, dir, "control-server.crt", issuedPEM)
	csrFile := writeTestFile(t, dir, "control-server.csr", request.CSRPEM)
	caFile := writeTestFile(t, dir, "control-server-ca.crt", ca.CertPEM)

	_, err = identity.VerifyIssuedCertificateForCSR(identity.IssuedCSRVerificationOptions{
		Profile:       identity.CertificateProfileServer,
		CertFile:      certFile,
		CSRFile:       csrFile,
		CAFile:        caFile,
		Now:           now,
		ComponentName: "control-server",
	})

	if err == nil {
		t.Fatal("expected verification to reject a certificate signed for another CSR public key")
	}
}

func TestVerifyIssuedCertificateForCSRRejectsMissingRequestedSAN(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "builders-net-test-ca",
		NotBefore:  now,
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority returned error: %v", err)
	}
	request, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
		Profile:    identity.CertificateProfileServer,
		CommonName: "builders-control",
		DNSNames:   []string{"x-builders-net.internal"},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest returned error: %v", err)
	}
	issuedPEM := issueCertificateFromCSR(t, ca, request.Request, identity.CertificateProfileServer, now, time.Hour, []string{"other.internal"})
	certFile := writeTestFile(t, dir, "control-server.crt", issuedPEM)
	csrFile := writeTestFile(t, dir, "control-server.csr", request.CSRPEM)
	caFile := writeTestFile(t, dir, "control-server-ca.crt", ca.CertPEM)

	_, err = identity.VerifyIssuedCertificateForCSR(identity.IssuedCSRVerificationOptions{
		Profile:       identity.CertificateProfileServer,
		CertFile:      certFile,
		CSRFile:       csrFile,
		CAFile:        caFile,
		Now:           now,
		ComponentName: "control-server",
	})

	if err == nil {
		t.Fatal("expected verification to reject a certificate missing the requested DNS SAN")
	}
}

func csrRequestsEKU(request *x509.CertificateRequest, want asn1.ObjectIdentifier) bool {
	for _, extension := range request.Extensions {
		if !extension.Id.Equal(testOIDExtensionExtendedKeyUsage) {
			continue
		}
		var usages []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(extension.Value, &usages); err != nil {
			return false
		}
		for _, usage := range usages {
			if usage.Equal(want) {
				return true
			}
		}
	}
	return false
}

func issueCertificateFromCSR(t *testing.T, ca identity.CertificateAuthority, request *x509.CertificateRequest, profile identity.CertificateProfile, notBefore time.Time, ttl time.Duration, overrideDNS []string) []byte {
	t.Helper()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int returned error: %v", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	uris := make([]*url.URL, len(request.URIs))
	copy(uris, request.URIs)
	dns := append([]string(nil), request.DNSNames...)
	if overrideDNS != nil {
		dns = append([]string(nil), overrideDNS...)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      request.Subject,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     dns,
		URIs:         uris,
	}
	switch profile {
	case identity.CertificateProfileServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case identity.CertificateProfileClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		t.Fatalf("unsupported profile %q", profile)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, request.PublicKey, ca.PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeTestFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("WriteFile %s returned error: %v", name, err)
	}
	return path
}
