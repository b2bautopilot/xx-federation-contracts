package gatewaycert_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert/testonly"
	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

func TestGatewayCertificateProviderConfigFailsClosedForProduction(t *testing.T) {
	t.Run("production requires explicit provider", func(t *testing.T) {
		_, err := gatewaycert.LoadGatewayCertificateProviderConfigFromEnv(lookupEnv(map[string]string{
			"BUILDERS_GATEWAY_CERT_PROVIDER_PRODUCTION": "true",
		}))
		if err == nil || !strings.Contains(err.Error(), "provider kind is required") {
			t.Fatalf("LoadGatewayCertificateProviderConfigFromEnv error = %v, want missing kind rejection", err)
		}
	})
	t.Run("production rejects test only provider", func(t *testing.T) {
		_, err := gatewaycert.LoadGatewayCertificateProviderConfigFromEnv(lookupEnv(map[string]string{
			"BUILDERS_GATEWAY_CERT_PROVIDER_PRODUCTION": "true",
			"BUILDERS_GATEWAY_CERT_PROVIDER_KIND":       string(gatewaycert.GatewayCertificateProviderKindTestOnlyMemory),
		}))
		if err == nil || !strings.Contains(err.Error(), "cannot use") {
			t.Fatalf("LoadGatewayCertificateProviderConfigFromEnv error = %v, want test-only production rejection", err)
		}
	})
	t.Run("external CA requires both files", func(t *testing.T) {
		_, err := gatewaycert.LoadGatewayCertificateProviderConfigFromEnv(lookupEnv(map[string]string{
			"BUILDERS_GATEWAY_CERT_PROVIDER_KIND": string(gatewaycert.GatewayCertificateProviderKindExternalCA),
		}))
		if err == nil || !strings.Contains(err.Error(), "requires CA cert and key files") {
			t.Fatalf("LoadGatewayCertificateProviderConfigFromEnv error = %v, want external CA file rejection", err)
		}
	})
	t.Run("external CA can be selected for production", func(t *testing.T) {
		cfg, err := gatewaycert.LoadGatewayCertificateProviderConfigFromEnv(lookupEnv(map[string]string{
			"BUILDERS_GATEWAY_CERT_PROVIDER_PRODUCTION":          "true",
			"BUILDERS_GATEWAY_CERT_PROVIDER_KIND":                string(gatewaycert.GatewayCertificateProviderKindExternalCA),
			"BUILDERS_GATEWAY_CERT_PROVIDER_CA_CERT_FILE":        "/run/builders/ca.pem",
			"BUILDERS_GATEWAY_CERT_PROVIDER_CA_KEY_FILE":         "/run/builders/ca-key.pem",
			"BUILDERS_GATEWAY_CERT_PROVIDER_SERVER_CA_CERT_FILE": "/run/builders/server-ca.pem",
			"BUILDERS_GATEWAY_CERT_PROVIDER_SERVER_CA_KEY_FILE":  "/run/builders/server-ca-key.pem",
		}))
		if err != nil {
			t.Fatalf("LoadGatewayCertificateProviderConfigFromEnv error = %v", err)
		}
		if cfg.Kind != gatewaycert.GatewayCertificateProviderKindExternalCA || !cfg.Production ||
			cfg.ServerCACertFile != "/run/builders/server-ca.pem" ||
			cfg.ServerCAKeyFile != "/run/builders/server-ca-key.pem" {
			t.Fatalf("cfg = %#v, want production external CA", cfg)
		}
	})
	t.Run("external CA server plane requires paired files", func(t *testing.T) {
		_, err := gatewaycert.LoadGatewayCertificateProviderConfigFromEnv(lookupEnv(map[string]string{
			"BUILDERS_GATEWAY_CERT_PROVIDER_KIND":                string(gatewaycert.GatewayCertificateProviderKindExternalCA),
			"BUILDERS_GATEWAY_CERT_PROVIDER_CA_CERT_FILE":        "/run/builders/ca.pem",
			"BUILDERS_GATEWAY_CERT_PROVIDER_CA_KEY_FILE":         "/run/builders/ca-key.pem",
			"BUILDERS_GATEWAY_CERT_PROVIDER_SERVER_CA_CERT_FILE": "/run/builders/server-ca.pem",
		}))
		if err == nil || !strings.Contains(err.Error(), "server CA requires both cert and key files") {
			t.Fatalf("LoadGatewayCertificateProviderConfigFromEnv error = %v, want server CA pair rejection", err)
		}
	})
}

func TestProductionIssuancePreflightFailsClosed(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	cfg := gatewaycert.GatewayCertificateProviderConfig{
		Kind:       gatewaycert.GatewayCertificateProviderKindExternalCA,
		FabricID:   "fabric-prod",
		Production: true,
		CACertFile: "/run/builders/prod-ca.pem",
		CAKeyFile:  "/run/builders/prod-ca-key.pem",
	}
	request := gatewaycert.GatewayCertificatePlaneDescriptorRequest{
		Plane:     gatewaycert.PlaneRelayGatewayClient,
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
	}
	validDesc := gatewaycert.TrustRootDescriptor{
		ID:                  "prod-relay-gateway-client-ca",
		Plane:               gatewaycert.PlaneRelayGatewayClient,
		SPIFFENamespace:     gatewaycert.RelayGatewayClientNamespace,
		VerifierAudience:    "gateway-to-relay client mtls",
		ActivationNotBefore: now.Add(-time.Hour),
		ActivationNotAfter:  now.Add(time.Hour),
		Production:          true,
	}

	t.Run("accepts production external CA descriptor", func(t *testing.T) {
		desc, err := gatewaycert.PreflightProductionIssuanceProvider(context.Background(), gatewaycert.ProductionIssuancePreflightInput{
			Config:   cfg,
			Provider: preflightProvider{desc: validDesc},
			Request:  request,
			Now:      now,
		})
		if err != nil {
			t.Fatalf("PreflightProductionIssuanceProvider error = %v", err)
		}
		if desc.ID != validDesc.ID || !desc.Production {
			t.Fatalf("descriptor = %#v, want production descriptor", desc)
		}
	})

	for _, tc := range []struct {
		name     string
		mutate   func(*gatewaycert.GatewayCertificateProviderConfig, *gatewaycert.TrustRootDescriptor)
		provider gatewaycert.GatewayCertificateProvider
		request  gatewaycert.GatewayCertificatePlaneDescriptorRequest
	}{
		{name: "production config required", mutate: func(cfg *gatewaycert.GatewayCertificateProviderConfig, _ *gatewaycert.TrustRootDescriptor) {
			cfg.Production = false
		}},
		{name: "rejects test-only kind", mutate: func(cfg *gatewaycert.GatewayCertificateProviderConfig, _ *gatewaycert.TrustRootDescriptor) {
			cfg.Kind = gatewaycert.GatewayCertificateProviderKindTestOnlyMemory
		}},
		{name: "rejects missing external CA files", mutate: func(cfg *gatewaycert.GatewayCertificateProviderConfig, _ *gatewaycert.TrustRootDescriptor) {
			cfg.CAKeyFile = ""
		}},
		{name: "rejects fabric mismatch", mutate: func(_ *gatewaycert.GatewayCertificateProviderConfig, _ *gatewaycert.TrustRootDescriptor) {}, request: gatewaycert.GatewayCertificatePlaneDescriptorRequest{
			Plane:     gatewaycert.PlaneRelayGatewayClient,
			FabricID:  "other-prod",
			OrgID:     "11111111-1111-4111-8111-111111111111",
			GatewayID: "gateway-newco-01",
		}},
		{name: "rejects provider without descriptor", provider: preflightProviderWithoutDescriptor{}},
		{name: "rejects descriptor-only provider without production capability marker", provider: preflightDescriptorOnlyProvider{desc: validDesc}},
		{name: "rejects non-production descriptor", mutate: func(_ *gatewaycert.GatewayCertificateProviderConfig, desc *gatewaycert.TrustRootDescriptor) {
			desc.Production = false
		}},
		{name: "rejects wrong namespace", mutate: func(_ *gatewaycert.GatewayCertificateProviderConfig, desc *gatewaycert.TrustRootDescriptor) {
			desc.SPIFFENamespace = gatewaycert.GatewayBusinessNamespace
		}},
		{name: "rejects inactive descriptor", mutate: func(_ *gatewaycert.GatewayCertificateProviderConfig, desc *gatewaycert.TrustRootDescriptor) {
			desc.ActivationNotBefore = now.Add(time.Minute)
			desc.ActivationNotAfter = now.Add(time.Hour)
		}},
		{name: "rejects missing descriptor id", mutate: func(_ *gatewaycert.GatewayCertificateProviderConfig, desc *gatewaycert.TrustRootDescriptor) {
			desc.ID = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg
			desc := validDesc
			if tc.mutate != nil {
				tc.mutate(&cfg, &desc)
			}
			provider := tc.provider
			if provider == nil {
				provider = preflightProvider{desc: desc}
			}
			request := request
			if tc.request.Plane != "" {
				request = tc.request
			}
			if _, err := gatewaycert.PreflightProductionIssuanceProvider(context.Background(), gatewaycert.ProductionIssuancePreflightInput{
				Config:   cfg,
				Provider: provider,
				Request:  request,
				Now:      now,
			}); err == nil {
				t.Fatal("PreflightProductionIssuanceProvider returned nil error, want fail-closed rejection")
			}
		})
	}

	t.Run("rejects test-only provider before production descriptor trust", func(t *testing.T) {
		provider, err := testonly.NewTestOnlyGatewayCertificateProvider(testonly.TestOnlyGatewayCertificateProviderOptions{
			NotBefore: now.Add(-time.Hour),
			Now:       func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewTestOnlyGatewayCertificateProvider error = %v", err)
		}
		if _, err := gatewaycert.PreflightProductionIssuanceProvider(context.Background(), gatewaycert.ProductionIssuancePreflightInput{
			Config:   cfg,
			Provider: provider,
			Request:  request,
			Now:      now,
		}); err == nil {
			t.Fatal("test-only provider satisfied production issuance preflight")
		}
	})
}

func TestParseGatewayCertificateCSRVerifiesProofAndSPKIBinding(t *testing.T) {
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/requested")

	parsed, err := gatewaycert.ParseGatewayCertificateCSR(gatewaycert.GatewayCertificateCSR{
		PEM:                csr.CSRPEM,
		ExpectedSPKISHA256: spki,
	})
	if err != nil {
		t.Fatalf("ParseGatewayCertificateCSR PEM error = %v", err)
	}
	if parsed.SPKISHA256 != spki {
		t.Fatalf("SPKI = %q, want %q", parsed.SPKISHA256, spki)
	}
	if len(parsed.RequestedURIs) != 1 || parsed.RequestedURIs[0] != "spiffe://attacker.invalid/requested" {
		t.Fatalf("RequestedURIs = %#v, want CSR requested URI captured for diagnostics", parsed.RequestedURIs)
	}

	if _, err := gatewaycert.ParseGatewayCertificateCSR(gatewaycert.GatewayCertificateCSR{
		DER:                csr.Request.Raw,
		ExpectedSPKISHA256: spki,
	}); err != nil {
		t.Fatalf("ParseGatewayCertificateCSR DER error = %v", err)
	}
	if _, err := gatewaycert.ParseGatewayCertificateCSR(gatewaycert.GatewayCertificateCSR{
		PEM:                csr.CSRPEM,
		DER:                csr.Request.Raw,
		ExpectedSPKISHA256: spki,
	}); err == nil {
		t.Fatal("ParseGatewayCertificateCSR accepted both PEM and DER")
	}
	if _, err := gatewaycert.ParseGatewayCertificateCSR(gatewaycert.GatewayCertificateCSR{
		DER:                csr.Request.Raw,
		ExpectedSPKISHA256: "wrong-spki",
	}); err == nil || !errors.Is(err, gatewaycert.ErrCSRSPKIMismatch) || !strings.Contains(err.Error(), "SPKI SHA-256 mismatch") {
		t.Fatalf("ParseGatewayCertificateCSR mismatch error = %v, want SPKI mismatch", err)
	}
	if _, err := gatewaycert.ParseGatewayCertificateCSR(gatewaycert.GatewayCertificateCSR{
		DER:                corruptCSRSignature(t, csr.Request.Raw),
		ExpectedSPKISHA256: spki,
	}); err == nil || !errors.Is(err, gatewaycert.ErrCSRSignatureInvalid) {
		t.Fatalf("ParseGatewayCertificateCSR invalid proof-of-possession error = %v, want typed signature error", err)
	}
}

func TestTestOnlyGatewayCertificateProviderIssuesPlaneSeparatedDerivedIdentity(t *testing.T) {
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
	request := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:   "fabric-prod",
		OrgID:      "11111111-1111-4111-8111-111111111111",
		GatewayID:  "gateway-newco-01",
		CommonName: "gateway-newco-01",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now.Add(-time.Minute),
		TTL:       time.Hour,
	}

	relay, err := provider.IssueRelayClient(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueRelayClient error = %v", err)
	}
	business, err := provider.IssueBusinessGateway(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueBusinessGateway error = %v", err)
	}
	transport, err := provider.IssueGatewayTransportServer(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueGatewayTransportServer error = %v", err)
	}

	wantRelaySPIFFE := gatewaycert.RelayGatewayClientSPIFFE("fabric-prod", "11111111-1111-4111-8111-111111111111", "gateway-newco-01")
	wantTransportSPIFFE := gatewaycert.GatewayTransportSPIFFE("fabric-prod", "11111111-1111-4111-8111-111111111111", "gateway-newco-01")
	wantBusinessSPIFFE := gatewaycert.GatewayBusinessSPIFFE("11111111-1111-4111-8111-111111111111", "gateway-newco-01")
	if relay.Evidence.SPIFFEID != wantRelaySPIFFE {
		t.Fatalf("relay SPIFFE = %q, want derived %q", relay.Evidence.SPIFFEID, wantRelaySPIFFE)
	}
	if transport.Evidence.SPIFFEID != wantTransportSPIFFE {
		t.Fatalf("transport SPIFFE = %q, want derived %q", transport.Evidence.SPIFFEID, wantTransportSPIFFE)
	}
	if business.Evidence.SPIFFEID != wantBusinessSPIFFE {
		t.Fatalf("business SPIFFE = %q, want derived %q", business.Evidence.SPIFFEID, wantBusinessSPIFFE)
	}
	if strings.Contains(relay.Evidence.SPIFFEID, "attacker.invalid") ||
		strings.Contains(transport.Evidence.SPIFFEID, "attacker.invalid") ||
		strings.Contains(business.Evidence.SPIFFEID, "attacker.invalid") {
		t.Fatalf("provider copied CSR-requested identity into evidence: relay=%q transport=%q business=%q", relay.Evidence.SPIFFEID, transport.Evidence.SPIFFEID, business.Evidence.SPIFFEID)
	}
	if relay.Evidence.TrustRootID == transport.Evidence.TrustRootID || relay.Evidence.TrustRootID == business.Evidence.TrustRootID || transport.Evidence.TrustRootID == business.Evidence.TrustRootID {
		t.Fatalf("trust roots not plane-separated: relay=%q transport=%q business=%q", relay.Evidence.TrustRootID, transport.Evidence.TrustRootID, business.Evidence.TrustRootID)
	}
	if relay.Evidence.Production || transport.Evidence.Production || business.Evidence.Production {
		t.Fatalf("test-only evidence marked production: relay=%v transport=%v business=%v", relay.Evidence.Production, transport.Evidence.Production, business.Evidence.Production)
	}
	if relay.Evidence.CSRSPKISHA256 != spki || transport.Evidence.CSRSPKISHA256 != spki || business.Evidence.CSRSPKISHA256 != spki {
		t.Fatalf("SPKI evidence = relay %q transport %q business %q, want %q", relay.Evidence.CSRSPKISHA256, transport.Evidence.CSRSPKISHA256, business.Evidence.CSRSPKISHA256, spki)
	}
	transportLeaf := parseGatewayCertificateLeaf(t, transport.CertificatePEM)
	if !hasExtKeyUsage(transportLeaf, x509.ExtKeyUsageServerAuth) || hasExtKeyUsage(transportLeaf, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("transport EKUs = %#v, want serverAuth only", transportLeaf.ExtKeyUsage)
	}

	roots := provider.TrustRoots()
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          relay.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayGatewayClient,
		ExpectedSPIFFENamespace: gatewaycert.RelayGatewayClientNamespace,
		Now:                     now,
	}); err != nil {
		t.Fatalf("relay certificate did not verify in relay plane: %v", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          transport.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneGatewayTransport,
		ExpectedSPIFFENamespace: gatewaycert.GatewayTransportNamespace,
		Now:                     now,
	}); err != nil {
		t.Fatalf("transport certificate did not verify in transport plane: %v", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          business.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneGatewayBusiness,
		ExpectedSPIFFENamespace: gatewaycert.GatewayBusinessNamespace,
		Now:                     now,
	}); err != nil {
		t.Fatalf("business certificate did not verify in business plane: %v", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          relay.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneGatewayTransport,
		ExpectedSPIFFENamespace: gatewaycert.GatewayTransportNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("relay certificate transport-plane error = %v, want plane mismatch", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          transport.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayGatewayClient,
		ExpectedSPIFFENamespace: gatewaycert.RelayGatewayClientNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("transport certificate relay-plane error = %v, want plane mismatch", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          relay.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneGatewayBusiness,
		ExpectedSPIFFENamespace: gatewaycert.GatewayBusinessNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("relay certificate business-plane error = %v, want plane mismatch", err)
	}
}

func TestTestOnlyGatewayCertificateProviderRejectsSPKIMismatch(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	provider, err := testonly.NewTestOnlyGatewayCertificateProvider(testonly.TestOnlyGatewayCertificateProviderOptions{
		NotBefore: now.Add(-time.Hour),
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewTestOnlyGatewayCertificateProvider error = %v", err)
	}
	csr, _ := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")

	_, err = provider.IssueRelayClient(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: "wrong-spki",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "SPKI SHA-256 mismatch") {
		t.Fatalf("IssueRelayClient error = %v, want SPKI mismatch", err)
	}
}

func TestExternalCAProviderIssuesProductionRelayClientFromFiles(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	ca, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: "builders-net staging relay gateway-client CA",
		NotBefore:  now.Add(-time.Hour),
		TTL:        48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority error = %v", err)
	}
	certFile, keyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, ca.KeyPEM)
	cfg := gatewaycert.GatewayCertificateProviderConfig{
		Kind:       gatewaycert.GatewayCertificateProviderKindExternalCA,
		FabricID:   "fabric-prod",
		Production: true,
		CACertFile: certFile,
		CAKeyFile:  keyFile,
	}
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: cfg,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v", err)
	}
	if !provider.ProductionGatewayCertificateProvider() {
		t.Fatal("external CA provider did not declare production capability")
	}
	desc, err := provider.DescribeGatewayCertificatePlane(context.Background(), gatewaycert.GatewayCertificatePlaneDescriptorRequest{
		Plane:     gatewaycert.PlaneRelayGatewayClient,
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
	})
	if err != nil {
		t.Fatalf("DescribeGatewayCertificatePlane error = %v", err)
	}
	if desc.Plane != gatewaycert.PlaneRelayGatewayClient || desc.SPIFFENamespace != gatewaycert.RelayGatewayClientNamespace || !desc.Production {
		t.Fatalf("descriptor = %#v, want production relay gateway-client descriptor", desc)
	}
	if _, err := gatewaycert.PreflightProductionIssuanceProvider(context.Background(), gatewaycert.ProductionIssuancePreflightInput{
		Config:   cfg,
		Provider: provider,
		Request: gatewaycert.GatewayCertificatePlaneDescriptorRequest{
			Plane:     gatewaycert.PlaneRelayGatewayClient,
			FabricID:  "fabric-prod",
			OrgID:     "11111111-1111-4111-8111-111111111111",
			GatewayID: "gateway-newco-01",
		},
		Now:       now,
		MinActive: time.Hour,
	}); err != nil {
		t.Fatalf("PreflightProductionIssuanceProvider error = %v", err)
	}

	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	request := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:   "fabric-prod",
		OrgID:      "11111111-1111-4111-8111-111111111111",
		GatewayID:  "gateway-newco-01",
		CommonName: "operator supplied admin cn",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now,
		TTL:       time.Hour,
	}
	issued, err := provider.IssueRelayClient(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueRelayClient error = %v", err)
	}
	wantSPIFFE := gatewaycert.RelayGatewayClientSPIFFE("fabric-prod", "11111111-1111-4111-8111-111111111111", "gateway-newco-01")
	if issued.Evidence.SPIFFEID != wantSPIFFE {
		t.Fatalf("issued SPIFFE = %q, want derived %q", issued.Evidence.SPIFFEID, wantSPIFFE)
	}
	if strings.Contains(issued.Evidence.SPIFFEID, "attacker.invalid") {
		t.Fatalf("external CA copied CSR-requested identity into evidence: %q", issued.Evidence.SPIFFEID)
	}

	// Fail-closed invariant: the same production provider rejects a relay-client
	// issuance whose OrgID (the future control-plane TenantID) is a domain/handle
	// rather than a uuid — closing the seam at the source.
	domainRequest := request
	domainRequest.OrgID = "oldco.example"
	if _, err := provider.IssueRelayClient(context.Background(), domainRequest); err == nil {
		t.Fatal("IssueRelayClient accepted a domain OrgID; want fail-closed uuid rejection")
	}
	issuedBlock, _ := pem.Decode(issued.CertificatePEM)
	if issuedBlock == nil {
		t.Fatal("issued external CA certificate PEM missing certificate block")
	}
	issuedCert, err := x509.ParseCertificate(issuedBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate issued external CA cert: %v", err)
	}
	if issuedCert.Subject.CommonName != request.GatewayID || issuedCert.Subject.CommonName == request.CommonName {
		t.Fatalf("issued CN = %q, want trusted gateway id %q and not caller CN %q", issuedCert.Subject.CommonName, request.GatewayID, request.CommonName)
	}
	if !issued.Evidence.Production || issued.Evidence.TrustRootID != desc.ID || issued.Evidence.CSRSPKISHA256 != spki {
		t.Fatalf("evidence = %#v, want production evidence rooted at %q with SPKI %q", issued.Evidence, desc.ID, spki)
	}
	verified, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          issued.CertificatePEM,
		TrustRoots:              provider.TrustRoots(),
		ExpectedPlane:           gatewaycert.PlaneRelayGatewayClient,
		ExpectedSPIFFENamespace: gatewaycert.RelayGatewayClientNamespace,
		Now:                     now,
	})
	if err != nil {
		t.Fatalf("VerifyPlaneCertificate error = %v", err)
	}
	if !verified.Production || verified.SPIFFEID != wantSPIFFE {
		t.Fatalf("verification = %#v, want production relay identity %q", verified, wantSPIFFE)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          issued.CertificatePEM,
		TrustRoots:              provider.TrustRoots(),
		ExpectedPlane:           gatewaycert.PlaneGatewayBusiness,
		ExpectedSPIFFENamespace: gatewaycert.GatewayBusinessNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("external relay certificate business-plane error = %v, want plane mismatch", err)
	}

	rotated, err := provider.Rotate(context.Background(), gatewaycert.GatewayCertificateRotateRequest{
		Plane:                gatewaycert.PlaneRelayGatewayClient,
		IssueRequest:         request,
		PreviousSerialNumber: issued.Evidence.SerialNumber,
		Reason:               "test-rotate",
	})
	if err != nil {
		t.Fatalf("Rotate error = %v", err)
	}
	if rotated.Evidence.SerialNumber == issued.Evidence.SerialNumber || rotated.Evidence.SPIFFEID != wantSPIFFE || !rotated.Evidence.Production {
		t.Fatalf("rotated evidence = %#v, original serial=%q", rotated.Evidence, issued.Evidence.SerialNumber)
	}
	revoked, err := provider.Revoke(context.Background(), gatewaycert.GatewayCertificateRevokeRequest{
		Plane:        gatewaycert.PlaneRelayGatewayClient,
		SerialNumber: issued.Evidence.SerialNumber,
		GatewayID:    "gateway-newco-01",
		Reason:       "test-revoke",
	})
	if err != nil {
		t.Fatalf("Revoke error = %v", err)
	}
	if revoked.TrustRootID != desc.ID || revoked.SerialNumber != issued.Evidence.SerialNumber || revoked.RevocationGeneration != 1 {
		t.Fatalf("revocation = %#v, want root=%q serial=%q generation=1", revoked, desc.ID, issued.Evidence.SerialNumber)
	}
}

func TestExternalCAProviderIssuesGatewayTransportServerFromDistinctRoot(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	relayCA, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: "builders-net staging relay gateway-client CA",
		NotBefore:  now.Add(-time.Hour),
		TTL:        48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority relay error = %v", err)
	}
	serverCA, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: "builders-net staging gateway transport-server CA",
		NotBefore:  now.Add(-time.Hour),
		TTL:        48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority server error = %v", err)
	}
	relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, relayCA.CertPEM, relayCA.KeyPEM)
	serverCertFile, serverKeyFile := writeGatewayCertificateProviderFiles(t, serverCA.CertPEM, serverCA.KeyPEM)
	provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
		Config: gatewaycert.GatewayCertificateProviderConfig{
			Kind:             gatewaycert.GatewayCertificateProviderKindExternalCA,
			FabricID:         "fabric-prod",
			Production:       true,
			CACertFile:       relayCertFile,
			CAKeyFile:        relayKeyFile,
			ServerCACertFile: serverCertFile,
			ServerCAKeyFile:  serverKeyFile,
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v", err)
	}
	serverIssuer, ok := any(provider).(gatewaycert.GatewayTransportServerCertificateProvider)
	if !ok {
		t.Fatal("external CA provider does not expose gateway transport-server issuer")
	}
	serverDesc, err := provider.DescribeGatewayCertificatePlane(context.Background(), gatewaycert.GatewayCertificatePlaneDescriptorRequest{
		Plane:     gatewaycert.PlaneGatewayTransport,
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
	})
	if err != nil {
		t.Fatalf("DescribeGatewayCertificatePlane transport error = %v", err)
	}
	if serverDesc.Plane != gatewaycert.PlaneGatewayTransport || serverDesc.SPIFFENamespace != gatewaycert.GatewayTransportNamespace || !serverDesc.Production {
		t.Fatalf("server descriptor = %#v, want production transport-server descriptor", serverDesc)
	}

	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	request := gatewaycert.GatewayCertificateIssueRequest{
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now,
		TTL:       time.Hour,
	}
	relay, err := provider.IssueRelayClient(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueRelayClient error = %v", err)
	}
	server, err := serverIssuer.IssueGatewayTransportServer(context.Background(), request)
	if err != nil {
		t.Fatalf("IssueGatewayTransportServer error = %v", err)
	}
	if relay.Evidence.TrustRootID == server.Evidence.TrustRootID {
		t.Fatalf("relay and transport server reused trust root %q", relay.Evidence.TrustRootID)
	}

	relayCert := parseGatewayCertificateLeaf(t, relay.CertificatePEM)
	serverCert := parseGatewayCertificateLeaf(t, server.CertificatePEM)
	if !hasExtKeyUsage(relayCert, x509.ExtKeyUsageClientAuth) || hasExtKeyUsage(relayCert, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("relay client EKUs = %#v, want clientAuth only", relayCert.ExtKeyUsage)
	}
	if !hasExtKeyUsage(serverCert, x509.ExtKeyUsageServerAuth) || hasExtKeyUsage(serverCert, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("transport server EKUs = %#v, want serverAuth only", serverCert.ExtKeyUsage)
	}

	wantServerSPIFFE := gatewaycert.GatewayTransportSPIFFE("fabric-prod", "11111111-1111-4111-8111-111111111111", "gateway-newco-01")
	if server.Evidence.SPIFFEID != wantServerSPIFFE {
		t.Fatalf("server SPIFFE = %q, want %q", server.Evidence.SPIFFEID, wantServerSPIFFE)
	}
	if server.Evidence.FingerprintSHA256 != componentidentity.CertificateFingerprintSHA256(serverCert) {
		t.Fatalf("server evidence fingerprint = %q, want parsed server cert fingerprint", server.Evidence.FingerprintSHA256)
	}

	roots := provider.TrustRoots()
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          server.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneGatewayTransport,
		ExpectedSPIFFENamespace: gatewaycert.GatewayTransportNamespace,
		Now:                     now,
	}); err != nil {
		t.Fatalf("transport server certificate rejected by server plane verifier: %v", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          server.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneRelayGatewayClient,
		ExpectedSPIFFENamespace: gatewaycert.RelayGatewayClientNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("transport server certificate relay-plane error = %v, want plane mismatch", err)
	}
	if _, err := gatewaycert.VerifyPlaneCertificate(context.Background(), gatewaycert.PlaneVerifyOptions{
		CertificatePEM:          relay.CertificatePEM,
		TrustRoots:              roots,
		ExpectedPlane:           gatewaycert.PlaneGatewayTransport,
		ExpectedSPIFFENamespace: gatewaycert.GatewayTransportNamespace,
		Now:                     now,
	}); !errorsIsPlaneMismatch(err) {
		t.Fatalf("relay client certificate transport-server-plane error = %v, want plane mismatch", err)
	}
	relayClientTLSWitness, err := componentidentity.IssueCertificate(componentidentity.CertificateIssueOptions{
		Profile:    componentidentity.CertificateProfileClient,
		CommonName: "relay client tls witness",
		DNSNames:   []string{"relay-client.invalid"},
		URIs:       []string{gatewaycert.RelayGatewayClientSPIFFE("fabric-prod", "11111111-1111-4111-8111-111111111111", "gateway-newco-01")},
		NotBefore:  now,
		TTL:        time.Hour,
		CA:         relayCA,
	})
	if err != nil {
		t.Fatalf("IssueCertificate relay client TLS witness error = %v", err)
	}
	relayAsServerErr := tlsServerAuthHandshakeError(t, relayClientTLSWitness.CertPEM, relayClientTLSWitness.KeyPEM, certPoolForTrustRoot(t, roots, relay.Evidence.TrustRootID), "relay-client.invalid", now)
	if relayAsServerErr == nil || !strings.Contains(relayAsServerErr.Error(), "incompatible key usage") {
		t.Fatalf("relay-client-as-server TLS error = %v, want incompatible key usage", relayAsServerErr)
	}
	validServerTLSWitness, err := componentidentity.IssueCertificate(componentidentity.CertificateIssueOptions{
		Profile:    componentidentity.CertificateProfileServer,
		CommonName: "gateway transport server tls witness",
		DNSNames:   []string{"transport-server.invalid"},
		URIs:       []string{wantServerSPIFFE},
		NotBefore:  now,
		TTL:        time.Hour,
		CA:         serverCA,
	})
	if err != nil {
		t.Fatalf("IssueCertificate transport server TLS witness error = %v", err)
	}
	_, serverErr := tlsClientAuthHandshakeErrors(t,
		validServerTLSWitness.CertPEM,
		validServerTLSWitness.KeyPEM,
		server.CertificatePEM,
		csr.KeyPEM,
		certPoolForTrustRoot(t, roots, server.Evidence.TrustRootID),
		"transport-server.invalid",
		now,
	)
	if serverErr == nil || !strings.Contains(serverErr.Error(), "incompatible key usage") {
		t.Fatalf("transport-server-as-client TLS server error = %v, want incompatible key usage", serverErr)
	}
}

func TestExternalCAProviderFailsClosedForInvalidMaterialAndUnsupportedPlanes(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	ca, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: "builders-net staging relay CA",
		NotBefore:  now.Add(-time.Hour),
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority error = %v", err)
	}
	otherCA, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: "wrong key CA",
		NotBefore:  now.Add(-time.Hour),
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateCertificateAuthority other error = %v", err)
	}
	leaf, err := componentidentity.IssueCertificate(componentidentity.CertificateIssueOptions{
		Profile:    componentidentity.CertificateProfileClient,
		CommonName: "not-a-ca",
		URIs:       []string{"spiffe://example.invalid/not-ca"},
		NotBefore:  now,
		TTL:        time.Hour,
		CA:         ca,
	})
	if err != nil {
		t.Fatalf("IssueCertificate leaf error = %v", err)
	}

	t.Run("rejects wrong provider kind", func(t *testing.T) {
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, ca.KeyPEM)
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: gatewaycert.GatewayCertificateProviderConfig{
				Kind:       gatewaycert.GatewayCertificateProviderKindTestOnlyMemory,
				FabricID:   "fabric-prod",
				Production: true,
				CACertFile: certFile,
				CAKeyFile:  keyFile,
			},
		})
		if err == nil || !strings.Contains(err.Error(), "requires kind") {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v, want kind rejection", err)
		}
	})
	t.Run("rejects mismatched CA key", func(t *testing.T) {
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, otherCA.KeyPEM)
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: externalCAProviderTestConfig("fabric-prod", true, certFile, keyFile),
		})
		if err == nil || !strings.Contains(err.Error(), "do not match") {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v, want key mismatch", err)
		}
	})
	t.Run("rejects non CA certificate", func(t *testing.T) {
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, leaf.CertPEM, leaf.KeyPEM)
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: externalCAProviderTestConfig("fabric-prod", true, certFile, keyFile),
		})
		if err == nil || !strings.Contains(err.Error(), "not a certificate authority") {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v, want non-CA rejection", err)
		}
	})
	t.Run("rejects CA without cert sign usage", func(t *testing.T) {
		certPEM, keyPEM := caWithoutCertSignPEM(t, now)
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, certPEM, keyPEM)
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: externalCAProviderTestConfig("fabric-prod", true, certFile, keyFile),
		})
		if err == nil || !strings.Contains(err.Error(), "not allowed to sign") {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v, want cert-sign rejection", err)
		}
	})
	t.Run("rejects same CA for relay client and transport server", func(t *testing.T) {
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, ca.KeyPEM)
		cfg := externalCAProviderTestConfig("fabric-prod", true, certFile, keyFile)
		cfg.ServerCACertFile = certFile
		cfg.ServerCAKeyFile = keyFile
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: cfg,
		})
		if err == nil || !strings.Contains(err.Error(), "distinct relay-client and transport-server CA") {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v, want same-CA rejection", err)
		}
	})
	t.Run("rejects same CA signing key even with different certificate", func(t *testing.T) {
		relayCertFile, relayKeyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, ca.KeyPEM)
		reissuedCertFile, reissuedKeyFile := writeGatewayCertificateProviderFiles(t, reissuedCACertificateWithSameKeyPEM(t, ca, now), ca.KeyPEM)
		cfg := externalCAProviderTestConfig("fabric-prod", true, relayCertFile, relayKeyFile)
		cfg.ServerCACertFile = reissuedCertFile
		cfg.ServerCAKeyFile = reissuedKeyFile
		_, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: cfg,
		})
		if err == nil || !strings.Contains(err.Error(), "distinct relay-client and transport-server CA signing keys") {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v, want same signing-key rejection", err)
		}
	})
	t.Run("preflight rejects non production config", func(t *testing.T) {
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, ca.KeyPEM)
		cfg := externalCAProviderTestConfig("fabric-prod", false, certFile, keyFile)
		provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: cfg,
			Now:    func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v", err)
		}
		if provider.ProductionGatewayCertificateProvider() {
			t.Fatal("non-production external CA provider returned production marker")
		}
		if _, err := gatewaycert.PreflightProductionIssuanceProvider(context.Background(), gatewaycert.ProductionIssuancePreflightInput{
			Config:   cfg,
			Provider: provider,
			Request: gatewaycert.GatewayCertificatePlaneDescriptorRequest{
				Plane:     gatewaycert.PlaneRelayGatewayClient,
				FabricID:  "fabric-prod",
				OrgID:     "11111111-1111-4111-8111-111111111111",
				GatewayID: "gateway-newco-01",
			},
			Now: now,
		}); err == nil {
			t.Fatal("non-production external CA provider satisfied production preflight")
		}
	})
	t.Run("rejects unsupported planes and wrong fabric", func(t *testing.T) {
		certFile, keyFile := writeGatewayCertificateProviderFiles(t, ca.CertPEM, ca.KeyPEM)
		provider, err := gatewaycert.NewExternalCAGatewayCertificateProvider(gatewaycert.ExternalCAGatewayCertificateProviderOptions{
			Config: externalCAProviderTestConfig("fabric-prod", true, certFile, keyFile),
			Now:    func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewExternalCAGatewayCertificateProvider error = %v", err)
		}
		if _, err := provider.DescribeGatewayCertificatePlane(context.Background(), gatewaycert.GatewayCertificatePlaneDescriptorRequest{
			Plane:     gatewaycert.PlaneGatewayBusiness,
			FabricID:  "fabric-prod",
			OrgID:     "11111111-1111-4111-8111-111111111111",
			GatewayID: "gateway-newco-01",
		}); !errorsIsPlaneMismatch(err) {
			t.Fatalf("DescribeGatewayCertificatePlane business error = %v, want plane mismatch", err)
		}
		csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
		request := gatewaycert.GatewayCertificateIssueRequest{
			FabricID:  "other-fabric",
			OrgID:     "11111111-1111-4111-8111-111111111111",
			GatewayID: "gateway-newco-01",
			CSR: gatewaycert.GatewayCertificateCSR{
				PEM:                csr.CSRPEM,
				ExpectedSPKISHA256: spki,
			},
		}
		if _, err := provider.IssueRelayClient(context.Background(), request); !errorsIsPlaneMismatch(err) {
			t.Fatalf("IssueRelayClient wrong fabric error = %v, want plane mismatch", err)
		}
		request.FabricID = "fabric-prod"
		if _, err := provider.IssueBusinessGateway(context.Background(), request); !errorsIsPlaneMismatch(err) {
			t.Fatalf("IssueBusinessGateway error = %v, want plane mismatch", err)
		}
		if _, err := provider.IssueGatewayTransportServer(context.Background(), request); !errorsIsPlaneMismatch(err) {
			t.Fatalf("IssueGatewayTransportServer without server CA error = %v, want plane mismatch", err)
		}
		if _, err := provider.Rotate(context.Background(), gatewaycert.GatewayCertificateRotateRequest{
			Plane:        gatewaycert.PlaneGatewayBusiness,
			IssueRequest: request,
		}); !errorsIsPlaneMismatch(err) {
			t.Fatalf("Rotate business error = %v, want plane mismatch", err)
		}
		if _, err := provider.Revoke(context.Background(), gatewaycert.GatewayCertificateRevokeRequest{
			Plane:        gatewaycert.PlaneGatewayBusiness,
			SerialNumber: "123",
		}); !errorsIsPlaneMismatch(err) {
			t.Fatalf("Revoke business error = %v, want plane mismatch", err)
		}
	})
}

func TestGatewayCertificateEvidenceRejectsNonCanonicalPlaneNamespace(t *testing.T) {
	now := time.Unix(1_700_100_000, 0).UTC()
	provider, err := testonly.NewTestOnlyGatewayCertificateProvider(testonly.TestOnlyGatewayCertificateProviderOptions{
		NotBefore: now.Add(-time.Hour),
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewTestOnlyGatewayCertificateProvider error = %v", err)
	}
	csr, spki := gatewayCertificateCSRFixture(t, "spiffe://attacker.invalid/csr-identity")
	issued, err := provider.IssueRelayClient(context.Background(), gatewaycert.GatewayCertificateIssueRequest{
		FabricID:  "fabric-prod",
		OrgID:     "11111111-1111-4111-8111-111111111111",
		GatewayID: "gateway-newco-01",
		CSR: gatewaycert.GatewayCertificateCSR{
			PEM:                csr.CSRPEM,
			ExpectedSPKISHA256: spki,
		},
		NotBefore: now.Add(-time.Minute),
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueRelayClient error = %v", err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	if block == nil {
		t.Fatal("issued certificate PEM missing certificate block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate error = %v", err)
	}
	root := provider.RelayGatewayClientRoot
	root.PlaneDescriptor.SPIFFENamespace = gatewaycert.GatewayBusinessNamespace
	_, err = gatewaycert.GatewayCertificateEvidenceFromIssued(gatewaycert.PlaneRelayGatewayClient, root, cert, spki)
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("GatewayCertificateEvidenceFromIssued error = %v, want canonical namespace rejection", err)
	}
}

func lookupEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func externalCAProviderTestConfig(fabricID string, production bool, certFile, keyFile string) gatewaycert.GatewayCertificateProviderConfig {
	return gatewaycert.GatewayCertificateProviderConfig{
		Kind:       gatewaycert.GatewayCertificateProviderKindExternalCA,
		FabricID:   fabricID,
		Production: production,
		CACertFile: certFile,
		CAKeyFile:  keyFile,
	}
}

func writeGatewayCertificateProviderFiles(t *testing.T, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	keyFile := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("write CA cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write CA key file: %v", err)
	}
	return certFile, keyFile
}

func parseGatewayCertificateLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certificate PEM missing certificate block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate error = %v", err)
	}
	return cert
}

func hasExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	for _, got := range cert.ExtKeyUsage {
		if got == usage {
			return true
		}
	}
	return false
}

func certPoolForTrustRoot(t *testing.T, roots []gatewaycert.TrustRoot, id string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, root := range roots {
		if root.ID != id {
			continue
		}
		for _, cert := range root.Certificates {
			pool.AddCert(cert)
		}
	}
	if len(pool.Subjects()) == 0 {
		t.Fatalf("trust root %q not found", id)
	}
	return pool
}

func tlsServerAuthHandshakeError(t *testing.T, certPEM, keyPEM []byte, rootPool *x509.CertPool, serverName string, verifyTime time.Time) error {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair error = %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		err = tlsConn.Handshake()
		_ = tlsConn.Close()
		serverErr <- err
	}()
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := tls.Client(rawConn, &tls.Config{
		RootCAs:    rootPool,
		ServerName: serverName,
		Time:       func() time.Time { return verifyTime },
	})
	clientErr := client.Handshake()
	_ = client.Close()
	var serverHandshakeErr error
	select {
	case serverHandshakeErr = <-serverErr:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TLS server handshake")
	}
	if clientErr != nil {
		return clientErr
	}
	return serverHandshakeErr
}

func tlsClientAuthHandshakeErrors(t *testing.T, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte, rootPool *x509.CertPool, serverName string, verifyTime time.Time) (error, error) {
	t.Helper()
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server X509KeyPair error = %v", err)
	}
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("client X509KeyPair error = %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    rootPool,
			Time:         func() time.Time { return verifyTime },
		})
		err = tlsConn.Handshake()
		_ = tlsConn.Close()
		serverErr <- err
	}()
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := tls.Client(rawConn, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootPool,
		ServerName:   serverName,
		Time:         func() time.Time { return verifyTime },
	})
	clientErr := client.Handshake()
	_ = client.Close()
	var serverHandshakeErr error
	select {
	case serverHandshakeErr = <-serverErr:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TLS server handshake")
	}
	return clientErr, serverHandshakeErr
}

func caWithoutCertSignPEM(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "builders-net invalid signing CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA without cert sign: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func reissuedCACertificateWithSameKeyPEM(t *testing.T, ca componentidentity.CertificateAuthority, now time.Time) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(43),
		Subject:               pkix.Name{CommonName: "builders-net reissued same-key transport CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, ca.PrivateKey.Public(), ca.PrivateKey)
	if err != nil {
		t.Fatalf("create reissued CA with same key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func gatewayCertificateCSRFixture(t *testing.T, requestedURI string) (componentidentity.CertificateSigningRequest, string) {
	t.Helper()
	csr, err := componentidentity.GenerateCertificateSigningRequest(componentidentity.CertificateSigningRequestOptions{
		Profile:    componentidentity.CertificateProfileClient,
		CommonName: "gateway-newco-01",
		URIs:       []string{requestedURI},
	})
	if err != nil {
		t.Fatalf("GenerateCertificateSigningRequest error = %v", err)
	}
	spki, err := gatewaycert.SPKISHA256ForPublicKey(csr.Request.PublicKey)
	if err != nil {
		t.Fatalf("SPKISHA256ForPublicKey error = %v", err)
	}
	return csr, spki
}

func corruptCSRSignature(t *testing.T, der []byte) []byte {
	t.Helper()
	var parsed struct {
		TBS                asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("asn1.Unmarshal CSR error = %v rest=%d", err, len(rest))
	}
	if len(parsed.Signature.Bytes) == 0 {
		t.Fatal("CSR signature has no bytes")
	}
	parsed.Signature.Bytes = append([]byte(nil), parsed.Signature.Bytes...)
	parsed.Signature.Bytes[len(parsed.Signature.Bytes)-1] ^= 0x01
	out, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatalf("asn1.Marshal corrupted CSR error = %v", err)
	}
	return out
}

func errorsIsPlaneMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), gatewaycert.ErrPlaneIdentityMismatch.Error())
}

type preflightProvider struct {
	desc gatewaycert.TrustRootDescriptor
}

func (p preflightProvider) DescribeGatewayCertificatePlane(context.Context, gatewaycert.GatewayCertificatePlaneDescriptorRequest) (gatewaycert.TrustRootDescriptor, error) {
	return p.desc, nil
}

func (p preflightProvider) ProductionGatewayCertificateProvider() bool {
	return true
}

func (p preflightProvider) IssueRelayClient(context.Context, gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightProvider) IssueBusinessGateway(context.Context, gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightProvider) Rotate(context.Context, gatewaycert.GatewayCertificateRotateRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightProvider) Revoke(context.Context, gatewaycert.GatewayCertificateRevokeRequest) (gatewaycert.GatewayCertificateRevocation, error) {
	return gatewaycert.GatewayCertificateRevocation{}, errors.New("not implemented")
}

type preflightProviderWithoutDescriptor struct{}

func (p preflightProviderWithoutDescriptor) ProductionGatewayCertificateProvider() bool {
	return true
}

func (p preflightProviderWithoutDescriptor) IssueRelayClient(context.Context, gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightProviderWithoutDescriptor) IssueBusinessGateway(context.Context, gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightProviderWithoutDescriptor) Rotate(context.Context, gatewaycert.GatewayCertificateRotateRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightProviderWithoutDescriptor) Revoke(context.Context, gatewaycert.GatewayCertificateRevokeRequest) (gatewaycert.GatewayCertificateRevocation, error) {
	return gatewaycert.GatewayCertificateRevocation{}, errors.New("not implemented")
}

type preflightDescriptorOnlyProvider struct {
	desc gatewaycert.TrustRootDescriptor
}

func (p preflightDescriptorOnlyProvider) DescribeGatewayCertificatePlane(context.Context, gatewaycert.GatewayCertificatePlaneDescriptorRequest) (gatewaycert.TrustRootDescriptor, error) {
	return p.desc, nil
}

func (p preflightDescriptorOnlyProvider) IssueRelayClient(context.Context, gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightDescriptorOnlyProvider) IssueBusinessGateway(context.Context, gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightDescriptorOnlyProvider) Rotate(context.Context, gatewaycert.GatewayCertificateRotateRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	return gatewaycert.GatewayCertificateIssueResult{}, errors.New("not implemented")
}

func (p preflightDescriptorOnlyProvider) Revoke(context.Context, gatewaycert.GatewayCertificateRevokeRequest) (gatewaycert.GatewayCertificateRevocation, error) {
	return gatewaycert.GatewayCertificateRevocation{}, errors.New("not implemented")
}
