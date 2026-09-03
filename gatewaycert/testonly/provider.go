package testonly

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
)

const (
	DefaultTestOnlyRelayGatewayClientTrustRootID = "testonly-relay-gateway-client-ca"
	DefaultTestOnlyGatewayTransportTrustRootID   = "testonly-gateway-transport-server-ca"
	DefaultTestOnlyGatewayBusinessTrustRootID    = "testonly-gateway-business-ca"
)

type TestOnlyGatewayCertificateProvider struct {
	RelayGatewayClientIssuer PlaneIssuer
	RelayGatewayClientRoot   gatewaycert.TrustRoot
	GatewayTransportIssuer   PlaneIssuer
	GatewayTransportRoot     gatewaycert.TrustRoot
	GatewayBusinessIssuer    PlaneIssuer
	GatewayBusinessRoot      gatewaycert.TrustRoot
	Now                      func() time.Time
}

type TestOnlyGatewayCertificateProviderOptions struct {
	NotBefore time.Time
	TTL       time.Duration
	Now       func() time.Time
}

func NewTestOnlyGatewayCertificateProvider(opts TestOnlyGatewayCertificateProviderOptions) (TestOnlyGatewayCertificateProvider, error) {
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	relayIssuer, relayRoot, err := NewPlaneIssuer(PlaneIssuerOptions{
		Descriptor: gatewaycert.TrustRootDescriptor{
			ID:                  DefaultTestOnlyRelayGatewayClientTrustRootID,
			Plane:               gatewaycert.PlaneRelayGatewayClient,
			SPIFFENamespace:     gatewaycert.RelayGatewayClientNamespace,
			VerifierAudience:    "gateway-to-relay client mtls",
			ActivationNotBefore: notBefore,
			ActivationNotAfter:  notBefore.Add(ttl),
			Production:          false,
		},
		CommonName: "builders-net test-only relay gateway-client CA",
		NotBefore:  notBefore,
		TTL:        ttl,
	})
	if err != nil {
		return TestOnlyGatewayCertificateProvider{}, err
	}
	transportIssuer, transportRoot, err := NewPlaneIssuer(PlaneIssuerOptions{
		Descriptor: gatewaycert.TrustRootDescriptor{
			ID:                  DefaultTestOnlyGatewayTransportTrustRootID,
			Plane:               gatewaycert.PlaneGatewayTransport,
			SPIFFENamespace:     gatewaycert.GatewayTransportNamespace,
			VerifierAudience:    "gateway transport server mtls",
			ActivationNotBefore: notBefore,
			ActivationNotAfter:  notBefore.Add(ttl),
			Production:          false,
		},
		CommonName: "builders-net test-only gateway transport-server CA",
		NotBefore:  notBefore,
		TTL:        ttl,
	})
	if err != nil {
		return TestOnlyGatewayCertificateProvider{}, err
	}
	businessIssuer, businessRoot, err := NewPlaneIssuer(PlaneIssuerOptions{
		Descriptor: gatewaycert.TrustRootDescriptor{
			ID:                  DefaultTestOnlyGatewayBusinessTrustRootID,
			Plane:               gatewaycert.PlaneGatewayBusiness,
			SPIFFENamespace:     gatewaycert.GatewayBusinessNamespace,
			VerifierAudience:    "gateway business facade mtls",
			ActivationNotBefore: notBefore,
			ActivationNotAfter:  notBefore.Add(ttl),
			Production:          false,
		},
		CommonName: "builders-net test-only gateway business CA",
		NotBefore:  notBefore,
		TTL:        ttl,
	})
	if err != nil {
		return TestOnlyGatewayCertificateProvider{}, err
	}
	return TestOnlyGatewayCertificateProvider{
		RelayGatewayClientIssuer: relayIssuer,
		RelayGatewayClientRoot:   relayRoot,
		GatewayTransportIssuer:   transportIssuer,
		GatewayTransportRoot:     transportRoot,
		GatewayBusinessIssuer:    businessIssuer,
		GatewayBusinessRoot:      businessRoot,
		Now:                      opts.Now,
	}, nil
}

func (p TestOnlyGatewayCertificateProvider) TrustRoots() []gatewaycert.TrustRoot {
	return []gatewaycert.TrustRoot{p.RelayGatewayClientRoot, p.GatewayTransportRoot, p.GatewayBusinessRoot}
}

func (p TestOnlyGatewayCertificateProvider) DescribeGatewayCertificatePlane(_ context.Context, request gatewaycert.GatewayCertificatePlaneDescriptorRequest) (gatewaycert.TrustRootDescriptor, error) {
	root, err := p.rootForPlane(request.Plane)
	if err != nil {
		return gatewaycert.TrustRootDescriptor{}, err
	}
	return root.PlaneDescriptor, nil
}

func (p TestOnlyGatewayCertificateProvider) IssueRelayClient(ctx context.Context, request gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	spiffeID := gatewaycert.RelayGatewayClientSPIFFE(request.FabricID, request.OrgID, request.GatewayID)
	return p.issue(ctx, gatewaycert.PlaneRelayGatewayClient, p.RelayGatewayClientIssuer, p.RelayGatewayClientRoot, spiffeID, request)
}

func (p TestOnlyGatewayCertificateProvider) IssueGatewayTransportServer(ctx context.Context, request gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	spiffeID := gatewaycert.GatewayTransportSPIFFE(request.FabricID, request.OrgID, request.GatewayID)
	return p.issue(ctx, gatewaycert.PlaneGatewayTransport, p.GatewayTransportIssuer, p.GatewayTransportRoot, spiffeID, request)
}

func (p TestOnlyGatewayCertificateProvider) IssueBusinessGateway(ctx context.Context, request gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	spiffeID := gatewaycert.GatewayBusinessSPIFFE(request.OrgID, request.GatewayID)
	return p.issue(ctx, gatewaycert.PlaneGatewayBusiness, p.GatewayBusinessIssuer, p.GatewayBusinessRoot, spiffeID, request)
}

func (p TestOnlyGatewayCertificateProvider) Rotate(ctx context.Context, request gatewaycert.GatewayCertificateRotateRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	switch request.Plane {
	case gatewaycert.PlaneRelayGatewayClient:
		return p.IssueRelayClient(ctx, request.IssueRequest)
	case gatewaycert.PlaneGatewayTransport:
		return p.IssueGatewayTransportServer(ctx, request.IssueRequest)
	case gatewaycert.PlaneGatewayBusiness:
		return p.IssueBusinessGateway(ctx, request.IssueRequest)
	default:
		return gatewaycert.GatewayCertificateIssueResult{}, fmt.Errorf("%w: unsupported gateway rotation plane %q", gatewaycert.ErrPlaneIdentityMismatch, request.Plane)
	}
}

func (p TestOnlyGatewayCertificateProvider) Revoke(_ context.Context, request gatewaycert.GatewayCertificateRevokeRequest) (gatewaycert.GatewayCertificateRevocation, error) {
	root, err := p.rootForPlane(request.Plane)
	if err != nil {
		return gatewaycert.GatewayCertificateRevocation{}, err
	}
	serial := strings.TrimSpace(request.SerialNumber)
	if serial == "" {
		return gatewaycert.GatewayCertificateRevocation{}, errors.New("gateway certificate revocation requires serial number")
	}
	revokedAt := request.RevokedAt.UTC()
	if revokedAt.IsZero() {
		revokedAt = p.now()
	}
	return gatewaycert.GatewayCertificateRevocation{
		Plane:                request.Plane,
		TrustRootID:          root.ID,
		SerialNumber:         serial,
		RevocationGeneration: root.PlaneDescriptor.RevocationGeneration + 1,
		RevokedAt:            revokedAt,
	}, nil
}

func (p TestOnlyGatewayCertificateProvider) issue(_ context.Context, plane gatewaycert.CertificatePlane, issuer PlaneIssuer, root gatewaycert.TrustRoot, spiffeID string, request gatewaycert.GatewayCertificateIssueRequest) (gatewaycert.GatewayCertificateIssueResult, error) {
	if err := gatewaycert.ValidateGatewayCertificateIssueRequest(plane, request); err != nil {
		return gatewaycert.GatewayCertificateIssueResult{}, err
	}
	parsedCSR, err := gatewaycert.ParseGatewayCertificateCSR(request.CSR)
	if err != nil {
		return gatewaycert.GatewayCertificateIssueResult{}, err
	}
	cert, certPEM, err := issueCSRWithPlaneRoot(issuer, parsedCSR.Request, spiffeID, request, plane, p.now())
	if err != nil {
		return gatewaycert.GatewayCertificateIssueResult{}, err
	}
	evidence, err := gatewaycert.GatewayCertificateEvidenceFromIssued(plane, root, cert, parsedCSR.SPKISHA256)
	if err != nil {
		return gatewaycert.GatewayCertificateIssueResult{}, err
	}
	return gatewaycert.GatewayCertificateIssueResult{
		Plane:               plane,
		CertificatePEM:      certPEM,
		CertificateChainPEM: append(append([]byte(nil), certPEM...), issuer.CA.CertPEM...),
		TrustRootPEM:        append([]byte(nil), issuer.CA.CertPEM...),
		Evidence:            evidence,
	}, nil
}

func (p TestOnlyGatewayCertificateProvider) rootForPlane(plane gatewaycert.CertificatePlane) (gatewaycert.TrustRoot, error) {
	switch plane {
	case gatewaycert.PlaneRelayGatewayClient:
		return p.RelayGatewayClientRoot, nil
	case gatewaycert.PlaneGatewayTransport:
		return p.GatewayTransportRoot, nil
	case gatewaycert.PlaneGatewayBusiness:
		return p.GatewayBusinessRoot, nil
	default:
		return gatewaycert.TrustRoot{}, fmt.Errorf("%w: unsupported gateway certificate revocation plane %q", gatewaycert.ErrPlaneIdentityMismatch, plane)
	}
}

func (p TestOnlyGatewayCertificateProvider) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func issueCSRWithPlaneRoot(issuer PlaneIssuer, request *x509.CertificateRequest, spiffeID string, opts gatewaycert.GatewayCertificateIssueRequest, plane gatewaycert.CertificatePlane, now time.Time) (*x509.Certificate, []byte, error) {
	if issuer.CA.Certificate == nil || issuer.CA.PrivateKey == nil {
		return nil, nil, errors.New("test-only gateway certificate provider requires a certificate authority")
	}
	if request == nil {
		return nil, nil, errors.New("parsed CSR is required")
	}
	uri, err := url.Parse(strings.TrimSpace(spiffeID))
	if err != nil {
		return nil, nil, fmt.Errorf("parse derived SPIFFE ID: %w", err)
	}
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = now.UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = strings.TrimSpace(opts.GatewayID)
	}
	if commonName == "" {
		commonName = "test-only gateway certificate"
	}
	keyUsage, err := keyUsageForPlane(plane)
	if err != nil {
		return nil, nil, err
	}
	serial, err := testOnlyRandomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{keyUsage},
		URIs:         []*url.URL{uri},
		DNSNames:     append([]string(nil), opts.DNSNames...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.CA.Certificate, request.PublicKey, issuer.CA.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issue test-only gateway certificate from CSR: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse issued test-only gateway certificate: %w", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func keyUsageForPlane(plane gatewaycert.CertificatePlane) (x509.ExtKeyUsage, error) {
	switch plane {
	case gatewaycert.PlaneGatewayTransport:
		return x509.ExtKeyUsageServerAuth, nil
	case gatewaycert.PlaneRelayGatewayClient, gatewaycert.PlaneGatewayBusiness, gatewaycert.PlaneRelayCellBackplane:
		return x509.ExtKeyUsageClientAuth, nil
	default:
		return 0, fmt.Errorf("%w: unsupported gateway certificate plane %q", gatewaycert.ErrPlaneIdentityMismatch, plane)
	}
}

func testOnlyRandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate test-only gateway certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

var _ gatewaycert.GatewayCertificateProvider = TestOnlyGatewayCertificateProvider{}
var _ gatewaycert.GatewayTransportServerCertificateProvider = TestOnlyGatewayCertificateProvider{}
