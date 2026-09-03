package testonly

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

const DefaultNonProductionTrustRootID = "dev-local-gateway-ca"

type NonProductionIssuer struct {
	TrustRootID string
	CA          componentidentity.CertificateAuthority
	Now         func() time.Time
}

type NonProductionIssuerOptions struct {
	TrustRootID string
	CommonName  string
	NotBefore   time.Time
	TTL         time.Duration
}

type PlaneIssuer struct {
	Descriptor gatewaycert.TrustRootDescriptor
	CA         componentidentity.CertificateAuthority
	Now        func() time.Time
}

type PlaneIssuerOptions struct {
	Descriptor gatewaycert.TrustRootDescriptor
	CommonName string
	NotBefore  time.Time
	TTL        time.Duration
}

type PlaneIssueOptions struct {
	SPIFFEID   string
	CommonName string
	NotBefore  time.Time
	TTL        time.Duration
}

type PlaneIssuedCertificate struct {
	TrustRootID  string
	Plane        gatewaycert.CertificatePlane
	SPIFFEID     string
	Certificate  *x509.Certificate
	CertPEM      []byte
	KeyPEM       []byte
	TrustRootPEM []byte
}

func NewNonProductionIssuer(opts NonProductionIssuerOptions) (NonProductionIssuer, gatewaycert.TrustRoot, error) {
	trustRootID := strings.TrimSpace(opts.TrustRootID)
	if trustRootID == "" {
		trustRootID = DefaultNonProductionTrustRootID
	}
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "builders-net non-production gateway CA"
	}
	ca, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: commonName,
		NotBefore:  notBefore,
		TTL:        ttl,
	})
	if err != nil {
		return NonProductionIssuer{}, gatewaycert.TrustRoot{}, err
	}
	root, err := gatewaycert.TrustRootFromPEM(trustRootID, ca.CertPEM)
	if err != nil {
		return NonProductionIssuer{}, gatewaycert.TrustRoot{}, err
	}
	return NonProductionIssuer{TrustRootID: trustRootID, CA: ca}, root, nil
}

func NewPlaneIssuer(opts PlaneIssuerOptions) (PlaneIssuer, gatewaycert.TrustRoot, error) {
	desc := opts.Descriptor
	if strings.TrimSpace(desc.ID) == "" {
		return PlaneIssuer{}, gatewaycert.TrustRoot{}, errors.New("test plane issuer requires trust root descriptor id")
	}
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "builders-net test " + string(desc.Plane) + " CA"
	}
	ca, err := componentidentity.GenerateCertificateAuthority(componentidentity.CertificateAuthorityOptions{
		CommonName: commonName,
		NotBefore:  notBefore,
		TTL:        ttl,
	})
	if err != nil {
		return PlaneIssuer{}, gatewaycert.TrustRoot{}, err
	}
	root, err := gatewaycert.TrustRootFromPEMWithDescriptor(desc, ca.CertPEM)
	if err != nil {
		return PlaneIssuer{}, gatewaycert.TrustRoot{}, err
	}
	return PlaneIssuer{Descriptor: root.PlaneDescriptor, CA: ca}, root, nil
}

func (i NonProductionIssuer) IssueGatewayCertificate(_ context.Context, opts gatewaycert.IssueOptions) (gatewaycert.IssuedCertificate, error) {
	if i.CA.Certificate == nil || i.CA.PrivateKey == nil {
		return gatewaycert.IssuedCertificate{}, errors.New("gateway certificate issuer requires a certificate authority")
	}
	identity := componentidentity.GatewayIdentity{
		TenantID:           strings.TrimSpace(opts.TenantID),
		GatewayID:          strings.TrimSpace(opts.GatewayID),
		ServicePrincipalID: strings.TrimSpace(opts.ServicePrincipalID),
	}
	if identity.TenantID == "" || identity.GatewayID == "" {
		return gatewaycert.IssuedCertificate{}, errors.New("gateway certificate tenant and gateway id are required")
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "federation-gateway " + identity.GatewayID
	}
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = i.now()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	issued, err := componentidentity.IssueCertificate(componentidentity.CertificateIssueOptions{
		Profile:    componentidentity.CertificateProfileClient,
		CommonName: commonName,
		URIs:       []string{componentidentity.GatewayURI(identity)},
		NotBefore:  notBefore,
		TTL:        ttl,
		CA:         i.CA,
	})
	if err != nil {
		return gatewaycert.IssuedCertificate{}, err
	}
	certIdentity, err := componentidentity.GatewayIdentityFromCertificate(issued.Certificate)
	if err != nil {
		return gatewaycert.IssuedCertificate{}, err
	}
	return gatewaycert.IssuedCertificate{
		TrustRootID:  strings.TrimSpace(i.TrustRootID),
		Identity:     certIdentity,
		Certificate:  issued.Certificate,
		CertPEM:      issued.CertPEM,
		KeyPEM:       issued.KeyPEM,
		TrustRootPEM: i.CA.CertPEM,
	}, nil
}

func (i PlaneIssuer) IssuePlaneCertificate(_ context.Context, opts PlaneIssueOptions) (PlaneIssuedCertificate, error) {
	if i.CA.Certificate == nil || i.CA.PrivateKey == nil {
		return PlaneIssuedCertificate{}, errors.New("plane certificate issuer requires a certificate authority")
	}
	spiffeID := strings.TrimSpace(opts.SPIFFEID)
	if spiffeID == "" {
		return PlaneIssuedCertificate{}, errors.New("plane certificate SPIFFE ID is required")
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "test " + string(i.Descriptor.Plane)
	}
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = i.now()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	issued, err := componentidentity.IssueCertificate(componentidentity.CertificateIssueOptions{
		Profile:    componentidentity.CertificateProfileClient,
		CommonName: commonName,
		URIs:       []string{spiffeID},
		NotBefore:  notBefore,
		TTL:        ttl,
		CA:         i.CA,
	})
	if err != nil {
		return PlaneIssuedCertificate{}, err
	}
	return PlaneIssuedCertificate{
		TrustRootID:  i.Descriptor.ID,
		Plane:        i.Descriptor.Plane,
		SPIFFEID:     spiffeID,
		Certificate:  issued.Certificate,
		CertPEM:      issued.CertPEM,
		KeyPEM:       issued.KeyPEM,
		TrustRootPEM: i.CA.CertPEM,
	}, nil
}

func (i NonProductionIssuer) now() time.Time {
	if i.Now != nil {
		return i.Now().UTC()
	}
	return time.Now().UTC()
}

func (i PlaneIssuer) now() time.Time {
	if i.Now != nil {
		return i.Now().UTC()
	}
	return time.Now().UTC()
}
