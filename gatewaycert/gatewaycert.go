package gatewaycert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

type Issuer interface {
	IssueGatewayCertificate(context.Context, IssueOptions) (IssuedCertificate, error)
}

type Verifier interface {
	VerifyGatewayCertificate(context.Context, VerifyOptions) (Verification, error)
}

type TrustRoot struct {
	ID              string
	PEM             []byte
	Certificates    []*x509.Certificate
	PlaneDescriptor TrustRootDescriptor
}

type IssueOptions struct {
	TenantID           string
	GatewayID          string
	ServicePrincipalID string
	CommonName         string
	NotBefore          time.Time
	TTL                time.Duration
}

type IssuedCertificate struct {
	TrustRootID  string
	Identity     componentidentity.GatewayIdentity
	Certificate  *x509.Certificate
	CertPEM      []byte
	KeyPEM       []byte
	TrustRootPEM []byte
}

type VerifyOptions struct {
	CertificatePEM             []byte
	TrustRoots                 []TrustRoot
	TrustRootID                string
	ExpectedTenantID           string
	ExpectedGatewayID          string
	ExpectedServicePrincipalID string
	ExpectedSPIFFEID           string
	ExpectedSubject            string
	MinValidFor                time.Duration
	Now                        time.Time
}

type Verification struct {
	TrustRootID       string
	Identity          componentidentity.GatewayIdentity
	Subject           string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

func VerifyGatewayCertificate(_ context.Context, opts VerifyOptions) (Verification, error) {
	leaf, intermediates, err := parseCertificatePEM(opts.CertificatePEM)
	if err != nil {
		return Verification{}, err
	}
	roots := selectedTrustRoots(opts.TrustRoots, opts.TrustRootID)
	if len(roots) == 0 {
		return Verification{}, errors.New("gateway certificate verifier requires a matching trust root")
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if opts.MinValidFor > 0 && now.Add(opts.MinValidFor).After(leaf.NotAfter) {
		return Verification{}, fmt.Errorf("gateway certificate expires before required rotation window: not_after=%s min_valid_for=%s", leaf.NotAfter.UTC().Format(time.RFC3339), opts.MinValidFor)
	}
	identity, err := componentidentity.GatewayIdentityFromCertificate(leaf)
	if err != nil {
		return Verification{}, err
	}
	if err := verifyExpectedIdentity(identity, opts); err != nil {
		return Verification{}, err
	}
	rootID, err := verifyAgainstTrustRoots(leaf, intermediates, roots, now)
	if err != nil {
		return Verification{}, err
	}
	return Verification{
		TrustRootID:       rootID,
		Identity:          identity,
		Subject:           identity.Subject,
		FingerprintSHA256: identity.FingerprintSHA256,
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
	}, nil
}

type StaticVerifier struct {
	TrustRoots []TrustRoot
	Now        func() time.Time
}

func (v StaticVerifier) VerifyGatewayCertificate(ctx context.Context, opts VerifyOptions) (Verification, error) {
	opts.TrustRoots = append([]TrustRoot(nil), v.TrustRoots...)
	if opts.Now.IsZero() && v.Now != nil {
		opts.Now = v.Now().UTC()
	}
	return VerifyGatewayCertificate(ctx, opts)
}

func TrustRootFromPEM(id string, pemBytes []byte) (TrustRoot, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return TrustRoot{}, errors.New("gateway trust root id is required")
	}
	certs, err := parseCertificates(pemBytes)
	if err != nil {
		return TrustRoot{}, err
	}
	if len(certs) == 0 {
		return TrustRoot{}, errors.New("gateway trust root PEM does not contain certificates")
	}
	for _, cert := range certs {
		if !cert.IsCA {
			return TrustRoot{}, fmt.Errorf("gateway trust root %q contains non-CA certificate %s", id, cert.Subject.String())
		}
	}
	return TrustRoot{ID: id, PEM: append([]byte(nil), pemBytes...), Certificates: certs}, nil
}

func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certs, err := parseCertificates(pemBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("gateway certificate PEM does not contain a leaf certificate")
	}
	return certs[0], certs[1:], nil
}

func parseCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	rest := append([]byte(nil), pemBytes...)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse gateway certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func selectedTrustRoots(roots []TrustRoot, trustRootID string) []TrustRoot {
	trustRootID = strings.TrimSpace(trustRootID)
	out := make([]TrustRoot, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root.ID) == "" || len(root.Certificates) == 0 {
			continue
		}
		if trustRootID == "" || root.ID == trustRootID {
			out = append(out, root)
		}
	}
	return out
}

func verifyAgainstTrustRoots(leaf *x509.Certificate, intermediates []*x509.Certificate, roots []TrustRoot, now time.Time) (string, error) {
	return verifyAgainstTrustRootsForUsage(leaf, intermediates, roots, now, x509.ExtKeyUsageClientAuth, "")
}

func verifyAgainstTrustRootsForPlane(leaf *x509.Certificate, intermediates []*x509.Certificate, roots []TrustRoot, now time.Time, plane CertificatePlane, serverName string) (string, error) {
	usage, err := extKeyUsageForPlane(plane)
	if err != nil {
		return "", err
	}
	return verifyAgainstTrustRootsForUsage(leaf, intermediates, roots, now, usage, serverName)
}

// verifyAgainstTrustRootsForUsage chains the leaf to one of the selected trust
// roots. A non-empty serverName is passed to x509.VerifyOptions.DNSName so a
// server-auth leaf must carry it as a DNS SAN; client-auth verification passes
// "" and binds the SPIFFE URI at a higher layer instead.
func verifyAgainstTrustRootsForUsage(leaf *x509.Certificate, intermediates []*x509.Certificate, roots []TrustRoot, now time.Time, usage x509.ExtKeyUsage, serverName string) (string, error) {
	intermediatePool := x509.NewCertPool()
	for _, cert := range intermediates {
		intermediatePool.AddCert(cert)
	}
	for _, root := range roots {
		rootPool := x509.NewCertPool()
		for _, cert := range root.Certificates {
			rootPool.AddCert(cert)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       serverName,
			Roots:         rootPool,
			Intermediates: intermediatePool,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{usage},
		}); err == nil {
			return root.ID, nil
		}
	}
	return "", errors.New("gateway certificate did not verify against selected trust roots")
}

func extKeyUsageForPlane(plane CertificatePlane) (x509.ExtKeyUsage, error) {
	switch plane {
	case PlaneGatewayTransport, PlaneRelayCellServer:
		return x509.ExtKeyUsageServerAuth, nil
	case PlaneRelayGatewayClient, PlaneGatewayBusiness, PlaneRelayCellBackplane:
		return x509.ExtKeyUsageClientAuth, nil
	default:
		return 0, fmt.Errorf("%w: unsupported certificate plane %q", ErrPlaneIdentityMismatch, plane)
	}
}

func verifyExpectedIdentity(identity componentidentity.GatewayIdentity, opts VerifyOptions) error {
	checks := []struct {
		name string
		want string
		got  string
	}{
		{name: "tenant", want: opts.ExpectedTenantID, got: identity.TenantID},
		{name: "gateway", want: opts.ExpectedGatewayID, got: identity.GatewayID},
		{name: "service principal", want: opts.ExpectedServicePrincipalID, got: identity.ServicePrincipalID},
		{name: "spiffe", want: opts.ExpectedSPIFFEID, got: identity.SPIFFEID},
		{name: "subject", want: opts.ExpectedSubject, got: identity.Subject},
	}
	for _, check := range checks {
		want := strings.TrimSpace(check.want)
		if want == "" {
			continue
		}
		if strings.TrimSpace(check.got) != want {
			return fmt.Errorf("gateway certificate %s mismatch: got %q want %q", check.name, check.got, want)
		}
	}
	return nil
}
