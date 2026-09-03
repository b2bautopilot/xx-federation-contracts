package gatewaycert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

const (
	relayGatewayClientVerifierAudience = "gateway-to-relay client mtls"
	gatewayTransportVerifierAudience   = "gateway transport server mtls"
	relayCellBackplaneVerifierAudience = "relay-cell backplane mtls"
	relayCellServerVerifierAudience    = "relay-cell :443 server mtls"
)

// ExternalCAGatewayCertificateProvider is the first real external_ca provider
// path. It supports relay gateway-client issuance and, when configured with a
// distinct server CA, the gateway transport-server plane. Business-facade and
// relay-cell roots need separate production providers before go-live.
type ExternalCAGatewayCertificateProvider struct {
	config           GatewayCertificateProviderConfig
	relayCA          componentidentity.CertificateAuthority
	relayRoot        TrustRoot
	serverCA         componentidentity.CertificateAuthority
	serverRoot       TrustRoot
	serverConfigured bool

	backplaneCA         componentidentity.CertificateAuthority
	backplaneRoot       TrustRoot
	backplaneConfigured bool

	serverCellCA         componentidentity.CertificateAuthority
	serverCellRoot       TrustRoot
	serverCellConfigured bool

	now func() time.Time
}

type ExternalCAGatewayCertificateProviderOptions struct {
	Config GatewayCertificateProviderConfig
	Now    func() time.Time
}

func NewExternalCAGatewayCertificateProvider(opts ExternalCAGatewayCertificateProviderOptions) (ExternalCAGatewayCertificateProvider, error) {
	cfg := opts.Config
	if cfg.Kind != GatewayCertificateProviderKindExternalCA {
		return ExternalCAGatewayCertificateProvider{}, fmt.Errorf("external CA provider requires kind %q", GatewayCertificateProviderKindExternalCA)
	}
	if strings.TrimSpace(cfg.CACertFile) == "" || strings.TrimSpace(cfg.CAKeyFile) == "" {
		return ExternalCAGatewayCertificateProvider{}, errors.New("external CA provider requires CA certificate and key files")
	}
	relayCA, err := componentidentity.LoadCertificateAuthority(cfg.CACertFile, cfg.CAKeyFile)
	if err != nil {
		return ExternalCAGatewayCertificateProvider{}, err
	}
	if err := validateExternalCA(relayCA); err != nil {
		return ExternalCAGatewayCertificateProvider{}, err
	}
	desc := TrustRootDescriptor{
		ID:                  externalCATrustRootID(PlaneRelayGatewayClient, relayCA.Certificate),
		Plane:               PlaneRelayGatewayClient,
		SPIFFENamespace:     RelayGatewayClientNamespace,
		VerifierAudience:    relayGatewayClientVerifierAudience,
		ActivationNotBefore: relayCA.Certificate.NotBefore.UTC(),
		ActivationNotAfter:  relayCA.Certificate.NotAfter.UTC(),
		Production:          cfg.Production,
	}
	relayRoot, err := TrustRootFromPEMWithDescriptor(desc, relayCA.CertPEM)
	if err != nil {
		return ExternalCAGatewayCertificateProvider{}, err
	}
	var serverCA componentidentity.CertificateAuthority
	var serverRoot TrustRoot
	serverConfigured := strings.TrimSpace(cfg.ServerCACertFile) != "" || strings.TrimSpace(cfg.ServerCAKeyFile) != ""
	if serverConfigured {
		if strings.TrimSpace(cfg.ServerCACertFile) == "" || strings.TrimSpace(cfg.ServerCAKeyFile) == "" {
			return ExternalCAGatewayCertificateProvider{}, errors.New("external CA provider server CA requires certificate and key files")
		}
		serverCA, err = componentidentity.LoadCertificateAuthority(cfg.ServerCACertFile, cfg.ServerCAKeyFile)
		if err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
		if err := validateExternalCA(serverCA); err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
		// (distinct-CA isolation is enforced once over ALL configured plane CAs
		// after loading — see ensureDistinctConfiguredCAs below.)
		serverDesc := TrustRootDescriptor{
			ID:                  externalCATrustRootID(PlaneGatewayTransport, serverCA.Certificate),
			Plane:               PlaneGatewayTransport,
			SPIFFENamespace:     GatewayTransportNamespace,
			VerifierAudience:    gatewayTransportVerifierAudience,
			ActivationNotBefore: serverCA.Certificate.NotBefore.UTC(),
			ActivationNotAfter:  serverCA.Certificate.NotAfter.UTC(),
			Production:          cfg.Production,
		}
		serverRoot, err = TrustRootFromPEMWithDescriptor(serverDesc, serverCA.CertPEM)
		if err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
	}
	var backplaneCA componentidentity.CertificateAuthority
	var backplaneRoot TrustRoot
	backplaneConfigured := strings.TrimSpace(cfg.BackplaneCACertFile) != "" || strings.TrimSpace(cfg.BackplaneCAKeyFile) != ""
	if backplaneConfigured {
		if strings.TrimSpace(cfg.BackplaneCACertFile) == "" || strings.TrimSpace(cfg.BackplaneCAKeyFile) == "" {
			return ExternalCAGatewayCertificateProvider{}, errors.New("external CA provider backplane CA requires certificate and key files")
		}
		backplaneCA, err = componentidentity.LoadCertificateAuthority(cfg.BackplaneCACertFile, cfg.BackplaneCAKeyFile)
		if err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
		if err := validateExternalCA(backplaneCA); err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
		backplaneDesc := TrustRootDescriptor{
			ID:                  externalCATrustRootID(PlaneRelayCellBackplane, backplaneCA.Certificate),
			Plane:               PlaneRelayCellBackplane,
			SPIFFENamespace:     RelayCellBackplaneNamespace,
			VerifierAudience:    relayCellBackplaneVerifierAudience,
			ActivationNotBefore: backplaneCA.Certificate.NotBefore.UTC(),
			ActivationNotAfter:  backplaneCA.Certificate.NotAfter.UTC(),
			Production:          cfg.Production,
		}
		backplaneRoot, err = TrustRootFromPEMWithDescriptor(backplaneDesc, backplaneCA.CertPEM)
		if err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
	}
	var serverCellCA componentidentity.CertificateAuthority
	var serverCellRoot TrustRoot
	serverCellConfigured := strings.TrimSpace(cfg.RelayCellServerCACertFile) != "" || strings.TrimSpace(cfg.RelayCellServerCAKeyFile) != ""
	if serverCellConfigured {
		if strings.TrimSpace(cfg.RelayCellServerCACertFile) == "" || strings.TrimSpace(cfg.RelayCellServerCAKeyFile) == "" {
			return ExternalCAGatewayCertificateProvider{}, errors.New("external CA provider relay-cell-server CA requires certificate and key files")
		}
		serverCellCA, err = componentidentity.LoadCertificateAuthority(cfg.RelayCellServerCACertFile, cfg.RelayCellServerCAKeyFile)
		if err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
		if err := validateExternalCA(serverCellCA); err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
		serverCellDesc := TrustRootDescriptor{
			ID:                  externalCATrustRootID(PlaneRelayCellServer, serverCellCA.Certificate),
			Plane:               PlaneRelayCellServer,
			SPIFFENamespace:     RelayCellServerNamespace,
			VerifierAudience:    relayCellServerVerifierAudience,
			ActivationNotBefore: serverCellCA.Certificate.NotBefore.UTC(),
			ActivationNotAfter:  serverCellCA.Certificate.NotAfter.UTC(),
			Production:          cfg.Production,
		}
		serverCellRoot, err = TrustRootFromPEMWithDescriptor(serverCellDesc, serverCellCA.CertPEM)
		if err != nil {
			return ExternalCAGatewayCertificateProvider{}, err
		}
	}
	// Cryptographic isolation: every configured plane CA must be a DISTINCT
	// certificate AND signing key from every other, so no plane can mint or verify
	// another plane's leaves. Pairwise over the configured set (relay-client always;
	// transport-server + backplane + relay-cell-server when configured); fail closed.
	if err := ensureDistinctConfiguredCAs([]configuredPlaneCA{
		{plane: PlaneRelayGatewayClient, ca: relayCA, configured: true},
		{plane: PlaneGatewayTransport, ca: serverCA, configured: serverConfigured},
		{plane: PlaneRelayCellBackplane, ca: backplaneCA, configured: backplaneConfigured},
		{plane: PlaneRelayCellServer, ca: serverCellCA, configured: serverCellConfigured},
	}); err != nil {
		return ExternalCAGatewayCertificateProvider{}, err
	}
	return ExternalCAGatewayCertificateProvider{
		config:               cfg,
		relayCA:              relayCA,
		relayRoot:            relayRoot,
		serverCA:             serverCA,
		serverRoot:           serverRoot,
		serverConfigured:     serverConfigured,
		backplaneCA:          backplaneCA,
		backplaneRoot:        backplaneRoot,
		backplaneConfigured:  backplaneConfigured,
		serverCellCA:         serverCellCA,
		serverCellRoot:       serverCellRoot,
		serverCellConfigured: serverCellConfigured,
		now:                  opts.Now,
	}, nil
}

type configuredPlaneCA struct {
	plane      CertificatePlane
	ca         componentidentity.CertificateAuthority
	configured bool
}

// ensureDistinctConfiguredCAs fails closed when any two CONFIGURED plane CAs share
// a certificate or signing key. It compares every unordered pair on both cert bytes
// AND SPKI public key (two independent properties; pairwise is required since
// distinctness is not transitive across both). The relay-client/transport-server
// pair preserves the original error strings (asserted by existing tests).
func ensureDistinctConfiguredCAs(entries []configuredPlaneCA) error {
	active := make([]configuredPlaneCA, 0, len(entries))
	for _, e := range entries {
		if e.configured {
			active = append(active, e)
		}
	}
	for i := 0; i < len(active); i++ {
		for j := i + 1; j < len(active); j++ {
			a, b := active[i], active[j]
			if bytes.Equal(a.ca.Certificate.Raw, b.ca.Certificate.Raw) {
				return errors.New(distinctCAErrorMessage(a.plane, b.plane, "certificates"))
			}
			same, err := sameCAPublicKey(a.ca, b.ca)
			if err != nil {
				return err
			}
			if same {
				return errors.New(distinctCAErrorMessage(a.plane, b.plane, "signing keys"))
			}
		}
	}
	return nil
}

func distinctCAErrorMessage(a, b CertificatePlane, kind string) string {
	return "external CA provider requires distinct " + planeShortName(a) + " and " + planeShortName(b) + " CA " + kind
}

func planeShortName(plane CertificatePlane) string {
	switch plane {
	case PlaneRelayGatewayClient:
		return "relay-client"
	case PlaneGatewayTransport:
		return "transport-server"
	case PlaneGatewayBusiness:
		return "business"
	case PlaneRelayCellBackplane:
		return "relay-cell-backplane"
	case PlaneRelayCellServer:
		return "relay-cell-server"
	default:
		return string(plane)
	}
}

func (p ExternalCAGatewayCertificateProvider) ProductionGatewayCertificateProvider() bool {
	return p.config.Production
}

func (p ExternalCAGatewayCertificateProvider) DescribeGatewayCertificatePlane(_ context.Context, request GatewayCertificatePlaneDescriptorRequest) (TrustRootDescriptor, error) {
	if strings.TrimSpace(p.config.FabricID) != "" && strings.TrimSpace(request.FabricID) != strings.TrimSpace(p.config.FabricID) {
		return TrustRootDescriptor{}, fmt.Errorf("%w: external CA fabric mismatch: provider=%q request=%q", ErrPlaneIdentityMismatch, p.config.FabricID, request.FabricID)
	}
	switch request.Plane {
	case PlaneRelayGatewayClient:
		return p.relayRoot.PlaneDescriptor, nil
	case PlaneGatewayTransport:
		if !p.serverConfigured {
			return TrustRootDescriptor{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneGatewayTransport)
		}
		return p.serverRoot.PlaneDescriptor, nil
	case PlaneRelayCellBackplane:
		if !p.backplaneConfigured {
			return TrustRootDescriptor{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneRelayCellBackplane)
		}
		return p.backplaneRoot.PlaneDescriptor, nil
	case PlaneRelayCellServer:
		if !p.serverCellConfigured {
			return TrustRootDescriptor{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneRelayCellServer)
		}
		return p.serverCellRoot.PlaneDescriptor, nil
	default:
		return TrustRootDescriptor{}, fmt.Errorf("%w: external CA provider does not support plane %q", ErrPlaneIdentityMismatch, request.Plane)
	}
}

func (p ExternalCAGatewayCertificateProvider) TrustRoots() []TrustRoot {
	roots := []TrustRoot{p.relayRoot}
	if p.serverConfigured {
		roots = append(roots, p.serverRoot)
	}
	if p.backplaneConfigured {
		roots = append(roots, p.backplaneRoot)
	}
	if p.serverCellConfigured {
		roots = append(roots, p.serverCellRoot)
	}
	return roots
}

func (p ExternalCAGatewayCertificateProvider) IssueRelayClient(_ context.Context, request GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	// Fail closed: the org segment becomes the control-plane TenantID, so the production
	// CA never mints a relay-client cert whose tenant is a domain/handle rather than a uuid.
	if err := ValidateRelayClientTenantID(request.OrgID); err != nil {
		return GatewayCertificateIssueResult{}, err
	}
	spiffeID := RelayGatewayClientSPIFFE(request.FabricID, request.OrgID, request.GatewayID)
	return p.issuePlane(PlaneRelayGatewayClient, p.relayCA, p.relayRoot, spiffeID, request)
}

func (p ExternalCAGatewayCertificateProvider) IssueGatewayTransportServer(_ context.Context, request GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	if !p.serverConfigured {
		return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneGatewayTransport)
	}
	spiffeID := GatewayTransportSPIFFE(request.FabricID, request.OrgID, request.GatewayID)
	return p.issuePlane(PlaneGatewayTransport, p.serverCA, p.serverRoot, spiffeID, request)
}

func (p ExternalCAGatewayCertificateProvider) IssueBusinessGateway(context.Context, GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA provider does not issue gateway business certificates in this slice", ErrPlaneIdentityMismatch)
}

// IssueRelayCellBackplane mints a relay-cell backplane leaf (relay_cell_backplane
// plane) under the distinct backplane CA. The leaf is fabric+cell scoped (no
// org/gateway). Fails closed when no backplane CA is configured. The cert carries
// ClientAuth EKU (matching the plane's mapping); the mutual cell↔cell listener and
// its EKU/ServerName decisions are wired in S2b.
func (p ExternalCAGatewayCertificateProvider) IssueRelayCellBackplane(_ context.Context, request GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	if !p.backplaneConfigured {
		return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneRelayCellBackplane)
	}
	spiffeID := RelayCellBackplaneSPIFFE(request.FabricID, request.RelayCellID)
	return p.issuePlane(PlaneRelayCellBackplane, p.backplaneCA, p.backplaneRoot, spiffeID, request)
}

// IssueRelayCellBackplaneServer mints the LISTENER-side relay-cell backplane leaf: the
// SAME relay_cell_backplane plane + distinct backplane CA, but role `backplane-server`
// with a ServerAuth EKU (vs IssueRelayCellBackplane's ClientAuth dialer leaf). It
// guarantees the backplane SPIFFE host is present as a DNS SAN so the mutual-mTLS dialer
// can verify the listener by ServerName + RootCAs=backplane CA. Two single-EKU roles,
// one CA — never a dual-EKU leaf (so it does not re-engage the keystone trap; and a
// gatewaycert-minted ServerAuth leaf is unrelated to x-mesh `--node-mode relay_server`).
// Issued only by the ExternalCA provider this slice (the testonly provider does not
// mirror it).
func (p ExternalCAGatewayCertificateProvider) IssueRelayCellBackplaneServer(_ context.Context, request GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	if !p.backplaneConfigured {
		return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneRelayCellBackplane)
	}
	request.DNSNames = appendIfMissing(request.DNSNames, relayCellBackplaneHost)
	spiffeID := RelayCellBackplaneServerSPIFFE(request.FabricID, request.RelayCellID)
	return p.issuePlane(PlaneRelayCellBackplane, p.backplaneCA, p.backplaneRoot, spiffeID, request)
}

// IssueRelayCellServer mints a relay cell's OUTER :443 mTLS server leaf (relay_cell_server
// plane, ServerAuth) under the distinct relay-cell-server CA. The leaf is fabric+cell scoped
// (no org/gateway) and carries the caller-supplied canonical hostname(s) as DNS SAN(s) — the
// value partner gateways verify by ServerName. The DNS SAN comes from request.DNSNames (the
// authority supplies the cell's canonical FQDN), NEVER the CSR (issueCSR ignores CSR-supplied
// SANs), so a node cannot request an impersonating hostname. Fails closed when no
// relay-cell-server CA is configured or no DNS SAN is supplied (enforced in the request validator).
func (p ExternalCAGatewayCertificateProvider) IssueRelayCellServer(_ context.Context, request GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	if !p.serverCellConfigured {
		return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA provider has no %q CA configured", ErrPlaneIdentityMismatch, PlaneRelayCellServer)
	}
	spiffeID := RelayCellServerSPIFFE(request.FabricID, request.RelayCellID)
	return p.issuePlane(PlaneRelayCellServer, p.serverCellCA, p.serverCellRoot, spiffeID, request)
}

// effectiveExtKeyUsage returns the single EKU for an issued leaf: the plane default
// (extKeyUsageForPlane) EXCEPT a relay-cell backplane SERVER SPIFFE (role/backplane-
// server), which gets ServerAuth so it can be the mutual-mTLS listener leaf — while the
// backplane dialer role (role/backplane) keeps the plane default ClientAuth. Each role
// stays single-EKU; the two share the one backplane CA.
func effectiveExtKeyUsage(plane CertificatePlane, spiffeURI *url.URL) (x509.ExtKeyUsage, error) {
	if plane == PlaneRelayCellBackplane && isRelayCellBackplaneServerSPIFFE(spiffeURI) {
		return x509.ExtKeyUsageServerAuth, nil
	}
	return extKeyUsageForPlane(plane)
}

// appendIfMissing returns vals with want appended if not already present.
func appendIfMissing(vals []string, want string) []string {
	for _, v := range vals {
		if v == want {
			return vals
		}
	}
	return append(append([]string(nil), vals...), want)
}

func (p ExternalCAGatewayCertificateProvider) Rotate(ctx context.Context, request GatewayCertificateRotateRequest) (GatewayCertificateIssueResult, error) {
	if request.Plane != PlaneRelayGatewayClient {
		return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA rotate supports only %q, got %q", ErrPlaneIdentityMismatch, PlaneRelayGatewayClient, request.Plane)
	}
	return p.IssueRelayClient(ctx, request.IssueRequest)
}

// Revoke returns registration-layer revocation metadata only. This file-backed
// provider does not publish CRLs, OCSP, or managed-CA revocation state; runtime
// enforcement is owned by the store/runtime credential usability gates.
func (p ExternalCAGatewayCertificateProvider) Revoke(_ context.Context, request GatewayCertificateRevokeRequest) (GatewayCertificateRevocation, error) {
	if request.Plane != PlaneRelayGatewayClient {
		return GatewayCertificateRevocation{}, fmt.Errorf("%w: external CA revoke supports only %q, got %q", ErrPlaneIdentityMismatch, PlaneRelayGatewayClient, request.Plane)
	}
	serial := strings.TrimSpace(request.SerialNumber)
	if serial == "" {
		return GatewayCertificateRevocation{}, errors.New("external CA revocation requires serial number")
	}
	revokedAt := request.RevokedAt.UTC()
	if revokedAt.IsZero() {
		revokedAt = p.currentTime()
	}
	return GatewayCertificateRevocation{
		Plane:                PlaneRelayGatewayClient,
		TrustRootID:          p.relayRoot.ID,
		SerialNumber:         serial,
		RevocationGeneration: p.relayRoot.PlaneDescriptor.RevocationGeneration + 1,
		RevokedAt:            revokedAt,
	}, nil
}

func (p ExternalCAGatewayCertificateProvider) issuePlane(plane CertificatePlane, ca componentidentity.CertificateAuthority, root TrustRoot, spiffeID string, request GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error) {
	if err := ValidateGatewayCertificateIssueRequest(plane, request); err != nil {
		return GatewayCertificateIssueResult{}, err
	}
	if strings.TrimSpace(p.config.FabricID) != "" && strings.TrimSpace(request.FabricID) != strings.TrimSpace(p.config.FabricID) {
		return GatewayCertificateIssueResult{}, fmt.Errorf("%w: external CA fabric mismatch: provider=%q request=%q", ErrPlaneIdentityMismatch, p.config.FabricID, request.FabricID)
	}
	parsedCSR, err := ParseGatewayCertificateCSR(request.CSR)
	if err != nil {
		return GatewayCertificateIssueResult{}, err
	}
	cert, certPEM, err := p.issueCSR(ca, parsedCSR.Request, spiffeID, request, plane)
	if err != nil {
		return GatewayCertificateIssueResult{}, err
	}
	evidence, err := GatewayCertificateEvidenceFromIssued(plane, root, cert, parsedCSR.SPKISHA256)
	if err != nil {
		return GatewayCertificateIssueResult{}, err
	}
	return GatewayCertificateIssueResult{
		Plane:               plane,
		CertificatePEM:      certPEM,
		CertificateChainPEM: append(append([]byte(nil), certPEM...), ca.CertPEM...),
		TrustRootPEM:        append([]byte(nil), ca.CertPEM...),
		Evidence:            evidence,
	}, nil
}

func (p ExternalCAGatewayCertificateProvider) issueCSR(ca componentidentity.CertificateAuthority, csr *x509.CertificateRequest, spiffeID string, opts GatewayCertificateIssueRequest, plane CertificatePlane) (*x509.Certificate, []byte, error) {
	if ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, nil, errors.New("external CA provider requires loaded CA material")
	}
	if csr == nil {
		return nil, nil, errors.New("parsed CSR is required")
	}
	uri, err := url.Parse(strings.TrimSpace(spiffeID))
	if err != nil {
		return nil, nil, fmt.Errorf("parse derived SPIFFE ID: %w", err)
	}
	notBefore := opts.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = p.currentTime()
	}
	if notBefore.Before(ca.Certificate.NotBefore) {
		notBefore = ca.Certificate.NotBefore.UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	notAfter := notBefore.Add(ttl)
	if notAfter.After(ca.Certificate.NotAfter) {
		notAfter = ca.Certificate.NotAfter.UTC()
	}
	if !notAfter.After(notBefore) {
		return nil, nil, errors.New("external CA certificate validity window is exhausted")
	}
	commonName := strings.TrimSpace(opts.GatewayID)
	if commonName == "" {
		commonName = "gateway " + string(plane)
	}
	keyUsage, err := effectiveExtKeyUsage(plane, uri)
	if err != nil {
		return nil, nil, err
	}
	serial, err := externalCARandomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{keyUsage},
		URIs:         []*url.URL{uri},
		DNSNames:     append([]string(nil), opts.DNSNames...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issue external CA gateway certificate from CSR: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse issued external CA gateway certificate: %w", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (p ExternalCAGatewayCertificateProvider) currentTime() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}
	return time.Now().UTC()
}

func validateExternalCA(ca componentidentity.CertificateAuthority) error {
	if ca.Certificate == nil || ca.PrivateKey == nil {
		return errors.New("external CA provider requires CA certificate and private key")
	}
	if !ca.Certificate.IsCA {
		return errors.New("external CA certificate is not a certificate authority")
	}
	if ca.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("external CA certificate is not allowed to sign certificates")
	}
	certPublic, err := x509.MarshalPKIXPublicKey(ca.Certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal external CA certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(ca.PrivateKey.Public())
	if err != nil {
		return fmt.Errorf("marshal external CA private key public key: %w", err)
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return errors.New("external CA certificate and private key do not match")
	}
	return nil
}

func sameCAPublicKey(a, b componentidentity.CertificateAuthority) (bool, error) {
	if a.Certificate == nil || b.Certificate == nil {
		return false, errors.New("external CA provider requires loaded CA certificates")
	}
	aSPKI, err := x509.MarshalPKIXPublicKey(a.Certificate.PublicKey)
	if err != nil {
		return false, fmt.Errorf("marshal CA public key (first): %w", err)
	}
	bSPKI, err := x509.MarshalPKIXPublicKey(b.Certificate.PublicKey)
	if err != nil {
		return false, fmt.Errorf("marshal CA public key (second): %w", err)
	}
	return bytes.Equal(aSPKI, bSPKI), nil
}

func externalCATrustRootID(plane CertificatePlane, cert *x509.Certificate) string {
	prefix := "external-ca-" + string(plane)
	if cert == nil {
		return prefix
	}
	sum := sha256.Sum256(cert.Raw)
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

func externalCARandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate external CA gateway certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

var _ GatewayCertificateProvider = ExternalCAGatewayCertificateProvider{}
var _ GatewayTransportServerCertificateProvider = ExternalCAGatewayCertificateProvider{}
var _ GatewayCertificatePlaneDescriptorProvider = ExternalCAGatewayCertificateProvider{}
var _ GatewayCertificateProductionProvider = ExternalCAGatewayCertificateProvider{}
