package gatewaycert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

const (
	CSRSPKIHashAlgorithmSHA256 = "sha256-spki"

	GatewayCertificateProviderKindUnconfigured   GatewayCertificateProviderKind = "unconfigured"
	GatewayCertificateProviderKindExternalCA     GatewayCertificateProviderKind = "external_ca"
	GatewayCertificateProviderKindTestOnlyMemory GatewayCertificateProviderKind = "testonly_in_memory"
)

var (
	ErrCSRBindingRequired  = errors.New("csr spki binding required")
	ErrCSRParseFailed      = errors.New("csr parse failed")
	ErrCSRSignatureInvalid = errors.New("csr signature invalid")
	ErrCSRSPKIMismatch     = errors.New("csr spki mismatch")
)

type GatewayCertificateProvider interface {
	IssueRelayClient(context.Context, GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error)
	IssueBusinessGateway(context.Context, GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error)
	Rotate(context.Context, GatewayCertificateRotateRequest) (GatewayCertificateIssueResult, error)
	Revoke(context.Context, GatewayCertificateRevokeRequest) (GatewayCertificateRevocation, error)
}

type GatewayTransportServerCertificateProvider interface {
	IssueGatewayTransportServer(context.Context, GatewayCertificateIssueRequest) (GatewayCertificateIssueResult, error)
}

type GatewayCertificatePlaneDescriptorProvider interface {
	DescribeGatewayCertificatePlane(context.Context, GatewayCertificatePlaneDescriptorRequest) (TrustRootDescriptor, error)
}

type GatewayCertificateProductionProvider interface {
	ProductionGatewayCertificateProvider() bool
}

type GatewayCertificatePlaneDescriptorRequest struct {
	Plane     CertificatePlane
	FabricID  string
	OrgID     string
	GatewayID string
}

type GatewayCertificateProviderKind string

type GatewayCertificateProviderConfig struct {
	Kind     GatewayCertificateProviderKind
	FabricID string

	Production bool

	CACertFile string
	CAKeyFile  string

	ServerCACertFile string
	ServerCAKeyFile  string

	// Backplane CA (relay_cell_backplane plane) — distinct root + key from the
	// relay-client and transport-server CAs (enforced fail-closed at construction).
	// Optional: when unset, the provider does not issue backplane certs.
	BackplaneCACertFile string
	BackplaneCAKeyFile  string

	// Relay-cell-server CA (relay_cell_server plane, A2b) — the cell's OUTER :443 server leaf.
	// Distinct root + key from every other plane CA (enforced fail-closed at construction).
	// Optional: when unset, the provider does not issue relay-cell server certs.
	RelayCellServerCACertFile string
	RelayCellServerCAKeyFile  string
}

type GatewayCertificateIssueRequest struct {
	FabricID   string
	OrgID      string
	GatewayID  string
	CommonName string

	// RelayCellID identifies the relay cell for the relay_cell_backplane plane
	// (which is fabric+cell scoped and has no org/gateway). Required for backplane
	// issuance; ignored by the relay-client / transport-server / business planes.
	RelayCellID string

	CSR GatewayCertificateCSR

	NotBefore time.Time
	TTL       time.Duration

	// DNSNames, when set, are added as the issued certificate's DNS SANs. Used
	// for the transport-server plane — the inner-mTLS server certificate needs a
	// DNS SAN for the peer's ServerName check. The relay-client plane sets none.
	// CSR-supplied DNS names remain ignored: only this server-controlled field is
	// honored, so a gateway cannot request an arbitrary/impersonating SAN.
	DNSNames []string
}

type GatewayCertificateRotateRequest struct {
	Plane                CertificatePlane
	IssueRequest         GatewayCertificateIssueRequest
	PreviousSerialNumber string
	Reason               string
}

type GatewayCertificateRevokeRequest struct {
	Plane        CertificatePlane
	TrustRootID  string
	SerialNumber string
	GatewayID    string
	Reason       string
	RevokedAt    time.Time
}

type GatewayCertificateCSR struct {
	PEM []byte
	DER []byte

	ExpectedSPKISHA256 string
}

type ParsedGatewayCertificateCSR struct {
	Request       *x509.CertificateRequest
	SPKISHA256    string
	RawDER        []byte
	RequestedURIs []string
}

type GatewayCertificateIssueResult struct {
	Plane               CertificatePlane
	CertificatePEM      []byte
	CertificateChainPEM []byte
	TrustRootPEM        []byte
	Evidence            GatewayCertificateIdentityEvidence
}

type GatewayCertificateIdentityEvidence struct {
	Plane                CertificatePlane
	SPIFFEID             string
	Subject              string
	FingerprintSHA256    string
	TrustRootID          string
	SerialNumber         string
	NotBefore            time.Time
	NotAfter             time.Time
	RevocationGeneration int64
	Production           bool
	CSRSPKISHA256        string
}

type GatewayCertificateRevocation struct {
	Plane                CertificatePlane
	TrustRootID          string
	SerialNumber         string
	RevocationGeneration int64
	RevokedAt            time.Time
}

func LoadGatewayCertificateProviderConfigFromEnv(lookup func(string) string) (GatewayCertificateProviderConfig, error) {
	if lookup == nil {
		lookup = os.Getenv
	}
	cfg := GatewayCertificateProviderConfig{
		Kind:             GatewayCertificateProviderKind(strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_KIND"))),
		FabricID:         strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_FABRIC_ID")),
		CACertFile:       strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_CA_CERT_FILE")),
		CAKeyFile:        strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_CA_KEY_FILE")),
		ServerCACertFile: strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_SERVER_CA_CERT_FILE")),
		ServerCAKeyFile:  strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_SERVER_CA_KEY_FILE")),

		BackplaneCACertFile: strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_BACKPLANE_CA_CERT_FILE")),
		BackplaneCAKeyFile:  strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_BACKPLANE_CA_KEY_FILE")),

		RelayCellServerCACertFile: strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_RELAY_CELL_SERVER_CA_CERT_FILE")),
		RelayCellServerCAKeyFile:  strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_RELAY_CELL_SERVER_CA_KEY_FILE")),
	}
	production := strings.TrimSpace(lookup("BUILDERS_GATEWAY_CERT_PROVIDER_PRODUCTION"))
	if production != "" {
		parsed, err := strconv.ParseBool(production)
		if err != nil {
			return GatewayCertificateProviderConfig{}, fmt.Errorf("parse BUILDERS_GATEWAY_CERT_PROVIDER_PRODUCTION: %w", err)
		}
		cfg.Production = parsed
	}
	if cfg.Kind == "" {
		if cfg.Production {
			return GatewayCertificateProviderConfig{}, errors.New("production gateway certificate provider kind is required")
		}
		cfg.Kind = GatewayCertificateProviderKindUnconfigured
	}
	if !cfg.Kind.Valid() {
		return GatewayCertificateProviderConfig{}, fmt.Errorf("unsupported gateway certificate provider kind %q", cfg.Kind)
	}
	if cfg.Production && cfg.Kind.NonProduction() {
		return GatewayCertificateProviderConfig{}, fmt.Errorf("production gateway certificate provider cannot use %q", cfg.Kind)
	}
	if cfg.Kind == GatewayCertificateProviderKindExternalCA && (cfg.CACertFile == "" || cfg.CAKeyFile == "") {
		return GatewayCertificateProviderConfig{}, errors.New("external_ca gateway certificate provider requires CA cert and key files")
	}
	if (cfg.ServerCACertFile == "") != (cfg.ServerCAKeyFile == "") {
		return GatewayCertificateProviderConfig{}, errors.New("external_ca gateway certificate provider server CA requires both cert and key files")
	}
	if (cfg.BackplaneCACertFile == "") != (cfg.BackplaneCAKeyFile == "") {
		return GatewayCertificateProviderConfig{}, errors.New("external_ca gateway certificate provider backplane CA requires both cert and key files")
	}
	if (cfg.RelayCellServerCACertFile == "") != (cfg.RelayCellServerCAKeyFile == "") {
		return GatewayCertificateProviderConfig{}, errors.New("external_ca gateway certificate provider relay-cell-server CA requires both cert and key files")
	}
	return cfg, nil
}

func ParseGatewayCertificateCSR(input GatewayCertificateCSR) (ParsedGatewayCertificateCSR, error) {
	expected := strings.TrimSpace(input.ExpectedSPKISHA256)
	if expected == "" {
		return ParsedGatewayCertificateCSR{}, fmt.Errorf("%w: expected CSR SPKI SHA-256 binding is required", ErrCSRBindingRequired)
	}
	der, err := certificateRequestDER(input)
	if err != nil {
		return ParsedGatewayCertificateCSR{}, err
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return ParsedGatewayCertificateCSR{}, fmt.Errorf("%w: parse CSR: %v", ErrCSRParseFailed, err)
	}
	if err := request.CheckSignature(); err != nil {
		return ParsedGatewayCertificateCSR{}, fmt.Errorf("%w: CSR signature check failed: %v", ErrCSRSignatureInvalid, err)
	}
	spki, err := SPKISHA256ForPublicKey(request.PublicKey)
	if err != nil {
		return ParsedGatewayCertificateCSR{}, err
	}
	if spki != expected {
		return ParsedGatewayCertificateCSR{}, fmt.Errorf("%w: CSR SPKI SHA-256 mismatch: got %q want %q", ErrCSRSPKIMismatch, spki, expected)
	}
	return ParsedGatewayCertificateCSR{
		Request:       request,
		SPKISHA256:    spki,
		RawDER:        append([]byte(nil), der...),
		RequestedURIs: csrURIStrings(request),
	}, nil
}

func GatewayCertificateEvidenceFromIssued(plane CertificatePlane, root TrustRoot, cert *x509.Certificate, csrSPKISHA256 string) (GatewayCertificateIdentityEvidence, error) {
	if cert == nil {
		return GatewayCertificateIdentityEvidence{}, errors.New("issued certificate is required")
	}
	desc := normalizeTrustRootDescriptor(root.PlaneDescriptor)
	if desc.Plane != plane {
		return GatewayCertificateIdentityEvidence{}, fmt.Errorf("%w: issued root plane %q does not match result plane %q", ErrPlaneIdentityMismatch, desc.Plane, plane)
	}
	namespace, err := canonicalSPIFFENamespaceForPlane(plane)
	if err != nil {
		return GatewayCertificateIdentityEvidence{}, err
	}
	if desc.SPIFFENamespace != namespace {
		return GatewayCertificateIdentityEvidence{}, fmt.Errorf("%w: issued root namespace %q is not canonical for plane %q", ErrPlaneIdentityMismatch, desc.SPIFFENamespace, plane)
	}
	spiffeID, err := planeSPIFFEID(cert, namespace)
	if err != nil {
		return GatewayCertificateIdentityEvidence{}, err
	}
	return GatewayCertificateIdentityEvidence{
		Plane:                plane,
		SPIFFEID:             spiffeID,
		Subject:              cert.Subject.String(),
		FingerprintSHA256:    componentidentity.CertificateFingerprintSHA256(cert),
		TrustRootID:          root.ID,
		SerialNumber:         cert.SerialNumber.String(),
		NotBefore:            cert.NotBefore.UTC(),
		NotAfter:             cert.NotAfter.UTC(),
		RevocationGeneration: desc.RevocationGeneration,
		Production:           desc.Production,
		CSRSPKISHA256:        strings.TrimSpace(csrSPKISHA256),
	}, nil
}

func SPKISHA256ForPublicKey(publicKey any) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal CSR public key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func ValidateGatewayCertificateIssueRequest(plane CertificatePlane, request GatewayCertificateIssueRequest) error {
	if !plane.Valid() {
		return fmt.Errorf("%w: unsupported gateway issuance plane %q", ErrPlaneIdentityMismatch, plane)
	}
	if plane == PlaneRelayCellBackplane {
		// The backplane plane is relay-cell-scoped (fabric + relay-cell id) and has
		// NO org/gateway — require fabric + relay-cell id, not org/gateway.
		if strings.TrimSpace(request.FabricID) == "" {
			return fmt.Errorf("%s issuance requires fabric id", plane)
		}
		if strings.TrimSpace(request.RelayCellID) == "" {
			return fmt.Errorf("%s issuance requires relay cell id", plane)
		}
		if _, err := ParseGatewayCertificateCSR(request.CSR); err != nil {
			return err
		}
		return nil
	}
	if plane == PlaneRelayCellServer {
		// The relay-cell server plane is relay-cell-scoped (fabric + relay-cell id), no
		// org/gateway, and REQUIRES at least one DNS name — the canonical hostname the SAN
		// carries (server-controlled; it is the value a partner gateway verifies by ServerName,
		// so a :443 leaf without it is useless). DNSNames come from the request, never the CSR.
		if strings.TrimSpace(request.FabricID) == "" {
			return fmt.Errorf("%s issuance requires fabric id", plane)
		}
		if strings.TrimSpace(request.RelayCellID) == "" {
			return fmt.Errorf("%s issuance requires relay cell id", plane)
		}
		if err := validateServerDNSNames(request.DNSNames); err != nil {
			return err
		}
		if _, err := ParseGatewayCertificateCSR(request.CSR); err != nil {
			return err
		}
		return nil
	}
	if (plane == PlaneRelayGatewayClient || plane == PlaneGatewayTransport) && strings.TrimSpace(request.FabricID) == "" {
		return fmt.Errorf("%s issuance requires fabric id", plane)
	}
	if strings.TrimSpace(request.OrgID) == "" {
		return errors.New("gateway issuance requires org id")
	}
	if strings.TrimSpace(request.GatewayID) == "" {
		return errors.New("gateway issuance requires gateway id")
	}
	if _, err := ParseGatewayCertificateCSR(request.CSR); err != nil {
		return err
	}
	return nil
}

// validateServerDNSNames enforces that a relay-cell :443 server leaf carries at least one DNS
// SAN and that EVERY supplied name is a strict, non-wildcard FQDN. A partner gateway trusts this
// leaf purely by ServerName + RootCAs, so a wildcard, blank, or malformed SAN would be exactly
// the over-broad impersonation this plane exists to prevent — and although the SAN is
// authority-supplied (never CSR-supplied), the authority must not be able to mint an over-broad
// cert either. Names are NOT trimmed here: a name with surrounding whitespace is rejected so the
// caller must supply a clean FQDN (the value lands on the leaf verbatim).
func validateServerDNSNames(names []string) error {
	if len(names) == 0 {
		return errors.New("relay-cell server issuance requires a canonical hostname DNS SAN")
	}
	for _, n := range names {
		if err := validateServerDNSName(n); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRelayCellServerDNSName reports whether name is a valid canonical hostname for a
// relay-cell :443 server leaf — a strict, non-wildcard FQDN. Exported so the relay-cell join
// authority can validate the hostname at MINT time (fail fast) with the SAME rule
// IssueRelayCellServer enforces at issuance (single source of truth).
func ValidateRelayCellServerDNSName(name string) error { return validateServerDNSName(name) }

func validateServerDNSName(name string) error {
	if name == "" || strings.TrimSpace(name) != name {
		return fmt.Errorf("relay-cell server DNS SAN %q must be a trimmed, non-empty hostname", name)
	}
	if strings.Contains(name, "*") {
		return fmt.Errorf("relay-cell server DNS SAN %q must not be a wildcard", name)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("relay-cell server DNS SAN %q must be a fully-qualified hostname", name)
	}
	for _, label := range labels {
		if !isDNSLabel(label) {
			return fmt.Errorf("relay-cell server DNS SAN %q has an invalid label %q", name, label)
		}
	}
	return nil
}

// isDNSLabel reports whether label is a valid DNS label (1-63 chars, alphanumeric or hyphen, not
// starting/ending with a hyphen).
func isDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func canonicalSPIFFENamespaceForPlane(plane CertificatePlane) (string, error) {
	switch plane {
	case PlaneRelayGatewayClient:
		return RelayGatewayClientNamespace, nil
	case PlaneGatewayTransport:
		return GatewayTransportNamespace, nil
	case PlaneGatewayBusiness:
		return GatewayBusinessNamespace, nil
	case PlaneRelayCellBackplane:
		return RelayCellBackplaneNamespace, nil
	case PlaneRelayCellServer:
		// Same relay-cell trust domain as the backplane; cross-plane isolation comes from the
		// DISTINCT plane + CA + SPIFFE role (verify still requires the cert chain to this
		// plane's trust root), never the namespace string alone.
		return RelayCellServerNamespace, nil
	default:
		return "", fmt.Errorf("%w: unsupported certificate plane %q", ErrPlaneIdentityMismatch, plane)
	}
}

func certificateRequestDER(input GatewayCertificateCSR) ([]byte, error) {
	hasPEM := len(strings.TrimSpace(string(input.PEM))) > 0
	hasDER := len(input.DER) > 0
	switch {
	case hasPEM && hasDER:
		return nil, errors.New("CSR must be provided as PEM or DER, not both")
	case hasPEM:
		block, _ := pem.Decode(input.PEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return nil, errors.New("CSR PEM did not contain a certificate request")
		}
		return append([]byte(nil), block.Bytes...), nil
	case hasDER:
		return append([]byte(nil), input.DER...), nil
	default:
		return nil, errors.New("CSR PEM or DER is required")
	}
}

func csrURIStrings(request *x509.CertificateRequest) []string {
	out := make([]string, 0, len(request.URIs))
	for _, uri := range request.URIs {
		if uri != nil {
			out = append(out, uri.String())
		}
	}
	return out
}

func (k GatewayCertificateProviderKind) Valid() bool {
	switch k {
	case GatewayCertificateProviderKindUnconfigured, GatewayCertificateProviderKindExternalCA, GatewayCertificateProviderKindTestOnlyMemory:
		return true
	default:
		return false
	}
}

func (k GatewayCertificateProviderKind) NonProduction() bool {
	switch k {
	case GatewayCertificateProviderKindUnconfigured, GatewayCertificateProviderKindTestOnlyMemory:
		return true
	default:
		return false
	}
}
