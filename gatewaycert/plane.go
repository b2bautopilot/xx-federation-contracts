package gatewaycert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
	"github.com/google/uuid"
)

type CertificatePlane string

const (
	PlaneRelayGatewayClient CertificatePlane = "relay_gateway_client"
	PlaneGatewayTransport   CertificatePlane = "gateway_transport_server"
	PlaneGatewayBusiness    CertificatePlane = "gateway_business"
	PlaneRelayCellBackplane CertificatePlane = "relay_cell_backplane"
	// PlaneRelayCellServer is a relay cell's OUTER :443 mTLS server leaf — what partner
	// GATEWAYS verify when they connect to the opaque forwarder. ServerAuth EKU, cell-scoped,
	// distinct CA (A2b). Distinct from PlaneRelayCellBackplane (the cell<->cell :8444 listener).
	PlaneRelayCellServer CertificatePlane = "relay_cell_server"
)

const (
	RelayGatewayClientNamespace = "spiffe://relay.b2bautopilot.com/"
	GatewayTransportNamespace   = "spiffe://gateway-transport.b2bautopilot.com/"
	GatewayBusinessNamespace    = "spiffe://gateway.b2bautopilot.com/"
	RelayCellBackplaneNamespace = "spiffe://relay-cell.b2bautopilot.com/"

	// RelayCellServerNamespace is the SPIFFE trust domain for a relay cell's OUTER :443 server
	// leaf. Deliberately DERIVED from RelayCellBackplaneNamespace: the two planes SHARE the
	// relay-cell trust domain (so this stays equal by construction — no silent drift), and their
	// isolation comes entirely from the DISTINCT plane + CA + SPIFFE role (role/server, ServerAuth),
	// verified by chaining to this plane's own trust root — never the namespace string. Partner
	// gateways verify by ServerName (the canonical hostname DNS SAN) + RootCAs, not by pinning it.
	RelayCellServerNamespace = RelayCellBackplaneNamespace

	// relayGatewayClientHost is the SPIFFE trust-domain host of the relay-client
	// namespace (the authority in RelayGatewayClientNamespace). It is the value a
	// relay-client leaf's URI must carry in url.Host; mirrors the host check in
	// gateway.parseRelayGatewayClientSPIFFE.
	relayGatewayClientHost = "relay.b2bautopilot.com"

	// relayCellBackplaneHost is the SPIFFE trust-domain host of the relay-cell
	// backplane namespace (the authority in RelayCellBackplaneNamespace). It is the
	// value a backplane leaf's URI must carry in url.Host.
	relayCellBackplaneHost = "relay-cell.b2bautopilot.com"
)

var ErrPlaneIdentityMismatch = errors.New("plane_identity_mismatch")

type TrustRootDescriptor struct {
	ID                   string
	Plane                CertificatePlane
	SPIFFENamespace      string
	VerifierAudience     string
	ActivationNotBefore  time.Time
	ActivationNotAfter   time.Time
	RevocationGeneration int64
	Production           bool
}

type PlaneVerifyOptions struct {
	CertificatePEM           []byte
	TrustRoots               []TrustRoot
	TrustRootID              string
	ExpectedPlane            CertificatePlane
	ExpectedSPIFFENamespace  string
	ExpectedVerifierAudience string
	MinValidFor              time.Duration
	Now                      time.Time
}

type PlaneVerification struct {
	TrustRootID          string
	Plane                CertificatePlane
	SPIFFEID             string
	Subject              string
	FingerprintSHA256    string
	VerifierAudience     string
	RevocationGeneration int64
	Production           bool
	NotBefore            time.Time
	NotAfter             time.Time
}

type PlaneVerifier struct {
	TrustRoots               []TrustRoot
	ExpectedPlane            CertificatePlane
	ExpectedSPIFFENamespace  string
	ExpectedVerifierAudience string
	Now                      func() time.Time
}

func (v PlaneVerifier) VerifyPlaneCertificate(ctx context.Context, opts PlaneVerifyOptions) (PlaneVerification, error) {
	if len(v.TrustRoots) > 0 {
		opts.TrustRoots = append([]TrustRoot(nil), v.TrustRoots...)
	}
	if opts.ExpectedPlane == "" {
		opts.ExpectedPlane = v.ExpectedPlane
	}
	if opts.ExpectedSPIFFENamespace == "" {
		opts.ExpectedSPIFFENamespace = v.ExpectedSPIFFENamespace
	}
	if opts.ExpectedVerifierAudience == "" {
		opts.ExpectedVerifierAudience = v.ExpectedVerifierAudience
	}
	if opts.Now.IsZero() && v.Now != nil {
		opts.Now = v.Now().UTC()
	}
	return VerifyPlaneCertificate(ctx, opts)
}

func VerifyPlaneCertificate(_ context.Context, opts PlaneVerifyOptions) (PlaneVerification, error) {
	if err := validatePlaneExpectation(opts.ExpectedPlane, opts.ExpectedSPIFFENamespace); err != nil {
		return PlaneVerification{}, err
	}
	leaf, intermediates, err := parseCertificatePEM(opts.CertificatePEM)
	if err != nil {
		return PlaneVerification{}, err
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	roots := selectedPlaneTrustRoots(opts.TrustRoots, opts.TrustRootID, opts.ExpectedPlane, opts.ExpectedSPIFFENamespace, opts.ExpectedVerifierAudience, now)
	if len(roots) == 0 {
		return PlaneVerification{}, fmt.Errorf("%w: no active trust root matches plane %q namespace %q", ErrPlaneIdentityMismatch, opts.ExpectedPlane, opts.ExpectedSPIFFENamespace)
	}
	if opts.MinValidFor > 0 && now.Add(opts.MinValidFor).After(leaf.NotAfter) {
		return PlaneVerification{}, fmt.Errorf("gateway certificate expires before required rotation window: not_after=%s min_valid_for=%s", leaf.NotAfter.UTC().Format(time.RFC3339), opts.MinValidFor)
	}
	spiffeID, err := planeSPIFFEID(leaf, opts.ExpectedSPIFFENamespace)
	if err != nil {
		return PlaneVerification{}, err
	}
	rootID, err := verifyAgainstTrustRootsForPlane(leaf, intermediates, roots, now, opts.ExpectedPlane)
	if err != nil {
		return PlaneVerification{}, fmt.Errorf("%w: %v", ErrPlaneIdentityMismatch, err)
	}
	root := rootByID(roots, rootID)
	return PlaneVerification{
		TrustRootID:          rootID,
		Plane:                root.PlaneDescriptor.Plane,
		SPIFFEID:             spiffeID,
		Subject:              leaf.Subject.String(),
		FingerprintSHA256:    componentidentity.CertificateFingerprintSHA256(leaf),
		VerifierAudience:     root.PlaneDescriptor.VerifierAudience,
		RevocationGeneration: root.PlaneDescriptor.RevocationGeneration,
		Production:           root.PlaneDescriptor.Production,
		NotBefore:            leaf.NotBefore.UTC(),
		NotAfter:             leaf.NotAfter.UTC(),
	}, nil
}

func TrustRootFromPEMWithDescriptor(desc TrustRootDescriptor, pemBytes []byte) (TrustRoot, error) {
	desc = normalizeTrustRootDescriptor(desc)
	if err := validateTrustRootDescriptor(desc); err != nil {
		return TrustRoot{}, err
	}
	root, err := TrustRootFromPEM(desc.ID, pemBytes)
	if err != nil {
		return TrustRoot{}, err
	}
	root.PlaneDescriptor = desc
	return root, nil
}

func RelayGatewayClientSPIFFE(fabricID, orgID, gatewayID string) string {
	return RelayGatewayClientNamespace +
		"fabric/" + escapeSPIFFEPart(fabricID) +
		"/org/" + escapeSPIFFEPart(orgID) +
		"/gateway/" + escapeSPIFFEPart(gatewayID) +
		"/role/relay-client"
}

// ValidateRelayClientTenantID enforces the invariant that a relay-client SPIFFE's org
// segment — which becomes the control-plane TenantID at authentication — is a uuid,
// never a domain or handle. The control plane is RLS-scoped by uuid tenant (the
// credential resolver parses tenant_id as a uuid), so a non-uuid tenant cannot
// authenticate; a domain is an addressing label resolved by the recipient directory,
// not a tenant. Enforced fail-closed at issuance (never mint such a cert) and at auth
// (never accept one) — deliberately NOT inside the shared SPIFFE parser, which must
// mirror the data-plane parser exactly and is therefore the wrong place for this policy.
func ValidateRelayClientTenantID(orgID string) error {
	if _, err := uuid.Parse(strings.TrimSpace(orgID)); err != nil {
		return fmt.Errorf("%w: relay-client tenant id %q must be a uuid", ErrPlaneIdentityMismatch, orgID)
	}
	return nil
}

// RelayGatewayClientIdentityFromCertificate extracts a gateway identity from a
// leaf that presents a Slice-120B relay-client SPIFFE
// (spiffe://relay.b2bautopilot.com/fabric/<f>/org/<o>/gateway/<g>/role/relay-client).
// It is the certificate-level inverse of RelayGatewayClientSPIFFE and the sibling of
// componentidentity.GatewayIdentityFromCertificate (which only parses the
// federation-gateway scheme). The org segment maps to TenantID and the gateway
// segment to GatewayID — IDENTICAL to how the receiver runtime
// (gateway.parseRelayGatewayClientSPIFFE -> relayClientTransportIdentity) derives
// the transport identity, so a relay rendezvous key built from this identity is
// consistent with how receivers register and senders target. It does NOT verify the
// chain (the caller's RequireAndVerifyClientCert / plane verifier owns that); it only
// reads identity from an already-verified leaf. A leaf with no relay-client SPIFFE
// URI yields ErrPlaneIdentityMismatch (caller treats this as unauthorized).
func RelayGatewayClientIdentityFromCertificate(cert *x509.Certificate) (componentidentity.GatewayIdentity, error) {
	identity, ok := RelayGatewayClientIdentityFromCertificateIfPresent(cert)
	if !ok {
		return componentidentity.GatewayIdentity{}, fmt.Errorf("%w: certificate is missing relay-client gateway identity", ErrPlaneIdentityMismatch)
	}
	return identity, nil
}

// RelayGatewayClientIdentityFromCertificateIfPresent reports whether the leaf carries
// a well-formed relay-client SPIFFE URI and, if so, returns the derived gateway
// identity. ok=false means no URI on the cert parsed as a relay-client SPIFFE (a
// malformed/wrong-host/wrong-role/short-path candidate is simply skipped, never
// accepted) — letting callers fall back to another scheme without conflating "not a
// relay-client cert" with a hard error.
func RelayGatewayClientIdentityFromCertificateIfPresent(cert *x509.Certificate) (componentidentity.GatewayIdentity, bool) {
	if cert == nil {
		return componentidentity.GatewayIdentity{}, false
	}
	for _, uri := range cert.URIs {
		_, orgID, gatewayID, ok := parseRelayGatewayClientSPIFFEURI(uri)
		if !ok {
			continue
		}
		return componentidentity.GatewayIdentity{
			TenantID:          orgID,
			GatewayID:         gatewayID,
			SPIFFEID:          uri.String(),
			Subject:           cert.Subject.String(),
			FingerprintSHA256: componentidentity.CertificateFingerprintSHA256(cert),
		}, true
	}
	return componentidentity.GatewayIdentity{}, false
}

// parseRelayGatewayClientSPIFFEURI parses one URI as a relay-client SPIFFE. It mirrors
// gateway.parseRelayGatewayClientSPIFFE EXACTLY (host relay.b2bautopilot.com; 8-part
// path fabric/<f>/org/<o>/gateway/<g>/role/relay-client; non-empty fabric/org/gateway
// segments) so the two paths cannot diverge. ok=false for any malformed candidate.
func parseRelayGatewayClientSPIFFEURI(uri *url.URL) (fabricID, orgID, gatewayID string, ok bool) {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != relayGatewayClientHost {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "fabric" || parts[2] != "org" || parts[4] != "gateway" || parts[6] != "role" || parts[7] != "relay-client" {
		return "", "", "", false
	}
	fabricID, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", "", false
	}
	orgID, err = url.PathUnescape(parts[3])
	if err != nil {
		return "", "", "", false
	}
	gatewayID, err = url.PathUnescape(parts[5])
	if err != nil {
		return "", "", "", false
	}
	if strings.TrimSpace(fabricID) == "" || strings.TrimSpace(orgID) == "" || strings.TrimSpace(gatewayID) == "" {
		return "", "", "", false
	}
	return fabricID, orgID, gatewayID, true
}

// OrgFromRelayGatewayClientSPIFFE parses a relay-client SPIFFE string and returns
// its org segment. ok is false for any SPIFFE that is not a well-formed relay-client
// identity (wrong scheme/host, wrong shape, empty segments) — so an ORG-LEVEL pin
// can require a valid, CA-shaped relay-client SPIFFE (the org segment is the
// cryptographic pin) rather than trusting a raw tenant string. It is the inbound
// twin of the outbound org matcher (matchesOrgTransportServer), which parses the
// transport-server SPIFFE's org segment the same way.
func OrgFromRelayGatewayClientSPIFFE(spiffe string) (orgID string, ok bool) {
	uri, err := url.Parse(strings.TrimSpace(spiffe))
	if err != nil {
		return "", false
	}
	_, orgID, _, ok = parseRelayGatewayClientSPIFFEURI(uri)
	return orgID, ok
}

func GatewayTransportSPIFFE(fabricID, orgID, gatewayID string) string {
	return GatewayTransportNamespace +
		"fabric/" + escapeSPIFFEPart(fabricID) +
		"/org/" + escapeSPIFFEPart(orgID) +
		"/gateway/" + escapeSPIFFEPart(gatewayID) +
		"/role/transport-server"
}

func GatewayBusinessSPIFFE(orgID, gatewayID string) string {
	return GatewayBusinessNamespace +
		"org/" + escapeSPIFFEPart(orgID) +
		"/gateway/" + escapeSPIFFEPart(gatewayID) +
		"/role/business-facade"
}

func RelayCellBackplaneSPIFFE(fabricID, relayCellID string) string {
	return RelayCellBackplaneNamespace +
		"fabric/" + escapeSPIFFEPart(fabricID) +
		"/relay-cell/" + escapeSPIFFEPart(relayCellID) +
		"/role/backplane"
}

// RelayCellBackplaneServerSPIFFE is the listener-side counterpart of
// RelayCellBackplaneSPIFFE: the SAME relay-cell trust domain + fabric/cell scope, but
// role `backplane-server` (the mutual-mTLS LISTENER leaf, ServerAuth EKU) instead of
// role `backplane` (the dialer leaf, ClientAuth EKU). Two SINGLE-EKU roles under the
// one backplane CA — never a dual-EKU leaf (that would re-engage the keystone trap S1.5
// avoided; and unlike an x-mesh `--node-mode relay_server` enrollment, a gatewaycert-
// minted ServerAuth leaf does not touch x-mesh's P2PMode). The dialer pins the listener
// by RootCAs=backplane CA + ServerName=relay-cell host, so the host is carried as a DNS
// SAN on the server leaf (see IssueRelayCellBackplaneServer).
func RelayCellBackplaneServerSPIFFE(fabricID, relayCellID string) string {
	return RelayCellBackplaneNamespace +
		"fabric/" + escapeSPIFFEPart(fabricID) +
		"/relay-cell/" + escapeSPIFFEPart(relayCellID) +
		"/role/backplane-server"
}

// RelayCellServerSPIFFE is a relay cell's OUTER :443 server leaf identity (role/server,
// ServerAuth). Partner gateways verify the forwarder by ServerName (the canonical hostname
// DNS SAN) + RootCAs=relay-cell-server CA; this SPIFFE is the cell-scoped identity carried for
// audit/consistency (the gateway does not pin it). Same relay-cell trust domain as the
// backplane leaves, but a distinct plane/CA/role.
func RelayCellServerSPIFFE(fabricID, relayCellID string) string {
	return RelayCellServerNamespace +
		"fabric/" + escapeSPIFFEPart(fabricID) +
		"/relay-cell/" + escapeSPIFFEPart(relayCellID) +
		"/role/server"
}

// RelayCellBackplaneIdentity is the identity carried by a relay-cell backplane
// leaf. Unlike a gateway identity, the relay-cell segment is a CELL id, not a
// tenant — so no uuid/tenant rule applies (cf. ValidateRelayClientTenantID).
type RelayCellBackplaneIdentity struct {
	FabricID          string
	RelayCellID       string
	SPIFFEID          string
	Subject           string
	FingerprintSHA256 string
}

// RelayCellBackplaneIdentityFromCertificate extracts the backplane identity from a
// leaf presenting a relay-cell backplane SPIFFE
// (spiffe://relay-cell.b2bautopilot.com/fabric/<f>/relay-cell/<c>/role/backplane).
// It is the certificate-level inverse of RelayCellBackplaneSPIFFE. It does NOT
// verify the chain (the caller's RequireAndVerifyClientCert / the backplane
// verifier owns that); it only reads identity from an already-verified leaf. A
// leaf with no backplane SPIFFE URI yields ErrPlaneIdentityMismatch.
func RelayCellBackplaneIdentityFromCertificate(cert *x509.Certificate) (RelayCellBackplaneIdentity, error) {
	identity, ok := RelayCellBackplaneIdentityFromCertificateIfPresent(cert)
	if !ok {
		return RelayCellBackplaneIdentity{}, fmt.Errorf("%w: certificate is missing relay-cell backplane identity", ErrPlaneIdentityMismatch)
	}
	return identity, nil
}

// RelayCellBackplaneIdentityFromCertificateIfPresent reports whether the leaf
// carries a well-formed relay-cell backplane SPIFFE URI and, if so, returns the
// derived identity. ok=false means no URI parsed as a backplane SPIFFE (a
// malformed/wrong-host/wrong-role/short-path candidate is skipped, never accepted).
func RelayCellBackplaneIdentityFromCertificateIfPresent(cert *x509.Certificate) (RelayCellBackplaneIdentity, bool) {
	if cert == nil {
		return RelayCellBackplaneIdentity{}, false
	}
	for _, uri := range cert.URIs {
		fabricID, relayCellID, ok := parseRelayCellBackplaneSPIFFEURI(uri)
		if !ok {
			continue
		}
		return RelayCellBackplaneIdentity{
			FabricID:          fabricID,
			RelayCellID:       relayCellID,
			SPIFFEID:          uri.String(),
			Subject:           cert.Subject.String(),
			FingerprintSHA256: componentidentity.CertificateFingerprintSHA256(cert),
		}, true
	}
	return RelayCellBackplaneIdentity{}, false
}

// parseRelayCellBackplaneSPIFFEURI parses one URI as a relay-cell backplane SPIFFE
// (host relay-cell.b2bautopilot.com; 6-part path fabric/<f>/relay-cell/<c>/role/
// backplane; non-empty fabric/relay-cell segments). ok=false for any malformed
// candidate. This parser is the single source of truth for the backplane scheme.
func parseRelayCellBackplaneSPIFFEURI(uri *url.URL) (fabricID, relayCellID string, ok bool) {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != relayCellBackplaneHost {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "fabric" || parts[2] != "relay-cell" || parts[4] != "role" || parts[5] != "backplane" {
		return "", "", false
	}
	fabricID, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", false
	}
	relayCellID, err = url.PathUnescape(parts[3])
	if err != nil {
		return "", "", false
	}
	if strings.TrimSpace(fabricID) == "" || strings.TrimSpace(relayCellID) == "" {
		return "", "", false
	}
	return fabricID, relayCellID, true
}

// isRelayCellBackplaneServerSPIFFE reports whether uri is a relay-cell backplane SERVER
// SPIFFE (role/backplane-server). It is used to select the ServerAuth EKU at issuance
// for the listener leaf. The dialer/client parser (parseRelayCellBackplaneSPIFFEURI)
// stays strict to role/backplane, so a server leaf can NEVER be accepted as a backplane
// client peer (VerifyBackplanePeer rejects it).
func isRelayCellBackplaneServerSPIFFE(uri *url.URL) bool {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != relayCellBackplaneHost {
		return false
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	return len(parts) == 6 && parts[0] == "fabric" && parts[2] == "relay-cell" &&
		parts[4] == "role" && parts[5] == "backplane-server" &&
		strings.TrimSpace(parts[1]) != "" && strings.TrimSpace(parts[3]) != ""
}

func selectedPlaneTrustRoots(roots []TrustRoot, trustRootID string, plane CertificatePlane, namespace, audience string, now time.Time) []TrustRoot {
	trustRootID = strings.TrimSpace(trustRootID)
	namespace = strings.TrimSpace(namespace)
	audience = strings.TrimSpace(audience)
	out := make([]TrustRoot, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root.ID) == "" || len(root.Certificates) == 0 {
			continue
		}
		if trustRootID != "" && root.ID != trustRootID {
			continue
		}
		desc := normalizeTrustRootDescriptor(root.PlaneDescriptor)
		if desc.ID == "" {
			desc.ID = root.ID
		}
		if desc.Plane != plane || desc.SPIFFENamespace != namespace {
			continue
		}
		if audience != "" && desc.VerifierAudience != audience {
			continue
		}
		if !desc.ActivationNotBefore.IsZero() && now.Before(desc.ActivationNotBefore) {
			continue
		}
		if !desc.ActivationNotAfter.IsZero() && !now.Before(desc.ActivationNotAfter) {
			continue
		}
		root.PlaneDescriptor = desc
		out = append(out, root)
	}
	return out
}

func rootByID(roots []TrustRoot, id string) TrustRoot {
	for _, root := range roots {
		if root.ID == id {
			return root
		}
	}
	return TrustRoot{}
}

func planeSPIFFEID(cert *x509.Certificate, namespace string) (string, error) {
	namespace = strings.TrimSpace(namespace)
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		candidate := uri.String()
		if strings.HasPrefix(candidate, namespace) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: certificate missing SPIFFE namespace %q", ErrPlaneIdentityMismatch, namespace)
}

func validatePlaneExpectation(plane CertificatePlane, namespace string) error {
	if !plane.Valid() {
		return fmt.Errorf("%w: unsupported certificate plane %q", ErrPlaneIdentityMismatch, plane)
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return fmt.Errorf("%w: expected SPIFFE namespace is required", ErrPlaneIdentityMismatch)
	}
	canonical, err := canonicalSPIFFENamespaceForPlane(plane)
	if err != nil {
		return err
	}
	if namespace != canonical {
		return fmt.Errorf("%w: plane %q requires SPIFFE namespace %q, got %q", ErrPlaneIdentityMismatch, plane, canonical, namespace)
	}
	return nil
}

func validateTrustRootDescriptor(desc TrustRootDescriptor) error {
	if strings.TrimSpace(desc.ID) == "" {
		return errors.New("gateway trust root descriptor id is required")
	}
	if err := validatePlaneExpectation(desc.Plane, desc.SPIFFENamespace); err != nil {
		return err
	}
	if strings.TrimSpace(desc.VerifierAudience) == "" {
		return errors.New("gateway trust root descriptor verifier audience is required")
	}
	if !desc.ActivationNotBefore.IsZero() && !desc.ActivationNotAfter.IsZero() && !desc.ActivationNotBefore.Before(desc.ActivationNotAfter) {
		return errors.New("gateway trust root descriptor activation window is invalid")
	}
	return nil
}

func normalizeTrustRootDescriptor(desc TrustRootDescriptor) TrustRootDescriptor {
	desc.ID = strings.TrimSpace(desc.ID)
	desc.SPIFFENamespace = strings.TrimSpace(desc.SPIFFENamespace)
	desc.VerifierAudience = strings.TrimSpace(desc.VerifierAudience)
	desc.ActivationNotBefore = desc.ActivationNotBefore.UTC()
	desc.ActivationNotAfter = desc.ActivationNotAfter.UTC()
	return desc
}

func (p CertificatePlane) Valid() bool {
	switch p {
	case PlaneRelayGatewayClient, PlaneGatewayTransport, PlaneGatewayBusiness, PlaneRelayCellBackplane, PlaneRelayCellServer:
		return true
	default:
		return false
	}
}

func escapeSPIFFEPart(value string) string {
	return url.PathEscape(strings.TrimSpace(value))
}
