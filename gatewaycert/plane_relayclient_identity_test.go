package gatewaycert_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
	componentidentity "github.com/b2bautopilot/xx-federation-contracts/identity"
)

// certWithURIs builds a minimal leaf carrying the given SPIFFE URIs (and a fixed
// Subject + Raw so Subject/FingerprintSHA256 extraction is observable). It does NOT
// represent a chain-verified cert — these tests cover ONLY identity extraction from
// the URI SAN, which is the sole concern of RelayGatewayClientIdentityFromCertificate.
func certWithURIs(t *testing.T, raws ...string) *x509.Certificate {
	t.Helper()
	uris := make([]*url.URL, 0, len(raws))
	for _, raw := range raws {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URI %q: %v", raw, err)
		}
		uris = append(uris, u)
	}
	cert := &x509.Certificate{URIs: uris, Raw: []byte("relay-client-leaf-der-fixture")}
	cert.Subject.CommonName = "relay-client-leaf"
	return cert
}

// Invariant 2 (extractor level): a relay-client SPIFFE maps org->TenantID,
// gateway->GatewayID, and carries SPIFFEID/Subject/FingerprintSHA256 from the leaf.
func TestRelayGatewayClientIdentityFromCertificate_MapsOrgAndGateway(t *testing.T) {
	spiffeID := gatewaycert.RelayGatewayClientSPIFFE("fabric-1", "org-acme", "gw-edge")
	cert := certWithURIs(t, spiffeID)

	identity, err := gatewaycert.RelayGatewayClientIdentityFromCertificate(cert)
	if err != nil {
		t.Fatalf("RelayGatewayClientIdentityFromCertificate error = %v", err)
	}
	if identity.TenantID != "org-acme" {
		t.Errorf("TenantID = %q, want org-acme (org segment)", identity.TenantID)
	}
	if identity.GatewayID != "gw-edge" {
		t.Errorf("GatewayID = %q, want gw-edge (gateway segment)", identity.GatewayID)
	}
	if identity.SPIFFEID != spiffeID {
		t.Errorf("SPIFFEID = %q, want %q", identity.SPIFFEID, spiffeID)
	}
	if identity.Subject == "" {
		t.Error("Subject should be populated from the leaf")
	}
	want := sha256.Sum256(cert.Raw)
	if identity.FingerprintSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("FingerprintSHA256 = %q, want %q", identity.FingerprintSHA256, hex.EncodeToString(want[:]))
	}
	// The fabric segment must NOT leak into tenant/gateway (only org/gateway are used).
	if identity.TenantID == "fabric-1" || identity.GatewayID == "fabric-1" {
		t.Error("fabric segment must not map into tenant or gateway")
	}
}

// Percent-encoded identity segments WITHOUT an embedded path separator round-trip
// (e.g. spaces) — matching gateway.parseRelayGatewayClientSPIFFE, which splits on the
// decoded url.Path and then url.PathUnescapes each segment.
func TestRelayGatewayClientIdentityFromCertificate_UnescapesSegments(t *testing.T) {
	spiffeID := gatewaycert.RelayGatewayClientSPIFFE("fabric one", "org with space", "gw with space")
	cert := certWithURIs(t, spiffeID)
	identity, err := gatewaycert.RelayGatewayClientIdentityFromCertificate(cert)
	if err != nil {
		t.Fatalf("RelayGatewayClientIdentityFromCertificate error = %v", err)
	}
	if identity.TenantID != "org with space" {
		t.Errorf("TenantID = %q, want %q", identity.TenantID, "org with space")
	}
	if identity.GatewayID != "gw with space" {
		t.Errorf("GatewayID = %q, want %q", identity.GatewayID, "gw with space")
	}
}

// EXACT-MIRROR guard: an identity segment containing an embedded '/' (encoded as %2F)
// decodes via url.Path into extra path elements, so the 8-part check fails. Both this
// extractor AND the canonical gateway.parseRelayGatewayClientSPIFFE reject it the same
// way (SPIFFE path segments cannot contain separators). This pins that the two paths
// do not diverge on the embedded-separator edge case — a divergence would let a cert
// route to a DIFFERENT rendezvous key than the one the receiver registered under.
func TestRelayGatewayClientIdentityFromCertificate_RejectsEmbeddedSeparator(t *testing.T) {
	spiffeID := gatewaycert.RelayGatewayClientSPIFFE("fabric-1", "org/with/slash", "gw-edge")
	cert := certWithURIs(t, spiffeID)
	if identity, ok := gatewaycert.RelayGatewayClientIdentityFromCertificateIfPresent(cert); ok {
		t.Fatalf("accepted a relay-client SPIFFE with an embedded separator: %#v", identity)
	}
}

// Invariants 3 & 5 (extractor level): no garbage / wrong-scheme / malformed
// relay-client SPIFFE is accepted. Each must yield ok=false and an error from the
// non-IfPresent form.
func TestRelayGatewayClientIdentityFromCertificate_RejectsNonRelayClient(t *testing.T) {
	cases := map[string][]string{
		"no URIs":                     nil,
		"federation-gateway scheme":   {componentidentity.GatewayURI(componentidentity.GatewayIdentity{TenantID: "t", GatewayID: "g"})},
		"transport-server scheme":     {gatewaycert.GatewayTransportSPIFFE("fabric-1", "org-1", "gw-1")},
		"business-facade scheme":      {gatewaycert.GatewayBusinessSPIFFE("org-1", "gw-1")},
		"relay-cell backplane scheme": {gatewaycert.RelayCellBackplaneSPIFFE("fabric-1", "cell-1")},
		"wrong host":                  {"spiffe://relay.evil.example/fabric/f/org/o/gateway/g/role/relay-client"},
		"wrong scheme (https)":        {"https://relay.b2bautopilot.com/fabric/f/org/o/gateway/g/role/relay-client"},
		"wrong role segment":          {"spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway/g/role/transport-server"},
		"missing role segment":        {"spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway/g"},
		"too few path parts":          {"spiffe://relay.b2bautopilot.com/fabric/f/org/o"},
		"too many path parts":         {"spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway/g/role/relay-client/extra/x"},
		"wrong fabric label":          {"spiffe://relay.b2bautopilot.com/cell/f/org/o/gateway/g/role/relay-client"},
		"wrong org label":             {"spiffe://relay.b2bautopilot.com/fabric/f/tenant/o/gateway/g/role/relay-client"},
		"wrong gateway label":         {"spiffe://relay.b2bautopilot.com/fabric/f/org/o/node/g/role/relay-client"},
		"empty org segment":           {"spiffe://relay.b2bautopilot.com/fabric/f/org//gateway/g/role/relay-client"},
		"empty gateway segment":       {"spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway//role/relay-client"},
		"empty fabric segment":        {"spiffe://relay.b2bautopilot.com/fabric//org/o/gateway/g/role/relay-client"},
		"namespace prefix only":       {gatewaycert.RelayGatewayClientNamespace},
		"unrelated workload uri":      {"spiffe://example.org/workload/not-a-gateway"},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			cert := certWithURIs(t, uris...)
			if identity, ok := gatewaycert.RelayGatewayClientIdentityFromCertificateIfPresent(cert); ok {
				t.Fatalf("IfPresent accepted a non-relay-client cert: %#v", identity)
			}
			if _, err := gatewaycert.RelayGatewayClientIdentityFromCertificate(cert); err == nil {
				t.Fatal("RelayGatewayClientIdentityFromCertificate returned nil error for a non-relay-client cert")
			}
		})
	}
}

// A nil certificate is rejected (defensive, fail-closed).
func TestRelayGatewayClientIdentityFromCertificate_NilCert(t *testing.T) {
	if _, ok := gatewaycert.RelayGatewayClientIdentityFromCertificateIfPresent(nil); ok {
		t.Fatal("IfPresent accepted a nil certificate")
	}
	if _, err := gatewaycert.RelayGatewayClientIdentityFromCertificate(nil); err == nil {
		t.Fatal("RelayGatewayClientIdentityFromCertificate(nil) returned nil error")
	}
}

// When a leaf carries BOTH a relay-client URI and unrelated URIs, the relay-client
// URI is found regardless of ordering (the loop scans all SANs).
func TestRelayGatewayClientIdentityFromCertificate_FindsAmongMixedURIs(t *testing.T) {
	spiffeID := gatewaycert.RelayGatewayClientSPIFFE("fabric-1", "org-acme", "gw-edge")
	for _, uris := range [][]string{
		{"spiffe://example.org/workload/x", spiffeID},
		{spiffeID, "spiffe://example.org/workload/x"},
	} {
		cert := certWithURIs(t, uris...)
		identity, err := gatewaycert.RelayGatewayClientIdentityFromCertificate(cert)
		if err != nil {
			t.Fatalf("error = %v for URIs %v", err, uris)
		}
		if identity.TenantID != "org-acme" || identity.GatewayID != "gw-edge" {
			t.Fatalf("unexpected identity %#v for URIs %v", identity, uris)
		}
	}
}
