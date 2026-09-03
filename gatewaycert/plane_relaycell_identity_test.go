package gatewaycert_test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
)

// (reuses certWithURIs from plane_relayclient_identity_test.go — same test package.)

// A relay-cell backplane SPIFFE maps fabric->FabricID, relay-cell->RelayCellID and
// carries SPIFFEID/Subject/FingerprintSHA256 from the leaf. The relay-cell segment is
// a CELL id, NOT a tenant — there is no uuid rule.
func TestRelayCellBackplaneIdentityFromCertificate_MapsFabricAndCell(t *testing.T) {
	spiffeID := gatewaycert.RelayCellBackplaneSPIFFE("fabric-prod", "gcp-us-east1-a")
	cert := certWithURIs(t, spiffeID)

	identity, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(cert)
	if err != nil {
		t.Fatalf("RelayCellBackplaneIdentityFromCertificate error = %v", err)
	}
	if identity.FabricID != "fabric-prod" {
		t.Errorf("FabricID = %q, want fabric-prod", identity.FabricID)
	}
	if identity.RelayCellID != "gcp-us-east1-a" {
		t.Errorf("RelayCellID = %q, want gcp-us-east1-a", identity.RelayCellID)
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
}

func TestRelayCellBackplaneIdentityFromCertificate_UnescapesSegments(t *testing.T) {
	spiffeID := gatewaycert.RelayCellBackplaneSPIFFE("fabric one", "cell with space")
	cert := certWithURIs(t, spiffeID)
	identity, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(cert)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if identity.FabricID != "fabric one" || identity.RelayCellID != "cell with space" {
		t.Fatalf("unexpected identity %#v", identity)
	}
}

// An embedded '/' (encoded %2F) decodes into extra path elements, breaking the
// 6-part check — rejected, same as the relay-client parser.
func TestRelayCellBackplaneIdentityFromCertificate_RejectsEmbeddedSeparator(t *testing.T) {
	spiffeID := gatewaycert.RelayCellBackplaneSPIFFE("fabric-1", "cell/with/slash")
	cert := certWithURIs(t, spiffeID)
	if identity, ok := gatewaycert.RelayCellBackplaneIdentityFromCertificateIfPresent(cert); ok {
		t.Fatalf("accepted a backplane SPIFFE with an embedded separator: %#v", identity)
	}
}

// No garbage / wrong-scheme / wrong-plane / malformed backplane SPIFFE is accepted.
// Notably the OTHER three plane schemes (relay-client, transport, business) are
// rejected — different host + path shape make cross-plane confusion impossible.
func TestRelayCellBackplaneIdentityFromCertificate_RejectsNonBackplane(t *testing.T) {
	cases := map[string][]string{
		"no URIs":                  nil,
		"relay-client scheme":      {gatewaycert.RelayGatewayClientSPIFFE("fabric-1", "11111111-1111-4111-8111-111111111111", "gw-1")},
		"transport-server scheme":  {gatewaycert.GatewayTransportSPIFFE("fabric-1", "org-1", "gw-1")},
		"business-facade scheme":   {gatewaycert.GatewayBusinessSPIFFE("org-1", "gw-1")},
		"wrong host (relay)":       {"spiffe://relay.b2bautopilot.com/fabric/f/relay-cell/c/role/backplane"},
		"wrong scheme (https)":     {"https://relay-cell.b2bautopilot.com/fabric/f/relay-cell/c/role/backplane"},
		"wrong role segment":       {"spiffe://relay-cell.b2bautopilot.com/fabric/f/relay-cell/c/role/relay-client"},
		"missing role segment":     {"spiffe://relay-cell.b2bautopilot.com/fabric/f/relay-cell/c"},
		"too few path parts":       {"spiffe://relay-cell.b2bautopilot.com/fabric/f"},
		"too many path parts":      {"spiffe://relay-cell.b2bautopilot.com/fabric/f/relay-cell/c/role/backplane/extra/x"},
		"wrong fabric label":       {"spiffe://relay-cell.b2bautopilot.com/cell/f/relay-cell/c/role/backplane"},
		"wrong relay-cell label":   {"spiffe://relay-cell.b2bautopilot.com/fabric/f/cell/c/role/backplane"},
		"empty fabric segment":     {"spiffe://relay-cell.b2bautopilot.com/fabric//relay-cell/c/role/backplane"},
		"empty relay-cell segment": {"spiffe://relay-cell.b2bautopilot.com/fabric/f/relay-cell//role/backplane"},
		"namespace prefix only":    {gatewaycert.RelayCellBackplaneNamespace},
		"unrelated workload uri":   {"spiffe://example.org/workload/not-a-cell"},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			cert := certWithURIs(t, uris...)
			if identity, ok := gatewaycert.RelayCellBackplaneIdentityFromCertificateIfPresent(cert); ok {
				t.Fatalf("IfPresent accepted a non-backplane cert: %#v", identity)
			}
			if _, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(cert); err == nil {
				t.Fatal("RelayCellBackplaneIdentityFromCertificate returned nil error for a non-backplane cert")
			}
		})
	}
}

func TestRelayCellBackplaneIdentityFromCertificate_NilCert(t *testing.T) {
	if _, ok := gatewaycert.RelayCellBackplaneIdentityFromCertificateIfPresent(nil); ok {
		t.Fatal("IfPresent accepted a nil certificate")
	}
	if _, err := gatewaycert.RelayCellBackplaneIdentityFromCertificate(nil); err == nil {
		t.Fatal("RelayCellBackplaneIdentityFromCertificate(nil) returned nil error")
	}
}

// Symmetric cross-plane rejection: a relay-client leaf is rejected by the backplane
// extractor, and a backplane leaf by the relay-client extractor.
func TestBackplaneAndRelayClientExtractors_RejectEachOther(t *testing.T) {
	relayLeaf := certWithURIs(t, gatewaycert.RelayGatewayClientSPIFFE("fabric-1", "11111111-1111-4111-8111-111111111111", "gw-1"))
	backplaneLeaf := certWithURIs(t, gatewaycert.RelayCellBackplaneSPIFFE("fabric-1", "cell-1"))
	if _, ok := gatewaycert.RelayCellBackplaneIdentityFromCertificateIfPresent(relayLeaf); ok {
		t.Error("backplane extractor accepted a relay-client leaf")
	}
	if _, ok := gatewaycert.RelayGatewayClientIdentityFromCertificateIfPresent(backplaneLeaf); ok {
		t.Error("relay-client extractor accepted a backplane leaf")
	}
}

// VerifyBackplanePeer reads the verified peer leaf from a tls.ConnectionState and is
// fail-closed: empty state or a non-backplane leaf yields an error and no identity.
func TestVerifyBackplanePeer(t *testing.T) {
	backplaneLeaf := certWithURIs(t, gatewaycert.RelayCellBackplaneSPIFFE("fabric-1", "cell-1"))
	id, err := gatewaycert.VerifyBackplanePeer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{backplaneLeaf}})
	if err != nil {
		t.Fatalf("VerifyBackplanePeer error = %v", err)
	}
	if id.RelayCellID != "cell-1" || id.FabricID != "fabric-1" {
		t.Errorf("unexpected identity %#v", id)
	}

	if _, err := gatewaycert.VerifyBackplanePeer(tls.ConnectionState{}); err == nil {
		t.Error("VerifyBackplanePeer accepted an empty connection state (no peer cert)")
	}

	relayLeaf := certWithURIs(t, gatewaycert.RelayGatewayClientSPIFFE("fabric-1", "11111111-1111-4111-8111-111111111111", "gw-1"))
	if _, err := gatewaycert.VerifyBackplanePeer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{relayLeaf}}); err == nil {
		t.Error("VerifyBackplanePeer accepted a relay-client leaf (cross-plane)")
	}
}
