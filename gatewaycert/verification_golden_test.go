package gatewaycert_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/gatewaycert"
)

// This file pins golden SPIFFE strings and fail-closed negative paths for the
// certificate-plane verification primitives. It is intentionally COMPLEMENTARY to
// plane_relayclient_identity_test.go / plane_relaycell_identity_test.go (which assert
// extractor behavior by comparing the builder output against itself) — here the exact
// literal SPIFFE strings are hardcoded so a drift in the builder REGRESSES visibly rather
// than round-tripping two code paths that could both be wrong in the same way.

// Golden relay-client SPIFFE. url.PathEscape leaves alphanumerics, '-', '.' and '_'
// untouched, so the fabric/org/gateway segments above appear verbatim.
func TestGoldenRelayGatewayClientSPIFFE(t *testing.T) {
	const fabric, org, gw = "fabric-alpha", "018f4c2f-0f35-7e60-9d8d-6fd7350b0001", "gw-1"
	const want = "spiffe://relay.b2bautopilot.com/fabric/fabric-alpha/org/018f4c2f-0f35-7e60-9d8d-6fd7350b0001/gateway/gw-1/role/relay-client"
	if got := gatewaycert.RelayGatewayClientSPIFFE(fabric, org, gw); got != want {
		t.Fatalf("RelayGatewayClientSPIFFE() = %q, want %q", got, want)
	}
	if gatewaycert.RelayGatewayClientNamespace != "spiffe://relay.b2bautopilot.com/" {
		t.Fatalf("RelayGatewayClientNamespace = %q", gatewaycert.RelayGatewayClientNamespace)
	}
}

func TestGoldenGatewayTransportSPIFFE(t *testing.T) {
	const fabric, org, gw = "fabric-alpha", "018f4c2f-0f35-7e60-9d8d-6fd7350b0001", "gw-1"
	const want = "spiffe://gateway-transport.b2bautopilot.com/fabric/fabric-alpha/org/018f4c2f-0f35-7e60-9d8d-6fd7350b0001/gateway/gw-1/role/transport-server"
	if got := gatewaycert.GatewayTransportSPIFFE(fabric, org, gw); got != want {
		t.Fatalf("GatewayTransportSPIFFE() = %q, want %q", got, want)
	}
}

func TestGoldenGatewayBusinessSPIFFE(t *testing.T) {
	const org, gw = "018f4c2f-0f35-7e60-9d8d-6fd7350b0001", "gw-1"
	const want = "spiffe://gateway.b2bautopilot.com/org/018f4c2f-0f35-7e60-9d8d-6fd7350b0001/gateway/gw-1/role/business-facade"
	if got := gatewaycert.GatewayBusinessSPIFFE(org, gw); got != want {
		t.Fatalf("GatewayBusinessSPIFFE() = %q, want %q", got, want)
	}
}

func TestGoldenRelayCellBackplaneSPIFFE(t *testing.T) {
	const fabric, cell = "fabric-alpha", "cell-us-east1"
	const want = "spiffe://relay-cell.b2bautopilot.com/fabric/fabric-alpha/relay-cell/cell-us-east1/role/backplane"
	if got := gatewaycert.RelayCellBackplaneSPIFFE(fabric, cell); got != want {
		t.Fatalf("RelayCellBackplaneSPIFFE() = %q, want %q", got, want)
	}
}

func TestGoldenRelayCellBackplaneServerSPIFFE(t *testing.T) {
	const fabric, cell = "fabric-alpha", "cell-us-east1"
	const want = "spiffe://relay-cell.b2bautopilot.com/fabric/fabric-alpha/relay-cell/cell-us-east1/role/backplane-server"
	if got := gatewaycert.RelayCellBackplaneServerSPIFFE(fabric, cell); got != want {
		t.Fatalf("RelayCellBackplaneServerSPIFFE() = %q, want %q", got, want)
	}
}

// RelayCellServerSPIFFE shares the relay-cell trust domain (RelayCellServerNamespace
// == RelayCellBackplaneNamespace) but carries the distinct role/server.
func TestGoldenRelayCellServerSPIFFE(t *testing.T) {
	const fabric, cell = "fabric-alpha", "cell-us-east1"
	const want = "spiffe://relay-cell.b2bautopilot.com/fabric/fabric-alpha/relay-cell/cell-us-east1/role/server"
	if got := gatewaycert.RelayCellServerSPIFFE(fabric, cell); got != want {
		t.Fatalf("RelayCellServerSPIFFE() = %q, want %q", got, want)
	}
	if gatewaycert.RelayCellServerNamespace != gatewaycert.RelayCellBackplaneNamespace {
		t.Fatalf("RelayCellServerNamespace %q != RelayCellBackplaneNamespace %q", gatewaycert.RelayCellServerNamespace, gatewaycert.RelayCellBackplaneNamespace)
	}
}

// OrgFromRelayGatewayClientSPIFFE decision table — accept cases. The org segment of a
// canonical, CA-shaped relay-client SPIFFE is the tenant pin.
func TestOrgFromRelayGatewayClientSPIFFE_Accept(t *testing.T) {
	const fabric, org, gw = "fabric-alpha", "org-acme", "gw-1"

	tests := []struct {
		name   string
		spiffe string
		want   string
	}{
		{name: "uuid org", spiffe: gatewaycert.RelayGatewayClientSPIFFE(fabric, "018f4c2f-0f35-7e60-9d8d-6fd7350b0001", gw), want: "018f4c2f-0f35-7e60-9d8d-6fd7350b0001"},
		{name: "plain org", spiffe: gatewaycert.RelayGatewayClientSPIFFE(fabric, org, gw), want: org},
		{name: "percent-encoded org", spiffe: gatewaycert.RelayGatewayClientSPIFFE(fabric, "org with space", gw), want: "org with space"},
	}
	for _, tt := range tests {
		got, ok := gatewaycert.OrgFromRelayGatewayClientSPIFFE(tt.spiffe)
		if !ok {
			t.Errorf("%s: OrgFromRelayGatewayClientSPIFFE ok=false, want true", tt.name)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: got org %q, want %q", tt.name, got, tt.want)
		}
	}
}

// OrgFromRelayGatewayClientSPIFFE decision table — reject cases (fail-closed on every
// malformed / wrong-plane / wrong-scheme / short-path candidate).
func TestOrgFromRelayGatewayClientSPIFFE_Reject(t *testing.T) {
	const fabric, org, gw = "fabric-alpha", "org-acme", "gw-1"
	rejects := map[string]string{
		"empty":            "",
		"whitespace":       "   ",
		"garbage":          "not-a-spiffe",
		"https scheme":     "https://relay.b2bautopilot.com/fabric/f/org/o/gateway/g/role/relay-client",
		"wrong host":       "spiffe://relay.evil.example/fabric/f/org/o/gateway/g/role/relay-client",
		"transport role":   gatewaycert.GatewayTransportSPIFFE(fabric, org, gw),
		"business role":    gatewaycert.GatewayBusinessSPIFFE(org, gw),
		"backplane role":   gatewaycert.RelayCellBackplaneSPIFFE(fabric, "cell-1"),
		"truncated path":   "spiffe://relay.b2bautopilot.com/fabric/f/org/" + org,
		"missing role":     "spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway/g",
		"empty org":        "spiffe://relay.b2bautopilot.com/fabric/f/org//gateway/g/role/relay-client",
		"empty gateway":    "spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway//role/relay-client",
		"empty fabric":     "spiffe://relay.b2bautopilot.com/fabric//org/o/gateway/g/role/relay-client",
		"wrong role label": "spiffe://relay.b2bautopilot.com/fabric/f/org/o/gateway/g/role/client",
		"wrong org label":  "spiffe://relay.b2bautopilot.com/fabric/f/tenant/o/gateway/g/role/relay-client",
		"namespace only":   gatewaycert.RelayGatewayClientNamespace,
	}
	for name, spiffe := range rejects {
		if got, ok := gatewaycert.OrgFromRelayGatewayClientSPIFFE(spiffe); ok {
			t.Errorf("%s: got (%q,true), want ok=false", name, got)
		}
	}
}

// ValidateRelayClientTenantID is the RLS-scoped uuid tenant gate. A non-uuid org segment
// (domain / handle / junk / whitespace) must be rejected as ErrPlaneIdentityMismatch.
func TestValidateRelayClientTenantID_Negative(t *testing.T) {
	rejects := []string{
		"",                                     // empty
		"   ",                                  // whitespace
		"oldco.example",                        // a domain (recipient-directory addressing label)
		"org-newco",                            // a handle
		"not-a-uuid",                           // junk
		"018f4c2f-0f35-7e60",                   // truncated uuid
		"018f4c2f 0f35 7e60 9d8d 6fd7350b0001", // space-formatted
		"018f4c2f_0f35_7e60_9d8d_6fd7350b0001", // underscore-formatted
	}
	for _, id := range rejects {
		err := gatewaycert.ValidateRelayClientTenantID(id)
		if err == nil {
			t.Errorf("ValidateRelayClientTenantID(%q) = nil, want error", id)
			continue
		}
		if !errors.Is(err, gatewaycert.ErrPlaneIdentityMismatch) {
			t.Errorf("ValidateRelayClientTenantID(%q) error = %v, want ErrPlaneIdentityMismatch", id, err)
		}
	}
}

// ValidateRelayCellServerDNSName is the fail-closed hostname gate for the relay-cell
// :443 server leaf. Any malformed label, bare hostname, wildcard, or untrimmed name is
// rejected — the rule EnforcedIssueRelayCellServer applies at mint time.
func TestValidateRelayCellServerDNSName_Negative(t *testing.T) {
	rejects := []string{
		"",
		"   ",
		"   cell.b2bautopilot.com",   // leading whitespace must NOT be trimmed away
		"cell.b2bautopilot.com   ",   // trailing whitespace
		"*.b2bautopilot.com",         // wildcard
		"cell",                       // single-label hostname, not an FQDN
		"-cell.b2bautopilot.com",     // label starts with hyphen
		"cell-.b2bautopilot.com",     // label ends with hyphen
		"cell_name.b2bautopilot.com", // underscore is not a DNS label char
		"cell..b2bautopilot.com",     // empty interior label
		"cell in.b2bautopilot.com",   // space inside label
	}
	for _, name := range rejects {
		if err := gatewaycert.ValidateRelayCellServerDNSName(name); err == nil {
			t.Errorf("ValidateRelayCellServerDNSName(%q) = nil, want error", name)
		}
	}
}

// ValidateRelayCellServerDNSName accepts a strict canonical FQDN.
func TestValidateRelayCellServerDNSName_Accept(t *testing.T) {
	accepts := []string{
		"cell-us-east1.b2bautopilot.com",
		"gcprelay.b2bautopilot.com",
		"a.example.com",
		"relay-01.eu-west3.b2bautopilot.cloud",
	}
	for _, name := range accepts {
		if err := gatewaycert.ValidateRelayCellServerDNSName(name); err != nil {
			t.Errorf("ValidateRelayCellServerDNSName(%q) = %v, want nil", name, err)
		}
	}
}

// VerifyBackplanePeer is fail-closed: no verified peer certificate yields
// ErrPlaneIdentityMismatch, as does a leaf that does not carry a well-formed
// backplane SPIFFE (here an embedded '%2F' separator breaks the 6-part parse).
func TestVerifyBackplanePeer_FailClosed(t *testing.T) {
	// Empty PeerCertificates.
	_, err := gatewaycert.VerifyBackplanePeer(tls.ConnectionState{})
	if err == nil {
		t.Fatal("VerifyBackplanePeer(empty state) = nil, want error")
	}
	if !errors.Is(err, gatewaycert.ErrPlaneIdentityMismatch) {
		t.Errorf("VerifyBackplanePeer(empty) error = %v, want ErrPlaneIdentityMismatch", err)
	}

	// A backplane leaf with an embedded '%2F' separator in the cell segment.
	malformed := gatewaycert.RelayCellBackplaneSPIFFE("fabric-1", "cell/with/slash")
	_, err = gatewaycert.VerifyBackplanePeer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certWithURIs(t, malformed)}})
	if err == nil {
		t.Fatal("VerifyBackplanePeer(malformed backplane SPIFFE) = nil, want error")
	}
	if !errors.Is(err, gatewaycert.ErrPlaneIdentityMismatch) {
		t.Errorf("VerifyBackplanePeer(malformed) error = %v, want ErrPlaneIdentityMismatch", err)
	}
}

// SPKISHA256ForPublicKey is a golden digest over the DER SPKI bytes, base64url-encoded
// (no padding). Semantics from provider.go: x509.MarshalPKIXPublicKey -> sha256 ->
// base64.RawURLEncoding. ed25519 PKIX is deterministic, so the digest is fixed per key.
func TestGoldenSPKISHA256ForPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey error = %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey error = %v", err)
	}
	sum := sha256.Sum256(spki)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	got, err := gatewaycert.SPKISHA256ForPublicKey(pub)
	if err != nil {
		t.Fatalf("SPKISHA256ForPublicKey error = %v", err)
	}
	if got != want {
		t.Fatalf("SPKISHA256ForPublicKey = %q, want %q", got, want)
	}
	// A 32-byte sha256 digest base64url-encoded is 43 chars with no padding.
	if len(got) != 43 {
		t.Errorf("SPKISHA256ForPublicKey length = %d, want 43 (base64url sha256)", len(got))
	}
}

// SPKISHA256ForPublicKey is fail-closed: a non-marshalable public key is an error.
func TestSPKISHA256ForPublicKey_RejectsInvalidKey(t *testing.T) {
	var nilTyped *ed25519.PublicKey
	if _, err := gatewaycert.SPKISHA256ForPublicKey(nilTyped); err == nil {
		t.Fatal("SPKISHA256ForPublicKey(nil typed pointer) = nil error, want error")
	}
}
