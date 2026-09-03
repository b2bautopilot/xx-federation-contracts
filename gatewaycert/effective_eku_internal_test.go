package gatewaycert

import (
	"crypto/x509"
	"net/url"
	"testing"
)

// effectiveExtKeyUsage is the EKU-selection guard for the backplane-server role. Lock
// it directly (it is unexported, so this is an internal test): a backplane-server SPIFFE
// gets ServerAuth, everything else gets the plane default — and crucially, a
// backplane-server-shaped SPIFFE on a DIFFERENT plane does NOT escalate to ServerAuth.
func TestEffectiveExtKeyUsageSelectsServerAuthOnlyForBackplaneServerRole(t *testing.T) {
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return u
	}
	serverURI := mustURL(RelayCellBackplaneServerSPIFFE("fabric-prod", "gcp-us-east1-a"))
	clientURI := mustURL(RelayCellBackplaneSPIFFE("fabric-prod", "gcp-us-east1-a"))

	for _, tc := range []struct {
		name  string
		plane CertificatePlane
		uri   *url.URL
		want  x509.ExtKeyUsage
	}{
		{"backplane-server role -> ServerAuth", PlaneRelayCellBackplane, serverURI, x509.ExtKeyUsageServerAuth},
		{"backplane (dialer) role -> ClientAuth", PlaneRelayCellBackplane, clientURI, x509.ExtKeyUsageClientAuth},
		{"server URI on a DIFFERENT plane -> ClientAuth (no escalation)", PlaneRelayGatewayClient, serverURI, x509.ExtKeyUsageClientAuth},
		{"transport plane -> ServerAuth (plane default, role-agnostic)", PlaneGatewayTransport, clientURI, x509.ExtKeyUsageServerAuth},
	} {
		got, err := effectiveExtKeyUsage(tc.plane, tc.uri)
		if err != nil {
			t.Fatalf("%s: effectiveExtKeyUsage error = %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: EKU = %v, want %v", tc.name, got, tc.want)
		}
	}
}
