package gatewaycert

import (
	"net/url"
	"strings"
	"testing"
)

// The relay-client host constant MUST stay equal to the authority embedded in the
// relay-client namespace. If they drift, RelayGatewayClientIdentityFromCertificate
// would reject (or accept) the wrong host. This guard fails fast on that drift.
func TestRelayGatewayClientHostMatchesNamespace(t *testing.T) {
	u, err := url.Parse(strings.TrimSuffix(RelayGatewayClientNamespace, "/"))
	if err != nil {
		t.Fatalf("parse RelayGatewayClientNamespace: %v", err)
	}
	if u.Scheme != "spiffe" {
		t.Fatalf("RelayGatewayClientNamespace scheme = %q, want spiffe", u.Scheme)
	}
	if u.Host != relayGatewayClientHost {
		t.Fatalf("relayGatewayClientHost = %q, want %q (host of RelayGatewayClientNamespace)", relayGatewayClientHost, u.Host)
	}
}

// The private single-URI parser and the exported certificate extractor must agree:
// a SPIFFE produced by the canonical constructor parses to the same org/gateway.
func TestParseRelayGatewayClientSPIFFEURIMatchesConstructor(t *testing.T) {
	raw := RelayGatewayClientSPIFFE("fabric-9", "org-z", "gw-q")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse constructor output: %v", err)
	}
	fabricID, orgID, gatewayID, ok := parseRelayGatewayClientSPIFFEURI(u)
	if !ok {
		t.Fatal("parseRelayGatewayClientSPIFFEURI rejected its own constructor output")
	}
	if fabricID != "fabric-9" || orgID != "org-z" || gatewayID != "gw-q" {
		t.Fatalf("parsed (%q,%q,%q), want (fabric-9,org-z,gw-q)", fabricID, orgID, gatewayID)
	}
}
