package gatewaycert

import "testing"

func TestOrgFromRelayGatewayClientSPIFFE(t *testing.T) {
	const fabric, org, gw = "cross-cloud-staging", "018f4c2f-0f35-7e60-9d8d-6fd7350b0001", "gw-1"
	valid := RelayGatewayClientSPIFFE(fabric, org, gw)

	if got, ok := OrgFromRelayGatewayClientSPIFFE(valid); !ok || got != org {
		t.Fatalf("valid relay-client SPIFFE: got (%q,%v), want (%q,true)", got, ok, org)
	}

	rejects := map[string]string{
		"empty":            "",
		"garbage":          "not-a-spiffe",
		"wrong scheme":     "https://relay.b2bautopilot.com/fabric/f/org/o/gateway/g/role/relay-client",
		"transport-server": GatewayTransportSPIFFE(fabric, org, gw), // wrong host + role
		"truncated":        "spiffe://relay.b2bautopilot.com/fabric/f/org/" + org,
	}
	for name, spiffe := range rejects {
		if got, ok := OrgFromRelayGatewayClientSPIFFE(spiffe); ok {
			t.Fatalf("%s: got (%q,true), want ok=false", name, got)
		}
	}
}
