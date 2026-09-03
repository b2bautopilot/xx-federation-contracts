package federationstate

import "testing"

func TestCredentialUsable(t *testing.T) {
	cases := []struct {
		name           string
		state          string
		revokedAt, nb  int64
		expiresAt, now int64
		want           bool
	}{
		{"active no windows usable", CredentialActive, 0, 0, 0, 500, true},
		{"revoked denied", CredentialActive, 100, 0, 0, 500, false},
		{"non-active denied", CredentialRevoked, 0, 0, 0, 500, false},
		{"before not-before denied", CredentialActive, 0, 1000, 0, 500, false},
		{"at-not-before usable", CredentialActive, 0, 1000, 0, 1000, true},
		{"at-expiry denied", CredentialActive, 0, 0, 2000, 2000, false},
		{"within window usable", CredentialActive, 0, 1000, 2000, 1500, true},
	}
	for _, c := range cases {
		if got := CredentialUsable(c.state, c.revokedAt, c.nb, c.expiresAt, c.now); got != c.want {
			t.Errorf("%s: CredentialUsable = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPartnerLinkRuntimeUsable(t *testing.T) {
	cases := []struct {
		name                         string
		state                        string
		killSwitch                   bool
		effective, expires, rev, now int64
		want                         bool
	}{
		{"active usable", PartnerLinkActive, false, 0, 0, 0, 500, true},
		{"kill switch denies", PartnerLinkActive, true, 0, 0, 0, 500, false},
		{"non-active denied", PartnerLinkPending, false, 0, 0, 0, 500, false},
		{"revoked denied", PartnerLinkActive, false, 0, 0, 300, 500, false},
		{"before effective denied", PartnerLinkActive, false, 1000, 0, 0, 500, false},
		{"expired denied", PartnerLinkActive, false, 0, 1000, 0, 1500, false},
	}
	for _, c := range cases {
		if got := PartnerLinkRuntimeUsable(c.state, c.killSwitch, c.effective, c.expires, c.rev, c.now); got != c.want {
			t.Errorf("%s: PartnerLinkRuntimeUsable = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPartnerTrustMaterialUsable(t *testing.T) {
	if !PartnerTrustMaterialUsable(PartnerTrustActive, 0, 0, 0, 500) {
		t.Error("active trust with no windows should be usable")
	}
	if PartnerTrustMaterialUsable(PartnerTrustPending, 0, 0, 0, 500) {
		t.Error("pending trust must not be usable")
	}
	if PartnerTrustMaterialUsable(PartnerTrustActive, 0, 1000, 0, 1500) {
		t.Error("expired trust must not be usable")
	}
	if PartnerTrustMaterialUsable(PartnerTrustActive, 1000, 0, 0, 500) {
		t.Error("trust not yet effective must not be usable")
	}
	if PartnerTrustMaterialUsable(PartnerTrustActive, 0, 0, 100, 500) {
		t.Error("revoked trust must not be usable")
	}
}

func TestGatewayPrincipalUsable(t *testing.T) {
	if !GatewayPrincipalUsable(GatewayActive, 0) {
		t.Error("active principal is usable")
	}
	if GatewayPrincipalUsable(GatewayPending, 0) {
		t.Error("pending principal must not be usable")
	}
	if GatewayPrincipalUsable(GatewayActive, 10) {
		t.Error("revoked principal must not be usable")
	}
}

func TestGatewayAllowedByIdentity(t *testing.T) {
	claims := GatewayIdentityClaims{GatewayID: "gw-a", ServicePrincipalID: "sp-a", MTLSSubject: "CN=gw-a", SPIFFEID: "spiffe://gw-a"}
	if !GatewayAllowedByIdentity(nil, claims) {
		t.Error("empty allow list must be open")
	}
	if !GatewayAllowedByIdentity([]string{"gw-a"}, claims) {
		t.Error("gateway id in allow list must match")
	}
	if !GatewayAllowedByIdentity([]string{"sp-a"}, claims) {
		t.Error("service principal in allow list must match")
	}
	if !GatewayAllowedByIdentity([]string{"CN=gw-a"}, claims) {
		t.Error("mtls subject in allow list must match")
	}
	if !GatewayAllowedByIdentity([]string{"spiffe://gw-a"}, claims) {
		t.Error("spiffe id in allow list must match")
	}
	if GatewayAllowedByIdentity([]string{"unrelated"}, claims) {
		t.Error("unrelated allow list must not match (fail closed)")
	}
}

func TestDefaultFallbacks(t *testing.T) {
	if got := DefaultPartnerLinkState(PartnerLinkActive); got != PartnerLinkActive {
		t.Errorf("DefaultPartnerLinkState active = %q", got)
	}
	if got := DefaultHealthState(HealthHealthy); got != HealthHealthy {
		t.Errorf("DefaultHealthState healthy = %q", got)
	}
	if got := DefaultGatewayState(GatewayDegraded); got != GatewayDegraded {
		t.Errorf("DefaultGatewayState degraded = %q", got)
	}
	if got := DefaultCredentialKind(CredentialSPIFFEJWT); got != CredentialSPIFFEJWT {
		t.Errorf("DefaultCredentialKind = %q", got)
	}
	if got := DefaultPartnerLinkState("bogus"); got != PartnerLinkPending {
		t.Errorf("unknown partner-link state = %q, want pending", got)
	}
	if got := DefaultHealthState(""); got != HealthUnknown {
		t.Errorf("unknown health = %q, want unknown", got)
	}
	if got := DefaultGatewayState(""); got != GatewayPending {
		t.Errorf("unknown gateway state = %q, want pending", got)
	}
	if got := DefaultCredentialKind(""); got != CredentialMTLSCertificate {
		t.Errorf("unknown credential kind = %q, want mtls_certificate", got)
	}
	if got := DefaultIdentityProvenance("", ""); got != IdentityProvenanceUnknown {
		t.Errorf("empty provenance = %q, want unknown", got)
	}
	if got := DefaultGatewayRoutingPolicy(""); got != GatewayRoutingActiveActive {
		t.Errorf("empty routing policy = %q, want active_active", got)
	}
	if got := DefaultPartnerTrustState(""); got != PartnerTrustPending {
		t.Errorf("empty trust state = %q, want pending", got)
	}
	if got := DefaultPartnerVerificationState(""); got != PartnerVerificationUnverified {
		t.Errorf("empty verification = %q, want unverified", got)
	}
	if got := DefaultGatewayBootstrapState(""); got != GatewayBootstrapPending {
		t.Errorf("empty bootstrap = %q, want pending", got)
	}
}

func TestValidPredicates_Tight(t *testing.T) {
	for _, bad := range []string{"nope", "", "pending-status"} {
		if ValidCredentialState(bad) {
			t.Errorf("ValidCredentialState(%q) = true", bad)
		}
		if ValidHealthState(bad) {
			t.Errorf("ValidHealthState(%q) = true", bad)
		}
		if ValidGatewayState(bad) {
			t.Errorf("ValidGatewayState(%q) = true", bad)
		}
		if ValidPartnerLinkState(bad) {
			t.Errorf("ValidPartnerLinkState(%q) = true", bad)
		}
		if ValidIdentityProvenance(bad) {
			t.Errorf("ValidIdentityProvenance(%q) = true", bad)
		}
		if ValidGatewayBootstrapState(bad) {
			t.Errorf("ValidGatewayBootstrapState(%q) = true", bad)
		}
		if ValidGatewayRoutingPolicy(bad) {
			t.Errorf("ValidGatewayRoutingPolicy(%q) = true", bad)
		}
	}
}
