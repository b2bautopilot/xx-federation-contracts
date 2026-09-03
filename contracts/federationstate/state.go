package federationstate

import "strings"

const (
	PartnerVerificationUnverified = "unverified"
	PartnerVerificationPending    = "pending"
	PartnerVerificationVerified   = "verified"
	PartnerVerificationSuspended  = "suspended"

	PartnerLinkPending   = "pending"
	PartnerLinkActive    = "active"
	PartnerLinkSuspended = "suspended"
	PartnerLinkRevoked   = "revoked"
	PartnerLinkExpired   = "expired"

	GatewayRoutingActiveActive  = "active_active"
	GatewayRoutingActiveStandby = "active_standby"
	GatewayRoutingManual        = "manual"

	HealthUnknown     = "unknown"
	HealthHealthy     = "healthy"
	HealthDegraded    = "degraded"
	HealthUnavailable = "unavailable"
	HealthRevoked     = "revoked"

	GatewayPending  = "pending"
	GatewayActive   = "active"
	GatewayDegraded = "degraded"
	GatewayRevoked  = "revoked"
	GatewayExpired  = "expired"

	CredentialMTLSCertificate = "mtls_certificate"
	CredentialSPIFFEJWT       = "spiffe_jwt"
	CredentialBootstrapToken  = "bootstrap_token"

	CredentialActive  = "active"
	CredentialRevoked = "revoked"
	CredentialExpired = "expired"

	IdentityProvenanceUnknown       = "unknown"
	IdentityProvenancePilotAsserted = "pilot_asserted"
	IdentityProvenanceCSRDerived    = "csr_derived"
	IdentityProvenanceNotIssued     = "not_issued"

	GatewayBootstrapPending          = "pending"
	GatewayBootstrapRedeemed         = "redeemed"
	GatewayBootstrapRevoked          = "revoked"
	GatewayBootstrapExpired          = "expired"
	GatewayBootstrapTerminalRejected = "terminal_rejected"

	PartnerTrustPending = "pending"
	PartnerTrustActive  = "active"
	PartnerTrustRevoked = "revoked"
	PartnerTrustExpired = "expired"
)

func DefaultPartnerVerificationState(value string) string {
	if ValidPartnerVerificationState(value) {
		return value
	}
	return PartnerVerificationUnverified
}

func ValidPartnerVerificationState(value string) bool {
	switch value {
	case PartnerVerificationUnverified, PartnerVerificationPending, PartnerVerificationVerified, PartnerVerificationSuspended:
		return true
	default:
		return false
	}
}

func DefaultPartnerLinkState(value string) string {
	if ValidPartnerLinkState(value) {
		return value
	}
	return PartnerLinkPending
}

func ValidPartnerLinkState(value string) bool {
	switch value {
	case PartnerLinkPending, PartnerLinkActive, PartnerLinkSuspended, PartnerLinkRevoked, PartnerLinkExpired:
		return true
	default:
		return false
	}
}

func PartnerLinkUsable(state string, killSwitchEnabled bool, nowMS, expiresAtMS int64) bool {
	if killSwitchEnabled || state != PartnerLinkActive {
		return false
	}
	return expiresAtMS == 0 || nowMS < expiresAtMS
}

func PartnerLinkRuntimeUsable(state string, killSwitchEnabled bool, effectiveAtMS, expiresAtMS, revokedAtMS, nowMS int64) bool {
	if revokedAtMS != 0 || !PartnerLinkUsable(state, killSwitchEnabled, nowMS, expiresAtMS) {
		return false
	}
	return effectiveAtMS == 0 || nowMS >= effectiveAtMS
}

func DefaultPartnerTrustState(value string) string {
	if ValidPartnerTrustState(value) {
		return value
	}
	return PartnerTrustPending
}

func ValidPartnerTrustState(value string) bool {
	switch value {
	case PartnerTrustPending, PartnerTrustActive, PartnerTrustRevoked, PartnerTrustExpired:
		return true
	default:
		return false
	}
}

func PartnerTrustMaterialUsable(state string, effectiveAtMS, expiresAtMS, revokedAtMS, nowMS int64) bool {
	if revokedAtMS != 0 || state != PartnerTrustActive {
		return false
	}
	if effectiveAtMS != 0 && nowMS < effectiveAtMS {
		return false
	}
	return expiresAtMS == 0 || nowMS < expiresAtMS
}

func DefaultGatewayRoutingPolicy(value string) string {
	if ValidGatewayRoutingPolicy(value) {
		return value
	}
	return GatewayRoutingActiveActive
}

func ValidGatewayRoutingPolicy(value string) bool {
	switch value {
	case GatewayRoutingActiveActive, GatewayRoutingActiveStandby, GatewayRoutingManual:
		return true
	default:
		return false
	}
}

func DefaultHealthState(value string) string {
	if ValidHealthState(value) {
		return value
	}
	return HealthUnknown
}

func ValidHealthState(value string) bool {
	switch value {
	case HealthUnknown, HealthHealthy, HealthDegraded, HealthUnavailable, HealthRevoked:
		return true
	default:
		return false
	}
}

func DefaultGatewayState(value string) string {
	if ValidGatewayState(value) {
		return value
	}
	return GatewayPending
}

func ValidGatewayState(value string) bool {
	switch value {
	case GatewayPending, GatewayActive, GatewayDegraded, GatewayRevoked, GatewayExpired:
		return true
	default:
		return false
	}
}

func GatewayPrincipalUsable(state string, revokedAtMS int64) bool {
	return state == GatewayActive && revokedAtMS == 0
}

func DefaultCredentialKind(value string) string {
	if ValidCredentialKind(value) {
		return value
	}
	return CredentialMTLSCertificate
}

func ValidCredentialKind(value string) bool {
	switch value {
	case CredentialMTLSCertificate, CredentialSPIFFEJWT, CredentialBootstrapToken:
		return true
	default:
		return false
	}
}

func DefaultCredentialState(value string) string {
	if ValidCredentialState(value) {
		return value
	}
	return CredentialActive
}

func ValidCredentialState(value string) bool {
	switch value {
	case CredentialActive, CredentialRevoked, CredentialExpired:
		return true
	default:
		return false
	}
}

func CredentialUsable(state string, revokedAtMS, notBeforeMS, expiresAtMS, nowMS int64) bool {
	if state != CredentialActive || revokedAtMS != 0 {
		return false
	}
	if notBeforeMS != 0 && nowMS < notBeforeMS {
		return false
	}
	return expiresAtMS == 0 || nowMS < expiresAtMS
}

func DefaultIdentityProvenance(value, fallback string) string {
	if ValidIdentityProvenance(value) {
		return value
	}
	if ValidIdentityProvenance(fallback) {
		return fallback
	}
	return IdentityProvenanceUnknown
}

func DefaultLegacyIdentityProvenance(value, fallback string) string {
	if value == IdentityProvenanceCSRDerived {
		value = ""
	}
	if fallback == IdentityProvenanceCSRDerived {
		fallback = IdentityProvenanceUnknown
	}
	return DefaultIdentityProvenance(value, fallback)
}

func ValidIdentityProvenance(value string) bool {
	switch value {
	case IdentityProvenanceUnknown, IdentityProvenancePilotAsserted, IdentityProvenanceCSRDerived, IdentityProvenanceNotIssued:
		return true
	default:
		return false
	}
}

func DefaultGatewayBootstrapState(value string) string {
	if ValidGatewayBootstrapState(value) {
		return value
	}
	return GatewayBootstrapPending
}

func ValidGatewayBootstrapState(value string) bool {
	switch value {
	case GatewayBootstrapPending, GatewayBootstrapRedeemed, GatewayBootstrapRevoked, GatewayBootstrapExpired, GatewayBootstrapTerminalRejected:
		return true
	default:
		return false
	}
}

const RelayGatewayClientCertificatePlane = "relay_gateway_client"

type GatewayIdentityClaims struct {
	GatewayID          string
	ServicePrincipalID string
	MTLSSubject        string
	SPIFFEID           string
}

func GatewayAllowedByIdentity(allowed []string, claims GatewayIdentityClaims) bool {
	if len(allowed) == 0 {
		return true
	}
	values := map[string]bool{}
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value != "" {
			values[value] = true
		}
	}
	return values[strings.TrimSpace(claims.GatewayID)] ||
		values[strings.TrimSpace(claims.ServicePrincipalID)] ||
		values[strings.TrimSpace(claims.MTLSSubject)] ||
		values[strings.TrimSpace(claims.SPIFFEID)]
}

func GatewayRelayCredentialAuthorityMatches(certificatePlane, credentialProvenance, gatewayRelayProvenance, requiredPlane, requiredProvenance string) bool {
	requiredPlane = strings.TrimSpace(requiredPlane)
	requiredProvenance = strings.TrimSpace(requiredProvenance)
	if requiredPlane != "" && strings.TrimSpace(certificatePlane) != requiredPlane {
		return false
	}
	if requiredProvenance != "" && strings.TrimSpace(credentialProvenance) != requiredProvenance {
		return false
	}
	if requiredPlane == RelayGatewayClientCertificatePlane && requiredProvenance != "" &&
		strings.TrimSpace(gatewayRelayProvenance) != requiredProvenance {
		return false
	}
	return true
}
