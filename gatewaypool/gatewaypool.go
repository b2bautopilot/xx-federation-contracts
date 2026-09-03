package gatewaypool

import "strings"

const (
	LeaseKindCoordinator = "coordinator"
	DefaultLeaseTTLMS    = int64(90_000)
)

func DefaultLeaseKind(kind string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return LeaseKindCoordinator
	}
	return kind
}

func ValidLeaseKind(kind string) bool {
	return DefaultLeaseKind(kind) == LeaseKindCoordinator
}

func Active(holderGatewayID string, expiresAtMS, nowMS int64) bool {
	return strings.TrimSpace(holderGatewayID) != "" && expiresAtMS > nowMS
}
