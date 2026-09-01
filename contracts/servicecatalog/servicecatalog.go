package servicecatalog

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/b2bautopilot/xx-federation-contracts/apperrors"
)

const (
	StateActive     = "active"
	StateDeprecated = "deprecated"
	StateRetired    = "retired"

	maxPublicSchemaBytes = 64 * 1024
)

type EntryInput struct {
	TenantID                  string
	ServiceCatalogID          string
	DisplayName               string
	Description               string
	ServiceKind               string
	SchemaJSON                string
	SchemaVersion             string
	AllowedActionsJSON        string
	State                     string
	ReplacementCatalogEntryID string
}

func DefaultState(state string) string {
	switch strings.TrimSpace(state) {
	case "", StateActive:
		return StateActive
	case StateDeprecated:
		return StateDeprecated
	case StateRetired:
		return StateRetired
	default:
		return strings.TrimSpace(state)
	}
}

func VisibleState(state string) bool {
	switch DefaultState(state) {
	case StateActive, StateDeprecated:
		return true
	default:
		return false
	}
}

func ValidateEntry(input EntryInput) error {
	if strings.TrimSpace(input.TenantID) == "" {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "tenant_id is required")
	}
	if strings.TrimSpace(input.DisplayName) == "" {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "display_name is required")
	}
	if containsPrivateMaterial(strings.TrimSpace(input.DisplayName)) {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "display_name contains private topology or secret material")
	}
	if containsPrivateMaterial(strings.TrimSpace(input.Description)) {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "description contains private topology or secret material")
	}
	if strings.TrimSpace(input.ServiceKind) == "" {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "service_kind is required")
	}
	if strings.TrimSpace(input.SchemaVersion) == "" {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "schema_version is required")
	}
	if err := ValidatePublicSchemaJSON(input.SchemaJSON); err != nil {
		return err
	}
	if err := ValidateAllowedActionsJSON(input.AllowedActionsJSON); err != nil {
		return err
	}
	state := DefaultState(input.State)
	if state != StateActive && state != StateDeprecated && state != StateRetired {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "state is invalid")
	}
	if state == StateDeprecated && strings.TrimSpace(input.ReplacementCatalogEntryID) == strings.TrimSpace(input.ServiceCatalogID) {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "replacement service_catalog_id must differ from the deprecated entry")
	}
	return nil
}

func PublicText(value string) string {
	value = strings.TrimSpace(value)
	if containsPrivateMaterial(value) {
		return ""
	}
	return value
}

func ValidatePublicSchemaJSON(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "schema_json is required")
	}
	if len(raw) > maxPublicSchemaBytes {
		return apperrors.New(apperrors.CodeCoordPayloadTooLarge, "service_catalog", "schema_json is too large")
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return apperrors.Wrap(apperrors.CodeControlInvalidArgument, "service_catalog", "schema_json must be valid JSON", err)
	}
	if containsPrivateMaterial(decoded) {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "schema_json contains private topology or secret material")
	}
	return nil
}

func ValidateAllowedActionsJSON(raw string) error {
	_, err := AllowedActions(raw)
	return err
}

func AllowedActions(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "allowed_actions_json is required")
	}
	var decoded []string
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, apperrors.Wrap(apperrors.CodeControlInvalidArgument, "service_catalog", "allowed_actions_json must be a JSON array of action strings", err)
	}
	actions := make([]string, 0, len(decoded))
	seen := map[string]bool{}
	for _, action := range decoded {
		action = strings.TrimSpace(action)
		if action == "" {
			return nil, apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "allowed_actions_json cannot include empty actions")
		}
		if !seen[action] {
			seen[action] = true
			actions = append(actions, action)
		}
	}
	if len(actions) == 0 {
		return nil, apperrors.New(apperrors.CodeControlInvalidArgument, "service_catalog", "allowed_actions_json must include at least one action")
	}
	return actions, nil
}

func containsPrivateMaterial(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if privateKey(key) || containsPrivateMaterial(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsPrivateMaterial(child) {
				return true
			}
		}
	case string:
		return privateString(typed)
	}
	return false
}

func privateKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""), ".", ""))
	switch normalized {
	case "meship", "privateip", "wireguardendpoint", "endpoint", "peerbundle", "libp2pmultiaddr", "multiaddr",
		"hostname", "internalhostname", "privatehostname", "repopath", "token", "secret", "credential", "password",
		"apikey", "accesskey", "servicetoken", "bearer":
		return true
	default:
		return false
	}
}

func privateString(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if secretLikeValue(value) {
		return true
	}
	if strings.Contains(value, "/.git") || strings.HasPrefix(value, "/Users/") || strings.HasPrefix(value, "/var/") {
		return true
	}
	host := candidateHost(value)
	if host == "" {
		return false
	}
	normalizedHost := strings.ToLower(strings.Trim(host, "[]"))
	if strings.EqualFold(normalizedHost, "localhost") ||
		strings.HasSuffix(normalizedHost, ".local") ||
		strings.HasSuffix(normalizedHost, ".internal") ||
		strings.HasSuffix(normalizedHost, ".lan") ||
		strings.HasSuffix(normalizedHost, ".corp") {
		return true
	}
	ip := net.ParseIP(normalizedHost)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func secretLikeValue(value string) bool {
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "bearer "),
		strings.HasPrefix(lower, "basic "),
		strings.HasPrefix(lower, "token:"),
		strings.HasPrefix(lower, "secret:"),
		strings.HasPrefix(value, "sk-"),
		strings.HasPrefix(value, "xoxb-"),
		strings.HasPrefix(value, "xoxp-"),
		strings.HasPrefix(value, "ghp_"),
		strings.HasPrefix(value, "github_pat_"),
		strings.HasPrefix(value, "AKIA"),
		strings.Contains(value, "-----BEGIN "):
		return true
	default:
		return false
	}
}

func candidateHost(value string) string {
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		if host, _, err := net.SplitHostPort(parsed.Host); err == nil {
			return host
		}
		return parsed.Hostname()
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end > 1 {
			return value[1:end]
		}
	}
	host := value
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if hostPort, _, err := net.SplitHostPort(host); err == nil {
		return hostPort
	}
	if colon := strings.LastIndexByte(host, ':'); colon > 0 && strings.Count(host, ":") == 1 {
		host = host[:colon]
	}
	return host
}
