package ordertocash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/b2bautopilot/xyz-b2b/packages/app-errors"
	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/contractmanifest"
	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/exchange"
	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/servicecatalog"
	"github.com/google/uuid"
)

const (
	CatalogVersion       = "order_to_cash.v1"
	ContractVersion      = "1.0.0"
	SchemaVersion        = "order_to_cash.schema.v1"
	DefaultMaxPayload    = 32768
	DefaultReplaySeconds = 86400
)

type Interaction struct {
	ContractID      string
	DisplayName     string
	ServiceKind     string
	BusinessAction  string
	TransactionKind string
	SchemaRef       string
	SchemaJSON      string
	ResultContracts []string
}

type ManifestInput struct {
	TenantID           string
	ManifestID         string
	IssuedAtMS         int64
	ExpiresAtMS        int64
	SigningKeyID       string
	PartnerLinkIDs     []string
	MaxPayloadBytes    int
	ReplayWindowSecs   int
	EgressPolicyPrefix string
}

type CatalogOptions struct {
	StateByContractID       map[string]string
	ReplacementByContractID map[string]string
}

type PayloadValidator struct{}

func Interactions() []Interaction {
	out := make([]Interaction, len(interactions))
	copy(out, interactions)
	for i := range out {
		out[i].ResultContracts = append([]string(nil), interactions[i].ResultContracts...)
	}
	return out
}

func Manifest(input ManifestInput) contractmanifest.Manifest {
	return contractmanifest.Manifest{
		SchemaVersion:  contractmanifest.SchemaVersion,
		TenantID:       strings.TrimSpace(input.TenantID),
		ManifestID:     strings.TrimSpace(input.ManifestID),
		IssuedAtMS:     input.IssuedAtMS,
		ExpiresAtMS:    input.ExpiresAtMS,
		CatalogVersion: CatalogVersion,
		SigningKeyID:   strings.TrimSpace(input.SigningKeyID),
		Contracts:      Contracts(input),
	}
}

func Contracts(input ManifestInput) []contractmanifest.Contract {
	partnerLinkIDs := normalizeStrings(input.PartnerLinkIDs)
	maxPayload := input.MaxPayloadBytes
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayload
	}
	replayWindow := input.ReplayWindowSecs
	if replayWindow <= 0 {
		replayWindow = DefaultReplaySeconds
	}
	egressPrefix := strings.TrimSpace(input.EgressPolicyPrefix)
	if egressPrefix == "" {
		egressPrefix = "egress.order_to_cash"
	}
	out := make([]contractmanifest.Contract, 0, len(interactions))
	for _, interaction := range interactions {
		out = append(out, contractmanifest.Contract{
			ContractID:                 interaction.ContractID,
			ContractVersion:            ContractVersion,
			DisplayName:                interaction.DisplayName,
			Action:                     exchange.ActionOpenFederationTransaction,
			ServiceCatalogAction:       interaction.BusinessAction,
			PayloadSchemaRef:           interaction.SchemaRef,
			PayloadSchemaHashSHA256:    PayloadSchemaHash(interaction.ContractID),
			MaxPayloadBytes:            maxPayload,
			RequiresIdempotency:        true,
			ReplayWindowSeconds:        replayWindow,
			AllowedPartnerLinkIDs:      partnerLinkIDs,
			AllowedGatewayMethodScopes: []string{"federation.open_federation_transaction"},
			PrivateTopologyAllowed:     false,
			EgressPolicyRef:            egressPrefix + "." + interaction.BusinessAction,
			AuditClass:                 "commercial_transaction",
			RetentionClass:             "order_to_cash",
			ResultContractIDs:          append([]string(nil), interaction.ResultContracts...),
		})
	}
	return out
}

func ServiceCatalogEntries(tenantID string, options CatalogOptions) []servicecatalog.EntryInput {
	out := make([]servicecatalog.EntryInput, 0, len(interactions))
	for _, interaction := range interactions {
		state := servicecatalog.StateActive
		if options.StateByContractID != nil && strings.TrimSpace(options.StateByContractID[interaction.ContractID]) != "" {
			state = strings.TrimSpace(options.StateByContractID[interaction.ContractID])
		}
		replacement := ""
		if options.ReplacementByContractID != nil {
			replacement = strings.TrimSpace(options.ReplacementByContractID[interaction.ContractID])
			if replacementInteraction, ok := interactionByContractID(replacement); ok {
				replacement = ServiceCatalogID(replacementInteraction.ContractID)
			}
		}
		out = append(out, servicecatalog.EntryInput{
			TenantID:                  strings.TrimSpace(tenantID),
			ServiceCatalogID:          ServiceCatalogID(interaction.ContractID),
			DisplayName:               interaction.DisplayName,
			ServiceKind:               interaction.ServiceKind,
			SchemaJSON:                interaction.SchemaJSON,
			SchemaVersion:             SchemaVersion,
			AllowedActionsJSON:        allowedActionJSON(interaction.BusinessAction),
			State:                     state,
			ReplacementCatalogEntryID: replacement,
		})
	}
	return out
}

func ServiceCatalogID(contractID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("x-builders-net:order-to-cash:"+strings.TrimSpace(contractID))).String()
}

func PayloadSchema(contractID string) (string, bool) {
	interaction, ok := interactionByContractID(contractID)
	if !ok {
		return "", false
	}
	return interaction.SchemaJSON, true
}

func PayloadSchemaHash(contractID string) string {
	schema, ok := PayloadSchema(contractID)
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(schema))
	return hex.EncodeToString(sum[:])
}

func (PayloadValidator) ValidateGatewayExchangePayload(_ context.Context, input exchange.PayloadValidationInput) error {
	interaction, ok := interactionByContractID(input.Contract.ContractID)
	if !ok {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "contract_id is not in the order-to-cash pack")
	}
	if input.Contract.ContractVersion != ContractVersion {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "contract_version is not supported")
	}
	if input.Contract.PayloadSchemaHashSHA256 != PayloadSchemaHash(interaction.ContractID) {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload schema hash does not match the compiled contract")
	}
	if input.Action.Action != exchange.ActionOpenFederationTransaction ||
		input.Action.FacadeMethod != exchange.FacadeOpenFederationTransaction ||
		!input.Action.IdempotencyRequired ||
		input.Action.PrivateTopologyAllowed {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "contract action is not the narrowed order-to-cash transaction facade")
	}
	return ValidatePayload(interaction.ContractID, input.Payload)
}

func ValidatePayload(contractID string, payload []byte) error {
	schemaJSON, ok := PayloadSchema(contractID)
	if !ok {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "contract_id is not in the order-to-cash pack")
	}
	var payloadObject map[string]any
	if err := json.Unmarshal(payload, &payloadObject); err != nil {
		return apperrors.Wrap(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload must be a JSON object", err)
	}
	interaction, _ := interactionByContractID(contractID)
	if got := strings.TrimSpace(stringValue(payloadObject["transaction_kind"])); got != interaction.TransactionKind {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload transaction_kind does not match the contract")
	}
	if strings.TrimSpace(stringValue(payloadObject["subject"])) == "" {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload subject is required")
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		return apperrors.Wrap(apperrors.CodeStorageUnavailable, "order_to_cash_contract", "compiled schema is invalid", err)
	}
	if containsPrivateTopology(payloadObject) {
		return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload contains private topology")
	}
	required, _ := schema["required"].([]any)
	for _, item := range required {
		key, ok := item.(string)
		if !ok || strings.TrimSpace(key) == "" {
			return apperrors.New(apperrors.CodeStorageUnavailable, "order_to_cash_contract", "compiled schema required list is invalid")
		}
		if _, ok := payloadObject[key]; !ok {
			return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload missing required property "+key)
		}
	}
	properties, _ := schema["properties"].(map[string]any)
	for key, value := range payloadObject {
		property, ok := properties[key].(map[string]any)
		if !ok {
			if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
				return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", "payload contains unsupported property "+key)
			}
			continue
		}
		want, _ := property["type"].(string)
		if want != "" && !jsonValueMatchesType(value, want) {
			return apperrors.New(apperrors.CodeControlInvalidArgument, "order_to_cash_contract", fmt.Sprintf("payload property %s must be %s", key, want))
		}
	}
	return nil
}

func interactionByContractID(contractID string) (Interaction, bool) {
	contractID = strings.TrimSpace(contractID)
	for _, interaction := range interactions {
		if interaction.ContractID == contractID {
			return interaction, true
		}
	}
	return Interaction{}, false
}

func allowedActionJSON(action string) string {
	encoded, err := json.Marshal([]string{action})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func normalizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func jsonValueMatchesType(value any, want string) bool {
	switch want {
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		_, ok := value.(float64)
		return ok
	case "integer":
		n, ok := value.(float64)
		return ok && math.Trunc(n) == n
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	default:
		return false
	}
}

func containsPrivateTopology(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if privateTopologyKey(key) || containsPrivateTopology(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsPrivateTopology(child) {
				return true
			}
		}
	case string:
		return privateTopologyString(typed)
	}
	return false
}

func privateTopologyKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(key), "_", ""), "-", ""), ".", ""))
	switch normalized {
	case "meship", "privateip", "internalip", "lanip", "hostip", "wireguardendpoint", "endpoint", "peerbundle",
		"hostname", "internalhostname", "privatehostname", "libp2pmultiaddr", "multiaddr", "repopath":
		return true
	default:
		return false
	}
}

func privateTopologyString(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if host := candidateHost(value); host != "" {
		if privateHost(host) {
			return true
		}
	}
	for _, candidate := range ipv4Pattern.FindAllString(value, -1) {
		if privateHost(candidate) {
			return true
		}
	}
	normalized := strings.ToLower(value)
	privateMarkers := []string{
		"fd00:", "fc00:", "fe80:", "::1", "localhost", ".local", ".internal", ".lan", ".corp",
		"10.0.", "10.1.", "10.2.", "10.3.", "10.4.", "10.5.", "10.6.", "10.7.", "10.8.", "10.9.",
		"192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
	}
	for _, marker := range privateMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
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
	return strings.Trim(host, "[]")
}

func privateHost(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".lan") ||
		strings.HasSuffix(host, ".corp") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

var ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

var interactions = []Interaction{
	{
		ContractID:      "order_to_cash.request_for_quote.request.v1",
		DisplayName:     "Request for quote",
		ServiceKind:     "order_to_cash.request_for_quote",
		BusinessAction:  "request_for_quote",
		TransactionKind: "order_to_cash.request_for_quote",
		SchemaRef:       "schemas/order_to_cash/request_for_quote.request.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","buyer_ref","seller_ref","requested_at","line_items"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"buyer_ref":{"type":"string"},"seller_ref":{"type":"string"},"requested_at":{"type":"string"},"due_at":{"type":"string"},"currency":{"type":"string"},"line_items":{"type":"array"},"notes":{"type":"string"}},"additionalProperties":false}`,
		ResultContracts: []string{"order_to_cash.quote.response.v1"},
	},
	{
		ContractID:      "order_to_cash.quote.response.v1",
		DisplayName:     "Quote response",
		ServiceKind:     "order_to_cash.quote",
		BusinessAction:  "submit_quote",
		TransactionKind: "order_to_cash.quote",
		SchemaRef:       "schemas/order_to_cash/quote.response.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","rfq_document_id","seller_ref","buyer_ref","quoted_at","currency","total_amount","line_items"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"rfq_document_id":{"type":"string"},"seller_ref":{"type":"string"},"buyer_ref":{"type":"string"},"quoted_at":{"type":"string"},"valid_until":{"type":"string"},"currency":{"type":"string"},"total_amount":{"type":"number"},"line_items":{"type":"array"},"terms_ref":{"type":"string"}},"additionalProperties":false}`,
		ResultContracts: []string{"order_to_cash.purchase_order.request.v1"},
	},
	{
		ContractID:      "order_to_cash.purchase_order.request.v1",
		DisplayName:     "Purchase order request",
		ServiceKind:     "order_to_cash.purchase_order",
		BusinessAction:  "submit_purchase_order",
		TransactionKind: "order_to_cash.purchase_order",
		SchemaRef:       "schemas/order_to_cash/purchase_order.request.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","quote_document_id","buyer_ref","seller_ref","ordered_at","currency","total_amount","line_items"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"quote_document_id":{"type":"string"},"buyer_ref":{"type":"string"},"seller_ref":{"type":"string"},"ordered_at":{"type":"string"},"currency":{"type":"string"},"total_amount":{"type":"number"},"line_items":{"type":"array"},"delivery_window":{"type":"string"},"buyer_reference":{"type":"string"}},"additionalProperties":false}`,
		ResultContracts: []string{"order_to_cash.order_confirmation.response.v1"},
	},
	{
		ContractID:      "order_to_cash.order_confirmation.response.v1",
		DisplayName:     "Order confirmation",
		ServiceKind:     "order_to_cash.order_confirmation",
		BusinessAction:  "confirm_order",
		TransactionKind: "order_to_cash.order_confirmation",
		SchemaRef:       "schemas/order_to_cash/order_confirmation.response.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","purchase_order_document_id","seller_ref","buyer_ref","confirmed_at","status"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"purchase_order_document_id":{"type":"string"},"seller_ref":{"type":"string"},"buyer_ref":{"type":"string"},"confirmed_at":{"type":"string"},"status":{"type":"string"},"promised_ship_at":{"type":"string"},"exception_reason":{"type":"string"}},"additionalProperties":false}`,
		ResultContracts: []string{"order_to_cash.shipment_status.update.v1", "order_to_cash.invoice.issue.v1"},
	},
	{
		ContractID:      "order_to_cash.shipment_status.update.v1",
		DisplayName:     "Shipment status update",
		ServiceKind:     "order_to_cash.shipment_status",
		BusinessAction:  "update_shipment_status",
		TransactionKind: "order_to_cash.shipment_status",
		SchemaRef:       "schemas/order_to_cash/shipment_status.update.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","purchase_order_document_id","seller_ref","buyer_ref","status","updated_at"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"purchase_order_document_id":{"type":"string"},"seller_ref":{"type":"string"},"buyer_ref":{"type":"string"},"status":{"type":"string"},"updated_at":{"type":"string"},"carrier_ref":{"type":"string"},"tracking_ref":{"type":"string"},"estimated_delivery_at":{"type":"string"}},"additionalProperties":false}`,
		ResultContracts: []string{"order_to_cash.invoice.issue.v1"},
	},
	{
		ContractID:      "order_to_cash.invoice.issue.v1",
		DisplayName:     "Invoice issue",
		ServiceKind:     "order_to_cash.invoice",
		BusinessAction:  "issue_invoice",
		TransactionKind: "order_to_cash.invoice",
		SchemaRef:       "schemas/order_to_cash/invoice.issue.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","purchase_order_document_id","seller_ref","buyer_ref","issued_at","currency","invoice_amount","due_at"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"purchase_order_document_id":{"type":"string"},"seller_ref":{"type":"string"},"buyer_ref":{"type":"string"},"issued_at":{"type":"string"},"currency":{"type":"string"},"invoice_amount":{"type":"number"},"due_at":{"type":"string"},"remittance_ref":{"type":"string"}},"additionalProperties":false}`,
		ResultContracts: []string{"order_to_cash.payment_status.update.v1"},
	},
	{
		ContractID:      "order_to_cash.payment_status.update.v1",
		DisplayName:     "Payment status update",
		ServiceKind:     "order_to_cash.payment_status",
		BusinessAction:  "update_payment_status",
		TransactionKind: "order_to_cash.payment_status",
		SchemaRef:       "schemas/order_to_cash/payment_status.update.v1.json",
		SchemaJSON:      `{"type":"object","required":["transaction_kind","subject","document_id","invoice_document_id","buyer_ref","seller_ref","status","updated_at"],"properties":{"transaction_kind":{"type":"string"},"subject":{"type":"string"},"document_id":{"type":"string"},"invoice_document_id":{"type":"string"},"buyer_ref":{"type":"string"},"seller_ref":{"type":"string"},"status":{"type":"string"},"updated_at":{"type":"string"},"payment_ref":{"type":"string"},"paid_amount":{"type":"number"},"currency":{"type":"string"}},"additionalProperties":false}`,
	},
}
