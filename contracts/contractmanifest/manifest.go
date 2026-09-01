package contractmanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/exchange"
)

const (
	SchemaVersion             = "builders.federation.service_contract_manifest.v1"
	SignatureAlgorithmEd25519 = "ed25519"
)

var (
	ErrUnsignedManifest         = errors.New("service contract manifest is unsigned")
	ErrManifestExpired          = errors.New("service contract manifest is expired")
	ErrManifestHashMismatch     = errors.New("service contract manifest hash mismatch")
	ErrManifestSignatureInvalid = errors.New("service contract manifest signature invalid")
	ErrManifestInvalid          = errors.New("service contract manifest is invalid")
	ErrManifestNotFound         = exchange.ErrManifestNotFound
)

type Keyring map[string]ed25519.PublicKey

type Manifest struct {
	SchemaVersion      string     `json:"schema_version"`
	TenantID           string     `json:"tenant_id"`
	ManifestID         string     `json:"manifest_id"`
	IssuedAtMS         int64      `json:"issued_at_ms"`
	ExpiresAtMS        int64      `json:"expires_at_ms"`
	CatalogVersion     string     `json:"catalog_version"`
	SigningKeyID       string     `json:"signing_key_id"`
	Contracts          []Contract `json:"contracts"`
	ManifestHashSHA256 string     `json:"manifest_hash_sha256"`
	Signature          Signature  `json:"signature"`
}

type Signature struct {
	Algorithm    string `json:"algorithm"`
	SignatureB64 string `json:"signature_b64"`
}

type Contract struct {
	ContractID                 string   `json:"contract_id"`
	ContractVersion            string   `json:"contract_version"`
	DisplayName                string   `json:"display_name,omitempty"`
	Action                     string   `json:"action"`
	ServiceCatalogAction       string   `json:"service_catalog_action,omitempty"`
	PayloadSchemaRef           string   `json:"payload_schema_ref"`
	PayloadSchemaHashSHA256    string   `json:"payload_schema_hash_sha256"`
	MaxPayloadBytes            int      `json:"max_payload_bytes"`
	RequiresIdempotency        bool     `json:"requires_idempotency"`
	ReplayWindowSeconds        int      `json:"replay_window_seconds"`
	AllowedPartnerLinkIDs      []string `json:"allowed_partner_link_ids"`
	AllowedGatewayMethodScopes []string `json:"allowed_gateway_method_scopes"`
	PrivateTopologyAllowed     bool     `json:"private_topology_allowed"`
	EgressPolicyRef            string   `json:"egress_policy_ref"`
	AuditClass                 string   `json:"audit_class"`
	RetentionClass             string   `json:"retention_class"`
	ResultContractIDs          []string `json:"result_contract_ids,omitempty"`
}

func Sign(manifest Manifest, privateKey ed25519.PrivateKey) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, fmt.Errorf("%w: ed25519 private key is required", ErrManifestSignatureInvalid)
	}
	manifest = normalizeManifest(manifest)
	if err := validateManifestShape(manifest); err != nil {
		return Manifest{}, err
	}
	manifest.ManifestHashSHA256 = ComputeManifestHash(manifest)
	signature := ed25519.Sign(privateKey, []byte(manifest.ManifestHashSHA256))
	manifest.Signature = Signature{
		Algorithm:    SignatureAlgorithmEd25519,
		SignatureB64: base64.StdEncoding.EncodeToString(signature),
	}
	return manifest, nil
}

func Verify(manifest Manifest, keyring Keyring, nowMS int64) error {
	manifest = normalizeManifest(manifest)
	if err := validateManifestShape(manifest); err != nil {
		return err
	}
	if manifest.ExpiresAtMS <= effectiveNowMS(nowMS) {
		return ErrManifestExpired
	}
	if strings.TrimSpace(manifest.ManifestHashSHA256) == "" ||
		strings.TrimSpace(manifest.Signature.Algorithm) == "" ||
		strings.TrimSpace(manifest.Signature.SignatureB64) == "" {
		return ErrUnsignedManifest
	}
	if manifest.Signature.Algorithm != SignatureAlgorithmEd25519 {
		return ErrManifestSignatureInvalid
	}
	computed := ComputeManifestHash(manifest)
	if !strings.EqualFold(computed, manifest.ManifestHashSHA256) {
		return ErrManifestHashMismatch
	}
	publicKey, ok := keyring[manifest.SigningKeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return ErrManifestSignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrManifestSignatureInvalid
	}
	if !ed25519.Verify(publicKey, []byte(manifest.ManifestHashSHA256), signature) {
		return ErrManifestSignatureInvalid
	}
	return nil
}

func ComputeManifestHash(manifest Manifest) string {
	manifest = normalizeManifest(manifest)
	manifest.ManifestHashSHA256 = ""
	manifest.Signature = Signature{}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		panic(fmt.Sprintf("canonical service contract manifest: %v", err))
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

type MemoryCache struct {
	mu        sync.RWMutex
	keyring   Keyring
	nowMS     func() int64
	manifests map[string]Manifest
}

func NewMemoryCache(keyring Keyring, nowMS func() int64) *MemoryCache {
	return &MemoryCache{
		keyring:   cloneKeyring(keyring),
		nowMS:     nowMS,
		manifests: map[string]Manifest{},
	}
}

func (c *MemoryCache) PutVerified(_ context.Context, manifest Manifest) error {
	if c == nil {
		return ErrManifestInvalid
	}
	manifest = normalizeManifest(manifest)
	if err := Verify(manifest, c.keyring, c.now()); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.manifests == nil {
		c.manifests = map[string]Manifest{}
	}
	c.manifests[manifest.ManifestHashSHA256] = manifest
	return nil
}

func (c *MemoryCache) ResolveManifest(_ context.Context, ref exchange.ContractRef) (exchange.Manifest, error) {
	if c == nil {
		return exchange.Manifest{}, ErrManifestNotFound
	}
	ref = normalizeContractRef(ref)
	c.mu.RLock()
	manifest, ok := c.manifests[ref.ManifestHashSHA256]
	c.mu.RUnlock()
	if !ok {
		return exchange.Manifest{}, ErrManifestNotFound
	}
	if err := Verify(manifest, c.keyring, c.now()); err != nil {
		return exchange.Manifest{}, err
	}
	contract, ok := findContract(manifest, ref)
	if !ok {
		return exchange.Manifest{}, ErrManifestNotFound
	}
	if contract.PayloadSchemaHashSHA256 != ref.PayloadSchemaHashSHA256 {
		return exchange.Manifest{}, ErrManifestHashMismatch
	}
	action, err := toExchangeAction(contract)
	if err != nil {
		return exchange.Manifest{}, err
	}
	return exchange.Manifest{
		TenantID:                manifest.TenantID,
		ManifestID:              manifest.ManifestID,
		CatalogVersion:          manifest.CatalogVersion,
		ContractID:              contract.ContractID,
		ContractVersion:         contract.ContractVersion,
		ManifestHashSHA256:      manifest.ManifestHashSHA256,
		PayloadSchemaHashSHA256: contract.PayloadSchemaHashSHA256,
		ExpiresAtMS:             manifest.ExpiresAtMS,
		Actions: map[string]exchange.ActionContract{
			contract.Action: action,
		},
	}, nil
}

func toExchangeAction(contract Contract) (exchange.ActionContract, error) {
	facadeMethod, mutating, err := facadeForAction(contract.Action)
	if err != nil {
		return exchange.ActionContract{}, err
	}
	return exchange.ActionContract{
		Action:                 contract.Action,
		ServiceCatalogAction:   contract.ServiceCatalogAction,
		FacadeMethod:           facadeMethod,
		Mutating:               mutating,
		IdempotencyRequired:    contract.RequiresIdempotency,
		PayloadEncoding:        exchange.PayloadEncodingJSON,
		MaxPayloadBytes:        contract.MaxPayloadBytes,
		PrivateTopologyAllowed: contract.PrivateTopologyAllowed,
		AllowedPartnerLinkIDs:  append([]string(nil), contract.AllowedPartnerLinkIDs...),
	}, nil
}

func facadeForAction(action string) (string, bool, error) {
	switch strings.TrimSpace(action) {
	case exchange.ActionGetServiceCatalogView:
		return exchange.FacadeGetServiceCatalogView, false, nil
	case exchange.ActionOpenFederationTransaction:
		return exchange.FacadeOpenFederationTransaction, true, nil
	case exchange.ActionCreateFederationRoom:
		return exchange.FacadeCreateFederationRoom, true, nil
	case exchange.ActionSubmitFederationMessage:
		return exchange.FacadeSubmitFederationMessage, true, nil
	case exchange.ActionRequestBuilderWork:
		return exchange.FacadeRequestBuilderWork, true, nil
	case exchange.ActionSubmitFederationResult:
		return exchange.FacadeSubmitFederationResult, true, nil
	case exchange.ActionDeliverBuilderWorkResult:
		return exchange.FacadeDeliverBuilderWorkResult, true, nil
	case exchange.ActionRequestForQuote,
		exchange.ActionSubmitQuote,
		exchange.ActionSubmitPurchaseOrder,
		exchange.ActionConfirmOrder,
		exchange.ActionUpdateShipmentStatus,
		exchange.ActionIssueInvoice,
		exchange.ActionUpdatePaymentStatus:
		// NE-4.1: every O2C business interaction is mutating and routes
		// through the typed commercial-event facade.
		return exchange.FacadeSubmitCommercialEvent, true, nil
	default:
		return "", false, fmt.Errorf("%w: unsupported action %q", ErrManifestInvalid, action)
	}
}

func findContract(manifest Manifest, ref exchange.ContractRef) (Contract, bool) {
	for _, contract := range manifest.Contracts {
		if contract.ContractID == ref.ContractID && contract.ContractVersion == ref.ContractVersion {
			return contract, true
		}
	}
	return Contract{}, false
}

func validateManifestShape(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion ||
		manifest.TenantID == "" ||
		manifest.ManifestID == "" ||
		manifest.CatalogVersion == "" ||
		manifest.SigningKeyID == "" ||
		manifest.IssuedAtMS <= 0 ||
		manifest.ExpiresAtMS <= manifest.IssuedAtMS ||
		len(manifest.Contracts) == 0 {
		return ErrManifestInvalid
	}
	seen := map[string]struct{}{}
	for _, contract := range manifest.Contracts {
		if err := validateContract(contract); err != nil {
			return err
		}
		key := contract.ContractID + "\x00" + contract.ContractVersion + "\x00" + contract.Action
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate contract action %q", ErrManifestInvalid, contract.ContractID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateContract(contract Contract) error {
	if contract.ContractID == "" ||
		contract.ContractVersion == "" ||
		contract.Action == "" ||
		contract.PayloadSchemaRef == "" ||
		contract.PayloadSchemaHashSHA256 == "" ||
		contract.MaxPayloadBytes <= 0 ||
		contract.ReplayWindowSeconds <= 0 ||
		len(contract.AllowedPartnerLinkIDs) == 0 ||
		len(contract.AllowedGatewayMethodScopes) == 0 ||
		contract.EgressPolicyRef == "" ||
		contract.AuditClass == "" ||
		contract.RetentionClass == "" {
		return ErrManifestInvalid
	}
	if _, _, err := facadeForAction(contract.Action); err != nil {
		return err
	}
	expectedScope := expectedMethodScope(contract.Action)
	if len(contract.AllowedGatewayMethodScopes) != 1 || contract.AllowedGatewayMethodScopes[0] != expectedScope {
		return fmt.Errorf("%w: action %q must declare only gateway method scope %q", ErrManifestInvalid, contract.Action, expectedScope)
	}
	return nil
}

func expectedMethodScope(action string) string {
	switch strings.TrimSpace(action) {
	case exchange.ActionGetServiceCatalogView:
		return "federation.get_service_catalog_view"
	case exchange.ActionOpenFederationTransaction:
		return "federation.open_federation_transaction"
	case exchange.ActionCreateFederationRoom:
		return "federation.create_federation_room"
	case exchange.ActionSubmitFederationMessage:
		return "federation.submit_federation_message"
	case exchange.ActionRequestBuilderWork:
		return "federation.request_builder_work"
	case exchange.ActionSubmitFederationResult:
		return "federation.submit_federation_result"
	case exchange.ActionDeliverBuilderWorkResult:
		return "federation.deliver_builder_work_result"
	// O2C typed commercial events (NE-4.1). Without these a manifest
	// carrying any O2C contract can never validate (scope must be the
	// single expected entry, and an empty list fails the shape check) —
	// found live wiring the first PO demo (NE-4.4).
	case exchange.ActionRequestForQuote,
		exchange.ActionSubmitQuote,
		exchange.ActionSubmitPurchaseOrder,
		exchange.ActionConfirmOrder,
		exchange.ActionUpdateShipmentStatus,
		exchange.ActionIssueInvoice,
		exchange.ActionUpdatePaymentStatus:
		return "federation." + strings.TrimSpace(action)
	default:
		return ""
	}
}

func normalizeManifest(manifest Manifest) Manifest {
	manifest.SchemaVersion = strings.TrimSpace(manifest.SchemaVersion)
	manifest.TenantID = strings.TrimSpace(manifest.TenantID)
	manifest.ManifestID = strings.TrimSpace(manifest.ManifestID)
	manifest.CatalogVersion = strings.TrimSpace(manifest.CatalogVersion)
	manifest.SigningKeyID = strings.TrimSpace(manifest.SigningKeyID)
	manifest.ManifestHashSHA256 = strings.TrimSpace(manifest.ManifestHashSHA256)
	manifest.Signature.Algorithm = strings.TrimSpace(manifest.Signature.Algorithm)
	manifest.Signature.SignatureB64 = strings.TrimSpace(manifest.Signature.SignatureB64)
	// Copy Contracts onto a fresh backing array before mutating/sorting. The
	// manifest is passed by value, but the struct copy shares the Contracts
	// backing array with the caller (and, for a cached manifest, with the array
	// stored in MemoryCache). Normalizing/sorting in place would mutate that
	// shared array, so concurrent ResolveManifest calls (goroutine-per-connection
	// in the inbound receiver) would race on it. Operating on a private copy keeps
	// normalizeManifest a pure function of its input.
	manifest.Contracts = append([]Contract(nil), manifest.Contracts...)
	for i := range manifest.Contracts {
		manifest.Contracts[i] = normalizeContract(manifest.Contracts[i])
	}
	sort.SliceStable(manifest.Contracts, func(i, j int) bool {
		left := manifest.Contracts[i].ContractID + "\x00" + manifest.Contracts[i].ContractVersion + "\x00" + manifest.Contracts[i].Action
		right := manifest.Contracts[j].ContractID + "\x00" + manifest.Contracts[j].ContractVersion + "\x00" + manifest.Contracts[j].Action
		return left < right
	})
	return manifest
}

func normalizeContract(contract Contract) Contract {
	contract.ContractID = strings.TrimSpace(contract.ContractID)
	contract.ContractVersion = strings.TrimSpace(contract.ContractVersion)
	contract.DisplayName = strings.TrimSpace(contract.DisplayName)
	contract.Action = strings.TrimSpace(contract.Action)
	contract.ServiceCatalogAction = strings.TrimSpace(contract.ServiceCatalogAction)
	contract.PayloadSchemaRef = strings.TrimSpace(contract.PayloadSchemaRef)
	contract.PayloadSchemaHashSHA256 = strings.TrimSpace(contract.PayloadSchemaHashSHA256)
	contract.EgressPolicyRef = strings.TrimSpace(contract.EgressPolicyRef)
	contract.AuditClass = strings.TrimSpace(contract.AuditClass)
	contract.RetentionClass = strings.TrimSpace(contract.RetentionClass)
	contract.AllowedPartnerLinkIDs = normalizeStringSlice(contract.AllowedPartnerLinkIDs)
	contract.AllowedGatewayMethodScopes = normalizeStringSlice(contract.AllowedGatewayMethodScopes)
	contract.ResultContractIDs = normalizeStringSlice(contract.ResultContractIDs)
	return contract
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
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

func normalizeContractRef(ref exchange.ContractRef) exchange.ContractRef {
	ref.ContractID = strings.TrimSpace(ref.ContractID)
	ref.ContractVersion = strings.TrimSpace(ref.ContractVersion)
	ref.ManifestHashSHA256 = strings.TrimSpace(ref.ManifestHashSHA256)
	ref.PayloadSchemaHashSHA256 = strings.TrimSpace(ref.PayloadSchemaHashSHA256)
	return ref
}

func cloneKeyring(keyring Keyring) Keyring {
	if len(keyring) == 0 {
		return Keyring{}
	}
	out := Keyring{}
	for keyID, publicKey := range keyring {
		out[strings.TrimSpace(keyID)] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return out
}

func (c *MemoryCache) now() int64 {
	if c != nil && c.nowMS != nil {
		return c.nowMS()
	}
	return time.Now().UnixMilli()
}

func effectiveNowMS(nowMS int64) int64 {
	if nowMS > 0 {
		return nowMS
	}
	return time.Now().UnixMilli()
}
