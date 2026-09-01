package contractapproval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/b2bautopilot/xx-federation-contracts/apperrors"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/contractmanifest"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/exchange"
)

const (
	StatePendingApproval = "pending_approval"
	StateApproved        = "approved"
	StateRevoked         = "revoked"
)

type ContractPin struct {
	ContractID              string `json:"contract_id"`
	ContractVersion         string `json:"contract_version"`
	PayloadSchemaHashSHA256 string `json:"payload_schema_hash_sha256"`
	ServiceCatalogID        string `json:"service_catalog_id"`
	Action                  string `json:"action"`
	ServiceCatalogAction    string `json:"service_catalog_action,omitempty"`
}

type ApprovalRecord struct {
	TenantID               string        `json:"tenant_id"`
	CatalogVersion         string        `json:"catalog_version"`
	PackVersion            string        `json:"pack_version"`
	ManifestID             string        `json:"manifest_id"`
	ManifestHashSHA256     string        `json:"manifest_hash_sha256"`
	State                  string        `json:"state"`
	AllowedPartnerLinkIDs  []string      `json:"allowed_partner_link_ids"`
	Contracts              []ContractPin `json:"contracts"`
	ApprovedBy             string        `json:"approved_by"`
	ApprovedAtMS           int64         `json:"approved_at_ms"`
	CreatedBy              string        `json:"created_by"`
	CreatedAtMS            int64         `json:"created_at_ms"`
	AuditBindingHashSHA256 string        `json:"audit_binding_hash_sha256"`
}

type PartnerPin struct {
	TenantID                   string `json:"tenant_id"`
	PartnerLinkID              string `json:"partner_link_id"`
	CatalogVersion             string `json:"catalog_version"`
	PackVersion                string `json:"pack_version"`
	ManifestHashSHA256         string `json:"manifest_hash_sha256"`
	PreviousPackVersion        string `json:"previous_pack_version,omitempty"`
	PreviousManifestHashSHA256 string `json:"previous_manifest_hash_sha256,omitempty"`
	PinnedBy                   string `json:"pinned_by"`
	PinnedAtMS                 int64  `json:"pinned_at_ms"`
	Reason                     string `json:"reason,omitempty"`
	AuditBindingHashSHA256     string `json:"audit_binding_hash_sha256"`
}

type ApprovalInput struct {
	Manifest                         contractmanifest.Manifest
	PackVersion                      string
	State                            string
	AllowedPartnerLinkIDs            []string
	ServiceCatalogIDByContractID     map[string]string
	ServiceCatalogActionByContractID map[string]string
	ApprovedBy                       string
	ApprovedAtMS                     int64
	CreatedBy                        string
	CreatedAtMS                      int64
}

type PinInput struct {
	TenantID           string
	PartnerLinkID      string
	CatalogVersion     string
	PackVersion        string
	ManifestHashSHA256 string
	PinnedBy           string
	PinnedAtMS         int64
	Reason             string
}

type Registry struct {
	mu      sync.RWMutex
	records map[string]ApprovalRecord
	pins    map[string]PartnerPin
}

func NewRegistry() *Registry {
	return &Registry{
		records: map[string]ApprovalRecord{},
		pins:    map[string]PartnerPin{},
	}
}

func NewApprovalRecord(input ApprovalInput) (ApprovalRecord, error) {
	manifest := input.Manifest
	state := strings.TrimSpace(input.State)
	if state == "" {
		state = StatePendingApproval
	}
	record := ApprovalRecord{
		TenantID:              strings.TrimSpace(manifest.TenantID),
		CatalogVersion:        strings.TrimSpace(manifest.CatalogVersion),
		PackVersion:           strings.TrimSpace(input.PackVersion),
		ManifestID:            strings.TrimSpace(manifest.ManifestID),
		ManifestHashSHA256:    strings.TrimSpace(manifest.ManifestHashSHA256),
		State:                 state,
		AllowedPartnerLinkIDs: normalizeStrings(input.AllowedPartnerLinkIDs),
		Contracts:             contractPinsFromManifest(manifest, input.ServiceCatalogIDByContractID, input.ServiceCatalogActionByContractID),
		ApprovedBy:            strings.TrimSpace(input.ApprovedBy),
		ApprovedAtMS:          input.ApprovedAtMS,
		CreatedBy:             strings.TrimSpace(input.CreatedBy),
		CreatedAtMS:           input.CreatedAtMS,
	}
	record.AuditBindingHashSHA256 = ApprovalAuditHash(record)
	if err := ValidateApprovalRecord(record); err != nil {
		return ApprovalRecord{}, err
	}
	return record, nil
}

func (r *Registry) PutApproval(record ApprovalRecord) error {
	record = normalizeApprovalRecord(record)
	if err := ValidateApprovalRecord(record); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.records == nil {
		r.records = map[string]ApprovalRecord{}
	}
	r.records[record.ManifestHashSHA256] = record
	return nil
}

func (r *Registry) PutPin(pin PartnerPin) error {
	if r == nil {
		return approvalErr("contract approval registry is required")
	}
	pin = normalizePartnerPin(pin)
	if err := ValidatePartnerPin(pin); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pins == nil {
		r.pins = map[string]PartnerPin{}
	}
	r.pins[pinKey(pin.TenantID, pin.PartnerLinkID, pin.CatalogVersion)] = pin
	return nil
}

func (r *Registry) Pin(input PinInput) (PartnerPin, error) {
	if r == nil {
		return PartnerPin{}, approvalErr("contract approval registry is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.records == nil {
		r.records = map[string]ApprovalRecord{}
	}
	if r.pins == nil {
		r.pins = map[string]PartnerPin{}
	}
	input = normalizePinInput(input)
	record, ok := r.records[input.ManifestHashSHA256]
	if !ok || record.State != StateApproved {
		return PartnerPin{}, approvalErr("contract pack version is not approved")
	}
	if record.TenantID != input.TenantID || record.CatalogVersion != input.CatalogVersion || record.PackVersion != input.PackVersion {
		return PartnerPin{}, approvalErr("contract pack pin does not match the approved pack version")
	}
	if !containsString(record.AllowedPartnerLinkIDs, input.PartnerLinkID) {
		return PartnerPin{}, approvalErr("partner link is not approved for this contract pack")
	}
	if input.PinnedBy == "" || input.PinnedAtMS <= 0 {
		return PartnerPin{}, approvalErr("pin approver and timestamp are required")
	}
	key := pinKey(input.TenantID, input.PartnerLinkID, input.CatalogVersion)
	previous := r.pins[key]
	pin := PartnerPin{
		TenantID:                   input.TenantID,
		PartnerLinkID:              input.PartnerLinkID,
		CatalogVersion:             input.CatalogVersion,
		PackVersion:                input.PackVersion,
		ManifestHashSHA256:         input.ManifestHashSHA256,
		PreviousPackVersion:        previous.PackVersion,
		PreviousManifestHashSHA256: previous.ManifestHashSHA256,
		PinnedBy:                   input.PinnedBy,
		PinnedAtMS:                 input.PinnedAtMS,
		Reason:                     input.Reason,
	}
	pin.AuditBindingHashSHA256 = PinAuditHash(pin)
	if err := ValidatePartnerPin(pin); err != nil {
		return PartnerPin{}, err
	}
	r.pins[key] = pin
	return pin, nil
}

func (r *Registry) AuthorizeContractApproval(_ context.Context, input exchange.ContractApprovalCheck) error {
	if r == nil {
		return approvalErr("contract approval registry is required")
	}
	tenantID := strings.TrimSpace(input.Session.LocalTenantID)
	partnerLinkID := strings.TrimSpace(input.Envelope.PartnerLinkID)
	catalogVersion := strings.TrimSpace(input.Manifest.CatalogVersion)
	manifestHash := strings.TrimSpace(input.Manifest.ManifestHashSHA256)
	if tenantID == "" || partnerLinkID == "" || catalogVersion == "" || manifestHash == "" {
		return approvalErr("contract approval check is missing required identity")
	}
	r.mu.RLock()
	record, ok := r.records[manifestHash]
	pin := r.pins[pinKey(tenantID, partnerLinkID, catalogVersion)]
	r.mu.RUnlock()
	if !ok || record.State != StateApproved {
		return approvalErr("contract pack version is not approved")
	}
	if record.TenantID != tenantID || record.CatalogVersion != catalogVersion {
		return approvalErr("contract pack approval does not match the exchange tenant or catalog")
	}
	if !containsString(record.AllowedPartnerLinkIDs, partnerLinkID) {
		return approvalErr("partner link is not approved for this contract pack")
	}
	if pin.ManifestHashSHA256 != manifestHash || pin.PackVersion != record.PackVersion ||
		pin.PartnerLinkID != partnerLinkID || pin.CatalogVersion != catalogVersion {
		return approvalErr("contract pack version is not pinned for this partner link")
	}
	if !contractPinned(record.Contracts, input.Envelope.Contract, input.Envelope.Action) {
		return approvalErr("contract is not pinned in the approved pack version")
	}
	return nil
}

func ValidateApprovalRecord(record ApprovalRecord) error {
	record = normalizeApprovalRecord(record)
	if record.TenantID == "" || record.CatalogVersion == "" || record.PackVersion == "" || record.ManifestID == "" ||
		record.ManifestHashSHA256 == "" || record.CreatedBy == "" || record.CreatedAtMS <= 0 || len(record.Contracts) == 0 {
		return approvalErr("contract approval record is incomplete")
	}
	switch record.State {
	case StatePendingApproval:
	case StateApproved:
		if record.ApprovedBy == "" || record.ApprovedAtMS <= 0 {
			return approvalErr("approved contract packs require approver evidence")
		}
	case StateRevoked:
	default:
		return approvalErr("contract approval state is invalid")
	}
	if record.State == StateApproved && len(record.AllowedPartnerLinkIDs) == 0 {
		return approvalErr("approved contract packs require explicit partner-link allowlists")
	}
	for _, pin := range record.Contracts {
		if pin.ContractID == "" || pin.ContractVersion == "" || pin.PayloadSchemaHashSHA256 == "" || pin.Action == "" || pin.ServiceCatalogID == "" {
			return approvalErr("contract approval pin is incomplete")
		}
	}
	if record.AuditBindingHashSHA256 != "" && record.AuditBindingHashSHA256 != ApprovalAuditHash(record) {
		return approvalErr("contract approval audit binding hash does not match")
	}
	return nil
}

func ValidatePartnerPin(pin PartnerPin) error {
	pin = normalizePartnerPin(pin)
	if pin.TenantID == "" || pin.PartnerLinkID == "" || pin.CatalogVersion == "" ||
		pin.PackVersion == "" || pin.ManifestHashSHA256 == "" || pin.PinnedBy == "" ||
		pin.PinnedAtMS <= 0 {
		return approvalErr("contract pack pin is incomplete")
	}
	if pin.AuditBindingHashSHA256 != "" && pin.AuditBindingHashSHA256 != PinAuditHash(pin) {
		return approvalErr("contract pack pin audit binding hash does not match")
	}
	return nil
}

func ApprovalAuditHash(record ApprovalRecord) string {
	record = normalizeApprovalRecord(record)
	record.AuditBindingHashSHA256 = ""
	return hashCanonical(record)
}

func PinAuditHash(pin PartnerPin) string {
	pin = normalizePartnerPin(pin)
	pin.AuditBindingHashSHA256 = ""
	return hashCanonical(pin)
}

func contractPinsFromManifest(manifest contractmanifest.Manifest, serviceCatalogIDs, serviceCatalogActions map[string]string) []ContractPin {
	pins := make([]ContractPin, 0, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		pins = append(pins, ContractPin{
			ContractID:              strings.TrimSpace(contract.ContractID),
			ContractVersion:         strings.TrimSpace(contract.ContractVersion),
			PayloadSchemaHashSHA256: strings.TrimSpace(contract.PayloadSchemaHashSHA256),
			ServiceCatalogID:        strings.TrimSpace(serviceCatalogIDs[contract.ContractID]),
			Action:                  strings.TrimSpace(contract.Action),
			ServiceCatalogAction:    strings.TrimSpace(serviceCatalogActions[contract.ContractID]),
		})
	}
	sort.SliceStable(pins, func(i, j int) bool {
		left := pins[i].ContractID + "\x00" + pins[i].ContractVersion + "\x00" + pins[i].Action
		right := pins[j].ContractID + "\x00" + pins[j].ContractVersion + "\x00" + pins[j].Action
		return left < right
	})
	return pins
}

func contractPinned(pins []ContractPin, ref exchange.ContractRef, action string) bool {
	for _, pin := range pins {
		if pin.ContractID == strings.TrimSpace(ref.ContractID) &&
			pin.ContractVersion == strings.TrimSpace(ref.ContractVersion) &&
			pin.PayloadSchemaHashSHA256 == strings.TrimSpace(ref.PayloadSchemaHashSHA256) &&
			pin.Action == strings.TrimSpace(action) {
			return true
		}
	}
	return false
}

func normalizeApprovalRecord(record ApprovalRecord) ApprovalRecord {
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.CatalogVersion = strings.TrimSpace(record.CatalogVersion)
	record.PackVersion = strings.TrimSpace(record.PackVersion)
	record.ManifestID = strings.TrimSpace(record.ManifestID)
	record.ManifestHashSHA256 = strings.TrimSpace(record.ManifestHashSHA256)
	record.State = strings.TrimSpace(record.State)
	if record.State == "" {
		record.State = StatePendingApproval
	}
	record.AllowedPartnerLinkIDs = normalizeStrings(record.AllowedPartnerLinkIDs)
	record.ApprovedBy = strings.TrimSpace(record.ApprovedBy)
	record.CreatedBy = strings.TrimSpace(record.CreatedBy)
	record.AuditBindingHashSHA256 = strings.TrimSpace(record.AuditBindingHashSHA256)
	for i := range record.Contracts {
		record.Contracts[i].ContractID = strings.TrimSpace(record.Contracts[i].ContractID)
		record.Contracts[i].ContractVersion = strings.TrimSpace(record.Contracts[i].ContractVersion)
		record.Contracts[i].PayloadSchemaHashSHA256 = strings.TrimSpace(record.Contracts[i].PayloadSchemaHashSHA256)
		record.Contracts[i].ServiceCatalogID = strings.TrimSpace(record.Contracts[i].ServiceCatalogID)
		record.Contracts[i].Action = strings.TrimSpace(record.Contracts[i].Action)
		record.Contracts[i].ServiceCatalogAction = strings.TrimSpace(record.Contracts[i].ServiceCatalogAction)
	}
	sort.SliceStable(record.Contracts, func(i, j int) bool {
		left := record.Contracts[i].ContractID + "\x00" + record.Contracts[i].ContractVersion + "\x00" + record.Contracts[i].Action
		right := record.Contracts[j].ContractID + "\x00" + record.Contracts[j].ContractVersion + "\x00" + record.Contracts[j].Action
		return left < right
	})
	return record
}

func normalizePinInput(input PinInput) PinInput {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.PartnerLinkID = strings.TrimSpace(input.PartnerLinkID)
	input.CatalogVersion = strings.TrimSpace(input.CatalogVersion)
	input.PackVersion = strings.TrimSpace(input.PackVersion)
	input.ManifestHashSHA256 = strings.TrimSpace(input.ManifestHashSHA256)
	input.PinnedBy = strings.TrimSpace(input.PinnedBy)
	input.Reason = strings.TrimSpace(input.Reason)
	return input
}

func normalizePartnerPin(pin PartnerPin) PartnerPin {
	pin.TenantID = strings.TrimSpace(pin.TenantID)
	pin.PartnerLinkID = strings.TrimSpace(pin.PartnerLinkID)
	pin.CatalogVersion = strings.TrimSpace(pin.CatalogVersion)
	pin.PackVersion = strings.TrimSpace(pin.PackVersion)
	pin.ManifestHashSHA256 = strings.TrimSpace(pin.ManifestHashSHA256)
	pin.PreviousPackVersion = strings.TrimSpace(pin.PreviousPackVersion)
	pin.PreviousManifestHashSHA256 = strings.TrimSpace(pin.PreviousManifestHashSHA256)
	pin.PinnedBy = strings.TrimSpace(pin.PinnedBy)
	pin.Reason = strings.TrimSpace(pin.Reason)
	pin.AuditBindingHashSHA256 = strings.TrimSpace(pin.AuditBindingHashSHA256)
	return pin
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

func containsString(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, value := range values {
		if strings.TrimSpace(value) == needle {
			return true
		}
	}
	return false
}

func pinKey(tenantID, partnerLinkID, catalogVersion string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(partnerLinkID) + "\x00" + strings.TrimSpace(catalogVersion)
}

func hashCanonical(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("contract approval canonical hash: %v", err))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func approvalErr(message string) error {
	return apperrors.New(apperrors.CodePolicyDenied, "contract_approval", message)
}
