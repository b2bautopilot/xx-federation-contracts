package servicecatalog

import (
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/apperrors"
)

func TestValidateEntryRequiresOwnerTenantSchemaVersionAndActions(t *testing.T) {
	valid := EntryInput{
		TenantID:           "tenant-a",
		DisplayName:        "Order Status",
		Description:        "Partner-visible order status lookup.",
		ServiceKind:        "order_status",
		SchemaJSON:         `{"type":"object","properties":{"order_id":{"type":"string"}}}`,
		SchemaVersion:      "2026-06-04",
		AllowedActionsJSON: `["read","read"]`,
		State:              StateActive,
	}
	if err := ValidateEntry(valid); err != nil {
		t.Fatalf("ValidateEntry(valid) error = %v", err)
	}
	if _, err := AllowedActions(valid.AllowedActionsJSON); err != nil {
		t.Fatalf("AllowedActions(valid) error = %v", err)
	}

	for _, tc := range []struct {
		name  string
		input EntryInput
	}{
		{name: "missing tenant", input: EntryInput{DisplayName: valid.DisplayName, ServiceKind: valid.ServiceKind, SchemaJSON: valid.SchemaJSON, SchemaVersion: valid.SchemaVersion, AllowedActionsJSON: valid.AllowedActionsJSON}},
		{name: "missing schema", input: EntryInput{TenantID: valid.TenantID, DisplayName: valid.DisplayName, ServiceKind: valid.ServiceKind, SchemaVersion: valid.SchemaVersion, AllowedActionsJSON: valid.AllowedActionsJSON}},
		{name: "missing version", input: EntryInput{TenantID: valid.TenantID, DisplayName: valid.DisplayName, ServiceKind: valid.ServiceKind, SchemaJSON: valid.SchemaJSON, AllowedActionsJSON: valid.AllowedActionsJSON}},
		{name: "missing actions", input: EntryInput{TenantID: valid.TenantID, DisplayName: valid.DisplayName, ServiceKind: valid.ServiceKind, SchemaJSON: valid.SchemaJSON, SchemaVersion: valid.SchemaVersion}},
		{name: "private display", input: EntryInput{TenantID: valid.TenantID, DisplayName: "orders.internal", ServiceKind: valid.ServiceKind, Description: valid.Description, SchemaJSON: valid.SchemaJSON, SchemaVersion: valid.SchemaVersion, AllowedActionsJSON: valid.AllowedActionsJSON}},
		{name: "private description", input: EntryInput{TenantID: valid.TenantID, DisplayName: valid.DisplayName, ServiceKind: valid.ServiceKind, Description: "Bearer super-secret", SchemaJSON: valid.SchemaJSON, SchemaVersion: valid.SchemaVersion, AllowedActionsJSON: valid.AllowedActionsJSON}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEntry(tc.input)
			if err == nil || apperrors.From(err).Code != apperrors.CodeControlInvalidArgument {
				t.Fatalf("ValidateEntry error = %v, want invalid argument", err)
			}
		})
	}
}

func TestPublicTextScrubsPrivateMaterial(t *testing.T) {
	if got := PublicText(" Partner-visible catalog text "); got != "Partner-visible catalog text" {
		t.Fatalf("PublicText safe value = %q", got)
	}
	for _, value := range []string{
		"orders.internal",
		"fd00::1",
		"Bearer super-secret",
		"/Users/silji/code/private",
	} {
		t.Run(value, func(t *testing.T) {
			if got := PublicText(value); got != "" {
				t.Fatalf("PublicText(%q) = %q, want scrubbed empty string", value, got)
			}
		})
	}
}

func TestValidatePublicSchemaRejectsTopologySecretsAndPrivateAddresses(t *testing.T) {
	for _, raw := range []string{
		`{"mesh_ip":"fd00::1"}`,
		`{"callback":"https://192.168.40.25:8443/internal"}`,
		`{"callback":"https://[fd00::1]/orders"}`,
		`{"callback":"https://orders.internal/status"}`,
		`{"auth_header":"Bearer super-secret"}`,
		`{"token":"secret"}`,
		`{"repo_path":"/Users/silji/code/private"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			err := ValidatePublicSchemaJSON(raw)
			if err == nil || apperrors.From(err).Code != apperrors.CodeControlInvalidArgument {
				t.Fatalf("ValidatePublicSchemaJSON error = %v, want invalid argument", err)
			}
		})
	}
}

func TestVisibleStateIncludesActiveAndDeprecatedOnly(t *testing.T) {
	if !VisibleState(StateActive) || !VisibleState(StateDeprecated) {
		t.Fatal("active and deprecated entries should be partner visible")
	}
	if VisibleState(StateRetired) {
		t.Fatal("retired entries should not be partner visible")
	}
}
