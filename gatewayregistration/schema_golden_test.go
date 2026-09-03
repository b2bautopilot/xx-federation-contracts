package gatewayregistration

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// regFixture mirrors testdata/parity/gatewayregistration.json — the JCS / digest
// compatibility vectors captured from the pre-move implementation.
type regFixture struct {
	JCS          map[string]string `json:"jcs"`
	LCACanonical string            `json:"lca_canonical"`
	LCADigest    string            `json:"lca_digest"`
}

func loadRegFixture(t *testing.T) regFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "parity", "gatewayregistration.json"))
	if err != nil {
		t.Fatalf("read gatewayregistration parity fixture: %v", err)
	}
	var f regFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode gatewayregistration parity fixture: %v", err)
	}
	return f
}

func testLCA() LocalControlAuthorization {
	return LocalControlAuthorization{
		SchemaVersion:       LocalControlAuthorizationVersion,
		AuthorizationID:     "auth-1",
		IssuerControlID:     "control-1",
		IssuerKeyID:         "kid-1",
		FabricID:            "fabric-a",
		OrgID:               "org-acme",
		TenantID:            "tenant-acme",
		GatewayPoolID:       "pool-a",
		GatewayID:           "gw-a",
		AllowedRelayFabric:  "fabric-a",
		AllowedRelayRegions: []string{"us", "eu"},
		FacadeScope:         []string{"fed-svc"},
		CSRPublicKeyBinding: PublicKeyBinding{Alg: PublicKeyBindingAlgorithmSHA256SPKI, Value: "spki-1"},
		NotBeforeMS:         1000,
		ExpiresAtMS:         9000,
		SignatureAlg:        SignatureAlgorithmEd25519JCSV1,
		Signature:           "sig-1",
	}
}

func TestGoldenJCSCanonicalBytes(t *testing.T) {
	f := loadRegFixture(t)
	// edge set: key ordering, number forms, nested arrays, unicode escapes
	edge := map[string]string{
		`{"b":2,"a":1}`:              f.JCS[`{"b":2,"a":1}`],
		`{"n":1.0,"m":100}`:          f.JCS[`{"n":1.0,"m":100}`],
		`{"a":[3,1,2],"s":"nested"}`: f.JCS[`{"a":[3,1,2],"s":"nested"}`],
		`{"u":"\u00fcn\u00ef"}`:      f.JCS[`{"u":"\u00fcn\u00ef"}`],
	}
	for in, want := range edge {
		cb, err := JCSCanonicalBytes([]byte(in))
		if err != nil {
			t.Fatalf("JCSCanonicalBytes(%q): %v", in, err)
		}
		if got := hex.EncodeToString(cb); got != want {
			t.Errorf("JCSCanonicalBytes(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestGoldenLocalControlAuthorization(t *testing.T) {
	f := loadRegFixture(t)
	canonical, err := LocalControlAuthorizationCanonicalBytes(testLCA())
	if err != nil {
		t.Fatalf("LocalControlAuthorizationCanonicalBytes: %v", err)
	}
	if got := string(canonical); got != f.LCACanonical {
		t.Errorf("LCA canonical = %s\nwant %s", got, f.LCACanonical)
	}
	digest, err := LocalControlAuthorizationDigestSHA256(testLCA())
	if err != nil {
		t.Fatalf("LocalControlAuthorizationDigestSHA256: %v", err)
	}
	if digest != f.LCADigest {
		t.Errorf("LCA digest = %s, want %s", digest, f.LCADigest)
	}
}

func TestPayloadAndEnvelopeDigests(t *testing.T) {
	payload := `{"org_id":"org-acme","gateway_id":"gw-a"}`
	single, err := PayloadDigestSHA256(payload)
	if err != nil {
		t.Fatalf("PayloadDigestSHA256: %v", err)
	}
	// EnvelopePayloadDigestSHA256 digests only the envelope Payload field.
	envJSON := `{"schema_version":"relay-mesh-registration.v0","idempotency_key":"k","correlation_id":"c1","actor":{"type":"user","principal_id":"p","auth_context":"a"},"payload":` + payload + `}`
	envDigest, err := EnvelopePayloadDigestSHA256([]byte(envJSON))
	if err != nil {
		t.Fatalf("EnvelopePayloadDigestSHA256: %v", err)
	}
	if envDigest != single {
		t.Errorf("envelope payload digest = %s, want %s", envDigest, single)
	}
}

func TestJCSCanonicalBytes_Negative(t *testing.T) {
	bad := []string{
		"not json",
		`{"a":1}{"b":2}`,
		`{"a":1,"a":2}`, // duplicate object name rejected
		"",
	}
	for _, in := range bad {
		if _, err := JCSCanonicalBytes([]byte(in)); err == nil {
			t.Errorf("JCSCanonicalBytes(%q) expected error", in)
		}
	}
}

func TestEnvelopeDecode_RejectsUnknownField(t *testing.T) {
	// strict decode must reject an unknown/unmapped field (security-sensitive).
	env := `{"schema_version":"relay-mesh-registration.v0","idempotency_key":"k","correlation_id":"c1","actor":{"type":"user","principal_id":"p","auth_context":"a"},"payload":{"org_id":"x"},"hostile_extra":true}`
	if _, err := DecodeCommandEnvelope([]byte(env), nil, false); err == nil {
		t.Error("expected DecodeCommandEnvelope to reject unknown envelope field")
	}
}

func TestResponseEnvelopes(t *testing.T) {
	errEnv := ErrorResponse(CodeSchemaInvalid, "cid-1", "")
	if errEnv.OK {
		t.Error("ErrorResponse must be OK=false")
	}
	okEnv := SuccessResponse("done", "cid-2")
	if !okEnv.OK || okEnv.Disposition != DispositionTerminalOK {
		t.Error("SuccessResponse must be OK=true terminal")
	}
	// OrgStatusInvalidResponse maps to a terminal non-OK envelope.
	invalid := OrgStatusInvalidResponse(OrgStatusSuspended, "cid-3", "boot-1")
	if invalid.OK {
		t.Error("OrgStatusInvalidResponse must be OK=false")
	}
	if invalid.Code != "org_status_invalid" {
		t.Errorf("OrgStatusInvalidResponse code = %q", invalid.Code)
	}
	if strings.TrimSpace(invalid.Message) == "" {
		t.Error("OrgStatusInvalidResponse must carry a sanitized message")
	}
}
