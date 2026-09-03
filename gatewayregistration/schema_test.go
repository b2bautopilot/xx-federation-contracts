package gatewayregistration

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeCreateGatewayBootstrapEnvelopeRejectsUnknownFields(t *testing.T) {
	valid := string(testCreateEnvelope(t, "corr-a", "idem-a", testCreatePayload()))

	topLevelUnknown := strings.Replace(valid, `"schema_version":`, `"unexpected":true,"schema_version":`, 1)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope([]byte(topLevelUnknown)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("top-level unknown error = %v, want %s", err, CodeSchemaInvalid)
	}

	payloadUnknown := strings.Replace(valid, `"ttl_seconds":900`, `"ttl_seconds":900,"mtls_subject":"CN=operator-supplied"`, 1)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope([]byte(payloadUnknown)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("payload unknown identity error = %v, want %s", err, CodeSchemaInvalid)
	}

	nestedUnknown := strings.Replace(valid, `"signature":"sig-1"`, `"signature":"sig-1","fingerprint_sha256":"bad"`, 1)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope([]byte(nestedUnknown)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("nested unknown identity error = %v, want %s", err, CodeSchemaInvalid)
	}
}

func TestDecodeCreateGatewayBootstrapEnvelopeRejectsDuplicateAndCaseVariantFields(t *testing.T) {
	valid := string(testCreateEnvelope(t, "corr-a", "idem-a", testCreatePayload()))

	duplicateKnown := strings.Replace(valid, `"idempotency_key":"idem-a"`, `"idempotency_key":"idem-a","idempotency_key":"idem-b"`, 1)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope([]byte(duplicateKnown)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("duplicate known field error = %v, want %s", err, CodeSchemaInvalid)
	}

	caseVariant := strings.Replace(valid, `"schema_version":`, `"Schema_Version":`, 1)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope([]byte(caseVariant)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("case-variant field error = %v, want %s", err, CodeSchemaInvalid)
	}
}

func TestDecodeCreateGatewayBootstrapEnvelopeRequiresIdempotencyForMutations(t *testing.T) {
	body := string(testCreateEnvelope(t, "corr-a", "idem-a", testCreatePayload()))
	body = strings.Replace(body, `"idempotency_key":"idem-a",`, "", 1)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope([]byte(body)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("missing idempotency error = %v, want %s", err, CodeSchemaInvalid)
	}
}

func TestCreateGatewayBootstrapPayloadValidatesLocalControlScope(t *testing.T) {
	payload := testCreatePayload()
	payload.LocalControlAuthorization.GatewayID = "gw-other"
	body := testCreateEnvelope(t, "corr-a", "idem-a", payload)
	if _, _, err := DecodeCreateGatewayBootstrapEnvelope(body); !IsCode(err, CodeLocalControlAuthorizationMismatch) {
		t.Fatalf("scope mismatch error = %v, want %s", err, CodeLocalControlAuthorizationMismatch)
	}
}

func TestOrgStatusEligibilityMappingIsDeterministic(t *testing.T) {
	cases := []struct {
		status      OrgStatus
		allowed     bool
		disposition Disposition
		retryable   bool
		poll        int
	}{
		{OrgStatusActive, true, DispositionTerminalOK, false, 0},
		{OrgStatusVerifiedBusiness, false, DispositionAwaitingHuman, true, DefaultPollAfterSeconds},
		{OrgStatusDomainVerified, false, DispositionAwaitingHuman, true, DefaultPollAfterSeconds},
		{OrgStatusDraft, false, DispositionAwaitingHuman, true, DefaultPollAfterSeconds},
		{OrgStatusDomainPending, false, DispositionAwaitingExternal, true, DefaultPollAfterSeconds},
		{OrgStatusKYGPending, false, DispositionAwaitingExternal, true, DefaultPollAfterSeconds},
		{OrgStatusDomainReverificationRequired, false, DispositionAwaitingExternal, true, DefaultPollAfterSeconds},
		{OrgStatusReviewHold, false, DispositionAwaitingHuman, true, DefaultPollAfterSeconds},
		{OrgStatusSuspendedPendingAppeal, false, DispositionAwaitingHuman, true, DefaultPollAfterSeconds},
		{OrgStatusSuspended, false, DispositionTerminalError, false, 0},
		{OrgStatusRevoked, false, DispositionTerminalError, false, 0},
		{OrgStatusDeleted, false, DispositionTerminalError, false, 0},
		{OrgStatusPermanentlyBarred, false, DispositionTerminalError, false, 0},
		{OrgStatusUnknownOrg, false, DispositionTerminalError, false, 0},
		{"not-a-status", false, DispositionTerminalError, false, 0},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			got := RegistrationEligibilityForOrgStatus(tc.status)
			if got.ProductionAllowed != tc.allowed || got.Disposition != tc.disposition ||
				got.Retryable != tc.retryable || got.PollAfterSeconds != tc.poll {
				t.Fatalf("eligibility = %#v, want allowed=%v disposition=%s retry=%v poll=%d",
					got, tc.allowed, tc.disposition, tc.retryable, tc.poll)
			}
			if tc.status == "not-a-status" && got.Status != OrgStatusUnknownOrg {
				t.Fatalf("unknown status maps to %q, want %q", got.Status, OrgStatusUnknownOrg)
			}
		})
	}
}

func TestOrgStatusInvalidResponseUsesStatusSpecificPolling(t *testing.T) {
	awaiting := OrgStatusInvalidResponse(OrgStatusDomainPending, "corr-1", "gwb-1")
	if awaiting.Code != CodeOrgStatusInvalid ||
		awaiting.Disposition != DispositionAwaitingExternal ||
		!awaiting.Retryable ||
		awaiting.PollAfterSeconds <= 0 ||
		awaiting.PollHandle != "gwb-1" {
		t.Fatalf("awaiting org response = %#v", awaiting)
	}

	terminal := OrgStatusInvalidResponse(OrgStatusRevoked, "corr-2", "gwb-2")
	if terminal.Code != CodeOrgStatusInvalid ||
		terminal.Disposition != DispositionTerminalError ||
		terminal.Retryable ||
		terminal.PollAfterSeconds != 0 ||
		terminal.PollHandle != "" {
		t.Fatalf("terminal org response = %#v", terminal)
	}

	active := OrgStatusInvalidResponse(OrgStatusActive, "corr-3", "gwb-3")
	if !active.OK || active.Code != "" || active.Disposition != DispositionTerminalOK || active.PollHandle != "" {
		t.Fatalf("active org response = %#v", active)
	}
}

func TestErrorCatalogAndResponsesFollowContract(t *testing.T) {
	expected := []ErrorCode{
		CodeSchemaInvalid,
		CodeActorUnauthenticated,
		CodeActorUnauthorized,
		CodeOrgStatusInvalid,
		CodeLocalControlAuthorizationRequired,
		CodeLocalControlAuthorizationInvalid,
		CodeLocalControlAuthorizationMismatch,
		CodeBootstrapExpired,
		CodeBootstrapConsumed,
		CodeBootstrapRevoked,
		CodeBootstrapSignatureInvalid,
		CodeBootstrapIntentMismatch,
		CodeCSRParseFailed,
		CodeCSRSignatureInvalid,
		CodeCSRIdentityAssertionMismatch,
		CodeCSRPublicKeyConflict,
		CodeIssuerUnavailable,
		CodeInternal,
		CodeIdempotencyConflict,
		CodeConcurrencyFenceLost,
		CodeLegacyIdentityRejected,
		CodeIdentityProvenanceRejected,
		CodePlaneIdentityMismatch,
		CodePilotCompatInProductionRejected,
		CodePinFailure,
	}
	catalog := ErrorCatalog()
	for _, code := range expected {
		spec, ok := catalog[code]
		if !ok {
			t.Fatalf("missing error code %s", code)
		}
		if spec.Code != code || spec.ExitCode <= 0 || spec.Disposition == "" || spec.Message == "" {
			t.Fatalf("incomplete error spec for %s: %#v", code, spec)
		}
		resp := ErrorResponse(code, "corr-1", "gwb-1")
		if resp.Code != code || resp.CorrelationID != "corr-1" {
			t.Fatalf("response for %s = %#v", code, resp)
		}
		if !resp.Retryable && (resp.PollAfterSeconds != 0 || resp.PollHandle != "") {
			t.Fatalf("terminal response for %s kept polling fields: %#v", code, resp)
		}
		if resp.Retryable && (resp.PollAfterSeconds <= 0 || resp.PollHandle != "gwb-1") {
			t.Fatalf("retryable response for %s did not preserve bootstrap poll handle: %#v", code, resp)
		}
	}
	if len(catalog) != len(expected) {
		t.Fatalf("catalog has %d codes, expected %d", len(catalog), len(expected))
	}
	// ExitCodes are a stable per-code contract (agents branch on them) — they must be unique.
	byExit := make(map[int]ErrorCode, len(catalog))
	for code, spec := range catalog {
		if prev, dup := byExit[spec.ExitCode]; dup {
			t.Fatalf("ExitCode %d is shared by %s and %s — exit codes must be unique", spec.ExitCode, prev, code)
		}
		byExit[spec.ExitCode] = code
	}
}

func TestEnvelopePayloadDigestExcludesEnvelopeMetadata(t *testing.T) {
	payload := testCreatePayload()
	first := testCreateEnvelope(t, "corr-a", "idem-a", payload)
	second := testCreateEnvelope(t, "corr-b", "idem-b", payload)

	firstDigest, err := EnvelopePayloadDigestSHA256(first)
	if err != nil {
		t.Fatalf("first digest error = %v", err)
	}
	secondDigest, err := EnvelopePayloadDigestSHA256(second)
	if err != nil {
		t.Fatalf("second digest error = %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("digest included envelope metadata: %s != %s", firstDigest, secondDigest)
	}

	payload.TTLSeconds = 899
	changed := testCreateEnvelope(t, "corr-a", "idem-a", payload)
	changedDigest, err := EnvelopePayloadDigestSHA256(changed)
	if err != nil {
		t.Fatalf("changed digest error = %v", err)
	}
	if changedDigest == firstDigest {
		t.Fatal("digest did not include payload bytes")
	}
}

func TestEnvelopePayloadDigestCanonicalizesNumbers(t *testing.T) {
	first := []byte(`{
	  "schema_version":"relay-mesh-registration.v0",
	  "idempotency_key":"idem-a",
	  "correlation_id":"corr-a",
	  "actor":{"type":"user","principal_id":"op_01J","auth_context":"oauth_mtls_session"},
	  "payload":{"count":1,"ttl_seconds":900,"nested":[1,1000]}
	}`)
	second := []byte(`{
	  "schema_version":"relay-mesh-registration.v0",
	  "idempotency_key":"idem-b",
	  "correlation_id":"corr-b",
	  "actor":{"type":"user","principal_id":"op_01J","auth_context":"oauth_mtls_session"},
	  "payload":{"nested":[1.0,1e3],"ttl_seconds":9.00e2,"count":1.0}
	}`)
	firstDigest, err := EnvelopePayloadDigestSHA256(first)
	if err != nil {
		t.Fatalf("first digest error = %v", err)
	}
	secondDigest, err := EnvelopePayloadDigestSHA256(second)
	if err != nil {
		t.Fatalf("second digest error = %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("number-equivalent payloads hashed differently: %s != %s", firstDigest, secondDigest)
	}
}

func TestCanonicalPayloadBytesUsesSortedNonHTMLEscapedJSON(t *testing.T) {
	got, err := CanonicalPayloadBytes([]byte(`{"z":"<&>","a":[1.0,1e3]}`))
	if err != nil {
		t.Fatalf("canonical payload error = %v", err)
	}
	want := `{"a":[1,1000],"z":"<&>"}`
	if string(got) != want {
		t.Fatalf("canonical payload = %s, want %s", got, want)
	}
}

func TestJCSCanonicalBytesConformanceVectors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "object order, nested values, and no HTML escaping",
			input: `{"z":"<&>","a":[1.0,1e3],"m":{"b":true,"a":false}}`,
			want:  `{"a":[1,1000],"m":{"a":false,"b":true},"z":"<&>"}`,
		},
		{
			name:  "ECMAScript number thresholds and exponent spelling",
			input: `{"n":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,1e20,1e21,1e-6,9.999999999999997e-7,-0]}`,
			want:  `{"n":[333333333.3333333,1e+30,4.5,0.002,1e-27,100000000000000000000,1e+21,0.000001,9.999999999999997e-7,0]}`,
		},
		{
			name:  "object keys sort by UTF-16 code units",
			input: `{"\ue000":1,"\ud83d\ude00":2}`,
			want:  "{\"\U0001f600\":2,\"\ue000\":1}",
		},
		{
			name:  "non-control Unicode line separators stay UTF-8",
			input: `{"s":"\u2028\u2029"}`,
			want:  "{\"s\":\"\u2028\u2029\"}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JCSCanonicalBytes([]byte(tc.input))
			if err != nil {
				t.Fatalf("JCS canonicalization error = %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("JCS canonical bytes = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestJCSCanonicalBytesRejectsDuplicateAndInvalidUnicode(t *testing.T) {
	cases := []string{
		`{"a":1,"a":2}`,
		`{"a":1,"\u0061":2}`,
		`{"bad":"\udead"}`,
		`{"bad":"\ud83d"}`,
		`{"bad":"\ud83d\u0041"}`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := JCSCanonicalBytes([]byte(input)); !IsCode(err, CodeSchemaInvalid) {
				t.Fatalf("JCS canonicalization error = %v, want %s", err, CodeSchemaInvalid)
			}
		})
	}
	if _, err := JCSCanonicalBytes([]byte{'"', 0xff, '"'}); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("raw invalid UTF-8 error = %v, want %s", err, CodeSchemaInvalid)
	}
	if _, err := CanonicalPayloadBytes(map[string]any{"bad": string([]byte{0xff})}); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("programmatic invalid UTF-8 error = %v, want %s", err, CodeSchemaInvalid)
	}
}

func TestEd25519JCSV1SignaturesUseCanonicalBytes(t *testing.T) {
	seed := []byte("slice104a-ed25519-jcs-v1-seed!!!")
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	raw := []byte(`{"z":"<&>","a":[1.0,1e3],"nested":{"b":true,"a":false}}`)
	canonical, err := JCSCanonicalBytes(raw)
	if err != nil {
		t.Fatalf("canonicalization error = %v", err)
	}
	signature := ed25519.Sign(private, canonical)

	equivalent := []byte(`{"nested":{"a":false,"b":true},"a":[1,1000.0],"z":"<&>"}`)
	equivalentCanonical, err := JCSCanonicalBytes(equivalent)
	if err != nil {
		t.Fatalf("equivalent canonicalization error = %v", err)
	}
	if !ed25519.Verify(public, equivalentCanonical, signature) {
		t.Fatal("signature did not verify over equivalent JCS canonical bytes")
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode raw JSON error = %v", err)
	}
	lossy, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("lossy remarshal error = %v", err)
	}
	if string(lossy) == string(canonical) {
		t.Fatalf("test remarshal unexpectedly matched canonical bytes: %s", lossy)
	}
	if ed25519.Verify(public, lossy, signature) {
		t.Fatal("signature verified over lossy decoded/remarshaled bytes")
	}
}

func TestLocalControlAuthorizationDigestExcludesOnlySignature(t *testing.T) {
	auth := testLocalControlAuthorization()
	first, err := LocalControlAuthorizationDigestSHA256(auth)
	if err != nil {
		t.Fatalf("digest error = %v", err)
	}

	auth.Signature = "different-signature"
	second, err := LocalControlAuthorizationDigestSHA256(auth)
	if err != nil {
		t.Fatalf("digest with changed signature error = %v", err)
	}
	if first != second {
		t.Fatalf("digest included signature: %s != %s", first, second)
	}

	auth.SignatureAlg = "different-alg"
	third, err := LocalControlAuthorizationDigestSHA256(auth)
	if err != nil {
		t.Fatalf("digest with changed signature_alg error = %v", err)
	}
	if third == first {
		t.Fatal("digest excluded signature_alg, but contract says signature_alg is included")
	}
}

func TestLocalControlAuthorizationCanonicalBytesRejectsInvalidUTF8(t *testing.T) {
	auth := testLocalControlAuthorization()
	auth.GatewayID = string([]byte{0xff})
	if _, err := LocalControlAuthorizationCanonicalBytes(auth); err == nil {
		t.Fatal("local-control canonical bytes accepted invalid UTF-8")
	}
}

func TestRedeemShapeRejectsFinalAuthoritativeIdentityFields(t *testing.T) {
	payload := testRedeemPayload(t)
	body := string(testEnvelope(t, "corr-r", "idem-r", payload))
	body = strings.Replace(body, `"advisory":`, `"relay_identity":{"spiffe_id":"spiffe://bad"},"advisory":`, 1)

	if _, _, err := DecodeRedeemGatewayBootstrapEnvelope([]byte(body)); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("authoritative identity field error = %v, want %s", err, CodeSchemaInvalid)
	}
}

func TestDecodeRedeemGatewayBootstrapEnvelopeRejectsLocalControlDigestMismatch(t *testing.T) {
	payload := testRedeemPayload(t)
	payload.LocalControlAuthorization.IssuerKeyID = "different-key"
	body := testEnvelope(t, "corr-r", "idem-r", payload)
	if _, _, err := DecodeRedeemGatewayBootstrapEnvelope(body); !IsCode(err, CodeLocalControlAuthorizationMismatch) {
		t.Fatalf("decode digest mismatch error = %v, want %s", err, CodeLocalControlAuthorizationMismatch)
	}
}

func TestRedeemLocalControlDigestBindingHelper(t *testing.T) {
	payload := testRedeemPayload(t)
	if err := ValidateRedeemLocalControlDigest(payload); err != nil {
		t.Fatalf("valid digest binding error = %v", err)
	}

	payload.LocalControlAuthorization.Signature = "different-signature"
	if err := ValidateRedeemLocalControlDigest(payload); err != nil {
		t.Fatalf("signature-only change must not affect digest binding: %v", err)
	}

	payload.LocalControlAuthorization.IssuerKeyID = "different-key"
	if err := ValidateRedeemLocalControlDigest(payload); !IsCode(err, CodeLocalControlAuthorizationMismatch) {
		t.Fatalf("changed signed field error = %v, want %s", err, CodeLocalControlAuthorizationMismatch)
	}
}

func TestIdempotencyScopeKeyIsStructured(t *testing.T) {
	scope := IdempotencyScope{
		FabricID:       "fabric-a",
		ActorOrgID:     "org-a",
		RPCMethod:      "CreateGatewayBootstrapIntent",
		IdempotencyKey: "idem-a",
	}
	key, err := scope.Key()
	if err != nil {
		t.Fatalf("scope key error = %v", err)
	}
	if !strings.Contains(key, "\x1f") || strings.Contains(key, "|") {
		t.Fatalf("scope key = %q, want structured non-printing separator", key)
	}

	scope.ActorOrgID = ""
	if _, err := scope.Key(); !IsCode(err, CodeSchemaInvalid) {
		t.Fatalf("incomplete scope error = %v, want %s", err, CodeSchemaInvalid)
	}
}

func testCreatePayload() CreateGatewayBootstrapPayload {
	auth := testLocalControlAuthorization()
	return CreateGatewayBootstrapPayload{
		OrgID:                     auth.OrgID,
		GatewayPoolID:             auth.GatewayPoolID,
		GatewayID:                 auth.GatewayID,
		DisplayName:               "newco gateway",
		AllowedRelayFabric:        auth.AllowedRelayFabric,
		AllowedRelayRegions:       []string{"us-east1"},
		FacadeScope:               []string{"catalog_discovery_v1", "b2b_exchange_v1"},
		CSRPublicKeyBinding:       auth.CSRPublicKeyBinding,
		LocalControlAuthorization: auth,
		TTLSeconds:                DefaultMaxBootstrapTTLSeconds,
	}
}

func testLocalControlAuthorization() LocalControlAuthorization {
	return LocalControlAuthorization{
		SchemaVersion:       LocalControlAuthorizationVersion,
		AuthorizationID:     "lc_auth_01J",
		IssuerControlID:     "control_newco_prod",
		IssuerKeyID:         "lc_key_01J",
		FabricID:            "b2bautopilot-prod",
		OrgID:               "org_newco_01",
		TenantID:            "tenant_newco_01",
		GatewayPoolID:       "gwp_newco_prod",
		GatewayID:           "gw_newco_prod_01",
		AllowedRelayFabric:  "b2bautopilot-prod",
		AllowedRelayRegions: []string{"us-east1", "us-west1"},
		FacadeScope:         []string{"catalog_discovery_v1", "b2b_exchange_v1", "future_scope"},
		CSRPublicKeyBinding: PublicKeyBinding{
			Alg:   PublicKeyBindingAlgorithmSHA256SPKI,
			Value: "base64url-sha256-of-subject-public-key-info",
		},
		NotBeforeMS:  1781400000000,
		ExpiresAtMS:  1781400900000,
		SignatureAlg: SignatureAlgorithmEd25519JCSV1,
		Signature:    "sig-1",
	}
}

func testRedeemPayload(t *testing.T) RedeemGatewayBootstrapPayload {
	t.Helper()
	auth := testLocalControlAuthorization()
	digest, err := LocalControlAuthorizationDigestSHA256(auth)
	if err != nil {
		t.Fatalf("digest fixture error = %v", err)
	}
	return RedeemGatewayBootstrapPayload{
		Bootstrap: GatewayBootstrapIntent{
			SchemaVersion:                         GatewayBootstrapIntentVersion,
			BootstrapID:                           "gwb_01J",
			FabricID:                              auth.FabricID,
			OrgID:                                 auth.OrgID,
			GatewayPoolID:                         auth.GatewayPoolID,
			GatewayID:                             auth.GatewayID,
			AllowedRelayFabric:                    auth.AllowedRelayFabric,
			AllowedRelayRegions:                   []string{"us-east1"},
			FacadeScope:                           []string{"catalog_discovery_v1", "b2b_exchange_v1"},
			LocalControlAuthorizationRef:          auth.AuthorizationID,
			LocalControlAuthorizationDigestSHA256: digest,
			CSRPublicKeyBinding:                   auth.CSRPublicKeyBinding,
			JTI:                                   "jti_01J",
			IssuedAtMS:                            1781400000000,
			ExpiresAtMS:                           1781400900000,
			SignatureAlg:                          SignatureAlgorithmEd25519JCSV1,
			Signature:                             "bootstrap-sig",
		},
		CSRPem:                    "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
		LocalControlAuthorization: auth,
		Advisory: AdvisoryIdentity{
			DisplayName: "newco gateway",
		},
	}
}

func testCreateEnvelope(t *testing.T, correlationID, idempotencyKey string, payload CreateGatewayBootstrapPayload) []byte {
	t.Helper()
	return testEnvelope(t, correlationID, idempotencyKey, payload)
}

func testEnvelope(t *testing.T, correlationID, idempotencyKey string, payload any) []byte {
	t.Helper()
	body, err := json.Marshal(CommandEnvelope{
		SchemaVersion:  CommandEnvelopeSchemaVersion,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID,
		Actor: Actor{
			Type:        ActorTypeUser,
			PrincipalID: "op_01J",
			AuthContext: "oauth_mtls_session",
			Scopes:      []string{"gateway.bootstrap.create", "gateway.bootstrap.redeem"},
		},
		Payload: mustRawMessage(t, payload),
	})
	if err != nil {
		t.Fatalf("marshal envelope error = %v", err)
	}
	return body
}

func mustRawMessage(t *testing.T, value any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal payload error = %v", err)
	}
	return body
}
