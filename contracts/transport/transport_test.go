package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenTransport is the pinned compatibility vector for the transport sealing
// contract (canonical source xx-builders-net/federation/transport at origin/dev
// c1ad78a). The ported body is byte-identical except the Metrics one-method
// interface; regenerating and replaying the fixture in testdata/parity guards the
// transport sealing contract against silent drift.
type goldenTransport struct {
	KeyHex        string `json:"key_hex"`
	AADHex        string `json:"aad_hex"`
	Plaintext     string `json:"plaintext"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

func goldenAAD(t *testing.T, g goldenTransport) []byte {
	t.Helper()
	aad, err := hex.DecodeString(g.AADHex)
	if err != nil {
		t.Fatalf("decode aad: %v", err)
	}
	return aad
}

func loadGoldenTransport(t *testing.T) goldenTransport {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "parity", "transport.json"))
	if err != nil {
		t.Fatalf("read transport parity fixture: %v", err)
	}
	var g goldenTransport
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("decode transport parity fixture: %v", err)
	}
	return g
}

func TestGoldenSealRelayPayloadReplays(t *testing.T) {
	g := loadGoldenTransport(t)
	key, err := hex.DecodeString(g.KeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	frame, err := SealRelayPayload([]byte(g.Plaintext), "kv-1", key, goldenAAD(t, g), bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
	if err != nil {
		t.Fatalf("SealRelayPayload: %v", err)
	}
	if got := hex.EncodeToString(frame.Nonce); got != g.NonceHex {
		t.Fatalf("nonce = %s, want %s", got, g.NonceHex)
	}
	if got := hex.EncodeToString(frame.Ciphertext); got != g.CiphertextHex {
		t.Fatalf("ciphertext = %s, want %s", got, g.CiphertextHex)
	}
	open, err := OpenRelayPayload(frame, key, goldenAAD(t, g))
	if err != nil {
		t.Fatalf("OpenRelayPayload: %v", err)
	}
	if !bytes.Equal(open, []byte(g.Plaintext)) {
		t.Fatalf("round-trip plaintext = %q, want %q", open, g.Plaintext)
	}
}

func TestOpenRelayPayload_RejectsWrongKey(t *testing.T) {
	g := loadGoldenTransport(t)
	key, _ := hex.DecodeString(g.KeyHex)
	other := make([]byte, 32)
	copy(other, key)
	other[0] ^= 0xff
	frame, err := SealRelayPayload([]byte(g.Plaintext), "kv-1", key, goldenAAD(t, g), bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
	if err != nil {
		t.Fatalf("SealRelayPayload: %v", err)
	}
	if _, err := OpenRelayPayload(frame, other, goldenAAD(t, g)); err == nil {
		t.Fatal("expected OpenRelayPayload to fail closed with the wrong key")
	}
}

func TestOpenRelayPayload_RejectsTamperedCiphertext(t *testing.T) {
	g := loadGoldenTransport(t)
	key, _ := hex.DecodeString(g.KeyHex)
	frame := RelayFrame{
		KeyID:      "kv-1",
		Nonce:      []byte(strings.Repeat("\x00", 12)),
		Ciphertext: []byte("tampered-aaaaaaaaaaaaaaaaaaaa"),
	}
	if _, err := OpenRelayPayload(frame, key, goldenAAD(t, g)); err == nil {
		t.Fatal("expected OpenRelayPayload to fail closed on tampered ciphertext")
	}
}

func TestSealRelayPayload_RejectsMissingKeyOrKeyID(t *testing.T) {
	if _, err := SealRelayPayload([]byte("p"), "", nil, nil, nil); err == nil {
		t.Fatal("expected error for missing key")
	}
	if _, err := SealRelayPayload([]byte("p"), "  ", []byte(strings.Repeat("\x00", 32)), nil, nil); !errors.Is(err, ErrRelayPayloadKey) {
		t.Fatalf("expected ErrRelayPayloadKey for blank key id, got %v", err)
	}
}

// relayRecorder is a stub RelayConnector that records the frame the Negotiator
// hands to the relay under OpenRelay, so the test can assert the associated data
// the Negotiator builds from both identities and the partner link.
type relayRecorder struct {
	frame RelayFrame
}

func (r *relayRecorder) OpenRelay(_ context.Context, req RelayRequest) (RelaySession, error) {
	r.frame = req.Frame
	return RelaySession{RemoteIdentity: req.ExpectedRemoteIdentity}, nil
}

func TestGoldenAssociatedDataObservedByRelayConnector(t *testing.T) {
	g := loadGoldenTransport(t)
	key, _ := hex.DecodeString(g.KeyHex)
	rec := &relayRecorder{}
	n := NewNegotiator(nil, rec)
	local := Identity{
		TenantID: "tenant-a", GatewayID: "gw-1", ServicePrincipalID: "sp-a",
		SPIFFEID: "spiffe-a", Subject: "sub-a", FingerprintSHA256: "fp-a",
		TrustRootID: "tr-a", TrustRootBundleSHA256: "trb-a",
	}
	remote := Identity{
		TenantID: "tenant-b", GatewayID: "gw-2", ServicePrincipalID: "sp-b",
		SPIFFEID: "spiffe-b", Subject: "sub-b", FingerprintSHA256: "fp-b",
		TrustRootID: "tr-b", TrustRootBundleSHA256: "trb-b",
	}
	_, err := n.Negotiate(context.Background(), Request{
		PartnerLinkID:          "part",
		LocalIdentity:          local,
		ExpectedRemoteIdentity: remote,
		Policy:                 Policy{DirectMode: DirectModeDisabled, RelayFallbackAllowed: true},
		BootstrapServers:       []BootstrapServer{{Endpoint: "relay.example", TrustRootRef: "tr", RendezvousNamespace: "ns"}},
		BusinessPayload:        []byte("payload"),
		RelayPayloadKeyID:      "kv-1",
		RelayPayloadKey:        key,
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if got := hex.EncodeToString(rec.frame.AssociatedData); got != g.AADHex {
		t.Fatalf("associated data = %s, want %s", got, g.AADHex)
	}
}

// TestAssociatedDataBoundaryCollision is the regression for the boundary-
// ambiguous pipe join: two distinct field tuples that collided under the old
// encoding must produce distinct associated data under length-delimiting.
func TestAssociatedDataBoundaryCollision(t *testing.T) {
	mkIdent := func(tenant, gateway, spiffe string) Identity {
		return Identity{TenantID: tenant, GatewayID: gateway, SPIFFEID: spiffe}
	}
	// ("a|b","c") vs ("a","b|c") across the partner-link/gateway boundary.
	a := relayPayloadAssociatedData("a|b", mkIdent("t", "c", "spiffe://x"), mkIdent("t", "g", "spiffe://y"))
	b := relayPayloadAssociatedData("a", mkIdent("t", "b|c", "spiffe://x"), mkIdent("t", "g", "spiffe://y"))
	if bytes.Equal(a, b) {
		t.Fatal("distinct field tuples produced identical associated data")
	}
	// Separator characters inside any single field must not shift boundaries.
	c := relayPayloadAssociatedData("part", mkIdent("ten|ant", "gw", "spiffe://x"), mkIdent("t", "g", "spiffe://y"))
	d := relayPayloadAssociatedData("part", mkIdent("ten", "ant|gw", "spiffe://x"), mkIdent("t", "g", "spiffe://y"))
	if bytes.Equal(c, d) {
		t.Fatal("separator-in-field tuples produced identical associated data")
	}
	// Encoding is deterministic: same tuple, same bytes.
	e := relayPayloadAssociatedData("part", mkIdent("t", "g", "spiffe://x"), mkIdent("t", "g", "spiffe://y"))
	f := relayPayloadAssociatedData("part", mkIdent("t", "g", "spiffe://x"), mkIdent("t", "g", "spiffe://y"))
	if !bytes.Equal(e, f) {
		t.Fatal("identical tuples produced different associated data")
	}
}

// hostileConnector fails OpenDirect/OpenRelay with errors carrying private
// topology a sanitized public Result must never repeat.
type hostileConnector struct {
	err error
}

func (h *hostileConnector) OpenDirect(_ context.Context, _ DirectRequest) (DirectSession, error) {
	return DirectSession{}, h.err
}

func (h *hostileConnector) OpenRelay(_ context.Context, _ RelayRequest) (RelaySession, error) {
	return RelaySession{}, h.err
}

func assertSanitizedResult(t *testing.T, result Result, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(result.ErrorMessage, secret) {
			t.Errorf("public ErrorMessage %q leaks %q", result.ErrorMessage, secret)
		}
		if strings.Contains(result.ErrorCode, secret) {
			t.Errorf("public ErrorCode %q leaks %q", result.ErrorCode, secret)
		}
	}
	if strings.TrimSpace(result.ErrorMessage) == "" {
		t.Error("public ErrorMessage must be a non-empty fixed message")
	}
}

func TestDirectDialErrorSanitized(t *testing.T) {
	leak := errors.New("dial tcp 10.244.1.7:8443: connect: connection refused (endpoint relay.internal:4101 spiffe://builders-net/internal)")
	n := NewNegotiator(&hostileConnector{err: leak}, nil)
	result, err := n.Negotiate(context.Background(), Request{
		PartnerLinkID:          "part",
		LocalIdentity:          Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g"},
		ExpectedRemoteIdentity: Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g"},
		Policy:                 Policy{DirectMode: DirectModeRequired},
	})
	if err == nil {
		t.Fatal("expected the raw connector cause on the local-diagnostics error return")
	}
	if !strings.Contains(err.Error(), "10.244.1.7") {
		t.Errorf("local error return should retain the diagnostic cause, got %v", err)
	}
	if result.State != StateDirectUnavailable || result.ErrorCode != ErrorDirectUnavailable {
		t.Fatalf("state = %q code = %q, want direct_unavailable", result.State, result.ErrorCode)
	}
	if result.ErrorMessage != "direct transport unavailable" {
		t.Errorf("ErrorMessage = %q, want the fixed sanitized message", result.ErrorMessage)
	}
	assertSanitizedResult(t, result, "10.244.1.7", "192.168.", "relay.internal:4101", "spiffe://builders-net/internal")
}

func TestRelaySealErrorSanitized(t *testing.T) {
	n := NewNegotiator(nil, &relayRecorder{})
	result, err := n.Negotiate(context.Background(), Request{
		PartnerLinkID:          "part",
		LocalIdentity:          Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g"},
		ExpectedRemoteIdentity: Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g"},
		Policy:                 Policy{DirectMode: DirectModeDisabled, RelayFallbackAllowed: true},
		BootstrapServers:       []BootstrapServer{{Endpoint: "10.0.0.9:443", TrustRootRef: "tr", RendezvousNamespace: "ns"}},
		BusinessPayload:        []byte("payload"),
		RelayPayloadKeyID:      "kv-1",
		RelayPayloadKey:        []byte("short"),
	})
	if err == nil {
		t.Fatal("expected the seal cause on the local-diagnostics error return")
	}
	if result.State != StateRelayUnavailable || result.ErrorCode != ErrorRelayPayloadEncrypted {
		t.Fatalf("state = %q code = %q, want relay unavailable/encryption failed", result.State, result.ErrorCode)
	}
	if result.ErrorMessage != "relay payload encryption failed" {
		t.Errorf("ErrorMessage = %q, want the fixed sanitized message", result.ErrorMessage)
	}
	// The configured endpoint must not surface even though the relay path
	// touches it; the seal failure message carries key-size detail instead.
	assertSanitizedResult(t, result, "10.0.0.9", "invalid key size")
}

// TestMatchesExpectedIdentity_RequiresCryptographicBinding pins the
// fail-closed binding rule: tenant/gateway alone (even with display-level
// service fields) never matches; SPIFFE ID or fingerprint must be pinned.
func TestMatchesExpectedIdentity_RequiresCryptographicBinding(t *testing.T) {
	subjectOnly := Identity{TenantID: "t", GatewayID: "g", Subject: "CN=gw", ServicePrincipalID: "sp"}
	if MatchesExpectedIdentity(subjectOnly, subjectOnly) {
		t.Error("tenant/gateway plus display-level fields must not match without a cryptographic binding")
	}
	fpBound := Identity{TenantID: "t", GatewayID: "g", FingerprintSHA256: "ab12"}
	if !MatchesExpectedIdentity(fpBound, fpBound) {
		t.Error("pinned fingerprint binding must match on equal values")
	}
	if MatchesExpectedIdentity(
		Identity{TenantID: "t", GatewayID: "g", FingerprintSHA256: "ab12"},
		Identity{TenantID: "t", GatewayID: "g", FingerprintSHA256: "cd34"},
	) {
		t.Error("mismatched fingerprint binding must not match")
	}
}

func TestMatchesExpectedIdentity_TruthTable(t *testing.T) {
	full := Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g"}
	cases := []struct {
		name     string
		actual   Identity
		expected Identity
		want     bool
	}{
		{"empty actual tenant rejected", Identity{}, full, false},
		{"tenant mismatch", Identity{TenantID: "x", GatewayID: "g", SPIFFEID: "spiffe://g"}, full, false},
		{"gateway mismatch", Identity{TenantID: "t", GatewayID: "x", SPIFFEID: "spiffe://g"}, full, false},
		{"exact match", full, full, true},
		{"actual missing service identity", Identity{TenantID: "t", GatewayID: "g"}, full, false},
		{"spiffe mismatch when expected set", full, Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://y"}, false},
		{"spiffe match", full, full, true},
		{"fingerprint mismatch when expected set", full, Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g", FingerprintSHA256: "fp"}, false},
		{"subject mismatch when expected set", full, Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g", Subject: "s"}, false},
		{"service principal mismatch when expected set", full, Identity{TenantID: "t", GatewayID: "g", SPIFFEID: "spiffe://g", ServicePrincipalID: "sp"}, false},
	}
	for _, c := range cases {
		if got := MatchesExpectedIdentity(c.actual, c.expected); got != c.want {
			t.Errorf("%s: MatchesExpectedIdentity = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIdentityNormalized(t *testing.T) {
	got := Identity{TenantID: " T ", GatewayID: "g", FingerprintSHA256: " AB ", TrustRootBundleSHA256: ""}.Normalized()
	if got.TenantID != "T" {
		t.Errorf("TenantID = %q, want T", got.TenantID)
	}
	if got.FingerprintSHA256 != "ab" {
		t.Errorf("FingerprintSHA256 = %q, want lowercase trimmed", got.FingerprintSHA256)
	}
}

func TestPolicyNormalized(t *testing.T) {
	if got := (Policy{}).Normalized(); got.DirectMode != DirectModePreferred {
		t.Errorf("empty policy normalized to %q, want direct_preferred", got.DirectMode)
	}
	if got := (Policy{DirectMode: "bogus"}).Normalized(); got.DirectMode != DirectModePreferred {
		t.Errorf("unknown mode normalized to %q, want direct_preferred", got.DirectMode)
	}
	if got := (Policy{DirectMode: DirectModeRequired}).Normalized(); got.DirectMode != DirectModeRequired {
		t.Errorf("known mode normalized away: %q", got.DirectMode)
	}
}

// TestSanitizedTransportErrors verifies transport error sentinels are fixed,
// non-empty codes that never leak internal topology detail.
func TestSanitizedTransportErrors(t *testing.T) {
	for _, err := range []error{ErrIdentityRequired, ErrDirectUnavailable, ErrBootstrapUnavailable, ErrRelayUnavailable, ErrRelayPayloadKey} {
		if err == nil || strings.TrimSpace(err.Error()) == "" {
			t.Fatal("expected non-empty sanitized sentinel")
		}
		if strings.Contains(err.Error(), "10.") || strings.Contains(err.Error(), "192.168.") {
			t.Fatalf("transport error leaks private topology: %v", err)
		}
	}
}
