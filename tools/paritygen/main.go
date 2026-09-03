// Command paritygen deterministically regenerates the golden compatibility
// vectors under testdata/parity from the (contracts) implementations. Most
// ported bodies are byte-identical to their canonical sources (enumerated in
// the enclosing PR); the transport AAD encoding, identity binding, intake
// status gating, and error sanitization are deliberate fail-closed
// hardenings owned by this repository, so their vectors are generated here
// and pinned by the replay tests. Regenerating must produce zero diff — any
// diff means a wire/digest/decision contract drifted and fails review.
//
// Usage:
//
//	cd <repo root>
//	go run ./tools/paritygen
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/orgregistry"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/relaywire"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/transport"
	"github.com/b2bautopilot/xx-federation-contracts/gatewayregistration"
)

// relayCapture is a stub RelayConnector that records the sealed frame the
// Negotiator hands to the relay, so the fixture captures the associated data
// built by the real negotiation path (not a hand-constructed string).
type relayCapture struct {
	frame transport.RelayFrame
}

func (r *relayCapture) OpenRelay(_ context.Context, req transport.RelayRequest) (transport.RelaySession, error) {
	r.frame = req.Frame
	return transport.RelaySession{RemoteIdentity: req.ExpectedRemoteIdentity}, nil
}

func writeFixture(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join("testdata", "parity", name+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func main() {
	// ---- transport seal ----
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte(`{"schema_version":"builders.federation.gateway_exchange.v1"}`)
	local := transport.Identity{
		TenantID: "tenant-a", GatewayID: "gw-1", ServicePrincipalID: "sp-a",
		SPIFFEID: "spiffe-a", Subject: "sub-a", FingerprintSHA256: "fp-a",
		TrustRootID: "tr-a", TrustRootBundleSHA256: "trb-a",
	}
	remote := transport.Identity{
		TenantID: "tenant-b", GatewayID: "gw-2", ServicePrincipalID: "sp-b",
		SPIFFEID: "spiffe-b", Subject: "sub-b", FingerprintSHA256: "fp-b",
		TrustRootID: "tr-b", TrustRootBundleSHA256: "trb-b",
	}
	rec := &relayCapture{}
	negotiator := transport.NewNegotiator(nil, rec)
	if _, err := negotiator.Negotiate(context.Background(), transport.Request{
		PartnerLinkID:          "part",
		LocalIdentity:          local,
		ExpectedRemoteIdentity: remote,
		Policy:                 transport.Policy{DirectMode: transport.DirectModeDisabled, RelayFallbackAllowed: true},
		BootstrapServers:       []transport.BootstrapServer{{Endpoint: "relay.example", TrustRootRef: "tr", RendezvousNamespace: "ns"}},
		BusinessPayload:        plaintext,
		RelayPayloadKeyID:      "kv-1",
		RelayPayloadKey:        key,
	}); err != nil {
		panic(err)
	}
	// Deterministic reseal over the captured associated data for the vector.
	frame, err := transport.SealRelayPayload(plaintext, "kv-1", key, rec.frame.AssociatedData, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
	if err != nil {
		panic(err)
	}
	transportVec := map[string]any{
		"key_hex":        hex.EncodeToString(key),
		"aad_hex":        hex.EncodeToString(rec.frame.AssociatedData),
		"plaintext":      string(plaintext),
		"nonce_hex":      hex.EncodeToString(frame.Nonce),
		"ciphertext_hex": hex.EncodeToString(frame.Ciphertext),
	}
	if err := writeFixture("transport", transportVec); err != nil {
		panic(err)
	}

	// ---- relaywire frames ----
	frames := []relaywire.Control{
		{Type: relaywire.TypeRegister, Namespace: "fed-acme-receiver",
			TargetIdentity: transport.Identity{TenantID: "tenant-b", GatewayID: "gw-b"},
			SenderIdentity: transport.Identity{TenantID: "tenant-a", GatewayID: "gw-a"}},
		{Type: relaywire.TypeSubmit, Namespace: "fed-acme-receiver", PresenceRef: "pr_abcd1234deadbeef", OrgLevel: true, Hop: 0},
		{Type: relaywire.TypeDeliver, Namespace: "fed-acme-receiver", TargetIdentity: transport.Identity{TenantID: "tenant-a", GatewayID: "gw-a"}},
		{Type: relaywire.TypeEstablished, Namespace: "fed-acme-receiver"},
		{Type: relaywire.TypeError, ErrorCode: relaywire.ErrorMalformed},
		{Type: relaywire.TypeBackplaneSubmit, Namespace: "fed-acme-receiver", Hop: 1},
	}
	relayVec := map[string]string{}
	for _, f := range frames {
		var buf bytes.Buffer
		if err := relaywire.WriteControl(&buf, f); err != nil {
			panic(err)
		}
		relayVec[f.Type] = hex.EncodeToString(buf.Bytes())
	}
	if err := writeFixture("relaywire", relayVec); err != nil {
		panic(err)
	}

	// ---- orgregistry presence ----
	secret := []byte("epoch-secret")
	presenceVec := map[string]string{}
	for _, d := range []string{"acme.com", "example.org"} {
		presenceVec[d] = orgregistry.PresenceRef(secret, d)
	}
	if err := writeFixture("orgregistry", presenceVec); err != nil {
		panic(err)
	}

	// ---- gatewayregistration digests ----
	jcsInputs := []string{
		`{"b":2,"a":1}`,
		`{"n":1.0,"m":100}`,
		`{"a":[3,1,2],"s":"nested"}`,
		`{"u":"\u00fcn\u00ef"}`,
	}
	jcsVec := map[string]string{}
	for _, raw := range jcsInputs {
		cb, err := gatewayregistration.JCSCanonicalBytes([]byte(raw))
		if err != nil {
			panic(err)
		}
		jcsVec[raw] = hex.EncodeToString(cb)
	}
	lca := gatewayregistration.LocalControlAuthorization{
		SchemaVersion:       gatewayregistration.LocalControlAuthorizationVersion,
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
		CSRPublicKeyBinding: gatewayregistration.PublicKeyBinding{Alg: gatewayregistration.PublicKeyBindingAlgorithmSHA256SPKI, Value: "spki-1"},
		NotBeforeMS:         1000,
		ExpiresAtMS:         9000,
		SignatureAlg:        gatewayregistration.SignatureAlgorithmEd25519JCSV1,
		Signature:           "sig-1",
	}
	lcaCanonical, err := gatewayregistration.LocalControlAuthorizationCanonicalBytes(lca)
	if err != nil {
		panic(err)
	}
	lcaDigest, err := gatewayregistration.LocalControlAuthorizationDigestSHA256(lca)
	if err != nil {
		panic(err)
	}
	regVec := map[string]any{
		"jcs":           jcsVec,
		"lca_canonical": string(lcaCanonical),
		"lca_digest":    lcaDigest,
	}
	if err := writeFixture("gatewayregistration", regVec); err != nil {
		panic(err)
	}

	fmt.Println("parity fixtures regenerated under testdata/parity/")
}
