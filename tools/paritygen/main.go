// Command paritygen deterministically regenerates the golden compatibility
// vectors under testdata/parity from the (contracts) implementations. The ported
// bodies are byte-identical to their canonical pre-move sources (enumerated in
// the enclosing PR), so regenerating here reproduces the vectors captured from
// the pre-move implementation. The replay tests verify the code reproduces these
// fixtures, so a silent drift in any wire/digest/decision contract fails CI.
//
// Usage:
//
//	cd <repo root>
//	go run ./tools/paritygen
package main

import (
	"bytes"
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
	aad := []byte("part|tenant-a|gw-1|sp-a|spiffe-a|sub-a|fp-a|tr-a|trb-a|tenant-b|gw-2|sp-b|spiffe-b|sub-b|fp-b|tr-b|trb-b")
	plaintext := []byte(`{"schema_version":"builders.federation.gateway_exchange.v1"}`)
	frame, err := transport.SealRelayPayload(plaintext, "kv-1", key, aad, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
	if err != nil {
		panic(err)
	}
	transportVec := map[string]any{
		"key_hex":        hex.EncodeToString(key),
		"aad":            string(aad),
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
