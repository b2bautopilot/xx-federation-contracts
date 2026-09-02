package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func claimWithKey(t *testing.T, meshPub []byte, fqname, meshIP string, issuedAt int64) MeshRegistrationClaim {
	t.Helper()
	wg := make([]byte, wgPublicKeySize)
	if _, err := rand.Read(wg); err != nil {
		t.Fatal(err)
	}
	return MeshRegistrationClaim{
		MeshPubKeyEd25519: meshPub, PubKeyWG: wg, MeshIP: meshIP,
		FQName: fqname, Role: "host", IssuedAtMS: issuedAt,
	}
}

// verified wraps a claim for assembler-logic tests (the assembler does not re-check the PoP).
// The real construction path (AsVerified) is exercised by the e2e test below.
func verified(c MeshRegistrationClaim) VerifiedMeshRegistration {
	return VerifiedMeshRegistration{claim: c}
}

func vClaims(cs ...MeshRegistrationClaim) []VerifiedMeshRegistration {
	out := make([]VerifiedMeshRegistration, len(cs))
	for i, c := range cs {
		out[i] = verified(c)
	}
	return out
}

func TestAssemble_SignsValidRoster(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	a := RosterAssembly{
		FabricID: "fed", Epoch: 3, IssuedAtMS: 1000, TTLMS: 60_000,
		Claims: vClaims(
			claimWithKey(t, mustKey(t), "relayA", "fd7a::1", 900),
			claimWithKey(t, mustKey(t), "relayB", "fd7a::2", 950),
		),
	}
	roster, err := AssembleFabricPeerRoster("mk-v1", priv, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.Verify(trusted, 30_000); err != nil {
		t.Fatalf("assembled roster must verify: %v", err)
	}
	if len(roster.Entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(roster.Entries))
	}
	if roster.NotAfterMS != 1000+60_000 {
		t.Fatalf("NotAfterMS=%d, want %d", roster.NotAfterMS, 1000+60_000)
	}
	if roster.Epoch != 3 {
		t.Fatalf("epoch=%d, want 3", roster.Epoch)
	}
}

// A re-registration (same mesh key, higher IssuedAtMS) supersedes the older one, regardless of
// input order.
func TestAssemble_DedupPickIsOrderIndependent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k := mustKey(t)
	old := claimWithKey(t, k, "relay-old", "fd7a::1", 100)
	fresh := claimWithKey(t, k, "relay-new", "fd7a::9", 200)
	for _, order := range [][]VerifiedMeshRegistration{vClaims(old, fresh), vClaims(fresh, old)} {
		a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000, Claims: order}
		roster, err := AssembleFabricPeerRoster("mk-v1", priv, a)
		if err != nil {
			t.Fatal(err)
		}
		if len(roster.Entries) != 1 || roster.Entries[0].FQName != "relay-new" {
			t.Fatalf("freshest must win regardless of order: %+v", roster.Entries)
		}
	}
}

// An equal-IssuedAtMS tie resolves deterministically by PoP bytes (the larger wins).
func TestAssemble_EqualIssuedAtTieIsDeterministic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k := mustKey(t)
	c1 := claimWithKey(t, k, "relay-1", "fd7a::1", 100)
	c1.ProofOfPossession = []byte{0x01}
	c2 := claimWithKey(t, k, "relay-2", "fd7a::2", 100) // same key + IssuedAt, distinct PoP
	c2.ProofOfPossession = []byte{0x02}
	base := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000}
	a1, a2 := base, base
	a1.Claims = vClaims(c1, c2)
	a2.Claims = vClaims(c2, c1)
	r1, err := AssembleFabricPeerRoster("mk-v1", priv, a1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := AssembleFabricPeerRoster("mk-v1", priv, a2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1.Signature, r2.Signature) {
		t.Fatal("equal-IssuedAtMS tie must resolve deterministically (by PoP) regardless of order")
	}
	if len(r1.Entries) != 1 || r1.Entries[0].FQName != "relay-2" {
		t.Fatalf("tie-break must pick the larger PoP: %+v", r1.Entries)
	}
}

// An explicit tombstone overrides a registration for the same key (de-peer wins), so the
// roster is never self-contradictory (which Validate would reject).
func TestAssemble_TombstoneOverridesClaim(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k := mustKey(t)
	a := RosterAssembly{
		FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000,
		Claims:     vClaims(claimWithKey(t, k, "relayK", "fd7a::1", 100)),
		Tombstones: [][]byte{k},
	}
	roster, err := AssembleFabricPeerRoster("mk-v1", priv, a)
	if err != nil {
		t.Fatalf("tombstone+claim for one key must assemble (tombstone wins): %v", err)
	}
	if len(roster.Entries) != 0 {
		t.Fatalf("entries=%d, want 0 (key tombstoned)", len(roster.Entries))
	}
	if len(roster.Tombstones) != 1 {
		t.Fatalf("tombstones=%d, want 1", len(roster.Tombstones))
	}
}

func TestAssemble_TombstoneForNonClaimKeySurvives(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tk := mustKey(t)
	a := RosterAssembly{
		FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000,
		Claims:     vClaims(claimWithKey(t, mustKey(t), "a", "fd7a::1", 1)),
		Tombstones: [][]byte{tk},
	}
	roster, err := AssembleFabricPeerRoster("mk-v1", priv, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Entries) != 1 || len(roster.Tombstones) != 1 {
		t.Fatalf("want 1 entry + 1 tombstone, got %d/%d", len(roster.Entries), len(roster.Tombstones))
	}
}

func TestAssemble_DedupsTombstones(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tk := mustKey(t)
	a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000, Tombstones: [][]byte{tk, tk, append([]byte(nil), tk...)}}
	roster, err := AssembleFabricPeerRoster("mk-v1", priv, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Tombstones) != 1 {
		t.Fatalf("tombstones=%d, want 1 (deduped)", len(roster.Tombstones))
	}
}

func TestAssemble_MalformedTombstoneFailsClosed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000, Tombstones: [][]byte{make([]byte, 8)}}
	if _, err := AssembleFabricPeerRoster("mk-v1", priv, a); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("malformed tombstone must fail (via roster Validate), got %v", err)
	}
}

// Assembly is deterministic: the same claims in any order sign identically.
func TestAssemble_DeterministicRegardlessOfOrder(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c1 := claimWithKey(t, mustKey(t), "a", "fd7a::1", 1)
	c2 := claimWithKey(t, mustKey(t), "b", "fd7a::2", 2)
	c3 := claimWithKey(t, mustKey(t), "c", "fd7a::3", 3)
	base := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000}
	a1, a2 := base, base
	a1.Claims = vClaims(c1, c2, c3)
	a2.Claims = vClaims(c3, c1, c2)
	r1, err := AssembleFabricPeerRoster("mk-v1", priv, a1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := AssembleFabricPeerRoster("mk-v1", priv, a2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1.Signature, r2.Signature) {
		t.Fatal("assembly must be deterministic regardless of claim order")
	}
}

// Fail-closed: a claim that projects to an invalid entry (bad path material) is never signed.
func TestAssemble_FailsClosedOnInvalidClaim(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	bad := claimWithKey(t, mustKey(t), "relayBad", "not-an-ip", 100)
	a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000, Claims: vClaims(bad)}
	if _, err := AssembleFabricPeerRoster("mk-v1", priv, a); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("a claim projecting to an invalid entry must fail assembly, got %v", err)
	}
}

func TestAssemble_RejectsEpochZero(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := RosterAssembly{FabricID: "fed", Epoch: 0, IssuedAtMS: 1000, TTLMS: 60_000, Claims: vClaims(claimWithKey(t, mustKey(t), "a", "fd7a::1", 1))}
	if _, err := AssembleFabricPeerRoster("mk-v1", priv, a); !errors.Is(err, ErrPeerRosterEpoch) {
		t.Fatalf("epoch 0 must be rejected, got %v", err)
	}
}

// A short TTL is mandatory: a non-positive IssuedAtMS or TTLMS is rejected (no immortal roster).
func TestAssemble_RequiresPositiveIssuedAtAndTTL(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	entry := vClaims(claimWithKey(t, mustKey(t), "a", "fd7a::1", 1))
	for _, tc := range []struct {
		name        string
		issued, ttl int64
	}{
		{"ttl 0 (immortal roster)", 1000, 0},
		{"issued 0", 0, 60_000},
		{"issued negative", -5, 60_000},
		{"ttl negative", 1000, -1},
	} {
		a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: tc.issued, TTLMS: tc.ttl, Claims: entry}
		if _, err := AssembleFabricPeerRoster("mk-v1", priv, a); !errors.Is(err, ErrRosterAssembly) {
			t.Fatalf("%s: want ErrRosterAssembly, got %v", tc.name, err)
		}
	}
}

func TestAssemble_EmptyIsValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	roster, err := AssembleFabricPeerRoster("mk-v1", priv, RosterAssembly{FabricID: "fed", Epoch: 5, IssuedAtMS: 1000, TTLMS: 60_000})
	if err != nil {
		t.Fatalf("empty assembly should sign a valid empty roster: %v", err)
	}
	if err := roster.Verify(trusted, 30_000); err != nil {
		t.Fatal(err)
	}
	if len(roster.Entries) != 0 {
		t.Fatal("want 0 entries")
	}
}

// BuildFabricPeerRoster returns an UNSIGNED roster; signing it externally (as the
// control-plane MembershipSigner interface does) equals the one-shot Assemble path.
func TestBuildFabricPeerRoster_UnsignedThenExternalSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000,
		Claims: vClaims(claimWithKey(t, mustKey(t), "a", "fd7a::1", 1))}

	built, err := BuildFabricPeerRoster(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Signature) != 0 || built.SignerKeyID != "" {
		t.Fatalf("BuildFabricPeerRoster must return an UNSIGNED roster, got sig=%d keyid=%q", len(built.Signature), built.SignerKeyID)
	}
	signed, err := SignFabricPeerRoster("mk-v1", priv, built)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Verify(trusted, 30_000); err != nil {
		t.Fatalf("build-then-sign must verify: %v", err)
	}
	assembled, err := AssembleFabricPeerRoster("mk-v1", priv, a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed.Signature, assembled.Signature) {
		t.Fatal("build+sign must equal one-shot assemble")
	}
	bad := a
	bad.TTLMS = 0
	if _, err := BuildFabricPeerRoster(bad); !errors.Is(err, ErrRosterAssembly) {
		t.Fatalf("build must reject TTLMS<=0, got %v", err)
	}
}

func TestAssemble_BadSignerKey(t *testing.T) {
	a := RosterAssembly{FabricID: "fed", Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000, Claims: vClaims(claimWithKey(t, mustKey(t), "a", "fd7a::1", 1))}
	if _, err := AssembleFabricPeerRoster("mk-v1", ed25519.PrivateKey("short"), a); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}

// The full G1 -> G2 chain via the REAL construction path: a daemon's registration is verified
// through AsVerified, assembled, and the signed roster's entry carries the material intact.
func TestAssemble_EndToEndFromVerifiedRegistration(t *testing.T) {
	mkPub, mkPriv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := map[string]ed25519.PublicKey{"mk-v1": mkPub}

	claim, meshPriv, _ := mkMeshClaim(t)
	signed, err := SignMeshRegistration(meshPriv, regFabric, regGateway, regBinding, claim)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signed.AsVerified(regFabric, regGateway, regBinding)
	if err != nil {
		t.Fatalf("AsVerified must succeed for a genuine registration: %v", err)
	}
	roster, err := AssembleFabricPeerRoster("mk-v1", mkPriv, RosterAssembly{
		FabricID: regFabric, Epoch: 1, IssuedAtMS: 1000, TTLMS: 60_000,
		Claims: []VerifiedMeshRegistration{v},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.Verify(trusted, 30_000); err != nil {
		t.Fatalf("assembled roster must verify: %v", err)
	}
	if len(roster.Entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(roster.Entries))
	}
	e := roster.Entries[0]
	if !bytes.Equal(e.MeshPubKeyEd25519, signed.MeshPubKeyEd25519) || !bytes.Equal(e.PubKeyWG, signed.PubKeyWG) || e.LibP2PPeerID != signed.LibP2PPeerID {
		t.Fatal("assembled entry lost the registered path/identity material")
	}
}

// AsVerified rejects a registration whose PoP does not match the identity — an unverified claim
// cannot be wrapped and thus cannot reach the assembler.
func TestAsVerified_RejectsBadRegistration(t *testing.T) {
	claim, meshPriv, _ := mkMeshClaim(t)
	signed, _ := SignMeshRegistration(meshPriv, regFabric, regGateway, regBinding, claim)
	if _, err := signed.AsVerified(regFabric, "gw-attacker", regBinding); err == nil {
		t.Fatal("AsVerified must reject a claim whose PoP does not match the identity")
	}
}
