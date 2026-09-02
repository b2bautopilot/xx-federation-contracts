package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

func mkRosterEntry(t *testing.T) PeerRosterEntry {
	t.Helper()
	meshPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wg := make([]byte, wgPublicKeySize)
	if _, err := rand.Read(wg); err != nil {
		t.Fatal(err)
	}
	return PeerRosterEntry{
		MeshPubKeyEd25519: meshPub,
		PubKeyWG:          wg,
		MeshIP:            "fd7a:b1d2:1::1",
		FQName:            "relayA",
		Role:              "host",
		LibP2PPeerID:      "12D3KooWexample",
		Endpoints:         []string{"203.0.113.1:51820"},
	}
}

func mkRoster(entries ...PeerRosterEntry) FabricPeerRoster {
	return FabricPeerRoster{
		FabricID:   "cross-cloud-staging",
		Epoch:      7,
		IssuedAtMS: 1_000,
		NotAfterMS: 100_000,
		Entries:    entries,
	}
}

func TestFabricPeerRoster_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := SignFabricPeerRoster("mk-v1", priv, mkRoster(mkRosterEntry(t), mkRosterEntry(t)))
	if err != nil {
		t.Fatal(err)
	}
	if signed.SignerKeyID != "mk-v1" || len(signed.Signature) != ed25519.SignatureSize {
		t.Fatalf("unexpected signed roster: %+v", signed)
	}
	if err := signed.Verify(map[string]ed25519.PublicKey{"mk-v1": pub}, 50_000); err != nil {
		t.Fatalf("valid roster should verify: %v", err)
	}
}

func TestFabricPeerRoster_UntrustedSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := SignFabricPeerRoster("mk-v1", priv, mkRoster(mkRosterEntry(t)))
	// keyID absent from the trust map.
	if err := signed.Verify(map[string]ed25519.PublicKey{"someone-else": other}, 50_000); !errors.Is(err, ErrPeerRosterSigner) {
		t.Fatalf("want ErrPeerRosterSigner, got %v", err)
	}
	// keyID present but bound to the WRONG pubkey → signature fails.
	if err := signed.Verify(map[string]ed25519.PublicKey{"mk-v1": other}, 50_000); !errors.Is(err, ErrPeerRosterSignature) {
		t.Fatalf("wrong pubkey for keyID: want ErrPeerRosterSignature, got %v", err)
	}
}

func TestFabricPeerRoster_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := SignFabricPeerRoster("mk-v1", priv, mkRoster(mkRosterEntry(t)))
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	// nowMS == NotAfterMS is already expired (>=).
	if err := signed.Verify(trusted, 100_000); !errors.Is(err, ErrPeerRosterExpired) {
		t.Fatalf("at NotAfterMS: want ErrPeerRosterExpired, got %v", err)
	}
	if err := signed.Verify(trusted, 99_999); err != nil {
		t.Fatalf("one ms before expiry should verify: %v", err)
	}
}

// Non-vacuity: the entries (including the WG-path material) are covered by the
// signature — flipping one byte of an entry's PubKeyWG after signing must fail verify.
func TestFabricPeerRoster_TamperedEntryFailsVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := SignFabricPeerRoster("mk-v1", priv, mkRoster(mkRosterEntry(t)))
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	if err := signed.Verify(trusted, 50_000); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	signed.Entries[0].PubKeyWG[0] ^= 0xFF // tamper with the tunnel key
	if err := signed.Verify(trusted, 50_000); !errors.Is(err, ErrPeerRosterSignature) {
		t.Fatalf("tampered PubKeyWG: want ErrPeerRosterSignature, got %v", err)
	}
}

// Non-vacuity: tombstones are covered by the signature too (removal cannot be forged).
func TestFabricPeerRoster_TamperedTombstoneFailsVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	victim, _, _ := ed25519.GenerateKey(rand.Reader)
	r := mkRoster(mkRosterEntry(t))
	r.Tombstones = [][]byte{victim}
	signed, _ := SignFabricPeerRoster("mk-v1", priv, r)
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	if err := signed.Verify(trusted, 50_000); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	signed.Tombstones[0][0] ^= 0xFF
	if err := signed.Verify(trusted, 50_000); !errors.Is(err, ErrPeerRosterSignature) {
		t.Fatalf("tampered tombstone: want ErrPeerRosterSignature, got %v", err)
	}
}

func TestFabricPeerRoster_TamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := SignFabricPeerRoster("mk-v1", priv, mkRoster(mkRosterEntry(t)))
	signed.Signature[0] ^= 0xFF
	if err := signed.Verify(map[string]ed25519.PublicKey{"mk-v1": pub}, 50_000); !errors.Is(err, ErrPeerRosterSignature) {
		t.Fatalf("want ErrPeerRosterSignature, got %v", err)
	}
}

// The canonical bytes are order-independent: entries + tombstones in any slice order
// produce the SAME (deterministic ed25519) signature.
func TestFabricPeerRoster_CanonicalOrderIndependent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e1, e2, e3 := mkRosterEntry(t), mkRosterEntry(t), mkRosterEntry(t)
	tA, _, _ := ed25519.GenerateKey(rand.Reader)
	tB, _, _ := ed25519.GenerateKey(rand.Reader)

	r1 := mkRoster(e1, e2, e3)
	r1.Tombstones = [][]byte{tA, tB}
	r2 := mkRoster(e3, e1, e2) // entries reordered
	r2.Tombstones = [][]byte{tB, tA}

	s1, _ := SignFabricPeerRoster("mk-v1", priv, r1)
	s2, _ := SignFabricPeerRoster("mk-v1", priv, r2)
	if !bytes.Equal(s1.Signature, s2.Signature) {
		t.Fatal("reordered entries/tombstones must produce identical canonical signatures")
	}
}

// Domain separation: a RevocationList signature minted by the SAME membership key must
// NOT validate as a FabricPeerRoster (a captured revocation list cannot be replayed).
func TestFabricPeerRoster_DomainSeparatedFromRevocationList(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	rl, err := SignRevocationList("mk-v1", priv, mkList())
	if err != nil {
		t.Fatal(err)
	}
	// Carry the revocation-list signature into a roster shell.
	roster := FabricPeerRoster{FabricID: "cross-cloud-staging", SignerKeyID: "mk-v1", Signature: rl.Signature}
	if err := roster.Verify(trusted, 50_000); !errors.Is(err, ErrPeerRosterSignature) {
		t.Fatalf("a revocation-list signature must not validate a roster (domain separation), got %v", err)
	}
}

// Load-bearing domain test (the cross-type test above passes on content-difference
// alone): this FAILS iff the signing domain is dropped from peerRosterCanonicalBytes.
// A signature over the DOMAIN-LESS canonical JSON (what a domain-stripped verifier would
// accept) must be rejected.
func TestFabricPeerRoster_DomainIsEnforced(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := map[string]ed25519.PublicKey{"mk-v1": pub}
	r := mkRoster(mkRosterEntry(t))
	r.SignerKeyID = "mk-v1"
	r.Signature = nil
	r.Entries = sortedRosterEntries(r.Entries)
	r.Tombstones = sortedTombstones(r.Tombstones)
	raw, err := json.Marshal(r) // canonical JSON WITHOUT the domain prefix
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(priv, raw)
	if err := r.Verify(trusted, 50_000); err == nil {
		t.Fatal("Verify accepted a signature over domain-less JSON — the signing domain is not enforced")
	}
}

// An empty allow-list is structurally valid — it means "retain last-known-good" (the
// reconcile decides), NOT a validation error.
func TestFabricPeerRoster_ValidateEmptyRoster(t *testing.T) {
	if err := mkRoster().Validate(); err != nil {
		t.Fatalf("empty roster should validate (retain-last-known-good semantics): %v", err)
	}
}

// Validate rejects self-contradictory rosters (F3): a duplicated mesh identity, or a key
// that is both authorized (an entry) and de-peered (a tombstone) in one epoch.
func TestFabricPeerRoster_ValidateRejectsDuplicateAndConflict(t *testing.T) {
	dup1 := mkRosterEntry(t)
	dup2 := mkRosterEntry(t)
	dup2.MeshPubKeyEd25519 = append([]byte(nil), dup1.MeshPubKeyEd25519...) // same identity, different WG
	if err := mkRoster(dup1, dup2).Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("duplicate mesh key across entries must be rejected, got %v", err)
	}

	e := mkRosterEntry(t)
	r := mkRoster(e)
	r.Tombstones = [][]byte{append([]byte(nil), e.MeshPubKeyEd25519...)}
	if err := r.Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("a key that is both an entry and a tombstone must be rejected, got %v", err)
	}
}

// A garbage MeshIP (authorized-but-undeliverable) is rejected fail-closed (F2).
func TestFabricPeerRoster_ValidateRejectsNonIPMeshIP(t *testing.T) {
	bad := mkRosterEntry(t)
	bad.MeshIP = "not-an-ip-just-garbage"
	if err := mkRoster(bad).Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("non-IP mesh_ip must be rejected, got %v", err)
	}
}

// Epoch 0 collides with a verifier's "nothing applied yet" fence, so it is reserved.
func TestFabricPeerRoster_ValidateRejectsEpochZeroAndNegative(t *testing.T) {
	for _, ep := range []int64{0, -1} {
		r := mkRoster(mkRosterEntry(t))
		r.Epoch = ep
		if err := r.Validate(); !errors.Is(err, ErrPeerRosterEpoch) {
			t.Fatalf("epoch %d must be rejected, got %v", ep, err)
		}
	}
}

func TestFabricPeerRoster_BadPrivKey(t *testing.T) {
	if _, err := SignFabricPeerRoster("mk-v1", ed25519.PrivateKey("too-short"), mkRoster(mkRosterEntry(t))); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}

// Validate enforces the reachability invariant: an entry authorized-but-unreachable
// (no PubKeyWG / mis-sized key / no MeshIP) is rejected fail-closed.
func TestFabricPeerRoster_Validate(t *testing.T) {
	if err := mkRoster(mkRosterEntry(t), mkRosterEntry(t)).Validate(); err != nil {
		t.Fatalf("a fully-formed roster should validate: %v", err)
	}

	noWG := mkRosterEntry(t)
	noWG.PubKeyWG = nil
	if err := mkRoster(noWG).Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("missing PubKeyWG must be rejected (no tunnel without it), got %v", err)
	}

	shortWG := mkRosterEntry(t)
	shortWG.PubKeyWG = make([]byte, 16)
	if err := mkRoster(shortWG).Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("mis-sized PubKeyWG must be rejected, got %v", err)
	}

	badMesh := mkRosterEntry(t)
	badMesh.MeshPubKeyEd25519 = make([]byte, 8)
	if err := mkRoster(badMesh).Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("mis-sized mesh pubkey must be rejected, got %v", err)
	}

	noIP := mkRosterEntry(t)
	noIP.MeshIP = ""
	if err := mkRoster(noIP).Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("missing MeshIP must be rejected, got %v", err)
	}

	r := mkRoster(mkRosterEntry(t))
	r.Tombstones = [][]byte{make([]byte, 8)} // mis-sized tombstone
	if err := r.Validate(); !errors.Is(err, ErrPeerRosterEntry) {
		t.Fatalf("mis-sized tombstone must be rejected, got %v", err)
	}
}
