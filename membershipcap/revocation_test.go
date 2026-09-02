package membershipcap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func mkEntry(epoch, revgen int64, revoked bool) (RevocationEntry, []byte) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return RevocationEntry{
		LibP2PPublicKey:      pub,
		CapabilityEpoch:      epoch,
		RevocationGeneration: revgen,
		Revoked:              revoked,
	}, pub
}

func mkList(entries ...RevocationEntry) RevocationList {
	return RevocationList{
		FabricID:       "cross-cloud-staging",
		ListGeneration: 42,
		IssuedAtMS:     1_000,
		NotAfterMS:     100_000,
		Entries:        entries,
	}
}

func TestRevocationSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e1, _ := mkEntry(3, 1, false)
	e2, _ := mkEntry(1, 2, true)
	signed, err := SignRevocationList("rl-key-v1", priv, mkList(e1, e2))
	if err != nil {
		t.Fatal(err)
	}
	if signed.SignerKeyID != "rl-key-v1" || len(signed.Signature) != ed25519.SignatureSize {
		t.Fatalf("unexpected signed list: %+v", signed)
	}
	if err := signed.Verify(map[string]ed25519.PublicKey{"rl-key-v1": pub}, 50_000); err != nil {
		t.Fatalf("valid list should verify: %v", err)
	}
}

func TestRevocationVerifyRejectsTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e1, _ := mkEntry(3, 1, false)
	signed, _ := SignRevocationList("k", priv, mkList(e1))
	trusted := map[string]ed25519.PublicKey{"k": pub}

	for name, mutate := range map[string]func(*RevocationList){
		"fabric":     func(l *RevocationList) { l.FabricID = "other" },
		"generation": func(l *RevocationList) { l.ListGeneration = 99 },
		"expiry":     func(l *RevocationList) { l.NotAfterMS = 200_000 },
		"entryEpoch": func(l *RevocationList) { l.Entries[0].CapabilityEpoch = 9 },
		"entryRevgn": func(l *RevocationList) { l.Entries[0].RevocationGeneration = 9 },
		"entryFlag":  func(l *RevocationList) { l.Entries[0].Revoked = true },
		"entryKey":   func(l *RevocationList) { l.Entries[0].LibP2PPublicKey[0] ^= 0xff },
	} {
		bad := signed
		bad.Entries = append([]RevocationEntry(nil), signed.Entries...)
		bad.Entries[0].LibP2PPublicKey = append([]byte(nil), signed.Entries[0].LibP2PPublicKey...)
		mutate(&bad)
		if err := bad.Verify(trusted, 0); !errors.Is(err, ErrRevocationSignature) {
			t.Fatalf("tampering %q should break the signature, got %v", name, err)
		}
	}
}

func TestRevocationVerifyExpiryAndUnknownSigner(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e1, _ := mkEntry(3, 1, false)
	signed, _ := SignRevocationList("k", priv, mkList(e1))

	if err := signed.Verify(map[string]ed25519.PublicKey{"k": pub}, 100_000); !errors.Is(err, ErrRevocationExpired) {
		t.Fatalf("at NotAfterMS should be expired, got %v", err)
	}
	if err := signed.Verify(map[string]ed25519.PublicKey{"other": pub}, 0); !errors.Is(err, ErrRevocationSigner) {
		t.Fatalf("unknown signer should fail, got %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := signed.Verify(map[string]ed25519.PublicKey{"k": otherPub}, 0); !errors.Is(err, ErrRevocationSignature) {
		t.Fatalf("wrong pubkey should fail signature, got %v", err)
	}
}

// Entry order must not affect the signature: an assembler iterating the store in
// any order produces the same signed bytes.
func TestRevocationSignatureIsOrderIndependent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e1, _ := mkEntry(3, 1, false)
	e2, _ := mkEntry(1, 2, true)
	e3, _ := mkEntry(5, 0, false)

	a, _ := SignRevocationList("k", priv, mkList(e1, e2, e3))
	b, _ := SignRevocationList("k", priv, mkList(e3, e1, e2)) // shuffled

	// Both must verify, and a signature made over one order must validate a list
	// presented in the other order.
	trusted := map[string]ed25519.PublicKey{"k": pub}
	if err := a.Verify(trusted, 0); err != nil {
		t.Fatalf("list a should verify: %v", err)
	}
	shuffled := a
	shuffled.Entries = []RevocationEntry{e3, e1, e2}
	if err := shuffled.Verify(trusted, 0); err != nil {
		t.Fatalf("a's signature must validate a reordered entry slice: %v", err)
	}
	if string(a.Signature) != string(b.Signature) {
		t.Fatal("signatures over the same entry set must be identical regardless of order")
	}
}

func TestRevocationCheckFencing(t *testing.T) {
	active, activeKey := mkEntry(2, 1, false)
	revoked, revokedKey := mkEntry(1, 3, true)
	list := mkList(active, revoked)

	// Present, active, capability epoch/revgen at least the listed values → valid.
	if st := list.Check(Capability{LibP2PPublicKey: activeKey, CapabilityEpoch: 2, RevocationGeneration: 1}); st != FenceValid {
		t.Fatalf("matching active capability = %v, want FenceValid", st)
	}
	// Present but revoked → revoked, regardless of the capability's own fields.
	if st := list.Check(Capability{LibP2PPublicKey: revokedKey, CapabilityEpoch: 1, RevocationGeneration: 3}); st != FenceRevoked {
		t.Fatalf("revoked peer = %v, want FenceRevoked", st)
	}
	// Superseded by a newer key epoch → revoked.
	if st := list.Check(Capability{LibP2PPublicKey: activeKey, CapabilityEpoch: 1, RevocationGeneration: 1}); st != FenceRevoked {
		t.Fatalf("stale-epoch capability = %v, want FenceRevoked", st)
	}
	// Capability predating a newer revocation generation → revoked.
	if st := list.Check(Capability{LibP2PPublicKey: activeKey, CapabilityEpoch: 2, RevocationGeneration: 0}); st != FenceRevoked {
		t.Fatalf("stale-revgen capability = %v, want FenceRevoked", st)
	}
	// Absent peer → unknown (caller decides allow vs deny).
	absent, _, _ := ed25519.GenerateKey(rand.Reader)
	if st := list.Check(Capability{LibP2PPublicKey: absent, CapabilityEpoch: 1, RevocationGeneration: 1}); st != FenceUnknown {
		t.Fatalf("absent peer = %v, want FenceUnknown", st)
	}
}

// If the SAME key appears twice — once active, once revoked — revocation must win,
// regardless of entry order, so a duplicate can never downgrade a revoked peer.
func TestRevocationCheckDuplicateKeyRevocationWins(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	active := RevocationEntry{LibP2PPublicKey: pub, CapabilityEpoch: 2, RevocationGeneration: 1, Revoked: false}
	revoked := RevocationEntry{LibP2PPublicKey: pub, CapabilityEpoch: 1, RevocationGeneration: 3, Revoked: true}
	cap := Capability{LibP2PPublicKey: pub, CapabilityEpoch: 2, RevocationGeneration: 1}

	for _, list := range []RevocationList{mkList(active, revoked), mkList(revoked, active)} {
		if st := list.Check(cap); st != FenceRevoked {
			t.Fatalf("duplicate-key check = %v, want FenceRevoked (revocation wins) for entries %+v", st, list.Entries)
		}
	}
}
