package serviceaccesscap

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func validTombstone(t *testing.T, issuerKeyID string, priv ed25519.PrivateKey) RevocationTombstone {
	t.Helper()
	tomb, err := SignTombstone(issuerKeyID, priv, RevocationTombstone{
		Resource:   "gcpco/control-grpc",
		Nonce:      "nonce-abc",
		NotAfterMS: 2_000,
	})
	if err != nil {
		t.Fatalf("SignTombstone: %v", err)
	}
	return tomb
}

func TestTombstoneSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tomb := validTombstone(t, "issuer-1", priv)
	trusted := map[string]ed25519.PublicKey{"issuer-1": pub}
	if err := tomb.Verify(trusted); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if tomb.Issuer != "issuer-1" || len(tomb.Signature) != ed25519.SignatureSize {
		t.Fatalf("sign did not stamp issuer/signature")
	}
}

func TestTombstoneEmptyKeyringDenies(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tomb := validTombstone(t, "issuer-1", priv)
	if err := tomb.Verify(map[string]ed25519.PublicKey{}); !errors.Is(err, ErrEmptyKeyring) {
		t.Fatalf("empty keyring must deny, got %v", err)
	}
}

func TestTombstoneUnknownSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	tomb := validTombstone(t, "issuer-1", priv)
	if err := tomb.Verify(map[string]ed25519.PublicKey{"issuer-2": otherPub}); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer must fail, got %v", err)
	}
}

func TestTombstoneTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	trusted := map[string]ed25519.PublicKey{"issuer-1": pub}
	for _, tc := range []struct {
		name   string
		mutate func(*RevocationTombstone)
	}{
		{"nonce", func(tt *RevocationTombstone) { tt.Nonce = "other" }},
		{"resource", func(tt *RevocationTombstone) { tt.Resource = "gcpco/control-pg" }},
		{"notafter", func(tt *RevocationTombstone) { tt.NotAfterMS += 1000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tomb := validTombstone(t, "issuer-1", priv)
			tc.mutate(&tomb)
			if err := tomb.Verify(trusted); err == nil {
				t.Fatalf("tamper must be rejected")
			}
		})
	}
}

func TestSignTombstoneRejectsBadShape(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, err := SignTombstone("i", priv, RevocationTombstone{Resource: "noslash", Nonce: "n", NotAfterMS: 1}); !errors.Is(err, ErrBadResource) {
		t.Fatalf("bad resource: %v", err)
	}
	if _, err := SignTombstone("i", priv, RevocationTombstone{Resource: "a/b", Nonce: "", NotAfterMS: 1}); !errors.Is(err, ErrTombstoneMalformed) {
		t.Fatalf("empty nonce: %v", err)
	}
	if _, err := SignTombstone("i", priv, RevocationTombstone{Resource: "a/b", Nonce: "n", NotAfterMS: 0}); !errors.Is(err, ErrTombstoneMalformed) {
		t.Fatalf("zero not_after: %v", err)
	}
}
