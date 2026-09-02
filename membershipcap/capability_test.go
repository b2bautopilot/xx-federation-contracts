package membershipcap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func mkCap() (Capability, ed25519.PrivateKey, []byte) {
	libpub, libpriv, _ := ed25519.GenerateKey(rand.Reader)
	cap := Capability{
		LibP2PPublicKey:      libpub,
		TenantHandle:         TenantHandle("018f-tenant", "cross-cloud-staging"),
		FabricID:             "cross-cloud-staging",
		CapabilityEpoch:      7,
		RevocationGeneration: 3,
		NotAfterMS:           1_000_000,
	}
	return cap, libpriv, libpub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cap, _, _ := mkCap()
	signed, err := Sign("membership-key-v1", signPriv, cap)
	if err != nil {
		t.Fatal(err)
	}
	if signed.SignerKeyID != "membership-key-v1" || len(signed.Signature) != ed25519.SignatureSize {
		t.Fatalf("unexpected signed cap: %+v", signed)
	}
	trusted := map[string]ed25519.PublicKey{"membership-key-v1": signPub}
	if err := signed.Verify(trusted, 999_999); err != nil {
		t.Fatalf("valid cap should verify: %v", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cap, _, _ := mkCap()
	signed, _ := Sign("k", signPriv, cap)
	trusted := map[string]ed25519.PublicKey{"k": signPub}

	// Tamper each signed field; every mutation must break the signature.
	for name, mutate := range map[string]func(*Capability){
		"epoch":  func(c *Capability) { c.CapabilityEpoch = 8 },
		"revgen": func(c *Capability) { c.RevocationGeneration = 4 },
		"handle": func(c *Capability) { c.TenantHandle = "other" },
		"fabric": func(c *Capability) { c.FabricID = "other" },
		"pubkey": func(c *Capability) { c.LibP2PPublicKey[0] ^= 0xff },
		"expiry": func(c *Capability) { c.NotAfterMS = 2_000_000 },
	} {
		bad := signed
		bad.LibP2PPublicKey = append([]byte(nil), signed.LibP2PPublicKey...)
		mutate(&bad)
		if err := bad.Verify(trusted, 0); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("tampering %q should fail signature, got %v", name, err)
		}
	}
}

func TestVerifyExpiryAndUnknownSigner(t *testing.T) {
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	cap, _, _ := mkCap()
	signed, _ := Sign("k", signPriv, cap)

	if err := signed.Verify(map[string]ed25519.PublicKey{"k": signPub}, 1_000_000); !errors.Is(err, ErrExpired) {
		t.Fatalf("at NotAfterMS should be expired, got %v", err)
	}
	if err := signed.Verify(map[string]ed25519.PublicKey{"other": signPub}, 0); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer should fail, got %v", err)
	}
	// A trusted signer whose key does not match the signature must fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := signed.Verify(map[string]ed25519.PublicKey{"k": otherPub}, 0); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong pubkey should fail signature, got %v", err)
	}
}

func TestProofOfPossession(t *testing.T) {
	_, libpriv, libpub := mkCap()
	challenge := []byte("issue-membership-nonce-abc123")
	sig := ed25519.Sign(libpriv, challenge)
	if err := VerifyProofOfPossession(libpub, challenge, sig); err != nil {
		t.Fatalf("valid PoP should pass: %v", err)
	}
	// Wrong challenge, wrong key, and short sig all reject.
	if err := VerifyProofOfPossession(libpub, []byte("different"), sig); !errors.Is(err, ErrProofOfPossession) {
		t.Fatal("PoP over the wrong challenge must fail")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyProofOfPossession(otherPub, challenge, sig); !errors.Is(err, ErrProofOfPossession) {
		t.Fatal("PoP against the wrong key must fail")
	}
	if err := VerifyProofOfPossession(libpub[:16], challenge, sig); !errors.Is(err, ErrBadKey) {
		t.Fatal("malformed key must fail")
	}
}

func TestTenantHandleOpaqueAndStable(t *testing.T) {
	h := TenantHandle("tenant-A", "fab")
	if h == "" || h == "tenant-A" {
		t.Fatalf("handle must be opaque, got %q", h)
	}
	if TenantHandle("tenant-A", "fab") != h {
		t.Fatal("handle must be deterministic")
	}
	if TenantHandle("tenant-B", "fab") == h || TenantHandle("tenant-A", "fab2") == h {
		t.Fatal("handle must vary by tenant and fabric")
	}
}

func TestEncodeDecodePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	round, err := DecodePublicKey(EncodePublicKey(pub))
	if err != nil || string(round) != string(pub) {
		t.Fatalf("pubkey encode/decode round-trip failed: %v", err)
	}
	if _, err := DecodePublicKey("not-base64!!"); !errors.Is(err, ErrBadKey) {
		t.Fatal("bad base64 should fail")
	}
	if _, err := DecodePublicKey(EncodePublicKey(pub[:8])); !errors.Is(err, ErrBadKey) {
		t.Fatal("wrong-length key should fail")
	}
}
