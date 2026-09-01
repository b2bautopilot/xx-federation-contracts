package serviceaccesscap

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// helpers ---------------------------------------------------------------------

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// a valid, signed capability for tests to mutate.
func validCap(t *testing.T, issuerKeyID string, issuerPriv ed25519.PrivateKey, subjectPub ed25519.PublicKey) Capability {
	t.Helper()
	c, err := Sign(issuerKeyID, issuerPriv, Capability{
		SubjectPublicKey: subjectPub,
		Resource:         "gcpco/control-grpc",
		Scope:            "reach",
		IssuedAtMS:       1_000,
		ExpiresAtMS:      1_000 + 15*60*1000,
		Nonce:            "nonce-abc",
	})
	if err != nil {
		t.Fatalf("Sign valid cap: %v", err)
	}
	return c
}

// Sign + Verify ---------------------------------------------------------------

func TestSignVerifyRoundTrip(t *testing.T) {
	issuerPub, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub)

	trusted := map[string]ed25519.PublicKey{"issuer-1": issuerPub}
	if err := c.Verify(trusted, 1_000); err != nil {
		t.Fatalf("Verify at issue time: %v", err)
	}
	// just before expiry
	if err := c.Verify(trusted, c.ExpiresAtMS-1); err != nil {
		t.Fatalf("Verify just before expiry: %v", err)
	}
	if c.Issuer != "issuer-1" {
		t.Fatalf("Sign did not stamp Issuer, got %q", c.Issuer)
	}
	if len(c.Signature) != ed25519.SignatureSize {
		t.Fatalf("Sign did not stamp a signature")
	}
}

func TestVerifyExpired(t *testing.T) {
	issuerPub, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub)
	trusted := map[string]ed25519.PublicKey{"issuer-1": issuerPub}

	if err := c.Verify(trusted, c.ExpiresAtMS); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired at exactly expiry, got %v", err)
	}
	if err := c.Verify(trusted, c.ExpiresAtMS+1); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired past expiry, got %v", err)
	}
}

func TestSignRejectsNoExpiry(t *testing.T) {
	_, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	_, err := Sign("issuer-1", issuerPriv, Capability{
		SubjectPublicKey: subjectPub,
		Resource:         "gcpco/control-grpc",
		IssuedAtMS:       1_000,
		ExpiresAtMS:      0, // no expiry
	})
	if !errors.Is(err, ErrNoExpiry) {
		t.Fatalf("expected ErrNoExpiry when ExpiresAtMS==0, got %v", err)
	}
}

func TestVerifyRejectsNoExpiryEvenIfSignatureForged(t *testing.T) {
	// A cap that somehow has a zero expiry must be rejected by Verify too, not only Sign.
	issuerPub, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := Capability{
		SubjectPublicKey: subjectPub,
		Resource:         "gcpco/control-grpc",
		IssuedAtMS:       1_000,
		ExpiresAtMS:      0,
		Issuer:           "issuer-1",
	}
	// sign it directly, bypassing Sign()'s guard, to simulate a hostile issuer
	b, _ := canonicalBytes(c)
	c.Signature = ed25519.Sign(issuerPriv, b)

	trusted := map[string]ed25519.PublicKey{"issuer-1": issuerPub}
	if err := c.Verify(trusted, 1_001); !errors.Is(err, ErrNoExpiry) {
		t.Fatalf("expected ErrNoExpiry from Verify, got %v", err)
	}
}

func TestVerifyEmptyKeyringDeniesAll(t *testing.T) {
	_, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub)

	if err := c.Verify(map[string]ed25519.PublicKey{}, 1_000); !errors.Is(err, ErrEmptyKeyring) {
		t.Fatalf("expected ErrEmptyKeyring for empty map, got %v", err)
	}
	if err := c.Verify(nil, 1_000); !errors.Is(err, ErrEmptyKeyring) {
		t.Fatalf("expected ErrEmptyKeyring for nil map, got %v", err)
	}
}

func TestVerifyUnknownSigner(t *testing.T) {
	_, issuerPriv := mustKeypair(t)
	otherPub, _ := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub)

	// keyring is non-empty but does not contain issuer-1
	trusted := map[string]ed25519.PublicKey{"issuer-2": otherPub}
	if err := c.Verify(trusted, 1_000); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("expected ErrUnknownSigner, got %v", err)
	}
}

func TestVerifyTamperDetected(t *testing.T) {
	issuerPub, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	trusted := map[string]ed25519.PublicKey{"issuer-1": issuerPub}

	for _, tc := range []struct {
		name   string
		mutate func(*Capability)
	}{
		{"resource", func(c *Capability) { c.Resource = "gcpco/control-pg" }},
		{"scope", func(c *Capability) { c.Scope = "admin" }},
		{"expires", func(c *Capability) { c.ExpiresAtMS += 3600_000 }},
		{"issuedat", func(c *Capability) { c.IssuedAtMS -= 1 }},
		{"nonce", func(c *Capability) { c.Nonce = "different" }},
		{"spiffe", func(c *Capability) { c.SubjectSPIFFE = "spiffe://evil" }},
		{"subjectkey", func(c *Capability) {
			np, _ := mustKeypair(t)
			c.SubjectPublicKey = np
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validCap(t, "issuer-1", issuerPriv, subjectPub)
			tc.mutate(&c)
			if err := c.Verify(trusted, 1_000); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrBadKey) {
				t.Fatalf("expected tamper to be rejected, got %v", err)
			}
		})
	}
}

func TestVerifyBadSubjectKey(t *testing.T) {
	issuerPub, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub)
	c.SubjectPublicKey = []byte{1, 2, 3} // wrong length
	trusted := map[string]ed25519.PublicKey{"issuer-1": issuerPub}
	if err := c.Verify(trusted, 1_000); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected ErrBadKey, got %v", err)
	}
}

func TestSignRejectsBadInputs(t *testing.T) {
	_, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)

	if _, err := Sign("issuer-1", []byte{1, 2}, Capability{SubjectPublicKey: subjectPub, Resource: "a/b", ExpiresAtMS: 2, IssuedAtMS: 1}); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected ErrBadKey for short priv, got %v", err)
	}
	if _, err := Sign("issuer-1", issuerPriv, Capability{SubjectPublicKey: []byte{1}, Resource: "a/b", ExpiresAtMS: 2, IssuedAtMS: 1}); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected ErrBadKey for short subject key, got %v", err)
	}
	if _, err := Sign("issuer-1", issuerPriv, Capability{SubjectPublicKey: subjectPub, Resource: "no-slash", ExpiresAtMS: 2, IssuedAtMS: 1}); !errors.Is(err, ErrBadResource) {
		t.Fatalf("expected ErrBadResource, got %v", err)
	}
	if _, err := Sign("issuer-1", issuerPriv, Capability{SubjectPublicKey: subjectPub, Resource: "a/b", ExpiresAtMS: 5, IssuedAtMS: 5}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired when expiry<=issued, got %v", err)
	}
}

// binding + resource ----------------------------------------------------------

func TestBindsPublicKey(t *testing.T) {
	_, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	otherPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub)

	if !c.BindsPublicKey(subjectPub) {
		t.Fatalf("expected BindsPublicKey true for the bound key")
	}
	if c.BindsPublicKey(otherPub) {
		t.Fatalf("expected BindsPublicKey false for a different key (stolen-cap replay)")
	}
	if c.BindsPublicKey([]byte{1, 2, 3}) {
		t.Fatalf("expected BindsPublicKey false for malformed key")
	}
}

func TestAuthorizesResource(t *testing.T) {
	_, issuerPriv := mustKeypair(t)
	subjectPub, _ := mustKeypair(t)
	c := validCap(t, "issuer-1", issuerPriv, subjectPub) // resource gcpco/control-grpc

	if !c.AuthorizesResource("gcpco/control-grpc") {
		t.Fatalf("expected AuthorizesResource true for the exact namespace")
	}
	if c.AuthorizesResource("gcpco/control-pg") {
		t.Fatalf("expected AuthorizesResource false for a different namespace (cross-service replay)")
	}
	if c.AuthorizesResource("") {
		t.Fatalf("expected AuthorizesResource false for empty namespace")
	}
}

func TestParseResource(t *testing.T) {
	for _, ok := range []string{"gcpco/control-grpc", "awsco/some-svc"} {
		if _, _, err := ParseResource(ok); err != nil {
			t.Fatalf("ParseResource(%q) unexpected err: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "noslash", "/svc", "org/", "a/b/c", "org//"} {
		if _, _, err := ParseResource(bad); !errors.Is(err, ErrBadResource) {
			t.Fatalf("ParseResource(%q) expected ErrBadResource, got %v", bad, err)
		}
	}
	org, svc, err := ParseResource("gcpco/control-grpc")
	if err != nil || org != "gcpco" || svc != "control-grpc" {
		t.Fatalf("ParseResource split wrong: %q %q %v", org, svc, err)
	}
}

// proof of possession ---------------------------------------------------------

func TestVerifyProofOfPossession(t *testing.T) {
	subjectPub, subjectPriv := mustKeypair(t)
	challenge := []byte("issuer-nonce-xyz")
	sig := ed25519.Sign(subjectPriv, challenge)

	if err := VerifyProofOfPossession(subjectPub, challenge, sig); err != nil {
		t.Fatalf("expected valid PoP, got %v", err)
	}
	// wrong signer
	_, otherPriv := mustKeypair(t)
	if err := VerifyProofOfPossession(subjectPub, challenge, ed25519.Sign(otherPriv, challenge)); !errors.Is(err, ErrProofOfPossession) {
		t.Fatalf("expected ErrProofOfPossession for wrong signer, got %v", err)
	}
	// empty challenge
	if err := VerifyProofOfPossession(subjectPub, nil, sig); !errors.Is(err, ErrProofOfPossession) {
		t.Fatalf("expected ErrProofOfPossession for empty challenge, got %v", err)
	}
	// bad key
	if err := VerifyProofOfPossession([]byte{1}, challenge, sig); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected ErrBadKey, got %v", err)
	}
}

// encoding --------------------------------------------------------------------

func TestEncodeDecodePublicKey(t *testing.T) {
	subjectPub, _ := mustKeypair(t)
	s := EncodePublicKey(subjectPub)
	back, err := DecodePublicKey(s)
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if string(back) != string(subjectPub) {
		t.Fatalf("round-trip mismatch")
	}
	if _, err := DecodePublicKey("!!!not-base64!!!"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected ErrBadKey for bad base64, got %v", err)
	}
	if _, err := DecodePublicKey(EncodePublicKey([]byte{1, 2, 3})); !errors.Is(err, ErrBadKey) {
		t.Fatalf("expected ErrBadKey for wrong-length decoded key, got %v", err)
	}
}
