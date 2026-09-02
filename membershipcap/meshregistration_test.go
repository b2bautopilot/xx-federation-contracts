package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

const (
	regFabric  = "fed"
	regGateway = "gw-relay-a"
	regBinding = "binding-123"
)

func mkMeshClaim(t *testing.T) (MeshRegistrationClaim, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	wg := make([]byte, wgPublicKeySize)
	if _, err := rand.Read(wg); err != nil {
		t.Fatal(err)
	}
	c := MeshRegistrationClaim{
		MeshPubKeyEd25519: pub, PubKeyWG: wg, MeshIP: "fd7a:b1d2:1::7",
		FQName: "relayX", Role: "host", LibP2PPeerID: "12D3KooWexample",
		Endpoints:      []string{"198.51.100.7:51820"},
		BootstrapAddrs: []string{"/ip4/198.51.100.7/udp/4001/quic"},
		IssuedAtMS:     1_700_000_000_000,
	}
	return c, priv, pub
}

func TestMeshRegistration_SignVerifyRoundTrip(t *testing.T) {
	c, priv, _ := mkMeshClaim(t)
	signed, err := SignMeshRegistration(priv, regFabric, regGateway, regBinding, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.ProofOfPossession) != ed25519.SignatureSize {
		t.Fatalf("no PoP stamped: %d bytes", len(signed.ProofOfPossession))
	}
	if err := signed.Verify(regFabric, regGateway, regBinding); err != nil {
		t.Fatalf("valid registration should verify: %v", err)
	}
}

// The security property: the PoP is bound to the ENROLLED identity the control plane
// derives from the mTLS leaf, so a captured claim cannot be replayed to register the mesh
// key under a DIFFERENT gateway/binding/fabric.
func TestMeshRegistration_WrongIdentityFailsPoP(t *testing.T) {
	c, priv, _ := mkMeshClaim(t)
	signed, _ := SignMeshRegistration(priv, regFabric, regGateway, regBinding, c)
	for _, tc := range []struct{ name, f, g, b string }{
		{"wrong gateway", regFabric, "gw-attacker", regBinding},
		{"wrong binding", regFabric, regGateway, "binding-999"},
		{"wrong fabric", "other-fabric", regGateway, regBinding},
	} {
		if err := signed.Verify(tc.f, tc.g, tc.b); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("%s: want ErrProofOfPossession, got %v", tc.name, err)
		}
	}
}

// Non-vacuity: the challenge covers the declared path material + freshness, so tampering
// any of it after signing invalidates the PoP (WG keys can't sign; the mesh-key PoP is
// what attests them).
func TestMeshRegistration_TamperedMaterialFailsPoP(t *testing.T) {
	c, priv, _ := mkMeshClaim(t)
	base, _ := SignMeshRegistration(priv, regFabric, regGateway, regBinding, c)

	t.Run("PubKeyWG", func(t *testing.T) {
		s := base
		s.PubKeyWG = append([]byte(nil), base.PubKeyWG...)
		s.PubKeyWG[0] ^= 0xFF
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered WG key: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("MeshIP", func(t *testing.T) {
		s := base
		s.MeshIP = "fd7a:b1d2:1::99" // valid IP so Validate passes; PoP must still fail
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered MeshIP: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("IssuedAtMS", func(t *testing.T) {
		s := base
		s.IssuedAtMS = base.IssuedAtMS + 1
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered IssuedAtMS: want ErrProofOfPossession, got %v", err)
		}
	})
	// A1: the fields ToRosterEntry propagates into the signed roster are ALSO PoP-bound, so
	// tampering any of them (post-mTLS) fails verification — nothing unauthenticated is
	// laundered into the authoritative roster.
	t.Run("LibP2PPeerID", func(t *testing.T) {
		s := base
		s.LibP2PPeerID = "12D3KooW-ATTACKER"
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered LibP2PPeerID: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("FQName", func(t *testing.T) {
		s := base
		s.FQName = "relay-evil"
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered FQName: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("Role", func(t *testing.T) {
		s := base
		s.Role = "relay_server"
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered Role: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("Endpoints", func(t *testing.T) {
		s := base
		s.Endpoints = []string{"203.0.113.66:51820"}
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered Endpoints: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("BootstrapAddrs", func(t *testing.T) {
		s := base
		s.BootstrapAddrs = []string{"/ip4/203.0.113.66/udp/4001/quic"}
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("tampered BootstrapAddrs: want ErrProofOfPossession, got %v", err)
		}
	})
	t.Run("nil PoP", func(t *testing.T) {
		s := base
		s.ProofOfPossession = nil
		if err := s.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
			t.Fatalf("nil PoP: want ErrProofOfPossession, got %v", err)
		}
	})
}

// D1: an equal-but-differently-encoded MeshIP string still verifies (the challenge binds
// the canonical address).
func TestMeshRegistration_MeshIPCanonicalization(t *testing.T) {
	c, priv, _ := mkMeshClaim(t)
	c.MeshIP = "fd7a:0:0:0:0:0:0:7" // non-canonical form of fd7a::7
	signed, err := SignMeshRegistration(priv, regFabric, regGateway, regBinding, c)
	if err != nil {
		t.Fatal(err)
	}
	signed.MeshIP = "fd7a::7" // same address, canonical string
	if err := signed.Verify(regFabric, regGateway, regBinding); err != nil {
		t.Fatalf("an equal-but-recanonicalized MeshIP must still verify: %v", err)
	}
}

// A daemon cannot register a mesh key it does not hold: SignMeshRegistration refuses a
// mismatched key (client guard), and even a hand-forged claim fails Verify (server catch).
func TestMeshRegistration_CannotClaimUnheldKey(t *testing.T) {
	c, _, _ := mkMeshClaim(t) // c claims its own pub
	_, priv2, _ := mkMeshClaim(t)

	if _, err := SignMeshRegistration(priv2, regFabric, regGateway, regBinding, c); !errors.Is(err, ErrMeshRegistration) {
		t.Fatalf("signing with a key not matching the claimed pubkey must be rejected, got %v", err)
	}

	forged := c // claims c's pubkey, but PoP is made by priv2
	forged.ProofOfPossession = ed25519.Sign(priv2, meshRegistrationChallenge(regFabric, regGateway, regBinding, forged))
	if err := forged.Verify(regFabric, regGateway, regBinding); !errors.Is(err, ErrProofOfPossession) {
		t.Fatalf("a PoP signed by a non-matching key must fail, got %v", err)
	}
}

func TestMeshRegistration_Validate(t *testing.T) {
	good, _, _ := mkMeshClaim(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("valid claim should validate: %v", err)
	}
	noWG := good
	noWG.PubKeyWG = nil
	if err := noWG.Validate(); !errors.Is(err, ErrMeshRegistration) {
		t.Fatalf("missing PubKeyWG: want ErrMeshRegistration, got %v", err)
	}
	badMesh := good
	badMesh.MeshPubKeyEd25519 = make([]byte, 8)
	if err := badMesh.Validate(); !errors.Is(err, ErrMeshRegistration) {
		t.Fatalf("mis-sized mesh key: want ErrMeshRegistration, got %v", err)
	}
	badIP := good
	badIP.MeshIP = "not-an-ip"
	if err := badIP.Validate(); !errors.Is(err, ErrMeshRegistration) {
		t.Fatalf("non-IP mesh_ip: want ErrMeshRegistration, got %v", err)
	}
	for _, ts := range []int64{0, -1} {
		bad := good
		bad.IssuedAtMS = ts
		if err := bad.Validate(); !errors.Is(err, ErrMeshRegistration) {
			t.Fatalf("issued_at_ms=%d: want ErrMeshRegistration, got %v", ts, err)
		}
	}
}

func TestMeshRegistration_BadPrivKey(t *testing.T) {
	c, _, _ := mkMeshClaim(t)
	if _, err := SignMeshRegistration(ed25519.PrivateKey("short"), regFabric, regGateway, regBinding, c); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}

// G1 -> G2: a verified registration projects into a PeerRosterEntry that satisfies the
// roster's own fail-closed validation (the assembler builds a roster from claims).
func TestMeshRegistration_ToRosterEntryPassesRosterValidate(t *testing.T) {
	c, priv, _ := mkMeshClaim(t)
	signed, _ := SignMeshRegistration(priv, regFabric, regGateway, regBinding, c)
	entry := signed.ToRosterEntry()
	r := FabricPeerRoster{FabricID: regFabric, Epoch: 1, NotAfterMS: 1_000_000, Entries: []PeerRosterEntry{entry}}
	if err := r.Validate(); err != nil {
		t.Fatalf("a registered claim must project into a valid roster entry: %v", err)
	}
	if !bytes.Equal(entry.MeshPubKeyEd25519, signed.MeshPubKeyEd25519) || !bytes.Equal(entry.PubKeyWG, signed.PubKeyWG) || entry.MeshIP != signed.MeshIP {
		t.Fatal("ToRosterEntry dropped path material")
	}
	if entry.FQName != signed.FQName || entry.Role != signed.Role || entry.LibP2PPeerID != signed.LibP2PPeerID {
		t.Fatal("ToRosterEntry dropped FQName/Role/LibP2PPeerID")
	}
	if len(entry.Endpoints) != len(signed.Endpoints) || len(entry.BootstrapAddrs) != len(signed.BootstrapAddrs) {
		t.Fatal("ToRosterEntry dropped endpoints/bootstrap addrs")
	}
}
