// Package membershipcap defines the short-TTL, signed libp2p-fabric MEMBERSHIP
// CAPABILITY that binds a gateway's libp2p host key to its authorized federation
// identity (libp2p-fabric-migration P1.3). The control plane's DEDICATED membership
// signer (§5.3) issues it; the relay + gateway daemon verify it.
//
// Deliberately self-contained (crypto/ed25519 only): it does NOT import libp2p and
// does NOT bind a PeerID string — it binds the ed25519 PUBLIC KEY, and the verifiers
// (which already run libp2p) derive the PeerID from it. This keeps builders-net free
// of the libp2p dependency and honors Q2 (a SEPARATE libp2p key, proven via PoP) and
// D11 (no new coupling). No DB, no proto — pure crypto.
package membershipcap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Capability is the signed token. It binds the gateway's ed25519 libp2p public key
// to an OPAQUE tenant handle (never a cleartext org/domain — D13).
type Capability struct {
	LibP2PPublicKey      []byte `json:"libp2p_public_key"` // 32-byte ed25519 host pubkey (PeerID derivable by verifiers)
	TenantHandle         string `json:"tenant_handle"`     // opaque, relay-unlinkable ref (not the tenant id)
	FabricID             string `json:"fabric_id"`
	CapabilityEpoch      int64  `json:"capability_epoch"`      // monotonic per issuance; fenced by the revocation list
	RevocationGeneration int64  `json:"revocation_generation"` // the binding's revgen at issuance
	NotAfterMS           int64  `json:"not_after_ms"`          // short TTL (~30-60m)
	SignerKeyID          string `json:"signer_key_id"`
	Signature            []byte `json:"signature,omitempty"` // excluded from the canonical signing bytes
}

var (
	ErrBadSignature      = errors.New("membership capability signature invalid")
	ErrExpired           = errors.New("membership capability expired")
	ErrUnknownSigner     = errors.New("membership capability signer not trusted")
	ErrBadKey            = errors.New("membership capability public key invalid")
	ErrProofOfPossession = errors.New("membership capability proof-of-possession invalid")
)

// canonicalBytes is the deterministic signing input: the capability sans signature,
// as JSON. encoding/json marshals struct fields in declaration order, so signer and
// verifier produce byte-identical input.
func canonicalBytes(c Capability) ([]byte, error) {
	c.Signature = nil
	return json.Marshal(c)
}

// Sign stamps SignerKeyID + Signature onto the capability using the dedicated
// membership signing key.
func Sign(keyID string, priv ed25519.PrivateKey, c Capability) (Capability, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Capability{}, ErrBadKey
	}
	if len(c.LibP2PPublicKey) != ed25519.PublicKeySize {
		return Capability{}, ErrBadKey
	}
	c.SignerKeyID = keyID
	c.Signature = nil
	b, err := canonicalBytes(c)
	if err != nil {
		return Capability{}, err
	}
	c.Signature = ed25519.Sign(priv, b)
	return c, nil
}

// Verify checks the capability is signed by a trusted membership signer, unexpired,
// and well-formed. It does NOT check revocation (the caller compares CapabilityEpoch /
// RevocationGeneration against the pulled revocation list) nor proof-of-possession
// (see VerifyProofOfPossession) — those are separate, caller-owned steps.
func (c Capability) Verify(trusted map[string]ed25519.PublicKey, nowMS int64) error {
	pub, ok := trusted[c.SignerKeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrUnknownSigner, c.SignerKeyID)
	}
	if len(c.LibP2PPublicKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	if c.NotAfterMS != 0 && nowMS >= c.NotAfterMS {
		return ErrExpired
	}
	sig := c.Signature
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	b, err := canonicalBytes(c) // zeroes Signature
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrBadSignature
	}
	return nil
}

// VerifyProofOfPossession proves the requester holds the private half of the libp2p
// key being bound: it must have signed `challenge`. crypto/ed25519 only — the
// PeerID<->pubkey relationship is a verifier concern (they run libp2p). The control
// plane calls this at issuance so a gateway cannot bind a key it does not control.
func VerifyProofOfPossession(libp2pPublicKey, challenge, popSignature []byte) error {
	if len(libp2pPublicKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	if len(challenge) == 0 || len(popSignature) != ed25519.SignatureSize {
		return ErrProofOfPossession
	}
	if !ed25519.Verify(ed25519.PublicKey(libp2pPublicKey), challenge, popSignature) {
		return ErrProofOfPossession
	}
	return nil
}

// TenantHandle derives a stable, opaque handle for a tenant within a fabric — the
// blind ref that appears in the capability instead of the cleartext tenant/org id
// (D13). Deterministic (same tenant+fabric -> same handle), matching the existing
// blind-rendezvous-key model; carries no cleartext identity.
func TenantHandle(tenantID, fabricID string) string {
	sum := sha256.Sum256([]byte("membership-tenant-handle|" + fabricID + "|" + tenantID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// EncodePublicKey / DecodePublicKey are the storage encoding for the bound libp2p
// pubkey (e.g. the federation_gateway_identity_bindings.libp2p_peer_id column holds
// the encoded pubkey; verifiers derive the PeerID from it).
func EncodePublicKey(pub []byte) string { return base64.RawURLEncoding.EncodeToString(pub) }

func DecodePublicKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrBadKey
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	return b, nil
}

// ConstantTimeEqualHandle compares two tenant handles without leaking timing.
func ConstantTimeEqualHandle(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
