package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// meshRegistrationDomain separates the mesh-registration PoP challenge from any other
// message the daemon's mesh ed25519 key signs (e.g. presence-flood announces).
const meshRegistrationDomain = "builders-net/membershipcap/mesh-registration/v1"

// MeshRegistrationClaim is what a relay daemon sends to register its MESH ed25519 identity
// + WireGuard-path material with the control plane (peer-feed bridge G1), so the control
// plane can later place it in a signed FabricPeerRoster (G2). The daemon proves it holds
// the mesh private key via ProofOfPossession over a challenge bound to its ENROLLED
// identity (fabric/gateway/binding), which the control plane recomputes from the mTLS leaf
// (NEVER the request body) — so a captured claim cannot register the key under another
// identity. WG/Curve25519 keys cannot sign, so the mesh-key PoP is what attests the
// declared path material (PubKeyWG/MeshIP/FQName/Role/LibP2PPeerID/endpoints). IssuedAtMS
// is PoP-bound but NOT TTL-checked here — the control-plane store MUST order
// re-registrations monotonically by it and keep the latest (that ordering, not this
// primitive, is what defeats replay of an old claim). Self-contained (crypto/ed25519 only).
type MeshRegistrationClaim struct {
	MeshPubKeyEd25519 []byte   `json:"mesh_pubkey_ed25519"`
	PubKeyWG          []byte   `json:"pubkey_wg"`
	MeshIP            string   `json:"mesh_ip"`
	FQName            string   `json:"fqname"`
	Role              string   `json:"role,omitempty"`
	LibP2PPeerID      string   `json:"libp2p_peer_id,omitempty"`
	Endpoints         []string `json:"endpoints,omitempty"`
	BootstrapAddrs    []string `json:"bootstrap_addrs,omitempty"`
	IssuedAtMS        int64    `json:"issued_at_ms"`
	ProofOfPossession []byte   `json:"proof_of_possession,omitempty"` // ed25519(meshPriv, challenge)
}

var ErrMeshRegistration = errors.New("mesh registration invalid")

// writeLenField writes an 8-byte big-endian length prefix then the bytes, so the concatenated
// challenge fields are unambiguously framed (no cross-field aliasing).
func writeLenField(w io.Writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

// meshRegistrationChallenge builds the deterministic PoP challenge. fabricID/gatewayID/
// bindingID are the ENROLLED identity the control plane derives from the mTLS leaf; the
// daemon must sign with the SAME values. Binds PubKeyWG + MeshIP + IssuedAtMS so the
// mesh-key PoP attests the declared path material and its freshness.
func meshRegistrationChallenge(fabricID, gatewayID, bindingID string, c MeshRegistrationClaim) []byte {
	h := sha256.New()
	writeLenField(h, []byte(meshRegistrationDomain))
	writeLenField(h, []byte(fabricID))
	writeLenField(h, []byte(gatewayID))
	writeLenField(h, []byte(bindingID))
	writeLenField(h, c.MeshPubKeyEd25519)
	writeLenField(h, c.PubKeyWG)
	// Bind the CANONICAL address so an equal-but-differently-encoded MeshIP string still
	// verifies (fall back to the raw string if unparseable — Validate rejects those first).
	meshIP := c.MeshIP
	if a, err := netip.ParseAddr(c.MeshIP); err == nil {
		meshIP = a.String()
	}
	writeLenField(h, []byte(meshIP))
	// EVERY field ToRosterEntry propagates into the (later control-plane-signed) roster is
	// PoP-bound, so a post-mTLS tamper of any of them fails verification — nothing
	// unauthenticated is laundered into the authoritative roster (esp. LibP2PPeerID, which
	// feeds the libp2p gater via state.Peers).
	writeLenField(h, []byte(c.FQName))
	writeLenField(h, []byte(c.Role))
	writeLenField(h, []byte(c.LibP2PPeerID))
	writeStringSlice(h, c.Endpoints)
	writeStringSlice(h, c.BootstrapAddrs)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(c.IssuedAtMS))
	_, _ = h.Write(ts[:])
	return h.Sum(nil)
}

// writeStringSlice frames a []string as an element count then each length-prefixed element,
// so nil / [] / a re-chunked slice cannot collide.
func writeStringSlice(w io.Writer, ss []string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(ss)))
	_, _ = w.Write(n[:])
	for _, s := range ss {
		writeLenField(w, []byte(s))
	}
}

// Validate enforces the same fail-closed path-material invariant as a PeerRosterEntry: a
// registration missing PubKeyWG (a mis-sized key, or a non-IP MeshIP) is authorized-but-
// unreachable and rejected. Uses netip.ParseAddr — the parser the daemon applies. Does NOT
// check the PoP (call Verify).
func (c MeshRegistrationClaim) Validate() error {
	if len(c.MeshPubKeyEd25519) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: mesh_pubkey_ed25519 is %d bytes, want %d", ErrMeshRegistration, len(c.MeshPubKeyEd25519), ed25519.PublicKeySize)
	}
	if len(c.PubKeyWG) != wgPublicKeySize {
		return fmt.Errorf("%w: pubkey_wg is %d bytes, want %d (no WireGuard tunnel without it)", ErrMeshRegistration, len(c.PubKeyWG), wgPublicKeySize)
	}
	if _, err := netip.ParseAddr(c.MeshIP); err != nil {
		return fmt.Errorf("%w: mesh_ip %q is not an IP", ErrMeshRegistration, c.MeshIP)
	}
	// IssuedAtMS must be positive — the control-plane store orders re-registrations by it
	// (int64), so a zero/negative value would sort as oldest or (MaxInt64) pin stale WG
	// material and block the daemon's own future rotations.
	if c.IssuedAtMS <= 0 {
		return fmt.Errorf("%w: issued_at_ms must be > 0, got %d", ErrMeshRegistration, c.IssuedAtMS)
	}
	return nil
}

// SignMeshRegistration validates the claim, checks the signing key matches the claimed mesh
// pubkey, and stamps the PoP by signing the challenge with the daemon's MESH private key.
// fabricID/gatewayID/bindingID are the daemon's OWN enrolled identity (must equal what the
// control plane derives from the mTLS leaf, or Verify fails).
func SignMeshRegistration(meshPriv ed25519.PrivateKey, fabricID, gatewayID, bindingID string, c MeshRegistrationClaim) (MeshRegistrationClaim, error) {
	if len(meshPriv) != ed25519.PrivateKeySize {
		return MeshRegistrationClaim{}, ErrBadKey
	}
	pub, ok := meshPriv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, c.MeshPubKeyEd25519) {
		return MeshRegistrationClaim{}, fmt.Errorf("%w: signing key does not match mesh_pubkey_ed25519", ErrMeshRegistration)
	}
	if err := c.Validate(); err != nil {
		return MeshRegistrationClaim{}, err
	}
	c.ProofOfPossession = ed25519.Sign(meshPriv, meshRegistrationChallenge(fabricID, gatewayID, bindingID, c))
	return c, nil
}

// Verify recomputes the challenge from the control-plane-authenticated identity
// (fabricID/gatewayID/bindingID from the mTLS leaf — NEVER the request body) and checks the
// daemon proved possession of the mesh key it is registering, AND that every field
// ToRosterEntry propagates is PoP-bound. Also structurally validates the path material. It
// does NOT check freshness (no TTL) — the store orders by IssuedAtMS (see the type doc).
func (c MeshRegistrationClaim) Verify(fabricID, gatewayID, bindingID string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	challenge := meshRegistrationChallenge(fabricID, gatewayID, bindingID, c)
	return VerifyProofOfPossession(c.MeshPubKeyEd25519, challenge, c.ProofOfPossession)
}

// VerifiedMeshRegistration wraps a MeshRegistrationClaim whose PoP has been checked against a
// control-plane-authenticated identity. It is UNCONSTRUCTABLE outside this package except via
// AsVerified, so a function that takes it (AssembleFabricPeerRoster) is statically guaranteed
// its inputs were verified — the "caller must Verify first" precondition is compiler-enforced,
// not a doc comment (closes the G1-review A1 class: unauthenticated path material can never be
// assembled + signed into an authoritative roster).
type VerifiedMeshRegistration struct {
	claim MeshRegistrationClaim
}

// AsVerified verifies the claim against the control-plane-authenticated identity (fabric/
// gateway/binding derived from the mTLS leaf) and, on success, returns a
// VerifiedMeshRegistration — the only way to obtain one. The roster assembler takes these, so
// an unverified claim cannot reach it.
func (c MeshRegistrationClaim) AsVerified(fabricID, gatewayID, bindingID string) (VerifiedMeshRegistration, error) {
	if err := c.Verify(fabricID, gatewayID, bindingID); err != nil {
		return VerifiedMeshRegistration{}, err
	}
	return VerifiedMeshRegistration{claim: c}, nil
}

// Claim returns the underlying verified registration (read-only).
func (v VerifiedMeshRegistration) Claim() MeshRegistrationClaim { return v.claim }

// ToRosterEntry projects a VERIFIED registration into a G2 PeerRosterEntry (the control
// plane's roster assembler builds a FabricPeerRoster from registered claims). Callers must
// Verify (and thus Validate) first.
func (c MeshRegistrationClaim) ToRosterEntry() PeerRosterEntry {
	return PeerRosterEntry{
		MeshPubKeyEd25519: append([]byte(nil), c.MeshPubKeyEd25519...),
		PubKeyWG:          append([]byte(nil), c.PubKeyWG...),
		MeshIP:            c.MeshIP,
		FQName:            c.FQName,
		Role:              c.Role,
		LibP2PPeerID:      c.LibP2PPeerID,
		Endpoints:         append([]string(nil), c.Endpoints...),
		BootstrapAddrs:    append([]string(nil), c.BootstrapAddrs...),
	}
}
