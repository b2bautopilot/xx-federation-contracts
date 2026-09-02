package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// wgPublicKeySize is the length of a WireGuard (Curve25519) public key in bytes.
const wgPublicKeySize = 32

// fabricPeerRosterDomain is a signing-domain separator prepended to the canonical
// bytes so a FabricPeerRoster signature can NEVER be confused with a RevocationList or
// Capability signature minted by the SAME dedicated membership key (all three share the
// one membership signer). RevocationList/Capability sign raw JSON; this type signs
// domain||JSON, so the signed byte strings are disjoint by construction — a captured
// revocation-list signature cannot be replayed as a roster. (Retrofitting the domain
// onto the already-shipped RevocationList/Capability would be a wire break; one-sided
// separation on this NEW type is sufficient for cross-type safety.)
const fabricPeerRosterDomain = "builders-net/membershipcap/fabric-peer-roster/v1\x00"

// FabricPeerRoster is the signed, short-TTL ALLOW-LIST of the relay cells that should
// mutually peer within a fabric's presence mesh — the control-plane feed that lets a
// relay daemon populate state.Peers WITHOUT the manual x-mesh overlay ceremony
// (docs/migration/control-plane-peer-feed-bridge.md, G2). Like RevocationList it is
// self-contained (crypto/ed25519 only): no libp2p, no DB, no proto. Signed by the
// dedicated membership signer; verified by the relay daemon before it injects peers.
//
// It carries the FULL WireGuard-path material per entry, not just identity, because
// ADMISSION IS NOT DELIVERY (the design-review fatal-flaw fix): a peer with no PubKeyWG
// or endpoint is authorized by both admission gates yet has no wg0 tunnel for its flood
// to ride, so Validate rejects it fail-closed.
//
// ALLOW-LIST semantics (the inverse of RevocationList's deny-list): an entry present =
// this cell should be a peer; Tombstones = an EXPLICIT de-peer. A verifier MUST treat a
// pull failure or an expired roster as "retain last-known-good", NEVER as "remove every
// peer" — otherwise a control-plane blip flaps the whole overlay. This type defines the
// signed primitive + structural validation only; the daemon apply/reconcile and the
// control-plane assembler are later slices.
type FabricPeerRoster struct {
	FabricID string `json:"fabric_id"`
	// Epoch is the anti-rollback ordinal a verifier compares against the last it saw
	// (monotonic per fabric); an older Epoch is ignored.
	Epoch      int64             `json:"epoch"`
	IssuedAtMS int64             `json:"issued_at_ms"`
	NotAfterMS int64             `json:"not_after_ms"` // short TTL — past it a verifier retains last-known-good, it does NOT de-peer
	Entries    []PeerRosterEntry `json:"entries"`
	// Tombstones are mesh ed25519 pubkeys explicitly de-peered this epoch — an explicit
	// removal, so a control-plane blip / TTL expiry can never silently collapse the mesh.
	Tombstones  [][]byte `json:"tombstones,omitempty"`
	SignerKeyID string   `json:"signer_key_id"`
	Signature   []byte   `json:"signature,omitempty"` // excluded from the canonical signing bytes
}

// PeerRosterEntry is one relay cell's full peer.Peer projection — enough to both ADMIT
// its floods (MeshPubKeyEd25519 → the presence flood gate; LibP2PPeerID → the libp2p
// gater, both fed from state.Peers) AND DELIVER them (PubKeyWG + MeshIP + an endpoint →
// the wg0 tunnel wireguard.Render builds). PubKeyWG is MANDATORY: no WireGuard [Peer]
// block, hence no tunnel, without it — and libp2p endpoint discovery never supplies it.
type PeerRosterEntry struct {
	MeshPubKeyEd25519 []byte   `json:"mesh_pubkey_ed25519"`       // 32-byte flood-signer identity (the state.Peers gate key)
	PubKeyWG          []byte   `json:"pubkey_wg"`                 // 32-byte WireGuard pubkey (MANDATORY — the tunnel key)
	MeshIP            string   `json:"mesh_ip"`                   // overlay ULA the flood targets (http://[MeshIP]:8442) / AllowedIPs
	FQName            string   `json:"fqname"`                    // stable node name (endpoint discovery matches on it)
	Role              string   `json:"role"`                      // mesh role (e.g. host)
	LibP2PPeerID      string   `json:"libp2p_peer_id,omitempty"`  // feeds the libp2p gater via state.Peers
	Endpoints         []string `json:"endpoints,omitempty"`       // WG endpoint host:port(s); empty ⇒ rely on an ARMED libp2p discovery
	BootstrapAddrs    []string `json:"bootstrap_addrs,omitempty"` // libp2p multiaddrs to converge the DHT (the option-b endpoint path)
}

var (
	ErrPeerRosterSignature = errors.New("fabric peer roster signature invalid")
	ErrPeerRosterExpired   = errors.New("fabric peer roster expired")
	ErrPeerRosterSigner    = errors.New("fabric peer roster signer not trusted")
	ErrPeerRosterEntry     = errors.New("fabric peer roster entry missing required path material")
	ErrPeerRosterEpoch     = errors.New("fabric peer roster epoch must be >= 1")
)

// sortedRosterEntries returns a copy ordered by mesh pubkey so the canonical signing
// bytes are independent of the assembler's iteration/store order.
func sortedRosterEntries(in []PeerRosterEntry) []PeerRosterEntry {
	out := make([]PeerRosterEntry, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		return bytes.Compare(out[i].MeshPubKeyEd25519, out[j].MeshPubKeyEd25519) < 0
	})
	return out
}

func sortedTombstones(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func peerRosterCanonicalBytes(r FabricPeerRoster) ([]byte, error) {
	r.Signature = nil
	r.Entries = sortedRosterEntries(r.Entries)
	r.Tombstones = sortedTombstones(r.Tombstones)
	j, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(fabricPeerRosterDomain), j...), nil
}

// SignFabricPeerRoster stamps SignerKeyID + Signature using the dedicated membership
// signing key (the same signer that mints capabilities + revocation lists).
func SignFabricPeerRoster(keyID string, priv ed25519.PrivateKey, r FabricPeerRoster) (FabricPeerRoster, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return FabricPeerRoster{}, ErrBadKey
	}
	r.SignerKeyID = keyID
	r.Signature = nil
	b, err := peerRosterCanonicalBytes(r)
	if err != nil {
		return FabricPeerRoster{}, err
	}
	r.Signature = ed25519.Sign(priv, b)
	return r, nil
}

// Verify checks the roster is signed by a trusted membership signer and unexpired. The
// caller separately enforces monotonic Epoch against the last it saw AND calls Validate
// before injecting any entry.
func (r FabricPeerRoster) Verify(trusted map[string]ed25519.PublicKey, nowMS int64) error {
	pub, ok := trusted[r.SignerKeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrPeerRosterSigner, r.SignerKeyID)
	}
	if r.NotAfterMS != 0 && nowMS >= r.NotAfterMS {
		return ErrPeerRosterExpired
	}
	sig := r.Signature
	if len(sig) != ed25519.SignatureSize {
		return ErrPeerRosterSignature
	}
	b, err := peerRosterCanonicalBytes(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrPeerRosterSignature
	}
	return nil
}

// Validate enforces that every entry carries the material needed to both ADMIT and
// DELIVER a flood — the reachability invariant from the design review: an entry missing
// PubKeyWG (mis-sized key, or a MeshIP that is not an IP) is authorized-but-unreachable,
// so it is rejected fail-closed rather than injected as a dead peer. It also rejects a
// SELF-CONTRADICTORY roster: a mesh key appearing on two entries (which would inject two
// conflicting peers for one identity) or a key that is BOTH an entry and a tombstone
// (authorize + de-peer in one epoch). It does NOT check the signature (call Verify
// first). The endpoint-reachability policy (at least one side of a pair must have an
// initiatable endpoint, or an armed libp2p bootstrap) is a control-plane-assembler
// concern — WireGuard reachability is pairwise, so it is NOT enforced per-entry here.
//
// Epoch must be >= 1 (monotonic from 1): a verifier's "nothing applied yet" fence is 0,
// so Epoch 0 is reserved and rejected — the assembler numbers rosters from 1.
func (r FabricPeerRoster) Validate() error {
	if r.Epoch < 1 {
		return fmt.Errorf("%w: got %d", ErrPeerRosterEpoch, r.Epoch)
	}
	seen := make(map[string]struct{}, len(r.Entries))
	for i, e := range r.Entries {
		if len(e.MeshPubKeyEd25519) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: entry %d mesh_pubkey_ed25519 is %d bytes, want %d", ErrPeerRosterEntry, i, len(e.MeshPubKeyEd25519), ed25519.PublicKeySize)
		}
		if len(e.PubKeyWG) != wgPublicKeySize {
			return fmt.Errorf("%w: entry %d pubkey_wg is %d bytes, want %d (no WireGuard tunnel without it)", ErrPeerRosterEntry, i, len(e.PubKeyWG), wgPublicKeySize)
		}
		// An empty MeshIP fails to parse, so this subsumes the "no mesh_ip" case AND rejects
		// garbage that would break AllowedIPs / http://[MeshIP]:8442 at daemon apply. Uses
		// netip.ParseAddr — the SAME parser the daemon applies (peerFromRosterEntry) — so a
		// value that validates here can never fail conversion mid-apply (no partial apply).
		if _, err := netip.ParseAddr(e.MeshIP); err != nil {
			return fmt.Errorf("%w: entry %d (%s) mesh_ip %q is not an IP (the flood target / AllowedIPs)", ErrPeerRosterEntry, i, e.FQName, e.MeshIP)
		}
		k := string(e.MeshPubKeyEd25519)
		if _, dup := seen[k]; dup {
			return fmt.Errorf("%w: entry %d (%s) duplicates the mesh_pubkey_ed25519 of an earlier entry", ErrPeerRosterEntry, i, e.FQName)
		}
		seen[k] = struct{}{}
	}
	for i, t := range r.Tombstones {
		if len(t) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: tombstone %d is %d bytes, want %d", ErrPeerRosterEntry, i, len(t), ed25519.PublicKeySize)
		}
		if _, both := seen[string(t)]; both {
			return fmt.Errorf("%w: tombstone %d also appears as an entry (authorize + de-peer in one epoch is contradictory)", ErrPeerRosterEntry, i)
		}
	}
	return nil
}
