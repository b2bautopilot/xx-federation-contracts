package membershipcap

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// RevocationList is the signed, short-TTL snapshot of a control plane's authorized
// libp2p peers and their revocation state (libp2p-fabric-migration P1.4). It is the
// PULL-distributed fence that verifiers (relay + gateway daemon) apply to presented
// membership capabilities — the D6 control-plane-pull alternative to a global gossip
// roster. Like Capability it is deliberately self-contained (crypto/ed25519 only):
// no libp2p, no DB, no proto. Entries are keyed by the ed25519 PUBLIC KEY (verifiers
// derive the PeerID). This slice defines the primitive only; the per-partner PULL
// TRANSPORT and disclosure boundary (D6/D10/D11) are a later phase.
type RevocationList struct {
	FabricID string `json:"fabric_id"`
	// ListGeneration is the anti-rollback ordinal a verifier compares against the
	// last it saw. The P1 assembler seeds it from max(binding.updated_at_ms), which
	// is monotonic only while bindings are append-only and the clock does not skew;
	// a dedicated persisted counter is the P2 hardening.
	ListGeneration int64             `json:"list_generation"`
	IssuedAtMS     int64             `json:"issued_at_ms"`
	NotAfterMS     int64             `json:"not_after_ms"` // short TTL — a verifier rejects a stale list (bounds the admit-after-revoke window)
	Entries        []RevocationEntry `json:"entries"`
	SignerKeyID    string            `json:"signer_key_id"`
	Signature      []byte            `json:"signature,omitempty"` // excluded from the canonical signing bytes
}

// RevocationEntry is one authorized peer's current membership + revocation state.
type RevocationEntry struct {
	LibP2PPublicKey      []byte `json:"libp2p_public_key"`     // 32-byte ed25519 pubkey (PeerID derivable)
	CapabilityEpoch      int64  `json:"capability_epoch"`      // the binding's CURRENT membership epoch (a lower-epoch capability is superseded)
	RevocationGeneration int64  `json:"revocation_generation"` // the binding's CURRENT revocation generation
	Revoked              bool   `json:"revoked"`               // true iff the binding is no longer Active
}

var (
	ErrRevocationSignature = errors.New("revocation list signature invalid")
	ErrRevocationExpired   = errors.New("revocation list expired")
	ErrRevocationSigner    = errors.New("revocation list signer not trusted")
)

// FenceStatus classifies a capability against a list WITHOUT baking in the allow-
// list vs deny-list policy for an ABSENT peer — that is the caller's (gater's)
// decision, because it depends on whether the list is authoritative for the peer's
// fabric/partner (a later-phase transport concern).
type FenceStatus int

const (
	FenceUnknown FenceStatus = iota // the peer is not in this list — caller decides (authoritative list ⇒ deny; incremental deny-list ⇒ allow)
	FenceValid                      // present, active, and the capability is not superseded
	FenceRevoked                    // present but revoked, or the capability is superseded (older epoch / predates a newer revocation generation)
)

// sortedEntries returns a copy ordered by public key, so the canonical signing bytes
// are independent of the assembler's iteration/store order. Stable, so entries that
// share a key keep a deterministic relative order.
func sortedEntries(in []RevocationEntry) []RevocationEntry {
	out := make([]RevocationEntry, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		return bytes.Compare(out[i].LibP2PPublicKey, out[j].LibP2PPublicKey) < 0
	})
	return out
}

func revocationCanonicalBytes(rl RevocationList) ([]byte, error) {
	rl.Signature = nil
	rl.Entries = sortedEntries(rl.Entries)
	return json.Marshal(rl)
}

// SignRevocationList stamps SignerKeyID + Signature using the dedicated membership
// signing key (the same signer that mints capabilities — §5.3).
func SignRevocationList(keyID string, priv ed25519.PrivateKey, rl RevocationList) (RevocationList, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return RevocationList{}, ErrBadKey
	}
	rl.SignerKeyID = keyID
	rl.Signature = nil
	b, err := revocationCanonicalBytes(rl)
	if err != nil {
		return RevocationList{}, err
	}
	rl.Signature = ed25519.Sign(priv, b)
	return rl, nil
}

// Verify checks the list is signed by a trusted membership signer and unexpired.
// The caller separately enforces monotonic ListGeneration against the last it saw.
func (rl RevocationList) Verify(trusted map[string]ed25519.PublicKey, nowMS int64) error {
	pub, ok := trusted[rl.SignerKeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrRevocationSigner, rl.SignerKeyID)
	}
	if rl.NotAfterMS != 0 && nowMS >= rl.NotAfterMS {
		return ErrRevocationExpired
	}
	sig := rl.Signature
	if len(sig) != ed25519.SignatureSize {
		return ErrRevocationSignature
	}
	b, err := revocationCanonicalBytes(rl)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrRevocationSignature
	}
	return nil
}

// Find returns the entry for a libp2p public key, if present.
func (rl RevocationList) Find(libp2pPublicKey []byte) (RevocationEntry, bool) {
	for _, e := range rl.Entries {
		if bytes.Equal(e.LibP2PPublicKey, libp2pPublicKey) {
			return e, true
		}
	}
	return RevocationEntry{}, false
}

// Check classifies a capability against the list. It does NOT itself verify the
// capability's signature or the list's signature — callers Verify() both first.
//
// REVOCATION WINS across duplicates: if more than one entry shares the capability's
// key (should not occur — issuance binds a key to one binding — but is not
// structurally prevented), ANY revoked or superseding entry yields FenceRevoked, so
// a duplicate can never downgrade a revoked peer to admitted.
func (rl RevocationList) Check(c Capability) FenceStatus {
	found := false
	for _, entry := range rl.Entries {
		if !bytes.Equal(entry.LibP2PPublicKey, c.LibP2PPublicKey) {
			continue
		}
		found = true
		// Revoked, or a capability minted before the key rotated (lower epoch) or
		// before a newer revocation generation, is superseded.
		if entry.Revoked || c.CapabilityEpoch < entry.CapabilityEpoch || c.RevocationGeneration < entry.RevocationGeneration {
			return FenceRevoked
		}
	}
	if !found {
		return FenceUnknown
	}
	return FenceValid
}
