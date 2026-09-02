package serviceaccesscap

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// RevocationTombstone is a signed, per-capability revocation (docs/design/
// sovereign-service-exposure.md §5, P4). It targets ONE capability by its nonce and is
// signed by the SAME issuer key that minted the capability — so a terminus verifies it
// against the SAME pinned issuer keyring it already holds, with no new trust root.
//
// It is best-effort/fast-path only: the v1 revocation floor remains TTL + whole-peer
// eviction. NotAfterMS bounds how long a terminus must retain the tombstone — once past
// it, the target capability has itself expired, so the tombstone is moot and can be GC'd.
// A tombstone therefore never needs to outlive the capability it kills.
type RevocationTombstone struct {
	Resource   string `json:"resource"`     // "<org>/<svc>" the target cap authorized (scoping)
	Nonce      string `json:"nonce"`        // the target capability's nonce
	NotAfterMS int64  `json:"not_after_ms"` // retain until here (>= the target cap's expiry)
	Issuer     string `json:"issuer"`       // signer key id (same keyring as the capability)
	Signature  []byte `json:"signature,omitempty"`
}

var (
	ErrTombstoneBadSignature = fmt.Errorf("revocation tombstone signature invalid")
	ErrTombstoneMalformed    = fmt.Errorf("revocation tombstone malformed")
)

func canonicalTombstoneBytes(t RevocationTombstone) ([]byte, error) {
	t.Signature = nil
	return json.Marshal(t)
}

// SignTombstone stamps Issuer + Signature onto a tombstone. Resource must be "<org>/<svc>",
// Nonce and a positive NotAfterMS are required (fail-closed shape validation).
func SignTombstone(issuerKeyID string, priv ed25519.PrivateKey, t RevocationTombstone) (RevocationTombstone, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return RevocationTombstone{}, ErrBadKey
	}
	if _, _, err := ParseResource(t.Resource); err != nil {
		return RevocationTombstone{}, err
	}
	if t.Nonce == "" || t.NotAfterMS <= 0 {
		return RevocationTombstone{}, ErrTombstoneMalformed
	}
	t.Issuer = issuerKeyID
	t.Signature = nil
	b, err := canonicalTombstoneBytes(t)
	if err != nil {
		return RevocationTombstone{}, err
	}
	t.Signature = ed25519.Sign(priv, b)
	return t, nil
}

// Verify checks the tombstone is signed by a trusted issuer and well-formed. An EMPTY
// keyring returns ErrEmptyKeyring (a terminus never applies an unverifiable tombstone —
// same fail-closed posture as capability verification). It does NOT check NotAfterMS
// against a clock: an expired tombstone is simply moot to apply (the caller GCs it).
func (t RevocationTombstone) Verify(trusted map[string]ed25519.PublicKey) error {
	if len(trusted) == 0 {
		return ErrEmptyKeyring
	}
	pub, ok := trusted[t.Issuer]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrUnknownSigner, t.Issuer)
	}
	if _, _, err := ParseResource(t.Resource); err != nil {
		return err
	}
	if t.Nonce == "" || t.NotAfterMS <= 0 {
		return ErrTombstoneMalformed
	}
	sig := t.Signature
	if len(sig) != ed25519.SignatureSize {
		return ErrTombstoneBadSignature
	}
	b, err := canonicalTombstoneBytes(t)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrTombstoneBadSignature
	}
	return nil
}
