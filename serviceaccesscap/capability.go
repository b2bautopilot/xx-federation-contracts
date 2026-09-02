// Package serviceaccesscap defines the short-TTL, signed SERVICE ACCESS CAPABILITY
// that authorizes a consumer peer to reach a published fed-svc service (`<org>/<svc>`)
// over the payload-blind libp2p circuit fabric. The publisher-org control plane issues
// it; the publisher-org fed-tcp terminus verifies it OFFLINE, fail-closed, before it
// splices any bytes to the local service.
//
// Modeled on packages/membershipcap (deliberately self-contained, crypto/ed25519 only):
// it does NOT import libp2p and does NOT bind a PeerID string — it binds the consumer's
// ed25519 PUBLIC KEY, and the verifier (which already runs libp2p) compares that key
// against the handshake-authenticated remote key of the connecting stream. This keeps
// builders-net free of the libp2p dependency and makes a leaked token inert for any peer
// that does not hold the bound private key. No DB, no proto — pure crypto.
//
// See docs/design/sovereign-service-exposure.md §3. What this package does NOT do (all
// caller-owned, at the terminus): compare the derived/bound peer key to the live stream
// (BindsPublicKey), match the cap resource to the SERVED namespace (AuthorizesResource),
// and check the local revocation set. Verify() covers only signer-trust, well-formedness,
// and expiry — the offline-checkable core.
package serviceaccesscap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// Capability is the signed grant. It binds the consumer's ed25519 public key to a single
// `<org>/<svc>` resource with a hard expiry. Unlike membershipcap, a zero ExpiresAtMS is
// REJECTED (fail-closed): a fed-svc capability that never expires would violate the design
// invariant that nothing outlives its TTL (docs/design/sovereign-service-exposure.md §5).
type Capability struct {
	SubjectPublicKey []byte `json:"subject_public_key"`       // 32-byte ed25519 pubkey of the consumer; verifier compares to the stream's remote key
	SubjectSPIFFE    string `json:"subject_spiffe,omitempty"` // optional, when the consumer is SPIFFE-enrolled (2c)
	Resource         string `json:"resource"`                 // "<org>/<svc>" — the served fed-tcp namespace this cap authorizes
	Scope            string `json:"scope"`                    // v1: coarse "reach"; reserved for L7 method-scopes later
	IssuedAtMS       int64  `json:"issued_at_ms"`
	ExpiresAtMS      int64  `json:"expires_at_ms"`       // MUST be > 0 and > IssuedAtMS; issued_at + <=15m (no app-authN) .. 30m (e2e-mTLS)
	Issuer           string `json:"issuer"`              // signer key id; verifier pins the public half in its trusted keyring
	Nonce            string `json:"nonce"`               // per-cap tombstone targeting (revocation)
	Signature        []byte `json:"signature,omitempty"` // excluded from the canonical signing bytes
}

var (
	ErrBadSignature      = errors.New("service access capability signature invalid")
	ErrExpired           = errors.New("service access capability expired")
	ErrNoExpiry          = errors.New("service access capability has no expiry (rejected fail-closed)")
	ErrUnknownSigner     = errors.New("service access capability signer not trusted")
	ErrEmptyKeyring      = errors.New("service access capability keyring is empty (deny-all)")
	ErrBadKey            = errors.New("service access capability subject key invalid")
	ErrBadResource       = errors.New("service access capability resource must be \"<org>/<svc>\"")
	ErrProofOfPossession = errors.New("service access capability proof-of-possession invalid")
)

// canonicalBytes is the deterministic signing input: the capability sans signature, as
// JSON. encoding/json marshals struct fields in declaration order, so signer and verifier
// produce byte-identical input (the membershipcap idiom — see §5 of the design; do NOT mix
// the hash-then-sign or sorted-key idioms).
func canonicalBytes(c Capability) ([]byte, error) {
	c.Signature = nil
	return json.Marshal(c)
}

// Sign stamps Issuer + Signature onto the capability using the publisher-org's dedicated
// service-access signing key. It validates the shape fail-closed so a malformed cap can
// never be minted: subject key must be a well-formed ed25519 pubkey, the resource must be
// "<org>/<svc>", and a hard future expiry is mandatory.
func Sign(issuerKeyID string, priv ed25519.PrivateKey, c Capability) (Capability, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Capability{}, ErrBadKey
	}
	if len(c.SubjectPublicKey) != ed25519.PublicKeySize {
		return Capability{}, ErrBadKey
	}
	if _, _, err := ParseResource(c.Resource); err != nil {
		return Capability{}, err
	}
	if c.ExpiresAtMS <= 0 {
		return Capability{}, ErrNoExpiry
	}
	if c.ExpiresAtMS <= c.IssuedAtMS {
		return Capability{}, ErrExpired
	}
	c.Issuer = issuerKeyID
	c.Signature = nil
	b, err := canonicalBytes(c)
	if err != nil {
		return Capability{}, err
	}
	c.Signature = ed25519.Sign(priv, b)
	return c, nil
}

// Verify checks the OFFLINE-checkable core: the cap is signed by a trusted issuer,
// well-formed, and unexpired. It deliberately does NOT check (all caller-owned at the
// terminus, and all fail-closed there): the peer binding (BindsPublicKey against the
// live stream's remote key), the resource match (AuthorizesResource against the SERVED
// namespace), or revocation (the local revocation set). An EMPTY trusted keyring returns
// ErrEmptyKeyring so the terminus denies-all rather than silently skipping the check
// (docs/design/sovereign-service-exposure.md §3/§4 — mirror the empty-allowlist deny-all
// precedent, NOT the fail-open portal-CA drop).
func (c Capability) Verify(trusted map[string]ed25519.PublicKey, nowMS int64) error {
	if len(trusted) == 0 {
		return ErrEmptyKeyring
	}
	pub, ok := trusted[c.Issuer]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrUnknownSigner, c.Issuer)
	}
	if len(c.SubjectPublicKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	if _, _, err := ParseResource(c.Resource); err != nil {
		return err
	}
	if c.ExpiresAtMS <= 0 {
		return ErrNoExpiry
	}
	if nowMS >= c.ExpiresAtMS {
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

// BindsPublicKey reports whether this capability is bound to the given ed25519 public key,
// in constant time. The terminus extracts the handshake-authenticated remote key of the
// connecting stream (s.Conn().RemotePublicKey() raw bytes) and calls this; a mismatch means
// a stolen/replayed cap presented by a different peer, and MUST be denied. Kept in-package
// and libp2p-free: the caller does the (libp2p) key extraction, we do the compare.
func (c Capability) BindsPublicKey(pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(c.SubjectPublicKey) != ed25519.PublicKeySize {
		return false
	}
	return subtle.ConstantTimeCompare(c.SubjectPublicKey, pub) == 1
}

// AuthorizesResource reports whether this capability authorizes the given served namespace,
// in constant time. The terminus reads the `<org>/<svc>` first frame and calls this AFTER
// Verify; a cap for resource A presented on namespace B MUST be denied (prevents a valid
// cap from being replayed across services).
func (c Capability) AuthorizesResource(servedNamespace string) bool {
	if c.Resource == "" || servedNamespace == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Resource), []byte(servedNamespace)) == 1
}

// Challenge is the request-bound proof-of-possession input the requester signs with the
// subject private key when asking the issuer to mint a capability. Binding
// resource+key+nonce stops a captured PoP being lifted onto a different resource, key, or
// issuance. It lives here (the shared protocol leaf) so both the control-plane issuer and
// the consumer client derive byte-identical input without cross-service coupling.
//
// Fields are LENGTH-PREFIXED into the hash (not string-joined by a delimiter) so no
// crafted field value containing a separator can make two distinct (resource, key, nonce)
// tuples collide onto the same challenge.
func Challenge(resource string, subjectPublicKey []byte, requestNonce string) []byte {
	h := sha256.New()
	writeLenPrefixed(h, []byte("fed-svc-pop/v1"))
	writeLenPrefixed(h, []byte(resource))
	writeLenPrefixed(h, subjectPublicKey)
	writeLenPrefixed(h, []byte(requestNonce))
	return h.Sum(nil)
}

func writeLenPrefixed(h hash.Hash, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

// VerifyProofOfPossession proves the requester holds the private half of the subject key
// being bound: it must have signed `challenge`. The control plane calls this at ISSUANCE so
// a consumer cannot obtain a cap bound to a key it does not control. crypto/ed25519 only.
func VerifyProofOfPossession(subjectPublicKey, challenge, popSignature []byte) error {
	if len(subjectPublicKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	if len(challenge) == 0 || len(popSignature) != ed25519.SignatureSize {
		return ErrProofOfPossession
	}
	if !ed25519.Verify(ed25519.PublicKey(subjectPublicKey), challenge, popSignature) {
		return ErrProofOfPossession
	}
	return nil
}

// ParseResource splits a "<org>/<svc>" resource into its parts, rejecting anything that is
// not exactly two non-empty, slash-free segments. This is the un-squattable naming shape:
// the org segment scopes ownership, the svc segment names the service.
func ParseResource(resource string) (org, svc string, err error) {
	if resource == "" {
		return "", "", ErrBadResource
	}
	org, svc, ok := strings.Cut(resource, "/")
	if !ok || org == "" || svc == "" || strings.Contains(svc, "/") {
		return "", "", ErrBadResource
	}
	return org, svc, nil
}

// EncodePublicKey / DecodePublicKey are the transport/storage encoding for the bound
// subject pubkey (URL-safe base64, no padding), matching the membershipcap encoding.
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
