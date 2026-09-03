package orgregistry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ReceiverRendezvousID is the deterministic receiver identity used by frictionless
// by-domain federation. It is BOTH:
//   - the relay rendezvous namespace the receiver parks on, and
//   - the wire partner-link id a sender addresses (the local link's RemotePartnerReference).
//
// Both ends compute it from the recipient org's VERIFIED DOMAIN alone — the federation's
// canonical, coordination-free identity (globally unique by DNS, verifiable by slice-2
// TXT, derivable by a sender with no lookup). No per-pair coordination, no operator-
// authored partner-link. It mirrors the gateway-registration default namespace template
// `fed-{org}-receiver` so a sender derives the exact namespace the receiver already parks on.
//
// Returns "" for an empty input (the caller must treat that as "not derivable").
func ReceiverRendezvousID(orgDomain string) string {
	h := strings.ToLower(strings.TrimSpace(orgDomain))
	if h == "" {
		return ""
	}
	return "fed-" + h + "-receiver"
}

// IsReceiverRendezvousID reports whether an id has the deterministic receiver shape
// `fed-<handle>-receiver` (i.e. was derived, not an operator-authored UUID link id).
// The gateway uses this to decide whether to derive a relay route for a link that
// has no explicit relay-targets entry.
func IsReceiverRendezvousID(id string) bool {
	return OrgHandleFromReceiverRendezvousID(id) != ""
}

// OrgHandleFromReceiverRendezvousID extracts the org identity (its verified domain) from
// a receiver rendezvous id, or "" if the id is not of the deterministic
// `fed-<domain>-receiver` shape. The inverse of ReceiverRendezvousID. (Name retained
// while C1b PR #254 is open; it returns the org's domain, not a handle.)
func OrgHandleFromReceiverRendezvousID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	const prefix, suffix = "fed-", "-receiver"
	if !strings.HasPrefix(id, prefix) || !strings.HasSuffix(id, suffix) {
		return ""
	}
	handle := id[len(prefix) : len(id)-len(suffix)]
	if handle == "" {
		return ""
	}
	return handle
}

// isCanonicalDomain reports whether domain is already in the canonical form the
// contracts PresenceRef accepts: trimmed, lowercase, and ASCII-only (no IDNA
// folding). The contracts subset deliberately does NOT import CanonicalDomain
// from the source orgregistry (it needs golang.org/x/net/idna, outside contracts
// invariant 5's dependency set); the gateway canonicalises via its own
// internal/orgdomain.CanonicalDomain before calling, and non-canonical input
// fails CLOSED here (returns "" — never a fall back to a different digest).
func isCanonicalDomain(domain string) bool {
	if domain == "" {
		return false
	}
	if domain != strings.TrimSpace(domain) || domain != strings.ToLower(domain) {
		return false
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] > 0x7f {
			return false
		}
	}
	return true
}

// PresenceRef is the BLIND rendezvous key a gateway publishes (when parking) and
// targets (when sending) on the relay presence index, so the relay forwarders and
// the shared index never see the cleartext recipient domain (which, embedded in the
// `fed-<domain>-receiver` namespace, would otherwise be dictionary-reversible — the
// C1 finding). It is `pr_` + hex(HMAC-SHA256(epochSecret, canonicalDomain)).
//
// Both ends MUST derive it from the recipient org's verified domain with the SAME
// canonicalization (trim + IDNA-fold + lowercase) so the sender's target and the
// receiver's park resolve to the IDENTICAL key — a one-byte input difference
// yields a completely different digest. epochSecret is held only by gateways and
// never distributed to relay nodes, which is what keeps the index blind.
//
// This contracts form takes ALREADY-canonical ASCII domain input and fails closed
// (returns "") on anything that is not trimmed, lowercase and ASCII-only. Callers
// canonicalise first (the gateway keeps CanonicalDomain as a gateway-local copy).
//
// NOTE: presence_ref blinds only the namespace segment of the relay rendezvous key.
// The forwarder still binds the key to the authenticated relay-client identity
// (tenant/gateway) to prevent a peer that shares epochSecret from parking under
// another org's ref; that tenant segment is a domain on legacy gateways and only
// becomes opaque after the uuid-org relay-client re-enrollment.
//
// Returns "" when epochSecret is empty or orgDomain is not canonical — the caller
// treats that as "not derivable" and must fail closed, never fall back to cleartext.
func PresenceRef(epochSecret []byte, orgDomain string) string {
	if len(epochSecret) == 0 {
		return ""
	}
	if !isCanonicalDomain(orgDomain) {
		return ""
	}
	mac := hmac.New(sha256.New, epochSecret)
	_, _ = mac.Write([]byte(orgDomain))
	return "pr_" + hex.EncodeToString(mac.Sum(nil))
}
