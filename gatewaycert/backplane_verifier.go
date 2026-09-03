package gatewaycert

import (
	"crypto/tls"
	"fmt"
)

// VerifyBackplanePeer is the post-handshake identity check for the relay-cell
// backplane listener. The caller's *tls.Config is expected to pin ClientCAs to the
// backplane CA and set RequireAndVerifyClientCert, so the peer chain is already
// verified against the backplane CA before this runs (a relay-client / transport /
// gateway leaf chains to a different CA and fails the handshake outright).
// VerifyBackplanePeer then enforces that the verified peer leaf presents a
// relay-cell backplane SPIFFE and returns its identity.
//
// It is fail-closed: no peer certificate, or a leaf that does not present a
// backplane SPIFFE, yields ErrPlaneIdentityMismatch and NO identity — never an
// invented one.
//
// S1.5 ships this verifier + its tests. The backplane *listener* itself (the
// *tls.Config builder pinning ClientCAs to the backplane CA, the net.Listen, and
// the cross-cell forwarding) is wired in S2b, alongside the EKU/ServerName decision
// for the mutual cell↔cell direction.
func VerifyBackplanePeer(state tls.ConnectionState) (RelayCellBackplaneIdentity, error) {
	if len(state.PeerCertificates) == 0 {
		return RelayCellBackplaneIdentity{}, fmt.Errorf("%w: backplane peer presented no verified certificate", ErrPlaneIdentityMismatch)
	}
	return RelayCellBackplaneIdentityFromCertificate(state.PeerCertificates[0])
}
