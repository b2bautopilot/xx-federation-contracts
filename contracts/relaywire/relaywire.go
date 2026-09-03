// Package relaywire is the SHARED control protocol spoken on the OUTER mTLS
// connections between a federation gateway and the opaque relay forwarder
// (FED-P16-007b-c). It is deliberately tiny: each party sends exactly ONE
// length-prefixed JSON control frame to set up the rendezvous, after which the
// connection switches to a RAW byte splice that carries the INNER mTLS tunnel
// (A<->B) the forwarder never parses.
//
// The forwarder reads ONLY these control frames; it never inspects the spliced
// inner-TLS bytes (payload-blind). Routing identities here are HINTS the forwarder
// uses to pair a submit with a parked responder — the authority over WHO B is, is
// the inner mTLS pin enforced end-to-end between A and B (a misroute fails the
// inner pin closed, no envelope written).
package relaywire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	federationtransport "github.com/b2bautopilot/xx-federation-contracts/contracts/transport"
)

// Control message types.
const (
	// TypeRegister: responder B -> forwarder. B parks an outbound conn under
	// (Namespace, verified-B-identity) and blocks for a Deliver.
	TypeRegister = "register"
	// TypeSubmit: initiator A -> forwarder. A asks to be paired with a parked
	// responder for (Namespace, TargetIdentity).
	TypeSubmit = "submit"
	// TypeDeliver: forwarder -> responder B. "A peer is paired; start the inner
	// mTLS handshake as SERVER now." Carries the verified A identity as a hint.
	TypeDeliver = "deliver"
	// TypeEstablished: forwarder -> initiator A. "Paired; start the inner mTLS
	// handshake as CLIENT now."
	TypeEstablished = "established"
	// TypeError: forwarder -> A/B. A sanitized, fixed-code failure; the conn closes.
	TypeError = "error"
	// TypeBackplaneSubmit: forwarder cell A -> forwarder cell B over the relay backplane
	// (S2b). Cell A had no LOCAL parked responder, found cell B in the presence index, and
	// forwards A's submit one hop. Cell B recomputes the IDENTICAL rendezvous key, claims a
	// LOCAL responder, and splices the backplane leg to it. Hop>1 is rejected (no re-hop).
	TypeBackplaneSubmit = "backplane_submit"
)

// Sanitized, fixed forwarder error codes (never leak host/IP/identity detail).
const (
	ErrorNoTarget     = "no_target"    // no parked responder for (namespace, target)
	ErrorAtCapacity   = "at_capacity"  // registry / splice concurrency ceiling reached
	ErrorUnauthorized = "unauthorized" // client cert carries no usable gateway identity
	ErrorTimeout      = "timeout"      // pairing / control deadline expired
	ErrorMalformed    = "malformed"    // undecodable / wrong-shape control frame
	ErrorInternal     = "internal"     // forwarder-side fault
)

// DefaultMaxControlFrameBytes caps a single control frame. Control frames are
// tiny (a namespace + two identities); a small cap bounds a hostile prefix BEFORE
// allocation, independent of the much larger inner-exchange frame cap.
const DefaultMaxControlFrameBytes = 64 * 1024

const frameHeaderLen = 4

var (
	// ErrControlFrameTooLarge is returned (before allocating the body) when a
	// declared control-frame length exceeds the cap.
	ErrControlFrameTooLarge = errors.New("relay control frame exceeds maximum size")
	// ErrControlFrameEmpty is returned when a control frame declares a zero body.
	ErrControlFrameEmpty = errors.New("relay control frame is empty")
)

// Control is the single rendezvous control message. Unused fields are zero. The
// identity fields are ROUTING HINTS only (the inner mTLS pin is the authority).
type Control struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
	// PresenceRef, when set, is the BLIND rendezvous key (orgregistry.PresenceRef) the
	// gateway uses INSTEAD of the cleartext Namespace, so the forwarder + shared index
	// never see the recipient domain (S2a). When set, the forwarder keys on it and uses
	// OrgLevel for the org-vs-bilateral decision (it can no longer sniff the namespace
	// shape); when empty, the forwarder falls back to the legacy cleartext Namespace
	// path. Both ends of a pairing must set it identically.
	PresenceRef string `json:"presence_ref,omitempty"`
	// OrgLevel marks an org-level (frictionless by-domain) rendezvous when PresenceRef
	// is set — the forwarder drops the gateway id from the key so ANY of the org's
	// gateways pairs. Ignored on the legacy namespace path (the shape is sniffed there).
	OrgLevel       bool                         `json:"org_level,omitempty"`
	TargetIdentity federationtransport.Identity `json:"target_identity,omitzero"`
	SenderIdentity federationtransport.Identity `json:"sender_identity,omitzero"`
	// Hop counts relay backplane hops (S2b). A direct A->forwarder submit is hop 0; a
	// forwarder->forwarder BackplaneSubmit is hop 1. The receiving cell claims LOCAL only
	// and never re-hops — a cross-cell submit makes at most ONE backplane hop.
	Hop       int    `json:"hop"`
	ErrorCode string `json:"error_code,omitempty"`
}

// Normalized trims the type/namespace/presence-ref/error code and normalizes identities.
func (c Control) Normalized() Control {
	c.Type = strings.TrimSpace(c.Type)
	c.Namespace = strings.TrimSpace(c.Namespace)
	c.PresenceRef = strings.TrimSpace(c.PresenceRef)
	c.ErrorCode = strings.TrimSpace(c.ErrorCode)
	c.TargetIdentity = c.TargetIdentity.Normalized()
	c.SenderIdentity = c.SenderIdentity.Normalized()
	return c
}

// WriteControl encodes msg as JSON and writes it as a length-prefixed frame.
func WriteControl(w io.Writer, msg Control) error {
	body, err := json.Marshal(msg.Normalized())
	if err != nil {
		return fmt.Errorf("marshal relay control: %w", err)
	}
	return writeFrame(w, body)
}

// ReadControl reads ONE length-prefixed control frame (rejecting oversize BEFORE
// allocation) and decodes it. maxBytes <= 0 falls back to the default cap.
func ReadControl(r io.Reader, maxBytes int) (Control, error) {
	body, err := readFrame(r, maxBytes)
	if err != nil {
		return Control{}, err
	}
	var msg Control
	if err := json.Unmarshal(body, &msg); err != nil {
		return Control{}, fmt.Errorf("decode relay control: %w", err)
	}
	return msg.Normalized(), nil
}

// writeFrame writes a 4-byte big-endian length prefix followed by body.
func writeFrame(w io.Writer, body []byte) error {
	if len(body) == 0 {
		return ErrControlFrameEmpty
	}
	var prefix [frameHeaderLen]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return fmt.Errorf("write relay control prefix: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write relay control body: %w", err)
	}
	return nil
}

// readFrame reads a length-prefixed frame, rejecting an oversize declared length
// BEFORE allocating the body buffer.
func readFrame(r io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxControlFrameBytes
	}
	var prefix [frameHeaderLen]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("read relay control prefix: %w", err)
	}
	declared := binary.BigEndian.Uint32(prefix[:])
	if declared == 0 {
		return nil, ErrControlFrameEmpty
	}
	if int64(declared) > int64(maxBytes) {
		return nil, fmt.Errorf("%w: declared=%d max=%d", ErrControlFrameTooLarge, declared, maxBytes)
	}
	body := make([]byte, declared)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read relay control body: %w", err)
	}
	return body, nil
}
