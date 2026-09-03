package orgregistry

import (
	"fmt"
	"strings"

	"github.com/b2bautopilot/xx-federation-contracts/gatewayregistration"
)

// IntakePosture is a receiver's default disposition for a request that reaches it
// by domain. The Relay Mesh grants reachability; this posture (and the receiver's
// per-request policy) decides what that reachability becomes. It is the vocabulary
// sourced from the source orgregistry organization.go with an unchanged body.
type IntakePosture string

const (
	IntakeDrop                IntakePosture = "drop"
	IntakeDeny                IntakePosture = "deny"
	IntakeChallenge           IntakePosture = "challenge"
	IntakeThrottle            IntakePosture = "throttle"
	IntakeNeedsHumanApproval  IntakePosture = "needs_human_approval"
	IntakeAllowLimitedCatalog IntakePosture = "allow_limited_catalog"
	IntakeAllowServiceRequest IntakePosture = "allow_service_request"
	IntakeAllowInvocation     IntakePosture = "allow_invocation"
)

// IsKnownIntakePosture reports whether p is one of the eight defined receiver
// intake outcomes.
func IsKnownIntakePosture(p IntakePosture) bool {
	switch p {
	case IntakeDrop, IntakeDeny, IntakeChallenge, IntakeThrottle,
		IntakeNeedsHumanApproval, IntakeAllowLimitedCatalog,
		IntakeAllowServiceRequest, IntakeAllowInvocation:
		return true
	default:
		return false
	}
}

// DataChannelPosture is a receiver's gate on whether an admitted sender may ALSO
// open the OPTIONAL secondary bulk data channel (the S4 gateway-to-gateway WireGuard
// tunnel). It is SEPARATE from and ADDITIONAL to the intake posture: a data channel
// is granted only when the receiver has opted in here AND the sender is already
// admitted to a service-level intake posture. The zero value ("") = deny, so the
// channel stays closed unless a receiver deliberately opens it. The PRIMARY
// store-and-forward request/response path is never gated by this posture.
type DataChannelPosture string

const (
	DataChannelDeny  DataChannelPosture = "deny"
	DataChannelAllow DataChannelPosture = "allow"
)

// IsKnownDataChannelPosture reports whether p is a recognized data-channel posture.
func IsKnownDataChannelPosture(p DataChannelPosture) bool {
	switch p {
	case DataChannelDeny, DataChannelAllow:
		return true
	default:
		return false
	}
}

// ReceiverIntakePolicy is a receiver's own configuration for deciding what an
// inbound, domain-reached request is allowed to become. It is RECEIVER-OWNED
// control-plane state, re-resolved at intake time — not a relay route and not a
// durable (sender_org, receiver_org) pair table. Approved/blocked sender lists
// are exactly the "approved-customer / private-invite state re-resolved by
// Receiver Control" the relay-mesh plan permits.
type ReceiverIntakePolicy struct {
	// DefaultPosture is applied to a sender with no explicit rule. A receiver
	// that wants to admit nothing by default sets this to drop/deny/challenge.
	DefaultPosture IntakePosture `json:"default_posture"`
	// ApprovedSenderPosture is applied to approved senders (default
	// allow_service_request when unset).
	ApprovedSenderPosture IntakePosture `json:"approved_sender_posture,omitempty"`
	BlockedSenderOrgIDs   []string      `json:"blocked_sender_org_ids,omitempty"`
	ApprovedSenderOrgIDs  []string      `json:"approved_sender_org_ids,omitempty"`
	// DataChannelPosture gates the OPTIONAL secondary bulk data channel (the S4
	// gateway-to-gateway WireGuard tunnel). Zero value ("") = deny; only
	// DataChannelAllow opens the gate, and even then only for a sender already
	// admitted to a service-level intake posture. The PRIMARY store-and-forward
	// request/response path is never gated by this.
	DataChannelPosture DataChannelPosture `json:"data_channel_posture,omitempty"`
}

// Validate fail-closes on an unknown configured posture.
func (p ReceiverIntakePolicy) Validate() error {
	if !IsKnownIntakePosture(p.DefaultPosture) {
		return fmt.Errorf("default_posture %q is not a known intake posture", p.DefaultPosture)
	}
	if p.ApprovedSenderPosture != "" && !IsKnownIntakePosture(p.ApprovedSenderPosture) {
		return fmt.Errorf("approved_sender_posture %q is not a known intake posture", p.ApprovedSenderPosture)
	}
	if p.DataChannelPosture != "" && !IsKnownDataChannelPosture(p.DataChannelPosture) {
		return fmt.Errorf("data_channel_posture %q is not a known data-channel posture", p.DataChannelPosture)
	}
	return nil
}

// IntakeRequest is the authenticated context for one inbound request. The
// authoritative sender identity is VerifiedSenderOrgID, derived from the verified
// csr_derived gateway certificate chain. PayloadAssertedSenderOrgID is a
// display/advisory value from the request body — it is NEVER an authorization
// input; it is cross-checked only to fail closed on a mismatch.
type IntakeRequest struct {
	VerifiedSenderOrgID        string
	PayloadAssertedSenderOrgID string
	SenderStatus               gatewayregistration.OrgStatus
}

// IntakeDecision is the receiver's outcome plus a safe reason code/string.
type IntakeDecision struct {
	Posture IntakePosture `json:"posture"`
	Reason  string        `json:"reason"`
}

// DecideIntake computes the receiver-owned intake outcome, fail-closed, keying on
// the VERIFIED csr_derived sender identity (never the payload). Precedence:
//
//	no verified identity                  -> drop
//	payload-asserted != verified          -> drop   (spoofing cross-check)
//	sender status not production-eligible -> deny   (unknown, empty/unwired,
//	                                           pending, terminal — see below)
//	sender blocked by policy              -> deny
//	sender approved by policy              -> ApprovedSenderPosture (default allow_service_request)
//	otherwise                             -> DefaultPosture (unset -> challenge)
//
// The sender-status gate uses RegistrationEligibilityForOrgStatus: only a
// production-eligible status (active) reaches policy evaluation. An unknown,
// empty/unwired, pending, or terminal status denies — a permissive
// DefaultPosture can never admit a sender whose standing is not established.
// An empty status is deliberately a deny (not "not yet wired, defer to
// policy"): a lookup miss must not fail open.
//
// Automatic rate-based throttle (counters) and the downstream PolicyGrant /
// execution are out of scope here; a receiver may still set DefaultPosture or
// ApprovedSenderPosture to throttle / needs_human_approval.
func DecideIntake(policy ReceiverIntakePolicy, request IntakeRequest) IntakeDecision {
	verified := strings.TrimSpace(request.VerifiedSenderOrgID)
	if verified == "" {
		return IntakeDecision{IntakeDrop, "no verified sender identity"}
	}
	if asserted := strings.TrimSpace(request.PayloadAssertedSenderOrgID); asserted != "" && asserted != verified {
		return IntakeDecision{IntakeDrop, "payload-asserted sender does not match the verified csr_derived identity"}
	}
	eligibility := gatewayregistration.RegistrationEligibilityForOrgStatus(request.SenderStatus)
	if !eligibility.ProductionAllowed {
		if eligibility.Disposition == gatewayregistration.DispositionTerminalError {
			return IntakeDecision{IntakeDeny, "sender organization is suspended, revoked, or unknown"}
		}
		return IntakeDecision{IntakeDeny, "sender organization is not in production standing"}
	}
	if intakeContainsOrg(policy.BlockedSenderOrgIDs, verified) {
		return IntakeDecision{IntakeDeny, "sender is blocked by receiver policy"}
	}
	if intakeContainsOrg(policy.ApprovedSenderOrgIDs, verified) {
		posture := policy.ApprovedSenderPosture
		if !IsKnownIntakePosture(posture) {
			posture = IntakeAllowServiceRequest
		}
		return IntakeDecision{posture, "sender is an approved partner"}
	}
	defaultPosture := policy.DefaultPosture
	if !IsKnownIntakePosture(defaultPosture) {
		defaultPosture = IntakeChallenge
	}
	return IntakeDecision{defaultPosture, "receiver default intake posture"}
}

// DataChannelDecision is the receiver's outcome for an OPTIONAL bulk data-channel
// request (the S4 WireGuard tunnel) plus a safe reason string.
type DataChannelDecision struct {
	Granted bool   `json:"granted"`
	Reason  string `json:"reason"`
}

// dataChannelEligibleIntake reports whether an intake posture is service-level —
// the only postures that may ALSO yield a data channel. A catalog-only, challenged,
// throttled, needs-approval, dropped, or denied sender never gets a tunnel.
func dataChannelEligibleIntake(p IntakePosture) bool {
	return p == IntakeAllowServiceRequest || p == IntakeAllowInvocation
}

// DecideDataChannel computes whether an admitted sender may ALSO open the optional
// secondary bulk data channel (the S4 gateway-to-gateway WireGuard tunnel). It is
// SELF-CONTAINED and fail-closed: it runs the receiver's primary intake gate
// (DecideIntake — VERIFIED csr_derived identity, sender status, block/approve lists)
// on the request itself, so a caller cannot bypass identity verification by
// hand-building an IntakeDecision. DEFAULT DENY: a channel is granted ONLY when ALL
// of the following hold —
//
//	(1) the receiver opted in            (DataChannelPosture == DataChannelAllow), AND
//	(2) the intake gate admitted the sender to a service-level posture
//	    (allow_service_request / allow_invocation),                              AND
//	(3) the sender org is production-eligible — a bulk tunnel is a
//	    higher-trust grant than a single request, so a non-production,
//	    unknown, or terminal sender is held to the primary path. DecideIntake
//	    already enforces this; the explicit check here is defense-in-depth so
//	    the channel gate stays closed even if the intake gate ever changes.
//
// NOTE (receiver-owned footgun): a receiver who runs a PERMISSIVE
// DefaultPosture (allow_service_request / allow_invocation) AND opens the
// channel (DataChannelAllow) grants a tunnel to every production-eligible
// verified sender. A receiver who wants the tunnel restricted should NAME
// senders in ApprovedSenderOrgIDs rather than rely on a permissive default
// (the same senders a permissive default already auto-admits to the primary
// exchange).
//
// It is purely additive — the PRIMARY store-and-forward path is never gated by this,
// and a deny here leaves the sender's primary exchange untouched.
func DecideDataChannel(policy ReceiverIntakePolicy, request IntakeRequest) DataChannelDecision {
	if policy.DataChannelPosture != DataChannelAllow {
		return DataChannelDecision{false, "receiver data-channel posture is deny (default)"}
	}
	intake := DecideIntake(policy, request)
	if !dataChannelEligibleIntake(intake.Posture) {
		return DataChannelDecision{false, "sender not admitted to a service-level intake posture: " + intake.Reason}
	}
	if !gatewayregistration.RegistrationEligibilityForOrgStatus(request.SenderStatus).ProductionAllowed {
		return DataChannelDecision{false, "data channel requires a production-eligible sender in good standing"}
	}
	return DataChannelDecision{true, "receiver allows a data channel for this admitted sender"}
}

func intakeContainsOrg(list []string, orgID string) bool {
	orgID = strings.TrimSpace(orgID)
	for _, v := range list {
		if strings.TrimSpace(v) == orgID {
			return true
		}
	}
	return false
}
