// Package attachment lifecycle: the authoritative custody-lifecycle and
// download-evidence vocabulary for orchestration attachments (issue #21,
// parent epic #18, spec revision 10).
//
// Authority: spec/b2b-federation-spec-v1.xml revision 10. The control plane
// (comp.builders-control, xx-builders-net) owns every custody object and
// evaluates every lifecycle transition and download decision server-side.
// The formal API surface lives in api/proto/builders/v1/attachment.proto
// (artifact.contracts.attachment-proto); this file is its enforcement
// implementation, not a second source of truth.
//
// Lifecycle model (closed; unknown states fail closed):
//
//	offered -> authorized -> fetched -> verified -> returned
//	produced -> verified -> returned
//	any non-terminal -> rejected | expired
//
// Terminal states (expired, rejected) accept no further transition.
//
// An attachment NEVER carries bytes, capability tokens, URLs, storage
// locations, paths, secrets, prompts, reasoning, or tool arguments: only
// the AttachmentRef descriptor defined in attachment.go travels, wrapped
// here with its server-evaluated lifecycle and downloadability decision.
// The browser (or any viewer) NEVER supplies a descriptor or a safety
// verdict; it reads AttachmentEvidence evaluated at EvaluatedAtMS.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/attachment
// Spec evidence: rel.agent-connects-control (attachment custody),
// rel.portal-dials-control (attachment evidence).
package attachment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Attachment lifecycle states. Entry is offered (fetch intent: the control
// authorizes a fetch capability) or produced (agent output submitted
// directly). verified gates returned: only digest/MIME-verified custody is
// ever bound as a result.
const (
	LifecycleOffered    = "offered"
	LifecycleAuthorized = "authorized"
	LifecycleFetched    = "fetched"
	LifecycleVerified   = "verified"
	LifecycleProduced   = "produced"
	LifecycleReturned   = "returned"
	LifecycleExpired    = "expired"
	LifecycleRejected   = "rejected"
)

// Download-decision reasons. downloadable is true if and only if the reason
// is available; the equivalence is enforced mechanically by
// ValidateEvidence so a server cannot claim "available" while reporting a
// blocking reason (or vice versa).
const (
	DownloadAvailable   = "available"
	DownloadScanPending = "scan_pending"
	DownloadNotClean    = "not_clean"
	DownloadExpired     = "expired"
	DownloadNotVerified = "not_verified"
	DownloadNotVisible  = "not_visible"
)

// Reject verdicts. quarantine retains bytes but revokes fetch forever;
// block discards bytes and retains metadata for audit. Nothing else is a
// legal verdict.
const (
	RejectQuarantine = "quarantine"
	RejectBlock      = "block"
)

// Put completion states. stored marks first completion; replayed marks an
// idempotent retry that bound the same custody instead of minting a
// duplicate. Nothing else is a legal completion state.
const (
	PutStored   = "stored"
	PutReplayed = "replayed"
)

// Custody RPC operation names. These are the exact rpc names served by
// AttachmentService in api/proto/builders/v1/attachment.proto; the
// orchestration consistency gate pins the two sides together.
const (
	CustodyOpMintCapability   = "mint_capability"
	CustodyOpPutAttachment    = "put_attachment"
	CustodyOpFetchAttachment  = "fetch_attachment"
	CustodyOpGetAttachment    = "get_attachment_ref"
	CustodyOpRejectAttachment = "reject_attachment"
	CustodyOpSweepAttachments = "sweep_attachments"
)

// Capability actions: the single action one capability authorizes. put
// covers upload and returned-artifact intake, fetch covers the agent fetch
// leg, download covers the browser download leg.
const (
	CapabilityPut      = "put"
	CapabilityFetch    = "fetch"
	CapabilityDownload = "download"
)

// MaxReasonCodeLen bounds a caller-supplied reject reason code. Reason codes
// are operator labels, never authorization input: the verdict enum decides.
const MaxReasonCodeLen = 128

var (
	ErrUnknownLifecycle = errors.New("attachment lifecycle unknown")
	ErrIllegalLifecycle = errors.New("attachment illegal lifecycle transition")
	ErrTerminalCustody  = errors.New("attachment custody is terminal")
	ErrUnknownReason    = errors.New("attachment download reason unknown")
	ErrUnknownVerdict   = errors.New("attachment reject verdict unknown")
	ErrUnknownPutStatus = errors.New("attachment put status unknown")
	ErrUnknownAction    = errors.New("attachment capability action unknown")
	ErrBadReasonCode    = errors.New("attachment reason code invalid")
	ErrEvidenceMismatch = errors.New("attachment evidence inconsistent")
)

// ValidLifecycle reports whether value names a declared custody lifecycle
// state.
func ValidLifecycle(value string) bool {
	switch value {
	case LifecycleOffered, LifecycleAuthorized, LifecycleFetched,
		LifecycleVerified, LifecycleProduced, LifecycleReturned,
		LifecycleExpired, LifecycleRejected:
		return true
	default:
		return false
	}
}

// IsTerminalLifecycle reports whether no further custody transition is
// legal. Expired and rejected objects stay readable as metadata for audit
// but are never fetchable again.
func IsTerminalLifecycle(value string) bool {
	return value == LifecycleExpired || value == LifecycleRejected
}

// AllowedLifecycleTransition reports whether custody may move from one
// state to the next. Unknown states and any move out of a terminal state
// fail closed.
func AllowedLifecycleTransition(from, to string) bool {
	if !ValidLifecycle(from) || !ValidLifecycle(to) || IsTerminalLifecycle(from) {
		return false
	}
	switch from {
	case LifecycleOffered:
		return to == LifecycleAuthorized || to == LifecycleRejected || to == LifecycleExpired
	case LifecycleAuthorized:
		return to == LifecycleFetched || to == LifecycleRejected || to == LifecycleExpired
	case LifecycleFetched:
		return to == LifecycleVerified || to == LifecycleRejected || to == LifecycleExpired
	case LifecycleVerified:
		return to == LifecycleReturned || to == LifecycleRejected || to == LifecycleExpired
	case LifecycleProduced:
		return to == LifecycleVerified || to == LifecycleRejected || to == LifecycleExpired
	case LifecycleReturned:
		return to == LifecycleExpired
	default:
		return false
	}
}

// ServableLifecycle reports whether the lifecycle gate permits download
// evaluation at all: only verified custody bound (or ready to bind) as a
// result may serve bytes. Every other non-terminal state reports
// not_verified instead of a fetchable verdict.
func ServableLifecycle(value string) bool {
	return value == LifecycleVerified || value == LifecycleReturned
}

// ValidDownloadReason reports whether value names a declared decision
// reason.
func ValidDownloadReason(value string) bool {
	switch value {
	case DownloadAvailable, DownloadScanPending, DownloadNotClean,
		DownloadExpired, DownloadNotVerified, DownloadNotVisible:
		return true
	default:
		return false
	}
}

// ValidRejectVerdict reports whether value names a declared reject
// verdict.
func ValidRejectVerdict(value string) bool {
	return value == RejectQuarantine || value == RejectBlock
}

// ValidPutStatus reports whether value names a declared put completion
// state.
func ValidPutStatus(value string) bool {
	return value == PutStored || value == PutReplayed
}

// ValidCapabilityAction reports whether value names a declared capability
// action.
func ValidCapabilityAction(value string) bool {
	switch value {
	case CapabilityPut, CapabilityFetch, CapabilityDownload:
		return true
	default:
		return false
	}
}

// ValidateReasonCode enforces the reject reason-code shape: non-empty,
// bounded, and limited to a log-safe alphabet. The code is a label only;
// authorization keys off the verdict enum.
func ValidateReasonCode(code string) error {
	if code == "" || len(code) > MaxReasonCodeLen {
		return fmt.Errorf("%w: length %d", ErrBadReasonCode, len(code))
	}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.' || r == ':') {
			return fmt.Errorf("%w: unsafe alphabet", ErrBadReasonCode)
		}
	}
	return nil
}

// AttachmentEvidence is the server-evaluated, viewer-scoped evidence for
// one custody object: its descriptor, its custody lifecycle state, the
// downloadability decision for the requesting viewer, the closed decision
// reason, and the server evaluation time. Viewers read this; they never
// supply any part of it.
type AttachmentEvidence struct {
	SchemaVersion string        `json:"schema_version"`
	Ref           AttachmentRef `json:"ref"`
	Lifecycle     string        `json:"lifecycle"`
	Downloadable  bool          `json:"downloadable"`
	Reason        string        `json:"reason"`
	EvaluatedAtMS int64         `json:"evaluated_at_ms"`
}

// Schema identifier for attachment evidence documents.
const SchemaAttachmentEvidenceV1 = "builders.federation.attachment_evidence.v1"

// EvaluateEvidence renders the server decision for one custody object as
// seen by one viewer audience at one server time. The precedence is fixed
// and total: server-recorded terminal states dominate (expired, then
// rejected), then descriptor liveness (expired, then malformed/blocked),
// then scan state, then the lifecycle gate, then viewer visibility.
// Every input maps to exactly one reason; nothing defaults to available.
func EvaluateEvidence(ref AttachmentRef, lifecycle, viewerAudience string, nowMS int64) (AttachmentEvidence, error) {
	if !ValidLifecycle(lifecycle) {
		return AttachmentEvidence{}, fmt.Errorf("%w: %q", ErrUnknownLifecycle, lifecycle)
	}
	if !ValidAudience(viewerAudience) {
		return AttachmentEvidence{}, fmt.Errorf("%w: %q", ErrUnknownAudience, viewerAudience)
	}
	ev := AttachmentEvidence{
		SchemaVersion: SchemaAttachmentEvidenceV1,
		Ref:           ref,
		Lifecycle:     lifecycle,
		EvaluatedAtMS: nowMS,
	}
	switch {
	case lifecycle == LifecycleExpired:
		ev.Reason = DownloadExpired
	case lifecycle == LifecycleRejected:
		ev.Reason = DownloadNotClean
	case nowMS >= ref.ExpiresAtMS || ref.ExpiresAtMS <= 0:
		ev.Reason = DownloadExpired
	case shapeError(ref) != nil:
		ev.Reason = DownloadNotVerified
	case ref.ScanState == ScanPending:
		ev.Reason = DownloadScanPending
	case ref.ScanState != ScanClean:
		ev.Reason = DownloadNotClean
	case !ServableLifecycle(lifecycle):
		ev.Reason = DownloadNotVerified
	case viewerAudience == AudiencePartner && ref.Audience != AudiencePartner:
		ev.Reason = DownloadNotVisible
	default:
		ev.Reason = DownloadAvailable
	}
	ev.Downloadable = ev.Reason == DownloadAvailable
	return ev, nil
}

// shapeError reports whether the descriptor is malformed without judging
// liveness (expiry, scan): malformed descriptors can never verify, so they
// report not_verified rather than a serving verdict.
func shapeError(ref AttachmentRef) error {
	if ref.SchemaVersion != SchemaAttachmentRefV1 {
		return fmt.Errorf("%w: schema %q", ErrBadRef, ref.SchemaVersion)
	}
	if strings.TrimSpace(ref.AttachmentID) == "" || len(ref.AttachmentID) > 128 {
		return fmt.Errorf("%w: bad id", ErrBadRef)
	}
	if len(ref.SHA256Hex) != 64 {
		return fmt.Errorf("%w: digest must be 64 hex chars", ErrBadRef)
	}
	if ref.SizeBytes <= 0 || ref.SizeBytes > MaxAttachmentBytes {
		return fmt.Errorf("%w: size %d", ErrOversize, ref.SizeBytes)
	}
	if strings.TrimSpace(ref.MIME) == "" || !ContentAllowed(ref.MIME) {
		return fmt.Errorf("%w: declared MIME blocked", ErrBlockedContent)
	}
	if ref.DisplayName != SanitizeDisplayName(ref.DisplayName) {
		return fmt.Errorf("%w: display name not sanitized", ErrBadRef)
	}
	if !ValidDirection(ref.Direction) {
		return fmt.Errorf("%w: %q", ErrUnknownDir, ref.Direction)
	}
	if !ValidScanState(ref.ScanState) {
		return fmt.Errorf("%w: %q", ErrUnknownScan, ref.ScanState)
	}
	if !ValidAudience(ref.Audience) {
		return fmt.Errorf("%w: %q", ErrUnknownAudience, ref.Audience)
	}
	return nil
}

// ValidateEvidence checks one evidence document fail-closed: known
// lifecycle and reason, a positive evaluation time, the mechanical
// equivalence downloadable == (reason == available), and a well-formed
// embedded descriptor. Liveness itself is the decision's job, not the
// shape's: expired and rejected evidence is legitimate projection and
// must validate as long as its decision says so.
func ValidateEvidence(ev AttachmentEvidence) error {
	if ev.SchemaVersion != SchemaAttachmentEvidenceV1 {
		return fmt.Errorf("%w: schema %q", ErrBadRef, ev.SchemaVersion)
	}
	if !ValidLifecycle(ev.Lifecycle) {
		return fmt.Errorf("%w: %q", ErrUnknownLifecycle, ev.Lifecycle)
	}
	if !ValidDownloadReason(ev.Reason) {
		return fmt.Errorf("%w: %q", ErrUnknownReason, ev.Reason)
	}
	if ev.EvaluatedAtMS <= 0 {
		return fmt.Errorf("%w: unevaluated evidence", ErrEvidenceMismatch)
	}
	if ev.Downloadable != (ev.Reason == DownloadAvailable) {
		return fmt.Errorf("%w: downloadable=%v with reason %q",
			ErrEvidenceMismatch, ev.Downloadable, ev.Reason)
	}
	if err := shapeError(ev.Ref); err != nil {
		return err
	}
	if ev.Lifecycle == LifecycleExpired && ev.Reason != DownloadExpired {
		return fmt.Errorf("%w: expired custody must report expired", ErrEvidenceMismatch)
	}
	if ev.Lifecycle == LifecycleRejected && ev.Downloadable {
		return fmt.Errorf("%w: rejected custody is never downloadable", ErrEvidenceMismatch)
	}
	return nil
}

// DecodeEvidenceStrict parses one evidence document with unknown JSON
// fields rejected fail-closed.
func DecodeEvidenceStrict(raw []byte) (AttachmentEvidence, error) {
	var ev AttachmentEvidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return AttachmentEvidence{}, fmt.Errorf("%w: %v", ErrBadRef, err)
	}
	return ev, nil
}
