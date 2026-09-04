// Typed GetRun/observation projection (issue #21, parent epic #18, spec
// revision 10).
//
// Authority: spec/b2b-federation-spec-v1.xml revision 10. The control plane
// (comp.builders-control) is the ONLY producer of this projection: run,
// complete roster with authoritative participant state, task DAG, runtime
// provenance records, attachment evidence (never bytes), server-computed
// aggregate counts, and explicit degraded/incomplete/cursor state. The
// portal (comp.builders-portal, xx-builders-portal#12) renders ONLY these
// fields; anything absent here must not be synthesized.
//
// Fail-closed rules enforced by this file:
//   - unknown participant states fail closed wherever status gates a
//     decision; legacy rows without status normalize explicitly
//     (NormalizeParticipantStatus), never silently;
//   - roster/task/provenance/attachment cross-references must resolve
//     (missing or duplicate entries fail the projection);
//   - run/tenant/provenance/attachment references must agree on run and
//     tenant scope;
//   - counts must be non-negative and exactly equal the served sections;
//   - cursors must be non-negative with next_after_seq <= head_seq, and
//     incomplete is exactly (next_after_seq < head_seq);
//   - sections must be in deterministic id order for byte-identical
//     canonical serialization;
//   - partner views carry no roster, task, provenance, or session identity,
//     only partner-audience evidence re-evaluated for the partner viewer.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/orchestration
// Spec evidence: rel.portal-dials-control (observation projection),
// rel.agent-connects-control (participant lifecycle).
package orchestration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/attachment"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/provenance"
)

// Schema identifier for the typed GetRun/observation projection.
const SchemaRunProjectionV1 = "builders.federation.run_projection.v1"

// Participant lifecycle states. invited marks a control-accepted slot with
// no session bound yet; active marks a bound live session; suspended marks
// an administratively paused session (resumable to active); departed and
// removed are terminal (graceful leave vs administrative removal).
const (
	ParticipantInvited   = "invited"
	ParticipantActive    = "active"
	ParticipantSuspended = "suspended"
	ParticipantDeparted  = "departed"
	ParticipantRemoved   = "removed"
)

var (
	ErrUnknownParticipantStatus = errors.New("orchestration participant status unknown")
	ErrBadCounts                = errors.New("orchestration observation counts invalid")
	ErrProjectionMismatch       = errors.New("orchestration projection inconsistent")
	ErrBadCursor                = errors.New("orchestration projection cursor invalid")
	ErrUnsortedProjection       = errors.New("orchestration projection not deterministically ordered")
)

// ValidParticipantStatus reports whether value names a declared
// participant lifecycle state. The empty string is NOT valid: callers that
// accept legacy rows must normalize explicitly via
// NormalizeParticipantStatus so the default is visible, never silent.
func ValidParticipantStatus(value string) bool {
	switch value {
	case ParticipantInvited, ParticipantActive, ParticipantSuspended,
		ParticipantDeparted, ParticipantRemoved:
		return true
	default:
		return false
	}
}

// IsTerminalParticipantStatus reports whether no further lifecycle move is
// legal. Unknown states report false: an unknown state is not safely
// terminal, and AllowedParticipantTransition rejects it regardless.
func IsTerminalParticipantStatus(value string) bool {
	return value == ParticipantDeparted || value == ParticipantRemoved
}

// AllowedParticipantTransition reports whether a participant may move from
// one lifecycle state to the next. Unknown states and any move out of a
// terminal state fail closed.
func AllowedParticipantTransition(from, to string) bool {
	if !ValidParticipantStatus(from) || !ValidParticipantStatus(to) || IsTerminalParticipantStatus(from) {
		return false
	}
	switch from {
	case ParticipantInvited:
		return to == ParticipantActive || to == ParticipantRemoved
	case ParticipantActive:
		return to == ParticipantSuspended || to == ParticipantDeparted || to == ParticipantRemoved
	case ParticipantSuspended:
		return to == ParticipantActive || to == ParticipantDeparted || to == ParticipantRemoved
	default:
		return false
	}
}

// NormalizeParticipantStatus maps a stored roster entry to its
// authoritative state, making the legacy default explicit. Rows recorded
// before status existed (revision 9) carry no status: a row WITH an
// authenticated session/workload/container binding was live, so it reads
// as active; a row with no binding is an unbound slot, so it reads as
// invited. Unknown non-empty states stay unknown (and fail validation);
// normalization never invents a binding.
func NormalizeParticipantStatus(p AgentParticipant) string {
	if p.Status != "" {
		return p.Status
	}
	if strings.TrimSpace(p.SessionID) != "" &&
		strings.TrimSpace(p.WorkloadID) != "" &&
		strings.TrimSpace(p.ContainerID) != "" {
		return ParticipantActive
	}
	return ParticipantInvited
}

// ObservationCounts are the server-computed aggregates the BFF/UI needs
// without synthesizing: roster size and live sessions, task DAG size and
// terminal states, provenance records, attachment evidence size and the
// viewer-scoped downloadable count, and the authoritative ledger head
// sequence framing the NextAfterSeq cursor.
type ObservationCounts struct {
	ParticipantsTotal       int64 `json:"participants_total"`
	ParticipantsActive      int64 `json:"participants_active"`
	TasksTotal              int64 `json:"tasks_total"`
	TasksTerminal           int64 `json:"tasks_terminal"`
	ProvenanceTotal         int64 `json:"provenance_total"`
	AttachmentsTotal        int64 `json:"attachments_total"`
	AttachmentsDownloadable int64 `json:"attachments_downloadable"`
	HeadSeq                 int64 `json:"head_seq"`
}

// ValidateCounts checks count shape fail-closed: every count
// non-negative, every part bounded by its whole, and the head sequence
// non-negative. Negative or part-exceeds-whole counts are never served.
func ValidateCounts(c ObservationCounts) error {
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"participants_total", c.ParticipantsTotal},
		{"participants_active", c.ParticipantsActive},
		{"tasks_total", c.TasksTotal},
		{"tasks_terminal", c.TasksTerminal},
		{"provenance_total", c.ProvenanceTotal},
		{"attachments_total", c.AttachmentsTotal},
		{"attachments_downloadable", c.AttachmentsDownloadable},
		{"head_seq", c.HeadSeq},
	} {
		if field.value < 0 {
			return fmt.Errorf("%w: %s = %d", ErrBadCounts, field.name, field.value)
		}
	}
	if c.ParticipantsActive > c.ParticipantsTotal {
		return fmt.Errorf("%w: active participants exceed total", ErrBadCounts)
	}
	if c.TasksTerminal > c.TasksTotal {
		return fmt.Errorf("%w: terminal tasks exceed total", ErrBadCounts)
	}
	if c.AttachmentsDownloadable > c.AttachmentsTotal {
		return fmt.Errorf("%w: downloadable attachments exceed total", ErrBadCounts)
	}
	return nil
}

// ComputeCounts derives the authoritative counts from the exact sections
// being served. parts/tasks/providence/evidence must be the served slices
// (already validated); headSeq is the ledger head at projection time. Any
// arithmetic overflow fails closed rather than wrapping.
func ComputeCounts(parts []AgentParticipant, tasks []OrchestrationTask, prov []provenance.RuntimeProvenance, evidence []attachment.AttachmentEvidence, headSeq int64) (ObservationCounts, error) {
	if headSeq < 0 {
		return ObservationCounts{}, fmt.Errorf("%w: head_seq = %d", ErrBadCounts, headSeq)
	}
	active := int64(0)
	for _, p := range parts {
		if NormalizeParticipantStatus(p) == ParticipantActive {
			var err error
			active, err = checkedAdd(active, 1)
			if err != nil {
				return ObservationCounts{}, err
			}
		}
	}
	terminal := int64(0)
	for _, t := range tasks {
		if IsTerminalTaskState(t.State) {
			var err error
			terminal, err = checkedAdd(terminal, 1)
			if err != nil {
				return ObservationCounts{}, err
			}
		}
	}
	downloadable := int64(0)
	for _, ev := range evidence {
		if ev.Downloadable {
			var err error
			downloadable, err = checkedAdd(downloadable, 1)
			if err != nil {
				return ObservationCounts{}, err
			}
		}
	}
	c := ObservationCounts{
		ParticipantsTotal:       int64(len(parts)),
		ParticipantsActive:      active,
		TasksTotal:              int64(len(tasks)),
		TasksTerminal:           terminal,
		ProvenanceTotal:         int64(len(prov)),
		AttachmentsTotal:        int64(len(evidence)),
		AttachmentsDownloadable: downloadable,
		HeadSeq:                 headSeq,
	}
	if err := ValidateCounts(c); err != nil {
		return ObservationCounts{}, err
	}
	return c, nil
}

// checkedAdd adds with overflow reported instead of wrapped.
func checkedAdd(a, b int64) (int64, error) {
	const maxInt64 = int64(^uint64(0) >> 1)
	if b > 0 && a > maxInt64-b {
		return 0, fmt.Errorf("%w: count overflow", ErrBadCounts)
	}
	return a + b, nil
}

// GetRunRequest is the typed observation query: one run of one tenant. The
// server verifies the tenant against the authenticated context before
// serving (ScopeRun); a cross-tenant query fails closed as outside scope.
type GetRunRequest struct {
	RunID    string `json:"run_id"`
	TenantID string `json:"tenant_id"`
}

// DecodeGetRunRequestStrict parses one query with unknown fields rejected
// fail-closed.
func DecodeGetRunRequestStrict(raw []byte) (GetRunRequest, error) {
	var req GetRunRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return GetRunRequest{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return req, nil
}

// ValidateGetRunRequest checks the query scope selectors.
func ValidateGetRunRequest(req GetRunRequest) error {
	if strings.TrimSpace(req.RunID) == "" || strings.TrimSpace(req.TenantID) == "" {
		return fmt.Errorf("%w: observation query must name run and tenant", ErrReplayOutsideScope)
	}
	return nil
}

// ScopedCursor frames the query as a cursor at the ledger head: after-seq
// zero means "from the start"; the served NextAfterSeq resumes from the
// projected head.
func (q GetRunRequest) ScopedCursor() (Cursor, error) {
	if err := ValidateGetRunRequest(q); err != nil {
		return Cursor{}, err
	}
	return Cursor{RunID: q.RunID, TenantID: q.TenantID, AfterSeq: 0}, nil
}

// GetRunResponse is the complete authoritative observation snapshot for
// one run: the run record, the complete roster, the task DAG, the runtime
// provenance records, the attachment evidence list (descriptors with
// server-evaluated lifecycle/download decisions, never bytes), the
// server-computed counts, explicit degraded/incomplete state, the resume
// cursor, and the server projection time. Every identity, sequence, time,
// visibility, and audit field here is server-owned.
type GetRunResponse struct {
	SchemaVersion string                          `json:"schema_version"`
	Run           OrchestrationRun                `json:"run"`
	Participants  []AgentParticipant              `json:"participants"`
	Tasks         []OrchestrationTask             `json:"tasks"`
	Provenance    []provenance.RuntimeProvenance  `json:"provenance"`
	Attachments   []attachment.AttachmentEvidence `json:"attachments"`
	Counts        ObservationCounts               `json:"counts"`
	Degraded      bool                            `json:"degraded"`
	Incomplete    bool                            `json:"incomplete"`
	NextAfterSeq  int64                           `json:"next_after_seq"`
	ProjectedAtMS int64                           `json:"projected_at_ms"`
}

// SortResponse orders every section deterministically by id (roster by
// participant, DAG by task, provenance by record, evidence by attachment)
// so canonical serialization is byte-identical for identical content.
func SortResponse(r *GetRunResponse) {
	sort.Slice(r.Participants, func(i, j int) bool {
		return r.Participants[i].ParticipantID < r.Participants[j].ParticipantID
	})
	sort.Slice(r.Tasks, func(i, j int) bool {
		return r.Tasks[i].TaskID < r.Tasks[j].TaskID
	})
	sort.Slice(r.Provenance, func(i, j int) bool {
		return r.Provenance[i].ProvenanceID < r.Provenance[j].ProvenanceID
	})
	sort.Slice(r.Attachments, func(i, j int) bool {
		return r.Attachments[i].Ref.AttachmentID < r.Attachments[j].Ref.AttachmentID
	})
}

// sortedIDs reports whether ids arrive in strictly increasing order.
// Duplicates fail here too (a duplicate is never strictly ordered), so
// ordering enforcement doubles as duplicate detection.
func sortedIDs(ids []string) bool {
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			return false
		}
	}
	return true
}

// ValidateResponse checks one served snapshot fail-closed. nowMS is the
// validator's clock for evidence evaluation-time sanity (evidence must
// have been evaluated at or before now, never in the future).
func ValidateResponse(r GetRunResponse, nowMS int64) error {
	if r.SchemaVersion != SchemaRunProjectionV1 {
		return fmt.Errorf("%w: schema %q", ErrUnknownField, r.SchemaVersion)
	}
	if err := ValidateRun(r.Run); err != nil {
		return err
	}
	// Tenant scope rides on the run record (ValidateRun requires a
	// non-empty tenant); the server additionally scopes every serve to the
	// authenticated context tenant via ControlContext.ScopeRun. Sections
	// without their own tenant field (roster, DAG, provenance, evidence)
	// are bound to the run by construction of this single response.
	if err := ValidateParticipants(r.Participants); err != nil {
		return err
	}
	if err := ValidateTaskDAG(r.Tasks, r.Participants); err != nil {
		return err
	}
	participantIDs := make([]string, 0, len(r.Participants))
	provenanceIDs := map[string]bool{}
	for _, p := range r.Participants {
		participantIDs = append(participantIDs, p.ParticipantID)
		// Bound participants must resolve their provenance record in this
		// same snapshot; invited slots carry no binding yet. A roster
		// entry pointing outside the served provenance set fails: the
		// portal must never render an unverified provenance claim.
		if NormalizeParticipantStatus(p) != ParticipantInvited {
			if strings.TrimSpace(p.RuntimeProvenanceID) == "" {
				return fmt.Errorf("%w: bound participant %q has no provenance ref",
					ErrProjectionMismatch, p.ParticipantID)
			}
			provenanceIDs[p.RuntimeProvenanceID] = true
		}
	}
	if !sortedIDs(participantIDs) {
		return fmt.Errorf("%w: roster", ErrUnsortedProjection)
	}
	taskIDs := make([]string, 0, len(r.Tasks))
	knownTasks := map[string]bool{}
	for _, t := range r.Tasks {
		taskIDs = append(taskIDs, t.TaskID)
		knownTasks[t.TaskID] = true
	}
	if !sortedIDs(taskIDs) {
		return fmt.Errorf("%w: task dag", ErrUnsortedProjection)
	}
	// Slots assigned to unknown tasks fail: the roster and the DAG must
	// describe the same run. (Invited slots may predate task registration
	// at StartRun time, but a SERVED snapshot must be coherent.)
	for _, p := range r.Participants {
		if p.AssignedTaskID != "" && !knownTasks[p.AssignedTaskID] {
			return fmt.Errorf("%w: participant %q assigned to unknown task %q",
				ErrProjectionMismatch, p.ParticipantID, p.AssignedTaskID)
		}
	}
	provIDs := make([]string, 0, len(r.Provenance))
	for _, doc := range r.Provenance {
		if err := doc.Validate(); err != nil {
			return err
		}
		provIDs = append(provIDs, doc.ProvenanceID)
		delete(provenanceIDs, doc.ProvenanceID)
	}
	if !sortedIDs(provIDs) {
		return fmt.Errorf("%w: provenance", ErrUnsortedProjection)
	}
	if len(provenanceIDs) > 0 {
		return fmt.Errorf("%w: roster references unserved provenance", ErrProjectionMismatch)
	}
	attachmentIDs := make([]string, 0, len(r.Attachments))
	knownAttachments := map[string]bool{}
	for _, ev := range r.Attachments {
		if err := attachment.ValidateEvidence(ev); err != nil {
			return err
		}
		if ev.EvaluatedAtMS > nowMS {
			return fmt.Errorf("%w: evidence evaluated in the future", ErrProjectionMismatch)
		}
		attachmentIDs = append(attachmentIDs, ev.Ref.AttachmentID)
		knownAttachments[ev.Ref.AttachmentID] = true
	}
	if !sortedIDs(attachmentIDs) {
		return fmt.Errorf("%w: attachments", ErrUnsortedProjection)
	}
	// Every task attachment ref must resolve to served evidence: dangling
	// refs fail instead of rendering as phantom downloads.
	for _, t := range r.Tasks {
		for _, id := range t.AttachmentIDs {
			if !knownAttachments[id] {
				return fmt.Errorf("%w: task %q references unserved attachment %q",
					ErrProjectionMismatch, t.TaskID, id)
			}
		}
	}
	// Counts must exactly equal the served sections: the portal renders
	// these numbers, so a mismatch is fabrication, not rounding.
	want, err := ComputeCounts(r.Participants, r.Tasks, r.Provenance, r.Attachments, r.Counts.HeadSeq)
	if err != nil {
		return err
	}
	if want != r.Counts {
		return fmt.Errorf("%w: counts %+v do not match served sections %+v",
			ErrProjectionMismatch, r.Counts, want)
	}
	// Cursor framing: non-negative, next never past the head, and
	// incomplete is EXACTLY (next < head). A partial backend outage is
	// shown as degraded/incomplete, never as a silently short roster.
	if r.NextAfterSeq < 0 || r.Counts.HeadSeq < 0 {
		return fmt.Errorf("%w: negative cursor", ErrBadCursor)
	}
	if r.NextAfterSeq > r.Counts.HeadSeq {
		return fmt.Errorf("%w: cursor past head", ErrBadCursor)
	}
	if r.Incomplete != (r.NextAfterSeq < r.Counts.HeadSeq) {
		return fmt.Errorf("%w: incomplete must be exactly (next_after_seq < head_seq)",
			ErrProjectionMismatch)
	}
	if r.ProjectedAtMS <= 0 {
		return fmt.Errorf("%w: unprojected time", ErrProjectionMismatch)
	}
	return nil
}

// CanonicalResponseBytes is the deterministic signing/comparison input:
// the response in declaration order (struct-order marshal is
// byte-identical for producer and verifier, the membershipcap idiom).
// Callers must SortResponse first; ValidateResponse rejects unsorted
// input so canonical bytes always mean ordered content.
func CanonicalResponseBytes(r GetRunResponse) ([]byte, error) {
	return json.Marshal(r)
}

// DecodeResponseStrict parses one snapshot with unknown JSON fields
// rejected fail-closed. Old-client payloads (e.g. roster rows without
// status) decode fine — unknown means extra, never absent — which is what
// makes the shape additively compatible.
func DecodeResponseStrict(raw []byte) (GetRunResponse, error) {
	var r GetRunResponse
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return GetRunResponse{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return r, nil
}

// PartnerRunView is the ONLY shape a partner viewer may receive for a
// run: run identity and lifecycle state, head/cursor framing, aggregate
// counts, partner-audience attachment evidence, and explicit
// degraded/incomplete state. Roster, task DAG, provenance records,
// session/workload/container identity, and tenant handles never cross this
// boundary.
type PartnerRunView struct {
	SchemaVersion string                          `json:"schema_version"`
	RunID         string                          `json:"run_id"`
	State         string                          `json:"state"`
	HeadSeq       int64                           `json:"head_seq"`
	NextAfterSeq  int64                           `json:"next_after_seq"`
	Counts        ObservationCounts               `json:"counts"`
	Attachments   []attachment.AttachmentEvidence `json:"attachments"`
	Degraded      bool                            `json:"degraded"`
	Incomplete    bool                            `json:"incomplete"`
	ProjectedAtMS int64                           `json:"projected_at_ms"`
}

// ProjectRunForPartner renders one validated snapshot into its partner-safe
// shape. (The event-level ProjectForPartner in visibility.go covers single
// events; this covers the run snapshot.) Evidence is re-evaluated for the partner viewer at nowMS:
// tenant-audience descriptors are dropped (not_visible), and only
// downloadable partner evidence is served. Unknown run states and empty
// scopes fail closed.
func ProjectRunForPartner(r GetRunResponse, nowMS int64) (PartnerRunView, error) {
	if err := ValidateResponse(r, nowMS); err != nil {
		return PartnerRunView{}, err
	}
	partnerEvidence := make([]attachment.AttachmentEvidence, 0, len(r.Attachments))
	for _, ev := range r.Attachments {
		if ev.Ref.Audience != attachment.AudiencePartner {
			continue
		}
		reevaluated, err := attachment.EvaluateEvidence(ev.Ref, ev.Lifecycle, attachment.AudiencePartner, nowMS)
		if err != nil {
			return PartnerRunView{}, err
		}
		if !reevaluated.Downloadable {
			continue
		}
		partnerEvidence = append(partnerEvidence, reevaluated)
	}
	counts, err := ComputeCounts(nil, r.Tasks, nil, partnerEvidence, r.Counts.HeadSeq)
	if err != nil {
		return PartnerRunView{}, err
	}
	view := PartnerRunView{
		SchemaVersion: SchemaRunProjectionV1,
		RunID:         r.Run.RunID,
		State:         r.Run.State,
		HeadSeq:       r.Counts.HeadSeq,
		NextAfterSeq:  r.NextAfterSeq,
		Counts:        counts,
		Attachments:   partnerEvidence,
		Degraded:      r.Degraded,
		Incomplete:    r.Incomplete,
		ProjectedAtMS: r.ProjectedAtMS,
	}
	return view, nil
}
