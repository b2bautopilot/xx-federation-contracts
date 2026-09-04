// Package orchestration is the machine-readable contract for truthful
// multi-agent orchestration, live observation, and BFF command evidence
// (issue #19, parent epic #18).
//
// Authority: spec/b2b-federation-spec-v1.xml revision 9. The control plane
// (comp.builders-control, xx-builders-net) owns the durable run/task/event/
// attachment ledger and the ordered observation stream; agents
// (comp.builders-agent) participate as authenticated Agent Kit container
// workloads with immutable runtime provenance; the portal
// (comp.builders-portal) consumes only the typed observation projection and
// BFF command evidence defined here. Relays stay payload-blind: no
// orchestration semantics are added to relay cells.
//
// Fail-closed rules enforced by this package:
//   - unknown event kinds and unknown JSON fields are rejected;
//   - illegal run/task lifecycle transitions are rejected;
//   - forged server fields (event id, sequence, timestamp, visibility) are rejected;
//   - duplicate event ids, duplicate terminal results, and appends past a
//     terminal run state are rejected;
//   - tenant mismatch between event, run, and cursor scope is rejected;
//   - replay outside the cursor scope (other run or other tenant) is rejected.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/orchestration
// Spec evidence: rel.agent-connects-control, rel.portal-dials-control.
package orchestration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Schema identifiers for the orchestration contract family.
const (
	SchemaOrchestrationRunV1   = "builders.federation.orchestration_run.v1"
	SchemaOrchestrationEventV1 = "builders.federation.orchestration_event.v1"
	SchemaBFFCommandV1         = "builders.federation.bff_command.v1"
)

// Run lifecycle states. A run moves requested -> authorized -> running and
// then exactly one terminal state. Terminal states accept no further events.
const (
	RunRequested  = "requested"
	RunAuthorized = "authorized"
	RunRunning    = "running"
	RunCompleted  = "completed"
	RunFailed     = "failed"
	RunTimedOut   = "timed_out"
	RunCancelled  = "cancelled"
)

// Task lifecycle states. A task moves pending -> assigned -> acknowledged ->
// in_progress and then in_review and/or a terminal state. Terminal states
// accept no further task events (duplicate terminal results fail closed).
const (
	TaskPending      = "pending"
	TaskAssigned     = "assigned"
	TaskAcknowledged = "acknowledged"
	TaskInProgress   = "in_progress"
	TaskInReview     = "in_review"
	TaskDone         = "done"
	TaskFailed       = "failed"
	TaskTimedOut     = "timed_out"
	TaskCancelled    = "cancelled"
)

// Typed orchestration lifecycle event kinds. Every lifecycle moment the
// observation stream may portray has exactly one kind; anything else fails
// closed as unknown.
const (
	EventRequest         = "request"
	EventAuthorization   = "authorization"
	EventPMStart         = "pm_start"
	EventPlanPublication = "plan_publication"
	EventAssignment      = "assignment"
	EventAcknowledgment  = "acknowledgment"
	EventProgress        = "progress"
	EventHandoff         = "handoff"
	EventDecision        = "decision"
	EventReview          = "review"
	EventSynthesis       = "synthesis"
	EventCompletion      = "completion"
	EventFailure         = "failure"
	EventTimeout         = "timeout"
	EventCancellation    = "cancellation"
)

// Participant roles on a run.
const (
	RolePM       = "pm"
	RoleBuilder  = "builder"
	RoleReviewer = "reviewer"
)

// Agent kinds that may fill a participant slot. The reviewer slot must hold
// a different kind than the PM slot (different-agent review).
const (
	AgentKindMuse        = "muse"
	AgentKindCodex       = "codex"
	AgentKindClaude      = "claude"
	AgentKindGrok        = "grok"
	AgentKindAntigravity = "antigravity"
	AgentKindHuman       = "human"
)

// Server-assigned observation visibility. Internal coordination stays
// tenant-local by default; partner viewers receive only the explicit
// partner-safe projection (see visibility.go).
const (
	VisibilityTenant  = "tenant"
	VisibilityPartner = "partner"
)

var (
	ErrUnknownRunState      = errors.New("orchestration run state unknown")
	ErrUnknownTaskState     = errors.New("orchestration task state unknown")
	ErrUnknownEventKind     = errors.New("orchestration event kind unknown")
	ErrUnknownRole          = errors.New("orchestration participant role unknown")
	ErrUnknownAgentKind     = errors.New("orchestration agent kind unknown")
	ErrUnknownVisibility    = errors.New("orchestration visibility unknown")
	ErrIllegalTransition    = errors.New("orchestration illegal lifecycle transition")
	ErrTerminalState        = errors.New("orchestration state is terminal")
	ErrDuplicateEvent       = errors.New("orchestration duplicate event id")
	ErrSequenceGap          = errors.New("orchestration sequence gap or reorder")
	ErrForgedServerField    = errors.New("orchestration client must not assert server fields")
	ErrTenantMismatch       = errors.New("orchestration tenant mismatch")
	ErrReplayOutsideScope   = errors.New("orchestration replay outside cursor scope")
	ErrUnknownField         = errors.New("orchestration unknown field")
	ErrDuplicateTerminal    = errors.New("orchestration duplicate terminal result")
	ErrTeamShape            = errors.New("orchestration team shape invalid")
	ErrTaskDAG              = errors.New("orchestration task DAG invalid")
	ErrDuplicateParticipant = errors.New("orchestration duplicate participant binding")
)

// ValidRunState reports whether value names a declared run lifecycle state.
func ValidRunState(value string) bool {
	switch value {
	case RunRequested, RunAuthorized, RunRunning,
		RunCompleted, RunFailed, RunTimedOut, RunCancelled:
		return true
	default:
		return false
	}
}

// IsTerminalRunState reports whether no further run events may be appended.
func IsTerminalRunState(value string) bool {
	switch value {
	case RunCompleted, RunFailed, RunTimedOut, RunCancelled:
		return true
	default:
		return false
	}
}

// AllowedRunTransition reports whether a run may move from one state to the
// next. Unknown states and any move out of a terminal state fail closed.
func AllowedRunTransition(from, to string) bool {
	if !ValidRunState(from) || !ValidRunState(to) || IsTerminalRunState(from) {
		return false
	}
	switch from {
	case RunRequested:
		return to == RunAuthorized || to == RunCancelled
	case RunAuthorized:
		return to == RunRunning || to == RunCancelled
	case RunRunning:
		return to == RunCompleted || to == RunFailed || to == RunTimedOut || to == RunCancelled
	default:
		return false
	}
}

// ValidTaskState reports whether value names a declared task lifecycle state.
func ValidTaskState(value string) bool {
	switch value {
	case TaskPending, TaskAssigned, TaskAcknowledged, TaskInProgress,
		TaskInReview, TaskDone, TaskFailed, TaskTimedOut, TaskCancelled:
		return true
	default:
		return false
	}
}

// IsTerminalTaskState reports whether no further task events may be appended.
func IsTerminalTaskState(value string) bool {
	switch value {
	case TaskDone, TaskFailed, TaskTimedOut, TaskCancelled:
		return true
	default:
		return false
	}
}

// AllowedTaskTransition reports whether a task may move from one state to the
// next. Unknown states and any move out of a terminal state fail closed.
func AllowedTaskTransition(from, to string) bool {
	if !ValidTaskState(from) || !ValidTaskState(to) || IsTerminalTaskState(from) {
		return false
	}
	switch from {
	case TaskPending:
		return to == TaskAssigned || to == TaskCancelled
	case TaskAssigned:
		return to == TaskAcknowledged || to == TaskCancelled || to == TaskTimedOut
	case TaskAcknowledged:
		return to == TaskInProgress || to == TaskCancelled
	case TaskInProgress:
		return to == TaskInReview || to == TaskDone || to == TaskFailed || to == TaskTimedOut || to == TaskCancelled
	case TaskInReview:
		return to == TaskDone || to == TaskFailed || to == TaskInProgress || to == TaskCancelled
	default:
		return false
	}
}

// ValidEventKind reports whether value names a declared lifecycle event kind.
func ValidEventKind(value string) bool {
	switch value {
	case EventRequest, EventAuthorization, EventPMStart, EventPlanPublication,
		EventAssignment, EventAcknowledgment, EventProgress, EventHandoff,
		EventDecision, EventReview, EventSynthesis, EventCompletion,
		EventFailure, EventTimeout, EventCancellation:
		return true
	default:
		return false
	}
}

// ValidRole reports whether value names a declared participant role.
func ValidRole(value string) bool {
	switch value {
	case RolePM, RoleBuilder, RoleReviewer:
		return true
	default:
		return false
	}
}

// ValidAgentKind reports whether value names a declared agent kind.
func ValidAgentKind(value string) bool {
	switch value {
	case AgentKindMuse, AgentKindCodex, AgentKindClaude,
		AgentKindGrok, AgentKindAntigravity, AgentKindHuman:
		return true
	default:
		return false
	}
}

// ValidVisibility reports whether value names a declared server-assigned
// visibility level.
func ValidVisibility(value string) bool {
	switch value {
	case VisibilityTenant, VisibilityPartner:
		return true
	default:
		return false
	}
}

// OrchestrationRun is the control-plane-owned run record: run/room/command
// ids, source/target organizations, lifecycle state, participants, task DAG,
// timestamps, and the revision/audit binding.
type OrchestrationRun struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	RoomID        string `json:"room_id"`
	CommandID     string `json:"command_id"`
	SourceOrgID   string `json:"source_org_id"`
	TargetOrgID   string `json:"target_org_id"`
	TenantID      string `json:"tenant_id"`
	State         string `json:"state"`
	Revision      int64  `json:"revision"`
	AuditHeadHash string `json:"audit_head_hash,omitempty"`
	CreatedAtMS   int64  `json:"created_at_ms"`
	UpdatedAtMS   int64  `json:"updated_at_ms"`
}

// AgentParticipant binds one PM/builder/reviewer slot to an authenticated
// session/workload/container triple plus the assigned task and the digest of
// its immutable runtime provenance document.
//
// Status is the authoritative participant lifecycle state (see
// projection.go: invited, active, suspended, departed, removed). It is
// server-assigned through BindParticipant/UpdateParticipantStatus and
// never browser-asserted. Rows recorded before status existed (revision 9)
// omit it and normalize explicitly via NormalizeParticipantStatus.
type AgentParticipant struct {
	ParticipantID       string `json:"participant_id"`
	Role                string `json:"role"`
	AgentKind           string `json:"agent_kind"`
	SessionID           string `json:"session_id"`
	WorkloadID          string `json:"workload_id"`
	ContainerID         string `json:"container_id"`
	AssignedTaskID      string `json:"assigned_task_id,omitempty"`
	RuntimeProvenanceID string `json:"runtime_provenance_id"`
	Status              string `json:"status,omitempty"`
}

// OrchestrationTask is one DAG node: dependency ids, assignment, lifecycle,
// a bounded public summary, and result/attachment references. It carries no
// prompts, tool arguments, or reasoning text.
type OrchestrationTask struct {
	TaskID          string   `json:"task_id"`
	DependsOn       []string `json:"depends_on,omitempty"`
	AssigneeID      string   `json:"assignee_id,omitempty"`
	State           string   `json:"state"`
	PublicSummary   string   `json:"public_summary,omitempty"`
	ResultRef       string   `json:"result_ref,omitempty"`
	AttachmentIDs   []string `json:"attachment_ids,omitempty"`
	TerminalResults int      `json:"terminal_results"`
}

// ClientEvent is the untrusted intake shape: workload-submitted fields only.
// Every server-assigned field (event id, sequence, timestamp, visibility,
// audit hash) MUST be empty here; presence fails closed as forgery.
type ClientEvent struct {
	RunID         string   `json:"run_id"`
	TaskID        string   `json:"task_id,omitempty"`
	ActorID       string   `json:"actor_id"`
	TenantID      string   `json:"tenant_id"`
	Kind          string   `json:"kind"`
	CausationID   string   `json:"causation_id,omitempty"`
	CorrelationID string   `json:"correlation_id,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	Attachments   []string `json:"attachments,omitempty"`
}

// OrchestrationEvent is the server-projected record: the client fields plus
// server-assigned event id, monotonic per-run sequence, server timestamp,
// server-assigned visibility, and the audit-chain hash.
type OrchestrationEvent struct {
	SchemaVersion string   `json:"schema_version"`
	EventID       string   `json:"event_id"`
	Seq           int64    `json:"seq"`
	RunID         string   `json:"run_id"`
	TaskID        string   `json:"task_id,omitempty"`
	ActorID       string   `json:"actor_id"`
	TenantID      string   `json:"tenant_id"`
	Kind          string   `json:"kind"`
	CausationID   string   `json:"causation_id,omitempty"`
	CorrelationID string   `json:"correlation_id,omitempty"`
	Visibility    string   `json:"visibility"`
	Summary       string   `json:"summary,omitempty"`
	Attachments   []string `json:"attachments,omitempty"`
	TimestampMS   int64    `json:"timestamp_ms"`
	AuditHash     string   `json:"audit_hash"`
}

// DecodeClientEventStrict parses one client event with unknown JSON fields
// rejected fail-closed.
func DecodeClientEventStrict(raw []byte) (ClientEvent, error) {
	var ev ClientEvent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return ClientEvent{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return ev, nil
}

// ValidateClientEvent checks the untrusted intake shape: known kind,
// non-empty run/actor/tenant ids, and a bounded sanitized summary.
func ValidateClientEvent(ev ClientEvent) error {
	if strings.TrimSpace(ev.RunID) == "" {
		return fmt.Errorf("%w: empty run_id", ErrUnknownField)
	}
	if strings.TrimSpace(ev.ActorID) == "" {
		return fmt.Errorf("%w: empty actor_id", ErrUnknownField)
	}
	if strings.TrimSpace(ev.TenantID) == "" {
		return fmt.Errorf("%w: empty tenant_id", ErrUnknownField)
	}
	if !ValidEventKind(ev.Kind) {
		return fmt.Errorf("%w: %q", ErrUnknownEventKind, ev.Kind)
	}
	if err := ValidateEventSummary(ev.Kind, ev.Summary); err != nil {
		return err
	}
	for _, id := range ev.Attachments {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%w: empty attachment ref", ErrUnknownField)
		}
	}
	return nil
}

// GenesisAuditHash starts the per-run tamper-evident audit chain.
func GenesisAuditHash(runID string) string {
	sum := sha256.Sum256([]byte("orchestration-audit-genesis|" + runID))
	return hex.EncodeToString(sum[:])
}

// EventAuditHash chains one stamped event onto its predecessor: the hash
// covers the canonical event bytes plus the previous audit hash, so any
// rewrite or reorder breaks the chain.
func EventAuditHash(prevHash string, ev OrchestrationEvent) (string, error) {
	stripped := ev
	stripped.AuditHash = ""
	raw, err := json.Marshal(stripped)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(prevHash + "|" + string(raw)))
	return hex.EncodeToString(sum[:]), nil
}

// StampEvent projects one validated client event into its server record. The
// server (never the workload) assigns event id, sequence, timestamp, and
// visibility, then seals the audit hash.
func StampEvent(ev ClientEvent, eventID string, seq int64, timestampMS int64, visibility, prevAuditHash string) (OrchestrationEvent, error) {
	if err := ValidateClientEvent(ev); err != nil {
		return OrchestrationEvent{}, err
	}
	if strings.TrimSpace(eventID) == "" {
		return OrchestrationEvent{}, fmt.Errorf("%w: empty event id", ErrForgedServerField)
	}
	if seq <= 0 {
		return OrchestrationEvent{}, fmt.Errorf("%w: non-positive sequence", ErrForgedServerField)
	}
	if !ValidVisibility(visibility) {
		return OrchestrationEvent{}, fmt.Errorf("%w: %q", ErrUnknownVisibility, visibility)
	}
	stamped := OrchestrationEvent{
		SchemaVersion: SchemaOrchestrationEventV1,
		EventID:       eventID,
		Seq:           seq,
		RunID:         ev.RunID,
		TaskID:        ev.TaskID,
		ActorID:       ev.ActorID,
		TenantID:      ev.TenantID,
		Kind:          ev.Kind,
		CausationID:   ev.CausationID,
		CorrelationID: ev.CorrelationID,
		Visibility:    visibility,
		Summary:       ev.Summary,
		Attachments:   ev.Attachments,
		TimestampMS:   timestampMS,
	}
	hash, err := EventAuditHash(prevAuditHash, stamped)
	if err != nil {
		return OrchestrationEvent{}, err
	}
	stamped.AuditHash = hash
	return stamped, nil
}
