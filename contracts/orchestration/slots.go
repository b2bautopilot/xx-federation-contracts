// Participant slots and authenticated binding (issue #21, parent epic
// #18, spec revision 10).
//
// Authority: spec/b2b-federation-spec-v1.xml revision 10. A browser (via
// the BFF) may PROPOSE participant slots — role and agent kind only. It can
// never assert identity: session, workload, container, and provenance
// bindings exist only after an authenticated BindParticipant call whose
// identity fields come from the control's authentication context, never
// from caller request fields. The request structs in this file have no
// identity fields by construction, so fabrication is unrepresentable.
//
// Slot lifecycle: StartRun accepts proposals and records invited
// participants with server-assigned ids. BindParticipant stamps the
// authenticated triple plus the session's registered provenance and moves
// invited -> active. UpdateParticipantStatus moves along
// AllowedParticipantTransition (suspend/resume/depart/removed).
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/orchestration
// Spec evidence: rel.agent-connects-control (participant lifecycle,
// provenance binding).
package orchestration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/provenance"
)

// Authenticated control-operation names. These are agent/control-plane
// operations, NOT browser BFF commands: ValidBFFCommand never accepts them,
// and the control resolves every identity field from the authenticated
// context (ControlContext), never from request fields. The orchestration
// consistency gate pins these strings to the OrchestrationService RPCs of
// the same names.
const (
	ControlOpRegisterProvenance = "register_provenance"
	ControlOpBindParticipant    = "bind_participant"
	ControlOpUpdateParticipant  = "update_participant_status"
	ControlOpGetProvenance      = "get_provenance"
)

var (
	ErrUnknownControlOp = errors.New("orchestration control operation unknown")
	ErrBadBinding       = errors.New("orchestration participant binding invalid")
	ErrBadProvenanceReg = errors.New("orchestration provenance registration invalid")
)

// ValidControlOp reports whether name is a declared authenticated
// control operation.
func ValidControlOp(name string) bool {
	switch name {
	case ControlOpRegisterProvenance, ControlOpBindParticipant,
		ControlOpUpdateParticipant, ControlOpGetProvenance:
		return true
	default:
		return false
	}
}

// ParticipantSlotProposal is the ONLY participant shape a browser may
// propose: role, agent kind, and optional task assignment. There are no
// session, workload, container, provenance, or status fields — a proposal
// cannot carry identity by construction. The control assigns participant
// ids and records invited status at StartRun.
type ParticipantSlotProposal struct {
	Role           string `json:"role"`
	AgentKind      string `json:"agent_kind"`
	AssignedTaskID string `json:"assigned_task_id,omitempty"`
}

// ValidateSlotProposal checks one browser-proposed slot fail-closed: known
// role and agent kind. Identity smuggling is impossible (no such fields
// exist); unknown roles and kinds are rejected here, before StartRun.
func ValidateSlotProposal(slot ParticipantSlotProposal) error {
	if !ValidRole(slot.Role) {
		return fmt.Errorf("%w: %q", ErrUnknownRole, slot.Role)
	}
	if !ValidAgentKind(slot.AgentKind) {
		return fmt.Errorf("%w: %q", ErrUnknownAgentKind, slot.AgentKind)
	}
	return nil
}

// ValidateSlotRoster checks a StartRun proposal set: every slot
// well-formed, exactly one PM, at least one builder, at least one reviewer
// whose agent kind differs from the PM. This mirrors ValidateParticipants
// for the pre-binding stage, where no identity exists yet to de-duplicate.
func ValidateSlotRoster(slots []ParticipantSlotProposal) error {
	if len(slots) == 0 {
		return fmt.Errorf("%w: empty slot proposal", ErrTeamShape)
	}
	var pmKind string
	pmCount, builderCount, reviewerCount := 0, 0, 0
	reviewerKinds := map[string]bool{}
	for _, slot := range slots {
		if err := ValidateSlotProposal(slot); err != nil {
			return err
		}
		switch slot.Role {
		case RolePM:
			pmCount++
			pmKind = slot.AgentKind
		case RoleBuilder:
			builderCount++
		case RoleReviewer:
			reviewerCount++
			reviewerKinds[slot.AgentKind] = true
		}
	}
	if pmCount != 1 {
		return fmt.Errorf("%w: want exactly one pm, have %d", ErrTeamShape, pmCount)
	}
	if builderCount < 1 {
		return fmt.Errorf("%w: want at least one builder", ErrTeamShape)
	}
	if reviewerCount < 1 {
		return fmt.Errorf("%w: want at least one reviewer", ErrTeamShape)
	}
	if reviewerKinds[pmKind] {
		return fmt.Errorf("%w: reviewer must differ in agent kind from the pm",
			ErrTeamShape)
	}
	return nil
}

// StartRunRequest is the typed StartRun intake: command correlation,
// idempotency, tenant scope, and the browser-proposed slot roster. It
// carries NO actor identity (the authenticated control context decides the
// actor via ResolveActor) and NO opaque payload bytes: slots are typed
// here, never smuggled as untyped JSON.
type StartRunRequest struct {
	CommandID      string                    `json:"command_id"`
	IdempotencyKey string                    `json:"idempotency_key"`
	TenantID       string                    `json:"tenant_id"`
	Slots          []ParticipantSlotProposal `json:"slots"`
	RequestedAtMS  int64                     `json:"requested_at_ms"`
}

// DecodeStartRunRequestStrict parses one StartRun request with unknown JSON
// fields rejected fail-closed. A proposal smuggling session_id,
// workload_id, container_id, or provenance fields fails here, before any
// validation, because those fields do not exist on the typed shape.
func DecodeStartRunRequestStrict(raw []byte) (StartRunRequest, error) {
	var req StartRunRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return StartRunRequest{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return req, nil
}

// ValidateStartRunRequest checks the typed StartRun intake fail-closed:
// non-empty command id, a valid idempotency key (replay returns the
// original receipt, never a second run), a tenant scope, and a legal slot
// roster.
func ValidateStartRunRequest(req StartRunRequest) error {
	if strings.TrimSpace(req.CommandID) == "" {
		return fmt.Errorf("%w: empty command id", ErrUnknownCommand)
	}
	if err := ValidateIdempotencyKey(req.IdempotencyKey); err != nil {
		return err
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return fmt.Errorf("%w: empty tenant", ErrTenantMismatch)
	}
	if err := ValidateSlotRoster(req.Slots); err != nil {
		return err
	}
	return nil
}

// ControlContext is the authenticated caller identity the control plane
// resolved from mutual TLS before invoking any binding operation. Every
// field is server-observed; request structs never carry them.
type ControlContext struct {
	TenantID    string
	ActorID     string
	SessionID   string
	WorkloadID  string
	ContainerID string
}

// Validate checks the context is fully bound: anonymous or partially
// bound contexts fail closed before any mutation.
func (c ControlContext) Validate() error {
	if strings.TrimSpace(c.TenantID) == "" || strings.TrimSpace(c.ActorID) == "" {
		return fmt.Errorf("%w: unauthenticated context", ErrActorMismatch)
	}
	if strings.TrimSpace(c.SessionID) == "" || strings.TrimSpace(c.WorkloadID) == "" ||
		strings.TrimSpace(c.ContainerID) == "" {
		return fmt.Errorf("%w: unbound session identity", ErrBadBinding)
	}
	return nil
}

// ScopeRun enforces strict tenant scoping: the context tenant must equal
// the run's tenant. Cross-tenant binding fails closed here.
func (c ControlContext) ScopeRun(runTenantID string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.TenantID != runTenantID {
		return fmt.Errorf("%w: context tenant %q outside run tenant %q",
			ErrTenantMismatch, c.TenantID, runTenantID)
	}
	return nil
}

// AssembleInvitedParticipant records one accepted slot proposal as an
// invited roster entry with a server-assigned participant id. Binding
// fields stay empty until BindParticipant stamps them from an
// authenticated context.
func AssembleInvitedParticipant(slot ParticipantSlotProposal, participantID string) (AgentParticipant, error) {
	if err := ValidateSlotProposal(slot); err != nil {
		return AgentParticipant{}, err
	}
	if strings.TrimSpace(participantID) == "" {
		return AgentParticipant{}, fmt.Errorf("%w: empty participant id", ErrBadBinding)
	}
	return AgentParticipant{
		ParticipantID:  participantID,
		Role:           slot.Role,
		AgentKind:      slot.AgentKind,
		AssignedTaskID: slot.AssignedTaskID,
		Status:         ParticipantInvited,
	}, nil
}

// BindParticipantRequest binds one invited slot to the caller's live
// session. It carries scope selectors only (run, participant); every
// identity field comes from the ControlContext argument, never from the
// wire.
type BindParticipantRequest struct {
	RunID         string `json:"run_id"`
	ParticipantID string `json:"participant_id"`
}

// DecodeBindParticipantRequestStrict parses one bind request with unknown
// fields rejected fail-closed.
func DecodeBindParticipantRequestStrict(raw []byte) (BindParticipantRequest, error) {
	var req BindParticipantRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return BindParticipantRequest{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return req, nil
}

// ValidateBindParticipantRequest checks the bind scope selectors.
func ValidateBindParticipantRequest(req BindParticipantRequest) error {
	if strings.TrimSpace(req.RunID) == "" || strings.TrimSpace(req.ParticipantID) == "" {
		return fmt.Errorf("%w: bind scope must name run and participant", ErrBadBinding)
	}
	return nil
}

// BindParticipant stamps the authenticated session triple plus the
// session's registered provenance onto an invited roster entry and moves
// it invited -> active. current must be the stored roster entry (status
// invited after NormalizeParticipantStatus); any other state, any tenant
// mismatch, or any unbound context fails closed without mutation.
func BindParticipant(ctx ControlContext, runTenantID string, current AgentParticipant, provenanceID string) (AgentParticipant, error) {
	if err := ValidateBindParticipantRequest(BindParticipantRequest{RunID: "scope-checked", ParticipantID: current.ParticipantID}); err != nil {
		return AgentParticipant{}, err
	}
	if err := ctx.ScopeRun(runTenantID); err != nil {
		return AgentParticipant{}, err
	}
	if NormalizeParticipantStatus(current) != ParticipantInvited {
		return AgentParticipant{}, fmt.Errorf("%w: participant %q is %q, not invited",
			ErrBadBinding, current.ParticipantID, NormalizeParticipantStatus(current))
	}
	if strings.TrimSpace(provenanceID) == "" {
		return AgentParticipant{}, fmt.Errorf("%w: empty provenance ref for %q", ErrBadBinding, current.ParticipantID)
	}
	bound := current
	bound.SessionID = ctx.SessionID
	bound.WorkloadID = ctx.WorkloadID
	bound.ContainerID = ctx.ContainerID
	bound.RuntimeProvenanceID = provenanceID
	bound.Status = ParticipantActive
	return bound, nil
}

// UpdateParticipantStatusRequest moves one bound participant along its
// lifecycle. The transition is validated against AllowedParticipantTransition
// with the stored entry; the actor comes from context (authorization policy
// beyond transition legality and tenant scope is downstream control duty).
type UpdateParticipantStatusRequest struct {
	RunID         string `json:"run_id"`
	ParticipantID string `json:"participant_id"`
	ToStatus      string `json:"to_status"`
}

// DecodeUpdateParticipantStatusRequestStrict parses one status-update
// request with unknown fields rejected fail-closed.
func DecodeUpdateParticipantStatusRequestStrict(raw []byte) (UpdateParticipantStatusRequest, error) {
	var req UpdateParticipantStatusRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return UpdateParticipantStatusRequest{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return req, nil
}

// ApplyParticipantStatusUpdate validates and applies one lifecycle move to
// a stored roster entry. Illegal moves, unknown states, moves out of
// terminal states, and cross-tenant updates fail closed without mutation.
func ApplyParticipantStatusUpdate(ctx ControlContext, runTenantID string, current AgentParticipant, toStatus string) (AgentParticipant, error) {
	if strings.TrimSpace(current.ParticipantID) == "" {
		return AgentParticipant{}, fmt.Errorf("%w: empty participant id", ErrBadBinding)
	}
	if err := ctx.ScopeRun(runTenantID); err != nil {
		return AgentParticipant{}, err
	}
	from := NormalizeParticipantStatus(current)
	if !ValidParticipantStatus(toStatus) || toStatus == "" {
		return AgentParticipant{}, fmt.Errorf("%w: %q", ErrUnknownParticipantStatus, toStatus)
	}
	if !AllowedParticipantTransition(from, toStatus) {
		return AgentParticipant{}, fmt.Errorf("%w: participant %q %s -> %s",
			ErrIllegalTransition, current.ParticipantID, from, toStatus)
	}
	updated := current
	updated.Status = toStatus
	if toStatus == ParticipantActive {
		// Activation requires a bound session triple plus provenance:
		// an invited slot carries none, so invited -> active is refused
		// here and must go through BindParticipant (which stamps the
		// authenticated context). Without this, a status update could
		// fabricate a live session with no identity behind it.
		if strings.TrimSpace(updated.SessionID) == "" ||
			strings.TrimSpace(updated.WorkloadID) == "" ||
			strings.TrimSpace(updated.ContainerID) == "" ||
			strings.TrimSpace(updated.RuntimeProvenanceID) == "" {
			return AgentParticipant{}, fmt.Errorf("%w: activation of %q needs a bound session; use BindParticipant",
				ErrBadBinding, current.ParticipantID)
		}
	}
	return updated, nil
}

// RegisterProvenanceRequest presents one runtime-provenance document for
// registration. The ProvenanceID MUST be empty: ids are server-assigned at
// registration (a caller-asserted id fails closed as forgery, exactly like
// client-asserted event sequence fields). Session binding is recorded
// server-side against the ControlContext, never from request fields.
type RegisterProvenanceRequest struct {
	Provenance provenance.RuntimeProvenance `json:"provenance"`
}

// DecodeRegisterProvenanceRequestStrict parses one registration request
// with unknown fields rejected fail-closed.
func DecodeRegisterProvenanceRequestStrict(raw []byte) (RegisterProvenanceRequest, error) {
	var req RegisterProvenanceRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return RegisterProvenanceRequest{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return req, nil
}

// PrepareProvenanceRegistration validates one registration and stamps the
// server-assigned provenance id. Order is load-bearing: the empty-id
// forgery check runs first, then the id is assigned, then the full
// document validates (provenance.Validate requires a non-empty id, which
// is now the server's own).
func PrepareProvenanceRegistration(ctx ControlContext, req RegisterProvenanceRequest, serverAssignedID string) (provenance.RuntimeProvenance, error) {
	if err := ctx.Validate(); err != nil {
		return provenance.RuntimeProvenance{}, err
	}
	if strings.TrimSpace(req.Provenance.ProvenanceID) != "" {
		return provenance.RuntimeProvenance{}, fmt.Errorf("%w: caller-asserted provenance id",
			ErrForgedServerField)
	}
	if strings.TrimSpace(serverAssignedID) == "" {
		return provenance.RuntimeProvenance{}, fmt.Errorf("%w: empty server provenance id", ErrBadProvenanceReg)
	}
	doc := req.Provenance
	doc.ProvenanceID = serverAssignedID
	if err := doc.Validate(); err != nil {
		return provenance.RuntimeProvenance{}, err
	}
	return doc, nil
}

// GetProvenanceRequest is the explicit minimal-scope provenance lookup: one
// run, one tenant, one provenance id. Tenant is verified against the
// authenticated context by the server before serving.
type GetProvenanceRequest struct {
	RunID        string `json:"run_id"`
	TenantID     string `json:"tenant_id"`
	ProvenanceID string `json:"provenance_id"`
}

// DecodeGetProvenanceRequestStrict parses one lookup with unknown fields
// rejected fail-closed.
func DecodeGetProvenanceRequestStrict(raw []byte) (GetProvenanceRequest, error) {
	var req GetProvenanceRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return GetProvenanceRequest{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}
	return req, nil
}

// ValidateGetProvenanceRequest checks the lookup scope: every selector
// non-empty. Cross-tenant service is rejected by ctx scoping at serve
// time (ScopeRun), not by shape alone.
func ValidateGetProvenanceRequest(req GetProvenanceRequest) error {
	if strings.TrimSpace(req.RunID) == "" || strings.TrimSpace(req.TenantID) == "" ||
		strings.TrimSpace(req.ProvenanceID) == "" {
		return fmt.Errorf("%w: provenance lookup must name run, tenant, and provenance",
			ErrReplayOutsideScope)
	}
	return nil
}
