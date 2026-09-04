// Ledger is the executable form of the run/task/event append rules: the
// control plane applies these checks before durable write and projection so
// sequence gaps, replays, illegal transitions, duplicate terminal results,
// tenant mismatches, and out-of-scope replays all fail closed in one place.
package orchestration

import (
	"fmt"
	"strings"
)

// Cursor scopes a resumable observation read to exactly one run of one
// tenant. A cursor minted for another run or tenant is rejected.
type Cursor struct {
	RunID    string `json:"run_id"`
	TenantID string `json:"tenant_id"`
	AfterSeq int64  `json:"after_seq"`
}

// ValidateCursor rejects cross-run and cross-tenant replay: the cursor must
// name this ledger's run and tenant.
func (c Cursor) ValidateScope(runID, tenantID string) error {
	if c.RunID != runID || c.TenantID != tenantID {
		return fmt.Errorf("%w: cursor for run %q tenant %q is outside scope",
			ErrReplayOutsideScope, c.RunID, c.TenantID)
	}
	if c.AfterSeq < 0 {
		return fmt.Errorf("%w: negative cursor", ErrReplayOutsideScope)
	}
	return nil
}

// Ledger holds one run's authoritative in-memory projection: run state, task
// states, the ordered stamped events, and the audit head. Durability stays in
// xx-builders-net; this type owns the fail-closed append rules both sides
// share.
type Ledger struct {
	RunID    string
	TenantID string
	State    string
	Tasks    map[string]*OrchestrationTask
	Events   []OrchestrationEvent
	seenIDs  map[string]bool
	headHash string
	baseHash string
}

// NewLedger opens a ledger for a validated run record. The head starts at
// the run's audit binding when present, else the genesis hash.
func NewLedger(run OrchestrationRun) (*Ledger, error) {
	if err := ValidateRun(run); err != nil {
		return nil, err
	}
	head := run.AuditHeadHash
	if head == "" {
		head = GenesisAuditHash(run.RunID)
	}
	return &Ledger{
		RunID:    run.RunID,
		TenantID: run.TenantID,
		State:    run.State,
		Tasks:    map[string]*OrchestrationTask{},
		seenIDs:  map[string]bool{},
		headHash: head,
		baseHash: head,
	}, nil
}

// ValidateRun checks the run record shape: known state, non-empty ids, and
// sane timestamps. Team shape and DAG shape are checked separately so a
// bare run row can exist before its roster lands.
func ValidateRun(run OrchestrationRun) error {
	if run.SchemaVersion != SchemaOrchestrationRunV1 {
		return fmt.Errorf("%w: schema %q", ErrUnknownField, run.SchemaVersion)
	}
	if strings.TrimSpace(run.RunID) == "" || strings.TrimSpace(run.RoomID) == "" ||
		strings.TrimSpace(run.CommandID) == "" {
		return fmt.Errorf("%w: run/room/command ids must be non-empty", ErrUnknownField)
	}
	if strings.TrimSpace(run.SourceOrgID) == "" || strings.TrimSpace(run.TargetOrgID) == "" {
		return fmt.Errorf("%w: source/target orgs must be non-empty", ErrUnknownField)
	}
	if strings.TrimSpace(run.TenantID) == "" {
		return fmt.Errorf("%w: empty tenant", ErrTenantMismatch)
	}
	if !ValidRunState(run.State) {
		return fmt.Errorf("%w: %q", ErrUnknownRunState, run.State)
	}
	if run.CreatedAtMS <= 0 || run.UpdatedAtMS < run.CreatedAtMS {
		return fmt.Errorf("%w: bad timestamps", ErrUnknownField)
	}
	return nil
}

// MinBuildersForAcceptance is the epic #18 capstone floor: a live acceptance
// run shows at least two parallel builders. ValidateRun requires at least
// one builder so lean local runs stay legal; acceptance checks this floor.
const MinBuildersForAcceptance = 2

// ValidateParticipants checks the roster: every slot well-formed, exactly
// one PM, at least one builder, at least one reviewer whose agent kind
// differs from the PM (different-agent review), and one distinct
// session/workload/container triple per participant.
func ValidateParticipants(participants []AgentParticipant) error {
	if len(participants) == 0 {
		return fmt.Errorf("%w: empty roster", ErrTeamShape)
	}
	var pmKind string
	pmCount, builderCount, reviewerCount := 0, 0, 0
	reviewerKinds := map[string]bool{}
	seenParticipant := map[string]bool{}
	seenSession := map[string]bool{}
	seenWorkload := map[string]bool{}
	seenContainer := map[string]bool{}
	for _, p := range participants {
		if strings.TrimSpace(p.ParticipantID) == "" {
			return fmt.Errorf("%w: empty participant id", ErrTeamShape)
		}
		if seenParticipant[p.ParticipantID] {
			return fmt.Errorf("%w: participant %q", ErrDuplicateParticipant, p.ParticipantID)
		}
		seenParticipant[p.ParticipantID] = true
		if !ValidRole(p.Role) {
			return fmt.Errorf("%w: %q", ErrUnknownRole, p.Role)
		}
		if !ValidAgentKind(p.AgentKind) {
			return fmt.Errorf("%w: %q", ErrUnknownAgentKind, p.AgentKind)
		}
		for _, binding := range []struct {
			name string
			id   string
			seen map[string]bool
		}{
			{"session", p.SessionID, seenSession},
			{"workload", p.WorkloadID, seenWorkload},
			{"container", p.ContainerID, seenContainer},
		} {
			if strings.TrimSpace(binding.id) == "" {
				return fmt.Errorf("%w: empty %s id for %q", ErrTeamShape, binding.name, p.ParticipantID)
			}
			if binding.seen[binding.id] {
				return fmt.Errorf("%w: %s id %q shared by two participants",
					ErrDuplicateParticipant, binding.name, binding.id)
			}
			binding.seen[binding.id] = true
		}
		if strings.TrimSpace(p.RuntimeProvenanceID) == "" {
			return fmt.Errorf("%w: empty provenance ref for %q", ErrTeamShape, p.ParticipantID)
		}
		switch p.Role {
		case RolePM:
			pmCount++
			pmKind = p.AgentKind
		case RoleBuilder:
			builderCount++
		case RoleReviewer:
			reviewerCount++
			reviewerKinds[p.AgentKind] = true
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

// AcceptanceShape reports whether the roster meets the epic #18 live
// acceptance floor (one PM, at least two parallel builders, one
// different-agent reviewer).
func AcceptanceShape(participants []AgentParticipant) bool {
	if err := ValidateParticipants(participants); err != nil {
		return false
	}
	builders := 0
	for _, p := range participants {
		if p.Role == RoleBuilder {
			builders++
		}
	}
	return builders >= MinBuildersForAcceptance
}

// ValidateTaskDAG checks task shape: known states, known assignees, declared
// dependencies that exist, no self-edges, and an acyclic graph.
func ValidateTaskDAG(tasks []OrchestrationTask, participants []AgentParticipant) error {
	known := map[string]bool{}
	for _, p := range participants {
		known[p.ParticipantID] = true
	}
	byID := map[string]OrchestrationTask{}
	for _, t := range tasks {
		if strings.TrimSpace(t.TaskID) == "" {
			return fmt.Errorf("%w: empty task id", ErrTaskDAG)
		}
		if _, dup := byID[t.TaskID]; dup {
			return fmt.Errorf("%w: duplicate task %q", ErrTaskDAG, t.TaskID)
		}
		if !ValidTaskState(t.State) {
			return fmt.Errorf("%w: %q", ErrUnknownTaskState, t.State)
		}
		if t.AssigneeID != "" && !known[t.AssigneeID] {
			return fmt.Errorf("%w: task %q assigned to unknown %q", ErrTaskDAG, t.TaskID, t.AssigneeID)
		}
		if err := ValidateTaskSummary(t.PublicSummary); err != nil {
			return err
		}
		byID[t.TaskID] = t
	}
	for _, t := range tasks {
		for _, dep := range t.DependsOn {
			if dep == t.TaskID {
				return fmt.Errorf("%w: task %q depends on itself", ErrTaskDAG, t.TaskID)
			}
			if _, ok := byID[dep]; !ok {
				return fmt.Errorf("%w: task %q depends on unknown %q", ErrTaskDAG, t.TaskID, dep)
			}
		}
	}
	// Kahn's algorithm over dependency edges: anything left unvisited is a cycle.
	indegree := map[string]int{}
	dependents := map[string][]string{}
	for _, t := range tasks {
		indegree[t.TaskID] = len(t.DependsOn)
		for _, dep := range t.DependsOn {
			dependents[dep] = append(dependents[dep], t.TaskID)
		}
	}
	var queue []string
	for id, deg := range indegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	visited := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		visited++
		for _, next := range dependents[id] {
			indegree[next]--
			if indegree[next] == 0 {
				queue = append(queue, next)
			}
		}
	}
	if visited != len(tasks) {
		return fmt.Errorf("%w: dependency cycle", ErrTaskDAG)
	}
	return nil
}

// RegisterTask loads one validated task into the ledger.
func (l *Ledger) RegisterTask(task OrchestrationTask) error {
	if _, ok := l.Tasks[task.TaskID]; ok {
		return fmt.Errorf("%w: task %q", ErrTaskDAG, task.TaskID)
	}
	if !ValidTaskState(task.State) {
		return fmt.Errorf("%w: %q", ErrUnknownTaskState, task.State)
	}
	cp := task
	l.Tasks[task.TaskID] = &cp
	return nil
}

// Append validates one client event against the full fail-closed rule set
// and projects it into the ordered stream: tenant scope, run liveness,
// event-id uniqueness, gap-free monotonic sequence, task transition
// legality, and duplicate-terminal rejection. It returns the stamped event.
func (l *Ledger) Append(ev ClientEvent, eventID string, timestampMS int64, visibility string) (OrchestrationEvent, error) {
	if err := ValidateClientEvent(ev); err != nil {
		return OrchestrationEvent{}, err
	}
	if ev.RunID != l.RunID {
		return OrchestrationEvent{}, fmt.Errorf("%w: event run %q is outside ledger %q",
			ErrReplayOutsideScope, ev.RunID, l.RunID)
	}
	if ev.TenantID != l.TenantID {
		return OrchestrationEvent{}, fmt.Errorf("%w: event tenant %q vs ledger %q",
			ErrTenantMismatch, ev.TenantID, l.TenantID)
	}
	if IsTerminalRunState(l.State) {
		return OrchestrationEvent{}, fmt.Errorf("%w: run is %s", ErrTerminalState, l.State)
	}
	if l.seenIDs[eventID] {
		return OrchestrationEvent{}, fmt.Errorf("%w: %q", ErrDuplicateEvent, eventID)
	}
	wantSeq := int64(len(l.Events) + 1)
	if _, err := l.applyStateGuard(ev); err != nil {
		return OrchestrationEvent{}, err
	}
	stamped, err := StampEvent(ev, eventID, wantSeq, timestampMS, visibility, l.headHash)
	if err != nil {
		return OrchestrationEvent{}, err
	}
	l.Events = append(l.Events, stamped)
	l.seenIDs[eventID] = true
	l.headHash = stamped.AuditHash
	return stamped, nil
}

// applyStateGuard enforces the lifecycle consequence of one event: run moves
// only along legal edges, task moves only along legal edges, and no task
// (or the run) records a second terminal result. It returns the task state
// the event would establish.
func (l *Ledger) applyStateGuard(ev ClientEvent) (string, error) {
	switch ev.Kind {
	case EventRequest, EventAuthorization, EventPMStart, EventPlanPublication,
		EventAssignment, EventAcknowledgment, EventProgress, EventHandoff,
		EventDecision, EventReview, EventSynthesis:
		// Non-terminal lifecycle signals: no state move by themselves.
		if ev.TaskID != "" {
			task, ok := l.Tasks[ev.TaskID]
			if !ok {
				return "", fmt.Errorf("%w: unknown task %q", ErrTaskDAG, ev.TaskID)
			}
			if IsTerminalTaskState(task.State) {
				return "", fmt.Errorf("%w: task %q is %s", ErrDuplicateTerminal, ev.TaskID, task.State)
			}
		}
		return "", nil
	case EventCompletion, EventFailure, EventTimeout, EventCancellation:
		if ev.TaskID != "" {
			task, ok := l.Tasks[ev.TaskID]
			if !ok {
				return "", fmt.Errorf("%w: unknown task %q", ErrTaskDAG, ev.TaskID)
			}
			if IsTerminalTaskState(task.State) {
				return "", fmt.Errorf("%w: task %q already %s", ErrDuplicateTerminal, ev.TaskID, task.State)
			}
			next := map[string]string{
				EventCompletion:   TaskDone,
				EventFailure:      TaskFailed,
				EventTimeout:      TaskTimedOut,
				EventCancellation: TaskCancelled,
			}[ev.Kind]
			if !AllowedTaskTransition(task.State, next) {
				return "", fmt.Errorf("%w: task %q %s -> %s",
					ErrIllegalTransition, ev.TaskID, task.State, next)
			}
			task.State = next
			task.TerminalResults++
			return next, nil
		}
		next := map[string]string{
			EventCompletion:   RunCompleted,
			EventFailure:      RunFailed,
			EventTimeout:      RunTimedOut,
			EventCancellation: RunCancelled,
		}[ev.Kind]
		if !AllowedRunTransition(l.State, next) {
			return "", fmt.Errorf("%w: run %s -> %s", ErrIllegalTransition, l.State, next)
		}
		l.State = next
		return next, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownEventKind, ev.Kind)
	}
}

// Read returns up to limit events after the cursor, scoped to this ledger.
// When events were compacted or the cursor points past the head, it reports
// degraded/incomplete instead of silently skipping: callers must surface
// that status, never a fake "connected" stream.
func (l *Ledger) Read(cursor Cursor, limit int) ([]OrchestrationEvent, Cursor, bool, error) {
	if err := cursor.ValidateScope(l.RunID, l.TenantID); err != nil {
		return nil, cursor, false, err
	}
	if limit <= 0 || limit > MaxWatchLimit {
		return nil, cursor, false, fmt.Errorf("%w: limit %d", ErrUnknownField, limit)
	}
	if cursor.AfterSeq > int64(len(l.Events)) {
		// Cursor beyond the head: the stream is incomplete, not empty.
		return nil, cursor, true, nil
	}
	end := cursor.AfterSeq + int64(limit)
	if end > int64(len(l.Events)) {
		end = int64(len(l.Events))
	}
	out := append([]OrchestrationEvent(nil), l.Events[cursor.AfterSeq:end]...)
	next := Cursor{RunID: l.RunID, TenantID: l.TenantID, AfterSeq: end}
	return out, next, false, nil
}

// VerifyChain recomputes every audit hash from the construction-time base
// (genesis, or the run's prior audit binding) and reports the first break.
// A projection that fails this check must not be served.
func (l *Ledger) VerifyChain() error {
	prev := l.baseHash
	for i, ev := range l.Events {
		if ev.Seq != int64(i+1) {
			return fmt.Errorf("%w: event %d has seq %d", ErrSequenceGap, i, ev.Seq)
		}
		want, err := EventAuditHash(prev, ev)
		if err != nil {
			return err
		}
		if want != ev.AuditHash {
			return fmt.Errorf("%w: audit break at seq %d", ErrSequenceGap, ev.Seq)
		}
		prev = ev.AuditHash
	}
	return nil
}

// HeadHash returns the current audit-chain head for revision binding.
func (l *Ledger) HeadHash() string { return l.headHash }
