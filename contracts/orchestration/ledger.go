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
// session/workload/container triple per BOUND participant.
//
// Status (revision 10) separates browser-proposed slots from control-bound
// participants: invited entries carry role/agent kind only and need no
// binding yet; every other state requires the full distinct triple plus a
// provenance ref. Unknown states fail closed; legacy rows without status
// normalize explicitly (bound triple present reads active, else invited).
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
		status := NormalizeParticipantStatus(p)
		if !ValidParticipantStatus(status) {
			return fmt.Errorf("%w: %q", ErrUnknownParticipantStatus, p.Status)
		}
		if status != ParticipantInvited {
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
	// Transactional append: compute the full transition plan WITHOUT
	// mutation, then stamp/validate the event, then append, and only then
	// commit state. Any failure before commit leaves run state, task
	// states, the event list, the sequence, and the head hash untouched.
	plan, err := l.computePlan(ev)
	if err != nil {
		return OrchestrationEvent{}, err
	}
	stamped, err := StampEvent(ev, eventID, wantSeq, timestampMS, visibility, l.headHash)
	if err != nil {
		return OrchestrationEvent{}, err
	}
	l.Events = append(l.Events, stamped)
	l.seenIDs[eventID] = true
	l.headHash = stamped.AuditHash
	plan.commit(l)
	return stamped, nil
}

// transitionPlan is the state consequence of one event, computed purely and
// committed only after the event stamps, validates, and appends. An empty
// runNext means the run does not move; taskNext maps task ids to their
// post-event state; taskTerminal marks tasks recording a terminal result.
type transitionPlan struct {
	runNext      string
	taskNext     map[string]string
	taskTerminal map[string]bool
}

// commit applies a computed plan. It runs only after a successful append.
func (p transitionPlan) commit(l *Ledger) {
	if p.runNext != "" {
		l.State = p.runNext
	}
	for id, next := range p.taskNext {
		if task, ok := l.Tasks[id]; ok {
			task.State = next
			if p.taskTerminal[id] {
				task.TerminalResults++
			}
		}
	}
}

// runFramingKinds may only appear at run level (no task id): they describe
// the run itself, never one task.
var runFramingKinds = map[string]bool{
	EventRequest:         true,
	EventAuthorization:   true,
	EventPMStart:         true,
	EventPlanPublication: true,
}

// taskFramingKinds may only appear at task level: they describe one task's
// assignment and custody, never the run.
var taskFramingKinds = map[string]bool{
	EventAssignment:     true,
	EventAcknowledgment: true,
	EventHandoff:        true,
}

// computePlan derives the lifecycle consequence of one event without mutating
// the ledger. Every move is validated through AllowedRunTransition and
// AllowedTaskTransition, so illegal and out-of-order events fail closed
// here, before any stamp or write.
func (l *Ledger) computePlan(ev ClientEvent) (transitionPlan, error) {
	plan := transitionPlan{taskNext: map[string]string{}, taskTerminal: map[string]bool{}}
	if !ValidEventKind(ev.Kind) {
		return plan, fmt.Errorf("%w: %q", ErrUnknownEventKind, ev.Kind)
	}
	if ev.TaskID == "" {
		return l.computeRunPlan(ev, plan)
	}
	return l.computeTaskPlan(ev, plan)
}

// computeRunPlan plans a run-level event: the request/authorization/PM-start
// chain moves the run requested -> authorized -> running; plan publication,
// progress, handoff, decision, review, and synthesis observe a running run;
// terminal kinds move it along legal edges only.
func (l *Ledger) computeRunPlan(ev ClientEvent, plan transitionPlan) (transitionPlan, error) {
	if taskFramingKinds[ev.Kind] {
		return plan, fmt.Errorf("%w: kind %q requires a task scope", ErrIllegalTransition, ev.Kind)
	}
	move := func(next string) (transitionPlan, error) {
		if !AllowedRunTransition(l.State, next) {
			return plan, fmt.Errorf("%w: run %s -> %s on %s",
				ErrIllegalTransition, l.State, next, ev.Kind)
		}
		plan.runNext = next
		return plan, nil
	}
	switch ev.Kind {
	case EventRequest:
		if l.State != RunRequested {
			return plan, fmt.Errorf("%w: request arrives for run in %s",
				ErrIllegalTransition, l.State)
		}
		return plan, nil
	case EventAuthorization:
		return move(RunAuthorized)
	case EventPMStart:
		return move(RunRunning)
	case EventPlanPublication, EventProgress, EventHandoff,
		EventDecision, EventReview, EventSynthesis:
		if l.State != RunRunning {
			return plan, fmt.Errorf("%w: kind %q outside a running run (%s)",
				ErrIllegalTransition, ev.Kind, l.State)
		}
		return plan, nil
	case EventCompletion, EventFailure, EventTimeout, EventCancellation:
		return move(map[string]string{
			EventCompletion:   RunCompleted,
			EventFailure:      RunFailed,
			EventTimeout:      RunTimedOut,
			EventCancellation: RunCancelled,
		}[ev.Kind])
	default:
		return plan, fmt.Errorf("%w: %q", ErrUnknownEventKind, ev.Kind)
	}
}

// computeTaskPlan plans a task-level event: assignment -> acknowledgment ->
// progress -> review (pending -> assigned -> acknowledged -> in_progress ->
// in_review), handoff/rework observed from in_progress or in_review,
// decision/synthesis observed from in_review, and terminal kinds along legal
// edges only. Task lifecycle proceeds only while the run itself is running,
// and never past a task terminal state (duplicate terminal results fail
// closed).
func (l *Ledger) computeTaskPlan(ev ClientEvent, plan transitionPlan) (transitionPlan, error) {
	if runFramingKinds[ev.Kind] {
		return plan, fmt.Errorf("%w: kind %q is run-scoped", ErrIllegalTransition, ev.Kind)
	}
	task, ok := l.Tasks[ev.TaskID]
	if !ok {
		return plan, fmt.Errorf("%w: unknown task %q", ErrTaskDAG, ev.TaskID)
	}
	if l.State != RunRunning {
		return plan, fmt.Errorf("%w: task %q event outside a running run (%s)",
			ErrIllegalTransition, ev.TaskID, l.State)
	}
	if IsTerminalTaskState(task.State) {
		return plan, fmt.Errorf("%w: task %q already %s", ErrDuplicateTerminal, ev.TaskID, task.State)
	}
	move := func(next string) (transitionPlan, error) {
		if !AllowedTaskTransition(task.State, next) {
			return plan, fmt.Errorf("%w: task %q %s -> %s on %s",
				ErrIllegalTransition, ev.TaskID, task.State, next, ev.Kind)
		}
		plan.taskNext[ev.TaskID] = next
		return plan, nil
	}
	observe := func(states ...string) (transitionPlan, error) {
		for _, s := range states {
			if task.State == s {
				return plan, nil
			}
		}
		return plan, fmt.Errorf("%w: kind %q illegal for task %q in %s",
			ErrIllegalTransition, ev.Kind, ev.TaskID, task.State)
	}
	switch ev.Kind {
	case EventAssignment:
		return move(TaskAssigned)
	case EventAcknowledgment:
		return move(TaskAcknowledged)
	case EventProgress:
		if task.State == TaskAcknowledged {
			return move(TaskInProgress)
		}
		return observe(TaskInProgress)
	case EventHandoff:
		return observe(TaskInProgress, TaskInReview)
	case EventReview:
		return move(TaskInReview)
	case EventDecision, EventSynthesis:
		return observe(TaskInReview)
	case EventCompletion, EventFailure, EventTimeout, EventCancellation:
		next := map[string]string{
			EventCompletion:   TaskDone,
			EventFailure:      TaskFailed,
			EventTimeout:      TaskTimedOut,
			EventCancellation: TaskCancelled,
		}[ev.Kind]
		plan, err := move(next)
		if err != nil {
			return plan, err
		}
		plan.taskTerminal[ev.TaskID] = true
		return plan, nil
	default:
		return plan, fmt.Errorf("%w: %q", ErrUnknownEventKind, ev.Kind)
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
