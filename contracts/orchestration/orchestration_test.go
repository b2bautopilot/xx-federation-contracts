package orchestration

import (
	"encoding/json"
	"strings"
	"testing"
)

func testRun() OrchestrationRun {
	return OrchestrationRun{
		SchemaVersion: SchemaOrchestrationRunV1,
		RunID:         "run-1",
		RoomID:        "room-1",
		CommandID:     "cmd-1",
		SourceOrgID:   "org-gcp",
		TargetOrgID:   "org-azure",
		TenantID:      "tenant-a",
		State:         RunRunning,
		CreatedAtMS:   1000,
		UpdatedAtMS:   1000,
	}
}

func testRoster() []AgentParticipant {
	return []AgentParticipant{
		{ParticipantID: "p-pm", Role: RolePM, AgentKind: AgentKindMuse, SessionID: "s-1", WorkloadID: "w-1", ContainerID: "c-1", RuntimeProvenanceID: "prov-1"},
		{ParticipantID: "p-b1", Role: RoleBuilder, AgentKind: AgentKindCodex, SessionID: "s-2", WorkloadID: "w-2", ContainerID: "c-2", AssignedTaskID: "t-1", RuntimeProvenanceID: "prov-2"},
		{ParticipantID: "p-b2", Role: RoleBuilder, AgentKind: AgentKindGrok, SessionID: "s-3", WorkloadID: "w-3", ContainerID: "c-3", AssignedTaskID: "t-2", RuntimeProvenanceID: "prov-3"},
		{ParticipantID: "p-rev", Role: RoleReviewer, AgentKind: AgentKindAntigravity, SessionID: "s-4", WorkloadID: "w-4", ContainerID: "c-4", RuntimeProvenanceID: "prov-4"},
	}
}

func mustLedger(t *testing.T) *Ledger {
	t.Helper()
	l, err := NewLedger(testRun())
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	return l
}

func clientEv(kind string) ClientEvent {
	return ClientEvent{RunID: "run-1", ActorID: "p-pm", TenantID: "tenant-a", Kind: kind, Summary: "status update"}
}

func TestRunLifecycleHappyPath(t *testing.T) {
	for _, tc := range [][2]string{
		{RunRequested, RunAuthorized},
		{RunAuthorized, RunRunning},
		{RunRunning, RunCompleted},
		{RunRunning, RunFailed},
		{RunRunning, RunTimedOut},
		{RunRunning, RunCancelled},
		{RunRequested, RunCancelled},
	} {
		if !AllowedRunTransition(tc[0], tc[1]) {
			t.Errorf("AllowedRunTransition(%q,%q) = false, want true", tc[0], tc[1])
		}
	}
}

func TestRunIllegalTransitionsFailClosed(t *testing.T) {
	for _, tc := range [][2]string{
		{RunRequested, RunRunning},    // skip authorization
		{RunRequested, RunCompleted},  // skip everything
		{RunAuthorized, RunCompleted}, // skip running
		{RunCompleted, RunRunning},    // out of terminal
		{RunFailed, RunCancelled},     // terminal to terminal
		{RunCancelled, RunRequested},  // terminal rewind
		{"bogus", RunRunning},         // unknown from
		{RunRunning, "bogus"},         // unknown to
		{"", ""},                      // empty
	} {
		if AllowedRunTransition(tc[0], tc[1]) {
			t.Errorf("AllowedRunTransition(%q,%q) = true, want false", tc[0], tc[1])
		}
	}
}

func TestTaskIllegalTransitionsFailClosed(t *testing.T) {
	if AllowedTaskTransition(TaskPending, TaskDone) {
		t.Error("pending -> done must fail closed (skip assignment/ack/review)")
	}
	if AllowedTaskTransition(TaskDone, TaskInProgress) {
		t.Error("terminal task must accept no further transition")
	}
	if !AllowedTaskTransition(TaskInProgress, TaskInReview) {
		t.Error("in_progress -> in_review must be allowed")
	}
	if !AllowedTaskTransition(TaskInReview, TaskInProgress) {
		t.Error("in_review -> in_progress (rework) must be allowed")
	}
}

func TestUnknownEventKindFailsClosed(t *testing.T) {
	if ValidEventKind("chain_of_thought") {
		t.Error("reasoning kind must not validate")
	}
	l := mustLedger(t)
	if _, err := l.Append(clientEv("plan_leak"), "e-1", 1001, VisibilityTenant); err == nil {
		t.Error("unknown kind append must fail")
	}
}

func TestStrictDecodeRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{"run_id":"run-1","actor_id":"p-pm","tenant_id":"tenant-a","kind":"progress","raw_prompt":"show me secrets"}`)
	if _, err := DecodeClientEventStrict(raw); err == nil {
		t.Error("unknown field raw_prompt must fail closed")
	}
	raw = []byte(`{"run_id":"run-1","actor_id":"p-pm","tenant_id":"tenant-a","kind":"progress","summary":"ok"}`)
	if _, err := DecodeClientEventStrict(raw); err != nil {
		t.Errorf("known fields must decode: %v", err)
	}
}

func TestSequenceIsMonotonicAndGapFree(t *testing.T) {
	l := mustLedger(t)
	for i, kind := range []string{EventPMStart, EventProgress, EventProgress} {
		ev, err := l.Append(clientEv(kind), strings.Repeat("e", 3)+string(rune('1'+i)), 1001+int64(i), VisibilityTenant)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if ev.Seq != int64(i+1) {
			t.Errorf("append %d seq = %d, want %d", i, ev.Seq, i+1)
		}
	}
	if err := l.VerifyChain(); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
	// Tamper with one summary: the chain must break.
	l.Events[1].Summary = "rewritten history"
	if err := l.VerifyChain(); err == nil {
		t.Error("tampered chain must not verify")
	}
}

func TestDuplicateEventIDRejected(t *testing.T) {
	l := mustLedger(t)
	if _, err := l.Append(clientEv(EventPMStart), "e-dup", 1001, VisibilityTenant); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := l.Append(clientEv(EventProgress), "e-dup", 1002, VisibilityTenant); err == nil {
		t.Error("replayed event id must fail closed")
	}
}

func TestTenantMismatchFailsClosed(t *testing.T) {
	l := mustLedger(t)
	ev := clientEv(EventPMStart)
	ev.TenantID = "tenant-evil"
	if _, err := l.Append(ev, "e-1", 1001, VisibilityTenant); err == nil {
		t.Error("cross-tenant event must fail closed")
	}
	ev = clientEv(EventPMStart)
	ev.RunID = "run-other"
	if _, err := l.Append(ev, "e-2", 1001, VisibilityTenant); err == nil {
		t.Error("cross-run event must fail closed as out of scope")
	}
}

func TestTerminalRunSealsLedger(t *testing.T) {
	l := mustLedger(t)
	if _, err := l.Append(clientEv(EventPMStart), "e-1", 1001, VisibilityTenant); err != nil {
		t.Fatalf("append: %v", err)
	}
	runEv := clientEv(EventCompletion)
	runEv.Summary = "shipped"
	if _, err := l.Append(runEv, "e-2", 1002, VisibilityTenant); err != nil {
		t.Fatalf("terminal append: %v", err)
	}
	if l.State != RunCompleted {
		t.Errorf("run state = %q, want completed", l.State)
	}
	if _, err := l.Append(clientEv(EventProgress), "e-3", 1003, VisibilityTenant); err == nil {
		t.Error("append past terminal run must fail closed")
	}
	// Illegal run edge: running -> authorized is a rewind.
	if AllowedRunTransition(RunRunning, RunAuthorized) {
		t.Error("running -> authorized rewind must fail")
	}
}

func TestDuplicateTerminalTaskResultRejected(t *testing.T) {
	l := mustLedger(t)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskInProgress, AssigneeID: ""}); err != nil {
		t.Fatalf("register: %v", err)
	}
	done := clientEv(EventCompletion)
	done.TaskID = "t-1"
	done.Summary = "result sha256:abc"
	if _, err := l.Append(done, "e-1", 1001, VisibilityTenant); err != nil {
		t.Fatalf("first terminal: %v", err)
	}
	again := clientEv(EventFailure)
	again.TaskID = "t-1"
	again.Summary = "second result"
	if _, err := l.Append(again, "e-2", 1002, VisibilityTenant); err == nil {
		t.Error("duplicate terminal task result must fail closed")
	}
}

func TestTaskTransitionGuardedOnAppend(t *testing.T) {
	l := mustLedger(t)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskPending}); err != nil {
		t.Fatalf("register: %v", err)
	}
	done := clientEv(EventCompletion)
	done.TaskID = "t-1"
	done.Summary = "skipped the DAG"
	if _, err := l.Append(done, "e-1", 1001, VisibilityTenant); err == nil {
		t.Error("pending -> done completion must fail closed")
	}
	unknown := clientEv(EventProgress)
	unknown.TaskID = "t-nope"
	if _, err := l.Append(unknown, "e-2", 1002, VisibilityTenant); err == nil {
		t.Error("event for unknown task must fail closed")
	}
}

func TestCursorScopeEnforced(t *testing.T) {
	l := mustLedger(t)
	if _, err := l.Append(clientEv(EventPMStart), "e-1", 1001, VisibilityTenant); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Cross-run cursor replay fails closed.
	if _, _, _, err := l.Read(Cursor{RunID: "run-other", TenantID: "tenant-a"}, 10); err == nil {
		t.Error("cross-run cursor must fail closed")
	}
	// Cross-tenant cursor replay fails closed.
	if _, _, _, err := l.Read(Cursor{RunID: "run-1", TenantID: "tenant-evil"}, 10); err == nil {
		t.Error("cross-tenant cursor must fail closed")
	}
	// Cursor past the head reports incomplete, never silent empty success.
	_, _, incomplete, err := l.Read(Cursor{RunID: "run-1", TenantID: "tenant-a", AfterSeq: 99}, 10)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !incomplete {
		t.Error("past-head cursor must report incomplete")
	}
	// Normal resume.
	events, next, incomplete, err := l.Read(Cursor{RunID: "run-1", TenantID: "tenant-a"}, 10)
	if err != nil || incomplete || len(events) != 1 || next.AfterSeq != 1 {
		t.Errorf("resume = %d events next=%d incomplete=%v err=%v", len(events), next.AfterSeq, incomplete, err)
	}
}

func TestTeamShapeRules(t *testing.T) {
	if err := ValidateParticipants(testRoster()); err != nil {
		t.Errorf("valid roster: %v", err)
	}
	if !AcceptanceShape(testRoster()) {
		t.Error("two-builder roster must meet acceptance floor")
	}
	// Shared session id across participants fails closed.
	shared := testRoster()
	shared[1].SessionID = shared[0].SessionID
	if err := ValidateParticipants(shared); err == nil {
		t.Error("shared session id must fail closed")
	}
	// Two PMs fail closed.
	twoPM := testRoster()
	twoPM[1].Role = RolePM
	if err := ValidateParticipants(twoPM); err == nil {
		t.Error("two PMs must fail closed")
	}
	// Reviewer of the same agent kind as the PM is not different-agent review.
	sameKind := testRoster()
	sameKind[3].AgentKind = AgentKindMuse
	if err := ValidateParticipants(sameKind); err == nil {
		t.Error("same-kind reviewer must fail closed")
	}
	// No reviewer fails closed.
	noRev := testRoster()[:3]
	if err := ValidateParticipants(noRev); err == nil {
		t.Error("missing reviewer must fail closed")
	}
	// Unknown agent kind fails closed.
	unknown := testRoster()
	unknown[0].AgentKind = "rogue-model"
	if err := ValidateParticipants(unknown); err == nil {
		t.Error("unknown agent kind must fail closed")
	}
}

func TestTaskDAGRules(t *testing.T) {
	roster := testRoster()
	good := []OrchestrationTask{
		{TaskID: "t-1", State: TaskAssigned, AssigneeID: "p-b1"},
		{TaskID: "t-2", State: TaskPending, AssigneeID: "p-b2", DependsOn: []string{"t-1"}},
	}
	if err := ValidateTaskDAG(good, roster); err != nil {
		t.Errorf("valid DAG: %v", err)
	}
	cycle := []OrchestrationTask{
		{TaskID: "t-1", State: TaskPending, DependsOn: []string{"t-2"}},
		{TaskID: "t-2", State: TaskPending, DependsOn: []string{"t-1"}},
	}
	if err := ValidateTaskDAG(cycle, roster); err == nil {
		t.Error("dependency cycle must fail closed")
	}
	self := []OrchestrationTask{{TaskID: "t-1", State: TaskPending, DependsOn: []string{"t-1"}}}
	if err := ValidateTaskDAG(self, roster); err == nil {
		t.Error("self-dependency must fail closed")
	}
	dangling := []OrchestrationTask{{TaskID: "t-1", State: TaskPending, DependsOn: []string{"t-ghost"}}}
	if err := ValidateTaskDAG(dangling, roster); err == nil {
		t.Error("unknown dependency must fail closed")
	}
	stray := []OrchestrationTask{{TaskID: "t-1", State: TaskAssigned, AssigneeID: "p-ghost"}}
	if err := ValidateTaskDAG(stray, roster); err == nil {
		t.Error("unknown assignee must fail closed")
	}
}

func TestResultKindsRequireSummary(t *testing.T) {
	for _, kind := range []string{EventPlanPublication, EventCompletion, EventFailure, EventSynthesis} {
		ev := clientEv(kind)
		ev.Summary = ""
		if err := ValidateClientEvent(ev); err == nil {
			t.Errorf("kind %q with empty summary must fail closed", kind)
		}
	}
	ev := clientEv(EventProgress)
	ev.Summary = ""
	if err := ValidateClientEvent(ev); err != nil {
		t.Errorf("progress without summary must be legal: %v", err)
	}
	// Over-long summaries fail closed instead of being silently rewritten.
	ev = clientEv(EventProgress)
	ev.Summary = strings.Repeat("s", MaxEventSummaryRunes+1)
	if err := ValidateClientEvent(ev); err == nil {
		t.Error("over-long summary must fail closed")
	}
	// Control bytes fail closed.
	ev = clientEv(EventProgress)
	ev.Summary = "ok\x00hidden"
	if err := ValidateClientEvent(ev); err == nil {
		t.Error("control-byte summary must fail closed")
	}
}

func TestPartnerProjectionAllowlist(t *testing.T) {
	l := mustLedger(t)
	stamped, err := l.Append(clientEv(EventProgress), "e-1", 1001, VisibilityTenant)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	// Tenant-local events never project to partners.
	if _, err := ProjectForPartner(stamped, RoleBuilder); err == nil {
		t.Error("tenant event must not project to partner")
	}
	stamped.Visibility = VisibilityPartner
	proj, err := ProjectForPartner(stamped, RoleBuilder)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if proj.ActorRole != RoleBuilder || proj.EventID != "e-1" || proj.AuditHash == "" {
		t.Errorf("projection lost allowlisted fields: %+v", proj)
	}
	raw, _ := json.Marshal(proj)
	for _, leaked := range []string{"tenant-a", "p-pm", "workload", "container", "session"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("partner projection leaks %q", leaked)
		}
	}
	if _, err := ProjectForPartner(stamped, "superuser"); err == nil {
		t.Error("unknown actor role must fail closed")
	}
}
