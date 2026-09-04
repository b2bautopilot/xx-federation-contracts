package orchestration

import (
	"strings"
	"testing"
)

func testRunAt(state string) OrchestrationRun {
	run := testRun()
	run.State = state
	return run
}

func mustLedgerAt(t *testing.T, state string) *Ledger {
	t.Helper()
	l, err := NewLedger(testRunAt(state))
	if err != nil {
		t.Fatalf("NewLedger(%q): %v", state, err)
	}
	return l
}

func taskEv(kind, taskID, summary string) ClientEvent {
	return ClientEvent{
		RunID: "run-1", TaskID: taskID, ActorID: "p-b1",
		TenantID: "tenant-a", Kind: kind, Summary: summary,
	}
}

// TestEndToEndLifecycle walks a real requested run and pending task through
// every legal edge to terminal states, asserting the state after each step.
func TestEndToEndLifecycle(t *testing.T) {
	l := mustLedgerAt(t, RunRequested)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskPending}); err != nil {
		t.Fatalf("register: %v", err)
	}
	steps := []struct {
		ev        ClientEvent
		id        string
		runState  string
		taskState string
	}{
		{clientEv(EventRequest), "e-1", RunRequested, TaskPending},
		{clientEv(EventAuthorization), "e-2", RunAuthorized, TaskPending},
		{clientEv(EventPMStart), "e-3", RunRunning, TaskPending},
		{taskEv(EventAssignment, "t-1", "assigned to builder one"), "e-4", RunRunning, TaskAssigned},
		{taskEv(EventAcknowledgment, "t-1", "builder one acks"), "e-5", RunRunning, TaskAcknowledged},
		{taskEv(EventProgress, "t-1", "halfway"), "e-6", RunRunning, TaskInProgress},
		{taskEv(EventProgress, "t-1", "three quarters"), "e-7", RunRunning, TaskInProgress},
		{taskEv(EventHandoff, "t-1", "handing draft to reviewer"), "e-8", RunRunning, TaskInProgress},
		{taskEv(EventReview, "t-1", "under review"), "e-9", RunRunning, TaskInReview},
		{taskEv(EventDecision, "t-1", "approved with notes"), "e-10", RunRunning, TaskInReview},
		{taskEv(EventSynthesis, "t-1", "merged result"), "e-11", RunRunning, TaskInReview},
		{taskEv(EventCompletion, "t-1", "result sha256:abc"), "e-12", RunRunning, TaskDone},
		{clientEv(EventCompletion), "e-13", RunCompleted, TaskDone},
	}
	// Result-bearing run completion needs a summary.
	steps[len(steps)-1].ev.Summary = "run complete"
	for i, s := range steps {
		ev, err := l.Append(s.ev, s.id, 1001+int64(i), VisibilityTenant)
		if err != nil {
			t.Fatalf("step %d (%s): %v", i, s.ev.Kind, err)
		}
		if ev.Seq != int64(i+1) {
			t.Fatalf("step %d seq = %d, want %d", i, ev.Seq, i+1)
		}
		if l.State != s.runState {
			t.Errorf("step %d run = %q, want %q", i, l.State, s.runState)
		}
		if got := l.Tasks["t-1"].State; got != s.taskState {
			t.Errorf("step %d task = %q, want %q", i, got, s.taskState)
		}
	}
	if err := l.VerifyChain(); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
	if got := l.Tasks["t-1"].TerminalResults; got != 1 {
		t.Errorf("terminal results = %d, want 1", got)
	}
}

func TestRunOutOfOrderFailsClosed(t *testing.T) {
	l := mustLedgerAt(t, RunRequested)
	// PM start before authorization skips a legal edge.
	if _, err := l.Append(clientEv(EventPMStart), "e-1", 1001, VisibilityTenant); err == nil {
		t.Fatal("pm_start while requested must fail closed")
	}
	// Authorization works once, then a second authorization is a rewind.
	if _, err := l.Append(clientEv(EventAuthorization), "e-2", 1002, VisibilityTenant); err != nil {
		t.Fatalf("authorization: %v", err)
	}
	if _, err := l.Append(clientEv(EventAuthorization), "e-3", 1003, VisibilityTenant); err == nil {
		t.Error("second authorization must fail closed")
	}
	// A late request for an authorized run is out of order.
	if _, err := l.Append(clientEv(EventRequest), "e-4", 1004, VisibilityTenant); err == nil {
		t.Error("late request must fail closed")
	}
	// Run completion that skips running is illegal.
	if _, err := l.Append(clientEv(EventCompletion), "e-5", 1005, VisibilityTenant); err == nil {
		t.Error("completion from authorized must fail closed")
	}
	// Plan publication outside a running run is illegal.
	plan := clientEv(EventPlanPublication)
	plan.Summary = "the plan"
	if _, err := l.Append(plan, "e-6", 1006, VisibilityTenant); err == nil {
		t.Error("plan publication while authorized must fail closed")
	}
	if l.State != RunAuthorized || len(l.Events) != 1 {
		t.Errorf("failed appends mutated the ledger: state=%q events=%d", l.State, len(l.Events))
	}
}

func TestTaskOutOfOrderFailsClosed(t *testing.T) {
	l := mustLedger(t)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskPending}); err != nil {
		t.Fatalf("register: %v", err)
	}
	illegal := []ClientEvent{
		taskEv(EventProgress, "t-1", "too early"),
		taskEv(EventAcknowledgment, "t-1", "too early"),
		taskEv(EventReview, "t-1", "too early"),
		taskEv(EventCompletion, "t-1", "skipped everything"),
	}
	for i, ev := range illegal {
		if _, err := l.Append(ev, "bad-"+string(rune('1'+i)), 1001+int64(i), VisibilityTenant); err == nil {
			t.Errorf("illegal task event %d (%s) must fail closed", i, ev.Kind)
		}
	}
	// Legal prefix, then a double assignment.
	if _, err := l.Append(taskEv(EventAssignment, "t-1", "go"), "e-1", 1010, VisibilityTenant); err != nil {
		t.Fatalf("assignment: %v", err)
	}
	if _, err := l.Append(taskEv(EventAssignment, "t-1", "go again"), "e-2", 1011, VisibilityTenant); err == nil {
		t.Error("double assignment must fail closed")
	}
	// Review from acknowledged skips in_progress.
	if _, err := l.Append(taskEv(EventAcknowledgment, "t-1", "ack"), "e-3", 1012, VisibilityTenant); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if _, err := l.Append(taskEv(EventReview, "t-1", "review"), "e-4", 1013, VisibilityTenant); err == nil {
		t.Error("review from acknowledged must fail closed")
	}
	if got := l.Tasks["t-1"].State; got != TaskAcknowledged {
		t.Errorf("task = %q, want acknowledged", got)
	}
}

func TestScopeFramingEnforced(t *testing.T) {
	l := mustLedger(t)
	// Task-framing kinds at run level fail closed.
	for i, kind := range []string{EventAssignment, EventAcknowledgment, EventHandoff} {
		if _, err := l.Append(clientEv(kind), "f1-"+string(rune('1'+i)), 1001, VisibilityTenant); err == nil {
			t.Errorf("run-level %s must fail closed", kind)
		}
	}
	// Run-framing kinds at task level fail closed.
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskInProgress}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for i, kind := range []string{EventRequest, EventAuthorization, EventPMStart, EventPlanPublication} {
		ev := taskEv(kind, "t-1", "framing probe")
		if _, err := l.Append(ev, "f2-"+string(rune('1'+i)), 1001, VisibilityTenant); err == nil {
			t.Errorf("task-level %s must fail closed", kind)
		}
	}
}

func TestTaskEventsRequireRunningRun(t *testing.T) {
	l := mustLedgerAt(t, RunAuthorized)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskPending}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := l.Append(taskEv(EventAssignment, "t-1", "early"), "e-1", 1001, VisibilityTenant); err == nil {
		t.Error("task assignment while run is authorized must fail closed")
	}
}

// TestAppendTransactional proves a stamp-stage failure leaves every ledger
// observable unchanged: run state, task state, terminal count, event list,
// next sequence, seen ids, and head hash.
func TestAppendTransactional(t *testing.T) {
	l := mustLedger(t)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskInProgress}); err != nil {
		t.Fatalf("register: %v", err)
	}
	before, err := l.Append(taskEv(EventProgress, "t-1", "steady"), "e-good", 1001, VisibilityTenant)
	if err != nil {
		t.Fatalf("baseline append: %v", err)
	}
	headBefore := l.HeadHash()
	// Stamp-stage failure: forged visibility is caught at stamp time, after
	// the (pure) plan computed fine — nothing may commit.
	bad := taskEv(EventCompletion, "t-1", "result sha256:abc")
	if _, err := l.Append(bad, "e-poison", 1002, "superuser"); err == nil {
		t.Fatal("forged visibility must fail closed")
	}
	if l.State != RunRunning {
		t.Errorf("run state mutated: %q", l.State)
	}
	task := l.Tasks["t-1"]
	if task.State != TaskInProgress || task.TerminalResults != 0 {
		t.Errorf("task mutated: %+v", task)
	}
	if len(l.Events) != 1 || l.Events[0].EventID != before.EventID {
		t.Errorf("event list mutated: %d events", len(l.Events))
	}
	if l.HeadHash() != headBefore {
		t.Error("head hash mutated by failed append")
	}
	// The poisoned id was never consumed and the sequence never advanced:
	// retrying a FRESH id lands on seq 2, and even the poisoned id is free.
	retry, err := l.Append(bad, "e-retry", 1003, VisibilityTenant)
	if err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if retry.Seq != 2 {
		t.Errorf("retry seq = %d, want 2", retry.Seq)
	}
	if task.State != TaskDone || task.TerminalResults != 1 {
		t.Errorf("task after retry: %+v", task)
	}
	// Intake-stage failure (over-long summary) is equally non-mutating.
	huge := taskEv(EventProgress, "t-1", strings.Repeat("x", MaxEventSummaryRunes+1))
	nEvents, head := len(l.Events), l.HeadHash()
	if _, err := l.Append(huge, "e-huge", 1004, VisibilityTenant); err == nil {
		t.Fatal("over-long summary must fail closed")
	}
	if len(l.Events) != nEvents || l.HeadHash() != head {
		t.Error("failed intake mutated the ledger")
	}
}

func TestRepeatProgressAndHandoffRework(t *testing.T) {
	l := mustLedger(t)
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-1", State: TaskAcknowledged}); err != nil {
		t.Fatalf("register: %v", err)
	}
	flow := []ClientEvent{
		taskEv(EventProgress, "t-1", "started"),
		taskEv(EventProgress, "t-1", "more"),
		taskEv(EventHandoff, "t-1", "passing the draft"),
		taskEv(EventReview, "t-1", "in review"),
		taskEv(EventHandoff, "t-1", "rework requested"),
	}
	for i, ev := range flow {
		if _, err := l.Append(ev, "r-"+string(rune('1'+i)), 1001+int64(i), VisibilityTenant); err != nil {
			t.Fatalf("flow %d (%s): %v", i, ev.Kind, err)
		}
	}
	if got := l.Tasks["t-1"].State; got != TaskInReview {
		t.Errorf("task = %q, want in_review", got)
	}
	// Handoff from an early state stays illegal.
	if err := l.RegisterTask(OrchestrationTask{TaskID: "t-2", State: TaskAssigned}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := l.Append(taskEv(EventHandoff, "t-2", "too early"), "r-x", 1010, VisibilityTenant); err == nil {
		t.Error("handoff from assigned must fail closed")
	}
}
