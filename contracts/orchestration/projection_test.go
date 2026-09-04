package orchestration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/attachment"
	"github.com/b2bautopilot/xx-federation-contracts/contracts/provenance"
)

const projNowMS = int64(5000)

func testProvDoc(id, runtime, cloud string) provenance.RuntimeProvenance {
	d := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return provenance.RuntimeProvenance{
		SchemaVersion:      provenance.SchemaRuntimeProvenanceV1,
		ProvenanceID:       id,
		OCIIndexDigest:     "sha256:" + d,
		OCIPlatformDigests: map[string]string{"linux/amd64": "sha256:" + d},
		AgentKitCommit:     "0123456789abcdef0123456789abcdef01234567",
		AgentKitVersion:    "agentkit-0.9.0",
		CLIName:            "muse",
		CLIVersion:         "1.2.3",
		ModelID:            "muse-spark",
		ProviderID:         "meta-msl",
		NetworkPolicyHash:  "sha256:" + d,
		SpecRevision:       10,
		SpecHash:           "sha256:" + d,
		RuntimeKind:        runtime,
		Cloud:              cloud,
		NonRoot:            true,
		NoNewPrivileges:    true,
		ImageVerified:      true,
	}
}

func testAttRef(id, audience string) attachment.AttachmentRef {
	return attachment.AttachmentRef{
		SchemaVersion: attachment.SchemaAttachmentRefV1,
		AttachmentID:  id,
		SHA256Hex:     attachment.DigestHex([]byte("evidence body " + id)),
		SizeBytes:     int64(len("evidence body " + id)),
		MIME:          "text/plain; charset=utf-8",
		DisplayName:   "evidence-" + id + ".txt",
		Direction:     attachment.DirectionReturned,
		ScanState:     attachment.ScanClean,
		Audience:      audience,
		ExpiresAtMS:   9000,
	}
}

func mustEvidence(t *testing.T, id, audience, lifecycle string) attachment.AttachmentEvidence {
	t.Helper()
	ev, err := attachment.EvaluateEvidence(testAttRef(id, audience), lifecycle, attachment.AudienceTenant, projNowMS)
	if err != nil {
		t.Fatalf("evaluate %s: %v", id, err)
	}
	return ev
}

// boundRoster returns a fully bound roster with explicit active status.
func boundRoster() []AgentParticipant {
	roster := testRoster()
	for i := range roster {
		roster[i].Status = ParticipantActive
	}
	return roster
}

func testTasks() []OrchestrationTask {
	return []OrchestrationTask{
		{TaskID: "t-1", AssigneeID: "p-b1", State: TaskInProgress, PublicSummary: "halfway", AttachmentIDs: []string{"att-1"}},
		{TaskID: "t-2", AssigneeID: "p-b2", State: TaskPending, DependsOn: []string{"t-1"}, PublicSummary: "queued"},
	}
}

// mustResponse builds the canonical valid snapshot: run + 4 bound
// participants + 2-task DAG + 4 provenance records + tenant evidence,
// counts computed from the served sections, cursor at head.
func mustResponse(t *testing.T) GetRunResponse {
	t.Helper()
	roster := boundRoster()
	tasks := testTasks()
	prov := []provenance.RuntimeProvenance{
		testProvDoc("prov-1", provenance.RuntimeGCPCloudRun, provenance.CloudGCP),
		testProvDoc("prov-2", provenance.RuntimeAzureContainerApps, provenance.CloudAzure),
		testProvDoc("prov-3", provenance.RuntimeAWSECSFargate, provenance.CloudAWS),
		testProvDoc("prov-4", provenance.RuntimeAzureContainerInst, provenance.CloudAzure),
	}
	evidence := []attachment.AttachmentEvidence{
		mustEvidence(t, "att-1", attachment.AudienceTenant, attachment.LifecycleReturned),
	}
	counts, err := ComputeCounts(roster, tasks, prov, evidence, 7)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	r := GetRunResponse{
		SchemaVersion: SchemaRunProjectionV1,
		Run:           testRun(),
		Participants:  roster,
		Tasks:         tasks,
		Provenance:    prov,
		Attachments:   evidence,
		Counts:        counts,
		NextAfterSeq:  7,
		ProjectedAtMS: projNowMS,
	}
	SortResponse(&r)
	if err := ValidateResponse(r, projNowMS); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	return r
}

func TestParticipantStatusVocabularyClosed(t *testing.T) {
	for _, tc := range [][2]string{
		{ParticipantInvited, ParticipantActive},
		{ParticipantActive, ParticipantSuspended},
		{ParticipantSuspended, ParticipantActive},
		{ParticipantActive, ParticipantDeparted},
		{ParticipantSuspended, ParticipantRemoved},
		{ParticipantInvited, ParticipantRemoved},
	} {
		if !AllowedParticipantTransition(tc[0], tc[1]) {
			t.Errorf("AllowedParticipantTransition(%q,%q) = false, want true", tc[0], tc[1])
		}
	}
	for _, tc := range [][2]string{
		{ParticipantInvited, ParticipantSuspended}, // must bind first
		{ParticipantInvited, ParticipantDeparted},  // must bind first
		{ParticipantActive, ParticipantInvited},    // rewind
		{ParticipantDeparted, ParticipantActive},   // out of terminal
		{ParticipantRemoved, ParticipantSuspended}, // out of terminal
		{"bogus", ParticipantActive},
		{ParticipantActive, "bogus"},
		{"", ""},
	} {
		if AllowedParticipantTransition(tc[0], tc[1]) {
			t.Errorf("AllowedParticipantTransition(%q,%q) = true, want false", tc[0], tc[1])
		}
	}
	if ValidParticipantStatus("") {
		t.Error("empty status is never valid; normalize explicitly")
	}
}

func TestNormalizeLegacyRowsExplicit(t *testing.T) {
	bound := AgentParticipant{SessionID: "s-1", WorkloadID: "w-1", ContainerID: "c-1"}
	if got := NormalizeParticipantStatus(bound); got != ParticipantActive {
		t.Errorf("bound legacy row normalizes to %q, want active", got)
	}
	slot := AgentParticipant{Role: RoleBuilder, AgentKind: AgentKindCodex}
	if got := NormalizeParticipantStatus(slot); got != ParticipantInvited {
		t.Errorf("unbound legacy row normalizes to %q, want invited", got)
	}
	partial := AgentParticipant{SessionID: "s-1"}
	if got := NormalizeParticipantStatus(partial); got != ParticipantInvited {
		t.Errorf("partially bound legacy row normalizes to %q, want invited (fail closed)", got)
	}
	explicit := AgentParticipant{Status: ParticipantSuspended}
	if got := NormalizeParticipantStatus(explicit); got != ParticipantSuspended {
		t.Errorf("explicit status must be preserved, got %q", got)
	}
	unknown := AgentParticipant{Status: "bogus"}
	if got := NormalizeParticipantStatus(unknown); got != "bogus" {
		t.Errorf("unknown status must pass through to fail validation, got %q", got)
	}
}

func TestLegacyRosterStillValidates(t *testing.T) {
	// Additive compatibility: revision-9 rows without status keep
	// validating (they normalize to active: the triple is bound).
	if err := ValidateParticipants(testRoster()); err != nil {
		t.Errorf("legacy roster without status: %v", err)
	}
	raw, err := json.Marshal(testRoster()[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "status") {
		t.Errorf("omitempty must keep legacy bytes free of status: %s", raw)
	}
	var decoded AgentParticipant
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if NormalizeParticipantStatus(decoded) != ParticipantActive {
		t.Error("legacy decoded row must read active")
	}
	// Unknown status fails even with a full binding.
	evil := testRoster()
	evil[0].Status = "superuser"
	if err := ValidateParticipants(evil); err == nil {
		t.Error("unknown security-relevant state must fail closed")
	}
	// Active claims without binding fail.
	unbound := testRoster()
	unbound[0].Status = ParticipantActive
	unbound[0].SessionID = ""
	if err := ValidateParticipants(unbound); err == nil {
		t.Error("active without session binding must fail")
	}
}

func TestDuplicateRosterFails(t *testing.T) {
	roster := boundRoster()
	roster = append(roster, roster[0])
	if err := ValidateParticipants(roster); err == nil {
		t.Error("duplicate roster entry must fail")
	}
}

func TestValidSnapshotRoundtrip(t *testing.T) {
	r := mustResponse(t)
	raw, err := CanonicalResponseBytes(r)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	decoded, err := DecodeResponseStrict(raw)
	if err != nil {
		t.Fatalf("strict decode of own canonical bytes: %v", err)
	}
	if err := ValidateResponse(decoded, projNowMS); err != nil {
		t.Errorf("roundtripped snapshot: %v", err)
	}
	again, err := CanonicalResponseBytes(decoded)
	if err != nil {
		t.Fatalf("re-canonical: %v", err)
	}
	if string(raw) != string(again) {
		t.Error("canonical serialization is not deterministic across roundtrip")
	}
}

func TestUnsortedSectionsFail(t *testing.T) {
	r := mustResponse(t)
	r.Participants[0], r.Participants[3] = r.Participants[3], r.Participants[0]
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("unsorted roster must fail (deterministic ordering)")
	}
	r = mustResponse(t)
	r.Tasks[0], r.Tasks[1] = r.Tasks[1], r.Tasks[0]
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("unsorted DAG must fail")
	}
}

func TestCountFabricationFails(t *testing.T) {
	r := mustResponse(t)
	r.Counts.ParticipantsTotal = 99
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("inflated participant count must fail")
	}
	r = mustResponse(t)
	r.Counts.AttachmentsDownloadable = 5
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("inflated downloadable count must fail")
	}
	r = mustResponse(t)
	r.Counts.HeadSeq = -1
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("negative head sequence must fail")
	}
	// Overflow-scale fabrication mismatches the served sections.
	r = mustResponse(t)
	r.Counts.ParticipantsTotal = math.MaxInt64
	r.Counts.ParticipantsActive = math.MaxInt64
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("overflow-scale counts must fail against served sections")
	}
	if err := ValidateCounts(ObservationCounts{TasksTotal: 2, TasksTerminal: 3}); err == nil {
		t.Error("terminal exceeding total must fail")
	}
	if err := ValidateCounts(ObservationCounts{ParticipantsTotal: -1}); err == nil {
		t.Error("negative counts must fail")
	}
}

func TestCursorSemanticsExplicit(t *testing.T) {
	r := mustResponse(t)
	// Cursor past head fails.
	r.NextAfterSeq = 8
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("cursor past head must fail")
	}
	// Incomplete MUST be exactly (next < head): both directions enforced.
	r = mustResponse(t)
	r.NextAfterSeq = 5
	r.Incomplete = false
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("lagging cursor without incomplete must fail")
	}
	r = mustResponse(t)
	r.Incomplete = true
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("incomplete at head must fail")
	}
	// Negative cursor fails.
	r = mustResponse(t)
	r.NextAfterSeq = -1
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("negative cursor must fail")
	}
	// A lagging cursor WITH incomplete validates: partial outage is
	// explicit, never silent.
	r = mustResponse(t)
	r.NextAfterSeq = 5
	r.Incomplete = true
	r.Degraded = true
	if err := ValidateResponse(r, projNowMS); err != nil {
		t.Errorf("explicit degraded/incomplete snapshot: %v", err)
	}
	// Degraded at head also validates: degraded reports backend health,
	// not cursor position.
	r = mustResponse(t)
	r.Degraded = true
	if err := ValidateResponse(r, projNowMS); err != nil {
		t.Errorf("degraded-at-head snapshot: %v", err)
	}
}

func TestMismatchedReferencesFail(t *testing.T) {
	// Task assigned outside the roster.
	r := mustResponse(t)
	r.Tasks[0].AssigneeID = "p-ghost"
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("task assigned to ghost must fail")
	}
	// Slot assigned to an unknown task.
	r = mustResponse(t)
	r.Participants[1].AssignedTaskID = "t-ghost"
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("slot assigned to ghost task must fail")
	}
	// Roster provenance ref outside the served set.
	r = mustResponse(t)
	r.Participants[1].RuntimeProvenanceID = "prov-ghost"
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("roster referencing unserved provenance must fail")
	}
	// Task attachment ref outside the served evidence.
	r = mustResponse(t)
	r.Tasks[0].AttachmentIDs = []string{"att-ghost"}
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("task referencing unserved attachment must fail")
	}
	// Evidence evaluated in the future.
	r = mustResponse(t)
	future := r.Attachments[0]
	future.EvaluatedAtMS = projNowMS + 1000
	r.Attachments[0] = future
	if err := ValidateResponse(r, projNowMS); err == nil {
		t.Error("future-evaluated evidence must fail")
	}
	// Run/tenant mismatch with the query scope is a serve-time rejection:
	// the cursor binds run+tenant and the ledger enforces it.
	r = mustResponse(t)
	cursor, err := GetRunRequest{RunID: "run-1", TenantID: "tenant-a"}.ScopedCursor()
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if err := cursor.ValidateScope(r.Run.RunID, "tenant-b"); err == nil {
		t.Error("cross-tenant cursor scope must fail")
	}
	if err := cursor.ValidateScope("run-other", "tenant-a"); err == nil {
		t.Error("cross-run cursor scope must fail")
	}
}

func TestUnknownEnumsFailClosedInSnapshot(t *testing.T) {
	mutations := []func(*GetRunResponse){
		func(r *GetRunResponse) { r.Run.State = "bogus" },
		func(r *GetRunResponse) { r.Participants[0].Status = "bogus" },
		func(r *GetRunResponse) { r.Participants[0].Role = "bogus" },
		func(r *GetRunResponse) { r.Participants[0].AgentKind = "bogus" },
		func(r *GetRunResponse) { r.Tasks[0].State = "bogus" },
		func(r *GetRunResponse) { r.Provenance[0].RuntimeKind = "bogus" },
		func(r *GetRunResponse) { r.Attachments[0].Lifecycle = "bogus" },
		func(r *GetRunResponse) { r.Attachments[0].Reason = "bogus" },
	}
	for i, mutate := range mutations {
		r := mustResponse(t)
		mutate(&r)
		if err := ValidateResponse(r, projNowMS); err == nil {
			t.Errorf("mutation %d with unknown enum must fail closed", i)
		}
	}
}

func TestPartnerViewRedactsInternals(t *testing.T) {
	r := mustResponse(t)
	// Add partner-audience evidence plus tenant evidence that must not cross.
	partnerEv, err := attachment.EvaluateEvidence(
		testAttRef("att-9", attachment.AudiencePartner),
		attachment.LifecycleReturned, attachment.AudiencePartner, projNowMS)
	if err != nil {
		t.Fatalf("partner evidence: %v", err)
	}
	r.Attachments = append(r.Attachments, partnerEv)
	SortResponse(&r)
	counts, err := ComputeCounts(r.Participants, r.Tasks, r.Provenance, r.Attachments, 7)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	r.Counts = counts
	if err := ValidateResponse(r, projNowMS); err != nil {
		t.Fatalf("snapshot with partner evidence: %v", err)
	}
	view, err := ProjectRunForPartner(r, projNowMS)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	for _, leaked := range []string{
		"s-1", "s-2", "w-1", "c-1", "prov-1", "prov-2",
		"tenant-a", "p-pm", "p-b1", "t-1", "att-1",
		`"session_id":`, `"workload_id":`, `"container_id":`,
		`"participants":`, `"tasks":`, `"provenance":`, `"tenant_id":`,
	} {
		if strings.Contains(s, leaked) {
			t.Errorf("partner view leaks %q: %s", leaked, s)
		}
	}
	if len(view.Attachments) != 1 || view.Attachments[0].Ref.AttachmentID != "att-9" {
		t.Errorf("partner view must carry only downloadable partner evidence: %+v", view.Attachments)
	}
	if view.Counts.AttachmentsTotal != 1 || view.Counts.AttachmentsDownloadable != 1 {
		t.Errorf("partner counts must cover served evidence only: %+v", view.Counts)
	}
	if view.RunID != "run-1" || view.State != RunRunning {
		t.Errorf("partner view identity/state: %+v", view)
	}
}

func TestPartnerViewDropsQuarantined(t *testing.T) {
	r := mustResponse(t)
	bad := testAttRef("att-q", attachment.AudiencePartner)
	bad.ScanState = attachment.ScanQuarantined
	qev, err := attachment.EvaluateEvidence(bad, attachment.LifecycleVerified, attachment.AudiencePartner, projNowMS)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	r.Attachments = append(r.Attachments, qev)
	SortResponse(&r)
	counts, err := ComputeCounts(r.Participants, r.Tasks, r.Provenance, r.Attachments, 7)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	r.Counts = counts
	if err := ValidateResponse(r, projNowMS); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	view, err := ProjectRunForPartner(r, projNowMS)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if len(view.Attachments) != 0 {
		t.Errorf("quarantined partner evidence must be dropped, got %+v", view.Attachments)
	}
}

func TestSnapshotPrivacySweep(t *testing.T) {
	r := mustResponse(t)
	raw, err := CanonicalResponseBytes(r)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, banned := range []string{
		"capability", "token", "secret", "https://", "http://",
		"prompt", "reasoning", "tool_arg", "topology",
		"begin private", "private_key", "169.254", "10.0.0.",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("snapshot carries %q: %s", banned, raw)
		}
	}
}

func TestMigrationTargetContract(t *testing.T) {
	if PostgresMigrationTarget != 60 {
		t.Errorf("target = %d, want 60", PostgresMigrationTarget)
	}
	for _, n := range []int{58, 59, 60} {
		if !ValidMigrationTarget(n) {
			t.Errorf("migration %d must be served", n)
		}
		if _, err := DescribeMigration(n); err != nil {
			t.Errorf("describe %d: %v", n, err)
		}
	}
	for _, n := range []int{0, 57, 61, -1} {
		if ValidMigrationTarget(n) {
			t.Errorf("migration %d must not validate", n)
		}
		if _, err := DescribeMigration(n); err == nil {
			t.Errorf("describe %d must fail closed", n)
		}
	}
}

func TestGoldenCanonicalSnapshot(t *testing.T) {
	r := mustResponse(t)
	raw, err := CanonicalResponseBytes(r)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	const want = "f006ab2f532277cbc697a4d84f8491b8aa8fc77252fad823e139bc8b3988e6c1"
	if got != want {
		t.Errorf("canonical snapshot drifted:\n got %s\nwant %s", got, want)
	}
}
