package orchestration

import (
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/provenance"
)

func testContext() ControlContext {
	return ControlContext{
		TenantID:    "tenant-a",
		ActorID:     "ctx-agent-1",
		SessionID:   "s-9",
		WorkloadID:  "w-9",
		ContainerID: "c-9",
	}
}

func testSlot(role, kind string) ParticipantSlotProposal {
	return ParticipantSlotProposal{Role: role, AgentKind: kind}
}

func testSlots() []ParticipantSlotProposal {
	return []ParticipantSlotProposal{
		testSlot(RolePM, AgentKindMuse),
		{Role: RoleBuilder, AgentKind: AgentKindCodex, AssignedTaskID: "t-1"},
		testSlot(RoleBuilder, AgentKindGrok),
		testSlot(RoleReviewer, AgentKindAntigravity),
	}
}

func testProvenanceClaims() provenance.RuntimeProvenance {
	d := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return provenance.RuntimeProvenance{
		SchemaVersion:      provenance.SchemaRuntimeProvenanceV1,
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
		RuntimeKind:        provenance.RuntimeGCPCloudRun,
		Cloud:              provenance.CloudGCP,
		NonRoot:            true,
		NoNewPrivileges:    true,
		ImageVerified:      true,
	}
}

func TestSlotRosterShape(t *testing.T) {
	if err := ValidateSlotRoster(testSlots()); err != nil {
		t.Errorf("valid slots: %v", err)
	}
	if err := ValidateSlotProposal(testSlot("bogus", AgentKindMuse)); err == nil {
		t.Error("unknown role must fail")
	}
	if err := ValidateSlotProposal(testSlot(RolePM, "bogus")); err == nil {
		t.Error("unknown agent kind must fail")
	}
	if err := ValidateSlotRoster(nil); err == nil {
		t.Error("empty proposal must fail")
	}
	twoPM := testSlots()
	twoPM = append(twoPM, testSlot(RolePM, AgentKindCodex))
	if err := ValidateSlotRoster(twoPM); err == nil {
		t.Error("two PMs must fail")
	}
	sameKind := testSlots()
	sameKind[3] = testSlot(RoleReviewer, AgentKindMuse)
	if err := ValidateSlotRoster(sameKind); err == nil {
		t.Error("same-kind reviewer must fail")
	}
}

func TestStartRunRequestStrictness(t *testing.T) {
	raw := []byte(`{"command_id":"cmd-9","idempotency_key":"start-9","tenant_id":"tenant-a",` +
		`"slots":[{"role":"pm","agent_kind":"muse"},{"role":"builder","agent_kind":"codex"},` +
		`{"role":"builder","agent_kind":"grok"},{"role":"reviewer","agent_kind":"antigravity"}],` +
		`"requested_at_ms":1000}`)
	req, err := DecodeStartRunRequestStrict(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := ValidateStartRunRequest(req); err != nil {
		t.Errorf("valid start request: %v", err)
	}
	// A browser smuggling session identity into a slot fails at decode:
	// those fields do not exist on the typed shape.
	smuggled := []byte(`{"command_id":"cmd-9","idempotency_key":"start-9","tenant_id":"tenant-a",` +
		`"slots":[{"role":"pm","agent_kind":"muse","session_id":"s-evil","workload_id":"w-evil",` +
		`"container_id":"c-evil","runtime_provenance_id":"prov-evil","status":"active"}],` +
		`"requested_at_ms":1000}`)
	if _, err := DecodeStartRunRequestStrict(smuggled); err == nil {
		t.Error("slot identity smuggling must be rejected as unknown fields")
	}
	// Actor identity smuggling fails the same way: there is no actor
	// field on the typed request.
	withActor := []byte(`{"command_id":"cmd-9","idempotency_key":"start-9","tenant_id":"tenant-a",` +
		`"actor_id":"root","slots":[],"requested_at_ms":1000}`)
	if _, err := DecodeStartRunRequestStrict(withActor); err == nil {
		t.Error("actor assertion must be rejected as unknown field")
	}
	badKey := req
	badKey.IdempotencyKey = ""
	if err := ValidateStartRunRequest(badKey); err == nil {
		t.Error("start without idempotency key must fail")
	}
}

func TestControlContextScoping(t *testing.T) {
	ctx := testContext()
	if err := ctx.Validate(); err != nil {
		t.Errorf("valid context: %v", err)
	}
	if err := ctx.ScopeRun("tenant-a"); err != nil {
		t.Errorf("same-tenant scope: %v", err)
	}
	if err := ctx.ScopeRun("tenant-b"); err == nil {
		t.Error("cross-tenant scope must fail closed")
	}
	anon := ControlContext{TenantID: "tenant-a"}
	if err := anon.Validate(); err == nil {
		t.Error("anonymous context must fail")
	}
	partial := ctx
	partial.ContainerID = ""
	if err := partial.Validate(); err == nil {
		t.Error("partially bound context must fail")
	}
}

func TestBindFlowStampsContextIdentity(t *testing.T) {
	ctx := testContext()
	slot := testSlot(RoleBuilder, AgentKindCodex)
	invited, err := AssembleInvitedParticipant(slot, "p-new")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if invited.Status != ParticipantInvited {
		t.Errorf("slot status = %q, want invited", invited.Status)
	}
	if invited.SessionID != "" || invited.RuntimeProvenanceID != "" {
		t.Error("invited slot must carry no identity")
	}
	if err := ValidateParticipants([]AgentParticipant{
		{ParticipantID: "p-pm", Role: RolePM, AgentKind: AgentKindMuse, Status: ParticipantInvited},
		invited,
		{ParticipantID: "p-b2", Role: RoleBuilder, AgentKind: AgentKindGrok, Status: ParticipantInvited},
		{ParticipantID: "p-rev", Role: RoleReviewer, AgentKind: AgentKindAntigravity, Status: ParticipantInvited},
	}); err != nil {
		t.Errorf("all-invited roster: %v", err)
	}
	bound, err := BindParticipant(ctx, "tenant-a", invited, "prov-9")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if bound.Status != ParticipantActive {
		t.Errorf("bound status = %q, want active", bound.Status)
	}
	if bound.SessionID != "s-9" || bound.WorkloadID != "w-9" ||
		bound.ContainerID != "c-9" || bound.RuntimeProvenanceID != "prov-9" {
		t.Errorf("binding not stamped from context: %+v", bound)
	}
	// Re-binding a bound participant fails: no double activation.
	if _, err := BindParticipant(ctx, "tenant-a", bound, "prov-9"); err == nil {
		t.Error("re-bind of active participant must fail")
	}
	// Cross-tenant bind fails.
	if _, err := BindParticipant(ctx, "tenant-b", invited, "prov-9"); err == nil {
		t.Error("cross-tenant bind must fail")
	}
	// Bind with no provenance fails.
	if _, err := BindParticipant(ctx, "tenant-a", invited, ""); err == nil {
		t.Error("bind without provenance must fail")
	}
}

func TestStatusUpdateLifecycle(t *testing.T) {
	ctx := testContext()
	bound := AgentParticipant{
		ParticipantID: "p-b1", Role: RoleBuilder, AgentKind: AgentKindCodex,
		SessionID: "s-2", WorkloadID: "w-2", ContainerID: "c-2",
		RuntimeProvenanceID: "prov-2", Status: ParticipantActive,
	}
	suspended, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", bound, ParticipantSuspended)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	resumed, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", suspended, ParticipantActive)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Status != ParticipantActive {
		t.Errorf("resumed status = %q", resumed.Status)
	}
	departed, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", resumed, ParticipantDeparted)
	if err != nil {
		t.Fatalf("depart: %v", err)
	}
	if _, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", departed, ParticipantActive); err == nil {
		t.Error("move out of terminal departed must fail")
	}
	if _, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", bound, "bogus"); err == nil {
		t.Error("unknown to-status must fail")
	}
	if _, err := ApplyParticipantStatusUpdate(ctx, "tenant-b", bound, ParticipantSuspended); err == nil {
		t.Error("cross-tenant update must fail")
	}
	// Invited slots cannot be activated by status update: only
	// BindParticipant stamps identity.
	invited := AgentParticipant{
		ParticipantID: "p-new", Role: RoleBuilder, AgentKind: AgentKindCodex,
		Status: ParticipantInvited,
	}
	if _, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", invited, ParticipantActive); err == nil {
		t.Error("invited->active without binding must fail; use BindParticipant")
	}
	// Invited slots CAN be removed administratively.
	if _, err := ApplyParticipantStatusUpdate(ctx, "tenant-a", invited, ParticipantRemoved); err != nil {
		t.Errorf("invited->removed: %v", err)
	}
}

func TestProvenanceRegistrationForbidsCallerIDs(t *testing.T) {
	ctx := testContext()
	claims := testProvenanceClaims()
	doc, err := PrepareProvenanceRegistration(ctx, RegisterProvenanceRequest{Provenance: claims}, "prov-9")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if doc.ProvenanceID != "prov-9" {
		t.Errorf("provenance id = %q, want the server-assigned id", doc.ProvenanceID)
	}
	// A caller-asserted provenance id is forgery, exactly like a
	// caller-asserted event sequence.
	forged := claims
	forged.ProvenanceID = "prov-evil"
	if _, err := PrepareProvenanceRegistration(ctx,
		RegisterProvenanceRequest{Provenance: forged}, "prov-9"); err == nil {
		t.Error("caller-asserted provenance id must fail as forgery")
	}
	// Bad claims fail even with a server id.
	bad := claims
	bad.RuntimeKind = "ec2"
	if _, err := PrepareProvenanceRegistration(ctx,
		RegisterProvenanceRequest{Provenance: bad}, "prov-9"); err == nil {
		t.Error("VM runtime kind must fail")
	}
	// Anonymous context registers nothing.
	if _, err := PrepareProvenanceRegistration(ControlContext{},
		RegisterProvenanceRequest{Provenance: claims}, "prov-9"); err == nil {
		t.Error("anonymous registration must fail")
	}
}

func TestGetProvenanceScope(t *testing.T) {
	good := GetProvenanceRequest{RunID: "run-1", TenantID: "tenant-a", ProvenanceID: "prov-1"}
	if err := ValidateGetProvenanceRequest(good); err != nil {
		t.Errorf("valid lookup: %v", err)
	}
	raw := []byte(`{"run_id":"run-1","tenant_id":"tenant-a","provenance_id":"prov-1","session_id":"s-evil"}`)
	if _, err := DecodeGetProvenanceRequestStrict(raw); err == nil {
		t.Error("lookup with identity assertion must be rejected")
	}
	bad := good
	bad.ProvenanceID = ""
	if err := ValidateGetProvenanceRequest(bad); err == nil {
		t.Error("unscoped lookup must fail")
	}
}

func TestControlOpVocabularyClosed(t *testing.T) {
	for _, op := range []string{
		ControlOpRegisterProvenance, ControlOpBindParticipant,
		ControlOpUpdateParticipant, ControlOpGetProvenance,
	} {
		if !ValidControlOp(op) {
			t.Errorf("control op %q must be valid", op)
		}
		if ValidBFFCommand(op) {
			t.Errorf("control op %q must never be a browser BFF command", op)
		}
	}
	if ValidControlOp("start_run") || ValidControlOp("bogus") {
		t.Error("BFF names and unknown ops are not control ops")
	}
}

func TestLegacyBFFEnvelopeStillValid(t *testing.T) {
	// Additive compatibility: the revision-9 envelope intake keeps
	// validating (CancelRun still takes it); typed StartRunRequest is an
	// addition, not a removal.
	env := CommandEnvelope{
		SchemaVersion: SchemaBFFCommandV1, CommandID: "cmd-1",
		IdempotencyKey: "cancel-1", Command: BFFCancelRun,
		RunID: "run-1", TenantID: "tenant-a", RequestedAtMS: 1000,
	}
	if err := ValidateCommandEnvelope(env); err != nil {
		t.Errorf("legacy cancel envelope: %v", err)
	}
}
