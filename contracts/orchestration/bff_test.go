package orchestration

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testEnvelope() CommandEnvelope {
	return CommandEnvelope{
		SchemaVersion:  SchemaBFFCommandV1,
		CommandID:      "cmd-1",
		IdempotencyKey: "start-abc-123",
		Command:        BFFStartRun,
		TenantID:       "tenant-a",
		ActorID:        "browser-claimed-root",
		RequestedAtMS:  1000,
	}
}

func TestBFFEnvelopeShape(t *testing.T) {
	if err := ValidateCommandEnvelope(testEnvelope()); err != nil {
		t.Errorf("valid envelope: %v", err)
	}
	bad := testEnvelope()
	bad.Command = "drop_tables"
	if err := ValidateCommandEnvelope(bad); err == nil {
		t.Error("unknown command must fail closed")
	}
	noKey := testEnvelope()
	noKey.IdempotencyKey = ""
	if err := ValidateCommandEnvelope(noKey); err == nil {
		t.Error("start without idempotency key must fail closed")
	}
	evil := testEnvelope()
	evil.IdempotencyKey = "../../etc/passwd"
	if err := ValidateCommandEnvelope(evil); err == nil {
		t.Error("unsafe idempotency alphabet must fail closed")
	}
}

func TestActorComesFromContextNeverRequest(t *testing.T) {
	env := testEnvelope()
	actor, err := ResolveActor("tenant-a", "ctx-op-7", env)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if actor != "ctx-op-7" {
		t.Errorf("actor = %q, want the context identity, not the request claim", actor)
	}
	// Cross-tenant envelope fails closed even with a valid context.
	if _, err := ResolveActor("tenant-b", "ctx-op-7", env); err == nil {
		t.Error("cross-tenant envelope must fail closed")
	}
	// Unauthenticated context fails closed.
	if _, err := ResolveActor("", "", env); err == nil {
		t.Error("empty context must fail closed")
	}
}

func TestAuditReceiptSeal(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sealed, err := SignReceipt("audit-k1", priv, CommandReceipt{
		CommandID: "cmd-1", RunID: "run-1", Accepted: true, Status: "started",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sealed.Verify(map[string]ed25519.PublicKey{"audit-k1": pub}); err != nil {
		t.Errorf("verify: %v", err)
	}
	// Tampered status breaks the seal.
	sealed.Status = "started-evil"
	if err := sealed.Verify(map[string]ed25519.PublicKey{"audit-k1": pub}); err == nil {
		t.Error("tampered receipt must fail closed")
	}
	// Unknown signer fails closed.
	sealed.Status = "started"
	sealed.AuditKeyID = "unknown-key"
	if err := sealed.Verify(map[string]ed25519.PublicKey{"audit-k1": pub}); err == nil {
		t.Error("unknown audit signer must fail closed")
	}
	// Empty keyring denies all.
	if err := sealed.Verify(map[string]ed25519.PublicKey{}); err == nil {
		t.Error("empty audit keyring must deny all")
	}
}

func TestWatchCursorRoundTrip(t *testing.T) {
	l := mustLedger(t)
	for i, kind := range []string{EventPMStart, EventProgress} {
		if _, err := l.Append(clientEv(kind), "w-"+string(rune('1'+i)), 1001+int64(i), VisibilityTenant); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	q := WatchQuery{RunID: "run-1", TenantID: "tenant-a", Limit: 1}
	cursor, err := q.ToCursor()
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	page1, next, incomplete, err := l.Read(cursor, q.Limit)
	if err != nil || incomplete || len(page1) != 1 {
		t.Fatalf("page1 = %d incomplete=%v err=%v", len(page1), incomplete, err)
	}
	page2, next2, incomplete, err := l.Read(next, q.Limit)
	if err != nil || incomplete || len(page2) != 1 || next2.AfterSeq != 2 {
		t.Fatalf("page2 = %d next=%d incomplete=%v err=%v", len(page2), next2.AfterSeq, incomplete, err)
	}
	// Unscoped watch query fails closed.
	bad := WatchQuery{RunID: "", TenantID: "tenant-a", Limit: 1}
	if _, err := bad.ToCursor(); err == nil {
		t.Error("unscoped watch must fail closed")
	}
}
