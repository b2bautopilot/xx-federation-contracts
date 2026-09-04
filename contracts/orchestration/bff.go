package orchestration

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// BFF command/query names. Browser mutations flow only through these
// envelopes to xx-builders-net; the control plane executes them against the
// authenticated context and returns a signed audit receipt.
const (
	BFFStartRun    = "start_run"
	BFFCancelRun   = "cancel_run"
	BFFGetRun      = "get_run"
	BFFWatchEvents = "watch_events"
)

// MaxIdempotencyKeyLen bounds the client idempotency key. Replaying a start
// with the same key MUST NOT create a second run or container set; the
// control plane returns the original receipt.
const MaxIdempotencyKeyLen = 128

var (
	ErrUnknownCommand  = errors.New("orchestration bff command unknown")
	ErrBadIdempotency  = errors.New("orchestration idempotency key invalid")
	ErrActorMismatch   = errors.New("orchestration actor outside authenticated context")
	ErrBadAuditSeal    = errors.New("orchestration audit signature invalid")
	ErrUnknownAuditKey = errors.New("orchestration audit signer not trusted")
)

// ValidBFFCommand reports whether name is a declared BFF command or query.
func ValidBFFCommand(name string) bool {
	switch name {
	case BFFStartRun, BFFCancelRun, BFFGetRun, BFFWatchEvents:
		return true
	default:
		return false
	}
}

// ValidateIdempotencyKey enforces the idempotency-key shape: non-empty,
// bounded, and limited to a safe alphabet so keys are log-safe.
func ValidateIdempotencyKey(key string) error {
	if key == "" || len(key) > MaxIdempotencyKeyLen {
		return fmt.Errorf("%w: length %d", ErrBadIdempotency, len(key))
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("%w: unsafe alphabet", ErrBadIdempotency)
		}
	}
	return nil
}

// CommandEnvelope is the single BFF intake shape for commands and queries.
// ActorID is advisory display only: browser actor identity can never be
// asserted by request fields. The authenticated control context decides the
// actor (ResolveActor) and signs the audit receipt.
type CommandEnvelope struct {
	SchemaVersion  string `json:"schema_version"`
	CommandID      string `json:"command_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Command        string `json:"command"`
	RunID          string `json:"run_id,omitempty"`
	TenantID       string `json:"tenant_id"`
	ActorID        string `json:"actor_id,omitempty"`
	Payload        []byte `json:"payload,omitempty"`
	RequestedAtMS  int64  `json:"requested_at_ms"`
}

// ValidateCommandEnvelope checks the envelope shape fail-closed. Start
// commands require an idempotency key; every envelope requires a tenant.
func ValidateCommandEnvelope(env CommandEnvelope) error {
	if env.SchemaVersion != SchemaBFFCommandV1 {
		return fmt.Errorf("%w: schema %q", ErrUnknownCommand, env.SchemaVersion)
	}
	if !ValidBFFCommand(env.Command) {
		return fmt.Errorf("%w: %q", ErrUnknownCommand, env.Command)
	}
	if strings.TrimSpace(env.CommandID) == "" {
		return fmt.Errorf("%w: empty command id", ErrUnknownCommand)
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return fmt.Errorf("%w: empty tenant", ErrTenantMismatch)
	}
	if env.Command == BFFStartRun {
		if err := ValidateIdempotencyKey(env.IdempotencyKey); err != nil {
			return err
		}
	} else if env.IdempotencyKey != "" {
		if err := ValidateIdempotencyKey(env.IdempotencyKey); err != nil {
			return err
		}
	}
	return nil
}

// ResolveActor binds the request to the authenticated control context. The
// request-carried ActorID is ignored for authorization: the context tenant
// must equal the envelope tenant, and the context actor is authoritative.
// A forged or cross-tenant actor fails closed here, before any mutation.
func ResolveActor(ctxTenantID, ctxActorID string, env CommandEnvelope) (string, error) {
	if strings.TrimSpace(ctxTenantID) == "" || strings.TrimSpace(ctxActorID) == "" {
		return "", fmt.Errorf("%w: unauthenticated context", ErrActorMismatch)
	}
	if ctxTenantID != env.TenantID {
		return "", fmt.Errorf("%w: envelope tenant %q outside context %q",
			ErrTenantMismatch, env.TenantID, ctxTenantID)
	}
	return ctxActorID, nil
}

// WatchQuery is the resumable observation read: a cursor plus a bound. The
// server answers with the events, the next cursor, and explicit
// degraded/incomplete status — a partial backend outage is shown as
// degraded, never silently "connected".
type WatchQuery struct {
	RunID    string `json:"run_id"`
	TenantID string `json:"tenant_id"`
	AfterSeq int64  `json:"after_seq"`
	Limit    int    `json:"limit"`
}

// ToCursor scopes the watch read to this run and tenant.
func (q WatchQuery) ToCursor() (Cursor, error) {
	if strings.TrimSpace(q.RunID) == "" || strings.TrimSpace(q.TenantID) == "" {
		return Cursor{}, fmt.Errorf("%w: watch scope must name run and tenant", ErrReplayOutsideScope)
	}
	c := Cursor{RunID: q.RunID, TenantID: q.TenantID, AfterSeq: q.AfterSeq}
	if err := c.ValidateScope(q.RunID, q.TenantID); err != nil {
		return Cursor{}, err
	}
	return c, nil
}

// CommandReceipt is the signed control response to a BFF envelope.
// Degraded reports a partial backend outage behind an otherwise served
// reply; Incomplete reports the projection is missing events the caller
// must still fetch. Both default false and MUST be surfaced, never
// defaulted away by the portal.
type CommandReceipt struct {
	SchemaVersion string `json:"schema_version"`
	CommandID     string `json:"command_id"`
	RunID         string `json:"run_id,omitempty"`
	Accepted      bool   `json:"accepted"`
	Degraded      bool   `json:"degraded"`
	Incomplete    bool   `json:"incomplete"`
	Status        string `json:"status"`
	NextAfterSeq  int64  `json:"next_after_seq,omitempty"`
	AuditKeyID    string `json:"audit_key_id"`
	Signature     []byte `json:"signature,omitempty"`
}

// canonicalReceiptBytes is the deterministic signing input: the receipt sans
// signature, as JSON (struct declaration order marshals byte-identically for
// signer and verifier — the membershipcap idiom).
func canonicalReceiptBytes(r CommandReceipt) ([]byte, error) {
	r.Signature = nil
	return json.Marshal(r)
}

// SignReceipt seals a control audit receipt with the control audit key.
func SignReceipt(keyID string, priv ed25519.PrivateKey, r CommandReceipt) (CommandReceipt, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return CommandReceipt{}, ErrBadAuditSeal
	}
	if strings.TrimSpace(r.CommandID) == "" {
		return CommandReceipt{}, fmt.Errorf("%w: empty command id", ErrUnknownCommand)
	}
	r.SchemaVersion = SchemaBFFCommandV1
	r.AuditKeyID = keyID
	r.Signature = nil
	raw, err := canonicalReceiptBytes(r)
	if err != nil {
		return CommandReceipt{}, err
	}
	r.Signature = ed25519.Sign(priv, raw)
	return r, nil
}

// VerifyReceipt checks the audit seal against the trusted control keyring.
// Unknown signers and bad signatures fail closed; an empty keyring denies
// all rather than skipping the check.
func (r CommandReceipt) Verify(trusted map[string]ed25519.PublicKey) error {
	if len(trusted) == 0 {
		return fmt.Errorf("%w: empty keyring", ErrUnknownAuditKey)
	}
	pub, ok := trusted[r.AuditKeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrUnknownAuditKey, r.AuditKeyID)
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return ErrBadAuditSeal
	}
	raw, err := canonicalReceiptBytes(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, raw, r.Signature) {
		return ErrBadAuditSeal
	}
	return nil
}
