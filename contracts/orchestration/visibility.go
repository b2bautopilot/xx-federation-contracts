package orchestration

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Summary bounds. Observation summaries are explicit plan/status text only —
// never model chain-of-thought or raw reasoning — and every bound is
// enforced fail-closed at intake.
const (
	// MaxEventSummaryRunes bounds one observation event summary.
	MaxEventSummaryRunes = 500
	// MaxTaskSummaryRunes bounds one task public summary.
	MaxTaskSummaryRunes = 2000
	// MaxWatchLimit bounds one resumable observation read.
	MaxWatchLimit = 200
)

// resultKinds must carry a non-empty summary: a result-bearing event with
// nothing to show is not evidence and must not project as success.
var resultKinds = map[string]bool{
	EventPlanPublication: true,
	EventDecision:        true,
	EventReview:          true,
	EventSynthesis:       true,
	EventCompletion:      true,
	EventFailure:         true,
}

// SanitizeText treats workload text as untrusted: it trims surrounding
// whitespace, drops non-printable runes (keeping tab and newline), and
// truncates to maxRunes. It reports whether truncation occurred; over-long
// input is shortened, never rejected, so one verbose workload cannot break
// the stream while the bound always holds.
func SanitizeText(text string, maxRunes int) (string, bool) {
	var b strings.Builder
	runes := 0
	truncated := false
	for _, r := range strings.TrimSpace(text) {
		if r != '\t' && r != '\n' && !unicode.IsPrint(r) {
			continue
		}
		if runes >= maxRunes {
			truncated = true
			continue
		}
		b.WriteRune(r)
		runes++
	}
	return b.String(), truncated
}

// ValidateEventSummary enforces the event summary contract: within bound,
// valid UTF-8, sanitized (no smuggled control bytes), and non-empty for
// result-bearing kinds.
func ValidateEventSummary(kind, summary string) error {
	if !utf8.ValidString(summary) {
		return fmt.Errorf("%w: summary is not valid UTF-8", ErrUnknownField)
	}
	clean, _ := SanitizeText(summary, MaxEventSummaryRunes)
	if clean != strings.TrimSpace(summary) && summary != "" {
		// The summary carries control bytes or exceeds the bound in a way
		// sanitization would silently rewrite: reject so the workload
		// resubmits explicit text instead of the server paraphrasing it.
		if utf8.RuneCountInString(summary) > MaxEventSummaryRunes {
			return fmt.Errorf("%w: summary exceeds %d runes", ErrUnknownField, MaxEventSummaryRunes)
		}
		return fmt.Errorf("%w: summary carries unsanitized bytes", ErrUnknownField)
	}
	if resultKinds[kind] && strings.TrimSpace(summary) == "" {
		return fmt.Errorf("%w: kind %q requires a non-empty summary", ErrUnknownField, kind)
	}
	return nil
}

// ValidateTaskSummary enforces the task public-summary bound. Surrounding
// whitespace (including a trailing newline) is tolerated: the comparison
// runs against the trimmed text, while genuinely altered or unsafe content
// (dropped control bytes, truncation) still fails closed.
func ValidateTaskSummary(summary string) error {
	if !utf8.ValidString(summary) {
		return fmt.Errorf("%w: task summary is not valid UTF-8", ErrUnknownField)
	}
	if utf8.RuneCountInString(summary) > MaxTaskSummaryRunes {
		return fmt.Errorf("%w: task summary exceeds %d runes", ErrUnknownField, MaxTaskSummaryRunes)
	}
	if _, truncated := SanitizeText(summary, MaxTaskSummaryRunes); truncated {
		return fmt.Errorf("%w: task summary exceeds bound", ErrUnknownField)
	}
	clean, _ := SanitizeText(summary, MaxTaskSummaryRunes)
	if clean != strings.TrimSpace(summary) {
		return fmt.Errorf("%w: task summary carries unsanitized bytes", ErrUnknownField)
	}
	return nil
}

// PartnerEvent is the ONLY shape a partner viewer may receive: an explicit
// allowlist of event fields. Session, workload, container, provenance,
// causation internals, and tenant handles never cross this boundary;
// internal coordination stays tenant-local by default.
type PartnerEvent struct {
	SchemaVersion string   `json:"schema_version"`
	EventID       string   `json:"event_id"`
	Seq           int64    `json:"seq"`
	RunID         string   `json:"run_id"`
	Kind          string   `json:"kind"`
	ActorRole     string   `json:"actor_role"`
	Summary       string   `json:"summary,omitempty"`
	Attachments   []string `json:"attachments,omitempty"`
	TimestampMS   int64    `json:"timestamp_ms"`
	AuditHash     string   `json:"audit_hash"`
}

// ProjectForPartner renders one stamped event into its partner-safe shape.
// It fails closed unless the server assigned partner visibility and the
// caller supplies the actor's role from the authenticated roster (never
// from workload-asserted fields).
func ProjectForPartner(ev OrchestrationEvent, actorRole string) (PartnerEvent, error) {
	if ev.Visibility != VisibilityPartner {
		return PartnerEvent{}, fmt.Errorf("%w: event %q is %s, not partner-visible",
			ErrUnknownVisibility, ev.EventID, ev.Visibility)
	}
	if !ValidRole(actorRole) {
		return PartnerEvent{}, fmt.Errorf("%w: %q", ErrUnknownRole, actorRole)
	}
	if err := ValidateEventSummary(ev.Kind, ev.Summary); err != nil {
		return PartnerEvent{}, err
	}
	return PartnerEvent{
		SchemaVersion: SchemaOrchestrationEventV1,
		EventID:       ev.EventID,
		Seq:           ev.Seq,
		RunID:         ev.RunID,
		Kind:          ev.Kind,
		ActorRole:     actorRole,
		Summary:       ev.Summary,
		Attachments:   append([]string(nil), ev.Attachments...),
		TimestampMS:   ev.TimestampMS,
		AuditHash:     ev.AuditHash,
	}, nil
}
