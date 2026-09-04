// Control-plane migration target (issue #21, parent epic #18, spec
// revision 10).
//
// Authority: spec/b2b-federation-spec-v1.xml revision 10,
// comp.builders-control postgres-migrations-count. This file mirrors that
// declared target so the orchestration consistency gate can prove the XML
// authority and the Go enforcement agree; neither side is a second source.
//
// Drift correction, recorded honestly: revision 9 declared 57 while
// xx-builders-net main had already integrated migration 58
// (000058_orchestration_ledger) and held migration 59
// (000059_attachment_custody, xx-builders-net PR #23) as code-only. This
// revision corrects the target to 60 — 58 orchestration ledger, 59
// attachment custody, planned 60 durable runtime/observation projection —
// as a CODE-ONLY target. No live database was migrated by this contracts
// change; downstream retains migration 59 as code-only until separately
// authorized, and implements planned migration 60 in its own slice.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/orchestration
// Spec evidence: comp.builders-control.
package orchestration

import (
	"errors"
	"fmt"
)

// PostgresMigrationTarget is the authoritative control-plane migration
// target served by comp.builders-control. It must equal the spec's
// postgres-migrations-count; the consistency gate enforces the equality.
const PostgresMigrationTarget = 60

// Served downstream migration entities mapped by this target.
const (
	// Migration58OrchestrationLedger is integrated on xx-builders-net main.
	Migration58OrchestrationLedger = "000058_orchestration_ledger"
	// Migration59AttachmentCustody is held code-only in xx-builders-net
	// PR #23 until separately authorized live migration.
	Migration59AttachmentCustody = "000059_attachment_custody"
	// Migration60Projection is the planned durable runtime/observation
	// projection store. Its exact entity filename is unassigned: the
	// downstream implementing slice fixes it; this target only reserves
	// the version.
	Migration60Projection = "000060_runtime_observation_projection"
)

var ErrMigrationTarget = errors.New("orchestration migration target unknown")

// ValidMigrationTarget reports whether n is a served migration version:
// every version from 58 through the target inclusive. Versions below 58
// predate the orchestration ledger contract and are not described here;
// versions above the target are unsealed.
func ValidMigrationTarget(n int) bool {
	return n >= 58 && n <= PostgresMigrationTarget
}

// DescribeMigration maps one served version to its entity purpose for
// audit and drift evidence. Unknown versions fail closed.
func DescribeMigration(n int) (string, error) {
	switch n {
	case 58:
		return Migration58OrchestrationLedger + " (orchestration ledger, integrated)", nil
	case 59:
		return Migration59AttachmentCustody + " (attachment custody, code-only until authorized)", nil
	case 60:
		return Migration60Projection + " (durable runtime/observation projection, planned)", nil
	default:
		return "", fmt.Errorf("%w: migration %d", ErrMigrationTarget, n)
	}
}
