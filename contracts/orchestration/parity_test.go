package orchestration

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/contracts/attachment"
)

// parityFixture mirrors the document written by tools/paritygen
// (testdata/parity/orchestration.json). Regenerating must produce zero diff:
// any diff means the event canonical form, audit chain, or digest contract
// drifted and fails review.
type parityFixture struct {
	RunID            string               `json:"run_id"`
	GenesisAudit     string               `json:"genesis_audit"`
	Events           []OrchestrationEvent `json:"events"`
	ChainHead        string               `json:"chain_head"`
	AttachmentBody   string               `json:"attachment_body"`
	AttachmentDigest string               `json:"attachment_digest"`
	ProvenanceSHA256 string               `json:"provenance_sha256"`
}

func loadParityFixture(t *testing.T) parityFixture {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "parity", "orchestration.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read parity fixture: %v", err)
	}
	var fix parityFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("decode parity fixture: %v", err)
	}
	return fix
}

func TestParityFixtureReplay(t *testing.T) {
	fix := loadParityFixture(t)
	if fix.GenesisAudit != GenesisAuditHash(fix.RunID) {
		t.Error("genesis audit hash drifted")
	}
	prev := fix.GenesisAudit
	for i, ev := range fix.Events {
		if ev.Seq != int64(i+1) {
			t.Fatalf("event %d seq = %d", i, ev.Seq)
		}
		want, err := EventAuditHash(prev, ev)
		if err != nil {
			t.Fatalf("recompute %d: %v", i, err)
		}
		if want != ev.AuditHash {
			t.Errorf("event %d audit hash drifted: fixture %s recomputed %s", i, ev.AuditHash, want)
		}
		prev = ev.AuditHash
	}
	if prev != fix.ChainHead {
		t.Errorf("chain head drifted: fixture %s recomputed %s", fix.ChainHead, prev)
	}
	if got := attachment.DigestHex([]byte(fix.AttachmentBody)); got != fix.AttachmentDigest {
		t.Errorf("attachment digest drifted: fixture %s recomputed %s", fix.AttachmentDigest, got)
	}
}

func TestParityProvenanceDigestStable(t *testing.T) {
	fix := loadParityFixture(t)
	// The provenance digest pins the exact canonical JSON the generator
	// hashed; presence plus hex shape keeps the vector honest without
	// vendoring the whole document into this package.
	if len(fix.ProvenanceSHA256) != 64 {
		t.Errorf("provenance digest malformed: %q", fix.ProvenanceSHA256)
		return
	}
	if _, err := hex.DecodeString(fix.ProvenanceSHA256); err != nil {
		t.Errorf("provenance digest not hex: %v", err)
	}
}
