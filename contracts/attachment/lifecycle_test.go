package attachment

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLifecycleTransitionsHappyPath(t *testing.T) {
	for _, tc := range [][2]string{
		{LifecycleOffered, LifecycleAuthorized},
		{LifecycleAuthorized, LifecycleFetched},
		{LifecycleFetched, LifecycleVerified},
		{LifecycleVerified, LifecycleReturned},
		{LifecycleProduced, LifecycleVerified},
		{LifecycleOffered, LifecycleRejected},
		{LifecycleVerified, LifecycleRejected},
		{LifecycleProduced, LifecycleExpired},
		{LifecycleReturned, LifecycleExpired},
	} {
		if !AllowedLifecycleTransition(tc[0], tc[1]) {
			t.Errorf("AllowedLifecycleTransition(%q,%q) = false, want true", tc[0], tc[1])
		}
	}
}

func TestLifecycleIllegalTransitionsFailClosed(t *testing.T) {
	for _, tc := range [][2]string{
		{LifecycleOffered, LifecycleFetched},   // skip authorization
		{LifecycleOffered, LifecycleVerified},  // skip fetch
		{LifecycleOffered, LifecycleReturned},  // skip everything
		{LifecycleProduced, LifecycleReturned}, // skip verification
		{LifecycleReturned, LifecycleVerified}, // rewind
		{LifecycleExpired, LifecycleOffered},   // out of terminal
		{LifecycleRejected, LifecycleExpired},  // terminal to terminal
		{LifecycleVerified, LifecycleOffered},  // rewind
		{"bogus", LifecycleOffered},            // unknown from
		{LifecycleOffered, "bogus"},            // unknown to
		{"", ""},                               // empty
	} {
		if AllowedLifecycleTransition(tc[0], tc[1]) {
			t.Errorf("AllowedLifecycleTransition(%q,%q) = true, want false", tc[0], tc[1])
		}
	}
	if IsTerminalLifecycle(LifecycleVerified) || IsTerminalLifecycle("bogus") {
		t.Error("only expired/rejected are terminal")
	}
	if !IsTerminalLifecycle(LifecycleExpired) || !IsTerminalLifecycle(LifecycleRejected) {
		t.Error("expired/rejected must be terminal")
	}
}

func TestEvaluateEvidenceDecisionMatrix(t *testing.T) {
	now := int64(5000)
	cases := []struct {
		name      string
		mutate    func(*AttachmentRef)
		lifecycle string
		viewer    string
		reason    string
		download  bool
	}{
		{"verified clean tenant served to tenant", func(r *AttachmentRef) {}, LifecycleVerified, AudienceTenant, DownloadAvailable, true},
		{"returned clean tenant served to tenant", func(r *AttachmentRef) {}, LifecycleReturned, AudienceTenant, DownloadAvailable, true},
		{"offered is never downloadable", func(r *AttachmentRef) {}, LifecycleOffered, AudienceTenant, DownloadNotVerified, false},
		{"authorized is never downloadable", func(r *AttachmentRef) {}, LifecycleAuthorized, AudienceTenant, DownloadNotVerified, false},
		{"fetched is never downloadable", func(r *AttachmentRef) {}, LifecycleFetched, AudienceTenant, DownloadNotVerified, false},
		{"produced is never downloadable", func(r *AttachmentRef) {}, LifecycleProduced, AudienceTenant, DownloadNotVerified, false},
		{"pending scan gates", func(r *AttachmentRef) { r.ScanState = ScanPending }, LifecycleVerified, AudienceTenant, DownloadScanPending, false},
		{"quarantined never serves", func(r *AttachmentRef) { r.ScanState = ScanQuarantined }, LifecycleVerified, AudienceTenant, DownloadNotClean, false},
		{"blocked never serves", func(r *AttachmentRef) { r.ScanState = ScanBlocked }, LifecycleVerified, AudienceTenant, DownloadNotClean, false},
		{"rejected lifecycle dominates clean scan", func(r *AttachmentRef) {}, LifecycleRejected, AudienceTenant, DownloadNotClean, false},
		{"expired lifecycle dominates clean scan", func(r *AttachmentRef) {}, LifecycleExpired, AudienceTenant, DownloadExpired, false},
		{"tenant descriptor hidden from partner", func(r *AttachmentRef) {}, LifecycleReturned, AudiencePartner, DownloadNotVisible, false},
		{"partner descriptor served to partner", func(r *AttachmentRef) { r.Audience = AudiencePartner }, LifecycleReturned, AudiencePartner, DownloadAvailable, true},
	}
	for _, tc := range cases {
		ref := testRef()
		tc.mutate(&ref)
		ev, err := EvaluateEvidence(ref, tc.lifecycle, tc.viewer, now)
		if err != nil {
			t.Errorf("%s: evaluate: %v", tc.name, err)
			continue
		}
		if ev.Reason != tc.reason || ev.Downloadable != tc.download {
			t.Errorf("%s: reason=%q downloadable=%v, want %q/%v",
				tc.name, ev.Reason, ev.Downloadable, tc.reason, tc.download)
		}
		if ev.EvaluatedAtMS != now {
			t.Errorf("%s: evaluated_at_ms = %d, want server time %d", tc.name, ev.EvaluatedAtMS, now)
		}
		if err := ValidateEvidence(ev); err != nil {
			t.Errorf("%s: decided evidence must validate: %v", tc.name, err)
		}
	}
}

func TestEvaluateEvidenceExpiryDominates(t *testing.T) {
	ref := testRef() // expires at 9000
	if ev, err := EvaluateEvidence(ref, LifecycleVerified, AudienceTenant, 9000); err != nil {
		t.Fatalf("evaluate: %v", err)
	} else if ev.Reason != DownloadExpired || ev.Downloadable {
		t.Errorf("expiry boundary: %+v", ev)
	}
	if ev, err := EvaluateEvidence(ref, LifecycleVerified, AudienceTenant, 12000); err != nil {
		t.Fatalf("evaluate: %v", err)
	} else if ev.Reason != DownloadExpired || ev.Downloadable {
		t.Errorf("past expiry: %+v", ev)
	}
}

func TestEvaluateEvidenceUnknownInputsFailClosed(t *testing.T) {
	ref := testRef()
	for _, tc := range []struct {
		lifecycle string
		viewer    string
	}{
		{"bogus", AudienceTenant},
		{"", AudienceTenant},
		{LifecycleVerified, "bogus"},
		{LifecycleVerified, ""},
	} {
		if _, err := EvaluateEvidence(ref, tc.lifecycle, tc.viewer, 1000); err == nil {
			t.Errorf("EvaluateEvidence(%q,%q) must fail closed", tc.lifecycle, tc.viewer)
		}
	}
}

func TestEvidenceDecisionEquivalenceEnforced(t *testing.T) {
	ref := testRef()
	ev, err := EvaluateEvidence(ref, LifecycleVerified, AudienceTenant, 1000)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	// A server claiming downloadable with a blocking reason (or vice
	// versa) is fabrication: the equivalence is mechanical.
	evil := ev
	evil.Downloadable = false
	if err := ValidateEvidence(evil); err == nil {
		t.Error("downloadable=false with reason=available must fail")
	}
	evil = ev
	evil.Reason = DownloadScanPending
	if err := ValidateEvidence(evil); err == nil {
		t.Error("downloadable=true with blocking reason must fail")
	}
	evil = ev
	evil.EvaluatedAtMS = 0
	if err := ValidateEvidence(evil); err == nil {
		t.Error("unevaluated evidence must fail")
	}
	evil = ev
	evil.Reason = "bogus"
	if err := ValidateEvidence(evil); err == nil {
		t.Error("unknown reason must fail")
	}
	// Expired custody must report expired, never available.
	expired, err := EvaluateEvidence(ref, LifecycleExpired, AudienceTenant, 1000)
	if err != nil {
		t.Fatalf("evaluate expired: %v", err)
	}
	expired.Reason = DownloadAvailable
	expired.Downloadable = true
	if err := ValidateEvidence(expired); err == nil {
		t.Error("expired custody reporting available must fail")
	}
}

func TestEvidenceCarriesNoSecrets(t *testing.T) {
	ref := testRef()
	ev, err := EvaluateEvidence(ref, LifecycleReturned, AudienceTenant, 1000)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, banned := range []string{
		"capability", "token", "secret", "http://", "https://",
		"storage", "bucket", "path", "prompt", "reasoning",
		"tool_arg", "topology", "private_key",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("evidence leaks %q: %s", banned, raw)
		}
	}
}

func TestRejectVerdictAndPutStatusClosed(t *testing.T) {
	for _, v := range []string{RejectQuarantine, RejectBlock} {
		if !ValidRejectVerdict(v) {
			t.Errorf("verdict %q must be valid", v)
		}
	}
	for _, v := range []string{"", "bogus", "delete", "quarantine_and_block"} {
		if ValidRejectVerdict(v) {
			t.Errorf("verdict %q must fail closed", v)
		}
	}
	for _, s := range []string{PutStored, PutReplayed} {
		if !ValidPutStatus(s) {
			t.Errorf("put status %q must be valid", s)
		}
	}
	if ValidPutStatus("bogus") || ValidPutStatus("") {
		t.Error("unknown put status must fail closed")
	}
	for _, a := range []string{CapabilityPut, CapabilityFetch, CapabilityDownload} {
		if !ValidCapabilityAction(a) {
			t.Errorf("action %q must be valid", a)
		}
	}
	if ValidCapabilityAction("bogus") || ValidCapabilityAction("admin") {
		t.Error("unknown capability action must fail closed")
	}
	if err := ValidateReasonCode("policy:scan-failed.v2"); err != nil {
		t.Errorf("bounded reason code: %v", err)
	}
	if err := ValidateReasonCode("../../etc"); err == nil {
		t.Error("traversal reason code must fail")
	}
	if err := ValidateReasonCode(""); err == nil {
		t.Error("empty reason code must fail")
	}
}

func TestEvidenceStrictDecodeRejectsUnknown(t *testing.T) {
	ref := testRef()
	ev, err := EvaluateEvidence(ref, LifecycleVerified, AudienceTenant, 1000)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	raw, _ := json.Marshal(ev)
	withExtra := strings.Replace(string(raw), `"reason"`, `"safety_verdict":"safe","reason"`, 1)
	if _, err := DecodeEvidenceStrict([]byte(withExtra)); err == nil {
		t.Error("browser-supplied safety verdict must be rejected as unknown field")
	}
}
