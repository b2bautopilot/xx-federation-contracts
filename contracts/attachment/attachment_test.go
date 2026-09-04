package attachment

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func testRef() AttachmentRef {
	return AttachmentRef{
		SchemaVersion: SchemaAttachmentRefV1,
		AttachmentID:  "att_01hzv3k7x4",
		SHA256Hex:     DigestHex([]byte("hello run input")),
		SizeBytes:     int64(len("hello run input")),
		MIME:          "text/plain; charset=utf-8",
		DisplayName:   "input-document.txt",
		Direction:     DirectionInput,
		ScanState:     ScanClean,
		Audience:      AudienceTenant,
		ExpiresAtMS:   9000,
	}
}

func TestRefHappyPath(t *testing.T) {
	ref := testRef()
	if err := ValidateRef(ref, 1000); err != nil {
		t.Errorf("valid ref: %v", err)
	}
	if err := ref.Fetchable(1000); err != nil {
		t.Errorf("fetchable: %v", err)
	}
}

func TestRefExpiryAndScanFailClosed(t *testing.T) {
	ref := testRef()
	if err := ValidateRef(ref, 9000); err == nil {
		t.Error("expired ref must fail closed")
	}
	noExp := testRef()
	noExp.ExpiresAtMS = 0
	if err := ValidateRef(noExp, 1000); err == nil {
		t.Error("missing expiry must fail closed")
	}
	pending := testRef()
	pending.ScanState = ScanPending
	if err := pending.Fetchable(1000); err == nil {
		t.Error("unscanned attachment must not be fetchable")
	}
	blocked := testRef()
	blocked.ScanState = ScanBlocked
	if err := blocked.Fetchable(1000); err == nil {
		t.Error("blocked attachment must not be fetchable")
	}
	if ValidScanState("infected-but-served") {
		t.Error("unknown scan state must not validate")
	}
}

func TestOversizeAndDigestMismatch(t *testing.T) {
	ref := testRef()
	huge := ref
	huge.SizeBytes = MaxAttachmentBytes + 1
	if err := ValidateRef(huge, 1000); err == nil {
		t.Error("oversize ref must fail closed")
	}
	body := []byte("hello run input")
	if err := VerifyBody(ref, body, "text/plain; charset=utf-8"); err != nil {
		t.Errorf("matching body: %v", err)
	}
	if err := VerifyBody(ref, []byte("tampered bytes!!"), "text/plain"); err == nil {
		t.Error("digest mismatch must fail closed")
	}
	short := ref
	short.SizeBytes = 3
	if err := VerifyBody(short, body, "text/plain"); err == nil {
		t.Error("size mismatch must fail closed")
	}
	if err := VerifyBody(ref, body, "application/pdf"); err == nil {
		t.Error("MIME confusion must fail closed")
	}
}

func TestExecutableContentBlockedByDefault(t *testing.T) {
	for _, mime := range []string{
		"text/html", "application/javascript",
		"application/x-msdownload", "application/x-executable",
	} {
		if ContentAllowed(mime) {
			t.Errorf("MIME %q must be blocked by default", mime)
		}
	}
	for _, mime := range []string{"text/plain", "application/pdf", "application/zip"} {
		if !ContentAllowed(mime) {
			t.Errorf("MIME %q must be attachable", mime)
		}
	}
}

func TestDisplayNameSanitized(t *testing.T) {
	if got := SanitizeDisplayName("../../etc/passwd"); strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Errorf("traversal survived: %q", got)
	}
	if got := SanitizeDisplayName("  report\x00final.pdf "); strings.Contains(got, "\x00") {
		t.Errorf("control byte survived: %q", got)
	}
	ref := testRef()
	ref.DisplayName = "../evil.sh"
	if err := ValidateRef(ref, 1000); err == nil {
		t.Error("unsanitized display name must fail closed")
	}
}

func TestFetchTargetDenyList(t *testing.T) {
	denied := []string{
		"file:///etc/passwd",
		"gopher://example.com/x",
		"https://user:pass@example.com/doc",
		"http://127.0.0.1/doc",
		"http://10.1.2.3/doc",
		"http://192.168.1.10/doc",
		"http://172.16.0.9/doc",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/doc",
		"http://[fd00::1]/doc",
		"https://metadata.google.internal/doc",
		"https://svc.internal/doc",
		"http://localhost:8080/doc",
		"https://example.com/../../secret",
		"https://",
	}
	for _, raw := range denied {
		if err := ValidateFetchTarget(raw); err == nil {
			t.Errorf("fetch target %q must be denied", raw)
		}
	}
	if err := ValidateFetchTarget("https://partner.example.com/docs/input-1"); err != nil {
		t.Errorf("public https target must be allowed: %v", err)
	}
}

func TestArchiveBombBudget(t *testing.T) {
	if err := CheckArchiveBudget(10, 1<<20, 10<<20); err != nil {
		t.Errorf("sane archive: %v", err)
	}
	if err := CheckArchiveBudget(MaxArchiveEntries+1, 1<<20, 1<<20); err == nil {
		t.Error("entry flood must fail closed")
	}
	if err := CheckArchiveBudget(1, 1<<20, MaxDecompressedBytes+1); err == nil {
		t.Error("output flood must fail closed")
	}
	if err := CheckArchiveBudget(1, 1024, 1024*(MaxCompressionRatio+1)); err == nil {
		t.Error("compression bomb must fail closed")
	}
}

func TestCapabilityMintAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	minted, err := Sign("att-k1", priv, Capability{
		AttachmentID: "att_01hzv3k7x4", Audience: AudienceTenant,
		Scope: ScopeFetch, IssuedAtMS: 1000, ExpiresAtMS: 9000, Nonce: "n-1",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	trusted := map[string]ed25519.PublicKey{"att-k1": pub}
	if err := minted.Verify(trusted, 2000, "att_01hzv3k7x4", AudienceTenant); err != nil {
		t.Errorf("verify: %v", err)
	}
	// Bound to another attachment: fails closed.
	if err := minted.Verify(trusted, 2000, "att_other", AudienceTenant); err == nil {
		t.Error("cross-attachment capability must fail closed")
	}
	// Wrong audience: fails closed.
	if err := minted.Verify(trusted, 2000, "att_01hzv3k7x4", AudiencePartner); err == nil {
		t.Error("cross-audience capability must fail closed")
	}
	// Expired: fails closed.
	if err := minted.Verify(trusted, 9999, "att_01hzv3k7x4", AudienceTenant); err == nil {
		t.Error("expired capability must fail closed")
	}
	// Unknown signer fails closed; empty keyring denies all.
	if err := minted.Verify(map[string]ed25519.PublicKey{"other": pub}, 2000, "att_01hzv3k7x4", AudienceTenant); err == nil {
		t.Error("unknown signer must fail closed")
	}
	if err := minted.Verify(map[string]ed25519.PublicKey{}, 2000, "att_01hzv3k7x4", AudienceTenant); err == nil {
		t.Error("empty keyring must deny all")
	}
	// No-expiry minting is rejected.
	if _, err := Sign("att-k1", priv, Capability{AttachmentID: "a", Audience: AudienceTenant, Scope: ScopeReturn, Nonce: "n"}); err == nil {
		t.Error("no-expiry capability must never be minted")
	}
}

func TestEventsCarryRefsNeverBytes(t *testing.T) {
	ref := testRef()
	if strings.Contains(ref.AttachmentID, "/") || strings.Contains(ref.AttachmentID, ":") {
		t.Errorf("attachment id must be opaque, got %q", ref.AttachmentID)
	}
	for _, field := range []string{ref.SHA256Hex, ref.MIME, ref.DisplayName} {
		if strings.Contains(field, "http") || strings.Contains(field, "/var/") {
			t.Errorf("ref field carries a path/URL: %q", field)
		}
	}
}
