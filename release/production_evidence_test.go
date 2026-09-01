package release_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/release"
)

func TestProductionEvidenceFragmentWritesRetainedSignedBackendEvidence(t *testing.T) {
	withReleaseMetadata(t)
	outDir := t.TempDir()
	outPath, err := release.WriteProductionEvidenceFragment(outDir, validProductionEvidenceOptions("builders-federation-gateway"))
	if err != nil {
		t.Fatalf("WriteProductionEvidenceFragment returned error: %v", err)
	}
	if filepath.Dir(outPath) != outDir {
		t.Fatalf("out path = %q, want under temp dir %q", outPath, outDir)
	}

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), outDir) {
		t.Fatalf("production evidence leaked output directory:\n%s", b)
	}
	if strings.Contains(string(b), "unsigned_exception") {
		t.Fatalf("production evidence must not carry unsigned exception fields:\n%s", b)
	}
	if err := release.ScanAcceptanceEvidence(b); err != nil {
		t.Fatalf("production evidence leaked forbidden evidence: %v\n%s", err, b)
	}

	var fragment release.ProductionEvidenceFragment
	if err := json.Unmarshal(b, &fragment); err != nil {
		t.Fatalf("fragment is not valid JSON: %v\n%s", err, b)
	}
	if fragment.SchemaVersion != release.ProductionEvidenceSchemaVersion {
		t.Fatalf("schema_version = %q", fragment.SchemaVersion)
	}
	if fragment.Component != "builders-federation-gateway" {
		t.Fatalf("component = %q", fragment.Component)
	}
	if fragment.ProductionEvidence.ProductionSigning.Result != "pass" {
		t.Fatalf("production signing gate = %#v", fragment.ProductionEvidence.ProductionSigning)
	}
	if got := fragment.ProductionEvidence.ProductionSigning.Artifacts[0].SignatureEvidence.Path; got != "signature-verifier-output.txt" {
		t.Fatalf("signature evidence path = %q", got)
	}
	if len(fragment.RetainedEvidence) != 16 {
		t.Fatalf("retained evidence refs = %#v", fragment.RetainedEvidence)
	}
	for _, ref := range fragment.RetainedEvidence {
		if filepath.IsAbs(ref.Path) {
			t.Fatalf("retained path is absolute: %#v", ref)
		}
		data, err := os.ReadFile(filepath.Join(outDir, ref.Path))
		if err != nil {
			t.Fatalf("read retained evidence %q: %v", ref.Path, err)
		}
		if int64(len(data)) != ref.SizeBytes {
			t.Fatalf("ref size for %q = %d, want %d", ref.Path, ref.SizeBytes, len(data))
		}
		if len(ref.SHA256) != 64 {
			t.Fatalf("ref sha for %q = %q", ref.Path, ref.SHA256)
		}
	}
}

func TestHandleCommandRecognizesProductionEvidence(t *testing.T) {
	withReleaseMetadata(t)
	tempDir := t.TempDir()
	artifact := filepath.Join(tempDir, "builders-net-backend.tar.gz")
	if err := os.WriteFile(artifact, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceFlags := writeProductionEvidenceInputFlags(t, tempDir)
	outDir := filepath.Join(tempDir, "retained")

	var out bytes.Buffer
	args := append([]string{
		"production-evidence",
		"--out-dir", outDir,
		"--component", "builders-control",
		"--release-id", "FED-P8-002-builders-net-prod-builders-control",
		"--release-date", "2026-06-04",
		"--owner", "release-engineering",
		"--pr", "https://github.com/b2bautopilot/xyz-b2b/services/builders-net/pull/87",
		"--merge-commit", "e0b68eb",
		"--tag-or-build-label", "x-builders-net-prod-2026-06-04",
		"--artifact", artifact,
		"--artifact-platform", "linux-amd64",
		"--signed-by", "production signing attestation",
		"--signed-at", "2026-06-04T12:00:00Z",
		"--signature-verifier", "cosign verify-blob",
	}, evidenceFlags...)
	handled, err := release.HandleCommand(args, &out, "builders-control")
	if err != nil {
		t.Fatalf("HandleCommand production-evidence returned error: %v", err)
	}
	if !handled {
		t.Fatal("HandleCommand did not recognize production-evidence")
	}
	if !strings.Contains(out.String(), "production evidence:") {
		t.Fatalf("stdout missing production evidence path:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(outDir, "builders-control-production-evidence.json")); err != nil {
		t.Fatalf("production evidence fragment was not written: %v", err)
	}
}

func TestProductionEvidenceBuildsForEachBuildersBackendComponent(t *testing.T) {
	withReleaseMetadata(t)
	for _, component := range []string{"builders-control", "builders-agent", "builders-federation-gateway"} {
		t.Run(component, func(t *testing.T) {
			fragment, err := release.BuildProductionEvidenceFragment(validProductionEvidenceOptions(component))
			if err != nil {
				t.Fatalf("BuildProductionEvidenceFragment returned error: %v", err)
			}
			if fragment.Component != component {
				t.Fatalf("component = %q", fragment.Component)
			}
			if !fragment.SecurityInvariants["gateway_facade_only"].Passed ||
				!fragment.SecurityInvariants["egress_default_deny"].Passed ||
				!fragment.SecurityInvariants["audit_evidence_preserved"].Passed {
				t.Fatalf("security invariants not retained: %#v", fragment.SecurityInvariants)
			}
		})
	}
}

func TestProductionEvidenceRequiresSignedInputs(t *testing.T) {
	withReleaseMetadata(t)
	opts := validProductionEvidenceOptions("builders-control")
	opts.SignedBy = ""
	_, err := release.BuildProductionEvidenceFragment(opts)
	if err == nil {
		t.Fatal("BuildProductionEvidenceFragment accepted missing signer")
	}
	if !strings.Contains(err.Error(), "signed-by is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestProductionEvidenceRejectsLocalProductionMetadata(t *testing.T) {
	withReleaseMetadata(t)
	tests := []struct {
		name string
		edit func(*release.ProductionEvidenceOptions)
		want string
	}{
		{
			name: "pull zero",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.PR = "https://github.com/b2bautopilot/xyz-b2b/services/builders-net/pull/0"
			},
			want: "nonzero pull number",
		},
		{
			name: "local release id",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.ReleaseID = "FED-P8-002-builders-net-local"
			},
			want: "release-id must not be local",
		},
		{
			name: "local label",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.TagOrBuildLabel = "x-builders-net-local-e0b68eb"
			},
			want: "tag-or-build-label must not be local",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validProductionEvidenceOptions("builders-control")
			tt.edit(&opts)
			_, err := release.BuildProductionEvidenceFragment(opts)
			if err == nil {
				t.Fatal("BuildProductionEvidenceFragment accepted local production metadata")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestProductionEvidenceRejectsLocalBuildVersion(t *testing.T) {
	withRawReleaseMetadata(t, "0.1.0-local", "e0b68eb", "2026-06-04T00:00:00Z")
	_, err := release.BuildProductionEvidenceFragment(validProductionEvidenceOptions("builders-control"))
	if err == nil {
		t.Fatal("BuildProductionEvidenceFragment accepted local build metadata")
	}
	if !strings.Contains(err.Error(), "non-local production metadata") {
		t.Fatalf("error = %v", err)
	}
}

func TestProductionEvidenceRejectsUnsafeRetainedEvidence(t *testing.T) {
	withReleaseMetadata(t)
	tests := []struct {
		name string
		edit func(*release.ProductionEvidenceOptions)
		want string
	}{
		{
			name: "absolute local path",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.LeakScanEvidence = []byte("scan_output=/tmp/builders-net/leak-scan.txt\n")
			},
			want: "private topology",
		},
		{
			name: "relative local path",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.InstallerBreadthEvidence = []byte("installer evidence path:dist/evidence/installer.txt\n")
			},
			want: "private topology",
		},
		{
			name: "unsigned exception",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.SignatureVerifierEvidence = []byte("package-smoke: unsigned exception recorded\n")
			},
			want: "unsigned evidence is not allowed",
		},
		{
			name: "request body identity acceptance",
			edit: func(opts *release.ProductionEvidenceOptions) {
				opts.GatewayBoundaryEvidence = []byte("gateway accepted tenant_id from request body as authenticated identity\n")
			},
			want: "request-body identity acceptance",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validProductionEvidenceOptions("builders-control")
			tt.edit(&opts)
			_, err := release.BuildProductionEvidenceFragment(opts)
			if err == nil {
				t.Fatal("BuildProductionEvidenceFragment accepted unsafe retained evidence")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestScanAcceptanceEvidenceRejectsLocalReleaseEvidencePaths(t *testing.T) {
	for _, evidence := range []string{
		`{"path":"/opt/release/evidence.txt"}`,
		`{"path":"dist/evidence/signature.txt"}`,
		`path=/tmp/evidence/signature.txt`,
		`artifact=bin/builders-control`,
		`artifact:C:\release\evidence.txt`,
	} {
		if err := release.ScanAcceptanceEvidence([]byte(evidence)); err == nil {
			t.Fatalf("ScanAcceptanceEvidence accepted unsafe evidence %q", evidence)
		}
	}
}

func validProductionEvidenceOptions(component string) release.ProductionEvidenceOptions {
	return release.ProductionEvidenceOptions{
		Component:                    component,
		ReleaseID:                    "FED-P8-002-builders-net-prod-" + component,
		ReleaseDate:                  "2026-06-04",
		Owner:                        "release-engineering",
		PR:                           "https://github.com/b2bautopilot/xyz-b2b/services/builders-net/pull/87",
		MergeCommit:                  "e0b68eb",
		TagOrBuildLabel:              "x-builders-net-prod-2026-06-04",
		ArtifactFilename:             "builders-net-backend.tar.gz",
		ArtifactSHA256:               strings.Repeat("5", 64),
		ArtifactSizeBytes:            4096,
		ArtifactPlatform:             "linux-amd64",
		SignedBy:                     "production signing attestation",
		SignedAt:                     "2026-06-04T12:00:00Z",
		SignatureVerifier:            "cosign verify-blob",
		SignatureVerifierEvidence:    []byte("signature verifier result: pass\n"),
		PackageSmokeEvidence:         []byte("package smoke result: pass; backend binaries verified\n"),
		SBOMDependencyEvidence:       []byte("sbom dependency result: pass; release manifest reviewed\n"),
		InstallerBreadthEvidence:     []byte("installer package breadth result: pass; builders-control builders-agent builders-federation-gateway\n"),
		GatewayBoundaryEvidence:      []byte("gateway boundary result: pass; facade only no inbound listener\n"),
		DefaultDenyEgressEvidence:    []byte("egress result: pass; denied ungranted attempt and allowed model target verified\n"),
		AuditChainEvidence:           []byte("audit chain result: pass; restore and rollback verifiers passed\n"),
		ServiceCatalogEvidence:       []byte("service catalog result: pass; retired entries hidden\n"),
		PolicyGrantEvidence:          []byte("policy grant result: pass; revoked expired approval-required denials verified\n"),
		TransactionEvidence:          []byte("transaction result: pass; idempotent replay and cross-partner denial verified\n"),
		BackupRestoreEvidence:        []byte("backup restore result: pass\n"),
		RollbackEvidence:             []byte("rollback result: pass; audit preserved\n"),
		LeakScanEvidence:             []byte("leak scan result: pass; findings count zero\n"),
		EnterpriseComplianceEvidence: []byte("enterprise compliance result: pass; release controls reviewed\n"),
		AdversarialReviewEvidence:    []byte("adversarial review result: pass\n"),
	}
}

func writeProductionEvidenceInputFlags(t *testing.T, dir string) []string {
	t.Helper()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	return []string{
		"--signature-evidence", write("signature.txt", "signature verifier result: pass\n"),
		"--package-smoke-evidence", write("package-smoke.txt", "package smoke result: pass; backend binaries verified\n"),
		"--sbom-evidence", write("sbom.txt", "sbom dependency result: pass; release manifest reviewed\n"),
		"--installer-evidence", write("installer.txt", "installer package breadth result: pass; builders-control builders-agent builders-federation-gateway\n"),
		"--gateway-boundary-evidence", write("gateway-boundary.txt", "gateway boundary result: pass; facade only no inbound listener\n"),
		"--egress-evidence", write("egress.txt", "egress result: pass; denied ungranted attempt and allowed model target verified\n"),
		"--audit-chain-evidence", write("audit-chain.txt", "audit chain result: pass; restore and rollback verifiers passed\n"),
		"--service-catalog-evidence", write("service-catalog.txt", "service catalog result: pass; retired entries hidden\n"),
		"--policy-grant-evidence", write("policy-grant.txt", "policy grant result: pass; revoked expired approval-required denials verified\n"),
		"--transaction-evidence", write("transaction.txt", "transaction result: pass; idempotent replay and cross-partner denial verified\n"),
		"--backup-restore-evidence", write("backup-restore.txt", "backup restore result: pass\n"),
		"--rollback-evidence", write("rollback.txt", "rollback result: pass; audit preserved\n"),
		"--leak-scan-evidence", write("leak-scan.txt", "leak scan result: pass; findings count zero\n"),
		"--enterprise-compliance-evidence", write("enterprise-compliance.txt", "enterprise compliance result: pass; release controls reviewed\n"),
		"--adversarial-review-evidence", write("adversarial-review.txt", "adversarial review result: pass\n"),
	}
}
