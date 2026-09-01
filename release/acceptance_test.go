package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/release"
)

func TestBuildAcceptanceRecordForEachBuildersComponentValidatorShape(t *testing.T) {
	withReleaseMetadata(t)
	for _, component := range []string{"builders-control", "builders-agent", "builders-federation-gateway"} {
		t.Run(component, func(t *testing.T) {
			opts := validAcceptanceOptions(component)
			record, err := release.BuildAcceptanceRecord(opts)
			if err != nil {
				t.Fatalf("BuildAcceptanceRecord returned error: %v", err)
			}
			if record.SchemaVersion != release.AcceptanceSchemaVersion {
				t.Fatalf("schema_version = %q", record.SchemaVersion)
			}
			if len(record.Components) != 1 || record.Components[0].Name != component {
				t.Fatalf("components = %#v", record.Components)
			}
			got := record.Components[0]
			if got.Repo != "https://github.com/b2bautopilot/xyz-b2b/services/builders-net" {
				t.Fatalf("repo = %q", got.Repo)
			}
			if got.VersionOutputSHA256 == "" || got.ManifestOutputSHA256 == "" {
				t.Fatalf("missing evidence hashes: %#v", got)
			}
			if got.PackageSmoke[0].RequiresPartnerAccess {
				t.Fatal("package smoke must not require partner access")
			}
			if !record.SecurityInvariants["gateway_facade_only"].Passed {
				t.Fatalf("gateway facade invariant not passed: %#v", record.SecurityInvariants["gateway_facade_only"])
			}
			out, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"192.168.",
				"fd00:",
				"12D3Koo",
				"/Users/",
				"private_key",
				"peer_bundle",
				"authorized by mesh",
			} {
				if strings.Contains(string(out), forbidden) {
					t.Fatalf("acceptance record leaked forbidden term %q:\n%s", forbidden, out)
				}
			}
		})
	}
}

func TestAcceptanceRecordGatewayPackageSmokeNamesFederationFacade(t *testing.T) {
	withReleaseMetadata(t)
	record, err := release.BuildAcceptanceRecord(validAcceptanceOptions("builders-federation-gateway"))
	if err != nil {
		t.Fatalf("BuildAcceptanceRecord returned error: %v", err)
	}
	command := record.Components[0].PackageSmoke[0].Command
	if !strings.Contains(strings.ToLower(command), "federation-facade") {
		t.Fatalf("gateway package smoke command = %q, want federation facade evidence", command)
	}
}

func TestAcceptanceRecordRecordsSignedArtifact(t *testing.T) {
	withReleaseMetadata(t)
	opts := signedAcceptanceOptions("builders-federation-gateway")
	record, err := release.BuildAcceptanceRecord(opts)
	if err != nil {
		t.Fatalf("BuildAcceptanceRecord returned error: %v", err)
	}
	artifact := record.Components[0].Artifacts[0]
	if !artifact.Signed || !artifact.SignatureVerified {
		t.Fatalf("signed artifact evidence was not recorded: %#v", artifact)
	}
	if artifact.SignerID != "production signing attestation" {
		t.Fatalf("signer id = %q", artifact.SignerID)
	}
	if artifact.UnsignedException != nil {
		t.Fatalf("signed artifact must not retain unsigned exception: %#v", artifact.UnsignedException)
	}
}

func TestAcceptanceRecordRejectsUnsafeEvidence(t *testing.T) {
	withReleaseMetadata(t)
	opts := validAcceptanceOptions("builders-control")
	opts.TagOrBuildLabel = "release-built-on-192.168.40.25"
	_, err := release.BuildAcceptanceRecord(opts)
	if err == nil {
		t.Fatal("BuildAcceptanceRecord accepted private topology evidence")
	}
	if !strings.Contains(err.Error(), "private topology") {
		t.Fatalf("error = %v, want topology refusal", err)
	}
}

func TestAcceptanceRecordRejectsDevBuildMetadata(t *testing.T) {
	withRawReleaseMetadata(t, "0.0.0-dev", "unknown", "unknown")
	_, err := release.BuildAcceptanceRecord(validAcceptanceOptions("builders-control"))
	if err == nil {
		t.Fatal("BuildAcceptanceRecord accepted dev metadata")
	}
	if !strings.Contains(err.Error(), "non-dev") && !strings.Contains(err.Error(), "Commit") {
		t.Fatalf("error = %v, want dev metadata refusal", err)
	}
}

func TestAcceptanceRecordRequiresCompleteUnsignedException(t *testing.T) {
	withReleaseMetadata(t)
	opts := validAcceptanceOptions("builders-control")
	opts.ExceptionOwner = ""
	_, err := release.BuildAcceptanceRecord(opts)
	if err == nil {
		t.Fatal("BuildAcceptanceRecord accepted incomplete unsigned exception")
	}
	if !strings.Contains(err.Error(), "unsigned artifacts require") {
		t.Fatalf("error = %v", err)
	}
}

func TestAcceptanceRecordDoesNotLeakArtifactLocalPath(t *testing.T) {
	withReleaseMetadata(t)
	artifactPath := filepath.Join(t.TempDir(), "builders-net-backend.tar.gz")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := release.ParseAcceptanceRecordArgs(append(validAcceptanceArgs("builders-control"), "--artifact", artifactPath), "builders-control")
	if err != nil {
		t.Fatalf("ParseAcceptanceRecordArgs returned error: %v", err)
	}
	record, err := release.BuildAcceptanceRecord(opts)
	if err != nil {
		t.Fatalf("BuildAcceptanceRecord returned error: %v", err)
	}
	out, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), filepath.Dir(artifactPath)) {
		t.Fatalf("acceptance record leaked local artifact path:\n%s", out)
	}
	if record.Components[0].Artifacts[0].Filename != "builders-net-backend.tar.gz" {
		t.Fatalf("artifact filename = %q", record.Components[0].Artifacts[0].Filename)
	}
}

func TestAcceptanceRecordRejectsReleaseManifestLocalReplacePath(t *testing.T) {
	err := release.ScanAcceptanceEvidence([]byte(`{"replace":"/Users/operator/x-builders-net"}`))
	if err == nil {
		t.Fatal("ScanAcceptanceEvidence accepted local path")
	}
}

func withReleaseMetadata(t *testing.T) {
	t.Helper()
	withRawReleaseMetadata(t, "1.2.3-test", "e0b68eb", "2026-06-04T00:00:00Z")
}

func withRawReleaseMetadata(t *testing.T, version, commit, date string) {
	t.Helper()
	oldVersion, oldCommit, oldDate := release.Version, release.Commit, release.Date
	release.Version, release.Commit, release.Date = version, commit, date
	t.Cleanup(func() {
		release.Version, release.Commit, release.Date = oldVersion, oldCommit, oldDate
	})
}

func validAcceptanceOptions(component string) release.AcceptanceOptions {
	return release.AcceptanceOptions{
		Component:                  component,
		ReleaseID:                  "FED-P7-004-builders-net-test-" + component,
		ReleaseDate:                "2026-06-04",
		Owner:                      "release-engineering",
		PR:                         "https://github.com/b2bautopilot/xyz-b2b/services/builders-net/pull/87",
		MergeCommit:                "e0b68eb",
		TagOrBuildLabel:            "x-builders-net-pilot-2026-06-04",
		ArtifactFilename:           "builders-net-backend.tar.gz",
		ArtifactSHA256:             strings.Repeat("1", 64),
		ArtifactSizeBytes:          2048,
		ArtifactPlatform:           "linux-amd64",
		UnsignedException:          "Pilot packaging path has not completed commercial signing procurement.",
		ExceptionOwner:             "release-engineering",
		ExceptionExpires:           "2026-12-31",
		PackageSmokeEvidenceSHA256: strings.Repeat("2", 64),
		BackupArtifactSHA256:       strings.Repeat("3", 64),
		RestoreVerifiedAt:          "2026-06-04T00:00:00Z",
		SecurityDocCommit:          "7beef82",
		SecurityDocEvidenceSHA256:  strings.Repeat("4", 64),
	}
}

func signedAcceptanceOptions(component string) release.AcceptanceOptions {
	opts := validAcceptanceOptions(component)
	opts.SignedBy = "production signing attestation"
	opts.SignedAt = "2026-06-04T12:00:00Z"
	opts.UnsignedException = ""
	opts.ExceptionOwner = ""
	opts.ExceptionExpires = ""
	return opts
}

func validAcceptanceArgs(component string) []string {
	return []string{
		"--component", component,
		"--release-id", "FED-P7-004-builders-net-test-" + component,
		"--release-date", "2026-06-04",
		"--owner", "release-engineering",
		"--pr", "https://github.com/b2bautopilot/xyz-b2b/services/builders-net/pull/87",
		"--merge-commit", "e0b68eb",
		"--tag-or-build-label", "x-builders-net-pilot-2026-06-04",
		"--artifact-platform", "linux-amd64",
		"--unsigned-exception", "Pilot packaging path has not completed commercial signing procurement.",
		"--exception-owner", "release-engineering",
		"--exception-expires", "2026-12-31",
		"--package-smoke-evidence-sha256", strings.Repeat("2", 64),
		"--backup-artifact-sha256", strings.Repeat("3", 64),
		"--restore-verified-at", "2026-06-04T00:00:00Z",
		"--security-doc-commit", "7beef82",
		"--security-doc-evidence-sha256", strings.Repeat("4", 64),
	}
}
