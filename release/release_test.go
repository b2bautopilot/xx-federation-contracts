package release_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b2bautopilot/xx-federation-contracts/release"
)

func TestVersionOutputIncludesComponentAndDocsVersion(t *testing.T) {
	var out bytes.Buffer

	if err := release.WriteVersion(&out, "builders-control"); err != nil {
		t.Fatalf("WriteVersion returned error: %v", err)
	}
	got := out.String()
	for _, want := range []string{"builders-control", "0.0.0-dev", "docs=v1.89", "go="} {
		if !strings.Contains(got, want) {
			t.Fatalf("version output missing %q:\n%s", want, got)
		}
	}
}

func TestReleaseManifestIsDependencyManifestWithoutSecrets(t *testing.T) {
	t.Setenv("BUILDERS_TEST_SECRET_TOKEN", "super-secret-token")
	var out bytes.Buffer

	if err := release.WriteManifest(&out, "builders-federation-gateway"); err != nil {
		t.Fatalf("WriteManifest returned error: %v", err)
	}
	if strings.Contains(out.String(), "super-secret-token") {
		t.Fatalf("release manifest leaked environment secret:\n%s", out.String())
	}

	var manifest release.Manifest
	if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, out.String())
	}
	if manifest.SchemaVersion != release.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", manifest.SchemaVersion, release.SchemaVersion)
	}
	if manifest.Component != "builders-federation-gateway" {
		t.Fatalf("component = %q", manifest.Component)
	}
	if manifest.DocsVersion != "v1.89" {
		t.Fatalf("docs_version = %q", manifest.DocsVersion)
	}
	if manifest.GoVersion == "" {
		t.Fatal("go_version is required")
	}
	if manifest.Module != "github.com/b2bautopilot/xx-federation-contracts" {
		t.Fatalf("module = %q", manifest.Module)
	}
	for i := 1; i < len(manifest.Dependencies); i++ {
		if manifest.Dependencies[i-1].Path > manifest.Dependencies[i].Path {
			t.Fatalf("dependencies are not sorted: %q before %q",
				manifest.Dependencies[i-1].Path, manifest.Dependencies[i].Path)
		}
	}
}

func TestHandleCommandRecognizesVersionAndManifest(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"release-manifest"}, {"--release-manifest"}} {
		var out bytes.Buffer
		handled, err := release.HandleCommand(args, &out, "builders-agent")
		if err != nil {
			t.Fatalf("HandleCommand(%v) error = %v", args, err)
		}
		if !handled {
			t.Fatalf("HandleCommand(%v) was not handled", args)
		}
		if out.Len() == 0 {
			t.Fatalf("HandleCommand(%v) wrote no output", args)
		}
	}
}
