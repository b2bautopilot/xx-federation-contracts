// Package projcheck_test exercises the facade IDL authority gate
// (scripts/check-projections.py) from Go: the offline pin check must pass,
// the removed reverse generator must be refused, and export must copy the
// authoritative bytes outward byte-identically. Skipped where python3 is
// absent; CI provides it for scripts/validate-spec.py already.
package projcheck_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var projections = []string{
	"api/proto/builders/v1/federation.proto",
	"api/proto/builders/v1/common.proto",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func runGate(t *testing.T, args ...string) (int, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	script := filepath.Join(repoRoot(t), "scripts", "check-projections.py")
	cmd := exec.Command(python, append([]string{script}, args...)...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatalf("exec gate: %v", err)
		}
	}
	return code, string(out)
}

func TestProjectionPinCheckPasses(t *testing.T) {
	code, out := runGate(t)
	if code != 0 {
		t.Fatalf("offline pin check exit = %d, want 0\n%s", code, out)
	}
	for _, p := range projections {
		if !strings.Contains(out, p) {
			t.Errorf("pin output does not mention %s\n%s", p, out)
		}
	}
}

func TestReverseGenerationRefused(t *testing.T) {
	for _, args := range [][]string{
		{"--generate", "--source", t.TempDir()},
		{"--source", t.TempDir()},
	} {
		code, out := runGate(t, args...)
		if code == 0 {
			t.Errorf("reverse generator %v accepted (exit 0), want refusal", args)
		}
		if !strings.Contains(out, "REFUSED") {
			t.Errorf("reverse generator %v output lacks refusal\n%s", args, out)
		}
	}
}

func TestExportCopiesAuthoritativeBytesOutward(t *testing.T) {
	dest := t.TempDir()
	code, out := runGate(t, "--export", "--dest", dest)
	if code != 0 {
		t.Fatalf("export exit = %d, want 0\n%s", code, out)
	}
	root := repoRoot(t)
	for _, p := range projections {
		want, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("read authoritative %s: %v", p, err)
		}
		got, err := os.ReadFile(filepath.Join(dest, p))
		if err != nil {
			t.Fatalf("read exported %s: %v", p, err)
		}
		if string(got) != string(want) {
			t.Errorf("exported %s differs from authoritative bytes", p)
		}
	}
}
