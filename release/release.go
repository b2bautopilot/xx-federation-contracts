package release

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
)

const (
	SchemaVersion = "builders.release.v1"
	DocsVersion   = "v1.89"
)

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Manifest struct {
	SchemaVersion string       `json:"schema_version"`
	Component     string       `json:"component"`
	Version       string       `json:"version"`
	Commit        string       `json:"commit"`
	Date          string       `json:"date"`
	DocsVersion   string       `json:"docs_version"`
	GoVersion     string       `json:"go_version"`
	Module        string       `json:"module"`
	Dependencies  []Dependency `json:"dependencies"`
}

type Dependency struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Replace string `json:"replace,omitempty"`
}

func BuildManifest(component string) Manifest {
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Component:     component,
		Version:       Version,
		Commit:        Commit,
		Date:          Date,
		DocsVersion:   DocsVersion,
		GoVersion:     runtime.Version(),
		Dependencies:  []Dependency{},
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		manifest.Module = info.Main.Path
		for _, dep := range info.Deps {
			entry := Dependency{Path: dep.Path, Version: dep.Version}
			entry.Replace = publicReplacement(dep.Replace)
			manifest.Dependencies = append(manifest.Dependencies, entry)
		}
	}
	sort.Slice(manifest.Dependencies, func(i, j int) bool {
		return manifest.Dependencies[i].Path < manifest.Dependencies[j].Path
	})
	return manifest
}

// publicReplacement omits filesystem-only module replacements from release
// evidence. Go identifies these with a local path and either an empty or
// "(devel)" version; exposing that path would leak checkout topology into an
// otherwise portable manifest. Versioned module replacements remain useful
// public provenance.
func publicReplacement(replacement *debug.Module) string {
	if replacement == nil || replacement.Version == "" || replacement.Version == "(devel)" ||
		filepath.IsAbs(replacement.Path) || strings.HasPrefix(replacement.Path, "./") ||
		strings.HasPrefix(replacement.Path, "../") {
		return ""
	}
	return replacement.Path + "@" + replacement.Version
}

func WriteVersion(out io.Writer, component string) error {
	_, err := fmt.Fprintf(out, "%s %s commit=%s date=%s docs=%s go=%s\n",
		component, Version, Commit, Date, DocsVersion, runtime.Version())
	return err
}

func WriteManifest(out io.Writer, component string) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(BuildManifest(component))
}

func HandleCommand(args []string, out io.Writer, component string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "version", "--version", "-version":
		return true, WriteVersion(out, component)
	case "release-manifest", "--release-manifest":
		return true, WriteManifest(out, component)
	case "acceptance-record", "--acceptance-record":
		return true, HandleAcceptanceRecordCommand(args, out, component)
	case "production-evidence", "--production-evidence":
		return true, HandleProductionEvidenceCommand(args, out, component)
	default:
		return false, nil
	}
}
