// Package provenance is the machine-readable contract for immutable
// participant runtime provenance (issue #19, parent epic #18).
//
// Every PM, builder, and reviewer runs as a distinct authenticated,
// non-privileged container workload. Before infrastructure consumes a
// runtime, the control plane verifies this document: exact OCI
// index/platform digests, Agent Kit commit/version, CLI/model/provider
// identifiers, network-policy hash, spec revision/hash pin, runtime kind,
// and non-root/non-privileged evidence. Anything unverifiable fails closed.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/provenance
// Spec evidence: rel.agent-connects-control (runtime provenance).
package provenance

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Schema identifier for runtime provenance documents.
const SchemaRuntimeProvenanceV1 = "builders.federation.runtime_provenance.v1"

// Container runtime kinds. One identity/session/container per participant:
// GCP runs Cloud Run services/jobs, Azure runs Container Apps/Container
// Instances services/jobs, and AWS stays ECS Fargate-only, forever.
const (
	RuntimeGCPCloudRun        = "gcp-cloud-run"
	RuntimeAzureContainerApps = "azure-container-apps"
	RuntimeAzureContainerInst = "azure-container-instances"
	RuntimeAWSECSFargate      = "aws-ecs-fargate"
)

// Cloud placement names.
const (
	CloudGCP   = "gcp"
	CloudAzure = "azure"
	CloudAWS   = "aws"
)

var (
	ErrBadProvenance  = errors.New("runtime provenance invalid")
	ErrBadDigest      = errors.New("runtime provenance digest malformed")
	ErrNotPinned      = errors.New("runtime provenance not pinned to expected value")
	ErrPrivileged     = errors.New("runtime provenance lacks non-privileged evidence")
	ErrUnknownCloud   = errors.New("runtime provenance cloud unknown")
	ErrUnknownRuntime = errors.New("runtime provenance runtime kind unknown")
)

var (
	digestRe = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ValidRuntimeKind reports whether value names a declared container runtime.
func ValidRuntimeKind(value string) bool {
	switch value {
	case RuntimeGCPCloudRun, RuntimeAzureContainerApps,
		RuntimeAzureContainerInst, RuntimeAWSECSFargate:
		return true
	default:
		return false
	}
}

// PlacementAllowed reports whether a runtime kind may run on a cloud. AWS is
// Fargate-only; GCP is Cloud Run-only; Azure is Container Apps/Instances
// only. Unknown clouds and kinds fail closed — and no VM kind exists to
// allow, by construction (pure container topology, Revision 6).
func PlacementAllowed(runtimeKind, cloud string) bool {
	switch cloud {
	case CloudGCP:
		return runtimeKind == RuntimeGCPCloudRun
	case CloudAzure:
		return runtimeKind == RuntimeAzureContainerApps || runtimeKind == RuntimeAzureContainerInst
	case CloudAWS:
		return runtimeKind == RuntimeAWSECSFargate
	default:
		return false
	}
}

// RuntimeProvenance is the immutable evidence for one participant container.
type RuntimeProvenance struct {
	SchemaVersion      string            `json:"schema_version"`
	ProvenanceID       string            `json:"provenance_id"`
	OCIIndexDigest     string            `json:"oci_index_digest"`
	OCIPlatformDigests map[string]string `json:"oci_platform_digests"`
	AgentKitCommit     string            `json:"agentkit_commit"`
	AgentKitVersion    string            `json:"agentkit_version"`
	CLIName            string            `json:"cli_name"`
	CLIVersion         string            `json:"cli_version"`
	ModelID            string            `json:"model_id"`
	ProviderID         string            `json:"provider_id"`
	NetworkPolicyHash  string            `json:"network_policy_hash"`
	SpecRevision       int64             `json:"spec_revision"`
	SpecHash           string            `json:"spec_hash"`
	RuntimeKind        string            `json:"runtime_kind"`
	Cloud              string            `json:"cloud"`
	NonRoot            bool              `json:"non_root"`
	NoNewPrivileges    bool              `json:"no_new_privileges"`
	ImageVerified      bool              `json:"image_verified"`
}

// ExpectedPins carries the values the consumer pinned before launch: the
// sealed spec revision/hash and the exact image digests. Verification fails
// closed on any drift from these pins.
type ExpectedPins struct {
	SpecRevision       int64
	SpecHash           string
	OCIIndexDigest     string
	OCIPlatformDigests map[string]string
	AgentKitCommit     string
	NetworkPolicyHash  string
}

// validDigest reports whether value is a 64-hex digest with optional sha256: prefix.
func validDigest(value string) bool { return digestRe.MatchString(value) }

// Validate checks the document shape fail-closed: required identifiers,
// well-formed digests, a known runtime kind on its permitted cloud, and
// non-root/non-privileged/verified evidence all asserted true.
func (p RuntimeProvenance) Validate() error {
	if p.SchemaVersion != SchemaRuntimeProvenanceV1 {
		return fmt.Errorf("%w: schema %q", ErrBadProvenance, p.SchemaVersion)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"provenance_id", p.ProvenanceID},
		{"agentkit_version", p.AgentKitVersion},
		{"cli_name", p.CLIName},
		{"cli_version", p.CLIVersion},
		{"model_id", p.ModelID},
		{"provider_id", p.ProviderID},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%w: empty %s", ErrBadProvenance, field.name)
		}
	}
	if !validDigest(p.OCIIndexDigest) {
		return fmt.Errorf("%w: oci index %q", ErrBadDigest, p.OCIIndexDigest)
	}
	if len(p.OCIPlatformDigests) == 0 {
		return fmt.Errorf("%w: no platform digests", ErrBadDigest)
	}
	for platform, digest := range p.OCIPlatformDigests {
		if strings.TrimSpace(platform) == "" || !validDigest(digest) {
			return fmt.Errorf("%w: platform %q", ErrBadDigest, platform)
		}
	}
	if !commitRe.MatchString(p.AgentKitCommit) {
		return fmt.Errorf("%w: agentkit commit", ErrBadDigest)
	}
	if !validDigest(p.NetworkPolicyHash) {
		return fmt.Errorf("%w: network policy hash", ErrBadDigest)
	}
	if p.SpecRevision <= 0 || !validDigest(p.SpecHash) {
		return fmt.Errorf("%w: spec pin", ErrBadDigest)
	}
	if !ValidRuntimeKind(p.RuntimeKind) {
		return fmt.Errorf("%w: %q", ErrUnknownRuntime, p.RuntimeKind)
	}
	switch p.Cloud {
	case CloudGCP, CloudAzure, CloudAWS:
	default:
		return fmt.Errorf("%w: %q", ErrUnknownCloud, p.Cloud)
	}
	if !PlacementAllowed(p.RuntimeKind, p.Cloud) {
		return fmt.Errorf("%w: %s on %s", ErrUnknownRuntime, p.RuntimeKind, p.Cloud)
	}
	if !p.NonRoot || !p.NoNewPrivileges || !p.ImageVerified {
		return fmt.Errorf("%w: non_root=%v no_new_privs=%v verified=%v",
			ErrPrivileged, p.NonRoot, p.NoNewPrivileges, p.ImageVerified)
	}
	return nil
}

// Verify checks shape and then pins the document against the consumer's
// expected values: sealed spec revision/hash, exact OCI digests, Agent Kit
// commit, and network-policy hash. Any drift — including a provenance
// document minted against a different spec revision — fails closed.
func (p RuntimeProvenance) Verify(pins ExpectedPins) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.SpecRevision != pins.SpecRevision || !equalDigest(p.SpecHash, pins.SpecHash) {
		return fmt.Errorf("%w: spec revision/hash", ErrNotPinned)
	}
	if !equalDigest(p.OCIIndexDigest, pins.OCIIndexDigest) {
		return fmt.Errorf("%w: oci index digest", ErrNotPinned)
	}
	for platform, want := range pins.OCIPlatformDigests {
		got, ok := p.OCIPlatformDigests[platform]
		if !ok || !equalDigest(got, want) {
			return fmt.Errorf("%w: platform %q digest", ErrNotPinned, platform)
		}
	}
	if p.AgentKitCommit != pins.AgentKitCommit {
		return fmt.Errorf("%w: agentkit commit", ErrNotPinned)
	}
	if !equalDigest(p.NetworkPolicyHash, pins.NetworkPolicyHash) {
		return fmt.Errorf("%w: network policy hash", ErrNotPinned)
	}
	return nil
}

// equalDigest compares digests ignoring an optional sha256: prefix and case.
func equalDigest(a, b string) bool {
	strip := func(s string) string {
		return strings.ToLower(strings.TrimPrefix(strings.ToLower(s), "sha256:"))
	}
	return strip(a) == strip(b)
}
