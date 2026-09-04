package provenance

import (
	"strings"
	"testing"
)

func testProvenance() RuntimeProvenance {
	d := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return RuntimeProvenance{
		SchemaVersion:      SchemaRuntimeProvenanceV1,
		ProvenanceID:       "prov-1",
		OCIIndexDigest:     "sha256:" + d,
		OCIPlatformDigests: map[string]string{"linux/amd64": "sha256:" + d},
		AgentKitCommit:     "0123456789abcdef0123456789abcdef01234567",
		AgentKitVersion:    "agentkit-0.9.0",
		CLIName:            "muse",
		CLIVersion:         "1.2.3",
		ModelID:            "muse-spark",
		ProviderID:         "meta-msl",
		NetworkPolicyHash:  "sha256:" + d,
		SpecRevision:       9,
		SpecHash:           "sha256:" + d,
		RuntimeKind:        RuntimeGCPCloudRun,
		Cloud:              CloudGCP,
		NonRoot:            true,
		NoNewPrivileges:    true,
		ImageVerified:      true,
	}
}

func testPins() ExpectedPins {
	d := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return ExpectedPins{
		SpecRevision:       9,
		SpecHash:           d,
		OCIIndexDigest:     d,
		OCIPlatformDigests: map[string]string{"linux/amd64": d},
		AgentKitCommit:     "0123456789abcdef0123456789abcdef01234567",
		NetworkPolicyHash:  d,
	}
}

func TestProvenanceHappyPath(t *testing.T) {
	p := testProvenance()
	if err := p.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
	if err := p.Verify(testPins()); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestPlacementMatrix(t *testing.T) {
	allowed := [][2]string{
		{RuntimeGCPCloudRun, CloudGCP},
		{RuntimeAzureContainerApps, CloudAzure},
		{RuntimeAzureContainerInst, CloudAzure},
		{RuntimeAWSECSFargate, CloudAWS},
	}
	for _, tc := range allowed {
		if !PlacementAllowed(tc[0], tc[1]) {
			t.Errorf("PlacementAllowed(%q,%q) = false, want true", tc[0], tc[1])
		}
	}
	denied := [][2]string{
		{RuntimeAWSECSFargate, CloudGCP}, // AWS runtime never leaves AWS
		{RuntimeGCPCloudRun, CloudAWS},   // GCP runtime never on AWS
		{RuntimeAzureContainerApps, CloudGCP},
		{RuntimeGCPCloudRun, CloudAzure},
		{RuntimeAWSECSFargate, CloudAzure},
		{"gce-vm", CloudGCP}, // no VM kind exists
		{"ec2-vm", CloudAWS},
		{RuntimeGCPCloudRun, "onprem"},
	}
	for _, tc := range denied {
		if PlacementAllowed(tc[0], tc[1]) {
			t.Errorf("PlacementAllowed(%q,%q) = true, want false", tc[0], tc[1])
		}
	}
	if ValidRuntimeKind("ec2-vm") || ValidRuntimeKind("aks-nodepool") {
		t.Error("VM-flavoured runtime kinds must not exist")
	}
}

func TestPrivilegeEvidenceRequired(t *testing.T) {
	for _, mutate := range []func(*RuntimeProvenance){
		func(p *RuntimeProvenance) { p.NonRoot = false },
		func(p *RuntimeProvenance) { p.NoNewPrivileges = false },
		func(p *RuntimeProvenance) { p.ImageVerified = false },
	} {
		p := testProvenance()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("missing privilege evidence must fail closed: %+v", p)
		}
	}
}

func TestDigestAndPinDrift(t *testing.T) {
	p := testProvenance()
	p.OCIIndexDigest = "not-a-digest"
	if err := p.Validate(); err == nil {
		t.Error("malformed digest must fail closed")
	}
	p = testProvenance()
	p.AgentKitCommit = "short"
	if err := p.Validate(); err == nil {
		t.Error("malformed agentkit commit must fail closed")
	}
	p = testProvenance()
	pins := testPins()
	pins.SpecRevision = 8
	if err := p.Verify(pins); err == nil {
		t.Error("stale spec revision pin must fail closed")
	}
	pins = testPins()
	pins.AgentKitCommit = strings.Repeat("0", 40)
	if err := p.Verify(pins); err == nil {
		t.Error("agentkit commit drift must fail closed")
	}
	pins = testPins()
	pins.NetworkPolicyHash = "sha256:" + strings.Repeat("f", 64)
	if err := p.Verify(pins); err == nil {
		t.Error("network policy drift must fail closed")
	}
	p = testProvenance()
	p.RuntimeKind = RuntimeAWSECSFargate // Fargate doc on GCP placement
	if err := p.Validate(); err == nil {
		t.Error("cross-cloud runtime placement must fail closed")
	}
}
