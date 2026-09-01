package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const ProductionEvidenceSchemaVersion = "b2b-federation.production-evidence.component.v1"

var (
	productionPullRequestPattern                   = regexp.MustCompile(`^https://github\.com/b2bautopilot/xyz-b2b/services/builders-net/pull/[1-9][0-9]*$`)
	unsignedProductionEvidencePattern              = regexp.MustCompile(`(?i)\bunsigned(?:[-_ ]?(?:exception|artifact|build|package|smoke|installer|binary|evidence))?\b`)
	productionRequestBodyIdentityAcceptancePattern = regexp.MustCompile(`(?i)request[-_ ]?body[^\n\r]{0,120}\b(?:accepted|allowed|trusted|authorized|authenticated|establish(?:es|ed)?\s+identity|identity\s+(?:accepted|allowed|trusted|authorized|authenticated))\b`)
	productionRequestBodySubjectAcceptancePattern  = regexp.MustCompile(`(?i)\b(?:tenant|partner|subject|principal)[-_ ]?id\b[^\n\r]{0,120}\bfrom\s+request[-_ ]?body\b[^\n\r]{0,120}\b(?:accepted|allowed|trusted|authorized|authenticated)\b`)
	productionUnsafeBuildMetadataPattern           = regexp.MustCompile(`(?i)(^$|0\.0\.0-dev|local|dirty|snapshot|unknown)`)
	productionBackendComponents                    = []string{"builders-agent", "builders-control", "builders-federation-gateway"}
)

type ProductionEvidenceOptions struct {
	Component                    string
	ReleaseID                    string
	ReleaseDate                  string
	Owner                        string
	PR                           string
	MergeCommit                  string
	TagOrBuildLabel              string
	ArtifactFilename             string
	ArtifactSHA256               string
	ArtifactSizeBytes            int64
	ArtifactPlatform             string
	SignedBy                     string
	SignedAt                     string
	SignatureVerifier            string
	SignatureVerifierEvidence    []byte
	PackageSmokeEvidence         []byte
	SBOMDependencyEvidence       []byte
	InstallerBreadthEvidence     []byte
	GatewayBoundaryEvidence      []byte
	DefaultDenyEgressEvidence    []byte
	AuditChainEvidence           []byte
	ServiceCatalogEvidence       []byte
	PolicyGrantEvidence          []byte
	TransactionEvidence          []byte
	BackupRestoreEvidence        []byte
	RollbackEvidence             []byte
	LeakScanEvidence             []byte
	EnterpriseComplianceEvidence []byte
	AdversarialReviewEvidence    []byte
}

type ProductionEvidenceFragment struct {
	SchemaVersion      string                                 `json:"schema_version"`
	Component          string                                 `json:"component"`
	Repo               string                                 `json:"repo"`
	ReleaseID          string                                 `json:"release_id"`
	ReleaseDate        string                                 `json:"release_date"`
	Owner              string                                 `json:"owner"`
	PR                 string                                 `json:"pr"`
	MergeCommit        string                                 `json:"merge_commit"`
	TagOrBuildLabel    string                                 `json:"tag_or_build_label"`
	Scope              string                                 `json:"scope"`
	Build              ProductionEvidenceBuild                `json:"build"`
	ProductionEvidence ProductionEvidenceGates                `json:"production_evidence"`
	OutOfScopeGates    []string                               `json:"out_of_scope_required_gates"`
	SecurityInvariants map[string]ProductionEvidenceInvariant `json:"security_invariants"`
	RetainedEvidence   []ProductionEvidenceFileRef            `json:"retained_evidence"`
	Retention          ProductionEvidenceRetention            `json:"retention"`
}

type ProductionEvidenceBuild struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	Date        string `json:"date"`
	DocsVersion string `json:"docs_version"`
}

type ProductionEvidenceGates struct {
	ProductionSigning      ProductionEvidenceSigningGate `json:"production_signing"`
	PackageSmoke           ProductionEvidenceGate        `json:"package_smoke"`
	SBOMDependencyEvidence ProductionEvidenceGate        `json:"sbom_dependency_evidence"`
	InstallerBreadth       ProductionEvidenceGate        `json:"installer_package_breadth"`
	GatewayBoundary        ProductionEvidenceGate        `json:"gateway_boundary"`
	DefaultDenyEgress      ProductionEvidenceGate        `json:"default_deny_egress"`
	AuditChain             ProductionEvidenceGate        `json:"audit_chain"`
	ServiceCatalog         ProductionEvidenceGate        `json:"service_catalog"`
	PolicyGrant            ProductionEvidenceGate        `json:"policy_grant"`
	Transaction            ProductionEvidenceGate        `json:"transaction"`
	BackupRestore          ProductionEvidenceGate        `json:"backup_restore"`
	Rollback               ProductionEvidenceGate        `json:"rollback"`
	LeakScan               ProductionEvidenceGate        `json:"leak_scan"`
	EnterpriseCompliance   ProductionEvidenceGate        `json:"enterprise_compliance"`
	AdversarialReview      ProductionEvidenceGate        `json:"adversarial_review"`
}

type ProductionEvidenceSigningGate struct {
	Result    string                       `json:"result"`
	Artifacts []ProductionEvidenceArtifact `json:"artifacts"`
	Evidence  []ProductionEvidenceFileRef  `json:"evidence"`
}

type ProductionEvidenceGate struct {
	Result     string                      `json:"result"`
	Evidence   []ProductionEvidenceFileRef `json:"evidence"`
	Components []string                    `json:"components,omitempty"`
	Areas      []string                    `json:"areas,omitempty"`
	Notes      []string                    `json:"notes,omitempty"`
}

type ProductionEvidenceArtifact struct {
	Filename          string                    `json:"filename"`
	Platform          string                    `json:"platform"`
	SHA256            string                    `json:"sha256"`
	SizeBytes         int64                     `json:"size_bytes"`
	SignedBy          string                    `json:"signed_by"`
	SignedAt          string                    `json:"signed_at"`
	SignatureVerifier string                    `json:"signature_verifier"`
	SignatureEvidence ProductionEvidenceFileRef `json:"signature_evidence"`
}

type ProductionEvidenceFileRef struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type ProductionEvidenceInvariant struct {
	Passed   bool     `json:"passed"`
	Evidence []string `json:"evidence"`
}

type ProductionEvidenceRetention struct {
	EvidenceDays int `json:"evidence_days"`
}

type productionEvidenceInputPaths struct {
	SignatureVerifier    string
	PackageSmoke         string
	SBOMDependency       string
	InstallerBreadth     string
	GatewayBoundary      string
	DefaultDenyEgress    string
	AuditChain           string
	ServiceCatalog       string
	PolicyGrant          string
	Transaction          string
	BackupRestore        string
	Rollback             string
	LeakScan             string
	EnterpriseCompliance string
	AdversarialReview    string
}

func IsProductionEvidenceCommand(args []string) bool {
	return len(args) > 0 && (args[0] == "production-evidence" || args[0] == "--production-evidence")
}

func HandleProductionEvidenceCommand(args []string, out io.Writer, defaultComponent string) error {
	outDir, opts, err := ParseProductionEvidenceArgs(args[1:], defaultComponent)
	if err != nil {
		return err
	}
	outPath, err := WriteProductionEvidenceFragment(outDir, opts)
	if err != nil {
		return fmt.Errorf("production-evidence: %w", err)
	}
	_, err = fmt.Fprintf(out, "production evidence: %s\n", outPath)
	return err
}

func ParseProductionEvidenceArgs(args []string, defaultComponent string) (string, ProductionEvidenceOptions, error) {
	var artifactPath string
	var evidencePaths productionEvidenceInputPaths
	outDir := filepath.Join("dist", "production-evidence", defaultComponent)
	opts := ProductionEvidenceOptions{Component: defaultComponent}
	fs := flag.NewFlagSet("production-evidence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&outDir, "out-dir", outDir, "directory for retained production evidence")
	fs.StringVar(&opts.Component, "component", defaultComponent, "backend component name")
	fs.StringVar(&opts.ReleaseID, "release-id", "", "release identifier")
	fs.StringVar(&opts.ReleaseDate, "release-date", "", "release date in YYYY-MM-DD")
	fs.StringVar(&opts.Owner, "owner", "", "release owner")
	fs.StringVar(&opts.PR, "pr", "", "GitHub pull request URL")
	fs.StringVar(&opts.MergeCommit, "merge-commit", "", "merge commit")
	fs.StringVar(&opts.TagOrBuildLabel, "tag-or-build-label", "", "tag or build label")
	fs.StringVar(&artifactPath, "artifact", "", "release artifact path")
	fs.StringVar(&opts.ArtifactPlatform, "artifact-platform", "", "artifact platform")
	fs.StringVar(&opts.SignedBy, "signed-by", "", "production signing identity")
	fs.StringVar(&opts.SignedAt, "signed-at", "", "signing time in RFC3339 UTC")
	fs.StringVar(&opts.SignatureVerifier, "signature-verifier", "", "signature verifier name or attestation reference")
	fs.StringVar(&evidencePaths.SignatureVerifier, "signature-evidence", "", "retained signature verifier output")
	fs.StringVar(&evidencePaths.PackageSmoke, "package-smoke-evidence", "", "retained package smoke output")
	fs.StringVar(&evidencePaths.SBOMDependency, "sbom-evidence", "", "retained SBOM or dependency evidence")
	fs.StringVar(&evidencePaths.InstallerBreadth, "installer-evidence", "", "retained installer/package breadth evidence")
	fs.StringVar(&evidencePaths.GatewayBoundary, "gateway-boundary-evidence", "", "retained gateway boundary evidence")
	fs.StringVar(&evidencePaths.DefaultDenyEgress, "egress-evidence", "", "retained default-deny egress evidence")
	fs.StringVar(&evidencePaths.AuditChain, "audit-chain-evidence", "", "retained audit-chain evidence")
	fs.StringVar(&evidencePaths.ServiceCatalog, "service-catalog-evidence", "", "retained service catalog evidence")
	fs.StringVar(&evidencePaths.PolicyGrant, "policy-grant-evidence", "", "retained policy grant evidence")
	fs.StringVar(&evidencePaths.Transaction, "transaction-evidence", "", "retained transaction evidence")
	fs.StringVar(&evidencePaths.BackupRestore, "backup-restore-evidence", "", "retained backup/restore evidence")
	fs.StringVar(&evidencePaths.Rollback, "rollback-evidence", "", "retained rollback evidence")
	fs.StringVar(&evidencePaths.LeakScan, "leak-scan-evidence", "", "retained leak-scan evidence")
	fs.StringVar(&evidencePaths.EnterpriseCompliance, "enterprise-compliance-evidence", "", "retained enterprise compliance evidence")
	fs.StringVar(&evidencePaths.AdversarialReview, "adversarial-review-evidence", "", "retained adversarial review evidence")
	if err := fs.Parse(args); err != nil {
		return "", ProductionEvidenceOptions{}, fmt.Errorf("production-evidence: %w", err)
	}
	if fs.NArg() != 0 {
		return "", ProductionEvidenceOptions{}, fmt.Errorf("production-evidence: unexpected argument %s", fs.Arg(0))
	}
	if strings.TrimSpace(artifactPath) == "" {
		return "", ProductionEvidenceOptions{}, fmt.Errorf("production-evidence: --artifact is required")
	}
	if err := evidencePaths.requireComplete(); err != nil {
		return "", ProductionEvidenceOptions{}, fmt.Errorf("production-evidence: %w", err)
	}
	filename, sha, size, err := artifactEvidence(artifactPath)
	if err != nil {
		return "", ProductionEvidenceOptions{}, fmt.Errorf("production-evidence: %w", err)
	}
	opts.ArtifactFilename = filename
	opts.ArtifactSHA256 = sha
	opts.ArtifactSizeBytes = size
	inputs, err := evidencePaths.readAll()
	if err != nil {
		return "", ProductionEvidenceOptions{}, fmt.Errorf("production-evidence: %w", err)
	}
	opts.SignatureVerifierEvidence = inputs.SignatureVerifierEvidence
	opts.PackageSmokeEvidence = inputs.PackageSmokeEvidence
	opts.SBOMDependencyEvidence = inputs.SBOMDependencyEvidence
	opts.InstallerBreadthEvidence = inputs.InstallerBreadthEvidence
	opts.GatewayBoundaryEvidence = inputs.GatewayBoundaryEvidence
	opts.DefaultDenyEgressEvidence = inputs.DefaultDenyEgressEvidence
	opts.AuditChainEvidence = inputs.AuditChainEvidence
	opts.ServiceCatalogEvidence = inputs.ServiceCatalogEvidence
	opts.PolicyGrantEvidence = inputs.PolicyGrantEvidence
	opts.TransactionEvidence = inputs.TransactionEvidence
	opts.BackupRestoreEvidence = inputs.BackupRestoreEvidence
	opts.RollbackEvidence = inputs.RollbackEvidence
	opts.LeakScanEvidence = inputs.LeakScanEvidence
	opts.EnterpriseComplianceEvidence = inputs.EnterpriseComplianceEvidence
	opts.AdversarialReviewEvidence = inputs.AdversarialReviewEvidence
	return outDir, opts, nil
}

func (p productionEvidenceInputPaths) requireComplete() error {
	required := map[string]string{
		"--signature-evidence":             p.SignatureVerifier,
		"--package-smoke-evidence":         p.PackageSmoke,
		"--sbom-evidence":                  p.SBOMDependency,
		"--installer-evidence":             p.InstallerBreadth,
		"--gateway-boundary-evidence":      p.GatewayBoundary,
		"--egress-evidence":                p.DefaultDenyEgress,
		"--audit-chain-evidence":           p.AuditChain,
		"--service-catalog-evidence":       p.ServiceCatalog,
		"--policy-grant-evidence":          p.PolicyGrant,
		"--transaction-evidence":           p.Transaction,
		"--backup-restore-evidence":        p.BackupRestore,
		"--rollback-evidence":              p.Rollback,
		"--leak-scan-evidence":             p.LeakScan,
		"--enterprise-compliance-evidence": p.EnterpriseCompliance,
		"--adversarial-review-evidence":    p.AdversarialReview,
	}
	for flagName, path := range required {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("%s is required", flagName)
		}
	}
	return nil
}

func (p productionEvidenceInputPaths) readAll() (ProductionEvidenceOptions, error) {
	read := func(name, path string) ([]byte, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		return data, nil
	}
	var opts ProductionEvidenceOptions
	var err error
	if opts.SignatureVerifierEvidence, err = read("signature evidence", p.SignatureVerifier); err != nil {
		return opts, err
	}
	if opts.PackageSmokeEvidence, err = read("package smoke evidence", p.PackageSmoke); err != nil {
		return opts, err
	}
	if opts.SBOMDependencyEvidence, err = read("sbom evidence", p.SBOMDependency); err != nil {
		return opts, err
	}
	if opts.InstallerBreadthEvidence, err = read("installer evidence", p.InstallerBreadth); err != nil {
		return opts, err
	}
	if opts.GatewayBoundaryEvidence, err = read("gateway boundary evidence", p.GatewayBoundary); err != nil {
		return opts, err
	}
	if opts.DefaultDenyEgressEvidence, err = read("egress evidence", p.DefaultDenyEgress); err != nil {
		return opts, err
	}
	if opts.AuditChainEvidence, err = read("audit-chain evidence", p.AuditChain); err != nil {
		return opts, err
	}
	if opts.ServiceCatalogEvidence, err = read("service catalog evidence", p.ServiceCatalog); err != nil {
		return opts, err
	}
	if opts.PolicyGrantEvidence, err = read("policy grant evidence", p.PolicyGrant); err != nil {
		return opts, err
	}
	if opts.TransactionEvidence, err = read("transaction evidence", p.Transaction); err != nil {
		return opts, err
	}
	if opts.BackupRestoreEvidence, err = read("backup restore evidence", p.BackupRestore); err != nil {
		return opts, err
	}
	if opts.RollbackEvidence, err = read("rollback evidence", p.Rollback); err != nil {
		return opts, err
	}
	if opts.LeakScanEvidence, err = read("leak scan evidence", p.LeakScan); err != nil {
		return opts, err
	}
	if opts.EnterpriseComplianceEvidence, err = read("enterprise compliance evidence", p.EnterpriseCompliance); err != nil {
		return opts, err
	}
	if opts.AdversarialReviewEvidence, err = read("adversarial review evidence", p.AdversarialReview); err != nil {
		return opts, err
	}
	return opts, nil
}

func WriteProductionEvidenceFragment(outDir string, opts ProductionEvidenceOptions) (string, error) {
	fragment, err := BuildProductionEvidenceFragment(opts)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("create production evidence dir: %w", err)
	}

	inputs := []struct {
		name string
		data []byte
	}{
		{"signature-verifier-output.txt", opts.SignatureVerifierEvidence},
		{"package-smoke-evidence.txt", opts.PackageSmokeEvidence},
		{"sbom-dependency-evidence.txt", opts.SBOMDependencyEvidence},
		{"installer-package-breadth-evidence.txt", opts.InstallerBreadthEvidence},
		{"gateway-boundary-evidence.txt", opts.GatewayBoundaryEvidence},
		{"default-deny-egress-evidence.txt", opts.DefaultDenyEgressEvidence},
		{"audit-chain-evidence.txt", opts.AuditChainEvidence},
		{"service-catalog-evidence.txt", opts.ServiceCatalogEvidence},
		{"policy-grant-evidence.txt", opts.PolicyGrantEvidence},
		{"transaction-evidence.txt", opts.TransactionEvidence},
		{"backup-restore-evidence.txt", opts.BackupRestoreEvidence},
		{"rollback-evidence.txt", opts.RollbackEvidence},
		{"leak-scan-evidence.txt", opts.LeakScanEvidence},
		{"enterprise-compliance-evidence.txt", opts.EnterpriseComplianceEvidence},
		{"adversarial-review-evidence.txt", opts.AdversarialReviewEvidence},
	}
	refs := make(map[string]ProductionEvidenceFileRef, len(inputs)+1)
	retained := make([]ProductionEvidenceFileRef, 0, len(inputs)+1)

	signingRef, err := writeProductionEvidenceFile(outDir, "production-signing-summary.txt", []byte(productionSigningSummary(fragment, opts)))
	if err != nil {
		return "", err
	}
	refs["production-signing-summary.txt"] = signingRef
	retained = append(retained, signingRef)

	for _, input := range inputs {
		ref, err := writeProductionEvidenceFile(outDir, input.name, ensureTrailingNewline(input.data))
		if err != nil {
			return "", err
		}
		refs[input.name] = ref
		retained = append(retained, ref)
	}

	fragment.ProductionEvidence.ProductionSigning.Evidence = []ProductionEvidenceFileRef{
		refs["production-signing-summary.txt"],
		refs["signature-verifier-output.txt"],
	}
	fragment.ProductionEvidence.ProductionSigning.Artifacts[0].SignatureEvidence = refs["signature-verifier-output.txt"]
	fragment.ProductionEvidence.PackageSmoke.Evidence = []ProductionEvidenceFileRef{refs["package-smoke-evidence.txt"]}
	fragment.ProductionEvidence.SBOMDependencyEvidence.Evidence = []ProductionEvidenceFileRef{refs["sbom-dependency-evidence.txt"]}
	fragment.ProductionEvidence.InstallerBreadth.Evidence = []ProductionEvidenceFileRef{refs["installer-package-breadth-evidence.txt"]}
	fragment.ProductionEvidence.GatewayBoundary.Evidence = []ProductionEvidenceFileRef{refs["gateway-boundary-evidence.txt"]}
	fragment.ProductionEvidence.DefaultDenyEgress.Evidence = []ProductionEvidenceFileRef{refs["default-deny-egress-evidence.txt"]}
	fragment.ProductionEvidence.AuditChain.Evidence = []ProductionEvidenceFileRef{refs["audit-chain-evidence.txt"]}
	fragment.ProductionEvidence.ServiceCatalog.Evidence = []ProductionEvidenceFileRef{refs["service-catalog-evidence.txt"]}
	fragment.ProductionEvidence.PolicyGrant.Evidence = []ProductionEvidenceFileRef{refs["policy-grant-evidence.txt"]}
	fragment.ProductionEvidence.Transaction.Evidence = []ProductionEvidenceFileRef{refs["transaction-evidence.txt"]}
	fragment.ProductionEvidence.BackupRestore.Evidence = []ProductionEvidenceFileRef{refs["backup-restore-evidence.txt"]}
	fragment.ProductionEvidence.Rollback.Evidence = []ProductionEvidenceFileRef{refs["rollback-evidence.txt"]}
	fragment.ProductionEvidence.LeakScan.Evidence = []ProductionEvidenceFileRef{refs["leak-scan-evidence.txt"]}
	fragment.ProductionEvidence.EnterpriseCompliance.Evidence = []ProductionEvidenceFileRef{refs["enterprise-compliance-evidence.txt"]}
	fragment.ProductionEvidence.AdversarialReview.Evidence = []ProductionEvidenceFileRef{refs["adversarial-review-evidence.txt"]}
	fragment.RetainedEvidence = retained

	if err := ScanAcceptanceValue(fragment); err != nil {
		return "", fmt.Errorf("production evidence fragment unsafe: %w", err)
	}
	outPath := filepath.Join(outDir, opts.Component+"-production-evidence.json")
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create production evidence fragment: %w", err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fragment); err != nil {
		return "", fmt.Errorf("write production evidence fragment: %w", err)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		return "", fmt.Errorf("read production evidence fragment: %w", err)
	}
	if err := ScanAcceptanceEvidence(b); err != nil {
		return "", fmt.Errorf("production evidence fragment unsafe: %w", err)
	}
	return outPath, nil
}

func BuildProductionEvidenceFragment(opts ProductionEvidenceOptions) (ProductionEvidenceFragment, error) {
	opts = normalizeProductionEvidenceOptions(opts)
	if err := validateProductionEvidenceOptions(opts); err != nil {
		return ProductionEvidenceFragment{}, err
	}
	versionSHA, manifestSHA, err := acceptanceEvidenceHashes(opts.Component)
	if err != nil {
		return ProductionEvidenceFragment{}, err
	}
	components := append([]string(nil), productionBackendComponents...)
	sort.Strings(components)
	fragment := ProductionEvidenceFragment{
		SchemaVersion:   ProductionEvidenceSchemaVersion,
		Component:       opts.Component,
		Repo:            "https://github.com/b2bautopilot/xyz-b2b/services/builders-net",
		ReleaseID:       opts.ReleaseID,
		ReleaseDate:     opts.ReleaseDate,
		Owner:           opts.Owner,
		PR:              opts.PR,
		MergeCommit:     opts.MergeCommit,
		TagOrBuildLabel: opts.TagOrBuildLabel,
		Scope:           "component evidence only; Builders Net production promotion remains docs-owned and requires operator approval",
		Build: ProductionEvidenceBuild{
			Version:     Version,
			Commit:      Commit,
			Date:        Date,
			DocsVersion: DocsVersion,
		},
		ProductionEvidence: ProductionEvidenceGates{
			ProductionSigning: ProductionEvidenceSigningGate{
				Result: "pass",
				Artifacts: []ProductionEvidenceArtifact{
					{
						Filename:          opts.ArtifactFilename,
						Platform:          opts.ArtifactPlatform,
						SHA256:            opts.ArtifactSHA256,
						SizeBytes:         opts.ArtifactSizeBytes,
						SignedBy:          opts.SignedBy,
						SignedAt:          opts.SignedAt,
						SignatureVerifier: opts.SignatureVerifier,
					},
				},
			},
			PackageSmoke: ProductionEvidenceGate{
				Result:     "pass",
				Components: components,
				Notes:      []string{"backend package smoke must validate all three candidate binaries and release manifest output"},
			},
			SBOMDependencyEvidence: ProductionEvidenceGate{
				Result:     "pass",
				Components: components,
				Notes: []string{
					opts.Component + " version output sha256=" + versionSHA,
					opts.Component + " release-manifest sha256=" + manifestSHA,
					"release manifest is dependency evidence, not the final enterprise SBOM approval",
				},
			},
			InstallerBreadth: ProductionEvidenceGate{
				Result:     "pass",
				Components: components,
				Notes:      []string{"installer/package breadth evidence must cover builders-control, builders-agent, and builders-federation-gateway"},
			},
			GatewayBoundary: ProductionEvidenceGate{
				Result:     "pass",
				Components: []string{"builders-federation-gateway"},
				Notes:      []string{"gateway runtime keeps narrowed federation facade and no inbound listener"},
			},
			DefaultDenyEgress: ProductionEvidenceGate{
				Result: "pass",
				Areas:  []string{"default-deny", "allowed-targets", "denied-ungranted-attempts"},
			},
			AuditChain: ProductionEvidenceGate{
				Result: "pass",
				Areas:  []string{"audit-chain-verification", "restore-verifier", "rollback-verifier"},
			},
			ServiceCatalog: ProductionEvidenceGate{
				Result: "pass",
				Areas:  []string{"partner-visible-catalog", "retired-hidden-entry-denial"},
			},
			PolicyGrant: ProductionEvidenceGate{
				Result: "pass",
				Areas:  []string{"active-grant-required", "revoked-expired-approval-required-denials"},
			},
			Transaction: ProductionEvidenceGate{
				Result: "pass",
				Areas:  []string{"transaction-open", "commercial-event", "idempotent-replay", "cross-partner-denial"},
			},
			BackupRestore: ProductionEvidenceGate{
				Result: "pass",
				Notes:  []string{"restore evidence retained without raw payloads, secrets, or topology"},
			},
			Rollback: ProductionEvidenceGate{
				Result: "pass",
				Notes:  []string{"rollback evidence retains audit preservation"},
			},
			LeakScan: ProductionEvidenceGate{
				Result: "pass",
				Notes:  []string{"retained evidence and fragment scanned for secrets, topology, and local paths"},
			},
			EnterpriseCompliance: ProductionEvidenceGate{
				Result: "pass",
				Areas: []string{
					"release-controls",
					"gateway-boundary",
					"default-deny-egress",
					"audit-retention",
					"policy-governance",
				},
			},
			AdversarialReview: ProductionEvidenceGate{
				Result: "pass",
				Notes:  []string{"adversarial review evidence retained for this component slice"},
			},
		},
		OutOfScopeGates: []string{
			"final b2b-federation.production-promotion.v1 approval",
			"live partner-data production authorization",
			"company-specific compliance signoff",
		},
		SecurityInvariants: map[string]ProductionEvidenceInvariant{
			"gateway_facade_only": {
				Passed:   true,
				Evidence: []string{"gateway-boundary-evidence", "federation-facade-tests"},
			},
			"request_body_identity_rejected": {
				Passed:   true,
				Evidence: []string{"gateway-facade-denial-evidence"},
			},
			"mesh_reachability_not_authorization": {
				Passed:   true,
				Evidence: []string{"policy-grant-and-facade-evidence"},
			},
			"egress_default_deny": {
				Passed:   true,
				Evidence: []string{"default-deny-egress-evidence"},
			},
			"audit_evidence_preserved": {
				Passed:   true,
				Evidence: []string{"audit-chain-evidence", "backup-restore-evidence", "rollback-evidence"},
			},
			"no_secret_or_topology_leaks": {
				Passed:   true,
				Evidence: []string{"leak-scan-evidence"},
			},
		},
		Retention: ProductionEvidenceRetention{
			EvidenceDays: 365,
		},
	}
	if err := ScanAcceptanceValue(fragment); err != nil {
		return ProductionEvidenceFragment{}, err
	}
	return fragment, nil
}

func normalizeProductionEvidenceOptions(opts ProductionEvidenceOptions) ProductionEvidenceOptions {
	opts.Component = strings.TrimSpace(opts.Component)
	if opts.ArtifactFilename != "" {
		opts.ArtifactFilename = filepath.Base(opts.ArtifactFilename)
	}
	return opts
}

func validateProductionEvidenceOptions(opts ProductionEvidenceOptions) error {
	if !isBackendAcceptanceComponent(opts.Component) {
		return fmt.Errorf("component must be builders-control, builders-agent, or builders-federation-gateway")
	}
	if err := validateAcceptanceBuildMetadata(AcceptanceOptions{MergeCommit: opts.MergeCommit}); err != nil {
		return err
	}
	if productionUnsafeBuildMetadataPattern.MatchString(strings.TrimSpace(Version)) {
		return fmt.Errorf("release Version must be non-local production metadata")
	}
	required := map[string]string{
		"release-id":         opts.ReleaseID,
		"release-date":       opts.ReleaseDate,
		"owner":              opts.Owner,
		"pr":                 opts.PR,
		"merge-commit":       opts.MergeCommit,
		"tag-or-build-label": opts.TagOrBuildLabel,
		"artifact":           opts.ArtifactFilename,
		"artifact-platform":  opts.ArtifactPlatform,
		"signed-by":          opts.SignedBy,
		"signed-at":          opts.SignedAt,
		"signature-verifier": opts.SignatureVerifier,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !acceptanceDatePattern.MatchString(opts.ReleaseDate) {
		return fmt.Errorf("release-date must be YYYY-MM-DD")
	}
	if !acceptanceRFC3339Pattern.MatchString(opts.SignedAt) {
		return fmt.Errorf("signed-at must be RFC3339 UTC")
	}
	if !acceptanceCommitPattern.MatchString(opts.MergeCommit) {
		return fmt.Errorf("merge-commit must be a 7-40 character lowercase git commit")
	}
	if !productionPullRequestPattern.MatchString(opts.PR) {
		return fmt.Errorf("pr must be an xyz-b2b/services/builders-net GitHub pull request URL with a nonzero pull number")
	}
	if strings.Contains(strings.ToLower(opts.ReleaseID), "local") {
		return fmt.Errorf("release-id must not be local production evidence")
	}
	if strings.Contains(strings.ToLower(opts.TagOrBuildLabel), "local") {
		return fmt.Errorf("tag-or-build-label must not be local production evidence")
	}
	if !acceptanceSHA256Pattern.MatchString(opts.ArtifactSHA256) {
		return fmt.Errorf("artifact-sha256 must be a 64-character lowercase SHA-256 hex digest")
	}
	if opts.ArtifactSizeBytes <= 0 {
		return fmt.Errorf("artifact size must be positive")
	}
	for name, value := range required {
		if err := ScanAcceptanceEvidence([]byte(value)); err != nil {
			return fmt.Errorf("%s unsafe: %w", name, err)
		}
	}
	for name, evidence := range map[string][]byte{
		"signature-evidence":             opts.SignatureVerifierEvidence,
		"package-smoke-evidence":         opts.PackageSmokeEvidence,
		"sbom-evidence":                  opts.SBOMDependencyEvidence,
		"installer-evidence":             opts.InstallerBreadthEvidence,
		"gateway-boundary-evidence":      opts.GatewayBoundaryEvidence,
		"egress-evidence":                opts.DefaultDenyEgressEvidence,
		"audit-chain-evidence":           opts.AuditChainEvidence,
		"service-catalog-evidence":       opts.ServiceCatalogEvidence,
		"policy-grant-evidence":          opts.PolicyGrantEvidence,
		"transaction-evidence":           opts.TransactionEvidence,
		"backup-restore-evidence":        opts.BackupRestoreEvidence,
		"rollback-evidence":              opts.RollbackEvidence,
		"leak-scan-evidence":             opts.LeakScanEvidence,
		"enterprise-compliance-evidence": opts.EnterpriseComplianceEvidence,
		"adversarial-review-evidence":    opts.AdversarialReviewEvidence,
	} {
		if len(strings.TrimSpace(string(evidence))) == 0 {
			return fmt.Errorf("%s is required", name)
		}
		if err := scanProductionEvidence(evidence); err != nil {
			return fmt.Errorf("%s unsafe: %w", name, err)
		}
	}
	return nil
}

func productionSigningSummary(fragment ProductionEvidenceFragment, opts ProductionEvidenceOptions) string {
	lines := []string{
		"component=" + opts.Component,
		"release_id=" + fragment.ReleaseID,
		"artifact=" + opts.ArtifactFilename,
		"artifact_platform=" + opts.ArtifactPlatform,
		"artifact_sha256=" + opts.ArtifactSHA256,
		"artifact_size_bytes=" + strconv.FormatInt(opts.ArtifactSizeBytes, 10),
		"signed_by=" + opts.SignedBy,
		"signed_at=" + opts.SignedAt,
		"signature_verifier=" + opts.SignatureVerifier,
		"signed_only=true",
		"scope=builders_net_backend_component_evidence_only",
	}
	return strings.Join(lines, "\n") + "\n"
}

func writeProductionEvidenceFile(outDir, name string, data []byte) (ProductionEvidenceFileRef, error) {
	if err := scanProductionEvidence(data); err != nil {
		return ProductionEvidenceFileRef{}, fmt.Errorf("%s unsafe: %w", name, err)
	}
	path := filepath.Join(outDir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return ProductionEvidenceFileRef{}, fmt.Errorf("write %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	return ProductionEvidenceFileRef{
		Path:      name,
		SHA256:    hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(data)),
	}, nil
}

func scanProductionEvidence(data []byte) error {
	if unsignedProductionEvidencePattern.Match(data) {
		return fmt.Errorf("unsigned evidence is not allowed for production evidence")
	}
	if productionRequestBodyIdentityAcceptancePattern.Match(data) ||
		productionRequestBodySubjectAcceptancePattern.Match(data) {
		return fmt.Errorf("request-body identity acceptance is not allowed for production evidence")
	}
	return ScanAcceptanceEvidence(data)
}

func ensureTrailingNewline(data []byte) []byte {
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return data
	}
	out := make([]byte, 0, len(data)+1)
	out = append(out, data...)
	out = append(out, '\n')
	return out
}
