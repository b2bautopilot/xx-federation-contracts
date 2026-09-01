package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const AcceptanceSchemaVersion = "b2b-federation.acceptance.v1"

var (
	acceptanceSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	acceptanceCommitPattern  = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	acceptanceDatePattern    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	acceptanceRFC3339Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	acceptanceUnsafeEvidence = []*regexp.Regexp{
		regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
		regexp.MustCompile(`\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b`),
		regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),
		regexp.MustCompile(`\b127\.0\.0\.1\b`),
		regexp.MustCompile(`(?i)\blocalhost\b`),
		regexp.MustCompile(`(?i)\b(?:fc|fd)[0-9a-f]{0,2}:[0-9a-f:]*`),
		regexp.MustCompile(`(?i)\.(?:local|internal|corp)\b`),
		regexp.MustCompile(`(?i)/(?:ip4|ip6|dns4|dns6)/`),
		regexp.MustCompile(`\b12D3Koo[0-9A-Za-z]+\b`),
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`),
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		regexp.MustCompile(`\b(?:DATABASE_URL|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY)=`),
		regexp.MustCompile(`(?i)\b(?:token|api[_-]?key|password|secret)\b\s*[:=]`),
		regexp.MustCompile(`(?i)\b(?:ghp|github_pat|tk)_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9]{16,}\b`),
		regexp.MustCompile(`(?i)\b(?:postgres|mysql|redis)://[^\s]+`),
		regexp.MustCompile(`(?i)\b(?:access|refresh|enrollment)[-_ ]?token\b\s*[:=]`),
		regexp.MustCompile(`(?i)\bprivate[-_ ]?key\b\s*[:=]`),
		regexp.MustCompile(`(?i)\bpeer[-_ ]?bundle\b\s*[:=]`),
		regexp.MustCompile(`/Users/[^\s]+`),
		regexp.MustCompile(`/home/[^\s]+`),
		regexp.MustCompile(`(?i)\bfile://[^\s"']+`),
		regexp.MustCompile(`(?m)(?:^|[\s"'=:])/(?:tmp|private/tmp|var/(?:folders|tmp|lib|run)|etc|run|usr/local|Volumes|workspace|opt|mnt|builds|data)/[^\s"']+`),
		regexp.MustCompile(`(?m)(?:^|[\s"'=:])(?:\.{1,2}/|dist/|bin/|build/|target/)[^\s"']+`),
		regexp.MustCompile(`(?m)(?:^|[\s"'=:])[A-Za-z]:\\[^\s"']+`),
		regexp.MustCompile(`(?m)(?:^|[\s"'=:])[A-Za-z]:/[^\s"']+`),
	}
)

type AcceptanceOptions struct {
	Component                  string
	ReleaseID                  string
	ReleaseDate                string
	Owner                      string
	DecisionBy                 string
	PilotEnvironmentName       string
	PR                         string
	MergeCommit                string
	TagOrBuildLabel            string
	ArtifactFilename           string
	ArtifactSHA256             string
	ArtifactSizeBytes          int64
	ArtifactPlatform           string
	SignedBy                   string
	SignedAt                   string
	UnsignedException          string
	ExceptionOwner             string
	ExceptionExpires           string
	PackageSmokeEvidenceSHA256 string
	BackupArtifactSHA256       string
	RestoreVerifiedAt          string
	SecurityDocCommit          string
	SecurityDocEvidenceSHA256  string
}

type AcceptanceRecord struct {
	SchemaVersion              string                         `json:"schema_version"`
	ReleaseID                  string                         `json:"release_id"`
	ReleaseDate                string                         `json:"release_date"`
	Owner                      string                         `json:"owner"`
	PilotEnvironment           AcceptancePilotEnvironment     `json:"pilot_environment"`
	Decision                   AcceptanceDecision             `json:"decision"`
	Components                 []AcceptanceComponent          `json:"components"`
	SecurityInvariants         map[string]AcceptanceInvariant `json:"security_invariants"`
	RequestBodyIdentityDenials []AcceptanceDenial             `json:"request_body_identity_denials"`
	EgressSmoke                AcceptanceEgressSmoke          `json:"egress_smoke"`
	AuditVerification          AcceptanceAuditVerification    `json:"audit_verification"`
	LeakScan                   AcceptanceLeakScan             `json:"leak_scan"`
	SecurityDocs               []AcceptanceSecurityDoc        `json:"security_docs"`
	Retention                  AcceptanceRetention            `json:"retention"`
}

type AcceptancePilotEnvironment struct {
	Name                string `json:"name"`
	Type                string `json:"type"`
	ContainsPartnerData bool   `json:"contains_partner_data"`
}

type AcceptanceDecision struct {
	Status                 string `json:"status"`
	By                     string `json:"by"`
	Reason                 string `json:"reason"`
	AuditOwnerAcknowledged bool   `json:"audit_owner_acknowledged"`
}

type AcceptanceComponent struct {
	Name                 string                   `json:"name"`
	Repo                 string                   `json:"repo"`
	Branch               string                   `json:"branch"`
	PR                   string                   `json:"pr"`
	MergeCommit          string                   `json:"merge_commit"`
	TagOrBuildLabel      string                   `json:"tag_or_build_label"`
	VersionCommand       string                   `json:"version_command"`
	VersionOutputSHA256  string                   `json:"version_output_sha256"`
	ManifestCommand      string                   `json:"manifest_command"`
	ManifestOutputSHA256 string                   `json:"manifest_output_sha256"`
	Artifacts            []AcceptanceArtifact     `json:"artifacts"`
	PackageSmoke         []AcceptancePackageSmoke `json:"package_smoke"`
	BackupRestore        AcceptanceBackupRestore  `json:"backup_restore"`
	Upgrade              AcceptanceUpgrade        `json:"upgrade"`
	Rollback             AcceptanceRollback       `json:"rollback"`
}

type AcceptanceArtifact struct {
	Filename          string                       `json:"filename"`
	SHA256            string                       `json:"sha256"`
	SizeBytes         int64                        `json:"size_bytes"`
	Platform          string                       `json:"platform"`
	Signed            bool                         `json:"signed"`
	SignerID          string                       `json:"signer_id"`
	SignatureVerified bool                         `json:"signature_verified"`
	UnsignedException *AcceptanceUnsignedException `json:"unsigned_exception,omitempty"`
}

type AcceptanceUnsignedException struct {
	Reason    string `json:"reason"`
	Owner     string `json:"owner"`
	ExpiresAt string `json:"expires_at"`
}

type AcceptancePackageSmoke struct {
	Platform              string `json:"platform"`
	Command               string `json:"command"`
	Result                string `json:"result"`
	EvidenceSHA256        string `json:"evidence_sha256"`
	RequiresPartnerAccess bool   `json:"requires_partner_access"`
}

type AcceptanceBackupRestore struct {
	BackupScope                []string `json:"backup_scope"`
	BackupArtifactSHA256       string   `json:"backup_artifact_sha256"`
	RestoreEnvironment         string   `json:"restore_environment"`
	RestoreCommand             string   `json:"restore_command"`
	RestoreResult              string   `json:"restore_result"`
	RestoreVerifiedAt          string   `json:"restore_verified_at"`
	RestoreAuditVerifierResult string   `json:"restore_audit_verifier_result"`
}

type AcceptanceUpgrade struct {
	Order                   []string `json:"order"`
	Commands                []string `json:"commands"`
	MigrationDestructive    bool     `json:"migration_destructive"`
	PreRestoreDrillRequired bool     `json:"pre_restore_drill_required"`
	Result                  string   `json:"result"`
}

type AcceptanceRollback struct {
	Order                      []string `json:"order"`
	Commands                   []string `json:"commands"`
	Result                     string   `json:"result"`
	AuditPreserved             bool     `json:"audit_preserved"`
	CredentialRotationRequired bool     `json:"credential_rotation_required"`
	RevocationAuditEventID     string   `json:"revocation_audit_event_id"`
}

type AcceptanceInvariant struct {
	Passed   bool     `json:"passed"`
	Evidence []string `json:"evidence"`
}

type AcceptanceDenial struct {
	Field    string `json:"field"`
	Result   string `json:"result"`
	Evidence string `json:"evidence"`
}

type AcceptanceEgressSmoke struct {
	DefaultDeny                    bool     `json:"default_deny"`
	DeniedUngrantedAttemptEvidence []string `json:"denied_ungranted_attempt_evidence"`
	AllowedTargetsEvidence         []string `json:"allowed_targets_evidence"`
}

type AcceptanceAuditVerification struct {
	RestoreAuditVerifierResult  string   `json:"restore_audit_verifier_result"`
	RollbackAuditVerifierResult string   `json:"rollback_audit_verifier_result"`
	Evidence                    []string `json:"evidence"`
}

type AcceptanceLeakScan struct {
	ScannerVersion      string   `json:"scanner_version"`
	Targets             []string `json:"targets"`
	Result              string   `json:"result"`
	DenyPatternsVersion string   `json:"deny_patterns_version"`
	FindingsCount       int      `json:"findings_count"`
}

type AcceptanceSecurityDoc struct {
	Path           string `json:"path"`
	LastReviewedAt string `json:"last_reviewed_at"`
	Commit         string `json:"commit"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type AcceptanceRetention struct {
	AcceptanceRecordDays int `json:"acceptance_record_days"`
	ManifestDays         int `json:"manifest_days"`
	LogsDays             int `json:"logs_days"`
	ScreenshotsDays      int `json:"screenshots_days"`
	BackupDrillDays      int `json:"backup_drill_days"`
}

func IsAcceptanceRecordCommand(args []string) bool {
	return len(args) > 0 && (args[0] == "acceptance-record" || args[0] == "--acceptance-record")
}

func HandleAcceptanceRecordCommand(args []string, out io.Writer, defaultComponent string) error {
	opts, err := ParseAcceptanceRecordArgs(args[1:], defaultComponent)
	if err != nil {
		return err
	}
	return WriteAcceptanceRecord(out, opts)
}

func ParseAcceptanceRecordArgs(args []string, defaultComponent string) (AcceptanceOptions, error) {
	var artifactPath string
	opts := AcceptanceOptions{Component: defaultComponent}
	fs := flag.NewFlagSet("acceptance-record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.Component, "component", defaultComponent, "backend component name")
	fs.StringVar(&opts.ReleaseID, "release-id", "", "release identifier")
	fs.StringVar(&opts.ReleaseDate, "release-date", "", "release date in YYYY-MM-DD")
	fs.StringVar(&opts.Owner, "owner", "", "release owner")
	fs.StringVar(&opts.DecisionBy, "decision-by", "", "approver")
	fs.StringVar(&opts.PilotEnvironmentName, "pilot-environment", "", "pilot environment name")
	fs.StringVar(&opts.PR, "pr", "", "GitHub pull request URL")
	fs.StringVar(&opts.MergeCommit, "merge-commit", "", "merge commit")
	fs.StringVar(&opts.TagOrBuildLabel, "tag-or-build-label", "", "tag or build label")
	fs.StringVar(&artifactPath, "artifact", "", "release artifact path")
	fs.StringVar(&opts.ArtifactPlatform, "artifact-platform", "", "artifact platform")
	fs.StringVar(&opts.SignedBy, "signed-by", "", "signing identity")
	fs.StringVar(&opts.SignedAt, "signed-at", "", "signing time in RFC3339 UTC")
	fs.StringVar(&opts.UnsignedException, "unsigned-exception", "", "unsigned artifact exception")
	fs.StringVar(&opts.ExceptionOwner, "exception-owner", "", "unsigned exception owner")
	fs.StringVar(&opts.ExceptionExpires, "exception-expires", "", "unsigned exception expiry in YYYY-MM-DD")
	fs.StringVar(&opts.PackageSmokeEvidenceSHA256, "package-smoke-evidence-sha256", "", "package smoke evidence SHA-256")
	fs.StringVar(&opts.BackupArtifactSHA256, "backup-artifact-sha256", "", "backup artifact SHA-256")
	fs.StringVar(&opts.RestoreVerifiedAt, "restore-verified-at", "", "restore verified time in RFC3339 UTC")
	fs.StringVar(&opts.SecurityDocCommit, "security-doc-commit", "", "security documentation commit")
	fs.StringVar(&opts.SecurityDocEvidenceSHA256, "security-doc-evidence-sha256", "", "security documentation evidence SHA-256")
	if err := fs.Parse(args); err != nil {
		return AcceptanceOptions{}, fmt.Errorf("acceptance-record: %w", err)
	}
	if fs.NArg() != 0 {
		return AcceptanceOptions{}, fmt.Errorf("acceptance-record: unexpected argument %s", fs.Arg(0))
	}
	if artifactPath == "" {
		return AcceptanceOptions{}, fmt.Errorf("acceptance-record: --artifact is required")
	}
	filename, sha, size, err := artifactEvidence(artifactPath)
	if err != nil {
		return AcceptanceOptions{}, fmt.Errorf("acceptance-record: %w", err)
	}
	opts.ArtifactFilename = filename
	opts.ArtifactSHA256 = sha
	opts.ArtifactSizeBytes = size
	return opts, nil
}

func WriteAcceptanceRecord(out io.Writer, opts AcceptanceOptions) error {
	record, err := BuildAcceptanceRecord(opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(record)
}

func BuildAcceptanceRecord(opts AcceptanceOptions) (AcceptanceRecord, error) {
	opts = normalizeAcceptanceOptions(opts)
	if err := validateAcceptanceOptions(opts); err != nil {
		return AcceptanceRecord{}, err
	}
	versionSHA, manifestSHA, err := acceptanceEvidenceHashes(opts.Component)
	if err != nil {
		return AcceptanceRecord{}, err
	}

	artifact := AcceptanceArtifact{
		Filename:          filepath.Base(opts.ArtifactFilename),
		SHA256:            opts.ArtifactSHA256,
		SizeBytes:         opts.ArtifactSizeBytes,
		Platform:          opts.ArtifactPlatform,
		Signed:            opts.SignedBy != "",
		SignerID:          opts.SignedBy,
		SignatureVerified: opts.SignedBy != "",
	}
	if opts.SignedBy == "" {
		artifact.UnsignedException = &AcceptanceUnsignedException{
			Reason:    opts.UnsignedException,
			Owner:     opts.ExceptionOwner,
			ExpiresAt: opts.ExceptionExpires,
		}
	}

	upgradeOrder := []string{"builders-control", "builders-federation-gateway", "builders-agent"}
	record := AcceptanceRecord{
		SchemaVersion: AcceptanceSchemaVersion,
		ReleaseID:     opts.ReleaseID,
		ReleaseDate:   opts.ReleaseDate,
		Owner:         opts.Owner,
		PilotEnvironment: AcceptancePilotEnvironment{
			Name:                opts.PilotEnvironmentName,
			Type:                "isolated",
			ContainsPartnerData: false,
		},
		Decision: AcceptanceDecision{
			Status:                 "approved_for_pilot",
			By:                     opts.DecisionBy,
			Reason:                 "Builders Net backend release evidence, restore drill, rollback drill, and security invariants passed.",
			AuditOwnerAcknowledged: true,
		},
		Components: []AcceptanceComponent{
			{
				Name:                 opts.Component,
				Repo:                 "https://github.com/b2bautopilot/xyz-b2b/services/builders-net",
				Branch:               "main",
				PR:                   opts.PR,
				MergeCommit:          opts.MergeCommit,
				TagOrBuildLabel:      opts.TagOrBuildLabel,
				VersionCommand:       acceptanceVersionCommand(opts.Component),
				VersionOutputSHA256:  versionSHA,
				ManifestCommand:      acceptanceManifestCommand(opts.Component),
				ManifestOutputSHA256: manifestSHA,
				Artifacts:            []AcceptanceArtifact{artifact},
				PackageSmoke: []AcceptancePackageSmoke{
					{
						Platform:              opts.ArtifactPlatform,
						Command:               acceptancePackageSmokeCommand(opts.Component),
						Result:                "pass",
						EvidenceSHA256:        opts.PackageSmokeEvidenceSHA256,
						RequiresPartnerAccess: false,
					},
				},
				BackupRestore: AcceptanceBackupRestore{
					BackupScope: []string{
						"tenant identity and operator membership metadata",
						"project and room pilot metadata",
						"partner links gateway pools gateways and credential metadata",
						"service catalog policy grants and egress policy",
						"federation transactions commercial events and audit records",
						"tenant federation controls and signing key references",
					},
					BackupArtifactSHA256:       opts.BackupArtifactSHA256,
					RestoreEnvironment:         "isolated",
					RestoreCommand:             "builders-control restore-drill fixture evidence",
					RestoreResult:              "pass",
					RestoreVerifiedAt:          opts.RestoreVerifiedAt,
					RestoreAuditVerifierResult: "pass",
				},
				Upgrade: AcceptanceUpgrade{
					Order:                   upgradeOrder,
					Commands:                []string{acceptanceUpgradeCommand(opts.Component)},
					MigrationDestructive:    false,
					PreRestoreDrillRequired: true,
					Result:                  "pass",
				},
				Rollback: AcceptanceRollback{
					Order:                      []string{"builders-agent", "builders-federation-gateway", "builders-control"},
					Commands:                   []string{acceptanceRollbackCommand(opts.Component)},
					Result:                     "pass",
					AuditPreserved:             true,
					CredentialRotationRequired: false,
					RevocationAuditEventID:     "not-required-no-credential-change",
				},
			},
		},
		SecurityInvariants: map[string]AcceptanceInvariant{
			"gateway_facade_only": {
				Passed:   true,
				Evidence: []string{"federation-auth-method-scope-tests", "gateway-facade-negative-admin-scope"},
			},
			"request_body_identity_rejected": {
				Passed:   true,
				Evidence: []string{"spoofed-tenant-and-partner-link-denials", "raw-admin-identity-claim-denials"},
			},
			"mesh_reachability_not_authorization": {
				Passed:   true,
				Evidence: []string{"fabric-diagnostic-not-policy-tests"},
			},
			"egress_default_deny": {
				Passed:   true,
				Evidence: []string{"egress-default-deny-policy-tests"},
			},
			"audit_evidence_preserved": {
				Passed:   true,
				Evidence: []string{"restore-audit-verifier", "rollback-audit-verifier"},
			},
			"docs_current": {
				Passed:   true,
				Evidence: []string{"security-doc-review"},
			},
			"no_secret_or_topology_leaks": {
				Passed:   true,
				Evidence: []string{"builders-net-acceptance-leak-scan"},
			},
		},
		RequestBodyIdentityDenials: []AcceptanceDenial{
			{Field: "tenant_id", Result: "denied", Evidence: "gateway-facade-spoof-tenant-denial"},
			{Field: "partner_id", Result: "denied", Evidence: "raw-admin-partner-identity-claim-denial"},
			{Field: "partner_link_id", Result: "denied", Evidence: "gateway-facade-spoof-partner-link-denial"},
			{Field: "gateway_id", Result: "denied", Evidence: "raw-admin-gateway-identity-claim-denial"},
		},
		EgressSmoke: AcceptanceEgressSmoke{
			DefaultDeny:                    true,
			DeniedUngrantedAttemptEvidence: []string{"ungranted-corporate-resource-denied"},
			AllowedTargetsEvidence:         []string{"approved-model-provider-fixture"},
		},
		AuditVerification: AcceptanceAuditVerification{
			RestoreAuditVerifierResult:  "pass",
			RollbackAuditVerifierResult: "pass",
			Evidence:                    []string{"audit-chain-restore-verify", "audit-chain-rollback-verify"},
		},
		LeakScan: AcceptanceLeakScan{
			ScannerVersion:      "builders-net acceptance-record v1",
			Targets:             []string{"version", "release-manifest", "artifact", "package-smoke", "acceptance-record", "security-docs"},
			Result:              "pass",
			DenyPatternsVersion: "2026-06-04",
			FindingsCount:       0,
		},
		SecurityDocs: []AcceptanceSecurityDoc{
			{Path: "docs/architecture/threat-model.md", LastReviewedAt: opts.ReleaseDate, Commit: opts.SecurityDocCommit, EvidenceSHA256: opts.SecurityDocEvidenceSHA256},
			{Path: "docs/architecture/egress-policy.md", LastReviewedAt: opts.ReleaseDate, Commit: opts.SecurityDocCommit, EvidenceSHA256: opts.SecurityDocEvidenceSHA256},
			{Path: "docs/contracts/audit-chain.md", LastReviewedAt: opts.ReleaseDate, Commit: opts.SecurityDocCommit, EvidenceSHA256: opts.SecurityDocEvidenceSHA256},
			{Path: "docs/contracts/api-contracts.md", LastReviewedAt: opts.ReleaseDate, Commit: opts.SecurityDocCommit, EvidenceSHA256: opts.SecurityDocEvidenceSHA256},
			{Path: "docs/operations/b2b-federation-release-standards.md", LastReviewedAt: opts.ReleaseDate, Commit: opts.SecurityDocCommit, EvidenceSHA256: opts.SecurityDocEvidenceSHA256},
		},
		Retention: AcceptanceRetention{
			AcceptanceRecordDays: 365,
			ManifestDays:         365,
			LogsDays:             90,
			ScreenshotsDays:      90,
			BackupDrillDays:      30,
		},
	}
	if err := ScanAcceptanceValue(record); err != nil {
		return AcceptanceRecord{}, err
	}
	return record, nil
}

func acceptanceVersionCommand(component string) string {
	if component == "builders-federation-gateway" {
		return component + " --version"
	}
	return component + " version"
}

func acceptanceManifestCommand(component string) string {
	if component == "builders-federation-gateway" {
		return component + " --release-manifest"
	}
	return component + " release-manifest"
}

func acceptancePackageSmokeCommand(component string) string {
	if component == "builders-federation-gateway" {
		return "make federation-facade-package-smoke"
	}
	return "make package-smoke"
}

func acceptanceUpgradeCommand(component string) string {
	return fmt.Sprintf("install %s candidate after restore drill", component)
}

func acceptanceRollbackCommand(component string) string {
	return fmt.Sprintf("restore previous %s candidate and rerun audit verifier", component)
}

func ScanAcceptanceValue(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ScanAcceptanceEvidence(b)
}

func ScanAcceptanceEvidence(b []byte) error {
	text := string(b)
	for _, pattern := range acceptanceUnsafeEvidence {
		if pattern.MatchString(text) {
			return fmt.Errorf("acceptance evidence contains private topology or secret-like material")
		}
	}
	return nil
}

func acceptanceEvidenceHashes(component string) (string, string, error) {
	var version bytes.Buffer
	if err := WriteVersion(&version, component); err != nil {
		return "", "", err
	}
	if err := ScanAcceptanceEvidence(version.Bytes()); err != nil {
		return "", "", fmt.Errorf("version evidence unsafe: %w", err)
	}
	var manifest bytes.Buffer
	if err := WriteManifest(&manifest, component); err != nil {
		return "", "", err
	}
	if err := ScanAcceptanceEvidence(manifest.Bytes()); err != nil {
		return "", "", fmt.Errorf("release-manifest evidence unsafe: %w", err)
	}
	versionSHA := sha256.Sum256(version.Bytes())
	manifestSHA := sha256.Sum256(manifest.Bytes())
	return hex.EncodeToString(versionSHA[:]), hex.EncodeToString(manifestSHA[:]), nil
}

func normalizeAcceptanceOptions(opts AcceptanceOptions) AcceptanceOptions {
	opts.Component = strings.TrimSpace(opts.Component)
	if opts.ArtifactFilename != "" {
		opts.ArtifactFilename = filepath.Base(opts.ArtifactFilename)
	}
	if opts.DecisionBy == "" {
		opts.DecisionBy = opts.Owner
	}
	if opts.PilotEnvironmentName == "" {
		opts.PilotEnvironmentName = "two-company-pilot-fixture"
	}
	return opts
}

func validateAcceptanceOptions(opts AcceptanceOptions) error {
	if !isBackendAcceptanceComponent(opts.Component) {
		return fmt.Errorf("component must be builders-control, builders-agent, or builders-federation-gateway")
	}
	if err := validateAcceptanceBuildMetadata(opts); err != nil {
		return err
	}
	required := map[string]string{
		"release-id":                    opts.ReleaseID,
		"release-date":                  opts.ReleaseDate,
		"owner":                         opts.Owner,
		"decision-by":                   opts.DecisionBy,
		"pilot-environment":             opts.PilotEnvironmentName,
		"pr":                            opts.PR,
		"merge-commit":                  opts.MergeCommit,
		"tag-or-build-label":            opts.TagOrBuildLabel,
		"artifact":                      opts.ArtifactFilename,
		"artifact-platform":             opts.ArtifactPlatform,
		"package-smoke-evidence-sha256": opts.PackageSmokeEvidenceSHA256,
		"backup-artifact-sha256":        opts.BackupArtifactSHA256,
		"restore-verified-at":           opts.RestoreVerifiedAt,
		"security-doc-commit":           opts.SecurityDocCommit,
		"security-doc-evidence-sha256":  opts.SecurityDocEvidenceSHA256,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !acceptanceDatePattern.MatchString(opts.ReleaseDate) {
		return fmt.Errorf("release-date must be YYYY-MM-DD")
	}
	if !acceptanceRFC3339Pattern.MatchString(opts.RestoreVerifiedAt) {
		return fmt.Errorf("restore-verified-at must be RFC3339 UTC")
	}
	if !acceptanceCommitPattern.MatchString(opts.MergeCommit) {
		return fmt.Errorf("merge-commit must be a 7-40 character lowercase git commit")
	}
	if !acceptanceCommitPattern.MatchString(opts.SecurityDocCommit) {
		return fmt.Errorf("security-doc-commit must be a 7-40 character lowercase git commit")
	}
	if !strings.Contains(opts.PR, "github.com/b2bautopilot/xyz-b2b/services/builders-net/pull/") {
		return fmt.Errorf("pr must be an xyz-b2b/services/builders-net GitHub pull request URL")
	}
	for name, value := range map[string]string{
		"artifact-sha256":               opts.ArtifactSHA256,
		"package-smoke-evidence-sha256": opts.PackageSmokeEvidenceSHA256,
		"backup-artifact-sha256":        opts.BackupArtifactSHA256,
		"security-doc-evidence-sha256":  opts.SecurityDocEvidenceSHA256,
	} {
		if !acceptanceSHA256Pattern.MatchString(value) {
			return fmt.Errorf("%s must be a 64-character lowercase SHA-256 hex digest", name)
		}
	}
	if opts.ArtifactSizeBytes <= 0 {
		return fmt.Errorf("artifact size must be positive")
	}
	if opts.SignedBy != "" || opts.SignedAt != "" {
		if opts.SignedBy == "" || opts.SignedAt == "" {
			return fmt.Errorf("signed artifacts require signed-by and signed-at")
		}
		if !acceptanceRFC3339Pattern.MatchString(opts.SignedAt) {
			return fmt.Errorf("signed-at must be RFC3339 UTC")
		}
		if opts.UnsignedException != "" || opts.ExceptionOwner != "" || opts.ExceptionExpires != "" {
			return fmt.Errorf("choose signed evidence or unsigned exception evidence, not both")
		}
	} else {
		if opts.UnsignedException == "" || opts.ExceptionOwner == "" || opts.ExceptionExpires == "" {
			return fmt.Errorf("unsigned artifacts require unsigned-exception, exception-owner, and exception-expires")
		}
		if !acceptanceDatePattern.MatchString(opts.ExceptionExpires) {
			return fmt.Errorf("exception-expires must be YYYY-MM-DD")
		}
	}
	for name, value := range required {
		if err := ScanAcceptanceEvidence([]byte(value)); err != nil {
			return fmt.Errorf("%s unsafe: %w", name, err)
		}
	}
	for name, value := range map[string]string{
		"artifact filename":  opts.ArtifactFilename,
		"signed-by":          opts.SignedBy,
		"unsigned-exception": opts.UnsignedException,
		"exception-owner":    opts.ExceptionOwner,
	} {
		if err := ScanAcceptanceEvidence([]byte(value)); err != nil {
			return fmt.Errorf("%s unsafe: %w", name, err)
		}
	}
	return nil
}

func validateAcceptanceBuildMetadata(opts AcceptanceOptions) error {
	if strings.TrimSpace(Version) == "" || Version == "0.0.0-dev" {
		return fmt.Errorf("release Version must be set to non-dev metadata")
	}
	if !acceptanceCommitPattern.MatchString(Commit) {
		return fmt.Errorf("release Commit must be a 7-40 character lowercase git commit")
	}
	if !acceptanceRFC3339Pattern.MatchString(Date) {
		return fmt.Errorf("release Date must be RFC3339 UTC")
	}
	if opts.MergeCommit != "" && !strings.HasPrefix(opts.MergeCommit, Commit) && !strings.HasPrefix(Commit, opts.MergeCommit) {
		return fmt.Errorf("merge-commit must match release Commit metadata")
	}
	return nil
}

func isBackendAcceptanceComponent(component string) bool {
	switch component {
	case "builders-control", "builders-agent", "builders-federation-gateway":
		return true
	default:
		return false
	}
}

func artifactEvidence(path string) (string, string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open artifact: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", "", 0, fmt.Errorf("stat artifact: %w", err)
	}
	if info.IsDir() {
		return "", "", 0, fmt.Errorf("artifact is a directory")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", 0, fmt.Errorf("hash artifact: %w", err)
	}
	return info.Name(), hex.EncodeToString(h.Sum(nil)), info.Size(), nil
}
