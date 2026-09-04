// Package attachment is the machine-readable contract for safe attachment
// exchange on orchestration runs (issue #19, parent epic #18).
//
// Attachments are content-addressed control-owned objects. Observation
// events carry only AttachmentRef values — opaque ids, digests, sizes,
// sniffed MIME, sanitized display names, direction, scan/classification/
// expiry state, and audience binding. Event payloads NEVER carry bytes,
// paths, storage URLs, secrets, or capability values.
//
// Fetch and return happen by scoped capability through the local control
// plane only. The fetch-target and content guards here deny, fail-closed:
// arbitrary URLs, redirects (caller-owned: the control never follows them),
// loopback, RFC1918/link-local/cloud-metadata hosts, traversal, archive
// bombs, executable/active content by default, oversize bodies, and
// digest/MIME mismatch.
//
// Source-pointer: github.com/b2bautopilot/xx-federation-contracts/contracts/attachment
// Spec evidence: rel.agent-connects-control (attachment capability),
// rel.portal-dials-control (attachment evidence, never bytes).
package attachment

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Schema identifier for attachment references.
const SchemaAttachmentRefV1 = "builders.federation.attachment_ref.v1"

// Attachment directions.
const (
	DirectionInput    = "input"
	DirectionReturned = "returned"
)

// Scan states for an attachment object.
const (
	ScanPending     = "pending"
	ScanClean       = "clean"
	ScanQuarantined = "quarantined"
	ScanBlocked     = "blocked"
)

// Audience bindings: tenant-local by default; partner only through the
// explicit partner-safe projection.
const (
	AudienceTenant  = "tenant"
	AudiencePartner = "partner"
)

// Size and archive budgets enforced fail-closed at fetch/return time.
const (
	// MaxAttachmentBytes caps one attachment body (16 MiB).
	MaxAttachmentBytes = 16 << 20
	// MaxDecompressedBytes caps total extraction output (64 MiB).
	MaxDecompressedBytes = 64 << 20
	// MaxArchiveEntries caps the number of entries expanded from one archive.
	MaxArchiveEntries = 1024
	// MaxCompressionRatio caps output:input for one archive (100:1); beyond
	// it the payload is treated as an archive bomb.
	MaxCompressionRatio = 100
)

var (
	ErrBadRef          = errors.New("attachment ref invalid")
	ErrUnknownDir      = errors.New("attachment direction unknown")
	ErrUnknownScan     = errors.New("attachment scan state unknown")
	ErrUnknownAudience = errors.New("attachment audience unknown")
	ErrOversize        = errors.New("attachment oversize")
	ErrDigestMismatch  = errors.New("attachment digest mismatch")
	ErrMIMEMismatch    = errors.New("attachment MIME mismatch")
	ErrBlockedContent  = errors.New("attachment content blocked")
	ErrFetchDenied     = errors.New("attachment fetch target denied")
	ErrBadCapability   = errors.New("attachment capability invalid")
	ErrBadSignature    = errors.New("attachment capability signature invalid")
	ErrExpired         = errors.New("attachment capability expired")
	ErrNoExpiry        = errors.New("attachment capability has no expiry")
	ErrUnknownSigner   = errors.New("attachment capability signer not trusted")
	ErrEmptyKeyring    = errors.New("attachment capability keyring is empty")
	ErrDecompression   = errors.New("attachment decompression budget exceeded")
)

// ValidDirection reports whether value names a declared direction.
func ValidDirection(value string) bool {
	return value == DirectionInput || value == DirectionReturned
}

// ValidScanState reports whether value names a declared scan state.
func ValidScanState(value string) bool {
	switch value {
	case ScanPending, ScanClean, ScanQuarantined, ScanBlocked:
		return true
	default:
		return false
	}
}

// ValidAudience reports whether value names a declared audience binding.
func ValidAudience(value string) bool {
	return value == AudienceTenant || value == AudiencePartner
}

// AttachmentRef is the event-safe descriptor. DisplayName is sanitized at
// mint time; no path separators or control bytes survive.
type AttachmentRef struct {
	SchemaVersion string `json:"schema_version"`
	AttachmentID  string `json:"attachment_id"`
	SHA256Hex     string `json:"sha256_hex"`
	SizeBytes     int64  `json:"size_bytes"`
	MIME          string `json:"mime"`
	DisplayName   string `json:"display_name"`
	Direction     string `json:"direction"`
	ScanState     string `json:"scan_state"`
	Audience      string `json:"audience"`
	ExpiresAtMS   int64  `json:"expires_at_ms"`
}

// SanitizeDisplayName strips path separators, traversal, and control bytes
// from a workload-supplied filename, keeping a bounded human label.
func SanitizeDisplayName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "\\", "/")
	parts := strings.Split(name, "/")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		var b strings.Builder
		for _, r := range p {
			if r < 0x20 || r == 0x7f {
				continue
			}
			b.WriteRune(r)
		}
		if clean := strings.TrimSpace(b.String()); clean != "" {
			kept = append(kept, clean)
		}
	}
	out := strings.Join(kept, "_")
	if out == "" {
		return "attachment"
	}
	if len(out) > 128 {
		return out[:128]
	}
	return out
}

// ValidateRef checks the descriptor shape fail-closed: opaque id, 64-hex
// digest, bounded size, sanitized display name, known direction/scan/
// audience, and a hard expiry.
func ValidateRef(ref AttachmentRef, nowMS int64) error {
	if ref.SchemaVersion != SchemaAttachmentRefV1 {
		return fmt.Errorf("%w: schema %q", ErrBadRef, ref.SchemaVersion)
	}
	if strings.TrimSpace(ref.AttachmentID) == "" || len(ref.AttachmentID) > 128 {
		return fmt.Errorf("%w: bad id", ErrBadRef)
	}
	if len(ref.SHA256Hex) != 64 {
		return fmt.Errorf("%w: digest must be 64 hex chars", ErrBadRef)
	}
	if _, err := hex.DecodeString(ref.SHA256Hex); err != nil {
		return fmt.Errorf("%w: digest not hex", ErrBadRef)
	}
	if ref.SizeBytes <= 0 || ref.SizeBytes > MaxAttachmentBytes {
		return fmt.Errorf("%w: size %d", ErrOversize, ref.SizeBytes)
	}
	if strings.TrimSpace(ref.MIME) == "" {
		return fmt.Errorf("%w: empty MIME", ErrBadRef)
	}
	if ref.DisplayName != SanitizeDisplayName(ref.DisplayName) {
		return fmt.Errorf("%w: display name not sanitized", ErrBadRef)
	}
	if !ValidDirection(ref.Direction) {
		return fmt.Errorf("%w: %q", ErrUnknownDir, ref.Direction)
	}
	if !ValidScanState(ref.ScanState) {
		return fmt.Errorf("%w: %q", ErrUnknownScan, ref.ScanState)
	}
	if !ValidAudience(ref.Audience) {
		return fmt.Errorf("%w: %q", ErrUnknownAudience, ref.Audience)
	}
	if ref.ExpiresAtMS <= 0 || nowMS >= ref.ExpiresAtMS {
		return fmt.Errorf("%w: expired or no expiry", ErrExpired)
	}
	return nil
}

// Fetchable reports whether the ref may be served: only clean-scanned,
// unexpired objects are fetchable; anything else fails closed.
func (ref AttachmentRef) Fetchable(nowMS int64) error {
	if err := ValidateRef(ref, nowMS); err != nil {
		return err
	}
	if ref.ScanState != ScanClean {
		return fmt.Errorf("%w: scan state %q", ErrBlockedContent, ref.ScanState)
	}
	return nil
}

// DigestHex returns the SHA-256 hex of one attachment body.
func DigestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// VerifyBody checks a fetched body against its ref: exact size, exact
// digest, and sniffed-MIME agreement with the declared MIME. Any mismatch
// fails closed (digest/MIME confusion is never served).
func VerifyBody(ref AttachmentRef, body []byte, sniffedMIME string) error {
	if int64(len(body)) != ref.SizeBytes {
		return fmt.Errorf("%w: size %d vs %d", ErrDigestMismatch, len(body), ref.SizeBytes)
	}
	if DigestHex(body) != strings.ToLower(ref.SHA256Hex) {
		return fmt.Errorf("%w", ErrDigestMismatch)
	}
	if normalizeMIME(sniffedMIME) != normalizeMIME(ref.MIME) {
		return fmt.Errorf("%w: %q vs %q", ErrMIMEMismatch, sniffedMIME, ref.MIME)
	}
	return nil
}

func normalizeMIME(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	if i := strings.Index(m, ";"); i >= 0 {
		m = strings.TrimSpace(m[:i])
	}
	return m
}

// blockedMIMEPrefixes denies executable/active content by default. Archives
// are allowed only inside the decompression budget (see CheckArchiveBudget).
var blockedMIMEPrefixes = []string{
	"application/x-executable",
	"application/x-msdownload",
	"application/x-msdos-program",
	"application/x-sh",
	"text/html",
	"application/javascript",
	"text/javascript",
	"application/x-shockwave-flash",
}

// ContentAllowed reports whether a sniffed MIME may be attached at all.
func ContentAllowed(sniffedMIME string) bool {
	norm := normalizeMIME(sniffedMIME)
	for _, prefix := range blockedMIMEPrefixes {
		if norm == prefix || strings.HasPrefix(norm, prefix+";") {
			return false
		}
	}
	return true
}

// CheckArchiveBudget enforces the archive-bomb budget before expansion:
// entry count, output bytes, and compression ratio all fail closed.
func CheckArchiveBudget(entries int, compressedBytes, decompressedBytes int64) error {
	if entries <= 0 || entries > MaxArchiveEntries {
		return fmt.Errorf("%w: entries %d", ErrDecompression, entries)
	}
	if decompressedBytes > MaxDecompressedBytes {
		return fmt.Errorf("%w: output %d bytes", ErrDecompression, decompressedBytes)
	}
	if compressedBytes <= 0 {
		return fmt.Errorf("%w: empty input", ErrDecompression)
	}
	if decompressedBytes/compressedBytes > MaxCompressionRatio {
		return fmt.Errorf("%w: ratio %d:1", ErrDecompression, decompressedBytes/compressedBytes)
	}
	return nil
}

// ValidateFetchTarget denies every unsafe fetch destination fail-closed:
// non-http(s) schemes, embedded credentials, loopback, unspecified,
// multicast, RFC1918 private, link-local (including the cloud metadata
// endpoints), .internal/.localhost names, explicit ports on metadata
// literals, and path traversal. Redirect-following is caller-owned: the
// control plane never follows redirects; each hop re-validates here.
func ValidateFetchTarget(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: unparsable %v", ErrFetchDenied, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%w: scheme %q", ErrFetchDenied, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL", ErrFetchDenied)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrFetchDenied)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".internal") || host == "metadata.google.internal" {
		return fmt.Errorf("%w: host %q", ErrFetchDenied, host)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() ||
			addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return fmt.Errorf("%w: host %q", ErrFetchDenied, host)
		}
	}
	clean := u.EscapedPath()
	if strings.Contains(clean, "..") {
		return fmt.Errorf("%w: traversal", ErrFetchDenied)
	}
	return nil
}

// Capability is the signed fetch/return grant for one attachment. It binds
// one attachment id to one audience tenant with a hard expiry; the token
// value never appears in observation events (only the opaque id does).
type Capability struct {
	AttachmentID string `json:"attachment_id"`
	Audience     string `json:"audience"`
	Scope        string `json:"scope"`
	IssuedAtMS   int64  `json:"issued_at_ms"`
	ExpiresAtMS  int64  `json:"expires_at_ms"`
	Issuer       string `json:"issuer"`
	Nonce        string `json:"nonce"`
	Signature    []byte `json:"signature,omitempty"`
}

// Capability scopes.
const (
	ScopeFetch  = "fetch"
	ScopeReturn = "return"
)

// ValidScope reports whether value names a declared capability scope.
func ValidScope(value string) bool {
	return value == ScopeFetch || value == ScopeReturn
}

// canonicalBytes is the deterministic signing input: the capability sans
// signature, as JSON (struct declaration order marshals byte-identically).
func canonicalBytes(c Capability) ([]byte, error) {
	c.Signature = nil
	return json.Marshal(c)
}

// Sign mints a scoped capability with a hard future expiry. Malformed
// grants can never be minted.
func Sign(issuerKeyID string, priv ed25519.PrivateKey, c Capability) (Capability, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Capability{}, ErrBadCapability
	}
	if strings.TrimSpace(c.AttachmentID) == "" {
		return Capability{}, ErrBadCapability
	}
	if !ValidAudience(c.Audience) {
		return Capability{}, ErrUnknownAudience
	}
	if !ValidScope(c.Scope) {
		return Capability{}, ErrBadCapability
	}
	if c.ExpiresAtMS <= 0 {
		return Capability{}, ErrNoExpiry
	}
	if c.ExpiresAtMS <= c.IssuedAtMS {
		return Capability{}, ErrExpired
	}
	if strings.TrimSpace(c.Nonce) == "" {
		return Capability{}, ErrBadCapability
	}
	c.Issuer = issuerKeyID
	c.Signature = nil
	raw, err := canonicalBytes(c)
	if err != nil {
		return Capability{}, err
	}
	c.Signature = ed25519.Sign(priv, raw)
	return c, nil
}

// Verify checks signer trust, shape, expiry, and audience binding. It does
// NOT check revocation (caller-owned tombstone set) nor re-validate the
// attachment body (VerifyBody). An empty keyring denies all.
func (c Capability) Verify(trusted map[string]ed25519.PublicKey, nowMS int64, wantAttachmentID, wantAudience string) error {
	if len(trusted) == 0 {
		return ErrEmptyKeyring
	}
	pub, ok := trusted[c.Issuer]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %q", ErrUnknownSigner, c.Issuer)
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	raw, err := canonicalBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, raw, c.Signature) {
		return ErrBadSignature
	}
	if c.ExpiresAtMS <= 0 || nowMS >= c.ExpiresAtMS {
		return ErrExpired
	}
	if c.AttachmentID != wantAttachmentID {
		return fmt.Errorf("%w: capability bound to another attachment", ErrBadCapability)
	}
	if c.Audience != wantAudience || !ValidAudience(c.Audience) {
		return fmt.Errorf("%w: audience %q", ErrUnknownAudience, c.Audience)
	}
	if !ValidScope(c.Scope) {
		return fmt.Errorf("%w: scope %q", ErrBadCapability, c.Scope)
	}
	return nil
}
