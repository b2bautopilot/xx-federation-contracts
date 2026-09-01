package keymaterial

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	DevLocalAuditSigningKeyID = "dev-local-ed25519-audit-key"
	DevLocalSSHCAKeyID        = "dev-local-ed25519-ssh-ca"
	// DevLocalMembershipSigningKeyID signs short-TTL libp2p-fabric membership
	// capabilities. It is DELIBERATELY DISTINCT from the audit key and the
	// enrollment/relay-client CA (libp2p-fabric-migration §5.3, P1.2): a compromised
	// membership signer must grant only NETWORK ADMISSION — never the ability to mint
	// a relay-client leaf or forge an audit record. Dormant until P1.3
	// (IssueMembershipCapability) is the first caller.
	DevLocalMembershipSigningKeyID = "dev-local-ed25519-membership-key"
	// DevLocalServiceAccessSigningKeyID signs short-TTL fed-svc SERVICE ACCESS
	// capabilities (docs/design/sovereign-service-exposure.md). Like the membership
	// signer it is DELIBERATELY DISTINCT from the audit/CA/membership keys: a
	// compromised service-access signer must grant only reach to a published service —
	// never a relay-client leaf, an audit record, or fabric membership. Dormant until
	// the fed-svc issuer (P2) is the first caller.
	DevLocalServiceAccessSigningKeyID = "dev-local-ed25519-service-access-key"
)

var ErrProviderUnavailable = errors.New("key material provider unavailable")

type AuditSigningMaterial struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

type Provider interface {
	AuditSigningMaterial(ctx context.Context) (AuditSigningMaterial, error)
	SSHCASigner(ctx context.Context) (ssh.Signer, error)
}

type ProviderConfig struct {
	Mode                string
	AuditSigningKeyID   string
	AuditSigningKeyFile string
	SSHCAKeyFile        string
	// Membership-capability signer (libp2p fabric migration, P1.2). Optional/additive:
	// unset falls back to the dev-local key (dev_local) or is reported unavailable
	// (kms_vault) so existing deployments are unaffected until they opt in.
	MembershipSigningKeyID   string
	MembershipSigningKeyFile string
	// Service-access-capability signer (fed-svc, P2). Optional/additive, same
	// dev_local / kms_vault resolution as the membership signer.
	ServiceAccessSigningKeyID   string
	ServiceAccessSigningKeyFile string
}

type DevLocalProvider struct{}

func ProviderForMode(mode string) (Provider, error) {
	return ProviderFromConfig(ProviderConfig{Mode: mode})
}

func ProviderFromConfig(cfg ProviderConfig) (Provider, error) {
	switch mode := cfg.Mode; mode {
	case "", "dev_local":
		return DevLocalProvider{}, nil
	case "kms_vault":
		if cfg.AuditSigningKeyID == "" || cfg.AuditSigningKeyFile == "" || cfg.SSHCAKeyFile == "" {
			return FailClosedProvider{Mode: mode}, nil
		}
		return MountedSecretProvider{
			AuditSigningKeyID:   cfg.AuditSigningKeyID,
			AuditSigningKeyFile: cfg.AuditSigningKeyFile,
			SSHCAKeyFile:        cfg.SSHCAKeyFile,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key material mode %q", mode)
	}
}

func (DevLocalProvider) AuditSigningMaterial(context.Context) (AuditSigningMaterial, error) {
	return AuditSigningMaterial{
		KeyID:      DevLocalAuditSigningKeyID,
		PrivateKey: DevLocalAuditSigningKey(),
	}, nil
}

func (DevLocalProvider) SSHCASigner(context.Context) (ssh.Signer, error) {
	signer, err := ssh.NewSignerFromKey(DevLocalSSHCAKey())
	if err != nil {
		return nil, fmt.Errorf("create dev-local SSH CA signer: %w", err)
	}
	return signer, nil
}

type FailClosedProvider struct {
	Mode string
}

func (p FailClosedProvider) AuditSigningMaterial(context.Context) (AuditSigningMaterial, error) {
	return AuditSigningMaterial{}, p.err()
}

func (p FailClosedProvider) SSHCASigner(context.Context) (ssh.Signer, error) {
	return nil, p.err()
}

func (p FailClosedProvider) err() error {
	mode := p.Mode
	if mode == "" {
		mode = "unknown"
	}
	return fmt.Errorf("%w: %s backend is not configured", ErrProviderUnavailable, mode)
}

type MountedSecretProvider struct {
	AuditSigningKeyID   string
	AuditSigningKeyFile string
	SSHCAKeyFile        string
}

func (p MountedSecretProvider) AuditSigningMaterial(context.Context) (AuditSigningMaterial, error) {
	privateKey, err := readEd25519PrivateKey(p.AuditSigningKeyFile)
	if err != nil {
		return AuditSigningMaterial{}, err
	}
	return AuditSigningMaterial{KeyID: p.AuditSigningKeyID, PrivateKey: privateKey}, nil
}

func (p MountedSecretProvider) SSHCASigner(context.Context) (ssh.Signer, error) {
	privateKey, err := readRawPrivateKey(p.SSHCAKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create mounted SSH CA signer: %w", err)
	}
	return signer, nil
}

func readEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	privateKey, err := readRawPrivateKey(path)
	if err != nil {
		return nil, err
	}
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		return append(ed25519.PrivateKey(nil), key...), nil
	case *ed25519.PrivateKey:
		return append(ed25519.PrivateKey(nil), (*key)...), nil
	default:
		return nil, fmt.Errorf("%w: audit signing key must be ed25519", ErrProviderUnavailable)
	}
}

func readRawPrivateKey(path string) (any, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: private key file is required", ErrProviderUnavailable)
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read private key file: %v", ErrProviderUnavailable, err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse private key file: %v", ErrProviderUnavailable, err)
	}
	return privateKey, nil
}

func LoadAuditPublicKeys(dir string) (map[string]ed25519.PublicKey, error) {
	if dir == "" {
		return map[string]ed25519.PublicKey{}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: read audit public keys dir: %v", ErrProviderUnavailable, err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read audit public key: %v", ErrProviderUnavailable, err)
		}
		publicKey, comment, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("%w: parse audit public key %q: %v", ErrProviderUnavailable, entry.Name(), err)
		}
		keyID := strings.TrimSpace(comment)
		if keyID == "" {
			keyID = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		}
		cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: audit public key %q is not exportable", ErrProviderUnavailable, keyID)
		}
		edKey, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: audit public key %q must be ed25519", ErrProviderUnavailable, keyID)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("%w: duplicate audit public key id %q", ErrProviderUnavailable, keyID)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), edKey...)
	}
	return keys, nil
}

func AuditPublicKeys(active AuditSigningMaterial, retainedDir string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	if active.KeyID != "" && active.PrivateKey != nil {
		keys[active.KeyID] = append(ed25519.PublicKey(nil), active.PrivateKey.Public().(ed25519.PublicKey)...)
	}
	retainedKeys, err := LoadAuditPublicKeys(retainedDir)
	if err != nil {
		return nil, err
	}
	for keyID, publicKey := range retainedKeys {
		keys[keyID] = publicKey
	}
	return keys, nil
}

func DevLocalAuditSigningKey() ed25519.PrivateKey {
	return devLocalKey("x-builders-net/dev-local-audit-signing-key/v1")
}

func DevLocalSSHCAKey() ed25519.PrivateKey {
	return devLocalKey("x-builders-net/dev-local-ssh-ca/v1")
}

// ---- libp2p-fabric membership-capability signer (P1.2) ---------------------
// A DEDICATED per-federation ed25519 signer for short-TTL membership capabilities,
// kept separate from the audit + enrollment CAs so its blast radius is only network
// admission (§5.3). Decoupled from the Provider interface (which stays unchanged so
// existing implementors/mocks are unaffected); dormant until P1.3 is the first caller.

// MembershipSigningMaterial is the active key that signs membership capabilities.
type MembershipSigningMaterial struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

// MembershipSigningMaterialFromConfig resolves the membership signer for a provider config:
//   - dev_local (or empty): the deterministic dev-local membership key.
//   - kms_vault: the mounted MembershipSigningKeyFile if set; otherwise ErrProviderUnavailable
//     ("not yet configured") so an existing kms_vault deployment is unaffected until it opts in.
func MembershipSigningMaterialFromConfig(cfg ProviderConfig) (MembershipSigningMaterial, error) {
	switch mode := cfg.Mode; mode {
	case "", "dev_local":
		return MembershipSigningMaterial{
			KeyID:      DevLocalMembershipSigningKeyID,
			PrivateKey: DevLocalMembershipSigningKey(),
		}, nil
	case "kms_vault":
		if cfg.MembershipSigningKeyFile == "" {
			return MembershipSigningMaterial{}, fmt.Errorf("%w: membership signing key not configured", ErrProviderUnavailable)
		}
		keyID := cfg.MembershipSigningKeyID
		if keyID == "" {
			keyID = "mounted-ed25519-membership-key"
		}
		privateKey, err := readEd25519PrivateKey(cfg.MembershipSigningKeyFile)
		if err != nil {
			return MembershipSigningMaterial{}, err
		}
		return MembershipSigningMaterial{KeyID: keyID, PrivateKey: privateKey}, nil
	default:
		return MembershipSigningMaterial{}, fmt.Errorf("unsupported key material mode %q", mode)
	}
}

// DevLocalMembershipSigningKey is the deterministic dev-local membership signer.
func DevLocalMembershipSigningKey() ed25519.PrivateKey {
	return devLocalKey("x-builders-net/dev-local-membership-signing-key/v1")
}

// ServiceAccessSigningMaterial is the active key that signs fed-svc service-access
// capabilities. A distinct key from the membership signer (§ decision #2 / non-goals).
type ServiceAccessSigningMaterial struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

// ServiceAccessSigningMaterialFromConfig resolves the service-access signer, mirroring
// MembershipSigningMaterialFromConfig:
//   - dev_local (or empty): the deterministic dev-local service-access key.
//   - kms_vault: the mounted ServiceAccessSigningKeyFile if set; otherwise
//     ErrProviderUnavailable so an existing kms_vault deployment is unaffected until it
//     opts in.
func ServiceAccessSigningMaterialFromConfig(cfg ProviderConfig) (ServiceAccessSigningMaterial, error) {
	switch mode := cfg.Mode; mode {
	case "", "dev_local":
		return ServiceAccessSigningMaterial{
			KeyID:      DevLocalServiceAccessSigningKeyID,
			PrivateKey: DevLocalServiceAccessSigningKey(),
		}, nil
	case "kms_vault":
		if cfg.ServiceAccessSigningKeyFile == "" {
			return ServiceAccessSigningMaterial{}, fmt.Errorf("%w: service-access signing key not configured", ErrProviderUnavailable)
		}
		keyID := cfg.ServiceAccessSigningKeyID
		if keyID == "" {
			keyID = "mounted-ed25519-service-access-key"
		}
		privateKey, err := readEd25519PrivateKey(cfg.ServiceAccessSigningKeyFile)
		if err != nil {
			return ServiceAccessSigningMaterial{}, err
		}
		return ServiceAccessSigningMaterial{KeyID: keyID, PrivateKey: privateKey}, nil
	default:
		return ServiceAccessSigningMaterial{}, fmt.Errorf("unsupported key material mode %q", mode)
	}
}

// DevLocalServiceAccessSigningKey is the deterministic dev-local service-access signer.
func DevLocalServiceAccessSigningKey() ed25519.PrivateKey {
	return devLocalKey("x-builders-net/dev-local-service-access-signing-key/v1")
}

// LoadMembershipPublicKeys loads the trusted membership-signer public keys (keyID ->
// ed25519.PublicKey) from a directory of authorized-keys files — the set a verifier
// (the relay + the gateway daemon) consults to check a capability's signer. Mirrors
// LoadAuditPublicKeys but for the membership trust bundle (a distinct directory).
func LoadMembershipPublicKeys(dir string) (map[string]ed25519.PublicKey, error) {
	if dir == "" {
		return map[string]ed25519.PublicKey{}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: read membership public keys dir: %v", ErrProviderUnavailable, err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read membership public key: %v", ErrProviderUnavailable, err)
		}
		publicKey, comment, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("%w: parse membership public key %q: %v", ErrProviderUnavailable, entry.Name(), err)
		}
		keyID := strings.TrimSpace(comment)
		if keyID == "" {
			keyID = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		}
		cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: membership public key %q is not exportable", ErrProviderUnavailable, keyID)
		}
		edKey, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: membership public key %q must be ed25519", ErrProviderUnavailable, keyID)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("%w: duplicate membership public key id %q", ErrProviderUnavailable, keyID)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), edKey...)
	}
	return keys, nil
}

// MembershipPublicKeys returns the active signer's public key merged with any retained
// (rotated-out but still-honored) keys from retainedDir — the full verifier trust set.
func MembershipPublicKeys(active MembershipSigningMaterial, retainedDir string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	if active.KeyID != "" && active.PrivateKey != nil {
		keys[active.KeyID] = append(ed25519.PublicKey(nil), active.PrivateKey.Public().(ed25519.PublicKey)...)
	}
	retainedKeys, err := LoadMembershipPublicKeys(retainedDir)
	if err != nil {
		return nil, err
	}
	for keyID, publicKey := range retainedKeys {
		keys[keyID] = publicKey
	}
	return keys, nil
}

func devLocalKey(seedMaterial string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(seedMaterial))
	return ed25519.NewKeyFromSeed(seed[:])
}
