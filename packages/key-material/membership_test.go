package keymaterial

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeMembershipKeyFile(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "membership.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDevLocalMembershipKeyDeterministicAndIsolated(t *testing.T) {
	k1 := DevLocalMembershipSigningKey()
	if !k1.Equal(DevLocalMembershipSigningKey()) {
		t.Fatal("dev-local membership key must be deterministic")
	}
	// §5.3 blast-radius isolation: distinct from the audit + ssh-ca keys.
	if k1.Equal(DevLocalAuditSigningKey()) {
		t.Fatal("membership key must differ from the audit key")
	}
	if k1.Equal(DevLocalSSHCAKey()) {
		t.Fatal("membership key must differ from the ssh-ca key")
	}
}

func TestMembershipSigningMaterialFromConfig(t *testing.T) {
	// dev_local and empty mode both return the dev-local key.
	for _, mode := range []string{"dev_local", ""} {
		m, err := MembershipSigningMaterialFromConfig(ProviderConfig{Mode: mode})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if m.KeyID != DevLocalMembershipSigningKeyID {
			t.Fatalf("mode %q: keyID = %q", mode, m.KeyID)
		}
		if !m.PrivateKey.Equal(DevLocalMembershipSigningKey()) {
			t.Fatalf("mode %q: expected the dev-local key", mode)
		}
	}

	// kms_vault without a configured file is unavailable (additive: existing
	// deployments are unaffected until they opt in), not a hard error.
	if _, err := MembershipSigningMaterialFromConfig(ProviderConfig{Mode: "kms_vault"}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("kms_vault without a key file should be ErrProviderUnavailable, got %v", err)
	}

	// Sign/verify round-trip with the resolved material.
	m, _ := MembershipSigningMaterialFromConfig(ProviderConfig{Mode: "dev_local"})
	msg := []byte("membership-capability|peerID|epoch=1")
	sig := ed25519.Sign(m.PrivateKey, msg)
	pub := m.PrivateKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("membership capability sign/verify round-trip failed")
	}
}

func TestMembershipSigningMaterialFromConfig_KMSVaultFile(t *testing.T) {
	keyPath := writeMembershipKeyFile(t)

	// kms_vault WITH a mounted key file resolves that key + the given keyID.
	m, err := MembershipSigningMaterialFromConfig(ProviderConfig{
		Mode:                     "kms_vault",
		MembershipSigningKeyFile: keyPath,
		MembershipSigningKeyID:   "fabric-membership-v1",
	})
	if err != nil {
		t.Fatalf("kms_vault with a key file: %v", err)
	}
	if m.KeyID != "fabric-membership-v1" {
		t.Fatalf("keyID = %q, want fabric-membership-v1", m.KeyID)
	}
	// It is the REAL mounted key, never the publicly-derivable dev-local key.
	if m.PrivateKey.Equal(DevLocalMembershipSigningKey()) {
		t.Fatal("kms_vault key file must NOT resolve to the dev-local key")
	}
	msg := []byte("roster|epoch=1")
	if !ed25519.Verify(m.PrivateKey.Public().(ed25519.PublicKey), msg, ed25519.Sign(m.PrivateKey, msg)) {
		t.Fatal("mounted membership key sign/verify round-trip failed")
	}

	// keyID defaults when unset.
	m2, err := MembershipSigningMaterialFromConfig(ProviderConfig{Mode: "kms_vault", MembershipSigningKeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if m2.KeyID != "mounted-ed25519-membership-key" {
		t.Fatalf("default keyID = %q, want mounted-ed25519-membership-key", m2.KeyID)
	}
}

func TestMembershipPublicKeysTrustBundle(t *testing.T) {
	m, _ := MembershipSigningMaterialFromConfig(ProviderConfig{Mode: "dev_local"})

	// Active signer only.
	keys, err := MembershipPublicKeys(m, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[m.KeyID] == nil {
		t.Fatalf("expected only the active pubkey, got %v", keys)
	}

	// Retained-dir round-trip: a rotated-out key still honored by verifiers.
	dir := t.TempDir()
	retainedPub := DevLocalAuditSigningKey().Public().(ed25519.PublicKey) // any ed25519 pub
	sshPub, err := ssh.NewPublicKey(retainedPub)
	if err != nil {
		t.Fatal(err)
	}
	line := ssh.MarshalAuthorizedKey(sshPub) // "ssh-ed25519 AAAA...\n"
	line = append(line[:len(line)-1], []byte(" retained-membership-v0\n")...)
	if err := os.WriteFile(filepath.Join(dir, "retained.pub"), line, 0o600); err != nil {
		t.Fatal(err)
	}
	keys2, err := MembershipPublicKeys(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	if keys2[m.KeyID] == nil {
		t.Fatal("active key missing when a retained key is present")
	}
	if keys2["retained-membership-v0"] == nil {
		t.Fatalf("retained key not loaded from the trust bundle: %v", keys2)
	}
}
