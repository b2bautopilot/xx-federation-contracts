package keymaterial_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/b2bautopilot/xyz-b2b/packages/key-material"
	"golang.org/x/crypto/ssh"
)

func TestDevLocalKeyMaterialIsStableAndSeparatedByPurpose(t *testing.T) {
	firstAudit := keymaterial.DevLocalAuditSigningKey()
	secondAudit := keymaterial.DevLocalAuditSigningKey()
	sshCA := keymaterial.DevLocalSSHCAKey()

	if !bytes.Equal(firstAudit, secondAudit) {
		t.Fatal("expected dev-local audit signing key to be stable")
	}
	if bytes.Equal(firstAudit, sshCA) {
		t.Fatal("expected dev-local audit and SSH CA keys to be distinct")
	}
}

func TestProviderForKMSVaultFailsClosed(t *testing.T) {
	provider, err := keymaterial.ProviderForMode("kms_vault")
	if err != nil {
		t.Fatalf("ProviderForMode returned error: %v", err)
	}

	if _, err := provider.AuditSigningMaterial(context.Background()); !errors.Is(err, keymaterial.ErrProviderUnavailable) {
		t.Fatalf("AuditSigningMaterial error = %v, want provider unavailable", err)
	}
	if _, err := provider.SSHCASigner(context.Background()); !errors.Is(err, keymaterial.ErrProviderUnavailable) {
		t.Fatalf("SSHCASigner error = %v, want provider unavailable", err)
	}
}

func TestKMSVaultMountedSecretProviderLoadsKeys(t *testing.T) {
	keyFile := writeEd25519PrivateKey(t)
	provider, err := keymaterial.ProviderFromConfig(keymaterial.ProviderConfig{
		Mode:                "kms_vault",
		AuditSigningKeyID:   "vault-ed25519-audit-key",
		AuditSigningKeyFile: keyFile,
		SSHCAKeyFile:        keyFile,
	})
	if err != nil {
		t.Fatalf("ProviderFromConfig returned error: %v", err)
	}

	auditMaterial, err := provider.AuditSigningMaterial(context.Background())
	if err != nil {
		t.Fatalf("AuditSigningMaterial returned error: %v", err)
	}
	if auditMaterial.KeyID != "vault-ed25519-audit-key" {
		t.Fatalf("KeyID = %q", auditMaterial.KeyID)
	}
	if len(auditMaterial.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key size = %d", len(auditMaterial.PrivateKey))
	}

	signer, err := provider.SSHCASigner(context.Background())
	if err != nil {
		t.Fatalf("SSHCASigner returned error: %v", err)
	}
	if signer.PublicKey() == nil {
		t.Fatal("expected SSH CA public key")
	}
}

func TestLoadAuditPublicKeysUsesAuthorizedKeyCommentAsKeyID(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("new SSH public key: %v", err)
	}
	authorizedKey := append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPublicKey)), []byte(" retained-audit-key\n")...)
	if err := os.WriteFile(filepath.Join(dir, "ignored-name.pub"), authorizedKey, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	keys, err := keymaterial.LoadAuditPublicKeys(dir)

	if err != nil {
		t.Fatalf("LoadAuditPublicKeys returned error: %v", err)
	}
	if _, ok := keys["retained-audit-key"]; !ok {
		t.Fatalf("expected retained-audit-key, got %#v", keys)
	}
}

func writeEd25519PrivateKey(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "ed25519.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}
