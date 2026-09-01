package identity_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/identity"
)

func TestLocalFSWorkloadCAProvider(t *testing.T) {
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "test-local-ca",
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	provider := identity.NewLocalFSWorkloadCAProvider(ca)

	issued, err := provider.IssueCertificate(
		context.Background(),
		identity.CertificateProfileServer,
		"test-server",
		[]string{"localhost"},
		[]string{"spiffe://builders-net/ns/test"},
		1*time.Hour,
	)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if issued.Certificate.Subject.CommonName != "test-server" {
		t.Errorf("Expected CN=test-server, got %s", issued.Certificate.Subject.CommonName)
	}

	roots, err := provider.TrustRoots(context.Background())
	if err != nil {
		t.Fatalf("TrustRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0].Subject.CommonName != "test-local-ca" {
		t.Errorf("Unexpected trust roots: %v", roots)
	}
}

func TestVaultWorkloadCAProvider(t *testing.T) {
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "test-vault-ca",
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Spin up a mock Vault HTTP Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock token validation
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if r.URL.Path == "/v1/pki/ca" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(ca.CertPEM)
			return
		}

		if r.URL.Path == "/v1/pki/sign/builders-net" {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			csrPEMStr, _ := body["csr"].(string)

			// Issue a certificate using local CA for the CSR
			block, _ := pem.Decode([]byte(csrPEMStr))
			if block == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			issued, err := identity.IssueCertificate(identity.CertificateIssueOptions{
				Profile:    identity.CertificateProfileServer,
				CommonName: csr.Subject.CommonName,
				DNSNames:   csr.DNSNames,
				URIs:       []string{"spiffe://builders-net/ns/test"},
				TTL:        1 * time.Hour,
				CA:         ca,
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			response := map[string]interface{}{
				"data": map[string]interface{}{
					"certificate": string(issued.CertPEM),
					"ca_chain":    []string{string(ca.CertPEM)},
					"issuing_ca":  string(ca.CertPEM),
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	provider := identity.NewVaultWorkloadCAProvider(srv.URL, "test-token", "pki", "builders-net", srv.Client())

	// 1. Test IssueCertificate
	issued, err := provider.IssueCertificate(
		context.Background(),
		identity.CertificateProfileServer,
		"test-vault-issued",
		[]string{"localhost"},
		[]string{"spiffe://builders-net/ns/test"},
		1*time.Hour,
	)
	if err != nil {
		t.Fatalf("Vault IssueCertificate failed: %v", err)
	}
	if issued.Certificate.Subject.CommonName != "test-vault-issued" {
		t.Errorf("Expected CN=test-vault-issued, got %s", issued.Certificate.Subject.CommonName)
	}

	// 2. Test TrustRoots
	roots, err := provider.TrustRoots(context.Background())
	if err != nil {
		t.Fatalf("Vault TrustRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0].Subject.CommonName != "test-vault-ca" {
		t.Errorf("Unexpected Vault trust roots: %v", roots)
	}
}

func TestSpireWorkloadCAProvider(t *testing.T) {
	ca, err := identity.GenerateCertificateAuthority(identity.CertificateAuthorityOptions{
		CommonName: "test-spire-ca",
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	provider := identity.NewSpireWorkloadCAProvider("/tmp/spire-agent.sock", "builders-net", ca)

	issued, err := provider.IssueCertificate(
		context.Background(),
		identity.CertificateProfileServer,
		"test-spire-workload",
		[]string{"localhost"},
		[]string{"spiffe://builders-net/ns/test"},
		1*time.Hour,
	)
	if err != nil {
		t.Fatalf("SPIRE IssueCertificate failed: %v", err)
	}
	if issued.Certificate.Subject.CommonName != "test-spire-workload" {
		t.Errorf("Expected CN=test-spire-workload, got %s", issued.Certificate.Subject.CommonName)
	}

	roots, err := provider.TrustRoots(context.Background())
	if err != nil {
		t.Fatalf("SPIRE TrustRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0].Subject.CommonName != "test-spire-ca" {
		t.Errorf("Unexpected SPIRE trust roots: %v", roots)
	}
}
