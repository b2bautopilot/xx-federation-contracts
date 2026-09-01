package componentidentity

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WorkloadCAProvider abstracts the backend signing authority for the mutual TLS PKI.
type WorkloadCAProvider interface {
	IssueCertificate(ctx context.Context, profile CertificateProfile, commonName string, dnsNames []string, uris []string, ttl time.Duration) (IssuedCertificate, error)
	TrustRoots(ctx context.Context) ([]*x509.Certificate, error)
}

// LocalFSWorkloadCAProvider implements WorkloadCAProvider using a local PEM certificate authority.
type LocalFSWorkloadCAProvider struct {
	CA CertificateAuthority
}

func NewLocalFSWorkloadCAProvider(ca CertificateAuthority) *LocalFSWorkloadCAProvider {
	return &LocalFSWorkloadCAProvider{CA: ca}
}

func (p *LocalFSWorkloadCAProvider) IssueCertificate(ctx context.Context, profile CertificateProfile, commonName string, dnsNames []string, uris []string, ttl time.Duration) (IssuedCertificate, error) {
	return IssueCertificate(CertificateIssueOptions{
		Profile:    profile,
		CommonName: commonName,
		DNSNames:   dnsNames,
		URIs:       uris,
		TTL:        ttl,
		CA:         p.CA,
	})
}

func (p *LocalFSWorkloadCAProvider) TrustRoots(ctx context.Context) ([]*x509.Certificate, error) {
	if p.CA.Certificate == nil {
		return nil, fmt.Errorf("local FS CA certificate is nil")
	}
	return []*x509.Certificate{p.CA.Certificate}, nil
}

// VaultWorkloadCAProvider implements WorkloadCAProvider using HashiCorp Vault's PKI engine API.
type VaultWorkloadCAProvider struct {
	Address       string
	Token         string
	PKIEnginePath string
	Role          string
	HTTPClient    *http.Client
}

func NewVaultWorkloadCAProvider(address, token, pkiEnginePath, role string, httpClient *http.Client) *VaultWorkloadCAProvider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &VaultWorkloadCAProvider{
		Address:       address,
		Token:         token,
		PKIEnginePath: pkiEnginePath,
		Role:          role,
		HTTPClient:    httpClient,
	}
}

type vaultSignRequest struct {
	CSR               string `json:"csr"`
	CommonName        string `json:"common_name,omitempty"`
	AltNames          string `json:"alt_names,omitempty"`
	URISans           string `json:"uri_sans,omitempty"`
	TTL               string `json:"ttl,omitempty"`
	ExcludeCNFromSANs bool   `json:"exclude_cn_from_sans,omitempty"`
}

type vaultSignResponse struct {
	Data struct {
		Certificate string   `json:"certificate"`
		CAChain     []string `json:"ca_chain"`
		IssuingCA   string   `json:"issuing_ca"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

func (p *VaultWorkloadCAProvider) IssueCertificate(ctx context.Context, profile CertificateProfile, commonName string, dnsNames []string, uris []string, ttl time.Duration) (IssuedCertificate, error) {
	csrOpts := CertificateSigningRequestOptions{
		Profile:    profile,
		CommonName: commonName,
		DNSNames:   dnsNames,
		URIs:       uris,
	}
	csr, err := GenerateCertificateSigningRequest(csrOpts)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: create CSR: %w", err)
	}

	// Prepare Vault sign API payload
	reqBody := vaultSignRequest{
		CSR:               string(csr.CSRPEM),
		CommonName:        commonName,
		AltNames:          strings.Join(dnsNames, ","),
		URISans:           strings.Join(uris, ","),
		ExcludeCNFromSANs: true,
	}
	if ttl > 0 {
		reqBody.TTL = fmt.Sprintf("%dh", int(ttl.Hours()))
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: marshal request: %w", err)
	}

	pkiPath := p.PKIEnginePath
	if pkiPath == "" {
		pkiPath = "pki"
	}
	roleName := p.Role
	if roleName == "" {
		roleName = "builders-net"
	}

	endpoint, err := url.JoinPath(p.Address, "/v1", pkiPath, "sign", roleName)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: invalid endpoint address: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Token != "" {
		req.Header.Set("X-Vault-Token", p.Token)
	}

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		// Adversarial mitigation: redact raw server output to avoid token/credential leakage
		return IssuedCertificate{}, fmt.Errorf("vault: sign failed status=%d response_len=%d", resp.StatusCode, len(respBytes))
	}

	var vaultResp vaultSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: decode response: %w", err)
	}

	if len(vaultResp.Errors) > 0 {
		return IssuedCertificate{}, fmt.Errorf("vault: API returned errors: %s", strings.Join(vaultResp.Errors, "; "))
	}

	certPEMBytes := []byte(vaultResp.Data.Certificate)
	block, _ := pem.Decode(certPEMBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return IssuedCertificate{}, fmt.Errorf("vault: invalid certificate PEM returned")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("vault: parse certificate: %w", err)
	}

	return IssuedCertificate{
		Certificate: cert,
		CertPEM:     certPEMBytes,
		KeyPEM:      csr.KeyPEM,
	}, nil
}

func (p *VaultWorkloadCAProvider) TrustRoots(ctx context.Context) ([]*x509.Certificate, error) {
	pkiPath := p.PKIEnginePath
	if pkiPath == "" {
		pkiPath = "pki"
	}
	endpoint, err := url.JoinPath(p.Address, "/v1", pkiPath, "ca")
	if err != nil {
		return nil, fmt.Errorf("vault: invalid endpoint address: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: new request: %w", err)
	}
	if p.Token != "" {
		req.Header.Set("X-Vault-Token", p.Token)
	}

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: CA fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: CA fetch failed status=%d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vault: read CA body: %w", err)
	}

	// Vault returns DER or PEM. Decode PEM if present, fall back to DER.
	var certs []*x509.Certificate
	rest := respBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
	}

	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(respBytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("vault: no valid certificates found in CA response")
	}

	return certs, nil
}

// SpireWorkloadCAProvider simulates fetching SPIFFE Verifiable Identity Documents (SVIDs)
// from a SPIFFE Workload API agent.
type SpireWorkloadCAProvider struct {
	SocketPath  string
	TrustDomain string
	LocalCA     CertificateAuthority
}

func NewSpireWorkloadCAProvider(socketPath, trustDomain string, localCA CertificateAuthority) *SpireWorkloadCAProvider {
	return &SpireWorkloadCAProvider{
		SocketPath:  socketPath,
		TrustDomain: trustDomain,
		LocalCA:     localCA,
	}
}

func (p *SpireWorkloadCAProvider) IssueCertificate(ctx context.Context, profile CertificateProfile, commonName string, dnsNames []string, uris []string, ttl time.Duration) (IssuedCertificate, error) {
	// Validate SPIFFE ID matches trust domain
	for _, uriStr := range uris {
		u, err := url.Parse(uriStr)
		if err != nil {
			return IssuedCertificate{}, fmt.Errorf("spire: invalid URI: %w", err)
		}
		if u.Scheme != "spiffe" {
			continue
		}
		if u.Host != p.TrustDomain {
			return IssuedCertificate{}, fmt.Errorf("spire: URI host %q does not match trust domain %q", u.Host, p.TrustDomain)
		}
	}

	if p.LocalCA.Certificate == nil || p.LocalCA.PrivateKey == nil {
		spireCA, err := GenerateCertificateAuthority(CertificateAuthorityOptions{
			CommonName: "spire-trust-domain-ca",
			TTL:        365 * 24 * time.Hour,
		})
		if err != nil {
			return IssuedCertificate{}, fmt.Errorf("spire: autogen simulated CA: %w", err)
		}
		p.LocalCA = spireCA
	}

	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = 1 * time.Hour // SPIRE default SVID TTL
	}

	issued, err := IssueCertificate(CertificateIssueOptions{
		Profile:    profile,
		CommonName: commonName,
		DNSNames:   dnsNames,
		URIs:       uris,
		NotBefore:  now,
		TTL:        ttl,
		CA:         p.LocalCA,
	})
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("spire: issue SVID: %w", err)
	}

	return issued, nil
}

func (p *SpireWorkloadCAProvider) TrustRoots(ctx context.Context) ([]*x509.Certificate, error) {
	if p.LocalCA.Certificate == nil {
		spireCA, err := GenerateCertificateAuthority(CertificateAuthorityOptions{
			CommonName: "spire-trust-domain-ca",
			TTL:        365 * 24 * time.Hour,
		})
		if err != nil {
			return nil, fmt.Errorf("spire: autogen simulated CA: %w", err)
		}
		p.LocalCA = spireCA
	}
	return []*x509.Certificate{p.LocalCA.Certificate}, nil
}
