package componentidentity

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

type IssuedCSRVerificationOptions struct {
	Profile       CertificateProfile
	CertFile      string
	CSRFile       string
	CAFile        string
	MinValidFor   time.Duration
	Now           time.Time
	ComponentName string
}

type IssuedCSRVerificationReport struct {
	ComponentName string
	Profile       CertificateProfile
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	DNSNames      []string
	URIs          []string
	CACount       int
}

func VerifyIssuedCertificateForCSR(opts IssuedCSRVerificationOptions) (IssuedCSRVerificationReport, error) {
	opts.CertFile = strings.TrimSpace(opts.CertFile)
	opts.CSRFile = strings.TrimSpace(opts.CSRFile)
	opts.CAFile = strings.TrimSpace(opts.CAFile)
	opts.ComponentName = strings.TrimSpace(opts.ComponentName)
	if opts.ComponentName == "" {
		opts.ComponentName = string(opts.Profile)
	}
	if opts.CertFile == "" || opts.CSRFile == "" {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s certificate and CSR files are required", opts.ComponentName)
	}
	if opts.Profile != CertificateProfileServer && opts.Profile != CertificateProfileClient {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s unsupported certificate profile %q", opts.ComponentName, opts.Profile)
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	certs, err := loadCertificates(opts.CertFile)
	if err != nil {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s %w", opts.ComponentName, err)
	}
	if len(certs) == 0 {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s certificate file did not contain a leaf certificate", opts.ComponentName)
	}
	leaf := certs[0]
	request, err := loadCertificateRequest(opts.CSRFile)
	if err != nil {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s %w", opts.ComponentName, err)
	}
	if err := request.CheckSignature(); err != nil {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s CSR signature check failed: %w", opts.ComponentName, err)
	}
	if err := verifyPublicKeyMatches(request.PublicKey, leaf.PublicKey); err != nil {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s issued certificate does not match CSR public key: %w", opts.ComponentName, err)
	}
	if request.Subject.CommonName != "" && leaf.Subject.CommonName != request.Subject.CommonName {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s issued certificate common name %q does not match CSR common name %q", opts.ComponentName, leaf.Subject.CommonName, request.Subject.CommonName)
	}
	if now.Before(leaf.NotBefore) {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s certificate is not valid before %s", opts.ComponentName, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s certificate expired at %s", opts.ComponentName, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if opts.MinValidFor > 0 && now.Add(opts.MinValidFor).After(leaf.NotAfter) {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s certificate expires before required rotation window: not_after=%s min_valid_for=%s", opts.ComponentName, leaf.NotAfter.UTC().Format(time.RFC3339), opts.MinValidFor)
	}
	switch opts.Profile {
	case CertificateProfileServer:
		if len(request.DNSNames) == 0 {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s server CSR did not request a DNS SAN", opts.ComponentName)
		}
		if !certificateHasExplicitUsage(leaf, x509.ExtKeyUsageServerAuth) {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s issued certificate does not allow server auth", opts.ComponentName)
		}
		if !csrRequestsUsage(request, oidExtKeyUsageServerAuth) {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s CSR did not request server auth EKU", opts.ComponentName)
		}
	case CertificateProfileClient:
		if len(request.URIs) == 0 {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s client CSR did not request a URI SAN", opts.ComponentName)
		}
		if !certificateHasExplicitUsage(leaf, x509.ExtKeyUsageClientAuth) {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s issued certificate does not allow client auth", opts.ComponentName)
		}
		if !csrRequestsUsage(request, oidExtKeyUsageClientAuth) {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s CSR did not request client auth EKU", opts.ComponentName)
		}
	}
	if err := ensureDNSNamesPreserved(request.DNSNames, leaf.DNSNames); err != nil {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s %w", opts.ComponentName, err)
	}
	if err := ensureURIsPreserved(request, leaf); err != nil {
		return IssuedCSRVerificationReport{}, fmt.Errorf("%s %w", opts.ComponentName, err)
	}
	caCount := 0
	if opts.CAFile != "" {
		caCount, err = verifyCertificateChain(opts.CAFile, certs, leaf, opts.Profile, now)
		if err != nil {
			return IssuedCSRVerificationReport{}, fmt.Errorf("%s %w", opts.ComponentName, err)
		}
	}
	return IssuedCSRVerificationReport{
		ComponentName: opts.ComponentName,
		Profile:       opts.Profile,
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		NotBefore:     leaf.NotBefore.UTC(),
		NotAfter:      leaf.NotAfter.UTC(),
		DNSNames:      slices.Clone(leaf.DNSNames),
		URIs:          certificateURIStrings(leaf),
		CACount:       caCount,
	}, nil
}

func loadCertificates(path string) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func loadCertificateRequest(path string) (*x509.CertificateRequest, error) {
	csrPEM, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read CSR file: %w", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR file did not contain a certificate request")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return request, nil
}

func verifyPublicKeyMatches(requestKey, certKey any) error {
	requestDER, err := x509.MarshalPKIXPublicKey(requestKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}
	certDER, err := x509.MarshalPKIXPublicKey(certKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	if !bytes.Equal(requestDER, certDER) {
		return fmt.Errorf("public keys differ")
	}
	return nil
}

func ensureDNSNamesPreserved(requested, issued []string) error {
	for _, want := range requested {
		if !slices.Contains(issued, want) {
			return fmt.Errorf("issued certificate is missing requested DNS SAN %q", want)
		}
	}
	return nil
}

func ensureURIsPreserved(request *x509.CertificateRequest, cert *x509.Certificate) error {
	issued := certificateURIStrings(cert)
	for _, uri := range request.URIs {
		if !slices.Contains(issued, uri.String()) {
			return fmt.Errorf("issued certificate is missing requested URI SAN %q", uri.String())
		}
	}
	return nil
}

func certificateURIStrings(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		out = append(out, uri.String())
	}
	return out
}

func csrRequestsUsage(request *x509.CertificateRequest, want asn1.ObjectIdentifier) bool {
	for _, extension := range request.Extensions {
		if !extension.Id.Equal(oidExtensionExtendedKeyUsage) {
			continue
		}
		var usages []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(extension.Value, &usages); err != nil {
			return false
		}
		for _, usage := range usages {
			if usage.Equal(want) {
				return true
			}
		}
	}
	return false
}

func certificateHasExplicitUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, candidate := range cert.ExtKeyUsage {
		if candidate == usage || candidate == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func verifyCertificateChain(caFile string, certs []*x509.Certificate, leaf *x509.Certificate, profile CertificateProfile, now time.Time) (int, error) {
	caPEM, err := os.ReadFile(strings.TrimSpace(caFile))
	if err != nil {
		return 0, fmt.Errorf("read CA file: %w", err)
	}
	roots := x509.NewCertPool()
	caCount := 0
	for {
		var block *pem.Block
		block, caPEM = pem.Decode(caPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, fmt.Errorf("parse CA certificate: %w", err)
		}
		roots.AddCert(ca)
		caCount++
	}
	if caCount == 0 {
		return 0, fmt.Errorf("CA file did not contain any certificates")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	keyUsage := x509.ExtKeyUsageServerAuth
	if profile == CertificateProfileClient {
		keyUsage = x509.ExtKeyUsageClientAuth
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{keyUsage},
	}); err != nil {
		return 0, fmt.Errorf("verify certificate chain: %w", err)
	}
	return caCount, nil
}
