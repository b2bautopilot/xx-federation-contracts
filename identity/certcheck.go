package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

type CertificateProfile string

const (
	CertificateProfileServer CertificateProfile = "server"
	CertificateProfileClient CertificateProfile = "client"
)

type CertificateCheckOptions struct {
	Profile       CertificateProfile
	CertFile      string
	KeyFile       string
	CAFile        string
	ExpectedDNS   string
	MinValidFor   time.Duration
	Now           time.Time
	ComponentName string
}

type CertificateCheckReport struct {
	ComponentName string
	Profile       CertificateProfile
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	CACount       int
}

func CheckCertificateMaterial(opts CertificateCheckOptions) (CertificateCheckReport, error) {
	opts.CertFile = strings.TrimSpace(opts.CertFile)
	opts.KeyFile = strings.TrimSpace(opts.KeyFile)
	opts.CAFile = strings.TrimSpace(opts.CAFile)
	opts.ExpectedDNS = strings.TrimSpace(opts.ExpectedDNS)
	opts.ComponentName = strings.TrimSpace(opts.ComponentName)
	if opts.ComponentName == "" {
		opts.ComponentName = string(opts.Profile)
	}
	if opts.CertFile == "" || opts.KeyFile == "" || opts.CAFile == "" {
		return CertificateCheckReport{}, fmt.Errorf("%s certificate, key, and CA files are required", opts.ComponentName)
	}
	if opts.Profile != CertificateProfileServer && opts.Profile != CertificateProfileClient {
		return CertificateCheckReport{}, fmt.Errorf("%s unsupported certificate profile %q", opts.ComponentName, opts.Profile)
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	keyPair, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return CertificateCheckReport{}, fmt.Errorf("%s load key pair: %w", opts.ComponentName, err)
	}
	if len(keyPair.Certificate) == 0 {
		return CertificateCheckReport{}, fmt.Errorf("%s certificate file did not contain a leaf certificate", opts.ComponentName)
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return CertificateCheckReport{}, fmt.Errorf("%s parse leaf certificate: %w", opts.ComponentName, err)
	}
	caCount, err := parseCACount(opts.CAFile)
	if err != nil {
		return CertificateCheckReport{}, fmt.Errorf("%s %w", opts.ComponentName, err)
	}
	if now.Before(leaf.NotBefore) {
		return CertificateCheckReport{}, fmt.Errorf("%s certificate is not valid before %s", opts.ComponentName, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return CertificateCheckReport{}, fmt.Errorf("%s certificate expired at %s", opts.ComponentName, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if opts.MinValidFor > 0 && now.Add(opts.MinValidFor).After(leaf.NotAfter) {
		return CertificateCheckReport{}, fmt.Errorf("%s certificate expires before required rotation window: not_after=%s min_valid_for=%s", opts.ComponentName, leaf.NotAfter.UTC().Format(time.RFC3339), opts.MinValidFor)
	}
	switch opts.Profile {
	case CertificateProfileServer:
		if !certificateAllowsUsage(leaf, x509.ExtKeyUsageServerAuth) {
			return CertificateCheckReport{}, fmt.Errorf("%s certificate does not allow server auth", opts.ComponentName)
		}
		if opts.ExpectedDNS != "" {
			if err := leaf.VerifyHostname(opts.ExpectedDNS); err != nil {
				return CertificateCheckReport{}, fmt.Errorf("%s certificate SAN does not match %q: %w", opts.ComponentName, opts.ExpectedDNS, err)
			}
		}
	case CertificateProfileClient:
		if !certificateAllowsUsage(leaf, x509.ExtKeyUsageClientAuth) {
			return CertificateCheckReport{}, fmt.Errorf("%s certificate does not allow client auth", opts.ComponentName)
		}
	}
	return CertificateCheckReport{
		ComponentName: opts.ComponentName,
		Profile:       opts.Profile,
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		NotBefore:     leaf.NotBefore.UTC(),
		NotAfter:      leaf.NotAfter.UTC(),
		CACount:       caCount,
	}, nil
}

func certificateAllowsUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, candidate := range cert.ExtKeyUsage {
		if candidate == usage || candidate == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func parseCACount(caFile string) (int, error) {
	caPEM, err := os.ReadFile(strings.TrimSpace(caFile))
	if err != nil {
		return 0, fmt.Errorf("read CA file: %w", err)
	}
	count := 0
	for {
		var block *pem.Block
		block, caPEM = pem.Decode(caPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return 0, fmt.Errorf("parse CA certificate: %w", err)
		}
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("CA file did not contain any certificates")
	}
	return count, nil
}
