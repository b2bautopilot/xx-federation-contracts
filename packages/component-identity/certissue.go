package componentidentity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
}

type IssuedCertificate struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

type CertificateSigningRequest struct {
	Request *x509.CertificateRequest
	CSRPEM  []byte
	KeyPEM  []byte
}

type CertificateAuthorityOptions struct {
	CommonName string
	NotBefore  time.Time
	TTL        time.Duration
	Random     io.Reader
}

type CertificateIssueOptions struct {
	Profile    CertificateProfile
	CommonName string
	DNSNames   []string
	URIs       []string
	NotBefore  time.Time
	TTL        time.Duration
	CA         CertificateAuthority
	Random     io.Reader
}

type CertificateSigningRequestOptions struct {
	Profile    CertificateProfile
	CommonName string
	DNSNames   []string
	URIs       []string
	Random     io.Reader
}

var (
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtKeyUsageServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func GenerateCertificateAuthority(opts CertificateAuthorityOptions) (CertificateAuthority, error) {
	now := opts.NotBefore.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = "builders-net-mtls-ca"
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial(random)
	if err != nil {
		return CertificateAuthority{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(random, template, template, publicKey, privateKey)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("create CA certificate: %w", err)
	}
	keyPEM, err := encodePrivateKey(privateKey)
	if err != nil {
		return CertificateAuthority{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	return CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      keyPEM,
	}, nil
}

func LoadCertificateAuthority(certFile, keyFile string) (CertificateAuthority, error) {
	certPEM, err := os.ReadFile(strings.TrimSpace(certFile))
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(strings.TrimSpace(keyFile))
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("read CA private key: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertificateAuthority{}, fmt.Errorf("CA certificate file did not contain a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return CertificateAuthority{}, fmt.Errorf("CA certificate is not a certificate authority")
	}
	privateKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("parse CA private key: %w", err)
	}
	return CertificateAuthority{Certificate: cert, PrivateKey: privateKey, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func IssueCertificate(opts CertificateIssueOptions) (IssuedCertificate, error) {
	if opts.CA.Certificate == nil || opts.CA.PrivateKey == nil {
		return IssuedCertificate{}, fmt.Errorf("CA certificate and private key are required")
	}
	if opts.Profile != CertificateProfileServer && opts.Profile != CertificateProfileClient {
		return IssuedCertificate{}, fmt.Errorf("unsupported certificate profile %q", opts.Profile)
	}
	now := opts.NotBefore.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		return IssuedCertificate{}, fmt.Errorf("certificate common name is required")
	}
	// Draw the key first, then the serial (via newLeafTemplate) — same random-draw
	// order as before the helper was extracted, so callers seeding Random are unaffected.
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("generate certificate key: %w", err)
	}
	template, err := newLeafTemplate(opts.Profile, commonName, opts.DNSNames, opts.URIs, now, ttl, random)
	if err != nil {
		return IssuedCertificate{}, err
	}
	der, err := x509.CreateCertificate(random, template, opts.CA.Certificate, publicKey, opts.CA.PrivateKey)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyPEM, err := encodePrivateKey(privateKey)
	if err != nil {
		return IssuedCertificate{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("parse generated certificate: %w", err)
	}
	return IssuedCertificate{
		Certificate: cert,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      keyPEM,
	}, nil
}

// newLeafTemplate builds the x509 leaf template shared by IssueCertificate and
// SignCertificateRequest, so an internally-keyed leaf and a leaf signed from an
// external CSR carry an IDENTICAL profile. The SANs come ONLY from the caller
// (dnsNames/uriStrings) — never from any CSR — which is the identity boundary for
// the CSR-signing path: the server stamps the SAN it authorizes, not what the CSR asks.
func newLeafTemplate(profile CertificateProfile, commonName string, dnsNames, uriStrings []string, now time.Time, ttl time.Duration, random io.Reader) (*x509.Certificate, error) {
	serial, err := randomSerial(random)
	if err != nil {
		return nil, err
	}
	uris, err := parseURIs(uriStrings)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     cleanStrings(dnsNames),
		URIs:         uris,
	}
	switch profile {
	case CertificateProfileServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if len(template.DNSNames) == 0 {
			return nil, fmt.Errorf("server certificate requires at least one DNS SAN")
		}
	case CertificateProfileClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if len(template.URIs) == 0 {
			return nil, fmt.Errorf("client certificate requires at least one URI SAN")
		}
	default:
		return nil, fmt.Errorf("unsupported certificate profile %q", profile)
	}
	return template, nil
}

// CertificateSignOptions configures SignCertificateRequest. The leaf's SAN/EKU are
// taken from these fields (server-authorized), NOT from the CSR.
type CertificateSignOptions struct {
	Profile    CertificateProfile
	CommonName string // if empty, the CSR's own CommonName is used (cosmetic; identity is the SAN)
	DNSNames   []string
	URIs       []string
	NotBefore  time.Time
	TTL        time.Duration
	CA         CertificateAuthority
	Random     io.Reader
}

// SignCertificateRequest signs an EXTERNALLY-generated CSR into a leaf, using the
// CSR's public key (so the requester's private key never leaves its host). It is the
// no-key-movement counterpart to IssueCertificate and produces a byte-identical
// profile via newLeafTemplate. Security:
//   - csr.CheckSignature() is verified (proof the requester holds the private key).
//   - The SAN/EKU are stamped from opts (server-authorized) and the CSR's own
//     SANs/extensions are IGNORED — a requester cannot obtain a cert for an identity
//     it was not authorized for.
//
// The returned IssuedCertificate has no KeyPEM (the key stays with the requester).
func SignCertificateRequest(csr *x509.CertificateRequest, opts CertificateSignOptions) (IssuedCertificate, error) {
	if opts.CA.Certificate == nil || opts.CA.PrivateKey == nil {
		return IssuedCertificate{}, fmt.Errorf("CA certificate and private key are required")
	}
	if opts.Profile != CertificateProfileServer && opts.Profile != CertificateProfileClient {
		return IssuedCertificate{}, fmt.Errorf("unsupported certificate profile %q", opts.Profile)
	}
	if csr == nil {
		return IssuedCertificate{}, fmt.Errorf("a parsed certificate signing request is required")
	}
	if csr.PublicKey == nil {
		return IssuedCertificate{}, fmt.Errorf("certificate signing request is missing a public key")
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedCertificate{}, fmt.Errorf("certificate signing request signature is invalid: %w", err)
	}
	now := opts.NotBefore.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = strings.TrimSpace(csr.Subject.CommonName)
	}
	if commonName == "" {
		return IssuedCertificate{}, fmt.Errorf("certificate common name is required (empty in both options and CSR)")
	}
	template, err := newLeafTemplate(opts.Profile, commonName, opts.DNSNames, opts.URIs, now, ttl, random)
	if err != nil {
		return IssuedCertificate{}, err
	}
	der, err := x509.CreateCertificate(random, template, opts.CA.Certificate, csr.PublicKey, opts.CA.PrivateKey)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("sign certificate request: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("parse signed certificate: %w", err)
	}
	return IssuedCertificate{
		Certificate: cert,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

type SelfSignedServerCertificateOptions struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	NotBefore   time.Time
	TTL         time.Duration
	Random      io.Reader
}

// GenerateSelfSignedServerCertificate mints a SELF-SIGNED ServerAuth leaf (not a CA) for one-way TLS: the server
// presents it and clients pin it DIRECTLY via --tls-ca-file (no separate CA). It mirrors IssueCertificate's server
// template but self-signs (parent==template, no CA) and adds IP SANs (IssueCertificate is DNS-only, which can't
// cover a loopback control plane a client dials by IP). Requires ≥1 SAN (DNS or IP) after trimming empties.
func GenerateSelfSignedServerCertificate(opts SelfSignedServerCertificateOptions) (IssuedCertificate, error) {
	now := opts.NotBefore.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		return IssuedCertificate{}, fmt.Errorf("certificate common name is required")
	}
	dnsNames := cleanStrings(opts.DNSNames)
	ips := cleanIPs(opts.IPAddresses)
	if len(dnsNames)+len(ips) == 0 {
		return IssuedCertificate{}, fmt.Errorf("self-signed server certificate requires at least one SAN (DNS or IP)")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("generate certificate key: %w", err)
	}
	serial, err := randomSerial(random)
	if err != nil {
		return IssuedCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(random, template, template, publicKey, privateKey) // self-signed: parent==template
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyPEM, err := encodePrivateKey(privateKey)
	if err != nil {
		return IssuedCertificate{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("parse generated certificate: %w", err)
	}
	return IssuedCertificate{
		Certificate: cert,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      keyPEM,
	}, nil
}

// cleanIPs drops nil entries (defensive; the caller classifies operator SAN input via net.ParseIP).
func cleanIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func GenerateCertificateSigningRequest(opts CertificateSigningRequestOptions) (CertificateSigningRequest, error) {
	if opts.Profile != CertificateProfileServer && opts.Profile != CertificateProfileClient {
		return CertificateSigningRequest{}, fmt.Errorf("unsupported certificate profile %q", opts.Profile)
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		return CertificateSigningRequest{}, fmt.Errorf("certificate common name is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return CertificateSigningRequest{}, fmt.Errorf("generate CSR key: %w", err)
	}
	uris, err := parseURIs(opts.URIs)
	if err != nil {
		return CertificateSigningRequest{}, err
	}
	template := &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: commonName},
		DNSNames:  cleanStrings(opts.DNSNames),
		URIs:      uris,
		PublicKey: publicKey,
	}
	switch opts.Profile {
	case CertificateProfileServer:
		if len(template.DNSNames) == 0 {
			return CertificateSigningRequest{}, fmt.Errorf("server CSR requires at least one DNS SAN")
		}
	case CertificateProfileClient:
		if len(template.URIs) == 0 {
			return CertificateSigningRequest{}, fmt.Errorf("client CSR requires at least one URI SAN")
		}
	}
	eku, err := requestedExtendedKeyUsage(opts.Profile)
	if err != nil {
		return CertificateSigningRequest{}, err
	}
	template.ExtraExtensions = []pkix.Extension{eku}
	der, err := x509.CreateCertificateRequest(random, template, privateKey)
	if err != nil {
		return CertificateSigningRequest{}, fmt.Errorf("create CSR: %w", err)
	}
	keyPEM, err := encodePrivateKey(privateKey)
	if err != nil {
		return CertificateSigningRequest{}, err
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return CertificateSigningRequest{}, fmt.Errorf("parse generated CSR: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return CertificateSigningRequest{}, fmt.Errorf("verify generated CSR signature: %w", err)
	}
	return CertificateSigningRequest{
		Request: request,
		CSRPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		KeyPEM:  keyPEM,
	}, nil
}

func requestedExtendedKeyUsage(profile CertificateProfile) (pkix.Extension, error) {
	var usage asn1.ObjectIdentifier
	switch profile {
	case CertificateProfileServer:
		usage = oidExtKeyUsageServerAuth
	case CertificateProfileClient:
		usage = oidExtKeyUsageClientAuth
	default:
		return pkix.Extension{}, fmt.Errorf("unsupported certificate profile %q", profile)
	}
	value, err := asn1.Marshal([]asn1.ObjectIdentifier{usage})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal CSR extended key usage: %w", err)
	}
	return pkix.Extension{Id: oidExtensionExtendedKeyUsage, Value: value}, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("private key PEM block is missing")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	return signer, nil
}

func encodePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func randomSerial(random io.Reader) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(random, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

func parseURIs(values []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(values))
	for _, value := range cleanStrings(values) {
		parsed, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("parse URI SAN %q: %w", value, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
