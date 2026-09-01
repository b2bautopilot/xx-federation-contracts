package componentidentity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc/credentials"
)

type ClientTLSConfig struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

type ServerTLSConfig struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
	CRLFile      string
}

func ClientTransportCredentials(cfg ClientTLSConfig) (credentials.TransportCredentials, error) {
	if strings.TrimSpace(cfg.CertFile) == "" ||
		strings.TrimSpace(cfg.KeyFile) == "" ||
		strings.TrimSpace(cfg.CAFile) == "" ||
		strings.TrimSpace(cfg.ServerName) == "" {
		return nil, fmt.Errorf("mTLS client cert, key, CA, and server name are required")
	}
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(cfg.CertFile), strings.TrimSpace(cfg.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("load mTLS client key pair: %w", err)
	}
	caPEM, err := os.ReadFile(strings.TrimSpace(cfg.CAFile))
	if err != nil {
		return nil, fmt.Errorf("read mTLS CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mTLS CA file did not contain any certificates")
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   strings.TrimSpace(cfg.ServerName),
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}), nil
}

func ServerTransportCredentials(cfg ServerTLSConfig) (credentials.TransportCredentials, error) {
	if strings.TrimSpace(cfg.CertFile) == "" ||
		strings.TrimSpace(cfg.KeyFile) == "" ||
		strings.TrimSpace(cfg.ClientCAFile) == "" {
		return nil, fmt.Errorf("mTLS server cert, key, and client CA are required")
	}
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(cfg.CertFile), strings.TrimSpace(cfg.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("load mTLS server key pair: %w", err)
	}
	caPEM, err := os.ReadFile(strings.TrimSpace(cfg.ClientCAFile))
	if err != nil {
		return nil, fmt.Errorf("read mTLS client CA file: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mTLS client CA file did not contain any certificates")
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	crlFile := strings.TrimSpace(cfg.CRLFile)
	if crlFile != "" {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			crlBytes, err := os.ReadFile(crlFile)
			if err != nil {
				return fmt.Errorf("read CRL file: %w", err)
			}
			block, _ := pem.Decode(crlBytes)
			var der []byte
			if block != nil {
				der = block.Bytes
			} else {
				der = crlBytes
			}
			crl, err := x509.ParseRevocationList(der)
			if err != nil {
				return fmt.Errorf("parse CRL: %w", err)
			}
			for _, chain := range verifiedChains {
				if len(chain) == 0 {
					continue
				}
				leaf := chain[0]
				// Verify CRL signature against the issuing parent if available
				if len(chain) > 1 {
					if err := crl.CheckSignatureFrom(chain[1]); err != nil {
						return fmt.Errorf("invalid CRL signature: %w", err)
					}
				}
				// Check if revoked
				for _, rc := range crl.RevokedCertificates {
					if rc.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
						return fmt.Errorf("client certificate (serial: %s) has been revoked by CRL", leaf.SerialNumber)
					}
				}
			}
			return nil
		}
	}
	return credentials.NewTLS(tlsConfig), nil
}

// ServerTLSOnlyCredentials builds ONE-WAY server-TLS credentials: the server presents its cert (so a client can
// pin/verify it) and encrypts the wire, but does NOT request or verify a client certificate (ClientAuth =
// NoClientCert). ⚠ SECURITY: this authenticates the SERVER to the client and encrypts the transport — it does
// NOT authenticate the CALLER. Caller authentication stays app-layer (the x-builders-dev-identity metadata
// header in dev — NOT a real credential — or an OIDC bearer in prod), independent of the transport. Do NOT read
// "TLS is on" as "safe to expose beyond loopback": enabling this does not change the bind, and a dev-auth
// control plane bound off-loopback is reachable by anyone who can send the header. For transport-level caller
// authentication use mutual TLS (ServerTransportCredentials + a client CA), not this.
func ServerTLSOnlyCredentials(certFile, keyFile string) (credentials.TransportCredentials, error) {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return nil, fmt.Errorf("one-way server TLS requires a server cert and key")
	}
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(certFile), strings.TrimSpace(keyFile))
	if err != nil {
		return nil, fmt.Errorf("load one-way server key pair: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}), nil
}
