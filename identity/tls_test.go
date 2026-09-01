package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b2bautopilot/xx-federation-contracts/identity"
	"google.golang.org/grpc/credentials"
)

// mtlsHandshake runs a real server/client TLS handshake over a loopback TCP connection using
// the EXACT transport credentials the control (server) and agent (client) use. Returns whether
// BOTH sides completed (server admitted the client cert AND client verified the server).
// (A loopback TCP conn is kernel-buffered; net.Pipe would deadlock the multi-flight handshake.)
func mtlsHandshake(t *testing.T, server, client credentials.TransportCredentials, serverName string) bool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		_, _, e := server.ServerHandshake(conn)
		conn.Close()
		done <- e
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, cerr := client.ClientHandshake(ctx, serverName, c)
	c.Close()
	serr := <-done
	if cerr != nil {
		t.Logf("client handshake err: %v", cerr)
	}
	if serr != nil {
		t.Logf("server handshake err: %v", serr)
	}
	return cerr == nil && serr == nil
}

// A sign-agent-minted client cert is ADMITTED by the control's mutual-TLS server; a cert
// from a different CA is REJECTED. This proves the --mtls provisioning path yields a cert
// that the hardened control actually accepts (the live agent-connect this stands in for).
func TestServerAdmitsSignAgentCertRejectsWrongCA(t *testing.T) {
	now := time.Now().UTC() // a real TLS handshake validates against the wall clock, not a fixed test time
	dir := t.TempDir()
	wr := func(name string, pem []byte) string { p := filepath.Join(dir, name); if err := os.WriteFile(p, pem, 0600); err != nil { t.Fatalf("write %s: %v", name, err) }; return p }

	ca := newSignTestCA(t, now)
	caFile := wr("ca.crt", ca.CertPEM)
	// control server cert (signed by ca), DNS SAN the agent will verify against.
	srv, err := identity.IssueCertificate(identity.CertificateIssueOptions{
		Profile: identity.CertificateProfileServer, CommonName: "builders-control",
		DNSNames: []string{"test.control"}, NotBefore: now, TTL: time.Hour, CA: ca,
	})
	if err != nil { t.Fatalf("issue server: %v", err) }
	serverCreds, err := identity.ServerTransportCredentials(identity.ServerTLSConfig{
		CertFile: wr("srv.crt", srv.CertPEM), KeyFile: wr("srv.key", srv.KeyPEM), ClientCAFile: caFile,
	})
	if err != nil { t.Fatalf("server creds: %v", err) }

	// helper: a sign-agent client cert signed by the given CA; returns cert+key files.
	mintAgent := func(prefix string, signCA identity.CertificateAuthority) (string, string) {
		uri := identity.AgentURI(identity.AgentIdentity{TenantID: "t", ProjectID: "t", NodeID: "n"})
		req, err := identity.GenerateCertificateSigningRequest(identity.CertificateSigningRequestOptions{
			Profile: identity.CertificateProfileClient, CommonName: "csr-agent n", URIs: []string{uri},
		})
		if err != nil { t.Fatalf("csr: %v", err) }
		leaf, err := identity.SignCertificateRequest(req.Request, identity.CertificateSignOptions{
			Profile: identity.CertificateProfileClient, URIs: []string{uri}, NotBefore: now, TTL: time.Hour, CA: signCA,
		})
		if err != nil { t.Fatalf("sign: %v", err) }
		return wr(prefix+".crt", leaf.CertPEM), wr(prefix+".key", req.KeyPEM) // the never-moved CSR key
	}

	goodCert, goodKey := mintAgent("good", ca)
	goodClient, err := identity.ClientTransportCredentials(identity.ClientTLSConfig{
		CertFile: goodCert, KeyFile: goodKey, CAFile: caFile, ServerName: "test.control",
	})
	if err != nil { t.Fatalf("good client creds: %v", err) }
	if !mtlsHandshake(t, serverCreds, goodClient, "test.control") {
		t.Fatal("a sign-agent cert signed by the control's client CA must be admitted at the mtls handshake")
	}

	badCert, badKey := mintAgent("bad", newSignTestCA(t, now)) // a DIFFERENT CA
	badClient, err := identity.ClientTransportCredentials(identity.ClientTLSConfig{
		CertFile: badCert, KeyFile: badKey, CAFile: caFile, ServerName: "test.control",
	})
	if err != nil { t.Fatalf("bad client creds: %v", err) }
	if mtlsHandshake(t, serverCreds, badClient, "test.control") {
		t.Fatal("a client cert from a DIFFERENT CA must be REJECTED by the mtls server")
	}
}

func TestClientTransportCredentialsLoadsMTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeClientTLSFixture(t, dir)

	creds, err := identity.ClientTransportCredentials(identity.ClientTLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ServerName: "x-builders-net.test",
	})

	if err != nil {
		t.Fatalf("ClientTransportCredentials returned error: %v", err)
	}
	if creds.Info().SecurityProtocol == "" {
		t.Fatalf("credentials security protocol is empty: %#v", creds.Info())
	}
}

func TestClientTransportCredentialsFailsClosedWhenMaterialMissing(t *testing.T) {
	_, err := identity.ClientTransportCredentials(identity.ClientTLSConfig{})

	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("ClientTransportCredentials error = %v, want required material error", err)
	}
}

func TestServerTransportCredentialsLoadsMTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeClientTLSFixture(t, dir)

	creds, err := identity.ServerTransportCredentials(identity.ServerTLSConfig{
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientCAFile: caFile,
	})

	if err != nil {
		t.Fatalf("ServerTransportCredentials returned error: %v", err)
	}
	if creds.Info().SecurityProtocol == "" {
		t.Fatalf("credentials security protocol is empty: %#v", creds.Info())
	}
}

func TestServerTransportCredentialsFailsClosedWhenMaterialMissing(t *testing.T) {
	_, err := identity.ServerTransportCredentials(identity.ServerTLSConfig{})

	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("ServerTransportCredentials error = %v, want required material error", err)
	}
}

func TestCheckCertificateMaterialValidatesServerProfile(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()
	certFile, keyFile, caFile := writeTLSFixture(t, dir, tlsFixture{
		CommonName:   "builders-control",
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"x-builders-net.internal"},
	})

	report, err := identity.CheckCertificateMaterial(identity.CertificateCheckOptions{
		Profile:       identity.CertificateProfileServer,
		CertFile:      certFile,
		KeyFile:       keyFile,
		CAFile:        caFile,
		ExpectedDNS:   "x-builders-net.internal",
		MinValidFor:   time.Hour,
		Now:           now,
		ComponentName: "control-server",
	})

	if err != nil {
		t.Fatalf("CheckCertificateMaterial returned error: %v", err)
	}
	if report.CACount != 1 || report.Profile != identity.CertificateProfileServer {
		t.Fatalf("unexpected certificate report: %#v", report)
	}
}

func TestCheckCertificateMaterialFailsWhenCertExpiresInsideRotationWindow(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()
	certFile, keyFile, caFile := writeTLSFixture(t, dir, tlsFixture{
		CommonName:   "builders-agent",
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(30 * time.Minute),
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	_, err := identity.CheckCertificateMaterial(identity.CertificateCheckOptions{
		Profile:       identity.CertificateProfileClient,
		CertFile:      certFile,
		KeyFile:       keyFile,
		CAFile:        caFile,
		MinValidFor:   time.Hour,
		Now:           now,
		ComponentName: "agent-client",
	})

	if err == nil || !strings.Contains(err.Error(), "rotation window") {
		t.Fatalf("CheckCertificateMaterial error = %v, want rotation window error", err)
	}
}

func TestCheckCertificateMaterialFailsWrongProfile(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()
	certFile, keyFile, caFile := writeTLSFixture(t, dir, tlsFixture{
		CommonName:   "builders-agent",
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	_, err := identity.CheckCertificateMaterial(identity.CertificateCheckOptions{
		Profile:       identity.CertificateProfileServer,
		CertFile:      certFile,
		KeyFile:       keyFile,
		CAFile:        caFile,
		MinValidFor:   time.Hour,
		Now:           now,
		ComponentName: "control-server",
	})

	if err == nil || !strings.Contains(err.Error(), "server auth") {
		t.Fatalf("CheckCertificateMaterial error = %v, want server auth error", err)
	}
}

func writeClientTLSFixture(t *testing.T, dir string) (string, string, string) {
	return writeTLSFixture(t, dir, tlsFixture{
		CommonName:   "builders-agent",
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:         true,
	})
}

type tlsFixture struct {
	CommonName   string
	NotBefore    time.Time
	NotAfter     time.Time
	ExtKeyUsages []x509.ExtKeyUsage
	DNSNames     []string
	IsCA         bool
}

func writeTLSFixture(t *testing.T, dir string, fixture tlsFixture) (string, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: fixture.CommonName},
		NotBefore:    fixture.NotBefore,
		NotAfter:     fixture.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  fixture.ExtKeyUsages,
		DNSNames:     fixture.DNSNames,
		IsCA:         fixture.IsCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey returned error: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("WriteFile cert returned error: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("WriteFile key returned error: %v", err)
	}
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatalf("WriteFile ca returned error: %v", err)
	}
	return certFile, keyFile, caFile
}

func TestServerTLSOnlyCredentials(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeTLSFixture(t, dir, tlsFixture{
		CommonName:   "127.0.0.1",
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	creds, err := identity.ServerTLSOnlyCredentials(certFile, keyFile)
	if err != nil {
		t.Fatalf("ServerTLSOnlyCredentials: %v", err)
	}
	// One-way TLS is genuine TLS (encrypt + server-auth) — NOT insecure.
	if got := creds.Info().SecurityProtocol; got != "tls" {
		t.Errorf("one-way creds must be TLS, got SecurityProtocol=%q", got)
	}
	// Fail-closed on empty cert/key and a bad keypair.
	if _, err := identity.ServerTLSOnlyCredentials("", keyFile); err == nil {
		t.Error("empty cert file must error")
	}
	if _, err := identity.ServerTLSOnlyCredentials(certFile, ""); err == nil {
		t.Error("empty key file must error")
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.ServerTLSOnlyCredentials(bad, bad); err == nil {
		t.Error("a bad keypair must error")
	}
}

func TestServerTransportCredentialsEnforcesCRL(t *testing.T) {
	dir := t.TempDir()

	// 1. Generate CA Cert and Key
	caPublicKey, caPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublicKey, caPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("WriteFile CA: %v", err)
	}

	// 2. Generate Server Key/Cert
	srvPublicKey, srvPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey srv: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDer, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPublicKey, caPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate srv: %v", err)
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvPrivateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey srv: %v", err)
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDer})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})
	srvFile := filepath.Join(dir, "srv.crt")
	srvKeyFile := filepath.Join(dir, "srv.key")
	if err := os.WriteFile(srvFile, srvPEM, 0600); err != nil {
		t.Fatalf("WriteFile srv: %v", err)
	}
	if err := os.WriteFile(srvKeyFile, srvKeyPEM, 0600); err != nil {
		t.Fatalf("WriteFile srvKey: %v", err)
	}

	// 3. Generate Client Certs
	// Client 1 (valid, serial 1)
	client1PubKey, client1PrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey client1: %v", err)
	}
	client1Template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Client 1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	client1Der, err := x509.CreateCertificate(rand.Reader, client1Template, caCert, client1PubKey, caPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate client1: %v", err)
	}
	client1KeyDER, _ := x509.MarshalPKCS8PrivateKey(client1PrivKey)
	client1PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client1Der})
	client1KeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: client1KeyDER})
	client1File := filepath.Join(dir, "client1.crt")
	client1KeyFile := filepath.Join(dir, "client1.key")
	_ = os.WriteFile(client1File, client1PEM, 0600)
	_ = os.WriteFile(client1KeyFile, client1KeyPEM, 0600)

	// Client 2 (revoked, serial 2)
	client2PubKey, client2PrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey client2: %v", err)
	}
	client2Template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Client 2"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	client2Der, err := x509.CreateCertificate(rand.Reader, client2Template, caCert, client2PubKey, caPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate client2: %v", err)
	}
	client2KeyDER, _ := x509.MarshalPKCS8PrivateKey(client2PrivKey)
	client2PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client2Der})
	client2KeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: client2KeyDER})
	client2File := filepath.Join(dir, "client2.crt")
	client2KeyFile := filepath.Join(dir, "client2.key")
	_ = os.WriteFile(client2File, client2PEM, 0600)
	_ = os.WriteFile(client2KeyFile, client2KeyPEM, 0600)

	// 4. Create CRL revoking client 2 (serial 2)
	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm: caCert.SignatureAlgorithm,
		Number:             big.NewInt(1),
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   big.NewInt(2),
				RevocationTime: time.Now(),
			},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caPrivateKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	crlFile := filepath.Join(dir, "ca.crl")
	if err := os.WriteFile(crlFile, crlPEM, 0600); err != nil {
		t.Fatalf("WriteFile CRL: %v", err)
	}

	// 5. Create Server Credentials with CRL
	creds, err := identity.ServerTransportCredentials(identity.ServerTLSConfig{
		CertFile:     srvFile,
		KeyFile:      srvKeyFile,
		ClientCAFile: caFile,
		CRLFile:      crlFile,
	})
	if err != nil {
		t.Fatalf("ServerTransportCredentials: %v", err)
	}

	runHandshake := func(clientCertFile, clientKeyFile string) error {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer ln.Close()

		serverErrChan := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				serverErrChan <- err
				return
			}
			defer conn.Close()
			_, _, handshakeErr := creds.ServerHandshake(conn)
			serverErrChan <- handshakeErr
		}()

		clientCreds, err := identity.ClientTransportCredentials(identity.ClientTLSConfig{
			CertFile:   clientCertFile,
			KeyFile:    clientKeyFile,
			CAFile:     caFile,
			ServerName: "127.0.0.1",
		})
		if err != nil {
			return err
		}

		dialConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return err
		}
		defer dialConn.Close()

		_, _, clientHandshakeErr := clientCreds.ClientHandshake(context.Background(), "127.0.0.1:0", dialConn)
		serverHandshakeErr := <-serverErrChan

		if clientHandshakeErr != nil {
			return clientHandshakeErr
		}
		return serverHandshakeErr
	}

	// Test Client 1 (valid)
	if err := runHandshake(client1File, client1KeyFile); err != nil {
		t.Errorf("Handshake for client 1 (valid) failed: %v", err)
	}

	// Test Client 2 (revoked)
	if err := runHandshake(client2File, client2KeyFile); err == nil {
		t.Errorf("Handshake for client 2 (revoked) succeeded, want failure")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("Handshake for client 2 (revoked) error = %q, want revocation error", err)
	}
}
