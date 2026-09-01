// Command manifestsign is the canonical manifest-signing authority tool.
//
//   mint <keydir>
//       Generate ONE ed25519 manifest-signing keypair (private stays here — the
//       authority; only the public verify key ships to gateways). Idempotent.
//
//   sign <keydir> <manifest-in.json> <signing-key-id> <manifest-out.json> <keyring-out.json>
//       Re-sign an existing manifest (its contracts/bindings unchanged) under the
//       canonical key, using the REAL contractmanifest.Sign so the hash is
//       byte-identical to what gateways compute. Writes the signed manifest + the
//       PUBLIC keyring JSON ({keyid: base64(pubkey)}) for the gateways.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/b2bautopilot/xyz-b2b/packages/federation-contracts/contractmanifest"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "ERR: "+f+"\n", a...); os.Exit(1) }

func main() {
	if len(os.Args) < 2 {
		die("usage: manifestsign mint|sign ...")
	}
	switch os.Args[1] {
	case "mint":
		dir := os.Args[2]
		_ = os.MkdirAll(dir, 0o700)
		if b, err := os.ReadFile(dir + "/manifest-ca.key"); err == nil {
			priv := ed25519.PrivateKey(mustB64(string(b)))
			pub := priv.Public().(ed25519.PublicKey)
			fmt.Printf("EXISTS manifest key reused. pub=%s\n", base64.StdEncoding.EncodeToString(pub)[:16])
			return
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("gen key: %v", err)
		}
		if err := os.WriteFile(dir+"/manifest-ca.key", []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
			die("write key: %v", err)
		}
		if err := os.WriteFile(dir+"/manifest-ca.pub", []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
			die("write pub: %v", err)
		}
		fmt.Printf("MINTED canonical manifest key -> %s/manifest-ca.{key,pub}\n pub=%s\n", dir, base64.StdEncoding.EncodeToString(pub))

	case "sign":
		keydir, in, keyID, out, keyringOut := os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]
		kb, err := os.ReadFile(keydir + "/manifest-ca.key")
		if err != nil {
			die("read key: %v", err)
		}
		priv := ed25519.PrivateKey(mustB64(string(kb)))
		if len(priv) != ed25519.PrivateKeySize {
			die("bad private key size %d", len(priv))
		}
		mb, err := os.ReadFile(in)
		if err != nil {
			die("read manifest: %v", err)
		}
		var m contractmanifest.Manifest
		if err := json.Unmarshal(mb, &m); err != nil {
			die("parse manifest: %v", err)
		}
		m.SigningKeyID = keyID
		signed, err := contractmanifest.Sign(m, priv)
		if err != nil {
			die("sign: %v", err)
		}
		sb, _ := json.MarshalIndent(signed, "", "  ")
		if err := os.WriteFile(out, sb, 0o600); err != nil {
			die("write out: %v", err)
		}
		pub := priv.Public().(ed25519.PublicKey)
		keyring := map[string]string{keyID: base64.StdEncoding.EncodeToString(pub)}
		krb, _ := json.Marshal(keyring)
		if err := os.WriteFile(keyringOut, krb, 0o600); err != nil {
			die("write keyring: %v", err)
		}
		fmt.Printf("SIGNED %s\n  signing_key_id=%s\n  manifest_hash=%s\n  keyring(public)=%s\n", out, keyID, signed.ManifestHashSHA256[:16], string(krb))

	default:
		die("unknown cmd %q", os.Args[1])
	}
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(trim(s))
	if err != nil {
		die("b64 decode: %v", err)
	}
	return b
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
