package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSigned makes a certificate and its key as the file holds them. The
// package cannot use tlsconf for this, which imports it.
func selfSigned(t *testing.T, name string) (cert, key string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return Encode(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Encode(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestDecodePEMAcceptsBothForms(t *testing.T) {
	cert, _ := selfSigned(t, "example")
	raw, err := DecodePEM(cert)
	if err != nil {
		t.Fatal(err)
	}

	// the PEM itself, as a multi-line string in the file would hold it
	pasted, err := DecodePEM(string(raw))
	if err != nil {
		t.Fatalf("pasted PEM has to be accepted: %v", err)
	}
	if string(pasted) != strings.TrimSpace(string(raw)) {
		t.Error("a pasted PEM came back changed")
	}

	// and base64 that a tool wrapped across lines
	if _, err := DecodePEM(cert[:20] + "\n" + cert[20:]); err != nil {
		t.Errorf("wrapped base64 has to be accepted: %v", err)
	}
}

// A path is what these keys held before this change, so it gets an error that
// says what to do rather than one about base64.
func TestDecodePEMRecognisesALeftoverPath(t *testing.T) {
	for _, value := range []string{"/etc/ssl/server.crt", "certs/server.pem", "server.key"} {
		_, err := DecodePEM(value)
		if err == nil {
			t.Fatalf("%q has to be refused", value)
		}
		if !strings.Contains(err.Error(), "looks like a file path") {
			t.Errorf("%q: %v", value, err)
		}
		if !strings.Contains(err.Error(), "base64") {
			t.Errorf("%q does not say what to do instead: %v", value, err)
		}
	}

	// something that is merely wrong keeps the plain message
	_, err := DecodePEM("not base64 !!")
	if err == nil || strings.Contains(err.Error(), "file path") {
		t.Errorf("garbage should not be reported as a path: %v", err)
	}
}

func TestDecodeRefusesTheOtherHalf(t *testing.T) {
	cert, key := selfSigned(t, "example")

	if _, err := DecodeCertificate(key); err == nil ||
		!strings.Contains(err.Error(), "not a certificate") {
		t.Errorf("a private key was accepted as a certificate: %v", err)
	}
	if _, err := DecodePrivateKey(cert); err == nil ||
		!strings.Contains(err.Error(), "not a private key") {
		t.Errorf("a certificate was accepted as a private key: %v", err)
	}
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeHostKey(hostKey); err != nil {
		t.Errorf("a generated host key has to be accepted: %v", err)
	}
	if _, err := DecodeHostKey(cert); err == nil {
		t.Error("a certificate was accepted as an SSH host key")
	}
	// an EC key is a host key SSH can use, so the TLS one is not refused here;
	// what makes it the wrong key is the certificate it does not match, which
	// is what checkPair reports
	if _, err := DecodeHostKey(key); err != nil {
		t.Errorf("an EC private key is a usable host key: %v", err)
	}
}

func TestDecodeCertificateKeepsAChain(t *testing.T) {
	leaf, _ := selfSigned(t, "leaf")
	issuer, _ := selfSigned(t, "issuer")
	leafPEM, _ := DecodePEM(leaf)
	issuerPEM, _ := DecodePEM(issuer)

	chain := Encode(append(leafPEM, issuerPEM...))
	decoded, err := DecodeCertificate(chain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(decoded), "BEGIN CERTIFICATE") != 2 {
		t.Error("the chain was not kept whole")
	}
	if !strings.Contains(Describe(KindCertificate, chain), "with a chain") {
		t.Errorf("a chain is not described as one: %q", Describe(KindCertificate, chain))
	}
}

func TestDecodePrivateKeyRefusesAPassphrase(t *testing.T) {
	locked := Encode(pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"},
		Bytes:   []byte("encrypted"),
	}))
	_, err := DecodePrivateKey(locked)
	if err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("an encrypted key has to be refused as such: %v", err)
	}
}

// A truncated paste decodes to something that starts like PEM, which is why
// the value is parsed rather than only recognised.
func TestDecodeRefusesATruncatedKey(t *testing.T) {
	_, key := selfSigned(t, "example")
	keyPEM, _ := DecodePEM(key)
	if _, err := DecodePrivateKey(Encode(keyPEM[:len(keyPEM)/2])); err == nil {
		t.Error("half a key was accepted")
	}
	if _, err := DecodePEM(base64.StdEncoding.EncodeToString([]byte("hello"))); err == nil {
		t.Error("base64 of something else was accepted")
	}
}

func TestDescribeSaysWhatIsStored(t *testing.T) {
	cert, key := selfSigned(t, "example.test")
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	if got := Describe(KindCertificate, cert); !strings.Contains(got, "example.test") ||
		!strings.Contains(got, "expires") {
		t.Errorf("certificate described as %q", got)
	}
	if got := Describe(KindTLSKey, key); !strings.Contains(got, "private key") {
		t.Errorf("key described as %q", got)
	}
	if got := Describe(KindSSHKey, hostKey); !strings.Contains(got, "ssh-ed25519") ||
		!strings.Contains(got, "SHA256:") {
		t.Errorf("host key described as %q", got)
	}
	if got := Describe(KindCertificate, ""); got != "" {
		t.Errorf("an empty value described as %q", got)
	}
	// a value that cannot be read says so rather than describing nothing
	if got := Describe(KindCertificate, "/etc/ssl/server.crt"); !strings.Contains(got, "file path") {
		t.Errorf("a leftover path described as %q", got)
	}
}

// The pair check is the reason the material is validated here at all: a key
// that belongs to another certificate cannot serve, and -check has to say so.
func TestValidateChecksTheWholePair(t *testing.T) {
	folder := t.TempDir()
	cert, key := selfSigned(t, "example")
	_, otherKey := selfSigned(t, "other")

	base := func() Config {
		cfg := Default()
		cfg.General.Basefolder = folder
		cfg.FTP.Basefolder = folder
		cfg.TFTP.Basefolder = folder
		cfg.FTPS.Enabled = true
		cfg.Users = []User{{Username: "john", Password: "doe", FTP: true}}
		return cfg
	}

	cfg := base()
	cfg.FTPS.Cert, cfg.FTPS.Key = cert, key
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a matching pair has to be accepted: %v", err)
	}

	cfg = base()
	cfg.FTPS.Cert, cfg.FTPS.Key = cert, otherKey
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "ftps.cert and ftps.key") {
		t.Errorf("a mismatched pair was not reported: %v", err)
	}

	cfg = base()
	cfg.FTPS.Cert, cfg.FTPS.Key = key, cert
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ftps.cert") {
		t.Errorf("a swapped pair was not reported: %v", err)
	}
}
