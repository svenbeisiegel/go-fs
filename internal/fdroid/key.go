package fdroid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// MinBits is the shortest RSA key accepted.
const MinBits = 2048

// generateBits is the size of a generated key, the size fdroidserver makes.
// Tests lower it, since a key of this size takes seconds to make.
var generateBits = 4096

// validity is how long a generated certificate is valid, the 10000 days
// fdroidserver gives its own. The client does not check it, but the
// fingerprint a repository is added by is the certificate's, so it is made to
// outlast the repository rather than to be renewed.
const validity = 10000 * 24 * time.Hour

// Key is the key the index of a repository is signed with: an RSA private key
// and the self-signed certificate of it. Clients pin the repository to the
// certificate, by its fingerprint.
type Key struct {
	private     *rsa.PrivateKey
	certificate *x509.Certificate
}

// Generate makes a new key for the repository called name, as PEM: the
// certificate, then the private key.
func Generate(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "go-fs"
	}
	private, err := rsa.GenerateKey(rand.Reader, generateBits)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, OrganizationalUnit: []string{"go-fs F-Droid repository"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return out.Bytes(), nil
}

// Parse reads a key from PEM. It has to hold one certificate and the RSA
// private key of it, of at least MinBits, without a passphrase.
func Parse(pemBytes []byte) (*Key, error) {
	var certificates []*x509.Certificate
	var private *rsa.PrivateKey
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("holds a certificate that cannot be parsed: %w", err)
			}
			certificates = append(certificates, c)
		case block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED"):
			return nil, errors.New("is protected by a passphrase, which is not supported")
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			if private != nil {
				return nil, errors.New("holds more than one private key")
			}
			k, err := parseRSA(block)
			if err != nil {
				return nil, err
			}
			private = k
		}
	}
	switch {
	case len(certificates) == 0:
		return nil, errors.New("holds no certificate; it is the certificate and the private key, PEM, one after the other")
	case len(certificates) > 1:
		// the client accepts an index signed by a single certificate only
		return nil, fmt.Errorf("holds %d certificates, it has to hold one", len(certificates))
	case private == nil:
		return nil, errors.New("holds no private key; it is the certificate and the private key, PEM, one after the other")
	}
	certificate := certificates[0]
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !public.Equal(&private.PublicKey) {
		return nil, errors.New("holds a certificate that is not the one of its private key")
	}
	if bits := private.N.BitLen(); bits < MinBits {
		return nil, fmt.Errorf("is an RSA key of %d bits, it has to have at least %d", bits, MinBits)
	}
	return &Key{private: private, certificate: certificate}, nil
}

func parseRSA(block *pem.Block) (*rsa.PrivateKey, error) {
	if block.Type == "RSA PRIVATE KEY" {
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("holds a private key that cannot be parsed: %w", err)
		}
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("holds a private key that cannot be parsed: %w", err)
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("holds a private key that is not RSA, which the index is signed with")
	}
	return k, nil
}

// Fingerprint is the SHA-256 of the certificate, in upper case hex. It is what
// a client is given with the address of the repository, and checks the index
// against.
func (k *Key) Fingerprint() string {
	sum := sha256.Sum256(k.certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Name is the common name of the certificate.
func (k *Key) Name() string {
	return k.certificate.Subject.CommonName
}

// Describe is the line the admin interface shows under the key.
func (k *Key) Describe() string {
	summary := fmt.Sprintf("RSA %d key, fingerprint %s", k.private.N.BitLen(), k.Fingerprint())
	if name := k.Name(); name != "" {
		summary += ", " + name
	}
	return summary
}
