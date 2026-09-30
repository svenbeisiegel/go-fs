package tlsconf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

func capture() (*slog.Logger, *bytes.Buffer) {
	var out bytes.Buffer
	return slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})), &out
}

// certificateExpiring makes a PEM pair whose certificate runs out at notAfter.
func certificateExpiring(t *testing.T, notAfter time.Time) (cert, key string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expiry test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"files.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return config.Encode(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		config.Encode(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestBuildDescribesTheCertificate(t *testing.T) {
	certPEM, keyPEM, err := SelfSignedPEM()
	if err != nil {
		t.Fatal(err)
	}
	logger, out := capture()
	if _, err := Build(config.Encode(certPEM), config.Encode(keyPEM), "ftps.cert", "ftps.key", logger); err != nil {
		t.Fatal(err)
	}
	log := out.String()
	if !strings.Contains(log, `msg="tls certificate loaded"`) || !strings.Contains(log, "setting=ftps.cert") {
		t.Errorf("a loaded certificate has to be described:\n%s", log)
	}
	if !strings.Contains(log, "localhost") || !strings.Contains(log, "notAfter=") {
		t.Errorf("the record has to carry the names and the expiry:\n%s", log)
	}
	if strings.Contains(log, "level=WARN") {
		t.Errorf("a fresh certificate must not warn:\n%s", log)
	}
}

func TestBuildWarnsAboutExpiry(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{"expires soon", time.Now().Add(10 * 24 * time.Hour), "expires soon"},
		{"expired", time.Now().Add(-time.Hour), "has expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := certificateExpiring(t, tc.notAfter)
			logger, out := capture()
			if _, err := Build(cert, key, "https.cert", "https.key", logger); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "level=WARN") || !strings.Contains(out.String(), tc.want) {
				t.Errorf("want a warning saying %q:\n%s", tc.want, out.String())
			}
		})
	}
}

func TestBuildWithoutMaterialWarns(t *testing.T) {
	logger, out := capture()
	if _, err := Build("", "", "ftps.cert", "ftps.key", logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "generated a temporary") {
		t.Errorf("a generated certificate has to be reported:\n%s", out.String())
	}
}
