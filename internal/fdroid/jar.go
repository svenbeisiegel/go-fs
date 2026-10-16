package fdroid

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/smallstep/pkcs7"
)

// signerName is the base name of the signature files in META-INF.
const signerName = "GOFS"

// createdBy is what the manifest and the signature file say made them.
const createdBy = "go-fs"

// signJAR makes a JAR that holds data as the file name, signed with key the
// way jarsigner signs (a JAR signature, which apksigner calls v1): a manifest
// with the digest of the file, a signature file with the digests of the
// manifest, and a detached PKCS #7 signature over the signature file. The
// client refuses MD5 and SHA-1, so every digest is SHA-256.
func signJAR(name string, data []byte, key *Key) ([]byte, error) {
	manifestMain := section(
		"Manifest-Version: 1.0",
		"Created-By: "+createdBy,
	)
	entry := section(
		"Name: "+name,
		"SHA-256-Digest: "+digest(data),
	)
	manifest := manifestMain + entry

	signature := section(
		"Signature-Version: 1.0",
		"Created-By: "+createdBy,
		"SHA-256-Digest-Manifest: "+digest([]byte(manifest)),
		"SHA-256-Digest-Manifest-Main-Attributes: "+digest([]byte(manifestMain)),
	) + section(
		"Name: "+name,
		"SHA-256-Digest: "+digest([]byte(entry)),
	)

	signed, err := pkcs7.NewSignedData([]byte(signature))
	if err != nil {
		return nil, err
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	// without signed attributes, as apksigner signs: the signature is over
	// the signature file itself
	if err := signed.SignWithoutAttr(key.certificate, key.private, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	signed.Detach()
	block, err := signed.Finish()
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	var out bytes.Buffer
	w := zip.NewWriter(&out)
	// the manifest first, where a JarInputStream looks for it
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"META-INF/MANIFEST.MF", []byte(manifest)},
		{"META-INF/" + signerName + ".SF", []byte(signature)},
		{"META-INF/" + signerName + ".RSA", block},
		{name, data},
	} {
		fw, err := w.Create(f.name)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// digest is the base64 SHA-256 of data, as a JAR manifest holds it.
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// section is a section of a manifest or a signature file: its lines, each
// ended by CRLF and wrapped at 72 bytes, and the empty line that ends it.
func section(lines ...string) string {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(wrap(line))
	}
	b.WriteString("\r\n")
	return b.String()
}

// wrap breaks a manifest line into lines of at most 72 bytes; a line that
// goes on begins with a space.
func wrap(line string) string {
	const width = 72
	var b strings.Builder
	first := true
	for len(line) > 0 {
		room := width
		if !first {
			b.WriteByte(' ')
			room--
		}
		n := min(room, len(line))
		b.WriteString(line[:n])
		b.WriteString("\r\n")
		line = line[n:]
		first = false
	}
	return b.String()
}
