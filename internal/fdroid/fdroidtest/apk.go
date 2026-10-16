// Package fdroidtest builds APKs for the tests of F-Droid repositories: a zip
// with a binary AndroidManifest.xml, as aapt2 writes one, signed with a JAR
// signature or an APK Signature Scheme v2 block. The signatures are made to
// be read, not to be installed: the v2 block carries the certificate and no
// digests that would check out, which is all a repository reads of it.
package fdroidtest

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"
	"unicode/utf16"

	"github.com/smallstep/pkcs7"
)

// Scheme is how an APK is signed.
type Scheme int

const (
	// V2 is an APK Signature Scheme v2 block, which APKs for Android 7
	// and later carry alone.
	V2 Scheme = iota
	// V1 is a JAR signature, in META-INF.
	V1
	// Unsigned is not signed at all.
	Unsigned
)

// APK describes an APK to build.
type APK struct {
	Package     string
	VersionCode int
	VersionName string
	MinSdk      int
	TargetSdk   int
	Label       string
	// Permissions are asked for with uses-permission, PermissionsSdk23
	// with uses-permission-sdk-23.
	Permissions      []string
	PermissionsSdk23 []string
	Features         []string
	// ABIs get a native library each, in lib/<abi>/.
	ABIs []string
	// Icon is put into the APK as res/icon.png, and named by the manifest
	// as the icon of the application.
	Icon   []byte
	Scheme Scheme
	// Signer is the certificate it is signed with; one is made when it is
	// nil.
	Signer *Signer
}

// Signer is a certificate APKs are signed with.
type Signer struct {
	Certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

// NewSigner makes a certificate to sign APKs with.
func NewSigner() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fdroidtest developer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(30, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Signer{Certificate: certificate, key: key}, nil
}

// Fingerprint is the SHA-256 of the certificate, in lower case hex, which is
// what the index lists as the signer of an APK.
func (s *Signer) Fingerprint() string {
	sum := sha256.Sum256(s.Certificate.Raw)
	return hex.EncodeToString(sum[:])
}

// Build builds the APK.
func Build(a APK) ([]byte, error) {
	if a.Signer == nil && a.Scheme != Unsigned {
		signer, err := NewSigner()
		if err != nil {
			return nil, err
		}
		a.Signer = signer
	}
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	add := func(name string, data []byte) error {
		f, err := w.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	if err := add("AndroidManifest.xml", Manifest(a)); err != nil {
		return nil, err
	}
	if err := add("classes.dex", []byte("dex\n035\x00")); err != nil {
		return nil, err
	}
	for _, abi := range a.ABIs {
		if err := add("lib/"+abi+"/libnative.so", []byte("\x7fELF")); err != nil {
			return nil, err
		}
	}
	if a.Icon != nil {
		if err := add("res/icon.png", a.Icon); err != nil {
			return nil, err
		}
	}
	if a.Scheme == V1 {
		signed, err := pkcs7.NewSignedData([]byte("Signature-Version: 1.0\r\n\r\n"))
		if err != nil {
			return nil, err
		}
		signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
		if err := signed.SignWithoutAttr(a.Signer.Certificate, a.Signer.key, pkcs7.SignerInfoConfig{}); err != nil {
			return nil, err
		}
		signed.Detach()
		block, err := signed.Finish()
		if err != nil {
			return nil, err
		}
		if err := add("META-INF/CERT.SF", []byte("Signature-Version: 1.0\r\n\r\n")); err != nil {
			return nil, err
		}
		if err := add("META-INF/CERT.EC", block); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if a.Scheme != V2 {
		return out.Bytes(), nil
	}
	return withSigningBlock(out.Bytes(), a.Signer.Certificate.Raw), nil
}

// withSigningBlock puts an APK Signing Block holding a v2 signer with the
// certificate before the central directory of the zip file, and moves the
// central directory's offset past it.
func withSigningBlock(apk []byte, certificate []byte) []byte {
	le := binary.LittleEndian
	prefixed := func(parts ...[]byte) []byte {
		var inner []byte
		for _, p := range parts {
			inner = append(inner, p...)
		}
		return append(le.AppendUint32(nil, uint32(len(inner))), inner...)
	}
	signedData := prefixed(
		prefixed(),                      // digests
		prefixed(prefixed(certificate)), // certificates
		prefixed(),                      // additional attributes
	)
	signer := prefixed(signedData, prefixed() /* signatures */, prefixed() /* public key */)
	value := prefixed(signer)

	var pairs []byte
	pairs = le.AppendUint64(pairs, uint64(4+len(value)))
	pairs = le.AppendUint32(pairs, 0x7109871a)
	pairs = append(pairs, value...)
	size := uint64(len(pairs) + 24)
	var block []byte
	block = le.AppendUint64(block, size)
	block = append(block, pairs...)
	block = le.AppendUint64(block, size)
	block = append(block, "APK Sig Block 42"...)

	eocd := bytes.LastIndex(apk, []byte{0x50, 0x4b, 0x05, 0x06})
	directory := le.Uint32(apk[eocd+16:])
	out := append([]byte{}, apk[:directory]...)
	out = append(out, block...)
	out = append(out, apk[directory:]...)
	le.PutUint32(out[eocd+len(block)+16:], directory+uint32(len(block)))
	return out
}

// Manifest is the binary AndroidManifest.xml of the APK.
func Manifest(a APK) []byte {
	m := element{name: "manifest", attrs: []attr{
		{name: "versionCode", ns: true, number: a.VersionCode},
		{name: "versionName", ns: true, text: a.VersionName},
		{name: "package", text: a.Package},
	}}
	if a.MinSdk != 0 || a.TargetSdk != 0 {
		sdk := element{name: "uses-sdk"}
		if a.MinSdk != 0 {
			sdk.attrs = append(sdk.attrs, attr{name: "minSdkVersion", ns: true, number: a.MinSdk})
		}
		if a.TargetSdk != 0 {
			sdk.attrs = append(sdk.attrs, attr{name: "targetSdkVersion", ns: true, number: a.TargetSdk})
		}
		m.children = append(m.children, sdk)
	}
	for _, p := range a.Permissions {
		m.children = append(m.children, element{name: "uses-permission",
			attrs: []attr{{name: "name", ns: true, text: p}}})
	}
	for _, p := range a.PermissionsSdk23 {
		m.children = append(m.children, element{name: "uses-permission-sdk-23",
			attrs: []attr{{name: "name", ns: true, text: p}}})
	}
	for _, f := range a.Features {
		m.children = append(m.children, element{name: "uses-feature",
			attrs: []attr{{name: "name", ns: true, text: f}}})
	}
	app := element{name: "application"}
	if a.Label != "" {
		app.attrs = append(app.attrs, attr{name: "label", ns: true, text: a.Label})
	}
	if a.Icon != nil {
		app.attrs = append(app.attrs, attr{name: "icon", ns: true, text: "res/icon.png"})
	}
	m.children = append(m.children, app)
	return encode(m)
}

// The binary XML of aapt: a string pool, then the namespace, the elements
// and their ends as chunks of their own.

const androidURI = "http://schemas.android.com/apk/res/android"

type element struct {
	name     string
	attrs    []attr
	children []element
}

// attr is an attribute, in the android namespace when ns is set; a text
// value or a decimal number.
type attr struct {
	name   string
	ns     bool
	text   string
	number int
}

type encoder struct {
	strings []string
	index   map[string]uint32
	body    bytes.Buffer
}

func (e *encoder) ref(s string) uint32 {
	if i, ok := e.index[s]; ok {
		return i
	}
	e.index[s] = uint32(len(e.strings))
	e.strings = append(e.strings, s)
	return e.index[s]
}

const none = 0xffffffff

func encode(root element) []byte {
	e := &encoder{index: map[string]uint32{}}
	le := binary.LittleEndian
	// the root's name first: a reader takes a namespace whose prefix is
	// the first string for none
	e.ref(root.name)
	prefix, uri := e.ref("android"), e.ref(androidURI)

	namespace := func(typ uint16) {
		var c []byte
		c = le.AppendUint16(c, typ)
		c = le.AppendUint16(c, 16)
		c = le.AppendUint32(c, 24)
		c = le.AppendUint32(c, 1)    // line
		c = le.AppendUint32(c, none) // comment
		c = le.AppendUint32(c, prefix)
		c = le.AppendUint32(c, uri)
		e.body.Write(c)
	}
	var write func(el element)
	write = func(el element) {
		var c []byte
		c = le.AppendUint16(c, 0x0102)
		c = le.AppendUint16(c, 16)
		c = le.AppendUint32(c, uint32(16+20+20*len(el.attrs)))
		c = le.AppendUint32(c, 1)
		c = le.AppendUint32(c, none)
		c = le.AppendUint32(c, none) // ns
		c = le.AppendUint32(c, e.ref(el.name))
		c = le.AppendUint16(c, 20) // attributeStart
		c = le.AppendUint16(c, 20) // attributeSize
		c = le.AppendUint16(c, uint16(len(el.attrs)))
		c = le.AppendUint16(c, 0)
		c = le.AppendUint16(c, 0)
		c = le.AppendUint16(c, 0)
		for _, a := range el.attrs {
			ns := uint32(none)
			if a.ns {
				ns = uri
			}
			c = le.AppendUint32(c, ns)
			c = le.AppendUint32(c, e.ref(a.name))
			if a.text != "" || a.number == 0 {
				r := e.ref(a.text)
				c = le.AppendUint32(c, r)
				c = le.AppendUint16(c, 8)
				c = append(c, 0, 0x03)
				c = le.AppendUint32(c, r)
			} else {
				c = le.AppendUint32(c, none)
				c = le.AppendUint16(c, 8)
				c = append(c, 0, 0x10)
				c = le.AppendUint32(c, uint32(a.number))
			}
		}
		e.body.Write(c)
		for _, child := range el.children {
			write(child)
		}
		c = nil
		c = le.AppendUint16(c, 0x0103)
		c = le.AppendUint16(c, 16)
		c = le.AppendUint32(c, 24)
		c = le.AppendUint32(c, 1)
		c = le.AppendUint32(c, none)
		c = le.AppendUint32(c, none)
		c = le.AppendUint32(c, e.ref(el.name))
		e.body.Write(c)
	}
	namespace(0x0100)
	write(root)
	namespace(0x0101)

	// the string pool, UTF-16
	var data []byte
	var offsets []byte
	for _, s := range e.strings {
		offsets = le.AppendUint32(offsets, uint32(len(data)))
		units := utf16.Encode([]rune(s))
		data = le.AppendUint16(data, uint16(len(units)))
		for _, u := range units {
			data = le.AppendUint16(data, u)
		}
		data = le.AppendUint16(data, 0)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	var pool []byte
	pool = le.AppendUint16(pool, 0x0001)
	pool = le.AppendUint16(pool, 28)
	pool = le.AppendUint32(pool, uint32(28+len(offsets)+len(data)))
	pool = le.AppendUint32(pool, uint32(len(e.strings)))
	pool = le.AppendUint32(pool, 0) // styles
	pool = le.AppendUint32(pool, 0) // flags: UTF-16
	pool = le.AppendUint32(pool, uint32(28+len(offsets)))
	pool = le.AppendUint32(pool, 0)
	pool = append(pool, offsets...)
	pool = append(pool, data...)

	var out []byte
	out = le.AppendUint16(out, 0x0003)
	out = le.AppendUint16(out, 8)
	out = le.AppendUint32(out, uint32(8+len(pool)+e.body.Len()))
	out = append(out, pool...)
	return append(out, e.body.Bytes()...)
}
