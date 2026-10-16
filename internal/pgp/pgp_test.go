package pgp

import (
	"bytes"
	"strings"
	"testing"
)

func init() {
	// a key of the size Generate makes takes seconds; the size does not
	// change anything these tests look at
	generateBits = MinBits
}

func TestGenerateParsesAndSigns(t *testing.T) {
	armored, err := Generate("go-fs (test) <x>")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(armored, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
		t.Fatalf("the key is not armored: %.40q", armored)
	}
	key, err := Parse(armored)
	if err != nil {
		t.Fatal(err)
	}
	if got := key.Name(); got != "go-fs test x (go-fs package repository)" {
		t.Errorf("name = %q", got)
	}
	if len(key.Fingerprint()) != 40 || len(key.KeyID()) != 16 {
		t.Errorf("fingerprint %q, key id %q", key.Fingerprint(), key.KeyID())
	}
	if !strings.HasPrefix(key.Describe(), "RSA 2048 OpenPGP key ") {
		t.Errorf("describe = %q", key.Describe())
	}

	data := []byte("the header of a package")
	signature, err := key.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Verify(bytes.NewReader(data), signature); err != nil {
		t.Fatalf("own signature does not verify: %v", err)
	}
	if err := key.Verify(bytes.NewReader([]byte("something else")), signature); err == nil {
		t.Fatal("a signature over other data verified")
	}

	armoredSignature, err := key.ArmoredSign(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(armoredSignature, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Errorf("signature is not armored: %.40q", armoredSignature)
	}

	public, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(public, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		t.Errorf("public key is not armored: %.40q", public)
	}
	if _, err := Parse(public); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Errorf("a public key parsed as a signing key: %v", err)
	}
}

func TestOtherKeyDoesNotVerify(t *testing.T) {
	one, _ := Generate("one")
	two, _ := Generate("two")
	first, err := Parse(one)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse(two)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("payload")
	signature, err := first.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Verify(bytes.NewReader(data), signature); err == nil {
		t.Fatal("a signature of another key verified")
	}
}

func TestParseRefusesGarbage(t *testing.T) {
	for _, input := range []string{"", "not a key", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n"} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("%q parsed", input)
		}
	}
}
