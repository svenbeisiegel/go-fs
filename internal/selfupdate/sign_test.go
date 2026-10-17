package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"os"
	"strings"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func signed(t *testing.T, private ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Sign(private, bytes.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func verify(file []byte, keys ...ed25519.PublicKey) (int64, string, error) {
	return Verify(bytes.NewReader(file), int64(len(file)), keys)
}

// A signed file verifies, and what precedes the trailer is the binary as it
// was signed.
func TestSignVerifyRoundTrip(t *testing.T) {
	public, private := newKey(t)
	payload := []byte("a binary, or something standing in for one")
	file := signed(t, private, payload)
	if len(file) != len(payload)+trailerSize {
		t.Fatalf("the update is %d bytes, want %d", len(file), len(payload)+trailerSize)
	}

	length, key, err := verify(file, public)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(file[:length], payload) {
		t.Error("the payload is not the binary that was signed")
	}
	if key != KeyID(public) {
		t.Errorf("key %q, want %q", key, KeyID(public))
	}
}

// The key that signed is looked up among several, which is what rotating a
// key relies on.
func TestVerifyPicksTheSigningKey(t *testing.T) {
	other, _ := newKey(t)
	public, private := newKey(t)
	file := signed(t, private, []byte("payload"))
	if _, key, err := verify(file, other, public); err != nil || key != KeyID(public) {
		t.Errorf("Verify: key %q, err %v", key, err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	public, private := newKey(t)
	other, otherPrivate := newKey(t)
	payload := []byte("the payload of an update")
	good := signed(t, private, payload)

	flipped := bytes.Clone(good)
	flipped[3] ^= 0x01

	badSignature := bytes.Clone(good)
	badSignature[len(payload)] ^= 0x01

	// a signature over the same hash without the context, as the key would
	// make for some other purpose, is not an update signature
	hash := sha512.Sum512(payload)
	foreign, err := private.Sign(nil, hash[:], &ed25519.Options{Hash: signOptions.Hash})
	if err != nil {
		t.Fatal(err)
	}
	withoutContext := bytes.Clone(good)
	copy(withoutContext[len(payload):], foreign)

	tests := []struct {
		name string
		file []byte
		keys []ed25519.PublicKey
		want error
	}{
		{"empty", nil, []ed25519.PublicKey{public}, ErrUnsigned},
		{"shorter than a trailer", []byte("short"), []ed25519.PublicKey{public}, ErrUnsigned},
		{"unsigned", bytes.Repeat([]byte{0x7f}, 200), []ed25519.PublicKey{public}, ErrUnsigned},
		{"payload changed", flipped, []ed25519.PublicKey{public}, ErrBadSignature},
		{"signature changed", badSignature, []ed25519.PublicKey{public}, ErrBadSignature},
		{"signed without the context", withoutContext, []ed25519.PublicKey{public}, ErrBadSignature},
		{"unknown key", good, []ed25519.PublicKey{other}, ErrUnknownKey},
		{"no keys", good, nil, ErrUnknownKey},
		{"other key", signed(t, otherPrivate, payload), []ed25519.PublicKey{public}, ErrUnknownKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := verify(test.file, test.keys...); !errors.Is(err, test.want) {
				t.Errorf("Verify: %v, want %v", err, test.want)
			}
		})
	}
}

// A key copied into the id of a trusted one does not pass as that key: the id
// only picks the key, the signature is still checked against it.
func TestVerifyForgedKeyID(t *testing.T) {
	public, _ := newKey(t)
	_, attacker := newKey(t)
	file := signed(t, attacker, []byte("payload"))
	id := keyID(public)
	copy(file[len(file)-len(magic)-keyIDSize:], id[:])
	if _, _, err := verify(file, public); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify: %v, want %v", err, ErrBadSignature)
	}
}

func TestParseKeys(t *testing.T) {
	first, private := newKey(t)
	second, _ := newKey(t)
	text := "# a comment\n\n" + EncodePublicKey(first) + "\n  " + EncodePublicKey(second) + "  \n"
	keys, err := parseKeys(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !keys[0].Equal(first) || !keys[1].Equal(second) {
		t.Errorf("parsed %d keys", len(keys))
	}

	for _, bad := range []string{"not base64!", "c2hvcnQ=", EncodePrivateKey(private) + "AAAA"} {
		if _, err := parseKeys(bad); err == nil {
			t.Errorf("%q parsed as a key", bad)
		}
	}
}

// The file that ships with the source has to parse, or every build would
// refuse to start.
func TestTrustedKeysParse(t *testing.T) {
	if _, err := TrustedKeys(); err != nil {
		t.Fatalf("keys file of %s: %v", Product, err)
	}
}

// productKeys reads the keys file of each product from the source tree, not
// from what this build embedded, so both are checked whichever tag the tests
// run with.
func productKeys(t *testing.T) map[string][]ed25519.PublicKey {
	t.Helper()
	files := map[string]string{"go-fs": "keys.txt", "go-fs-light": "keys_light.txt"}
	keys := make(map[string][]ed25519.PublicKey)
	for product, name := range files {
		text, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseKeys(string(text))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		keys[product] = parsed
	}
	return keys
}

// A key both products trusted would let one install the update files of the
// other, which share its release.
func TestProductKeysAreDisjoint(t *testing.T) {
	keys := productKeys(t)
	for _, full := range keys["go-fs"] {
		for _, light := range keys["go-fs-light"] {
			if full.Equal(light) {
				t.Errorf("key %s is trusted by go-fs and go-fs-light", KeyID(full))
			}
		}
	}
}

// This build trusts the keys of its own product and none of the other's, so
// an update signed for the other product is refused as signed with an unknown
// key.
func TestTrustedKeysAreTheProductsOwn(t *testing.T) {
	saved := buildKeys
	t.Cleanup(func() { buildKeys = saved })
	buildKeys = ""

	trusted, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	keys := productKeys(t)
	own := keys[Product]
	if len(trusted) != len(own) {
		t.Fatalf("%s trusts %d keys, its keys file holds %d", Product, len(trusted), len(own))
	}
	for i := range own {
		if !trusted[i].Equal(own[i]) {
			t.Errorf("trusted key %d is %s, want %s", i, KeyID(trusted[i]), KeyID(own[i]))
		}
	}
	for product, set := range keys {
		if product == Product {
			continue
		}
		for _, key := range set {
			for _, mine := range trusted {
				if key.Equal(mine) {
					t.Errorf("%s trusts key %s of %s", Product, KeyID(key), product)
				}
			}
		}
	}

	// The other product's keys file may hold no key yet, so a fresh key
	// stands in for it when signing.
	_, otherPrivate := newKey(t)
	if _, _, err := verify(signed(t, otherPrivate, []byte("binary")), trusted...); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("update signed for the other product: %v, want %v", err, ErrUnknownKey)
	}
}

func TestBuildKeysAreTrusted(t *testing.T) {
	first, _ := newKey(t)
	second, _ := newKey(t)
	saved := buildKeys
	t.Cleanup(func() { buildKeys = saved })
	buildKeys = EncodePublicKey(first) + "," + EncodePublicKey(second)

	keys, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, key := range keys {
		if key.Equal(first) || key.Equal(second) {
			found++
		}
	}
	if found != 2 {
		t.Errorf("found %d of the 2 build keys among %d", found, len(keys))
	}
}

func TestPrivateKeyEncoding(t *testing.T) {
	_, private := newKey(t)
	decoded, err := DecodePrivateKey(" " + EncodePrivateKey(private) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(private) {
		t.Error("the private key did not survive encoding")
	}
	if _, err := DecodePrivateKey(strings.Repeat("A", 10)); err == nil {
		t.Error("a short key decoded")
	}
}
