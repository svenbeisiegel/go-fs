package cryptomator

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCMAC checks AES-CMAC against the examples of RFC 4493 4.
func TestCMAC(t *testing.T) {
	block, err := aes.NewCipher(unhex(t, "2b7e1516 28aed2a6 abf71588 09cf4f3c"))
	if err != nil {
		t.Fatal(err)
	}
	mac := newCMAC(block)
	cases := map[string]string{
		"":                                    "bb1d6929 e9593728 7fa37d12 9b756746",
		"6bc1bee2 2e409f96 e93d7e11 7393172a": "070a16b4 6b4d4144 f79bdd9d d04a287c",
		"6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411": "dfa66747 de9ae630 30ca3261 1497c827",
	}
	for msg, want := range cases {
		got := mac.sum(unhex(t, msg))
		if !bytes.Equal(got[:], unhex(t, want)) {
			t.Errorf("the CMAC of %q is %x, not %s", msg, got, want)
		}
	}
}

// TestSIV checks AES-SIV against the deterministic example of RFC 5297 A.1,
// whose first half of the key is the one of S2V.
func TestSIV(t *testing.T) {
	key := unhex(t, "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")
	s, err := newSIV(key[16:], key[:16])
	if err != nil {
		t.Fatal(err)
	}
	ad := unhex(t, "10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627")
	plaintext := unhex(t, "11223344 55667788 99aabbcc ddee")
	want := unhex(t, "85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c")
	sealed := s.seal(plaintext, ad)
	if !bytes.Equal(sealed, want) {
		t.Fatalf("sealed is %x, not %x", sealed, want)
	}
	opened, err := s.open(sealed, ad)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened is %x, %v", opened, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := s.open(sealed, ad); err == nil {
		t.Error("a tampered ciphertext was opened")
	}
	if _, err := s.open(want, []byte("other")); err == nil {
		t.Error("a ciphertext was opened with other associated data")
	}
}

// TestKeyWrap checks AES Key Wrap against RFC 3394 4.6.
func TestKeyWrap(t *testing.T) {
	kek := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	key := unhex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	want := unhex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
	wrapped, err := wrapKey(kek, key)
	if err != nil || !bytes.Equal(wrapped, want) {
		t.Fatalf("wrapped is %x, %v", wrapped, err)
	}
	unwrapped, err := unwrapKey(kek, wrapped)
	if err != nil || !bytes.Equal(unwrapped, key) {
		t.Fatalf("unwrapped is %x, %v", unwrapped, err)
	}
	other := append([]byte(nil), kek...)
	other[0] ^= 1
	if _, err := unwrapKey(other, wrapped); err == nil {
		t.Error("a key unwrapped under another key")
	}
}
