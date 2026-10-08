package cryptomator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// AES-SIV (RFC 5297) is what a vault encrypts the names of its files and its
// folders with: deterministic, so that the same name in the same folder is
// always the same ciphertext and a name can be looked up without listing the
// folder, and authenticated, so that a name that was tampered with does not
// decrypt. It is built on AES-CMAC (RFC 4493), which neither the standard
// library nor x/crypto offer. A vault keeps the two halves of the key apart:
// its MAC key is the one S2V runs with, its encryption key the one of CTR.

// errSIV is what a ciphertext that does not decrypt is, whether it was
// tampered with, cut short or made with another key.
var errSIV = errors.New("the name does not decrypt with the key of the vault")

// sivTagSize is how long the synthetic IV in front of a ciphertext is.
const sivTagSize = aes.BlockSize

// cmac is AES-CMAC under a block cipher, with the two subkeys derived once.
type cmac struct {
	block  cipher.Block
	k1, k2 [aes.BlockSize]byte
}

func newCMAC(block cipher.Block) *cmac {
	c := &cmac{block: block}
	var l [aes.BlockSize]byte
	block.Encrypt(l[:], l[:])
	c.k1 = dbl(l)
	c.k2 = dbl(c.k1)
	return c
}

// dbl is the doubling in GF(2^128) both CMAC and S2V are made of.
func dbl(b [aes.BlockSize]byte) [aes.BlockSize]byte {
	var out [aes.BlockSize]byte
	carry := b[0] >> 7
	for i := 0; i < aes.BlockSize-1; i++ {
		out[i] = b[i]<<1 | b[i+1]>>7
	}
	out[aes.BlockSize-1] = b[aes.BlockSize-1]<<1 ^ carry*0x87
	return out
}

func (c *cmac) sum(msg []byte) [aes.BlockSize]byte {
	var x [aes.BlockSize]byte
	n := (len(msg) + aes.BlockSize - 1) / aes.BlockSize
	complete := n > 0 && len(msg)%aes.BlockSize == 0
	if n == 0 {
		n = 1
	}
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x[:], x[:], msg[i*aes.BlockSize:(i+1)*aes.BlockSize])
		c.block.Encrypt(x[:], x[:])
	}
	var last [aes.BlockSize]byte
	rest := msg[(n-1)*aes.BlockSize:]
	if complete {
		subtle.XORBytes(last[:], rest, c.k1[:])
	} else {
		copy(last[:], rest)
		last[len(rest)] = 0x80
		subtle.XORBytes(last[:], last[:], c.k2[:])
	}
	subtle.XORBytes(x[:], x[:], last[:])
	c.block.Encrypt(x[:], x[:])
	return x
}

// siv is AES-SIV with the keys of a vault.
type siv struct {
	mac *cmac
	ctr cipher.Block
}

func newSIV(encKey, macKey []byte) (*siv, error) {
	macBlock, err := aes.NewCipher(macKey)
	if err != nil {
		return nil, err
	}
	ctrBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	return &siv{mac: newCMAC(macBlock), ctr: ctrBlock}, nil
}

// s2v is the pseudo random function of RFC 5297 2.4 over the associated data
// and the plaintext, the plaintext last.
func (s *siv) s2v(plaintext []byte, ad [][]byte) [aes.BlockSize]byte {
	var zero [aes.BlockSize]byte
	d := s.mac.sum(zero[:])
	for _, a := range ad {
		m := s.mac.sum(a)
		d = dbl(d)
		subtle.XORBytes(d[:], d[:], m[:])
	}
	var t []byte
	if len(plaintext) >= aes.BlockSize {
		t = append([]byte(nil), plaintext...)
		end := t[len(t)-aes.BlockSize:]
		subtle.XORBytes(end, end, d[:])
	} else {
		var padded [aes.BlockSize]byte
		copy(padded[:], plaintext)
		padded[len(plaintext)] = 0x80
		d = dbl(d)
		subtle.XORBytes(padded[:], padded[:], d[:])
		t = padded[:]
	}
	return s.mac.sum(t)
}

// ctr runs AES-CTR from the synthetic IV, with the two bits RFC 5297 2.5
// clears so that the counter can be added to with 64 bits.
func (s *siv) ctrXOR(v [aes.BlockSize]byte, dst, src []byte) {
	q := v
	q[8] &= 0x7f
	q[12] &= 0x7f
	cipher.NewCTR(s.ctr, q[:]).XORKeyStream(dst, src)
}

// seal is the synthetic IV followed by the ciphertext.
func (s *siv) seal(plaintext []byte, ad ...[]byte) []byte {
	v := s.s2v(plaintext, ad)
	out := make([]byte, sivTagSize+len(plaintext))
	copy(out, v[:])
	s.ctrXOR(v, out[sivTagSize:], plaintext)
	return out
}

func (s *siv) open(ciphertext []byte, ad ...[]byte) ([]byte, error) {
	if len(ciphertext) < sivTagSize {
		return nil, errSIV
	}
	var v [aes.BlockSize]byte
	copy(v[:], ciphertext)
	plaintext := make([]byte, len(ciphertext)-sivTagSize)
	s.ctrXOR(v, plaintext, ciphertext[sivTagSize:])
	check := s.s2v(plaintext, ad)
	if subtle.ConstantTimeCompare(check[:], v[:]) != 1 {
		return nil, errSIV
	}
	return plaintext, nil
}
