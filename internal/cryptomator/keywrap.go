package cryptomator

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// The keys of a vault are kept in masterkey.cryptomator wrapped by AES Key
// Wrap (RFC 3394) under a key derived from the password, which neither the
// standard library nor x/crypto offer.

// errUnwrap is what a wrapped key that does not unwrap is: almost always a
// key derived from the wrong password.
var errUnwrap = errors.New("the key does not unwrap")

// keyWrapIV is the default initial value of RFC 3394 2.2.3.1.
var keyWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// wrapKey wraps a key that is a multiple of 8 bytes and at least 16 long.
func wrapKey(kek, key []byte) ([]byte, error) {
	if len(key)%8 != 0 || len(key) < 16 {
		return nil, errors.New("a wrapped key is a multiple of 8 bytes and at least 16 long")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	out := make([]byte, 8+len(key))
	copy(out[8:], key)
	a := keyWrapIV
	var b [aes.BlockSize]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], out[i*8:i*8+8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^t)
			copy(out[i*8:], b[8:])
		}
	}
	copy(out, a[:])
	return out, nil
}

// unwrapKey undoes wrapKey, and fails when the integrity check of RFC 3394
// 2.2.3 does not hold.
func unwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errUnwrap
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	out := make([]byte, len(wrapped))
	copy(out, wrapped)
	var a [8]byte
	copy(a[:], wrapped[:8])
	var b [aes.BlockSize]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(b[8:], out[i*8:i*8+8])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(out[i*8:], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], keyWrapIV[:]) != 1 {
		return nil, errUnwrap
	}
	return out[8:], nil
}
