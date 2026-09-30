package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// KindToken is what the admin interface asks to generate for a new bearer
// token. Unlike the key material kinds it is never uploaded or described: the
// file holds only its hash.
const KindToken = "token"

// tokenPrefix marks a go-fs token, so that one pasted into the wrong place is
// recognisable, and a secret scanner can be taught to look for it.
const tokenPrefix = "gofs_"

// tokenBytes is how much randomness is behind a token: 256 bits, the length of
// the hash it is stored as.
const tokenBytes = 32

// GenerateToken produces a new bearer token and the hash the file holds for it.
func GenerateToken() (plain, hash string, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	plain = tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return plain, HashToken(plain), nil
}

// HashToken is the value Token.Hash holds for a token. A plain SHA-256 is
// enough: a token is 256 random bits, not a password someone chose, so there
// is nothing for a slow hash to protect against.
func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// ValidTokenHash reports whether a value can be a Token.Hash.
func ValidTokenHash(hash string) bool {
	if len(hash) != 2*sha256.Size {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}
