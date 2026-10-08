package config

import (
	"crypto/rand"
	"encoding/base64"
)

// MinShareSecret is the shortest http.shareLinkSecret accepted. A generated
// one is far longer; this only stops a key typed by hand from being trivial.
const MinShareSecret = 32

// shareSecretBytes is how much randomness is behind a generated secret: 512
// bits, the size of the HMAC-SHA512 it keys.
const shareSecretBytes = 64

// GenerateShareSecret produces a new value for http.shareLinkSecret.
func GenerateShareSecret() (string, error) {
	raw := make([]byte, shareSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
