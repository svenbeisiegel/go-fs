// Package secrets compares credentials without leaking their content through
// timing. Both servers that authenticate users depend on it.
package secrets

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Match reports whether two secrets are equal, in time that does not depend on
// where they first differ. Both sides are hashed first so that differing
// lengths stay indistinguishable too.
func Match(a, b string) bool {
	hashA := sha256.Sum256([]byte(a))
	hashB := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(hashA[:], hashB[:]) == 1
}

// MatchBytes is Match for values that are already bytes, such as the wire
// encoding of a public key.
func MatchBytes(a, b []byte) bool {
	hashA := sha256.Sum256(a)
	hashB := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(hashA[:], hashB[:]) == 1
}
