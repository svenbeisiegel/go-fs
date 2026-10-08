package cryptomator

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strings"
)

// The recovery key is the two keys of the vault written out, with a checksum
// that catches a mistyped one, in groups of base32: whoever holds it holds the
// vault, whatever its password, and can give it a new one (Recover). It is
// not the word list the Cryptomator apps show, which go-fs cannot embed, so
// the apps do not take it in their recovery dialog.

// recoveryGroup is how many characters of the key are written together.
const recoveryGroup = 6

// ErrRecoveryKey is what a recovery key that was mistyped, or is not one,
// fails with.
var ErrRecoveryKey = errors.New("that is not the recovery key of a vault")

// RecoveryKey is the recovery key of the vault.
func (v *Vault) RecoveryKey() string {
	raw := v.rawKey()
	raw = binary.BigEndian.AppendUint32(raw, crc32.ChecksumIEEE(raw))
	text := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	var groups []string
	for len(text) > 0 {
		n := min(recoveryGroup, len(text))
		groups = append(groups, text[:n])
		text = text[n:]
	}
	return strings.Join(groups, "-")
}

// Recover is the content of a new MasterkeyFile that the password unlocks,
// for the vault the recovery key is of. Its VaultFile stays as it is.
func Recover(recoveryKey, password string) ([]byte, error) {
	text := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, recoveryKey))
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil || len(raw) != 2*keySize+4 {
		return nil, ErrRecoveryKey
	}
	keys := raw[:2*keySize]
	if binary.BigEndian.Uint32(raw[2*keySize:]) != crc32.ChecksumIEEE(keys) {
		return nil, ErrRecoveryKey
	}
	v, err := newVault(keys[:keySize], keys[keySize:], DefaultShorteningThreshold)
	if err != nil {
		return nil, err
	}
	return v.masterkeyFile(password)
}
