//go:build !light && (!no_sftpd || !no_sftp_remote)

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// The SSH host key, and private keys in the encoding of ssh-keygen, are read
// by golang.org/x/crypto/ssh, which only a binary with the SFTP server or
// sending by SFTP imports; the tags no_sftpd and no_sftp_remote together, or
// light, leave this file out.
func init() {
	registerKeyKind(KindSSHKey, keyKind{decode: DecodeHostKey, describe: describeHostKey,
		generate: func(string) (string, error) { return GenerateHostKey() }})
	parseOpenSSHKey = func(block *pem.Block) (any, error) {
		return ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
	}
}

// DecodeHostKey turns the configured sftp.hostkey value into the PEM bytes of
// an SSH private key.
func DecodeHostKey(value string) ([]byte, error) {
	decoded, err := DecodePrivateKey(value)
	if err != nil {
		return nil, err
	}
	if _, err := ssh.ParsePrivateKey(decoded); err != nil {
		var passphraseNeeded *ssh.PassphraseMissingError
		if errors.As(err, &passphraseNeeded) {
			return nil, errors.New("is protected by a passphrase, which is not supported")
		}
		return nil, fmt.Errorf("cannot be used as an SSH host key: %w", err)
	}
	return decoded, nil
}

// GenerateHostKey produces an ed25519 host key as the value the file holds. It
// is what the SFTP server falls back to when no key is configured and what the
// web interface stores when Generate is pressed, so a generated key and a
// configured one are the same thing.
func GenerateHostKey() (string, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return "", err
	}
	return Encode(pem.EncodeToMemory(block)), nil
}

func describeHostKey(value string) string {
	decoded, err := DecodeHostKey(value)
	if err != nil {
		return "this value " + err.Error()
	}
	signer, err := ssh.ParsePrivateKey(decoded)
	if err != nil {
		return "this value cannot be parsed: " + err.Error()
	}
	return fmt.Sprintf("%s host key, %s",
		signer.PublicKey().Type(), ssh.FingerprintSHA256(signer.PublicKey()))
}
