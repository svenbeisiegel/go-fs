// Package pgp is the OpenPGP that a package repository needs: a signing key
// that is generated or read from the configuration file, the public half of it
// that clients import, detached signatures over the metadata of a repository
// and over the header of an rpm, and checking such a signature.
//
// The key is held unencrypted, as the TLS and SSH keys in the file are: go-fs
// signs while nobody is there to type a passphrase. Only RSA signing keys are
// accepted, because those are what every rpm in use verifies, where EdDSA is
// not understood by some of the older ones still supported.
package pgp

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// MinBits is the shortest RSA key accepted. Shorter ones are refused by the
// crypto policies of current distributions.
const MinBits = 2048

// generateBits is the size of a generated key. Tests lower it, since a key of
// this size takes seconds to make.
var generateBits = 4096

// config is what every signature is made with: SHA-256, which is what rpm
// verifies everywhere and what the crypto policies still accept.
var config = &packet.Config{DefaultHash: crypto.SHA256}

// Key is a private signing key.
type Key struct {
	entity *openpgp.Entity
	signer *packet.PrivateKey
}

// Generate makes a new RSA signing key for name, armored as the file holds it.
func Generate(name string) ([]byte, error) {
	name = strings.Map(func(r rune) rune {
		// the characters a user id cannot hold
		if strings.ContainsRune("()<>\x00", r) {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if name == "" {
		name = "go-fs"
	}
	entity, err := openpgp.NewEntity(name, "go-fs package repository", "", &packet.Config{
		Algorithm:   packet.PubKeyAlgoRSA,
		RSABits:     generateBits,
		DefaultHash: crypto.SHA256,
	})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := entity.SerializePrivate(writer, config); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Parse reads an armored private key. It has to hold one key, unencrypted,
// whose signing key is RSA of at least MinBits.
func Parse(armored []byte) (*Key, error) {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("is not an OpenPGP key: %w", err)
	}
	switch {
	case len(entities) == 0:
		return nil, errors.New("holds no OpenPGP key")
	case len(entities) > 1:
		return nil, fmt.Errorf("holds %d OpenPGP keys, it has to hold one", len(entities))
	}
	entity := entities[0]
	if entity.PrivateKey == nil {
		return nil, errors.New("is a public key; the private key is what signs")
	}
	found, ok := entity.SigningKey(time.Now())
	if !ok || found.PrivateKey == nil {
		return nil, errors.New("holds no key that may sign, or it has expired or been revoked")
	}
	signer := found.PrivateKey
	if signer.Encrypted {
		return nil, errors.New("is protected by a passphrase, which is not supported; " +
			"export it without one, as in: gpg --passwd <id> and then gpg --armor --export-secret-keys <id>")
	}
	if signer.PubKeyAlgo != packet.PubKeyAlgoRSA && signer.PubKeyAlgo != packet.PubKeyAlgoRSASignOnly {
		return nil, errors.New("signs with a key that is not RSA, which not every rpm verifies")
	}
	if bits, err := signer.BitLength(); err != nil || int(bits) < MinBits {
		return nil, fmt.Errorf("signs with an RSA key of %d bits, it has to have at least %d", bits, MinBits)
	}
	return &Key{entity: entity, signer: signer}, nil
}

// Fingerprint is the fingerprint of the primary key, in upper case hex as gpg
// shows it.
func (k *Key) Fingerprint() string {
	return strings.ToUpper(fmt.Sprintf("%x", k.entity.PrimaryKey.Fingerprint))
}

// KeyID is the id of the key that signs, the last 16 hex digits of its
// fingerprint, in lower case as rpm shows it.
func (k *Key) KeyID() string {
	return fmt.Sprintf("%016x", k.signer.KeyId)
}

// Name is the user id of the key.
func (k *Key) Name() string {
	if identity := k.entity.PrimaryIdentity(); identity != nil {
		return identity.Name
	}
	return ""
}

// Describe is the line the admin interface shows under the key.
func (k *Key) Describe() string {
	bits, _ := k.signer.BitLength()
	summary := fmt.Sprintf("RSA %d OpenPGP key %s", bits, k.Fingerprint())
	if name := k.Name(); name != "" {
		summary += ", " + name
	}
	return summary
}

// Public is the armored public key, what a client imports.
func (k *Key) Public() ([]byte, error) {
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := k.entity.Serialize(writer); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Sign makes a binary detached signature over data, the kind rpm keeps in
// the signature header of a package.
func (k *Key) Sign(data io.Reader) ([]byte, error) {
	var out bytes.Buffer
	if err := openpgp.DetachSign(&out, k.entity, data, config); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ArmoredSign makes an armored detached signature over data, the kind
// repomd.xml.asc is.
func (k *Key) ArmoredSign(data io.Reader) ([]byte, error) {
	var out bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&out, k.entity, data, config); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Verify reports whether signature is a valid binary detached signature over
// data made by this key.
func (k *Key) Verify(data io.Reader, signature []byte) error {
	_, err := openpgp.CheckDetachedSignature(openpgp.EntityList{k.entity}, data,
		bytes.NewReader(signature), config)
	return err
}
