package selfupdate

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// An update file is a go-fs binary with a trailer appended:
//
//	[ binary ][ signature, 64 bytes ][ key id, 8 bytes ][ "GOFSSIG1" ]
//
// The trailer is cut off before the binary is installed, so what lands on disk
// is byte for byte the build that was signed. That matters on macOS, where the
// linker signs every arm64 binary and the kernel refuses one whose bytes no
// longer match; a trailer left in place would not be covered by that
// signature.
//
// The signature is Ed25519ph: the SHA-512 of the binary is what is signed, so
// the upload is verified by streaming it from disk rather than holding it in
// memory. The context string binds the signature to this one purpose, so a
// signature the same key made for anything else is not accepted as an update.
const (
	magic       = "GOFSSIG1"
	keyIDSize   = 8
	trailerSize = ed25519.SignatureSize + keyIDSize + len(magic)
	signContext = "go-fs update v1"
)

var signOptions = &ed25519.Options{Hash: crypto.SHA512, Context: signContext}

// keysFile holds the public keys every build trusts, one base64 key per line.
// It is compiled in, so nothing at runtime — not the configuration file, not
// the admin interface — can add a key.
//
//go:embed keys.txt
var keysFile string

// buildKeys adds keys at build time, comma separated, for a fork that signs
// its own builds and for the tests that build go-fs:
//
//	go build -ldflags "-X go-fs/internal/selfupdate.buildKeys=<base64>"
var buildKeys string

var (
	// ErrUnsigned is a file that carries no trailer at all, which is what an
	// unsigned binary uploaded by mistake looks like.
	ErrUnsigned = errors.New("the file carries no go-fs update signature")
	// ErrUnknownKey is a trailer made with a key this build does not trust.
	ErrUnknownKey = errors.New("the file is signed with a key this build does not trust")
	// ErrBadSignature is a trailer whose signature does not cover the file.
	ErrBadSignature = errors.New("the signature does not match the file")
)

// KeyID names a public key: the first bytes of its SHA-256, hex encoded. It is
// what a trailer carries to say which key made it, and what the records and
// the update endpoint show.
func KeyID(public ed25519.PublicKey) string {
	id := keyID(public)
	return hex.EncodeToString(id[:])
}

func keyID(public ed25519.PublicKey) [keyIDSize]byte {
	sum := sha256.Sum256(public)
	var id [keyIDSize]byte
	copy(id[:], sum[:keyIDSize])
	return id
}

// Sign copies a binary from in to out and appends the trailer.
func Sign(private ed25519.PrivateKey, in io.Reader, out io.Writer) error {
	hash := sha512.New()
	if _, err := io.Copy(io.MultiWriter(out, hash), in); err != nil {
		return err
	}
	signature, err := private.Sign(nil, hash.Sum(nil), signOptions)
	if err != nil {
		return err
	}
	id := keyID(private.Public().(ed25519.PublicKey))
	trailer := make([]byte, 0, trailerSize)
	trailer = append(trailer, signature...)
	trailer = append(trailer, id[:]...)
	trailer = append(trailer, magic...)
	_, err = out.Write(trailer)
	return err
}

// Verify checks the trailer at the end of the size bytes in file against the
// trusted keys. It returns how many bytes precede the trailer, which is the
// binary, and the id of the key that signed it.
func Verify(file io.ReaderAt, size int64, keys []ed25519.PublicKey) (int64, string, error) {
	if size < int64(trailerSize) {
		return 0, "", ErrUnsigned
	}
	payload := size - int64(trailerSize)
	trailer := make([]byte, trailerSize)
	if _, err := file.ReadAt(trailer, payload); err != nil {
		return 0, "", err
	}
	if string(trailer[trailerSize-len(magic):]) != magic {
		return 0, "", ErrUnsigned
	}
	signature := trailer[:ed25519.SignatureSize]
	id := trailer[ed25519.SignatureSize : ed25519.SignatureSize+keyIDSize]

	var public ed25519.PublicKey
	for _, key := range keys {
		if known := keyID(key); bytes.Equal(known[:], id) {
			public = key
			break
		}
	}
	if public == nil {
		return 0, "", fmt.Errorf("%w (key %s)", ErrUnknownKey, hex.EncodeToString(id))
	}

	hash := sha512.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, payload)); err != nil {
		return 0, "", err
	}
	if err := ed25519.VerifyWithOptions(public, hash.Sum(nil), signature, signOptions); err != nil {
		return 0, "", ErrBadSignature
	}
	return payload, KeyID(public), nil
}

// TrustedKeys are the keys this build accepts updates from: those in keys.txt
// and those stamped in with buildKeys. A key that does not parse is an error
// rather than skipped, since it can only be a mistake made at build time.
func TrustedKeys() ([]ed25519.PublicKey, error) {
	return parseKeys(keysFile + "\n" + strings.ReplaceAll(buildKeys, ",", "\n"))
}

// parseKeys reads one base64 public key per line. Blank lines and lines
// starting with # are skipped.
func parseKeys(text string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := DecodePublicKey(line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, scanner.Err()
}

// DecodePublicKey reads a public key in the form keys.txt holds it: the 32
// bytes of an ed25519 public key, base64 encoded.
func DecodePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update key %q is not a base64 ed25519 public key", text)
	}
	return ed25519.PublicKey(raw), nil
}

// DecodePrivateKey reads a private key in the form the signing tool prints it:
// the 32 byte ed25519 seed, base64 encoded.
func DecodePrivateKey(text string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, errors.New("the signing key is not a base64 ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// EncodePublicKey and EncodePrivateKey are the inverses of the decoders.
func EncodePublicKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

func EncodePrivateKey(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Seed())
}
