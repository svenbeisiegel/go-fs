package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Key material — certificates, private keys and the SSH host key — is held in
// the configuration file itself rather than in files it points at, base64 of
// the PEM encoding so that each one stays on a single line of TOML. That keeps
// the whole configuration in one file that can be copied to another host, lets
// the web interface put a key there at all, and means the servers need no read
// access outside their own configuration.
//
// This file is the only place that knows the encoding: tlsconf, sftp and admin
// all decode through it, so what the web interface accepts on upload is exactly
// what the servers accept at startup.
//
// The errors read as a continuation of the key they belong to, the way the
// host key errors always have, so a caller reports them as
// "ftps.cert: is neither base64 nor PEM".

// The kinds of material a key can hold. They name what a value has to be, and
// the web interface labels its fields with them so that an uploaded file is
// checked against the same rule the server applies at startup.
const (
	KindCertificate = "certificate"
	KindTLSKey      = "tlskey"
	KindSSHKey      = "sshkey"
	// KindSessionSecret is the odd one out: it is not PEM but raw random
	// bytes, base64 of them, because it is a symmetric key rather than
	// anything with a structure. It is here all the same, so that the web
	// interface reaches it through the same Decode and Describe as the rest.
	KindSessionSecret = "sessionsecret"
)

// minSessionSecret is the shortest key HS256 is signed with here. RFC 8725
// section 3.5 asks for a key at least as long as the output of the hash, which
// is 32 bytes for SHA-256; a shorter one is refused rather than stretched,
// because stretching would hide how little entropy is behind it.
const minSessionSecret = 32

// Decode checks a value against one of the kinds and returns its PEM bytes.
func Decode(kind, value string) ([]byte, error) {
	switch kind {
	case KindCertificate:
		return DecodeCertificate(value)
	case KindTLSKey:
		return DecodePrivateKey(value)
	case KindSSHKey:
		return DecodeHostKey(value)
	case KindSessionSecret:
		return DecodeSessionSecret(value)
	default:
		return nil, fmt.Errorf("%q is not a kind of key material", kind)
	}
}

// DecodePEM turns a configured value into the PEM bytes it stands for. The
// value is base64 of a PEM file; a PEM file pasted as is passes through, so
// that a key put into a TOML multi-line string works rather than failing as bad
// base64.
func DecodePEM(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("is empty")
	}
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		return []byte(trimmed), nil
	}
	// tolerate the line breaks a base64 tool leaves behind
	compact := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(trimmed)
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, errors.New(notBase64(trimmed))
	}
	if !strings.HasPrefix(string(decoded), "-----BEGIN") {
		return nil, errors.New("does not decode to a PEM block")
	}
	return decoded, nil
}

// notBase64 says what is wrong with a value that is neither base64 nor PEM. A
// path gets its own message, because it is what these keys held before they
// became the material itself and "is not base64" would not explain that.
func notBase64(value string) string {
	if looksLikeAPath(value) {
		return "looks like a file path; the value is now the content of that file, " +
			`base64 encoded, as in: base64 < server.crt | tr -d "\n"`
	}
	return "is neither base64 nor PEM"
}

func looksLikeAPath(value string) bool {
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	if strings.ContainsAny(value, `/\`) {
		return true
	}
	switch {
	case strings.HasSuffix(value, ".pem"), strings.HasSuffix(value, ".crt"),
		strings.HasSuffix(value, ".cer"), strings.HasSuffix(value, ".key"):
		return true
	}
	return false
}

// DecodeCertificate decodes a configured certificate. A chain is kept whole,
// because that is what a server has to send; every block in it has to be a
// certificate that parses, so a private key put into a certificate key is
// refused here rather than at the next start.
func DecodeCertificate(value string) ([]byte, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	found := 0
	for rest := decoded; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("holds %s, not a certificate", describeBlock(block.Type))
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("cannot be parsed: %w", err)
		}
		found++
	}
	if found == 0 {
		return nil, errors.New("holds no certificate")
	}
	return decoded, nil
}

// DecodePrivateKey decodes a configured private key. A key protected by a
// passphrase is refused: the servers start with nobody to ask for one.
func DecodePrivateKey(value string) ([]byte, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(decoded)
	if block == nil {
		return nil, errors.New("does not decode to a PEM block")
	}
	if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("holds %s, not a private key", describeBlock(block.Type))
	}
	if encrypted(block) {
		return nil, errors.New("is protected by a passphrase, which is not supported")
	}
	if _, err := parsePrivateKey(block); err != nil {
		return nil, fmt.Errorf("cannot be parsed: %w", err)
	}
	return decoded, nil
}

// parsePrivateKey accepts the encodings openssl and ssh-keygen produce.
func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
	default:
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	}
}

// encrypted reports a key that openssl encrypted the old way. A modern one
// carries no header and fails to parse instead, which the caller reports.
func encrypted(block *pem.Block) bool {
	if header := block.Headers["Proc-Type"]; header != "" {
		return strings.Contains(header, "ENCRYPTED")
	}
	return block.Type == "ENCRYPTED PRIVATE KEY"
}

func describeBlock(blockType string) string {
	if blockType == "" {
		return "an unnamed PEM block"
	}
	return "a " + strings.ToLower(blockType) + " block"
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

// DecodeSessionSecret turns the configured http.httpSessionTokenSecret into the
// key the login tokens are signed with. Unlike the other kinds the value is not
// PEM: it is base64 of the key bytes themselves, which is what a key with no
// structure looks like.
func DecodeSessionSecret(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("is empty")
	}
	// tolerate the line breaks a base64 tool leaves behind, as DecodePEM does
	compact := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(trimmed)
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		if looksLikeAPath(trimmed) {
			return nil, errors.New("looks like a file path; the value is the key itself, " +
				`base64 encoded, as in: head -c 32 /dev/urandom | base64`)
		}
		return nil, errors.New("is not base64")
	}
	if len(decoded) < minSessionSecret {
		return nil, fmt.Errorf("decodes to %d bytes, it has to be at least %d",
			len(decoded), minSessionSecret)
	}
	return decoded, nil
}

// GenerateSessionSecret produces a signing key as the value the file holds. It
// is what the HTTP server falls back to when none is configured and what the
// web interface stores when Generate is pressed, so a generated key and a
// configured one are the same thing.
func GenerateSessionSecret() (string, error) {
	key := make([]byte, minSessionSecret)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return Encode(key), nil
}

func describeSessionSecret(value string) string {
	decoded, err := DecodeSessionSecret(value)
	if err != nil {
		return "this value " + err.Error()
	}
	return fmt.Sprintf("a %d byte signing key", len(decoded))
}

// Encode is how PEM bytes become a value in the file.
func Encode(pemBytes []byte) string {
	return base64.StdEncoding.EncodeToString(pemBytes)
}

// Describe is the line the web interface shows under a stored value, since
// base64 tells the reader nothing about what they are looking at. kind is one
// of the upload kinds the interface knows. A value that cannot be read
// describes the reason, which is what a start would fail with.
func Describe(kind, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	switch kind {
	case KindCertificate:
		return describeCertificate(value)
	case KindSSHKey:
		return describeHostKey(value)
	case KindSessionSecret:
		return describeSessionSecret(value)
	default:
		return describePrivateKey(value)
	}
}

func describeCertificate(value string) string {
	decoded, err := DecodeCertificate(value)
	if err != nil {
		return "this value " + err.Error()
	}
	block, rest := pem.Decode(decoded)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "this value cannot be parsed: " + err.Error()
	}

	name := certificate.Subject.CommonName
	if name == "" {
		name = strings.Join(certificate.DNSNames, ", ")
	}
	summary := fmt.Sprintf("certificate %s, expires %s",
		name, certificate.NotAfter.Format(time.DateOnly))
	if time.Now().After(certificate.NotAfter) {
		summary += " (expired)"
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		summary += ", with a chain"
	}
	return summary
}

func describePrivateKey(value string) string {
	decoded, err := DecodePrivateKey(value)
	if err != nil {
		return "this value " + err.Error()
	}
	block, _ := pem.Decode(decoded)
	return strings.ToLower(block.Type)
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
