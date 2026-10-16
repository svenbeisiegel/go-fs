package fdroid

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/smallstep/pkcs7"
)

// The ids of the APK Signature Scheme blocks in the APK Signing Block.
const (
	schemeV2 = 0x7109871a
	schemeV3 = 0xf05368c0
)

// signingBlockMagic ends the APK Signing Block.
var signingBlockMagic = []byte("APK Sig Block 42")

// errNoSigner is an APK that is not signed, which Android does not install.
var errNoSigner = errors.New("is not signed, and Android installs no APK that is not")

// signer is the SHA-256 of the certificate the APK is signed with: the first
// signer of APK Signature Scheme v3, else v2, else the JAR signature. The
// signatures are not checked, which Android does when it installs the APK;
// the index only says which key an app is signed with, so that the client
// offers an update for the app installed from the same developer.
func signer(r io.ReaderAt, size int64, z *zip.Reader, files map[string]*zip.File) (string, error) {
	if block, err := signingBlock(r, size); err == nil {
		for _, id := range []uint32{schemeV3, schemeV2} {
			if value, ok := block[id]; ok {
				certificate, err := firstCertificate(value)
				if err != nil {
					return "", fmt.Errorf("has a signature that cannot be read: %w", err)
				}
				return fingerprint(certificate), nil
			}
		}
	}
	for _, f := range z.File {
		dir, name := path.Split(f.Name)
		ext := strings.ToUpper(path.Ext(name))
		if dir != "META-INF/" || (ext != ".RSA" && ext != ".DSA" && ext != ".EC") {
			continue
		}
		data, err := readFile(files, f.Name)
		if err != nil {
			return "", err
		}
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return "", fmt.Errorf("has a signature that cannot be read: %w", err)
		}
		certificate := p7.GetOnlySigner()
		if certificate == nil && len(p7.Certificates) > 0 {
			certificate = p7.Certificates[0]
		}
		if certificate == nil {
			return "", errors.New("has a signature without a certificate")
		}
		return fingerprint(certificate.Raw), nil
	}
	return "", errNoSigner
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// signingBlock reads the APK Signing Block, which is right before the
// central directory, into its values by id.
func signingBlock(r io.ReaderAt, size int64) (map[uint32][]byte, error) {
	directory, err := centralDirectory(r, size)
	if err != nil {
		return nil, err
	}
	if directory < 24 {
		return nil, errors.New("no signing block")
	}
	footer := make([]byte, 24)
	if _, err := r.ReadAt(footer, directory-24); err != nil {
		return nil, err
	}
	if !bytes.Equal(footer[8:], signingBlockMagic) {
		return nil, errors.New("no signing block")
	}
	blockSize := int64(binary.LittleEndian.Uint64(footer[:8]))
	start := directory - blockSize - 8
	if blockSize < 24 || start < 0 {
		return nil, errors.New("a signing block of a size that does not fit")
	}
	// the pairs, between the size at the start and the size and magic at
	// the end
	pairs := make([]byte, blockSize-24)
	if _, err := r.ReadAt(pairs, start+8); err != nil {
		return nil, err
	}
	values := map[uint32][]byte{}
	for len(pairs) > 0 {
		if len(pairs) < 12 {
			return nil, errors.New("a signing block cut short")
		}
		n := binary.LittleEndian.Uint64(pairs[:8])
		if n < 4 || n > uint64(len(pairs)-8) {
			return nil, errors.New("a signing block cut short")
		}
		id := binary.LittleEndian.Uint32(pairs[8:12])
		values[id] = pairs[12 : 8+n]
		pairs = pairs[8+n:]
	}
	return values, nil
}

// centralDirectory finds where the central directory of the zip file
// begins, from the end of central directory record.
func centralDirectory(r io.ReaderAt, size int64) (int64, error) {
	const eocdSize = 22
	// the record ends in a comment of at most 65535 bytes
	tail := min(size, eocdSize+65535)
	buf := make([]byte, tail)
	if _, err := r.ReadAt(buf, size-tail); err != nil {
		return 0, err
	}
	for i := len(buf) - eocdSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == 0x06054b50 {
			return int64(binary.LittleEndian.Uint32(buf[i+16:])), nil
		}
	}
	return 0, ErrIncomplete
}

// firstCertificate reads the first certificate of the first signer of an APK
// Signature Scheme v2 or v3 block. Both begin alike: a sequence of signers,
// each beginning with its signed data, which holds the digests and then the
// certificates; every item is prefixed by its length.
func firstCertificate(value []byte) ([]byte, error) {
	signers, err := prefixed(value)
	if err != nil {
		return nil, err
	}
	first, err := prefixed(signers)
	if err != nil {
		return nil, err
	}
	signedData, err := prefixed(first)
	if err != nil {
		return nil, err
	}
	digests, err := prefixed(signedData)
	if err != nil {
		return nil, err
	}
	certificates, err := prefixed(signedData[4+len(digests):])
	if err != nil {
		return nil, err
	}
	certificate, err := prefixed(certificates)
	if err != nil {
		return nil, err
	}
	if len(certificate) == 0 {
		return nil, errors.New("a signer without a certificate")
	}
	return certificate, nil
}

// prefixed reads the item at the start of b that is prefixed by its length,
// a little endian uint32.
func prefixed(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("cut short")
	}
	n := binary.LittleEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, errors.New("cut short")
	}
	return b[4 : 4+n], nil
}
