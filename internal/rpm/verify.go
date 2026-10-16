package rpm

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

// ErrIncomplete is what Verify reports for a package whose length or digests
// do not match what its signature header says. That is a package still being
// written as much as a broken one, so a caller tries it again later rather than
// giving up on it.
var ErrIncomplete = errors.New("the package is incomplete or damaged")

// Verify checks the package against the digests its signature header and
// header carry: its length, the digest of the header, and the digest of the
// payload. It does not check a signature, which is the job of SignedBy.
func (f *File) Verify() error {
	length := f.Size - f.HeaderStart
	if want, ok := f.Signature.Int(sigLongSize); ok && want != length {
		return fmt.Errorf("%w: it is %d bytes where it says %d", ErrIncomplete, length, want)
	} else if want, ok := f.Signature.Int(sigSize); ok && !f.Signature.Has(sigLongSize) && want != length {
		return fmt.Errorf("%w: it is %d bytes where it says %d", ErrIncomplete, length, want)
	}

	header := f.Header.raw
	switch {
	case f.Signature.Has(sigSHA256):
		if err := matches("header SHA-256", sha256.New(), header, f.Signature.String(sigSHA256)); err != nil {
			return err
		}
	case f.Signature.Has(sigSHA1):
		if err := matches("header SHA-1", sha1.New(), header, f.Signature.String(sigSHA1)); err != nil {
			return err
		}
	}

	file, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	// the payload is read once, into each digest that checks it
	var digests []check
	if want := f.Header.String(tagPayloadDigest); want != "" {
		algo, _ := f.Header.Int(tagPayloadDigestAlgo)
		h := hashOf(algo)
		if h == nil {
			return fmt.Errorf("the payload digest is of an unknown algorithm %d", algo)
		}
		digests = append(digests, check{"payload digest", h, want})
	}
	if want := f.Signature.Bytes(sigMD5); want != nil {
		// over the header and the payload
		h := md5.New()
		h.Write(header)
		digests = append(digests, check{"MD5", h, hex.EncodeToString(want)})
	}
	if len(digests) == 0 {
		return errors.New("the package carries no digest of its payload to check it by")
	}
	writers := make([]io.Writer, len(digests))
	for i, d := range digests {
		writers[i] = d.hash
	}
	if _, err := file.Seek(f.PayloadStart, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(io.MultiWriter(writers...), file); err != nil {
		return err
	}
	for _, d := range digests {
		if got := hex.EncodeToString(d.hash.Sum(nil)); got != d.want {
			return fmt.Errorf("%w: the %s does not match", ErrIncomplete, d.name)
		}
	}
	return nil
}

type check struct {
	name string
	hash hash.Hash
	want string
}

func matches(name string, h hash.Hash, data []byte, want string) error {
	h.Write(data)
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: the %s does not match", ErrIncomplete, name)
	}
	return nil
}

// hashOf is the digest an OpenPGP algorithm number names, nil for one this
// does not know.
func hashOf(algo int64) hash.Hash {
	switch algo {
	case hashMD5:
		return md5.New()
	case hashSHA1:
		return sha1.New()
	case hashSHA224:
		return sha256.New224()
	case hashSHA256:
		return sha256.New()
	case hashSHA384:
		return sha512.New384()
	case hashSHA512:
		return sha512.New()
	}
	return nil
}

// Signer is the key a package is signed and checked with; *pgp.Key is one.
type Signer interface {
	// Sign makes a binary detached OpenPGP signature over data.
	Sign(data io.Reader) ([]byte, error)
	// Verify checks a binary detached signature over data made by the key.
	Verify(data io.Reader, signature []byte) error
}

// SignedBy reports whether the header of the package carries a signature of
// key that is valid. A package signed by another key, or by none, is not.
func (f *File) SignedBy(key Signer) bool {
	for _, tag := range []int32{sigRSA, sigDSA} {
		signature := f.Signature.Bytes(tag)
		if signature == nil {
			continue
		}
		if key.Verify(bytes.NewReader(f.Header.raw), signature) == nil {
			return true
		}
	}
	return false
}
