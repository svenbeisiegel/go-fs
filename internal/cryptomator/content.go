package cryptomator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The content of a file of the vault is a header followed by chunks, each
// encrypted with AES-GCM. The header holds the key of the content, sealed
// with the key of the vault; each chunk is up to 32 KiB of the cleartext,
// sealed with the key of the content and bound to its place in the file and
// to the header, so that chunks can be neither moved nor swapped between
// files. A file of nothing is its header alone.

const (
	nonceSize = 12
	tagSize   = 16
	// HeaderSize is how long the header in front of every file is.
	HeaderSize = nonceSize + 8 + keySize + tagSize
	// ChunkSize is how much of the cleartext a chunk holds.
	ChunkSize = 32 * 1024
	// chunkOverhead is how much longer a chunk is than what it holds.
	chunkOverhead = nonceSize + tagSize
	// cipherChunkSize is how long a whole chunk is.
	cipherChunkSize = ChunkSize + chunkOverhead
)

// ErrCorrupt is what reading a file of the vault that was cut short or
// tampered with fails with.
var ErrCorrupt = errors.New("the file in the vault is damaged")

// CiphertextSize is how long a file of cleartextSize bytes is in the vault.
func CiphertextSize(cleartextSize int64) int64 {
	if cleartextSize < 0 {
		return -1
	}
	chunks := (cleartextSize + ChunkSize - 1) / ChunkSize
	return HeaderSize + cleartextSize + chunks*chunkOverhead
}

// CleartextSize is how much a file of the vault ciphertextSize bytes long
// holds, and -1 for a length no file of a vault has.
func CleartextSize(ciphertextSize int64) int64 {
	body := ciphertextSize - HeaderSize
	if body < 0 {
		return -1
	}
	full, rest := body/cipherChunkSize, body%cipherChunkSize
	if rest > 0 && rest <= chunkOverhead {
		return -1
	}
	size := full * ChunkSize
	if rest > 0 {
		size += rest - chunkOverhead
	}
	return size
}

// header is what the header of a file holds: its nonce, which every chunk is
// bound to, and the key of the content.
type header struct {
	nonce [nonceSize]byte
	key   cipher.AEAD
}

func (v *Vault) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(v.encKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (v *Vault) newHeader() (*header, []byte, error) {
	h := &header{}
	payload := make([]byte, 8+keySize)
	for i := range 8 {
		payload[i] = 0xff
	}
	if _, err := rand.Read(h.nonce[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(payload[8:]); err != nil {
		return nil, nil, err
	}
	if err := h.keyed(payload[8:]); err != nil {
		return nil, nil, err
	}
	sealer, err := v.gcm()
	if err != nil {
		return nil, nil, err
	}
	return h, sealer.Seal(h.nonce[:], h.nonce[:], payload, nil), nil
}

func (v *Vault) openHeader(b []byte) (*header, error) {
	if len(b) != HeaderSize {
		return nil, ErrCorrupt
	}
	opener, err := v.gcm()
	if err != nil {
		return nil, err
	}
	payload, err := opener.Open(nil, b[:nonceSize], b[nonceSize:], nil)
	if err != nil {
		return nil, ErrCorrupt
	}
	h := &header{}
	copy(h.nonce[:], b)
	return h, h.keyed(payload[8:])
}

func (h *header) keyed(contentKey []byte) error {
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return err
	}
	h.key, err = cipher.NewGCM(block)
	return err
}

func (h *header) aad(chunk int64) []byte {
	aad := make([]byte, 8+nonceSize)
	binary.BigEndian.PutUint64(aad, uint64(chunk))
	copy(aad[8:], h.nonce[:])
	return aad
}

// Writer encrypts what is written to it into a file of the vault. Close
// writes the last chunk; it does not close what it writes to.
type Writer struct {
	w     io.Writer
	h     *header
	buf   []byte
	chunk int64
	err   error
}

// NewWriter writes the header of a new file to w and returns what encrypts
// its content.
func (v *Vault) NewWriter(w io.Writer) (*Writer, error) {
	h, sealed, err := v.newHeader()
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(sealed); err != nil {
		return nil, err
	}
	return &Writer{w: w, h: h, buf: make([]byte, 0, ChunkSize)}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(p) > 0 {
		n := copy(w.buf[len(w.buf):cap(w.buf)], p)
		w.buf = w.buf[:len(w.buf)+n]
		p = p[n:]
		written += n
		// a full chunk waits until more comes, as the last one is written by
		// Close whatever its size
		if len(w.buf) == cap(w.buf) && len(p) > 0 {
			if w.err = w.flush(); w.err != nil {
				return written, w.err
			}
		}
	}
	return written, nil
}

func (w *Writer) flush() error {
	nonce := make([]byte, nonceSize, cipherChunkSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := w.h.key.Seal(nonce, nonce, w.buf, w.h.aad(w.chunk))
	w.chunk++
	w.buf = w.buf[:0]
	_, err := w.w.Write(sealed)
	return err
}

// Close writes what is left as the last chunk; a file of nothing has none.
func (w *Writer) Close() error {
	if w.err == nil && len(w.buf) > 0 {
		w.err = w.flush()
	}
	err := w.err
	if err == nil {
		w.err = errClosed
	}
	return err
}

// errClosed is what writing to a Writer that was closed fails with.
var errClosed = errors.New("the file was closed")

// Reader decrypts a file of the vault, a chunk at a time, from wherever it
// is sought to.
type Reader struct {
	r      io.ReadSeeker
	h      *header
	size   int64
	offset int64
	// chunk is the cleartext of the chunk numbered index, nil when none was
	// read yet.
	chunk []byte
	index int64
	raw   []byte
}

// NewReader reads the header of a file of the vault that is ciphertextSize
// bytes long, and returns what decrypts its content.
func (v *Vault) NewReader(r io.ReadSeeker, ciphertextSize int64) (*Reader, error) {
	size := CleartextSize(ciphertextSize)
	if size < 0 {
		return nil, ErrCorrupt
	}
	b := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, corrupt(err)
	}
	h, err := v.openHeader(b)
	if err != nil {
		return nil, err
	}
	return &Reader{r: r, h: h, size: size, index: -1, raw: make([]byte, cipherChunkSize)}, nil
}

// Size is how much the file holds.
func (r *Reader) Size() int64 { return r.size }

func (r *Reader) Read(p []byte) (int, error) {
	if r.offset >= r.size {
		return 0, io.EOF
	}
	index := r.offset / ChunkSize
	if r.chunk == nil || r.index != index {
		if err := r.load(index); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.chunk[r.offset-index*ChunkSize:])
	r.offset += int64(n)
	return n, nil
}

func (r *Reader) load(index int64) error {
	at := HeaderSize + index*cipherChunkSize
	length := min(int64(cipherChunkSize), CiphertextSize(r.size)-at)
	if _, err := r.r.Seek(at, io.SeekStart); err != nil {
		return err
	}
	raw := r.raw[:length]
	if _, err := io.ReadFull(r.r, raw); err != nil {
		return corrupt(err)
	}
	plain, err := r.h.key.Open(r.chunk[:0], raw[:nonceSize], raw[nonceSize:], r.h.aad(index))
	if err != nil {
		r.chunk = nil
		return ErrCorrupt
	}
	r.chunk, r.index = plain, index
	return nil
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.offset
	case io.SeekEnd:
		offset += r.size
	default:
		return 0, fmt.Errorf("%d is not a whence", whence)
	}
	if offset < 0 {
		return 0, errors.New("seek before the start of the file")
	}
	r.offset = offset
	return offset, nil
}

// corrupt is a file that ended before what its length said it holds.
func corrupt(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrCorrupt
	}
	return err
}
