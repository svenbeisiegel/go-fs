// Package rpm reads, checks and signs rpm packages, and writes the rpm-md
// metadata zypper and dnf read a repository of them by, as createrepo_c does.
//
// An rpm is a lead of 96 bytes that nothing reads any more, the signature
// header, padded to a multiple of 8 bytes, the header that describes the
// package, and the compressed payload. Both headers are the same structure: an
// index of tags, each pointing into a store of their values. The signature
// header holds the digests of the header and the payload and the OpenPGP
// signatures over them; signing a package replaces it and nothing else.
package rpm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	leadSize = 96
	// maxHeader bounds a header read from a file. rpm itself refuses one
	// larger than 256 MB; a package of ordinary size has one of kilobytes.
	maxHeader = 256 << 20
	// maxEntries bounds the index of a header, as rpm does.
	maxEntries = 0xffff
)

var (
	leadMagic   = []byte{0xed, 0xab, 0xee, 0xdb}
	headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01}
)

// The types of a value in a header.
const (
	typeNull        = 0
	typeChar        = 1
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeInt64       = 5
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

// regionSignatures and regionImmutable are the tags that mark a header as
// whole: the first entry of the index, whose value, at the end of the store,
// says how many entries the region holds.
const (
	regionSignatures = 62
	regionImmutable  = 63
)

// entry is one tag of a header with its value as it is stored.
type entry struct {
	tag   int32
	typ   int32
	count int32
	data  []byte
}

// Header is a parsed header: its tags, and the bytes it was read from.
type Header struct {
	entries map[int32]entry
	// order is the order the index lists the tags in.
	order []int32
	// raw is the header as it is in the file, from its magic to the end of
	// its store, without the padding after a signature header. It is what the
	// digests and signatures in the signature header are taken over.
	raw []byte
}

// readHeader reads a header from r. The store is not padded; the caller
// skips the padding of a signature header.
func readHeader(r io.Reader) (*Header, error) {
	var intro [16]byte
	if _, err := io.ReadFull(r, intro[:]); err != nil {
		return nil, fmt.Errorf("the header is cut short: %w", unexpected(err))
	}
	if !bytes.Equal(intro[:4], headerMagic) {
		return nil, errors.New("the header has no magic")
	}
	count := binary.BigEndian.Uint32(intro[8:12])
	size := binary.BigEndian.Uint32(intro[12:16])
	if count == 0 || count > maxEntries || size > maxHeader {
		return nil, fmt.Errorf("the header claims %d entries and %d bytes", count, size)
	}
	raw := make([]byte, 16+int(count)*16+int(size))
	copy(raw, intro[:])
	if _, err := io.ReadFull(r, raw[16:]); err != nil {
		return nil, fmt.Errorf("the header is cut short: %w", unexpected(err))
	}
	return parseHeader(raw, int(count), int(size))
}

func parseHeader(raw []byte, count, size int) (*Header, error) {
	index := raw[16 : 16+count*16]
	store := raw[16+count*16:]
	h := &Header{entries: make(map[int32]entry, count), raw: raw}
	for i := range count {
		at := index[i*16:]
		e := entry{
			tag:   int32(binary.BigEndian.Uint32(at[0:])),
			typ:   int32(binary.BigEndian.Uint32(at[4:])),
			count: int32(binary.BigEndian.Uint32(at[12:])),
		}
		offset := int32(binary.BigEndian.Uint32(at[8:]))
		if offset < 0 || int(offset) > size || e.count < 0 {
			return nil, fmt.Errorf("tag %d points outside the header", e.tag)
		}
		length, err := valueLength(e.typ, int(e.count), store[offset:])
		if err != nil {
			return nil, fmt.Errorf("tag %d: %w", e.tag, err)
		}
		e.data = store[offset : int(offset)+length]
		if _, seen := h.entries[e.tag]; !seen {
			h.order = append(h.order, e.tag)
		}
		h.entries[e.tag] = e
	}
	return h, nil
}

// valueLength is how many bytes of store a value of the type and count takes.
func valueLength(typ int32, count int, store []byte) (int, error) {
	width := 0
	switch typ {
	case typeNull:
		return 0, nil
	case typeChar, typeInt8, typeBin:
		width = 1
	case typeInt16:
		width = 2
	case typeInt32:
		width = 4
	case typeInt64:
		width = 8
	case typeString, typeStringArray, typeI18NString:
		if typ == typeString {
			count = 1
		}
		length := 0
		for range count {
			end := bytes.IndexByte(store[length:], 0)
			if end < 0 {
				return 0, errors.New("a string runs past the header")
			}
			length += end + 1
		}
		return length, nil
	default:
		return 0, fmt.Errorf("unknown type %d", typ)
	}
	if count > len(store)/width {
		return 0, errors.New("the value runs past the header")
	}
	return count * width, nil
}

// Has reports whether the header holds tag.
func (h *Header) Has(tag int32) bool {
	_, ok := h.entries[tag]
	return ok
}

// String is the value of a string tag, the first one of an array, "" when
// the header has none.
func (h *Header) String(tag int32) string {
	if s := h.Strings(tag); len(s) > 0 {
		return s[0]
	}
	return ""
}

// Strings is the value of a string or string array tag.
func (h *Header) Strings(tag int32) []string {
	e, ok := h.entries[tag]
	if !ok {
		return nil
	}
	switch e.typ {
	case typeString, typeStringArray, typeI18NString:
	default:
		return nil
	}
	parts := bytes.Split(bytes.TrimSuffix(e.data, []byte{0}), []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, string(part))
	}
	if e.typ == typeI18NString && len(out) > 1 {
		// the first is the untranslated one
		out = out[:1]
	}
	return out
}

// Ints is the value of an integer tag of any width.
func (h *Header) Ints(tag int32) []int64 {
	e, ok := h.entries[tag]
	if !ok {
		return nil
	}
	out := make([]int64, e.count)
	for i := range out {
		switch e.typ {
		case typeChar, typeInt8:
			out[i] = int64(e.data[i])
		case typeInt16:
			out[i] = int64(binary.BigEndian.Uint16(e.data[i*2:]))
		case typeInt32:
			out[i] = int64(binary.BigEndian.Uint32(e.data[i*4:]))
		case typeInt64:
			out[i] = int64(binary.BigEndian.Uint64(e.data[i*8:]))
		default:
			return nil
		}
	}
	return out
}

// Int is the first value of an integer tag, and whether there is one.
func (h *Header) Int(tag int32) (int64, bool) {
	if values := h.Ints(tag); len(values) > 0 {
		return values[0], true
	}
	return 0, false
}

// Bytes is the value of a binary tag.
func (h *Header) Bytes(tag int32) []byte {
	if e, ok := h.entries[tag]; ok && e.typ == typeBin {
		return e.data
	}
	return nil
}

// Raw is the header as it is in the file.
func (h *Header) Raw() []byte {
	return h.raw
}

// File is an rpm package as it is laid out on disk.
type File struct {
	Path string
	// Size is the length of the file.
	Size int64
	lead []byte
	// Signature is the signature header and Header the header of the
	// package.
	Signature *Header
	Header    *Header
	// HeaderStart is where the header begins in the file, after the lead and
	// the padded signature header, and PayloadStart where it ends.
	HeaderStart  int64
	PayloadStart int64
}

// Open reads the lead and the headers of the package at path. The payload is
// read only by Verify.
func Open(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	f := &File{Path: path, Size: info.Size(), lead: make([]byte, leadSize)}
	if _, err := io.ReadFull(file, f.lead); err != nil {
		return nil, fmt.Errorf("the lead is cut short: %w", unexpected(err))
	}
	if !bytes.Equal(f.lead[:4], leadMagic) {
		return nil, errors.New("is not an rpm package")
	}
	if f.Signature, err = readHeader(file); err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	// the signature header is padded so the header begins on 8 bytes
	sigEnd := int64(leadSize + len(f.Signature.raw))
	f.HeaderStart = sigEnd + padding(sigEnd)
	if _, err := file.Seek(f.HeaderStart, io.SeekStart); err != nil {
		return nil, err
	}
	if f.Header, err = readHeader(file); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	f.PayloadStart = f.HeaderStart + int64(len(f.Header.raw))
	return f, nil
}

// padding is what brings offset up to a multiple of 8.
func padding(offset int64) int64 {
	return (8 - offset%8) % 8
}

// unexpected reads a file that ends early as such, rather than as io.EOF,
// which a caller would take for the end of something it expected to end.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
