package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// dropped are the signatures Sign takes out of the signature header before it
// puts its own in: whatever key made them, the package is to carry the
// signature of the repository it is in. The ones over the header and the
// payload together are not made again; rpm 4.14 and later sign the header
// alone, which covers the payload through its digest.
var dropped = []int32{sigDSA, sigRSA, sigPGP, sigGPG, sigOpenPGP}

// Sign signs the header of the package with key, replacing whatever
// signatures it carried, and writes the package anew in place of the file:
// beside it first, then renamed over it, so that the file is never seen half
// written. The header and the payload are left as they are, so every digest
// stays valid.
//
// It returns the package as it is now on disk.
func (f *File) Sign(key Signer) (*File, error) {
	signature, err := key.Sign(bytes.NewReader(f.Header.raw))
	if err != nil {
		return nil, fmt.Errorf("signing the header: %w", err)
	}
	entries := make([]entry, 0, len(f.Signature.order)+1)
	for _, tag := range f.Signature.order {
		if tag == regionSignatures || tag == regionImmutable || slices.Contains(dropped, tag) {
			continue
		}
		entries = append(entries, f.Signature.entries[tag])
	}
	entries = append(entries, entry{tag: sigRSA, typ: typeBin, count: int32(len(signature)), data: signature})
	header := serialize(entries, regionSignatures)

	source, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(filepath.Dir(f.Path), "."+filepath.Base(f.Path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	written := false
	defer func() {
		if !written {
			temp.Close()
			os.Remove(temp.Name())
		}
	}()

	var head bytes.Buffer
	head.Write(f.lead)
	head.Write(header)
	head.Write(make([]byte, padding(int64(head.Len()))))
	if _, err := temp.Write(head.Bytes()); err != nil {
		return nil, err
	}
	if _, err := source.Seek(f.HeaderStart, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.Copy(temp, source); err != nil {
		return nil, err
	}
	// Windows does not replace a file that is still open
	source.Close()
	if err := temp.Sync(); err != nil {
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(temp.Name(), info.Mode().Perm()); err != nil {
		return nil, err
	}
	if err := os.Rename(temp.Name(), f.Path); err != nil {
		return nil, err
	}
	written = true
	return Open(f.Path)
}

// serialize writes a header of the entries, sorted by tag, behind a region
// tag that marks all of them as one region, as rpm writes its own: an index
// entry first that points at a trailer at the end of the store, which holds
// the region tag again and the negative length of the index.
func serialize(entries []entry, region int32) []byte {
	slices.SortFunc(entries, func(a, b entry) int { return int(a.tag) - int(b.tag) })

	var store bytes.Buffer
	offsets := make([]int, len(entries))
	for i, e := range entries {
		if width := alignment(e.typ); width > 1 && store.Len()%width != 0 {
			store.Write(make([]byte, width-store.Len()%width))
		}
		offsets[i] = store.Len()
		store.Write(e.data)
	}
	count := len(entries) + 1
	trailerAt := store.Len()
	trailer := indexEntry(region, typeBin, int32(-16*count), 16)
	store.Write(trailer)

	var out bytes.Buffer
	out.Write(headerMagic)
	out.Write([]byte{0, 0, 0, 0})
	binary.Write(&out, binary.BigEndian, int32(count))
	binary.Write(&out, binary.BigEndian, int32(store.Len()))
	out.Write(indexEntry(region, typeBin, int32(trailerAt), 16))
	for i, e := range entries {
		out.Write(indexEntry(e.tag, e.typ, int32(offsets[i]), e.count))
	}
	out.Write(store.Bytes())
	return out.Bytes()
}

func indexEntry(tag, typ, offset, count int32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:], uint32(tag))
	binary.BigEndian.PutUint32(b[4:], uint32(typ))
	binary.BigEndian.PutUint32(b[8:], uint32(offset))
	binary.BigEndian.PutUint32(b[12:], uint32(count))
	return b
}

// alignment is the boundary a value of the type starts on in the store.
func alignment(typ int32) int {
	switch typ {
	case typeInt16:
		return 2
	case typeInt32:
		return 4
	case typeInt64:
		return 8
	}
	return 1
}
